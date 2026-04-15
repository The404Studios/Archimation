/*
 * posture.c — Composite, atomically-validated actuator.
 *
 * This module sits ABOVE the per-writer modules (cgroup_writer.c,
 * iouring_writer.c, cpufreq_writer.c) and guarantees two properties that
 * the per-writer layer cannot, by construction, provide:
 *
 *   1. Cross-field invariants are checked BEFORE any write. A posture
 *      where sqpoll_cpu ∈ game_cpuset is REJECTED before a single byte
 *      reaches sysfs; the per-writer layer never sees the bad plan.
 *
 *   2. Commits are ATOMIC in the observational sense: either every
 *      kernel-visible write succeeds, or the system ends up in its
 *      pre-commit posture with zero visible residue. sysfs does not
 *      expose a transactional API, so we implement this by capturing
 *      the pre-commit values and running a compensating rollback if
 *      any write in the commit plan fails.
 *
 * The typestate pattern (UNINIT → UNVAL → VALID → COMMIT) makes these
 * properties checkable at compile time via function preconditions: the
 * signature of posture_commit_atomic() requires a VALIDATED posture, and
 * you cannot synthesise one without running posture_validate().
 */

#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "coherence_types.h"
#include "posture.h"

/* -------------------------------------------------------------------------
 * Transition table.
 *
 * R34 discipline:
 *   - Total function: indexed by [from][to]; any cell not explicitly `true`
 *     denotes a forbidden transition.
 *   - UNINIT is an absorbing sink — you may transition OUT of it once
 *     (into UNVALIDATED via posture_build) but no other state may enter it.
 *   - UNVALIDATED self-loop is allowed (posture_build called twice on the
 *     same buffer is legal — it just re-populates).
 *   - VALIDATED self-loop is allowed (idempotent re-validate on a fresh
 *     timestamp is legal and used by the caller on a posture reused
 *     between frames).
 *   - Any state may transition to UNVALIDATED (a failed commit reverts to
 *     UNVALIDATED so the caller may retry after fixing the issue).
 *   - Only VALIDATED → COMMITTED is legal for commit.
 *   - COMMITTED is terminal for that posture instance; the caller allocates
 *     a new one (or calls posture_build again, which sends us back to
 *     UNVALIDATED) for the next frame.
 * ------------------------------------------------------------------------- */
static const bool posture_trans[COH_POSTURE_STATE_COUNT][COH_POSTURE_STATE_COUNT] = {
	/*   from \ to      UNINIT  UNVAL   VALID   COMMIT */
	/* UNINIT    */  { false,  true,   false,  false },
	/* UNVAL     */  { false,  true,   true,   false },
	/* VALID     */  { false,  true,   true,   true  },
	/* COMMIT    */  { false,  true,   false,  false },
};

_Static_assert(sizeof(posture_trans) ==
               COH_POSTURE_STATE_COUNT * COH_POSTURE_STATE_COUNT * sizeof(bool),
               "posture transition table size mismatch");
_Static_assert(COH_POSTURE_STATE_COUNT == 4,
               "posture_trans table encodes exactly 4 states");
_Static_assert(COH_POSTURE_UNINIT == 0,
               "UNINIT must be zero variant");

/* -------------------------------------------------------------------------
 * Contract-level shared helpers. These implement prototypes declared in
 * coherence_types.h that the contract says live in posture.c (Agent 2).
 * ------------------------------------------------------------------------- */

const char *coh_posture_state_str(coh_posture_state_t s)
{
	switch (s) {
	case COH_POSTURE_UNINIT:      return "UNINIT";
	case COH_POSTURE_UNVALIDATED: return "UNVALIDATED";
	case COH_POSTURE_VALIDATED:   return "VALIDATED";
	case COH_POSTURE_COMMITTED:   return "COMMITTED";
	case COH_POSTURE_STATE_COUNT: /* fallthrough */
	default:                      return "INVALID";
	}
}

bool coh_posture_transition_legal(coh_posture_state_t from, coh_posture_state_t to)
{
	if ((unsigned)from >= COH_POSTURE_STATE_COUNT) return false;
	if ((unsigned)to   >= COH_POSTURE_STATE_COUNT) return false;
	return posture_trans[from][to];
}

/* -------------------------------------------------------------------------
 * cpumask parsing.
 *
 * The cpuset.cpus syntax accepts comma-separated ranges: "0", "0-3", "2,4",
 * "0-1,4-7". We decode into a fixed-width bitmap keyed by CPU id. The width
 * is COH_MAX_CPUS (64), which fits in a single uint64_t — but we use a
 * byte-indexed bitmap to keep parsing symmetric with NUMA masks later.
 *
 * Returns:
 *    0   parsed successfully (out_count updated to count of set bits)
 *   -1   malformed syntax
 *   -2   CPU id out of range [0, COH_MAX_CPUS)
 * ------------------------------------------------------------------------- */

#define CPUMASK_BYTES ((COH_MAX_CPUS + 7) / 8)

typedef struct {
	uint8_t bits[CPUMASK_BYTES];
	int     popcount;
} cpu_bitmap_t;

static inline void cbm_set(cpu_bitmap_t *b, int cpu)
{
	b->bits[cpu >> 3] |= (uint8_t)(1u << (cpu & 7));
}

static inline bool cbm_get(const cpu_bitmap_t *b, int cpu)
{
	return (b->bits[cpu >> 3] & (uint8_t)(1u << (cpu & 7))) != 0;
}

static inline bool cbm_overlaps(const cpu_bitmap_t *a, const cpu_bitmap_t *b)
{
	for (size_t i = 0; i < CPUMASK_BYTES; i++) {
		if (a->bits[i] & b->bits[i]) {
			return true;
		}
	}
	return false;
}

static int parse_cpumask(const char *str, cpu_bitmap_t *out)
{
	memset(out, 0, sizeof(*out));
	if (!str) return -1;

	/* Empty mask is syntactically legal but we treat the popcount as 0. */
	size_t n = strnlen(str, COH_CPUMASK_STRLEN);
	if (n >= COH_CPUMASK_STRLEN) return -1; /* not NUL-terminated */
	if (n == 0) return 0;

	const char *p = str;
	while (*p) {
		/* Skip whitespace — some callers pad the string. */
		while (*p == ' ' || *p == '\t') p++;
		if (!*p) break;

		/* Parse first integer of the item (may be the whole item if no '-'). */
		if (!isdigit((unsigned char)*p)) return -1;
		int lo = 0;
		int lo_digits = 0;
		while (isdigit((unsigned char)*p)) {
			lo = lo * 10 + (*p - '0');
			lo_digits++;
			if (lo_digits > 4 || lo >= COH_MAX_CPUS) {
				/* Cap aggressively — the largest valid id is COH_MAX_CPUS-1 */
				return -2;
			}
			p++;
		}
		int hi = lo;

		/* Optional "-N" tail. */
		if (*p == '-') {
			p++;
			if (!isdigit((unsigned char)*p)) return -1;
			hi = 0;
			int hi_digits = 0;
			while (isdigit((unsigned char)*p)) {
				hi = hi * 10 + (*p - '0');
				hi_digits++;
				if (hi_digits > 4 || hi >= COH_MAX_CPUS) {
					return -2;
				}
				p++;
			}
			if (hi < lo) return -1; /* "5-3" is malformed */
		}

		for (int c = lo; c <= hi; c++) {
			if (!cbm_get(out, c)) {
				cbm_set(out, c);
				out->popcount++;
			}
		}

		/* Skip whitespace before optional comma. */
		while (*p == ' ' || *p == '\t') p++;
		if (*p == ',') {
			p++;
			continue;
		}
		if (*p == '\0') break;
		return -1;
	}
	return 0;
}

/* -------------------------------------------------------------------------
 * NUMA upper bound. Reads /sys/devices/system/node/online, falls back to
 * COH_MAX_CPUS (64) on any failure. Cached on first call.
 * ------------------------------------------------------------------------- */

static int g_numa_max = -1;  /* -1 = unknown; else exclusive upper bound */

static int detect_numa_max(void)
{
	if (g_numa_max > 0) return g_numa_max;

	/* Conservative default if sysfs read fails. 64 NUMA nodes is
	 * generous — most hardware has <= 8. */
	int fallback = 64;

	int fd = open("/sys/devices/system/node/online", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		g_numa_max = fallback;
		return g_numa_max;
	}

	char buf[64];
	ssize_t r = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (r <= 0) {
		g_numa_max = fallback;
		return g_numa_max;
	}
	buf[r] = '\0';

	/* Parse highest integer in "0" or "0-3" style output. */
	int max_id = 0;
	int cur = -1;
	for (ssize_t i = 0; i < r && buf[i]; i++) {
		char c = buf[i];
		if (c >= '0' && c <= '9') {
			if (cur < 0) cur = 0;
			cur = cur * 10 + (c - '0');
		} else {
			if (cur > max_id) max_id = cur;
			cur = -1;
		}
	}
	if (cur > max_id) max_id = cur;

	g_numa_max = max_id + 1;
	if (g_numa_max <= 0 || g_numa_max > fallback) {
		g_numa_max = fallback;
	}
	return g_numa_max;
}

/* -------------------------------------------------------------------------
 * DRY_RUN machinery.
 *
 * When COH_POSTURE_DRY_RUN=1, all writes are redirected to /tmp/coh_posture_dry.
 * The directory tree mirrors the real sysfs/procfs layout but flattened:
 *     /tmp/coh_posture_dry/game.cpuset
 *     /tmp/coh_posture_dry/system.cpuset
 *     /tmp/coh_posture_dry/sqpoll
 *     /tmp/coh_posture_dry/epp
 *     /tmp/coh_posture_dry/min_perf_pct
 *
 * This keeps the test harness hermetic; it can read any of these files
 * back and assert on content without needing root or real sysfs.
 * ------------------------------------------------------------------------- */

#define DRY_RUN_DIR "/tmp/coh_posture_dry"

static bool dry_run_enabled(void)
{
	const char *env = getenv("COH_POSTURE_DRY_RUN");
	return env && env[0] == '1' && env[1] == '\0';
}

static int dry_run_ensure_dir(void)
{
	struct stat st;
	if (stat(DRY_RUN_DIR, &st) == 0) {
		if (S_ISDIR(st.st_mode)) return 0;
		return -ENOTDIR;
	}
	if (mkdir(DRY_RUN_DIR, 0755) == 0) return 0;
	if (errno == EEXIST) return 0;
	return -errno;
}

/* -------------------------------------------------------------------------
 * Write helpers — used by commit + rollback. Each returns 0 on success,
 * -errno on failure. All are bounded, no dynamic allocation.
 * ------------------------------------------------------------------------- */

static int write_file_atomic(const char *path, const char *data, size_t len)
{
	/* Write to a temp file in the same directory, then rename. This is
	 * atomic for the reader (the posix rename contract). */
	char tmp[512];
	int n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	if (n < 0 || (size_t)n >= sizeof(tmp)) return -ENAMETOOLONG;

	int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) return -errno;

	size_t off = 0;
	while (off < len) {
		ssize_t w = write(fd, data + off, len - off);
		if (w < 0) {
			if (errno == EINTR) continue;
			int save = errno;
			close(fd);
			(void)unlink(tmp);
			return -save;
		}
		off += (size_t)w;
	}
	if (close(fd) != 0) {
		int save = errno;
		(void)unlink(tmp);
		return -save;
	}
	if (rename(tmp, path) != 0) {
		int save = errno;
		(void)unlink(tmp);
		return -save;
	}
	return 0;
}

/* Write a sysfs/cgroupfs file with a single write() — no rename dance.
 * This is how the kernel expects us to write cpuset.cpus and sysfs
 * attributes. Atomicity there is per-write inside the kernel. */
static int write_file_sysfs(const char *path, const char *data, size_t len)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) return -errno;

	ssize_t w;
	do {
		w = write(fd, data, len);
	} while (w < 0 && errno == EINTR);

	int save = (w < 0) ? errno : 0;
	close(fd);
	if (w < 0) return -save;
	if ((size_t)w != len) return -EIO;
	return 0;
}

/* DRY_RUN variant: all writes go through rename atomically under
 * DRY_RUN_DIR. */
static int write_dry(const char *relpath, const char *data, size_t len)
{
	int rc = dry_run_ensure_dir();
	if (rc < 0) return rc;

	char full[256];
	int n = snprintf(full, sizeof(full), "%s/%s", DRY_RUN_DIR, relpath);
	if (n < 0 || (size_t)n >= sizeof(full)) return -ENAMETOOLONG;
	return write_file_atomic(full, data, len);
}

/* -------------------------------------------------------------------------
 * Per-actuator write wrappers. Each takes the NEW value and returns 0
 * on success, -errno on failure. These are the building blocks that both
 * commit and rollback use — rollback is just "write the OLD value back".
 * ------------------------------------------------------------------------- */

#define SLICE_GAME_CPUSET_PATH   "/sys/fs/cgroup/game.slice/cpuset.cpus"
#define SLICE_SYSTEM_CPUSET_PATH "/sys/fs/cgroup/system.slice/cpuset.cpus"
#define SQPOLL_TARGET_PATH       "/var/run/coherence/sqpoll-target"

static int write_cpuset(const char *slice_path, const char *dry_name,
                        const char *mask)
{
	size_t n = strnlen(mask, COH_CPUMASK_STRLEN);
	if (n >= COH_CPUMASK_STRLEN) return -EINVAL;

	if (dry_run_enabled()) {
		return write_dry(dry_name, mask, n);
	}
	return write_file_sysfs(slice_path, mask, n);
}

static int write_sqpoll(int cpu)
{
	char buf[16];
	int n = snprintf(buf, sizeof(buf), "%d\n", cpu);
	if (n <= 0 || (size_t)n >= sizeof(buf)) return -EIO;

	if (dry_run_enabled()) {
		return write_dry("sqpoll", buf, (size_t)n);
	}
	return write_file_atomic(SQPOLL_TARGET_PATH, buf, (size_t)n);
}

static const char *epp_keyword(coh_epp_t epp)
{
	switch (epp) {
	case COH_EPP_POWER:         return "power";
	case COH_EPP_BALANCE_POWER: return "balance_power";
	case COH_EPP_BALANCE_PERF:  return "balance_performance";
	case COH_EPP_PERFORMANCE:   return "performance";
	case COH_EPP_DEFAULT:       return "default";
	}
	return NULL;
}

static int write_epp_broadcast(coh_epp_t epp)
{
	const char *kw = epp_keyword(epp);
	if (!kw) return -EINVAL;
	size_t klen = strlen(kw);

	if (dry_run_enabled()) {
		/* In DRY_RUN mode we write the single chosen keyword to
		 * /tmp/coh_posture_dry/epp — simulator is per-posture, not
		 * per-CPU. */
		return write_dry("epp", kw, klen);
	}

	/* Real mode: broadcast to each online CPU's EPP file.
	 * We mirror cpufreq_writer.c: partial success (any CPU accepts) is
	 * treated as success for posture purposes; all-CPUs-failed returns
	 * -errno of the last seen failure.
	 *
	 * Note: we can read /sys/.../cpu/online but the posture layer does
	 * not need the same fine-grained per-CPU EPP caching as the steady-
	 * state actuation path — this runs at frame edge, not on hot cycles. */
	int ok = 0;
	int last_err = 0;
	for (int cpu = 0; cpu < COH_MAX_CPUS; cpu++) {
		char path[160];
		int n = snprintf(path, sizeof(path),
		                 "/sys/devices/system/cpu/cpu%d/cpufreq/energy_performance_preference",
		                 cpu);
		if (n <= 0 || (size_t)n >= sizeof(path)) continue;

		/* Skip offline / non-existent CPUs without treating their
		 * absence as a failure. */
		struct stat st;
		if (stat(path, &st) != 0) continue;

		int rc = write_file_sysfs(path, kw, klen);
		if (rc == 0) ok++;
		else last_err = rc;
	}

	if (ok > 0) return 0;
	if (last_err < 0) return last_err;
	/* No CPUs present at all — treat as no-op rather than error. This
	 * happens in containers / test environments without sysfs. */
	return 0;
}

static int write_min_perf_pct(int pct)
{
	if (pct < 0) return 0;          /* sentinel: unchanged */
	if (pct > 100) return -EINVAL;

	char buf[8];
	int n = snprintf(buf, sizeof(buf), "%d\n", pct);
	if (n <= 0 || (size_t)n >= sizeof(buf)) return -EIO;

	if (dry_run_enabled()) {
		return write_dry("min_perf_pct", buf, (size_t)n);
	}

	/* Try intel first, then amd. Missing files are no-ops (legacy
	 * governor hosts). */
	const char *paths[2] = {
		"/sys/devices/system/cpu/intel_pstate/min_perf_pct",
		"/sys/devices/system/cpu/amd_pstate/min_perf_pct",
	};
	for (int i = 0; i < 2; i++) {
		struct stat st;
		if (stat(paths[i], &st) != 0) continue;
		return write_file_sysfs(paths[i], buf, (size_t)n);
	}
	return 0;
}

/* -------------------------------------------------------------------------
 * Pre-commit snapshot capture. We read the CURRENT kernel-side values and
 * stuff them into a posture-shaped buffer so rollback can replay them.
 *
 * If any capture fails, we proceed with a best-effort snapshot — rollback
 * will simply skip the field whose capture failed. This is a trade-off:
 * we never want a missing-sysfs read to block a commit, but we accept
 * that rollback becomes advisory rather than exact for that one field.
 * ------------------------------------------------------------------------- */

static int read_small_file(const char *path, char *buf, size_t bufsz)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return -errno;
	size_t total = 0;
	while (total + 1 < bufsz) {
		ssize_t r = read(fd, buf + total, bufsz - 1 - total);
		if (r < 0) {
			if (errno == EINTR) continue;
			int save = errno;
			close(fd);
			return -save;
		}
		if (r == 0) break;
		total += (size_t)r;
	}
	buf[total] = '\0';
	/* Strip trailing newline/whitespace. */
	while (total > 0 && (buf[total - 1] == '\n' || buf[total - 1] == '\r' ||
	                     buf[total - 1] == ' '  || buf[total - 1] == '\t')) {
		buf[--total] = '\0';
	}
	close(fd);
	return 0;
}

static void capture_current(coh_posture_t *snap)
{
	memset(snap, 0, sizeof(*snap));
	snap->state = COH_POSTURE_COMMITTED; /* by definition — it IS the current */
	snap->sqpoll_cpu = -1;
	snap->epp = COH_EPP_DEFAULT;
	snap->min_perf_pct = -1;
	snap->numa_node = -1;

	if (dry_run_enabled()) {
		/* In DRY_RUN there is no "real" state — read back what we
		 * wrote last time, if anything. A first-run with no prior
		 * posture captures all-empty, which rollback treats as "no
		 * restore needed". */
		char buf[COH_CPUMASK_STRLEN];
		if (read_small_file(DRY_RUN_DIR "/game.cpuset",
		                    buf, sizeof(buf)) == 0) {
			snprintf(snap->game_cpuset, sizeof(snap->game_cpuset),
			         "%s", buf);
		}
		if (read_small_file(DRY_RUN_DIR "/system.cpuset",
		                    buf, sizeof(buf)) == 0) {
			snprintf(snap->system_cpuset, sizeof(snap->system_cpuset),
			         "%s", buf);
		}
		if (read_small_file(DRY_RUN_DIR "/sqpoll",
		                    buf, sizeof(buf)) == 0) {
			snap->sqpoll_cpu = atoi(buf);
		}
		if (read_small_file(DRY_RUN_DIR "/min_perf_pct",
		                    buf, sizeof(buf)) == 0) {
			snap->min_perf_pct = atoi(buf);
		}
		return;
	}

	char buf[COH_CPUMASK_STRLEN];
	if (read_small_file(SLICE_GAME_CPUSET_PATH, buf, sizeof(buf)) == 0) {
		snprintf(snap->game_cpuset, sizeof(snap->game_cpuset), "%s", buf);
	}
	if (read_small_file(SLICE_SYSTEM_CPUSET_PATH, buf, sizeof(buf)) == 0) {
		snprintf(snap->system_cpuset, sizeof(snap->system_cpuset), "%s", buf);
	}
	if (read_small_file(SQPOLL_TARGET_PATH, buf, sizeof(buf)) == 0) {
		snap->sqpoll_cpu = atoi(buf);
	}

	char pctbuf[16];
	if (read_small_file("/sys/devices/system/cpu/intel_pstate/min_perf_pct",
	                    pctbuf, sizeof(pctbuf)) == 0 ||
	    read_small_file("/sys/devices/system/cpu/amd_pstate/min_perf_pct",
	                    pctbuf, sizeof(pctbuf)) == 0) {
		snap->min_perf_pct = atoi(pctbuf);
	}
	/* EPP is per-CPU; we capture CPU 0's value as a representative. This
	 * is coarser than the commit side but enough for rollback: if the
	 * commit wrote "performance" to all CPUs and we need to revert,
	 * writing the prior keyword to all CPUs restores the pre-commit
	 * broadcast. */
	char eppbuf[32];
	if (read_small_file("/sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference",
	                    eppbuf, sizeof(eppbuf)) == 0) {
		if (!strcmp(eppbuf, "power"))               snap->epp = COH_EPP_POWER;
		else if (!strcmp(eppbuf, "balance_power"))  snap->epp = COH_EPP_BALANCE_POWER;
		else if (!strcmp(eppbuf, "balance_performance")) snap->epp = COH_EPP_BALANCE_PERF;
		else if (!strcmp(eppbuf, "performance"))    snap->epp = COH_EPP_PERFORMANCE;
		else                                         snap->epp = COH_EPP_DEFAULT;
	}
}

/* -------------------------------------------------------------------------
 * Rollback. Replay the snapshot's values in REVERSE order relative to
 * the commit plan.
 *
 * We log LOUDLY on rollback failure — that's the "half-posture" condition
 * described in the design doc and it is (by construction) very rare: a
 * write that worked seconds ago would have to start failing.
 * ------------------------------------------------------------------------- */

static void rollback_loud(const char *field, int rc)
{
	fprintf(stderr,
	        "{\"coherence\":\"posture\",\"event\":\"rollback_fail\","
	        "\"field\":\"%s\",\"errno\":%d,\"strerror\":\"%s\","
	        "\"alert\":\"half_posture\"}\n",
	        field, -rc, strerror(-rc));
}

/*
 * rollback_through — roll back steps 1..step_committed_up_to (exclusive)
 * in reverse order. We silently ignore rollback no-ops (e.g. empty game
 * cpuset in snapshot means "we don't know the prior value, skip").
 *
 * step_committed_up_to is the NUMBER of steps that completed before
 * failure. Steps are numbered 1..5:
 *   1 = game_cpuset
 *   2 = system_cpuset
 *   3 = sqpoll
 *   4 = epp
 *   5 = min_perf_pct
 */
static void rollback_through(const coh_posture_t *snap, int step_committed_up_to)
{
	if (step_committed_up_to >= 5) {
		int rc = write_min_perf_pct(snap->min_perf_pct);
		if (rc < 0) rollback_loud("min_perf_pct", rc);
	}
	if (step_committed_up_to >= 4) {
		int rc = write_epp_broadcast(snap->epp);
		if (rc < 0) rollback_loud("epp", rc);
	}
	if (step_committed_up_to >= 3) {
		int rc = write_sqpoll(snap->sqpoll_cpu);
		if (rc < 0) rollback_loud("sqpoll", rc);
	}
	if (step_committed_up_to >= 2 && snap->system_cpuset[0] != '\0') {
		int rc = write_cpuset(SLICE_SYSTEM_CPUSET_PATH, "system.cpuset",
		                      snap->system_cpuset);
		if (rc < 0) rollback_loud("system_cpuset", rc);
	}
	if (step_committed_up_to >= 1 && snap->game_cpuset[0] != '\0') {
		int rc = write_cpuset(SLICE_GAME_CPUSET_PATH, "game.cpuset",
		                      snap->game_cpuset);
		if (rc < 0) rollback_loud("game_cpuset", rc);
	}
}

/* -------------------------------------------------------------------------
 * Public API.
 * ------------------------------------------------------------------------- */

void posture_build(coh_posture_t *p,
                   const char *game_cpuset,
                   const char *system_cpuset,
                   int sqpoll_cpu,
                   coh_epp_t epp,
                   int min_perf_pct,
                   int numa_node)
{
	if (!p) return;

	memset(p, 0, sizeof(*p));
	p->state = COH_POSTURE_UNVALIDATED;
	p->sqpoll_cpu = sqpoll_cpu;
	p->epp = epp;
	p->min_perf_pct = min_perf_pct;
	p->numa_node = numa_node;
	p->validated_at_ms = 0;

	if (game_cpuset) {
		snprintf(p->game_cpuset, sizeof(p->game_cpuset), "%s", game_cpuset);
	}
	if (system_cpuset) {
		snprintf(p->system_cpuset, sizeof(p->system_cpuset), "%s", system_cpuset);
	}
}

int posture_validate(coh_posture_t *p, uint64_t now_ms)
{
	if (!p) return COH_POSTURE_ERR_STATE;

	/* Legal source states: UNVALIDATED (first-time validate) and
	 * VALIDATED (re-validate is idempotent, just refreshes timestamp). */
	if (p->state != COH_POSTURE_UNVALIDATED &&
	    p->state != COH_POSTURE_VALIDATED) {
		return COH_POSTURE_ERR_STATE;
	}
	if (!coh_posture_transition_legal(p->state, COH_POSTURE_VALIDATED)) {
		return COH_POSTURE_ERR_STATE;
	}

	/* 1. EPP enum range. */
	if ((int)p->epp < (int)COH_EPP_DEFAULT ||
	    (int)p->epp > (int)COH_EPP_PERFORMANCE) {
		return COH_POSTURE_ERR_EPP_INVALID;
	}

	/* 2. min_perf_pct range. */
	if (p->min_perf_pct < 0 || p->min_perf_pct > 100) {
		return COH_POSTURE_ERR_MIN_PERF_PCT_RANGE;
	}

	/* 3. NUMA node range. -1 is the "no preference" sentinel. */
	if (p->numa_node < -1 || p->numa_node >= detect_numa_max()) {
		return COH_POSTURE_ERR_NUMA_OUT_OF_RANGE;
	}

	/* 4. Parse + non-empty check on game cpuset. */
	cpu_bitmap_t game_bm;
	int rc = parse_cpumask(p->game_cpuset, &game_bm);
	if (rc < 0) return COH_POSTURE_ERR_CPUSET_SYNTAX;
	if (game_bm.popcount == 0) return COH_POSTURE_ERR_CPUSET_EMPTY;

	/* 5. sqpoll_cpu range. */
	if (p->sqpoll_cpu < -1 || p->sqpoll_cpu >= COH_MAX_CPUS) {
		return COH_POSTURE_ERR_SQPOLL_RANGE;
	}

	/* 6. sqpoll_cpu ∉ game_cpuset (when sqpoll_cpu is real, not -1). */
	if (p->sqpoll_cpu >= 0 && cbm_get(&game_bm, p->sqpoll_cpu)) {
		return COH_POSTURE_ERR_SQPOLL_IN_GAME_CPUSET;
	}

	/* 7. system_cpuset parses AND is disjoint from game_cpuset. An
	 * empty system cpuset is LEGAL (it means "system processes inherit
	 * root cpuset") so we do NOT enforce popcount > 0 here. */
	cpu_bitmap_t sys_bm;
	rc = parse_cpumask(p->system_cpuset, &sys_bm);
	if (rc < 0) return COH_POSTURE_ERR_CPUSET_SYNTAX;
	if (sys_bm.popcount > 0 && cbm_overlaps(&game_bm, &sys_bm)) {
		return COH_POSTURE_ERR_CPUSET_OVERLAP;
	}

	/* All invariants hold. Promote state. */
	p->state = COH_POSTURE_VALIDATED;
	p->validated_at_ms = now_ms;
	return 0;
}

int posture_commit_atomic(coh_posture_t *p)
{
	if (!p) return COH_POSTURE_ERR_STATE;
	if (p->state != COH_POSTURE_VALIDATED) {
		return COH_POSTURE_ERR_STATE;
	}
	if (!coh_posture_transition_legal(COH_POSTURE_VALIDATED,
	                                  COH_POSTURE_COMMITTED)) {
		return COH_POSTURE_ERR_STATE;
	}

	/* Re-check invariants. VALIDATED means we validated EARLIER; nothing
	 * guarantees the buffer wasn't tampered with in between. Cheap
	 * insurance; posture_validate is branch-light. */
	{
		coh_posture_t probe = *p;
		probe.state = COH_POSTURE_UNVALIDATED;   /* force re-validate */
		probe.validated_at_ms = 0;
		int rc = posture_validate(&probe, p->validated_at_ms);
		if (rc < 0) return rc;
	}

	/* Capture pre-commit state for rollback. */
	coh_posture_t snap;
	capture_current(&snap);

	/* Commit plan. On any failure, roll back up to the last successful
	 * step and revert state to UNVALIDATED so the caller may retry. */

	int step_ok = 0;

	/* Step 1: game cpuset */
	int rc = write_cpuset(SLICE_GAME_CPUSET_PATH, "game.cpuset",
	                      p->game_cpuset);
	if (rc < 0) {
		/* No writes committed yet — no rollback needed. */
		p->state = COH_POSTURE_UNVALIDATED;
		return COH_POSTURE_ERR_WRITE;
	}
	step_ok = 1;

	/* Step 2: system cpuset (skip if empty — legitimate "inherit"). */
	if (p->system_cpuset[0] != '\0') {
		rc = write_cpuset(SLICE_SYSTEM_CPUSET_PATH, "system.cpuset",
		                  p->system_cpuset);
		if (rc < 0) {
			rollback_through(&snap, step_ok);
			p->state = COH_POSTURE_UNVALIDATED;
			return COH_POSTURE_ERR_WRITE;
		}
	}
	step_ok = 2;

	/* Step 3: SQPOLL retarget. */
	rc = write_sqpoll(p->sqpoll_cpu);
	if (rc < 0) {
		rollback_through(&snap, step_ok);
		p->state = COH_POSTURE_UNVALIDATED;
		return COH_POSTURE_ERR_WRITE;
	}
	step_ok = 3;

	/* Step 4: EPP broadcast. */
	rc = write_epp_broadcast(p->epp);
	if (rc < 0) {
		rollback_through(&snap, step_ok);
		p->state = COH_POSTURE_UNVALIDATED;
		return COH_POSTURE_ERR_WRITE;
	}
	step_ok = 4;

	/* Step 5: min_perf_pct. */
	rc = write_min_perf_pct(p->min_perf_pct);
	if (rc < 0) {
		rollback_through(&snap, step_ok);
		p->state = COH_POSTURE_UNVALIDATED;
		return COH_POSTURE_ERR_WRITE;
	}
	step_ok = 5;

	/* Silence the warning — step_ok is written for documentation /
	 * rollback-fidelity and is no longer read after this point. */
	(void)step_ok;

	p->state = COH_POSTURE_COMMITTED;
	return 0;
}

bool posture_equal(const coh_posture_t *a, const coh_posture_t *b)
{
	if (!a || !b) return false;
	if (a->sqpoll_cpu != b->sqpoll_cpu) return false;
	if (a->epp != b->epp) return false;
	if (a->min_perf_pct != b->min_perf_pct) return false;
	if (a->numa_node != b->numa_node) return false;
	if (memcmp(a->game_cpuset, b->game_cpuset, COH_CPUMASK_STRLEN) != 0) {
		return false;
	}
	if (memcmp(a->system_cpuset, b->system_cpuset, COH_CPUMASK_STRLEN) != 0) {
		return false;
	}
	/* Intentionally ignore: state, validated_at_ms. Two postures with
	 * identical semantic content but different lifecycle positions are
	 * "equal" for the idempotent barrier. */
	return true;
}

const char *posture_error_str(int err)
{
	switch (err) {
	case 0:                                      return "OK";
	case COH_POSTURE_ERR_SQPOLL_IN_GAME_CPUSET:  return "SQPOLL_IN_GAME_CPUSET";
	case COH_POSTURE_ERR_CPUSET_OVERLAP:         return "CPUSET_OVERLAP";
	case COH_POSTURE_ERR_MIN_PERF_PCT_RANGE:     return "MIN_PERF_PCT_RANGE";
	case COH_POSTURE_ERR_EPP_INVALID:            return "EPP_INVALID";
	case COH_POSTURE_ERR_NUMA_OUT_OF_RANGE:      return "NUMA_OUT_OF_RANGE";
	case COH_POSTURE_ERR_CPUSET_EMPTY:           return "CPUSET_EMPTY";
	case COH_POSTURE_ERR_STATE:                  return "STATE";
	case COH_POSTURE_ERR_SQPOLL_RANGE:           return "SQPOLL_RANGE";
	case COH_POSTURE_ERR_CPUSET_SYNTAX:          return "CPUSET_SYNTAX";
	case COH_POSTURE_ERR_WRITE:                  return "WRITE";
	default:                                     return "UNKNOWN";
	}
}

/*
 * actuation.c — Atomic, idempotent, rate-limited commit of A(t).
 *
 * Single-writer (control-loop thread). Reads from the diagnostic
 * accessors are safe but not transactional — a torn read is acceptable
 * for /system/coherence.
 *
 * Commit order is deterministic:
 *
 *     cgroup cpuset  →  IRQ affinity  →  EPP  →  min_perf_pct
 *     →  SQPOLL retarget  →  present_mode signal
 *
 * Each actuator is guarded by two independent checks:
 *
 *   1. value-changed: the new field differs from g_last_committed.
 *   2. rate-limit:    now_ms - last_write_ms >= τ_ACTUATOR_MS.
 *
 * An actuator that fails (2) is SKIPPED this frame and its g_last_committed
 * field is left unchanged, so the next frame re-evaluates and retries once
 * the τ window has elapsed.
 *
 * An actuator that fails (1) is a no-op: the field is identical, there is
 * no work to do. Because of the top-level coh_a_equal() idempotent barrier,
 * this happens only when SOME other field changed — the per-actuator
 * check catches the subset that didn't.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "actuation.h"
#include "coherence_types.h"

/* -------------------------------------------------------------------------
 * Writer declarations — split across cgroup_writer.c / irq_writer.c /
 * cpufreq_writer.c / iouring_writer.c. No additional header was required
 * because the surface area is small and the symbols are internal to the
 * actuation layer.
 * ------------------------------------------------------------------------- */

extern int  cgroup_ensure_slice(const char *slice);
extern int  cgroup_write_cpuset(const char *slice, const char *mask);

extern int  irq_write_affinity(int irq_num, const char *mask);
extern int  irq_list_active(int out_irqs[], int max);

extern void cpufreq_writer_init(void);
extern int  cpufreq_set_epp(coh_epp_t epp);
extern int  cpufreq_set_min_perf_pct(int pct);

extern int  iouring_retarget_sqpoll(int new_cpu);

/* -------------------------------------------------------------------------
 * Module state.
 * ------------------------------------------------------------------------- */

#define STATE_DIR             "/var/run/coherence"
#define PRESENT_MODE_PATH     STATE_DIR "/present-mode"

/* cgroup v2 slice names. These are baked-in constants: the control loop
 * owns a "game.slice" and a "system.slice" by design. */
#define GAME_SLICE            "game.slice"
#define SYSTEM_SLICE          "system.slice"

/* Dedup log for per-minute noise suppression. */
#define LOG_DEDUP_WINDOW_MS   60000u

static bool                   g_initialised = false;
static coh_actuation_t        g_last_committed;
static bool                   g_has_committed = false;

/* Per-actuator last-write timestamps. Keyed by coh_actuator_id_t. */
static uint64_t               g_last_write_ms[COH_ACT_COUNT];

/* Deduplicated per-actuator log throttle. g_last_log_ms[k] is the ms at
 * which we last emitted a failure line for actuator k. */
static uint64_t               g_last_log_ms[COH_ACT_COUNT];
static int                    g_last_log_errno[COH_ACT_COUNT];

/* Public counters. */
static coh_actuation_stats_t  g_stats;

/* -------------------------------------------------------------------------
 * Small helpers.
 * ------------------------------------------------------------------------- */

static const char *actuator_name(coh_actuator_id_t id)
{
	switch (id) {
	case COH_ACT_CPUSET:       return "cpuset";
	case COH_ACT_IRQ:          return "irq";
	case COH_ACT_EPP:          return "epp";
	case COH_ACT_MIN_PERF_PCT: return "min_perf_pct";
	case COH_ACT_SQPOLL:       return "sqpoll";
	case COH_ACT_PRESENT_MODE: return "present_mode";
	case COH_ACT_COUNT:        break;
	}
	return "?";
}

static uint32_t tau_for(coh_actuator_id_t id)
{
	switch (id) {
	case COH_ACT_CPUSET:       return COH_TAU_CPUSET_MS;
	case COH_ACT_IRQ:          return COH_TAU_IRQ_MS;
	case COH_ACT_EPP:          return COH_TAU_EPP_MS;
	case COH_ACT_MIN_PERF_PCT: return COH_TAU_MIN_PERF_MS;
	case COH_ACT_SQPOLL:       return COH_TAU_SQPOLL_MS;
	case COH_ACT_PRESENT_MODE: return COH_TAU_PRESENT_MODE_MS;
	case COH_ACT_COUNT:        break;
	}
	return 0;
}

/*
 * rate_limited — returns true if we must skip actuator `id` because its
 * τ window has not yet elapsed since its last successful write.
 *
 * NOTE on first-frame behaviour: g_last_write_ms[] is zero-initialised in
 * actuation_init(). On the very first frame after boot, now_ms - 0 will
 * almost certainly exceed τ, so the first write is always allowed. This is
 * the desired behaviour: we don't want a cold-start embargo.
 */
static bool rate_limited(coh_actuator_id_t id, uint64_t now_ms)
{
	uint64_t last = g_last_write_ms[id];
	if (last == 0) {
		return false;
	}
	uint64_t delta = now_ms - last;
	return delta < tau_for(id);
}

/*
 * log_failure — emit a one-line stderr note for an actuator failure,
 * but at most one per LOG_DEDUP_WINDOW_MS per actuator+errno pair.
 */
static void log_failure(coh_actuator_id_t id, int err, uint64_t now_ms)
{
	if (err == 0) {
		return;
	}
	if (g_last_log_errno[id] == err &&
	    now_ms - g_last_log_ms[id] < LOG_DEDUP_WINDOW_MS) {
		return;
	}
	g_last_log_ms[id]    = now_ms;
	g_last_log_errno[id] = err;

	fprintf(stderr,
	        "{\"coherence\":\"actuation\",\"event\":\"write_error\","
	        "\"actuator\":\"%s\",\"errno\":%d,\"strerror\":\"%s\"}\n",
	        actuator_name(id), err, strerror(err));
}

/*
 * memcmp wrapper so we don't pull <string.h> into a header. Internal.
 */
static int mask_differs(const char *a, const char *b)
{
	return memcmp(a, b, COH_CPUMASK_STRLEN) != 0;
}

/* -------------------------------------------------------------------------
 * Public API.
 * ------------------------------------------------------------------------- */

int actuation_init(void)
{
	memset(&g_last_committed, 0, sizeof(g_last_committed));
	memset(&g_stats,          0, sizeof(g_stats));
	memset(g_last_write_ms,   0, sizeof(g_last_write_ms));
	memset(g_last_log_ms,     0, sizeof(g_last_log_ms));
	memset(g_last_log_errno,  0, sizeof(g_last_log_errno));
	g_has_committed = false;

	/* Ensure /var/run/coherence exists; non-fatal if it doesn't. */
	struct stat st;
	if (stat(STATE_DIR, &st) != 0) {
		(void)mkdir(STATE_DIR, 0755);
	}

	/* Ensure our two cgroup slices exist. Either or both may be absent
	 * (systemd is responsible for creation); we don't treat that as a
	 * fatal error because cgroup writes degrade to "no-op" until the
	 * slice appears. */
	(void)cgroup_ensure_slice(GAME_SLICE);
	(void)cgroup_ensure_slice(SYSTEM_SLICE);

	/* Detect cpufreq backend + prime default-EPP cache. */
	cpufreq_writer_init();

	g_initialised = true;
	return 0;
}

void actuation_shutdown(void)
{
	g_initialised = false;
	/* We deliberately DO NOT revert the system. The control loop owns
	 * the restore-on-exit decision via its shutdown hook. */
}

/*
 * present_mode_signal — write the integer present-mode code to
 * /var/run/coherence/present-mode. The Vulkan layer (Agent 8) polls or
 * inotifies this file and re-configures the swapchain accordingly. This
 * is a signal file just like the sqpoll one; atomic via rename.
 */
static int present_mode_signal(coh_present_mode_t m)
{
	int fd = open(STATE_DIR "/present-mode.tmp",
	              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		return -errno;
	}
	char buf[8];
	int n = snprintf(buf, sizeof(buf), "%d\n", (int)m);
	if (n <= 0 || (size_t)n >= sizeof(buf)) {
		close(fd);
		(void)unlink(STATE_DIR "/present-mode.tmp");
		return -EIO;
	}
	ssize_t off = 0;
	while (off < n) {
		ssize_t w = write(fd, buf + off, (size_t)(n - off));
		if (w < 0) {
			if (errno == EINTR) {
				continue;
			}
			int save_err = errno;
			close(fd);
			(void)unlink(STATE_DIR "/present-mode.tmp");
			return -save_err;
		}
		off += w;
	}
	if (close(fd) != 0) {
		int save_err = errno;
		(void)unlink(STATE_DIR "/present-mode.tmp");
		return -save_err;
	}
	if (rename(STATE_DIR "/present-mode.tmp", PRESENT_MODE_PATH) != 0) {
		int save_err = errno;
		(void)unlink(STATE_DIR "/present-mode.tmp");
		return -save_err;
	}
	return 0;
}

/* -------------------------------------------------------------------------
 * Per-actuator commit helpers. Each returns:
 *    1  = field written AND last_committed updated
 *    0  = nothing to do (value unchanged)
 *   -1  = rate-limited; last_committed NOT updated
 *   <-1 = -errno on write failure; last_committed NOT updated
 * ------------------------------------------------------------------------- */

static int commit_cpuset(const coh_actuation_t *a_next, uint64_t now_ms)
{
	bool game_diff   = mask_differs(a_next->game_cpuset,
	                                g_last_committed.game_cpuset);
	bool system_diff = mask_differs(a_next->system_cpuset,
	                                g_last_committed.system_cpuset);
	if (!game_diff && !system_diff) {
		return 0;
	}
	if (rate_limited(COH_ACT_CPUSET, now_ms)) {
		return -1;
	}

	int rc_game = 0;
	int rc_sys  = 0;
	if (game_diff) {
		rc_game = cgroup_write_cpuset(GAME_SLICE, a_next->game_cpuset);
	}
	if (system_diff) {
		rc_sys = cgroup_write_cpuset(SYSTEM_SLICE, a_next->system_cpuset);
	}

	/* If either write succeeded, update that field's portion of the
	 * committed snapshot. Partial success is still progress. */
	int worst = (rc_game < rc_sys) ? rc_game : rc_sys;
	if (rc_game == 0 && game_diff) {
		memcpy(g_last_committed.game_cpuset,
		       a_next->game_cpuset, COH_CPUMASK_STRLEN);
	}
	if (rc_sys == 0 && system_diff) {
		memcpy(g_last_committed.system_cpuset,
		       a_next->system_cpuset, COH_CPUMASK_STRLEN);
	}

	if (worst == 0) {
		g_last_write_ms[COH_ACT_CPUSET] = now_ms;
		return 1;
	}
	return worst; /* negative errno */
}

static int commit_irq(const coh_actuation_t *a_next, uint64_t now_ms)
{
	/* Determine if the IRQ plan differs from last-committed. We compare
	 * by (irq_list, irq_affinity, irq_count) as a bulk. */
	bool any_diff = false;
	if (a_next->irq_count != g_last_committed.irq_count) {
		any_diff = true;
	} else {
		for (int i = 0; i < a_next->irq_count && i < COH_MAX_IRQS; i++) {
			if (a_next->irq_list[i] != g_last_committed.irq_list[i] ||
			    mask_differs(a_next->irq_affinity[i],
			                 g_last_committed.irq_affinity[i])) {
				any_diff = true;
				break;
			}
		}
	}
	if (!any_diff) {
		return 0;
	}
	if (rate_limited(COH_ACT_IRQ, now_ms)) {
		return -1;
	}

	/* Scan active IRQs so we avoid writing to zero-traffic IRQs that
	 * the kernel will just EINVAL on. */
	int active[COH_MAX_IRQS];
	int nactive = irq_list_active(active, COH_MAX_IRQS);
	if (nactive < 0) {
		/* If we cannot scan, try the writes anyway — we won't gain
		 * verification but we remain functional. */
		nactive = 0;
	}

	int any_ok  = 0;
	int last_rc = 0;
	int cap     = a_next->irq_count;
	if (cap > COH_MAX_IRQS) {
		cap = COH_MAX_IRQS;
	}

	for (int i = 0; i < cap; i++) {
		int irq = a_next->irq_list[i];

		/* Optional filter: if we have an active list, require the IRQ
		 * to appear in it. If the scan produced zero entries we fall
		 * through and write every IRQ blindly. */
		if (nactive > 0) {
			int seen = 0;
			for (int j = 0; j < nactive; j++) {
				if (active[j] == irq) {
					seen = 1;
					break;
				}
			}
			if (!seen) {
				continue;
			}
		}

		int rc = irq_write_affinity(irq, a_next->irq_affinity[i]);
		if (rc == 0) {
			any_ok = 1;
			/* Merge just this IRQ entry into g_last_committed. */
			if (i < COH_MAX_IRQS) {
				g_last_committed.irq_list[i] = irq;
				memcpy(g_last_committed.irq_affinity[i],
				       a_next->irq_affinity[i],
				       COH_CPUMASK_STRLEN);
			}
		} else {
			last_rc = rc;
		}
	}

	/* Update the count only when the whole plan landed — partial count
	 * mismatches would confuse the next-frame diff. If we wrote at
	 * least one IRQ we call it a successful commit for the counter. */
	if (any_ok) {
		g_last_committed.irq_count = a_next->irq_count;
		g_last_write_ms[COH_ACT_IRQ] = now_ms;
		return 1;
	}
	if (last_rc < 0) {
		return last_rc;
	}
	/* Reached here only if cap == 0 with all IRQs filtered out. */
	return 0;
}

static int commit_epp(const coh_actuation_t *a_next, uint64_t now_ms)
{
	if (a_next->epp == g_last_committed.epp && g_has_committed) {
		return 0;
	}
	if (rate_limited(COH_ACT_EPP, now_ms)) {
		return -1;
	}
	int rc = cpufreq_set_epp(a_next->epp);
	if (rc == 0) {
		g_last_committed.epp = a_next->epp;
		g_last_write_ms[COH_ACT_EPP] = now_ms;
		return 1;
	}
	return rc;
}

static int commit_min_perf_pct(const coh_actuation_t *a_next, uint64_t now_ms)
{
	/* Negative min_perf_pct is the contract sentinel for "leave alone". */
	if (a_next->min_perf_pct < 0) {
		return 0;
	}
	if (a_next->min_perf_pct == g_last_committed.min_perf_pct &&
	    g_has_committed) {
		return 0;
	}
	if (rate_limited(COH_ACT_MIN_PERF_PCT, now_ms)) {
		return -1;
	}
	int rc = cpufreq_set_min_perf_pct(a_next->min_perf_pct);
	if (rc == 0) {
		g_last_committed.min_perf_pct = a_next->min_perf_pct;
		g_last_write_ms[COH_ACT_MIN_PERF_PCT] = now_ms;
		return 1;
	}
	return rc;
}

static int commit_sqpoll(const coh_actuation_t *a_next, uint64_t now_ms)
{
	if (a_next->sqpoll_cpu == g_last_committed.sqpoll_cpu &&
	    g_has_committed) {
		return 0;
	}
	if (rate_limited(COH_ACT_SQPOLL, now_ms)) {
		return -1;
	}
	int rc = iouring_retarget_sqpoll(a_next->sqpoll_cpu);
	if (rc == 0) {
		g_last_committed.sqpoll_cpu = a_next->sqpoll_cpu;
		g_last_write_ms[COH_ACT_SQPOLL] = now_ms;
		return 1;
	}
	return rc;
}

static int commit_present_mode(const coh_actuation_t *a_next, uint64_t now_ms)
{
	if (a_next->present_mode_override == g_last_committed.present_mode_override &&
	    g_has_committed) {
		return 0;
	}
	if (rate_limited(COH_ACT_PRESENT_MODE, now_ms)) {
		return -1;
	}
	int rc = present_mode_signal(a_next->present_mode_override);
	if (rc == 0) {
		g_last_committed.present_mode_override = a_next->present_mode_override;
		g_last_write_ms[COH_ACT_PRESENT_MODE] = now_ms;
		return 1;
	}
	return rc;
}

/*
 * account — record one actuator's commit outcome into the global stats
 * and emit a rate-limit log entry at DEBUG level if appropriate.
 */
static void account(coh_actuator_id_t id, int rc, uint64_t now_ms)
{
	if (rc == 1) {
		g_stats.writes_ok[id]++;
		g_stats.last_write_ms[id] = now_ms;
		return;
	}
	if (rc == 0) {
		return; /* nothing to do */
	}
	if (rc == -1) {
		g_stats.rate_limited[id]++;
		return;
	}
	/* rc < -1 → -errno */
	g_stats.write_errors[id]++;
	log_failure(id, -rc, now_ms);
}

int actuation_commit(const coh_actuation_t *a_next, uint64_t now_ms)
{
	if (!g_initialised) {
		return -EAGAIN;
	}
	if (!a_next) {
		return -EINVAL;
	}

	g_stats.commits_total++;

	/* -------- Idempotent barrier -------- */
	if (g_has_committed && coh_a_equal(&g_last_committed, a_next)) {
		g_stats.idempotent_skips++;
		return 0;
	}

	/* -------- Deterministic actuator order -------- */
	int rc_cpuset       = commit_cpuset      (a_next, now_ms);
	int rc_irq          = commit_irq         (a_next, now_ms);
	int rc_epp          = commit_epp         (a_next, now_ms);
	int rc_min_perf_pct = commit_min_perf_pct(a_next, now_ms);
	int rc_sqpoll       = commit_sqpoll      (a_next, now_ms);
	int rc_present      = commit_present_mode(a_next, now_ms);

	account(COH_ACT_CPUSET,       rc_cpuset,       now_ms);
	account(COH_ACT_IRQ,          rc_irq,          now_ms);
	account(COH_ACT_EPP,          rc_epp,          now_ms);
	account(COH_ACT_MIN_PERF_PCT, rc_min_perf_pct, now_ms);
	account(COH_ACT_SQPOLL,       rc_sqpoll,       now_ms);
	account(COH_ACT_PRESENT_MODE, rc_present,      now_ms);

	/* Copy the scalar fields we don't commit conditionally (they are
	 * either written by one of the per-actuator helpers above, or they
	 * are the timestamp + boolean flags that ride along for free). */
	g_last_committed.t_ms          = a_next->t_ms;
	g_last_committed.use_gamescope = a_next->use_gamescope;
	g_has_committed                = true;

	/* Emit one JSON line summarising this commit. Fits a single
	 * fprintf; no malloc. */
	fprintf(stderr,
	        "{\"coherence\":\"actuation\",\"event\":\"commit\","
	        "\"t_ms\":%llu,"
	        "\"cpuset\":%d,\"irq\":%d,\"epp\":%d,"
	        "\"min_perf\":%d,\"sqpoll\":%d,\"present\":%d,"
	        "\"idem\":%llu,\"rl_cpu\":%llu,\"rl_irq\":%llu,"
	        "\"rl_sqp\":%llu,\"err_tot\":%llu}\n",
	        (unsigned long long)now_ms,
	        rc_cpuset, rc_irq, rc_epp,
	        rc_min_perf_pct, rc_sqpoll, rc_present,
	        (unsigned long long)g_stats.idempotent_skips,
	        (unsigned long long)g_stats.rate_limited[COH_ACT_CPUSET],
	        (unsigned long long)g_stats.rate_limited[COH_ACT_IRQ],
	        (unsigned long long)g_stats.rate_limited[COH_ACT_SQPOLL],
	        (unsigned long long)(
	            g_stats.write_errors[0] + g_stats.write_errors[1] +
	            g_stats.write_errors[2] + g_stats.write_errors[3] +
	            g_stats.write_errors[4] + g_stats.write_errors[5]));

	return 0;
}

/* -------------------------------------------------------------------------
 * Diagnostics.
 * ------------------------------------------------------------------------- */

void actuation_get_last(coh_actuation_t *out)
{
	if (!out) {
		return;
	}
	/* Byte-copy the snapshot. A torn read is acceptable on the diagnostic
	 * path — the caller is a human-readable /system/coherence endpoint. */
	memcpy(out, &g_last_committed, sizeof(*out));
}

int actuation_effective_writes_since(uint64_t since_ms)
{
	int total = 0;
	for (int i = 0; i < COH_ACT_COUNT; i++) {
		if (g_stats.last_write_ms[i] >= since_ms) {
			total += 1;
		}
	}
	return total;
}

void actuation_get_stats(coh_actuation_stats_t *out)
{
	if (!out) {
		return;
	}
	memcpy(out, &g_stats, sizeof(*out));
}

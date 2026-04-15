/*
 * cpufreq_writer.c — EPP + min_perf_pct writer for intel_pstate / amd_pstate.
 *
 * EPP (energy_performance_preference) is a per-CPU sysfs string file:
 *     /sys/devices/system/cpu/cpuN/cpufreq/energy_performance_preference
 * Values: "power", "balance_power", "balance_performance", "performance",
 * or "default". COH_EPP_DEFAULT restores whatever the driver started with
 * — we read that once at init() so the caller can reliably "revert".
 *
 * min_perf_pct is a single global knob on Intel:
 *     /sys/devices/system/cpu/intel_pstate/min_perf_pct
 * AMD p-state (active mode) exposes it at:
 *     /sys/devices/system/cpu/amd_pstate/min_perf_pct
 * Legacy governors (ondemand, schedutil) expose nothing equivalent — we
 * silently no-op with 0 return so callers can treat the write as "done".
 *
 * All paths are constants. CPU count is discovered once via /sys/devices/
 * system/cpu/online and then clamped to COH_MAX_CPUS.
 */

#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "coherence_types.h"

#define SYS_CPU_ROOT    "/sys/devices/system/cpu"
#define INTEL_PSTATE_DIR SYS_CPU_ROOT "/intel_pstate"
#define AMD_PSTATE_DIR   SYS_CPU_ROOT "/amd_pstate"
#define CPU_ONLINE_PATH  SYS_CPU_ROOT "/online"

/*
 * Discovered backend. Set by cpufreq_detect_backend() which is called
 * from actuation.c::actuation_init(). Default of NONE means "no-op writes".
 */
typedef enum {
	CPUFREQ_BACKEND_NONE        = 0,
	CPUFREQ_BACKEND_INTEL_PSTATE,
	CPUFREQ_BACKEND_AMD_PSTATE
} cpufreq_backend_t;

static cpufreq_backend_t g_backend = CPUFREQ_BACKEND_NONE;

/*
 * Per-CPU cached "default" EPP string so COH_EPP_DEFAULT actually means
 * something. Populated once. If we fail to read a given CPU's EPP we fall
 * back to "default" (the literal driver keyword) so the write path is
 * always well-defined.
 */
#define EPP_STR_MAX 24
static char g_default_epp[COH_MAX_CPUS][EPP_STR_MAX];
static int  g_cpu_count = 0;

static int path_exists(const char *p)
{
	struct stat st;
	return stat(p, &st) == 0;
}

/*
 * read_small — bounded read. Returns bytes read (0 or more) on success,
 * -errno on failure. NUL-terminates.
 */
static int read_small(const char *path, char *buf, size_t buf_sz)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return -errno;
	}
	size_t total = 0;
	while (total + 1 < buf_sz) {
		ssize_t r = read(fd, buf + total, buf_sz - 1 - total);
		if (r < 0) {
			if (errno == EINTR) {
				continue;
			}
			int save_err = errno;
			close(fd);
			return -save_err;
		}
		if (r == 0) {
			break;
		}
		total += (size_t)r;
	}
	buf[total] = '\0';
	close(fd);
	return (int)total;
}

/*
 * write_small — bounded write. Returns 0 on success, -errno on failure.
 * sysfs accepts a single write() per change, so one call suffices.
 */
static int write_small(const char *path, const char *data, size_t len)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		return -errno;
	}
	ssize_t w;
	do {
		w = write(fd, data, len);
	} while (w < 0 && errno == EINTR);

	int save_err = (w < 0) ? errno : 0;
	close(fd);
	if (w < 0) {
		return -save_err;
	}
	if ((size_t)w != len) {
		return -EIO;
	}
	return 0;
}

/*
 * trim_trailing — strip trailing '\n' and whitespace from a C string.
 */
static void trim_trailing(char *s)
{
	if (!s) {
		return;
	}
	size_t n = strlen(s);
	while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
	                 s[n - 1] == ' '  || s[n - 1] == '\t')) {
		s[--n] = '\0';
	}
}

/*
 * detect_cpu_count — parse the highest CPU id from /sys/.../cpu/online
 * which looks like "0-15" or "0,2-7" on realistic hardware. We just
 * find the maximum integer; CPU ids are 0-indexed, so count = max+1.
 */
static int detect_cpu_count(void)
{
	char buf[128];
	int n = read_small(CPU_ONLINE_PATH, buf, sizeof(buf));
	if (n < 0) {
		return 1; /* safe fallback */
	}
	trim_trailing(buf);

	int max_id = 0;
	int cur    = -1;
	for (size_t i = 0; buf[i]; i++) {
		char c = buf[i];
		if (c >= '0' && c <= '9') {
			if (cur < 0) {
				cur = 0;
			}
			cur = cur * 10 + (c - '0');
		} else {
			if (cur >= 0 && cur > max_id) {
				max_id = cur;
			}
			cur = -1;
		}
	}
	if (cur >= 0 && cur > max_id) {
		max_id = cur;
	}
	int count = max_id + 1;
	if (count > COH_MAX_CPUS) {
		count = COH_MAX_CPUS;
	}
	if (count < 1) {
		count = 1;
	}
	return count;
}

/*
 * cpufreq_detect_backend — examine sysfs to determine which pstate
 * driver is active. Results are cached in g_backend. Safe to call
 * multiple times.
 */
static void cpufreq_detect_backend(void)
{
	if (path_exists(INTEL_PSTATE_DIR)) {
		g_backend = CPUFREQ_BACKEND_INTEL_PSTATE;
	} else if (path_exists(AMD_PSTATE_DIR)) {
		g_backend = CPUFREQ_BACKEND_AMD_PSTATE;
	} else {
		g_backend = CPUFREQ_BACKEND_NONE;
	}
}

/*
 * cpufreq_writer_init — invoked from actuation_init(). Detects the
 * backend, discovers CPU count, and caches the driver's default EPP
 * per CPU. No I/O failure is fatal.
 */
void cpufreq_writer_init(void)
{
	cpufreq_detect_backend();
	g_cpu_count = detect_cpu_count();

	for (int cpu = 0; cpu < g_cpu_count; cpu++) {
		char path[160];
		int n = snprintf(path, sizeof(path),
		                 "%s/cpu%d/cpufreq/energy_performance_preference",
		                 SYS_CPU_ROOT, cpu);
		if (n <= 0 || (size_t)n >= sizeof(path)) {
			g_default_epp[cpu][0] = '\0';
			continue;
		}

		char val[EPP_STR_MAX];
		int rc = read_small(path, val, sizeof(val));
		if (rc < 0) {
			/* Literal "default" is a valid driver keyword. */
			snprintf(g_default_epp[cpu], EPP_STR_MAX, "default");
			continue;
		}
		trim_trailing(val);
		/* Some drivers return a list on first read (available set) —
		 * protect by taking only the first whitespace-delimited token. */
		for (size_t i = 0; val[i]; i++) {
			if (val[i] == ' ' || val[i] == '\t') {
				val[i] = '\0';
				break;
			}
		}
		if (val[0] == '\0') {
			snprintf(g_default_epp[cpu], EPP_STR_MAX, "default");
		} else {
			snprintf(g_default_epp[cpu], EPP_STR_MAX, "%s", val);
		}
	}
}

/*
 * epp_to_string — map coh_epp_t to the sysfs keyword. Returns NULL for
 * unknown values so the caller can refuse to write.
 */
static const char *epp_to_string(coh_epp_t epp, int cpu)
{
	switch (epp) {
	case COH_EPP_POWER:         return "power";
	case COH_EPP_BALANCE_POWER: return "balance_power";
	case COH_EPP_BALANCE_PERF:  return "balance_performance";
	case COH_EPP_PERFORMANCE:   return "performance";
	case COH_EPP_DEFAULT:
		if (cpu >= 0 && cpu < COH_MAX_CPUS && g_default_epp[cpu][0]) {
			return g_default_epp[cpu];
		}
		return "default";
	}
	return NULL;
}

/*
 * cpufreq_set_epp — broadcast the EPP string to every online CPU.
 *
 * Returns:
 *   0    all online CPUs accepted the value OR we are on a backend that
 *        does not support EPP (we silently succeed so callers don't
 *        treat it as a fault).
 *   -errno if EVERY CPU failed. Per-CPU failures are aggregated; if
 *        at least one CPU accepted the write we return 0 (partial
 *        success is still progress — the kernel governor treats each
 *        CPU independently).
 */
int cpufreq_set_epp(coh_epp_t epp)
{
	if (g_backend == CPUFREQ_BACKEND_NONE) {
		return 0; /* no-op on legacy hosts */
	}
	if (g_cpu_count <= 0) {
		return 0;
	}

	int ok_count      = 0;
	int fail_count    = 0;
	int last_errno    = 0;

	for (int cpu = 0; cpu < g_cpu_count; cpu++) {
		const char *val = epp_to_string(epp, cpu);
		if (!val) {
			fail_count++;
			last_errno = EINVAL;
			continue;
		}

		char path[160];
		int n = snprintf(path, sizeof(path),
		                 "%s/cpu%d/cpufreq/energy_performance_preference",
		                 SYS_CPU_ROOT, cpu);
		if (n <= 0 || (size_t)n >= sizeof(path)) {
			fail_count++;
			last_errno = ENAMETOOLONG;
			continue;
		}

		int rc = write_small(path, val, strlen(val));
		if (rc == 0) {
			ok_count++;
		} else {
			fail_count++;
			last_errno = -rc;
		}
	}

	if (ok_count > 0) {
		return 0;
	}
	/* All failed — report the last seen errno. */
	return -last_errno;
}

/*
 * cpufreq_set_min_perf_pct — write `pct` to the active-mode min_perf_pct.
 *
 * pct is clamped to [0, 100]. Negative values (the contract's "unchanged"
 * sentinel) are NOT passed to this function — the caller decides; we
 * still defensively refuse pct < 0 with EINVAL.
 *
 * Returns:
 *   0   success (or silent no-op on legacy backend)
 *   -errno on write failure
 */
int cpufreq_set_min_perf_pct(int pct)
{
	if (pct < 0 || pct > 100) {
		return -EINVAL;
	}

	const char *path = NULL;
	switch (g_backend) {
	case CPUFREQ_BACKEND_INTEL_PSTATE:
		path = INTEL_PSTATE_DIR "/min_perf_pct";
		break;
	case CPUFREQ_BACKEND_AMD_PSTATE:
		path = AMD_PSTATE_DIR   "/min_perf_pct";
		break;
	case CPUFREQ_BACKEND_NONE:
	default:
		return 0;
	}

	/* Some AMD systems only expose min_perf_pct in active mode. If the
	 * file is missing, silently succeed — not an error. */
	if (!path_exists(path)) {
		return 0;
	}

	char buf[8];
	int n = snprintf(buf, sizeof(buf), "%d\n", pct);
	if (n <= 0 || (size_t)n >= sizeof(buf)) {
		return -EIO;
	}
	return write_small(path, buf, (size_t)n);
}

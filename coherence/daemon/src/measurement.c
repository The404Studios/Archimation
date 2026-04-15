/*
 * measurement.c — Coherence measurement layer.
 *
 * Produces one fully-populated coh_metrics_t per CONTROL_FRAME (100 ms).
 * See measurement.h for the public contract.
 *
 * Hot-path rules:
 *   1. NO malloc. Every buffer is static or pre-allocated in init.
 *   2. NO seek; every /proc/sys read uses pread(offset=0) on a long-lived fd.
 *   3. NO sleep. Any blocking source (AI daemon HTTP) has short timeouts and
 *      short-circuits on cached data.
 *   4. Partial reads on /proc are handled in the slurp helpers (looped pread).
 *   5. A single-source failure updates source_health and keeps last-known
 *      values; the struct is ALWAYS fully populated.
 *
 * Threading:
 *   Sampling is called from the frame scheduler thread. The Vulkan setters
 *   are called from the Vulkan layer (typically a distinct thread). We use
 *   a classic seqlock (atomic release/acquire on a seq counter) to publish
 *   and read the triple (ft_mean_ms, ft_var_ms2, present_mode) atomically.
 *
 *   stdatomic.h is a C11 header — available under POSIX-C11 per the spec.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "coherence_types.h"
#include "measurement.h"
#include "proc_reader_priv.h"
#include "sysfs_reader_priv.h"
#include "iouring_stats_priv.h"

/* ===== Sizing & tunables ===== */

#define PROC_STAT_BUF        (16u * 1024u)   /* ~5 KB typical @64 CPUs */
#define PROC_INT_BUF         (16u * 1024u)   /* spec-capped */
#define PROC_SCHED_BUF       ( 4u * 1024u)
#define SYSFS_LINE_BUF       128
#define THERMAL_ZONE_MAX     64              /* scan zone0..zone63 at most */

#define PATH_CPU_FREQ        "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq"
#define PATH_PROC_STAT       "/proc/stat"
#define PATH_PROC_INT        "/proc/interrupts"
#define PATH_PROC_SCHED      "/proc/schedstat"
#define PATH_THERMAL_ZONE    "/sys/class/thermal/thermal_zone%d/temp"
#define PATH_DRM_CARD0       "/sys/class/drm/card0"
#define PATH_DRM_CARDN       "/sys/class/drm/card%d"
#define VK_SHM_PATH          "/dev/shm/coherence_vk"

/* Source health bits (mirror measurement.h doc). */
#define HEALTH_PROC_STAT     (1u << 0)
#define HEALTH_CPUFREQ       (1u << 1)
#define HEALTH_THERMAL       (1u << 2)
#define HEALTH_INTERRUPTS    (1u << 3)
#define HEALTH_SCHEDSTAT     (1u << 4)
#define HEALTH_IOURING       (1u << 5)
#define HEALTH_VULKAN        (1u << 6)
#define HEALTH_GPU_PRESENT   (1u << 7)

/* ===== Vulkan shared-memory layout (Agent 8 contract) =====
 *
 * sequence uses a classic seqlock: writer increments to odd before writing
 * fields, then increments to even after. Reader retries if it ever sees odd
 * or a changed value between two reads.
 */
struct vk_shared {
	uint32_t sequence;        /* atomic via aligned u32 */
	uint32_t present_mode;    /* coh_present_mode_t */
	double   ft_mean_ms;
	double   ft_var_ms2;
	uint64_t last_update_ms;
};

/* ===== Static state ===== */

static struct {
	/* Lifecycle. */
	int      inited;

	/* Cached FDs. -1 means "not open / source failed". */
	int      fd_proc_stat;
	int      fd_proc_int;
	int      fd_proc_sched;
	int      fd_thermal;                 /* first viable zone */
	int      fd_cpu_freq[COH_MAX_CPUS];
	int      has_drm;                    /* 0/1 */

	/* Counts. */
	int      cpu_count;

	/* Delta state (previous sample). */
	int      have_prev;
	uint64_t prev_t_ms;
	pr_cpu_sample_t prev_cpus[COH_MAX_CPUS];
	uint64_t prev_ctxt;
	uint64_t prev_migrations;
	uint64_t prev_irq_per_cpu[COH_MAX_CPUS];

	/* Last-known output values (carry-forward on source failure). */
	coh_metrics_t last;

	/* Source health (1 = healthy). */
	uint32_t source_health;

	/* "logged once" bits for each source so we don't spam stderr. */
	uint32_t logged_failure;

	/* Vulkan shared memory. */
	struct vk_shared *vk_shm;        /* mmap'd, or NULL if unavailable */
	int              vk_shm_fd;

	/* Fallback / in-process Vulkan state, published by the setters if shm
	 * is not being updated externally. Also used as the "initial defaults"
	 * (60 Hz = 16.67 ms, FIFO). */
	_Atomic uint32_t vk_fallback_seq;
	double           vk_fallback_ft_mean;
	double           vk_fallback_ft_var;
	uint32_t         vk_fallback_present_mode;

	char             game_slice_path[256];
} g;

/* ===== Utility ===== */

static uint64_t now_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static void log_once(uint32_t bit, const char *msg)
{
	if (g.logged_failure & bit)
		return;
	g.logged_failure |= bit;
	/* Use write(2) to avoid pulling locale from fprintf on hot path. */
	(void)!write(2, msg, strlen(msg));
}

/* Set / clear a health bit. */
static void health_set(uint32_t bit, int ok)
{
	if (ok) g.source_health |=  bit;
	else    g.source_health &= ~bit;
}

/* ===== Vulkan shared-memory open (best-effort) ===== */

static void vk_shm_try_open(void)
{
	g.vk_shm_fd = -1;
	g.vk_shm    = NULL;

	int fd = open(VK_SHM_PATH, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		/* Not an error — no game running yet. */
		return;
	}
	struct stat st;
	if (fstat(fd, &st) != 0 || (size_t)st.st_size < sizeof(struct vk_shared)) {
		close(fd);
		return;
	}
	void *p = mmap(NULL, sizeof(struct vk_shared), PROT_READ,
	               MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		close(fd);
		return;
	}
	g.vk_shm_fd = fd;
	g.vk_shm    = (struct vk_shared *)p;
}

static void vk_shm_close(void)
{
	if (g.vk_shm) {
		munmap((void *)g.vk_shm, sizeof(struct vk_shared));
		g.vk_shm = NULL;
	}
	if (g.vk_shm_fd >= 0) {
		close(g.vk_shm_fd);
		g.vk_shm_fd = -1;
	}
}

/* ===== Vulkan setters (publish via atomic seq-counter) ===== */

void measurement_vulkan_set_frametime(double mean_ms, double var_ms2)
{
	/* Acquire odd (writing). */
	uint32_t s = atomic_load_explicit(&g.vk_fallback_seq, memory_order_relaxed);
	atomic_store_explicit(&g.vk_fallback_seq, s | 1u, memory_order_release);

	g.vk_fallback_ft_mean = mean_ms;
	g.vk_fallback_ft_var  = var_ms2;

	atomic_store_explicit(&g.vk_fallback_seq, (s | 1u) + 1u, memory_order_release);
}

void measurement_vulkan_set_present_mode(coh_present_mode_t mode)
{
	uint32_t s = atomic_load_explicit(&g.vk_fallback_seq, memory_order_relaxed);
	atomic_store_explicit(&g.vk_fallback_seq, s | 1u, memory_order_release);

	g.vk_fallback_present_mode = (uint32_t)mode;

	atomic_store_explicit(&g.vk_fallback_seq, (s | 1u) + 1u, memory_order_release);
}

/*
 * Read Vulkan state with a seqlock retry loop. Returns 1 if a stable
 * snapshot was obtained, 0 on persistent tear (caller uses defaults).
 *
 * Prefers /dev/shm if present; otherwise falls back to the in-process
 * counters populated by the setters.
 */
static int vk_read(double *mean, double *var, uint32_t *mode_out, uint64_t *ts_out)
{
	if (g.vk_shm) {
		for (int i = 0; i < 4; i++) {
			uint32_t s0 = __atomic_load_n(&g.vk_shm->sequence, __ATOMIC_ACQUIRE);
			if (s0 & 1u)
				continue;
			double m  = g.vk_shm->ft_mean_ms;
			double v  = g.vk_shm->ft_var_ms2;
			uint32_t pm = g.vk_shm->present_mode;
			uint64_t upd = g.vk_shm->last_update_ms;
			uint32_t s1 = __atomic_load_n(&g.vk_shm->sequence, __ATOMIC_ACQUIRE);
			if (s0 == s1) {
				*mean = m;
				*var  = v;
				*mode_out = pm;
				*ts_out   = upd;
				return 1;
			}
		}
		/* Tear after 4 retries: fall through to in-process fallback. */
	}

	for (int i = 0; i < 4; i++) {
		uint32_t s0 = atomic_load_explicit(&g.vk_fallback_seq, memory_order_acquire);
		if (s0 & 1u)
			continue;
		double m  = g.vk_fallback_ft_mean;
		double v  = g.vk_fallback_ft_var;
		uint32_t pm = g.vk_fallback_present_mode;
		uint32_t s1 = atomic_load_explicit(&g.vk_fallback_seq, memory_order_acquire);
		if (s0 == s1) {
			*mean = m;
			*var  = v;
			*mode_out = pm;
			*ts_out   = 0;
			/* If we never got a setter call, seq will be 0. Signal that
			 * by returning 0 so caller can flag VULKAN health as stale.
			 * Still populate defaults so the struct stays consistent. */
			return (s0 != 0);
		}
	}
	return 0;
}

/* ===== cpufreq per-CPU fd cache ===== */

static void open_cpufreq_fds(void)
{
	char path[sizeof(PATH_CPU_FREQ) + 16];
	for (int i = 0; i < g.cpu_count && i < COH_MAX_CPUS; i++) {
		snprintf(path, sizeof(path), PATH_CPU_FREQ, i);
		int fd = sf_open_scalar(path);
		g.fd_cpu_freq[i] = (fd >= 0) ? fd : -1;
	}
}

/* ===== GPU presence probe (cheap; done once in init) ===== */

static int detect_gpu_present(void)
{
	char path[64];
	for (int i = 0; i < 8; i++) {
		snprintf(path, sizeof(path), PATH_DRM_CARDN, i);
		int r = sf_path_exists(path);
		if (r == 1)
			return 1;
	}
	return 0;
}

/* ===== Thermal zone probe (prefer "x86_pkg_temp" etc.) ===== */

/*
 * Pick the first thermal zone whose temp reads as a plausible positive
 * milli-degC. We intentionally skip "0" readings (sensor not ready).
 * Called once in init; fd cached thereafter.
 */
static int open_first_viable_thermal_zone(void)
{
	char path[sizeof(PATH_THERMAL_ZONE) + 16];
	char buf[SYSFS_LINE_BUF];
	for (int i = 0; i < THERMAL_ZONE_MAX; i++) {
		snprintf(path, sizeof(path), PATH_THERMAL_ZONE, i);
		int fd = sf_open_scalar(path);
		if (fd < 0)
			continue;
		ssize_t n = sf_pread_line(fd, buf, sizeof(buf));
		if (n <= 0) {
			close(fd);
			continue;
		}
		int64_t milli = 0;
		if (sf_parse_i64(buf, (size_t)n, &milli) == 0 && milli > 0) {
			return fd;
		}
		close(fd);
	}
	return -1;
}

/* ===== Public API: init / shutdown / health ===== */

int measurement_init(const char *game_slice_path)
{
	if (g.inited)
		return 0;

	memset(&g, 0, sizeof(g));
	g.fd_proc_stat  = -1;
	g.fd_proc_int   = -1;
	g.fd_proc_sched = -1;
	g.fd_thermal    = -1;
	for (int i = 0; i < COH_MAX_CPUS; i++)
		g.fd_cpu_freq[i] = -1;

	if (game_slice_path) {
		strncpy(g.game_slice_path, game_slice_path,
		        sizeof(g.game_slice_path) - 1);
	}

	/* CPU count (sysconf is cheap and allowed — POSIX, not a glibc ext). */
	long nproc = sysconf(_SC_NPROCESSORS_ONLN);
	if (nproc < 1) nproc = 1;
	if (nproc > COH_MAX_CPUS) nproc = COH_MAX_CPUS;
	g.cpu_count = (int)nproc;

	/* Open long-lived FDs. Failures are non-fatal; health bits reflect them. */
	g.fd_proc_stat  = sf_open_scalar(PATH_PROC_STAT);
	if (g.fd_proc_stat < 0)
		log_once(HEALTH_PROC_STAT,
		         "measurement: open /proc/stat failed (cpu_util/ctxt unavailable)\n");
	else
		health_set(HEALTH_PROC_STAT, 1);

	g.fd_proc_int = sf_open_scalar(PATH_PROC_INT);
	if (g.fd_proc_int < 0)
		log_once(HEALTH_INTERRUPTS,
		         "measurement: open /proc/interrupts failed (irq_rate unavailable)\n");
	else
		health_set(HEALTH_INTERRUPTS, 1);

	g.fd_proc_sched = sf_open_scalar(PATH_PROC_SCHED);
	if (g.fd_proc_sched < 0)
		log_once(HEALTH_SCHEDSTAT,
		         "measurement: open /proc/schedstat failed (migration_rate unavailable)\n");
	else
		health_set(HEALTH_SCHEDSTAT, 1);

	g.fd_thermal = open_first_viable_thermal_zone();
	if (g.fd_thermal < 0)
		log_once(HEALTH_THERMAL,
		         "measurement: no viable thermal_zone (will try AI daemon only)\n");
	else
		health_set(HEALTH_THERMAL, 1);

	open_cpufreq_fds();
	{
		int any = 0;
		for (int i = 0; i < g.cpu_count; i++)
			if (g.fd_cpu_freq[i] >= 0) { any = 1; break; }
		if (!any)
			log_once(HEALTH_CPUFREQ,
			         "measurement: no cpufreq sysfs (cpu_freq_khz unavailable)\n");
		else
			health_set(HEALTH_CPUFREQ, 1);
	}

	g.has_drm = detect_gpu_present();
	health_set(HEALTH_GPU_PRESENT, g.has_drm);

	/* Vulkan shared-mem is optional; in-process setter is the primary path. */
	vk_shm_try_open();

	/* Sensible defaults for Vulkan (60 Hz assumption, FIFO). */
	g.vk_fallback_ft_mean = 16.666667;
	g.vk_fallback_ft_var  = 0.0;
	g.vk_fallback_present_mode = (uint32_t)COH_PRESENT_FIFO;
	/* Seq stays 0 so readers know "never set by anyone external yet". */

	/* Bootstrap last-known output to defaults. */
	g.last.ft_mean_ms = g.vk_fallback_ft_mean;
	g.last.present_mode_actual = COH_PRESENT_FIFO;
	g.last.cpu_count = g.cpu_count;

	/* Prime the delta reference by running one throwaway sample; without
	 * this the very first sample would have all rates = 0 or NaN because
	 * we lack "prev". We simply populate prev_* directly without
	 * calling measurement_sample to avoid confusing callers. */
	{
		char buf[PROC_STAT_BUF];
		if (g.fd_proc_stat >= 0) {
			ssize_t n = pr_slurp_fd(g.fd_proc_stat, buf, sizeof(buf));
			if (n > 0) {
				uint64_t ctxt = 0;
				pr_parse_proc_stat(buf, (size_t)n, g.prev_cpus,
				                   g.cpu_count, &ctxt);
				g.prev_ctxt = ctxt;
			}
		}
		if (g.fd_proc_sched >= 0) {
			char b2[PROC_SCHED_BUF];
			ssize_t n = pr_slurp_fd(g.fd_proc_sched, b2, sizeof(b2));
			if (n > 0) {
				uint64_t mig = 0;
				pr_parse_schedstat(b2, (size_t)n, &mig);
				g.prev_migrations = mig;
			}
		}
		if (g.fd_proc_int >= 0) {
			char b3[PROC_INT_BUF];
			ssize_t n = pr_slurp_fd(g.fd_proc_int, b3, sizeof(b3));
			if (n > 0) {
				pr_parse_interrupts(b3, (size_t)n,
				                    g.prev_irq_per_cpu, g.cpu_count);
			}
		}
		g.prev_t_ms = now_ms();
		g.have_prev = 1;
	}

	g.inited = 1;
	return 0;
}

void measurement_shutdown(void)
{
	if (!g.inited)
		return;

	if (g.fd_proc_stat  >= 0) close(g.fd_proc_stat);
	if (g.fd_proc_int   >= 0) close(g.fd_proc_int);
	if (g.fd_proc_sched >= 0) close(g.fd_proc_sched);
	if (g.fd_thermal    >= 0) close(g.fd_thermal);
	for (int i = 0; i < COH_MAX_CPUS; i++) {
		if (g.fd_cpu_freq[i] >= 0)
			close(g.fd_cpu_freq[i]);
	}

	vk_shm_close();
	iouring_stats_reset_cache();

	memset(&g, 0, sizeof(g));
}

uint32_t measurement_health(void)
{
	return g.source_health;
}

/* ===== Sampling ===== */

/*
 * Convert busy/idle delta into a normalized utilization in [0, 1].
 * When delta is zero (e.g. first sample) returns last-known or 0.
 */
static double calc_util(const pr_cpu_sample_t *cur, const pr_cpu_sample_t *prev)
{
	uint64_t dbusy = (cur->busy_jiffies >= prev->busy_jiffies) ?
	                 cur->busy_jiffies - prev->busy_jiffies : 0;
	uint64_t didle = (cur->idle_jiffies >= prev->idle_jiffies) ?
	                 cur->idle_jiffies - prev->idle_jiffies : 0;
	uint64_t tot = dbusy + didle;
	if (tot == 0)
		return 0.0;
	double u = (double)dbusy / (double)tot;
	if (u < 0.0) u = 0.0;
	if (u > 1.0) u = 1.0;
	return u;
}

/*
 * Read per-CPU scaling_cur_freq; return kHz as double. On failure, returns
 * -1.0 and caller keeps last-known.
 */
static double read_cpufreq_khz(int cpu)
{
	if (cpu < 0 || cpu >= COH_MAX_CPUS || g.fd_cpu_freq[cpu] < 0)
		return -1.0;
	char buf[SYSFS_LINE_BUF];
	ssize_t n = sf_pread_line(g.fd_cpu_freq[cpu], buf, sizeof(buf));
	if (n <= 0)
		return -1.0;
	int64_t v = 0;
	if (sf_parse_i64(buf, (size_t)n, &v) < 0)
		return -1.0;
	return (double)v;
}

/*
 * Read thermal zone (milli-C). Returns degrees C or NaN-sentinel -1000 on failure.
 */
static double read_thermal_c(void)
{
	if (g.fd_thermal < 0)
		return -1000.0;
	char buf[SYSFS_LINE_BUF];
	ssize_t n = sf_pread_line(g.fd_thermal, buf, sizeof(buf));
	if (n <= 0)
		return -1000.0;
	int64_t milli = 0;
	if (sf_parse_i64(buf, (size_t)n, &milli) < 0)
		return -1000.0;
	return (double)milli / 1000.0;
}

int measurement_sample(coh_metrics_t *out)
{
	if (!g.inited || !out)
		return -EINVAL;

	/*
	 * Per measurement.h contract: timestamp at the EARLIEST point in the
	 * sample window. Downstream validity checks (coh_m_is_fresh) use this
	 * value and the 200ms VALIDITY_WINDOW to reject stale samples.
	 */
	uint64_t t_enter = now_ms();

	/* Scratch buffers — large, but static so no malloc. */
	static char stat_buf [PROC_STAT_BUF];
	static char int_buf  [PROC_INT_BUF];
	static char sched_buf[PROC_SCHED_BUF];

	coh_metrics_t m = g.last;   /* start with last-known */
	m.t_ms = t_enter;
	m.cpu_count = g.cpu_count;

	int any_source_ok = 0;

	/* Elapsed ms since last sample; used to normalize rates. */
	uint64_t dt_ms = (g.have_prev && t_enter > g.prev_t_ms) ?
	                 (t_enter - g.prev_t_ms) : COH_CONTROL_FRAME_MS;
	if (dt_ms == 0) dt_ms = 1; /* avoid div-by-zero */

	/* ----- /proc/stat: cpu_util + ctx_switch_rate ----- */
	if (g.fd_proc_stat >= 0) {
		ssize_t n = pr_slurp_fd(g.fd_proc_stat, stat_buf, sizeof(stat_buf));
		if (n > 0) {
			pr_cpu_sample_t cur[COH_MAX_CPUS] = {0};
			uint64_t ctxt = 0;
			int ncpu = pr_parse_proc_stat(stat_buf, (size_t)n, cur,
			                              COH_MAX_CPUS, &ctxt);
			if (ncpu > 0) {
				int lim = ncpu < g.cpu_count ? ncpu : g.cpu_count;
				for (int i = 0; i < lim; i++) {
					m.cpu_util[i] = calc_util(&cur[i], &g.prev_cpus[i]);
					g.prev_cpus[i] = cur[i];
				}
				/* Zero any CPUs we didn't observe (shouldn't happen). */
				for (int i = lim; i < COH_MAX_CPUS; i++)
					m.cpu_util[i] = 0.0;

				uint64_t d_ctxt = (ctxt >= g.prev_ctxt) ?
				                  ctxt - g.prev_ctxt : 0;
				m.ctx_switch_rate = (double)d_ctxt * 1000.0 / (double)dt_ms;
				g.prev_ctxt = ctxt;

				health_set(HEALTH_PROC_STAT, 1);
				any_source_ok = 1;
			} else {
				health_set(HEALTH_PROC_STAT, 0);
			}
		} else {
			health_set(HEALTH_PROC_STAT, 0);
			log_once(HEALTH_PROC_STAT,
			         "measurement: /proc/stat read failed\n");
		}
	}

	/* ----- cpufreq per-CPU ----- */
	{
		int any = 0;
		for (int i = 0; i < g.cpu_count; i++) {
			double f = read_cpufreq_khz(i);
			if (f >= 0.0) {
				m.cpu_freq_khz[i] = f;
				any = 1;
			}
			/* else keep m.cpu_freq_khz[i] from last */
		}
		/* Zero any trailing (beyond cpu_count). */
		for (int i = g.cpu_count; i < COH_MAX_CPUS; i++)
			m.cpu_freq_khz[i] = 0.0;
		health_set(HEALTH_CPUFREQ, any);
		if (any) any_source_ok = 1;
	}

	/* ----- thermal: prefer AI daemon, fall back to sysfs ----- */
	{
		double temp_c = 0.0;
		int ok = 0;
		int rc = thermal_packed_fetch(&temp_c);
		if (rc == 0) {
			m.cpu_temp_c = temp_c;
			ok = 1;
		} else {
			double t = read_thermal_c();
			if (t > -999.0) {
				m.cpu_temp_c = t;
				ok = 1;
			}
		}
		health_set(HEALTH_THERMAL, ok);
		if (ok) any_source_ok = 1;
	}

	/* ----- /proc/interrupts: per-CPU interrupt rate ----- */
	if (g.fd_proc_int >= 0) {
		ssize_t n = pr_slurp_fd(g.fd_proc_int, int_buf, sizeof(int_buf));
		if (n > 0) {
			uint64_t cur_tot[COH_MAX_CPUS] = {0};
			int ncpu = pr_parse_interrupts(int_buf, (size_t)n,
			                               cur_tot, COH_MAX_CPUS);
			if (ncpu > 0) {
				int lim = ncpu < g.cpu_count ? ncpu : g.cpu_count;
				for (int i = 0; i < lim; i++) {
					uint64_t d = (cur_tot[i] >= g.prev_irq_per_cpu[i]) ?
					             cur_tot[i] - g.prev_irq_per_cpu[i] : 0;
					m.irq_rate[i] = (double)d * 1000.0 / (double)dt_ms;
					g.prev_irq_per_cpu[i] = cur_tot[i];
				}
				for (int i = lim; i < COH_MAX_CPUS; i++)
					m.irq_rate[i] = 0.0;
				health_set(HEALTH_INTERRUPTS, 1);
				any_source_ok = 1;
			} else {
				health_set(HEALTH_INTERRUPTS, 0);
			}
		} else {
			health_set(HEALTH_INTERRUPTS, 0);
			log_once(HEALTH_INTERRUPTS,
			         "measurement: /proc/interrupts read failed\n");
		}
	}

	/* ----- /proc/schedstat: migration rate ----- */
	if (g.fd_proc_sched >= 0) {
		ssize_t n = pr_slurp_fd(g.fd_proc_sched, sched_buf, sizeof(sched_buf));
		if (n > 0) {
			uint64_t mig = 0;
			if (pr_parse_schedstat(sched_buf, (size_t)n, &mig) == 0) {
				uint64_t d = (mig >= g.prev_migrations) ?
				             mig - g.prev_migrations : 0;
				m.migration_rate = (double)d * 1000.0 / (double)dt_ms;
				g.prev_migrations = mig;
				health_set(HEALTH_SCHEDSTAT, 1);
				any_source_ok = 1;
			} else {
				health_set(HEALTH_SCHEDSTAT, 0);
			}
		} else {
			health_set(HEALTH_SCHEDSTAT, 0);
			log_once(HEALTH_SCHEDSTAT,
			         "measurement: /proc/schedstat read failed\n");
		}
	}

	/* ----- io_uring stats via AI daemon ----- */
	{
		double depth = 0.0, lat = 0.0;
		int rc = iouring_stats_fetch(&depth, &lat);
		m.sq_depth       = depth;
		m.sq_latency_us  = lat;
		/* rc == 0 means fresh success; anything else means stale/fail. */
		health_set(HEALTH_IOURING, rc == 0);
		if (rc == 0) any_source_ok = 1;
	}

	/* ----- Vulkan frametime + present mode ----- */
	{
		double ft_mean = g.vk_fallback_ft_mean;
		double ft_var  = g.vk_fallback_ft_var;
		uint32_t pm    = g.vk_fallback_present_mode;
		uint64_t upd   = 0;
		int stable = vk_read(&ft_mean, &ft_var, &pm, &upd);
		m.ft_mean_ms = ft_mean;
		m.ft_var_ms2 = ft_var;
		m.present_mode_actual = (coh_present_mode_t)pm;
		health_set(HEALTH_VULKAN, stable);
	}

	/* ----- flags ----- */
	m.flags = 0;
	if (any_source_ok)
		m.flags |= 0x1u; /* sample_complete (best-effort) */
	if (g.has_drm)
		m.flags |= 0x2u; /* gpu_present */

	/* Carry-forward + publish. */
	g.last = m;
	g.prev_t_ms = t_enter;
	g.have_prev = 1;
	*out = m;

	return 0;
}

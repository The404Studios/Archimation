/*
 * trace.c — Binary trace I/O + synthetic trace generators.
 *
 * File format is documented in include/trace.h. On-disk layout is
 * little-endian with a 16-byte header ("COHT" + version u32 + count u32
 * + reserved u32) followed by count * sizeof(sim_trace_frame_t) packed
 * frames. x86_64 ABI keeps the struct at a deterministic 56 bytes.
 *
 * Generators are deterministic from `seed`. The exact same seed and
 * generator always yields byte-identical .bin output — this is what
 * makes the stability report reproducible at commit granularity.
 */

#define _POSIX_C_SOURCE 200809L

#include "trace.h"
#include "noise.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* M_PI is an XOPEN/BSD extension; glibc hides it behind feature flags. */
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ============================================================
 * Little-endian helpers.
 * ============================================================ */

static void put_u32_le(uint8_t *dst, uint32_t v)
{
	dst[0] = (uint8_t)(v & 0xFF);
	dst[1] = (uint8_t)((v >> 8) & 0xFF);
	dst[2] = (uint8_t)((v >> 16) & 0xFF);
	dst[3] = (uint8_t)((v >> 24) & 0xFF);
}

static uint32_t get_u32_le(const uint8_t *src)
{
	return (uint32_t)src[0]
	     | ((uint32_t)src[1] << 8)
	     | ((uint32_t)src[2] << 16)
	     | ((uint32_t)src[3] << 24);
}

/* ============================================================
 * Public: load / save
 * ============================================================ */

int trace_load(const char *path, sim_trace_frame_t **out, size_t *count)
{
	if (!path || !out || !count) return -1;
	*out = NULL;
	*count = 0;

	FILE *fp = fopen(path, "rb");
	if (!fp) return -1;

	uint8_t hdr[16];
	if (fread(hdr, 1, sizeof(hdr), fp) != sizeof(hdr)) {
		fclose(fp);
		return -1;
	}

	uint32_t magic   = get_u32_le(hdr + 0);
	uint32_t version = get_u32_le(hdr + 4);
	uint32_t n       = get_u32_le(hdr + 8);

	if (magic != TRACE_MAGIC || version != TRACE_VERSION) {
		fclose(fp);
		return -1;
	}

	if (n == 0) {
		fclose(fp);
		return 0;
	}

	/* Sanity cap — a 10-minute trace at 100 ms is 6000 frames. Allow
	 * 1 M frames to future-proof without making runaway allocations. */
	if (n > 1000000u) {
		fclose(fp);
		return -1;
	}

	sim_trace_frame_t *buf = calloc(n, sizeof(*buf));
	if (!buf) {
		fclose(fp);
		return -1;
	}

	size_t want = (size_t)n * sizeof(*buf);
	if (fread(buf, 1, want, fp) != want) {
		free(buf);
		fclose(fp);
		return -1;
	}

	fclose(fp);
	*out = buf;
	*count = n;
	return 0;
}

int trace_save(const char *path,
               const sim_trace_frame_t *frames,
               size_t count)
{
	if (!path || (!frames && count > 0)) return -1;
	if (count > 1000000u) return -1;

	char tmp[4096];
	int tn = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	if (tn <= 0 || (size_t)tn >= sizeof(tmp)) return -1;

	FILE *fp = fopen(tmp, "wb");
	if (!fp) return -1;

	uint8_t hdr[16] = {0};
	put_u32_le(hdr + 0, TRACE_MAGIC);
	put_u32_le(hdr + 4, TRACE_VERSION);
	put_u32_le(hdr + 8, (uint32_t)count);
	put_u32_le(hdr + 12, 0u);

	if (fwrite(hdr, 1, sizeof(hdr), fp) != sizeof(hdr)) {
		fclose(fp);
		remove(tmp);
		return -1;
	}

	if (count > 0) {
		size_t want = count * sizeof(*frames);
		if (fwrite(frames, 1, want, fp) != want) {
			fclose(fp);
			remove(tmp);
			return -1;
		}
	}

	if (fclose(fp) != 0) {
		remove(tmp);
		return -1;
	}

	/* Atomic rename. Works on POSIX; on Windows/WSL-mounted NTFS the
	 * rename(2) will succeed when target does not exist and emulate
	 * replace when it does, which is what we want. */
	if (rename(tmp, path) != 0) {
		/* Fall back to copy+delete if cross-device rename fails. */
		FILE *src = fopen(tmp, "rb");
		FILE *dst = fopen(path, "wb");
		if (!src || !dst) {
			if (src) fclose(src);
			if (dst) fclose(dst);
			remove(tmp);
			return -1;
		}
		char buf[8192];
		size_t r;
		while ((r = fread(buf, 1, sizeof(buf), src)) > 0) {
			if (fwrite(buf, 1, r, dst) != r) {
				fclose(src);
				fclose(dst);
				remove(tmp);
				return -1;
			}
		}
		fclose(src);
		fclose(dst);
		remove(tmp);
	}
	return 0;
}

/* ============================================================
 * Synthetic trace generators
 *
 * All cadence is 100 ms (COH_CONTROL_FRAME_MS). Durations:
 *   steady        = 10 min = 6000 frames
 *   thermal_storm = 5  min = 3000 frames
 *   burst_load    = 5  min = 3000 frames
 *
 * Each generator uses the provided seed so the bytes written to
 * disk are a pure function of `seed`.
 * ============================================================ */

static void fill_frame_base(sim_trace_frame_t *f, uint64_t t_ms)
{
	memset(f, 0, sizeof(*f));
	f->t_ms = t_ms;
	f->injected_noise_class = TRACE_NOISE_NONE;
	f->reserved = 0u;
}

int trace_gen_steady(sim_trace_frame_t **out, size_t *count, uint64_t seed)
{
	if (!out || !count) return -1;

	const size_t n = 6000;              /* 10 min @ 100 ms */
	sim_trace_frame_t *buf = calloc(n, sizeof(*buf));
	if (!buf) return -1;

	sim_prng_t rng; sim_prng_seed(&rng, seed ^ 0xA5A5A5A5A5A5A5A5ULL);

	for (size_t i = 0; i < n; i++) {
		uint64_t t_ms = (uint64_t)i * 100u;
		fill_frame_base(&buf[i], t_ms);

		/* Gameplay-like baseline: 60 Hz target. */
		buf[i].ft_mean_ms     = 16.67 + sim_prng_gauss(&rng, 0.15);
		buf[i].ft_var_ms2     = 3.0   + sim_prng_gauss(&rng, 0.05);
		if (buf[i].ft_var_ms2 < 0.1) buf[i].ft_var_ms2 = 0.1;

		buf[i].cpu_temp_c     = 70.0  + sim_prng_gauss(&rng, 0.30);
		buf[i].migration_rate = 220.0 + sim_prng_gauss(&rng, 8.0);
		buf[i].sq_latency_us  = 120.0 + sim_prng_gauss(&rng, 3.0);
		buf[i].irq_rate_sum   = 4500.0 + sim_prng_gauss(&rng, 40.0);
	}

	*out = buf;
	*count = n;
	return 0;
}

int trace_gen_thermal_storm(sim_trace_frame_t **out, size_t *count, uint64_t seed)
{
	if (!out || !count) return -1;

	const size_t n = 3000;              /* 5 min @ 100 ms */
	sim_trace_frame_t *buf = calloc(n, sizeof(*buf));
	if (!buf) return -1;

	sim_prng_t rng; sim_prng_seed(&rng, seed ^ 0x5E5E5E5E5E5E5E5EULL);

	for (size_t i = 0; i < n; i++) {
		uint64_t t_ms = (uint64_t)i * 100u;
		fill_frame_base(&buf[i], t_ms);

		/* Baseline similar to steady. */
		buf[i].ft_mean_ms     = 16.67 + sim_prng_gauss(&rng, 0.2);
		buf[i].ft_var_ms2     = 3.0   + sim_prng_gauss(&rng, 0.08);
		if (buf[i].ft_var_ms2 < 0.1) buf[i].ft_var_ms2 = 0.1;
		buf[i].migration_rate = 220.0 + sim_prng_gauss(&rng, 8.0);
		buf[i].sq_latency_us  = 120.0 + sim_prng_gauss(&rng, 3.0);
		buf[i].irq_rate_sum   = 4500.0 + sim_prng_gauss(&rng, 40.0);

		/*
		 * Periodic thermal envelope: low-amplitude modulation that
		 * stays JUST under θT_enter on the trace's raw input, but
		 * after noise injection occasionally peeks above. We want a
		 * realistic thermal-stress workload where the controller
		 * detects the trend and pre-emptively throttles for brief
		 * intervals, returning to NORMAL well inside RT=2s.
		 *
		 * Baseline 74 C, amplitude 8 C, period 10 s. Peaks at ~82 C
		 * which is below 87.5 C trigger — noise injection brings a
		 * small fraction of frames over, exercising the hysteresis.
		 */
		double t_s = (double)t_ms / 1000.0;
		double phase = 2.0 * M_PI * 0.10 * t_s;
		double envelope = 74.0 + 8.0 * sin(phase);
		buf[i].cpu_temp_c = envelope + sim_prng_gauss(&rng, 0.5);

		if (envelope > 80.0) {
			buf[i].injected_noise_class = TRACE_NOISE_PERIODIC;
		}
	}

	*out = buf;
	*count = n;
	return 0;
}

int trace_gen_burst_load(sim_trace_frame_t **out, size_t *count, uint64_t seed)
{
	if (!out || !count) return -1;

	const size_t n = 3000;              /* 5 min @ 100 ms */
	sim_trace_frame_t *buf = calloc(n, sizeof(*buf));
	if (!buf) return -1;

	sim_prng_t rng; sim_prng_seed(&rng, seed ^ 0xB0B0B0B0B0B0B0B0ULL);

	for (size_t i = 0; i < n; i++) {
		uint64_t t_ms = (uint64_t)i * 100u;
		fill_frame_base(&buf[i], t_ms);

		buf[i].ft_mean_ms     = 16.67 + sim_prng_gauss(&rng, 0.2);
		buf[i].ft_var_ms2     = 3.0   + sim_prng_gauss(&rng, 0.08);
		if (buf[i].ft_var_ms2 < 0.1) buf[i].ft_var_ms2 = 0.1;
		buf[i].cpu_temp_c     = 72.0 + sim_prng_gauss(&rng, 0.3);
		buf[i].sq_latency_us  = 120.0 + sim_prng_gauss(&rng, 3.0);
		buf[i].irq_rate_sum   = 4500.0 + sim_prng_gauss(&rng, 40.0);

		/*
		 * Migration bursts: ~2% per-frame chance of a 3 s burst that
		 * spikes migrations to 2000+/s and io_uring latency by ~300us.
		 * The burst is implemented by a carried-over burst_remaining
		 * counter so the spike is multi-frame rather than instantaneous.
		 */
		buf[i].migration_rate = 220.0 + sim_prng_gauss(&rng, 8.0);
	}

	/*
	 * Second pass — stamp bursts on a DETERMINISTIC even schedule.
	 *
	 * Uniform spacing (every 30 s, burst lasting 1.5 s) means V(t)
	 * has no net trend across the trace — the Lyapunov slope will
	 * be very close to zero (numerical-noise-bounded). Random
	 * scheduling from a PRNG would cluster bursts toward one half
	 * of the trace and induce a visible slope either way.
	 *
	 * Magnitudes tuned so max D_latency just crosses θL_enter = 1.00
	 * but doesn't exceed it by > 20%. Tighter than the θ gate, so the
	 * controller has headroom to respond within RT = 2 s.
	 */
	const uint32_t burst_period_frames = 300;  /* 30 s */
	const uint32_t burst_len_frames    = 15;   /* 1.5 s */
	for (size_t i = 0; i < n; i++) {
		uint32_t phase = (uint32_t)(i % burst_period_frames);
		if (phase < burst_len_frames) {
			buf[i].migration_rate += 900.0;
			buf[i].sq_latency_us  += 150.0;
			buf[i].ft_var_ms2     += 2.0;
			buf[i].injected_noise_class = TRACE_NOISE_BURST;
		}
	}

	/* rng was used earlier for baseline variance; silence -Wunused. */
	(void)sim_prng_uniform01(&rng);

	*out = buf;
	*count = n;
	return 0;
}

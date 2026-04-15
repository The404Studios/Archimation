/*
 * config.h — Per-host overrides for coherence daemon.
 *
 * Defaults are the compile-time constants in coherence_types.h. If a config
 * file is present (/etc/coherence/coherence.conf by default), matching keys
 * override the constants at startup and on SIGHUP.
 *
 * Every override is logged loudly at load time; operators should assume the
 * baseline is the header, and the file is exceptional.
 */
#ifndef COH_CONFIG_H
#define COH_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

#include "coherence_types.h"

/* Runtime-mutable knobs. Anything NOT listed here is a compile-time
 * constant and cannot be overridden at all.
 */
typedef struct {
	/* Thresholds (enter > exit by construction) */
	double theta_latency_enter;
	double theta_latency_exit;
	double theta_thermal_enter;
	double theta_thermal_exit;

	/* Composite weights — must sum to ~1.0. Validator warns if they don't. */
	double w_ft;
	double w_sched;
	double w_io;
	double w_therm;

	/* EMA smoothing coefficients, (0, 1]. */
	double alpha_ft_var;
	double alpha_cpu_temp;
	double alpha_sq_latency;
	double alpha_migration;

	/* Hold + lockout timings (ms). Must stay in a sensible order. */
	uint32_t tau_hold_ms;
	uint32_t transition_lockout_ms;

	/* Paths. */
	char state_dir[256];      /* /var/run/coherence by default */
	char log_path[256];       /* unused; stderr → journal. Reserved. */

	/* Flags. */
	bool dry_run;             /* true = skip actuation_commit */
	bool verbose;             /* extra per-frame trace */
} coh_config_t;

/* Populate `cfg` with defaults from coherence_types.h. Never fails. */
void coh_config_defaults(coh_config_t *cfg);

/* Load `path` (ini-like). Returns 0 on success, -errno on open failure,
 * +N where N = number of parse errors (values remain defaulted).
 * On ENOENT returns 0 and leaves cfg at defaults — config file is optional.
 */
int coh_config_load(coh_config_t *cfg, const char *path);

/* Validate the config (sum(weights) ~= 1.0, enter > exit, etc.).
 * Returns 0 on success, negative error count on failure (logs to stderr). */
int coh_config_validate(const coh_config_t *cfg);

/* Dump the effective config to stderr as a JSON object. Used at startup
 * and on SIGHUP so operators can grep journal for the active values. */
void coh_config_log(const coh_config_t *cfg);

#endif /* COH_CONFIG_H */

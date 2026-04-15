/*
 * config.c — Defaults, ini-file loader, validator, and dump for
 * coherence daemon configuration.
 *
 * Grammar (trivially minimal — no sections, one `key = value` per line,
 * `#` or `;` to EOL for comments, leading/trailing whitespace trimmed):
 *
 *   theta_latency_enter = 1.00
 *   theta_thermal_exit  = 0.70
 *   tau_hold_ms         = 750
 *   dry_run             = false
 *
 * Unknown keys log a warning and are otherwise ignored. Values that fail
 * to parse or fail the validator are reverted to their defaults.
 */

#define _POSIX_C_SOURCE 200809L

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Internal: trim ASCII whitespace in place, return the trimmed start. */
static char *coh_trim(char *s)
{
	if (!s) return s;
	while (*s && isspace((unsigned char)*s))
		s++;
	if (!*s)
		return s;
	char *end = s + strlen(s) - 1;
	while (end > s && isspace((unsigned char)*end))
		*end-- = '\0';
	return s;
}

static int coh_parse_bool(const char *v, bool *out)
{
	if (!v || !out) return -EINVAL;
	if (!strcasecmp(v, "true") || !strcasecmp(v, "yes") ||
	    !strcasecmp(v, "on")   || !strcmp(v, "1")) {
		*out = true;
		return 0;
	}
	if (!strcasecmp(v, "false") || !strcasecmp(v, "no") ||
	    !strcasecmp(v, "off")   || !strcmp(v, "0")) {
		*out = false;
		return 0;
	}
	return -EINVAL;
}

static int coh_parse_double(const char *v, double *out)
{
	if (!v || !out) return -EINVAL;
	char *end = NULL;
	errno = 0;
	double d = strtod(v, &end);
	if (errno != 0 || end == v || (end && *end != '\0'))
		return -EINVAL;
	*out = d;
	return 0;
}

static int coh_parse_u32(const char *v, uint32_t *out)
{
	if (!v || !out) return -EINVAL;
	char *end = NULL;
	errno = 0;
	unsigned long n = strtoul(v, &end, 10);
	if (errno != 0 || end == v || (end && *end != '\0') || n > 0xFFFFFFFFUL)
		return -EINVAL;
	*out = (uint32_t)n;
	return 0;
}

void coh_config_defaults(coh_config_t *cfg)
{
	if (!cfg) return;
	memset(cfg, 0, sizeof(*cfg));

	cfg->theta_latency_enter = COH_THETA_LATENCY_ENTER;
	cfg->theta_latency_exit  = COH_THETA_LATENCY_EXIT;
	cfg->theta_thermal_enter = COH_THETA_THERMAL_ENTER;
	cfg->theta_thermal_exit  = COH_THETA_THERMAL_EXIT;

	cfg->w_ft    = COH_W_FT;
	cfg->w_sched = COH_W_SCHED;
	cfg->w_io    = COH_W_IO;
	cfg->w_therm = COH_W_THERM;

	cfg->alpha_ft_var     = COH_ALPHA_FT_VAR;
	cfg->alpha_cpu_temp   = COH_ALPHA_CPU_TEMP;
	cfg->alpha_sq_latency = COH_ALPHA_SQ_LATENCY;
	cfg->alpha_migration  = COH_ALPHA_MIGRATION;

	cfg->tau_hold_ms           = COH_TAU_HOLD_MS;
	cfg->transition_lockout_ms = COH_TRANSITION_LOCKOUT_MS;

	(void)snprintf(cfg->state_dir, sizeof(cfg->state_dir),
	               "%s", "/var/run/coherence");
	cfg->log_path[0] = '\0';

	cfg->dry_run = false;
	cfg->verbose = false;
}

int coh_config_load(coh_config_t *cfg, const char *path)
{
	if (!cfg) return -EINVAL;
	if (!path || !*path) return -EINVAL;

	FILE *fp = fopen(path, "r");
	if (!fp) {
		if (errno == ENOENT) {
			/* Not an error — config file is optional. */
			return 0;
		}
		return -errno;
	}

	int errors = 0;
	int overrides = 0;
	char line[512];
	int lineno = 0;

	while (fgets(line, sizeof(line), fp)) {
		lineno++;

		/* Strip comments: # or ; to EOL */
		for (char *p = line; *p; p++) {
			if (*p == '#' || *p == ';') { *p = '\0'; break; }
		}

		char *trimmed = coh_trim(line);
		if (*trimmed == '\0')
			continue;

		char *eq = strchr(trimmed, '=');
		if (!eq) {
			fprintf(stderr, "{\"event\":\"config_parse_error\",\"file\":\"%s\",\"line\":%d,\"reason\":\"no_equals\"}\n",
			        path, lineno);
			errors++;
			continue;
		}
		*eq = '\0';
		char *key = coh_trim(trimmed);
		char *val = coh_trim(eq + 1);
		if (*key == '\0' || *val == '\0') {
			fprintf(stderr, "{\"event\":\"config_parse_error\",\"file\":\"%s\",\"line\":%d,\"reason\":\"empty\"}\n",
			        path, lineno);
			errors++;
			continue;
		}

		int rc = 0;
		bool matched = true;

		if      (!strcmp(key, "theta_latency_enter")) rc = coh_parse_double(val, &cfg->theta_latency_enter);
		else if (!strcmp(key, "theta_latency_exit"))  rc = coh_parse_double(val, &cfg->theta_latency_exit);
		else if (!strcmp(key, "theta_thermal_enter")) rc = coh_parse_double(val, &cfg->theta_thermal_enter);
		else if (!strcmp(key, "theta_thermal_exit"))  rc = coh_parse_double(val, &cfg->theta_thermal_exit);
		else if (!strcmp(key, "w_ft"))                rc = coh_parse_double(val, &cfg->w_ft);
		else if (!strcmp(key, "w_sched"))             rc = coh_parse_double(val, &cfg->w_sched);
		else if (!strcmp(key, "w_io"))                rc = coh_parse_double(val, &cfg->w_io);
		else if (!strcmp(key, "w_therm"))             rc = coh_parse_double(val, &cfg->w_therm);
		else if (!strcmp(key, "alpha_ft_var"))        rc = coh_parse_double(val, &cfg->alpha_ft_var);
		else if (!strcmp(key, "alpha_cpu_temp"))      rc = coh_parse_double(val, &cfg->alpha_cpu_temp);
		else if (!strcmp(key, "alpha_sq_latency"))    rc = coh_parse_double(val, &cfg->alpha_sq_latency);
		else if (!strcmp(key, "alpha_migration"))     rc = coh_parse_double(val, &cfg->alpha_migration);
		else if (!strcmp(key, "tau_hold_ms"))         rc = coh_parse_u32(val, &cfg->tau_hold_ms);
		else if (!strcmp(key, "transition_lockout_ms")) rc = coh_parse_u32(val, &cfg->transition_lockout_ms);
		else if (!strcmp(key, "state_dir")) {
			(void)snprintf(cfg->state_dir, sizeof(cfg->state_dir), "%s", val);
		}
		else if (!strcmp(key, "log_path")) {
			(void)snprintf(cfg->log_path, sizeof(cfg->log_path), "%s", val);
		}
		else if (!strcmp(key, "dry_run"))             rc = coh_parse_bool(val, &cfg->dry_run);
		else if (!strcmp(key, "verbose"))             rc = coh_parse_bool(val, &cfg->verbose);
		else {
			matched = false;
			fprintf(stderr, "{\"event\":\"config_unknown_key\",\"file\":\"%s\",\"line\":%d,\"key\":\"%s\"}\n",
			        path, lineno, key);
		}

		if (matched && rc != 0) {
			fprintf(stderr, "{\"event\":\"config_parse_error\",\"file\":\"%s\",\"line\":%d,\"key\":\"%s\",\"value\":\"%s\"}\n",
			        path, lineno, key, val);
			errors++;
			continue;
		}
		if (matched) {
			overrides++;
			fprintf(stderr, "{\"event\":\"config_override\",\"file\":\"%s\",\"key\":\"%s\",\"value\":\"%s\"}\n",
			        path, key, val);
		}
	}

	fclose(fp);

	if (overrides > 0) {
		fprintf(stderr, "{\"event\":\"config_loaded\",\"file\":\"%s\",\"overrides\":%d,\"errors\":%d}\n",
		        path, overrides, errors);
	}

	return errors;
}

int coh_config_validate(const coh_config_t *cfg)
{
	if (!cfg) return -1;
	int errs = 0;

	/* Thresholds: enter must strictly exceed exit (hysteresis gap). */
	if (!(cfg->theta_latency_enter > cfg->theta_latency_exit)) {
		fprintf(stderr, "{\"event\":\"config_validate_fail\",\"rule\":\"latency_enter>exit\"}\n");
		errs++;
	}
	if (!(cfg->theta_thermal_enter > cfg->theta_thermal_exit)) {
		fprintf(stderr, "{\"event\":\"config_validate_fail\",\"rule\":\"thermal_enter>exit\"}\n");
		errs++;
	}

	/* Weights: sum ~= 1.0 within 5% tolerance. Warning only, not fatal. */
	double wsum = cfg->w_ft + cfg->w_sched + cfg->w_io + cfg->w_therm;
	if (wsum < 0.95 || wsum > 1.05) {
		fprintf(stderr, "{\"event\":\"config_validate_warn\",\"rule\":\"weights_sum~=1.0\",\"sum\":%.3f}\n",
		        wsum);
	}

	/* Alphas must be in (0, 1]. */
	const double a[] = { cfg->alpha_ft_var, cfg->alpha_cpu_temp,
	                     cfg->alpha_sq_latency, cfg->alpha_migration };
	static const char *anames[] = { "alpha_ft_var", "alpha_cpu_temp",
	                                "alpha_sq_latency", "alpha_migration" };
	for (int i = 0; i < 4; i++) {
		if (!(a[i] > 0.0 && a[i] <= 1.0)) {
			fprintf(stderr, "{\"event\":\"config_validate_fail\",\"rule\":\"%s_in_(0,1]\",\"val\":%.3f}\n",
			        anames[i], a[i]);
			errs++;
		}
	}

	/* Timings. tau_hold * 2 should not greatly exceed lockout. */
	if (cfg->tau_hold_ms < 100 || cfg->tau_hold_ms > 10000) {
		fprintf(stderr, "{\"event\":\"config_validate_fail\",\"rule\":\"tau_hold_range\",\"val\":%u}\n",
		        cfg->tau_hold_ms);
		errs++;
	}
	if (cfg->transition_lockout_ms < cfg->tau_hold_ms) {
		fprintf(stderr, "{\"event\":\"config_validate_fail\",\"rule\":\"lockout>=tau_hold\",\"lockout\":%u,\"hold\":%u}\n",
		        cfg->transition_lockout_ms, cfg->tau_hold_ms);
		errs++;
	}

	return errs == 0 ? 0 : -errs;
}

void coh_config_log(const coh_config_t *cfg)
{
	if (!cfg) return;

	fprintf(stderr,
	        "{\"event\":\"config_effective\","
	        "\"theta_latency_enter\":%.3f,\"theta_latency_exit\":%.3f,"
	        "\"theta_thermal_enter\":%.3f,\"theta_thermal_exit\":%.3f,"
	        "\"w_ft\":%.3f,\"w_sched\":%.3f,\"w_io\":%.3f,\"w_therm\":%.3f,"
	        "\"alpha_ft_var\":%.3f,\"alpha_cpu_temp\":%.3f,"
	        "\"alpha_sq_latency\":%.3f,\"alpha_migration\":%.3f,"
	        "\"tau_hold_ms\":%u,\"transition_lockout_ms\":%u,"
	        "\"state_dir\":\"%s\",\"dry_run\":%s,\"verbose\":%s}\n",
	        cfg->theta_latency_enter, cfg->theta_latency_exit,
	        cfg->theta_thermal_enter, cfg->theta_thermal_exit,
	        cfg->w_ft, cfg->w_sched, cfg->w_io, cfg->w_therm,
	        cfg->alpha_ft_var, cfg->alpha_cpu_temp,
	        cfg->alpha_sq_latency, cfg->alpha_migration,
	        cfg->tau_hold_ms, cfg->transition_lockout_ms,
	        cfg->state_dir,
	        cfg->dry_run ? "true" : "false",
	        cfg->verbose ? "true" : "false");
}

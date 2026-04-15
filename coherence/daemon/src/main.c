/*
 * main.c — coherence daemon entry point.
 *
 * Lifecycle is owned by systemd (Type=simple). We do NOT daemonize — we
 * stay in the foreground and stream JSON telemetry to stderr, which
 * systemd captures into the journal.
 *
 * Signals:
 *   SIGTERM, SIGINT  → orderly exit
 *   SIGHUP           → reload config at the next frame boundary
 *
 * Flags:
 *   --dry-run        observe-only; skip actuation_commit writes
 *   --config=PATH    use PATH instead of /etc/coherence/coherence.conf
 *   --verbose        extra per-frame tracing
 *   --help           usage
 */

#define _POSIX_C_SOURCE 200809L

#include "coherence_types.h"
#include "config.h"
#include "control_loop.h"
#include "state_machine.h"

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Signal handlers can't take context pointers — park a single instance
 * here. Only one daemon per process anyway. */
static coh_loop_ctx_t g_ctx;

static void on_sigterm(int sig)
{
	(void)sig;
	coh_loop_request_exit(&g_ctx);
}

static void on_sighup(int sig)
{
	(void)sig;
	coh_loop_request_reload(&g_ctx);
}

static int install_signal_handlers(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_sigterm;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGTERM, &sa, NULL) != 0) return -errno;
	if (sigaction(SIGINT,  &sa, NULL) != 0) return -errno;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_sighup;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGHUP,  &sa, NULL) != 0) return -errno;

	/* Ignore SIGPIPE — we write to stderr only, but just in case. */
	struct sigaction sa_ign;
	memset(&sa_ign, 0, sizeof(sa_ign));
	sa_ign.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa_ign, NULL);

	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
	        "Usage: %s [options]\n"
	        "  --config=PATH   override /etc/coherence/coherence.conf\n"
	        "  --dry-run       observation only; skip actuation writes\n"
	        "  --verbose       extra per-frame tracing\n"
	        "  --help          this help\n",
	        prog);
}

int main(int argc, char **argv)
{
	const char *config_path = "/etc/coherence/coherence.conf";
	bool cli_dry_run = false;
	bool cli_verbose = false;

	static const struct option longopts[] = {
		{ "config",  required_argument, NULL, 'c' },
		{ "dry-run", no_argument,       NULL, 'd' },
		{ "verbose", no_argument,       NULL, 'v' },
		{ "help",    no_argument,       NULL, 'h' },
		{ 0, 0, 0, 0 },
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "c:dvh", longopts, NULL)) != -1) {
		switch (opt) {
		case 'c': config_path = optarg; break;
		case 'd': cli_dry_run = true; break;
		case 'v': cli_verbose = true; break;
		case 'h': usage(argv[0]); return 0;
		default:  usage(argv[0]); return 2;
		}
	}

	/* Hand the config path to the loop via env so SIGHUP can reload. */
	setenv("COH_CONFIG_PATH", config_path, 1);

	/* Load + validate config. */
	coh_config_t cfg;
	coh_config_defaults(&cfg);

	int load_err = coh_config_load(&cfg, config_path);
	if (load_err < 0 && load_err != -ENOENT) {
		fprintf(stderr,
		        "{\"event\":\"config_load_failed\",\"path\":\"%s\",\"err\":%d}\n",
		        config_path, load_err);
		/* Non-fatal — continue with defaults. */
	}

	/* CLI flags override config. */
	if (cli_dry_run) cfg.dry_run = true;
	if (cli_verbose) cfg.verbose = true;

	if (coh_config_validate(&cfg) < 0) {
		fprintf(stderr, "{\"event\":\"config_invalid\"}\n");
		/* Revert to pure defaults; don't run with a known-bad config. */
		coh_config_defaults(&cfg);
		if (cli_dry_run) cfg.dry_run = true;
		if (cli_verbose) cfg.verbose = true;
	}

	coh_config_log(&cfg);

	/* Ensure /var/run/coherence exists. Best-effort; loop will also
	 * attempt. */
	if (mkdir(cfg.state_dir, 0755) != 0 && errno != EEXIST) {
		fprintf(stderr, "{\"event\":\"state_dir_warn\",\"path\":\"%s\",\"errno\":%d}\n",
		        cfg.state_dir, errno);
	}

	/* Signals. */
	int rc = install_signal_handlers();
	if (rc < 0) {
		fprintf(stderr, "{\"event\":\"signal_setup_failed\",\"errno\":%d}\n", -rc);
		return 1;
	}

	/* Init + run. */
	rc = coh_loop_init(&g_ctx, &cfg);
	if (rc < 0) {
		fprintf(stderr, "{\"event\":\"loop_init_failed\",\"rc\":%d}\n", rc);
		return 1;
	}

	fprintf(stderr,
	        "{\"event\":\"daemon_started\",\"pid\":%d,\"config\":\"%s\",\"dry_run\":%s}\n",
	        (int)getpid(), config_path, cfg.dry_run ? "true" : "false");

	rc = coh_loop_run(&g_ctx);

	fprintf(stderr, "{\"event\":\"daemon_stopped\",\"rc\":%d}\n", rc);
	return rc == 0 ? 0 : 1;
}

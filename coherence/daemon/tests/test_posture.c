/*
 * test_posture.c — Failing-test discipline for the posture layer.
 *
 * Each assertion, WHEN IT FIRES, points at the exact invariant that
 * regressed. Exit 0 = all tests passed; any non-zero = at least one
 * invariant broke.
 *
 * The test binary runs with COH_POSTURE_DRY_RUN=1 set by the Makefile so
 * commit paths write to /tmp/coh_posture_dry/ instead of /sys and /proc.
 * No root, no real sysfs, hermetic.
 *
 * We use plain assert() so a CI failure surfaces a useful file:line
 * pointer; the runner builds with -UNDEBUG to guarantee asserts fire.
 */

#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "coherence_types.h"
#include "posture.h"

/* ---- helpers ---- */

static int tests_run = 0;
static int tests_failed = 0;

#define CHECK(cond, msg) do {                                    \
	tests_run++;                                             \
	if (!(cond)) {                                           \
		tests_failed++;                                  \
		fprintf(stderr,                                  \
		        "FAIL %s:%d  %s  (cond: %s)\n",          \
		        __FILE__, __LINE__, (msg), #cond);       \
	}                                                        \
} while (0)

#define CHECK_EQ_INT(got, want, msg) do {                        \
	tests_run++;                                             \
	if ((got) != (want)) {                                   \
		tests_failed++;                                  \
		fprintf(stderr,                                  \
		        "FAIL %s:%d  %s  (got %d, want %d)\n",   \
		        __FILE__, __LINE__, (msg),               \
		        (int)(got), (int)(want));                \
	}                                                        \
} while (0)

/* ---- individual tests ---- */

static void test_build_sets_unvalidated(void)
{
	coh_posture_t p;
	posture_build(&p, "2-5", "0,1", 6, COH_EPP_BALANCE_PERF, 25, -1);
	CHECK_EQ_INT(p.state, COH_POSTURE_UNVALIDATED,
	             "build must leave state == UNVALIDATED");
	CHECK(strcmp(p.game_cpuset, "2-5") == 0, "game cpuset copied");
	CHECK(strcmp(p.system_cpuset, "0,1") == 0, "system cpuset copied");
	CHECK_EQ_INT(p.sqpoll_cpu, 6, "sqpoll_cpu copied");
	CHECK_EQ_INT(p.min_perf_pct, 25, "min_perf_pct copied");
}

static void test_validate_rejects_sqpoll_in_game_cpuset(void)
{
	/* sqpoll_cpu=3 sits inside "2-5" → must fail. */
	coh_posture_t p;
	posture_build(&p, "2-5", "0,1", 3, COH_EPP_BALANCE_PERF, 25, -1);
	int rc = posture_validate(&p, 1000);
	CHECK_EQ_INT(rc, COH_POSTURE_ERR_SQPOLL_IN_GAME_CPUSET,
	             "sqpoll inside game cpuset must be rejected");
	CHECK_EQ_INT(p.state, COH_POSTURE_UNVALIDATED,
	             "failed validate must leave state == UNVALIDATED");
}

static void test_validate_rejects_min_perf_pct_range(void)
{
	coh_posture_t p;
	/* min_perf_pct=150 is out of [0,100]. */
	posture_build(&p, "2-5", "0,1", 6, COH_EPP_BALANCE_PERF, 150, -1);
	int rc = posture_validate(&p, 1000);
	CHECK_EQ_INT(rc, COH_POSTURE_ERR_MIN_PERF_PCT_RANGE,
	             "min_perf_pct > 100 must be rejected");

	/* And negative. */
	posture_build(&p, "2-5", "0,1", 6, COH_EPP_BALANCE_PERF, -1, -1);
	rc = posture_validate(&p, 1000);
	CHECK_EQ_INT(rc, COH_POSTURE_ERR_MIN_PERF_PCT_RANGE,
	             "min_perf_pct < 0 must be rejected");
}

static void test_validate_rejects_cpuset_overlap(void)
{
	coh_posture_t p;
	/* game "2-5" and system "4-7" share CPUs 4-5. */
	posture_build(&p, "2-5", "4-7", 1, COH_EPP_BALANCE_PERF, 25, -1);
	int rc = posture_validate(&p, 1000);
	CHECK_EQ_INT(rc, COH_POSTURE_ERR_CPUSET_OVERLAP,
	             "overlapping cpusets must be rejected");
}

static void test_validate_rejects_empty_game_cpuset(void)
{
	coh_posture_t p;
	posture_build(&p, "", "0-3", -1, COH_EPP_BALANCE_PERF, 25, -1);
	int rc = posture_validate(&p, 1000);
	CHECK_EQ_INT(rc, COH_POSTURE_ERR_CPUSET_EMPTY,
	             "empty game cpuset must be rejected");
}

static void test_validate_rejects_bad_epp(void)
{
	coh_posture_t p;
	posture_build(&p, "2-5", "0,1", 6, (coh_epp_t)99, 25, -1);
	int rc = posture_validate(&p, 1000);
	CHECK_EQ_INT(rc, COH_POSTURE_ERR_EPP_INVALID,
	             "out-of-range EPP must be rejected");
}

static void test_validate_rejects_bad_sqpoll_range(void)
{
	coh_posture_t p;
	/* COH_MAX_CPUS = 64; 64 is out of range. */
	posture_build(&p, "2-5", "0,1", 64, COH_EPP_BALANCE_PERF, 25, -1);
	int rc = posture_validate(&p, 1000);
	CHECK_EQ_INT(rc, COH_POSTURE_ERR_SQPOLL_RANGE,
	             "sqpoll_cpu >= COH_MAX_CPUS must be rejected");
}

static void test_validate_rejects_numa_out_of_range(void)
{
	coh_posture_t p;
	/* NUMA max on a typical host is small; 999 is always out. */
	posture_build(&p, "2-5", "0,1", 6, COH_EPP_BALANCE_PERF, 25, 999);
	int rc = posture_validate(&p, 1000);
	CHECK_EQ_INT(rc, COH_POSTURE_ERR_NUMA_OUT_OF_RANGE,
	             "numa_node far out of range must be rejected");
}

static void test_validate_accepts_sane_posture(void)
{
	coh_posture_t p;
	posture_build(&p, "4-7", "0-3", 1, COH_EPP_PERFORMANCE, 50, -1);
	int rc = posture_validate(&p, 12345);
	CHECK_EQ_INT(rc, 0, "sane posture must validate");
	CHECK_EQ_INT(p.state, COH_POSTURE_VALIDATED,
	             "successful validate must promote state to VALIDATED");
	CHECK(p.validated_at_ms == 12345,
	      "validate must stamp validated_at_ms");
}

static void test_validate_accepts_sqpoll_minus_one(void)
{
	/* sqpoll = -1 means "no affinity"; must pass even if -1 is technically
	 * "not in" game_cpuset (the invariant explicitly excludes -1 from the
	 * overlap check). */
	coh_posture_t p;
	posture_build(&p, "2-5", "0,1", -1, COH_EPP_BALANCE_PERF, 25, -1);
	int rc = posture_validate(&p, 1000);
	CHECK_EQ_INT(rc, 0, "sqpoll=-1 must pass the membership test");
}

static void test_validate_accepts_empty_system_cpuset(void)
{
	/* Empty system_cpuset is legal — it means "inherit root cpuset". */
	coh_posture_t p;
	posture_build(&p, "2-5", "", 6, COH_EPP_BALANCE_PERF, 25, -1);
	int rc = posture_validate(&p, 1000);
	CHECK_EQ_INT(rc, 0, "empty system_cpuset must be legal");
}

static void test_transitions_legal(void)
{
	CHECK(coh_posture_transition_legal(COH_POSTURE_UNINIT,
	                                   COH_POSTURE_UNVALIDATED),
	      "UNINIT→UNVAL legal");
	CHECK(coh_posture_transition_legal(COH_POSTURE_UNVALIDATED,
	                                   COH_POSTURE_VALIDATED),
	      "UNVAL→VALID legal");
	CHECK(coh_posture_transition_legal(COH_POSTURE_VALIDATED,
	                                   COH_POSTURE_COMMITTED),
	      "VALID→COMMIT legal");
	CHECK(coh_posture_transition_legal(COH_POSTURE_VALIDATED,
	                                   COH_POSTURE_UNVALIDATED),
	      "VALID→UNVAL legal (retry path)");
	CHECK(coh_posture_transition_legal(COH_POSTURE_COMMITTED,
	                                   COH_POSTURE_UNVALIDATED),
	      "COMMIT→UNVAL legal (rebuild for next frame)");
}

static void test_transitions_illegal(void)
{
	/* UNINIT is absorbing; no re-entry. */
	CHECK(!coh_posture_transition_legal(COH_POSTURE_UNVALIDATED,
	                                    COH_POSTURE_UNINIT),
	      "UNVAL→UNINIT illegal");
	CHECK(!coh_posture_transition_legal(COH_POSTURE_COMMITTED,
	                                    COH_POSTURE_UNINIT),
	      "COMMIT→UNINIT illegal");

	/* Cannot commit without first validating. */
	CHECK(!coh_posture_transition_legal(COH_POSTURE_UNVALIDATED,
	                                    COH_POSTURE_COMMITTED),
	      "UNVAL→COMMIT illegal (must validate first)");
	CHECK(!coh_posture_transition_legal(COH_POSTURE_UNINIT,
	                                    COH_POSTURE_COMMITTED),
	      "UNINIT→COMMIT illegal");

	/* Cannot skip back to VALIDATED from COMMITTED (must rebuild). */
	CHECK(!coh_posture_transition_legal(COH_POSTURE_COMMITTED,
	                                    COH_POSTURE_VALIDATED),
	      "COMMIT→VALID illegal (this test specifically required by spec)");

	/* Out-of-range inputs return false rather than UB. */
	CHECK(!coh_posture_transition_legal((coh_posture_state_t)99,
	                                    COH_POSTURE_UNVALIDATED),
	      "oob from state returns false");
	CHECK(!coh_posture_transition_legal(COH_POSTURE_UNINIT,
	                                    (coh_posture_state_t)99),
	      "oob to state returns false");
}

static void test_state_str_never_null(void)
{
	CHECK(coh_posture_state_str(COH_POSTURE_UNINIT) != NULL, "UNINIT str not null");
	CHECK(coh_posture_state_str(COH_POSTURE_UNVALIDATED) != NULL, "UNVAL str not null");
	CHECK(coh_posture_state_str(COH_POSTURE_VALIDATED) != NULL, "VALID str not null");
	CHECK(coh_posture_state_str(COH_POSTURE_COMMITTED) != NULL, "COMMIT str not null");
	CHECK(strcmp(coh_posture_state_str((coh_posture_state_t)999), "INVALID") == 0,
	      "unknown state must stringify to INVALID");
}

static void test_equal_idempotent_barrier(void)
{
	coh_posture_t a, b;
	posture_build(&a, "2-5", "0,1", 6, COH_EPP_BALANCE_PERF, 25, -1);
	posture_build(&b, "2-5", "0,1", 6, COH_EPP_BALANCE_PERF, 25, -1);
	CHECK(posture_equal(&a, &b), "two fresh identical postures must be equal");

	/* Change one field. */
	b.sqpoll_cpu = 7;
	CHECK(!posture_equal(&a, &b),
	      "postures differing in sqpoll_cpu must NOT be equal");

	/* State / validated_at_ms intentionally ignored by posture_equal. */
	b.sqpoll_cpu = 6; /* restore */
	b.state = COH_POSTURE_COMMITTED;
	b.validated_at_ms = 999999;
	CHECK(posture_equal(&a, &b),
	      "posture_equal must ignore state + validated_at_ms");
}

static void test_error_str_coverage(void)
{
	/* Every defined error code must have a concrete (non-"UNKNOWN") string. */
	const int codes[] = {
		0,
		COH_POSTURE_ERR_SQPOLL_IN_GAME_CPUSET,
		COH_POSTURE_ERR_CPUSET_OVERLAP,
		COH_POSTURE_ERR_MIN_PERF_PCT_RANGE,
		COH_POSTURE_ERR_EPP_INVALID,
		COH_POSTURE_ERR_NUMA_OUT_OF_RANGE,
		COH_POSTURE_ERR_CPUSET_EMPTY,
		COH_POSTURE_ERR_STATE,
		COH_POSTURE_ERR_SQPOLL_RANGE,
		COH_POSTURE_ERR_CPUSET_SYNTAX,
		COH_POSTURE_ERR_WRITE,
	};
	for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); i++) {
		const char *s = posture_error_str(codes[i]);
		CHECK(s != NULL, "error str never null");
		CHECK(strcmp(s, "UNKNOWN") != 0,
		      "defined error codes must NOT resolve to UNKNOWN");
	}
	CHECK(strcmp(posture_error_str(-9999), "UNKNOWN") == 0,
	      "truly unknown code returns UNKNOWN");
}

/* ---- DRY-RUN commit test ---- */

static void cleanup_dry_run_dir(void)
{
	/* Best-effort — ignore errors. */
	(void)unlink("/tmp/coh_posture_dry/game.cpuset");
	(void)unlink("/tmp/coh_posture_dry/system.cpuset");
	(void)unlink("/tmp/coh_posture_dry/sqpoll");
	(void)unlink("/tmp/coh_posture_dry/epp");
	(void)unlink("/tmp/coh_posture_dry/min_perf_pct");
	(void)unlink("/tmp/coh_posture_dry/game.cpuset.tmp");
	(void)unlink("/tmp/coh_posture_dry/system.cpuset.tmp");
	(void)unlink("/tmp/coh_posture_dry/sqpoll.tmp");
	(void)unlink("/tmp/coh_posture_dry/epp.tmp");
	(void)unlink("/tmp/coh_posture_dry/min_perf_pct.tmp");
}

static int read_dry_file(const char *name, char *buf, size_t bufsz)
{
	char path[256];
	snprintf(path, sizeof(path), "/tmp/coh_posture_dry/%s", name);
	int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
	ssize_t r = read(fd, buf, bufsz - 1);
	close(fd);
	if (r < 0) return -1;
	buf[r] = '\0';
	/* strip trailing newline */
	while (r > 0 && (buf[r - 1] == '\n' || buf[r - 1] == '\r')) {
		buf[--r] = '\0';
	}
	return (int)r;
}

static void test_commit_dry_run_happy_path(void)
{
	/* Precondition: DRY_RUN is enabled via environment. */
	const char *env = getenv("COH_POSTURE_DRY_RUN");
	CHECK(env && env[0] == '1',
	      "test harness must export COH_POSTURE_DRY_RUN=1");

	cleanup_dry_run_dir();

	coh_posture_t p;
	posture_build(&p, "4-7", "0-3", 1, COH_EPP_PERFORMANCE, 50, -1);
	int rc = posture_validate(&p, 5000);
	CHECK_EQ_INT(rc, 0, "sane posture validates");

	rc = posture_commit_atomic(&p);
	CHECK_EQ_INT(rc, 0, "commit on validated posture succeeds");
	CHECK_EQ_INT(p.state, COH_POSTURE_COMMITTED,
	             "successful commit must set state = COMMITTED");

	/* Verify the contents that landed. */
	char buf[64];
	int n = read_dry_file("game.cpuset", buf, sizeof(buf));
	CHECK(n > 0, "game.cpuset file was written");
	CHECK(strcmp(buf, "4-7") == 0, "game.cpuset has the right mask");

	n = read_dry_file("system.cpuset", buf, sizeof(buf));
	CHECK(n > 0, "system.cpuset file was written");
	CHECK(strcmp(buf, "0-3") == 0, "system.cpuset has the right mask");

	n = read_dry_file("sqpoll", buf, sizeof(buf));
	CHECK(n > 0, "sqpoll file was written");
	CHECK(strcmp(buf, "1") == 0, "sqpoll target is 1");

	n = read_dry_file("epp", buf, sizeof(buf));
	CHECK(n > 0, "epp file was written");
	CHECK(strcmp(buf, "performance") == 0, "epp keyword is performance");

	n = read_dry_file("min_perf_pct", buf, sizeof(buf));
	CHECK(n > 0, "min_perf_pct file was written");
	CHECK(strcmp(buf, "50") == 0, "min_perf_pct is 50");
}

static void test_commit_refuses_unvalidated(void)
{
	coh_posture_t p;
	posture_build(&p, "4-7", "0-3", 1, COH_EPP_PERFORMANCE, 50, -1);
	/* Skip validate — commit must refuse. */
	int rc = posture_commit_atomic(&p);
	CHECK_EQ_INT(rc, COH_POSTURE_ERR_STATE,
	             "commit on UNVALIDATED posture must return ERR_STATE");
	CHECK_EQ_INT(p.state, COH_POSTURE_UNVALIDATED,
	             "failed commit must leave state unchanged");
}

/* ---- main ---- */

int main(void)
{
	/* Ensure DRY_RUN is on for this process. If the Makefile didn't set
	 * it, set it here — defensive for manual test runs. */
	setenv("COH_POSTURE_DRY_RUN", "1", 1);

	test_build_sets_unvalidated();
	test_validate_rejects_sqpoll_in_game_cpuset();
	test_validate_rejects_min_perf_pct_range();
	test_validate_rejects_cpuset_overlap();
	test_validate_rejects_empty_game_cpuset();
	test_validate_rejects_bad_epp();
	test_validate_rejects_bad_sqpoll_range();
	test_validate_rejects_numa_out_of_range();
	test_validate_accepts_sane_posture();
	test_validate_accepts_sqpoll_minus_one();
	test_validate_accepts_empty_system_cpuset();
	test_transitions_legal();
	test_transitions_illegal();
	test_state_str_never_null();
	test_equal_idempotent_barrier();
	test_error_str_coverage();
	test_commit_dry_run_happy_path();
	test_commit_refuses_unvalidated();

	fprintf(stderr,
	        "{\"coherence\":\"posture_test\",\"run\":%d,\"fail\":%d}\n",
	        tests_run, tests_failed);

	if (tests_failed > 0) return 1;
	return 0;
}

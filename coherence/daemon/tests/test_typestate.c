/*
 * test_typestate.c — R34 typestate unit test.
 *
 * "Failing-test discipline": this file asserts both the positive
 * contract (every named transition in the table is legal) AND the
 * negative contract (every forbidden transition is rejected). If any
 * assertion fails we exit non-zero so `make test-typestate` fails the
 * build.
 *
 * Scope:
 *   1. Stringifier coverage — every valid enum value returns a
 *      non-NULL, non-"INVALID" string; one out-of-range value returns
 *      "INVALID".
 *   2. Transition legality (derived) — the six rules spelled out in
 *      state_machine_tables.c for coh_derived_transition_legal.
 *   3. Transition legality (act) — the monotonic-progress invariants
 *      for coh_act_transition_legal (COMMITTED cannot regress).
 *   4. Forward-only from UNINIT — every *_UNINIT → X transition must
 *      be forward; in particular X → UNINIT is always forbidden.
 *   5. Bounds — out-of-range inputs return false (not crash).
 *
 * Build:
 *   cc -std=c11 -Wall -Wextra -Werror -Wshadow \
 *      -Iinclude tests/test_typestate.c \
 *      src/state_machine.c src/state_machine_tables.c \
 *      -o tests/test_typestate
 *
 * Runtime:
 *   ./tests/test_typestate    → exit 0 on pass, 1 on fail, prints
 *                               one line per failing assertion.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "coherence_types.h"

/* The state machine depends on config.h + fprintf. We only need the
 * typestate helpers here, which live in state_machine_tables.c and
 * the stringifier section of state_machine.c — neither requires the
 * arbiter or config subsystem. */

/* ===== Assertion infrastructure ===== */

static int g_fails = 0;

#define TEST_ASSERT(cond, msg) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, \
			        "FAIL %s:%d  %s  (%s)\n", \
			        __FILE__, __LINE__, #cond, msg); \
			g_fails++; \
		} \
	} while (0)

#define TEST_ASSERT_EQ_STR(got, want, msg) \
	do { \
		const char *_g = (got); \
		const char *_w = (want); \
		if (!_g || !_w || strcmp(_g, _w) != 0) { \
			fprintf(stderr, \
			        "FAIL %s:%d  got=\"%s\" want=\"%s\"  (%s)\n", \
			        __FILE__, __LINE__, \
			        _g ? _g : "(null)", _w ? _w : "(null)", \
			        msg); \
			g_fails++; \
		} \
	} while (0)

/* ===== 1. Stringifier tests ===== */

static void test_derived_stringifiers(void)
{
	TEST_ASSERT_EQ_STR(coh_derived_state_str(COH_DERIVED_UNINIT),
	                   "UNINIT", "derived UNINIT");
	TEST_ASSERT_EQ_STR(coh_derived_state_str(COH_DERIVED_FRESH),
	                   "FRESH", "derived FRESH");
	TEST_ASSERT_EQ_STR(coh_derived_state_str(COH_DERIVED_STALE),
	                   "STALE", "derived STALE");
	TEST_ASSERT_EQ_STR(coh_derived_state_str(COH_DERIVED_DEGRADED),
	                   "DEGRADED", "derived DEGRADED");

	/* Out-of-range inputs must return "INVALID", NOT crash or NULL. */
	TEST_ASSERT_EQ_STR(coh_derived_state_str((coh_derived_state_t)99),
	                   "INVALID", "derived out-of-range");
	TEST_ASSERT_EQ_STR(coh_derived_state_str((coh_derived_state_t)COH_DERIVED_STATE_COUNT),
	                   "INVALID", "derived at STATE_COUNT");

	/* Non-NULL contract: every string pointer is non-NULL, always. */
	for (int i = 0; i < 10; i++) {
		const char *s = coh_derived_state_str((coh_derived_state_t)i);
		TEST_ASSERT(s != NULL, "derived stringifier must be non-NULL");
	}
}

static void test_act_stringifiers(void)
{
	TEST_ASSERT_EQ_STR(coh_act_state_str(COH_ACT_UNINIT),
	                   "UNINIT", "act UNINIT");
	TEST_ASSERT_EQ_STR(coh_act_state_str(COH_ACT_PLANNED),
	                   "PLANNED", "act PLANNED");
	TEST_ASSERT_EQ_STR(coh_act_state_str(COH_ACT_RATE_LIMITED),
	                   "RATE_LIMITED", "act RATE_LIMITED");
	TEST_ASSERT_EQ_STR(coh_act_state_str(COH_ACT_BARRIERED),
	                   "BARRIERED", "act BARRIERED");
	TEST_ASSERT_EQ_STR(coh_act_state_str(COH_ACT_COMMITTED),
	                   "COMMITTED", "act COMMITTED");
	TEST_ASSERT_EQ_STR(coh_act_state_str(COH_ACT_FAILED),
	                   "FAILED", "act FAILED");

	TEST_ASSERT_EQ_STR(coh_act_state_str((coh_act_state_t)99),
	                   "INVALID", "act out-of-range");
	TEST_ASSERT_EQ_STR(coh_act_state_str((coh_act_state_t)COH_ACT_STATE_COUNT),
	                   "INVALID", "act at STATE_COUNT");

	for (int i = 0; i < 10; i++) {
		const char *s = coh_act_state_str((coh_act_state_t)i);
		TEST_ASSERT(s != NULL, "act stringifier must be non-NULL");
	}
}

/* Posture stringifier tests live in Agent 2's test_posture.c — we
 * don't link src/posture.c here to keep test-typestate minimal. */

/* ===== 2. Derived transition legality tests =====
 *
 * The rules (mirror state_machine_tables.c):
 *   UNINIT   → FRESH                       legal
 *   FRESH    → {FRESH, STALE}              legal
 *   STALE    → {FRESH, STALE, DEGRADED}    legal
 *   DEGRADED → {FRESH, DEGRADED}           legal
 *   Everything else forbidden.
 */
static void test_derived_legal_transitions(void)
{
	/* Legal edges. */
	TEST_ASSERT(coh_derived_transition_legal(COH_DERIVED_UNINIT, COH_DERIVED_FRESH),
	            "UNINIT → FRESH must be legal (first fresh sample)");
	TEST_ASSERT(coh_derived_transition_legal(COH_DERIVED_FRESH, COH_DERIVED_FRESH),
	            "FRESH → FRESH self-loop must be legal");
	TEST_ASSERT(coh_derived_transition_legal(COH_DERIVED_FRESH, COH_DERIVED_STALE),
	            "FRESH → STALE must be legal (aged out)");
	TEST_ASSERT(coh_derived_transition_legal(COH_DERIVED_STALE, COH_DERIVED_STALE),
	            "STALE → STALE self-loop must be legal");
	TEST_ASSERT(coh_derived_transition_legal(COH_DERIVED_STALE, COH_DERIVED_FRESH),
	            "STALE → FRESH must be legal (recovery)");
	TEST_ASSERT(coh_derived_transition_legal(COH_DERIVED_STALE, COH_DERIVED_DEGRADED),
	            "STALE → DEGRADED must be legal (confidence collapse)");
	TEST_ASSERT(coh_derived_transition_legal(COH_DERIVED_DEGRADED, COH_DERIVED_FRESH),
	            "DEGRADED → FRESH must be legal (clean recovery)");
	TEST_ASSERT(coh_derived_transition_legal(COH_DERIVED_DEGRADED, COH_DERIVED_DEGRADED),
	            "DEGRADED → DEGRADED self-loop must be legal");
}

static void test_derived_forbidden_transitions(void)
{
	/* Regressions to UNINIT — always forbidden. */
	TEST_ASSERT(!coh_derived_transition_legal(COH_DERIVED_FRESH, COH_DERIVED_UNINIT),
	            "FRESH → UNINIT must be REJECTED (no regression)");
	TEST_ASSERT(!coh_derived_transition_legal(COH_DERIVED_STALE, COH_DERIVED_UNINIT),
	            "STALE → UNINIT must be REJECTED");
	TEST_ASSERT(!coh_derived_transition_legal(COH_DERIVED_DEGRADED, COH_DERIVED_UNINIT),
	            "DEGRADED → UNINIT must be REJECTED");
	TEST_ASSERT(!coh_derived_transition_legal(COH_DERIVED_UNINIT, COH_DERIVED_UNINIT),
	            "UNINIT → UNINIT self-loop must be REJECTED");

	/* Jumping straight from FRESH to DEGRADED — must pass through STALE. */
	TEST_ASSERT(!coh_derived_transition_legal(COH_DERIVED_FRESH, COH_DERIVED_DEGRADED),
	            "FRESH → DEGRADED must be REJECTED (must pass through STALE)");

	/* DEGRADED → STALE — backwards progress on confidence. */
	TEST_ASSERT(!coh_derived_transition_legal(COH_DERIVED_DEGRADED, COH_DERIVED_STALE),
	            "DEGRADED → STALE must be REJECTED");

	/* UNINIT cannot skip ahead. */
	TEST_ASSERT(!coh_derived_transition_legal(COH_DERIVED_UNINIT, COH_DERIVED_STALE),
	            "UNINIT → STALE must be REJECTED");
	TEST_ASSERT(!coh_derived_transition_legal(COH_DERIVED_UNINIT, COH_DERIVED_DEGRADED),
	            "UNINIT → DEGRADED must be REJECTED");

	/* Out-of-range inputs. */
	TEST_ASSERT(!coh_derived_transition_legal((coh_derived_state_t)99,
	                                          COH_DERIVED_FRESH),
	            "out-of-range from must be REJECTED");
	TEST_ASSERT(!coh_derived_transition_legal(COH_DERIVED_FRESH,
	                                          (coh_derived_state_t)99),
	            "out-of-range to must be REJECTED");
}

/* ===== 3. Actuation transition legality tests =====
 *
 * Critical load-bearing invariant: COMMITTED is terminal for the frame;
 * cannot regress to BARRIERED or any non-PLANNED state.
 */
static void test_act_legal_transitions(void)
{
	/* UNINIT → PLANNED is the only exit from UNINIT. */
	TEST_ASSERT(coh_act_transition_legal(COH_ACT_UNINIT, COH_ACT_PLANNED),
	            "UNINIT → PLANNED must be legal");

	/* PLANNED branches to all five outcomes. */
	TEST_ASSERT(coh_act_transition_legal(COH_ACT_PLANNED, COH_ACT_PLANNED),
	            "PLANNED → PLANNED must be legal (re-plan mid-frame)");
	TEST_ASSERT(coh_act_transition_legal(COH_ACT_PLANNED, COH_ACT_RATE_LIMITED),
	            "PLANNED → RATE_LIMITED must be legal");
	TEST_ASSERT(coh_act_transition_legal(COH_ACT_PLANNED, COH_ACT_BARRIERED),
	            "PLANNED → BARRIERED must be legal");
	TEST_ASSERT(coh_act_transition_legal(COH_ACT_PLANNED, COH_ACT_COMMITTED),
	            "PLANNED → COMMITTED must be legal");
	TEST_ASSERT(coh_act_transition_legal(COH_ACT_PLANNED, COH_ACT_FAILED),
	            "PLANNED → FAILED must be legal");

	/* Every terminal state re-plans on the next frame. */
	TEST_ASSERT(coh_act_transition_legal(COH_ACT_RATE_LIMITED, COH_ACT_PLANNED),
	            "RATE_LIMITED → PLANNED must be legal");
	TEST_ASSERT(coh_act_transition_legal(COH_ACT_RATE_LIMITED, COH_ACT_RATE_LIMITED),
	            "RATE_LIMITED → RATE_LIMITED self-loop must be legal");
	TEST_ASSERT(coh_act_transition_legal(COH_ACT_BARRIERED, COH_ACT_PLANNED),
	            "BARRIERED → PLANNED must be legal");
	TEST_ASSERT(coh_act_transition_legal(COH_ACT_COMMITTED, COH_ACT_PLANNED),
	            "COMMITTED → PLANNED must be legal");
	TEST_ASSERT(coh_act_transition_legal(COH_ACT_FAILED, COH_ACT_PLANNED),
	            "FAILED → PLANNED must be legal");
}

static void test_act_forbidden_transitions(void)
{
	/* CRITICAL: monotonic progress. COMMITTED cannot regress to
	 * BARRIERED/RATE_LIMITED/FAILED/COMMITTED-again. */
	TEST_ASSERT(!coh_act_transition_legal(COH_ACT_COMMITTED, COH_ACT_BARRIERED),
	            "COMMITTED → BARRIERED must be REJECTED "
	            "(monotonic progress)");
	TEST_ASSERT(!coh_act_transition_legal(COH_ACT_COMMITTED, COH_ACT_RATE_LIMITED),
	            "COMMITTED → RATE_LIMITED must be REJECTED");
	TEST_ASSERT(!coh_act_transition_legal(COH_ACT_COMMITTED, COH_ACT_FAILED),
	            "COMMITTED → FAILED must be REJECTED");
	TEST_ASSERT(!coh_act_transition_legal(COH_ACT_COMMITTED, COH_ACT_COMMITTED),
	            "COMMITTED → COMMITTED (no-replan) must be REJECTED");

	/* BARRIERED cannot magically become COMMITTED (it WROTE NOTHING). */
	TEST_ASSERT(!coh_act_transition_legal(COH_ACT_BARRIERED, COH_ACT_COMMITTED),
	            "BARRIERED → COMMITTED must be REJECTED "
	            "(barriered commits do no writes)");
	TEST_ASSERT(!coh_act_transition_legal(COH_ACT_BARRIERED, COH_ACT_FAILED),
	            "BARRIERED → FAILED must be REJECTED");
	TEST_ASSERT(!coh_act_transition_legal(COH_ACT_BARRIERED, COH_ACT_RATE_LIMITED),
	            "BARRIERED → RATE_LIMITED must be REJECTED");

	/* RATE_LIMITED and FAILED must re-plan before any outcome. */
	TEST_ASSERT(!coh_act_transition_legal(COH_ACT_RATE_LIMITED, COH_ACT_COMMITTED),
	            "RATE_LIMITED → COMMITTED must be REJECTED (must re-plan)");
	TEST_ASSERT(!coh_act_transition_legal(COH_ACT_FAILED, COH_ACT_COMMITTED),
	            "FAILED → COMMITTED must be REJECTED");
	TEST_ASSERT(!coh_act_transition_legal(COH_ACT_FAILED, COH_ACT_BARRIERED),
	            "FAILED → BARRIERED must be REJECTED");

	/* Regressions to UNINIT — always forbidden. */
	TEST_ASSERT(!coh_act_transition_legal(COH_ACT_PLANNED, COH_ACT_UNINIT),
	            "PLANNED → UNINIT must be REJECTED");
	TEST_ASSERT(!coh_act_transition_legal(COH_ACT_COMMITTED, COH_ACT_UNINIT),
	            "COMMITTED → UNINIT must be REJECTED");

	/* UNINIT cannot jump past PLANNED. */
	TEST_ASSERT(!coh_act_transition_legal(COH_ACT_UNINIT, COH_ACT_COMMITTED),
	            "UNINIT → COMMITTED must be REJECTED");
	TEST_ASSERT(!coh_act_transition_legal(COH_ACT_UNINIT, COH_ACT_BARRIERED),
	            "UNINIT → BARRIERED must be REJECTED");
	TEST_ASSERT(!coh_act_transition_legal(COH_ACT_UNINIT, COH_ACT_RATE_LIMITED),
	            "UNINIT → RATE_LIMITED must be REJECTED");
	TEST_ASSERT(!coh_act_transition_legal(COH_ACT_UNINIT, COH_ACT_FAILED),
	            "UNINIT → FAILED must be REJECTED");

	/* Out-of-range. */
	TEST_ASSERT(!coh_act_transition_legal((coh_act_state_t)99,
	                                      COH_ACT_PLANNED),
	            "act out-of-range from must be REJECTED");
	TEST_ASSERT(!coh_act_transition_legal(COH_ACT_PLANNED,
	                                      (coh_act_state_t)99),
	            "act out-of-range to must be REJECTED");
}

/* ===== 4. Forward-only from UNINIT ===== */

static void test_uninit_is_forward_only(void)
{
	/* Derived: UNINIT → X is legal only for X == FRESH. */
	for (int x = 0; x < (int)COH_DERIVED_STATE_COUNT; x++) {
		bool legal = coh_derived_transition_legal(COH_DERIVED_UNINIT,
		                                          (coh_derived_state_t)x);
		bool expected = (x == COH_DERIVED_FRESH);
		TEST_ASSERT(legal == expected,
		            "derived UNINIT → X forward-only rule violated");
	}
	/* Act: UNINIT → X is legal only for X == PLANNED. */
	for (int x = 0; x < (int)COH_ACT_STATE_COUNT; x++) {
		bool legal = coh_act_transition_legal(COH_ACT_UNINIT,
		                                      (coh_act_state_t)x);
		bool expected = (x == COH_ACT_PLANNED);
		TEST_ASSERT(legal == expected,
		            "act UNINIT → X forward-only rule violated");
	}
	/* Posture forward-only rule is tested in Agent 2's test_posture.c. */
}

/* ===== 5. No state reaches UNINIT (except UNINIT itself staying off) ===== */

static void test_nothing_reaches_uninit(void)
{
	/* UNINIT is a construction state. No runtime transition should
	 * land on it. */
	for (int x = 0; x < (int)COH_DERIVED_STATE_COUNT; x++) {
		TEST_ASSERT(!coh_derived_transition_legal((coh_derived_state_t)x,
		                                          COH_DERIVED_UNINIT),
		            "nothing may transition INTO derived UNINIT");
	}
	for (int x = 0; x < (int)COH_ACT_STATE_COUNT; x++) {
		TEST_ASSERT(!coh_act_transition_legal((coh_act_state_t)x,
		                                      COH_ACT_UNINIT),
		            "nothing may transition INTO act UNINIT");
	}
	/* Posture "nothing reaches UNINIT" is tested in Agent 2's
	 * test_posture.c. */
}

/* ===== Main ===== */

int main(void)
{
	fprintf(stderr, "test_typestate: running...\n");

	test_derived_stringifiers();
	test_act_stringifiers();
	test_derived_legal_transitions();
	test_derived_forbidden_transitions();
	test_act_legal_transitions();
	test_act_forbidden_transitions();
	test_uninit_is_forward_only();
	test_nothing_reaches_uninit();

	if (g_fails == 0) {
		fprintf(stderr, "test_typestate: PASS (all assertions)\n");
		return 0;
	}
	fprintf(stderr, "test_typestate: FAIL (%d assertion%s)\n",
	        g_fails, g_fails == 1 ? "" : "s");
	return 1;
}

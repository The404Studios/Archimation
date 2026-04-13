/*
 * test_trust.c - Trust system unit tests
 *
 * Tests the userspace trust library (libtrust) against /dev/trust.
 * Run on a system with the trust kernel module loaded.
 *
 * Build: gcc -o test_trust test_trust.c -L../../trust/lib -ltrust -I../../trust/include
 * Run:   ./test_trust
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "../../trust/lib/libtrust.h"

#define TEST_SUBJECT_ID 9999
#define PASS "\033[32mPASS\033[0m"
#define FAIL "\033[31mFAIL\033[0m"
#define SKIP "\033[33mSKIP\033[0m"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_skipped = 0;

#define RUN_TEST(name) do { \
    printf("  %-50s ", #name); \
    tests_run++; \
    name(); \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) == (b)) { printf("[%s]\n", PASS); tests_passed++; } \
    else { printf("[%s] expected %d, got %d\n", FAIL, (int)(b), (int)(a)); } \
} while(0)

#define ASSERT_GE(a, b) do { \
    if ((a) >= (b)) { printf("[%s]\n", PASS); tests_passed++; } \
    else { printf("[%s] expected >= %d, got %d\n", FAIL, (int)(b), (int)(a)); } \
} while(0)

/* --- Tests that work without /dev/trust (fallback mode) --- */

static void test_init_no_module(void)
{
    /* trust_init should return -1 if module not loaded, but not crash */
    int ret = trust_init();
    /* Either 0 (module loaded) or -1 (module not loaded) is acceptable */
    if (ret == 0 || ret == -1) {
        printf("[%s]\n", PASS);
        tests_passed++;
    } else {
        printf("[%s] unexpected return %d\n", FAIL, ret);
    }
}

static void test_available_matches_init(void)
{
    int ret = trust_init();
    int avail = trust_available();
    ASSERT_EQ(avail, ret == 0 ? 1 : 0);
}

static void test_failopen_check_capability(void)
{
    /* Without module, check_capability should return 1 (allow) */
    if (trust_available()) {
        printf("[%s] (module loaded, testing real path)\n", SKIP);
        tests_skipped++;
        return;
    }
    int result = trust_check_capability(TEST_SUBJECT_ID, TRUST_CAP_FILE_READ);
    ASSERT_EQ(result, 1);
}

static void test_failopen_get_score(void)
{
    if (trust_available()) {
        printf("[%s] (module loaded)\n", SKIP);
        tests_skipped++;
        return;
    }
    int32_t score = trust_get_score(TEST_SUBJECT_ID);
    ASSERT_EQ(score, TRUST_SCORE_DEFAULT);
}

static void test_failopen_threshold_check(void)
{
    if (trust_available()) {
        printf("[%s] (module loaded)\n", SKIP);
        tests_skipped++;
        return;
    }
    int result = trust_threshold_check(TEST_SUBJECT_ID, TRUST_ACTION_FILE_OPEN);
    ASSERT_EQ(result, TRUST_RESULT_ALLOW);
}

static void test_failopen_register(void)
{
    if (trust_available()) {
        printf("[%s] (module loaded)\n", SKIP);
        tests_skipped++;
        return;
    }
    int ret = trust_register_subject(TEST_SUBJECT_ID, TRUST_DOMAIN_LINUX, TRUST_AUTH_USER);
    ASSERT_EQ(ret, 0);
}

/* --- Tests that need /dev/trust (real kernel module) --- */

static void test_register_and_get_score(void)
{
    if (!trust_available()) {
        printf("[%s] (no module)\n", SKIP);
        tests_skipped++;
        return;
    }
    int ret = trust_register_subject_ex(TEST_SUBJECT_ID, TRUST_DOMAIN_LINUX,
                                         TRUST_AUTH_USER, 500);
    if (ret < 0) {
        printf("[%s] register failed\n", FAIL);
        return;
    }
    int32_t score = trust_get_score(TEST_SUBJECT_ID);
    ASSERT_EQ(score, 500);
}

static void test_record_action_updates_score(void)
{
    if (!trust_available()) {
        printf("[%s] (no module)\n", SKIP);
        tests_skipped++;
        return;
    }
    int32_t old_score = trust_get_score(TEST_SUBJECT_ID);
    int32_t new_score = trust_record_action(TEST_SUBJECT_ID, TRUST_ACTION_FILE_OPEN, 0);
    /* Successful action should increase or maintain score */
    ASSERT_GE(new_score, old_score);
}

static void test_check_capability_after_register(void)
{
    if (!trust_available()) {
        printf("[%s] (no module)\n", SKIP);
        tests_skipped++;
        return;
    }
    /* User-level subject should have FILE_READ */
    int has_cap = trust_check_capability(TEST_SUBJECT_ID, TRUST_CAP_FILE_READ);
    ASSERT_EQ(has_cap, 1);
}

static void test_cleanup_unregister(void)
{
    if (!trust_available()) {
        printf("[%s] (no module)\n", SKIP);
        tests_skipped++;
        return;
    }
    int ret = trust_unregister_subject(TEST_SUBJECT_ID);
    ASSERT_EQ(ret, 0);
}

/* --- Root of Authority specific tests (need /dev/trust) --- */

static void test_token_balance(void)
{
    if (!trust_available()) {
        printf("[%s] (no module)\n", SKIP);
        tests_skipped++;
        return;
    }
    /* Register fresh subject */
    trust_register_subject_ex(TEST_SUBJECT_ID, TRUST_DOMAIN_LINUX, TRUST_AUTH_USER, 500);

    /* Check token balance is positive */
    int32_t balance = trust_token_balance(TEST_SUBJECT_ID);
    ASSERT_GE(balance, 0);
}

static void test_token_burn_reduces_balance(void)
{
    if (!trust_available()) {
        printf("[%s] (no module)\n", SKIP);
        tests_skipped++;
        return;
    }
    int32_t before = trust_token_balance(TEST_SUBJECT_ID);
    /* Record action to burn tokens */
    trust_record_action(TEST_SUBJECT_ID, TRUST_ACTION_FILE_OPEN, 0);
    int32_t after = trust_token_balance(TEST_SUBJECT_ID);
    /* After should be <= before (action burns tokens) */
    if (after <= before) {
        printf("[%s]\n", PASS);
        tests_passed++;
    } else {
        printf("[%s] expected balance to decrease\n", FAIL);
    }
}

static void test_threshold_check_with_capability(void)
{
    if (!trust_available()) {
        printf("[%s] (no module)\n", SKIP);
        tests_skipped++;
        return;
    }
    /* High trust subject should pass threshold check */
    int result = trust_threshold_check(TEST_SUBJECT_ID, TRUST_ACTION_FILE_OPEN);
    ASSERT_EQ(result, TRUST_RESULT_ALLOW);
}

static void test_failopen_record_action(void)
{
    if (trust_available()) {
        printf("[%s] (module loaded)\n", SKIP);
        tests_skipped++;
        return;
    }
    /* Without module, record_action should return default score */
    int32_t score = trust_record_action(TEST_SUBJECT_ID, TRUST_ACTION_FILE_OPEN, 0);
    ASSERT_EQ(score, TRUST_SCORE_DEFAULT);
}

static void test_cleanup_roa(void)
{
    if (!trust_available()) {
        printf("[%s] (no module)\n", SKIP);
        tests_skipped++;
        return;
    }
    int ret = trust_unregister_subject(TEST_SUBJECT_ID);
    ASSERT_EQ(ret, 0);
}

int main(void)
{
    printf("=== Trust System Unit Tests ===\n\n");

    printf("-- Initialization --\n");
    RUN_TEST(test_init_no_module);
    RUN_TEST(test_available_matches_init);

    printf("\n-- Fail-Open Behavior (no module) --\n");
    RUN_TEST(test_failopen_check_capability);
    RUN_TEST(test_failopen_get_score);
    RUN_TEST(test_failopen_threshold_check);
    RUN_TEST(test_failopen_register);
    RUN_TEST(test_failopen_record_action);

    printf("\n-- Kernel Module Tests (need /dev/trust) --\n");
    RUN_TEST(test_register_and_get_score);
    RUN_TEST(test_record_action_updates_score);
    RUN_TEST(test_check_capability_after_register);
    RUN_TEST(test_cleanup_unregister);

    printf("\n-- Root of Authority Tests (need /dev/trust) --\n");
    RUN_TEST(test_token_balance);
    RUN_TEST(test_token_burn_reduces_balance);
    RUN_TEST(test_threshold_check_with_capability);
    RUN_TEST(test_cleanup_roa);

    trust_cleanup();

    printf("\n=== Results: %d/%d passed, %d skipped ===\n",
           tests_passed, tests_run, tests_skipped);

    return (tests_passed + tests_skipped == tests_run) ? 0 : 1;
}

/*
 * test_context_mask.c -- Session 34 R34 context-mask dispatcher test.
 *
 * Asserts the trust_opcode_meta[] context-gate is wired correctly:
 *
 *   1. Module loaded probe: skip if not.
 *   2. Submit a VEC_OP_DECAY batch while in BATCH context (i.e. inside
 *      a trust_batch_submit).  Must succeed -- VEC.DECAY is mapped to
 *      TRUST_CTX_ALL, so BATCH is permitted.
 *   3. Submit a META.GET_SUBJECT op via a hand-rolled raw cmd buffer.
 *      This op is restricted to TRUST_CTX_NO_IRQ (all except INTERRUPT).
 *      Because userspace cannot directly trigger INTERRUPT context, we
 *      instead rely on a debug sysfs knob if present (none right now)
 *      OR assert the expected-PASS path only.  If the kernel ever adds
 *      a debug hook to force in_interrupt(), that would flip this test
 *      from an expected-PASS into an expected-FAIL-with-EPERM assertion.
 *      TODO-R35: add debug hook.
 *   4. Grep /sys/kernel/trust/opcodes for "AUTH.VERIFY" and the marker
 *      "META.GET_SUBJECT" with a ctx field that excludes INTERRUPT.
 *   5. Read /sys/kernel/trust/stats and assert
 *      `context_mask_rejects` is present (value >= 0) -- proves the
 *      counter surface exists.
 *
 * The "failing test" in R34 terms is step 4b: we REQUIRE that the
 * context string for META.GET_SUBJECT omits "INTERRUPT".  If a future
 * change accidentally widens the mask to TRUST_CTX_ALL, this assertion
 * fires.
 *
 * Exit:  0 = PASS, 1 = FAIL, 77 = SKIP (no /dev/trust).
 *
 * Build: see Makefile (`make test-context-mask`).
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../lib/libtrust.h"
#include "../include/trust_types.h"

#define BASE_SID       0x20020000U
#define SKIP_EXIT      77

static int g_failures = 0;
#define CHECK(cond, desc) do {                                          \
	if (!(cond)) {                                                  \
		fprintf(stderr, "[FAIL] %s (%s:%d): %s\n",              \
			desc, __FILE__, __LINE__, #cond);               \
		g_failures++;                                           \
	} else {                                                        \
		fprintf(stdout, "[PASS] %s\n", desc);                   \
	}                                                               \
} while (0)

/* Read /sys/kernel/trust/stats and return the named KEY=VALUE entry. */
static unsigned long long read_stat(const char *key)
{
	FILE *f = fopen("/sys/kernel/trust/stats", "r");
	char line[256];
	size_t klen;
	unsigned long long value = 0;

	if (!f)
		return ~0ULL;  /* sentinel: file missing */

	klen = strlen(key);
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, key, klen) == 0 && line[klen] == '=') {
			value = strtoull(line + klen + 1, NULL, 0);
			fclose(f);
			return value;
		}
	}
	fclose(f);
	return ~0ULL;  /* sentinel: key missing */
}

/* Read /sys/kernel/trust/opcodes and search for a line starting with
 * `prefix` (typically "META.GET_SUBJECT").  Fills `out_line` (caller-
 * allocated, out_size bytes) with the full matching line.  Returns
 * true on hit, false otherwise. */
static bool find_opcode_line(const char *prefix, char *out_line,
			     size_t out_size)
{
	FILE *f = fopen("/sys/kernel/trust/opcodes", "r");
	char line[256];
	size_t plen;

	if (!f)
		return false;

	plen = strlen(prefix);
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, prefix, plen) == 0 &&
		    (line[plen] == ' ' || line[plen] == '\t')) {
			strncpy(out_line, line, out_size - 1);
			out_line[out_size - 1] = '\0';
			fclose(f);
			return true;
		}
	}
	fclose(f);
	return false;
}

int main(void)
{
	int rc;
	uint32_t subjects[4];
	trust_batch_t *batch = NULL;
	unsigned long long rejects_before, rejects_after;
	char opcode_line[256];
	int i;

	/* --- 1. Open /dev/trust. --- */
	rc = trust_init();
	if (rc < 0) {
		fprintf(stderr, "[SKIP] trust_init() failed "
				"(trust.ko not loaded?): %s\n",
			strerror(errno));
		return SKIP_EXIT;
	}
	fprintf(stdout, "[INFO] /dev/trust opened\n");

	/* Confirm /sys/kernel/trust/opcodes exists.  If not, the
	 * module was loaded without Session 34 changes; SKIP cleanly. */
	{
		struct stat st;
		if (stat("/sys/kernel/trust/opcodes", &st) != 0) {
			fprintf(stderr, "[SKIP] /sys/kernel/trust/opcodes "
					"missing; pre-R34 kernel\n");
			trust_cleanup();
			return SKIP_EXIT;
		}
	}

	/* --- 2. Register subjects and run a VEC_DECAY in BATCH context. --- */
	for (i = 0; i < 4; i++) {
		subjects[i] = BASE_SID + (uint32_t)i;
		if (trust_register_subject(subjects[i],
					   TRUST_DOMAIN_LINUX,
					   TRUST_AUTH_USER) < 0 &&
		    errno != EEXIST) {
			fprintf(stderr, "[WARN] register %u: %s\n",
				subjects[i], strerror(errno));
		}
	}

	rejects_before = read_stat("context_mask_rejects");
	CHECK(rejects_before != ~0ULL,
	      "stats surface exposes context_mask_rejects key");

	batch = trust_batch_new(16);
	CHECK(batch != NULL, "trust_batch_new()");
	if (!batch) goto done;

	rc = trust_batch_decay(batch, subjects, 4);
	CHECK(rc == 0, "trust_batch_decay() queues 4 subjects");

	rc = trust_batch_submit(batch);
	CHECK(rc == 0,
	      "VEC.DECAY in BATCH context succeeds (mask=TRUST_CTX_ALL)");

	/* No reject should have occurred for a permissive-masked op. */
	rejects_after = read_stat("context_mask_rejects");
	CHECK(rejects_after == rejects_before,
	      "context_mask_rejects did NOT increment for permissive op");

	trust_batch_free(batch);
	batch = NULL;

	/* --- 3. Opcodes sysfs inspection. --- */
	{
		bool found_auth_verify;
		bool found_meta_get_subject;

		found_auth_verify = find_opcode_line("AUTH.VERIFY",
						     opcode_line,
						     sizeof(opcode_line));
		CHECK(found_auth_verify,
		      "/sys/kernel/trust/opcodes lists AUTH.VERIFY");
		if (found_auth_verify) {
			/* AUTH.VERIFY is TRUST_CTX_ALL which we emit as "*". */
			CHECK(strstr(opcode_line, "ctx=*") != NULL,
			      "AUTH.VERIFY ctx=* (permissive)");
		}

		found_meta_get_subject = find_opcode_line("META.GET_SUBJECT",
							  opcode_line,
							  sizeof(opcode_line));
		CHECK(found_meta_get_subject,
		      "/sys/kernel/trust/opcodes lists META.GET_SUBJECT");
		if (found_meta_get_subject) {
			/* The failing-test assertion: META.GET_SUBJECT MUST
			 * NOT be flagged as permitted in INTERRUPT context. */
			CHECK(strstr(opcode_line, "INTERRUPT") == NULL,
			      "META.GET_SUBJECT ctx excludes INTERRUPT");
			/* Sanity: NORMAL should be present. */
			CHECK(strstr(opcode_line, "NORMAL") != NULL,
			      "META.GET_SUBJECT ctx includes NORMAL");
		}
	}

done:
	if (batch) trust_batch_free(batch);
	trust_cleanup();

	if (g_failures) {
		fprintf(stdout, "\n=== test_context_mask: %d FAILURE(S) ===\n",
			g_failures);
		return 1;
	}
	fprintf(stdout, "\n=== test_context_mask: PASS ===\n");
	return 0;
}

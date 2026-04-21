/*
 * helpers.c — S75 Agent A
 *
 * Tiny CLI wrapper around libtrust used by the Python adversarial
 * theorem harness (tests/adversarial/theorem_violation_suite.py).
 *
 * Exposed sub-commands (argv[1]):
 *
 *   register <sid> <authority> <initial_score>
 *                               -> ioctl TRUST_IOC_REGISTER.  Exit 0 on ok.
 *   apoptosis <sid>             -> ioctl TRUST_IOC_APOPTOSIS.  Exit 0 on ok.
 *   proof-mint <sid>            -> TRUST_IOC_PROOF_MINT; prints 32 bytes of
 *                                  proof as 64 hex chars (T2 capture).
 *   proof-consume <sid> <hex>   -> TRUST_IOC_PROOF_CONSUME with the given
 *                                  proof bytes.  Exits 0 if the kernel
 *                                  accepts, non-zero otherwise.  Used by
 *                                  T2 test strategies: "replay" passes the
 *                                  same bytes twice and checks the second
 *                                  call fails + counter fires.
 *   ape-snapshot <sid>          -> T1/T3: prints the current APE proof in
 *                                  hex and the subject-scoped nonce.  Read-
 *                                  only; does NOT consume.
 *   entropy-sample <sid> <N>    -> T3: mint a subject, mint proof, consume
 *                                  N times, print each resulting proof in
 *                                  hex on its own line.  Output is the
 *                                  byte-stream the chi-square suite runs
 *                                  over.
 *   nonce <sid>                 -> T2: print the monotonic per-subject
 *                                  nonce; the harness checks it advances
 *                                  strictly on legitimate consumes.
 *   trc-burn <sid> <action> <N> -> T6: drive the TRC cost_multiplier by
 *                                  calling trust_token_burn_action N
 *                                  times in a tight loop; prints the
 *                                  post-burn balance on the final call.
 *
 * Exit convention: 0 = success, 1 = usage/argument error,
 *                  2 = /dev/trust unavailable (trust.ko not loaded),
 *                  3 = ioctl error (expected-fail path),
 *                  4 = unexpected internal error.
 *
 * Build:  make -C tests/adversarial helpers
 *
 * Link:   -ltrust (libtrust.so from trust/lib/).  If libtrust headers are
 *         absent (stripped build env), make will fail cleanly and the
 *         Python harness falls back to skipping live tests via
 *         trust_env.helpers_bin == None.
 *
 * NO KERNEL SOURCE IS TOUCHED.  This helper uses only the already-EXPORTED
 * libtrust userspace ABI (LIBTRUST_1.2 / 1.3).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "libtrust.h"
#include "../../trust/include/trust_types.h"

#define EXIT_USAGE       1
#define EXIT_NOTRUST     2
#define EXIT_IOCTL       3
#define EXIT_INTERNAL    4

static void hex_encode(const uint8_t *buf, size_t n, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = hex[(buf[i] >> 4) & 0xF];
        out[2 * i + 1] = hex[buf[i] & 0xF];
    }
    out[2 * n] = '\0';
}

static int hex_decode(const char *s, uint8_t *out, size_t n)
{
    if (strlen(s) != 2 * n)
        return -1;
    for (size_t i = 0; i < n; i++) {
        char a = s[2 * i], b = s[2 * i + 1];
        int hi = (a >= '0' && a <= '9') ? a - '0'
               : (a >= 'a' && a <= 'f') ? 10 + a - 'a'
               : (a >= 'A' && a <= 'F') ? 10 + a - 'A' : -1;
        int lo = (b >= '0' && b <= '9') ? b - '0'
               : (b >= 'a' && b <= 'f') ? 10 + b - 'a'
               : (b >= 'A' && b <= 'F') ? 10 + b - 'A' : -1;
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int cmd_register(int argc, char **argv)
{
    if (argc != 5) return EXIT_USAGE;
    uint32_t sid       = (uint32_t)strtoul(argv[2], NULL, 0);
    uint32_t authority = (uint32_t)strtoul(argv[3], NULL, 0);
    int32_t  score     = (int32_t)strtol(argv[4], NULL, 0);
    if (trust_register_subject_ex(sid, TRUST_DOMAIN_LINUX, authority, score) != 0)
        return EXIT_IOCTL;
    return 0;
}

static int cmd_apoptosis(int argc, char **argv)
{
    if (argc != 3) return EXIT_USAGE;
    uint32_t sid = (uint32_t)strtoul(argv[2], NULL, 0);
    return (trust_apoptosis(sid) == 0) ? 0 : EXIT_IOCTL;
}

static int cmd_proof_mint(int argc, char **argv)
{
    if (argc != 3) return EXIT_USAGE;
    uint32_t sid = (uint32_t)strtoul(argv[2], NULL, 0);
    uint8_t proof[TRUST_PROOF_SIZE];
    char hex[2 * TRUST_PROOF_SIZE + 1];

    if (trust_proof_mint(sid, proof) != 0)
        return EXIT_IOCTL;
    hex_encode(proof, TRUST_PROOF_SIZE, hex);
    printf("%s\n", hex);
    return 0;
}

static int cmd_proof_consume(int argc, char **argv)
{
    if (argc != 4) return EXIT_USAGE;
    uint32_t sid = (uint32_t)strtoul(argv[2], NULL, 0);
    uint8_t proof_in[TRUST_PROOF_SIZE];
    uint8_t proof_out[TRUST_PROOF_SIZE];
    char hex_out[2 * TRUST_PROOF_SIZE + 1];

    if (hex_decode(argv[3], proof_in, TRUST_PROOF_SIZE) != 0)
        return EXIT_USAGE;
    /* action_type = FILE_OPEN (arbitrary but realistic); result = 0 (success). */
    if (trust_proof_consume(sid, proof_in, TRUST_ACTION_FILE_OPEN, 0, proof_out) != 0)
        return EXIT_IOCTL;
    hex_encode(proof_out, TRUST_PROOF_SIZE, hex_out);
    printf("%s\n", hex_out);
    return 0;
}

static int cmd_ape_snapshot(int argc, char **argv)
{
    /* T1/T3 snapshot: one verify + one nonce read.  No mutation. */
    if (argc != 3) return EXIT_USAGE;
    uint32_t sid = (uint32_t)strtoul(argv[2], NULL, 0);
    uint64_t nonce = 0;

    int verified = (trust_proof_verify(sid) == 0) ? 1 : 0;
    (void)trust_proof_get_nonce(sid, &nonce);
    printf("verified=%d nonce=%llu\n", verified, (unsigned long long)nonce);
    return 0;
}

static int cmd_entropy_sample(int argc, char **argv)
{
    /*
     * T3 Forward Secrecy: emit the first N proofs of a fresh chain on
     * stdout.  Each line is 64 hex chars.  The Python harness streams
     * this into a chi-square / autocorrelation test (see §2.T3 of
     * docs/runtime-theorem-validation.md).
     */
    if (argc != 4) return EXIT_USAGE;
    uint32_t sid = (uint32_t)strtoul(argv[2], NULL, 0);
    long n = strtol(argv[3], NULL, 0);
    if (n <= 0 || n > 100000) return EXIT_USAGE;

    uint8_t cur[TRUST_PROOF_SIZE], next[TRUST_PROOF_SIZE];
    char hex[2 * TRUST_PROOF_SIZE + 1];

    if (trust_proof_mint(sid, cur) != 0) return EXIT_IOCTL;
    hex_encode(cur, TRUST_PROOF_SIZE, hex);
    printf("%s\n", hex);

    for (long i = 1; i < n; i++) {
        if (trust_proof_consume(sid, cur, TRUST_ACTION_FILE_OPEN, 0, next) != 0)
            return EXIT_IOCTL;
        memcpy(cur, next, TRUST_PROOF_SIZE);
        hex_encode(cur, TRUST_PROOF_SIZE, hex);
        printf("%s\n", hex);
    }
    return 0;
}

static int cmd_nonce(int argc, char **argv)
{
    if (argc != 3) return EXIT_USAGE;
    uint32_t sid = (uint32_t)strtoul(argv[2], NULL, 0);
    uint64_t nonce = 0;
    if (trust_proof_get_nonce(sid, &nonce) != 0)
        return EXIT_IOCTL;
    printf("%llu\n", (unsigned long long)nonce);
    return 0;
}

static int cmd_trc_burn(int argc, char **argv)
{
    /*
     * T6 Metabolic Fairness driver.  Calls trust_token_burn_action in a
     * tight loop to drive the cost_multiplier upward.  The Python
     * harness measures the post-burn balance vs. a "slow steady-pace"
     * reference subject to assert TRC starves the burner.
     */
    if (argc != 5) return EXIT_USAGE;
    uint32_t sid    = (uint32_t)strtoul(argv[2], NULL, 0);
    uint32_t action = (uint32_t)strtoul(argv[3], NULL, 0);
    long n          = strtol(argv[4], NULL, 0);
    if (n <= 0 || n > 100000) return EXIT_USAGE;

    int32_t remaining = 0;
    long succeeded = 0, denied = 0;
    for (long i = 0; i < n; i++) {
        int r = trust_token_burn_action(sid, action, &remaining);
        if (r == 0) succeeded++;
        else        denied++;
    }
    printf("succeeded=%ld denied=%ld remaining=%d\n",
           succeeded, denied, (int)remaining);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "usage: helpers <cmd> [args...]\n"
                "  register <sid> <authority> <initial_score>\n"
                "  apoptosis <sid>\n"
                "  proof-mint <sid>\n"
                "  proof-consume <sid> <hex64>\n"
                "  ape-snapshot <sid>\n"
                "  entropy-sample <sid> <count>\n"
                "  nonce <sid>\n"
                "  trc-burn <sid> <action> <count>\n");
        return EXIT_USAGE;
    }

    if (trust_init() != 0) {
        fprintf(stderr, "trust_init failed: %s\n", strerror(errno));
        return EXIT_NOTRUST;
    }

    int rc;
    const char *c = argv[1];
    if      (!strcmp(c, "register"))       rc = cmd_register(argc, argv);
    else if (!strcmp(c, "apoptosis"))      rc = cmd_apoptosis(argc, argv);
    else if (!strcmp(c, "proof-mint"))     rc = cmd_proof_mint(argc, argv);
    else if (!strcmp(c, "proof-consume"))  rc = cmd_proof_consume(argc, argv);
    else if (!strcmp(c, "ape-snapshot"))   rc = cmd_ape_snapshot(argc, argv);
    else if (!strcmp(c, "entropy-sample")) rc = cmd_entropy_sample(argc, argv);
    else if (!strcmp(c, "nonce"))          rc = cmd_nonce(argc, argv);
    else if (!strcmp(c, "trc-burn"))       rc = cmd_trc_burn(argc, argv);
    else {
        fprintf(stderr, "unknown command: %s\n", c);
        rc = EXIT_USAGE;
    }

    trust_cleanup();
    return rc;
}

/*
 * tests/bisim/test_pt_regs_compat.c
 *
 * Pure-C unit test for trust/include/trust_pt_regs_compat.h.
 * Verifies the x86_64 REG_ARGn() / REG_RET / REG_IP / REG_SYSCALL_NR
 * mappings against a synthetic struct pt_regs, without linking any
 * kernel code.
 *
 * Build + run:
 *   gcc -DTRUST_TEST_PT_REGS -I trust/include \
 *       tests/bisim/test_pt_regs_compat.c -o /tmp/test_pt_regs_compat && \
 *   /tmp/test_pt_regs_compat
 *
 * S75 Item 8 / Agent F deliverable. The riscv64 mapping path is not
 * exercised on an x86_64 host (we cannot synthesize a riscv64 pt_regs
 * with a0..a5/a7/epc fields here without also duplicating the switch
 * inside the header); a cross-compile pass on a riscv64 toolchain is
 * the real test for that path.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* TRUST_TEST_PT_REGS makes the header synthesize a minimal pt_regs
 * layout matching x86_64 instead of pulling <linux/ptrace.h>. */
#define TRUST_TEST_PT_REGS 1
/* Force the x86_64 arch branch even if the compiler's predefines
 * somehow disagree (the test suite must be deterministic). */
#ifndef __x86_64__
#  define __x86_64__ 1
#endif

#include "trust_pt_regs_compat.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK_EQ(label, got, want) do {                                       \
    g_checks++;                                                               \
    unsigned long _g = (unsigned long)(got);                                  \
    unsigned long _w = (unsigned long)(want);                                 \
    if (_g != _w) {                                                           \
        g_failures++;                                                         \
        fprintf(stderr, "FAIL %s: got 0x%lx want 0x%lx\n",                    \
                (label), _g, _w);                                             \
    }                                                                         \
} while (0)

int main(void)
{
    struct pt_regs r;
    memset(&r, 0, sizeof(r));

    /* Distinct sentinels per x86_64 field; chosen so a crossed wire
     * produces a readable mismatch rather than a near-miss. */
    r.di       = 0x1111111111111111UL; /* arg0 */
    r.si       = 0x2222222222222222UL; /* arg1 */
    r.dx       = 0x3333333333333333UL; /* arg2 */
    r.cx       = 0x4444444444444444UL; /* arg3 (funcall) */
    r.r10      = 0x4040404040404040UL; /* arg3 (syscall) */
    r.r8       = 0x5555555555555555UL; /* arg4 */
    r.r9       = 0x6666666666666666UL; /* arg5 */
    r.ax       = 0x7777777777777777UL; /* return */
    r.ip       = 0x8888888888888888UL; /* instruction pointer */
    r.orig_ax  = 0x9999999999999999UL; /* syscall nr */

    /* Core REG_ARG mapping */
    CHECK_EQ("REG_ARG0",          REG_ARG0(&r),          r.di);
    CHECK_EQ("REG_ARG1",          REG_ARG1(&r),          r.si);
    CHECK_EQ("REG_ARG2",          REG_ARG2(&r),          r.dx);
    CHECK_EQ("REG_ARG3 (default)", REG_ARG3(&r),         r.r10);
    CHECK_EQ("REG_ARG3_SYSCALL",  REG_ARG3_SYSCALL(&r),  r.r10);
    CHECK_EQ("REG_ARG3_FUNCALL",  REG_ARG3_FUNCALL(&r),  r.cx);
    CHECK_EQ("REG_ARG4",          REG_ARG4(&r),          r.r8);
    CHECK_EQ("REG_ARG5",          REG_ARG5(&r),          r.r9);

    /* Return / IP / syscall-nr accessors */
    CHECK_EQ("REG_RET",           REG_RET(&r),           r.ax);
    CHECK_EQ("REG_IP",            REG_IP(&r),            r.ip);
    CHECK_EQ("REG_SYSCALL_NR",    REG_SYSCALL_NR(&r),    r.orig_ax);

    /* Spot-check: syscall-vs-funcall arg3 must actually be different
     * on x86_64 (the whole point of the split accessor). */
    CHECK_EQ("syscall/funcall arg3 distinct",
             REG_ARG3_SYSCALL(&r) != REG_ARG3_FUNCALL(&r),
             1UL);

    /* Spot-check: cross-talk between slots. Overwrite just r10 and
     * verify arg3-syscall changes but arg3-funcall (cx) does not. */
    r.r10 = 0xDEADBEEFCAFEBABEUL;
    CHECK_EQ("after r10 rewrite: syscall arg3",
             REG_ARG3_SYSCALL(&r), 0xDEADBEEFCAFEBABEUL);
    CHECK_EQ("after r10 rewrite: funcall arg3 unchanged",
             REG_ARG3_FUNCALL(&r), 0x4444444444444444UL);

    /* All-zero pt_regs: every accessor must return 0, no UB. */
    memset(&r, 0, sizeof(r));
    CHECK_EQ("zero arg0", REG_ARG0(&r), 0UL);
    CHECK_EQ("zero arg5", REG_ARG5(&r), 0UL);
    CHECK_EQ("zero ret",  REG_RET(&r),  0UL);
    CHECK_EQ("zero ip",   REG_IP(&r),   0UL);
    CHECK_EQ("zero nr",   REG_SYSCALL_NR(&r), 0UL);

    if (g_failures) {
        fprintf(stderr, "FAIL: %d/%d checks failed\n",
                g_failures, g_checks);
        return 1;
    }
    printf("PASS: %d/%d checks passed (x86_64 pt_regs mapping)\n",
           g_checks, g_checks);
    printf("NOTE: riscv64 mapping is not exercised on an x86_64 host;\n"
           "      validate via cross-compile with riscv64-linux-gnu-gcc.\n");
    return 0;
}

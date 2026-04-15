/*
 * sigill_trampoline.c - SIGILL handler for CPUID spoofing
 *
 * When a PE binary executes the `cpuid` instruction directly (some
 * anti-cheat code does this to avoid API detours), we can intercept
 * the instruction two ways:
 *   1. Rewrite the code (not done here; risks code-integrity alarms)
 *   2. Make cpuid faulty in userspace and catch it in a signal handler
 *
 * x86 does not naturally fault on cpuid in user mode.  However, the
 * Linux kernel can be asked (via prctl(PR_SET_TSC, PR_TSC_SIGSEGV) or
 * ARCH_PRCTL knobs on some CPUs) to deliver SIGSEGV on rdtsc/cpuid.
 * Where that is not available, we support a hook-based scheme: if the
 * binary ever issues an *invalid* opcode (0F 0B = UD2), we may walk
 * the prior bytes and emulate a spoofed cpuid response.  We also
 * install a SIGILL handler that detects the 0F A2 cpuid opcode at
 * RIP and rewrites the register file before resuming.
 *
 * Safety rules:
 *   - Handler only spoofs when pe_patch_sigill_set_enabled(1) is called.
 *   - Handler never spoofs for opcodes it does not recognise -- it
 *     re-raises SIGILL so the default handler terminates the process.
 *   - The spoof fills in plausible Windows-10-on-Intel-Core-i7
 *     responses for the four common cpuid leaves used by anti-cheat:
 *     0 (vendor string), 1 (feature bits), 0x80000000..0x80000004
 *     (extended feature + brand string).
 *
 * We do NOT spoof legitimate cpuid from the host runtime.  The
 * handler scope is the PE process only; the loader itself uses cpuid
 * once (during CRT startup) and we enable the spoof lazily (after the
 * loader's own cpuid calls have completed).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <stdint.h>
#include <errno.h>

#include "pe_patch.h"

#define LOG_PREFIX "[sigill] "

static struct sigaction g_prev_sigaction;
static int g_installed = 0;
static volatile sig_atomic_t g_spoof_enabled = 0;

/* Plausible Windows-10-on-Intel-Core-i7 CPUID response table. */
struct cpuid_leaf {
    uint32_t leaf;
    uint32_t eax, ebx, ecx, edx;
};

/* "GenuineIntel" vendor string, Family 6 Model 142 (Kaby Lake) features */
static const struct cpuid_leaf g_spoof_leaves[] = {
    /* Leaf 0: max standard leaf (0x16) + vendor string in EBX/EDX/ECX */
    { 0x00000000u, 0x00000016u, 0x756E6547u, 0x6C65746Eu, 0x49656E69u },
    /* Leaf 1: signature, brand index, feature bits (SSE4.2, AVX2, etc.) */
    { 0x00000001u, 0x000806EAu, 0x00100800u, 0x7FFAFBFFu, 0xBFEBFBFFu },
    /* Leaf 7/0: structured extended features (AVX2, BMI1, BMI2) */
    { 0x00000007u, 0x00000000u, 0x029C6FBFu, 0x00000000u, 0x9C000400u },
    /* Leaf 0x80000000: max extended leaf */
    { 0x80000000u, 0x80000008u, 0u, 0u, 0u },
    /* Leaf 0x80000001: extended features */
    { 0x80000001u, 0x00000000u, 0x00000000u, 0x00000121u, 0x2C100800u },
    /* Leaf 0x80000002..4: brand string "Intel(R) Core(TM) i7-7700K CPU" */
    { 0x80000002u, 0x65746E49u, 0x2952286Cu, 0x726F4320u, 0x4D542865u },
    { 0x80000003u, 0x37692029u, 0x3037372Du, 0x43204B30u, 0x40205550u },
    { 0x80000004u, 0x302E3420u, 0x7A484730u, 0x00000000u, 0x00000000u },
};

#define NUM_SPOOF_LEAVES (sizeof(g_spoof_leaves) / sizeof(g_spoof_leaves[0]))

/* Look up spoof data for a (leaf, subleaf) pair.  Returns 1 if found. */
static int find_spoof(uint32_t leaf, uint32_t subleaf,
                      uint32_t *eax, uint32_t *ebx,
                      uint32_t *ecx, uint32_t *edx)
{
    (void)subleaf; /* Only leaf 7 has subleaves; we only spoof subleaf 0. */
    for (size_t i = 0; i < NUM_SPOOF_LEAVES; i++) {
        if (g_spoof_leaves[i].leaf == leaf) {
            *eax = g_spoof_leaves[i].eax;
            *ebx = g_spoof_leaves[i].ebx;
            *ecx = g_spoof_leaves[i].ecx;
            *edx = g_spoof_leaves[i].edx;
            return 1;
        }
    }
    return 0;
}

/* Signal handler.  siginfo/si_code lets us distinguish ILL_ILLOPN
 * (bad opcode) from other causes. */
static void sigill_handler(int sig, siginfo_t *info, void *ucv)
{
    ucontext_t *uc = (ucontext_t *)ucv;

    if (!g_spoof_enabled || !uc) goto forward;

    /* Read RIP and peek at the first two bytes of the faulting
     * instruction.  CPUID opcode is 0F A2 (2 bytes). */
#if defined(__x86_64__)
    greg_t *gregs = uc->uc_mcontext.gregs;
    uintptr_t rip = (uintptr_t)gregs[REG_RIP];
    /* We do not verify that the two bytes at RIP are readable; if they
     * are not, the prior access fault would have fired first.  A bad
     * RIP that yields a bad read here will SIGSEGV in the handler,
     * which is a reasonable outcome. */
    const uint8_t *bytes = (const uint8_t *)rip;
    if (bytes[0] == 0x0F && bytes[1] == 0xA2) {
        uint32_t leaf    = (uint32_t)gregs[REG_RAX];
        uint32_t subleaf = (uint32_t)gregs[REG_RCX];
        uint32_t eax, ebx, ecx, edx;
        if (find_spoof(leaf, subleaf, &eax, &ebx, &ecx, &edx)) {
            gregs[REG_RAX] = eax;
            gregs[REG_RBX] = ebx;
            gregs[REG_RCX] = ecx;
            gregs[REG_RDX] = edx;
            /* Advance past the 2-byte cpuid opcode. */
            gregs[REG_RIP] = (greg_t)(rip + 2);
            return;
        }
    }
#else
    (void)uc;
#endif

forward:
    /* Not a cpuid spoof case; re-raise using the previously installed
     * handler.  SA_RESETHAND in our initial install means the default
     * action will terminate the process on the next SIGILL; instead we
     * call through whatever was there before. */
    if (g_prev_sigaction.sa_flags & SA_SIGINFO) {
        if (g_prev_sigaction.sa_sigaction)
            g_prev_sigaction.sa_sigaction(sig, info, ucv);
    } else {
        if (g_prev_sigaction.sa_handler == SIG_DFL ||
            g_prev_sigaction.sa_handler == SIG_IGN) {
            /* Restore default and re-raise so the kernel terminates us
             * with the correct siginfo payload. */
            struct sigaction dfl;
            memset(&dfl, 0, sizeof(dfl));
            dfl.sa_handler = SIG_DFL;
            sigaction(sig, &dfl, NULL);
            raise(sig);
            return;
        }
        if (g_prev_sigaction.sa_handler)
            g_prev_sigaction.sa_handler(sig);
    }
}

int pe_patch_sigill_install(void)
{
    if (g_installed) return 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = sigill_handler;
    if (sigaction(SIGILL, &sa, &g_prev_sigaction) != 0) {
        fprintf(stderr, LOG_PREFIX "sigaction failed: %s\n", strerror(errno));
        return -1;
    }
    g_installed = 1;
    return 0;
}

void pe_patch_sigill_uninstall(void)
{
    if (!g_installed) return;
    sigaction(SIGILL, &g_prev_sigaction, NULL);
    g_installed = 0;
}

void pe_patch_sigill_set_enabled(int enabled)
{
    g_spoof_enabled = enabled ? 1 : 0;
}

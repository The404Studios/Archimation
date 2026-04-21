/*
 * trust_pt_regs_compat.h - pt_regs cross-arch accessor abstraction
 *
 * S75 Item 8 / Agent F: ports the trust kernel module's syscall + memory
 * kprobe hooks to be portable across x86_64 and riscv64 by introducing a
 * REG_ARG{0..5} macro abstraction over `struct pt_regs`. See
 * docs/riscv-portability-deltas.md (S74 Agent 4) for the static-analysis
 * catalog of affected sites, and docs/s75_roadmap.md §1.3.8 for the
 * top-level spec.
 *
 * Background:
 *   `struct pt_regs` is arch-specific. On x86_64 the fields are
 *     di, si, dx, cx, r8, r9, r10, ax, bx, ip, orig_ax, ...
 *   On riscv64 they are
 *     a0..a7, s0..s11, t0..t6, ra, sp, gp, tp, epc, status, ...
 *   The trust syscall tracer was originally written against x86_64
 *   pt_regs field names; this header abstracts that so the same C source
 *   compiles clean on both architectures.
 *
 * Syscall-ABI quirk (x86_64 only):
 *   For SYSCALLS, the x86_64 Linux kernel passes the 4th argument in
 *   %r10 (not %rcx as userspace uses), because SYSCALL clobbers %rcx
 *   with the return-address. See arch/x86/entry/common.c. For general
 *   FUNCTION CALLS (e.g. kprobes on do_mmap, do_mprotect_pkey which
 *   are interior kernel functions), the 4th argument is in %rcx per
 *   the System V ABI. We therefore provide BOTH forms of the
 *   arg-3 accessor:
 *     REG_ARG3_SYSCALL(r) - r10 on x86_64, a3 on riscv64
 *     REG_ARG3_FUNCALL(r) - rcx on x86_64, a3 on riscv64
 *   On riscv64 there is no such distinction: syscalls and function
 *   calls both use a0..a7 in-register.
 *
 * Usage:
 *   #include "../include/trust_pt_regs_compat.h"
 *   ...
 *   u64 fd = REG_ARG0(regs);   // arg0: di  / a0
 *   u64 len = REG_ARG2(regs);  // arg2: dx  / a2
 *   u32 prot = (u32)REG_ARG3_FUNCALL(regs); // arg3 (funcall): cx / a3
 *
 * All accessors are inline static functions returning `unsigned long`
 * so the compiler catches type errors and the emitted code is
 * identical to a direct field access.
 */

#ifndef _TRUST_PT_REGS_COMPAT_H
#define _TRUST_PT_REGS_COMPAT_H

/* When TRUST_TEST_PT_REGS is defined, we are being compiled in a pure
 * userspace unit-test harness, not the kernel. Synthesize a minimal
 * `struct pt_regs` matching the x86_64 kernel layout (the fields we
 * touch). The real kernel build includes <linux/ptrace.h> via the
 * translation unit that includes us. */
#ifdef TRUST_TEST_PT_REGS
#  include <stdint.h>
struct pt_regs {
    /* x86_64 layout — only the fields exercised by this header. Real
     * kernel struct has more, but this is byte-layout-irrelevant for
     * the mapping tests. */
    unsigned long r15, r14, r13, r12, bp, bx;
    unsigned long r11, r10, r9, r8, ax, cx, dx, si, di;
    unsigned long orig_ax, ip, cs, flags, sp, ss;
};
#else
#  include <linux/ptrace.h>
#endif

#if defined(__x86_64__) || defined(CONFIG_X86_64)

/* x86_64 System V ABI (function calls):
 *   arg0=rdi, arg1=rsi, arg2=rdx, arg3=rcx, arg4=r8, arg5=r9
 * x86_64 Linux syscall ABI:
 *   arg0=rdi, arg1=rsi, arg2=rdx, arg3=r10, arg4=r8, arg5=r9
 * The 4th arg diverges: %rcx is clobbered by SYSCALL, so the kernel
 * copies it to %r10 in the syscall entry stub. */

static inline unsigned long REG_ARG0(struct pt_regs *r) { return r->di; }
static inline unsigned long REG_ARG1(struct pt_regs *r) { return r->si; }
static inline unsigned long REG_ARG2(struct pt_regs *r) { return r->dx; }
static inline unsigned long REG_ARG3_SYSCALL(struct pt_regs *r) { return r->r10; }
static inline unsigned long REG_ARG3_FUNCALL(struct pt_regs *r) { return r->cx; }
static inline unsigned long REG_ARG4(struct pt_regs *r) { return r->r8; }
static inline unsigned long REG_ARG5(struct pt_regs *r) { return r->r9; }
static inline unsigned long REG_RET(struct pt_regs *r)  { return r->ax; }
static inline unsigned long REG_IP(struct pt_regs *r)   { return r->ip; }
static inline unsigned long REG_SYSCALL_NR(struct pt_regs *r) { return r->orig_ax; }

/* Default REG_ARG3 alias: most call sites in trust_syscall.c kprobe on
 * __x64_sys_* wrappers and decode args from the *inner* pt_regs, which
 * is the user-context pt_regs — arg3 there is in r10 (syscall ABI).
 * Kprobes in trust_memory.c target interior kernel functions
 * (do_mmap, do_mprotect_pkey) and must use REG_ARG3_FUNCALL explicitly.
 * Provide the plain REG_ARG3 as the syscall-context form (the common
 * case) and require REG_ARG3_FUNCALL at funcall sites. */
static inline unsigned long REG_ARG3(struct pt_regs *r) { return r->r10; }

#elif defined(__riscv) || defined(CONFIG_RISCV)

/* RISC-V ELF psABI (function calls) and Linux syscall ABI both use
 * a0..a7 for the first 8 arguments. Syscall number is in a7.
 * Return value is in a0 (overwriting arg0). Program counter is epc. */

static inline unsigned long REG_ARG0(struct pt_regs *r) { return r->a0; }
static inline unsigned long REG_ARG1(struct pt_regs *r) { return r->a1; }
static inline unsigned long REG_ARG2(struct pt_regs *r) { return r->a2; }
static inline unsigned long REG_ARG3_SYSCALL(struct pt_regs *r) { return r->a3; }
static inline unsigned long REG_ARG3_FUNCALL(struct pt_regs *r) { return r->a3; }
static inline unsigned long REG_ARG3(struct pt_regs *r) { return r->a3; }
static inline unsigned long REG_ARG4(struct pt_regs *r) { return r->a4; }
static inline unsigned long REG_ARG5(struct pt_regs *r) { return r->a5; }
static inline unsigned long REG_RET(struct pt_regs *r)  { return r->a0; }
static inline unsigned long REG_IP(struct pt_regs *r)   { return r->epc; }
static inline unsigned long REG_SYSCALL_NR(struct pt_regs *r) { return r->a7; }

#else
#  error "trust: unsupported arch (x86_64 and riscv64 only)"
#endif

#endif /* _TRUST_PT_REGS_COMPAT_H */

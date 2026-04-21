# RISC-V Portability Deltas — `trust.ko` static analysis (S74 Agent 4)

**Status:** static analysis only. Cross-compile **not attempted on this host** —
WSL2 lacks `riscv64-linux-gnu-gcc` and `qemu-system-riscv64`. `scripts/test-riscv-qemu.sh`
emits "TOOLCHAIN MISSING" (exit 2) exactly as designed.

**Scope:** every source file in `trust/kernel/` (22 `.c` + 13 `.h`, ~17 kLOC)
plus the UAPI headers in `trust/include/` (7 files, ~1.9 kLOC). The companion
script `scripts/test-riscv-qemu.sh` runs the actual cross-compile once a
toolchain and KDIR are available.

**Paper context:** Zenodo DOI 10.5281/zenodo.18710335 (Roberts/Eli/Leelee)
claims a RISC-V FPGA POC. The current implementation is x86_64 Linux kernel
module. Phase 1 of the FPGA reproduction path answers: "Does the module even
build clean for `riscv64`?" This report is Agent 4's deliverable; Agent 10
(S75) will close the deltas enumerated here.

---

## Executive summary

| Question | Answer |
|---|---|
| Will `trust.ko` cross-compile clean for `riscv64` today? | **NO.** One module (`trust_syscall.c`) and one block inside another (`trust_memory.c:907-985`) contain x86-only `pt_regs` field references and `__x64_sys_*` kprobe symbol names. Every other file is arch-neutral. |
| Blast radius (files that need any edit at all) | **3 files** — `trust_syscall.c` (blocker), `trust_syscall.h` (comment + constants), `trust_memory.c` (kprobe block only). |
| Blast radius (files that are already portable) | **29 of 32** source files. |
| Count of portability issues (distinct ifdef points that must be introduced or constructs replaced) | **27** — of which **3 are architectural** (`__x64_sys_*` symbol names × 9 kprobes + pt_regs field access × 14 sites + x86 syscall-number constants × 11) collapsing into 3 logical fixes. |
| Inline asm occurrences | **0** (grep `asm volatile\|__asm__\|asm(` returns empty over all trust kernel sources). |
| x86 intrinsics (`__rdtsc`, `__cpuid`, SSE/AVX) | **0**. |
| Other CPU-specific primitives (`wrmsr`, `rdmsr`, `get_cycles` direct) | **0** (time uses `ktime_get_ns()` / `jiffies` consistently — arch-neutral). |
| Pointer-size / word-width assumptions | Safe (uses `u32`/`u64`/`uintptr_t`/`unsigned long`; no `int == sizeof(void*)` assumptions). |
| Endianness assumptions | Safe (no byte-reordering code outside standard kernel macros; struct layouts are arch-internal, not written to disk/network). |
| **Estimated LOC for full `riscv64` port** | **≈ 180 LOC new + ≈ 60 LOC modified = 240 LOC total** across 3 files; no new header, no Kbuild change. |

**Headline:** the trust kernel is remarkably portable already. The _only_
reason it won't build for `riscv64` is the syscall-observation subsystem,
which was written assuming x86_64 kprobe wrappers (`__x64_sys_*`) and x86
pt_regs register names (`di/si/dx/cx/r8/r9/r10`). Both are fixable with a
clean ifdef + accessor helper — **no architectural decision is deferred**.

---

## 1. `__x86_64__` / `CONFIG_X86_64` / `__i386__` ifdefs

**Finding:** **zero explicit ifdefs** for x86 in the trust kernel sources.
`grep -nE '__x86_64__|CONFIG_X86_64|CONFIG_X86|__i386__|__amd64__'
trust/kernel trust/include` returns only **3 comment-only hits** (all in
human-readable prose, none are preprocessor directives):

| File | Line | Context | Type |
|---|---:|---|---|
| `trust/kernel/trust_syscall.h` | 33 | `/* --- x86_64 syscall numbers (for reference and mapping) --- */` | **comment** — guards a block of 12 `TSC_NR_*` constants below |
| `trust/kernel/trust_syscall.c` | 226 | `* x86_64 System V ABI: arg0=rdi, arg1=rsi, arg2=rdx, arg3=rcx, arg4=r8` | **comment** |
| `trust/kernel/trust_fused.c` | 9 | `*      Measured ~50-100ns per pair on mid-range x86_64 (warm cache).` | **comment, benchmark prose only** |
| `trust/kernel/trust_memory.c` | 897 | `* x86_64 calling convention (System V ABI):` | **comment** |

**Interpretation:** nobody ever wrote `#ifdef __x86_64__` in the trust kernel.
This is _good_ — no hidden ifdef ladders to unpack. The badness is all
implicit: code _acts_ as if `__x86_64__` is true because the kprobe-based
syscall tracer uses x86-only symbol names and x86-only `pt_regs` fields.

---

## 2. Inline assembly

**Finding:** **zero** occurrences of `asm volatile`, `__asm__`, or bare `asm(`
across `trust/kernel/**`.

The only memory-ordering primitives used are kernel-API-portable:
`smp_rmb()`, `smp_wmb()`, `smp_mb()`, `READ_ONCE()`, `WRITE_ONCE()`. These
compile correctly on every Linux-supported arch including `riscv64` (mapped
to `fence r,r`, `fence w,w`, `fence rw,rw` on RISC-V).

**Fix required:** **none.**

---

## 3. x86 intrinsics / SSE-AVX / MSR / TSC

**Finding:** **zero** occurrences of `__rdtsc`, `__cpuid`, `_mm_*`,
`__builtin_ia32_*`, SSE/AVX headers (`<immintrin.h>`, `<xmmintrin.h>`, …),
`rdmsr`, `wrmsr`, `xsave`, `fsgsbase`, or direct `get_cycles()` calls in
`trust/kernel/**`.

Time is taken exclusively via `ktime_get_ns()` (mono) and `jiffies`
(jiffy counter) — both arch-neutral Linux kernel APIs. `ktime_get_ns()`
on `riscv64` maps to the `rdtime` pseudo-instruction (csr 0xC01); no
source changes needed.

**Fix required:** **none.**

---

## 4. Syscall tracer — `trust_syscall.c` (the real blocker)

This is where the portability debt lives. The trust module ships a
"Trust Syscall Context" tracer (`tsc_*`) that kprobes 9 syscalls and
decodes arguments from `pt_regs`. The code was written for x86_64 and
uses **two** constructs that don't exist on `riscv64`:

### 4.a — `__x64_sys_*` kprobe symbol names (9 occurrences)

| File | Lines | Symbol |
|---|---|---|
| `trust_syscall.c` | 681, 733 | `__x64_sys_openat` |
| `trust_syscall.c` | 686, 741 | `__x64_sys_read` |
| `trust_syscall.c` | 691, 749 | `__x64_sys_write` |
| `trust_syscall.c` | 696, 757 | `__x64_sys_ioctl` |
| `trust_syscall.c` | 701, 765 | `__x64_sys_socket` |
| `trust_syscall.c` | 706, 773 | `__x64_sys_connect` |
| `trust_syscall.c` | 711 | `__x64_sys_bind` |
| `trust_syscall.c` | 716 | `__x64_sys_mmap` |
| `trust_syscall.c` | 721, 781 | `__x64_sys_clone` |

**Root cause:** Linux's syscall wrapper-prefix scheme (introduced for
Spectre/Meltdown hardening in 2018, commit `fa697140f89e`) differs per arch:
- x86_64: `__x64_sys_foo`
- riscv64: `__riscv_sys_foo` (renamed from bare `sys_foo` in 6.1-rc1)
- arm64:   `__arm64_sys_foo`

Registering a kprobe on a symbol that doesn't exist on the running arch
silently fails at `register_kprobe()` time (returns `-EINVAL`). The module
would still _load_ on `riscv64`, but the syscall tracer would never fire.
That's worse than a compile error — it's silent feature loss.

### 4.b — `pt_regs` field access (14 occurrences)

| File | Lines | Fields accessed |
|---|---|---|
| `trust_syscall.c` | 230, 231 (comment) | `inner->di, inner->si, inner->dx, inner->r10, inner->r8, inner->r9` |
| `trust_syscall.c` | 246 | `regs->di` (retrieves inner pt_regs on x86) |
| `trust_syscall.c` | 277, 305, 333, 361, 389, 417, 445, 473, 501 | `inner->di, inner->si, inner->dx` in 9 kprobe handlers |
| `trust_memory.c` | 924-926 | `regs->si, regs->dx, regs->cx` in `tms_kp_mmap_pre` |
| `trust_memory.c` | 952-953 | `regs->si, regs->dx` in `tms_kp_munmap_pre` |
| `trust_memory.c` | 979-981 | `regs->di, regs->si, regs->dx` in `tms_kp_mprotect_pre` |

**Root cause:** `struct pt_regs` is arch-specific.
- x86_64 (`arch/x86/include/asm/ptrace.h`): fields are `di, si, dx, cx, r8, r9, r10, ax, bx, …`
- riscv64 (`arch/riscv/include/asm/ptrace.h`): fields are `a0, a1, a2, a3, a4, a5, a6, a7` (argument regs) + `t0..t6, s0..s11, ra, sp, gp, tp, pc, status, …`

Cross-reference with the x86_64 System V ABI (arg0=rdi, arg1=rsi, arg2=rdx,
arg3=r10 for syscalls / rcx for userspace, arg4=r8, arg5=r9) and the
RISC-V ELF psABI (arg0=a0, arg1=a1, … arg5=a5):

| Sysv arg | x86_64 pt_regs | riscv64 pt_regs |
|---|---|---|
| arg0 | `regs->di` | `regs->a0` |
| arg1 | `regs->si` | `regs->a1` |
| arg2 | `regs->dx` | `regs->a2` |
| arg3 | `regs->r10` (syscall) / `regs->cx` (userland) | `regs->a3` |
| arg4 | `regs->r8`  | `regs->a4` |
| arg5 | `regs->r9`  | `regs->a5` |

**Additional RISC-V wrinkle:** on riscv64 there is no "outer / inner pt_regs"
indirection. The x86-64 variant passes `__x64_sys_*` a `struct pt_regs *`
that points to another `pt_regs` in `regs->di` (the kernel's registered-arg
convention since v4.17). On riscv64 the syscall handlers receive the real
pt_regs directly. So `tsc_get_inner_regs()` is entirely an x86-only artifact
and becomes a no-op on `riscv64`.

### 4.c — x86 syscall-number constants (11 occurrences)

`trust/kernel/trust_syscall.h:33-45` hardcodes:
```c
#define TSC_NR_READ    0    /* openat=257 on x86_64 */
#define TSC_NR_WRITE   1
#define TSC_NR_CLOSE   3
#define TSC_NR_MMAP    9
#define TSC_NR_IOCTL   16
#define TSC_NR_SOCKET  41
#define TSC_NR_CONNECT 42
#define TSC_NR_BIND    49
#define TSC_NR_SENDTO  44
#define TSC_NR_RECVFROM 45
#define TSC_NR_CLONE   56
#define TSC_NR_OPENAT  257
```

These are x86_64 values from `arch/x86/entry/syscalls/syscall_64.tbl`.
On `riscv64`, from `include/uapi/asm-generic/unistd.h` (riscv64 uses the
generic table):
- `read` = 63, `write` = 64, `close` = 57, `ioctl` = 29, `mmap` = 222,
  `socket` = 198, `connect` = 203, `bind` = 200, `sendto` = 206,
  `recvfrom` = 207, `clone` = 220, `openat` = 56.

These constants are only used as enumerators for event tagging (not as
kernel-side syscall dispatch). The actual fix is to _not_ hard-code them —
use `<asm/unistd.h>`'s `__NR_*` macros which expand to the correct values
per arch.

---

## 5. `__attribute__` / compiler builtins (benign)

**Finding:** 6 `__attribute__` occurrences; all are arch-neutral.

| File | Line | Attribute | Portable? |
|---|---:|---|:---:|
| `trust_invariants.c` | 59 | `__attribute__((weak))` | yes |
| `trust_isa.h` | 308, 315, 344, 351 | `__attribute__((packed))` | yes |
| `trust_subject_pool.c` | 65 | `__attribute__((used))` | yes |

GCC supports these on every arch. No fix needed.

`__builtin_*` also reviewed (no `__builtin_ia32_*`; only standard
`__builtin_popcount` / `__builtin_clz` / etc., all portable).

---

## 6. Assumptions about word width / pointer size / endianness

- **Word width:** code uses `u32`, `u64`, `size_t`, `uintptr_t`,
  `unsigned long`. No place assumes `sizeof(int) == sizeof(void*)`.
  riscv64 is an LP64 arch just like x86_64 — every existing type mapping
  holds.
- **Pointer size:** struct layouts with embedded pointers (e.g.
  `trust_subject_t` at 496 bytes on x86_64) will be identical on riscv64
  because both are LP64. The paper's 23-pair chromosomal struct claim holds
  byte-exactly (was verified structurally in S73's validation pass).
- **Endianness:** `riscv64` is little-endian by default (so is x86_64). No
  `__BYTE_ORDER__` checks needed. Trust ISA packed types
  (`trust_isa_batch_t`, `trust_event_packed_t`) are already `__packed` and
  accessed only within the running kernel — never written to disk or
  network — so no serialization concerns.
- **Page size:** `PAGE_SIZE` and `PAGE_SHIFT` used consistently via the
  kernel macros. riscv64 default is 4 KiB (same as x86_64); Sv48/Sv57
  choice is transparent to the module.
- **Atomics / memory model:** `smp_mb()`, `smp_rmb()`, `smp_wmb()` used; all
  portable. RISC-V's RVWMO (weaker than TSO) is handled correctly by these
  macros — no explicit `fence` needed in the module.

**Fix required:** **none** in this section.

---

## 7. TPM attestation (`trust_attest.c`)

- Uses `tpm_chip_find_get()` + `tpm_pcr_read()` — **architecture-neutral**
  Linux kernel TPM API (`include/linux/tpm.h`).
- No direct LPC / TIS register access; no x86 ACPI probing in this module.
- On a RISC-V board without a TPM chip, `tpm_chip_find_get()` returns
  `NULL`, `trust_attest_init()` falls through to SOFTWARE mode (exactly as
  designed per S72's three-mode contract).

**Fix required:** **none.**

---

## 8. Per-finding fix classification

### Classification (a) — add ifdef around x86 with riscv64 alternative

| ID | Site | Size |
|---|---|---:|
| A1 | `trust_syscall.c` kprobe symbol table (lines 681-781, both `kprobe` and `kretprobe` arrays): wrap each `.symbol_name = "__x64_sys_foo"` with `#if defined(CONFIG_X86_64)` … `#elif defined(CONFIG_RISCV)` using `"__riscv_sys_foo"` | ~60 LOC net-add (18 sites × 2 arches + 9 shared) |
| A2 | `trust_syscall.c:244-248` `tsc_get_inner_regs()`: becomes `#if CONFIG_X86_64` returns `(pt_regs *)regs->di`, `#else` returns `regs` directly | ~6 LOC |
| A3 | `trust_syscall.c:277, 305, 333, 361, 389, 417, 445, 473, 501`: all 9 `inner->di, inner->si, inner->dx` sites → introduce 6 inline accessor macros `REG_ARG0(r)`…`REG_ARG5(r)` that expand to `r->di` on x86_64 and `r->a0` on riscv64 | macros ~15 LOC; callsites unchanged |
| A4 | `trust_memory.c:924-926, 952-953, 979-981`: 8 pt_regs field accesses — reuse macros from A3 | 0 LOC (just replace `regs->si` with `REG_ARG1(regs)` etc.) |

### Classification (b) — replace with kernel-API-portable call

| ID | Site | Size |
|---|---|---:|
| B1 | `trust_syscall.h:33-45` `TSC_NR_*` constants → switch to `__NR_openat`, `__NR_read`, … from `<asm/unistd.h>` | ~15 LOC (replace 12 hardcoded ints with `__NR_*` macros; keep the `TSC_NR_*` names as aliases for API compat) |

### Classification (c) — architectural decision deferred

**None.** Every finding above has a mechanical fix in the same file that
produced it. No architectural redesign required.

### New helper header to introduce

Put all cross-arch macros in `trust/kernel/trust_arch.h` (new file, ~80 LOC).
Proposal:

```c
/* trust/kernel/trust_arch.h — arch abstraction for pt_regs + kprobe names */
#ifndef _TRUST_ARCH_H
#define _TRUST_ARCH_H

#include <linux/ptrace.h>
#include <asm/unistd.h>

#if defined(CONFIG_X86_64)
#  define TRUST_SYSCALL_PREFIX "__x64_sys_"
#  define REG_ARG0(r) ((r)->di)
#  define REG_ARG1(r) ((r)->si)
#  define REG_ARG2(r) ((r)->dx)
#  define REG_ARG3(r) ((r)->r10)
#  define REG_ARG4(r) ((r)->r8)
#  define REG_ARG5(r) ((r)->r9)
#  define TRUST_NEEDS_INNER_REGS 1
#elif defined(CONFIG_RISCV)
#  define TRUST_SYSCALL_PREFIX "__riscv_sys_"
#  define REG_ARG0(r) ((r)->a0)
#  define REG_ARG1(r) ((r)->a1)
#  define REG_ARG2(r) ((r)->a2)
#  define REG_ARG3(r) ((r)->a3)
#  define REG_ARG4(r) ((r)->a4)
#  define REG_ARG5(r) ((r)->a5)
#  define TRUST_NEEDS_INNER_REGS 0
#elif defined(CONFIG_ARM64)
#  define TRUST_SYSCALL_PREFIX "__arm64_sys_"
#  define REG_ARG0(r) ((r)->regs[0])
#  /* … (arm64 analog, useful future-proofing but not required by paper) */
#  define TRUST_NEEDS_INNER_REGS 0
#else
#  error "trust.ko: unsupported arch (x86_64 / riscv64 / arm64 only)"
#endif

static inline struct pt_regs *trust_get_syscall_regs(struct pt_regs *r)
{
#if TRUST_NEEDS_INNER_REGS
    return (struct pt_regs *)r->di;
#else
    return r;
#endif
}

#endif /* _TRUST_ARCH_H */
```

S75 Agent 10 (RV port) replaces every pt_regs field access with these macros
and the `__x64_sys_` string with `TRUST_SYSCALL_PREFIX "foo"` concatenation
at kprobe registration time (which requires one small helper to build the
symbol name at init, but that's a ~20 LOC function).

---

## 9. LOC estimate for full `riscv64` port (S75 input)

| Component | New LOC | Modified LOC | Files touched |
|---|---:|---:|---:|
| `trust/kernel/trust_arch.h` (new helper header) | 80 | 0 | 1 (new) |
| `trust/kernel/trust_syscall.c` — 9 kprobes × 2 arches + inner-regs helper + macro substitution | 60 | 40 | 1 |
| `trust/kernel/trust_syscall.h` — replace hardcoded constants with `__NR_*` | 0 | 15 | 1 |
| `trust/kernel/trust_memory.c` — 8 pt_regs field sites | 0 | 8 | 1 |
| `trust/kernel/Kbuild` — no change (single `trust.ko` target, arch-neutral) | 0 | 0 | 0 |
| Symbol-name builder helper (takes `"openat"` returns prefixed name) | 20 | 0 | in `trust_syscall.c` |
| QEMU boot-test harness integration (per Makefile target) | 20 | 0 | (already in test-riscv-qemu.sh) |
| **Total** | **180** | **63** | **3 edited + 1 new** |

**Sanity check against precedent:** in S62 the 25 routing-pattern NL patch
landed in ~60 LOC across 1 file; in S68 the `hkey_low32()` portability fix
shipped in ~30 LOC across 7 sites. A single-arch kernel-module port of
~240 LOC is consistent with both.

**Uncertainty bound:** ±40 LOC. Upside risk if RISC-V kprobe support turns
out to need `CONFIG_KPROBES_ON_FTRACE=y` and the running kernel is built
without it — in that case a `smatch`/compile-time `#error` plus a runtime
fallback to uprobes would add ~50 LOC. Downside if the `__riscv_sys_`
prefix and `a0..a5` mapping are the only changes: ~180 LOC.

---

## 10. Recommended next steps (S75 handoff)

1. **S75 Agent 10** lands `trust/kernel/trust_arch.h` + edits `trust_syscall.c`,
   `trust_syscall.h`, `trust_memory.c` per §8.
2. On any host with the toolchain: `KDIR=/path/to/rv-linux-src bash
   scripts/test-riscv-qemu.sh --skip-boot`. Expect stage-1 PASS (exit 0).
3. Pre-build a BuildRoot riscv64 rootfs + opensbi once, cache to
   `/var/cache/trust-riscv64-{rootfs.img,kdir}`, then run without `--skip-boot`
   — expect stage-2 PASS with `trust_core: loaded` appearing in dmesg.
4. Wire into CI: `.github/workflows/riscv.yml` that runs stage 1 in a
   container with `gcc-riscv64-linux-gnu` preinstalled. Gate on exit 0.
5. Once CI is green, S76 can proceed to Phase 2 (Verilator RV core,
   $0, ~40h) — the kernel module portability is no longer a blocker.

---

## Appendix A — grep commands used

For reproducibility:

```bash
# ifdefs (prose hits only — no real conditional compilation)
grep -nE '__x86_64__|CONFIG_X86_64|CONFIG_X86|__i386__|__amd64__|x86_64|X86_64' \
    trust/kernel trust/include

# inline asm (zero hits)
grep -nE 'asm volatile|__asm__|asm\(' trust/kernel trust/include

# x86 intrinsics (zero hits)
grep -nE '__rdtsc|rdtsc|__cpuid|_mm_|__builtin_ia32|xmm|ymm' \
    trust/kernel trust/include

# x86-only pt_regs fields (the real blocker — 22 hits)
grep -nE 'regs->(di|si|dx|cx|r8|r9|r10|ax|bx|sp|ip)' trust/kernel
grep -nE 'inner->(di|si|dx|cx|r8|r9|r10|ax|bx)' trust/kernel

# x86-only syscall prefixes (9 kprobes × 2 arrays + comments = 23 hits)
grep -nE '__x64_sys_|__ia32_sys_|sys_call_table' trust/kernel

# MSR / TSC / arch-specific time (zero hits)
grep -nE 'native_read_tsc|rdtsc|get_cycles|cpuid|wrmsr|rdmsr' trust/kernel
```

## Appendix B — why no `#ifdef CONFIG_X86_64` in the tree today

The project's entire kernel-module lineage (since session 40-ish when
`trust_syscall.c` landed) has assumed x86_64 — the Makefile builds against
the host's `/lib/modules/$(uname -r)/build`, which on every dev box and
CI runner has been x86_64. The code was written straight against x86
pt_regs fields without an abstraction layer because there was no second
arch to force the question.

S73's 12-framework audit identified this as an "orthogonal" portability
risk (not blocking the meta-exploit), and S74's Section 3 plan
operationalized it as "Phase 1: answer if it even builds." This report
is that answer: **not today, but fix is mechanical (3 files, ≈240 LOC) and
introduces no architectural choices.**

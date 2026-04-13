/*
 * abi_thunk.S - Windows x64 <-> Linux System V ABI bridge
 *
 * Windows x64:    args in RCX, RDX, R8, R9, then stack (32-byte shadow)
 * Linux System V: args in RDI, RSI, RDX, RCX, R8, R9, then stack
 *
 * These thunks allow Linux (SysV ABI) code to call into Windows (ms_abi)
 * PE functions -- used for PE entry points, thread starts, callbacks, etc.
 *
 * Stack alignment contract:
 *   On entry (after caller's CALL pushed return address), RSP mod 16 = 8.
 *   The CALL instruction in our thunk requires RSP mod 16 = 0.
 *   Strategy: 3 PUSHes (24 bytes) + SUB 32 = 56 bytes total.
 *   RSP at CALL = (8 - 56) mod 16 = -48 mod 16 = 0.  Aligned.
 *
 * Callee-saved registers (SysV): RBX, RBP, R12-R15.
 *   We save RBP (frame pointer) and RDI/RSI (as a safety measure -- the
 *   ms_abi callee treats them as non-volatile and will preserve them, but
 *   we save them explicitly so the thunk is self-contained and correct
 *   even if the callee misbehaves).
 *   RBX and R12-R15: we never touch these, and the ms_abi callee preserves them.
 *
 * Shadow space: 32 bytes allocated above the CALL for the Windows callee.
 */

    .text
    .intel_syntax noprefix

/*
 * abi_call_win64_0 - Call a Windows ABI function with 0 args from Linux code
 *   SysV args: RDI = function pointer
 *   ms_abi args: (none)
 *
 * Stack: 3 pushes (24) + sub 32 = 56 bytes.  Entry RSP = 8 mod 16.
 *        RSP at CALL = (8 - 56) mod 16 = 0.  Aligned.
 */
    .globl abi_call_win64_0
    .type  abi_call_win64_0, @function
abi_call_win64_0:
    push   rbp
    mov    rbp, rsp
    push   rdi
    push   rsi
    sub    rsp, 32              /* 32-byte shadow space for ms_abi callee */
    mov    rax, rdi             /* function pointer -> RAX */
    call   rax
    add    rsp, 32
    pop    rsi
    pop    rdi
    pop    rbp
    ret
    .size  abi_call_win64_0, .-abi_call_win64_0

/*
 * abi_call_win64_1 - Call a Windows ABI function with 1 arg
 *   SysV args: RDI = function pointer, RSI = arg1
 *   ms_abi args: RCX = arg1
 *
 * Stack: same as _0.  Aligned.
 */
    .globl abi_call_win64_1
    .type  abi_call_win64_1, @function
abi_call_win64_1:
    push   rbp
    mov    rbp, rsp
    push   rdi
    push   rsi
    sub    rsp, 32              /* 32-byte shadow space */
    mov    rcx, rsi             /* arg1: SysV RSI -> ms_abi RCX */
    mov    rax, rdi
    call   rax
    add    rsp, 32
    pop    rsi
    pop    rdi
    pop    rbp
    ret
    .size  abi_call_win64_1, .-abi_call_win64_1

/*
 * abi_call_win64_2 - Call a Windows ABI function with 2 args
 *   SysV args: RDI = func, RSI = arg1, RDX = arg2
 *   ms_abi args: RCX = arg1, RDX = arg2
 *
 * Stack: same as _0.  Aligned.
 */
    .globl abi_call_win64_2
    .type  abi_call_win64_2, @function
abi_call_win64_2:
    push   rbp
    mov    rbp, rsp
    push   rdi
    push   rsi
    sub    rsp, 32              /* 32-byte shadow space */
    mov    rcx, rsi             /* arg1: SysV RSI -> ms_abi RCX */
    /* RDX already holds arg2 in both ABIs */
    mov    rax, rdi
    call   rax
    add    rsp, 32
    pop    rsi
    pop    rdi
    pop    rbp
    ret
    .size  abi_call_win64_2, .-abi_call_win64_2

/*
 * abi_call_win64_3 - Call a Windows ABI function with 3 args
 *   SysV args: RDI = func, RSI = arg1, RDX = arg2, RCX = arg3
 *   ms_abi args: RCX = arg1, RDX = arg2, R8 = arg3
 *
 * Register shuffling:  RCX holds arg3 (SysV) but must become arg1 (ms_abi).
 *   Must save arg3 before overwriting RCX.
 *   Order: R8 <- RCX (arg3), then RCX <- RSI (arg1). RDX stays.
 *
 * Stack: same as _0.  Aligned.
 */
    .globl abi_call_win64_3
    .type  abi_call_win64_3, @function
abi_call_win64_3:
    push   rbp
    mov    rbp, rsp
    push   rdi
    push   rsi
    sub    rsp, 32              /* 32-byte shadow space */
    mov    r8, rcx              /* arg3: SysV RCX -> ms_abi R8 (must be first!) */
    mov    rcx, rsi             /* arg1: SysV RSI -> ms_abi RCX */
    /* RDX already holds arg2 in both ABIs */
    mov    rax, rdi
    call   rax
    add    rsp, 32
    pop    rsi
    pop    rdi
    pop    rbp
    ret
    .size  abi_call_win64_3, .-abi_call_win64_3

/*
 * abi_call_win64_4 - Call a Windows ABI function with 4 args
 *   SysV args: RDI = func, RSI = arg1, RDX = arg2, RCX = arg3, R8 = arg4
 *   ms_abi args: RCX = arg1, RDX = arg2, R8 = arg3, R9 = arg4
 *
 * Register shuffling:  RCX holds arg3, R8 holds arg4.  Must move arg4
 *   before overwriting R8, and arg3 before overwriting RCX.
 *   Order: R9 <- R8 (arg4), R8 <- RCX (arg3), RCX <- RSI (arg1). RDX stays.
 *
 * Stack: same as _0.  Aligned.
 */
    .globl abi_call_win64_4
    .type  abi_call_win64_4, @function
abi_call_win64_4:
    push   rbp
    mov    rbp, rsp
    push   rdi
    push   rsi
    sub    rsp, 32              /* 32-byte shadow space */
    mov    r9, r8               /* arg4: SysV R8 -> ms_abi R9 (must be first!) */
    mov    r8, rcx              /* arg3: SysV RCX -> ms_abi R8 */
    mov    rcx, rsi             /* arg1: SysV RSI -> ms_abi RCX */
    /* RDX already holds arg2 in both ABIs */
    mov    rax, rdi
    call   rax
    add    rsp, 32
    pop    rsi
    pop    rdi
    pop    rbp
    ret
    .size  abi_call_win64_4, .-abi_call_win64_4

/*
 * The following notes describe the REVERSE direction (PE -> stub libs).
 *
 * PE code (Windows ABI) calling into our Linux stub functions:
 * Our stub libraries are compiled with __attribute__((ms_abi)), so
 * GCC/Clang handles the calling convention translation at compile time.
 * No runtime thunking is needed for this direction.
 */

    .section .note.GNU-stack,"",@progbits

#ifndef ABI_BRIDGE_H
#define ABI_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

/*
 * ABI Bridge: Windows x64 <-> Linux System V x86-64
 *
 * Windows x64 ABI:
 *   Args 1-4:  RCX, RDX, R8, R9
 *   Args 5+:   Stack (after 32-byte shadow space)
 *   Return:    RAX
 *   Callee-saved: RBX, RBP, RDI, RSI, R12-R15
 *   Caller-saved: RAX, RCX, RDX, R8, R9, R10, R11
 *
 * Linux System V ABI:
 *   Args 1-6:  RDI, RSI, RDX, RCX, R8, R9
 *   Args 7+:   Stack
 *   Return:    RAX
 *   Callee-saved: RBX, RBP, R12-R15
 *   Caller-saved: RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11
 */

/*
 * NOTE: Runtime ABI thunking is NOT needed. Our stub DLL implementations
 * use __attribute__((ms_abi)) which makes GCC/Clang handle the calling
 * convention translation at compile time. The abi_thunk_create/free
 * functions are kept as simple no-op stubs for compatibility, but the
 * thunk's code pointer just points directly to the target function.
 */

/* Create a thunk that converts Windows ABI call to Linux ABI */
typedef void *(*thunk_target_t)(void);

/*
 * Thunk descriptor. Since ms_abi handles the ABI bridge at compile time,
 * the code pointer simply equals the target pointer (direct call).
 */
typedef struct {
    void *code;         /* Pointer to callable function (== target) */
    size_t code_size;   /* Size of the thunk (0 for direct calls) */
    void *target;       /* The real function */
    int num_args;       /* Number of arguments the function takes */
} abi_thunk_t;

/* Create a thunk - no-op since ms_abi handles ABI at compile time */
int abi_thunk_create(abi_thunk_t *thunk, void *target, int num_args);

/* Free a thunk - no-op since no runtime code is allocated */
void abi_thunk_free(abi_thunk_t *thunk);

/*
 * Call a Windows-ABI function from Linux code (reverse direction).
 * Used when our code needs to call back into PE code (e.g., thread start,
 * window procedures, callbacks).
 */
uint64_t abi_call_win64_0(void *func);
uint64_t abi_call_win64_1(void *func, uint64_t a1);
uint64_t abi_call_win64_2(void *func, uint64_t a1, uint64_t a2);
uint64_t abi_call_win64_3(void *func, uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t abi_call_win64_4(void *func, uint64_t a1, uint64_t a2,
                           uint64_t a3, uint64_t a4);

#endif /* ABI_BRIDGE_H */

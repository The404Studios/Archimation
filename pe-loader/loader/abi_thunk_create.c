/*
 * abi_thunk_create.c - Stub thunk creation (no-op)
 *
 * No runtime thunking is needed because our stub DLL implementations
 * use __attribute__((ms_abi)), which makes the compiler handle the
 * Windows x64 <-> System V ABI translation at compile time.
 *
 * These functions exist only for API compatibility.
 */

#include "compat/abi_bridge.h"
#include <string.h>

/* No runtime thunking needed - our stub DLLs use __attribute__((ms_abi)) */
int abi_thunk_create(abi_thunk_t *thunk, void *target, int num_args)
{
    if (!thunk)
        return -1;
    memset(thunk, 0, sizeof(*thunk));
    thunk->target = target;
    thunk->code = target;  /* Direct call - ms_abi handles ABI */
    thunk->num_args = num_args;
    return 0;
}

void abi_thunk_free(abi_thunk_t *thunk)
{
    if (thunk) {
        memset(thunk, 0, sizeof(*thunk));
    }
}

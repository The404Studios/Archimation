/*
 * kernel32_error.c - Error handling stubs
 *
 * RaiseException delegates to ntdll's exception dispatcher.
 * SetUnhandledExceptionFilter delegates to ntdll's filter.
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "common/dll_common.h"

/* Implemented in ntdll_exception.c — must use ms_abi since they're WINAPI_EXPORT */
extern __attribute__((ms_abi)) void ntdll_RaiseException(DWORD, DWORD, DWORD, const ULONG_PTR *);
extern __attribute__((ms_abi)) void *ntdll_SetUnhandledExceptionFilter(void *);

/*
 * VEH/VCH helpers: resolve ntdll symbols at first call via dlsym.
 * On Windows these are kernel32 exports; PE binaries import them from kernel32.dll.
 * Our ntdll.so exports them under their standard names.
 */
typedef PVOID (__attribute__((ms_abi)) *veh_add_fn)(ULONG, void *);
typedef ULONG (__attribute__((ms_abi)) *veh_remove_fn)(PVOID);

static void *resolve_ntdll_sym(const char *name)
{
    /* Try RTLD_DEFAULT first (symbol may be globally visible) */
    void *sym = dlsym(RTLD_DEFAULT, name);
    if (sym)
        return sym;

    /* Try loading ntdll explicitly */
    void *ntdll = dlopen("libpe_ntdll.so", RTLD_NOW | RTLD_NOLOAD);
    if (!ntdll)
        ntdll = dlopen("./dlls/libpe_ntdll.so", RTLD_NOW | RTLD_NOLOAD);
    if (ntdll) {
        sym = dlsym(ntdll, name);
        dlclose(ntdll);
    }
    return sym;
}

WINAPI_EXPORT DWORD GetLastError(void)
{
    return get_last_error();
}

WINAPI_EXPORT void SetLastError(DWORD dwErrCode)
{
    set_last_error(dwErrCode);
}

WINAPI_EXPORT void RaiseException(
    DWORD dwExceptionCode,
    DWORD dwExceptionFlags,
    DWORD nNumberOfArguments,
    const ULONG_PTR *lpArguments)
{
    ntdll_RaiseException(dwExceptionCode, dwExceptionFlags,
                         nNumberOfArguments, lpArguments);
}

WINAPI_EXPORT LONG UnhandledExceptionFilter(void *ExceptionInfo)
{
    (void)ExceptionInfo;
    return 1; /* EXCEPTION_EXECUTE_HANDLER */
}

WINAPI_EXPORT void *SetUnhandledExceptionFilter(void *lpTopLevelExceptionFilter)
{
    return ntdll_SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
}

/*
 * Vectored Exception/Continue Handlers.
 * These are kernel32 exports on Windows. PE binaries import them from
 * kernel32.dll. Delegate to ntdll_exception.c's implementations via dlsym.
 */
WINAPI_EXPORT PVOID AddVectoredExceptionHandler(ULONG First, void *Handler)
{
    static veh_add_fn fn = NULL;
    if (!fn)
        fn = (veh_add_fn)resolve_ntdll_sym("AddVectoredExceptionHandler");
    if (fn)
        return fn(First, Handler);
    fprintf(stderr, "[kernel32] AddVectoredExceptionHandler: ntdll not available\n");
    return NULL;
}

WINAPI_EXPORT ULONG RemoveVectoredExceptionHandler(PVOID Handle)
{
    static veh_remove_fn fn = NULL;
    if (!fn)
        fn = (veh_remove_fn)resolve_ntdll_sym("RemoveVectoredExceptionHandler");
    if (fn)
        return fn(Handle);
    return 0;
}

WINAPI_EXPORT PVOID AddVectoredContinueHandler(ULONG First, void *Handler)
{
    static veh_add_fn fn = NULL;
    if (!fn)
        fn = (veh_add_fn)resolve_ntdll_sym("AddVectoredContinueHandler");
    if (fn)
        return fn(First, Handler);
    return NULL;
}

WINAPI_EXPORT ULONG RemoveVectoredContinueHandler(PVOID Handle)
{
    static veh_remove_fn fn = NULL;
    if (!fn)
        fn = (veh_remove_fn)resolve_ntdll_sym("RemoveVectoredContinueHandler");
    if (fn)
        return fn(Handle);
    return 0;
}

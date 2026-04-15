/*
 * msvcrt_except.c - C++ exception support
 *
 * Provides _CxxThrowException, __CxxFrameHandler, and SEH translator support.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "common/dll_common.h"

/* MSVC C++ exception code */
#define CXX_EXCEPTION_CODE 0xE06D7363

/* RaiseException is implemented in kernel32 */
extern void __attribute__((ms_abi)) RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags,
                              DWORD nNumberOfArguments, const ULONG_PTR *lpArguments);

/*
 * _CxxThrowException - throws a C++ exception
 * This is called by MSVC-compiled code when 'throw' is used.
 * We translate to RaiseException with the MSVC magic code.
 */
WINAPI_EXPORT void _CxxThrowException(void *pExceptionObject, void *pThrowInfo)
{
    /* 3 parameters: magic number, exception object, throw info */
    ULONG_PTR args[3];
    args[0] = 0x19930520;  /* MSVC C++ magic number */
    args[1] = (ULONG_PTR)pExceptionObject;
    args[2] = (ULONG_PTR)pThrowInfo;

    RaiseException(CXX_EXCEPTION_CODE, 1, 3, args);

    /* If RaiseException returns (shouldn't for C++ exceptions), abort */
    fprintf(stderr, "[msvcrt] _CxxThrowException: unhandled C++ exception\n");
    abort();
}

/*
 * __CxxFrameHandler3/4 - MSVC C++ frame handler
 * Called by the runtime to handle C++ exceptions in try/catch blocks.
 * Stub: we just return "continue search" to let the exception propagate.
 */
typedef enum {
    ExceptionContinueExecution = 0,
    ExceptionContinueSearch = 1,
    ExceptionNestedException = 2,
    ExceptionCollidedUnwind = 3
} EXCEPTION_DISPOSITION;

WINAPI_EXPORT EXCEPTION_DISPOSITION __CxxFrameHandler3(
    void *ExceptionRecord,
    void *EstablisherFrame,
    void *ContextRecord,
    void *DispatcherContext)
{
    (void)ExceptionRecord; (void)EstablisherFrame;
    (void)ContextRecord; (void)DispatcherContext;
    return ExceptionContinueSearch;
}

WINAPI_EXPORT EXCEPTION_DISPOSITION __CxxFrameHandler4(
    void *ExceptionRecord,
    void *EstablisherFrame,
    void *ContextRecord,
    void *DispatcherContext)
{
    (void)ExceptionRecord; (void)EstablisherFrame;
    (void)ContextRecord; (void)DispatcherContext;
    return ExceptionContinueSearch;
}

/* __C_specific_handler is an ntdll export, not msvcrt.
 * See dlls/ntdll/ntdll_exception.c for that implementation. */

WINAPI_EXPORT EXCEPTION_DISPOSITION _except_handler3(
    void *ExceptionRecord,
    void *EstablisherFrame,
    void *ContextRecord,
    void *DispatcherContext)
{
    (void)ExceptionRecord; (void)EstablisherFrame;
    (void)ContextRecord; (void)DispatcherContext;
    return ExceptionContinueSearch;
}

WINAPI_EXPORT EXCEPTION_DISPOSITION _except_handler4_common(
    void *CookiePointer,
    void *CookieCheckFunction,
    void *ExceptionRecord,
    void *EstablisherFrame,
    void *ContextRecord,
    void *DispatcherContext)
{
    (void)CookiePointer; (void)CookieCheckFunction;
    (void)ExceptionRecord; (void)EstablisherFrame;
    (void)ContextRecord; (void)DispatcherContext;
    return ExceptionContinueSearch;
}

/* _set_se_translator - set structured exception translator */
typedef void (*_se_translator_function)(unsigned int, void *);
static __thread _se_translator_function g_se_translator = NULL;

WINAPI_EXPORT _se_translator_function _set_se_translator(_se_translator_function _NewPtFunc)
{
    _se_translator_function old = g_se_translator;
    g_se_translator = _NewPtFunc;
    return old;
}

/* _XcptFilter - exception filter for main/wmain */
WINAPI_EXPORT int _XcptFilter(unsigned long xcptnum, void *pxcptinfoptrs)
{
    (void)xcptnum; (void)pxcptinfoptrs;
    return 1; /* EXCEPTION_EXECUTE_HANDLER */
}

/* __std_terminate / __std_exception_copy/destroy */
WINAPI_EXPORT void __std_terminate(void)
{
    fprintf(stderr, "[msvcrt] __std_terminate called\n");
    abort();
}

WINAPI_EXPORT void __std_exception_copy(const void *src, void *dst)
{
    /* Copy the what() string pointer */
    if (src && dst)
        memcpy(dst, src, sizeof(void *) * 2);
}

WINAPI_EXPORT void __std_exception_destroy(void *exc)
{
    /*
     * MSVC __std_exception_data layout: { const char* What; bool DoFree; }
     * The What string is heap-allocated ONLY when DoFree is true.
     * Session 23 flagged the original code which called free(exc[0]) on the
     * vtable pointer, corrupting the heap.  Check DoFree flag first.
     */
    if (!exc) return;
    struct {
        const char *what;
        unsigned char do_free;
    } *data = exc;
    if (data->do_free && data->what) {
        free((void *)data->what);
        data->what = NULL;
        data->do_free = 0;
    }
}

/* _purecall - called when a pure virtual function is invoked */
WINAPI_EXPORT int _purecall(void)
{
    fprintf(stderr, "[msvcrt] pure virtual function call\n");
    abort();
    return 0;
}

/* ----------------------------------------------------------------
 * GCC Unwinder Stubs (for libgcc_s_dw2-1.dll / libgcc_s_seh-1.dll)
 *
 * When mingw-compiled PE code calls LoadLibrary("libgcc_s_dw2-1.dll"),
 * we redirect to libpe_msvcrt.so. The CRT then calls GetProcAddress
 * for these GCC unwinder functions. They must be ms_abi since they're
 * called from PE code.
 *
 * These stubs allow the CRT init to succeed. Real exception handling
 * goes through our SEH stubs above.
 * ---------------------------------------------------------------- */

/* _Unwind_* stubs */
typedef int _Unwind_Reason_Code;
typedef int _Unwind_Action;
typedef struct _Unwind_Exception _Unwind_Exception;
typedef struct _Unwind_Context _Unwind_Context;

WINAPI_EXPORT _Unwind_Reason_Code _Unwind_RaiseException(_Unwind_Exception *exc)
{
    (void)exc;
    return 9; /* _URC_FATAL_PHASE1_ERROR */
}

WINAPI_EXPORT void _Unwind_Resume(_Unwind_Exception *exc)
{
    (void)exc;
    abort();
}

WINAPI_EXPORT void *_Unwind_GetLanguageSpecificData(_Unwind_Context *ctx)
{
    (void)ctx;
    return NULL;
}

WINAPI_EXPORT unsigned long _Unwind_GetRegionStart(_Unwind_Context *ctx)
{
    (void)ctx;
    return 0;
}

WINAPI_EXPORT unsigned long _Unwind_GetIP(_Unwind_Context *ctx)
{
    (void)ctx;
    return 0;
}

WINAPI_EXPORT void _Unwind_SetIP(_Unwind_Context *ctx, unsigned long ip)
{
    (void)ctx; (void)ip;
}

WINAPI_EXPORT void _Unwind_SetGR(_Unwind_Context *ctx, int index, unsigned long value)
{
    (void)ctx; (void)index; (void)value;
}

WINAPI_EXPORT unsigned long _Unwind_GetGR(_Unwind_Context *ctx, int index)
{
    (void)ctx; (void)index;
    return 0;
}

WINAPI_EXPORT _Unwind_Reason_Code _Unwind_ForcedUnwind(
    _Unwind_Exception *exc, void *stop, void *stop_param)
{
    (void)exc; (void)stop; (void)stop_param;
    return 9;
}

WINAPI_EXPORT void *_Unwind_GetDataRelBase(_Unwind_Context *ctx)
{
    (void)ctx;
    return NULL;
}

WINAPI_EXPORT void *_Unwind_GetTextRelBase(_Unwind_Context *ctx)
{
    (void)ctx;
    return NULL;
}

WINAPI_EXPORT void _Unwind_DeleteException(_Unwind_Exception *exc)
{
    (void)exc;
}

WINAPI_EXPORT void *_Unwind_FindEnclosingFunction(void *pc)
{
    (void)pc;
    return NULL;
}

WINAPI_EXPORT _Unwind_Reason_Code _Unwind_Backtrace(
    void *callback, void *arg)
{
    (void)callback; (void)arg;
    return 0;
}

/* __register_frame_info / __deregister_frame_info
 * Called by CRT startup to register DWARF EH frame tables.
 * For our purposes, these are no-ops. */
WINAPI_EXPORT void __register_frame_info(const void *begin, void *ob)
{
    (void)begin; (void)ob;
}

WINAPI_EXPORT void __register_frame_info_bases(
    const void *begin, void *ob, void *tbase, void *dbase)
{
    (void)begin; (void)ob; (void)tbase; (void)dbase;
}

WINAPI_EXPORT void *__deregister_frame_info(const void *begin)
{
    (void)begin;
    return NULL;
}

WINAPI_EXPORT void *__deregister_frame_info_bases(const void *begin)
{
    (void)begin;
    return NULL;
}

WINAPI_EXPORT void __register_frame(void *begin)
{
    (void)begin;
}

WINAPI_EXPORT void __deregister_frame(void *begin)
{
    (void)begin;
}

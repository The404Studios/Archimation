/*
 * kernel32_fiber.c - Fiber and Fiber Local Storage (FLS) API
 *
 * Fibers are cooperative (non-preemptive) threads. FLS is per-fiber
 * storage, analogous to TLS for threads.
 *
 * Many modern CRTs (VS2015+) and applications use FLS during init.
 * We implement FLS using thread-local storage since most apps only
 * use one fiber per thread (the main thread fiber).
 *
 * Implements: FlsAlloc, FlsFree, FlsGetValue, FlsSetValue,
 *             ConvertThreadToFiber, ConvertThreadToFiberEx,
 *             CreateFiber, CreateFiberEx, DeleteFiber,
 *             SwitchToFiber, IsThreadAFiber, GetCurrentFiber,
 *             GetFiberData.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <ucontext.h>

#include "common/dll_common.h"
#include "compat/abi_bridge.h"

/* ----------------------------------------------------------------
 * FLS (Fiber Local Storage)
 *
 * Backed by a simple per-thread array. Since we run one fiber
 * per thread, FLS indices map directly to array slots.
 * ---------------------------------------------------------------- */

#define FLS_MAX_SLOTS 256

typedef void (*PFLS_CALLBACK_FUNCTION)(PVOID lpFlsData);

static PFLS_CALLBACK_FUNCTION g_fls_callbacks[FLS_MAX_SLOTS];
static int g_fls_used[FLS_MAX_SLOTS] = {0};
static pthread_mutex_t g_fls_lock = PTHREAD_MUTEX_INITIALIZER;

/* Per-thread FLS values */
static __thread PVOID g_fls_values[FLS_MAX_SLOTS];
static __thread int g_fls_initialized = 0;

#define FLS_OUT_OF_INDEXES ((DWORD)0xFFFFFFFF)

static void fls_ensure_init(void)
{
    if (!g_fls_initialized) {
        memset(g_fls_values, 0, sizeof(g_fls_values));
        g_fls_initialized = 1;
    }
}

WINAPI_EXPORT DWORD FlsAlloc(PFLS_CALLBACK_FUNCTION lpCallback)
{
    pthread_mutex_lock(&g_fls_lock);

    for (int i = 0; i < FLS_MAX_SLOTS; i++) {
        if (!g_fls_used[i]) {
            g_fls_used[i] = 1;
            g_fls_callbacks[i] = lpCallback;
            pthread_mutex_unlock(&g_fls_lock);
            return (DWORD)i;
        }
    }

    pthread_mutex_unlock(&g_fls_lock);
    set_last_error(ERROR_NOT_ENOUGH_MEMORY);
    return FLS_OUT_OF_INDEXES;
}

WINAPI_EXPORT BOOL FlsFree(DWORD dwFlsIndex)
{
    if (dwFlsIndex >= FLS_MAX_SLOTS) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    pthread_mutex_lock(&g_fls_lock);

    if (!g_fls_used[dwFlsIndex]) {
        pthread_mutex_unlock(&g_fls_lock);
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Call the callback with the current value before freeing */
    fls_ensure_init();
    PFLS_CALLBACK_FUNCTION callback = g_fls_callbacks[dwFlsIndex];
    PVOID value = g_fls_values[dwFlsIndex];

    g_fls_used[dwFlsIndex] = 0;
    g_fls_callbacks[dwFlsIndex] = NULL;
    g_fls_values[dwFlsIndex] = NULL;

    pthread_mutex_unlock(&g_fls_lock);

    if (callback && value)
        abi_call_win64_1((void *)callback, (uint64_t)(uintptr_t)value);

    return TRUE;
}

WINAPI_EXPORT PVOID FlsGetValue(DWORD dwFlsIndex)
{
    if (dwFlsIndex >= FLS_MAX_SLOTS) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    fls_ensure_init();
    set_last_error(ERROR_SUCCESS);
    return g_fls_values[dwFlsIndex];
}

WINAPI_EXPORT BOOL FlsSetValue(DWORD dwFlsIndex, PVOID lpFlsData)
{
    if (dwFlsIndex >= FLS_MAX_SLOTS) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    fls_ensure_init();
    g_fls_values[dwFlsIndex] = lpFlsData;
    return TRUE;
}

/*
 * fls_thread_cleanup - Fire FLS callbacks for all slots with non-NULL values.
 * Must be called on thread exit (from the dying thread's context) so that
 * __thread g_fls_values[] is still accessible.  Windows fires FLS callbacks
 * before TLS callbacks on thread termination.
 */
void fls_thread_cleanup(void)
{
    if (!g_fls_initialized)
        return;

    pthread_mutex_lock(&g_fls_lock);
    for (int i = 0; i < FLS_MAX_SLOTS; i++) {
        if (g_fls_used[i] && g_fls_callbacks[i] && g_fls_values[i]) {
            PFLS_CALLBACK_FUNCTION cb = g_fls_callbacks[i];
            PVOID val = g_fls_values[i];
            g_fls_values[i] = NULL;
            pthread_mutex_unlock(&g_fls_lock);
            abi_call_win64_1((void *)cb, (uint64_t)(uintptr_t)val);
            pthread_mutex_lock(&g_fls_lock);
        }
    }
    pthread_mutex_unlock(&g_fls_lock);
}

/* ----------------------------------------------------------------
 * Fiber API
 *
 * Fibers are cooperative user-mode threads. We implement them
 * using ucontext_t for context switching.
 * ---------------------------------------------------------------- */

#define FIBER_FLAG_FLOAT_SWITCH 0x01

typedef void (*LPFIBER_START_ROUTINE)(LPVOID);

typedef struct fiber_data {
    ucontext_t          context;
    LPFIBER_START_ROUTINE start_routine;
    LPVOID              parameter;
    LPVOID              fls_data;       /* User data accessible via GetFiberData */
    void               *stack;
    size_t              stack_size;
    int                 is_thread_fiber; /* Created by ConvertThreadToFiber */
} fiber_data_t;

/* Current fiber per thread */
static __thread fiber_data_t *g_current_fiber = NULL;

static void fiber_entry(void)
{
    fiber_data_t *fiber = g_current_fiber;
    if (fiber && fiber->start_routine)
        abi_call_win64_1((void *)fiber->start_routine,
            (uint64_t)(uintptr_t)fiber->parameter);

    /* If the fiber routine returns, terminate the thread */
    pthread_exit(NULL);
}

/* Forward declarations */
WINAPI_EXPORT LPVOID ConvertThreadToFiberEx(LPVOID lpParameter, DWORD dwFlags);
WINAPI_EXPORT LPVOID CreateFiberEx(SIZE_T dwStackCommitSize, SIZE_T dwStackReserveSize,
    DWORD dwFlags, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter);

WINAPI_EXPORT LPVOID ConvertThreadToFiber(LPVOID lpParameter)
{
    return ConvertThreadToFiberEx(lpParameter, 0);
}

WINAPI_EXPORT LPVOID ConvertThreadToFiberEx(LPVOID lpParameter, DWORD dwFlags)
{
    (void)dwFlags;

    if (g_current_fiber)
        return g_current_fiber; /* Already a fiber */

    fiber_data_t * volatile fiber = calloc(1, sizeof(fiber_data_t));
    if (!fiber) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    fiber->parameter = lpParameter;
    fiber->fls_data = lpParameter;
    fiber->is_thread_fiber = 1;

    /* Save current context */
    getcontext(&fiber->context);

    g_current_fiber = fiber;
    return (LPVOID)fiber;
}

WINAPI_EXPORT LPVOID CreateFiber(SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
    return CreateFiberEx(dwStackSize, dwStackSize, 0, lpStartAddress, lpParameter);
}

WINAPI_EXPORT LPVOID CreateFiberEx(
    SIZE_T dwStackCommitSize,
    SIZE_T dwStackReserveSize,
    DWORD dwFlags,
    LPFIBER_START_ROUTINE lpStartAddress,
    LPVOID lpParameter)
{
    (void)dwStackCommitSize;
    (void)dwFlags;

    fiber_data_t * volatile fiber = calloc(1, sizeof(fiber_data_t));
    if (!fiber) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    fiber->start_routine = lpStartAddress;
    fiber->parameter = lpParameter;
    fiber->fls_data = lpParameter;
    fiber->stack_size = dwStackReserveSize > 0 ? dwStackReserveSize : (1024 * 1024);
    fiber->stack = malloc(fiber->stack_size);
    if (!fiber->stack) {
        free(fiber);
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    /* Set up the fiber context */
    getcontext(&fiber->context);
    fiber->context.uc_stack.ss_sp = fiber->stack;
    fiber->context.uc_stack.ss_size = fiber->stack_size;
    fiber->context.uc_link = NULL;
    makecontext(&fiber->context, (void (*)(void))fiber_entry, 0);

    return (LPVOID)fiber;
}

WINAPI_EXPORT void DeleteFiber(LPVOID lpFiber)
{
    fiber_data_t *fiber = (fiber_data_t *)lpFiber;
    if (!fiber) return;

    if (fiber == g_current_fiber) {
        /* Deleting current fiber - undefined behavior on Windows, but
         * we should at least not crash */
        g_current_fiber = NULL;
    }

    if (fiber->stack)
        free(fiber->stack);
    free(fiber);
}

WINAPI_EXPORT void SwitchToFiber(LPVOID lpFiber)
{
    fiber_data_t *target = (fiber_data_t *)lpFiber;
    if (!target) return;

    fiber_data_t *current = g_current_fiber;
    if (current == target)
        return; /* Already on this fiber */

    g_current_fiber = target;

    if (current)
        swapcontext(&current->context, &target->context);
    else
        setcontext(&target->context);
}

WINAPI_EXPORT BOOL IsThreadAFiber(void)
{
    return g_current_fiber != NULL;
}

WINAPI_EXPORT LPVOID GetCurrentFiber(void)
{
    return (LPVOID)g_current_fiber;
}

WINAPI_EXPORT LPVOID GetFiberData(void)
{
    if (g_current_fiber)
        return g_current_fiber->fls_data;
    return NULL;
}

/* ConvertFiberToThread - undo ConvertThreadToFiber */
WINAPI_EXPORT BOOL ConvertFiberToThread(void)
{
    if (!g_current_fiber || !g_current_fiber->is_thread_fiber) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    fiber_data_t *fiber = g_current_fiber;
    g_current_fiber = NULL;
    free(fiber);
    return TRUE;
}

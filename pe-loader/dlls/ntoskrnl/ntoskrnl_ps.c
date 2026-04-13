/*
 * ntoskrnl_ps.c - Process/Thread stubs for ntoskrnl.exe
 *
 * PsCreateSystemThread, ObReferenceObjectByHandle, etc.
 * Maps to pthreads and the handle table.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "common/dll_common.h"
#include "win32/wdm.h"
#include "compat/abi_bridge.h"

#define LOG_PREFIX "[ntoskrnl/ps] "

/* Thread wrapper: Windows thread start routine uses ms_abi */
typedef struct {
    void    *start_routine;
    PVOID   context;
} thread_wrapper_t;

static void *thread_trampoline(void *arg)
{
    thread_wrapper_t *tw = (thread_wrapper_t *)arg;
    void *routine = tw->start_routine;
    PVOID context = tw->context;
    free(tw);

    /* Call the Windows thread function via ABI bridge */
    abi_call_win64_1(routine, (uint64_t)(uintptr_t)context);
    return NULL;
}

/* ===== PsCreateSystemThread ===== */
WINAPI_EXPORT NTSTATUS PsCreateSystemThread(
    HANDLE          *ThreadHandle,
    ULONG           DesiredAccess,
    PVOID           ObjectAttributes,
    HANDLE          ProcessHandle,
    PVOID           ClientId,
    void            *StartRoutine,
    PVOID           StartContext)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)ProcessHandle;
    (void)ClientId;

    thread_wrapper_t *tw = (thread_wrapper_t *)malloc(sizeof(thread_wrapper_t));
    if (!tw)
        return STATUS_INSUFFICIENT_RESOURCES;

    tw->start_routine = StartRoutine;
    tw->context = StartContext;

    pthread_t tid;
    int rc = pthread_create(&tid, NULL, thread_trampoline, tw);
    if (rc != 0) {
        free(tw);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Detach - Windows system threads are fire-and-forget unless waited on */
    pthread_detach(tid);

    /* Return a handle wrapping the thread id */
    if (ThreadHandle) {
        *ThreadHandle = handle_alloc(HANDLE_TYPE_THREAD, -1, (void *)(uintptr_t)tid);
    }

    printf(LOG_PREFIX "PsCreateSystemThread: created thread %lu\n",
           (unsigned long)tid);
    return STATUS_SUCCESS;
}

/* ===== PsTerminateSystemThread ===== */
WINAPI_EXPORT NTSTATUS PsTerminateSystemThread(NTSTATUS ExitStatus)
{
    (void)ExitStatus;
    pthread_exit(NULL);
    return STATUS_SUCCESS; /* unreachable */
}

/* ===== PsGetCurrentProcessId / PsGetCurrentThreadId ===== */
WINAPI_EXPORT HANDLE PsGetCurrentProcessId(void)
{
    return (HANDLE)(uintptr_t)getpid();
}

WINAPI_EXPORT HANDLE PsGetCurrentThreadId(void)
{
    return (HANDLE)(uintptr_t)pthread_self();
}

/* ===== Object Manager stubs ===== */

WINAPI_EXPORT NTSTATUS ObReferenceObjectByHandle(
    HANDLE Handle, ULONG DesiredAccess, PVOID ObjectType,
    UCHAR AccessMode, PVOID *Object, PVOID HandleInformation)
{
    (void)DesiredAccess;
    (void)ObjectType;
    (void)AccessMode;
    (void)HandleInformation;

    handle_entry_t *entry = handle_lookup(Handle);
    if (!entry) {
        *Object = NULL;
        return STATUS_INVALID_HANDLE;
    }

    entry->ref_count++;
    *Object = entry->data;
    return STATUS_SUCCESS;
}

WINAPI_EXPORT void ObDereferenceObject(PVOID Object)
{
    (void)Object;
    /* In a full implementation, would decrement refcount and free */
}

WINAPI_EXPORT NTSTATUS ObReferenceObjectByPointer(
    PVOID Object, ULONG DesiredAccess, PVOID ObjectType, UCHAR AccessMode)
{
    (void)Object;
    (void)DesiredAccess;
    (void)ObjectType;
    (void)AccessMode;
    return STATUS_SUCCESS;
}

/* ===== ZwClose ===== */
WINAPI_EXPORT NTSTATUS ZwClose(HANDLE Handle)
{
    if (handle_close(Handle) == 0)
        return STATUS_SUCCESS;
    return STATUS_INVALID_HANDLE;
}

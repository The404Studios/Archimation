/*
 * ntdll_thread.c - NT native thread and process functions
 *
 * NtCreateThread, RtlCreateUserThread, NtDelayExecution, etc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sched.h>
#include <sys/syscall.h>

#include "common/dll_common.h"
#include "compat/abi_bridge.h"
#include "compat/env_setup.h"
#include "pe/pe_tls.h"

/* Thread start routine (Windows convention) */
typedef DWORD (*PUSER_THREAD_START_ROUTINE)(PVOID);

/* Thread wrapper data */
typedef struct {
    PUSER_THREAD_START_ROUTINE start_routine;
    PVOID parameter;
    int suspended;
    pthread_mutex_t suspend_lock;
    pthread_cond_t suspend_cond;
} nt_thread_data_t;

static void *nt_thread_wrapper(void *arg)
{
    nt_thread_data_t *data = (nt_thread_data_t *)arg;

    /* Set up TEB/GS register for this new thread */
    env_setup_thread();

    /* Allocate PE TLS data for this thread (populates TEB TLS slots) */
    pe_tls_alloc_thread();

    if (data->suspended) {
        pthread_mutex_lock(&data->suspend_lock);
        while (data->suspended)
            pthread_cond_wait(&data->suspend_cond, &data->suspend_lock);
        pthread_mutex_unlock(&data->suspend_lock);
    }

    PUSER_THREAD_START_ROUTINE start = data->start_routine;
    PVOID param = data->parameter;

    DWORD result = (DWORD)abi_call_win64_1((void *)start, (uint64_t)(uintptr_t)param);

    return (void *)(uintptr_t)result;
}

WINAPI_EXPORT NTSTATUS RtlCreateUserThread(
    HANDLE ProcessHandle,
    PVOID SecurityDescriptor,
    BOOL CreateSuspended,
    ULONG StackZeroBits,
    PSIZE_T StackReserve,
    PSIZE_T StackCommit,
    PVOID StartAddress,
    PVOID Parameter,
    HANDLE *ThreadHandle,
    PVOID ClientId)
{
    (void)ProcessHandle;
    (void)SecurityDescriptor;
    (void)StackZeroBits;
    (void)ClientId;

    if (!ThreadHandle || !StartAddress)
        return STATUS_INVALID_PARAMETER;

    nt_thread_data_t *data = calloc(1, sizeof(nt_thread_data_t));
    if (!data)
        return STATUS_UNSUCCESSFUL;

    data->start_routine = (PUSER_THREAD_START_ROUTINE)StartAddress;
    data->parameter = Parameter;
    data->suspended = CreateSuspended ? 1 : 0;
    pthread_mutex_init(&data->suspend_lock, NULL);
    pthread_cond_init(&data->suspend_cond, NULL);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    if (StackReserve && *StackReserve > 0)
        pthread_attr_setstacksize(&attr, *StackReserve);
    else if (StackCommit && *StackCommit > 0)
        pthread_attr_setstacksize(&attr, *StackCommit);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    pthread_t thread;
    int ret = pthread_create(&thread, &attr, nt_thread_wrapper, data);
    pthread_attr_destroy(&attr);

    if (ret != 0) {
        free(data);
        return STATUS_UNSUCCESSFUL;
    }

    *ThreadHandle = handle_alloc(HANDLE_TYPE_THREAD, -1, data);
    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtDelayExecution(BOOL Alertable, PLARGE_INTEGER DelayInterval)
{
    (void)Alertable;

    if (!DelayInterval)
        return STATUS_INVALID_PARAMETER;

    /* DelayInterval is in 100-nanosecond units, negative = relative */
    LONGLONG interval = DelayInterval->QuadPart;
    if (interval < 0)
        interval = -interval;

    /* Convert 100-ns units to nanoseconds */
    struct timespec ts;
    LONGLONG nanoseconds = interval * 100;
    ts.tv_sec = nanoseconds / 1000000000LL;
    ts.tv_nsec = nanoseconds % 1000000000LL;

    nanosleep(&ts, NULL);
    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtYieldExecution(void)
{
    sched_yield();
    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus)
{
    (void)ExitStatus;

    if (ThreadHandle == NULL || ThreadHandle == (HANDLE)(intptr_t)-1) {
        /* Terminate current thread */
        pthread_exit(NULL);
    }

    /* Can't easily kill other threads in POSIX; just return success */
    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
{
    handle_entry_t *entry = handle_lookup(ThreadHandle);
    if (!entry || entry->type != HANDLE_TYPE_THREAD)
        return STATUS_INVALID_HANDLE;

    nt_thread_data_t *data = (nt_thread_data_t *)entry->data;
    if (data && data->suspended) {
        pthread_mutex_lock(&data->suspend_lock);
        data->suspended = 0;
        pthread_cond_signal(&data->suspend_cond);
        pthread_mutex_unlock(&data->suspend_lock);
        if (PreviousSuspendCount)
            *PreviousSuspendCount = 1;
    } else {
        if (PreviousSuspendCount)
            *PreviousSuspendCount = 0;
    }

    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
{
    handle_entry_t *entry = handle_lookup(ThreadHandle);
    if (!entry || entry->type != HANDLE_TYPE_THREAD)
        return STATUS_INVALID_HANDLE;

    nt_thread_data_t *data = (nt_thread_data_t *)entry->data;
    if (data) {
        pthread_mutex_lock(&data->suspend_lock);
        if (PreviousSuspendCount)
            *PreviousSuspendCount = data->suspended ? 1 : 0;
        data->suspended = 1;
        pthread_mutex_unlock(&data->suspend_lock);
    }

    return STATUS_SUCCESS;
}

/*
 * Convert LARGE_INTEGER timeout (100-ns units, negative = relative)
 * to milliseconds for WaitForSingleObject. Returns INFINITE for NULL timeout.
 */
static DWORD nt_timeout_to_ms(PLARGE_INTEGER Timeout)
{
    if (!Timeout)
        return INFINITE;

    LONGLONG interval = Timeout->QuadPart;
    if (interval < 0)
        interval = -interval;

    /* Convert 100-ns units to milliseconds */
    LONGLONG ms = interval / 10000;
    if (ms > 0xFFFFFFFE)
        return INFINITE;
    return (DWORD)ms;
}

/* Convert WaitForSingleObject DWORD result to NTSTATUS */
static NTSTATUS wait_result_to_ntstatus(DWORD result)
{
    if (result == WAIT_OBJECT_0)
        return STATUS_SUCCESS;
    if (result == WAIT_TIMEOUT)
        return STATUS_TIMEOUT;
    return STATUS_UNSUCCESSFUL;
}

/*
 * Forward declaration: calls into kernel32's WaitForSingleObject.
 * We declare this weak so it links even if kernel32 isn't loaded yet.
 */
DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
    __attribute__((weak));
DWORD WaitForMultipleObjects(DWORD nCount, const HANDLE *lpHandles,
    BOOL bWaitAll, DWORD dwMilliseconds)
    __attribute__((weak));

WINAPI_EXPORT NTSTATUS NtWaitForSingleObject(
    HANDLE Handle,
    BOOL Alertable,
    PLARGE_INTEGER Timeout)
{
    (void)Alertable;

    handle_entry_t *entry = handle_lookup(Handle);
    if (!entry)
        return STATUS_INVALID_HANDLE;

    DWORD ms = nt_timeout_to_ms(Timeout);

    /* Delegate to kernel32's WaitForSingleObject if available */
    if (WaitForSingleObject) {
        DWORD result = WaitForSingleObject(Handle, ms);
        return wait_result_to_ntstatus(result);
    }

    /* Fallback: basic sleep-based wait */
    if (ms == INFINITE) {
        usleep(100000);
        return STATUS_SUCCESS;
    }
    usleep((useconds_t)(ms > 1000 ? 1000000 : ms * 1000));
    return STATUS_TIMEOUT;
}

WINAPI_EXPORT NTSTATUS NtWaitForMultipleObjects(
    ULONG Count,
    HANDLE *Handles,
    ULONG WaitType,
    BOOL Alertable,
    PLARGE_INTEGER Timeout)
{
    (void)Alertable;

    if (Count == 0 || !Handles)
        return STATUS_INVALID_PARAMETER;

    DWORD ms = nt_timeout_to_ms(Timeout);
    BOOL bWaitAll = (WaitType == 0) ? TRUE : FALSE; /* WaitAll=0, WaitAny=1 */

    /* Delegate to kernel32's WaitForMultipleObjects if available */
    if (WaitForMultipleObjects) {
        DWORD result = WaitForMultipleObjects(Count, (const HANDLE *)Handles,
                                               bWaitAll, ms);
        if (result < WAIT_OBJECT_0 + Count)
            return STATUS_SUCCESS;
        if (result == WAIT_TIMEOUT)
            return STATUS_TIMEOUT;
        return STATUS_UNSUCCESSFUL;
    }

    /* Fallback: basic sleep */
    if (ms == INFINITE)
        usleep(100000);
    else
        usleep((useconds_t)(ms > 1000 ? 1000000 : ms * 1000));
    return STATUS_SUCCESS;
}

/* Thread ID helpers */
WINAPI_EXPORT DWORD RtlGetCurrentThreadId(void)
{
    return (DWORD)syscall(SYS_gettid);
}

WINAPI_EXPORT DWORD RtlGetCurrentProcessId(void)
{
    return (DWORD)getpid();
}

/* Process/thread cookie (stack cookie for security) */
WINAPI_EXPORT NTSTATUS NtSetInformationThread(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength)
{
    (void)ThreadHandle;
    (void)ThreadInformationClass;
    (void)ThreadInformation;
    (void)ThreadInformationLength;
    return STATUS_SUCCESS;
}

/* NtQueryInformationThread is defined in ntdll_main.c (uses env_get_teb()) */

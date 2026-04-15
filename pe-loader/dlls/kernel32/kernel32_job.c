/*
 * kernel32_job.c - Windows Job Object stubs
 *
 * Stubs for CreateJobObject{A,W}, OpenJobObject{A,W},
 * AssignProcessToJobObject, SetInformationJobObject,
 * QueryInformationJobObject, TerminateJobObject, and
 * IsProcessInJob.
 *
 * Chromium/Edge/Firefox sandbox init paths rely on these.
 * We claim success without real cgroup enforcement — job
 * objects become bookkeeping in the handle table.  Sandboxes
 * typically configure limits once (SetInformationJobObject)
 * and then AssignProcessToJobObject; both paths just store
 * and return TRUE so the sandbox boots.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#include "common/dll_common.h"
#include "kernel32_internal.h"

/* ---------- Local constants (not in project headers) ---------- */

/* Error code missing from winnt.h — pick canonical Windows value. */
#ifndef ERROR_NOT_FOUND
#define ERROR_NOT_FOUND 1168
#endif

/* Handle type for job objects. dll_common.h's HANDLE_DTOR_SLOTS is 64 and
 * the highest defined value is HANDLE_TYPE_IOCP (25), so 26 is safe. */
#ifndef HANDLE_TYPE_JOB
#define HANDLE_TYPE_JOB 27
#endif

/* PBOOL missing from project headers — MSDN defines it as BOOL*. */
#ifndef _PBOOL_DEFINED
#define _PBOOL_DEFINED
typedef BOOL *PBOOL;
#endif

/* JOBOBJECTINFOCLASS values (subset — Chromium/Edge touch these) */
#define JobObjectBasicAccountingInformation     1
#define JobObjectBasicLimitInformation          2
#define JobObjectBasicProcessIdList             3
#define JobObjectBasicUIRestrictions            4
#define JobObjectSecurityLimitInformation       5
#define JobObjectEndOfJobTimeInformation        6
#define JobObjectAssociateCompletionPortInfo    7
#define JobObjectBasicAndIoAccountingInformation 8
#define JobObjectExtendedLimitInformation       9
#define JobObjectJobSetInformation              10
#define JobObjectGroupInformation               11

/* MSDN layout for JOBOBJECT_BASIC_LIMIT_INFORMATION on x64:
 *   LARGE_INTEGER PerProcessUserTimeLimit   (8)
 *   LARGE_INTEGER PerJobUserTimeLimit       (8)
 *   DWORD         LimitFlags                (4)
 *   <padding>                               (4)
 *   SIZE_T        MinimumWorkingSetSize     (8)
 *   SIZE_T        MaximumWorkingSetSize     (8)
 *   DWORD         ActiveProcessLimit        (4)
 *   <padding>                               (4)
 *   ULONG_PTR     Affinity                  (8)
 *   DWORD         PriorityClass             (4)
 *   DWORD         SchedulingClass           (4)
 * Total: 64 bytes.
 */
typedef struct {
    LARGE_INTEGER PerProcessUserTimeLimit;
    LARGE_INTEGER PerJobUserTimeLimit;
    DWORD         LimitFlags;
    SIZE_T        MinimumWorkingSetSize;
    SIZE_T        MaximumWorkingSetSize;
    DWORD         ActiveProcessLimit;
    ULONG_PTR     Affinity;
    DWORD         PriorityClass;
    DWORD         SchedulingClass;
} JOBOBJECT_BASIC_LIMIT_INFORMATION;

/* IO_COUNTERS is 6x ULONGLONG = 48 bytes. */
typedef struct {
    ULONGLONG ReadOperationCount;
    ULONGLONG WriteOperationCount;
    ULONGLONG OtherOperationCount;
    ULONGLONG ReadTransferCount;
    ULONGLONG WriteTransferCount;
    ULONGLONG OtherTransferCount;
} JOB_IO_COUNTERS;

/* JOBOBJECT_EXTENDED_LIMIT_INFORMATION — basic + IO + memory + peaks. */
typedef struct {
    JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
    JOB_IO_COUNTERS                   IoInfo;
    SIZE_T                            ProcessMemoryLimit;
    SIZE_T                            JobMemoryLimit;
    SIZE_T                            PeakProcessMemoryUsed;
    SIZE_T                            PeakJobMemoryUsed;
} JOBOBJECT_EXTENDED_LIMIT_INFORMATION;

/* JOBOBJECT_BASIC_UI_RESTRICTIONS — one DWORD flags field. */
typedef struct {
    DWORD UIRestrictionsClass;
} JOBOBJECT_BASIC_UI_RESTRICTIONS;

/* JOBOBJECT_BASIC_ACCOUNTING_INFORMATION — returned by query. */
typedef struct {
    LARGE_INTEGER TotalUserTime;
    LARGE_INTEGER TotalKernelTime;
    LARGE_INTEGER ThisPeriodTotalUserTime;
    LARGE_INTEGER ThisPeriodTotalKernelTime;
    DWORD         TotalPageFaultCount;
    DWORD         TotalProcesses;
    DWORD         ActiveProcesses;
    DWORD         TotalTerminatedProcesses;
} JOBOBJECT_BASIC_ACCOUNTING_INFORMATION;

/* ---------- Job data ---------- */

#define JOB_MAX_PIDS 256

typedef struct {
    uint32_t        type_tag;      /* sanity check: 'JOB\0' */
    pthread_mutex_t lock;
    uint32_t        pid_count;
    uint32_t        pids[JOB_MAX_PIDS];

    int             has_basic_limits;
    int             has_ext_limits;
    int             has_ui_restrictions;

    JOBOBJECT_BASIC_LIMIT_INFORMATION      basic_limits;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION   ext_limits;
    JOBOBJECT_BASIC_UI_RESTRICTIONS        ui_restrictions;
} job_data_t;

#define JOB_TYPE_TAG 0x004A4F42u /* 'J','O','B',0 little-endian */

/* ---------- Helpers ---------- */

/* Look up a job handle.  Returns NULL with last-error set on failure. */
static job_data_t *job_lookup(HANDLE h)
{
    if (!h || h == (HANDLE)(intptr_t)-1) {
        set_last_error(ERROR_INVALID_HANDLE);
        return NULL;
    }
    handle_entry_t *e = handle_lookup(h);
    if (!e || e->type != HANDLE_TYPE_JOB || !e->data) {
        set_last_error(ERROR_INVALID_HANDLE);
        return NULL;
    }
    job_data_t *jd = (job_data_t *)e->data;
    if (jd->type_tag != JOB_TYPE_TAG) {
        set_last_error(ERROR_INVALID_HANDLE);
        return NULL;
    }
    return jd;
}

/* Defined in kernel32_process.c — resolves a Win32 process HANDLE
 * (real, duplicated, or pseudo) to a Linux PID.  Returns 0 on failure,
 * getpid() for the current-process pseudo-handle ((HANDLE)-1 or NULL).
 * Returns 0 for the thread pseudo-handle ((HANDLE)-2).  Handles with
 * HANDLE_FLAG_DUP are readable (borrowed data).  */
extern int kernel32_process_handle_to_pid(HANDLE hProcess);

/* ---------- Destructor ---------- */

static void destroy_job(const handle_entry_t *entry)
{
    if (!entry || !entry->data) return;
    job_data_t *jd = (job_data_t *)entry->data;
    pthread_mutex_destroy(&jd->lock);
    free(jd);
}

__attribute__((constructor))
static void kernel32_job_register_dtor(void)
{
    handle_register_dtor((handle_type_t)HANDLE_TYPE_JOB, destroy_job);
}

/* ---------- Exports ---------- */

WINAPI_EXPORT HANDLE CreateJobObjectA(LPSECURITY_ATTRIBUTES lpJobAttributes,
                                      LPCSTR lpName)
{
    (void)lpJobAttributes;
    (void)lpName; /* named jobs: ignored for stub — every call returns a fresh job */

    job_data_t *jd = calloc(1, sizeof(job_data_t));
    if (!jd) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    jd->type_tag = JOB_TYPE_TAG;
    if (pthread_mutex_init(&jd->lock, NULL) != 0) {
        free(jd);
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    HANDLE h = handle_alloc((handle_type_t)HANDLE_TYPE_JOB, -1, jd);
    if (!h) {
        pthread_mutex_destroy(&jd->lock);
        free(jd);
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    set_last_error(ERROR_SUCCESS);
    return h;
}

WINAPI_EXPORT HANDLE CreateJobObjectW(LPSECURITY_ATTRIBUTES lpJobAttributes,
                                      LPCWSTR lpName)
{
    /* Name is ignored — forward with NULL narrow name. */
    (void)lpName;
    return CreateJobObjectA(lpJobAttributes, NULL);
}

WINAPI_EXPORT HANDLE OpenJobObjectA(DWORD dwDesiredAccess, BOOL bInheritHandle,
                                    LPCSTR lpName)
{
    (void)dwDesiredAccess;
    (void)bInheritHandle;
    (void)lpName;
    /* We do not track named jobs cross-process. */
    set_last_error(ERROR_NOT_FOUND);
    return NULL;
}

WINAPI_EXPORT HANDLE OpenJobObjectW(DWORD dwDesiredAccess, BOOL bInheritHandle,
                                    LPCWSTR lpName)
{
    (void)lpName;
    return OpenJobObjectA(dwDesiredAccess, bInheritHandle, NULL);
}

WINAPI_EXPORT BOOL AssignProcessToJobObject(HANDLE hJob, HANDLE hProcess)
{
    job_data_t *jd = job_lookup(hJob);
    if (!jd) return FALSE;

    /* Resolve HANDLE -> PID.  Covers:
     *   (HANDLE)-1 or NULL -> getpid() (Chromium sandbox needs this)
     *   real HANDLE_TYPE_PROCESS -> process_data_t->pid
     *   DuplicateHandle'd (HANDLE_FLAG_DUP) -> still readable
     *   GetCurrentThread() (-2) -> 0 (invalid for process param)
     */
    int pid = kernel32_process_handle_to_pid(hProcess);
    if (pid <= 0) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    pthread_mutex_lock(&jd->lock);
    /* Dedup: don't add same PID twice (idempotent reassign). */
    for (uint32_t i = 0; i < jd->pid_count; i++) {
        if (jd->pids[i] == (uint32_t)pid) {
            pthread_mutex_unlock(&jd->lock);
            set_last_error(ERROR_SUCCESS);
            return TRUE;
        }
    }
    if (jd->pid_count >= JOB_MAX_PIDS) {
        pthread_mutex_unlock(&jd->lock);
        set_last_error(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    jd->pids[jd->pid_count++] = (uint32_t)pid;
    pthread_mutex_unlock(&jd->lock);
    set_last_error(ERROR_SUCCESS);
    return TRUE;
}

WINAPI_EXPORT BOOL SetInformationJobObject(HANDLE hJob,
                                           DWORD JobObjectInformationClass,
                                           LPVOID lpJobObjectInformation,
                                           DWORD cbJobObjectInformationLength)
{
    job_data_t *jd = job_lookup(hJob);
    if (!jd) return FALSE;

    if (!lpJobObjectInformation || cbJobObjectInformationLength == 0) {
        /* Some classes accept NULL, but treat empty as success for stubs. */
        set_last_error(ERROR_SUCCESS);
        return TRUE;
    }

    pthread_mutex_lock(&jd->lock);
    switch (JobObjectInformationClass) {
    case JobObjectBasicLimitInformation:
        if (cbJobObjectInformationLength >= sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION)) {
            memcpy(&jd->basic_limits, lpJobObjectInformation,
                   sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION));
            jd->has_basic_limits = 1;
        }
        break;
    case JobObjectExtendedLimitInformation:
        if (cbJobObjectInformationLength >= sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)) {
            memcpy(&jd->ext_limits, lpJobObjectInformation,
                   sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            jd->has_ext_limits = 1;
            /* Extended contains basic — keep basic_limits mirrored. */
            jd->basic_limits = jd->ext_limits.BasicLimitInformation;
            jd->has_basic_limits = 1;
        }
        break;
    case JobObjectBasicUIRestrictions:
        if (cbJobObjectInformationLength >= sizeof(JOBOBJECT_BASIC_UI_RESTRICTIONS)) {
            memcpy(&jd->ui_restrictions, lpJobObjectInformation,
                   sizeof(JOBOBJECT_BASIC_UI_RESTRICTIONS));
            jd->has_ui_restrictions = 1;
        }
        break;
    default:
        /* Unknown class: pretend we stored it. */
        break;
    }
    pthread_mutex_unlock(&jd->lock);
    set_last_error(ERROR_SUCCESS);
    return TRUE;
}

WINAPI_EXPORT BOOL QueryInformationJobObject(HANDLE hJob,
                                             DWORD JobObjectInformationClass,
                                             LPVOID lpJobObjectInformation,
                                             DWORD cbJobObjectInformationLength,
                                             LPDWORD lpReturnLength)
{
    /* QueryInformationJobObject allows hJob == NULL to query the current
     * process's ambient job.  We have none, so treat that as "no job". */
    if (!hJob) {
        if (lpReturnLength) *lpReturnLength = 0;
        if (lpJobObjectInformation && cbJobObjectInformationLength)
            memset(lpJobObjectInformation, 0, cbJobObjectInformationLength);
        set_last_error(ERROR_SUCCESS);
        return TRUE;
    }

    job_data_t *jd = job_lookup(hJob);
    if (!jd) return FALSE;

    if (!lpJobObjectInformation) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    DWORD need = 0;
    pthread_mutex_lock(&jd->lock);
    switch (JobObjectInformationClass) {
    case JobObjectBasicLimitInformation:
        need = sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION);
        if (cbJobObjectInformationLength < need) break;
        memcpy(lpJobObjectInformation, &jd->basic_limits, need);
        break;
    case JobObjectExtendedLimitInformation:
        need = sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
        if (cbJobObjectInformationLength < need) break;
        memcpy(lpJobObjectInformation, &jd->ext_limits, need);
        break;
    case JobObjectBasicUIRestrictions:
        need = sizeof(JOBOBJECT_BASIC_UI_RESTRICTIONS);
        if (cbJobObjectInformationLength < need) break;
        memcpy(lpJobObjectInformation, &jd->ui_restrictions, need);
        break;
    case JobObjectBasicAccountingInformation: {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acc;
        memset(&acc, 0, sizeof(acc));
        acc.ActiveProcesses = jd->pid_count;
        acc.TotalProcesses  = jd->pid_count;
        need = sizeof(acc);
        if (cbJobObjectInformationLength < need) break;
        memcpy(lpJobObjectInformation, &acc, need);
        break;
    }
    case JobObjectBasicProcessIdList: {
        /* struct JOBOBJECT_BASIC_PROCESS_ID_LIST {
         *     DWORD     NumberOfAssignedProcesses;
         *     DWORD     NumberOfProcessIdsInList;
         *     ULONG_PTR ProcessIdList[1];
         * };  Chromium/Edge sandbox walks this to confirm assignment. */
        DWORD header = sizeof(DWORD) * 2;
        DWORD fit = 0;
        if (cbJobObjectInformationLength > header)
            fit = (cbJobObjectInformationLength - header) / sizeof(ULONG_PTR);
        DWORD to_copy = jd->pid_count < fit ? jd->pid_count : fit;
        need = header + (DWORD)(jd->pid_count * sizeof(ULONG_PTR));
        if (cbJobObjectInformationLength < header) break;
        DWORD *out = (DWORD *)lpJobObjectInformation;
        out[0] = jd->pid_count;        /* NumberOfAssignedProcesses */
        out[1] = to_copy;              /* NumberOfProcessIdsInList */
        ULONG_PTR *list = (ULONG_PTR *)((char *)lpJobObjectInformation + header);
        for (DWORD i = 0; i < to_copy; i++)
            list[i] = (ULONG_PTR)jd->pids[i];
        /* If the buffer was shorter than full list, still report the
         * actual required size via `need`. */
        break;
    }
    default:
        /* Unknown class: zero the output buffer and succeed. */
        need = cbJobObjectInformationLength;
        memset(lpJobObjectInformation, 0, cbJobObjectInformationLength);
        break;
    }
    pthread_mutex_unlock(&jd->lock);

    if (lpReturnLength) *lpReturnLength = need;

    if (need > cbJobObjectInformationLength) {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    set_last_error(ERROR_SUCCESS);
    return TRUE;
}

WINAPI_EXPORT BOOL TerminateJobObject(HANDLE hJob, UINT uExitCode)
{
    (void)uExitCode;
    job_data_t *jd = job_lookup(hJob);
    if (!jd) return FALSE;

    /* Snapshot PID list under lock; signal outside to avoid holding
     * the lock while the kernel delivers the signal. */
    pid_t snap[JOB_MAX_PIDS];
    uint32_t n;
    pthread_mutex_lock(&jd->lock);
    n = jd->pid_count;
    for (uint32_t i = 0; i < n; i++) snap[i] = (pid_t)jd->pids[i];
    jd->pid_count = 0;
    pthread_mutex_unlock(&jd->lock);

    pid_t self = getpid();
    for (uint32_t i = 0; i < n; i++) {
        pid_t p = snap[i];
        /* Guard rails:
         *   pid <= 0: kill(0) signals the whole process group, kill(-1)
         *             signals every process we can reach. Never do that.
         *   pid == 1: init. Also never.
         *   pid == self: killing our own process here would prevent the
         *             caller from ever seeing the return value.  Windows
         *             would actually terminate the caller, but that's a
         *             sandbox-suicide pattern we don't want to replicate.
         */
        if (p <= 1 || p == self) continue;
        /* Best-effort SIGTERM — ignore ESRCH/EPERM for dead/foreign PIDs. */
        (void)kill(p, SIGTERM);
    }
    set_last_error(ERROR_SUCCESS);
    return TRUE;
}

WINAPI_EXPORT BOOL IsProcessInJob(HANDLE hProcess, HANDLE hJob, PBOOL Result)
{
    if (!Result) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *Result = FALSE;

    /* Resolve hProcess -- pseudo-handle (HANDLE)-1 maps to getpid(). */
    int pid = kernel32_process_handle_to_pid(hProcess);
    if (pid <= 0) {
        /* Unknown handle: treat as not-in-any-job rather than failing so
         * Chromium-style "check if we're sandboxed" probes succeed. */
        set_last_error(ERROR_SUCCESS);
        return TRUE;
    }

    /* Null job means "is the process in any job it can be queried for".
     * We have no ambient-job tracking, so the answer is always FALSE. */
    if (!hJob) {
        set_last_error(ERROR_SUCCESS);
        return TRUE;
    }

    job_data_t *jd = job_lookup(hJob);
    if (!jd) return FALSE;

    pthread_mutex_lock(&jd->lock);
    for (uint32_t i = 0; i < jd->pid_count; i++) {
        if (jd->pids[i] == (uint32_t)pid) {
            *Result = TRUE;
            break;
        }
    }
    pthread_mutex_unlock(&jd->lock);
    set_last_error(ERROR_SUCCESS);
    return TRUE;
}

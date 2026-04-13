/*
 * ntdll_process.c - NT process and object functions
 *
 * NtOpenProcess, NtReadVirtualMemory, NtWriteVirtualMemory,
 * NtDuplicateObject, NtQueryObject.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sched.h>
#include <time.h>
#include <sys/uio.h>

#include "common/dll_common.h"
#include "compat/trust_gate.h"

/* NTSTATUS values (supplement those in winnt.h) */
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL     0xC0000023
#endif

/* OBJECT_ATTRIBUTES */
#ifndef _OBJECT_ATTRIBUTES_DEFINED
#define _OBJECT_ATTRIBUTES_DEFINED
typedef struct {
    ULONG Length;
    HANDLE RootDirectory;
    void *ObjectName;
    ULONG Attributes;
    void *SecurityDescriptor;
    void *SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
#endif

/* CLIENT_ID */
typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

/* ---------- NtOpenProcess ---------- */

WINAPI_EXPORT NTSTATUS NtOpenProcess(HANDLE *ProcessHandle,
                                      DWORD DesiredAccess,
                                      OBJECT_ATTRIBUTES *ObjectAttributes,
                                      CLIENT_ID *ClientId)
{
    (void)DesiredAccess; (void)ObjectAttributes;
    if (!ProcessHandle || !ClientId) return STATUS_INVALID_PARAMETER;

    /* Return the PID as a pseudo-handle */
    pid_t pid = (pid_t)(uintptr_t)ClientId->UniqueProcess;

    /* Check if process exists */
    if (kill(pid, 0) != 0 && errno == ESRCH)
        return STATUS_INVALID_PARAMETER;

    *ProcessHandle = (HANDLE)(uintptr_t)pid;
    return STATUS_SUCCESS;
}

/* ---------- NtReadVirtualMemory ---------- */

WINAPI_EXPORT NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle,
                                            PVOID BaseAddress,
                                            PVOID Buffer,
                                            SIZE_T NumberOfBytesToRead,
                                            SIZE_T *NumberOfBytesRead)
{
    if (!Buffer) return STATUS_INVALID_PARAMETER;

    pid_t pid = (pid_t)(uintptr_t)ProcessHandle;

    /* Self-process */
    if (pid == getpid() || ProcessHandle == (HANDLE)(intptr_t)-1) {
        memcpy(Buffer, BaseAddress, NumberOfBytesToRead);
        if (NumberOfBytesRead) *NumberOfBytesRead = NumberOfBytesToRead;
        return STATUS_SUCCESS;
    }

    struct iovec local = { Buffer, NumberOfBytesToRead };
    struct iovec remote = { BaseAddress, NumberOfBytesToRead };
    ssize_t result = process_vm_readv(pid, &local, 1, &remote, 1, 0);

    if (result < 0) return STATUS_ACCESS_DENIED;
    if (NumberOfBytesRead) *NumberOfBytesRead = (SIZE_T)result;
    return STATUS_SUCCESS;
}

/* ---------- NtWriteVirtualMemory ---------- */

WINAPI_EXPORT NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle,
                                             PVOID BaseAddress,
                                             PVOID Buffer,
                                             SIZE_T NumberOfBytesToWrite,
                                             SIZE_T *NumberOfBytesWritten)
{
    if (!Buffer) return STATUS_INVALID_PARAMETER;

    pid_t pid = (pid_t)(uintptr_t)ProcessHandle;

    if (pid == getpid() || ProcessHandle == (HANDLE)(intptr_t)-1) {
        memcpy(BaseAddress, Buffer, NumberOfBytesToWrite);
        if (NumberOfBytesWritten) *NumberOfBytesWritten = NumberOfBytesToWrite;
        return STATUS_SUCCESS;
    }

    struct iovec local = { Buffer, NumberOfBytesToWrite };
    struct iovec remote = { BaseAddress, NumberOfBytesToWrite };
    ssize_t result = process_vm_writev(pid, &local, 1, &remote, 1, 0);

    if (result < 0) return STATUS_ACCESS_DENIED;
    if (NumberOfBytesWritten) *NumberOfBytesWritten = (SIZE_T)result;
    return STATUS_SUCCESS;
}

/* ---------- NtDuplicateObject ---------- */

WINAPI_EXPORT NTSTATUS NtDuplicateObject(HANDLE SourceProcessHandle,
                                          HANDLE SourceHandle,
                                          HANDLE TargetProcessHandle,
                                          HANDLE *TargetHandle,
                                          DWORD DesiredAccess,
                                          DWORD HandleAttributes,
                                          DWORD Options)
{
    (void)SourceProcessHandle; (void)TargetProcessHandle;
    (void)DesiredAccess; (void)HandleAttributes; (void)Options;

    if (!TargetHandle) return STATUS_INVALID_PARAMETER;

    handle_entry_t *entry = handle_lookup(SourceHandle);
    if (!entry) return STATUS_INVALID_HANDLE;

    /* Duplicate by allocating a new handle pointing to same data.
     * Increment source ref_count so the shared data/fd isn't freed
     * when the duplicate is closed. */
    entry->ref_count++;

    HANDLE dup = handle_alloc(entry->type, entry->fd, entry->data);
    if (dup == INVALID_HANDLE_VALUE) {
        entry->ref_count--;
        return STATUS_INVALID_HANDLE;
    }

    *TargetHandle = dup;
    return STATUS_SUCCESS;
}

/* ---------- RtlPcToFileHeader ---------- */

WINAPI_EXPORT void *RtlPcToFileHeader(void *PcValue, void **BaseOfImage)
{
    (void)PcValue;
    if (BaseOfImage) *BaseOfImage = NULL;
    return NULL;
}

/* ---------- NtQueryObject ---------- */

/* OBJECT_INFORMATION_CLASS */
#define ObjectBasicInformation  0
#define ObjectNameInformation   1
#define ObjectTypeInformation   2

WINAPI_EXPORT NTSTATUS NtQueryObject(HANDLE Handle, int ObjectInformationClass,
                                      PVOID ObjectInformation, ULONG ObjectInformationLength,
                                      ULONG *ReturnLength)
{
    (void)Handle;

    switch (ObjectInformationClass) {
    case ObjectBasicInformation: {
        ULONG needed = 56; /* sizeof(OBJECT_BASIC_INFORMATION) */
        if (ReturnLength) *ReturnLength = needed;
        if (ObjectInformationLength < needed) return STATUS_INFO_LENGTH_MISMATCH;
        if (ObjectInformation) memset(ObjectInformation, 0, needed);
        return STATUS_SUCCESS;
    }
    case ObjectTypeInformation: {
        ULONG needed = 128;
        if (ReturnLength) *ReturnLength = needed;
        if (ObjectInformationLength < needed) return STATUS_INFO_LENGTH_MISMATCH;
        if (ObjectInformation) memset(ObjectInformation, 0, needed);
        return STATUS_SUCCESS;
    }
    default:
        return STATUS_NOT_IMPLEMENTED;
    }
}

/* ---------- NtCreateProcess ---------- */

WINAPI_EXPORT NTSTATUS NtCreateProcess(HANDLE *ProcessHandle,
                                        DWORD DesiredAccess,
                                        OBJECT_ATTRIBUTES *ObjectAttributes,
                                        HANDLE ParentProcess,
                                        BOOL InheritObjectTable,
                                        HANDLE SectionHandle,
                                        HANDLE DebugPort,
                                        HANDLE ExceptionPort)
{
    TRUST_CHECK_RET(TRUST_GATE_PROCESS_CREATE, "NtCreateProcess", STATUS_ACCESS_DENIED);
    (void)DesiredAccess; (void)ObjectAttributes; (void)ParentProcess;
    (void)InheritObjectTable; (void)SectionHandle; (void)DebugPort;
    (void)ExceptionPort;

    if (!ProcessHandle) return STATUS_INVALID_PARAMETER;

    /* Stub: process creation not fully implemented */
    return STATUS_NOT_IMPLEMENTED;
}

/* ---------- NtCreateProcessEx ---------- */

WINAPI_EXPORT NTSTATUS NtCreateProcessEx(HANDLE *ProcessHandle,
                                          DWORD DesiredAccess,
                                          OBJECT_ATTRIBUTES *ObjectAttributes,
                                          HANDLE ParentProcess,
                                          ULONG Flags,
                                          HANDLE SectionHandle,
                                          HANDLE DebugPort,
                                          HANDLE ExceptionPort,
                                          ULONG JobMemberLevel)
{
    TRUST_CHECK_RET(TRUST_GATE_PROCESS_CREATE, "NtCreateProcessEx", STATUS_ACCESS_DENIED);
    (void)DesiredAccess; (void)ObjectAttributes; (void)ParentProcess;
    (void)Flags; (void)SectionHandle; (void)DebugPort;
    (void)ExceptionPort; (void)JobMemberLevel;

    if (!ProcessHandle) return STATUS_INVALID_PARAMETER;

    /* Stub: process creation not fully implemented */
    return STATUS_NOT_IMPLEMENTED;
}

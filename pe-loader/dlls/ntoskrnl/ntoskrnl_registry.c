/*
 * ntoskrnl_registry.c - Registry stubs for ntoskrnl.exe
 *
 * ZwOpenKey, ZwQueryValueKey, etc.
 * Returns sensible defaults for common queries.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common/dll_common.h"
#include "win32/wdm.h"

#define LOG_PREFIX "[ntoskrnl/reg] "

/* Registry value types */
#define REG_NONE        0
#define REG_SZ          1
#define REG_EXPAND_SZ   2
#define REG_BINARY      3
#define REG_DWORD       4
#define REG_MULTI_SZ    7
#define REG_QWORD       11

/* Key information classes */
#define KeyBasicInformation         0
#define KeyFullInformation          2

/* Value information classes */
#define KeyValueBasicInformation    0
#define KeyValueFullInformation     1
#define KeyValuePartialInformation  2

typedef struct {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1]; /* Variable length */
} KEY_VALUE_PARTIAL_INFORMATION;

/* ===== ZwOpenKey ===== */
WINAPI_EXPORT NTSTATUS ZwOpenKey(
    HANDLE *KeyHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
    (void)DesiredAccess;

    if (!KeyHandle || !ObjectAttributes || !ObjectAttributes->ObjectName)
        return STATUS_INVALID_PARAMETER;

    PUNICODE_STRING name = ObjectAttributes->ObjectName;
    static const uint16_t null_str[] = {'(','n','u','l','l',')',0};
    /* Print key name as narrow */
    if (name->Buffer) {
        char nb[512];
        size_t ni;
        for (ni = 0; name->Buffer[ni] && ni < 511; ni++)
            nb[ni] = (char)(name->Buffer[ni] & 0xFF);
        nb[ni] = '\0';
        printf(LOG_PREFIX "ZwOpenKey: '%s'\n", nb);
    } else {
        printf(LOG_PREFIX "ZwOpenKey: '(null)'\n");
    }
    (void)null_str;

    /* Return a dummy handle */
    *KeyHandle = handle_alloc(HANDLE_TYPE_REGISTRY_KEY, -1, NULL);
    if (!*KeyHandle)
        return STATUS_INSUFFICIENT_RESOURCES;

    return STATUS_SUCCESS;
}

/* ===== ZwQueryValueKey ===== */
WINAPI_EXPORT NTSTATUS ZwQueryValueKey(
    HANDLE KeyHandle, PUNICODE_STRING ValueName,
    ULONG KeyValueInformationClass,
    PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
{
    (void)KeyHandle;
    (void)KeyValueInformationClass;

    if (!ValueName)
        return STATUS_INVALID_PARAMETER;

    if (ValueName->Buffer) {
        char nb[512];
        size_t ni;
        for (ni = 0; ValueName->Buffer[ni] && ni < 511; ni++)
            nb[ni] = (char)(ValueName->Buffer[ni] & 0xFF);
        nb[ni] = '\0';
        printf(LOG_PREFIX "ZwQueryValueKey: '%s'\n", nb);
    } else {
        printf(LOG_PREFIX "ZwQueryValueKey: '(null)'\n");
    }

    /* Return STATUS_OBJECT_NAME_NOT_FOUND for unknown keys */
    if (ResultLength)
        *ResultLength = 0;
    (void)KeyValueInformation;
    (void)Length;

    return STATUS_OBJECT_NAME_NOT_FOUND;
}

/* ===== ZwSetValueKey ===== */
WINAPI_EXPORT NTSTATUS ZwSetValueKey(
    HANDLE KeyHandle, PUNICODE_STRING ValueName,
    ULONG TitleIndex, ULONG Type,
    PVOID Data, ULONG DataSize)
{
    (void)KeyHandle;
    (void)TitleIndex;
    (void)Type;
    (void)Data;
    (void)DataSize;

    {
        char nb[512];
        const char *display = "(null)";
        if (ValueName && ValueName->Buffer) {
            size_t ni;
            for (ni = 0; ValueName->Buffer[ni] && ni < 511; ni++)
                nb[ni] = (char)(ValueName->Buffer[ni] & 0xFF);
            nb[ni] = '\0';
            display = nb;
        }
        printf(LOG_PREFIX "ZwSetValueKey: '%s' (type=%u, size=%u) - STUB\n",
               display, Type, DataSize);
    }

    return STATUS_SUCCESS;
}

/* ===== ZwCreateKey ===== */
WINAPI_EXPORT NTSTATUS ZwCreateKey(
    HANDLE *KeyHandle, ULONG DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex, PUNICODE_STRING Class,
    ULONG CreateOptions, PULONG Disposition)
{
    (void)DesiredAccess;
    (void)TitleIndex;
    (void)Class;
    (void)CreateOptions;

    if (!KeyHandle || !ObjectAttributes)
        return STATUS_INVALID_PARAMETER;

    *KeyHandle = handle_alloc(HANDLE_TYPE_REGISTRY_KEY, -1, NULL);
    if (Disposition)
        *Disposition = 1; /* REG_CREATED_NEW_KEY */

    return STATUS_SUCCESS;
}

/* ===== ZwEnumerateKey ===== */
WINAPI_EXPORT NTSTATUS ZwEnumerateKey(
    HANDLE KeyHandle, ULONG Index, ULONG KeyInformationClass,
    PVOID KeyInformation, ULONG Length, PULONG ResultLength)
{
    (void)KeyHandle;
    (void)Index;
    (void)KeyInformationClass;
    (void)KeyInformation;
    (void)Length;
    if (ResultLength)
        *ResultLength = 0;
    return STATUS_NO_MORE_ENTRIES;
}

/* ===== ZwEnumerateValueKey ===== */
WINAPI_EXPORT NTSTATUS ZwEnumerateValueKey(
    HANDLE KeyHandle, ULONG Index, ULONG KeyValueInformationClass,
    PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
{
    (void)KeyHandle;
    (void)Index;
    (void)KeyValueInformationClass;
    (void)KeyValueInformation;
    (void)Length;
    if (ResultLength)
        *ResultLength = 0;
    return STATUS_NO_MORE_ENTRIES;
}

/* ===== ZwDeleteKey / ZwDeleteValueKey ===== */
WINAPI_EXPORT NTSTATUS ZwDeleteKey(HANDLE KeyHandle)
{
    (void)KeyHandle;
    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS ZwDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName)
{
    (void)KeyHandle;
    (void)ValueName;
    return STATUS_SUCCESS;
}

/*
 * ntoskrnl_rtl.c - Runtime Library stubs for ntoskrnl.exe
 *
 * String operations (UNICODE_STRING, ANSI_STRING),
 * debug printing, and basic RTL helpers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common/dll_common.h"
#include "win32/wdm.h"
#include "compat/ms_abi_format.h"

#define LOG_PREFIX "[ntoskrnl/rtl] "

/* RtlInitUnicodeString, RtlFreeUnicodeString: canonical home is ntdll
 * (ntdll_main.c). Removed duplicates from ntoskrnl to avoid symbol
 * conflicts between the two .so files. */

WINAPI_EXPORT void RtlCopyUnicodeString(
    PUNICODE_STRING Dest, PUNICODE_STRING Src)
{
    if (!Dest || !Src)
        return;

    if (Dest->MaximumLength < sizeof(WCHAR)) {
        Dest->Length = 0;
        return;
    }
    USHORT copy_len = Src->Length;
    if (copy_len > Dest->MaximumLength - sizeof(WCHAR))
        copy_len = Dest->MaximumLength - sizeof(WCHAR);

    if (Dest->Buffer && Src->Buffer) {
        memcpy(Dest->Buffer, Src->Buffer, copy_len);
        Dest->Length = copy_len;
        /* Null-terminate if space */
        if (copy_len < Dest->MaximumLength)
            Dest->Buffer[copy_len / sizeof(WCHAR)] = 0;
    }
}

WINAPI_EXPORT LONG RtlCompareUnicodeString(
    PUNICODE_STRING String1, PUNICODE_STRING String2,
    BOOLEAN CaseInSensitive)
{
    if (!String1 || !String2)
        return 0;

    USHORT len = String1->Length < String2->Length
        ? String1->Length : String2->Length;
    USHORT chars = len / sizeof(WCHAR);

    for (USHORT i = 0; i < chars; i++) {
        WCHAR c1 = String1->Buffer[i];
        WCHAR c2 = String2->Buffer[i];
        if (CaseInSensitive) {
            if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
            if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
        }
        if (c1 != c2)
            return (LONG)c1 - (LONG)c2;
    }

    return (LONG)String1->Length - (LONG)String2->Length;
}

WINAPI_EXPORT BOOLEAN RtlEqualUnicodeString(
    PUNICODE_STRING String1, PUNICODE_STRING String2,
    BOOLEAN CaseInSensitive)
{
    return RtlCompareUnicodeString(String1, String2, CaseInSensitive) == 0;
}

WINAPI_EXPORT NTSTATUS RtlUpcaseUnicodeString(
    PUNICODE_STRING Dest, PUNICODE_STRING Src, BOOLEAN AllocateDestinationString)
{
    if (!Dest || !Src)
        return STATUS_INVALID_PARAMETER;

    if (AllocateDestinationString) {
        Dest->Buffer = (PWSTR)malloc(Src->Length + sizeof(WCHAR));
        if (!Dest->Buffer)
            return STATUS_INSUFFICIENT_RESOURCES;
        Dest->MaximumLength = Src->Length + sizeof(WCHAR);
    }

    Dest->Length = Src->Length;
    USHORT chars = Src->Length / sizeof(WCHAR);
    for (USHORT i = 0; i < chars; i++) {
        WCHAR c = Src->Buffer[i];
        Dest->Buffer[i] = (c >= 'a' && c <= 'z') ? c - 32 : c;
    }
    if (Dest->Length < Dest->MaximumLength)
        Dest->Buffer[chars] = 0;

    return STATUS_SUCCESS;
}

/* ===== ANSI_STRING operations ===== */

/* RtlInitAnsiString: canonical home is ntdll (ntdll_main.c).
 * Removed duplicate from ntoskrnl. */

WINAPI_EXPORT NTSTATUS RtlAnsiStringToUnicodeString(
    PUNICODE_STRING Dest, PANSI_STRING Src, BOOLEAN AllocateDestinationString)
{
    if (!Dest || !Src)
        return STATUS_INVALID_PARAMETER;

    USHORT wlen = Src->Length * sizeof(WCHAR);

    if (AllocateDestinationString) {
        Dest->Buffer = (PWSTR)malloc(wlen + sizeof(WCHAR));
        if (!Dest->Buffer)
            return STATUS_INSUFFICIENT_RESOURCES;
        Dest->MaximumLength = wlen + sizeof(WCHAR);
    }

    if (wlen > Dest->MaximumLength - sizeof(WCHAR))
        wlen = Dest->MaximumLength - sizeof(WCHAR);

    Dest->Length = wlen;
    for (USHORT i = 0; i < Src->Length && i < wlen / sizeof(WCHAR); i++)
        Dest->Buffer[i] = (WCHAR)(unsigned char)Src->Buffer[i];

    if (wlen < Dest->MaximumLength)
        Dest->Buffer[wlen / sizeof(WCHAR)] = 0;

    return STATUS_SUCCESS;
}

WINAPI_EXPORT NTSTATUS RtlUnicodeStringToAnsiString(
    PANSI_STRING Dest, PUNICODE_STRING Src, BOOLEAN AllocateDestinationString)
{
    if (!Dest || !Src)
        return STATUS_INVALID_PARAMETER;

    USHORT alen = Src->Length / sizeof(WCHAR);

    if (AllocateDestinationString) {
        Dest->Buffer = (PSTR)malloc(alen + 1);
        if (!Dest->Buffer)
            return STATUS_INSUFFICIENT_RESOURCES;
        Dest->MaximumLength = alen + 1;
    }

    if (alen > Dest->MaximumLength - 1)
        alen = Dest->MaximumLength - 1;

    Dest->Length = alen;
    for (USHORT i = 0; i < alen; i++)
        Dest->Buffer[i] = (CHAR)(Src->Buffer[i] & 0xFF);
    Dest->Buffer[alen] = 0;

    return STATUS_SUCCESS;
}

/* ===== Debug printing ===== */

/* DbgPrint: canonical home is ntdll (ntdll_main.c).
 * Removed duplicate from ntoskrnl. */

/* DbgPrintEx is only in ntoskrnl (not in ntdll), so it stays here. */
WINAPI_EXPORT ULONG DbgPrintEx(
    ULONG ComponentId, ULONG Level, const char *Format, ...)
{
    (void)ComponentId;
    (void)Level;
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, Format);
    fprintf(stderr, "[DbgPrint] ");
    int ret = ms_abi_vformat(stderr, NULL, 0, Format, args);
    __builtin_ms_va_end(args);
    return (ULONG)ret;
}

/* ===== Misc RTL ===== */

WINAPI_EXPORT ULONG RtlRandomEx(PULONG Seed)
{
    if (Seed) {
        *Seed = *Seed * 1103515245 + 12345;
        return *Seed >> 16;
    }
    return 0;
}

WINAPI_EXPORT NTSTATUS RtlGUIDFromString(
    PUNICODE_STRING GuidString, PVOID Guid)
{
    (void)GuidString;
    (void)Guid;
    return STATUS_NOT_IMPLEMENTED;
}

WINAPI_EXPORT NTSTATUS RtlStringFromGUID(
    PVOID Guid, PUNICODE_STRING GuidString)
{
    (void)Guid;
    (void)GuidString;
    return STATUS_NOT_IMPLEMENTED;
}

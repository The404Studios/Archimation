/*
 * combase_winrt.c - WinRT foundation (combase.dll)
 *
 * UE5 calls RoInitialize() on startup and uses HSTRING for WinRT APIs.
 * RoGetActivationFactory returns CLASS_E_CLASSNOTAVAILABLE to force
 * UE5 to fall back to XInput/DirectInput for gamepads.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>

#include "common/dll_common.h"

#define COMBASE_LOG "[combase] "

/* HRESULT codes */
#define S_OK                      ((HRESULT)0x00000000)
#define S_FALSE                   ((HRESULT)0x00000001)
#define E_OUTOFMEMORY             ((HRESULT)0x8007000E)
#define E_NOTIMPL                 ((HRESULT)0x80004001)
#define E_INVALIDARG              ((HRESULT)0x80070057)
#define RO_E_CLOSED               ((HRESULT)0x80000013)
#define CLASS_E_CLASSNOTAVAILABLE ((HRESULT)0x80040111)

/* Forward declaration for use in RoGetActivationFactory */
WINAPI_EXPORT const uint16_t *WindowsGetStringRawBuffer(void *string, uint32_t *length);

/* RO_INIT_TYPE */
#define RO_INIT_SINGLETHREADED 0
#define RO_INIT_MULTITHREADED  1

/*
 * WinRT apartments: UE5 + other apps may call RoInitialize/RoUninitialize
 * from worker threads and pool allocators concurrently. A plain int counter
 * had torn-read/lost-increment races; use atomic_int (single-word relaxed
 * updates are cheap on both old HW and new HW). */
static atomic_int g_ro_init_count = 0;

/* ========== WinRT Initialization ========== */

WINAPI_EXPORT HRESULT RoInitialize(uint32_t initType)
{
    (void)initType;
    int n = atomic_fetch_add(&g_ro_init_count, 1) + 1;
    fprintf(stderr, COMBASE_LOG "RoInitialize(%s): OK (count=%d)\n",
            initType == RO_INIT_MULTITHREADED ? "MTA" : "STA", n);
    return S_OK;
}

WINAPI_EXPORT void RoUninitialize(void)
{
    /* Saturate at zero so over-releasing callers don't push negative. */
    for (;;) {
        int cur = atomic_load(&g_ro_init_count);
        if (cur <= 0) return;
        if (atomic_compare_exchange_weak(&g_ro_init_count, &cur, cur - 1))
            return;
    }
}

/* ========== Activation Factories ========== */

/*
 * Return CLASS_E_CLASSNOTAVAILABLE for all activation factories.
 * This forces UE5 to fall back to non-WinRT codepaths:
 *   - Windows.Gaming.Input → falls back to XInput/DirectInput
 *   - Windows.System.Profile → falls back to GetSystemInfo()
 *   - etc.
 */
WINAPI_EXPORT HRESULT RoGetActivationFactory(
    void *activatableClassId, const GUID *iid, void **factory)
{
    (void)iid;

    /* Log what class was requested for debugging */
    if (activatableClassId) {
        /* HSTRING — try to extract the string for logging */
        uint32_t len = 0;
        const uint16_t *buf = WindowsGetStringRawBuffer(activatableClassId, &len);
        if (buf && len > 0) {
            char narrow[256];
            int i;
            for (i = 0; i < (int)len && i < 255; i++)
                narrow[i] = (buf[i] < 128) ? (char)buf[i] : '?';
            narrow[i] = '\0';
            fprintf(stderr, COMBASE_LOG "RoGetActivationFactory(\"%s\"): not available\n", narrow);
        } else {
            fprintf(stderr, COMBASE_LOG "RoGetActivationFactory: not available\n");
        }
    }

    if (factory) *factory = NULL;
    return CLASS_E_CLASSNOTAVAILABLE;
}

WINAPI_EXPORT HRESULT RoActivateInstance(void *activatableClassId, void **instance)
{
    (void)activatableClassId;
    if (instance) *instance = NULL;
    return CLASS_E_CLASSNOTAVAILABLE;
}

WINAPI_EXPORT HRESULT RoRegisterActivationFactories(
    void *activatableClassIds, void *activationFactoryCallbacks,
    uint32_t count, void *cookie)
{
    (void)activatableClassIds; (void)activationFactoryCallbacks;
    (void)count; (void)cookie;
    return S_OK;
}

WINAPI_EXPORT void RoRevokeActivationFactories(void *cookie)
{
    (void)cookie;
}

/* ========== HSTRING Implementation ========== */

/*
 * HSTRING is an opaque handle to a reference-counted UTF-16 string.
 * Internally it's a pointer to hstring_internal_t.
 * NULL HSTRING represents the empty string.
 */

typedef struct {
    uint32_t ref_count;
    uint32_t length;        /* In uint16_t units, NOT including null terminator */
    uint16_t *buffer;       /* Heap-allocated copy (or reference) */
    int is_reference;       /* 1 = WindowsCreateStringReference (buffer not owned) */
} hstring_internal_t;

WINAPI_EXPORT HRESULT WindowsCreateString(
    const uint16_t *sourceString, uint32_t length, void **string)
{
    if (!string) return E_INVALIDARG;

    if (!sourceString || length == 0) {
        *string = NULL; /* Empty HSTRING = NULL */
        return S_OK;
    }

    /* Guard against (length + 1) overflow when computing buffer bytes. */
    if (length >= (UINT32_MAX / sizeof(uint16_t)) - 1)
        return E_OUTOFMEMORY;

    hstring_internal_t *hs = calloc(1, sizeof(hstring_internal_t));
    if (!hs) return E_OUTOFMEMORY;

    hs->ref_count = 1;
    hs->length = length;
    hs->is_reference = 0;

    /* Allocate buffer with null terminator */
    hs->buffer = malloc((length + 1) * sizeof(uint16_t));
    if (!hs->buffer) {
        free(hs);
        return E_OUTOFMEMORY;
    }
    memcpy(hs->buffer, sourceString, length * sizeof(uint16_t));
    hs->buffer[length] = 0;

    *string = hs;
    return S_OK;
}

/*
 * WindowsCreateStringReference creates a non-owning reference.
 * The caller must keep sourceString alive for the lifetime of the HSTRING.
 * hstringHeader is an opaque buffer the caller provides (we use our own struct).
 */
WINAPI_EXPORT HRESULT WindowsCreateStringReference(
    const uint16_t *sourceString, uint32_t length,
    void *hstringHeader, void **string)
{
    if (!string || !hstringHeader) return E_INVALIDARG;

    if (!sourceString || length == 0) {
        *string = NULL;
        return S_OK;
    }

    /* Use hstringHeader as our internal struct storage */
    hstring_internal_t *hs = (hstring_internal_t *)hstringHeader;
    hs->ref_count = 1;
    hs->length = length;
    hs->buffer = (uint16_t *)sourceString; /* Non-owning reference */
    hs->is_reference = 1;

    *string = hs;
    return S_OK;
}

WINAPI_EXPORT HRESULT WindowsDeleteString(void *string)
{
    if (!string) return S_OK;

    hstring_internal_t *hs = (hstring_internal_t *)string;
    if (hs->ref_count > 0) hs->ref_count--;

    if (hs->ref_count == 0 && !hs->is_reference) {
        free(hs->buffer);
        free(hs);
    }
    return S_OK;
}

WINAPI_EXPORT const uint16_t *WindowsGetStringRawBuffer(void *string, uint32_t *length)
{
    static const uint16_t empty_str[] = { 0 };

    if (!string) {
        if (length) *length = 0;
        return empty_str;
    }

    hstring_internal_t *hs = (hstring_internal_t *)string;
    if (length) *length = hs->length;
    return hs->buffer ? hs->buffer : empty_str;
}

WINAPI_EXPORT BOOL WindowsIsStringEmpty(void *string)
{
    if (!string) return TRUE;
    hstring_internal_t *hs = (hstring_internal_t *)string;
    return hs->length == 0;
}

WINAPI_EXPORT uint32_t WindowsGetStringLen(void *string)
{
    if (!string) return 0;
    return ((hstring_internal_t *)string)->length;
}

WINAPI_EXPORT HRESULT WindowsDuplicateString(void *string, void **newString)
{
    if (!newString) return E_INVALIDARG;

    if (!string) {
        *newString = NULL;
        return S_OK;
    }

    hstring_internal_t *src = (hstring_internal_t *)string;

    /* If it's a reference, create an owned copy */
    return WindowsCreateString(src->buffer, src->length, newString);
}

WINAPI_EXPORT HRESULT WindowsStringHasEmbeddedNull(void *string, BOOL *hasEmbedNull)
{
    if (!hasEmbedNull) return E_INVALIDARG;
    *hasEmbedNull = FALSE;

    if (!string) return S_OK;

    hstring_internal_t *hs = (hstring_internal_t *)string;
    for (uint32_t i = 0; i < hs->length; i++) {
        if (hs->buffer[i] == 0) {
            *hasEmbedNull = TRUE;
            break;
        }
    }
    return S_OK;
}

WINAPI_EXPORT HRESULT WindowsCompareStringOrdinal(
    void *string1, void *string2, int32_t *result)
{
    if (!result) return E_INVALIDARG;

    uint32_t len1 = 0, len2 = 0;
    const uint16_t *buf1 = WindowsGetStringRawBuffer(string1, &len1);
    const uint16_t *buf2 = WindowsGetStringRawBuffer(string2, &len2);

    uint32_t min_len = len1 < len2 ? len1 : len2;
    for (uint32_t i = 0; i < min_len; i++) {
        if (buf1[i] != buf2[i]) {
            *result = (buf1[i] < buf2[i]) ? -1 : 1;
            return S_OK;
        }
    }
    *result = (len1 < len2) ? -1 : (len1 > len2) ? 1 : 0;
    return S_OK;
}

WINAPI_EXPORT HRESULT WindowsConcatString(void *string1, void *string2, void **newString)
{
    if (!newString) return E_INVALIDARG;

    uint32_t len1 = 0, len2 = 0;
    const uint16_t *buf1 = WindowsGetStringRawBuffer(string1, &len1);
    const uint16_t *buf2 = WindowsGetStringRawBuffer(string2, &len2);

    /* Guard against len1 + len2 overflow. */
    if (len1 > UINT32_MAX - len2)
        return E_OUTOFMEMORY;
    uint32_t total = len1 + len2;
    if (total == 0) {
        *newString = NULL;
        return S_OK;
    }

    uint16_t *combined = malloc((total + 1) * sizeof(uint16_t));
    if (!combined) return E_OUTOFMEMORY;

    if (len1 > 0) memcpy(combined, buf1, len1 * sizeof(uint16_t));
    if (len2 > 0) memcpy(combined + len1, buf2, len2 * sizeof(uint16_t));
    combined[total] = 0;

    HRESULT hr = WindowsCreateString(combined, total, newString);
    free(combined);
    return hr;
}

WINAPI_EXPORT HRESULT WindowsSubstring(void *string, uint32_t startIndex, void **newString)
{
    if (!newString) return E_INVALIDARG;

    uint32_t len = 0;
    const uint16_t *buf = WindowsGetStringRawBuffer(string, &len);

    if (startIndex > len) return E_INVALIDARG;
    if (startIndex == len) {
        *newString = NULL;
        return S_OK;
    }

    return WindowsCreateString(buf + startIndex, len - startIndex, newString);
}

WINAPI_EXPORT HRESULT WindowsSubstringWithSpecifiedLength(
    void *string, uint32_t startIndex, uint32_t length, void **newString)
{
    if (!newString) return E_INVALIDARG;

    uint32_t srcLen = 0;
    const uint16_t *buf = WindowsGetStringRawBuffer(string, &srcLen);

    /* Use subtraction form to avoid overflow in startIndex + length. */
    if (startIndex > srcLen || length > srcLen - startIndex)
        return E_INVALIDARG;

    return WindowsCreateString(buf + startIndex, length, newString);
}

/* ========== RoBuffer (IBufferByteAccess) ========== */

WINAPI_EXPORT HRESULT RoGetBufferMarshaler(void **bufferMarshaler)
{
    (void)bufferMarshaler;
    return E_NOTIMPL;
}

/* ========== Error Reporting ========== */

WINAPI_EXPORT HRESULT RoOriginateError(HRESULT error, void *message)
{
    (void)error; (void)message;
    return S_OK;
}

WINAPI_EXPORT HRESULT RoOriginateErrorW(HRESULT error, uint32_t cchMax,
                                          const uint16_t *message)
{
    (void)error; (void)cchMax; (void)message;
    return S_OK;
}

WINAPI_EXPORT BOOL RoOriginateLanguageException(
    HRESULT error, void *message, void *languageException)
{
    (void)error; (void)message; (void)languageException;
    return FALSE;
}

WINAPI_EXPORT HRESULT RoTransformError(HRESULT oldError, HRESULT newError, void *message)
{
    (void)oldError; (void)message;
    return newError;
}

WINAPI_EXPORT HRESULT GetRestrictedErrorInfo(void **ppRestrictedErrorInfo)
{
    if (ppRestrictedErrorInfo) *ppRestrictedErrorInfo = NULL;
    return S_FALSE; /* No error info available */
}

WINAPI_EXPORT HRESULT SetRestrictedErrorInfo(void *pRestrictedErrorInfo)
{
    (void)pRestrictedErrorInfo;
    return S_OK;
}

/* ========== COM marshaling helpers ========== */

WINAPI_EXPORT HRESULT CoIncrementMTAUsage(void *pCookie)
{
    if (pCookie) *(void **)pCookie = (void *)(uintptr_t)0xCB010001;
    return S_OK;
}

WINAPI_EXPORT HRESULT CoDecrementMTAUsage(void *cookie)
{
    (void)cookie;
    return S_OK;
}

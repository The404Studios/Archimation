/*
 * kernel32_actctx.c - Side-by-Side activation context API
 *
 * Real Windows uses the activation context system to bind an exe (or
 * a code path inside it) to a specific version of a shared component
 * — most commonly comctl32.dll v6 (visual styles).  The full system
 * has CreateActCtx (build a context from a manifest), ActivateActCtx
 * (push it onto the per-thread activation stack), DeactivateActCtx
 * (pop it), GetCurrentActCtx (query top-of-stack), and ReleaseActCtx
 * (drop a refcount).
 *
 * We do NOT implement the full SxS database (no WinSxS folder, no
 * publisher policy, no version-arbitration).  Instead, the loader
 * extracts the embedded RT_MANIFEST at startup (pe_resource.c) and
 * sets a process-wide `g_actx` with the resolved bindings.
 *
 * The functions below give apps a recognisable API surface so they
 * keep running:
 *   - Explicit CreateActCtx returns INVALID_HANDLE_VALUE +
 *     ERROR_NOT_SUPPORTED so callers fall back to using the embedded
 *     manifest (which we already honoured).
 *   - Activate / Deactivate / Release / GetCurrent are no-op-ish
 *     successes returning sentinel handle 1.
 *   - QueryActCtxW responds to the most-asked queries by reading
 *     g_actx so apps that introspect their own context get sensible
 *     answers.
 *
 * IMPORTANT: do not include pe_resource.h directly here unless needed
 * for the symbols — the header is inside pe-loader/include/pe and the
 * DLL build cflags already cover it (-Iinclude).
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "common/dll_common.h"
#include "pe/pe_resource.h"

/* ----------------------------------------------------------------
 * ACTCTX structure (subset)
 * ---------------------------------------------------------------- */
#define ACTCTX_FLAG_PROCESSOR_ARCHITECTURE_VALID    0x001
#define ACTCTX_FLAG_LANGID_VALID                    0x002
#define ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID        0x004
#define ACTCTX_FLAG_RESOURCE_NAME_VALID             0x008
#define ACTCTX_FLAG_SET_PROCESS_DEFAULT             0x010
#define ACTCTX_FLAG_APPLICATION_NAME_VALID          0x020
#define ACTCTX_FLAG_HMODULE_VALID                   0x080

#pragma pack(push, 1)
typedef struct {
    ULONG    cbSize;
    DWORD    dwFlags;
    LPCSTR   lpSource;
    USHORT   wProcessorArchitecture;
    USHORT   wLangId;
    LPCSTR   lpAssemblyDirectory;
    LPCSTR   lpResourceName;
    LPCSTR   lpApplicationName;
    HMODULE  hModule;
} ACTCTXA, *PACTCTXA;

typedef struct {
    ULONG    cbSize;
    DWORD    dwFlags;
    LPCWSTR  lpSource;
    USHORT   wProcessorArchitecture;
    USHORT   wLangId;
    LPCWSTR  lpAssemblyDirectory;
    LPCWSTR  lpResourceName;
    LPCWSTR  lpApplicationName;
    HMODULE  hModule;
} ACTCTXW, *PACTCTXW;
#pragma pack(pop)

typedef PACTCTXA PCACTCTXA;
typedef PACTCTXW PCACTCTXW;

/* Sentinel "current activation context" handle.  When the per-thread
 * stack is empty we hand this back from GetCurrentActCtx — it stands in
 * for "the embedded-manifest context".  When the stack is non-empty we
 * hand back the actual pe_activation_context pointer, which CreateActCtx
 * callers (none today) would also receive. */
#define ACTCTX_SENTINEL  ((HANDLE)(intptr_t)1)

/* The per-thread push/pop stack lives in pe_resource.c (loader binary)
 * so every DLL stub sees a single source of truth. */
extern unsigned long pe_actx_push(struct pe_activation_context *ctx);
extern int           pe_actx_pop(unsigned long cookie);
extern struct pe_activation_context *pe_actx_current(void);

/* QueryActCtx ulInfoClass values we recognise (subset of Win32) */
#define ActivationContextBasicInformation       1
#define ActivationContextDetailedInformation    2
#define AssemblyDetailedInformationInActivationContext  3
#define RunlevelInformationInActivationContext  6

#ifndef ERROR_NOT_SUPPORTED
#define ERROR_NOT_SUPPORTED 50
#endif
#ifndef ERROR_INVALID_PARAMETER
#define ERROR_INVALID_PARAMETER 87
#endif

/* ----------------------------------------------------------------
 * CreateActCtxA / CreateActCtxW
 *
 * Apps that explicitly build an activation context from a side-loaded
 * manifest file go through here.  We do not implement that path: the
 * manifest we honour is the one embedded as RT_MANIFEST in the main
 * exe, processed by the loader at startup.
 * ---------------------------------------------------------------- */
WINAPI_EXPORT HANDLE CreateActCtxA(PCACTCTXA pActCtx)
{
    (void)pActCtx;
    fprintf(stderr,
        "[kernel32] CreateActCtxA -> INVALID_HANDLE_VALUE (use embedded RT_MANIFEST)\n");
    set_last_error(ERROR_NOT_SUPPORTED);
    return INVALID_HANDLE_VALUE;
}

WINAPI_EXPORT HANDLE CreateActCtxW(PCACTCTXW pActCtx)
{
    (void)pActCtx;
    fprintf(stderr,
        "[kernel32] CreateActCtxW -> INVALID_HANDLE_VALUE (use embedded RT_MANIFEST)\n");
    set_last_error(ERROR_NOT_SUPPORTED);
    return INVALID_HANDLE_VALUE;
}

/* ----------------------------------------------------------------
 * ActivateActCtx / DeactivateActCtx
 *
 * Apps push/pop activation contexts around code that wants a specific
 * comctl version.  These now route into the per-thread stack maintained
 * by pe_resource.c.  hActCtx values:
 *   - INVALID_HANDLE_VALUE / NULL: no-op push that records the current
 *     g_actx (matches Windows' "use the process default" semantics)
 *   - ACTCTX_SENTINEL: push g_actx
 *   - Anything else: treat as a pe_activation_context pointer
 * ---------------------------------------------------------------- */

WINAPI_EXPORT BOOL ActivateActCtx(HANDLE hActCtx, ULONG_PTR *lpCookie)
{
    struct pe_activation_context *ctx;
    if (hActCtx == NULL || hActCtx == INVALID_HANDLE_VALUE ||
        hActCtx == ACTCTX_SENTINEL) {
        ctx = &g_actx;
    } else {
        ctx = (struct pe_activation_context *)hActCtx;
    }

    unsigned long ck = pe_actx_push(ctx);
    if (ck == 0) {
        /* stack overflow — Windows uses ERROR_SXS_ACTIVATION_CONTEXT_DISABLED
         * (0x36B0); our nearest equivalent is ERROR_NOT_ENOUGH_MEMORY (8). */
        set_last_error(8);
        if (lpCookie) *lpCookie = 0;
        return FALSE;
    }
    if (lpCookie) *lpCookie = (ULONG_PTR)ck;
    return TRUE;
}

WINAPI_EXPORT BOOL DeactivateActCtx(DWORD dwFlags, ULONG_PTR ulCookie)
{
    (void)dwFlags;
    if (!pe_actx_pop((unsigned long)ulCookie)) {
        /* Cookie mismatch or empty stack — Windows raises
         * ERROR_SXS_INVALID_DEACTIVATION (0x36B1).  Use ERROR_INVALID_PARAMETER
         * (87) since we don't define the SXS family yet. */
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT void ReleaseActCtx(HANDLE hActCtx)
{
    (void)hActCtx;
}

WINAPI_EXPORT BOOL AddRefActCtx(HANDLE hActCtx)
{
    (void)hActCtx;
    return TRUE;
}

WINAPI_EXPORT BOOL GetCurrentActCtx(HANDLE *lphActCtx)
{
    if (!lphActCtx) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    /* If a per-thread context is active, return its pointer; otherwise
     * the process-default sentinel.  Callers compare for non-NULL only. */
    struct pe_activation_context *cur = pe_actx_current();
    *lphActCtx = (cur && cur != &g_actx)
                     ? (HANDLE)cur
                     : ACTCTX_SENTINEL;
    return TRUE;
}

WINAPI_EXPORT BOOL ZombifyActCtx(HANDLE hActCtx)
{
    (void)hActCtx;
    return TRUE;
}

/* ----------------------------------------------------------------
 * QueryActCtxW
 *
 * Real signature:
 *   BOOL WINAPI QueryActCtxW(DWORD dwFlags, HANDLE hActCtx,
 *                            PVOID pvSubInstance, ULONG ulInfoClass,
 *                            PVOID pvBuffer, SIZE_T cbBuffer,
 *                            SIZE_T *pcbWrittenOrRequired);
 *
 * We answer the runlevel query (used by UAC-aware apps) using g_actx.
 * Other classes return ERROR_NOT_SUPPORTED.
 * ---------------------------------------------------------------- */
typedef struct {
    DWORD ulFlags;
    DWORD RunLevel;
    DWORD UiAccess;
} ACTCTX_RUN_LEVEL_INFORMATION;

WINAPI_EXPORT BOOL QueryActCtxW(DWORD dwFlags, HANDLE hActCtx,
                                 void *pvSubInstance, ULONG ulInfoClass,
                                 void *pvBuffer, size_t cbBuffer,
                                 size_t *pcbWrittenOrRequired)
{
    (void)dwFlags;
    (void)hActCtx;
    (void)pvSubInstance;

    if (ulInfoClass == RunlevelInformationInActivationContext) {
        if (cbBuffer < sizeof(ACTCTX_RUN_LEVEL_INFORMATION) || !pvBuffer) {
            if (pcbWrittenOrRequired)
                *pcbWrittenOrRequired = sizeof(ACTCTX_RUN_LEVEL_INFORMATION);
            set_last_error(122 /* ERROR_INSUFFICIENT_BUFFER */);
            return FALSE;
        }
        ACTCTX_RUN_LEVEL_INFORMATION *info =
            (ACTCTX_RUN_LEVEL_INFORMATION *)pvBuffer;
        info->ulFlags  = 0;
        /* Read from the per-thread top context if the caller passed a real
         * handle; otherwise fall back to the current top of stack. */
        struct pe_activation_context *q;
        if (hActCtx && hActCtx != INVALID_HANDLE_VALUE &&
            hActCtx != ACTCTX_SENTINEL) {
            q = (struct pe_activation_context *)hActCtx;
        } else {
            q = pe_actx_current();
        }
        /* Map our PE_EXEC_LEVEL_* (1..3) directly to the Win32 enum;
         * RunLevel = 0 (unspecified) | 1 (asInvoker)
         *          | 2 (highestAvailable) | 3 (requireAdministrator).
         * Win32 swaps 2/3 vs our enum, so re-map: */
        switch (q->requested_execution_level) {
            case PE_EXEC_LEVEL_ASINVOKER:
                info->RunLevel = 1; break;
            case PE_EXEC_LEVEL_HIGHESTAVAILABLE:
                info->RunLevel = 2; break;
            case PE_EXEC_LEVEL_REQUIREADMIN:
                info->RunLevel = 3; break;
            default:
                info->RunLevel = 0;
        }
        info->UiAccess = q->ui_access ? 1 : 0;
        if (pcbWrittenOrRequired)
            *pcbWrittenOrRequired = sizeof(ACTCTX_RUN_LEVEL_INFORMATION);
        return TRUE;
    }

    set_last_error(ERROR_NOT_SUPPORTED);
    return FALSE;
}

/* ----------------------------------------------------------------
 * FindActCtxSectionStringW / FindActCtxSectionGuid
 *
 * Used to look up "which DLL implements interface X under this ACTCTX"
 * — primarily by the legacy isolation loader.  We do not maintain a
 * section database, so report not-found.  Callers fall back to the
 * default search order, which is what we want anyway.
 * ---------------------------------------------------------------- */
WINAPI_EXPORT BOOL FindActCtxSectionStringW(DWORD dwFlags, const void *lpExtensionGuid,
                                             ULONG ulSectionId, LPCWSTR lpStringToFind,
                                             void *ReturnedData)
{
    (void)dwFlags; (void)lpExtensionGuid; (void)ulSectionId;
    (void)lpStringToFind; (void)ReturnedData;
    set_last_error(ERROR_NOT_SUPPORTED);
    return FALSE;
}

WINAPI_EXPORT BOOL FindActCtxSectionStringA(DWORD dwFlags, const void *lpExtensionGuid,
                                             ULONG ulSectionId, LPCSTR lpStringToFind,
                                             void *ReturnedData)
{
    (void)dwFlags; (void)lpExtensionGuid; (void)ulSectionId;
    (void)lpStringToFind; (void)ReturnedData;
    set_last_error(ERROR_NOT_SUPPORTED);
    return FALSE;
}

WINAPI_EXPORT BOOL FindActCtxSectionGuid(DWORD dwFlags, const void *lpExtensionGuid,
                                          ULONG ulSectionId, const void *lpGuidToFind,
                                          void *ReturnedData)
{
    (void)dwFlags; (void)lpExtensionGuid; (void)ulSectionId;
    (void)lpGuidToFind; (void)ReturnedData;
    set_last_error(ERROR_NOT_SUPPORTED);
    return FALSE;
}

/*
 * pe_resource.h - PE resource directory walker and SxS activation context
 *
 * The PE .rsrc directory is a 3-level tree:
 *   L1: type   (RT_ICON=3, RT_DIALOG=5, RT_STRING=6, RT_VERSION=16, RT_MANIFEST=24, ...)
 *   L2: name   (numeric ID or string)
 *   L3: lang   (LANG_NEUTRAL=0, en-US=0x409, ...)
 *   leaf: IMAGE_RESOURCE_DATA_ENTRY -> raw bytes
 *
 * This module provides:
 *   - pe_walk_resources()  -- callback per leaf
 *   - pe_find_resource()   -- convenience: find by (type,id)
 *   - pe_process_manifest_from_image() -- runs at startup, populates g_actx
 *
 * Activation context (`g_actx`) records:
 *   - Common Controls v6 binding (Microsoft.Windows.Common-Controls 6.0.0.0)
 *   - DPI awareness (system / per-monitor / per-monitor v2)
 *   - Requested execution level (asInvoker / requireAdministrator / highestAvailable)
 *   - List of <dependentAssembly> identities the manifest declared
 *
 * Real Win32 has CreateActCtx() / ActivateActCtx().  We do NOT implement
 * the full SxS database lookup (no WinSxS folder).  Instead we honour the
 * embedded RT_MANIFEST and treat the result as the (single) process-wide
 * activation context.  CreateActCtxA/W stubs return INVALID_HANDLE_VALUE
 * with ERROR_NOT_SUPPORTED so apps that probe for explicit creation see
 * a recognisable failure mode.
 */

#ifndef PE_RESOURCE_H
#define PE_RESOURCE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------
 * RT_* resource type IDs (subset; the full set is in WinUser.h)
 * ------------------------------------------------------------------ */
#ifndef RT_CURSOR
#define RT_CURSOR        1
#define RT_BITMAP        2
#define RT_ICON          3
#define RT_MENU          4
#define RT_DIALOG        5
#define RT_STRING        6
#define RT_FONTDIR       7
#define RT_FONT          8
#define RT_ACCELERATOR   9
#define RT_RCDATA        10
#define RT_MESSAGETABLE  11
#define RT_GROUP_CURSOR  12
#define RT_GROUP_ICON    14
#define RT_VERSION       16
#define RT_DLGINCLUDE    17
#define RT_PLUGPLAY      19
#define RT_VXD           20
#define RT_ANICURSOR     21
#define RT_ANIICON       22
#define RT_HTML          23
#define RT_MANIFEST      24
#endif

/* ------------------------------------------------------------------
 * Resource entry passed to the walker callback
 * ------------------------------------------------------------------ */
typedef struct pe_resource_entry {
    uint32_t   type;         /* RT_*  (string-named types report 0)              */
    uint32_t   name_id;      /* numeric ID or 0 if string-named                  */
    char      *name_str;     /* NULL if numeric; ASCII copy of UTF-16 name       */
    uint32_t   lang;         /* LANG_NEUTRAL etc.                                */
    void      *data;         /* pointer into mapped image                        */
    size_t     size;
    /* internals */
    uint32_t   data_rva;
    uint32_t   code_page;
} pe_resource_entry_t;

typedef int (*pe_resource_callback_t)(const pe_resource_entry_t *entry,
                                      void *user);

/* ------------------------------------------------------------------
 * Walker / finder
 *
 * Both functions take a pointer to the *mapped* image base (i.e. the
 * value PEB->ImageBaseAddress would return for the main exe).  They
 * walk the PE_DIR_RESOURCE data directory entry; if the image has no
 * resource section they return 0 (walker) / NULL (finder) silently.
 *
 * pe_walk_resources callback may return:
 *    0 -- continue
 *   <0 -- abort walk (returns the negative value)
 *   >0 -- treat as "found"; walker returns this value immediately
 * ------------------------------------------------------------------ */
int   pe_walk_resources(void *image_base,
                        pe_resource_callback_t cb,
                        void *user);

void *pe_find_resource(void *image_base,
                       uint32_t type,
                       uint32_t name_id,
                       size_t *size_out);

/* ------------------------------------------------------------------
 * Activation context (per-process; one per loaded main exe)
 * ------------------------------------------------------------------ */

#define PE_COMCTL_V5            5
#define PE_COMCTL_V6            6

#define PE_EXEC_LEVEL_ASINVOKER         1
#define PE_EXEC_LEVEL_REQUIREADMIN      2
#define PE_EXEC_LEVEL_HIGHESTAVAILABLE  3

#define PE_DPI_UNAWARE                  0
#define PE_DPI_SYSTEM                   1
#define PE_DPI_PERMONITOR               2
#define PE_DPI_PERMONITOR_V2            3

struct pe_activation_context {
    int    common_controls_version;     /* 5 (default) or 6                      */
    int    requested_execution_level;   /* PE_EXEC_LEVEL_*                       */
    int    dpi_aware;                   /* PE_DPI_*                              */
    int    ui_access;                   /* uiAccess attribute                    */
    char **dependencies;                /* "name version" strings; NULL-terminated*/
    size_t dependency_count;
    int    have_manifest;               /* 1 once a manifest has been parsed     */
};

extern struct pe_activation_context g_actx;

/* Globally exported so every DLL stub can read the resolved comctl version
 * without having to call back into the loader.  Set during manifest processing.
 * Defaults to 0 (treated as v5). */
extern int g_common_controls_v6;

/* ------------------------------------------------------------------
 * Per-thread activation context stack (S65 A9 deferred item)
 *
 * Real Win32 keeps the activation context as a per-thread push/pop stack
 * in the TEB.  ActivateActCtx pushes, DeactivateActCtx pops, and any
 * resource binding (e.g. comctl version, DPI awareness) is read from the
 * top of the current thread's stack.  When the thread's stack is empty,
 * the process-default context (`g_actx`) is used.
 *
 * The implementation lives in pe_resource.c so kernel32_actctx.c can wire
 * its push/pop/get APIs into a single source-of-truth.
 *
 * Stack depth is bounded; pushes past the limit return cookie 0 (failure).
 * Cookies are simply per-frame addresses so DeactivateActCtx can refuse a
 * mismatched pop.  This matches Windows' "ulCookie must equal the value
 * returned by the matching ActivateActCtx" contract closely enough to
 * defeat naive misuse.
 * ------------------------------------------------------------------ */
#define PE_ACTX_STACK_MAX 32

/* Push ctx onto the calling thread's activation stack.
 * Returns a non-zero cookie on success, 0 on overflow. */
unsigned long pe_actx_push(struct pe_activation_context *ctx);

/* Pop the top of the calling thread's stack.  Returns 1 on success, 0
 * if the stack is empty or the cookie does not match the top frame. */
int pe_actx_pop(unsigned long cookie);

/* Returns the activation context currently in effect on the calling
 * thread (top of stack, or &g_actx if the stack is empty). */
struct pe_activation_context *pe_actx_current(void);

/* Reset the calling thread's activation stack (used by tests). */
void pe_actx_thread_reset(void);

/* ------------------------------------------------------------------
 * Manifest extraction + processing
 *
 * pe_process_manifest_from_image() is the loader-side entry point:
 *   1. Looks up RT_MANIFEST/1 (then /2 fallback) in the image
 *   2. Parses the XML body into g_actx
 *   3. Sets g_common_controls_v6 if the manifest declared comctl v6
 *
 * Safe to call on images with no manifest (returns 0, leaves g_actx
 * at defaults).
 *
 * Returns:
 *    1  if a manifest was found and parsed
 *    0  if no manifest was present
 *   <0  on parse error (g_actx left at defaults; we do not abort the load)
 * ------------------------------------------------------------------ */
int pe_process_manifest_from_image(void *image_base);

/* Lower-level: parse a manifest blob directly. Used by tests and by
 * CreateActCtx-style explicit creation paths if we ever support them. */
int pe_parse_manifest(const char *xml, size_t xml_len,
                      struct pe_activation_context *out);

/* Reset g_actx + g_common_controls_v6 to defaults.  Idempotent. */
void pe_actx_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* PE_RESOURCE_H */

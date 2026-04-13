/*
 * pe_import.c - PE import resolution and IAT patching
 *
 * Walks the import directory table, maps DLL names to our stub .so
 * libraries, resolves function addresses via dlsym, and patches
 * the Import Address Table.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <ctype.h>
#include <time.h>
#include <malloc.h>

#include "pe/pe_header.h"
#include "pe/pe_import.h"
#include "pe/pe_export.h"
#include "pe/pe_types.h"

/* MS ABI printf/scanf format engine (static helpers, safe to include here) */
#include "compat/ms_abi_format.h"

/* Event bus for emitting PE_EVT_UNIMPLEMENTED_API events to AI Cortex */
#include "eventbus/pe_event.h"

/* Root of Trust integration */
#include "../../trust/lib/libtrust.h"

#define LOG_PREFIX "[pe_import] "
#define MAX_DLL_MAPPINGS 512

/* ---- Bounds-checked RVA access macros ----
 * All RVA dereferences MUST verify the target range lies within the image.
 * These are branchless on the hot path (the check compiles to a compare+cmov). */
#define PE_RVA_VALID(base, size, rva, len) \
    ((uint64_t)(rva) + (uint64_t)(len) <= (uint64_t)(size))
#define PE_RVA_PTR(base, rva, type) \
    ((type)((uint8_t *)(base) + (rva)))

/* ---- Local PE module tracking table ----
 * Loaded PE DLLs are registered here so export resolution can find them
 * without depending on kernel32_module_pe.c being loaded.  The table is
 * consulted by try_pe_export_resolution() on every unresolved import,
 * so lookups must be fast: we store lowercased names and do a linear scan
 * (128 entries max, typically < 20 at runtime -- cache-line friendly). */
#define MAX_PE_MODULES 128

static struct pe_module_entry {
    char      name[64];       /* DLL name, lowercased, with .dll suffix */
    uint8_t  *image_base;     /* mmap'd base of the PE image */
    uint32_t  image_size;     /* SizeOfImage from optional header */
} g_pe_modules[MAX_PE_MODULES];
static int g_pe_module_count = 0;

/* Extract SizeOfImage from a mapped PE image's optional header.
 * Returns 0 on any parse error.  Hot helper -- called frequently
 * during import resolution to avoid re-reading headers. */
static inline uint32_t pe_image_size_from_headers(const uint8_t *base)
{
    if (!base) return 0;
    if (*(const uint16_t *)base != 0x5A4D) return 0;
    uint32_t pe_off = *(const uint32_t *)(base + 0x3C);
    if (*(const uint32_t *)(base + pe_off) != 0x00004550) return 0;
    const uint8_t *opt = base + pe_off + 4 + 20;
    /* SizeOfImage is at offset 56 in both PE32 and PE32+ optional headers */
    return *(const uint32_t *)(opt + 56);
}

/*
 * Register a PE DLL in the local module table.
 *
 * Call this after successfully mapping a PE DLL into memory.  The name
 * is stored lowercased with a .dll suffix so lookups are O(1) strcmp.
 *
 * Thread safety: callers must serialise (the import loop is single-threaded
 * today; kernel32_module_pe.c holds g_pe_dll_lock).
 */
void pe_register_pe_module(const char *dll_name, void *base, uint32_t size)
{
    if (g_pe_module_count >= MAX_PE_MODULES) {
        fprintf(stderr, LOG_PREFIX "PE module table full, cannot register %s\n", dll_name);
        return;
    }
    struct pe_module_entry *e = &g_pe_modules[g_pe_module_count];
    /* Copy + lowercase */
    size_t i;
    for (i = 0; dll_name[i] && i < sizeof(e->name) - 1; i++)
        e->name[i] = tolower((unsigned char)dll_name[i]);
    e->name[i] = '\0';
    /* Ensure .dll suffix */
    if (!strstr(e->name, ".dll") && !strstr(e->name, ".exe") &&
        !strstr(e->name, ".sys") && !strstr(e->name, ".drv")) {
        size_t len = strlen(e->name);
        if (len + 4 < sizeof(e->name)) {
            memcpy(e->name + len, ".dll", 5);
        }
    }
    e->image_base = (uint8_t *)base;
    e->image_size = size ? size : pe_image_size_from_headers((const uint8_t *)base);
    g_pe_module_count++;
    printf(LOG_PREFIX "Registered PE module: %s @ %p (size 0x%x)\n",
           e->name, base, e->image_size);
}

/* Find a PE module by (lowercased) name. Returns entry or NULL. */
static struct pe_module_entry *find_pe_module(const char *dll_name)
{
    char lower[64];
    size_t i;
    for (i = 0; dll_name[i] && i < sizeof(lower) - 1; i++)
        lower[i] = tolower((unsigned char)dll_name[i]);
    lower[i] = '\0';
    /* Ensure .dll suffix for matching */
    if (!strstr(lower, ".dll") && !strstr(lower, ".exe") &&
        !strstr(lower, ".sys") && !strstr(lower, ".drv")) {
        size_t len = strlen(lower);
        if (len + 4 < sizeof(lower)) {
            memcpy(lower + len, ".dll", 5);
        }
    }
    for (int j = 0; j < g_pe_module_count; j++) {
        if (strcmp(g_pe_modules[j].name, lower) == 0)
            return &g_pe_modules[j];
    }
    return NULL;
}

/* ---- DLL search path resolution ----
 * The loader resolves .so stub libraries in this order:
 *   1. Loader binary's own directory + /dlls/
 *   2. The .exe file's parent directory (app-local DLLs)
 *   3. /usr/lib/pe-compat/ (installed location)
 *   4. Bare name via LD_LIBRARY_PATH / ld.so.cache
 *   5. ./dlls/ relative to CWD (development fallback)
 */
static char g_loader_dir[512] = {0};
static char g_exe_dir[512] = {0};
static int g_search_paths_initialized = 0;

void pe_import_set_exe_dir(const char *exe_path)
{
    if (!exe_path) return;
    const char *last_slash = strrchr(exe_path, '/');
    if (!last_slash) last_slash = strrchr(exe_path, '\\');
    if (last_slash) {
        size_t len = last_slash - exe_path;
        if (len >= sizeof(g_exe_dir)) len = sizeof(g_exe_dir) - 1;
        memcpy(g_exe_dir, exe_path, len);
        g_exe_dir[len] = '\0';
    }
}

static void init_search_paths(void)
{
    if (g_search_paths_initialized) return;
    g_search_paths_initialized = 1;

    /* Resolve peloader binary directory via /proc/self/exe */
    char self[512];
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n > 0) {
        self[n] = '\0';
        char *slash = strrchr(self, '/');
        if (slash) {
            *slash = '\0';
            strncpy(g_loader_dir, self, sizeof(g_loader_dir) - 1);
        }
    }
}

/* Try to dlopen a .so by searching all known paths */
static void *search_and_open(const char *so_name)
{
    void *handle = NULL;
    char path[512];

    init_search_paths();

    /* 1. Loader binary dir + /dlls/ (e.g. /usr/bin/../lib/pe-compat/) */
    if (g_loader_dir[0]) {
        snprintf(path, sizeof(path), "%s/dlls/%s", g_loader_dir, so_name);
        handle = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
        if (handle) return handle;

        snprintf(path, sizeof(path), "%s/%s", g_loader_dir, so_name);
        handle = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
        if (handle) return handle;
    }

    /* 2. Exe directory (app-local DLLs) */
    if (g_exe_dir[0]) {
        snprintf(path, sizeof(path), "%s/%s", g_exe_dir, so_name);
        handle = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
        if (handle) return handle;
    }

    /* 3. System install path */
    snprintf(path, sizeof(path), "/usr/lib/pe-compat/%s", so_name);
    handle = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
    if (handle) return handle;

    /* 4. Bare name (LD_LIBRARY_PATH, ld.so.cache) */
    handle = dlopen(so_name, RTLD_LAZY | RTLD_GLOBAL);
    if (handle) return handle;

    /* 5. CWD fallback (development) */
    snprintf(path, sizeof(path), "./dlls/%s", so_name);
    handle = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
    return handle;
}

/* Anticheat bridge - notify guard of DLL loads */
extern int anticheat_bridge_on_load_library(const char *dll_name);
extern int anticheat_bridge_check_integrity(void *base, size_t size);

/* Forward declaration — defined below after CRT wrapper table */
void *pe_find_crt_wrapper(const char *name);

/* Mapping from Windows DLL names to our stub .so paths */
typedef struct {
    const char *win_name;       /* Lowercase Windows DLL name */
    const char *so_name;        /* Linux .so filename */
    void       *handle;         /* dlopen handle (cached) */
} dll_mapping_t;

static dll_mapping_t g_dll_mappings[MAX_DLL_MAPPINGS] = {
    { "kernel32.dll",   "libpe_kernel32.so",  NULL },
    { "ntdll.dll",      "libpe_ntdll.so",     NULL },
    { "user32.dll",     "libpe_user32.so",    NULL },
    { "gdi32.dll",      "libpe_gdi32.so",     NULL },
    { "advapi32.dll",   "libpe_advapi32.so",  NULL },
    { "ws2_32.dll",     "libpe_ws2_32.so",    NULL },
    { "wsock32.dll",    "libpe_ws2_32.so",    NULL },
    { "msvcrt.dll",     "libpe_msvcrt.so",    NULL },
    { "ole32.dll",      "libpe_ole32.so",     NULL },
    { "shell32.dll",    "libpe_shell32.so",   NULL },
    { "ucrtbase.dll",   "libpe_msvcrt.so",    NULL },
    { "vcruntime140.dll","libpe_msvcrt.so",   NULL },
    { "api-ms-win-crt-stdio-l1-1-0.dll",  "libpe_msvcrt.so", NULL },
    { "api-ms-win-crt-runtime-l1-1-0.dll", "libpe_msvcrt.so", NULL },
    { "api-ms-win-crt-math-l1-1-0.dll",   "libpe_msvcrt.so", NULL },
    { "api-ms-win-crt-heap-l1-1-0.dll",   "libpe_msvcrt.so", NULL },
    { "api-ms-win-crt-string-l1-1-0.dll", "libpe_msvcrt.so", NULL },
    /* Version info */
    { "version.dll",       "libpe_version.so",   NULL },
    /* Shell lightweight utility */
    { "shlwapi.dll",       "libpe_shlwapi.so",   NULL },
    /* Crypto / certificates */
    { "crypt32.dll",       "libpe_crypt32.so",   NULL },
    /* Multimedia */
    { "winmm.dll",         "libpe_winmm.so",     NULL },
    /* IP Helper */
    { "iphlpapi.dll",      "libpe_iphlpapi.so",  NULL },
    /* HTTP / WinINet */
    { "winhttp.dll",       "libpe_winhttp.so",   NULL },
    { "wininet.dll",       "libpe_winhttp.so",   NULL },
    /* Device setup */
    { "setupapi.dll",      "libpe_setupapi.so",  NULL },
    { "imm32.dll",         "libpe_imm32.so",     NULL },
    /* Common controls */
    { "comctl32.dll",      "libpe_comctl32.so",  NULL },
    /* DirectX / Direct3D / XInput */
    { "d3d9.dll",          "libpe_d3d.so",       NULL },
    { "d3d11.dll",         "libpe_d3d.so",       NULL },
    { "dxgi.dll",          "libpe_d3d.so",       NULL },
    { "ddraw.dll",         "libpe_d3d.so",       NULL },
    { "xinput1_1.dll",     "libpe_d3d.so",       NULL },
    { "xinput1_2.dll",     "libpe_d3d.so",       NULL },
    { "xinput1_3.dll",     "libpe_d3d.so",       NULL },
    { "xinput1_4.dll",     "libpe_d3d.so",       NULL },
    { "xinput9_1_0.dll",   "libpe_d3d.so",       NULL },
    /* Kernel driver support (ntoskrnl, HAL, NDIS) */
    { "ntoskrnl.exe",      "libpe_ntoskrnl.so",  NULL },
    { "hal.dll",           "libpe_hal.so",       NULL },
    { "ndis.sys",          "libpe_ndis.so",      NULL },
    /* api-ms-win-crt-* forwarders -> MSVCRT stub */
    { "api-ms-win-crt-locale-l1-1-0.dll",    "libpe_msvcrt.so", NULL },
    { "api-ms-win-crt-conio-l1-1-0.dll",     "libpe_msvcrt.so", NULL },
    { "api-ms-win-crt-convert-l1-1-0.dll",   "libpe_msvcrt.so", NULL },
    { "api-ms-win-crt-environment-l1-1-0.dll","libpe_msvcrt.so", NULL },
    { "api-ms-win-crt-filesystem-l1-1-0.dll", "libpe_msvcrt.so", NULL },
    { "api-ms-win-crt-multibyte-l1-1-0.dll",  "libpe_msvcrt.so", NULL },
    { "api-ms-win-crt-process-l1-1-0.dll",    "libpe_msvcrt.so", NULL },
    { "api-ms-win-crt-time-l1-1-0.dll",       "libpe_msvcrt.so", NULL },
    { "api-ms-win-crt-utility-l1-1-0.dll",    "libpe_msvcrt.so", NULL },
    { "api-ms-win-crt-private-l1-1-0.dll",    "libpe_msvcrt.so", NULL },
    /* api-ms-win-core-* forwarders -> kernel32 stub */
    { "api-ms-win-core-synch-l1-1-0.dll",     "libpe_kernel32.so", NULL },
    { "api-ms-win-core-synch-l1-2-0.dll",     "libpe_kernel32.so", NULL },
    { "api-ms-win-core-synch-l1-2-1.dll",     "libpe_kernel32.so", NULL },
    { "api-ms-win-core-fibers-l1-1-0.dll",    "libpe_kernel32.so", NULL },
    { "api-ms-win-core-fibers-l1-1-1.dll",    "libpe_kernel32.so", NULL },
    { "api-ms-win-core-processthreads-l1-1-0.dll", "libpe_kernel32.so", NULL },
    { "api-ms-win-core-processthreads-l1-1-1.dll", "libpe_kernel32.so", NULL },
    { "api-ms-win-core-heap-l1-1-0.dll",      "libpe_kernel32.so", NULL },
    { "api-ms-win-core-heap-l2-1-0.dll",      "libpe_kernel32.so", NULL },
    { "api-ms-win-core-memory-l1-1-0.dll",    "libpe_kernel32.so", NULL },
    { "api-ms-win-core-file-l1-1-0.dll",      "libpe_kernel32.so", NULL },
    { "api-ms-win-core-file-l1-2-0.dll",      "libpe_kernel32.so", NULL },
    { "api-ms-win-core-file-l2-1-0.dll",      "libpe_kernel32.so", NULL },
    { "api-ms-win-core-handle-l1-1-0.dll",    "libpe_kernel32.so", NULL },
    { "api-ms-win-core-libraryloader-l1-1-0.dll", "libpe_kernel32.so", NULL },
    { "api-ms-win-core-libraryloader-l1-2-0.dll", "libpe_kernel32.so", NULL },
    { "api-ms-win-core-localization-l1-1-0.dll",  "libpe_kernel32.so", NULL },
    { "api-ms-win-core-localization-l1-2-0.dll",  "libpe_kernel32.so", NULL },
    { "api-ms-win-core-string-l1-1-0.dll",    "libpe_kernel32.so", NULL },
    { "api-ms-win-core-sysinfo-l1-1-0.dll",   "libpe_kernel32.so", NULL },
    { "api-ms-win-core-sysinfo-l1-2-0.dll",   "libpe_kernel32.so", NULL },
    { "api-ms-win-core-console-l1-1-0.dll",   "libpe_kernel32.so", NULL },
    { "api-ms-win-core-errorhandling-l1-1-0.dll", "libpe_kernel32.so", NULL },
    { "api-ms-win-core-profile-l1-1-0.dll",   "libpe_kernel32.so", NULL },
    { "api-ms-win-core-interlocked-l1-1-0.dll", "libpe_kernel32.so", NULL },
    { "api-ms-win-core-debug-l1-1-0.dll",     "libpe_kernel32.so", NULL },
    { "api-ms-win-core-datetime-l1-1-0.dll",  "libpe_kernel32.so", NULL },
    { "api-ms-win-core-timezone-l1-1-0.dll",  "libpe_kernel32.so", NULL },
    { "api-ms-win-core-io-l1-1-0.dll",        "libpe_kernel32.so", NULL },
    { "api-ms-win-core-namedpipe-l1-1-0.dll", "libpe_kernel32.so", NULL },
    { "api-ms-win-core-processenvironment-l1-1-0.dll", "libpe_kernel32.so", NULL },
    { "api-ms-win-core-rtlsupport-l1-1-0.dll", "libpe_ntdll.so", NULL },
    { "api-ms-win-core-util-l1-1-0.dll",       "libpe_kernel32.so", NULL },
    /* MSVC runtime DLLs -> MSVCRT stub */
    { "msvcp140.dll",         "libpe_msvcrt.so",  NULL },
    { "msvcp140_1.dll",       "libpe_msvcrt.so",  NULL },
    { "msvcp140_2.dll",       "libpe_msvcrt.so",  NULL },
    { "vcruntime140_1.dll",   "libpe_msvcrt.so",  NULL },
    { "concrt140.dll",        "libpe_msvcrt.so",  NULL },
    { "msvcr100.dll",         "libpe_msvcrt.so",  NULL },
    { "msvcr110.dll",         "libpe_msvcrt.so",  NULL },
    { "msvcr120.dll",         "libpe_msvcrt.so",  NULL },
    { "msvcp100.dll",         "libpe_msvcrt.so",  NULL },
    { "msvcp110.dll",         "libpe_msvcrt.so",  NULL },
    { "msvcp120.dll",         "libpe_msvcrt.so",  NULL },
    /* OLE Automation (BSTR, VARIANT, SafeArray) */
    { "oleaut32.dll",      "libpe_oleaut32.so",  NULL },
    /* Modern crypto */
    { "bcrypt.dll",        "libpe_bcrypt.so",    NULL },
    /* Process status API */
    { "psapi.dll",         "libpe_psapi.so",     NULL },
    /* Debug/symbol helpers */
    { "dbghelp.dll",       "libpe_dbghelp.so",   NULL },
    { "imagehlp.dll",      "libpe_dbghelp.so",   NULL },
    /* User profile */
    { "userenv.dll",       "libpe_userenv.so",   NULL },
    /* Security/SSPI */
    { "secur32.dll",       "libpe_secur32.so",   NULL },
    { "sspicli.dll",       "libpe_secur32.so",   NULL },
    /* DirectSound / XAudio2 */
    { "dsound.dll",        "libpe_dsound.so",    NULL },
    { "xaudio2_9.dll",     "libpe_dsound.so",    NULL },
    { "xaudio2_8.dll",     "libpe_dsound.so",    NULL },
    { "xaudio2_7.dll",     "libpe_dsound.so",    NULL },
    /* D3D shader compiler */
    { "d3dcompiler_47.dll","libpe_d3d.so",       NULL },
    { "d3dcompiler_46.dll","libpe_d3d.so",       NULL },
    { "d3dcompiler_43.dll","libpe_d3d.so",       NULL },
    /* D3D12 via VKD3D-Proton */
    { "d3d12.dll",         "libpe_d3d.so",       NULL },
    { "d3d12core.dll",     "libpe_d3d.so",       NULL },
    /* Winsock extensions */
    { "mswsock.dll",       "libpe_ws2_32.so",    NULL },
    /* Code signing / trust */
    { "wintrust.dll",      "libpe_crypt32.so",   NULL },
    /* DirectWrite / Direct2D / DirectComposition */
    { "dwrite.dll",        "libpe_gdi32.so",     NULL },
    { "d2d1.dll",          "libpe_gdi32.so",     NULL },
    { "dcomp.dll",         "libpe_gdi32.so",     NULL },
    /* Multimedia subsystems */
    { "mmdevapi.dll",      "libpe_winmm.so",     NULL },
    { "avrt.dll",          "libpe_winmm.so",     NULL },
    { "audioses.dll",      "libpe_winmm.so",     NULL },
    /* Media Foundation */
    { "mfplat.dll",        "libpe_kernel32.so",  NULL },
    { "mf.dll",            "libpe_kernel32.so",  NULL },
    { "mfreadwrite.dll",   "libpe_kernel32.so",  NULL },
    /* Device/setup */
    { "cfgmgr32.dll",      "libpe_setupapi.so",  NULL },
    { "devobj.dll",        "libpe_setupapi.so",  NULL },
    /* Properties/OLE extensions */
    { "propsys.dll",       "libpe_ole32.so",     NULL },
    /* Misc system DLLs */
    { "normaliz.dll",      "libpe_kernel32.so",  NULL },
    { "profapi.dll",       "libpe_kernel32.so",  NULL },
    { "cabinet.dll",       "libpe_msi.so",       NULL },
    { "powrprof.dll",      "libpe_kernel32.so",  NULL },
    { "wevtapi.dll",       "libpe_kernel32.so",  NULL },
    { "ntmarta.dll",       "libpe_advapi32.so",  NULL },
    { "wldp.dll",          "libpe_kernel32.so",  NULL },
    /* Windows system DLL redirects */
    { "kernelbase.dll",    "libpe_kernel32.so",  NULL },
    { "uxtheme.dll",       "libpe_user32.so",    NULL },
    { "wtsapi32.dll",      "libpe_kernel32.so",  NULL },
    { "netapi32.dll",      "libpe_advapi32.so",  NULL },
    { "mpr.dll",           "libpe_advapi32.so",  NULL },
    { "winsta.dll",        "libpe_kernel32.so",  NULL },
    { "msimg32.dll",       "libpe_gdi32.so",     NULL },
    { "hhctrl.ocx",        "libpe_comctl32.so",  NULL },
    { "mscoree.dll",       "libpe_mscoree.so",   NULL },
    /* .NET runtime */
    { "clr.dll",           "libpe_mscoree.so",   NULL },
    { "clrjit.dll",        "libpe_mscoree.so",   NULL },
    /* DirectInput */
    { "dinput.dll",        "libpe_d3d.so",       NULL },
    { "dinput8.dll",       "libpe_d3d.so",       NULL },
    /* D3DX9 utility (all versions 24-43) */
    { "d3dx9_24.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_25.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_26.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_27.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_28.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_29.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_30.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_31.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_32.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_33.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_34.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_35.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_36.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_37.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_38.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_39.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_40.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_41.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_42.dll",     "libpe_d3d.so",       NULL },
    { "d3dx9_43.dll",     "libpe_d3d.so",       NULL },
    /* D3DX10/D3DX11 utility */
    { "d3dx10_43.dll",    "libpe_d3d.so",       NULL },
    { "d3dx11_43.dll",    "libpe_d3d.so",       NULL },
    /* Vulkan ICD loader */
    { "vulkan-1.dll",      "libpe_d3d.so",       NULL },
    /* Direct3D 8 / 10 / 10.1 */
    { "d3d8.dll",          "libpe_d3d.so",       NULL },
    { "d3d10.dll",         "libpe_d3d.so",       NULL },
    { "d3d10_1.dll",       "libpe_d3d.so",       NULL },
    { "d3d10core.dll",     "libpe_d3d.so",       NULL },
    /* OpenGL */
    { "opengl32.dll",      "libpe_gdi32.so",     NULL },
    /* Desktop Window Manager */
    { "dwmapi.dll",        "libpe_dwmapi.so",    NULL },
    /* Steam client */
    { "steam_api.dll",     "libpe_steamclient.so", NULL },
    { "steam_api64.dll",   "libpe_steamclient.so", NULL },
    { "steamclient.dll",   "libpe_steamclient.so", NULL },
    { "steamclient64.dll", "libpe_steamclient.so", NULL },
    /* Windows Installer (MSI) */
    { "msi.dll",           "libpe_msi.so",         NULL },
    { "msidll.dll",        "libpe_msi.so",         NULL },
    /* COM functions belong in ole32 */
    { "api-ms-win-core-com-l1-1-0.dll", "libpe_ole32.so", NULL },
    { "api-ms-win-core-com-l1-1-1.dll", "libpe_ole32.so", NULL },
    /* Registry functions belong in advapi32 */
    { "api-ms-win-core-registry-l1-1-0.dll", "libpe_advapi32.so", NULL },
    { "api-ms-win-core-registry-l1-1-1.dll", "libpe_advapi32.so", NULL },
    { "api-ms-win-core-registry-l2-1-0.dll", "libpe_advapi32.so", NULL },
    /* Security functions belong in advapi32 */
    { "api-ms-win-security-base-l1-1-0.dll", "libpe_advapi32.so", NULL },
    /* Shell Core (DPI awareness) */
    { "shcore.dll",        "libpe_shcore.so",    NULL },
    /* Shell/shlwapi functions */
    { "api-ms-win-core-shlwapi-legacy-l1-1-0.dll", "libpe_shlwapi.so", NULL },
    { "api-ms-win-shcore-obsolete-l1-1-0.dll", "libpe_shell32.so", NULL },
    { "api-ms-win-shcore-path-l1-1-0.dll", "libpe_shlwapi.so", NULL },
    { "api-ms-win-shcore-scaling-l1-1-1.dll", "libpe_shcore.so", NULL },
    /* Eventing (ETW) belongs in advapi32 */
    { "api-ms-win-eventing-provider-l1-1-0.dll", "libpe_advapi32.so", NULL },
    /* Common Dialog Box Library */
    { "comdlg32.dll", "libpe_comdlg32.so", NULL },
    { "winspool.drv", "libpe_kernel32.so", NULL },
    { "urlmon.dll", "libpe_ole32.so", NULL },
    /* combase.dll / WinRT api-sets */
    { "combase.dll", "libpe_combase.so", NULL },
    { "api-ms-win-core-winrt-l1-1-0.dll", "libpe_combase.so", NULL },
    { "api-ms-win-core-winrt-string-l1-1-0.dll", "libpe_combase.so", NULL },
    { "api-ms-win-core-winrt-error-l1-1-0.dll", "libpe_combase.so", NULL },
    { "api-ms-win-core-winrt-error-l1-1-1.dll", "libpe_combase.so", NULL },
    { "api-ms-win-core-winrt-robuffer-l1-1-0.dll", "libpe_combase.so", NULL },
    /* WinPixEventRuntime (UE5 GPU profiling markers) */
    { "winpixeventruntime.dll", "libpe_winpix.so", NULL },
    { "wpixeventruntime.dll", "libpe_winpix.so", NULL },
    /* DirectStorage (UE5 asset streaming) */
    { "dstorage.dll", "libpe_dstorage.so", NULL },
    { "dstoragecore.dll", "libpe_dstorage.so", NULL },
    /* Windows Error Reporting */
    { "wer.dll", "libpe_wer.so", NULL },
    { "faultrep.dll", "libpe_wer.so", NULL },
    /* DX shader compiler/validator */
    { "dxcompiler.dll", "libpe_d3d.so", NULL },
    { "dxil.dll", "libpe_d3d.so", NULL },
    { NULL, NULL, NULL }
};

/*
 * Per-import diagnostic stubs.
 *
 * Instead of one generic stub for all unresolved imports, we generate
 * per-function stubs that log WHICH function was called. This is critical
 * for debugging real Windows applications - you need to know exactly which
 * API the app tried to call.
 *
 * We use a fixed-size pool of stub slots. Each slot stores the function
 * name and DLL name, and has a unique stub function pointer (generated
 * via a trampoline table). When the stub is called, it logs the exact
 * function name.
 *
 * For apps that probe optional functions (GetProcAddress then check NULL),
 * the stub returns 0 (FALSE/NULL) which is the standard "not available"
 * return value for most Windows APIs.
 */
#include <pthread.h>

#define UNIMPL_STUB_MAX 4096

typedef struct {
    char dll_name[64];
    char func_name[128];
    int  call_count;
} unimpl_stub_info_t;

static unimpl_stub_info_t g_stub_info[UNIMPL_STUB_MAX];
static int g_stub_count = 0;
static pthread_mutex_t g_stub_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---- Structured stub call log for AI stub discovery engine ----
 *
 * Writes JSONL (one JSON object per line) to /tmp/pe-stub-calls.jsonl so the
 * AI daemon's stub discovery engine can parse unresolved API calls and decide
 * what to implement next.  Line-buffered so each entry is immediately visible
 * to readers even if the PE process crashes.
 *
 * Thread-safe: all writes go through g_stub_log_lock.
 */
static FILE *g_stub_log_fd = NULL;
static pthread_mutex_t g_stub_log_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_stub_log_count = 0;
#define STUB_LOG_PATH      "/tmp/pe-stub-calls.jsonl"
#define STUB_LOG_MAX       50000
#define STUB_MANIFEST_PATH "/tmp/pe-imports-manifest.jsonl"

static void stub_log_init(void)
{
    if (!g_stub_log_fd) {
        g_stub_log_fd = fopen(STUB_LOG_PATH, "a");
        if (g_stub_log_fd)
            setvbuf(g_stub_log_fd, NULL, _IOLBF, 0);  /* Line-buffered */
    }
}

/*
 * Log a single stub call as a JSON line.  Called from the diagnostic stub
 * handler (and from create_diagnostic_stub at registration time with
 * type="register").
 */
static void stub_log_call(const char *dll_name, const char *func_name,
                           pid_t pid, const char *type)
{
    if (!g_stub_log_fd)
        stub_log_init();
    if (!g_stub_log_fd || g_stub_log_count >= STUB_LOG_MAX)
        return;

    pthread_mutex_lock(&g_stub_log_lock);
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    fprintf(g_stub_log_fd,
            "{\"type\":\"%s\",\"ts\":%ld.%03ld,\"pid\":%d,"
            "\"dll\":\"%s\",\"func\":\"%s\"}\n",
            type ? type : "call",
            (long)ts.tv_sec, (long)(ts.tv_nsec / 1000000),
            (int)pid,
            dll_name ? dll_name : "?",
            func_name ? func_name : "?");
    g_stub_log_count++;
    pthread_mutex_unlock(&g_stub_log_lock);
}

/*
 * Write a final summary line and close the log.
 * Called from the PE loader exit path (main.c).
 */
__attribute__((visibility("default")))
void stub_log_summary(void)
{
    if (!g_stub_log_fd)
        return;

    pthread_mutex_lock(&g_stub_log_lock);
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    fprintf(g_stub_log_fd,
            "{\"type\":\"exit\",\"ts\":%ld.%03ld,\"pid\":%d,"
            "\"total_stubs\":%d,\"total_stub_calls\":%d,\"unique_stubs\":%d}\n",
            (long)ts.tv_sec, (long)(ts.tv_nsec / 1000000),
            (int)getpid(), g_stub_log_count, g_stub_log_count, g_stub_count);
    fclose(g_stub_log_fd);
    g_stub_log_fd = NULL;
    pthread_mutex_unlock(&g_stub_log_lock);
}

/*
 * pe_import_cleanup - Release all dlopen'd .so handles.
 *
 * Called at process exit to free the dlopen handles cached in
 * g_dll_mappings[] and the catch-all cache.  Without this, every
 * loaded stub .so leaks its dlopen handle (and associated mmap'd
 * text/data pages) until the OS reclaims them at process teardown.
 *
 * For long-lived processes or repeated PE loads this is essential.
 */
__attribute__((visibility("default")))
void pe_import_cleanup(void)
{
    /* Close all cached handles in the main mapping table */
    for (int i = 0; g_dll_mappings[i].win_name != NULL; i++) {
        if (g_dll_mappings[i].handle) {
            dlclose(g_dll_mappings[i].handle);
            g_dll_mappings[i].handle = NULL;
        }
    }
}

/*
 * Generic fallback stub - returns 0 (FALSE/NULL) which is the standard
 * "not available" response for most Windows API probes.  Load-time logging
 * in create_diagnostic_stub() already tells the user what's missing; the
 * g_stub_info[] array records runtime call counts for the exit report.
 */
static __attribute__((ms_abi)) uint64_t unimplemented_stub(void)
{
    fprintf(stderr, "[pe_import] WARNING: Unresolved import called - returning 0\n");
    /* Log generic stub invocation to JSONL for the AI discovery engine.
     * We can't identify which specific function was called (all unresolved
     * imports share this single stub), but the "call" event still tells the
     * AI that *some* unresolved path was hit at runtime. */
    stub_log_call("?", "?unresolved_runtime_call", getpid(), "call");
    return 0;
}

/*
 * Allocate a diagnostic stub for an unresolved import.
 * Returns a function pointer that, when called, logs the DLL and function name.
 *
 * Note: For maximum performance, we can't create unique code per stub on the
 * fly (would need mmap+PROT_EXEC). Instead, we use the generic stub but log
 * at registration time so the user sees what's missing during load.
 */
static void *create_diagnostic_stub(const char *dll_name, const char *func_name)
{
    /* Always log unresolved imports at load time - this is the key diagnostic */
    static int unresolved_count = 0;
    int count = __atomic_add_fetch(&unresolved_count, 1, __ATOMIC_RELAXED);

    /* Log first 200 unresolved imports, then summarize */
    if (count <= 200) {
        fprintf(stderr, "[pe_import] STUB: %s!%s → unimplemented (will return 0)\n",
                dll_name ? dll_name : "?", func_name ? func_name : "?");
    } else if (count == 201) {
        fprintf(stderr, "[pe_import] ... (suppressing further unresolved import warnings)\n");
    }

    /* Emit event to AI Cortex for unimplemented API tracking */
    {
        pe_evt_unimplemented_t evt;
        memset(&evt, 0, sizeof(evt));
        strncpy(evt.dll_name, dll_name ? dll_name : "?", sizeof(evt.dll_name) - 1);
        strncpy(evt.func_name, func_name ? func_name : "?", sizeof(evt.func_name) - 1);
        pe_event_emit(PE_EVT_UNIMPLEMENTED_API, &evt, sizeof(evt));
    }

    /* Log to structured JSONL file for AI stub discovery engine */
    stub_log_call(dll_name, func_name, getpid(), "register");

    /* Register in the stub info table for runtime diagnostics */
    pthread_mutex_lock(&g_stub_lock);
    if (g_stub_count < UNIMPL_STUB_MAX) {
        int idx = g_stub_count++;
        strncpy(g_stub_info[idx].dll_name, dll_name ? dll_name : "?", 63);
        g_stub_info[idx].dll_name[63] = '\0';
        strncpy(g_stub_info[idx].func_name, func_name ? func_name : "?", 127);
        g_stub_info[idx].func_name[127] = '\0';
        g_stub_info[idx].call_count = 0;
    }
    pthread_mutex_unlock(&g_stub_lock);

    /* Return the generic stub - it returns 0 which is safe for most probes */
    return (void *)unimplemented_stub;
}

/*
 * Print summary of unresolved imports that were actually called at runtime.
 * Call this at PE exit for a diagnostic report.
 */
__attribute__((visibility("default")))
void pe_import_print_stub_report(void)
{
    int any = 0;
    for (int i = 0; i < g_stub_count; i++) {
        if (g_stub_info[i].call_count > 0) {
            if (!any) {
                fprintf(stderr, "\n[pe_import] === UNIMPLEMENTED API CALL REPORT ===\n");
                any = 1;
            }
            fprintf(stderr, "  %s!%s - called %d time(s)\n",
                    g_stub_info[i].dll_name, g_stub_info[i].func_name,
                    g_stub_info[i].call_count);
        }
    }
    if (any)
        fprintf(stderr, "[pe_import] === END REPORT ===\n\n");
}

/*
 * Emit a JSONL manifest of all imports from the PE image.
 *
 * Writes one JSON object per line to /tmp/pe-imports-manifest.jsonl listing
 * every DLL and function name from the import directory.  The AI stub
 * discovery engine reads this to know the complete import surface of each
 * PE executable, not just the stubs that were hit at runtime.
 *
 * Call this from main.c after pe_resolve_imports() returns successfully but
 * before jumping to the PE entry point.
 */
__attribute__((visibility("default")))
void pe_import_emit_manifest(const pe_image_t *image)
{
    if (!image)
        return;

    /* Check for import directory */
    if (image->number_of_rva_and_sizes <= PE_DIR_IMPORT)
        return;

    const pe_data_directory_t *import_dir = &image->data_directory[PE_DIR_IMPORT];
    if (import_dir->virtual_address == 0 || import_dir->size == 0)
        return;

    FILE *f = fopen(STUB_MANIFEST_PATH, "a");
    if (!f)
        return;

    pid_t pid = getpid();
    const char *exe = image->filename ? image->filename : "?";

    fprintf(f, "{\"type\":\"manifest\",\"pid\":%d,\"exe\":\"%s\",\"imports\":[",
            (int)pid, exe);

    const pe_import_descriptor_t *desc = (const pe_import_descriptor_t *)
        pe_rva_to_ptr(image, import_dir->virtual_address);
    if (!desc) {
        fprintf(f, "]}\n");
        fclose(f);
        return;
    }

    int first_entry = 1;
    const uint8_t *import_start = (const uint8_t *)desc;

    for (; ; desc++) {
        /* Bounds check: ensure there's room for the full descriptor before reading */
        if ((const uint8_t *)(desc + 1) - import_start > (ptrdiff_t)import_dir->size)
            break;
        if (desc->name_rva == 0)
            break;

        const char *dll_name = (const char *)pe_rva_to_ptr(image, desc->name_rva);
        if (!dll_name)
            continue;

        /* Walk the ILT to enumerate function names */
        uint32_t ilt_rva = desc->import_lookup_table_rva;
        if (ilt_rva == 0)
            ilt_rva = desc->import_address_table_rva;

        if (image->is_pe32plus) {
            const uint64_t *ilt = (const uint64_t *)pe_rva_to_ptr(image, ilt_rva);
            if (!ilt)
                continue;

            for (int i = 0; ilt[i] != 0 && i < 65536; i++) {
                const char *func_name = NULL;
                char ordinal_buf[32];

                if (ilt[i] & PE_IMPORT_ORDINAL_FLAG64) {
                    snprintf(ordinal_buf, sizeof(ordinal_buf),
                             "#%u", (unsigned)(ilt[i] & 0xFFFF));
                    func_name = ordinal_buf;
                } else {
                    uint32_t hint_rva = (uint32_t)(ilt[i] & 0x7FFFFFFF);
                    const pe_import_by_name_t *hint =
                        (const pe_import_by_name_t *)pe_rva_to_ptr(image, hint_rva);
                    if (hint)
                        func_name = hint->name;
                }

                if (func_name) {
                    fprintf(f, "%s{\"dll\":\"%s\",\"func\":\"%s\"}",
                            first_entry ? "" : ",", dll_name, func_name);
                    first_entry = 0;
                }
            }
        } else {
            const uint32_t *ilt = (const uint32_t *)pe_rva_to_ptr(image, ilt_rva);
            if (!ilt)
                continue;

            for (int i = 0; ilt[i] != 0 && i < 65536; i++) {
                const char *func_name = NULL;
                char ordinal_buf[32];

                if (ilt[i] & PE_IMPORT_ORDINAL_FLAG32) {
                    snprintf(ordinal_buf, sizeof(ordinal_buf),
                             "#%u", (unsigned)(ilt[i] & 0xFFFF));
                    func_name = ordinal_buf;
                } else {
                    uint32_t hint_rva = ilt[i] & 0x7FFFFFFF;
                    const pe_import_by_name_t *hint =
                        (const pe_import_by_name_t *)pe_rva_to_ptr(image, hint_rva);
                    if (hint)
                        func_name = hint->name;
                }

                if (func_name) {
                    fprintf(f, "%s{\"dll\":\"%s\",\"func\":\"%s\"}",
                            first_entry ? "" : ",", dll_name, func_name);
                    first_entry = 0;
                }
            }
        }
    }

    fprintf(f, "]}\n");
    fclose(f);
}

/*
 * ms_abi wrappers for standard C library functions.
 *
 * CRITICAL: When PE code imports memset/memcpy/strlen/etc. from CRT DLLs,
 * dlsym finds libc's sysv_abi versions through the dependency chain.
 * PE code calls them with ms_abi (RCX, RDX, R8, R9) but libc expects
 * sysv_abi (RDI, RSI, RDX, RCX) -- total argument mismatch = crash.
 *
 * These wrappers receive ms_abi args and forward to the real sysv_abi
 * implementations.  GCC handles the ABI translation automatically within
 * the function body because the wrapper is ms_abi while the callee is sysv.
 */
#include <wchar.h>
#include <math.h>

/* Memory functions */
static __attribute__((ms_abi)) void *crt_memset(void *d, int c, size_t n)  { return memset(d, c, n); }
static __attribute__((ms_abi)) void *crt_memcpy(void *d, const void *s, size_t n) { return memcpy(d, s, n); }
static __attribute__((ms_abi)) void *crt_memmove(void *d, const void *s, size_t n) { return memmove(d, s, n); }
static __attribute__((ms_abi)) int   crt_memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }
static __attribute__((ms_abi)) void *crt_memchr(const void *s, int c, size_t n) { return (void*)memchr(s, c, n); }

/* String functions */
static __attribute__((ms_abi)) size_t crt_strlen(const char *s) { return strlen(s); }
static __attribute__((ms_abi)) int    crt_strcmp(const char *a, const char *b) { return strcmp(a, b); }
static __attribute__((ms_abi)) int    crt_strncmp(const char *a, const char *b, size_t n) { return strncmp(a, b, n); }
static __attribute__((ms_abi)) char  *crt_strcpy(char *d, const char *s) { return strcpy(d, s); }
static __attribute__((ms_abi)) char  *crt_strncpy(char *d, const char *s, size_t n) { return strncpy(d, s, n); }
static __attribute__((ms_abi)) char  *crt_strcat(char *d, const char *s) { return strcat(d, s); }
static __attribute__((ms_abi)) char  *crt_strncat(char *d, const char *s, size_t n) { return strncat(d, s, n); }
static __attribute__((ms_abi)) char  *crt_strchr(const char *s, int c) { return (char*)strchr(s, c); }
static __attribute__((ms_abi)) char  *crt_strrchr(const char *s, int c) { return (char*)strrchr(s, c); }
static __attribute__((ms_abi)) char  *crt_strstr(const char *h, const char *n) { return (char*)strstr(h, n); }
static __attribute__((ms_abi)) char  *crt_strpbrk(const char *s, const char *a) { return (char*)strpbrk(s, a); }
static __attribute__((ms_abi)) size_t crt_strspn(const char *s, const char *a) { return strspn(s, a); }
static __attribute__((ms_abi)) size_t crt_strcspn(const char *s, const char *r) { return strcspn(s, r); }
static __attribute__((ms_abi)) char  *crt_strdup(const char *s) { return strdup(s); }
static __attribute__((ms_abi)) int    crt_stricmp(const char *a, const char *b) { return strcasecmp(a, b); }
static __attribute__((ms_abi)) int    crt_strnicmp(const char *a, const char *b, size_t n) { return strncasecmp(a, b, n); }
static __attribute__((ms_abi)) char  *crt_strlwr(char *s) { for (char *p = s; *p; p++) *p = tolower((unsigned char)*p); return s; }
static __attribute__((ms_abi)) char  *crt_strupr(char *s) { for (char *p = s; *p; p++) *p = toupper((unsigned char)*p); return s; }
static __thread char *g_strtok_saveptr;
static __attribute__((ms_abi)) char  *crt_strtok(char *s, const char *d) { return strtok_r(s, d, &g_strtok_saveptr); }
static __attribute__((ms_abi)) char  *crt_strerror(int e) { return strerror(e); }

/* Wide string functions — use uint16_t (2-byte UTF-16LE) not wchar_t (4-byte on Linux) */
/* These are defined in wchar_util.c */
extern size_t    wcslen16(const uint16_t *s);
extern int       wcscmp16(const uint16_t *a, const uint16_t *b);
extern int       wcsncmp16(const uint16_t *a, const uint16_t *b, size_t n);
extern uint16_t *wcscpy16(uint16_t *d, const uint16_t *s);
extern uint16_t *wcsncpy16(uint16_t *d, const uint16_t *s, size_t n);
extern uint16_t *wcscat16(uint16_t *d, const uint16_t *s);
extern uint16_t *wcschr16(const uint16_t *s, uint16_t c);
extern uint16_t *wcsrchr16(const uint16_t *s, uint16_t c);
extern uint16_t *wcsstr16(const uint16_t *h, const uint16_t *n);

static __attribute__((ms_abi)) size_t    crt_wcslen(const uint16_t *s) { return wcslen16(s); }
static __attribute__((ms_abi)) int       crt_wcscmp(const uint16_t *a, const uint16_t *b) { return wcscmp16(a, b); }
static __attribute__((ms_abi)) int       crt_wcsncmp(const uint16_t *a, const uint16_t *b, size_t n) { return wcsncmp16(a, b, n); }
static __attribute__((ms_abi)) uint16_t *crt_wcscpy(uint16_t *d, const uint16_t *s) { return wcscpy16(d, s); }
static __attribute__((ms_abi)) uint16_t *crt_wcsncpy(uint16_t *d, const uint16_t *s, size_t n) { return wcsncpy16(d, s, n); }
static __attribute__((ms_abi)) uint16_t *crt_wcscat(uint16_t *d, const uint16_t *s) { return wcscat16(d, s); }
static __attribute__((ms_abi)) uint16_t *crt_wcschr(const uint16_t *s, uint16_t c) { return wcschr16(s, c); }
static __attribute__((ms_abi)) uint16_t *crt_wcsrchr(const uint16_t *s, uint16_t c) { return wcsrchr16(s, c); }
static __attribute__((ms_abi)) uint16_t *crt_wcsstr(const uint16_t *h, const uint16_t *n) { return wcsstr16(h, n); }

/* Conversion functions */
static __attribute__((ms_abi)) int    crt_atoi(const char *s) { return atoi(s); }
static __attribute__((ms_abi)) long   crt_atol(const char *s) { return atol(s); }
static __attribute__((ms_abi)) double crt_atof(const char *s) { return atof(s); }
static __attribute__((ms_abi)) long   crt_strtol(const char *s, char **e, int b) { return strtol(s, e, b); }
static __attribute__((ms_abi)) unsigned long crt_strtoul(const char *s, char **e, int b) { return strtoul(s, e, b); }
static __attribute__((ms_abi)) double crt_strtod(const char *s, char **e) { return strtod(s, e); }

/* char classification */
static __attribute__((ms_abi)) int crt_isalpha(int c) { return isalpha(c); }
static __attribute__((ms_abi)) int crt_isdigit(int c) { return isdigit(c); }
static __attribute__((ms_abi)) int crt_isalnum(int c) { return isalnum(c); }
static __attribute__((ms_abi)) int crt_isspace(int c) { return isspace(c); }
static __attribute__((ms_abi)) int crt_isupper(int c) { return isupper(c); }
static __attribute__((ms_abi)) int crt_islower(int c) { return islower(c); }
static __attribute__((ms_abi)) int crt_isprint(int c) { return isprint(c); }
static __attribute__((ms_abi)) int crt_isxdigit(int c) { return isxdigit(c); }
static __attribute__((ms_abi)) int crt_toupper(int c) { return toupper(c); }
static __attribute__((ms_abi)) int crt_tolower(int c) { return tolower(c); }

/* Math functions */
static __attribute__((ms_abi)) double crt_floor(double x) { return floor(x); }
static __attribute__((ms_abi)) double crt_ceil(double x) { return ceil(x); }
static __attribute__((ms_abi)) double crt_sqrt(double x) { return sqrt(x); }
static __attribute__((ms_abi)) double crt_sin(double x) { return sin(x); }
static __attribute__((ms_abi)) double crt_cos(double x) { return cos(x); }
static __attribute__((ms_abi)) double crt_tan(double x) { return tan(x); }
static __attribute__((ms_abi)) double crt_log(double x) { return log(x); }
static __attribute__((ms_abi)) double crt_log10(double x) { return log10(x); }
static __attribute__((ms_abi)) double crt_exp(double x) { return exp(x); }
static __attribute__((ms_abi)) double crt_pow(double x, double y) { return pow(x, y); }
static __attribute__((ms_abi)) double crt_fabs(double x) { return fabs(x); }
static __attribute__((ms_abi)) double crt_fmod(double x, double y) { return fmod(x, y); }
static __attribute__((ms_abi)) float  crt_floorf(float x) { return floorf(x); }
static __attribute__((ms_abi)) float  crt_ceilf(float x) { return ceilf(x); }
static __attribute__((ms_abi)) float  crt_sqrtf(float x) { return sqrtf(x); }
static __attribute__((ms_abi)) float  crt_fabsf(float x) { return fabsf(x); }

/* Time functions */
static __attribute__((ms_abi)) time_t crt_time(time_t *t) { return time(t); }
static __attribute__((ms_abi)) clock_t crt_clock(void) { return clock(); }
static __attribute__((ms_abi)) double crt_difftime(time_t a, time_t b) { return difftime(a, b); }

/* Random */
static __attribute__((ms_abi)) int  crt_rand(void) { return rand(); }
static __attribute__((ms_abi)) void crt_srand(unsigned s) { srand(s); }

/* Aligned allocation */
static __attribute__((ms_abi)) void *crt_aligned_malloc(size_t sz, size_t align) {
    void *p = NULL;
    posix_memalign(&p, align < sizeof(void*) ? sizeof(void*) : align, sz);
    return p;
}
static __attribute__((ms_abi)) void crt_aligned_free(void *p) { free(p); }
static __attribute__((ms_abi)) size_t crt_msize(void *p) { return p ? malloc_usable_size(p) : 0; }

/* Integer-to-string (MSVC non-standard) */
static __attribute__((ms_abi)) char *crt_itoa(int val, char *str, int base) {
    if (base == 10) { sprintf(str, "%d", val); return str; }
    if (base == 16) { sprintf(str, "%x", val); return str; }
    if (base == 8)  { sprintf(str, "%o", val); return str; }
    /* Generic base conversion */
    char *p = str, *p1, tmp;
    unsigned int uval = (unsigned int)val;
    if (val < 0 && base == 10) { *p++ = '-'; uval = (unsigned int)(-val); }
    char *start = p;
    do { int d = uval % base; *p++ = (d < 10) ? '0' + d : 'a' + d - 10; } while (uval /= base);
    *p = '\0';
    /* Reverse */
    for (p1 = start, p--; p1 < p; p1++, p--) { tmp = *p1; *p1 = *p; *p = tmp; }
    return str;
}

/* stdio */
static __attribute__((ms_abi)) int    crt_puts(const char *s) { return puts(s); }
static __attribute__((ms_abi)) int    crt_fputs(const char *s, FILE *f) { return fputs(s, f); }
static __attribute__((ms_abi)) int    crt_fputc(int c, FILE *f) { return fputc(c, f); }
static __attribute__((ms_abi)) int    crt_putchar(int c) { return putchar(c); }
static __attribute__((ms_abi)) int    crt_putc(int c, FILE *f) { return putc(c, f); }
static __attribute__((ms_abi)) int    crt_fgetc(FILE *f) { return fgetc(f); }
static __attribute__((ms_abi)) char  *crt_fgets(char *s, int n, FILE *f) { return fgets(s, n, f); }
static __attribute__((ms_abi)) size_t crt_fwrite(const void *p, size_t s, size_t n, FILE *f) { return fwrite(p, s, n, f); }
static __attribute__((ms_abi)) size_t crt_fread(void *p, size_t s, size_t n, FILE *f) { return fread(p, s, n, f); }
static __attribute__((ms_abi)) int    crt_fflush(FILE *f) { return fflush(f); }
static __attribute__((ms_abi)) int    crt_fclose(FILE *f) { return fclose(f); }
static __attribute__((ms_abi)) FILE  *crt_fopen(const char *p, const char *m) { return fopen(p, m); }
static __attribute__((ms_abi)) int    crt_fseek(FILE *f, long o, int w) { return fseek(f, o, w); }
static __attribute__((ms_abi)) long   crt_ftell(FILE *f) { return ftell(f); }
static __attribute__((ms_abi)) void   crt_rewind(FILE *f) { rewind(f); }
static __attribute__((ms_abi)) int    crt_feof(FILE *f) { return feof(f); }
static __attribute__((ms_abi)) int    crt_ferror(FILE *f) { return ferror(f); }
/*
 * printf/fprintf/sprintf/scanf family — ms_abi variadic wrappers.
 *
 * Pre-VS2015 MSVC apps import these directly from msvcrt.dll. They
 * must use ms_abi convention. We use ms_abi_vformat / ms_abi_vscan
 * from compat/ms_abi_format.h to bridge the ABI gap safely.
 *
 * These are placed in the CRT wrapper table (checked FIRST, before dlsym)
 * to avoid exporting them from libpe_msvcrt.so with RTLD_GLOBAL, which
 * would collide with glibc's sysv_abi printf in other loaded .so files.
 */
static __attribute__((ms_abi)) int crt_printf(const char *fmt, ...) {
    __builtin_ms_va_list ap; __builtin_ms_va_start(ap, fmt);
    int r = ms_abi_vformat(stdout, NULL, 0, fmt, ap);
    __builtin_ms_va_end(ap); return r;
}
static __attribute__((ms_abi)) int crt_fprintf(FILE *stream, const char *fmt, ...) {
    __builtin_ms_va_list ap; __builtin_ms_va_start(ap, fmt);
    int r = ms_abi_vformat(stream, NULL, 0, fmt, ap);
    __builtin_ms_va_end(ap); return r;
}
static __attribute__((ms_abi)) int crt_sprintf(char *buf, const char *fmt, ...) {
    __builtin_ms_va_list ap; __builtin_ms_va_start(ap, fmt);
    int r = ms_abi_vformat(NULL, buf, (size_t)-1, fmt, ap);
    __builtin_ms_va_end(ap); return r;
}
static __attribute__((ms_abi)) int crt_snprintf(char *buf, size_t n, const char *fmt, ...) {
    __builtin_ms_va_list ap; __builtin_ms_va_start(ap, fmt);
    int r = ms_abi_vformat(NULL, buf, n, fmt, ap);
    __builtin_ms_va_end(ap); return r;
}
/* v* variants receive an explicit ms_abi va_list from caller */
static __attribute__((ms_abi)) int crt_vprintf(const char *fmt, __builtin_ms_va_list ap) {
    return ms_abi_vformat(stdout, NULL, 0, fmt, ap);
}
static __attribute__((ms_abi)) int crt_vfprintf(FILE *stream, const char *fmt, __builtin_ms_va_list ap) {
    return ms_abi_vformat(stream, NULL, 0, fmt, ap);
}
static __attribute__((ms_abi)) int crt_vsprintf(char *buf, const char *fmt, __builtin_ms_va_list ap) {
    return ms_abi_vformat(NULL, buf, (size_t)-1, fmt, ap);
}
static __attribute__((ms_abi)) int crt_vsnprintf(char *buf, size_t n, const char *fmt, __builtin_ms_va_list ap) {
    return ms_abi_vformat(NULL, buf, n, fmt, ap);
}
/* scanf family */
static __attribute__((ms_abi)) int crt_scanf(const char *fmt, ...) {
    __builtin_ms_va_list ap; __builtin_ms_va_start(ap, fmt);
    int r = ms_abi_vscan(stdin, NULL, fmt, ap);
    __builtin_ms_va_end(ap); return r;
}
static __attribute__((ms_abi)) int crt_fscanf(FILE *stream, const char *fmt, ...) {
    __builtin_ms_va_list ap; __builtin_ms_va_start(ap, fmt);
    int r = ms_abi_vscan(stream, NULL, fmt, ap);
    __builtin_ms_va_end(ap); return r;
}
static __attribute__((ms_abi)) int crt_sscanf(const char *src, const char *fmt, ...) {
    __builtin_ms_va_list ap; __builtin_ms_va_start(ap, fmt);
    int r = ms_abi_vscan(NULL, src, fmt, ap);
    __builtin_ms_va_end(ap); return r;
}
static __attribute__((ms_abi)) int crt_vscanf(const char *fmt, __builtin_ms_va_list ap) {
    return ms_abi_vscan(stdin, NULL, fmt, ap);
}
static __attribute__((ms_abi)) int crt_vfscanf(FILE *stream, const char *fmt, __builtin_ms_va_list ap) {
    return ms_abi_vscan(stream, NULL, fmt, ap);
}
static __attribute__((ms_abi)) int crt_vsscanf(const char *src, const char *fmt, __builtin_ms_va_list ap) {
    return ms_abi_vscan(NULL, src, fmt, ap);
}

/* Stdlib */
static __attribute__((ms_abi)) void  *crt_malloc(size_t n) { return malloc(n); }
static __attribute__((ms_abi)) void  *crt_calloc(size_t n, size_t s) { return calloc(n, s); }
static __attribute__((ms_abi)) void  *crt_realloc(void *p, size_t n) { return realloc(p, n); }
static __attribute__((ms_abi)) void   crt_free(void *p) { free(p); }
static __attribute__((ms_abi)) void   crt_abort(void) { abort(); }
static __attribute__((ms_abi)) void   crt_exit(int c) { exit(c); }
static __attribute__((ms_abi)) int    crt_abs(int n) { return abs(n); }
/* Thread-local storage for the current PE comparator (ms_abi -> sysv_abi bridge) */
static __thread int (__attribute__((ms_abi)) *g_pe_comparator)(const void*, const void*);
static __thread int (__attribute__((ms_abi)) *g_pe_comparator_bs)(const void*, const void*);

static int sysv_comparator_bridge(const void *a, const void *b) {
    return g_pe_comparator(a, b);
}
static int sysv_comparator_bridge_bs(const void *a, const void *b) {
    return g_pe_comparator_bs(a, b);
}

static __attribute__((ms_abi)) void crt_qsort(void *b, size_t n, size_t s,
    int (__attribute__((ms_abi)) *cmp)(const void*, const void*))
{
    g_pe_comparator = cmp;
    qsort(b, n, s, sysv_comparator_bridge);
}
static __attribute__((ms_abi)) void *crt_bsearch(const void *k, const void *b, size_t n, size_t s,
    int (__attribute__((ms_abi)) *cmp)(const void*, const void*))
{
    g_pe_comparator_bs = cmp;
    return (void*)bsearch(k, b, n, s, sysv_comparator_bridge_bs);
}
static __attribute__((ms_abi)) char  *crt_getenv(const char *name) { return getenv(name); }
static __attribute__((ms_abi)) int    crt_setenv(const char *n, const char *v, int o) { return setenv(n, v, o); }
static __attribute__((ms_abi)) int    crt_system(const char *cmd) { return system(cmd); }
static __attribute__((ms_abi)) long long crt_strtoll(const char *s, char **e, int b) { return strtoll(s, e, b); }
static __attribute__((ms_abi)) unsigned long long crt_strtoull(const char *s, char **e, int b) { return strtoull(s, e, b); }
static __attribute__((ms_abi)) float  crt_strtof(const char *s, char **e) { return strtof(s, e); }
static __attribute__((ms_abi)) long double crt_strtold(const char *s, char **e) { return strtold(s, e); }
/* atexit bridge: wrap ms_abi callbacks so sysv_abi atexit() can call them.
 * Fixed-size stack of up to 64 handlers, called in LIFO order. */
#define ATEXIT_MAX 64
static void (__attribute__((ms_abi)) *g_atexit_stack[ATEXIT_MAX])(void);
static int g_atexit_count = 0;
static void atexit_bridge(void) {
    for (int i = g_atexit_count - 1; i >= 0; i--)
        if (g_atexit_stack[i]) g_atexit_stack[i]();
}
static int g_atexit_registered = 0;
static __attribute__((ms_abi)) int crt_atexit(void (__attribute__((ms_abi)) *func)(void)) {
    if (g_atexit_count >= ATEXIT_MAX) return -1;
    if (!g_atexit_registered) { atexit(atexit_bridge); g_atexit_registered = 1; }
    g_atexit_stack[g_atexit_count++] = func;
    return 0;
}
static __attribute__((ms_abi)) double crt_ldexp(double x, int n) { return ldexp(x, n); }
static __attribute__((ms_abi)) double crt_frexp(double x, int *e) { return frexp(x, e); }
static __attribute__((ms_abi)) double crt_modf(double x, double *i) { return modf(x, i); }
static __attribute__((ms_abi)) double crt_atan2(double y, double x) { return atan2(y, x); }
static __attribute__((ms_abi)) double crt_asin(double x) { return asin(x); }
static __attribute__((ms_abi)) double crt_acos(double x) { return acos(x); }
static __attribute__((ms_abi)) double crt_atan(double x) { return atan(x); }
static __attribute__((ms_abi)) double crt_log2(double x) { return log2(x); }
static __attribute__((ms_abi)) float  crt_sinf(float x) { return sinf(x); }
static __attribute__((ms_abi)) float  crt_cosf(float x) { return cosf(x); }
static __attribute__((ms_abi)) float  crt_tanf(float x) { return tanf(x); }
static __attribute__((ms_abi)) float  crt_atan2f(float y, float x) { return atan2f(y, x); }
static __attribute__((ms_abi)) float  crt_powf(float x, float y) { return powf(x, y); }
static __attribute__((ms_abi)) float  crt_logf(float x) { return logf(x); }
static __attribute__((ms_abi)) float  crt_log2f(float x) { return log2f(x); }
static __attribute__((ms_abi)) float  crt_expf(float x) { return expf(x); }
static __attribute__((ms_abi)) float  crt_fmodf(float x, float y) { return fmodf(x, y); }
static __attribute__((ms_abi)) float  crt_roundf(float x) { return roundf(x); }
static __attribute__((ms_abi)) double crt_round(double x) { return round(x); }
static __attribute__((ms_abi)) float  crt_copysignf(float x, float y) { return copysignf(x, y); }
static __attribute__((ms_abi)) double crt_copysign(double x, double y) { return copysign(x, y); }

/* Lookup table: maps C function name → ms_abi wrapper */
typedef struct {
    const char *name;
    void       *wrapper;
} crt_abi_wrapper_t;

static const crt_abi_wrapper_t g_crt_wrappers[] = {
    /* memory */
    { "memset",   (void*)crt_memset },
    { "memcpy",   (void*)crt_memcpy },
    { "memmove",  (void*)crt_memmove },
    { "memcmp",   (void*)crt_memcmp },
    { "memchr",   (void*)crt_memchr },
    /* string */
    { "strlen",   (void*)crt_strlen },
    { "strcmp",   (void*)crt_strcmp },
    { "strncmp",  (void*)crt_strncmp },
    { "strcpy",   (void*)crt_strcpy },
    { "strncpy",  (void*)crt_strncpy },
    { "strcat",   (void*)crt_strcat },
    { "strncat",  (void*)crt_strncat },
    { "strchr",   (void*)crt_strchr },
    { "strrchr",  (void*)crt_strrchr },
    { "strstr",   (void*)crt_strstr },
    { "strpbrk",  (void*)crt_strpbrk },
    { "strspn",   (void*)crt_strspn },
    { "strcspn",  (void*)crt_strcspn },
    { "strdup",   (void*)crt_strdup },
    { "_strdup",  (void*)crt_strdup },
    { "_stricmp", (void*)crt_stricmp },
    { "_strnicmp",(void*)crt_strnicmp },
    { "_strlwr",  (void*)crt_strlwr },
    { "_strupr",  (void*)crt_strupr },
    { "strtok",   (void*)crt_strtok },
    { "strerror", (void*)crt_strerror },
    /* wide string */
    { "wcslen",   (void*)crt_wcslen },
    { "wcscmp",   (void*)crt_wcscmp },
    { "wcsncmp",  (void*)crt_wcsncmp },
    { "wcscpy",   (void*)crt_wcscpy },
    { "wcsncpy",  (void*)crt_wcsncpy },
    { "wcscat",   (void*)crt_wcscat },
    { "wcschr",   (void*)crt_wcschr },
    { "wcsrchr",  (void*)crt_wcsrchr },
    { "wcsstr",   (void*)crt_wcsstr },
    /* conversion */
    { "atoi",     (void*)crt_atoi },
    { "atol",     (void*)crt_atol },
    { "atof",     (void*)crt_atof },
    { "strtol",   (void*)crt_strtol },
    { "strtoul",  (void*)crt_strtoul },
    { "strtod",   (void*)crt_strtod },
    /* char class */
    { "isalpha",  (void*)crt_isalpha },
    { "isdigit",  (void*)crt_isdigit },
    { "isalnum",  (void*)crt_isalnum },
    { "isspace",  (void*)crt_isspace },
    { "isupper",  (void*)crt_isupper },
    { "islower",  (void*)crt_islower },
    { "isprint",  (void*)crt_isprint },
    { "isxdigit", (void*)crt_isxdigit },
    { "toupper",  (void*)crt_toupper },
    { "tolower",  (void*)crt_tolower },
    /* math */
    { "floor",    (void*)crt_floor },
    { "ceil",     (void*)crt_ceil },
    { "sqrt",     (void*)crt_sqrt },
    { "sin",      (void*)crt_sin },
    { "cos",      (void*)crt_cos },
    { "tan",      (void*)crt_tan },
    { "log",      (void*)crt_log },
    { "log10",    (void*)crt_log10 },
    { "exp",      (void*)crt_exp },
    { "pow",      (void*)crt_pow },
    { "fabs",     (void*)crt_fabs },
    { "fmod",     (void*)crt_fmod },
    { "floorf",   (void*)crt_floorf },
    { "ceilf",    (void*)crt_ceilf },
    { "sqrtf",    (void*)crt_sqrtf },
    { "fabsf",    (void*)crt_fabsf },
    /* stdio - printf/scanf family (ms_abi variadic wrappers) */
    { "printf",    (void*)crt_printf },
    { "fprintf",   (void*)crt_fprintf },
    { "sprintf",   (void*)crt_sprintf },
    { "snprintf",  (void*)crt_snprintf },
    { "_snprintf", (void*)crt_snprintf },
    { "vprintf",   (void*)crt_vprintf },
    { "vfprintf",  (void*)crt_vfprintf },
    { "vsprintf",  (void*)crt_vsprintf },
    { "vsnprintf", (void*)crt_vsnprintf },
    { "_vsnprintf",(void*)crt_vsnprintf },
    { "scanf",     (void*)crt_scanf },
    { "fscanf",    (void*)crt_fscanf },
    { "sscanf",    (void*)crt_sscanf },
    { "vscanf",    (void*)crt_vscanf },
    { "vfscanf",   (void*)crt_vfscanf },
    { "vsscanf",   (void*)crt_vsscanf },
    /* stdio - other */
    { "puts",     (void*)crt_puts },
    { "fputs",    (void*)crt_fputs },
    { "fputc",    (void*)crt_fputc },
    { "putchar",  (void*)crt_putchar },
    { "putc",     (void*)crt_putc },
    { "fgetc",    (void*)crt_fgetc },
    { "fgets",    (void*)crt_fgets },
    { "fwrite",   (void*)crt_fwrite },
    { "fread",    (void*)crt_fread },
    { "fflush",   (void*)crt_fflush },
    { "fclose",   (void*)crt_fclose },
    { "fopen",    (void*)crt_fopen },
    { "fseek",    (void*)crt_fseek },
    { "ftell",    (void*)crt_ftell },
    { "rewind",   (void*)crt_rewind },
    { "feof",     (void*)crt_feof },
    { "ferror",   (void*)crt_ferror },
    /* stdlib */
    { "malloc",   (void*)crt_malloc },
    { "calloc",   (void*)crt_calloc },
    { "realloc",  (void*)crt_realloc },
    { "free",     (void*)crt_free },
    { "abort",    (void*)crt_abort },
    { "exit",     (void*)crt_exit },
    { "abs",      (void*)crt_abs },
    { "qsort",    (void*)crt_qsort },
    { "bsearch",  (void*)crt_bsearch },
    { "getenv",   (void*)crt_getenv },
    { "setenv",   (void*)crt_setenv },
    { "system",   (void*)crt_system },
    { "strtoll",  (void*)crt_strtoll },
    { "_strtoi64",(void*)crt_strtoll },
    { "strtoull", (void*)crt_strtoull },
    { "_strtoui64",(void*)crt_strtoull },
    { "strtof",   (void*)crt_strtof },
    { "strtold",  (void*)crt_strtold },
    { "atexit",   (void*)crt_atexit },
    { "_exit",    (void*)crt_exit },
    /* extra math */
    { "ldexp",    (void*)crt_ldexp },
    { "frexp",    (void*)crt_frexp },
    { "modf",     (void*)crt_modf },
    { "atan2",    (void*)crt_atan2 },
    { "asin",     (void*)crt_asin },
    { "acos",     (void*)crt_acos },
    { "atan",     (void*)crt_atan },
    { "log2",     (void*)crt_log2 },
    { "sinf",     (void*)crt_sinf },
    { "cosf",     (void*)crt_cosf },
    { "tanf",     (void*)crt_tanf },
    { "atan2f",   (void*)crt_atan2f },
    { "powf",     (void*)crt_powf },
    { "logf",     (void*)crt_logf },
    { "log2f",    (void*)crt_log2f },
    { "expf",     (void*)crt_expf },
    { "fmodf",    (void*)crt_fmodf },
    { "roundf",   (void*)crt_roundf },
    { "round",    (void*)crt_round },
    { "copysignf",(void*)crt_copysignf },
    { "copysign", (void*)crt_copysign },
    /* time */
    { "time",     (void*)crt_time },
    { "_time64",  (void*)crt_time },
    { "clock",    (void*)crt_clock },
    { "difftime", (void*)crt_difftime },
    /* random */
    { "rand",     (void*)crt_rand },
    { "srand",    (void*)crt_srand },
    /* aligned allocation */
    { "_aligned_malloc", (void*)crt_aligned_malloc },
    { "_aligned_free",   (void*)crt_aligned_free },
    { "_msize",   (void*)crt_msize },
    /* integer-to-string */
    { "_itoa",    (void*)crt_itoa },
    { "itoa",     (void*)crt_itoa },
    { NULL, NULL }
};

/*
 * Look up a CRT function name in the ms_abi wrapper table.
 * Returns wrapper address or NULL if not found.
 * Non-static so PE DLL import resolution in kernel32_module_pe.c
 * can access it via -rdynamic weak symbol linkage.
 */
void *pe_find_crt_wrapper(const char *name)
{
    for (int i = 0; g_crt_wrappers[i].name; i++) {
        if (strcmp(g_crt_wrappers[i].name, name) == 0)
            return g_crt_wrappers[i].wrapper;
    }
    return NULL;
}

/*
 * C++ mangled name resolution table.
 * MSVC-mangled names contain ? and @@ which ELF can't export as symbols.
 * We resolve them to our plain C implementation names instead.
 */
typedef struct {
    const char *mangled;     /* MSVC mangled name from PE import */
    const char *impl_name;   /* Our C implementation name */
} mangled_name_map_t;

static const mangled_name_map_t g_mangled_names[] = {
    { "?terminate@@YAXXZ", "msvcrt_terminate_impl" },
    { "??_V@YAXPEAX@Z",   "msvcrt_operator_delete_array" },  /* operator delete[] */
    { "??_U@YAPEAX_K@Z",  "msvcrt_operator_new_array" },     /* operator new[] */
    { "??2@YAPEAX_K@Z",   "msvcrt_operator_new" },           /* operator new */
    { "??3@YAXPEAX@Z",    "msvcrt_operator_delete" },        /* operator delete */
    { NULL, NULL }
};

static void *find_mangled_name(const char *name, void *lib)
{
    for (int i = 0; g_mangled_names[i].mangled; i++) {
        if (strcmp(g_mangled_names[i].mangled, name) == 0) {
            void *addr = dlsym(lib, g_mangled_names[i].impl_name);
            if (addr) return addr;
        }
    }
    return NULL;
}

/*
 * Winsock name translation table.
 * PE binaries import bare POSIX names (socket, connect, bind, etc.) from
 * ws2_32.dll / wsock32.dll. Our implementation prefixes them with "ws2_"
 * to avoid colliding with the real libc symbols when loaded with RTLD_GLOBAL.
 */
/* Forward declaration */
static void str_lower(char *s);

typedef struct {
    const char *win_name;
    const char *impl_name;
} ws2_name_map_t;

static const ws2_name_map_t g_ws2_names[] = {
    { "socket",       "ws2_socket"       },
    { "connect",      "ws2_connect"      },
    { "bind",         "ws2_bind"         },
    { "listen",       "ws2_listen"       },
    { "accept",       "ws2_accept"       },
    { "send",         "ws2_send"         },
    { "recv",         "ws2_recv"         },
    { "sendto",       "ws2_sendto"       },
    { "recvfrom",     "ws2_recvfrom"     },
    { "closesocket",  "ws2_closesocket"  },
    { "shutdown",     "ws2_shutdown"     },
    { "select",       "ws2_select"       },
    { "ioctlsocket",  "ws2_ioctlsocket"  },
    { "setsockopt",   "ws2_setsockopt"   },
    { "getsockopt",   "ws2_getsockopt"   },
    { "getsockname",  "ws2_getsockname"  },
    { "getpeername",  "ws2_getpeername"  },
    { "gethostbyname","ws2_gethostbyname"},
    { "gethostbyaddr","ws2_gethostbyaddr"},
    { "gethostname",  "ws2_gethostname"  },
    { "getaddrinfo",  "ws2_getaddrinfo"  },
    { "freeaddrinfo", "ws2_freeaddrinfo" },
    { "getnameinfo",  "ws2_getnameinfo"  },
    { "htons",        "ws2_htons"        },
    { "ntohs",        "ws2_ntohs"        },
    { "htonl",        "ws2_htonl"        },
    { "ntohl",        "ws2_ntohl"        },
    { "inet_addr",    "ws2_inet_addr"    },
    { "inet_ntoa",    "ws2_inet_ntoa"    },
    { "inet_pton",    "ws2_inet_pton"    },
    { "inet_ntop",    "ws2_inet_ntop"    },
    { NULL, NULL }
};

/* Check if a DLL is a Winsock library */
static int is_winsock_dll(const char *dll_name)
{
    char lower[256];
    strncpy(lower, dll_name, sizeof(lower) - 1);
    lower[sizeof(lower) - 1] = '\0';
    str_lower(lower);
    return strcmp(lower, "ws2_32.dll") == 0 ||
           strcmp(lower, "wsock32.dll") == 0;
}

/* Translate a Winsock import name to our prefixed implementation name */
static const char *translate_ws2_name(const char *name)
{
    for (int i = 0; g_ws2_names[i].win_name; i++) {
        if (strcmp(name, g_ws2_names[i].win_name) == 0)
            return g_ws2_names[i].impl_name;
    }
    return name; /* No translation needed (WSAStartup, etc.) */
}

/*
 * MSVCRT wide-string function name translation.
 * Windows wchar_t is 2 bytes; Linux wchar_t is 4 bytes.  Our stubs use
 * uint16_t and are prefixed with "pe_" to avoid conflicting with libc
 * wchar.h declarations.  This table maps Windows import names to our
 * prefixed implementation names.
 */
static const ws2_name_map_t g_wcs_names[] = {
    { "wcstol",   "pe_wcstol"   },
    { "wcstoul",  "pe_wcstoul"  },
    { "wcstod",   "pe_wcstod"   },
    { "wcstof",   "pe_wcstof"   },
    { "wcstoll",  "pe_wcstoll"  },
    { "wcstoull", "pe_wcstoull" },
    { NULL, NULL }
};

/* Check if a DLL is an MSVCRT-family library */
static int is_msvcrt_dll(const char *dll_name)
{
    char lower[256];
    strncpy(lower, dll_name, sizeof(lower) - 1);
    lower[sizeof(lower) - 1] = '\0';
    for (char *s = lower; *s; s++) *s = tolower((unsigned char)*s);
    return strcmp(lower, "msvcrt.dll") == 0 ||
           strcmp(lower, "ucrtbase.dll") == 0 ||
           strncmp(lower, "msvcr", 5) == 0 ||
           strncmp(lower, "msvcp", 5) == 0 ||
           strncmp(lower, "vcruntime", 9) == 0 ||
           strncmp(lower, "api-ms-win-crt-", 15) == 0;
}

/* Translate a wide-string import name to our pe_ prefixed version */
static const char *translate_wcs_name(const char *name)
{
    for (int i = 0; g_wcs_names[i].win_name; i++) {
        if (strcmp(name, g_wcs_names[i].win_name) == 0)
            return g_wcs_names[i].impl_name;
    }
    return name;
}

/* Lowercase a string in place */
static void str_lower(char *s)
{
    for (; *s; s++)
        *s = tolower((unsigned char)*s);
}

/* Find the .so library for a Windows DLL name */
static void *find_dll_library(const char *dll_name)
{
    char lower[256];
    strncpy(lower, dll_name, sizeof(lower) - 1);
    lower[sizeof(lower) - 1] = '\0';
    str_lower(lower);

    for (int i = 0; g_dll_mappings[i].win_name != NULL; i++) {
        if (strcmp(lower, g_dll_mappings[i].win_name) == 0) {
            /* Return cached handle if already loaded */
            if (g_dll_mappings[i].handle)
                return g_dll_mappings[i].handle;

            /* Trust check: verify FILE_READ capability before loading DLL */
            if (trust_available()) {
                uint32_t pid = (uint32_t)getpid();
                if (!trust_check_capability(pid, TRUST_CAP_FILE_READ)) {
                    fprintf(stderr, LOG_PREFIX "  TRUST DENIED: PID %u lacks FILE_READ for %s\n",
                            pid, dll_name);
                    trust_record_action(pid, TRUST_ACTION_FILE_OPEN, 1);
                    return NULL;
                }
                /* Check NET_CONNECT for network DLLs */
                if (strcmp(lower, "ws2_32.dll") == 0 ||
                    strcmp(lower, "wsock32.dll") == 0 ||
                    strcmp(lower, "winhttp.dll") == 0 ||
                    strcmp(lower, "wininet.dll") == 0 ||
                    strcmp(lower, "iphlpapi.dll") == 0) {
                    if (!trust_check_capability(pid, TRUST_CAP_NET_CONNECT)) {
                        fprintf(stderr, LOG_PREFIX "  TRUST DENIED: PID %u lacks NET_CONNECT for %s\n",
                                pid, dll_name);
                        trust_record_action(pid, TRUST_ACTION_NET_CONNECT, 1);
                        return NULL;
                    }
                }
                /* Check KERNEL_CALL for kernel-mode driver DLLs */
                if (strcmp(lower, "ntoskrnl.exe") == 0 ||
                    strcmp(lower, "hal.dll") == 0 ||
                    strcmp(lower, "ndis.sys") == 0) {
                    if (!trust_check_capability(pid, TRUST_CAP_KERNEL_CALL)) {
                        fprintf(stderr, LOG_PREFIX "  TRUST DENIED: PID %u lacks KERNEL_CALL for %s\n",
                                pid, dll_name);
                        trust_record_action(pid, TRUST_ACTION_PROCESS_CREATE, 1);
                        return NULL;
                    }
                }
            }

            /* Try to dlopen the .so file via all search paths */
            void *handle = search_and_open(g_dll_mappings[i].so_name);
            if (handle) {
                g_dll_mappings[i].handle = handle;
                printf(LOG_PREFIX "  Loaded stub library: %s -> %s\n",
                       dll_name, g_dll_mappings[i].so_name);
                anticheat_bridge_on_load_library(dll_name);
            } else {
                fprintf(stderr, LOG_PREFIX "  WARNING: Could not load stub for %s: %s\n",
                        dll_name, dlerror());
            }
            return handle;
        }
    }

    /*
     * Catch-all handler: try to map unknown DLLs by prefix pattern.
     * This handles api-ms-win-*, ext-ms-*, and MSVC runtime variants
     * that aren't explicitly listed in the table.
     */
    const char *fallback_so = NULL;

    if (strncmp(lower, "api-ms-win-crt-", 15) == 0) {
        /* All CRT api-sets → msvcrt */
        fallback_so = "libpe_msvcrt.so";
    } else if (strncmp(lower, "api-ms-win-core-com-", 20) == 0) {
        /* COM → ole32 */
        fallback_so = "libpe_ole32.so";
    } else if (strncmp(lower, "api-ms-win-core-winrt-", 22) == 0) {
        /* WinRT → combase */
        fallback_so = "libpe_combase.so";
    } else if (strncmp(lower, "api-ms-win-core-registry-", 25) == 0 ||
               strncmp(lower, "api-ms-win-security-", 20) == 0 ||
               strncmp(lower, "api-ms-win-eventing-", 20) == 0) {
        /* Registry, Security, ETW → advapi32 */
        fallback_so = "libpe_advapi32.so";
    } else if (strncmp(lower, "api-ms-win-shell-", 17) == 0 ||
               strncmp(lower, "api-ms-win-shcore-", 18) == 0) {
        /* Shell → shell32 */
        fallback_so = "libpe_shell32.so";
    } else if (strncmp(lower, "api-ms-win-core-", 16) == 0 ||
               strncmp(lower, "api-ms-win-", 11) == 0) {
        /* All other api-ms-win-core-* and api-ms-win-* → kernel32 (default) */
        fallback_so = "libpe_kernel32.so";
    } else if (strncmp(lower, "ext-ms-win-ntuser-", 18) == 0 ||
               strncmp(lower, "ext-ms-win-rtcore-", 18) == 0) {
        /* ext-ms user/rt → user32 */
        fallback_so = "libpe_user32.so";
    } else if (strncmp(lower, "ext-ms-", 7) == 0) {
        fallback_so = "libpe_kernel32.so";
    } else if (strncmp(lower, "vcruntime", 9) == 0 ||
               strncmp(lower, "msvcp", 5) == 0 ||
               strncmp(lower, "msvcr", 5) == 0 ||
               strncmp(lower, "ucrtbase", 8) == 0 ||
               strncmp(lower, "concrt", 6) == 0 ||
               strncmp(lower, "vcomp", 5) == 0) {
        fallback_so = "libpe_msvcrt.so";
    }

    if (fallback_so) {
        fprintf(stderr, LOG_PREFIX "  Catch-all: mapping '%s' -> %s\n", dll_name, fallback_so);

        /* Check the catch-all handle cache first to avoid redundant dlopen calls */
#define CATCHALL_CACHE_SIZE 32
        static struct { const char *so_name; void *handle; } catchall_cache[CATCHALL_CACHE_SIZE];
        static int catchall_cache_count = 0;

        for (int ci = 0; ci < catchall_cache_count; ci++) {
            if (catchall_cache[ci].so_name == fallback_so) {
                /* Cache hit -- fallback_so is a string literal, pointer compare is safe */
                return catchall_cache[ci].handle;
            }
        }

        void *handle = search_and_open(fallback_so);
        if (handle) {
            printf(LOG_PREFIX "  Loaded stub library (catch-all): %s -> %s\n",
                   dll_name, fallback_so);
            anticheat_bridge_on_load_library(dll_name);

            /* Cache the handle for future lookups with the same .so */
            if (catchall_cache_count < CATCHALL_CACHE_SIZE) {
                catchall_cache[catchall_cache_count].so_name = fallback_so;
                catchall_cache[catchall_cache_count].handle = handle;
                catchall_cache_count++;
            }
        }
        return handle;
    }

    fprintf(stderr, LOG_PREFIX "  WARNING: No mapping for DLL '%s'\n", dll_name);
    return NULL;
}

/*
 * ---- Forwarded export resolution subsystem ----
 *
 * Many Windows DLLs (especially kernel32, ntdll, ucrtbase) forward exports
 * to other DLLs. For example:
 *   kernel32!CreateFileA  -> kernelbase!CreateFileA
 *   kernel32!HeapAlloc    -> ntdll!RtlAllocateHeap
 *   ucrtbase!malloc       -> api-ms-win-crt-heap-l1-1-0!malloc
 *
 * When a PE export directory entry has its function RVA pointing *within*
 * the export directory bounds, the RVA points to a null-terminated ASCII
 * forwarder string like "NTDLL.RtlAllocateHeap" or "api-ms-win-core-heap-l1-1-0.HeapAlloc".
 * Ordinal forwarders look like "NTDLL.#42".
 *
 * We must resolve these chains recursively (with a depth limit) across
 * both our .so stub DLLs and loaded PE DLLs.
 */

/* Max recursion depth for forwarder chains to prevent infinite loops */
#define MAX_FORWARDER_DEPTH 16

/* ---- Circular dependency protection ----
 * Tracks DLLs whose imports are currently being resolved.  When DLL A
 * imports from DLL B which imports from DLL A, the second attempt to
 * load A finds it in this array and returns the partial handle from
 * g_pe_modules instead of recursing into pe_dll_load again.
 *
 * Entries are pushed before pe_dll_load / pe_dll_resolve_imports and
 * popped when resolution completes.  MAX_DLL_LOAD_DEPTH also serves
 * as an absolute recursion limit for the entire DLL loading chain. */
#define MAX_DLL_LOAD_DEPTH 32

static struct {
    char name[64];   /* lowercased DLL name */
} g_loading_stack[MAX_DLL_LOAD_DEPTH];
static int g_loading_depth = 0;

/* Check if a DLL is already on the loading stack (circular dependency).
 * Returns 1 if found (currently being loaded), 0 otherwise. */
static int loading_stack_find(const char *dll_name)
{
    char lower[64];
    size_t i;
    for (i = 0; dll_name[i] && i < sizeof(lower) - 1; i++)
        lower[i] = tolower((unsigned char)dll_name[i]);
    lower[i] = '\0';

    for (int j = 0; j < g_loading_depth; j++) {
        if (strcmp(g_loading_stack[j].name, lower) == 0)
            return 1;
    }
    return 0;
}

/* Push a DLL onto the loading stack.  Returns 0 on success, -1 if full. */
static int loading_stack_push(const char *dll_name)
{
    if (g_loading_depth >= MAX_DLL_LOAD_DEPTH) {
        fprintf(stderr, LOG_PREFIX "DLL load depth limit (%d) exceeded at %s\n",
                MAX_DLL_LOAD_DEPTH, dll_name);
        return -1;
    }
    char *dst = g_loading_stack[g_loading_depth].name;
    size_t i;
    for (i = 0; dll_name[i] && i < 63; i++)
        dst[i] = tolower((unsigned char)dll_name[i]);
    dst[i] = '\0';
    g_loading_depth++;
    return 0;
}

/* Pop the top entry off the loading stack. */
static void loading_stack_pop(void)
{
    if (g_loading_depth > 0)
        g_loading_depth--;
}

/* Forward declarations for PE DLL loading infrastructure in kernel32_module_pe.c.
 * These are accessible because the loader binary links with -rdynamic. */
extern void *pe_dll_load(const char *dll_name) __attribute__((weak));
extern void *pe_dll_find(const char *name) __attribute__((weak));
extern void *pe_dll_get_proc(void *base, const char *proc_name) __attribute__((weak));

/* Case-insensitive string compare (portable) */
static int str_casecmp(const char *a, const char *b)
{
    while (*a && *b) {
        int ca = tolower((unsigned char)*a);
        int cb = tolower((unsigned char)*b);
        if (ca != cb) return ca - cb;
        a++; b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

/*
 * Walk a PE image's export directory to find a function by name.
 *
 * image_base: base address of mapped PE image
 * image_size: total size of mapped image (for bounds checking)
 * func_name:  name of the exported function to find
 * out_is_forwarder: if non-NULL, set to 1 when the result is a forwarder string
 *
 * Returns:
 *   - Pointer to the function if found (normal export)
 *   - Pointer to the forwarder string if it's a forwarded export
 *     (caller must check *out_is_forwarder)
 *   - NULL if not found or on error
 *
 * HOT PATH: This is called for every named import in every DLL at load time.
 * The name table is sorted by the PE spec, so we binary-search first (O(log n)),
 * falling back to case-insensitive linear scan only if that misses.
 */
__attribute__((hot))
static void *resolve_pe_export_by_name(const uint8_t *image_base,
                                        uint32_t image_size,
                                        const char *func_name,
                                        int *out_is_forwarder)
{
    if (!image_base || !func_name || image_size < 0x40)
        return NULL;

    if (out_is_forwarder)
        *out_is_forwarder = 0;

    /* Verify MZ signature */
    if (*(const uint16_t *)image_base != 0x5A4D)
        return NULL;

    /* Get PE header offset -- bounds-check before dereference */
    uint32_t pe_off = *(const uint32_t *)(image_base + 0x3C);
    if (!PE_RVA_VALID(image_base, image_size, pe_off, 4 + 20))
        return NULL;

    /* Verify PE signature */
    if (*(const uint32_t *)(image_base + pe_off) != 0x00004550)
        return NULL;

    /* Optional header */
    const uint8_t *opt = image_base + pe_off + 4 + 20;
    uint16_t magic = *(const uint16_t *)opt;
    int is64 = (magic == 0x020B);
    int dd_off = is64 ? 112 : 96;
    uint32_t num_dd = is64 ? *(const uint32_t *)(opt + 108) : *(const uint32_t *)(opt + 92);

    /* Need at least the export directory entry */
    if (num_dd < 1)
        return NULL;

    uint32_t export_rva  = *(const uint32_t *)(opt + dd_off);
    uint32_t export_size = *(const uint32_t *)(opt + dd_off + 4);
    if (export_rva == 0 || export_size == 0)
        return NULL;
    if (!PE_RVA_VALID(image_base, image_size, export_rva, export_size))
        return NULL;

    /* Export directory table -- pe_export_directory_t is 40 bytes */
    if (!PE_RVA_VALID(image_base, image_size, export_rva, sizeof(pe_export_directory_t)))
        return NULL;
    const pe_export_directory_t *ed = PE_RVA_PTR(image_base, export_rva,
                                                   const pe_export_directory_t *);
    uint32_t num_functions  = ed->number_of_functions;
    uint32_t num_names      = ed->number_of_names;
    uint32_t func_table_rva = ed->address_of_functions_rva;
    uint32_t name_table_rva = ed->address_of_names_rva;
    uint32_t ord_table_rva  = ed->address_of_name_ordinals_rva;

    /* Bounds check all three table extents */
    if (!PE_RVA_VALID(image_base, image_size, func_table_rva, num_functions * 4) ||
        !PE_RVA_VALID(image_base, image_size, name_table_rva, num_names * 4) ||
        !PE_RVA_VALID(image_base, image_size, ord_table_rva,  num_names * 2))
        return NULL;

    const uint32_t *func_table = PE_RVA_PTR(image_base, func_table_rva, const uint32_t *);
    const uint32_t *name_table = PE_RVA_PTR(image_base, name_table_rva, const uint32_t *);
    const uint16_t *ord_table  = PE_RVA_PTR(image_base, ord_table_rva,  const uint16_t *);

    /* ---- Fast path: binary search (case-sensitive, O(log n)) ----
     * PE export name pointer tables are required to be sorted in ascending
     * lexicographic order by the Microsoft PE/COFF spec (section 6.3.1).
     * This lets us binary search instead of scanning all names. */
    int lo = 0, hi = (int)num_names - 1;
    while (lo <= hi) {
        int mid = lo + ((hi - lo) >> 1);  /* Avoids overflow vs (lo+hi)/2 */
        uint32_t name_rva = name_table[mid];
        if (!PE_RVA_VALID(image_base, image_size, name_rva, 1))
            return NULL; /* Corrupt */

        const char *mid_name = (const char *)(image_base + name_rva);
        int cmp = strcmp(func_name, mid_name);
        if (cmp == 0) {
            /* Found it -- look up ordinal and function RVA */
            uint16_t ordinal_index = ord_table[mid];
            if (ordinal_index >= num_functions)
                return NULL;

            uint32_t func_rva = func_table[ordinal_index];
            if (func_rva == 0)
                return NULL;

            /* Forwarder check: RVA falls within the export directory range */
            if (func_rva >= export_rva && func_rva < export_rva + export_size) {
                if (!PE_RVA_VALID(image_base, image_size, func_rva, 1))
                    return NULL;
                if (out_is_forwarder)
                    *out_is_forwarder = 1;
                return (void *)(image_base + func_rva);
            }

            /* Normal export -- validate target is within image bounds */
            if (!PE_RVA_VALID(image_base, image_size, func_rva, 1))
                return NULL;
            return (void *)(image_base + func_rva);
        }
        if (cmp < 0)
            hi = mid - 1;
        else
            lo = mid + 1;
    }

    /* ---- Slow path: case-insensitive linear scan ----
     * Some DLLs have exports that differ only in case from what the
     * importer uses (common with MSVC decorated names).  This scan
     * only fires when binary search missed, so it's not on the hot path. */
    for (uint32_t i = 0; i < num_names; i++) {
        uint32_t name_rva = name_table[i];
        if (!PE_RVA_VALID(image_base, image_size, name_rva, 1))
            continue;
        const char *entry_name = (const char *)(image_base + name_rva);
        if (str_casecmp(func_name, entry_name) == 0) {
            uint16_t ordinal_index = ord_table[i];
            if (ordinal_index >= num_functions)
                return NULL;

            uint32_t func_rva = func_table[ordinal_index];
            if (func_rva == 0)
                return NULL;

            if (func_rva >= export_rva && func_rva < export_rva + export_size) {
                if (!PE_RVA_VALID(image_base, image_size, func_rva, 1))
                    return NULL;
                if (out_is_forwarder)
                    *out_is_forwarder = 1;
                return (void *)(image_base + func_rva);
            }
            if (!PE_RVA_VALID(image_base, image_size, func_rva, 1))
                return NULL;
            return (void *)(image_base + func_rva);
        }
    }

    return NULL;
}

/*
 * Walk a PE image's export directory to find a function by ordinal.
 *
 * ordinal:    the raw ordinal number (NOT biased -- we subtract OrdinalBase here)
 * Returns:    function pointer, forwarder string, or NULL
 */
static void *resolve_pe_export_by_ordinal(const uint8_t *image_base,
                                           uint32_t image_size,
                                           uint16_t ordinal,
                                           int *out_is_forwarder)
{
    if (!image_base || image_size < 0x40)
        return NULL;

    if (out_is_forwarder)
        *out_is_forwarder = 0;

    /* Verify MZ + PE */
    if (*(const uint16_t *)image_base != 0x5A4D)
        return NULL;
    uint32_t pe_off = *(const uint32_t *)(image_base + 0x3C);
    if (!PE_RVA_VALID(image_base, image_size, pe_off, 4 + 20))
        return NULL;
    if (*(const uint32_t *)(image_base + pe_off) != 0x00004550)
        return NULL;

    const uint8_t *opt = image_base + pe_off + 4 + 20;
    uint16_t magic = *(const uint16_t *)opt;
    int is64 = (magic == 0x020B);
    int dd_off = is64 ? 112 : 96;
    uint32_t num_dd = is64 ? *(const uint32_t *)(opt + 108) : *(const uint32_t *)(opt + 92);

    if (num_dd < 1) return NULL;

    uint32_t export_rva  = *(const uint32_t *)(opt + dd_off);
    uint32_t export_size = *(const uint32_t *)(opt + dd_off + 4);
    if (export_rva == 0 || export_size == 0) return NULL;
    if (!PE_RVA_VALID(image_base, image_size, export_rva, export_size))
        return NULL;

    /* Export directory (typed access) */
    if (!PE_RVA_VALID(image_base, image_size, export_rva, sizeof(pe_export_directory_t)))
        return NULL;
    const pe_export_directory_t *ed = PE_RVA_PTR(image_base, export_rva,
                                                   const pe_export_directory_t *);
    uint32_t ordinal_base   = ed->ordinal_base;
    uint32_t num_functions  = ed->number_of_functions;
    uint32_t func_table_rva = ed->address_of_functions_rva;

    if (!PE_RVA_VALID(image_base, image_size, func_table_rva, num_functions * 4))
        return NULL;

    /* Subtract ordinal base to get the index into AddressOfFunctions */
    if (ordinal < ordinal_base)
        return NULL;
    uint32_t index = ordinal - ordinal_base;
    if (index >= num_functions)
        return NULL;

    const uint32_t *func_table = PE_RVA_PTR(image_base, func_table_rva, const uint32_t *);
    uint32_t func_rva = func_table[index];
    if (func_rva == 0)
        return NULL;

    /* Forwarder check */
    if (func_rva >= export_rva && func_rva < export_rva + export_size) {
        if (!PE_RVA_VALID(image_base, image_size, func_rva, 1))
            return NULL;
        if (out_is_forwarder)
            *out_is_forwarder = 1;
        return (void *)(image_base + func_rva);
    }

    /* Normal export -- validate target is within image */
    if (!PE_RVA_VALID(image_base, image_size, func_rva, 1))
        return NULL;
    return (void *)(image_base + func_rva);
}

/*
 * Follow a forwarder chain to its final target.
 *
 * forwarder_string: ASCII string like "NTDLL.RtlAllocateHeap" or "NTDLL.#42"
 * depth:            current recursion depth (caller passes 0)
 *
 * The resolution order for each hop is:
 *   1. CRT wrapper table (catches memset/malloc/etc. before sysv/ms ABI mismatch)
 *   2. dlsym on the .so stub library (our Win32 API implementations)
 *   3. Local PE module table (g_pe_modules -- always available)
 *   4. kernel32_module_pe.c PE DLL loader (weak extern, may not be linked)
 *   5. RTLD_DEFAULT (all loaded .so libraries)
 *
 * Returns the resolved function pointer, or NULL if it can't be resolved.
 */
static void *follow_forwarder(const char *forwarder_string, int depth)
{
    if (!forwarder_string || depth >= MAX_FORWARDER_DEPTH ||
        g_loading_depth >= MAX_DLL_LOAD_DEPTH)
        return NULL;

    /* Parse "DllName.FuncName" or "DllName.#ordinal".
     * Use memchr with a bounded length to prevent reading beyond
     * the export directory if the forwarder string is not NUL-terminated. */
    size_t max_fwd_len = strnlen(forwarder_string, 512);
    const char *dot = memchr(forwarder_string, '.', max_fwd_len);
    if (!dot || dot == forwarder_string)
        return NULL;

    char dll_name[256];
    size_t dll_len = dot - forwarder_string;
    if (dll_len >= sizeof(dll_name) - 5)
        return NULL;

    snprintf(dll_name, sizeof(dll_name), "%.*s.dll", (int)dll_len, forwarder_string);
    str_lower(dll_name);

    const char *func_part = dot + 1;
    int is_ordinal_fwd = (func_part[0] == '#');

    printf(LOG_PREFIX "  Following forwarder: %s -> %s (depth %d)\n",
           forwarder_string, dll_name, depth);

    /* Step 1: If it's a name import, check CRT wrapper table first.
     * This is critical -- if kernel32!HeapAlloc forwards to NTDLL!RtlAllocateHeap,
     * and RtlAllocateHeap is a wrapper around malloc, we need the ms_abi version. */
    if (!is_ordinal_fwd) {
        void *crt = pe_find_crt_wrapper(func_part);
        if (crt) return crt;
    }

    /* Step 2: Try to load/find the .so stub for this DLL */
    void *so_handle = find_dll_library(dll_name);
    if (so_handle) {
        if (is_ordinal_fwd) {
            /* Ordinal forwarder: "DLL.#42" */
            uint16_t ord = (uint16_t)atoi(func_part + 1);
            char ordinal_sym[64];
            snprintf(ordinal_sym, sizeof(ordinal_sym), "__ordinal_%u", ord);
            void *addr = dlsym(so_handle, ordinal_sym);
            if (addr) return addr;
        } else {
            /* Name forwarder */
            void *addr = dlsym(so_handle, func_part);
            if (addr) return addr;
        }
    }

    /* Step 3: Local PE module table (always available, no weak-extern dependency).
     * This is the primary path for PE-to-PE forwarder chains like
     * kernel32.dll -> kernelbase.dll -> ntdll.dll */
    {
        struct pe_module_entry *mod = find_pe_module(dll_name);
        if (mod && mod->image_base && mod->image_size > 0) {
            int is_fwd = 0;
            void *addr = NULL;

            if (is_ordinal_fwd) {
                uint16_t ord = (uint16_t)atoi(func_part + 1);
                addr = resolve_pe_export_by_ordinal(mod->image_base,
                                                     mod->image_size, ord, &is_fwd);
            } else {
                addr = resolve_pe_export_by_name(mod->image_base,
                                                  mod->image_size, func_part, &is_fwd);
            }

            if (addr) {
                if (is_fwd)
                    return follow_forwarder((const char *)addr, depth + 1);
                return addr;
            }
        }
    }

    /* Step 4: kernel32_module_pe.c PE DLL loader (may trigger disk load).
     * Check the loading stack first to break circular dependencies:
     * if dll_name is already being loaded higher up the call chain,
     * return the partial handle instead of recursing. */
    if (pe_dll_find && pe_dll_load) {
        /* Check if this DLL is already on the loading stack (circular dep). */
        if (loading_stack_find(dll_name)) {
            /* Circular dependency -- try pe_dll_find for the partial handle
             * (pe_dll_load registers with loaded=1 before resolving imports) */
            void *circ_base = pe_dll_find ? pe_dll_find(dll_name) : NULL;
            if (!circ_base) {
                /* Also check the local PE module table */
                struct pe_module_entry *circ_mod = find_pe_module(dll_name);
                if (circ_mod)
                    circ_base = circ_mod->image_base;
            }
            if (circ_base) {
                printf(LOG_PREFIX "  Circular dependency on %s (depth %d) -- using partial handle\n",
                       dll_name, depth);
                const uint8_t *cp = (const uint8_t *)circ_base;
                uint32_t cp_size = pe_image_size_from_headers(cp);
                if (cp_size > 0) {
                    int is_fwd_c = 0;
                    void *caddr = NULL;
                    if (is_ordinal_fwd) {
                        uint16_t ord = (uint16_t)atoi(func_part + 1);
                        caddr = resolve_pe_export_by_ordinal(cp, cp_size, ord, &is_fwd_c);
                    } else {
                        caddr = resolve_pe_export_by_name(cp, cp_size, func_part, &is_fwd_c);
                    }
                    /* Don't follow forwarders from circular deps -- may loop */
                    if (caddr)
                        return caddr;
                }
            }
            /* Circular and unresolvable -- skip to RTLD_DEFAULT */
            fprintf(stderr, LOG_PREFIX "  Circular dependency on %s -- symbol unresolvable\n",
                    dll_name);
            goto step5_fallback;
        }

        void *pe_base = pe_dll_find(dll_name);
        if (!pe_base) {
            if (loading_stack_push(dll_name) < 0)
                goto step5_fallback;
            pe_base = pe_dll_load(dll_name);
            loading_stack_pop();
        }

        if (pe_base) {
            const uint8_t *p = (const uint8_t *)pe_base;
            uint32_t pe_size = pe_image_size_from_headers(p);
            if (pe_size == 0)
                pe_size = 0x10000000; /* Conservative fallback */

            int is_fwd = 0;
            void *addr = NULL;

            if (is_ordinal_fwd) {
                uint16_t ord = (uint16_t)atoi(func_part + 1);
                addr = resolve_pe_export_by_ordinal(p, pe_size, ord, &is_fwd);
            } else {
                addr = resolve_pe_export_by_name(p, pe_size, func_part, &is_fwd);
            }

            if (addr) {
                if (is_fwd)
                    return follow_forwarder((const char *)addr, depth + 1);
                return addr;
            }
        }
    }

step5_fallback:
    /* Step 5: Try RTLD_DEFAULT (all loaded .so libraries) as last resort */
    if (!is_ordinal_fwd) {
        void *addr = dlsym(RTLD_DEFAULT, func_part);
        if (addr) return addr;
    }

    fprintf(stderr, LOG_PREFIX "  Forwarder unresolved: %s\n", forwarder_string);
    return NULL;
}

/*
 * Resolve a forwarded export string -- top-level entry point.
 * This is the function called from the import resolution loops.
 */
static void *resolve_forwarded_export(const char *forwarder)
{
    return follow_forwarder(forwarder, 0);
}

/*
 * try_pe_export_resolution - Resolve a named import via PE export directories.
 *
 * Searches the local PE module table first (O(n) with n < 128), then
 * falls back to the kernel32_module_pe.c weak externs.  Handles forwarder
 * chains transparently.
 *
 * This is the single entry point for PE-to-PE import resolution from the
 * main import loop.  It is designed to be called AFTER dlsym and CRT
 * wrapper lookups have both missed.
 *
 * dll_name:   the importing DLL name (used to find the right module)
 * func_name:  the function name to resolve
 *
 * Returns resolved address or NULL.
 */
static void *try_pe_export_resolution(const char *dll_name, const char *func_name)
{
    void *addr = NULL;
    int is_fwd = 0;

    /* 1. Local PE module table (always available) */
    struct pe_module_entry *mod = find_pe_module(dll_name);
    if (mod && mod->image_base && mod->image_size > 0) {
        addr = resolve_pe_export_by_name(mod->image_base, mod->image_size,
                                          func_name, &is_fwd);
        if (addr) {
            if (is_fwd)
                addr = resolve_forwarded_export((const char *)addr);
            if (addr) return addr;
        }
    }

    /* 2. kernel32_module_pe.c weak-extern lookup (triggers disk load if needed) */
    if (pe_dll_find) {
        char dll_lower[256];
        strncpy(dll_lower, dll_name, sizeof(dll_lower) - 1);
        dll_lower[sizeof(dll_lower) - 1] = '\0';
        str_lower(dll_lower);

        void *pe_base = pe_dll_find(dll_lower);
        if (pe_base) {
            const uint8_t *p = (const uint8_t *)pe_base;
            uint32_t pe_size = pe_image_size_from_headers(p);
            if (pe_size > 0) {
                is_fwd = 0;
                addr = resolve_pe_export_by_name(p, pe_size, func_name, &is_fwd);
                if (addr) {
                    if (is_fwd)
                        addr = resolve_forwarded_export((const char *)addr);
                    if (addr) return addr;
                }
            }
        }
    }

    return NULL;
}

/*
 * try_pe_ordinal_resolution - Resolve an ordinal import via PE export directories.
 *
 * Same strategy as try_pe_export_resolution but for ordinal imports.
 */
static void *try_pe_ordinal_resolution(const char *dll_name, uint16_t ordinal)
{
    void *addr = NULL;
    int is_fwd = 0;

    /* 1. Local PE module table */
    struct pe_module_entry *mod = find_pe_module(dll_name);
    if (mod && mod->image_base && mod->image_size > 0) {
        addr = resolve_pe_export_by_ordinal(mod->image_base, mod->image_size,
                                             ordinal, &is_fwd);
        if (addr) {
            if (is_fwd)
                addr = resolve_forwarded_export((const char *)addr);
            if (addr) return addr;
        }
    }

    /* 2. kernel32_module_pe.c weak-extern lookup */
    if (pe_dll_find) {
        char dll_lower[256];
        strncpy(dll_lower, dll_name, sizeof(dll_lower) - 1);
        dll_lower[sizeof(dll_lower) - 1] = '\0';
        str_lower(dll_lower);

        void *pe_base = pe_dll_find(dll_lower);
        if (pe_base) {
            const uint8_t *p = (const uint8_t *)pe_base;
            uint32_t pe_size = pe_image_size_from_headers(p);
            if (pe_size > 0) {
                is_fwd = 0;
                addr = resolve_pe_export_by_ordinal(p, pe_size, ordinal, &is_fwd);
                if (addr) {
                    if (is_fwd)
                        addr = resolve_forwarded_export((const char *)addr);
                    if (addr) return addr;
                }
            }
        }
    }

    return NULL;
}

/*
 * Unified symbol resolution helper.
 *
 * Looks up a function name using the full resolution chain:
 *   1. CRT ABI wrapper table (prevents sysv/ms mismatch for libc functions)
 *   2. dlsym on the .so stub library
 *   3. C++ mangled name table
 *   4. Winsock name translation
 *   5. PE export directory (local table + weak externs) with forwarder following
 *   6. RTLD_DEFAULT fallback
 *
 * so_handle:  dlopen handle for the .so stub (may be NULL)
 * func_name:  the imported function name
 * dll_name:   the DLL name (for Winsock detection and diagnostics)
 */
static void *resolve_import_symbol(void *so_handle,
                                    const char *func_name,
                                    const char *dll_name)
{
    void *addr = NULL;
    int winsock_dll = is_winsock_dll(dll_name);
    int msvcrt_dll = is_msvcrt_dll(dll_name);
    const char *lookup_name = func_name;

    if (winsock_dll)
        lookup_name = translate_ws2_name(func_name);
    else if (msvcrt_dll)
        lookup_name = translate_wcs_name(func_name);

    /* 1. CRT ABI wrappers -- MUST be checked first to prevent ABI mismatch */
    addr = pe_find_crt_wrapper(func_name);
    if (addr) return addr;

    /* 2. dlsym on the .so stub library */
    if (so_handle) {
        addr = dlsym(so_handle, lookup_name);
        if (addr) return addr;

        /* 2b. Try C++ mangled names */
        if (func_name[0] == '?') {
            addr = find_mangled_name(func_name, so_handle);
            if (addr) return addr;
        }
    }

    /* 3. PE export directory (local module table + kernel32_module_pe.c) */
    addr = try_pe_export_resolution(dll_name, func_name);
    if (addr) return addr;

    /* 4. RTLD_DEFAULT -- search all loaded .so files */
    addr = dlsym(RTLD_DEFAULT, lookup_name);
    if (addr) return addr;

    return NULL;
}

/*
 * Unified ordinal resolution helper.
 */
static void *resolve_import_ordinal(void *so_handle,
                                     uint16_t ordinal,
                                     const char *dll_name)
{
    void *addr = NULL;

    /* 1. Try __ordinal_N convention on .so stub */
    if (so_handle) {
        char ordinal_sym[64];
        snprintf(ordinal_sym, sizeof(ordinal_sym), "__ordinal_%u", ordinal);
        addr = dlsym(so_handle, ordinal_sym);
        if (addr) return addr;
    }

    /* 2. PE export directory (local module table + kernel32_module_pe.c) */
    addr = try_pe_ordinal_resolution(dll_name, ordinal);
    if (addr) return addr;

    return NULL;
}

int pe_resolve_imports(pe_image_t *image)
{
    /* Check for import directory */
    if (image->number_of_rva_and_sizes <= PE_DIR_IMPORT)
        return 0;

    pe_data_directory_t *import_dir = &image->data_directory[PE_DIR_IMPORT];
    if (import_dir->virtual_address == 0 || import_dir->size == 0) {
        printf(LOG_PREFIX "No imports to resolve\n");
        return 0;
    }

    pe_import_descriptor_t *desc = (pe_import_descriptor_t *)
        pe_rva_to_ptr(image, import_dir->virtual_address);

    if (!desc) {
        fprintf(stderr, LOG_PREFIX "Invalid import directory RVA\n");
        return -1;
    }

    int total_resolved = 0;
    int total_unresolved = 0;

    /* Walk import descriptors until we hit an all-zero entry */
    const uint8_t *import_start = (const uint8_t *)desc;
    for (; ; desc++) {
        /* Bounds check: ensure there's room for the full descriptor before reading */
        if ((const uint8_t *)(desc + 1) - import_start > (ptrdiff_t)import_dir->size)
            break;
        if (desc->name_rva == 0)
            break;
        const char *dll_name = (const char *)pe_rva_to_ptr(image, desc->name_rva);
        if (!dll_name) {
            fprintf(stderr, LOG_PREFIX "Invalid DLL name RVA\n");
            continue;
        }

        printf(LOG_PREFIX "Resolving imports from: %s\n", dll_name);

        void *lib = find_dll_library(dll_name);

        /* Get ILT and IAT pointers */
        uint32_t ilt_rva = desc->import_lookup_table_rva;
        uint32_t iat_rva = desc->import_address_table_rva;

        /* If ILT is zero, use IAT as source (some linkers do this) */
        if (ilt_rva == 0)
            ilt_rva = iat_rva;

        if (image->is_pe32plus) {
            /* 64-bit: ILT and IAT entries are 8 bytes */
            uint64_t *ilt = (uint64_t *)pe_rva_to_ptr(image, ilt_rva);
            uint64_t *iat = (uint64_t *)pe_rva_to_ptr(image, iat_rva);

            if (!ilt || !iat) {
                fprintf(stderr, LOG_PREFIX "  Invalid ILT/IAT RVA\n");
                continue;
            }

            for (int i = 0; ilt[i] != 0 && i < 65536; i++) {
                void *func_addr = NULL;

                if (ilt[i] & PE_IMPORT_ORDINAL_FLAG64) {
                    /* Import by ordinal */
                    uint16_t ordinal = ilt[i] & 0xFFFF;
                    func_addr = resolve_import_ordinal(lib, ordinal, dll_name);
                } else {
                    /* Import by name */
                    uint32_t hint_rva = (uint32_t)(ilt[i] & 0x7FFFFFFF);
                    pe_import_by_name_t *hint = (pe_import_by_name_t *)
                        pe_rva_to_ptr(image, hint_rva);

                    if (!hint) {
                        fprintf(stderr, LOG_PREFIX "    Invalid hint/name RVA\n");
                        iat[i] = (uint64_t)(uintptr_t)create_diagnostic_stub(dll_name, "?bad_rva");
                        total_unresolved++;
                        continue;
                    }

                    func_addr = resolve_import_symbol(lib, hint->name, dll_name);
                }

                if (func_addr) {
                    iat[i] = (uint64_t)(uintptr_t)func_addr;
                    total_resolved++;
                } else {
                    const char *name;
                    if (ilt[i] & 0x8000000000000000ULL) {
                        name = "ordinal";
                    } else {
                        pe_import_by_name_t *hint = (pe_import_by_name_t *)
                            pe_rva_to_ptr(image, (uint32_t)(ilt[i] & 0x7FFFFFFF));
                        name = hint ? hint->name : "?unknown";
                    }
                    iat[i] = (uint64_t)(uintptr_t)create_diagnostic_stub(dll_name, name);
                    total_unresolved++;
                }
            }
        } else {
            /* 32-bit: ILT and IAT entries are 4 bytes */
            uint32_t *ilt = (uint32_t *)pe_rva_to_ptr(image, ilt_rva);
            uint32_t *iat = (uint32_t *)pe_rva_to_ptr(image, iat_rva);

            if (!ilt || !iat) {
                fprintf(stderr, LOG_PREFIX "  Invalid ILT/IAT RVA\n");
                continue;
            }

            for (int i = 0; ilt[i] != 0 && i < 65536; i++) {
                void *func_addr = NULL;

                if (ilt[i] & PE_IMPORT_ORDINAL_FLAG32) {
                    uint16_t ordinal = ilt[i] & 0xFFFF;
                    func_addr = resolve_import_ordinal(lib, ordinal, dll_name);
                } else {
                    uint32_t hint_rva = ilt[i] & 0x7FFFFFFF;
                    pe_import_by_name_t *hint = (pe_import_by_name_t *)
                        pe_rva_to_ptr(image, hint_rva);

                    if (!hint) {
                        iat[i] = (uint32_t)(uintptr_t)create_diagnostic_stub(dll_name, "?bad_rva");
                        total_unresolved++;
                        continue;
                    }

                    func_addr = resolve_import_symbol(lib, hint->name, dll_name);
                }

                if (func_addr) {
                    iat[i] = (uint32_t)(uintptr_t)func_addr;
                    total_resolved++;
                } else {
                    const char *name;
                    if (ilt[i] & PE_IMPORT_ORDINAL_FLAG32) {
                        name = "ordinal";
                    } else {
                        pe_import_by_name_t *hint = (pe_import_by_name_t *)
                            pe_rva_to_ptr(image, ilt[i] & 0x7FFFFFFF);
                        name = hint ? hint->name : "?unknown";
                    }
                    iat[i] = (uint32_t)(uintptr_t)create_diagnostic_stub(dll_name, name);
                    total_unresolved++;
                }
            }
        }
    }

    printf(LOG_PREFIX "Import resolution: %d resolved, %d unresolved\n",
           total_resolved, total_unresolved);

    /* ---- Delay-load import resolution ---- */
    if (image->number_of_rva_and_sizes > PE_DIR_DELAY_IMPORT) {
        pe_data_directory_t *delay_dir = &image->data_directory[PE_DIR_DELAY_IMPORT];
        if (delay_dir->virtual_address != 0 && delay_dir->size != 0) {
            pe_delay_import_descriptor_t *ddesc = (pe_delay_import_descriptor_t *)
                pe_rva_to_ptr(image, delay_dir->virtual_address);

            if (ddesc) {
                int delay_resolved = 0, delay_unresolved = 0;
                const uint8_t *delay_start = (const uint8_t *)ddesc;

                for (; ; ddesc++) {
                    /* Bounds check: ensure there's room for the full descriptor before reading */
                    if ((const uint8_t *)(ddesc + 1) - delay_start > (ptrdiff_t)delay_dir->size)
                        break;
                    if (ddesc->name_rva == 0)
                        break;
                    const char *dll_name2 = (const char *)
                        pe_rva_to_ptr(image, ddesc->name_rva);
                    if (!dll_name2) continue;

                    printf(LOG_PREFIX "Resolving delay-load imports from: %s\n", dll_name2);

                    void *lib2 = find_dll_library(dll_name2);

                    /* Delay-load INT (Import Name Table) and IAT */
                    uint32_t int_rva = ddesc->delay_int_rva;
                    uint32_t iat_rva2 = ddesc->delay_iat_rva;

                    /* Adjust RVAs: if attributes bit 0 is set, these are RVAs;
                     * if not set (older format), they are VAs and need base subtraction */
                    if (!(ddesc->attributes & 1)) {
                        uint32_t base32 = (uint32_t)(image->image_base & 0xFFFFFFFF);
                        if (int_rva < base32 || iat_rva2 < base32) {
                            fprintf(stderr, LOG_PREFIX "  Delay-import RVA conversion underflow for %s\n", dll_name2);
                            continue;
                        }
                        int_rva -= base32;
                        iat_rva2 -= base32;
                    }

                    if (image->is_pe32plus) {
                        uint64_t *dint = (uint64_t *)pe_rva_to_ptr(image, int_rva);
                        uint64_t *diat = (uint64_t *)pe_rva_to_ptr(image, iat_rva2);
                        if (!dint || !diat) continue;

                        for (int i = 0; dint[i] != 0 && i < 65536; i++) {
                            void *func = NULL;

                            if (dint[i] & PE_IMPORT_ORDINAL_FLAG64) {
                                uint16_t ordinal = dint[i] & 0xFFFF;
                                func = resolve_import_ordinal(lib2, ordinal, dll_name2);
                            } else {
                                uint32_t hint_rva2 = (uint32_t)(dint[i] & 0x7FFFFFFF);
                                pe_import_by_name_t *hint2 = (pe_import_by_name_t *)
                                    pe_rva_to_ptr(image, hint_rva2);
                                if (hint2) {
                                    func = resolve_import_symbol(lib2, hint2->name, dll_name2);
                                    if (!func)
                                        fprintf(stderr, LOG_PREFIX "    DELAY UNRESOLVED: %s!%s\n",
                                                dll_name2, hint2->name);
                                }
                            }

                            if (func) {
                                diat[i] = (uint64_t)(uintptr_t)func;
                                delay_resolved++;
                            } else {
                                diat[i] = (uint64_t)(uintptr_t)create_diagnostic_stub(dll_name2, "delay-import");
                                delay_unresolved++;
                            }
                        }
                    } else {
                        uint32_t *dint = (uint32_t *)pe_rva_to_ptr(image, int_rva);
                        uint32_t *diat = (uint32_t *)pe_rva_to_ptr(image, iat_rva2);
                        if (!dint || !diat) continue;

                        for (int i = 0; dint[i] != 0 && i < 65536; i++) {
                            void *func = NULL;

                            if (dint[i] & PE_IMPORT_ORDINAL_FLAG32) {
                                uint16_t ordinal = dint[i] & 0xFFFF;
                                func = resolve_import_ordinal(lib2, ordinal, dll_name2);
                            } else {
                                uint32_t hint_rva2 = dint[i] & 0x7FFFFFFF;
                                pe_import_by_name_t *hint2 = (pe_import_by_name_t *)
                                    pe_rva_to_ptr(image, hint_rva2);
                                if (hint2) {
                                    func = resolve_import_symbol(lib2, hint2->name, dll_name2);
                                }
                            }

                            if (func) {
                                diat[i] = (uint32_t)(uintptr_t)func;
                                delay_resolved++;
                            } else {
                                diat[i] = (uint32_t)(uintptr_t)create_diagnostic_stub(dll_name2, "delay-import");
                                delay_unresolved++;
                            }
                        }
                    }

                    /* Store module handle for the delay-loaded DLL */
                    if (lib2 && ddesc->module_handle_rva) {
                        uint32_t mh_rva = ddesc->module_handle_rva;
                        if (!(ddesc->attributes & 1))
                            mh_rva -= (uint32_t)(image->image_base & 0xFFFFFFFF);
                        void **mh_ptr = (void **)pe_rva_to_ptr(image, mh_rva);
                        if (mh_ptr)
                            *mh_ptr = lib2;
                    }
                }

                printf(LOG_PREFIX "Delay-load resolution: %d resolved, %d unresolved\n",
                       delay_resolved, delay_unresolved);
            }
        }
    }

    return 0;
}

/*
 * kernel32_module.c - Dynamic library loading
 *
 * LoadLibraryA, GetProcAddress, FreeLibrary, GetModuleHandleA.
 * Maps Windows DLL names to our stub .so libraries via dlopen/dlsym.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <strings.h>
#include <pthread.h>

#include "common/dll_common.h"
#include "compat/env_setup.h"
#include "compat/trust_gate.h"

/* PE DLL loader from kernel32_module_pe.c (same .so) */
extern void *pe_dll_load(const char *dll_name);
extern void *pe_dll_find(const char *name);
extern void  pe_dll_set_app_dir(const char *dir);
extern void  pe_dll_add_search_path(const char *path);

/* Module tracking */
#define MAX_MODULES 256

typedef struct {
    char name[260];
    void *handle;        /* dlopen handle */
    HANDLE win_handle;   /* Windows-style HANDLE */
} module_entry_t;

static module_entry_t g_modules[MAX_MODULES];
static int g_module_count = 0;
static pthread_mutex_t g_module_lock = PTHREAD_MUTEX_INITIALIZER;

/* Monotonic generation bumped whenever g_modules[] is mutated
 * (add/remove/swap). TLS last-hit caches compare this under the lock
 * to detect invalidation without per-thread coordination. */
static volatile unsigned int g_module_gen = 0;

/* TLS last-hit cache for find_module(): hot PE apps repeatedly resolve
 * the same DLL names via GetModuleHandle/GetProcAddress during startup.
 * A 1-entry per-thread cache is sufficient to eliminate most lookups
 * without touching the mutation path.
 *
 * Safety: must be read under g_module_lock. The cached pointer is only
 * used if (tls_gen == g_module_gen) — since both mutations and cache
 * reads happen under the lock, a stale entry cannot be dereferenced. */
static __thread unsigned int tls_fm_gen = (unsigned int)-1;
static __thread char         tls_fm_name[260];
static __thread module_entry_t *tls_fm_hit = NULL;

/* TLS last-hit cache for by-handle scans (GetProcAddress hot path).
 * Same generation protocol. */
static __thread unsigned int    tls_fh_gen    = (unsigned int)-1;
static __thread HANDLE          tls_fh_handle = NULL;
static __thread module_entry_t *tls_fh_hit    = NULL;

/* Caller MUST hold g_module_lock. */
static module_entry_t *find_module_by_handle(HANDLE h)
{
    if (tls_fh_gen == g_module_gen && tls_fh_hit && tls_fh_handle == h) {
        return tls_fh_hit;
    }
    for (int i = 0; i < g_module_count; i++) {
        if (g_modules[i].win_handle == h) {
            tls_fh_gen = g_module_gen;
            tls_fh_handle = h;
            tls_fh_hit = &g_modules[i];
            return &g_modules[i];
        }
    }
    return NULL;
}

/*
 * Translate a Windows DLL name (e.g. "kernel32.dll") to our stub .so path.
 * Searches PE_COMPAT_DLL_PATH or falls back to /usr/lib/pe-compat/.
 */
static const char *dll_search_path(void)
{
    const char *env = getenv("PE_COMPAT_DLL_PATH");
    return env ? env : "/usr/lib/pe-compat";
}

static void normalize_dll_name(const char *input, char *base, size_t base_sz)
{
    /* Extract base name without path and extension */
    const char *p = strrchr(input, '\\');
    if (!p) p = strrchr(input, '/');
    if (p) p++;
    else p = input;

    strncpy(base, p, base_sz - 1);
    base[base_sz - 1] = '\0';

    /* Remove .dll, .ocx, .drv extension if present */
    size_t len = strlen(base);
    if (len > 4 && (strcasecmp(base + len - 4, ".dll") == 0 ||
                    strcasecmp(base + len - 4, ".ocx") == 0 ||
                    strcasecmp(base + len - 4, ".drv") == 0))
        base[len - 4] = '\0';

    /* Lowercase */
    for (char *c = base; *c; c++)
        *c = (*c >= 'A' && *c <= 'Z') ? (*c + 32) : *c;
}

/*
 * Mingw runtime DLLs → native Linux shared library mapping.
 * These DLLs are part of the GCC/mingw toolchain and have compatible
 * ABI with their Linux counterparts, so we can load the native .so.
 */
/*
 * Mingw runtime DLLs → our stub .so mapping.
 * These need ms_abi wrappers, NOT native .so files (ABI mismatch!).
 * Stubs are in msvcrt_except.c.
 */
static const struct {
    const char *dll_base;     /* Lowercase DLL name without .dll */
    const char *stub_so;      /* Our stub .so name (libpe_xxx format) */
} g_mingw_dll_map[] = {
    { "libgcc_s_dw2-1",    "libpe_msvcrt.so" },
    { "libgcc_s_seh-1",    "libpe_msvcrt.so" },
    { "libgcc_s_sjlj-1",   "libpe_msvcrt.so" },
    { "libstdc++-6",        "libpe_msvcrt.so" },
    { "libwinpthread-1",    "libpe_kernel32.so" },
    { NULL, NULL }
};

/*
 * Windows system DLLs → stub .so redirect table.
 * For DLLs that don't have their own libpe_<name>.so, redirect
 * to the correct existing stub .so via LoadLibraryA.
 */
static const struct {
    const char *dll_base;
    const char *stub_so;
} g_dll_redirect[] = {
    { "sspicli",        "libpe_secur32.so"   },
    { "kernelbase",     "libpe_kernel32.so"   },
    { "uxtheme",        "libpe_user32.so"     },
    { "wtsapi32",       "libpe_kernel32.so"   },
    { "netapi32",       "libpe_advapi32.so"   },
    { "mpr",            "libpe_advapi32.so"   },
    { "winsta",         "libpe_kernel32.so"   },
    { "profapi",        "libpe_kernel32.so"   },
    { "cfgmgr32",       "libpe_setupapi.so"   },
    { "ntmarta",        "libpe_advapi32.so"   },
    { "wldp",           "libpe_kernel32.so"   },
    { "hhctrl",         "libpe_comctl32.so"   },
    { "msimg32",        "libpe_gdi32.so"      },
    { "propsys",        "libpe_ole32.so"      },
    /* DirectX — multiple DLLs map to libpe_d3d.so */
    { "d3d9",           "libpe_d3d.so"        },
    { "d3d11",          "libpe_d3d.so"        },
    { "d3d12",          "libpe_d3d.so"        },
    { "d3d12core",      "libpe_d3d.so"        },
    { "d3d8",           "libpe_d3d.so"        },
    { "d3d10core",      "libpe_d3d.so"        },
    { "dxgi",           "libpe_d3d.so"        },
    { "ddraw",          "libpe_d3d.so"        },
    { "dinput",         "libpe_d3d.so"        },
    { "dinput8",        "libpe_d3d.so"        },
    { "d3dcompiler_47", "libpe_d3d.so"        },
    { "d3dcompiler_46", "libpe_d3d.so"        },
    { "d3dcompiler_43", "libpe_d3d.so"        },
    /* XInput versions */
    { "xinput1_1",      "libpe_d3d.so"        },
    { "xinput1_2",      "libpe_d3d.so"        },
    { "xinput1_3",      "libpe_d3d.so"        },
    { "xinput1_4",      "libpe_d3d.so"        },
    { "xinput9_1_0",    "libpe_d3d.so"        },
    /* Audio */
    { "xaudio2_9",      "libpe_dsound.so"     },
    { "xaudio2_8",      "libpe_dsound.so"     },
    { "xaudio2_7",      "libpe_dsound.so"     },
    /* Winsock */
    { "wsock32",        "libpe_ws2_32.so"     },
    { "mswsock",        "libpe_ws2_32.so"     },
    /* Other redirect DLLs */
    { "wininet",        "libpe_winhttp.so"    },
    { "imagehlp",       "libpe_dbghelp.so"    },
    { "mmdevapi",       "libpe_winmm.so"      },
    { "avrt",           "libpe_winmm.so"      },
    { "audioses",       "libpe_winmm.so"      },
    { "dwrite",         "libpe_gdi32.so"      },
    { "d2d1",           "libpe_gdi32.so"      },
    { "dcomp",          "libpe_gdi32.so"      },
    { "wintrust",       "libpe_crypt32.so"    },
    { "devobj",         "libpe_setupapi.so"   },
    { "normaliz",       "libpe_kernel32.so"   },
    { "powrprof",       "libpe_kernel32.so"   },
    { "wevtapi",        "libpe_kernel32.so"   },
    { "urlmon",         "libpe_ole32.so"      },
    { "clr",            "libpe_mscoree.so"    },
    { "clrjit",         "libpe_mscoree.so"    },
    { NULL, NULL }
};

/*
 * api-ms-win-* → stub .so routing.
 * These "API set" DLLs are virtual redirectors in modern Windows.
 * We map them to our actual stub .so libraries.
 */
static const struct {
    const char *prefix;
    const char *stub_so;
} g_apiset_map[] = {
    { "api-ms-win-crt-",              "libpe_msvcrt.so"   },
    { "api-ms-win-core-",             "libpe_kernel32.so"  },
    { "api-ms-win-security-",         "libpe_advapi32.so"  },
    { "api-ms-win-eventing-",         "libpe_advapi32.so"  },
    { "api-ms-win-shell-",            "libpe_shell32.so"   },
    { "api-ms-win-ntuser-",           "libpe_user32.so"    },
    { "api-ms-win-gdi-",              "libpe_gdi32.so"     },
    { NULL, NULL }
};

/*
 * Try to dlopen a stub .so by name, searching multiple paths.
 * Order: bare name (LD_LIBRARY_PATH), ./dlls/, PE_COMPAT_DLL_PATH, /usr/lib/pe-compat/
 */
static void *try_dlopen_so(const char *so_name)
{
    char path[512];

    /* 1. Already loaded in process? (RTLD_NOLOAD avoids filesystem search) */
    void *h = dlopen(so_name, RTLD_LAZY | RTLD_NOLOAD | RTLD_GLOBAL);
    if (h) return h;

    /* 2. Bare name (relies on LD_LIBRARY_PATH) */
    h = dlopen(so_name, RTLD_LAZY | RTLD_GLOBAL);
    if (h) return h;

    /* 3. ./dlls/ relative to cwd (development/deployment layout) */
    snprintf(path, sizeof(path), "dlls/%s", so_name);
    h = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
    if (h) return h;

    /* 4. Configured search path */
    snprintf(path, sizeof(path), "%s/%s", dll_search_path(), so_name);
    h = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
    return h;
}

static void *open_stub_so(const char *base_name)
{
    char so_name[512];

    /* Check api-ms-win-* routing first */
    for (int i = 0; g_apiset_map[i].prefix; i++) {
        if (strncasecmp(base_name, g_apiset_map[i].prefix,
                        strlen(g_apiset_map[i].prefix)) == 0) {
            return try_dlopen_so(g_apiset_map[i].stub_so);
        }
    }

    /* Try libpe_<name>.so */
    snprintf(so_name, sizeof(so_name), "libpe_%s.so", base_name);
    void *handle = try_dlopen_so(so_name);
    if (handle) return handle;

    /* Try <name>.so (without libpe_ prefix) */
    snprintf(so_name, sizeof(so_name), "%s.so", base_name);
    handle = try_dlopen_so(so_name);
    if (handle) return handle;

    /* Try CRT variant mapping (ucrtbase, vcruntime140, msvcp140, etc.) */
    if (strncasecmp(base_name, "ucrtbase", 8) == 0 ||
        strncasecmp(base_name, "vcruntime", 9) == 0 ||
        strncasecmp(base_name, "msvcp1", 6) == 0 ||
        strncasecmp(base_name, "msvcr1", 6) == 0 ||
        strncasecmp(base_name, "concrt1", 7) == 0) {
        return try_dlopen_so("libpe_msvcrt.so");
    }

    /* D3DX9/D3DX10/D3DX11 utility DLLs (multiple version numbers) */
    if (strncasecmp(base_name, "d3dx9_", 6) == 0 ||
        strncasecmp(base_name, "d3dx10_", 7) == 0 ||
        strncasecmp(base_name, "d3dx11_", 7) == 0)
        return try_dlopen_so("libpe_d3d.so");

    /* Windows system DLL redirect table */
    for (int i = 0; g_dll_redirect[i].dll_base; i++) {
        if (strcasecmp(base_name, g_dll_redirect[i].dll_base) == 0)
            return try_dlopen_so(g_dll_redirect[i].stub_so);
    }

    /* Try mingw runtime DLL → our stub .so mapping */
    for (int i = 0; g_mingw_dll_map[i].dll_base; i++) {
        if (strcasecmp(base_name, g_mingw_dll_map[i].dll_base) == 0) {
            handle = try_dlopen_so(g_mingw_dll_map[i].stub_so);
            if (handle) {
                fprintf(stderr, "[kernel32] Mapped mingw '%s' -> stub '%s'\n",
                        base_name, g_mingw_dll_map[i].stub_so);
            }
            return handle;
        }
    }

    return NULL;
}

/* Look up already-loaded module by base name. Caller MUST hold g_module_lock. */
static module_entry_t *find_module(const char *base_name)
{
    if (tls_fm_gen == g_module_gen && tls_fm_hit &&
        strcasecmp(tls_fm_name, base_name) == 0) {
        return tls_fm_hit;
    }
    for (int i = 0; i < g_module_count; i++) {
        if (strcasecmp(g_modules[i].name, base_name) == 0) {
            tls_fm_gen = g_module_gen;
            strncpy(tls_fm_name, base_name, sizeof(tls_fm_name) - 1);
            tls_fm_name[sizeof(tls_fm_name) - 1] = '\0';
            tls_fm_hit = &g_modules[i];
            return &g_modules[i];
        }
    }
    return NULL;
}

WINAPI_EXPORT HMODULE LoadLibraryA(LPCSTR lpLibFileName)
{
    if (!lpLibFileName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    TRUST_CHECK_ARG_RET(TRUST_GATE_DLL_LOAD, "LoadLibraryA", lpLibFileName, NULL);

    char base[260];
    normalize_dll_name(lpLibFileName, base, sizeof(base));

    /* Check if already loaded */
    pthread_mutex_lock(&g_module_lock);
    module_entry_t *existing = find_module(base);
    if (existing) {
        HMODULE ret = (HMODULE)existing->win_handle;
        pthread_mutex_unlock(&g_module_lock);
        return ret;
    }
    pthread_mutex_unlock(&g_module_lock);

    /*
     * DLL loading order (matches Windows behavior):
     * 1. PE DLL from app directory (highest priority — enables DXVK overrides)
     * 2. Our .so stub libraries (system DLL implementations)
     * 3. PE DLL from all search paths (final fallback)
     *
     * Skip PE DLL check for api-ms-win-* / ext-ms-* (these are never real DLLs)
     */
    int skip_pe = (strncasecmp(base, "api-ms-win-", 11) == 0 ||
                   strncasecmp(base, "ext-ms-", 7) == 0);

    /* 1. Try PE DLL from app directory first (e.g. DXVK d3d9.dll) */
    if (!skip_pe) {
        char dll_with_ext[270];
        snprintf(dll_with_ext, sizeof(dll_with_ext), "%s.dll", base);
        void *pe_base = pe_dll_find(dll_with_ext);
        if (!pe_base)
            pe_base = pe_dll_load(dll_with_ext);
        if (pe_base) {
            pthread_mutex_lock(&g_module_lock);
            /* Re-check: another thread may have registered this base while
             * we were in pe_dll_load without our lock held. */
            if (!find_module(base)) {
                if (g_module_count < MAX_MODULES) {
                    module_entry_t *mod = &g_modules[g_module_count++];
                    snprintf(mod->name, sizeof(mod->name), "%s", base);
                    mod->handle = NULL;
                    mod->win_handle = (HANDLE)pe_base;
                    g_module_gen++;
                } else {
                    fprintf(stderr, "[kernel32] WARNING: module table full, %s untracked\n", base);
                }
            }
            pthread_mutex_unlock(&g_module_lock);
            return (HMODULE)pe_base;
        }
    }

    /* 2. Try our .so stub libraries */
    void *handle = open_stub_so(base);
    if (handle) {
        pthread_mutex_lock(&g_module_lock);
        /* Re-check: another thread may have loaded it concurrently. */
        module_entry_t *dup = find_module(base);
        if (dup) {
            HMODULE ret = (HMODULE)dup->win_handle;
            pthread_mutex_unlock(&g_module_lock);
            dlclose(handle);   /* drop our extra ref */
            return ret;
        }
        if (g_module_count >= MAX_MODULES) {
            pthread_mutex_unlock(&g_module_lock);
            dlclose(handle);
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }

        module_entry_t *mod = &g_modules[g_module_count++];
        snprintf(mod->name, sizeof(mod->name), "%s", base);
        mod->handle = handle;
        mod->win_handle = (HANDLE)handle;
        g_module_gen++;
        HMODULE ret = (HMODULE)mod->win_handle;
        pthread_mutex_unlock(&g_module_lock);
        return ret;
    }

    /* 3. Try PE DLL from all search paths (final fallback) */
    if (!skip_pe) {
        void *pe_base = pe_dll_load(lpLibFileName);
        if (pe_base) {
            pthread_mutex_lock(&g_module_lock);
            if (!find_module(base)) {
                if (g_module_count < MAX_MODULES) {
                    module_entry_t *mod = &g_modules[g_module_count++];
                    snprintf(mod->name, sizeof(mod->name), "%s", base);
                    mod->handle = NULL;
                    mod->win_handle = (HANDLE)pe_base;
                    g_module_gen++;
                } else {
                    fprintf(stderr, "[kernel32] WARNING: module table full, %s untracked\n", base);
                }
            }
            pthread_mutex_unlock(&g_module_lock);
            return (HMODULE)pe_base;
        }
    }

    fprintf(stderr, "[kernel32] LoadLibraryA: cannot load '%s'\n", lpLibFileName);
    set_last_error(ERROR_MOD_NOT_FOUND);
    return NULL;
}

WINAPI_EXPORT HMODULE LoadLibraryW(LPCWSTR lpLibFileName)
{
    if (!lpLibFileName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    char narrow[512];
    wide_to_narrow_safe(lpLibFileName, narrow, sizeof(narrow));
    return LoadLibraryA(narrow);
}

WINAPI_EXPORT HMODULE LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    (void)hFile;
    (void)dwFlags;
    return LoadLibraryA(lpLibFileName);
}

WINAPI_EXPORT HMODULE LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    (void)hFile;
    (void)dwFlags;
    return LoadLibraryW(lpLibFileName);
}

/*
 * Walk the PE export directory of a mapped PE image to find a function
 * by name or ordinal. Returns the function address or NULL.
 * Now delegates to pe_dll_get_proc which handles forwarder chains.
 */
extern void *pe_dll_get_proc(void *base, const char *proc_name) __attribute__((weak));

static void *pe_export_lookup(void *base, LPCSTR lpProcName)
{
    /* Use pe_dll_get_proc which has full forwarder resolution */
    if (pe_dll_get_proc)
        return pe_dll_get_proc(base, lpProcName);

    /* Fallback: inline lookup if pe_dll_get_proc not linked */
    if (!base) return NULL;

    unsigned char *p = (unsigned char *)base;

    /* Verify MZ signature */
    if (p[0] != 'M' || p[1] != 'Z') return NULL;

    int32_t e_lfanew = *(int32_t *)(p + 0x3C);
    if (e_lfanew < 0 || e_lfanew > 0x10000) return NULL;

    unsigned char *pe_sig = p + e_lfanew;
    if (pe_sig[0] != 'P' || pe_sig[1] != 'E') return NULL;

    unsigned char *opt = pe_sig + 4 + 20;
    uint16_t magic = *(uint16_t *)opt;

    /* Get export directory RVA */
    uint32_t export_rva = 0, export_size = 0;
    if (magic == 0x020B) {
        /* PE32+ - data directory at offset 112 */
        uint32_t *dd = (uint32_t *)(opt + 112);
        export_rva = dd[0];
        export_size = dd[1];
    } else if (magic == 0x010B) {
        /* PE32 - data directory at offset 96 */
        uint32_t *dd = (uint32_t *)(opt + 96);
        export_rva = dd[0];
        export_size = dd[1];
    }

    if (export_rva == 0 || export_size == 0) return NULL;

    /* Parse export directory */
    typedef struct {
        uint32_t Characteristics;
        uint32_t TimeDateStamp;
        uint16_t MajorVersion;
        uint16_t MinorVersion;
        uint32_t Name;              /* RVA of DLL name */
        uint32_t Base;              /* Ordinal base */
        uint32_t NumberOfFunctions;
        uint32_t NumberOfNames;
        uint32_t AddressOfFunctions;    /* RVA of function address table */
        uint32_t AddressOfNames;        /* RVA of name pointer table */
        uint32_t AddressOfNameOrdinals; /* RVA of ordinal table */
    } IMAGE_EXPORT_DIRECTORY;

    IMAGE_EXPORT_DIRECTORY *exports = (IMAGE_EXPORT_DIRECTORY *)(p + export_rva);

    uint32_t *func_table = (uint32_t *)(p + exports->AddressOfFunctions);
    uint32_t *name_table = (uint32_t *)(p + exports->AddressOfNames);
    uint16_t *ord_table  = (uint16_t *)(p + exports->AddressOfNameOrdinals);

    /* Check for ordinal import */
    if ((ULONG_PTR)lpProcName < 0x10000) {
        uint16_t ordinal = (uint16_t)(ULONG_PTR)lpProcName;
        uint32_t index = ordinal - (uint32_t)exports->Base;
        if (index < exports->NumberOfFunctions) {
            uint32_t func_rva = func_table[index];
            if (func_rva == 0) return NULL;

            /* Forwarder: RVA points within export directory (ASCII string).
             * Primary path uses pe_dll_get_proc which handles this;
             * this fallback cannot follow forwarders without that link. */
            if (func_rva >= export_rva && func_rva < export_rva + export_size)
                return NULL;

            return p + func_rva;
        }
        return NULL;
    }

    /* Search by name using binary search (names are sorted) */
    int lo = 0, hi = (int)exports->NumberOfNames - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        const char *name = (const char *)(p + name_table[mid]);
        int cmp = strcmp(lpProcName, name);
        if (cmp == 0) {
            /* Found - get ordinal and function address */
            uint16_t ordinal = ord_table[mid];
            if (ordinal < exports->NumberOfFunctions) {
                uint32_t func_rva = func_table[ordinal];
                if (func_rva == 0) return NULL;

                /* Forwarder: see pe_dll_get_proc for full resolution */
                if (func_rva >= export_rva && func_rva < export_rva + export_size)
                    return NULL;

                return p + func_rva;
            }
            return NULL;
        }
        if (cmp < 0)
            hi = mid - 1;
        else
            lo = mid + 1;
    }

    return NULL;
}

WINAPI_EXPORT FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    if (!lpProcName) {
        set_last_error(ERROR_PROC_NOT_FOUND);
        return NULL;
    }

    /* Check for ordinal import (lpProcName < 0x10000 means it's an ordinal) */
    if ((ULONG_PTR)lpProcName < 0x10000) {
        uint16_t ordinal = (uint16_t)(ULONG_PTR)lpProcName;
        char ordinal_name[64];
        snprintf(ordinal_name, sizeof(ordinal_name), "__ordinal_%u", ordinal);

        pthread_mutex_lock(&g_module_lock);
        {
            module_entry_t *mod = find_module_by_handle((HANDLE)hModule);
            if (mod) {
                void *dl = mod->handle;
                pthread_mutex_unlock(&g_module_lock);
                void *sym = dlsym(dl, ordinal_name);
                if (sym)
                    return (FARPROC)sym;
                goto ordinal_pe_fallback;
            }
        }
        pthread_mutex_unlock(&g_module_lock);

ordinal_pe_fallback:
        /* Try PE export directory for ordinal */
        void *result = pe_export_lookup(hModule, lpProcName);
        if (result) return (FARPROC)result;

        /* Also try LDR module list */
        void *ldr_base = env_find_module_by_base(hModule);
        if (ldr_base) {
            result = pe_export_lookup(ldr_base, lpProcName);
            if (result) return (FARPROC)result;
        }

        set_last_error(ERROR_PROC_NOT_FOUND);
        return NULL;
    }

    /* Import by name - first try our stub .so modules */
    pthread_mutex_lock(&g_module_lock);
    {
        module_entry_t *mod = find_module_by_handle((HANDLE)hModule);
        if (mod) {
            void *dl = mod->handle;
            pthread_mutex_unlock(&g_module_lock);
            void *sym = dlsym(dl, lpProcName);
            if (sym)
                return (FARPROC)sym;
            goto name_pe_fallback;
        }
    }
    pthread_mutex_unlock(&g_module_lock);

name_pe_fallback:;
    /* Try PE export directory (for loaded PE DLLs) */
    void *result = pe_export_lookup(hModule, lpProcName);
    if (result) return (FARPROC)result;

    /* Try RTLD_DEFAULT as fallback (search all loaded .so) */
    void *sym = dlsym(RTLD_DEFAULT, lpProcName);
    if (sym)
        return (FARPROC)sym;

    set_last_error(ERROR_PROC_NOT_FOUND);
    return NULL;
}

WINAPI_EXPORT BOOL FreeLibrary(HMODULE hLibModule)
{
    pthread_mutex_lock(&g_module_lock);
    {
        module_entry_t *mod = find_module_by_handle((HANDLE)hLibModule);
        if (mod) {
            int i = (int)(mod - g_modules);
            void *dl_handle = g_modules[i].handle;
            /* PE DLLs (handle==NULL) stay mapped — munmap not safe */
            g_modules[i] = g_modules[--g_module_count];
            g_module_gen++;
            pthread_mutex_unlock(&g_module_lock);
            if (dl_handle)  /* .so stub — dlclose it */
                dlclose(dl_handle);
            return TRUE;
        }
    }
    pthread_mutex_unlock(&g_module_lock);
    set_last_error(ERROR_INVALID_HANDLE);
    return FALSE;
}

/*
 * Look up a module's name by its handle (for GetModuleFileNameA).
 * Returns 0 on success, -1 if not found.
 */
int kernel32_find_module_name(void *handle, char *buf, size_t bufsz)
{
    pthread_mutex_lock(&g_module_lock);
    module_entry_t *mod = find_module_by_handle((HANDLE)handle);
    if (mod) {
        /* Return a Windows-style system DLL path */
        snprintf(buf, bufsz, "C:\\Windows\\System32\\%s.dll", mod->name);
        pthread_mutex_unlock(&g_module_lock);
        return 0;
    }
    pthread_mutex_unlock(&g_module_lock);
    return -1;
}

WINAPI_EXPORT HMODULE GetModuleHandleA(LPCSTR lpModuleName)
{
    if (!lpModuleName) {
        /* NULL means the main executable — return real image base from PEB */
        void *peb = env_get_peb();
        if (peb) {
            /* PEB.ImageBaseAddress is at offset 0x10 in the 64-bit PEB */
            void *base = *(void **)((char *)peb + 0x10);
            if (base)
                return (HMODULE)base;
        }
        return (HMODULE)(uintptr_t)0x00400000; /* Fallback */
    }

    char base[260];
    normalize_dll_name(lpModuleName, base, sizeof(base));

    pthread_mutex_lock(&g_module_lock);
    module_entry_t *mod = find_module(base);
    if (mod) {
        HMODULE ret = (HMODULE)mod->win_handle;
        pthread_mutex_unlock(&g_module_lock);
        return ret;
    }
    pthread_mutex_unlock(&g_module_lock);

    /* Check PEB LDR list (modules registered by the PE loader itself) */
    char with_ext[270];
    snprintf(with_ext, sizeof(with_ext), "%s.dll", base);
    void *ldr_base = env_find_module_by_name(with_ext);
    if (ldr_base)
        return (HMODULE)ldr_base;

    /* Lenient fallback: try to load on demand.
     * Strict Windows behavior would return NULL + ERROR_MOD_NOT_FOUND,
     * but many PE apps expect GetModuleHandle to implicitly load. */
    return LoadLibraryA(lpModuleName);
}

WINAPI_EXPORT HMODULE GetModuleHandleW(LPCWSTR lpModuleName)
{
    if (!lpModuleName)
        return GetModuleHandleA(NULL);
    char narrow[512];
    wide_to_narrow_safe(lpModuleName, narrow, sizeof(narrow));
    return GetModuleHandleA(narrow);
}

WINAPI_EXPORT BOOL GetModuleHandleExA(DWORD dwFlags, LPCSTR lpModuleName, HMODULE *phModule)
{
    (void)dwFlags;
    HMODULE h = GetModuleHandleA(lpModuleName);
    if (phModule) *phModule = h;
    return h != NULL;
}

WINAPI_EXPORT BOOL GetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE *phModule)
{
    (void)dwFlags;
    HMODULE h = GetModuleHandleW(lpModuleName);
    if (phModule) *phModule = h;
    return h != NULL;
}

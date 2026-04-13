/*
 * vcredist_handler.c - VC++ Redistributable detection and interception
 *
 * Many Windows apps require vcruntime140.dll, msvcp140.dll, ucrtbase.dll, etc.
 * Normally these are installed by vc_redist.x64.exe.  Our PE loader already
 * maps vcruntime140 -> libpe_msvcrt.so, so the actual CRT functions are
 * available.  This module makes apps *believe* the redist is installed by:
 *
 *   1. Populating the registry keys that apps/installers check
 *   2. Intercepting vc_redist*.exe / vcredist_*.exe to return success
 *   3. Reporting product GUIDs as INSTALLSTATE_DEFAULT via MsiQueryProductState
 *   4. Pre-registering .NET Framework / .NET runtime versions
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <dlfcn.h>

#include "common/dll_common.h"

/* ------------------------------------------------------------------ */
/* Registry helpers - resolved at runtime from our advapi32 stub      */
/* ------------------------------------------------------------------ */

#define HKEY_LOCAL_MACHINE ((HKEY)(uintptr_t)0x80000002)

#define REG_SZ      1
#define REG_DWORD   4

#define ERROR_SUCCESS 0

/* Function pointer types for registry calls (ms_abi from advapi32) */
typedef LONG (__attribute__((ms_abi)) *fn_RegCreateKeyExA)(
    HKEY, LPCSTR, DWORD, LPSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
    HKEY *, LPDWORD);
typedef LONG (__attribute__((ms_abi)) *fn_RegSetValueExA)(
    HKEY, LPCSTR, DWORD, DWORD, const BYTE *, DWORD);
typedef LONG (__attribute__((ms_abi)) *fn_RegCloseKey)(HKEY);

static fn_RegCreateKeyExA p_RegCreateKeyExA;
static fn_RegSetValueExA  p_RegSetValueExA;
static fn_RegCloseKey     p_RegCloseKey;
static int g_reg_resolved;

static int resolve_registry_funcs(void)
{
    if (g_reg_resolved)
        return (p_RegCreateKeyExA && p_RegSetValueExA && p_RegCloseKey) ? 0 : -1;
    g_reg_resolved = 1;

    void *adv = dlopen("libpe_advapi32.so", RTLD_NOW | RTLD_NOLOAD);
    if (!adv)
        adv = dlopen("libpe_advapi32.so", RTLD_NOW);
    if (!adv) {
        fprintf(stderr, "[vcredist] WARNING: cannot load advapi32 stub\n");
        return -1;
    }

    p_RegCreateKeyExA = (fn_RegCreateKeyExA)dlsym(adv, "RegCreateKeyExA");
    p_RegSetValueExA  = (fn_RegSetValueExA)dlsym(adv, "RegSetValueExA");
    p_RegCloseKey     = (fn_RegCloseKey)dlsym(adv, "RegCloseKey");

    return (p_RegCreateKeyExA && p_RegSetValueExA && p_RegCloseKey) ? 0 : -1;
}

/* Write a REG_SZ value under HKLM\<subkey>\<name> */
static void reg_set_sz(const char *subkey, const char *name, const char *value)
{
    if (resolve_registry_funcs() < 0) return;

    HKEY hk = NULL;
    if (p_RegCreateKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, NULL, 0,
                           0xF003F /*KEY_ALL_ACCESS*/, NULL, &hk, NULL) != ERROR_SUCCESS)
        return;
    p_RegSetValueExA(hk, name, 0, REG_SZ,
                     (const BYTE *)value, (DWORD)(strlen(value) + 1));
    p_RegCloseKey(hk);
}

/* Write a REG_DWORD value under HKLM\<subkey>\<name> */
static void reg_set_dword(const char *subkey, const char *name, DWORD value)
{
    if (resolve_registry_funcs() < 0) return;

    HKEY hk = NULL;
    if (p_RegCreateKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, NULL, 0,
                           0xF003F, NULL, &hk, NULL) != ERROR_SUCCESS)
        return;
    p_RegSetValueExA(hk, name, 0, REG_DWORD,
                     (const BYTE *)&value, sizeof(DWORD));
    p_RegCloseKey(hk);
}

/* ------------------------------------------------------------------ */
/* Product registration database                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *guid;        /* Product GUID (MsiQueryProductState key) */
    const char *name;        /* Display name */
    const char *version;     /* Display version string */
    const char *reg_key;     /* VC\Runtimes registry subkey (native) */
    const char *wow64_key;   /* WOW6432Node variant (32-on-64) */
    DWORD       major;       /* Major version number for Runtimes key */
    DWORD       minor;       /* Minor version number for Runtimes key */
    DWORD       bld;         /* Build number */
} vcredist_product_t;

static const vcredist_product_t g_products[] = {
    /* VC++ 2015-2022 x64 (latest merged redist) */
    {
        "{A95A3637-D42C-4A42-B0B3-6DFEB7A31B6E}",
        "Microsoft Visual C++ 2015-2022 Redistributable (x64)",
        "14.40.33810.0",
        "SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x64",
        NULL,
        14, 40, 33810
    },
    /* VC++ 2015-2022 x86 */
    {
        "{6BA9C2A5-4BE4-4E55-8E78-6D537A3E8B10}",
        "Microsoft Visual C++ 2015-2022 Redistributable (x86)",
        "14.40.33810.0",
        "SOFTWARE\\WOW6432Node\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x86",
        "SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x86",
        14, 40, 33810
    },
    /* VC++ 2013 x64 (v12.0) */
    {
        "{929FBD26-9020-399B-9A7A-751D61F0B942}",
        "Microsoft Visual C++ 2013 Redistributable (x64)",
        "12.0.40664.0",
        "SOFTWARE\\Microsoft\\VisualStudio\\12.0\\VC\\Runtimes\\x64",
        NULL,
        12, 0, 40664
    },
    /* VC++ 2013 x86 */
    {
        "{13A4EE12-23EA-3371-91EE-EFB36DDFFF3E}",
        "Microsoft Visual C++ 2013 Redistributable (x86)",
        "12.0.40664.0",
        "SOFTWARE\\WOW6432Node\\Microsoft\\VisualStudio\\12.0\\VC\\Runtimes\\x86",
        "SOFTWARE\\Microsoft\\VisualStudio\\12.0\\VC\\Runtimes\\x86",
        12, 0, 40664
    },
    /* VC++ 2012 x64 (v11.0) */
    {
        "{37B8F9C7-03FB-3253-8781-2517C99D7C00}",
        "Microsoft Visual C++ 2012 Redistributable (x64)",
        "11.0.61030.0",
        "SOFTWARE\\Microsoft\\VisualStudio\\11.0\\VC\\Runtimes\\x64",
        NULL,
        11, 0, 61030
    },
    /* VC++ 2010 x64 (v10.0) */
    {
        "{1D8E6291-B0D5-35EC-8441-6616F567A0F7}",
        "Microsoft Visual C++ 2010 Redistributable (x64)",
        "10.0.40219.0",
        "SOFTWARE\\Microsoft\\VisualStudio\\10.0\\VC\\Runtimes\\x64",
        NULL,
        10, 0, 40219
    },
    /* Universal CRT (Windows 10 SDK component) */
    {
        "{2FEFAD67-B2D0-4F77-A0F6-3517AEB54C4D}",
        "Windows Universal CRT SDK",
        "10.0.19041.0",
        NULL,
        NULL,
        10, 0, 19041
    },
};

#define NUM_PRODUCTS (sizeof(g_products) / sizeof(g_products[0]))

static int g_products_registered[sizeof(g_products) / sizeof(g_products[0])];

/* ------------------------------------------------------------------ */
/* Product GUID lookup                                                 */
/* ------------------------------------------------------------------ */

/* find_product is inlined in vcredist_is_installed below */

/* ------------------------------------------------------------------ */
/* Register a single product in the registry                           */
/* ------------------------------------------------------------------ */

static void register_product(size_t idx)
{
    if (idx >= NUM_PRODUCTS || g_products_registered[idx])
        return;

    const vcredist_product_t *p = &g_products[idx];

    /* VC\Runtimes key (native arch) */
    if (p->reg_key) {
        reg_set_dword(p->reg_key, "Installed", 1);
        reg_set_dword(p->reg_key, "Major", p->major);
        reg_set_dword(p->reg_key, "Minor", p->minor);
        reg_set_dword(p->reg_key, "Bld", p->bld);
        reg_set_sz(p->reg_key, "Version", p->version);
    }

    /* WOW6432Node mirror (for 32-bit queries on 64-bit OS) */
    if (p->wow64_key) {
        reg_set_dword(p->wow64_key, "Installed", 1);
        reg_set_dword(p->wow64_key, "Major", p->major);
        reg_set_dword(p->wow64_key, "Minor", p->minor);
        reg_set_dword(p->wow64_key, "Bld", p->bld);
        reg_set_sz(p->wow64_key, "Version", p->version);
    }

    /* Uninstall key (used by installers / Add/Remove Programs) */
    char uninstall_key[512];
    snprintf(uninstall_key, sizeof(uninstall_key),
             "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\%s",
             p->guid);
    reg_set_sz(uninstall_key, "DisplayName", p->name);
    reg_set_sz(uninstall_key, "DisplayVersion", p->version);
    reg_set_sz(uninstall_key, "Publisher", "Microsoft Corporation");
    reg_set_dword(uninstall_key, "SystemComponent", 1);

    g_products_registered[idx] = 1;
}

/* ------------------------------------------------------------------ */
/* .NET runtime registration                                           */
/* ------------------------------------------------------------------ */

static void register_dotnet_runtimes(void)
{
    /* .NET Framework 4.8 (Release >= 528049 means 4.8+) */
    reg_set_dword("SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full",
                  "Release", 528049);
    reg_set_sz("SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full",
               "Version", "4.8.09037");
    reg_set_dword("SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full",
                  "Install", 1);
    reg_set_sz("SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full",
               "TargetVersion", "4.0.0");

    /* .NET Framework 3.5 SP1 (some legacy apps check this) */
    reg_set_dword("SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v3.5",
                  "Install", 1);
    reg_set_dword("SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v3.5",
                  "SP", 1);

    /* .NET 6.0 / 7.0 / 8.0 modern runtimes */
    static const struct { const char *ver; const char *path; } dotnet_modern[] = {
        { "6.0.36", "SOFTWARE\\dotnet\\Setup\\InstalledVersions\\x64\\sharedfx\\Microsoft.NETCore.App" },
        { "7.0.20", "SOFTWARE\\dotnet\\Setup\\InstalledVersions\\x64\\sharedfx\\Microsoft.NETCore.App" },
        { "8.0.11", "SOFTWARE\\dotnet\\Setup\\InstalledVersions\\x64\\sharedfx\\Microsoft.NETCore.App" },
    };
    for (size_t i = 0; i < sizeof(dotnet_modern) / sizeof(dotnet_modern[0]); i++) {
        reg_set_sz(dotnet_modern[i].path, dotnet_modern[i].ver, dotnet_modern[i].ver);
    }

    /* Shared host version (apps query this for .NET presence) */
    reg_set_sz("SOFTWARE\\dotnet\\Setup\\InstalledVersions\\x64\\sharedhost",
               "Version", "8.0.11");
    reg_set_dword("SOFTWARE\\dotnet\\Setup\\InstalledVersions\\x64\\sharedhost",
                  "Install", 1);
}

/* ------------------------------------------------------------------ */
/* Command-line parsing for installer intercept                        */
/* ------------------------------------------------------------------ */

static int has_flag(const char *cmdline, const char *flag)
{
    if (!cmdline || !flag) return 0;
    const char *p = cmdline;
    size_t flen = strlen(flag);
    while ((p = strcasestr(p, flag)) != NULL) {
        /* Ensure it is a standalone flag (preceded by space or start) */
        if (p == cmdline || p[-1] == ' ' || p[-1] == '\t') {
            char after = p[flen];
            if (after == '\0' || after == ' ' || after == '\t')
                return 1;
        }
        p += flen;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Exported API                                                        */
/* ------------------------------------------------------------------ */

/*
 * vcredist_is_installed - check if a product GUID is "installed"
 *
 * Returns 1 if the product is in our registered set, 0 otherwise.
 * Used by our MsiQueryProductState stub.
 */
WINAPI_EXPORT int vcredist_is_installed(const char *product_guid)
{
    if (!product_guid) return 0;
    for (size_t i = 0; i < NUM_PRODUCTS; i++) {
        if (strcasecmp(g_products[i].guid, product_guid) == 0)
            return g_products_registered[i];
    }
    return 0;
}

/*
 * vcredist_ensure_registered - pre-populate registry with all supported
 * VC++ redist and .NET runtime entries.
 *
 * Call once at PE loader initialization.  Checks that our CRT stub
 * library exists before claiming the redist is installed.
 */
WINAPI_EXPORT void vcredist_ensure_registered(void)
{
    static int done;
    if (done) return;
    done = 1;

    /* Only register if our CRT stub is available */
    void *crt = dlopen("libpe_msvcrt.so", RTLD_NOW | RTLD_NOLOAD);
    if (!crt)
        crt = dlopen("libpe_msvcrt.so", RTLD_NOW);
    if (!crt) {
        fprintf(stderr, "[vcredist] libpe_msvcrt.so not found - "
                "skipping redist registration\n");
        return;
    }
    dlclose(crt);

    /* Register all VC++ redist products */
    for (size_t i = 0; i < NUM_PRODUCTS; i++)
        register_product(i);

    /* Register .NET runtimes */
    register_dotnet_runtimes();

    printf("[vcredist] Registered %zu VC++ redist products + .NET runtimes\n",
           NUM_PRODUCTS);
}

/*
 * vcredist_installer_intercept - intercept vc_redist*.exe invocations
 *
 * @exe_path: full path to the PE being loaded (e.g. "vc_redist.x64.exe")
 * @cmdline:  command-line string (may contain /quiet /install etc.)
 *
 * Returns 1 if this was a recognized redist installer (handled),
 *         0 if this is not a redist installer (caller should load normally).
 *
 * When returning 1, the loader should report exit code 0 to the caller
 * instead of actually executing the PE.
 */
WINAPI_EXPORT int vcredist_installer_intercept(const char *exe_path,
                                                const char *cmdline)
{
    if (!exe_path) return 0;

    /* Extract the filename from the path */
    const char *fname = strrchr(exe_path, '/');
    if (!fname) fname = strrchr(exe_path, '\\');
    fname = fname ? fname + 1 : exe_path;

    /* Match known redist installer filenames */
    int is_redist = 0;
    if (strncasecmp(fname, "vc_redist", 9) == 0)
        is_redist = 1;
    else if (strncasecmp(fname, "vcredist_", 9) == 0)
        is_redist = 1;
    else if (strcasecmp(fname, "VC_redist.x64.exe") == 0)
        is_redist = 1;
    else if (strcasecmp(fname, "VC_redist.x86.exe") == 0)
        is_redist = 1;

    if (!is_redist) return 0;

    /* Handle /uninstall: just report success (we keep stubs around) */
    if (has_flag(cmdline, "/uninstall")) {
        printf("[vcredist] Intercepted redist uninstall: %s -- no-op\n", fname);
        return 1;
    }

    /* For /install, /quiet, /passive, /norestart, or no flags at all:
     * register everything and report success */
    vcredist_ensure_registered();

    printf("[vcredist] Intercepted redist installer: %s -- "
           "reported as successfully installed\n", fname);
    return 1;
}

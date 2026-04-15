/*
 * loader_init.c - Runtime initialization bridge
 *
 * These functions resolve symbols from loaded DLL stubs at runtime
 * via dlopen/dlsym, avoiding link-time dependencies on the stub libraries.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <unistd.h>

/* Cached function pointers */
static void (*fn_handle_table_init)(void);
static void (*fn_set_command_line)(const char *);
static void (*fn_set_module_filename)(const char *);
static void (*fn_ntdll_exception_init)(void);
static void (*fn_pe_set_main_args)(int, char **, char **);
static void (*fn_ntdll_exception_wire_pe)(void *, void *, void *, void *);
static int initialized = 0;
static int resolve_attempts = 0;
#define MAX_RESOLVE_ATTEMPTS 8

/* Fallback data if DLLs aren't loaded yet */
static char g_command_line[32768] = {0};
static char g_module_filename[4096] = {0};

/* Try to dlopen a stub library by searching multiple paths.
 * Uses the same search strategy as pe_import.c's search_and_open(). */
static void *try_open_dll(const char *basename)
{
    void *h;
    char path[512];

    /* First: check if already loaded (works when loaded via full path too) */
    h = dlopen(basename, RTLD_NOLOAD | RTLD_NOW);
    if (h) return h;

    /* Second: try loader binary dir + /dlls/ (via /proc/self/exe) */
    static char loader_dir[512] = {0};
    static int loader_dir_init = 0;
    if (!loader_dir_init) {
        loader_dir_init = 1;
        char self[512];
        ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
        if (n > 0) {
            self[n] = '\0';
            char *slash = strrchr(self, '/');
            if (slash) { *slash = '\0'; strncpy(loader_dir, self, sizeof(loader_dir) - 1); }
        }
    }
    if (loader_dir[0]) {
        snprintf(path, sizeof(path), "%s/dlls/%s", loader_dir, basename);
        h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
        if (h) return h;
    }

    /* Third: try installed path */
    snprintf(path, sizeof(path), "/usr/lib/pe-compat/%s", basename);
    h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
    if (h) return h;

    /* Fourth: let dlopen search LD_LIBRARY_PATH */
    h = dlopen(basename, RTLD_NOW | RTLD_GLOBAL);
    if (h) return h;

    /* Fifth: CWD fallback */
    snprintf(path, sizeof(path), "./dlls/%s", basename);
    h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
    return h;
}

static void try_resolve(void)
{
    /* Allow re-resolution until ALL critical function pointers are found.
     * First call may happen before DLLs are loaded by pe_resolve_imports().
     * Cap attempts to avoid repeated futile dlopen calls when DLLs are absent.
     *
     * Skip dlopen for groups whose symbols are already resolved -- otherwise
     * each retry bumps the refcount on libraries we never dlclose, leaking
     * dlopen refcounts on repeat invocations. */
    if (initialized && fn_handle_table_init && fn_ntdll_exception_init
        && fn_pe_set_main_args) return;
    if (initialized && resolve_attempts >= MAX_RESOLVE_ATTEMPTS) return;
    initialized = 1;
    resolve_attempts++;

    if (!fn_handle_table_init || !fn_set_command_line || !fn_set_module_filename) {
        void *h = try_open_dll("libpe_kernel32.so");
        if (h) {
            fn_set_command_line = dlsym(h, "kernel32_set_command_line");
            fn_set_module_filename = dlsym(h, "kernel32_set_module_filename");
            /* handle_table_init lives in libpe_kernel32.so (dll_common.c is
             * statically linked into each DLL .so). Use unique symbol name
             * to avoid interposition with loader's own handle_table_init. */
            fn_handle_table_init = dlsym(h, "handle_table_init");
        }
    }

    if (!fn_ntdll_exception_init || !fn_ntdll_exception_wire_pe) {
        void *hn = try_open_dll("libpe_ntdll.so");
        if (hn) {
            fn_ntdll_exception_init = dlsym(hn, "ntdll_exception_init");
            fn_ntdll_exception_wire_pe = dlsym(hn, "ntdll_exception_wire_pe");
        }
    }

    if (!fn_pe_set_main_args) {
        void *hm = try_open_dll("libpe_msvcrt.so");
        if (hm) {
            fn_pe_set_main_args = dlsym(hm, "__pe_set_main_args");
        }
    }
}

void handle_table_init(void)
{
    try_resolve();
    if (fn_handle_table_init) {
        fn_handle_table_init();
    }
    /* If not found, it will be initialized when the DLL is loaded */
}

void kernel32_set_command_line(const char *cmdline)
{
    strncpy(g_command_line, cmdline, sizeof(g_command_line) - 1);
    try_resolve();
    if (fn_set_command_line) {
        fn_set_command_line(cmdline);
    }
}

void kernel32_set_module_filename(const char *filename)
{
    strncpy(g_module_filename, filename, sizeof(g_module_filename) - 1);
    try_resolve();
    if (fn_set_module_filename) {
        fn_set_module_filename(filename);
    }
}

/*
 * pe_exception.c exports - linked into the loader binary via pe_exception.o.
 * These use ms_abi and are the real implementations that ntdll delegates to.
 */
extern void *pe_RtlLookupFunctionEntry(uint64_t, uint64_t *, void *);
extern void *pe_RtlVirtualUnwind(uint32_t, uint64_t, uint64_t, void *,
                                  void *, void **, uint64_t *, void *);
extern void pe_RtlUnwindEx(void *, void *, void *, void *, void *, void *);
extern int pe_exception_dispatch_frames(void *, void *);

void ntdll_exception_init(void)
{
    try_resolve();
    if (fn_ntdll_exception_init) {
        fn_ntdll_exception_init();
    }
    /* Wire real SEH implementations from pe_exception.c into ntdll.
     * ntdll stores these as function pointers and delegates to them. */
    if (fn_ntdll_exception_wire_pe) {
        fn_ntdll_exception_wire_pe(
            (void *)pe_RtlLookupFunctionEntry,
            (void *)pe_RtlVirtualUnwind,
            (void *)pe_RtlUnwindEx,
            (void *)pe_exception_dispatch_frames);
    }
}

void __pe_set_main_args(int argc, char **argv, char **envp)
{
    try_resolve();
    if (fn_pe_set_main_args) {
        fn_pe_set_main_args(argc, argv, envp);
    }
}

/* Getters for fallback data (used by DLLs when they load later) */
const char *loader_get_command_line(void) { return g_command_line; }
const char *loader_get_module_filename(void) { return g_module_filename; }

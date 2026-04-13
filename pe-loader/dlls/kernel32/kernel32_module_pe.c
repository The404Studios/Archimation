/*
 * kernel32_module_pe.c - Load actual PE .dll files from disk
 *
 * When a .so stub is not found, this module parses/maps/relocates
 * actual PE DLL files and calls DllMain(DLL_PROCESS_ATTACH).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <pthread.h>
#include <strings.h>  /* strcasecmp */

#include "common/dll_common.h"
#include "compat/env_setup.h"
#include "compat/abi_bridge.h"
#include "eventbus/pe_event.h"

#define LOG_PREFIX "[pe_dll] "

/* PE header constants */
#define IMAGE_DOS_SIGNATURE     0x5A4D
#define IMAGE_NT_SIGNATURE      0x00004550
#define IMAGE_FILE_DLL          0x2000
#define IMAGE_DIRECTORY_ENTRY_EXPORT  0
#define IMAGE_DIRECTORY_ENTRY_IMPORT  1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5

/* DLL_PROCESS_ATTACH etc */
#define DLL_PROCESS_DETACH      0
#define DLL_PROCESS_ATTACH      1
#define DLL_THREAD_ATTACH       2
#define DLL_THREAD_DETACH       3

/* Loaded PE DLL tracking */
#define MAX_PE_DLLS 128

typedef struct {
    char name[260];
    void *base;
    uint32_t size;
    void *entry_point;
    int loaded;
    /* Export directory cache */
    uint32_t export_rva;
    uint32_t export_size;
} pe_dll_entry_t;

static pe_dll_entry_t g_pe_dlls[MAX_PE_DLLS];
static int g_pe_dll_count = 0;
static pthread_mutex_t g_pe_dll_lock = PTHREAD_MUTEX_INITIALIZER;

/* Forward declarations */
static int pe_dll_resolve_imports(void *base, uint32_t size_of_image);
void *pe_dll_get_proc(void *base, const char *proc_name);
static void *pe_dll_get_proc_depth(void *base, const char *proc_name, int fwd_depth);
static void *pe_dll_resolve_forwarder(const char *fwd_string, int depth);
void *pe_dll_find(const char *name);

/* DLL search paths */
static char g_app_dir[4096] = ".";
static char g_dll_search_paths[8][4096];
static int g_dll_search_path_count = 0;

void pe_dll_set_app_dir(const char *dir)
{
    if (dir) strncpy(g_app_dir, dir, sizeof(g_app_dir) - 1);
}

void pe_dll_add_search_path(const char *path)
{
    if (g_dll_search_path_count < 8 && path) {
        strncpy(g_dll_search_paths[g_dll_search_path_count], path,
                sizeof(g_dll_search_paths[0]) - 1);
        g_dll_search_path_count++;
    }
}

/* Try to find a DLL file on disk */
static int find_dll_file(const char *name, char *result, size_t result_size)
{
    struct stat st;
    char path[4096];

    /* 1. App directory */
    snprintf(path, sizeof(path), "%s/%s", g_app_dir, name);
    if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
        strncpy(result, path, result_size - 1);
        return 0;
    }

    /* 2. PE_COMPAT_DLL_PATH env var */
    const char *env_path = getenv("PE_COMPAT_DLL_PATH");
    if (env_path) {
        char *paths = strdup(env_path);
        if (!paths) return -1;
        char *tok = strtok(paths, ":");
        while (tok) {
            snprintf(path, sizeof(path), "%s/%s", tok, name);
            if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
                strncpy(result, path, result_size - 1);
                free(paths);
                return 0;
            }
            tok = strtok(NULL, ":");
        }
        free(paths);
    }

    /* 3. Custom search paths */
    for (int i = 0; i < g_dll_search_path_count; i++) {
        snprintf(path, sizeof(path), "%s/%s", g_dll_search_paths[i], name);
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            strncpy(result, path, result_size - 1);
            return 0;
        }
    }

    /* 4. ~/.pe-compat/drives/c/windows/system32 */
    const char *home = getenv("HOME");
    if (home) {
        snprintf(path, sizeof(path), "%s/.pe-compat/drives/c/windows/system32/%s", home, name);
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            strncpy(result, path, result_size - 1);
            return 0;
        }
    }

    /* 5. CWD */
    snprintf(path, sizeof(path), "./%s", name);
    if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
        strncpy(result, path, result_size - 1);
        return 0;
    }

    return -1;
}

/* Check if already loaded */
static pe_dll_entry_t *find_loaded_pe_dll(const char *name)
{
    char lower[260];
    size_t i;
    for (i = 0; name[i] && i < sizeof(lower) - 1; i++)
        lower[i] = (name[i] >= 'A' && name[i] <= 'Z') ? name[i] + 32 : name[i];
    lower[i] = '\0';

    for (int j = 0; j < g_pe_dll_count; j++) {
        if (strcmp(g_pe_dlls[j].name, lower) == 0 && g_pe_dlls[j].loaded)
            return &g_pe_dlls[j];
    }
    return NULL;
}

/*
 * Load a PE DLL from disk: parse headers, map sections, apply relocations.
 * Returns module base address or NULL on failure.
 */
void *pe_dll_load(const char *dll_name)
{
    pthread_mutex_lock(&g_pe_dll_lock);

    /* Check if already loaded */
    pe_dll_entry_t *existing = find_loaded_pe_dll(dll_name);
    if (existing) {
        pthread_mutex_unlock(&g_pe_dll_lock);
        return existing->base;
    }

    if (g_pe_dll_count >= MAX_PE_DLLS) {
        pthread_mutex_unlock(&g_pe_dll_lock);
        fprintf(stderr, LOG_PREFIX "Too many PE DLLs loaded\n");
        return NULL;
    }

    /* Find the file */
    char filepath[4096];
    if (find_dll_file(dll_name, filepath, sizeof(filepath)) < 0) {
        pthread_mutex_unlock(&g_pe_dll_lock);
        return NULL;
    }

    printf(LOG_PREFIX "Loading PE DLL: %s from %s\n", dll_name, filepath);

    /* Open and read DOS header */
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        pthread_mutex_unlock(&g_pe_dll_lock);
        return NULL;
    }

    unsigned char dos_header[64];
    if (read(fd, dos_header, 64) != 64) {
        close(fd);
        pthread_mutex_unlock(&g_pe_dll_lock);
        return NULL;
    }

    uint16_t mz = *(uint16_t *)dos_header;
    if (mz != IMAGE_DOS_SIGNATURE) {
        close(fd);
        pthread_mutex_unlock(&g_pe_dll_lock);
        fprintf(stderr, LOG_PREFIX "%s: not a valid PE file (bad MZ)\n", dll_name);
        return NULL;
    }

    uint32_t pe_offset = *(uint32_t *)(dos_header + 0x3C);
    lseek(fd, pe_offset, SEEK_SET);

    unsigned char pe_sig[4];
    if (read(fd, pe_sig, 4) != 4 || *(uint32_t *)pe_sig != IMAGE_NT_SIGNATURE) {
        close(fd);
        pthread_mutex_unlock(&g_pe_dll_lock);
        return NULL;
    }

    /* Read COFF header (20 bytes) */
    unsigned char coff[20];
    if (read(fd, coff, 20) != 20) {
        close(fd);
        pthread_mutex_unlock(&g_pe_dll_lock);
        return NULL;
    }

    uint16_t num_sections = *(uint16_t *)(coff + 2);
    uint16_t opt_header_size = *(uint16_t *)(coff + 16);

    /* Read optional header */
    unsigned char *opt = malloc(opt_header_size);
    if (!opt || read(fd, opt, opt_header_size) != opt_header_size) {
        free(opt);
        close(fd);
        pthread_mutex_unlock(&g_pe_dll_lock);
        return NULL;
    }

    uint16_t magic = *(uint16_t *)opt;
    int is_pe64 = (magic == 0x20B);

    uint64_t image_base;
    uint32_t size_of_image;
    uint32_t entry_rva;
    uint32_t num_data_dirs;

    if (is_pe64) {
        entry_rva = *(uint32_t *)(opt + 16);
        image_base = *(uint64_t *)(opt + 24);
        size_of_image = *(uint32_t *)(opt + 56);
        num_data_dirs = *(uint32_t *)(opt + 108);
    } else {
        entry_rva = *(uint32_t *)(opt + 16);
        image_base = *(uint32_t *)(opt + 28);
        size_of_image = *(uint32_t *)(opt + 56);
        num_data_dirs = *(uint32_t *)(opt + 92);
    }

    /* Get export directory info */
    uint32_t export_rva = 0, export_size = 0;
    if (num_data_dirs > 0) {
        int dd_offset = is_pe64 ? 112 : 96;
        export_rva = *(uint32_t *)(opt + dd_offset);
        export_size = *(uint32_t *)(opt + dd_offset + 4);
    }

    /* Get exception directory (.pdata) for SEH unwinding registration */
    uint32_t exception_rva = 0, exception_size = 0;
    if (num_data_dirs > 3) {
        int dd_offset = is_pe64 ? 112 : 96;
        exception_rva  = *(uint32_t *)(opt + dd_offset + 3 * 8);
        exception_size = *(uint32_t *)(opt + dd_offset + 3 * 8 + 4);
    }

    /* Map the image */
    void *base = mmap(NULL, size_of_image,
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        free(opt);
        close(fd);
        pthread_mutex_unlock(&g_pe_dll_lock);
        return NULL;
    }

    /* Copy PE headers */
    lseek(fd, 0, SEEK_SET);
    uint32_t headers_size = is_pe64 ? *(uint32_t *)(opt + 60) : *(uint32_t *)(opt + 60);
    if (headers_size > (uint32_t)size_of_image) headers_size = size_of_image;
    unsigned char *hdr_buf = malloc(headers_size);
    if (hdr_buf) {
        ssize_t n = read(fd, hdr_buf, headers_size);
        if (n > 0)
            memcpy(base, hdr_buf, (size_t)n);
        free(hdr_buf);
    }

    /* Read and map sections */
    long section_offset = pe_offset + 4 + 20 + opt_header_size;
    lseek(fd, section_offset, SEEK_SET);

    for (int i = 0; i < num_sections; i++) {
        unsigned char sec[40];
        if (read(fd, sec, 40) != 40) break;

        uint32_t virt_size = *(uint32_t *)(sec + 8);
        uint32_t virt_addr = *(uint32_t *)(sec + 12);
        uint32_t raw_size = *(uint32_t *)(sec + 16);
        uint32_t raw_offset = *(uint32_t *)(sec + 20);

        if (raw_size > 0 && raw_offset > 0) {
            long cur = lseek(fd, 0, SEEK_CUR);
            lseek(fd, raw_offset, SEEK_SET);
            uint32_t copy_size = raw_size < virt_size ? raw_size : virt_size;
            if (virt_addr + copy_size <= (uint32_t)size_of_image) {
                ssize_t nr = read(fd, (unsigned char *)base + virt_addr, copy_size);
                if (nr < 0) break;
            }
            lseek(fd, cur, SEEK_SET);
        }
    }

    free(opt);
    close(fd);

    /* Apply base relocations */
    int64_t delta = (int64_t)((uintptr_t)base - image_base);
    if (delta != 0) {
        /* Find relocation directory from mapped headers */
        unsigned char *p = (unsigned char *)base;
        uint32_t pe_off2 = *(uint32_t *)(p + 0x3C);
        unsigned char *opt2 = p + pe_off2 + 4 + 20;
        uint16_t magic2 = *(uint16_t *)opt2;
        int is64 = (magic2 == 0x20B);
        int dd_off = is64 ? 112 : 96;
        uint32_t ndd = is64 ? *(uint32_t *)(opt2 + 108) : *(uint32_t *)(opt2 + 92);

        if (ndd > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
            uint32_t reloc_rva = *(uint32_t *)(opt2 + dd_off + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8);
            uint32_t reloc_size = *(uint32_t *)(opt2 + dd_off + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8 + 4);

            if (reloc_rva && reloc_size) {
                unsigned char *reloc = p + reloc_rva;
                unsigned char *reloc_end = reloc + reloc_size;

                while (reloc < reloc_end) {
                    uint32_t page_rva = *(uint32_t *)reloc;
                    uint32_t block_size = *(uint32_t *)(reloc + 4);
                    if (block_size == 0) break;

                    int num_entries = (block_size - 8) / 2;
                    uint16_t *entries = (uint16_t *)(reloc + 8);

                    for (int i = 0; i < num_entries; i++) {
                        uint16_t entry = entries[i];
                        int type = entry >> 12;
                        uint32_t offset = entry & 0xFFF;
                        unsigned char *fix = p + page_rva + offset;

                        switch (type) {
                        case 0: break; /* IMAGE_REL_BASED_ABSOLUTE - padding */
                        case 3: /* IMAGE_REL_BASED_HIGHLOW (32-bit) */
                            *(uint32_t *)fix += (uint32_t)delta;
                            break;
                        case 10: /* IMAGE_REL_BASED_DIR64 */
                            *(uint64_t *)fix += delta;
                            break;
                        }
                    }

                    reloc += block_size;
                }
            }
        }
    }

    /* Register in our tracking table */
    pe_dll_entry_t *entry = &g_pe_dlls[g_pe_dll_count];
    memset(entry, 0, sizeof(*entry));
    size_t ni;
    for (ni = 0; dll_name[ni] && ni < sizeof(entry->name) - 1; ni++)
        entry->name[ni] = (dll_name[ni] >= 'A' && dll_name[ni] <= 'Z') ?
                          dll_name[ni] + 32 : dll_name[ni];
    entry->name[ni] = '\0';
    entry->base = base;
    entry->size = size_of_image;
    entry->entry_point = entry_rva ? (void *)((uintptr_t)base + entry_rva) : NULL;
    entry->export_rva = export_rva;
    entry->export_size = export_size;
    entry->loaded = 1;
    g_pe_dll_count++;

    /* Register in PEB LDR module list */
    env_register_module(base, size_of_image, entry->entry_point,
                        filepath, dll_name, 1);

    /* Register .pdata section for x64 SEH frame-based unwinding */
    if (exception_rva && exception_size) {
        extern void pe_exception_register_module(uint64_t image_base,
                                                  uint64_t image_size,
                                                  const void *func_table_ptr,
                                                  uint32_t entry_count);
        void *pdata = (unsigned char *)base + exception_rva;
        /* Each RUNTIME_FUNCTION entry is 12 bytes (start_rva, end_rva, unwind_rva) */
        uint32_t entry_count = exception_size / 12;
        pe_exception_register_module((uint64_t)(uintptr_t)base,
                                     (uint64_t)size_of_image,
                                     pdata, entry_count);
        printf(LOG_PREFIX "%s: registered %u .pdata entries for SEH\n",
               dll_name, entry_count);
    }

    printf(LOG_PREFIX "PE DLL loaded: %s at %p (size=0x%x)\n",
           dll_name, base, size_of_image);

    /*
     * Resolve imports BEFORE calling DllMain.
     * Must unlock mutex first because LoadLibraryA may recursively
     * load more PE DLLs (which need to acquire the same lock).
     */
    pthread_mutex_unlock(&g_pe_dll_lock);

    pe_dll_resolve_imports(base, size_of_image);

    /* Emit PE_EVT_DLL_LOAD event to AI Cortex */
    {
        pe_evt_dll_load_t dll_evt;
        memset(&dll_evt, 0, sizeof(dll_evt));
        strncpy(dll_evt.dll_name, dll_name, sizeof(dll_evt.dll_name) - 1);
        /* resolved/unresolved counts are not easily available here;
         * pe_dll_resolve_imports logs them to stderr but doesn't return them. */
        pe_event_emit(PE_EVT_DLL_LOAD, &dll_evt, sizeof(dll_evt));
    }

    /* Call DllMain(DLL_PROCESS_ATTACH) if entry point exists */
    if (entry->entry_point) {
        printf(LOG_PREFIX "Calling DllMain for %s\n", dll_name);
        /* DllMain(HINSTANCE, DWORD reason, LPVOID reserved) */
        abi_call_win64_3(entry->entry_point,
                         (uint64_t)(uintptr_t)base,
                         DLL_PROCESS_ATTACH,
                         0);
    }

    return base;
}

/*
 * Resolve a forwarded PE export.
 *
 * When an export directory entry points back into the export directory
 * (i.e. func_rva is within [export_rva, export_rva + export_size)),
 * the memory at that RVA is an ASCII forwarder string like
 * "NTDLL.RtlAllocateHeap" or "api-ms-win-core-heap-l1-1-0.HeapAlloc".
 *
 * We parse "DllName.FuncName" (or "DllName.#ordinal"), load the target
 * DLL (which may be another PE or an .so stub), and resolve the function.
 *
 * depth_limit prevents infinite recursion if a chain loops.
 */
#define PE_DLL_MAX_FWD_DEPTH 16

/* CRT wrapper lookup from pe_import.c (accessible via -rdynamic) */
extern void *pe_find_crt_wrapper(const char *name) __attribute__((weak));

static void *pe_dll_resolve_forwarder(const char *fwd_string, int depth)
{
    if (!fwd_string || depth >= PE_DLL_MAX_FWD_DEPTH)
        return NULL;

    const char *dot = strchr(fwd_string, '.');
    if (!dot || dot == fwd_string)
        return NULL;

    /* Parse DLL name */
    char dll_name[260];
    size_t dll_len = (size_t)(dot - fwd_string);
    if (dll_len >= sizeof(dll_name) - 5)
        return NULL;
    memcpy(dll_name, fwd_string, dll_len);
    dll_name[dll_len] = '\0';
    strcat(dll_name, ".dll");

    /* Lowercase the DLL name */
    for (char *c = dll_name; *c; c++)
        *c = (*c >= 'A' && *c <= 'Z') ? *c + 32 : *c;

    const char *func_part = dot + 1;
    int is_ordinal = (func_part[0] == '#');

    printf(LOG_PREFIX "  Resolving forwarder: %s (depth %d)\n", fwd_string, depth);

    /* Check CRT wrappers first for ABI safety */
    if (!is_ordinal && pe_find_crt_wrapper) {
        void *crt = pe_find_crt_wrapper(func_part);
        if (crt) return crt;
    }

    /* Try to find/load the target DLL as a PE DLL */
    void *target_base = pe_dll_find(dll_name);
    if (!target_base)
        target_base = pe_dll_load(dll_name);

    if (target_base) {
        /* Recursive call with incremented depth to prevent infinite loops */
        void *result = NULL;
        if (is_ordinal) {
            uint16_t ord = (uint16_t)atoi(func_part + 1);
            result = pe_dll_get_proc_depth(target_base,
                         (const char *)(uintptr_t)ord, depth + 1);
        } else {
            result = pe_dll_get_proc_depth(target_base, func_part, depth + 1);
        }
        if (result) return result;
    }

    /* Fallback: try dlsym in all loaded .so libraries */
    if (!is_ordinal) {
        void *sym = dlsym(RTLD_DEFAULT, func_part);
        if (sym) return sym;
    }

    return NULL;
}

/*
 * Internal implementation of pe_dll_get_proc with depth tracking.
 * Walks the PE export directory table and follows forwarder chains.
 */
static void *pe_dll_get_proc_depth(void *base, const char *proc_name, int fwd_depth)
{
    if (!base || !proc_name) return NULL;
    if (fwd_depth >= PE_DLL_MAX_FWD_DEPTH) return NULL;

    unsigned char *p = (unsigned char *)base;

    /* Verify MZ */
    if (*(uint16_t *)p != IMAGE_DOS_SIGNATURE) return NULL;

    uint32_t pe_off = *(uint32_t *)(p + 0x3C);
    unsigned char *opt = p + pe_off + 4 + 20;
    uint16_t magic = *(uint16_t *)opt;
    int is64 = (magic == 0x20B);
    int dd_off = is64 ? 112 : 96;
    uint32_t num_dd = is64 ? *(uint32_t *)(opt + 108) : *(uint32_t *)(opt + 92);

    if (num_dd < 1) return NULL;

    uint32_t export_rva = *(uint32_t *)(opt + dd_off);
    uint32_t export_size = *(uint32_t *)(opt + dd_off + 4);
    if (!export_rva || !export_size) return NULL;

    /* Bounds check: get image size */
    uint32_t size_of_image = *(uint32_t *)(opt + 56);
    if (export_rva + export_size > size_of_image) return NULL;

    /* Export directory */
    unsigned char *ed = p + export_rva;
    uint32_t num_functions = *(uint32_t *)(ed + 20);
    uint32_t num_names = *(uint32_t *)(ed + 24);
    uint32_t func_table_rva = *(uint32_t *)(ed + 28);
    uint32_t name_table_rva = *(uint32_t *)(ed + 32);
    uint32_t ord_table_rva = *(uint32_t *)(ed + 36);
    uint32_t ordinal_base = *(uint32_t *)(ed + 16);

    /* Bounds checks on tables */
    if (func_table_rva + num_functions * 4 > size_of_image ||
        name_table_rva + num_names * 4 > size_of_image ||
        ord_table_rva + num_names * 2 > size_of_image)
        return NULL;

    uint32_t *func_table = (uint32_t *)(p + func_table_rva);
    uint32_t *name_table = (uint32_t *)(p + name_table_rva);
    uint16_t *ord_table = (uint16_t *)(p + ord_table_rva);

    /* Check if importing by ordinal */
    if ((uintptr_t)proc_name < 0x10000) {
        uint16_t raw_ordinal = (uint16_t)(uintptr_t)proc_name;
        if (raw_ordinal < ordinal_base) return NULL;
        uint32_t index = raw_ordinal - ordinal_base;
        if (index >= num_functions) return NULL;

        uint32_t func_rva = func_table[index];
        if (func_rva == 0) return NULL;

        /* Check for forwarder */
        if (func_rva >= export_rva && func_rva < export_rva + export_size) {
            const char *fwd = (const char *)(p + func_rva);
            return pe_dll_resolve_forwarder(fwd, fwd_depth);
        }
        return p + func_rva;
    }

    /* Binary search the name table */
    int lo = 0, hi = (int)num_names - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (name_table[mid] >= size_of_image) return NULL;
        const char *mid_name = (const char *)(p + name_table[mid]);
        int cmp = strcmp(proc_name, mid_name);
        if (cmp == 0) {
            uint16_t ordinal = ord_table[mid];
            if (ordinal >= num_functions) return NULL;

            uint32_t func_rva = func_table[ordinal];
            if (func_rva == 0) return NULL;

            /* Check for forwarder */
            if (func_rva >= export_rva && func_rva < export_rva + export_size) {
                const char *fwd = (const char *)(p + func_rva);
                return pe_dll_resolve_forwarder(fwd, fwd_depth);
            }
            return p + func_rva;
        }
        if (cmp < 0) hi = mid - 1;
        else lo = mid + 1;
    }

    /* Case-insensitive fallback (some imports use wrong case) */
    for (uint32_t i = 0; i < num_names; i++) {
        if (name_table[i] >= size_of_image) continue;
        const char *entry_name = (const char *)(p + name_table[i]);
        if (strcasecmp(proc_name, entry_name) == 0) {
            uint16_t ordinal = ord_table[i];
            if (ordinal >= num_functions) return NULL;

            uint32_t func_rva = func_table[ordinal];
            if (func_rva == 0) return NULL;

            if (func_rva >= export_rva && func_rva < export_rva + export_size) {
                const char *fwd = (const char *)(p + func_rva);
                return pe_dll_resolve_forwarder(fwd, fwd_depth);
            }
            return p + func_rva;
        }
    }

    return NULL;
}

/*
 * Public API: Look up an export in a loaded PE DLL.
 * Walks the export directory table. Follows forwarder chains.
 */
void *pe_dll_get_proc(void *base, const char *proc_name)
{
    return pe_dll_get_proc_depth(base, proc_name, 0);
}

/* Check if a PE DLL is loaded, return base address */
void *pe_dll_find(const char *name)
{
    pe_dll_entry_t *e = find_loaded_pe_dll(name);
    return e ? e->base : NULL;
}

/*
 * CRT ABI wrapper lookup — provided by pe_import.c in the loader binary.
 * Accessible via -rdynamic. Returns ms_abi wrapper for C functions
 * like memset/malloc/strlen that PE code imports from CRT DLLs.
 * Without these, PE code would call libc's sysv_abi versions → crash.
 */
extern void *pe_find_crt_wrapper(const char *name) __attribute__((weak));

/*
 * Graceful stub for unimplemented imports in PE DLLs.
 * Returns 0 (FALSE/NULL/S_OK) — many apps probe for optional functions.
 */
static __attribute__((ms_abi)) uint64_t pe_dll_unimplemented_stub(void)
{
    fprintf(stderr, LOG_PREFIX "WARNING: Unresolved PE DLL import called - returning 0\n");
    return 0;
}

/*
 * Resolve imports for a PE DLL that was loaded by pe_dll_load().
 *
 * Walks the import directory table, resolves each imported DLL via
 * LoadLibraryA (which handles .so stubs, api-ms-win-*, and recursive
 * PE DLL loading), and resolves each function via GetProcAddress.
 *
 * CRT functions (memset, malloc, etc.) get ms_abi wrappers to prevent
 * the sysv_abi/ms_abi calling convention mismatch.
 *
 * Must be called BEFORE DllMain, with g_pe_dll_lock NOT held
 * (because LoadLibraryA may recursively load more PE DLLs).
 */
static int pe_dll_resolve_imports(void *base, uint32_t size_of_image)
{
    unsigned char *p = (unsigned char *)base;

    /* Navigate to optional header to find import directory */
    uint32_t pe_off = *(uint32_t *)(p + 0x3C);
    unsigned char *opt = p + pe_off + 4 + 20;
    uint16_t magic = *(uint16_t *)opt;
    int is64 = (magic == 0x20B);
    int dd_off = is64 ? 112 : 96;
    uint32_t num_dd = is64 ? *(uint32_t *)(opt + 108) : *(uint32_t *)(opt + 92);

    /* Import directory is data directory entry #1 */
    if (num_dd <= IMAGE_DIRECTORY_ENTRY_IMPORT)
        return 0; /* No imports */

    uint32_t import_rva  = *(uint32_t *)(opt + dd_off + IMAGE_DIRECTORY_ENTRY_IMPORT * 8);
    uint32_t import_size = *(uint32_t *)(opt + dd_off + IMAGE_DIRECTORY_ENTRY_IMPORT * 8 + 4);

    if (import_rva == 0 || import_size == 0)
        return 0; /* No imports */

    if (import_rva >= size_of_image) {
        fprintf(stderr, LOG_PREFIX "Import directory RVA 0x%x out of bounds\n", import_rva);
        return -1;
    }

    /* Import descriptor table: array of 20-byte entries, null-terminated */
    typedef struct {
        uint32_t ilt_rva;           /* Import Lookup Table RVA */
        uint32_t time_date_stamp;
        uint32_t forwarder_chain;
        uint32_t name_rva;          /* DLL name RVA */
        uint32_t iat_rva;           /* Import Address Table RVA */
    } import_desc_t;

    import_desc_t *desc = (import_desc_t *)(p + import_rva);
    int total_resolved = 0, total_unresolved = 0;

    /* Use LoadLibraryA and GetProcAddress from kernel32_module.c (same .so).
     * CRITICAL: These are ms_abi functions — must declare with correct ABI! */
    extern __attribute__((ms_abi)) HMODULE LoadLibraryA(LPCSTR);
    extern __attribute__((ms_abi)) FARPROC GetProcAddress(HMODULE, LPCSTR);

    for (; desc->name_rva != 0; desc++) {
        if (desc->name_rva >= size_of_image) continue;
        const char *dll_name = (const char *)(p + desc->name_rva);

        printf(LOG_PREFIX "  Resolving PE DLL imports from: %s\n", dll_name);

        /* Load the dependency DLL (handles .so stubs, api-ms-win-*, PE DLLs) */
        HMODULE dep_mod = LoadLibraryA(dll_name);

        /* Get ILT and IAT */
        uint32_t ilt_rva = desc->ilt_rva;
        uint32_t iat_rva = desc->iat_rva;
        if (ilt_rva == 0) ilt_rva = iat_rva; /* Some linkers omit ILT */

        if (ilt_rva == 0 || ilt_rva >= size_of_image ||
            iat_rva == 0 || iat_rva >= size_of_image)
            continue;

        if (is64) {
            uint64_t *ilt = (uint64_t *)(p + ilt_rva);
            uint64_t *iat = (uint64_t *)(p + iat_rva);

            for (int i = 0; ilt[i] != 0; i++) {
                void *func_addr = NULL;

                if (ilt[i] & 0x8000000000000000ULL) {
                    /* Import by ordinal */
                    uint16_t ordinal = (uint16_t)(ilt[i] & 0xFFFF);
                    if (dep_mod)
                        func_addr = (void *)GetProcAddress(dep_mod, (LPCSTR)(uintptr_t)ordinal);
                } else {
                    /* Import by name */
                    uint32_t hint_rva = (uint32_t)(ilt[i] & 0x7FFFFFFF);
                    if (hint_rva >= size_of_image) {
                        iat[i] = (uint64_t)(uintptr_t)pe_dll_unimplemented_stub;
                        total_unresolved++;
                        continue;
                    }

                    /* hint/name: uint16_t hint + null-terminated name */
                    const char *func_name = (const char *)(p + hint_rva + 2);

                    /* Check CRT ABI wrapper FIRST (prevents sysv/ms mismatch) */
                    if (pe_find_crt_wrapper)
                        func_addr = pe_find_crt_wrapper(func_name);

                    /* Then try GetProcAddress (dlsym + PE export lookup) */
                    if (!func_addr && dep_mod)
                        func_addr = (void *)GetProcAddress(dep_mod, func_name);

                    /* Last resort: search all loaded .so via RTLD_DEFAULT */
                    if (!func_addr)
                        func_addr = dlsym(RTLD_DEFAULT, func_name);

                    if (!func_addr) {
                        fprintf(stderr, LOG_PREFIX "    UNRESOLVED: %s!%s\n",
                                dll_name, func_name);
                    }
                }

                if (func_addr) {
                    iat[i] = (uint64_t)(uintptr_t)func_addr;
                    total_resolved++;
                } else {
                    iat[i] = (uint64_t)(uintptr_t)pe_dll_unimplemented_stub;
                    total_unresolved++;
                }
            }
        } else {
            /* 32-bit PE */
            uint32_t *ilt = (uint32_t *)(p + ilt_rva);
            uint32_t *iat = (uint32_t *)(p + iat_rva);

            for (int i = 0; ilt[i] != 0; i++) {
                void *func_addr = NULL;

                if (ilt[i] & 0x80000000U) {
                    uint16_t ordinal = (uint16_t)(ilt[i] & 0xFFFF);
                    if (dep_mod)
                        func_addr = (void *)GetProcAddress(dep_mod, (LPCSTR)(uintptr_t)ordinal);
                } else {
                    uint32_t hint_rva = ilt[i] & 0x7FFFFFFF;
                    if (hint_rva >= size_of_image) {
                        iat[i] = (uint32_t)(uintptr_t)pe_dll_unimplemented_stub;
                        total_unresolved++;
                        continue;
                    }

                    const char *func_name = (const char *)(p + hint_rva + 2);

                    if (pe_find_crt_wrapper)
                        func_addr = pe_find_crt_wrapper(func_name);
                    if (!func_addr && dep_mod)
                        func_addr = (void *)GetProcAddress(dep_mod, func_name);
                    if (!func_addr)
                        func_addr = dlsym(RTLD_DEFAULT, func_name);

                    if (!func_addr)
                        fprintf(stderr, LOG_PREFIX "    UNRESOLVED: %s!%s\n",
                                dll_name, func_name);
                }

                if (func_addr) {
                    iat[i] = (uint32_t)(uintptr_t)func_addr;
                    total_resolved++;
                } else {
                    iat[i] = (uint32_t)(uintptr_t)pe_dll_unimplemented_stub;
                    total_unresolved++;
                }
            }
        }
    }

    printf(LOG_PREFIX "PE DLL import resolution: %d resolved, %d unresolved\n",
           total_resolved, total_unresolved);
    return 0;
}

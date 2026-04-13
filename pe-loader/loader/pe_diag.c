/*
 * pe_diag.c - PE diagnostics and compatibility analysis
 *
 * Provides tools for analysing a PE binary's import coverage against
 * our stub DLL libraries, runtime API-call tracing, and a graceful
 * stub fallback for unresolved imports.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <ctype.h>
#include <sys/mman.h>

#include "pe/pe_header.h"
#include "pe/pe_import.h"
#include "pe/pe_types.h"

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */
#define DIAG_LOG_PREFIX     "[pe_diag] "
#define MAX_MISSING         4096
#define MAX_DLL_NAME        256
#define MAX_FUNC_NAME       512
#define MAX_DLLS            128

/* DLL name -> .so mapping (mirrors pe_import.c; kept local so pe_diag
 * can be compiled independently of the loader's runtime state). */
typedef struct {
    const char *win_name;
    const char *so_name;
} diag_dll_map_t;

static const diag_dll_map_t g_diag_dll_map[] = {
    { "kernel32.dll",       "libpe_kernel32.so" },
    { "ntdll.dll",          "libpe_ntdll.so"    },
    { "user32.dll",         "libpe_user32.so"   },
    { "gdi32.dll",          "libpe_gdi32.so"    },
    { "advapi32.dll",       "libpe_advapi32.so" },
    { "ws2_32.dll",         "libpe_ws2_32.so"   },
    { "wsock32.dll",        "libpe_ws2_32.so"   },
    { "msvcrt.dll",         "libpe_msvcrt.so"   },
    { "ole32.dll",          "libpe_ole32.so"    },
    { "shell32.dll",        "libpe_shell32.so"  },
    { "ucrtbase.dll",       "libpe_msvcrt.so"   },
    { "vcruntime140.dll",   "libpe_msvcrt.so"   },
    { "version.dll",        "libpe_version.so"  },
    { "shlwapi.dll",        "libpe_shlwapi.so"  },
    { "crypt32.dll",        "libpe_crypt32.so"  },
    { "winmm.dll",          "libpe_winmm.so"    },
    { "iphlpapi.dll",       "libpe_iphlpapi.so" },
    { "winhttp.dll",        "libpe_winhttp.so"  },
    { "wininet.dll",        "libpe_winhttp.so"  },
    { "setupapi.dll",       "libpe_setupapi.so" },
    { "comctl32.dll",       "libpe_comctl32.so" },
    { "comdlg32.dll",       "libpe_comdlg32.so" },
    { "imm32.dll",          "libpe_imm32.so"    },
    { "oleaut32.dll",       "libpe_oleaut32.so" },
    { "bcrypt.dll",         "libpe_bcrypt.so"   },
    { "psapi.dll",          "libpe_psapi.so"    },
    { "dbghelp.dll",        "libpe_dbghelp.so"  },
    { "userenv.dll",        "libpe_userenv.so"  },
    { "secur32.dll",        "libpe_secur32.so"  },
    { "dsound.dll",         "libpe_dsound.so"   },
    { "dwmapi.dll",         "libpe_dwmapi.so"   },
    { "mscoree.dll",        "libpe_mscoree.so"  },
    { "d3d9.dll",           "libpe_d3d.so"      },
    { "d3d11.dll",          "libpe_d3d.so"      },
    { "dxgi.dll",           "libpe_d3d.so"      },
    { "ddraw.dll",          "libpe_d3d.so"      },
    { "dinput.dll",         "libpe_d3d.so"      },
    { "dinput8.dll",        "libpe_d3d.so"      },
    { "xinput1_3.dll",      "libpe_d3d.so"      },
    { "xinput1_4.dll",      "libpe_d3d.so"      },
    { "xinput9_1_0.dll",    "libpe_d3d.so"      },
    { "ntoskrnl.exe",       "libpe_ntoskrnl.so" },
    { "hal.dll",            "libpe_hal.so"      },
    { "ndis.sys",           "libpe_ndis.so"     },
    { "msi.dll",            "libpe_msi.so"      },
    { "steam_api64.dll",    "libpe_steamclient.so" },
    { NULL, NULL }
};

/* ------------------------------------------------------------------ */
/* Missing-function accumulator (used during report generation)        */
/* ------------------------------------------------------------------ */
typedef struct {
    char dll[MAX_DLL_NAME];
    char func[MAX_FUNC_NAME];
} missing_entry_t;

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */
static void str_to_lower(char *s)
{
    for (; *s; s++)
        *s = (char)tolower((unsigned char)*s);
}

/* Find the .so name for a Windows DLL.  Returns NULL if unknown. */
static const char *find_so_for_dll(const char *dll_name)
{
    char lower[MAX_DLL_NAME];
    strncpy(lower, dll_name, sizeof(lower) - 1);
    lower[sizeof(lower) - 1] = '\0';
    str_to_lower(lower);

    for (int i = 0; g_diag_dll_map[i].win_name; i++) {
        if (strcmp(lower, g_diag_dll_map[i].win_name) == 0)
            return g_diag_dll_map[i].so_name;
    }

    /* Handle api-ms-win-crt-* -> libpe_msvcrt.so */
    if (strncmp(lower, "api-ms-win-crt-", 15) == 0)
        return "libpe_msvcrt.so";

    /* Handle api-ms-win-core-* -> libpe_kernel32.so */
    if (strncmp(lower, "api-ms-win-core-", 16) == 0)
        return "libpe_kernel32.so";

    /* Handle MSVC runtime variants */
    if (strncmp(lower, "msvcp1", 6) == 0 ||
        strncmp(lower, "msvcr1", 6) == 0 ||
        strncmp(lower, "vcruntime", 9) == 0 ||
        strncmp(lower, "concrt1", 7) == 0)
        return "libpe_msvcrt.so";

    return NULL;
}

/*
 * File-based RVA resolver: translates an RVA to a pointer in the
 * mmap'd raw file using section headers.  Unlike pe_rva_to_ptr which
 * needs sections to be mapped at their virtual addresses, this works
 * with the raw file contents by converting RVA -> file offset.
 */
static void *diag_rva_to_ptr(const pe_image_t *image, const uint8_t *file_base,
                              size_t file_size, uint32_t rva)
{
    if (rva == 0) return NULL;

    /* Check if RVA falls within file headers (before any section) */
    if (rva < image->size_of_headers && rva < file_size)
        return (void *)(file_base + rva);

    /* Walk sections to find which one contains this RVA */
    for (uint16_t i = 0; i < image->num_sections; i++) {
        const pe_section_header_t *s = &image->sections[i];
        if (rva >= s->virtual_address &&
            rva < s->virtual_address + s->size_of_raw_data) {
            uint32_t offset = s->pointer_to_raw_data + (rva - s->virtual_address);
            if (offset < file_size)
                return (void *)(file_base + offset);
        }
    }
    return NULL;
}

/* Try to dlopen a .so using our search paths.  Returns handle or NULL. */
static void *try_dlopen_so(const char *so_name)
{
    void *handle;

    /* 1. Bare name (LD_LIBRARY_PATH / ld.so.cache) */
    handle = dlopen(so_name, RTLD_LAZY | RTLD_NOLOAD);
    if (handle) return handle;

    handle = dlopen(so_name, RTLD_LAZY);
    if (handle) return handle;

    /* 2. Installed location */
    char path[512];
    snprintf(path, sizeof(path), "/usr/lib/pe-compat/%s", so_name);
    handle = dlopen(path, RTLD_LAZY);
    if (handle) return handle;

    /* 3. Development location */
    snprintf(path, sizeof(path), "./dlls/%s", so_name);
    handle = dlopen(path, RTLD_LAZY);
    if (handle) return handle;

    return NULL;
}

/* Return a human-readable machine name. */
static const char *machine_name(uint16_t machine)
{
    switch (machine) {
    case PE_MACHINE_I386:  return "x86 (i386)";
    case PE_MACHINE_AMD64: return "x64 (AMD64)";
    case PE_MACHINE_ARM64: return "ARM64 (AArch64)";
    default:               return "unknown";
    }
}

/* ------------------------------------------------------------------ */
/* pe_diag_report -- full compatibility analysis of a PE binary        */
/* ------------------------------------------------------------------ */
int pe_diag_report(const char *exe_path)
{
    if (!exe_path) {
        fprintf(stderr, DIAG_LOG_PREFIX "pe_diag_report: NULL path\n");
        return -1;
    }

    pe_image_t image;
    memset(&image, 0, sizeof(image));

    if (pe_parse_file(exe_path, &image) != 0) {
        fprintf(stderr, DIAG_LOG_PREFIX "Failed to parse PE file: %s\n", exe_path);
        return -1;
    }

    /* ---- Header summary ---- */
    printf("=== PE Compatibility Report: %s ===\n\n", exe_path);
    printf("Architecture : %s\n", machine_name(image.file_header.machine));
    printf("PE format    : %s\n", image.is_pe32plus ? "PE32+ (64-bit)" : "PE32 (32-bit)");
    printf("Image base   : 0x%llx\n", (unsigned long long)image.image_base);
    printf("Entry point  : 0x%08x\n", image.address_of_entry_point);
    printf("Subsystem    : %u", image.subsystem);
    switch (image.subsystem) {
    case PE_SUBSYSTEM_WINDOWS_GUI: printf(" (Windows GUI)"); break;
    case PE_SUBSYSTEM_WINDOWS_CUI: printf(" (Windows Console)"); break;
    case PE_SUBSYSTEM_NATIVE:      printf(" (Native / Driver)"); break;
    default: break;
    }
    printf("\nSections     : %u\n", image.num_sections);
    printf("\n");

    /* ---- Import analysis ---- */
    if (image.number_of_rva_and_sizes <= PE_DIR_IMPORT ||
        image.data_directory[PE_DIR_IMPORT].virtual_address == 0) {
        printf("No import directory found.\n");
        pe_image_free(&image);
        return 0;
    }

    /* mmap the raw file so we can resolve RVAs via section table */
    uint8_t *file_base = NULL;
    if (image.fd >= 0 && image.file_size > 0) {
        file_base = mmap(NULL, image.file_size, PROT_READ, MAP_PRIVATE, image.fd, 0);
        if (file_base == MAP_FAILED)
            file_base = NULL;
    }

    /* Use file-based RVA resolver (works without pe_map_sections) */
    #define DIAG_RVA(rva) diag_rva_to_ptr(&image, file_base, image.file_size, (rva))

    pe_import_descriptor_t *desc = (pe_import_descriptor_t *)
        DIAG_RVA(image.data_directory[PE_DIR_IMPORT].virtual_address);

    if (!desc) {
        fprintf(stderr, DIAG_LOG_PREFIX "Invalid import directory RVA\n");
        if (file_base) munmap(file_base, image.file_size);
        pe_image_free(&image);
        return -1;
    }

    int total_imports   = 0;
    int total_resolved  = 0;
    int total_missing   = 0;
    int total_dll_count = 0;
    int dlls_found      = 0;
    int dlls_missing    = 0;

    /* Accumulate missing functions for grouped output */
    missing_entry_t *missing_list = (missing_entry_t *)
        calloc(MAX_MISSING, sizeof(missing_entry_t));
    int missing_count = 0;

    /* Walk each imported DLL */
    for (; desc->name_rva != 0; desc++) {
        const char *dll_name = (const char *)DIAG_RVA(desc->name_rva);
        if (!dll_name) continue;

        total_dll_count++;

        /* Find our stub .so */
        const char *so_name = find_so_for_dll(dll_name);
        void *lib = NULL;
        int have_lib = 0;

        if (so_name) {
            lib = try_dlopen_so(so_name);
            if (lib) {
                have_lib = 1;
                dlls_found++;
            } else {
                dlls_missing++;
            }
        } else {
            dlls_missing++;
        }

        /* Count functions from this DLL */
        uint32_t ilt_rva = desc->import_lookup_table_rva;
        if (ilt_rva == 0)
            ilt_rva = desc->import_address_table_rva;

        if (image.is_pe32plus) {
            uint64_t *ilt = (uint64_t *)DIAG_RVA(ilt_rva);
            if (!ilt) continue;

            for (int i = 0; ilt[i] != 0; i++) {
                total_imports++;
                const char *func_name = NULL;

                if (ilt[i] & PE_IMPORT_ORDINAL_FLAG64) {
                    /* Ordinal import -- can't check by name */
                    uint16_t ordinal = (uint16_t)(ilt[i] & 0xFFFF);
                    char ordinal_name[64];
                    snprintf(ordinal_name, sizeof(ordinal_name), "__ordinal_%u", ordinal);
                    if (have_lib && dlsym(lib, ordinal_name)) {
                        total_resolved++;
                    } else {
                        total_missing++;
                        if (missing_count < MAX_MISSING) {
                            strncpy(missing_list[missing_count].dll, dll_name, MAX_DLL_NAME - 1);
                            snprintf(missing_list[missing_count].func, MAX_FUNC_NAME,
                                     "ordinal#%u", ordinal);
                            missing_count++;
                        }
                    }
                } else {
                    uint32_t hint_rva = (uint32_t)(ilt[i] & 0x7FFFFFFF);
                    pe_import_by_name_t *hint = (pe_import_by_name_t *)
                        DIAG_RVA(hint_rva);
                    if (!hint) {
                        total_missing++;
                        continue;
                    }
                    func_name = hint->name;

                    if (have_lib && dlsym(lib, func_name)) {
                        total_resolved++;
                    } else {
                        total_missing++;
                        if (missing_count < MAX_MISSING) {
                            strncpy(missing_list[missing_count].dll, dll_name, MAX_DLL_NAME - 1);
                            strncpy(missing_list[missing_count].func, func_name, MAX_FUNC_NAME - 1);
                            missing_count++;
                        }
                    }
                }
            }
        } else {
            /* 32-bit */
            uint32_t *ilt = (uint32_t *)DIAG_RVA(ilt_rva);
            if (!ilt) continue;

            for (int i = 0; ilt[i] != 0; i++) {
                total_imports++;

                if (ilt[i] & PE_IMPORT_ORDINAL_FLAG32) {
                    uint16_t ordinal = (uint16_t)(ilt[i] & 0xFFFF);
                    char ordinal_name[64];
                    snprintf(ordinal_name, sizeof(ordinal_name), "__ordinal_%u", ordinal);
                    if (have_lib && dlsym(lib, ordinal_name)) {
                        total_resolved++;
                    } else {
                        total_missing++;
                        if (missing_count < MAX_MISSING) {
                            strncpy(missing_list[missing_count].dll, dll_name, MAX_DLL_NAME - 1);
                            snprintf(missing_list[missing_count].func, MAX_FUNC_NAME,
                                     "ordinal#%u", ordinal);
                            missing_count++;
                        }
                    }
                } else {
                    uint32_t hint_rva = ilt[i] & 0x7FFFFFFF;
                    pe_import_by_name_t *hint = (pe_import_by_name_t *)
                        DIAG_RVA(hint_rva);
                    if (!hint) {
                        total_missing++;
                        continue;
                    }
                    const char *func_name = hint->name;

                    if (have_lib && dlsym(lib, func_name)) {
                        total_resolved++;
                    } else {
                        total_missing++;
                        if (missing_count < MAX_MISSING) {
                            strncpy(missing_list[missing_count].dll, dll_name, MAX_DLL_NAME - 1);
                            strncpy(missing_list[missing_count].func, func_name, MAX_FUNC_NAME - 1);
                            missing_count++;
                        }
                    }
                }
            }
        }

        /* Close the library handle (opened only for probing) */
        if (lib)
            dlclose(lib);
    }

    /* ---- Summary ---- */
    double coverage = total_imports > 0
        ? ((double)total_resolved / (double)total_imports) * 100.0
        : 0.0;

    printf("--- Import Summary ---\n");
    printf("DLLs imported     : %d\n", total_dll_count);
    printf("DLLs with stubs   : %d\n", dlls_found);
    printf("DLLs without stubs: %d\n", dlls_missing);
    printf("Total imports     : %d\n", total_imports);
    printf("Resolved          : %d\n", total_resolved);
    printf("Missing           : %d\n", total_missing);
    printf("Coverage          : %.1f%%\n", coverage);
    printf("\n");

    /* ---- Missing functions grouped by DLL ---- */
    if (missing_count > 0) {
        printf("--- Missing Functions (by DLL) ---\n");

        /* Collect unique DLL names */
        char seen_dlls[MAX_DLLS][MAX_DLL_NAME];
        int  seen_count = 0;

        for (int i = 0; i < missing_count; i++) {
            int found = 0;
            for (int j = 0; j < seen_count; j++) {
                if (strcmp(seen_dlls[j], missing_list[i].dll) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found && seen_count < MAX_DLLS) {
                strncpy(seen_dlls[seen_count], missing_list[i].dll, MAX_DLL_NAME - 1);
                seen_dlls[seen_count][MAX_DLL_NAME - 1] = '\0';
                seen_count++;
            }
        }

        /* Print missing functions grouped by DLL */
        for (int d = 0; d < seen_count; d++) {
            int count = 0;
            for (int i = 0; i < missing_count; i++) {
                if (strcmp(missing_list[i].dll, seen_dlls[d]) == 0)
                    count++;
            }

            printf("\n  %s (%d missing):\n", seen_dlls[d], count);
            for (int i = 0; i < missing_count; i++) {
                if (strcmp(missing_list[i].dll, seen_dlls[d]) == 0)
                    printf("    - %s\n", missing_list[i].func);
            }
        }
        printf("\n");
    }

    free(missing_list);
    if (file_base) munmap(file_base, image.file_size);
    #undef DIAG_RVA
    pe_image_free(&image);
    return 0;
}

/* ------------------------------------------------------------------ */
/* API call tracing                                                    */
/* ------------------------------------------------------------------ */
static int g_trace_enabled = 0;

/*
 * pe_diag_trace_init -- check the PE_DIAG environment variable.
 * Called automatically via constructor attribute, or can be called
 * explicitly before loading a PE.
 */
__attribute__((constructor))
void pe_diag_trace_init(void)
{
    const char *env = getenv("PE_DIAG");
    if (env) {
        /* Any non-empty value enables tracing; "trace" or "1" are common */
        if (env[0] != '\0')
            g_trace_enabled = 1;
    }
}

/*
 * pe_diag_trace_call -- log an API call to stderr with a timestamp.
 * Intended to be called from thunks or wrapper code when --trace is
 * active.  If tracing is disabled this is a no-op.
 */
void pe_diag_trace_call(const char *dll, const char *func)
{
    if (!g_trace_enabled)
        return;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    double elapsed = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;

    fprintf(stderr, "[TRACE %10.6f] %s!%s\n",
            elapsed,
            dll  ? dll  : "???",
            func ? func : "???");
}

/* ------------------------------------------------------------------ */
/* Stub fallback for unresolved imports                                */
/* ------------------------------------------------------------------ */

/*
 * pe_diag_stub -- print a diagnostic message instead of aborting.
 * This function can be used as the fallback address in the IAT when
 * an import cannot be resolved, giving the user actionable information
 * about what is missing rather than a bare crash.
 */
void pe_diag_stub(const char *dll, const char *func)
{
    fprintf(stderr, "[STUB] %s!%s called\n",
            dll  ? dll  : "<unknown>",
            func ? func : "<unknown>");
}

/*
 * main.c - PE Loader entry point
 *
 * Orchestrates the loading and execution of a Windows PE executable:
 *   1. Reserve address space (preloader)
 *   2. Parse PE headers
 *   3. Map sections into memory
 *   4. Apply base relocations
 *   5. Resolve imports (patch IAT)
 *   6. Transfer control to entry point
 *
 * Usage: peloader [options] <file.exe> [args...]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <dlfcn.h>
#include <strings.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "pe/pe_header.h"
#include "pe/pe_import.h"
#include "pe/pe_reloc.h"
#include "pe/pe_tls.h"
#include "pe/pe_types.h"
#include "compat/abi_bridge.h"
#include "compat/env_setup.h"
#include "compat/objectd_client.h"
#include "windrv_manager.h"
#include "pe_patch.h"

/* Event bus - lock-free event emission to AI Cortex */
#include "eventbus/pe_event.h"

/* Command channel - request/response to AI Cortex for load approval */
#include "compat/cortex_cmd.h"

/* Root of Trust integration */
#include "../../trust/lib/libtrust.h"

/* environ for CRT args */
extern char **environ;

/* Implemented in pe_mapper.c */
extern int pe_map_sections(pe_image_t *image);
extern int pe_restore_section_protections(pe_image_t *image);

/* Implemented in preloader.c */
extern int preloader_reserve(void);
extern void preloader_release(void);
extern void preloader_release_range(uint64_t addr, size_t size);

/* Implemented in loader_init.c - runtime bridge via dlopen/dlsym */
extern void kernel32_set_command_line(const char *cmdline);
extern void kernel32_set_module_filename(const char *filename);
extern void handle_table_init(void);

/* Implemented in msvcrt_stdio.c - set up CRT argc/argv */
extern void __pe_set_main_args(int argc, char **argv, char **envp);

/* Implemented in pe_import.c - set exe directory for DLL search */
extern void pe_import_set_exe_dir(const char *exe_path);
extern void pe_import_print_stub_report(void);
extern void pe_import_emit_manifest(const pe_image_t *image);
extern void stub_log_summary(void);
extern void pe_import_cleanup(void);

/* Implemented in pe_diag.c */
extern int pe_diag_report(const char *exe_path);

/* Implemented in anticheat_bridge.c */
extern int anticheat_bridge_init(void);
extern int anticheat_bridge_shutdown(void);
extern int anticheat_bridge_register_game(int pid, const char *game_name);
extern int anticheat_bridge_check_integrity(void *base, size_t size);

/* Implemented in pe_exception.c - x64 SEH exception handling */
extern void pe_exception_init(void);
extern int  pe_exception_register_image(pe_image_t *image);

/* objectd_connect / objectd_disconnect declared via compat/objectd_client.h */

/* Implemented in trust_gate.c - trust-gated API interception */
extern int trust_gate_init(void);
extern void trust_gate_shutdown(void);
extern int trust_gate_register_pe(const char *exe_path, uint32_t image_hash);
extern int trust_gate_get_score(int32_t *score_out);
extern int trust_gate_get_tokens(uint32_t *balance_out);

/* Implemented in windrv_host.c - Windows driver model host */
extern void windrv_host_init(void);
extern void windrv_host_shutdown(void);

/* Implemented in msi/vcredist_handler.c (loaded via dlsym) - these are ms_abi */
typedef int  __attribute__((ms_abi)) (*vcredist_intercept_fn)(const char *, const char *);
typedef void __attribute__((ms_abi)) (*vcredist_register_fn)(void);
typedef int  __attribute__((ms_abi)) (*msiexec_main_fn)(int, char **);

/* Check if target is a VC++ Redistributable installer or msiexec */
static int check_special_exe(const char *exe_path, int argc, char **argv, int exe_index)
{
    const char *basename = strrchr(exe_path, '/');
    if (!basename) basename = strrchr(exe_path, '\\');
    basename = basename ? basename + 1 : exe_path;

    /* Try VC++ Redistributable intercept */
    void *msi_so = dlopen("libpe_msi.so", RTLD_NOW);
    if (!msi_so) msi_so = dlopen("./dlls/libpe_msi.so", RTLD_NOW);
    if (msi_so) {
        /* Check vcredist intercept */
        vcredist_intercept_fn intercept = (vcredist_intercept_fn)dlsym(msi_so, "vcredist_installer_intercept");
        if (intercept) {
            /* Build command line for intercept */
            char cmdline[4096] = {0};
            size_t pos = 0;
            for (int i = exe_index; i < argc && pos < sizeof(cmdline) - 2; i++) {
                if (i > exe_index) cmdline[pos++] = ' ';
                size_t len = strlen(argv[i]);
                if (pos + len < sizeof(cmdline) - 1) {
                    memcpy(cmdline + pos, argv[i], len);
                    pos += len;
                }
            }
            if (intercept(exe_path, cmdline)) {
                printf("[peloader] VC++ Redistributable handled (our CRT stubs provide the functions)\n");
                dlclose(msi_so);
                return 0; /* success exit code */
            }
        }

        /* Check if target is msiexec.exe */
        if (strcasecmp(basename, "msiexec.exe") == 0) {
            msiexec_main_fn msi_main = (msiexec_main_fn)dlsym(msi_so, "msiexec_main");
            if (msi_main) {
                printf("[peloader] Detected msiexec.exe — using built-in MSI engine\n");
                int rc = msi_main(argc - exe_index, argv + exe_index);
                dlclose(msi_so);
                return rc;
            }
        }

        /* Pre-register VC++ redistributables for all PE loads */
        vcredist_register_fn reg = (vcredist_register_fn)dlsym(msi_so, "vcredist_ensure_registered");
        if (reg) reg();

        dlclose(msi_so);
    }

    return -1; /* not handled, proceed with normal PE loading */
}

#define VERSION "0.1.0"

static void print_usage(const char *progname)
{
    fprintf(stderr,
        "PE Loader v" VERSION " - Windows PE executable loader for Linux\n"
        "\n"
        "Usage: %s [options] <file.exe|file.sys> [args...]\n"
        "\n"
        "Options:\n"
        "  -v, --verbose    Enable verbose output\n"
        "  -d, --debug      Enable debug logging\n"
        "  -D, --diag       Run diagnostics (show import coverage) and exit\n"
        "  -t, --trace      Enable API call tracing\n"
        "  -h, --help       Show this help\n"
        "  --version        Show version\n"
        "\n", progname);
}

static void build_command_line(int argc, char **argv, int exe_index)
{
    /* Build a Windows-style command line from remaining args */
    char cmdline[32768];
    size_t pos = 0;

    for (int i = exe_index; i < argc && pos < sizeof(cmdline) - 2; i++) {
        if (i > exe_index && pos < sizeof(cmdline) - 1)
            cmdline[pos++] = ' ';

        /* Quote arguments containing spaces */
        int needs_quote = strchr(argv[i], ' ') != NULL;
        if (needs_quote && pos < sizeof(cmdline) - 1)
            cmdline[pos++] = '"';

        size_t len = strlen(argv[i]);
        if (pos + len < sizeof(cmdline) - 1) {
            memcpy(cmdline + pos, argv[i], len);
            pos += len;
        }

        if (needs_quote && pos < sizeof(cmdline) - 1)
            cmdline[pos++] = '"';
    }
    cmdline[pos] = '\0';

    kernel32_set_command_line(cmdline);
}

int main(int argc, char **argv)
{
    /* Unbuffered stdout/stderr so crash doesn't lose output */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    int verbose = 0;
    int debug = 0;
    int diag = 0;
    int trace = 0;

    static struct option long_options[] = {
        {"verbose", no_argument, 0, 'v'},
        {"debug",   no_argument, 0, 'd'},
        {"diag",    no_argument, 0, 'D'},
        {"trace",   no_argument, 0, 't'},
        {"help",    no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "+vdDth", long_options, NULL)) != -1) {
        switch (opt) {
        case 'v':
            verbose = 1;
            break;
        case 'd':
            debug = 1;
            break;
        case 'D':
            diag = 1;
            break;
        case 't':
            trace = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        case 'V':
            printf("peloader " VERSION "\n");
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: No PE executable specified\n\n");
        print_usage(argv[0]);
        return 1;
    }

    const char *exe_path = argv[optind];

    /* Early file existence check — gives a clear error before subsystem init */
    if (access(exe_path, R_OK) != 0) {
        fprintf(stderr, "[peloader] Cannot access '%s': %s\n", exe_path, strerror(errno));
        return 1;
    }

    /* --diag mode: analyze PE imports and exit */
    if (diag) {
        return pe_diag_report(exe_path);
    }

    /* --trace mode: enable API call tracing via environment variable */
    if (trace) {
        setenv("PE_DIAG", "1", 1);
    }

    /* Check for special executables (vcredist, msiexec) before PE loading */
    int special_rc = check_special_exe(exe_path, argc, argv, optind);
    if (special_rc >= 0) {
        return special_rc;
    }

    if (verbose || debug) {
        printf("[peloader] Loading: %s\n", exe_path);
    }

    /* Set up DLL search paths based on exe location */
    pe_import_set_exe_dir(exe_path);

    /* Step 0: Initialize subsystems */

    /* Connect to the object broker (pe-objectd) for cross-process named objects,
     * registry, and namespace resolution.  Non-fatal if the daemon isn't running;
     * callers fall back to local (intra-process) implementations. */
    if (objectd_connect() < 0) {
        if (verbose)
            printf("[peloader] Object broker not available (local fallback)\n");
    } else {
        if (verbose)
            printf("[peloader] Connected to object broker (%s)\n", OBJECTD_SOCK);
    }

    handle_table_init();
    anticheat_bridge_init();

    /* Step 1: Reserve address space */
    if (verbose)
        printf("[peloader] Step 1: Reserving address space...\n");
    if (preloader_reserve() < 0) {
        fprintf(stderr, "[peloader] WARNING: Could not reserve PE address space at 0x400000.\n"
                "  If the PE has no relocations, loading may fail.\n");
    }

    /* Step 2: Parse PE headers */
    if (verbose)
        printf("[peloader] Step 2: Parsing PE headers...\n");

    pe_image_t image;
    if (pe_parse_file(exe_path, &image) < 0) {
        fprintf(stderr, "[peloader] Failed to parse PE file: %s\n", exe_path);
        preloader_release();
        return 1;
    }

    if (debug) {
        printf("[peloader] Image base: 0x%lX\n", (unsigned long)image.image_base);
        printf("[peloader] Entry point RVA: 0x%08X\n", image.address_of_entry_point);
        printf("[peloader] Size of image: 0x%08X\n", image.size_of_image);
        printf("[peloader] Subsystem: %s (%u)\n",
               image.subsystem == PE_SUBSYSTEM_NATIVE ? "Native (Driver)" :
               image.subsystem == 3 ? "Console" :
               image.subsystem == 2 ? "GUI" : "Unknown",
               image.subsystem);
        printf("[peloader] Sections: %u\n", image.num_sections);
    }

    /* PE32 (32-bit) executables cannot run in our 64-bit process.
     *
     * S74 A1 Wine handoff shim: rather than hard-refuse, execve() Wine and
     * LD_PRELOAD a tiny shim (libtrust_wine_shim.so) that funnels open/openat/
     * execve syscalls through /dev/trust TRUST_IOC_CHECK_CAP before the
     * underlying glibc call.  This restores Steam + older game compatibility
     * while preserving trust gating end-to-end.  Set AICONTROL_NO_WINE=1 to
     * opt out and keep the legacy rejection behaviour.
     */
    if (!image.is_pe32plus) {
        const char *basename = strrchr(exe_path, '/');
        if (!basename) basename = strrchr(exe_path, '\\');
        basename = basename ? basename + 1 : exe_path;

        const char *no_wine = getenv("AICONTROL_NO_WINE");
        const char *wine_bin = getenv("AICONTROL_WINE_BIN");
        if (!wine_bin || !*wine_bin) wine_bin = "/usr/bin/wine";

        struct stat wst;
        int wine_usable = (!no_wine || !*no_wine) && stat(wine_bin, &wst) == 0 &&
                          (wst.st_mode & S_IXUSR);

        if (wine_usable) {
            if (verbose) {
                fprintf(stderr, "[peloader] PE32 detected (%s) -> Wine handoff via %s\n",
                        basename, wine_bin);
            }

            /* Free parser resources before execve (execve replaces the process
             * image, so strictly leaks are harmless, but be polite on any
             * error-return path below). */
            pe_image_free(&image);
            preloader_release();

            /* Build argv: [wine, exe_path, <original args>...]  Forward any
             * remaining positional args (argv[optind+1] onward) to the PE. */
            int forward_argc = (argc > optind + 1) ? (argc - optind - 1) : 0;
            char **wargv = (char **)calloc((size_t)forward_argc + 3, sizeof(char *));
            if (!wargv) {
                fprintf(stderr, "[peloader] calloc failed for Wine argv\n");
                return 1;
            }
            wargv[0] = (char *)wine_bin;
            wargv[1] = (char *)exe_path;
            for (int i = 0; i < forward_argc; i++) {
                wargv[2 + i] = argv[optind + 1 + i];
            }
            wargv[2 + forward_argc] = NULL;

            /* Advertise the caller pid so the shim can register the Wine
             * process as the same trust subject that the loader speaks for. */
            char pidbuf[32];
            snprintf(pidbuf, sizeof(pidbuf), "%d", (int)getpid());
            setenv("TRUST_SHIM_PID", pidbuf, 1);

            /* LD_PRELOAD the trust shim.  Prepend to any existing value so we
             * don't clobber user-supplied preloads. */
            const char *shim_path = getenv("AICONTROL_WINE_SHIM");
            if (!shim_path || !*shim_path)
                shim_path = "/usr/lib/libtrust_wine_shim.so";
            const char *cur_preload = getenv("LD_PRELOAD");
            if (cur_preload && *cur_preload) {
                size_t need = strlen(shim_path) + 1 + strlen(cur_preload) + 1;
                char *merged = (char *)malloc(need);
                if (merged) {
                    snprintf(merged, need, "%s:%s", shim_path, cur_preload);
                    setenv("LD_PRELOAD", merged, 1);
                    free(merged);
                }
            } else {
                setenv("LD_PRELOAD", shim_path, 1);
            }

            execv(wine_bin, wargv);
            /* execv only returns on failure. */
            fprintf(stderr, "[peloader] execv(%s) failed: %s\n",
                    wine_bin, strerror(errno));
            free(wargv);
            return 1;
        }

        /* Wine unavailable or explicitly disabled: legacy hard-refusal. */
        fprintf(stderr, "\n");
        fprintf(stderr, "Error: %s is a 32-bit (PE32) executable.\n", basename);
        fprintf(stderr, "This loader only supports 64-bit (PE32+/AMD64) executables.\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "  File:   %s\n", exe_path);
        fprintf(stderr, "  Magic:  0x10B (PE32 / i386)\n");
        fprintf(stderr, "  Need:   0x20B (PE32+ / AMD64)\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Alternatives:\n");
        fprintf(stderr, "  - Install wine + libtrust-wine-shim for trust-gated Wine handoff.\n");
        fprintf(stderr, "  - Try running this through Wine:  wine %s\n", basename);
        fprintf(stderr, "  - Download the 64-bit (x64) version of this program if available.\n");
        fprintf(stderr, "  - Use --diag to analyze import coverage without execution.\n");
        fprintf(stderr, "\n");
        pe_image_free(&image);
        preloader_release();
        return 66;
    }

    /* Count DLL imports from the PE import directory (for cortex request).
     * NOTE: This is an approximation.  The import directory size field
     * may include padding or be rounded up, so dividing by descriptor
     * size can overcount.  This value is used only for cortex telemetry
     * (informational), not for actual import resolution logic. */
    uint32_t pe_import_count = 0;
    {
        pe_data_directory_t *idir = &image.data_directory[PE_DIR_IMPORT];
        if (idir->virtual_address != 0 && idir->size >= sizeof(pe_import_descriptor_t)) {
            pe_import_count = idir->size / (uint32_t)sizeof(pe_import_descriptor_t);
            /* The table is terminated by an all-zero entry */
            if (pe_import_count > 0)
                pe_import_count--;
        }
    }

    /* Step 2b: Ask AI Cortex for permission to load this PE */
    cortex_pe_load_response_t cortex_response;
    int cortex_rc = cortex_request_pe_load(exe_path, image.subsystem,
                                            pe_import_count, &cortex_response);
    if (cortex_rc == 0 && cortex_response.verdict == CORTEX_VERDICT_DENY) {
        fprintf(stderr, "[peloader] DENIED by AI Cortex: %s\n",
                cortex_response.deny_reason);
        pe_image_free(&image);
        preloader_release();
        return 1;
    }
    if (cortex_rc == 0 && verbose) {
        printf("[peloader] Cortex approved: budget=%u, caps=0x%x, priority=%d\n",
               cortex_response.token_budget, cortex_response.capabilities,
               cortex_response.priority);
    }
    if (cortex_rc < 0 && verbose) {
        printf("[peloader] Cortex unavailable, using default budget\n");
    }

    /* Release the reservation at the PE's image base so we can map there */
    preloader_release_range(image.image_base, image.size_of_image);

    /* Step 3: Map sections */
    if (verbose)
        printf("[peloader] Step 3: Mapping sections...\n");

    if (pe_map_sections(&image) < 0) {
        fprintf(stderr, "[peloader] Failed to map PE sections\n");
        pe_image_free(&image);
        preloader_release();
        return 1;
    }

    /* Step 4: Apply relocations */
    if (verbose)
        printf("[peloader] Step 4: Applying relocations...\n");

    if (pe_apply_relocations(&image) < 0) {
        fprintf(stderr, "[peloader] Failed to apply relocations\n");
        pe_image_free(&image);
        preloader_release();
        return 1;
    }

    /* Step 5: Resolve imports */
    if (verbose)
        printf("[peloader] Step 5: Resolving imports...\n");

    if (pe_resolve_imports(&image) < 0) {
        fprintf(stderr, "[peloader] Failed to resolve imports\n");
        pe_image_free(&image);
        preloader_release();
        return 1;
    }

    /* Step 5a1: Patch common CRT function bodies in the IAT with our
     * SSE2/AVX2 optimized versions.  Must run BEFORE section protections
     * are restored so IAT pages are still writable. */
    {
        /* Build a short SHA-256-like hex key from the existing image
         * hash helper below.  A stronger hash would be ideal but the
         * Rolling FNV already used here is stable per-binary and good
         * enough as a cache key.  We format it into a hex-ish string
         * so the cache naming scheme matches the on-disk contract. */
        char patch_key[65] = {0};
        uint32_t key_hash = 0;
        FILE *kf = fopen(exe_path, "rb");
        if (kf) {
            uint8_t buf[4096];
            size_t n;
            uint64_t size_sum = 0;
            while ((n = fread(buf, 1, sizeof(buf), kf)) > 0) {
                for (size_t i = 0; i < n; i++)
                    key_hash = (key_hash * 31u) + buf[i];
                size_sum += n;
            }
            fclose(kf);
            /* 16 hex chars for hash + 16 hex chars for size -> 32 chars
             * + the binary's basename-hash gives enough uniqueness
             * across typical install sets. */
            snprintf(patch_key, sizeof(patch_key),
                     "%08x%08x%016llx%08x",
                     key_hash, (uint32_t)size_sum,
                     (unsigned long long)image.image_base,
                     (uint32_t)image.size_of_image);
            /* Pad out to 64 chars so the cache file name is uniform. */
            size_t klen = strlen(patch_key);
            while (klen < 64 && klen < sizeof(patch_key) - 1) {
                patch_key[klen++] = '0';
            }
            patch_key[64] = '\0';
        }
        pe_patch_init();
        int n_applied = pe_patch_apply(&image,
                                       patch_key[0] ? patch_key : NULL);
        if (verbose && n_applied > 0)
            printf("[peloader] pe_patch: %d CRT bodies patched\n", n_applied);
    }

    /* Step 5b: Restore per-section memory protections (relocation made everything RWX) */
    if (verbose)
        printf("[peloader] Step 5b: Restoring section protections...\n");
    pe_restore_section_protections(&image);

    /* Emit JSONL manifest of all PE imports for the AI stub discovery engine.
     * This runs after import resolution so the manifest captures resolved vs
     * unresolved status.  Written to /tmp/pe-imports-manifest.jsonl. */
    pe_import_emit_manifest(&image);

    /* Detect kernel-mode driver (.sys) */
    int is_driver = (image.subsystem == PE_SUBSYSTEM_NATIVE) ||
                    (image.file_header.characteristics & 0x1000 /* IMAGE_FILE_SYSTEM */);

    /* Register with Root of Trust */
    if (trust_init() == 0) {
        uint32_t pid = (uint32_t)getpid();
        uint32_t auth_level = is_driver ? TRUST_AUTH_SERVICE : TRUST_AUTH_USER;
        if (trust_register_subject(pid, TRUST_DOMAIN_WIN32, auth_level) == 0) {
            if (verbose)
                printf("[peloader] Trust: Registered PID %u in WIN32 domain (auth=%u)\n",
                       pid, auth_level);
        }
    } else {
        if (verbose)
            printf("[peloader] Trust: Module not available (running without trust)\n");
    }

    /* Initialize trust gate API interception layer */
    trust_gate_init();
    /* Compute a simple image hash from the PE file for trust registration */
    {
        uint32_t image_hash = 0;
        FILE *hf = fopen(exe_path, "rb");
        if (hf) {
            uint8_t buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), hf)) > 0) {
                for (size_t i = 0; i < n; i++)
                    image_hash = (image_hash * 31) + buf[i];
            }
            fclose(hf);
        }
        trust_gate_register_pe(exe_path, image_hash);
    }

    /* The cortex-assigned token_budget and capabilities are used below in the
     * PE_EVT_LOAD event emission. The trust kernel module manages actual token
     * accounting; the cortex budget informs initial allocation. */

    /* Initialize event bus (lock-free emission to AI Cortex) */
    pe_event_init();

    /* Initialize Windows Driver Model host */
    windrv_host_init();

    /* Release remaining reserved regions */
    preloader_release();

    void *entry = pe_get_entry_point(&image);
    if (!entry) {
        fprintf(stderr, "[peloader] Invalid entry point (RVA 0x%08X out of bounds)\n",
                image.address_of_entry_point);
        pe_image_free(&image);
        return 1;
    }

    int exit_code = 1;  /* Default to failure; overwritten by entry point return */
    struct timespec pe_start_ts;
    clock_gettime(CLOCK_MONOTONIC, &pe_start_ts);

    if (is_driver) {
        /*
         * ===== KERNEL DRIVER PATH =====
         *
         * Windows kernel drivers (.sys files) have:
         *   - Subsystem = NATIVE (1)
         *   - Entry: NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)
         *   - Import from ntoskrnl.exe, HAL.dll, NDIS.sys
         *
         * No PEB/TEB needed. No CRT initialization.
         */
        printf("[peloader] ========================================\n");
        printf("[peloader] Loading as Windows kernel driver (.sys)\n");
        printf("[peloader] ========================================\n");

        /* Extract driver name from filename */
        const char *basename = strrchr(exe_path, '/');
        if (!basename)
            basename = strrchr(exe_path, '\\');
        basename = basename ? basename + 1 : exe_path;

        /* Strip .sys extension for the driver name */
        char driver_name[256];
        strncpy(driver_name, basename, sizeof(driver_name) - 1);
        driver_name[sizeof(driver_name) - 1] = '\0';
        char *dot = strrchr(driver_name, '.');
        if (dot)
            *dot = '\0';

        printf("[peloader] Driver: %s\n", driver_name);
        printf("[peloader] Entry point: %p\n", entry);
        printf("[peloader] ----------------------------------------\n");

        exit_code = windrv_run_driver(&image, entry, driver_name);

    } else {
        /*
         * ===== USERSPACE EXE/DLL PATH =====
         */

        /* Initialize PEB/TEB environment */
        if (verbose)
            printf("[peloader] Step 5c: Setting up PEB/TEB...\n");
        env_setup_init(image.mapped_base, exe_path, argv[optind]);

        /* Register with anti-cheat bridge */
        anticheat_bridge_register_game(getpid(), exe_path);

        /* Verify PE image integrity via anti-cheat bridge */
        anticheat_bridge_check_integrity(image.mapped_base, image.size_of_image);

        /* Register the main executable in the PEB LDR module list */
        {
            const char *basename = strrchr(exe_path, '/');
            if (!basename)
                basename = strrchr(exe_path, '\\');
            basename = basename ? basename + 1 : exe_path;

            env_register_module(image.mapped_base, image.size_of_image,
                               pe_get_entry_point(&image),
                               exe_path, basename, 0 /* not a DLL */);
        }

        /* Initialize x64 SEH exception handling system */
        pe_exception_init();

        /* Register this PE image's .pdata for frame-based unwinding */
        pe_exception_register_image(&image);

        /* Install signal-based exception handlers (SEH/VEH) */
        ntdll_exception_init();

        /* Emit PE_EVT_LOAD event to AI Cortex */
        {
            pe_evt_load_t load_evt;
            memset(&load_evt, 0, sizeof(load_evt));
            strncpy(load_evt.exe_path, exe_path, sizeof(load_evt.exe_path) - 1);
            /* Import counts are logged by pe_resolve_imports but not exported;
             * the cortex can correlate with loader stdout if needed. */
            load_evt.imports_resolved = 0;
            load_evt.imports_unresolved = 0;
            trust_gate_get_score(&load_evt.trust_score);
            /* Use cortex-assigned budget if available, otherwise query trust */
            if (cortex_rc == 0 && cortex_response.token_budget > 0) {
                load_evt.token_budget = cortex_response.token_budget;
            } else {
                trust_gate_get_tokens(&load_evt.token_budget);
            }
            pe_event_emit(PE_EVT_LOAD, &load_evt, sizeof(load_evt));
        }

        /* Initialize Thread-Local Storage */
        if (verbose)
            printf("[peloader] Step 5d: Initializing TLS...\n");
        pe_tls_init(&image);

        /* Set up Windows environment */
        kernel32_set_module_filename(exe_path);
        build_command_line(argc, argv, optind);
        __pe_set_main_args(argc - optind, argv + optind, environ);

        printf("[peloader] Jumping to entry point at %p\n", entry);
        printf("[peloader] ----------------------------------------\n");

        if (image.file_header.characteristics & 0x2000 /* IMAGE_FILE_DLL */) {
            exit_code = (int)abi_call_win64_3(entry,
                (uint64_t)(uintptr_t)image.mapped_base,
                1, /* DLL_PROCESS_ATTACH */
                0);
        } else {
            /*
             * Pass argc/argv via RCX/RDX even for CRT entry points.
             * CRT startup (mainCRTStartup) ignores register args — it calls
             * __getmainargs internally. For non-CRT entry points that expect
             * main(argc, argv), this provides the correct arguments.
             * Passing unused register args is safe per the x64 calling convention.
             */
            exit_code = (int)abi_call_win64_2(entry,
                (uint64_t)(argc - optind),
                (uint64_t)(uintptr_t)(argv + optind));
        }

        printf("[peloader] ----------------------------------------\n");
        printf("[peloader] PE exited with code: %d\n", exit_code);
    }

    /* Emit PE_EVT_EXIT event to AI Cortex */
    {
        struct timespec pe_end_ts;
        clock_gettime(CLOCK_MONOTONIC, &pe_end_ts);
        uint32_t runtime_ms = (uint32_t)(
            (pe_end_ts.tv_sec - pe_start_ts.tv_sec) * 1000 +
            (pe_end_ts.tv_nsec - pe_start_ts.tv_nsec) / 1000000);

        pe_evt_exit_t exit_evt;
        memset(&exit_evt, 0, sizeof(exit_evt));
        exit_evt.exit_code  = (uint32_t)exit_code;
        exit_evt.runtime_ms = runtime_ms;
        exit_evt.stubs_called = 0;  /* Filled by stub report if available */
        pe_event_emit(PE_EVT_EXIT, &exit_evt, sizeof(exit_evt));
    }

    /* Record process exit and clean up trust */
    if (trust_available()) {
        uint32_t pid = (uint32_t)getpid();
        trust_record_action(pid, TRUST_ACTION_PROCESS_CREATE,
                            exit_code == 0 ? 0 : 1);
        trust_record_action(pid, TRUST_ACTION_FILE_OPEN, 0);
        trust_unregister_subject(pid);
        trust_cleanup();
    }

    /* Flush JSONL stub log with exit summary for the AI stub discovery engine */
    stub_log_summary();

    /* Print report of which unimplemented APIs were actually called */
    pe_import_print_stub_report();

    anticheat_bridge_shutdown();
    windrv_host_shutdown();
    pe_event_shutdown();
    trust_gate_shutdown();
    objectd_disconnect();
    pe_import_cleanup();
    pe_patch_shutdown();
    pe_image_free(&image);
    return exit_code;
}

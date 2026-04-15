/*
 * kernel32_toolhelp.c - Toolhelp32 snapshot / process / module / thread
 * enumeration.
 *
 * Implements the CreateToolhelp32Snapshot family used by anti-cheat, task
 * managers, and plenty of generic Win32 apps to walk the process/module/
 * thread universe.
 *
 * Strategy: at snapshot time we capture a point-in-time copy of the data
 * requested by the flag set by walking /proc (Linux live processes). Each
 * Process32/Module32/Thread32 iterator then advances through its own array
 * in the snapshot object. The snapshot is freed when the caller releases
 * the handle via CloseHandle, driven by the per-type destructor we register
 * at library load.
 *
 * We merge ntdll's fake Win10 process table (exposed via pe_fake_process_*)
 * into the /proc walk so that anti-cheat sees the same world no matter
 * which API it queries: NtQuerySystemInformation(SystemProcessInformation)
 * and Process32Next must agree, or the discrepancy itself is a red flag.
 * Fake PIDs live below 4821 and never collide with modern Linux PIDs; if
 * they do, the /proc entry wins (real beats synthetic). For fake PIDs the
 * module snapshot is filled from the fake kernel-module table so that
 * pid-keyed module walks don't come back empty.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>

#include "common/dll_common.h"
#include "kernel32_internal.h"

/* ---------- Accessors into ntdll's fake-table (SysV-ABI, internal) ----------
 * Defined at the end of pe-loader/dlls/ntdll/ntdll_main.c. We access the
 * fake Win10 process/module tables through getters so the struct layouts
 * stay private to ntdll. All accessors are 0-based; counts exclude the
 * NULL-name sentinel terminator. */
extern size_t pe_fake_process_count(void);
extern int    pe_fake_process_get(size_t idx, const char **name,
                                  uint32_t *pid, uint32_t *ppid,
                                  uint32_t *threads, uint32_t *session_id);
extern size_t pe_fake_kmod_count(void);
extern int    pe_fake_kmod_get(size_t idx, const char **name,
                               uint64_t *base, uint32_t *size);

/* ---------- Toolhelp32 constants (Win32 SDK values) ---------- */
#define TH32CS_SNAPHEAPLIST  0x00000001
#define TH32CS_SNAPPROCESS   0x00000002
#define TH32CS_SNAPTHREAD    0x00000004
#define TH32CS_SNAPMODULE    0x00000008
#define TH32CS_SNAPMODULE32  0x00000010
#define TH32CS_SNAPALL       (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | \
                              TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
#define TH32CS_INHERIT       0x80000000

#define INVALID_HANDLE_VALUE_TH ((HANDLE)(intptr_t)-1)

/* HANDLE_TYPE_TOOLHELP is provided by common/dll_common.h (value 26).
 * Guard against stale local copies of that header. */
#ifndef HANDLE_TYPE_TOOLHELP
#define HANDLE_TYPE_TOOLHELP 26
#endif

/* ---------- Windows Toolhelp32 struct layouts (x64, exact binary) ---------- */

/* PROCESSENTRY32W (Win32: tlhelp32.h). All fields pack to their natural
 * alignment on x64 (8-byte pointer-like fields get 8-byte alignment). */
typedef struct {
    DWORD   dwSize;
    DWORD   cntUsage;
    DWORD   th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD   th32ModuleID;
    DWORD   cntThreads;
    DWORD   th32ParentProcessID;
    LONG    pcPriClassBase;
    DWORD   dwFlags;
    WCHAR   szExeFile[260];      /* MAX_PATH */
} PROCESSENTRY32W_LOCAL;

typedef struct {
    DWORD   dwSize;
    DWORD   cntUsage;
    DWORD   th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD   th32ModuleID;
    DWORD   cntThreads;
    DWORD   th32ParentProcessID;
    LONG    pcPriClassBase;
    DWORD   dwFlags;
    CHAR    szExeFile[260];      /* MAX_PATH */
} PROCESSENTRY32A_LOCAL;

/* MODULEENTRY32W. Note the two fixed buffers: szModule[256], szExePath[260]. */
typedef struct {
    DWORD   dwSize;
    DWORD   th32ModuleID;
    DWORD   th32ProcessID;
    DWORD   GlblcntUsage;
    DWORD   ProccntUsage;
    BYTE   *modBaseAddr;
    DWORD   modBaseSize;
    HMODULE hModule;
    WCHAR   szModule[256];       /* MAX_MODULE_NAME32 + 1 */
    WCHAR   szExePath[260];      /* MAX_PATH */
} MODULEENTRY32W_LOCAL;

typedef struct {
    DWORD   dwSize;
    DWORD   th32ModuleID;
    DWORD   th32ProcessID;
    DWORD   GlblcntUsage;
    DWORD   ProccntUsage;
    BYTE   *modBaseAddr;
    DWORD   modBaseSize;
    HMODULE hModule;
    CHAR    szModule[256];
    CHAR    szExePath[260];
} MODULEENTRY32A_LOCAL;

/* THREADENTRY32 is shared between A and W (no string fields). */
typedef struct {
    DWORD   dwSize;
    DWORD   cntUsage;
    DWORD   th32ThreadID;
    DWORD   th32OwnerProcessID;
    LONG    tpBasePri;
    LONG    tpDeltaPri;
    DWORD   dwFlags;
} THREADENTRY32_LOCAL;

/* HEAPLIST32 / HEAPENTRY32 - defined only so we can report sensible sizes;
 * all heap walk exports are no-op stubs returning FALSE. */
typedef struct {
    SIZE_T  dwSize;
    DWORD   th32ProcessID;
    ULONG_PTR th32HeapID;
    DWORD   dwFlags;
} HEAPLIST32_LOCAL;

typedef struct {
    SIZE_T  dwSize;
    HANDLE  hHandle;
    ULONG_PTR dwAddress;
    SIZE_T  dwBlockSize;
    DWORD   dwFlags;
    DWORD   dwLockCount;
    DWORD   dwResvd;
    DWORD   th32ProcessID;
    ULONG_PTR th32HeapID;
} HEAPENTRY32_LOCAL;

/* ---------- Snapshot object ---------- */

typedef struct {
    int                     flags;        /* TH32CS_* as passed by caller */
    uint32_t                proc_count;
    uint32_t                proc_pos;
    PROCESSENTRY32W_LOCAL  *processes;
    uint32_t                mod_count;
    uint32_t                mod_pos;
    MODULEENTRY32W_LOCAL   *modules;
    uint32_t                thr_count;
    uint32_t                thr_pos;
    THREADENTRY32_LOCAL    *threads;
} toolhelp_snap_t;

/* ---------- Helpers ---------- */

static int is_all_digits(const char *s)
{
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++) {
        if (!isdigit((unsigned char)*p)) return 0;
    }
    return 1;
}

/* Read a small file fully into buf. Returns bytes read (0 on failure). */
static size_t read_small_file(const char *path, char *buf, size_t buf_size)
{
    if (buf_size == 0) return 0;
    FILE *f = fopen(path, "rb");
    if (!f) { buf[0] = '\0'; return 0; }
    size_t n = fread(buf, 1, buf_size - 1, f);
    fclose(f);
    buf[n] = '\0';
    return n;
}

/* Copy a narrow string into a fixed-size WCHAR buffer, null-terminating.
 * cap is the count of WCHARs in the destination buffer (including null). */
static void a2w_fixed(WCHAR *dst, size_t cap, const char *src)
{
    if (!dst || cap == 0) return;
    size_t i = 0;
    if (src) {
        for (; i + 1 < cap && src[i]; i++)
            dst[i] = (WCHAR)(unsigned char)src[i];
    }
    dst[i] = 0;
}

/* Convert a WCHAR buffer to narrow, null-terminating. cap is CHAR count. */
static void w2a_fixed(char *dst, size_t cap, const WCHAR *src)
{
    if (!dst || cap == 0) return;
    size_t i = 0;
    if (src) {
        for (; i + 1 < cap && src[i]; i++)
            dst[i] = (char)(src[i] & 0xFF);
    }
    dst[i] = '\0';
}

/* Parse /proc/<pid>/stat for comm (field 2, inside parentheses) and
 * ppid (field 4). Returns 1 on success. Handles processes whose comm
 * contains parentheses or whitespace by scanning from the last ')'. */
static int parse_proc_stat(pid_t pid, char *comm, size_t comm_size,
                           pid_t *out_ppid, long *out_nthreads)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    char buf[2048];
    size_t n = read_small_file(path, buf, sizeof(buf));
    if (n == 0) return 0;

    /* Find the opening '(' and LAST ')' */
    char *lparen = strchr(buf, '(');
    char *rparen = strrchr(buf, ')');
    if (!lparen || !rparen || rparen <= lparen) return 0;

    size_t clen = (size_t)(rparen - lparen - 1);
    if (clen >= comm_size) clen = comm_size - 1;
    memcpy(comm, lparen + 1, clen);
    comm[clen] = '\0';

    /* Field 3 is state, field 4 is ppid, field 20 is num_threads.
     * Scan after the closing paren. */
    char *p = rparen + 1;
    while (*p == ' ') p++;
    /* state */
    while (*p && *p != ' ') p++;
    while (*p == ' ') p++;
    /* ppid */
    long ppid = strtol(p, &p, 10);
    if (out_ppid) *out_ppid = (pid_t)ppid;

    /* Skip to field 20 (num_threads) - that's 16 more fields after ppid.
     * Fields: 4=ppid, 5=pgrp, 6=session, 7=tty_nr, 8=tpgid, 9=flags,
     *         10=minflt, 11=cminflt, 12=majflt, 13=cmajflt, 14=utime,
     *         15=stime, 16=cutime, 17=cstime, 18=priority, 19=nice,
     *         20=num_threads */
    for (int i = 0; i < 16; i++) {
        while (*p == ' ') p++;
        while (*p && *p != ' ') p++;
    }
    while (*p == ' ') p++;
    long nthreads = strtol(p, NULL, 10);
    if (out_nthreads) *out_nthreads = nthreads;
    return 1;
}

/* Resolve /proc/<pid>/exe -> path. Falls back to comm if readlink fails. */
static int resolve_proc_exe(pid_t pid, char *out, size_t out_size,
                            const char *comm_fallback)
{
    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/exe", (int)pid);
    ssize_t n = readlink(link, out, out_size - 1);
    if (n > 0) {
        out[n] = '\0';
        return 1;
    }
    /* Permission-denied / dead-process: synthesize a plausible name. */
    if (comm_fallback && *comm_fallback) {
        snprintf(out, out_size, "%s", comm_fallback);
    } else {
        snprintf(out, out_size, "[pid %d]", (int)pid);
    }
    return 0;
}

/* Extract trailing filename component from a path (handles both '/' and '\'). */
static const char *basename_of(const char *path)
{
    if (!path) return "";
    const char *last = path;
    for (const char *p = path; *p; p++) {
        if (*p == '/' || *p == '\\')
            last = p + 1;
    }
    return last;
}

/* ---------- Capture: processes via /proc ---------- */

static int capture_processes(toolhelp_snap_t *s)
{
    DIR *d = opendir("/proc");
    if (!d) return 0;

    /* Grow-on-demand vector. */
    size_t cap = 64;
    PROCESSENTRY32W_LOCAL *arr = calloc(cap, sizeof(*arr));
    if (!arr) { closedir(d); return 0; }
    size_t n = 0;

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!is_all_digits(e->d_name)) continue;
        pid_t pid = (pid_t)atoi(e->d_name);
        if (pid <= 0) continue;

        char comm[256] = {0};
        pid_t ppid = 0;
        long nthreads = 1;
        if (!parse_proc_stat(pid, comm, sizeof(comm), &ppid, &nthreads))
            continue; /* process exited mid-read: skip gracefully */

        char exe_path[PATH_MAX];
        resolve_proc_exe(pid, exe_path, sizeof(exe_path), comm);
        const char *leaf = basename_of(exe_path);
        /* Windows convention: if the leaf has no extension, append .exe so
         * anti-cheat pattern-matchers (often looking for ".exe" suffix)
         * don't reject us. Don't double-append. */
        char leaf_buf[260];
        if (strchr(leaf, '.')) {
            snprintf(leaf_buf, sizeof(leaf_buf), "%s", leaf);
        } else {
            snprintf(leaf_buf, sizeof(leaf_buf), "%s.exe", leaf);
        }

        if (n == cap) {
            size_t new_cap = cap * 2;
            PROCESSENTRY32W_LOCAL *grown = realloc(arr, new_cap * sizeof(*arr));
            if (!grown) break; /* stop growing; return what we have */
            memset(grown + cap, 0, (new_cap - cap) * sizeof(*arr));
            arr = grown;
            cap = new_cap;
        }

        PROCESSENTRY32W_LOCAL *pe = &arr[n++];
        pe->dwSize = sizeof(*pe);
        pe->cntUsage = 0;
        pe->th32ProcessID = (DWORD)pid;
        pe->th32DefaultHeapID = 0;
        pe->th32ModuleID = 0;
        pe->cntThreads = (DWORD)(nthreads > 0 ? nthreads : 1);
        pe->th32ParentProcessID = (DWORD)ppid;
        pe->pcPriClassBase = 8; /* NORMAL_PRIORITY_CLASS base */
        pe->dwFlags = 0;
        a2w_fixed(pe->szExeFile,
                  sizeof(pe->szExeFile) / sizeof(WCHAR),
                  leaf_buf);
    }
    closedir(d);

    /* Merge in the fake Win10 process table from ntdll so this snapshot
     * matches what NtQuerySystemInformation(SystemProcessInformation)
     * reports. Skip any fake PID that collided with a real /proc PID
     * (real beats synthetic — we never want duplicate th32ProcessID).
     * Real Linux user PIDs are almost always >> 4820, so collisions are
     * only possible for the kernel-only PIDs 0 and 4 which don't appear
     * in /proc anyway. */
    size_t fake_n = pe_fake_process_count();
    for (size_t fi = 0; fi < fake_n; fi++) {
        const char *fname = NULL;
        uint32_t fpid = 0, fppid = 0, fthreads = 0, fsid = 0;
        if (!pe_fake_process_get(fi, &fname, &fpid, &fppid, &fthreads, &fsid))
            continue;
        if (!fname) continue;

        /* Deduplicate against real /proc entries. */
        int dup = 0;
        for (size_t i = 0; i < n; i++) {
            if (arr[i].th32ProcessID == (DWORD)fpid) { dup = 1; break; }
        }
        if (dup) continue;

        if (n == cap) {
            size_t new_cap = cap * 2;
            PROCESSENTRY32W_LOCAL *grown = realloc(arr, new_cap * sizeof(*arr));
            if (!grown) break;
            memset(grown + cap, 0, (new_cap - cap) * sizeof(*arr));
            arr = grown;
            cap = new_cap;
        }

        PROCESSENTRY32W_LOCAL *pe = &arr[n++];
        pe->dwSize = sizeof(*pe);
        pe->cntUsage = 0;
        pe->th32ProcessID = (DWORD)fpid;
        pe->th32DefaultHeapID = 0;
        pe->th32ModuleID = 0;
        pe->cntThreads = (DWORD)(fthreads > 0 ? fthreads : 1);
        pe->th32ParentProcessID = (DWORD)fppid;
        pe->pcPriClassBase = 8;
        pe->dwFlags = 0;
        a2w_fixed(pe->szExeFile,
                  sizeof(pe->szExeFile) / sizeof(WCHAR),
                  fname);
    }

    s->processes = arr;
    s->proc_count = (uint32_t)n;
    s->proc_pos = 0;
    return 1;
}

/* ---------- fake-PID module fallback ----------
 * When capture_modules() is called for a fake Win10 PID (one from
 * g_fake_processes but not present in /proc), we fill the snapshot from
 * the fake kernel-module list instead of returning a lone "unknown.exe".
 * The fake kmods live in kernel-space addresses (0xFFFFF800_xxxx_xxxx),
 * which is the value anti-cheat code that already queried
 * NtQuerySystemInformation(SystemModuleInformation) expects to see. */
static int capture_fake_modules(toolhelp_snap_t *s, DWORD pid)
{
    size_t km_n = pe_fake_kmod_count();
    if (km_n == 0) return 0;
    MODULEENTRY32W_LOCAL *arr = calloc(km_n, sizeof(*arr));
    if (!arr) return 0;

    size_t out = 0;
    for (size_t i = 0; i < km_n; i++) {
        const char *kname = NULL;
        uint64_t kbase = 0;
        uint32_t ksize = 0;
        if (!pe_fake_kmod_get(i, &kname, &kbase, &ksize)) continue;
        if (!kname) continue;

        MODULEENTRY32W_LOCAL *m = &arr[out++];
        m->dwSize = sizeof(*m);
        m->th32ModuleID = (DWORD)(out);
        m->th32ProcessID = pid;
        m->GlblcntUsage = 0xFFFF;
        m->ProccntUsage = 1;
        m->modBaseAddr = (BYTE *)(uintptr_t)kbase;
        m->modBaseSize = (DWORD)ksize;
        m->hModule = (HMODULE)(uintptr_t)kbase;
        /* kname is a Windows NT path ("\SystemRoot\..\name.sys"); the
         * szModule leaf is the trailing filename component with either
         * separator. szExePath keeps the full NT path. */
        a2w_fixed(m->szModule, sizeof(m->szModule) / sizeof(WCHAR),
                  basename_of(kname));
        a2w_fixed(m->szExePath, sizeof(m->szExePath) / sizeof(WCHAR), kname);
    }

    s->modules = arr;
    s->mod_count = (uint32_t)out;
    s->mod_pos = 0;
    return 1;
}

/* Check whether `pid` corresponds to a fake Win10 process.  Cheap
 * linear scan -- the table has ~34 entries. */
static int is_fake_pid(DWORD pid)
{
    size_t n = pe_fake_process_count();
    for (size_t i = 0; i < n; i++) {
        uint32_t fpid = 0;
        if (!pe_fake_process_get(i, NULL, &fpid, NULL, NULL, NULL)) continue;
        if (fpid == pid) return 1;
    }
    return 0;
}

/* ---------- Capture: modules via /proc/<pid>/maps ---------- */

/* A line in /proc/pid/maps looks like:
 *   7f12a0000000-7f12a0021000 r-xp 00000000 fd:00 1234  /usr/lib/libfoo.so
 * We want entries that are file-backed and executable, one per unique path.
 * We accumulate the min start address and max end address across segments
 * of the same file to approximate modBaseAddr / modBaseSize. */
typedef struct {
    char     path[PATH_MAX];
    uint64_t base;
    uint64_t end;
} mod_span_t;

static int capture_modules(toolhelp_snap_t *s, DWORD pid)
{
    if (pid == 0) pid = (DWORD)getpid();

    /* If caller asked about a fake Win10 PID (one from ntdll's fake
     * process table), serve modules from the fake kernel-module list so
     * the two data paths (NtQuerySystemInformation vs Toolhelp32) agree.
     * Route through capture_fake_modules even before attempting /proc —
     * a fake PID number might coincidentally exist on the host and we
     * don't want to return the host process's real modules for it. */
    if (is_fake_pid(pid))
        return capture_fake_modules(s, pid);

    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/maps", (unsigned)pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        /* ENOENT (process exited) / EACCES (no permission): synthesize a
         * single entry for the main image so callers that only need the
         * exe module (common in anti-cheat) still get something usable. */
        s->modules = calloc(1, sizeof(*s->modules));
        if (!s->modules) return 0;
        MODULEENTRY32W_LOCAL *m = &s->modules[0];
        m->dwSize = sizeof(*m);
        m->th32ProcessID = pid;
        m->GlblcntUsage = 0xFFFF;
        m->ProccntUsage = 1;
        m->modBaseAddr = NULL;
        m->modBaseSize = 0x1000;
        m->hModule = NULL;
        a2w_fixed(m->szModule, sizeof(m->szModule) / sizeof(WCHAR), "unknown.exe");
        a2w_fixed(m->szExePath, sizeof(m->szExePath) / sizeof(WCHAR), "unknown.exe");
        s->mod_count = 1;
        s->mod_pos = 0;
        return 1;
    }

    size_t cap = 64;
    mod_span_t *spans = calloc(cap, sizeof(*spans));
    if (!spans) { fclose(f); return 0; }
    size_t n = 0;

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        uint64_t start = 0, end = 0;
        char perms[8] = {0};
        /* Format: START-END PERMS OFFSET DEV INODE  PATH */
        int consumed = 0;
        if (sscanf(line, "%" PRIx64 "-%" PRIx64 " %7s %*s %*s %*s%n",
                   &start, &end, perms, &consumed) < 3)
            continue;

        /* Only executable file-backed mappings count as "modules". */
        if (!strchr(perms, 'x')) continue;

        /* Path starts after the 5 numeric columns, optionally preceded by
         * whitespace. sscanf already consumed up to (and including) the
         * inode; the rest of the line is the path. */
        char *p = line + consumed;
        while (*p == ' ' || *p == '\t') p++;
        /* Strip trailing newline */
        size_t plen = strlen(p);
        while (plen > 0 && (p[plen - 1] == '\n' || p[plen - 1] == '\r'))
            p[--plen] = '\0';
        if (plen == 0) continue;
        /* Skip pseudo-files like [vdso], [heap], [stack] */
        if (p[0] == '[') continue;
        /* /proc/<pid>/maps appends " (deleted)" to paths whose backing
         * file was unlinked after mmap. Strip it so (a) our dedup by
         * path works, and (b) the main-exe match against /proc/<pid>/exe
         * (which returns the original path even after delete) succeeds. */
        const char *del_suffix = " (deleted)";
        size_t del_len = 10; /* strlen(" (deleted)") */
        if (plen >= del_len &&
            memcmp(p + plen - del_len, del_suffix, del_len) == 0) {
            plen -= del_len;
            p[plen] = '\0';
        }
        if (plen == 0) continue;

        /* Deduplicate by path - extend span if we've seen this file already. */
        int found = -1;
        for (size_t i = 0; i < n; i++) {
            if (strcmp(spans[i].path, p) == 0) { found = (int)i; break; }
        }
        if (found >= 0) {
            if (start < spans[found].base) spans[found].base = start;
            if (end > spans[found].end)    spans[found].end = end;
            continue;
        }

        if (n == cap) {
            size_t new_cap = cap * 2;
            mod_span_t *grown = realloc(spans, new_cap * sizeof(*spans));
            if (!grown) break;
            memset(grown + cap, 0, (new_cap - cap) * sizeof(*spans));
            spans = grown;
            cap = new_cap;
        }
        snprintf(spans[n].path, sizeof(spans[n].path), "%s", p);
        spans[n].base = start;
        spans[n].end = end;
        n++;
    }
    fclose(f);

    /* Materialize into MODULEENTRY32W array. Reorder so main exe is first
     * (Windows contract: Module32First returns the .exe of the process). */
    MODULEENTRY32W_LOCAL *arr = calloc(n > 0 ? n : 1, sizeof(*arr));
    if (!arr) { free(spans); return 0; }

    /* Find the main-exe span by checking /proc/pid/exe's target. */
    char exe_link[64];
    snprintf(exe_link, sizeof(exe_link), "/proc/%u/exe", (unsigned)pid);
    char exe_target[PATH_MAX] = {0};
    ssize_t el = readlink(exe_link, exe_target, sizeof(exe_target) - 1);
    if (el > 0) exe_target[el] = '\0';

    int main_idx = -1;
    for (size_t i = 0; i < n; i++) {
        if (exe_target[0] && strcmp(spans[i].path, exe_target) == 0) {
            main_idx = (int)i;
            break;
        }
    }

    size_t out = 0;
    if (main_idx >= 0) {
        MODULEENTRY32W_LOCAL *m = &arr[out++];
        m->dwSize = sizeof(*m);
        m->th32ModuleID = 1;
        m->th32ProcessID = pid;
        m->GlblcntUsage = 0xFFFF;
        m->ProccntUsage = 1;
        m->modBaseAddr = (BYTE *)(uintptr_t)spans[main_idx].base;
        m->modBaseSize = (DWORD)(spans[main_idx].end - spans[main_idx].base);
        m->hModule = (HMODULE)(uintptr_t)spans[main_idx].base;
        a2w_fixed(m->szModule, sizeof(m->szModule) / sizeof(WCHAR),
                  basename_of(spans[main_idx].path));
        a2w_fixed(m->szExePath, sizeof(m->szExePath) / sizeof(WCHAR),
                  spans[main_idx].path);
    }
    for (size_t i = 0; i < n; i++) {
        if ((int)i == main_idx) continue;
        MODULEENTRY32W_LOCAL *m = &arr[out++];
        m->dwSize = sizeof(*m);
        m->th32ModuleID = (DWORD)(out); /* non-zero synthetic id */
        m->th32ProcessID = pid;
        m->GlblcntUsage = 0xFFFF;
        m->ProccntUsage = 1;
        m->modBaseAddr = (BYTE *)(uintptr_t)spans[i].base;
        m->modBaseSize = (DWORD)(spans[i].end - spans[i].base);
        m->hModule = (HMODULE)(uintptr_t)spans[i].base;
        a2w_fixed(m->szModule, sizeof(m->szModule) / sizeof(WCHAR),
                  basename_of(spans[i].path));
        a2w_fixed(m->szExePath, sizeof(m->szExePath) / sizeof(WCHAR),
                  spans[i].path);
    }
    free(spans);

    s->modules = arr;
    s->mod_count = (uint32_t)out;
    s->mod_pos = 0;
    return 1;
}

/* ---------- Capture: threads via /proc/<pid>/task/ ---------- */

/* If a specific PID is given, enumerate only its tasks. Otherwise walk
 * every /proc/<pid>/task. Windows semantics: TH32CS_SNAPTHREAD ignores
 * th32ProcessID (system-wide); callers filter by comparing
 * th32OwnerProcessID against the PID they want. We honor that. */
static int capture_threads(toolhelp_snap_t *s)
{
    DIR *d = opendir("/proc");
    if (!d) return 0;

    size_t cap = 128;
    THREADENTRY32_LOCAL *arr = calloc(cap, sizeof(*arr));
    if (!arr) { closedir(d); return 0; }
    size_t n = 0;

    struct dirent *pe;
    while ((pe = readdir(d)) != NULL) {
        if (!is_all_digits(pe->d_name)) continue;
        pid_t pid = (pid_t)atoi(pe->d_name);
        if (pid <= 0) continue;

        char task_path[64];
        snprintf(task_path, sizeof(task_path), "/proc/%d/task", (int)pid);
        DIR *td = opendir(task_path);
        if (!td) continue; /* Process exited or no permission: skip. */

        struct dirent *te;
        while ((te = readdir(td)) != NULL) {
            if (!is_all_digits(te->d_name)) continue;
            pid_t tid = (pid_t)atoi(te->d_name);
            if (tid <= 0) continue;

            if (n == cap) {
                size_t new_cap = cap * 2;
                THREADENTRY32_LOCAL *grown = realloc(arr, new_cap * sizeof(*arr));
                if (!grown) { /* stop growing, keep what we have */
                    break;
                }
                memset(grown + cap, 0, (new_cap - cap) * sizeof(*arr));
                arr = grown;
                cap = new_cap;
            }

            THREADENTRY32_LOCAL *t = &arr[n++];
            t->dwSize = sizeof(*t);
            t->cntUsage = 0;
            t->th32ThreadID = (DWORD)tid;
            t->th32OwnerProcessID = (DWORD)pid;
            t->tpBasePri = 8;   /* NORMAL */
            t->tpDeltaPri = 0;
            t->dwFlags = 0;
        }
        closedir(td);
    }
    closedir(d);

    s->threads = arr;
    s->thr_count = (uint32_t)n;
    s->thr_pos = 0;
    return 1;
}

/* ---------- Destructor ---------- */

static void toolhelp_destroy(const handle_entry_t *entry)
{
    if (!entry || !entry->data) return;
    toolhelp_snap_t *s = (toolhelp_snap_t *)entry->data;
    free(s->processes);
    free(s->modules);
    free(s->threads);
    free(s);
}

__attribute__((constructor))
static void kernel32_toolhelp_register(void)
{
    handle_register_dtor((handle_type_t)HANDLE_TYPE_TOOLHELP, toolhelp_destroy);
}

/* Safely fetch snapshot from a handle. Returns NULL if handle is not a
 * toolhelp snapshot. Sets last error. */
static toolhelp_snap_t *snap_from_handle(HANDLE h)
{
    if (h == NULL || h == INVALID_HANDLE_VALUE_TH) {
        set_last_error(ERROR_INVALID_HANDLE);
        return NULL;
    }
    handle_entry_t *e = handle_lookup(h);
    if (!e || (int)e->type != HANDLE_TYPE_TOOLHELP || !e->data) {
        set_last_error(ERROR_INVALID_HANDLE);
        return NULL;
    }
    return (toolhelp_snap_t *)e->data;
}

/* ---------- Public exports ---------- */

WINAPI_EXPORT HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
{
    toolhelp_snap_t *s = calloc(1, sizeof(*s));
    if (!s) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return INVALID_HANDLE_VALUE_TH;
    }
    s->flags = (int)dwFlags;

    if (dwFlags & TH32CS_SNAPPROCESS) {
        if (!capture_processes(s)) {
            free(s->processes); s->processes = NULL;
        }
    }
    if (dwFlags & (TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32)) {
        if (!capture_modules(s, th32ProcessID)) {
            free(s->modules); s->modules = NULL;
        }
    }
    if (dwFlags & TH32CS_SNAPTHREAD) {
        if (!capture_threads(s)) {
            free(s->threads); s->threads = NULL;
        }
    }
    /* TH32CS_SNAPHEAPLIST is accepted but we produce no entries (see below). */

    HANDLE h = handle_alloc((handle_type_t)HANDLE_TYPE_TOOLHELP, -1, s);
    if (!h) {
        free(s->processes); free(s->modules); free(s->threads);
        free(s);
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return INVALID_HANDLE_VALUE_TH;
    }
    return h;
}

/* ---------- Process32 ---------- */

WINAPI_EXPORT BOOL Process32FirstW(HANDLE hSnapshot, PROCESSENTRY32W_LOCAL *lppe)
{
    if (!lppe) { set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (lppe->dwSize < sizeof(*lppe)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    toolhelp_snap_t *s = snap_from_handle(hSnapshot);
    if (!s) return FALSE;
    if (!s->processes || s->proc_count == 0) {
        set_last_error(ERROR_NO_MORE_FILES);
        return FALSE;
    }
    s->proc_pos = 0;
    DWORD caller_size = lppe->dwSize;
    *lppe = s->processes[0];
    lppe->dwSize = caller_size; /* preserve caller's declared size */
    s->proc_pos = 1;
    return TRUE;
}

WINAPI_EXPORT BOOL Process32NextW(HANDLE hSnapshot, PROCESSENTRY32W_LOCAL *lppe)
{
    if (!lppe) { set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (lppe->dwSize < sizeof(*lppe)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    toolhelp_snap_t *s = snap_from_handle(hSnapshot);
    if (!s) return FALSE;
    if (!s->processes || s->proc_pos >= s->proc_count) {
        set_last_error(ERROR_NO_MORE_FILES);
        return FALSE;
    }
    DWORD caller_size = lppe->dwSize;
    *lppe = s->processes[s->proc_pos++];
    lppe->dwSize = caller_size;
    return TRUE;
}

/* ANSI variants: convert from our internal W representation into the
 * caller's A structure. Callers still set dwSize = sizeof(PROCESSENTRY32A). */
WINAPI_EXPORT BOOL Process32First(HANDLE hSnapshot, PROCESSENTRY32A_LOCAL *lppe)
{
    if (!lppe) { set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (lppe->dwSize < sizeof(*lppe)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    toolhelp_snap_t *s = snap_from_handle(hSnapshot);
    if (!s) return FALSE;
    if (!s->processes || s->proc_count == 0) {
        set_last_error(ERROR_NO_MORE_FILES);
        return FALSE;
    }
    PROCESSENTRY32W_LOCAL *src = &s->processes[0];
    DWORD caller_size = lppe->dwSize;
    memset(lppe, 0, sizeof(*lppe));
    lppe->dwSize = caller_size;
    lppe->cntUsage = src->cntUsage;
    lppe->th32ProcessID = src->th32ProcessID;
    lppe->th32DefaultHeapID = src->th32DefaultHeapID;
    lppe->th32ModuleID = src->th32ModuleID;
    lppe->cntThreads = src->cntThreads;
    lppe->th32ParentProcessID = src->th32ParentProcessID;
    lppe->pcPriClassBase = src->pcPriClassBase;
    lppe->dwFlags = src->dwFlags;
    w2a_fixed(lppe->szExeFile, sizeof(lppe->szExeFile), src->szExeFile);
    s->proc_pos = 1;
    return TRUE;
}

WINAPI_EXPORT BOOL Process32Next(HANDLE hSnapshot, PROCESSENTRY32A_LOCAL *lppe)
{
    if (!lppe) { set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (lppe->dwSize < sizeof(*lppe)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    toolhelp_snap_t *s = snap_from_handle(hSnapshot);
    if (!s) return FALSE;
    if (!s->processes || s->proc_pos >= s->proc_count) {
        set_last_error(ERROR_NO_MORE_FILES);
        return FALSE;
    }
    PROCESSENTRY32W_LOCAL *src = &s->processes[s->proc_pos++];
    DWORD caller_size = lppe->dwSize;
    memset(lppe, 0, sizeof(*lppe));
    lppe->dwSize = caller_size;
    lppe->cntUsage = src->cntUsage;
    lppe->th32ProcessID = src->th32ProcessID;
    lppe->th32DefaultHeapID = src->th32DefaultHeapID;
    lppe->th32ModuleID = src->th32ModuleID;
    lppe->cntThreads = src->cntThreads;
    lppe->th32ParentProcessID = src->th32ParentProcessID;
    lppe->pcPriClassBase = src->pcPriClassBase;
    lppe->dwFlags = src->dwFlags;
    w2a_fixed(lppe->szExeFile, sizeof(lppe->szExeFile), src->szExeFile);
    return TRUE;
}

/* ---------- Module32 ---------- */

WINAPI_EXPORT BOOL Module32FirstW(HANDLE hSnapshot, MODULEENTRY32W_LOCAL *lpme)
{
    if (!lpme) { set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (lpme->dwSize < sizeof(*lpme)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    toolhelp_snap_t *s = snap_from_handle(hSnapshot);
    if (!s) return FALSE;
    if (!s->modules || s->mod_count == 0) {
        set_last_error(ERROR_NO_MORE_FILES);
        return FALSE;
    }
    DWORD caller_size = lpme->dwSize;
    *lpme = s->modules[0];
    lpme->dwSize = caller_size;
    s->mod_pos = 1;
    return TRUE;
}

WINAPI_EXPORT BOOL Module32NextW(HANDLE hSnapshot, MODULEENTRY32W_LOCAL *lpme)
{
    if (!lpme) { set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (lpme->dwSize < sizeof(*lpme)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    toolhelp_snap_t *s = snap_from_handle(hSnapshot);
    if (!s) return FALSE;
    if (!s->modules || s->mod_pos >= s->mod_count) {
        set_last_error(ERROR_NO_MORE_FILES);
        return FALSE;
    }
    DWORD caller_size = lpme->dwSize;
    *lpme = s->modules[s->mod_pos++];
    lpme->dwSize = caller_size;
    return TRUE;
}

WINAPI_EXPORT BOOL Module32First(HANDLE hSnapshot, MODULEENTRY32A_LOCAL *lpme)
{
    if (!lpme) { set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (lpme->dwSize < sizeof(*lpme)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    toolhelp_snap_t *s = snap_from_handle(hSnapshot);
    if (!s) return FALSE;
    if (!s->modules || s->mod_count == 0) {
        set_last_error(ERROR_NO_MORE_FILES);
        return FALSE;
    }
    MODULEENTRY32W_LOCAL *src = &s->modules[0];
    DWORD caller_size = lpme->dwSize;
    memset(lpme, 0, sizeof(*lpme));
    lpme->dwSize = caller_size;
    lpme->th32ModuleID = src->th32ModuleID;
    lpme->th32ProcessID = src->th32ProcessID;
    lpme->GlblcntUsage = src->GlblcntUsage;
    lpme->ProccntUsage = src->ProccntUsage;
    lpme->modBaseAddr = src->modBaseAddr;
    lpme->modBaseSize = src->modBaseSize;
    lpme->hModule = src->hModule;
    w2a_fixed(lpme->szModule, sizeof(lpme->szModule), src->szModule);
    w2a_fixed(lpme->szExePath, sizeof(lpme->szExePath), src->szExePath);
    s->mod_pos = 1;
    return TRUE;
}

WINAPI_EXPORT BOOL Module32Next(HANDLE hSnapshot, MODULEENTRY32A_LOCAL *lpme)
{
    if (!lpme) { set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (lpme->dwSize < sizeof(*lpme)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    toolhelp_snap_t *s = snap_from_handle(hSnapshot);
    if (!s) return FALSE;
    if (!s->modules || s->mod_pos >= s->mod_count) {
        set_last_error(ERROR_NO_MORE_FILES);
        return FALSE;
    }
    MODULEENTRY32W_LOCAL *src = &s->modules[s->mod_pos++];
    DWORD caller_size = lpme->dwSize;
    memset(lpme, 0, sizeof(*lpme));
    lpme->dwSize = caller_size;
    lpme->th32ModuleID = src->th32ModuleID;
    lpme->th32ProcessID = src->th32ProcessID;
    lpme->GlblcntUsage = src->GlblcntUsage;
    lpme->ProccntUsage = src->ProccntUsage;
    lpme->modBaseAddr = src->modBaseAddr;
    lpme->modBaseSize = src->modBaseSize;
    lpme->hModule = src->hModule;
    w2a_fixed(lpme->szModule, sizeof(lpme->szModule), src->szModule);
    w2a_fixed(lpme->szExePath, sizeof(lpme->szExePath), src->szExePath);
    return TRUE;
}

/* ---------- Thread32 ---------- */

WINAPI_EXPORT BOOL Thread32First(HANDLE hSnapshot, THREADENTRY32_LOCAL *lpte)
{
    if (!lpte) { set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (lpte->dwSize < sizeof(*lpte)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    toolhelp_snap_t *s = snap_from_handle(hSnapshot);
    if (!s) return FALSE;
    if (!s->threads || s->thr_count == 0) {
        set_last_error(ERROR_NO_MORE_FILES);
        return FALSE;
    }
    DWORD caller_size = lpte->dwSize;
    *lpte = s->threads[0];
    lpte->dwSize = caller_size;
    s->thr_pos = 1;
    return TRUE;
}

WINAPI_EXPORT BOOL Thread32Next(HANDLE hSnapshot, THREADENTRY32_LOCAL *lpte)
{
    if (!lpte) { set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (lpte->dwSize < sizeof(*lpte)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    toolhelp_snap_t *s = snap_from_handle(hSnapshot);
    if (!s) return FALSE;
    if (!s->threads || s->thr_pos >= s->thr_count) {
        set_last_error(ERROR_NO_MORE_FILES);
        return FALSE;
    }
    DWORD caller_size = lpte->dwSize;
    *lpte = s->threads[s->thr_pos++];
    lpte->dwSize = caller_size;
    return TRUE;
}

/* ---------- Heap32* stubs ---------- */
/* We don't expose the per-process heap structure; callers expecting to
 * walk heap entries get an empty list (ERROR_NO_MORE_FILES on First). */

WINAPI_EXPORT BOOL Heap32ListFirst(HANDLE hSnapshot, HEAPLIST32_LOCAL *lphl)
{
    (void)hSnapshot; (void)lphl;
    set_last_error(ERROR_NO_MORE_FILES);
    return FALSE;
}

WINAPI_EXPORT BOOL Heap32ListNext(HANDLE hSnapshot, HEAPLIST32_LOCAL *lphl)
{
    (void)hSnapshot; (void)lphl;
    set_last_error(ERROR_NO_MORE_FILES);
    return FALSE;
}

WINAPI_EXPORT BOOL Heap32First(HEAPENTRY32_LOCAL *lphe, DWORD th32ProcessID,
                                ULONG_PTR th32HeapID)
{
    (void)lphe; (void)th32ProcessID; (void)th32HeapID;
    set_last_error(ERROR_NO_MORE_FILES);
    return FALSE;
}

WINAPI_EXPORT BOOL Heap32Next(HEAPENTRY32_LOCAL *lphe)
{
    (void)lphe;
    set_last_error(ERROR_NO_MORE_FILES);
    return FALSE;
}

WINAPI_EXPORT BOOL Toolhelp32ReadProcessMemory(DWORD th32ProcessID,
                                                const void *lpBaseAddress,
                                                void *lpBuffer,
                                                SIZE_T cbRead,
                                                SIZE_T *lpNumberOfBytesRead)
{
    (void)th32ProcessID; (void)lpBaseAddress; (void)lpBuffer; (void)cbRead;
    if (lpNumberOfBytesRead) *lpNumberOfBytesRead = 0;
    set_last_error(ERROR_NO_MORE_FILES);
    return FALSE;
}

/*
 * wbem_providers.c - back the common Win32_* classes from /proc + /sys
 *
 * Each provider builds an array of WbemClassObject* (refcount +1 each),
 * filters according to q->where_*, and wraps the survivors in a
 * WbemEnum.  On any read failure we still return a valid (possibly
 * empty) enum -- partial answers beat hard failures because some
 * consumers treat ExecQuery failure as "WMI broken" and abort.
 *
 * Classes implemented:
 *   Win32_OperatingSystem            (1 row)
 *   Win32_Processor                  (N rows, one per logical CPU)
 *   Win32_Process                    (N rows from /proc/[pid])
 *   Win32_Service                    (N rows from systemctl)
 *   Win32_LogicalDisk                (N rows from /proc/mounts)
 *   Win32_NetworkAdapter[Configuration] (N rows from /sys/class/net)
 *   Win32_BIOS                       (1 row from /sys/class/dmi/id/bios_*)
 *   Win32_ComputerSystem(Product)    (1 row, hostname + dmi sys vendor)
 */

#define _GNU_SOURCE
#include "wbem_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/statvfs.h>

/* ---- small file helpers ----------------------------------------- */

/* Slurp a whole file into a heap buffer.  Returns NULL on any error.
 * Caller free()s.  Bound at 64 KiB to keep WMI queries cheap. */
static char *slurp(const char *path, size_t *out_len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { if (out_len) *out_len = 0; return NULL; }
    char *buf = (char *)malloc(65537);
    if (!buf) { close(fd); if (out_len) *out_len = 0; return NULL; }
    ssize_t n = read(fd, buf, 65536);
    close(fd);
    if (n <= 0) { free(buf); if (out_len) *out_len = 0; return NULL; }
    buf[n] = '\0';
    if (out_len) *out_len = (size_t)n;
    return buf;
}

/* Slurp a one-line file and strip trailing whitespace.  Returns "" on
 * failure (caller should still free). */
static char *slurp_line(const char *path)
{
    size_t n = 0;
    char *s = slurp(path, &n);
    if (!s) { s = (char *)malloc(1); if (s) s[0] = '\0'; return s; }
    /* Trim trailing CR/LF/whitespace. */
    while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r' || s[n-1] == ' ' || s[n-1] == '\t')) {
        s[--n] = '\0';
    }
    return s;
}

/* Find "Key:" line in /proc/meminfo-style buffer.  Returns numeric value
 * (kB units preserved, caller must convert).  -1 on miss. */
static long find_kv_long(const char *buf, const char *key)
{
    if (!buf) return -1;
    size_t klen = strlen(key);
    const char *p = buf;
    while (*p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == ':') {
            const char *q = p + klen + 1;
            while (*q == ' ' || *q == '\t') q++;
            return atol(q);
        }
        const char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    return -1;
}

/* Pull "Key: value" string from a key:value file; caller free()s.  NULL
 * on miss. */
static char *find_kv_str(const char *buf, const char *key)
{
    if (!buf) return NULL;
    size_t klen = strlen(key);
    const char *p = buf;
    while (*p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == ':') {
            const char *q = p + klen + 1;
            while (*q == ' ' || *q == '\t') q++;
            const char *nl = strchr(q, '\n');
            size_t L = nl ? (size_t)(nl - q) : strlen(q);
            char *out = (char *)malloc(L + 1);
            if (!out) return NULL;
            memcpy(out, q, L);
            out[L] = '\0';
            /* Strip trailing whitespace. */
            while (L > 0 && (out[L-1] == ' ' || out[L-1] == '\t' || out[L-1] == '\r'))
                out[--L] = '\0';
            return out;
        }
        const char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    return NULL;
}

/* Count digits-only entries in a directory.  Returns 0 on dir-not-found. */
static int dir_count_pids(const char *path)
{
    DIR *d = opendir(path);
    if (!d) return 0;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        const char *p = e->d_name;
        int is_num = 1;
        while (*p) { if (!isdigit((unsigned char)*p)) { is_num = 0; break; } p++; }
        if (is_num && e->d_name[0]) n++;
    }
    closedir(d);
    return n;
}

/* Format a Linux `time_t` as a CIM datetime (yyyymmddHHMMSS.ffffff+zzz).
 * The buffer must be >= 26 bytes. */
static void cim_datetime(time_t t, char *out, size_t cap)
{
    struct tm tmv;
    if (!localtime_r(&t, &tmv)) { snprintf(out, cap, "00000000000000.000000+000"); return; }
    /* GMT offset in minutes -- glibc tm_gmtoff is in seconds east of UTC. */
    long off_min = tmv.tm_gmtoff / 60;
    snprintf(out, cap, "%04d%02d%02d%02d%02d%02d.000000%+04ld",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec, off_min);
}

/* Filter+wrap helper: pushes row into rows[] iff matches WHERE; on push
 * failure, releases row. */
static void push_if_match(WbemClassObject ***rows, int *n, int *cap,
                          WbemClassObject *row, const wbem_query_t *q)
{
    if (!row) return;
    if (!wbem_row_matches_where(row, q)) {
        row->vtbl->Release(row);
        return;
    }
    if (*n >= *cap) {
        int new_cap = (*cap == 0) ? 16 : (*cap * 2);
        WbemClassObject **nr = (WbemClassObject **)realloc(*rows,
                                          (size_t)new_cap * sizeof(WbemClassObject *));
        if (!nr) { row->vtbl->Release(row); return; }
        *rows = nr;
        *cap = new_cap;
    }
    (*rows)[(*n)++] = row;
}

/* ================================================================== */
/* Win32_OperatingSystem                                              */
/* ================================================================== */
WbemEnum *wbem_provider_os(const wbem_query_t *q)
{
    WbemClassObject *o = wbem_classobject_new("Win32_OperatingSystem");
    if (!o) return NULL;

    /* /etc/os-release: PRETTY_NAME, VERSION_ID, ID */
    char *osrel = slurp("/etc/os-release", NULL);
    char *pretty = NULL, *verid = NULL;
    if (osrel) {
        /* parse VAR=VALUE lines (VALUE may be quoted). */
        char *line = osrel;
        while (line && *line) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            char *eq = strchr(line, '=');
            if (eq) {
                *eq = '\0';
                char *val = eq + 1;
                if (*val == '"') {
                    val++;
                    char *end = strchr(val, '"');
                    if (end) *end = '\0';
                }
                if (strcmp(line, "PRETTY_NAME") == 0 && !pretty) pretty = strdup(val);
                else if (strcmp(line, "VERSION_ID") == 0 && !verid) verid = strdup(val);
            }
            line = nl ? nl + 1 : NULL;
        }
        free(osrel);
    }

    char host[256] = {0};
    gethostname(host, sizeof(host) - 1);

    struct utsname uts;
    uname(&uts);

    /* Boot time */
    struct sysinfo si;
    sysinfo(&si);
    time_t now = time(NULL);
    time_t boot = now - si.uptime;
    char dt_boot[40], dt_install[40];
    cim_datetime(boot, dt_boot, sizeof(dt_boot));
    /* InstallDate: stat / for ctime; fall back to boot time on failure. */
    struct stat st;
    time_t inst = (stat("/", &st) == 0) ? st.st_ctime : boot;
    cim_datetime(inst, dt_install, sizeof(dt_install));

    /* Memory (kB units in /proc/meminfo) */
    char *mi = slurp("/proc/meminfo", NULL);
    long memtotal_kb  = mi ? find_kv_long(mi, "MemTotal")     : -1;
    long memavail_kb  = mi ? find_kv_long(mi, "MemAvailable") : -1;
    long swaptotal_kb = mi ? find_kv_long(mi, "SwapTotal")    : -1;
    long swapfree_kb  = mi ? find_kv_long(mi, "SwapFree")     : -1;
    free(mi);

    char ver_full[128];
    snprintf(ver_full, sizeof(ver_full), "10.0.19045.%s", verid ? verid : "0");

    wbem_row_set_str(o, "Caption",                pretty ? pretty : "Archimation");
    wbem_row_set_str(o, "Name",                   pretty ? pretty : "Archimation");
    wbem_row_set_str(o, "Version",                ver_full);
    wbem_row_set_str(o, "BuildNumber",            "19045");
    wbem_row_set_str(o, "OSArchitecture",         "64-bit");
    wbem_row_set_str(o, "Manufacturer",           "Microsoft Corporation");
    wbem_row_set_str(o, "CSName",                 host[0] ? host : "ARCHWIN");
    wbem_row_set_str(o, "SerialNumber",           "00000-00000-00000-AAAAA");
    wbem_row_set_str(o, "WindowsDirectory",       "C:\\Windows");
    wbem_row_set_str(o, "SystemDirectory",        "C:\\Windows\\System32");
    wbem_row_set_str(o, "BootDevice",             "\\Device\\HarddiskVolume1");
    wbem_row_set_str(o, "SystemDrive",            "C:");
    wbem_row_set_str(o, "Locale",                 "0409");
    wbem_row_set_str(o, "OSLanguage",             "1033");
    wbem_row_set_str(o, "CountryCode",            "1");
    wbem_row_set_str(o, "InstallDate",            dt_install);
    wbem_row_set_str(o, "LastBootUpTime",         dt_boot);
    wbem_row_set_str(o, "LocalDateTime",          dt_boot);
    wbem_row_set_u4 (o, "OperatingSystemSKU",     48);   /* PRODUCT_PROFESSIONAL */
    wbem_row_set_u4 (o, "ProductType",            1);    /* WORKSTATION */
    wbem_row_set_u4 (o, "ServicePackMajorVersion",0);
    wbem_row_set_u4 (o, "ServicePackMinorVersion",0);
    wbem_row_set_u8 (o, "TotalVisibleMemorySize", memtotal_kb > 0 ? (uint64_t)memtotal_kb : 0);
    wbem_row_set_u8 (o, "FreePhysicalMemory",     memavail_kb > 0 ? (uint64_t)memavail_kb : 0);
    wbem_row_set_u8 (o, "TotalVirtualMemorySize",
                     (memtotal_kb > 0 ? (uint64_t)memtotal_kb : 0) +
                     (swaptotal_kb > 0 ? (uint64_t)swaptotal_kb : 0));
    wbem_row_set_u8 (o, "FreeVirtualMemory",
                     (memavail_kb > 0 ? (uint64_t)memavail_kb : 0) +
                     (swapfree_kb  > 0 ? (uint64_t)swapfree_kb  : 0));
    wbem_row_set_u8 (o, "SizeStoredInPagingFiles", swaptotal_kb > 0 ? (uint64_t)swaptotal_kb : 0);
    wbem_row_set_u8 (o, "FreeSpaceInPagingFiles",  swapfree_kb  > 0 ? (uint64_t)swapfree_kb  : 0);
    wbem_row_set_u4 (o, "NumberOfProcesses",      (uint32_t)dir_count_pids("/proc"));
    wbem_row_set_u4 (o, "NumberOfUsers",          1);

    free(pretty); free(verid);

    WbemClassObject **rows = NULL;
    int n = 0, cap = 0;
    push_if_match(&rows, &n, &cap, o, q);
    return wbem_enum_new(rows, n);
}

/* ================================================================== */
/* Win32_Processor                                                     */
/* ================================================================== */
WbemEnum *wbem_provider_processor(const wbem_query_t *q)
{
    char *cpuinfo = slurp("/proc/cpuinfo", NULL);
    /* We get one record per logical processor in /proc/cpuinfo on Linux. */
    int n_logical = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (n_logical < 1) n_logical = 1;

    /* For Win32_Processor we want one row per *physical* CPU package, but
     * many tools use Win32_Processor as a logical-CPU enumerator.  Match
     * the common-case behaviour: one row per logical CPU.  Anti-cheat
     * fingerprinting prefers this anyway. */
    char *model_name = NULL;
    char *vendor_id  = NULL;
    long  mhz_max    = 0;
    if (cpuinfo) {
        model_name = find_kv_str(cpuinfo, "model name");
        vendor_id  = find_kv_str(cpuinfo, "vendor_id");
        char *mhz_s = find_kv_str(cpuinfo, "cpu MHz");
        if (mhz_s) { mhz_max = (long)atof(mhz_s); free(mhz_s); }
    }
    free(cpuinfo);

    WbemClassObject **rows = NULL;
    int n = 0, cap = 0;
    for (int i = 0; i < n_logical; i++) {
        WbemClassObject *o = wbem_classobject_new("Win32_Processor");
        if (!o) continue;
        char devid[32];
        snprintf(devid, sizeof(devid), "CPU%d", i);
        wbem_row_set_str(o, "DeviceID",                  devid);
        wbem_row_set_str(o, "Name",                      model_name ? model_name : "Generic CPU");
        wbem_row_set_str(o, "Manufacturer",              vendor_id ? vendor_id : "GenuineIntel");
        wbem_row_set_str(o, "Caption",                   "Intel64 Family 6 Model 142 Stepping 10");
        wbem_row_set_str(o, "Description",               "Intel64 Family 6 Model 142 Stepping 10");
        wbem_row_set_str(o, "ProcessorId",               "BFEBFBFF000806EA");
        wbem_row_set_str(o, "SocketDesignation",         "U3E1");
        wbem_row_set_str(o, "Status",                    "OK");
        wbem_row_set_str(o, "ProcessorType",             "3");          /* CentralProcessor */
        wbem_row_set_str(o, "Architecture",              "9");          /* x64 */
        wbem_row_set_str(o, "Family",                    "198");        /* Intel Core */
        wbem_row_set_u4 (o, "AddressWidth",              64);
        wbem_row_set_u4 (o, "DataWidth",                 64);
        wbem_row_set_u4 (o, "MaxClockSpeed",             (uint32_t)(mhz_max > 0 ? mhz_max : 2400));
        wbem_row_set_u4 (o, "CurrentClockSpeed",         (uint32_t)(mhz_max > 0 ? mhz_max : 2400));
        wbem_row_set_u4 (o, "NumberOfCores",             (uint32_t)n_logical);
        wbem_row_set_u4 (o, "NumberOfLogicalProcessors", (uint32_t)n_logical);
        wbem_row_set_u4 (o, "ThreadCount",               (uint32_t)n_logical);
        wbem_row_set_u4 (o, "L2CacheSize",               256);
        wbem_row_set_u4 (o, "L3CacheSize",               6144);
        wbem_row_set_u4 (o, "Level",                     6);
        wbem_row_set_u4 (o, "Revision",                  0x8E0A);
        wbem_row_set_bool(o, "VirtualizationFirmwareEnabled", 1);
        wbem_row_set_bool(o, "VMMonitorModeExtensions",       0);
        push_if_match(&rows, &n, &cap, o, q);
    }
    free(model_name); free(vendor_id);
    return wbem_enum_new(rows, n);
}

/* ================================================================== */
/* Win32_Process                                                       */
/* ================================================================== */
WbemEnum *wbem_provider_process(const wbem_query_t *q)
{
    DIR *d = opendir("/proc");
    if (!d) return wbem_enum_new(NULL, 0);

    WbemClassObject **rows = NULL;
    int n = 0, cap = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        const char *p = e->d_name;
        int is_num = 1;
        for (const char *q1 = p; *q1; q1++)
            if (!isdigit((unsigned char)*q1)) { is_num = 0; break; }
        if (!is_num || !p[0]) continue;

        char path[256], buf[8192];

        /* /proc/[pid]/status -> Name, PPid, VmRSS */
        snprintf(path, sizeof(path), "/proc/%s/status", p);
        char *status = slurp(path, NULL);
        if (!status) continue;

        char *name = find_kv_str(status, "Name");
        char *ppid_s = find_kv_str(status, "PPid");
        char *vmrss_s = find_kv_str(status, "VmRSS");
        char *vmsize_s = find_kv_str(status, "VmSize");
        free(status);

        /* /proc/[pid]/cmdline -> CommandLine (NUL-separated args) */
        snprintf(path, sizeof(path), "/proc/%s/cmdline", p);
        size_t clen = 0;
        char *cl = slurp(path, &clen);
        if (cl) {
            for (size_t k = 0; k + 1 < clen; k++) if (cl[k] == '\0') cl[k] = ' ';
        }

        /* /proc/[pid]/exe -> ExecutablePath (symlink target) */
        snprintf(path, sizeof(path), "/proc/%s/exe", p);
        ssize_t exel = readlink(path, buf, sizeof(buf) - 1);
        if (exel > 0) buf[exel] = '\0'; else buf[0] = '\0';

        WbemClassObject *o = wbem_classobject_new("Win32_Process");
        if (!o) {
            free(name); free(ppid_s); free(vmrss_s); free(vmsize_s); free(cl);
            continue;
        }

        uint32_t pid_v = (uint32_t)atoi(p);
        wbem_row_set_u4 (o, "ProcessId",       pid_v);
        wbem_row_set_u4 (o, "ParentProcessId", ppid_s ? (uint32_t)atoi(ppid_s) : 0);
        wbem_row_set_str(o, "Name",            name ? name : "");
        wbem_row_set_str(o, "Caption",         name ? name : "");
        wbem_row_set_str(o, "Description",     name ? name : "");
        wbem_row_set_str(o, "ExecutablePath",  buf);
        wbem_row_set_str(o, "CommandLine",     cl ? cl : (name ? name : ""));
        wbem_row_set_str(o, "Status",          "OK");
        wbem_row_set_str(o, "ExecutionState",  "");
        wbem_row_set_str(o, "Handle",          p);     /* PID as string */
        /* VmRSS / VmSize values come back like "1234 kB"; strip suffix. */
        uint64_t rss_kb  = vmrss_s  ? (uint64_t)atoll(vmrss_s)  : 0;
        uint64_t vm_kb   = vmsize_s ? (uint64_t)atoll(vmsize_s) : 0;
        wbem_row_set_u8 (o, "WorkingSetSize",  rss_kb * 1024);
        wbem_row_set_u8 (o, "VirtualSize",     vm_kb  * 1024);
        wbem_row_set_u8 (o, "PageFileUsage",   0);
        wbem_row_set_u4 (o, "Priority",        8);
        wbem_row_set_u4 (o, "ThreadCount",     1);
        wbem_row_set_u4 (o, "HandleCount",     0);
        wbem_row_set_u4 (o, "SessionId",       1);

        free(name); free(ppid_s); free(vmrss_s); free(vmsize_s); free(cl);

        push_if_match(&rows, &n, &cap, o, q);
    }
    closedir(d);
    return wbem_enum_new(rows, n);
}

/* ================================================================== */
/* Win32_Service                                                       */
/* ================================================================== */

/* Run `systemctl list-units --type=service --no-pager --no-legend --plain
 * --all` and parse the 4-column output: UNIT  LOAD  ACTIVE  SUB ... DESC.
 * `popen` is fine here -- WMI service queries are coarse.  Returns the
 * number of rows produced. */
static int load_services(WbemClassObject ***rows, int *n, int *cap, const wbem_query_t *q)
{
    FILE *fp = popen("systemctl list-units --type=service --no-pager --no-legend "
                     "--plain --all 2>/dev/null", "r");
    if (!fp) return 0;
    int produced = 0;

    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        /* Tokenise: UNIT  LOAD  ACTIVE  SUB  DESCRIPTION-with-spaces */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        char *unit = p;
        char *sp = strchr(unit, ' ');
        if (!sp) continue;
        *sp = '\0';
        p = sp + 1;
        while (*p == ' ') p++;
        char *load = p; sp = strchr(load, ' '); if (!sp) continue; *sp='\0'; p=sp+1;
        while (*p == ' ') p++;
        char *active = p; sp = strchr(active, ' '); if (!sp) continue; *sp='\0'; p=sp+1;
        while (*p == ' ') p++;
        char *sub = p; sp = strchr(sub, ' '); if (!sp) continue; *sp='\0'; p=sp+1;
        while (*p == ' ') p++;
        char *desc = p;
        /* Strip trailing CR/LF. */
        size_t L = strlen(desc);
        while (L && (desc[L-1] == '\n' || desc[L-1] == '\r' || desc[L-1] == ' '))
            desc[--L] = '\0';

        /* Strip the ".service" suffix from the unit name to make it more
         * Windows-y as both Name and DisplayName. */
        char unit_short[256];
        snprintf(unit_short, sizeof(unit_short), "%s", unit);
        char *dot = strrchr(unit_short, '.');
        if (dot && strcmp(dot, ".service") == 0) *dot = '\0';

        const char *state =
            strcmp(active, "active") == 0    ? "Running" :
            strcmp(active, "activating") == 0 ? "Start Pending" :
            strcmp(active, "deactivating")==0 ? "Stop Pending"  :
            strcmp(active, "failed") == 0    ? "Stopped"  :
                                                "Stopped";
        const char *start_mode =
            strcmp(load, "loaded") == 0 ? "Auto" : "Disabled";

        WbemClassObject *o = wbem_classobject_new("Win32_Service");
        if (!o) continue;
        wbem_row_set_str(o, "Name",         unit_short);
        wbem_row_set_str(o, "DisplayName",  desc[0] ? desc : unit_short);
        wbem_row_set_str(o, "Caption",      desc[0] ? desc : unit_short);
        wbem_row_set_str(o, "Description",  desc[0] ? desc : unit_short);
        wbem_row_set_str(o, "State",        state);
        wbem_row_set_str(o, "Status",       strcmp(active, "active") == 0 ? "OK" : "Stopped");
        wbem_row_set_str(o, "StartMode",    start_mode);
        wbem_row_set_str(o, "ServiceType",  "Own Process");
        wbem_row_set_str(o, "PathName",     "/usr/bin/systemctl");
        wbem_row_set_str(o, "StartName",    "LocalSystem");
        wbem_row_set_str(o, "SystemName",   "LOCALHOST");
        wbem_row_set_bool(o, "Started",     strcmp(active, "active") == 0);
        wbem_row_set_bool(o, "AcceptStop",  1);
        wbem_row_set_bool(o, "AcceptPause", 0);
        wbem_row_set_u4 (o, "ProcessId",    0);
        wbem_row_set_u4 (o, "ExitCode",     0);
        wbem_row_set_u4 (o, "ServiceSpecificExitCode", 0);
        push_if_match(rows, n, cap, o, q);
        produced++;
        /* Cap to a reasonable number to avoid runaway WMI dumps. */
        if (produced > 1024) break;
    }
    pclose(fp);
    return produced;
}

WbemEnum *wbem_provider_service(const wbem_query_t *q)
{
    WbemClassObject **rows = NULL;
    int n = 0, cap = 0;
    load_services(&rows, &n, &cap, q);
    return wbem_enum_new(rows, n);
}

/* ================================================================== */
/* Win32_LogicalDisk                                                   */
/* ================================================================== */
WbemEnum *wbem_provider_disk(const wbem_query_t *q)
{
    WbemClassObject **rows = NULL;
    int n = 0, cap = 0;

    char *mounts = slurp("/proc/mounts", NULL);
    if (!mounts) return wbem_enum_new(NULL, 0);

    /* Drive letter map: assign C: to /, then D:, E:, ... to other real
     * mounts.  We skip pseudo filesystems (/proc, /sys, /dev/pts, etc.). */
    char letter = 'C';
    char *line = mounts;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        char dev[256], mnt[256], typ[64];
        if (sscanf(line, "%255s %255s %63s", dev, mnt, typ) == 3) {
            /* Skip pseudo-FSes that don't represent real drives. */
            int skip =
                strcmp(typ, "proc") == 0 ||
                strcmp(typ, "sysfs") == 0 ||
                strcmp(typ, "tmpfs") == 0 ||
                strcmp(typ, "devtmpfs") == 0 ||
                strcmp(typ, "devpts") == 0 ||
                strcmp(typ, "cgroup") == 0 ||
                strcmp(typ, "cgroup2") == 0 ||
                strcmp(typ, "securityfs") == 0 ||
                strcmp(typ, "pstore") == 0 ||
                strcmp(typ, "bpf") == 0 ||
                strcmp(typ, "autofs") == 0 ||
                strcmp(typ, "mqueue") == 0 ||
                strcmp(typ, "debugfs") == 0 ||
                strcmp(typ, "tracefs") == 0 ||
                strcmp(typ, "configfs") == 0 ||
                strcmp(typ, "fusectl") == 0 ||
                strcmp(typ, "hugetlbfs") == 0 ||
                strcmp(typ, "fuse.gvfsd-fuse") == 0 ||
                strcmp(typ, "rpc_pipefs") == 0 ||
                strcmp(typ, "binfmt_misc") == 0;
            /* Always allow / through. */
            if (strcmp(mnt, "/") == 0) skip = 0;
            if (skip) goto next;

            struct statvfs vfs;
            uint64_t size = 0, freebytes = 0;
            if (statvfs(mnt, &vfs) == 0) {
                size      = (uint64_t)vfs.f_blocks * vfs.f_frsize;
                freebytes = (uint64_t)vfs.f_bavail * vfs.f_frsize;
            }
            char devid[8];
            snprintf(devid, sizeof(devid), "%c:", letter);

            WbemClassObject *o = wbem_classobject_new("Win32_LogicalDisk");
            if (!o) goto next;
            wbem_row_set_str(o, "DeviceID",    devid);
            wbem_row_set_str(o, "Name",        devid);
            wbem_row_set_str(o, "Caption",     devid);
            wbem_row_set_str(o, "Description", "Local Fixed Disk");
            wbem_row_set_str(o, "VolumeName",  strcmp(mnt, "/") == 0 ? "System" : mnt);
            wbem_row_set_str(o, "FileSystem",  typ);
            wbem_row_set_str(o, "ProviderName", dev);
            wbem_row_set_u4 (o, "DriveType",   3);   /* DRIVE_FIXED */
            wbem_row_set_u4 (o, "MediaType",   12);  /* Fixed hard disk media */
            wbem_row_set_u8 (o, "Size",        size);
            wbem_row_set_u8 (o, "FreeSpace",   freebytes);
            wbem_row_set_bool(o, "Compressed", 0);
            push_if_match(&rows, &n, &cap, o, q);
            if (letter < 'Z') letter++;
        }
next:
        line = nl ? nl + 1 : NULL;
    }
    free(mounts);
    return wbem_enum_new(rows, n);
}

/* ================================================================== */
/* Win32_NetworkAdapter                                                */
/* ================================================================== */
WbemEnum *wbem_provider_netadapter(const wbem_query_t *q)
{
    DIR *d = opendir("/sys/class/net");
    if (!d) return wbem_enum_new(NULL, 0);
    WbemClassObject **rows = NULL;
    int n = 0, cap = 0;
    int idx = 1;

    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char path[512];

        snprintf(path, sizeof(path), "/sys/class/net/%s/address", e->d_name);
        char *mac = slurp_line(path);

        snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", e->d_name);
        char *oper = slurp_line(path);

        snprintf(path, sizeof(path), "/sys/class/net/%s/carrier", e->d_name);
        char *carrier = slurp_line(path);

        snprintf(path, sizeof(path), "/sys/class/net/%s/speed", e->d_name);
        char *speed = slurp_line(path);

        WbemClassObject *o = wbem_classobject_new("Win32_NetworkAdapter");
        if (!o) {
            free(mac); free(oper); free(carrier); free(speed);
            continue;
        }
        char devid[16]; snprintf(devid, sizeof(devid), "%d", idx);
        wbem_row_set_str(o, "DeviceID",        devid);
        wbem_row_set_str(o, "Name",            e->d_name);
        wbem_row_set_str(o, "Caption",         e->d_name);
        wbem_row_set_str(o, "Description",     e->d_name);
        wbem_row_set_str(o, "AdapterType",     "Ethernet 802.3");
        wbem_row_set_u4 (o, "AdapterTypeID",   0);
        wbem_row_set_str(o, "MACAddress",      mac && mac[0] ? mac : "00:00:00:00:00:00");
        wbem_row_set_str(o, "Manufacturer",    "Linux Kernel");
        wbem_row_set_str(o, "ProductName",     e->d_name);
        wbem_row_set_str(o, "ServiceName",     e->d_name);
        wbem_row_set_str(o, "PNPDeviceID",     "PCI\\VEN_1AF4&DEV_1000");
        wbem_row_set_str(o, "GUID",            "{00000000-0000-0000-0000-000000000000}");
        wbem_row_set_u4 (o, "Index",           (uint32_t)idx);
        wbem_row_set_u4 (o, "InterfaceIndex",  (uint32_t)idx);
        int up = oper && strcmp(oper, "up") == 0;
        wbem_row_set_bool(o, "NetEnabled",     up);
        wbem_row_set_u4 (o, "NetConnectionStatus",
                         (carrier && carrier[0] == '1') ? 2 : 0);  /* 2 = Connected */
        if (speed && speed[0]) {
            uint64_t mbps = (uint64_t)atoll(speed);
            wbem_row_set_u8(o, "Speed", mbps * 1000000ull);
        } else {
            wbem_row_set_u8(o, "Speed", 0);
        }
        free(mac); free(oper); free(carrier); free(speed);
        push_if_match(&rows, &n, &cap, o, q);
        idx++;
    }
    closedir(d);
    return wbem_enum_new(rows, n);
}

/* ================================================================== */
/* Win32_BIOS                                                           */
/* ================================================================== */
WbemEnum *wbem_provider_bios(const wbem_query_t *q)
{
    WbemClassObject *o = wbem_classobject_new("Win32_BIOS");
    if (!o) return NULL;

    char *vendor = slurp_line("/sys/class/dmi/id/bios_vendor");
    char *ver    = slurp_line("/sys/class/dmi/id/bios_version");
    char *date   = slurp_line("/sys/class/dmi/id/bios_date");
    char *serial = slurp_line("/sys/class/dmi/id/product_serial");

    /* date format on /sys is mm/dd/yyyy; convert to CIM datetime if we can. */
    char dt[40];
    snprintf(dt, sizeof(dt), "20240101000000.000000+000");
    if (date && strlen(date) == 10 && date[2] == '/' && date[5] == '/') {
        snprintf(dt, sizeof(dt), "%c%c%c%c%c%c%c%c000000.000000+000",
                 date[6], date[7], date[8], date[9],   /* yyyy */
                 date[0], date[1],                     /* mm */
                 date[3], date[4]);                    /* dd */
    }

    wbem_row_set_str(o, "Manufacturer",      vendor && vendor[0] ? vendor : "American Megatrends Inc.");
    wbem_row_set_str(o, "Caption",           ver && ver[0] ? ver : "F.40");
    wbem_row_set_str(o, "Name",              ver && ver[0] ? ver : "F.40");
    wbem_row_set_str(o, "Version",           ver && ver[0] ? ver : "INTEL  - 1");
    wbem_row_set_str(o, "SMBIOSBIOSVersion", ver && ver[0] ? ver : "F.40");
    wbem_row_set_str(o, "ReleaseDate",       dt);
    wbem_row_set_str(o, "SerialNumber",      serial && serial[0] ? serial : "Default string");
    wbem_row_set_str(o, "Status",            "OK");
    wbem_row_set_u4 (o, "SMBIOSMajorVersion", 3);
    wbem_row_set_u4 (o, "SMBIOSMinorVersion", 2);
    wbem_row_set_bool(o, "PrimaryBIOS",       1);

    free(vendor); free(ver); free(date); free(serial);

    WbemClassObject **rows = NULL;
    int n = 0, cap = 0;
    push_if_match(&rows, &n, &cap, o, q);
    return wbem_enum_new(rows, n);
}

/* ================================================================== */
/* Win32_ComputerSystem(Product)                                       */
/* ================================================================== */
WbemEnum *wbem_provider_computersystem(const wbem_query_t *q)
{
    WbemClassObject *o = wbem_classobject_new("Win32_ComputerSystem");
    if (!o) return NULL;

    char host[256] = {0};
    gethostname(host, sizeof(host) - 1);

    char *vendor  = slurp_line("/sys/class/dmi/id/sys_vendor");
    char *product = slurp_line("/sys/class/dmi/id/product_name");
    char *family  = slurp_line("/sys/class/dmi/id/product_family");
    char *uuid    = slurp_line("/sys/class/dmi/id/product_uuid");
    char *serial  = slurp_line("/sys/class/dmi/id/product_serial");

    struct sysinfo si; sysinfo(&si);
    uint64_t total = (uint64_t)si.totalram * (uint64_t)si.mem_unit;

    int n_logical = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (n_logical < 1) n_logical = 1;

    wbem_row_set_str(o, "Name",                host[0] ? host : "ARCHWIN");
    wbem_row_set_str(o, "Caption",             host[0] ? host : "ARCHWIN");
    wbem_row_set_str(o, "DNSHostName",         host[0] ? host : "ARCHWIN");
    wbem_row_set_str(o, "Domain",              "WORKGROUP");
    wbem_row_set_str(o, "Workgroup",           "WORKGROUP");
    wbem_row_set_str(o, "Manufacturer",        vendor && vendor[0] ? vendor : "Innotek GmbH");
    wbem_row_set_str(o, "Model",               product && product[0] ? product : "VirtualBox");
    wbem_row_set_str(o, "SystemFamily",        family && family[0] ? family : "Virtual Machine");
    wbem_row_set_str(o, "SystemSKUNumber",     "");
    wbem_row_set_str(o, "PrimaryOwnerName",    "User");
    wbem_row_set_str(o, "PCSystemType",        "1");      /* Desktop */
    wbem_row_set_str(o, "Status",              "OK");
    wbem_row_set_str(o, "BootupState",         "Normal boot");
    wbem_row_set_str(o, "ChassisBootupState",  "3");      /* Safe */
    wbem_row_set_str(o, "PowerState",          "0");
    wbem_row_set_str(o, "ThermalState",        "3");
    wbem_row_set_str(o, "UUID",                uuid && uuid[0] ? uuid :
                                               "00000000-0000-0000-0000-000000000000");
    wbem_row_set_str(o, "IdentifyingNumber",   serial && serial[0] ? serial : "0");
    wbem_row_set_u4 (o, "NumberOfProcessors",        1);
    wbem_row_set_u4 (o, "NumberOfLogicalProcessors", (uint32_t)n_logical);
    wbem_row_set_u8 (o, "TotalPhysicalMemory",       total);
    wbem_row_set_bool(o, "PartOfDomain",             0);
    wbem_row_set_bool(o, "DaylightInEffect",         0);
    wbem_row_set_bool(o, "InfraredSupported",        0);
    wbem_row_set_bool(o, "AdminPasswordStatus",      1);

    free(vendor); free(product); free(family); free(uuid); free(serial);

    WbemClassObject **rows = NULL;
    int n = 0, cap = 0;
    push_if_match(&rows, &n, &cap, o, q);
    return wbem_enum_new(rows, n);
}

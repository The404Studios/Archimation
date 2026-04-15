/*
 * registry_defaults.c - Pre-populate registry with Windows defaults
 *
 * Called during objectd_registry_init (authoritative) OR, if the broker
 * is not running, from advapi32's constructor for standalone PE runs.
 * Idempotent: values are only written when not already present so user
 * changes survive re-invocation.  The only exception is volatile per-run
 * state like hostname, which we intentionally refresh.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "registry.h"

/* Registry value types */
#define REG_SZ      1
#define REG_DWORD   4

/* HKEY predefined roots */
#define HKLM ((HKEY)(uintptr_t)0x80000002)
#define HKCU ((HKEY)(uintptr_t)0x80000001)
#define HKCR ((HKEY)(uintptr_t)0x80000000)

/* Helper: value already present? Avoids overwriting user changes. */
static int reg_value_exists(HKEY root, const char *subkey, const char *name)
{
    HKEY hk;
    if (registry_open_key(root, subkey, &hk) != 0)
        return 0;
    DWORD type = 0, size = 0;
    LONG ret = registry_get_value(hk, NULL, name ? name : "", &type, NULL, &size);
    registry_close_key(hk);
    /* ERROR_SUCCESS means the value file exists (we passed NULL data for
     * query-only).  Any other result (incl ERROR_FILE_NOT_FOUND) = absent. */
    return ret == 0;
}

/* Helper: create key and set a string value. Idempotent: won't clobber
 * an existing value (so user customisations via RegSetValueEx survive
 * subsequent defaults population). */
static void reg_set_sz(HKEY root, const char *subkey, const char *name, const char *value)
{
    if (reg_value_exists(root, subkey, name ? name : ""))
        return;
    HKEY hk;
    if (registry_create_key(root, subkey, &hk) == 0) {
        registry_set_value(hk, name, REG_SZ, value, (DWORD)(strlen(value) + 1));
        registry_close_key(hk);
    }
}

/* Helper: create key and set a DWORD value (idempotent). */
static void reg_set_dw(HKEY root, const char *subkey, const char *name, unsigned int value)
{
    if (reg_value_exists(root, subkey, name ? name : ""))
        return;
    HKEY hk;
    if (registry_create_key(root, subkey, &hk) == 0) {
        registry_set_value(hk, name, REG_DWORD, &value, sizeof(value));
        registry_close_key(hk);
    }
}

/* Force-write variant for values that must refresh each startup (e.g.
 * ComputerName may change if the host was renamed between runs). */
static void reg_set_sz_force(HKEY root, const char *subkey,
                              const char *name, const char *value)
{
    HKEY hk;
    if (registry_create_key(root, subkey, &hk) == 0) {
        registry_set_value(hk, name, REG_SZ, value, (DWORD)(strlen(value) + 1));
        registry_close_key(hk);
    }
}

/* Derive a stable 32-hex GUID from the host's /etc/machine-id.
 * Anti-cheat tooling correlates this value across launches, so we must
 * NOT regenerate randomly on each run (prior code called srand(time(NULL)).
 * Falls back to a fixed placeholder if machine-id is unreadable. */
static void stable_machine_guid(char *out, size_t size)
{
    char mid[64] = {0};
    FILE *f = fopen("/etc/machine-id", "r");
    if (f) {
        if (!fgets(mid, sizeof(mid), f)) mid[0] = '\0';
        fclose(f);
    }
    /* Strip newline */
    for (char *p = mid; *p; p++) {
        if (*p == '\n' || *p == '\r') { *p = '\0'; break; }
    }
    /* /etc/machine-id is 32 hex chars.  Format as 8-4-4-4-12 GUID. */
    if (strlen(mid) >= 32) {
        snprintf(out, size, "%.8s-%.4s-%.4s-%.4s-%.12s",
                 mid, mid + 8, mid + 12, mid + 16, mid + 20);
    } else {
        /* Fallback: stable placeholder (not random -- must match across runs). */
        snprintf(out, size,
                 "00000000-0000-4000-8000-000000000001");
    }
}

void registry_populate_defaults(void)
{
    const char *home = getenv("HOME");
    const char *user = getenv("USER");
    if (!user) user = "user";
    char path[4096];

    /* ---- Windows NT CurrentVersion ---- */
    const char *cv = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    reg_set_sz(HKLM, cv, "ProductName",            "Windows 10 Pro");
    reg_set_sz(HKLM, cv, "CurrentVersion",          "6.3");
    reg_set_sz(HKLM, cv, "CurrentBuild",             "19045");
    reg_set_sz(HKLM, cv, "CurrentBuildNumber",      "19045");
    reg_set_dw(HKLM, cv, "CurrentMajorVersionNumber", 10);
    reg_set_dw(HKLM, cv, "CurrentMinorVersionNumber", 0);
    reg_set_dw(HKLM, cv, "UBR",                    2965);
    reg_set_sz(HKLM, cv, "EditionID",               "Professional");
    reg_set_sz(HKLM, cv, "InstallationType",        "Client");
    reg_set_sz(HKLM, cv, "ReleaseId",               "2009");
    reg_set_sz(HKLM, cv, "DisplayVersion",          "22H2");
    reg_set_sz(HKLM, cv, "RegisteredOwner",         "User");
    reg_set_sz(HKLM, cv, "RegisteredOrganization",  "");
    reg_set_sz(HKLM, cv, "SystemRoot",              "C:\\Windows");
    reg_set_sz(HKLM, cv, "PathName",               "C:\\Windows");
    reg_set_sz(HKLM, cv, "BuildLab",                "19041.vb_release.191206-1406");
    reg_set_sz(HKLM, cv, "BuildLabEx",              "19041.1.amd64fre.vb_release.191206-1406");
    reg_set_sz(HKLM, cv, "BuildBranch",             "vb_release");
    reg_set_sz(HKLM, cv, "BuildGUID",               "ffffffff-ffff-ffff-ffff-ffffffffffff");
    reg_set_sz(HKLM, cv, "CompositionEditionID",    "Enterprise");
    reg_set_sz(HKLM, cv, "ProductId",               "00330-80000-00000-AA228");
    reg_set_dw(HKLM, cv, "InstallDate",             1640995200);  /* 2022-01-01 epoch */

    /* ---- Cryptography MachineGuid ----
     * Must be STABLE across PE process invocations and objectd restarts --
     * anti-cheat tooling (BattlEye, EasyAntiCheat, Ricochet) correlates
     * this value with session identity.  Derived from /etc/machine-id,
     * with reg_set_sz idempotency ensuring it's written exactly once. */
    char guid[64];
    stable_machine_guid(guid, sizeof(guid));
    reg_set_sz(HKLM, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid", guid);

    /* ---- DirectX ---- */
    reg_set_sz(HKLM, "SOFTWARE\\Microsoft\\DirectX", "Version", "4.09.00.0904");
    reg_set_dw(HKLM, "SOFTWARE\\Microsoft\\DirectX", "InstalledVersion", 0x00040009);
    reg_set_dw(HKLM, "SOFTWARE\\Microsoft\\DirectX", "DXGIFactory1Supported", 1);

    /* ---- .NET Framework 4.8 ---- */
    reg_set_dw(HKLM, "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full", "Release", 528040);
    reg_set_sz(HKLM, "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full", "Version", "4.8.04084");
    reg_set_dw(HKLM, "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full", "Install", 1);

    /* ---- Processor info ---- */
    reg_set_sz(HKLM, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
               "ProcessorNameString", "AMD Ryzen 9 5900X 12-Core Processor");
    reg_set_dw(HKLM, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "~MHz", 3700);
    reg_set_sz(HKLM, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
               "VendorIdentifier", "AuthenticAMD");
    reg_set_sz(HKLM, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
               "Identifier", "AMD64 Family 25 Model 33 Stepping 0");

    /* ---- BIOS / System info ---- */
    reg_set_sz(HKLM, "HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemManufacturer", "ASUS");
    reg_set_sz(HKLM, "HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemProductName",  "ROG STRIX B550-F");
    reg_set_sz(HKLM, "HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVendor",         "American Megatrends Inc.");
    reg_set_sz(HKLM, "HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVersion",        "2602");
    reg_set_sz(HKLM, "HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSReleaseDate",    "03/09/2022");

    /* ---- Session manager environment ---- */
    const char *env_key = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
    reg_set_sz(HKLM, env_key, "PROCESSOR_ARCHITECTURE", "AMD64");
    reg_set_sz(HKLM, env_key, "OS", "Windows_NT");
    char nproc[16];
    snprintf(nproc, sizeof(nproc), "%ld", sysconf(_SC_NPROCESSORS_ONLN));
    reg_set_sz(HKLM, env_key, "NUMBER_OF_PROCESSORS", nproc);
    reg_set_sz(HKLM, env_key, "PROCESSOR_IDENTIFIER",
               "AMD64 Family 25 Model 33 Stepping 0, AuthenticAMD");
    reg_set_sz(HKLM, env_key, "SystemRoot", "C:\\Windows");
    reg_set_sz(HKLM, env_key, "Path",
               "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;"
               "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\");

    /* ---- Windows Defender (disable RT protection check) ---- */
    reg_set_dw(HKLM, "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
               "DisableRealtimeMonitoring", 1);

    /* ---- UAC disabled ---- */
    reg_set_dw(HKLM, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
               "EnableLUA", 0);
    reg_set_dw(HKLM, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
               "ConsentPromptBehaviorAdmin", 0);

    /* ---- Windows version compatibility (apps that check this) ---- */
    reg_set_sz(HKLM, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
               "ProgramFilesDir", "C:\\Program Files");
    reg_set_sz(HKLM, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
               "ProgramFilesDir (x86)", "C:\\Program Files (x86)");
    reg_set_sz(HKLM, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
               "CommonFilesDir", "C:\\Program Files\\Common Files");
    reg_set_sz(HKLM, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
               "SystemRoot", "C:\\Windows");

    /* ---- User profile paths ---- */
    if (home) {
        const char *shell_key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
        const char *ushell_key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders";

        snprintf(path, sizeof(path), "C:\\Users\\%s\\Desktop", user);
        reg_set_sz(HKCU, shell_key, "Desktop", path);
        reg_set_sz(HKCU, ushell_key, "Desktop", path);

        snprintf(path, sizeof(path), "C:\\Users\\%s\\Documents", user);
        reg_set_sz(HKCU, shell_key, "Personal", path);
        reg_set_sz(HKCU, ushell_key, "Personal", path);

        snprintf(path, sizeof(path), "C:\\Users\\%s\\AppData\\Roaming", user);
        reg_set_sz(HKCU, shell_key, "AppData", path);
        reg_set_sz(HKCU, ushell_key, "AppData", path);

        snprintf(path, sizeof(path), "C:\\Users\\%s\\AppData\\Local", user);
        reg_set_sz(HKCU, shell_key, "Local AppData", path);
        reg_set_sz(HKCU, ushell_key, "Local AppData", path);

        snprintf(path, sizeof(path), "C:\\Users\\%s\\Downloads", user);
        reg_set_sz(HKCU, ushell_key, "{374DE290-123F-4565-9164-39C4925E467B}", path);

        snprintf(path, sizeof(path), "C:\\Users\\%s\\Saved Games", user);
        reg_set_sz(HKCU, ushell_key, "{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}", path);

        snprintf(path, sizeof(path), "C:\\Users\\%s\\Music", user);
        reg_set_sz(HKCU, shell_key, "My Music", path);
        reg_set_sz(HKCU, ushell_key, "My Music", path);

        snprintf(path, sizeof(path), "C:\\Users\\%s\\Videos", user);
        reg_set_sz(HKCU, shell_key, "My Video", path);
        reg_set_sz(HKCU, ushell_key, "My Video", path);

        snprintf(path, sizeof(path), "C:\\Users\\%s\\Pictures", user);
        reg_set_sz(HKCU, shell_key, "My Pictures", path);
        reg_set_sz(HKCU, ushell_key, "My Pictures", path);

        snprintf(path, sizeof(path), "C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu", user);
        reg_set_sz(HKCU, shell_key, "Start Menu", path);
        reg_set_sz(HKCU, ushell_key, "Start Menu", path);

        snprintf(path, sizeof(path), "C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs", user);
        reg_set_sz(HKCU, shell_key, "Programs", path);
        reg_set_sz(HKCU, ushell_key, "Programs", path);

        snprintf(path, sizeof(path), "C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", user);
        reg_set_sz(HKCU, shell_key, "Startup", path);
        reg_set_sz(HKCU, ushell_key, "Startup", path);

        snprintf(path, sizeof(path), "C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Templates", user);
        reg_set_sz(HKCU, shell_key, "Templates", path);
        reg_set_sz(HKCU, ushell_key, "Templates", path);

        snprintf(path, sizeof(path), "C:\\Users\\%s\\AppData\\Local\\Microsoft\\Windows\\INetCache", user);
        reg_set_sz(HKCU, shell_key, "Cache", path);
        reg_set_sz(HKCU, ushell_key, "Cache", path);

        reg_set_sz(HKCU, shell_key, "Fonts", "C:\\Windows\\Fonts");
        reg_set_sz(HKCU, ushell_key, "Fonts", "C:\\Windows\\Fonts");

        /* Common (all-users) shell folders */
        reg_set_sz(HKLM, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                   "Common AppData", "C:\\ProgramData");
        reg_set_sz(HKLM, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                   "Common Desktop", "C:\\Users\\Public\\Desktop");
        reg_set_sz(HKLM, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                   "Common Documents", "C:\\Users\\Public\\Documents");

        /* Steam install paths */
        snprintf(path, sizeof(path), "%s/.pe-compat/drives/c/Program Files (x86)/Steam", home);
        reg_set_sz(HKCU, "SOFTWARE\\Valve\\Steam", "SteamPath", path);
        reg_set_sz(HKCU, "SOFTWARE\\Valve\\Steam", "Language", "english");
        reg_set_dw(HKCU, "SOFTWARE\\Valve\\Steam", "AlreadyRetriedOfflineMode", 0);
        reg_set_dw(HKCU, "SOFTWARE\\Valve\\Steam", "RunningAppID", 0);
        reg_set_sz(HKLM, "SOFTWARE\\Valve\\Steam", "InstallPath",
                   "C:\\Program Files (x86)\\Steam");
        reg_set_sz(HKLM, "SOFTWARE\\WOW6432Node\\Valve\\Steam", "InstallPath",
                   "C:\\Program Files (x86)\\Steam");
    }

    /* ---- Vulkan registry (ICD loader) ---- */
    reg_set_sz(HKLM, "SOFTWARE\\Khronos\\Vulkan\\ImplicitLayers",
               "VK_LAYER_VALVE_steam_overlay_64", "");

    /* ---- TimeZone ---- */
    reg_set_sz(HKLM, "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
               "TimeZoneKeyName", "UTC");
    reg_set_dw(HKLM, "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
               "ActiveTimeBias", 0);
    reg_set_dw(HKLM, "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
               "Bias", 0);

    /* ---- ComputerName ----
     * Volatile: refresh each startup so hostname changes on the host
     * are reflected.  Force-write bypasses idempotency check. */
    char hostname[256] = "DESKTOP-PECOMPAT";
    gethostname(hostname, sizeof(hostname));
    reg_set_sz_force(HKLM, "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
                     "ComputerName", hostname);
    reg_set_sz_force(HKLM, "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",
                     "ComputerName", hostname);

    /* ---- Windows Installer ---- */
    reg_set_dw(HKLM, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer",
               "InstallerLocation", 0);

    /* ---- Secure Boot / TPM (for anti-cheat) ---- */
    reg_set_dw(HKLM, "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
               "UEFISecureBootEnabled", 1);

    /* ---- HKLM\SOFTWARE\Classes (authoritative backing for HKCR) ----
     * Windows apps enumerate HKCR for COM/ProgID info; HKCR is a virtual
     * merge of HKLM\SOFTWARE\Classes overlaid with HKCU\SOFTWARE\Classes
     * (implemented in registry.c's resolve_hkcr_path).  We populate only
     * HKLM side here -- HKCR reads fall through to HKLM automatically,
     * so no legacy HKCR directory duplication is needed. */
    reg_set_sz(HKLM, "SOFTWARE\\Classes",                   NULL, "");
    reg_set_sz(HKLM, "SOFTWARE\\Classes\\.exe",             NULL, "exefile");
    reg_set_sz(HKLM, "SOFTWARE\\Classes\\.txt",             NULL, "txtfile");
    reg_set_sz(HKLM, "SOFTWARE\\Classes\\.dll",             NULL, "dllfile");
    reg_set_sz(HKLM, "SOFTWARE\\Classes\\.bat",             NULL, "batfile");
    reg_set_sz(HKLM, "SOFTWARE\\Classes\\.cmd",             NULL, "cmdfile");
    reg_set_sz(HKLM, "SOFTWARE\\Classes\\.lnk",             NULL, "lnkfile");
    reg_set_sz(HKLM, "SOFTWARE\\Classes\\exefile",          NULL, "Application");
    reg_set_sz(HKLM, "SOFTWARE\\Classes\\txtfile",          NULL, "Text Document");
    reg_set_sz(HKLM, "SOFTWARE\\Classes\\dllfile",          NULL, "Application Extension");
    reg_set_sz(HKLM, "SOFTWARE\\Classes\\Directory",        NULL, "File Folder");
    reg_set_sz(HKLM, "SOFTWARE\\Classes\\CLSID",            NULL, "");

    /* ---- HKLM\SYSTEM\CurrentControlSet\Services (driver stubs) ---- */
    reg_set_sz(HKLM, "SYSTEM\\CurrentControlSet\\Services",        NULL, "");
    reg_set_sz(HKLM, "SYSTEM\\CurrentControlSet\\Services\\Tcpip",
               "DisplayName", "TCP/IP Protocol Driver");
    reg_set_dw(HKLM, "SYSTEM\\CurrentControlSet\\Services\\Tcpip", "Start", 1);
    reg_set_dw(HKLM, "SYSTEM\\CurrentControlSet\\Services\\Tcpip", "Type",  1);
    reg_set_sz(HKLM, "SYSTEM\\CurrentControlSet\\Services\\Dnscache",
               "DisplayName", "DNS Client");
    reg_set_dw(HKLM, "SYSTEM\\CurrentControlSet\\Services\\Dnscache", "Start", 2);
    reg_set_sz(HKLM, "SYSTEM\\CurrentControlSet\\Services\\RpcSs",
               "DisplayName", "Remote Procedure Call (RPC)");
    reg_set_dw(HKLM, "SYSTEM\\CurrentControlSet\\Services\\RpcSs", "Start", 2);
    /* Anti-cheat commonly checks for these driver services */
    reg_set_sz(HKLM, "SYSTEM\\CurrentControlSet\\Services\\mouclass",
               "DisplayName", "Mouse Class Driver");
    reg_set_dw(HKLM, "SYSTEM\\CurrentControlSet\\Services\\mouclass", "Start", 3);
    reg_set_sz(HKLM, "SYSTEM\\CurrentControlSet\\Services\\kbdclass",
               "DisplayName", "Keyboard Class Driver");
    reg_set_dw(HKLM, "SYSTEM\\CurrentControlSet\\Services\\kbdclass", "Start", 3);

    /* Typical storage/display driver stack — AC enumerates these to
     * distinguish real Windows from stripped sandbox environments.
     * Type=1 (kernel driver), Start=0/1/2/3 per Windows defaults. */
    struct { const char *name, *display; unsigned start, type; } svc_stubs[] = {
        { "BasicDisplay", "Microsoft Basic Display Driver",  1, 1 },
        { "BasicRender",  "Microsoft Basic Render Driver",   3, 1 },
        { "mountmgr",     "Mount Point Manager",             0, 1 },
        { "storvsc",      "Hyper-V Storage Interface",       3, 1 },
        { "disk",         "Disk Driver",                     0, 1 },
        { "partmgr",      "Partition Manager",               0, 1 },
        { "volume",       "Volume Manager Driver",           3, 1 },
        { "volsnap",      "Volume Shadow Copy Driver",       3, 1 },
        { "iaStorA",      "Intel Rapid Storage Technology",  3, 1 },
        { "Ntfs",         "Ntfs",                            1, 2 },
        { "HDAudBus",     "Microsoft UAA Bus Driver for HD Audio", 3, 1 },
        { "usbhub",       "USB Hub Driver",                  3, 1 },
        { "hidusb",       "HID Device Driver for USB",       3, 1 },
        { "HidIr",        "Microsoft HID IR Parser",         3, 1 },
        { "i8042prt",     "i8042 Keyboard and PS/2 Mouse Port Driver", 3, 1 },
        { "ACPI",         "Microsoft ACPI Driver",           0, 1 },
        { "PCI",          "PCI Bus Driver",                  0, 1 },
        { "pci",          "PCI Bus Driver",                  0, 1 },
        { "NDIS",         "NDIS System Driver",              0, 1 },
        { "AFD",          "Ancillary Function Driver for Winsock", 1, 1 },
        { "LanmanServer", "Server",                          2, 0x20 },
        { "LanmanWorkstation", "Workstation",                2, 0x20 },
    };
    for (size_t i = 0; i < sizeof(svc_stubs)/sizeof(svc_stubs[0]); i++) {
        char svc_key[256];
        snprintf(svc_key, sizeof(svc_key),
                 "SYSTEM\\CurrentControlSet\\Services\\%s", svc_stubs[i].name);
        reg_set_sz(HKLM, svc_key, "DisplayName", svc_stubs[i].display);
        reg_set_dw(HKLM, svc_key, "Start", svc_stubs[i].start);
        reg_set_dw(HKLM, svc_key, "Type",  svc_stubs[i].type);
        reg_set_dw(HKLM, svc_key, "ErrorControl", 1);
    }

    /* Tcpip\Parameters — HostName / NV Hostname.  Hostname is volatile. */
    reg_set_sz_force(HKLM, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                     "Hostname", hostname);
    reg_set_sz_force(HKLM, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                     "NV Hostname", hostname);
    reg_set_sz(HKLM, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
               "Domain", "");
    reg_set_sz(HKLM, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
               "NV Domain", "");
    reg_set_sz(HKLM, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
               "DhcpDomain", "");
    reg_set_dw(HKLM, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
               "EnableICMPRedirect", 1);
    reg_set_dw(HKLM, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
               "EnableSecurityFilters", 0);
    /* Note: EAC/BEService/vgk keys intentionally NOT populated — games must
     * see "service not installed" to drive the user into the AC installer. */

    /* ---- HARDWARE\DESCRIPTION\System (root) ---- */
    reg_set_sz(HKLM, "HARDWARE\\DESCRIPTION\\System",
               "Identifier", "AT/AT COMPATIBLE");
    reg_set_sz(HKLM, "HARDWARE\\DESCRIPTION\\System",
               "SystemBiosVersion", "2602");
    reg_set_sz(HKLM, "HARDWARE\\DESCRIPTION\\System",
               "VideoBiosVersion", "");
    reg_set_dw(HKLM, "HARDWARE\\DESCRIPTION\\System",
               "Capabilities", 0x0007cd80);

    /* CentralProcessor — add Update Revision and feature bits */
    reg_set_dw(HKLM, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
               "Update Revision", 0xa201016);
    reg_set_dw(HKLM, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
               "FeatureSet", 0x7fffffff);
    reg_set_dw(HKLM, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
               "Configuration Data", 0);
    /* CentralProcessor root (enumeration anchor) */
    reg_set_sz(HKLM, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor",
               NULL, "");

    /* HARDWARE\DEVICEMAP — GPU adapter table */
    reg_set_sz(HKLM, "HARDWARE\\DEVICEMAP\\VideoDevices",
               "\\Device\\Video0",
               "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000");
    reg_set_sz(HKLM, "HARDWARE\\DEVICEMAP\\Video",
               "MaxObjectNumber", "1");

    /* DEVICEMAP\KeyboardClass / PointerClass — plausible HID enumeration */
    reg_set_sz(HKLM, "HARDWARE\\DEVICEMAP\\KeyboardClass",
               "\\Device\\KeyboardClass0",
               "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\kbdclass");
    reg_set_sz(HKLM, "HARDWARE\\DEVICEMAP\\PointerClass",
               "\\Device\\PointerClass0",
               "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\mouclass");

    /* Physical Memory resource map — AC uses this to fingerprint RAM layout.
     * Empty but-present key is enough for existence checks. */
    reg_set_sz(HKLM, "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
               NULL, "");
    reg_set_sz(HKLM, "HARDWARE\\RESOURCEMAP\\System Resources\\Loader Reserved",
               NULL, "");

    /* ---- SystemInformation (mirror of BIOS block, anti-cheat reads both) ---- */
    const char *sysinfo = "SYSTEM\\CurrentControlSet\\Control\\SystemInformation";
    reg_set_sz(HKLM, sysinfo, "SystemManufacturer", "ASUS");
    reg_set_sz(HKLM, sysinfo, "SystemProductName",  "ROG STRIX B550-F");
    reg_set_sz(HKLM, sysinfo, "SystemFamily",       "ROG STRIX");
    reg_set_sz(HKLM, sysinfo, "SystemSKU",          "ROG STRIX B550-F GAMING");
    reg_set_sz(HKLM, sysinfo, "BaseBoardManufacturer", "ASUSTeK COMPUTER INC.");
    reg_set_sz(HKLM, sysinfo, "BaseBoardProduct",   "ROG STRIX B550-F GAMING");
    reg_set_sz(HKLM, sysinfo, "BaseBoardVersion",   "Rev 1.xx");
    reg_set_sz(HKLM, sysinfo, "BIOSVendor",         "American Megatrends Inc.");
    reg_set_sz(HKLM, sysinfo, "BIOSVersion",        "2602");
    reg_set_sz(HKLM, sysinfo, "BIOSReleaseDate",    "03/09/2022");

    /* ---- Internet Explorer / legacy WinInet (many games use WinHTTP/IE) ---- */
    reg_set_sz(HKLM, "SOFTWARE\\Microsoft\\Internet Explorer",
               "Version",    "11.0.19041.3570");
    reg_set_sz(HKLM, "SOFTWARE\\Microsoft\\Internet Explorer",
               "svcVersion", "11.0.19041.3570");
    reg_set_sz(HKLM, "SOFTWARE\\Microsoft\\Internet Explorer",
               "Build",      "19041.3570");
    reg_set_sz(HKLM, "SOFTWARE\\Microsoft\\Internet Explorer",
               "W2kVersion", "11.0.19041.3570");

    /* ---- Windows Defender presence (stub so AC knows Defender "exists") ---- */
    reg_set_sz(HKLM, "SOFTWARE\\Microsoft\\Windows Defender",
               "InstallLocation", "C:\\ProgramData\\Microsoft\\Windows Defender\\");
    reg_set_dw(HKLM, "SOFTWARE\\Microsoft\\Windows Defender",
               "DisableAntiSpyware", 0);
    reg_set_sz(HKLM, "SOFTWARE\\Microsoft\\Windows Defender\\MpService",
               "DisplayName", "Microsoft Defender Antivirus Service");
    reg_set_dw(HKLM, "SOFTWARE\\Microsoft\\Windows Defender\\MpService",
               "Start", 3);  /* manual — present but not running */
    reg_set_sz(HKLM, "SYSTEM\\CurrentControlSet\\Services\\WinDefend",
               "DisplayName", "Microsoft Defender Antivirus Service");
    reg_set_dw(HKLM, "SYSTEM\\CurrentControlSet\\Services\\WinDefend", "Start", 3);
    reg_set_dw(HKLM, "SYSTEM\\CurrentControlSet\\Services\\WinDefend", "Type", 0x10);

    /* ---- DirectX feature level metadata ---- */
    reg_set_sz(HKLM, "SOFTWARE\\Microsoft\\DirectX",
               "DXGIVersion", "1.6");
    reg_set_dw(HKLM, "SOFTWARE\\Microsoft\\DirectX",
               "MajorVersion", 12);
    reg_set_dw(HKLM, "SOFTWARE\\Microsoft\\DirectX",
               "MinorVersion", 0);

    /* ---- ProfileList — default user profile path ---- */
    const char *profiles_key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    reg_set_sz(HKLM, profiles_key, "ProfilesDirectory", "C:\\Users");
    reg_set_sz(HKLM, profiles_key, "Default",           "C:\\Users\\Default");
    reg_set_sz(HKLM, profiles_key, "Public",            "C:\\Users\\Public");
    reg_set_sz(HKLM, profiles_key, "ProgramData",       "C:\\ProgramData");
    /* Per-user profile — SID is stable but synthetic since we have no real SAM.
     * S-1-5-21-X-Y-Z-1000 format, X/Y/Z derived from machine-id if possible. */
    if (user) {
        char sid_key[512];
        snprintf(sid_key, sizeof(sid_key),
                 "%s\\S-1-5-21-1000000000-1000000001-1000000002-1000",
                 profiles_key);
        char profile_path[256];
        snprintf(profile_path, sizeof(profile_path), "C:\\Users\\%s", user);
        reg_set_sz(HKLM, sid_key, "ProfileImagePath", profile_path);
        reg_set_dw(HKLM, sid_key, "Flags", 0);
        reg_set_dw(HKLM, sid_key, "State", 0);
    }

    /* ---- HKU\.DEFAULT skeleton ---- */
    /* HKU root isn't one of our HKEY predefineds, but HKCU is \.DEFAULT for
     * non-interactive processes per Windows semantics.  We stash defaults
     * into HKCU — the broker's HKU resolver will point .DEFAULT at this hive. */
    reg_set_sz(HKCU, "Environment", "TEMP",
               "C:\\Users\\Default\\AppData\\Local\\Temp");
    reg_set_sz(HKCU, "Environment", "TMP",
               "C:\\Users\\Default\\AppData\\Local\\Temp");
    if (user) {
        snprintf(path, sizeof(path), "C:\\Users\\%s\\AppData\\Local\\Temp", user);
        reg_set_sz(HKCU, "Environment", "TEMP", path);
        reg_set_sz(HKCU, "Environment", "TMP", path);
    }
    reg_set_sz(HKCU, "Environment", "Path", "");

    /* ---- HKCU\Control Panel\International ---- */
    const char *intl = "Control Panel\\International";
    reg_set_sz(HKCU, intl, "sLanguage",  "ENU");
    reg_set_sz(HKCU, intl, "sCountry",   "United States");
    reg_set_sz(HKCU, intl, "sShortDate", "M/d/yyyy");
    reg_set_sz(HKCU, intl, "sLongDate",  "dddd, MMMM d, yyyy");
    reg_set_sz(HKCU, intl, "sTimeFormat","h:mm:ss tt");
    reg_set_sz(HKCU, intl, "sDecimal",   ".");
    reg_set_sz(HKCU, intl, "sThousand",  ",");
    reg_set_sz(HKCU, intl, "sList",      ",");
    reg_set_sz(HKCU, intl, "iCountry",   "1");
    reg_set_sz(HKCU, intl, "iMeasure",   "1");
    reg_set_sz(HKCU, intl, "LocaleName", "en-US");
    reg_set_dw(HKCU, intl, "Locale",     0x00000409);

    /* ---- HKCU\Control Panel\Desktop (some apps probe this) ---- */
    reg_set_sz(HKCU, "Control Panel\\Desktop", "Wallpaper", "");
    reg_set_dw(HKCU, "Control Panel\\Desktop", "DpiScalingVer", 0x00001018);
    reg_set_dw(HKCU, "Control Panel\\Desktop", "LogPixels", 96);

    printf("[registry] Default hive populated\n");
}

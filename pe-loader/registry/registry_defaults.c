/*
 * registry_defaults.c - Pre-populate registry with Windows defaults
 *
 * Called during env_setup_init to provide registry values that
 * Windows applications expect to find.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "registry.h"

/* Registry value types */
#define REG_SZ      1
#define REG_DWORD   4

/* HKEY predefined roots */
#define HKLM ((HKEY)(uintptr_t)0x80000002)
#define HKCU ((HKEY)(uintptr_t)0x80000001)
#define HKCR ((HKEY)(uintptr_t)0x80000000)

/* Helper: create key and set a string value */
static void reg_set_sz(HKEY root, const char *subkey, const char *name, const char *value)
{
    HKEY hk;
    if (registry_create_key(root, subkey, &hk) == 0) {
        registry_set_value(hk, name, REG_SZ, value, (DWORD)(strlen(value) + 1));
        registry_close_key(hk);
    }
}

/* Helper: create key and set a DWORD value */
static void reg_set_dw(HKEY root, const char *subkey, const char *name, unsigned int value)
{
    HKEY hk;
    if (registry_create_key(root, subkey, &hk) == 0) {
        registry_set_value(hk, name, REG_DWORD, &value, sizeof(value));
        registry_close_key(hk);
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

    /* ---- Cryptography MachineGuid ---- */
    char guid[64];
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    snprintf(guid, sizeof(guid), "%08x-%04x-%04x-%04x-%012lx",
             (unsigned)(time(NULL) & 0xFFFFFFFF),
             (unsigned)(rand() & 0xFFFF),
             (unsigned)(0x4000 | (rand() & 0x0FFF)),
             (unsigned)(0x8000 | (rand() & 0x3FFF)),
             (unsigned long)(((unsigned long)rand() << 16) | rand()) & 0xFFFFFFFFFFFFUL);
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

    /* ---- ComputerName ---- */
    char hostname[256] = "DESKTOP-PECOMPAT";
    gethostname(hostname, sizeof(hostname));
    reg_set_sz(HKLM, "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
               "ComputerName", hostname);
    reg_set_sz(HKLM, "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",
               "ComputerName", hostname);

    /* ---- Windows Installer ---- */
    reg_set_dw(HKLM, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer",
               "InstallerLocation", 0);

    /* ---- Secure Boot / TPM (for anti-cheat) ---- */
    reg_set_dw(HKLM, "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
               "UEFISecureBootEnabled", 1);

    printf("[registry] Default hive populated\n");
}

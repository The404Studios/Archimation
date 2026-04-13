/*
 * ac_compat.c - Anti-cheat detection and compatibility layer
 *
 * Detects which anti-cheat system a game uses by examining known files,
 * registry keys, and service names. Sets up the appropriate compatibility
 * environment for each anti-cheat type.
 *
 * Supported anti-cheat systems:
 *   - EasyAntiCheat (EAC)
 *   - BattlEye (BE)
 *   - Vanguard (Riot)
 *   - GameGuard (nProtect)
 *   - PunkBuster
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

#define AC_LOG_PREFIX   "[anticheat] "
#define AC_BASE_PATH    "/var/lib/pe-compat"
#define AC_REG_PATH     "/var/lib/pe-compat/registry"
#define AC_SVC_PATH     "/var/lib/pe-compat/services"
#define MAX_PATH_LEN    4096

/* Anti-cheat type enumeration */
typedef enum {
    AC_NONE             = 0,
    AC_EASY_ANTI_CHEAT  = 1,
    AC_BATTLEYE         = 2,
    AC_VANGUARD         = 3,
    AC_GAMEGUARD        = 4,
    AC_PUNKBUSTER       = 5,
    AC_BLACKSHIELD      = 6     /* IRONMACE - Dark and Darker */
} ac_type_t;

/* Anti-cheat state */
typedef struct {
    ac_type_t   type;
    char        game_dir[MAX_PATH_LEN];
    int         initialized;
    int         environment_ready;
} ac_state_t;

static ac_state_t g_ac_state = { AC_NONE, {0}, 0, 0 };

/* Forward declarations */
static int file_exists(const char *path);
static int dir_exists(const char *path);
static int mkdir_p(const char *path);
static int create_fake_registry_key(const char *hive, const char *subkey);
static int create_fake_registry_value(const char *hive, const char *subkey,
                                       const char *name, const char *value);
static int register_fake_service(const char *name, const char *display,
                                  const char *binary, int type, int start);
static int setup_eac_environment(const char *game_dir);
static int setup_battleye_environment(const char *game_dir);
static int setup_vanguard_environment(void);
static int setup_gameguard_environment(const char *game_dir);
static int setup_punkbuster_environment(const char *game_dir);
int ac_cleanup(void);

/* --- Utility functions --- */

static int file_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
}

static int dir_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

static int mkdir_p(const char *path)
{
    char tmp[MAX_PATH_LEN];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return mkdir(tmp, 0755);
}

static int create_fake_registry_key(const char *hive, const char *subkey)
{
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s/%s", AC_REG_PATH, hive, subkey);

    fprintf(stderr, AC_LOG_PREFIX "Creating registry key: %s\\%s\n", hive, subkey);
    return mkdir_p(path);
}

static int create_fake_registry_value(const char *hive, const char *subkey,
                                       const char *name, const char *value)
{
    char dir_path[MAX_PATH_LEN];
    snprintf(dir_path, sizeof(dir_path), "%s/%s/%s/.values",
             AC_REG_PATH, hive, subkey);
    mkdir_p(dir_path);

    char val_path[MAX_PATH_LEN];
    snprintf(val_path, sizeof(val_path), "%s/%s", dir_path, name);

    FILE *f = fopen(val_path, "wb");
    if (!f) {
        fprintf(stderr, AC_LOG_PREFIX "Failed to create registry value %s: %s\n",
                val_path, strerror(errno));
        return -1;
    }

    /* Write REG_SZ type (1) followed by string data */
    unsigned int type = 1; /* REG_SZ */
    fwrite(&type, sizeof(unsigned int), 1, f);
    fwrite(value, 1, strlen(value) + 1, f);
    fclose(f);

    fprintf(stderr, AC_LOG_PREFIX "Set registry value: %s\\%s\\%s = \"%s\"\n",
            hive, subkey, name, value);
    return 0;
}

static int register_fake_service(const char *name, const char *display,
                                  const char *binary, int type, int start)
{
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s.svc", AC_SVC_PATH, name);

    mkdir_p(AC_SVC_PATH);

    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, AC_LOG_PREFIX "Failed to register service %s: %s\n",
                name, strerror(errno));
        return -1;
    }

    fprintf(f, "name=%s\n", name);
    fprintf(f, "display=%s\n", display);
    fprintf(f, "binary=%s\n", binary);
    fprintf(f, "type=%d\n", type);
    fprintf(f, "start=%d\n", start);
    fprintf(f, "depends=\n");
    fclose(f);

    fprintf(stderr, AC_LOG_PREFIX "Registered service: %s (%s)\n", name, display);
    return 0;
}

/* --- Detection functions --- */

/*
 * Check for EasyAntiCheat presence:
 *   - EasyAntiCheat/ directory in game folder
 *   - easyanticheat_x64.so or easyanticheat_x86.so files
 *   - EasyAntiCheat.exe or EasyAntiCheat_Setup.exe
 */
static int detect_eac(const char *game_dir)
{
    char path[MAX_PATH_LEN];

    snprintf(path, sizeof(path), "%s/EasyAntiCheat", game_dir);
    if (dir_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found EasyAntiCheat/ directory\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/easyanticheat_x64.so", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found easyanticheat_x64.so\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/easyanticheat_x86.so", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found easyanticheat_x86.so\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/EasyAntiCheat_Setup.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found EasyAntiCheat_Setup.exe\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/EasyAntiCheat.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found EasyAntiCheat.exe\n");
        return 1;
    }

    return 0;
}

/*
 * Check for BattlEye presence:
 *   - BattlEye/ directory in game folder
 *   - BEService_x64.exe, BEClient_x64.dll
 *   - BEService.exe, BEClient.dll
 */
static int detect_battleye(const char *game_dir)
{
    char path[MAX_PATH_LEN];

    snprintf(path, sizeof(path), "%s/BattlEye", game_dir);
    if (dir_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found BattlEye/ directory\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/BEService_x64.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found BEService_x64.exe\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/BEClient_x64.dll", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found BEClient_x64.dll\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/BEService.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found BEService.exe\n");
        return 1;
    }

    return 0;
}

/*
 * Check for Vanguard (Riot) presence:
 *   - vgc.exe or vgk.sys in system paths
 *   - Registry keys under HKLM\SYSTEM\CurrentControlSet\Services\vgc
 *   - Registry keys under HKLM\SYSTEM\CurrentControlSet\Services\vgk
 */
static int detect_vanguard(const char *game_dir)
{
    char path[MAX_PATH_LEN];

    /* Check for Vanguard executables in game directory */
    snprintf(path, sizeof(path), "%s/vgc.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found vgc.exe (Vanguard client)\n");
        return 1;
    }

    /* Check for Riot Vanguard service registry keys */
    snprintf(path, sizeof(path), "%s/HKLM/SYSTEM/CurrentControlSet/Services/vgc",
             AC_REG_PATH);
    if (dir_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found Vanguard service registry key (vgc)\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/HKLM/SYSTEM/CurrentControlSet/Services/vgk",
             AC_REG_PATH);
    if (dir_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found Vanguard kernel registry key (vgk)\n");
        return 1;
    }

    /* Check for RiotClientServices.exe nearby */
    snprintf(path, sizeof(path), "%s/RiotClientServices.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found RiotClientServices.exe\n");
        return 1;
    }

    return 0;
}

/*
 * Check for GameGuard (nProtect) presence:
 *   - GameGuard/ directory
 *   - GameGuard.des, GameMon.des, GameMon64.des
 */
static int detect_gameguard(const char *game_dir)
{
    char path[MAX_PATH_LEN];

    snprintf(path, sizeof(path), "%s/GameGuard", game_dir);
    if (dir_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found GameGuard/ directory\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/GameGuard.des", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found GameGuard.des\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/GameMon.des", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found GameMon.des\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/GameMon64.des", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found GameMon64.des\n");
        return 1;
    }

    return 0;
}

/*
 * Check for PunkBuster presence:
 *   - pb/ directory in game folder
 *   - PunkBuster/ directory
 *   - PnkBstrA.exe, PnkBstrB.exe
 */
static int detect_punkbuster(const char *game_dir)
{
    char path[MAX_PATH_LEN];

    snprintf(path, sizeof(path), "%s/pb", game_dir);
    if (dir_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found pb/ directory (PunkBuster)\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/PunkBuster", game_dir);
    if (dir_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found PunkBuster/ directory\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/PnkBstrA.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found PnkBstrA.exe\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/PnkBstrB.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found PnkBstrB.exe\n");
        return 1;
    }

    return 0;
}

/*
 * Check for Blackshield (IRONMACE / Dark and Darker) presence:
 *   - tavern.exe (Dark and Darker launcher / Blacksmith)
 *   - taverncomn.exe / tavernworker.exe (IRONMACE custom anti-cheat)
 *   - DungeonCrawler.exe or DungeonCrawler-Win64-Shipping.exe
 *   - Blackshield/ directory (legacy)
 *   - bshield.sys or bshield_svc.exe (legacy)
 *   - IRONMACE directory markers
 */
static int detect_blackshield(const char *game_dir)
{
    char path[MAX_PATH_LEN];

    /* tavern.exe is the main Dark and Darker launcher (Blacksmith) */
    snprintf(path, sizeof(path), "%s/tavern.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found tavern.exe (Blacksmith launcher)\n");
        return 1;
    }

    /* taverncomn / tavernworker: IRONMACE's custom anti-cheat processes */
    snprintf(path, sizeof(path), "%s/taverncomn.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found taverncomn.exe (IRONMACE anti-cheat)\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/tavernworker.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found tavernworker.exe (IRONMACE anti-cheat)\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/TavernWorker.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found TavernWorker.exe (IRONMACE anti-cheat)\n");
        return 1;
    }

    /* Game executable */
    snprintf(path, sizeof(path), "%s/DungeonCrawler.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found DungeonCrawler.exe\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/DungeonCrawler-Win64-Shipping.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found DungeonCrawler-Win64-Shipping.exe\n");
        return 1;
    }

    /* Blackshield directory (legacy — may still exist in older installs) */
    snprintf(path, sizeof(path), "%s/Blackshield", game_dir);
    if (dir_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found Blackshield/ directory\n");
        return 1;
    }

    /* Blackshield driver/service files (legacy) */
    snprintf(path, sizeof(path), "%s/bshield.sys", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found bshield.sys\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/bshield_svc.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found bshield_svc.exe\n");
        return 1;
    }

    /* IRONMACE launcher markers */
    snprintf(path, sizeof(path), "%s/IRONMACE", game_dir);
    if (dir_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found IRONMACE/ directory\n");
        return 1;
    }

    /* Check parent directory for IRONMACE pattern */
    snprintf(path, sizeof(path), "%s/../tavern.exe", game_dir);
    if (file_exists(path)) {
        fprintf(stderr, AC_LOG_PREFIX "Found tavern.exe in parent directory\n");
        return 1;
    }

    return 0;
}

/* --- Environment setup functions --- */

static int setup_eac_environment(const char *game_dir)
{
    char path[MAX_PATH_LEN];

    fprintf(stderr, AC_LOG_PREFIX "Setting up EasyAntiCheat environment\n");

    /* Create EasyAntiCheat directory structure */
    snprintf(path, sizeof(path), "%s/EasyAntiCheat", game_dir);
    mkdir_p(path);
    fprintf(stderr, AC_LOG_PREFIX "Ensured directory: %s\n", path);

    snprintf(path, sizeof(path), "%s/EasyAntiCheat/Certificates", game_dir);
    mkdir_p(path);

    /* Create registry entries for EAC service */
    create_fake_registry_key("HKLM",
        "SYSTEM/CurrentControlSet/Services/EasyAntiCheat");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/EasyAntiCheat",
        "DisplayName", "EasyAntiCheat");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/EasyAntiCheat",
        "ImagePath",
        "C:\\Program Files (x86)\\EasyAntiCheat\\EasyAntiCheat.exe");

    /* Register EAC as a Windows service via SCM database */
    register_fake_service("EasyAntiCheat", "EasyAntiCheat Service",
                          "EasyAntiCheat.exe",
                          0x00000010, /* SERVICE_WIN32_OWN_PROCESS */
                          3);         /* SERVICE_DEMAND_START */

    /* Create EAC installation registry key */
    create_fake_registry_key("HKLM",
        "SOFTWARE/EasyAntiCheat");
    create_fake_registry_value("HKLM",
        "SOFTWARE/EasyAntiCheat",
        "InstallDir", "C:\\Program Files (x86)\\EasyAntiCheat");

    fprintf(stderr, AC_LOG_PREFIX "EasyAntiCheat environment ready\n");
    return 0;
}

static int setup_battleye_environment(const char *game_dir)
{
    char path[MAX_PATH_LEN];

    fprintf(stderr, AC_LOG_PREFIX "Setting up BattlEye environment\n");

    /* Create BattlEye directory structure */
    snprintf(path, sizeof(path), "%s/BattlEye", game_dir);
    mkdir_p(path);
    fprintf(stderr, AC_LOG_PREFIX "Ensured directory: %s\n", path);

    snprintf(path, sizeof(path), "%s/BattlEye/BELauncher", game_dir);
    mkdir_p(path);

    /* Registry entries for BattlEye */
    create_fake_registry_key("HKLM",
        "SYSTEM/CurrentControlSet/Services/BEService");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/BEService",
        "DisplayName", "BattlEye Service");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/BEService",
        "ImagePath",
        "C:\\Program Files (x86)\\Common Files\\BattlEye\\BEService.exe");

    create_fake_registry_key("HKLM",
        "SYSTEM/CurrentControlSet/Services/BEDaisy");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/BEDaisy",
        "DisplayName", "BattlEye Kernel Driver");

    /* Register BattlEye as a Windows service */
    register_fake_service("BEService", "BattlEye Service",
                          "BEService.exe",
                          0x00000010, /* SERVICE_WIN32_OWN_PROCESS */
                          3);         /* SERVICE_DEMAND_START */

    /* Register BattlEye kernel driver (fake) */
    register_fake_service("BEDaisy", "BattlEye Protection Driver",
                          "BEDaisy.sys",
                          0x00000001, /* SERVICE_KERNEL_DRIVER */
                          3);         /* SERVICE_DEMAND_START */

    fprintf(stderr, AC_LOG_PREFIX "BattlEye environment ready\n");
    return 0;
}

static int setup_vanguard_environment(void)
{
    fprintf(stderr, AC_LOG_PREFIX "Setting up Riot Vanguard environment\n");

    /* Registry entries for Vanguard client service */
    create_fake_registry_key("HKLM",
        "SYSTEM/CurrentControlSet/Services/vgc");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/vgc",
        "DisplayName", "Vanguard Client");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/vgc",
        "ImagePath",
        "C:\\Program Files\\Riot Vanguard\\vgc.exe");

    /* Registry entries for Vanguard kernel driver */
    create_fake_registry_key("HKLM",
        "SYSTEM/CurrentControlSet/Services/vgk");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/vgk",
        "DisplayName", "Vanguard");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/vgk",
        "ImagePath",
        "\\SystemRoot\\System32\\drivers\\vgk.sys");

    /* Register Vanguard services */
    register_fake_service("vgc", "Vanguard Client",
                          "vgc.exe",
                          0x00000010, /* SERVICE_WIN32_OWN_PROCESS */
                          2);         /* SERVICE_AUTO_START */

    register_fake_service("vgk", "Vanguard Kernel Driver",
                          "vgk.sys",
                          0x00000001, /* SERVICE_KERNEL_DRIVER */
                          0);         /* SERVICE_BOOT_START */

    /* Vanguard checks for its tray icon process */
    create_fake_registry_key("HKLM",
        "SOFTWARE/Riot Vanguard");
    create_fake_registry_value("HKLM",
        "SOFTWARE/Riot Vanguard",
        "InstallDir", "C:\\Program Files\\Riot Vanguard");

    fprintf(stderr, AC_LOG_PREFIX "Riot Vanguard environment ready\n");
    return 0;
}

static int setup_gameguard_environment(const char *game_dir)
{
    char path[MAX_PATH_LEN];

    fprintf(stderr, AC_LOG_PREFIX "Setting up GameGuard (nProtect) environment\n");

    /* Create GameGuard directory structure */
    snprintf(path, sizeof(path), "%s/GameGuard", game_dir);
    mkdir_p(path);
    fprintf(stderr, AC_LOG_PREFIX "Ensured directory: %s\n", path);

    /* Registry entries for GameGuard */
    create_fake_registry_key("HKLM",
        "SYSTEM/CurrentControlSet/Services/npggsvc");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/npggsvc",
        "DisplayName", "nProtect GameGuard Service");

    /* Register GameGuard service */
    register_fake_service("npggsvc", "nProtect GameGuard Service",
                          "GameMon.des",
                          0x00000010, /* SERVICE_WIN32_OWN_PROCESS */
                          3);         /* SERVICE_DEMAND_START */

    /* GameGuard also uses a kernel driver */
    create_fake_registry_key("HKLM",
        "SYSTEM/CurrentControlSet/Services/npptNT2");
    register_fake_service("npptNT2", "nProtect GameGuard Protection Driver",
                          "npptNT2.sys",
                          0x00000001, /* SERVICE_KERNEL_DRIVER */
                          3);         /* SERVICE_DEMAND_START */

    fprintf(stderr, AC_LOG_PREFIX "GameGuard environment ready\n");
    return 0;
}

static int setup_punkbuster_environment(const char *game_dir)
{
    char path[MAX_PATH_LEN];

    fprintf(stderr, AC_LOG_PREFIX "Setting up PunkBuster environment\n");

    /* Create PunkBuster directory structure */
    snprintf(path, sizeof(path), "%s/pb", game_dir);
    mkdir_p(path);
    fprintf(stderr, AC_LOG_PREFIX "Ensured directory: %s\n", path);

    snprintf(path, sizeof(path), "%s/pb/htm", game_dir);
    mkdir_p(path);

    snprintf(path, sizeof(path), "%s/pb/dll", game_dir);
    mkdir_p(path);

    /* Registry entries for PunkBuster */
    create_fake_registry_key("HKLM",
        "SYSTEM/CurrentControlSet/Services/PnkBstrA");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/PnkBstrA",
        "DisplayName", "PnkBstrA");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/PnkBstrA",
        "ImagePath",
        "C:\\Windows\\system32\\PnkBstrA.exe");

    create_fake_registry_key("HKLM",
        "SYSTEM/CurrentControlSet/Services/PnkBstrB");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/PnkBstrB",
        "DisplayName", "PnkBstrB");

    /* Register PunkBuster services */
    register_fake_service("PnkBstrA", "PunkBuster Service A",
                          "PnkBstrA.exe",
                          0x00000010, /* SERVICE_WIN32_OWN_PROCESS */
                          2);         /* SERVICE_AUTO_START */

    register_fake_service("PnkBstrB", "PunkBuster Service B",
                          "PnkBstrB.exe",
                          0x00000010, /* SERVICE_WIN32_OWN_PROCESS */
                          3);         /* SERVICE_DEMAND_START */

    /* PunkBuster installation registry key */
    create_fake_registry_key("HKLM",
        "SOFTWARE/Even Balance/PunkBuster");
    create_fake_registry_value("HKLM",
        "SOFTWARE/Even Balance/PunkBuster",
        "InstallPath", "C:\\Program Files (x86)\\PunkBuster");

    fprintf(stderr, AC_LOG_PREFIX "PunkBuster environment ready\n");
    return 0;
}

static int setup_blackshield_environment(const char *game_dir)
{
    char path[MAX_PATH_LEN];

    fprintf(stderr, AC_LOG_PREFIX "Setting up IRONMACE/Tavern anti-cheat environment\n");

    /* Create Blackshield directory structure (legacy compat) */
    snprintf(path, sizeof(path), "%s/Blackshield", game_dir);
    mkdir_p(path);

    /* Registry entries for legacy Blackshield kernel driver */
    create_fake_registry_key("HKLM",
        "SYSTEM/CurrentControlSet/Services/bshield");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/bshield",
        "DisplayName", "Blackshield Anti-Cheat Driver");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/bshield",
        "ImagePath", "\\SystemRoot\\System32\\drivers\\bshield.sys");

    /* Registry entries for legacy Blackshield client service */
    create_fake_registry_key("HKLM",
        "SYSTEM/CurrentControlSet/Services/bshield_svc");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/bshield_svc",
        "DisplayName", "Blackshield Anti-Cheat Service");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/bshield_svc",
        "ImagePath",
        "C:\\Program Files\\IRONMACE\\Blackshield\\bshield_svc.exe");

    /* Register legacy Blackshield services */
    register_fake_service("bshield", "Blackshield Anti-Cheat Driver",
                          "bshield.sys",
                          0x00000001, /* SERVICE_KERNEL_DRIVER */
                          3);         /* SERVICE_DEMAND_START */

    register_fake_service("bshield_svc", "Blackshield Anti-Cheat Service",
                          "bshield_svc.exe",
                          0x00000010, /* SERVICE_WIN32_OWN_PROCESS */
                          2);         /* SERVICE_AUTO_START */

    /* Tavern anti-cheat services (current IRONMACE custom AC) */
    create_fake_registry_key("HKLM",
        "SYSTEM/CurrentControlSet/Services/taverncomn");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/taverncomn",
        "DisplayName", "IRONMACE Anti-Cheat Monitor");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/taverncomn",
        "ImagePath",
        "C:\\Program Files\\IRONMACE\\DarkAndDarker\\taverncomn.exe");

    create_fake_registry_key("HKLM",
        "SYSTEM/CurrentControlSet/Services/tavernworker");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/tavernworker",
        "DisplayName", "IRONMACE Anti-Cheat Worker");
    create_fake_registry_value("HKLM",
        "SYSTEM/CurrentControlSet/Services/tavernworker",
        "ImagePath",
        "C:\\Program Files\\IRONMACE\\DarkAndDarker\\tavernworker.exe");

    register_fake_service("taverncomn", "IRONMACE Anti-Cheat Monitor",
                          "taverncomn.exe",
                          0x00000010, /* SERVICE_WIN32_OWN_PROCESS */
                          2);         /* SERVICE_AUTO_START */

    register_fake_service("tavernworker", "IRONMACE Anti-Cheat Worker",
                          "tavernworker.exe",
                          0x00000010, /* SERVICE_WIN32_OWN_PROCESS */
                          2);         /* SERVICE_AUTO_START */

    /* IRONMACE / Dark and Darker registry keys */
    create_fake_registry_key("HKLM",
        "SOFTWARE/IRONMACE/DarkAndDarker");
    create_fake_registry_value("HKLM",
        "SOFTWARE/IRONMACE/DarkAndDarker",
        "InstallDir", game_dir);

    fprintf(stderr, AC_LOG_PREFIX "IRONMACE/Tavern anti-cheat environment ready\n");
    return 0;
}

/* --- Public API --- */

/*
 * ac_detect_type - Detect which anti-cheat system a game uses
 *
 * @game_dir: Path to the game installation directory
 *
 * Returns the detected anti-cheat type, or AC_NONE if none found.
 * Checks in priority order: EAC, BattlEye, Vanguard, GameGuard, PunkBuster.
 */
ac_type_t ac_detect_type(const char *game_dir)
{
    if (!game_dir || !game_dir[0]) {
        fprintf(stderr, AC_LOG_PREFIX "ac_detect_type: no game directory specified\n");
        return AC_NONE;
    }

    fprintf(stderr, AC_LOG_PREFIX "Scanning game directory: %s\n", game_dir);

    if (detect_eac(game_dir)) {
        fprintf(stderr, AC_LOG_PREFIX "Detected anti-cheat: EasyAntiCheat\n");
        return AC_EASY_ANTI_CHEAT;
    }

    if (detect_battleye(game_dir)) {
        fprintf(stderr, AC_LOG_PREFIX "Detected anti-cheat: BattlEye\n");
        return AC_BATTLEYE;
    }

    if (detect_vanguard(game_dir)) {
        fprintf(stderr, AC_LOG_PREFIX "Detected anti-cheat: Riot Vanguard\n");
        return AC_VANGUARD;
    }

    if (detect_gameguard(game_dir)) {
        fprintf(stderr, AC_LOG_PREFIX "Detected anti-cheat: nProtect GameGuard\n");
        return AC_GAMEGUARD;
    }

    if (detect_punkbuster(game_dir)) {
        fprintf(stderr, AC_LOG_PREFIX "Detected anti-cheat: PunkBuster\n");
        return AC_PUNKBUSTER;
    }

    if (detect_blackshield(game_dir)) {
        fprintf(stderr, AC_LOG_PREFIX "Detected anti-cheat: Blackshield (IRONMACE)\n");
        return AC_BLACKSHIELD;
    }

    fprintf(stderr, AC_LOG_PREFIX "No known anti-cheat system detected\n");
    return AC_NONE;
}

/*
 * ac_init - Initialize the anti-cheat compatibility layer
 *
 * @game_dir: Path to the game installation directory
 *
 * Detects the anti-cheat type and stores state for subsequent calls.
 * Returns 0 on success, -1 on error.
 */
int ac_init(const char *game_dir)
{
    if (!game_dir || !game_dir[0]) {
        fprintf(stderr, AC_LOG_PREFIX "ac_init: game directory is required\n");
        return -1;
    }

    if (g_ac_state.initialized) {
        fprintf(stderr, AC_LOG_PREFIX "ac_init: already initialized, cleaning up first\n");
        ac_cleanup();
    }

    fprintf(stderr, AC_LOG_PREFIX "Initializing anti-cheat compatibility layer\n");

    strncpy(g_ac_state.game_dir, game_dir, sizeof(g_ac_state.game_dir) - 1);
    g_ac_state.game_dir[sizeof(g_ac_state.game_dir) - 1] = '\0';

    /* Ensure base directories exist */
    mkdir_p(AC_BASE_PATH);
    mkdir_p(AC_REG_PATH);
    mkdir_p(AC_SVC_PATH);

    /* Detect anti-cheat type */
    g_ac_state.type = ac_detect_type(game_dir);
    g_ac_state.initialized = 1;
    g_ac_state.environment_ready = 0;

    const char *type_names[] = {
        "None", "EasyAntiCheat", "BattlEye",
        "Vanguard", "GameGuard", "PunkBuster", "Blackshield"
    };
    fprintf(stderr, AC_LOG_PREFIX "Initialized: type=%s, game_dir=%s\n",
            type_names[g_ac_state.type], g_ac_state.game_dir);

    return 0;
}

/*
 * ac_setup_environment - Set up the compatibility environment for the detected anti-cheat
 *
 * Must call ac_init() first. Creates fake registry entries, expected file
 * paths, and service registrations appropriate for the detected anti-cheat.
 *
 * Returns 0 on success, -1 on error.
 */
int ac_setup_environment(void)
{
    if (!g_ac_state.initialized) {
        fprintf(stderr, AC_LOG_PREFIX "ac_setup_environment: not initialized\n");
        return -1;
    }

    if (g_ac_state.type == AC_NONE) {
        fprintf(stderr, AC_LOG_PREFIX "ac_setup_environment: no anti-cheat detected, "
                "nothing to set up\n");
        return 0;
    }

    fprintf(stderr, AC_LOG_PREFIX "Setting up compatibility environment\n");

    int ret = 0;

    switch (g_ac_state.type) {
    case AC_EASY_ANTI_CHEAT:
        ret = setup_eac_environment(g_ac_state.game_dir);
        break;
    case AC_BATTLEYE:
        ret = setup_battleye_environment(g_ac_state.game_dir);
        break;
    case AC_VANGUARD:
        ret = setup_vanguard_environment();
        break;
    case AC_GAMEGUARD:
        ret = setup_gameguard_environment(g_ac_state.game_dir);
        break;
    case AC_PUNKBUSTER:
        ret = setup_punkbuster_environment(g_ac_state.game_dir);
        break;
    case AC_BLACKSHIELD:
        ret = setup_blackshield_environment(g_ac_state.game_dir);
        break;
    default:
        break;
    }

    if (ret == 0) {
        g_ac_state.environment_ready = 1;
        fprintf(stderr, AC_LOG_PREFIX "Compatibility environment set up successfully\n");
    } else {
        fprintf(stderr, AC_LOG_PREFIX "Failed to set up compatibility environment\n");
    }

    return ret;
}

/*
 * ac_cleanup - Clean up anti-cheat compatibility state
 *
 * Resets internal state. Does not remove files or registry entries
 * that were created during setup (they may be needed by running games).
 *
 * Returns 0 on success.
 */
int ac_cleanup(void)
{
    if (!g_ac_state.initialized) {
        fprintf(stderr, AC_LOG_PREFIX "ac_cleanup: not initialized\n");
        return 0;
    }

    const char *type_names[] = {
        "None", "EasyAntiCheat", "BattlEye",
        "Vanguard", "GameGuard", "PunkBuster", "Blackshield"
    };
    fprintf(stderr, AC_LOG_PREFIX "Cleaning up anti-cheat state (was: %s)\n",
            type_names[g_ac_state.type]);

    memset(&g_ac_state, 0, sizeof(g_ac_state));

    fprintf(stderr, AC_LOG_PREFIX "Cleanup complete\n");
    return 0;
}

/*
 * registry.c - Windows Registry emulation
 *
 * Implements a tree-based registry that maps to a file-backed store.
 * Registry keys map to directories, values map to files.
 * Root hives:
 *   HKEY_LOCAL_MACHINE  -> ~/.pe-compat/registry/HKLM/
 *   HKEY_CURRENT_USER   -> ~/.pe-compat/registry/HKCU/
 *   HKEY_CLASSES_ROOT   -> ~/.pe-compat/registry/HKCR/
 *   HKEY_USERS          -> ~/.pe-compat/registry/HKU/
 *   HKEY_CURRENT_CONFIG -> ~/.pe-compat/registry/HKCC/
 */

/* Path operations intentionally allow truncation for safety */
#pragma GCC diagnostic ignored "-Wformat-truncation"
#pragma GCC diagnostic ignored "-Wstringop-truncation"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  /* strcasecmp, strncasecmp */
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>

#include "registry.h"

/* Reject path components that could escape the registry root.
 *
 * Windows registry allows ".." as a substring within names (e.g. value
 * names like "config..backup" are legal).  We only reject ".." when it
 * appears as an entire path component -- i.e. bracketed by path separators
 * or at the start/end of the string.  Path separators in the registry
 * API are backslashes; forward slashes are treated as literal chars by
 * Windows but we also treat them as separators because we translate them
 * to filesystem slashes later. */
static int registry_validate_name(const char *name)
{
    if (!name || !*name)
        return 0;  /* empty is OK (root key) */

    /* Reject absolute paths */
    if (name[0] == '/' || name[0] == '\\')
        return -1;

    /* Walk components separated by '\\' or '/' and reject any that are
     * exactly "..".  Also reject any single component equal to "." which
     * would be a no-op traversal. */
    const char *p = name;
    const char *comp = name;
    while (1) {
        char c = *p;
        if (c == '\\' || c == '/' || c == '\0') {
            size_t len = (size_t)(p - comp);
            if (len == 2 && comp[0] == '.' && comp[1] == '.')
                return -1;
            if (len == 1 && comp[0] == '.')
                return -1;
            if (c == '\0') break;
            comp = p + 1;
        }
        p++;
    }
    return 0;
}

/* Predefined HKEY values (same as Windows) */
#define HKEY_CLASSES_ROOT     ((HKEY)(uintptr_t)0x80000000)
#define HKEY_CURRENT_USER     ((HKEY)(uintptr_t)0x80000001)
#define HKEY_LOCAL_MACHINE    ((HKEY)(uintptr_t)0x80000002)
#define HKEY_USERS            ((HKEY)(uintptr_t)0x80000003)
#define HKEY_CURRENT_CONFIG   ((HKEY)(uintptr_t)0x80000005)

/* Registry value types */
#define REG_NONE         0
#define REG_SZ           1
#define REG_EXPAND_SZ    2
#define REG_BINARY       3
#define REG_DWORD        4
#define REG_DWORD_BIG_ENDIAN 5
#define REG_MULTI_SZ     7
#define REG_QWORD        11

/* Error codes */
#define ERROR_SUCCESS           0
#define ERROR_FILE_NOT_FOUND    2
#define ERROR_ACCESS_DENIED     5
#define ERROR_INVALID_HANDLE    6
#define ERROR_OUTOFMEMORY       14
#define ERROR_INVALID_PARAMETER 87
#define ERROR_MORE_DATA         234
#define ERROR_NO_MORE_ITEMS     259

/* Registry key data stored in handle */
typedef struct {
    char path[4096]; /* Linux filesystem path for this key */
    int  enum_index; /* For RegEnumKeyEx / RegEnumValue */
} reg_key_data_t;

static char g_registry_root[4096] = {0};

static void ensure_registry_root(void)
{
    if (g_registry_root[0])
        return;

    const char *home = getenv("HOME");
    if (!home)
        home = "/tmp";

    snprintf(g_registry_root, sizeof(g_registry_root),
             "%s/.pe-compat/registry", home);

    /* Create base directory structure */
    char buf[4096];
    snprintf(buf, sizeof(buf), "%s/HKLM", g_registry_root);
    mkdir(g_registry_root, 0755);
    mkdir(buf, 0755);
    snprintf(buf, sizeof(buf), "%s/HKCU", g_registry_root);
    mkdir(buf, 0755);
    snprintf(buf, sizeof(buf), "%s/HKCR", g_registry_root);
    mkdir(buf, 0755);
    snprintf(buf, sizeof(buf), "%s/HKU", g_registry_root);
    mkdir(buf, 0755);
    snprintf(buf, sizeof(buf), "%s/HKCC", g_registry_root);
    mkdir(buf, 0755);
}

/* Map a predefined HKEY to its directory prefix */
static const char *hkey_to_prefix(HKEY hKey)
{
    uintptr_t val = (uintptr_t)hKey;
    switch (val) {
    case 0x80000000: return "HKCR";
    case 0x80000001: return "HKCU";
    case 0x80000002: return "HKLM";
    case 0x80000003: return "HKU";
    case 0x80000005: return "HKCC";
    default:         return NULL;
    }
}

/* Check if HKEY is a predefined root */
static int is_predefined_hkey(HKEY hKey)
{
    uintptr_t val = (uintptr_t)hKey;
    return (val >= 0x80000000 && val <= 0x80000005);
}

/*
 * HKCR merge view helpers.
 *
 * Windows semantics: HKEY_CLASSES_ROOT is a virtual merged view of
 *   HKCU\SOFTWARE\Classes  (per-user overrides, wins on collision)
 * overlaid on
 *   HKLM\SOFTWARE\Classes  (system-wide defaults)
 *
 * We implement this by resolving HKCR subkeys against both HKCU\SOFTWARE\Classes
 * and HKLM\SOFTWARE\Classes, preferring HKCU when the key/value exists there.
 * The legacy ~/.pe-compat/registry/HKCR/ directory is kept as a fallback (some
 * callers historically write to it directly) but is checked last.
 */
static void build_hkcr_candidate(const char *base, const char *subkey,
                                 char *out, size_t size)
{
    if (subkey && subkey[0])
        snprintf(out, size, "%s/SOFTWARE/Classes/%s", base, subkey);
    else
        snprintf(out, size, "%s/SOFTWARE/Classes", base);
    for (char *p = out; *p; p++) {
        if (*p == '\\') *p = '/';
    }
}

static int path_is_dir(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

/* Resolve an HKCR-relative path to the best concrete filesystem path.
 * Priority: HKCU\SOFTWARE\Classes -> HKLM\SOFTWARE\Classes -> legacy HKCR dir.
 * If none exist yet and for_write is set, return the HKLM path so writes
 * land in a Windows-compatible location. Caller converts slashes. */
static void resolve_hkcr_path(const char *subkey, char *out, size_t size,
                              int for_write)
{
    char hkcu_path[4096], hklm_path[4096], legacy_path[4096];
    char hkcu_base[4096], hklm_base[4096];

    snprintf(hkcu_base, sizeof(hkcu_base), "%s/HKCU", g_registry_root);
    snprintf(hklm_base, sizeof(hklm_base), "%s/HKLM", g_registry_root);

    build_hkcr_candidate(hkcu_base, subkey, hkcu_path, sizeof(hkcu_path));
    build_hkcr_candidate(hklm_base, subkey, hklm_path, sizeof(hklm_path));
    if (subkey && subkey[0])
        snprintf(legacy_path, sizeof(legacy_path), "%s/HKCR/%s",
                 g_registry_root, subkey);
    else
        snprintf(legacy_path, sizeof(legacy_path), "%s/HKCR", g_registry_root);
    for (char *p = legacy_path; *p; p++) {
        if (*p == '\\') *p = '/';
    }

    /* Read: HKCU first (user wins), then HKLM, then legacy. */
    if (!for_write) {
        if (path_is_dir(hkcu_path))   { snprintf(out, size, "%s", hkcu_path); return; }
        if (path_is_dir(hklm_path))   { snprintf(out, size, "%s", hklm_path); return; }
        if (path_is_dir(legacy_path)) { snprintf(out, size, "%s", legacy_path); return; }
        /* None exist -- return HKLM path so open-then-auto-create lands
         * in the Windows-canonical location. */
        snprintf(out, size, "%s", hklm_path);
        return;
    }

    /* Write: prefer existing HKCU, else existing HKLM, else legacy if it
     * already exists (don't regress callers who wrote there); default HKLM. */
    if (path_is_dir(hkcu_path))   { snprintf(out, size, "%s", hkcu_path); return; }
    if (path_is_dir(hklm_path))   { snprintf(out, size, "%s", hklm_path); return; }
    if (path_is_dir(legacy_path)) { snprintf(out, size, "%s", legacy_path); return; }
    snprintf(out, size, "%s", hklm_path);
}

/*
 * Build the filesystem path for a registry key.
 *
 * NOTE: Multi-level subkey paths (e.g. "SOFTWARE\Microsoft\Windows") are
 * supported via backslash-to-slash conversion, mapping each component to a
 * directory level in the filesystem.  However, this requires every intermediate
 * directory to already exist.  registry_open_key() will fail with
 * ERROR_FILE_NOT_FOUND if any component in the middle is missing, even if the
 * leaf exists.  registry_create_key() handles this via mkdir_recursive().
 * We auto-create intermediate directories when opening well-known paths
 * (Windows apps assume parent keys exist for paths like
 * HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion).
 *
 * HKCR paths are virtualised: reads prefer HKCU\SOFTWARE\Classes then
 * HKLM\SOFTWARE\Classes (see resolve_hkcr_path).  for_write=1 biases the
 * path towards a location suitable for writes (existing user override if
 * present, else HKLM system-wide).
 */
static int build_key_path_ex(HKEY hKey, const char *subkey,
                             char *path, size_t size, int for_write)
{
    ensure_registry_root();

    if (is_predefined_hkey(hKey)) {
        uintptr_t val = (uintptr_t)hKey;
        if (val == 0x80000000) {
            /* HKCR: resolve through merge view */
            resolve_hkcr_path(subkey, path, size, for_write);
        } else {
            const char *prefix = hkey_to_prefix(hKey);
            if (!prefix) return -1;

            if (subkey && subkey[0]) {
                snprintf(path, size, "%s/%s/%s", g_registry_root, prefix, subkey);
            } else {
                snprintf(path, size, "%s/%s", g_registry_root, prefix);
            }
        }
    } else {
        /* hKey is an opened key handle - look up its path */
        handle_entry_t *entry = handle_lookup(hKey);
        if (!entry || entry->type != HANDLE_TYPE_REGISTRY_KEY)
            return -1;

        reg_key_data_t *data = (reg_key_data_t *)entry->data;
        if (subkey && subkey[0]) {
            snprintf(path, size, "%s/%s", data->path, subkey);
        } else {
            snprintf(path, size, "%s", data->path);
        }
    }

    /* Convert backslashes to forward slashes */
    for (char *p = path; *p; p++) {
        if (*p == '\\')
            *p = '/';
    }

    return 0;
}

static int build_key_path(HKEY hKey, const char *subkey, char *path, size_t size)
{
    return build_key_path_ex(hKey, subkey, path, size, 0);
}

/* Create directories recursively (creates all intermediate components) */
static int mkdir_recursive(const char *path)
{
    char tmp[4096];
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

/*
 * Ensure all parent directories for a given path exist.
 * This is called before opening or creating registry keys so that
 * intermediate keys are automatically materialised -- Windows apps
 * assume parents exist for well-known paths like
 * HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion.
 */
static void ensure_key_parents(const char *path)
{
    char tmp[4096];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    /* Note: we do NOT mkdir the final component here --
     * that is the caller's responsibility. */
}

/*
 * Whitelist of subkey prefixes for which RegOpenKeyEx is allowed to
 * auto-create missing intermediate directories. Many Windows apps call
 * RegOpenKeyEx on well-known hierarchies and expect the keys to already
 * exist; without auto-create they would see ERROR_FILE_NOT_FOUND and fail
 * to launch. But auto-creating on any arbitrary subkey pollutes the
 * registry tree with empty dirs (Session 25 Agent 9 concern). Only the
 * canonical system hives are whitelisted here.
 */
static int is_whitelisted_auto_create(const char *subkey)
{
    if (!subkey || !*subkey)
        return 1;  /* opening a predefined root itself */
    /* Match case-insensitive prefix - Windows registry paths are CI */
    static const char *prefixes[] = {
        "SOFTWARE",
        "SOFTWARE\\Microsoft",
        "SOFTWARE\\Classes",
        "SOFTWARE\\Wow6432Node",
        "SOFTWARE\\WOW6432Node",
        "SYSTEM\\CurrentControlSet",
        "SYSTEM",
        "HARDWARE",
        "SECURITY",
        "SAM",
        NULL
    };
    for (int i = 0; prefixes[i]; i++) {
        size_t len = strlen(prefixes[i]);
        if (strncasecmp(subkey, prefixes[i], len) == 0) {
            char next = subkey[len];
            if (next == '\0' || next == '\\' || next == '/')
                return 1;
        }
    }
    return 0;
}

/* --- Public API --- */

LONG registry_open_key(HKEY hKey, const char *subkey, HKEY *result)
{
    if (!result)
        return ERROR_INVALID_PARAMETER;

    if (registry_validate_name(subkey) < 0)
        return ERROR_INVALID_PARAMETER;

    char path[4096];
    if (build_key_path(hKey, subkey, path, sizeof(path)) < 0)
        return ERROR_INVALID_HANDLE;

    /*
     * Auto-create intermediate directories -- but ONLY for whitelisted
     * system paths.  Many Windows applications call RegOpenKeyEx on
     * well-known paths like HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
     * and expect every component to already exist.  But auto-creating on
     * arbitrary subkeys pollutes the registry tree with empty dirs.
     */
    if (is_whitelisted_auto_create(subkey)) {
        ensure_key_parents(path);
        mkdir(path, 0755);  /* create leaf key if not present */
    }

    struct stat st;
    if (stat(path, &st) < 0 || !S_ISDIR(st.st_mode))
        return ERROR_FILE_NOT_FOUND;

    reg_key_data_t *data = calloc(1, sizeof(reg_key_data_t));
    if (!data)
        return ERROR_OUTOFMEMORY;

    strncpy(data->path, path, sizeof(data->path) - 1);
    data->enum_index = 0;

    *result = handle_alloc(HANDLE_TYPE_REGISTRY_KEY, -1, data);
    if (*result == INVALID_HANDLE_VALUE) {
        free(data);
        return ERROR_OUTOFMEMORY;
    }

    return ERROR_SUCCESS;
}

LONG registry_create_key(HKEY hKey, const char *subkey, HKEY *result)
{
    if (!result)
        return ERROR_INVALID_PARAMETER;

    if (registry_validate_name(subkey) < 0)
        return ERROR_INVALID_PARAMETER;

    char path[4096];
    /* Writes to HKCR should land in an appropriate HKLM/HKCU mirror. */
    if (build_key_path_ex(hKey, subkey, path, sizeof(path), 1) < 0)
        return ERROR_INVALID_HANDLE;

    ensure_key_parents(path);
    mkdir_recursive(path);

    reg_key_data_t *data = calloc(1, sizeof(reg_key_data_t));
    if (!data)
        return ERROR_OUTOFMEMORY;

    strncpy(data->path, path, sizeof(data->path) - 1);
    data->enum_index = 0;

    *result = handle_alloc(HANDLE_TYPE_REGISTRY_KEY, -1, data);
    if (*result == INVALID_HANDLE_VALUE) {
        free(data);
        return ERROR_OUTOFMEMORY;
    }

    return ERROR_SUCCESS;
}

LONG registry_close_key(HKEY hKey)
{
    if (is_predefined_hkey(hKey))
        return ERROR_SUCCESS; /* Predefined keys can't be closed */

    if (handle_close(hKey) < 0)
        return ERROR_INVALID_HANDLE;

    return ERROR_SUCCESS;
}

LONG registry_set_value(HKEY hKey, const char *name, DWORD type,
                        const void *data, DWORD size)
{
    if (registry_validate_name(name) < 0)
        return ERROR_INVALID_PARAMETER;

    char key_path[4096];
    if (is_predefined_hkey(hKey)) {
        /* Writes to HKCR root-level default values route via merge-view write path */
        if (build_key_path_ex(hKey, NULL, key_path, sizeof(key_path), 1) < 0)
            return ERROR_INVALID_HANDLE;
    } else {
        handle_entry_t *entry = handle_lookup(hKey);
        if (!entry || entry->type != HANDLE_TYPE_REGISTRY_KEY)
            return ERROR_INVALID_HANDLE;
        reg_key_data_t *kd = (reg_key_data_t *)entry->data;
        strncpy(key_path, kd->path, sizeof(key_path) - 1);
        key_path[sizeof(key_path) - 1] = '\0';
    }

    /* Value file name: "@" for default value, otherwise the value name */
    const char *val_name = (name && name[0]) ? name : "@";

    char val_path[4096];
    snprintf(val_path, sizeof(val_path), "%s/.values/%s", key_path, val_name);

    /* Ensure .values directory exists */
    char dir_path[4096];
    snprintf(dir_path, sizeof(dir_path), "%s/.values", key_path);
    mkdir(dir_path, 0755);

    /* Write value file: 4 bytes type + N bytes data */
    FILE *f = fopen(val_path, "wb");
    if (!f)
        return ERROR_ACCESS_DENIED;

    size_t written = fwrite(&type, sizeof(DWORD), 1, f);
    if (data && size > 0)
        written += fwrite(data, 1, size, f);
    fclose(f);
    if (written == 0) return ERROR_ACCESS_DENIED;

    return ERROR_SUCCESS;
}

LONG registry_get_value(HKEY hKey, const char *subkey, const char *name,
                        DWORD *type, void *data, DWORD *size)
{
    if (registry_validate_name(name) < 0)
        return ERROR_INVALID_PARAMETER;

    char key_path[4096];
    if (subkey && subkey[0]) {
        if (build_key_path(hKey, subkey, key_path, sizeof(key_path)) < 0)
            return ERROR_INVALID_HANDLE;
    } else if (is_predefined_hkey(hKey)) {
        if (build_key_path(hKey, NULL, key_path, sizeof(key_path)) < 0)
            return ERROR_INVALID_HANDLE;
    } else {
        handle_entry_t *entry = handle_lookup(hKey);
        if (!entry || entry->type != HANDLE_TYPE_REGISTRY_KEY)
            return ERROR_INVALID_HANDLE;
        reg_key_data_t *kd = (reg_key_data_t *)entry->data;
        strncpy(key_path, kd->path, sizeof(key_path) - 1);
        key_path[sizeof(key_path) - 1] = '\0';
    }

    const char *val_name = (name && name[0]) ? name : "@";

    char val_path[4096];
    snprintf(val_path, sizeof(val_path), "%s/.values/%s", key_path, val_name);

    FILE *f = fopen(val_path, "rb");
    /* HKCR merge-view fallback: if the HKCU resolution missed the value,
     * fall back to HKLM\SOFTWARE\Classes. build_key_path() already picks
     * HKCU if its directory exists, but the value file might only live on
     * the HKLM side. */
    if (!f && is_predefined_hkey(hKey) && (uintptr_t)hKey == 0x80000000) {
        char hklm_base[4096];
        char hklm_path[4096];
        snprintf(hklm_base, sizeof(hklm_base), "%s/HKLM", g_registry_root);
        build_hkcr_candidate(hklm_base, subkey, hklm_path, sizeof(hklm_path));
        char fallback_val[4096];
        snprintf(fallback_val, sizeof(fallback_val), "%s/.values/%s",
                 hklm_path, val_name);
        for (char *p = fallback_val; *p; p++) {
            if (*p == '\\') *p = '/';
        }
        f = fopen(fallback_val, "rb");
    }
    if (!f)
        return ERROR_FILE_NOT_FOUND;

    /* Read type */
    DWORD val_type;
    if (fread(&val_type, sizeof(DWORD), 1, f) != 1) {
        fclose(f);
        return ERROR_FILE_NOT_FOUND;
    }

    if (type)
        *type = val_type;

    /* Determine data size */
    long pos = ftell(f);
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, pos, SEEK_SET);
    DWORD data_size = (DWORD)(file_size - pos);

    if (!data || !size) {
        /* Query size only (lpData is NULL) -- return required size */
        if (size)
            *size = data_size;
        fclose(f);
        return ERROR_SUCCESS;
    }

    if (*size == 0) {
        /* Caller provided a buffer pointer but zero size -- buffer too small */
        *size = data_size;
        fclose(f);
        return data_size > 0 ? ERROR_MORE_DATA : ERROR_SUCCESS;
    }

    if (*size < data_size) {
        *size = data_size;
        fclose(f);
        return ERROR_MORE_DATA;
    }

    if (fread(data, 1, data_size, f) < data_size) { /* partial read ok */ }
    *size = data_size;
    fclose(f);

    return ERROR_SUCCESS;
}

LONG registry_delete_value(HKEY hKey, const char *name)
{
    char key_path[4096];
    if (is_predefined_hkey(hKey)) {
        if (build_key_path(hKey, NULL, key_path, sizeof(key_path)) < 0)
            return ERROR_INVALID_HANDLE;
    } else {
        handle_entry_t *entry = handle_lookup(hKey);
        if (!entry || entry->type != HANDLE_TYPE_REGISTRY_KEY)
            return ERROR_INVALID_HANDLE;
        reg_key_data_t *kd = (reg_key_data_t *)entry->data;
        strncpy(key_path, kd->path, sizeof(key_path) - 1);
        key_path[sizeof(key_path) - 1] = '\0';
    }

    const char *val_name = (name && name[0]) ? name : "@";

    char val_path[4096];
    snprintf(val_path, sizeof(val_path), "%s/.values/%s", key_path, val_name);

    if (unlink(val_path) < 0)
        return ERROR_FILE_NOT_FOUND;

    return ERROR_SUCCESS;
}

LONG registry_delete_key(HKEY hKey, const char *subkey)
{
    if (registry_validate_name(subkey) < 0)
        return ERROR_INVALID_PARAMETER;

    char path[4096];
    if (build_key_path(hKey, subkey, path, sizeof(path)) < 0)
        return ERROR_INVALID_HANDLE;

    /* Only delete if empty (like Windows RegDeleteKey) */
    if (rmdir(path) < 0)
        return errno == ENOTEMPTY ? ERROR_ACCESS_DENIED : ERROR_FILE_NOT_FOUND;

    return ERROR_SUCCESS;
}

/* Collect subkey names from a directory into out[]. Returns count appended.
 * Skips "." "..", ".values" and any entries already present in out[]
 * (dedup for HKCR merge).  out_cap is max entries; each is up to 256 chars. */
static DWORD collect_subkeys(const char *dir_path,
                             char (*out)[256], DWORD out_count,
                             DWORD out_cap)
{
    DIR *d = opendir(dir_path);
    if (!d)
        return out_count;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && out_count < out_cap) {
        if (ent->d_name[0] == '.') {
            if (ent->d_name[1] == '\0') continue;
            if (ent->d_name[1] == '.' && ent->d_name[2] == '\0') continue;
            if (strcmp(ent->d_name, ".values") == 0) continue;
        }

        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", dir_path, ent->d_name);
        struct stat st;
        if (stat(full, &st) < 0 || !S_ISDIR(st.st_mode))
            continue;

        /* Dedup: case-insensitive match against existing entries
         * (Windows registry is case-preserving but case-insensitive). */
        int dup = 0;
        for (DWORD i = 0; i < out_count; i++) {
            if (strcasecmp(out[i], ent->d_name) == 0) {
                dup = 1;
                break;
            }
        }
        if (dup)
            continue;

        size_t nlen = strlen(ent->d_name);
        if (nlen >= 256) nlen = 255;
        memcpy(out[out_count], ent->d_name, nlen);
        out[out_count][nlen] = '\0';
        out_count++;
    }
    closedir(d);
    return out_count;
}

LONG registry_enum_key(HKEY hKey, DWORD index, char *name, DWORD *name_size)
{
    /* HKCR merge: enumerate union of HKCU\SOFTWARE\Classes,
     * HKLM\SOFTWARE\Classes, and the legacy HKCR directory (HKCU wins).
     * This mirrors Windows HKCR semantics. */
    if (is_predefined_hkey(hKey) && (uintptr_t)hKey == 0x80000000) {
        ensure_registry_root();

        /* Cap at 4096 unique class names; more than enough for stubs. */
        enum { MAX_HKCR_ENTRIES = 4096 };
        static char names[MAX_HKCR_ENTRIES][256];
        DWORD count = 0;

        char hkcu_base[4096], hklm_base[4096], legacy[4096];
        snprintf(hkcu_base, sizeof(hkcu_base),
                 "%s/HKCU/SOFTWARE/Classes", g_registry_root);
        snprintf(hklm_base, sizeof(hklm_base),
                 "%s/HKLM/SOFTWARE/Classes", g_registry_root);
        snprintf(legacy, sizeof(legacy),
                 "%s/HKCR", g_registry_root);

        /* HKCU first: its entries take precedence (dedup keeps first seen). */
        count = collect_subkeys(hkcu_base, names, count, MAX_HKCR_ENTRIES);
        count = collect_subkeys(hklm_base, names, count, MAX_HKCR_ENTRIES);
        count = collect_subkeys(legacy,    names, count, MAX_HKCR_ENTRIES);

        if (index >= count)
            return ERROR_NO_MORE_ITEMS;

        DWORD len = (DWORD)strlen(names[index]);
        if (!name || !name_size || *name_size <= len) {
            if (name_size)
                *name_size = len + 1;
            return ERROR_MORE_DATA;
        }
        memcpy(name, names[index], len);
        name[len] = '\0';
        *name_size = len;
        return ERROR_SUCCESS;
    }

    char key_path[4096];
    if (is_predefined_hkey(hKey)) {
        if (build_key_path(hKey, NULL, key_path, sizeof(key_path)) < 0)
            return ERROR_INVALID_HANDLE;
    } else {
        handle_entry_t *entry = handle_lookup(hKey);
        if (!entry || entry->type != HANDLE_TYPE_REGISTRY_KEY)
            return ERROR_INVALID_HANDLE;
        reg_key_data_t *kd = (reg_key_data_t *)entry->data;
        strncpy(key_path, kd->path, sizeof(key_path) - 1);
        key_path[sizeof(key_path) - 1] = '\0';
    }

    DIR *d = opendir(key_path);
    if (!d)
        return ERROR_FILE_NOT_FOUND;

    struct dirent *ent;
    DWORD current = 0;

    while ((ent = readdir(d)) != NULL) {
        /* Skip "." and ".." only - Windows registry keys CAN start with "."
         * (e.g. HKCR\.txt, HKCR\.exe).  Also skip our ".values" sidecar dir. */
        if (ent->d_name[0] == '.') {
            if (ent->d_name[1] == '\0') continue;                          /* "."  */
            if (ent->d_name[1] == '.' && ent->d_name[2] == '\0') continue; /* ".." */
            if (strcmp(ent->d_name, ".values") == 0) continue;
        }

        /* Only list directories (subkeys) */
        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", key_path, ent->d_name);
        struct stat st;
        if (stat(full, &st) < 0 || !S_ISDIR(st.st_mode))
            continue;

        if (current == index) {
            DWORD len = (DWORD)strlen(ent->d_name);
            /* Windows semantics: lpcchName on input = buffer size in chars
             * (INCLUDING room for NUL). On success, lpcchName = length
             * WITHOUT the NUL. Need strictly greater than len. */
            if (!name || !name_size || *name_size <= len) {
                if (name_size)
                    *name_size = len + 1;
                closedir(d);
                return ERROR_MORE_DATA;
            }
            memcpy(name, ent->d_name, len);
            name[len] = '\0';
            *name_size = len;
            closedir(d);
            return ERROR_SUCCESS;
        }
        current++;
    }

    closedir(d);
    return ERROR_NO_MORE_ITEMS;
}

LONG registry_enum_value(HKEY hKey, DWORD index, char *name, DWORD *name_size,
                         DWORD *type, void *data, DWORD *data_size)
{
    char key_path[4096];
    if (is_predefined_hkey(hKey)) {
        if (build_key_path(hKey, NULL, key_path, sizeof(key_path)) < 0)
            return ERROR_INVALID_HANDLE;
    } else {
        handle_entry_t *entry = handle_lookup(hKey);
        if (!entry || entry->type != HANDLE_TYPE_REGISTRY_KEY)
            return ERROR_INVALID_HANDLE;
        reg_key_data_t *kd = (reg_key_data_t *)entry->data;
        strncpy(key_path, kd->path, sizeof(key_path) - 1);
        key_path[sizeof(key_path) - 1] = '\0';
    }

    char values_dir[4096];
    snprintf(values_dir, sizeof(values_dir), "%s/.values", key_path);

    DIR *d = opendir(values_dir);
    if (!d)
        return ERROR_NO_MORE_ITEMS;

    struct dirent *ent;
    DWORD current = 0;

    while ((ent = readdir(d)) != NULL) {
        /* Skip "." and ".." only.  (Value files may not legally start with ".",
         * but we still explicitly filter the two special entries.) */
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0' ||
             (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
            continue;

        if (current == index) {
            /* Found the value */
            const char *val_name = strcmp(ent->d_name, "@") == 0 ? "" : ent->d_name;
            DWORD len = (DWORD)strlen(val_name);

            /* Check name buffer FIRST - on ERROR_MORE_DATA we must not
             * touch data output, but we should still report required size. */
            if (!name || !name_size || *name_size <= len) {
                if (name_size)
                    *name_size = len + 1;
                closedir(d);
                return ERROR_MORE_DATA;
            }
            memcpy(name, val_name, len);
            name[len] = '\0';
            *name_size = len;

            /* Read value data */
            char val_path[4096];
            snprintf(val_path, sizeof(val_path), "%s/%s", values_dir, ent->d_name);
            FILE *f = fopen(val_path, "rb");
            if (f) {
                DWORD val_type = 0;
                if (fread(&val_type, sizeof(DWORD), 1, f) < 1) val_type = 0;
                if (type)
                    *type = val_type;

                long pos = ftell(f);
                fseek(f, 0, SEEK_END);
                long file_size = ftell(f);
                fseek(f, pos, SEEK_SET);
                DWORD val_size = (DWORD)(file_size - pos);

                if (data_size) {
                    if (data && *data_size >= val_size) {
                        if (val_size > 0 &&
                            fread(data, 1, val_size, f) < val_size) {
                            /* partial read tolerated */
                        }
                        *data_size = val_size;
                    } else {
                        DWORD needed = val_size;
                        *data_size = needed;
                        if (data) {
                            /* Caller provided buffer but too small */
                            fclose(f);
                            closedir(d);
                            return ERROR_MORE_DATA;
                        }
                        /* data==NULL: query-only, SUCCESS with size filled */
                    }
                }
                fclose(f);
            }

            closedir(d);
            return ERROR_SUCCESS;
        }
        current++;
    }

    closedir(d);
    return ERROR_NO_MORE_ITEMS;
}

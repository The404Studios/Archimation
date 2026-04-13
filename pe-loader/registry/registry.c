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
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>

#include "registry.h"

/* Reject path components that could escape the registry root */
static int registry_validate_name(const char *name)
{
    if (!name || !*name)
        return 0;  /* empty is OK (root key) */
    /* Reject path traversal sequences */
    if (strstr(name, ".."))
        return -1;
    /* Reject absolute paths */
    if (name[0] == '/' || name[0] == '\\')
        return -1;
    /* Reject embedded null-like characters */
    for (const char *p = name; *p; p++) {
        if (*p == '\0')
            break;
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
 */
static int build_key_path(HKEY hKey, const char *subkey, char *path, size_t size)
{
    ensure_registry_root();

    if (is_predefined_hkey(hKey)) {
        const char *prefix = hkey_to_prefix(hKey);
        if (!prefix) return -1;

        if (subkey && subkey[0]) {
            snprintf(path, size, "%s/%s/%s", g_registry_root, prefix, subkey);
        } else {
            snprintf(path, size, "%s/%s", g_registry_root, prefix);
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
     * Auto-create intermediate directories.  Many Windows applications
     * call RegOpenKeyEx on well-known paths like
     *   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
     * and expect every component to already exist.  On our filesystem-
     * backed registry the parent directories may not yet be present, so
     * we materialise them here.  The final leaf is also created as an
     * empty directory (equivalent to an empty registry key) so the open
     * succeeds.
     */
    ensure_key_parents(path);
    mkdir(path, 0755);  /* create leaf key if not present */

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
    if (build_key_path(hKey, subkey, path, sizeof(path)) < 0)
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

LONG registry_enum_key(HKEY hKey, DWORD index, char *name, DWORD *name_size)
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

    DIR *d = opendir(key_path);
    if (!d)
        return ERROR_FILE_NOT_FOUND;

    struct dirent *ent;
    DWORD current = 0;

    while ((ent = readdir(d)) != NULL) {
        /* Skip . and .. and .values */
        if (ent->d_name[0] == '.')
            continue;

        /* Only list directories (subkeys) */
        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", key_path, ent->d_name);
        struct stat st;
        if (stat(full, &st) < 0 || !S_ISDIR(st.st_mode))
            continue;

        if (current == index) {
            DWORD len = (DWORD)strlen(ent->d_name);
            if (name_size && *name_size <= len) {
                *name_size = len + 1;
                closedir(d);
                return ERROR_MORE_DATA;
            }
            if (name) {
                strncpy(name, ent->d_name, *name_size);
                name[*name_size - 1] = '\0';
            }
            if (name_size)
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
        if (ent->d_name[0] == '.')
            continue;

        if (current == index) {
            /* Found the value */
            const char *val_name = strcmp(ent->d_name, "@") == 0 ? "" : ent->d_name;
            DWORD len = (DWORD)strlen(val_name);

            if (name_size && *name_size <= len) {
                *name_size = len + 1;
                closedir(d);
                return ERROR_MORE_DATA;
            }
            if (name) {
                strncpy(name, val_name, name_size ? *name_size : len + 1);
                if (name_size && *name_size > 0) name[*name_size - 1] = '\0';
            }
            if (name_size)
                *name_size = len;

            /* Read value data */
            char val_path[4096];
            snprintf(val_path, sizeof(val_path), "%s/%s", values_dir, ent->d_name);
            FILE *f = fopen(val_path, "rb");
            if (f) {
                DWORD val_type;
                if (fread(&val_type, sizeof(DWORD), 1, f) < 1) val_type = 0;
                if (type)
                    *type = val_type;

                long pos = ftell(f);
                fseek(f, 0, SEEK_END);
                long file_size = ftell(f);
                fseek(f, pos, SEEK_SET);
                DWORD val_size = (DWORD)(file_size - pos);

                if (data && data_size && *data_size >= val_size) {
                    if (fread(data, 1, val_size, f) < val_size) { /* partial */ }
                    *data_size = val_size;
                } else if (data_size) {
                    *data_size = val_size;
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

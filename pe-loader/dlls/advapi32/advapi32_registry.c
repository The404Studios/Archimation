/*
 * advapi32_registry.c - Windows Registry Win32 API
 *
 * RegOpenKeyExA, RegCreateKeyExA, RegQueryValueExA, RegSetValueExA,
 * RegCloseKey, RegEnumKeyExA, RegEnumValueA, RegDeleteKeyA, RegDeleteValueA.
 *
 * When the Object Broker (pe-objectd) is running, registry operations are
 * delegated to it for cross-process consistency.  Falls back to direct
 * file-backed registry access when the broker is unavailable.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/dll_common.h"
#include "compat/objectd_client.h"
#include "compat/trust_gate.h"

/* Forward declarations - implemented in registry/registry.c */
extern LONG registry_open_key(HKEY hKey, const char *subkey, HKEY *result);
extern LONG registry_create_key(HKEY hKey, const char *subkey, HKEY *result);
extern LONG registry_close_key(HKEY hKey);
extern LONG registry_set_value(HKEY hKey, const char *name, DWORD type,
                               const void *data, DWORD size);
extern LONG registry_get_value(HKEY hKey, const char *subkey, const char *name,
                               DWORD *type, void *data, DWORD *size);
extern LONG registry_delete_value(HKEY hKey, const char *name);
extern LONG registry_delete_key(HKEY hKey, const char *subkey);
extern LONG registry_enum_key(HKEY hKey, DWORD index, char *name, DWORD *name_size);
extern LONG registry_enum_value(HKEY hKey, DWORD index, char *name, DWORD *name_size,
                                DWORD *type, void *data, DWORD *data_size);

/* Forward declaration - implemented in registry/registry_defaults.c */
extern void registry_populate_defaults(void);

/* Shared library constructor: populate registry defaults when advapi32.so
 * loads.
 *
 * When pe-objectd is running it is the authoritative source of truth for
 * the registry and populates the default hive itself in objectd_registry_init().
 * We skip per-process default population in that case -- writing directly
 * to the filesystem here bypasses the broker, races with other PE processes,
 * and regenerates non-idempotent values like MachineGuid on every startup.
 *
 * Fallback: if the broker is NOT running (standalone PE invocation) we
 * still populate locally so a solo .exe run has sensible defaults.
 * registry_populate_defaults() is idempotent-for-reads via reg_set_sz_once.
 */
__attribute__((constructor))
static void advapi32_registry_init(void)
{
    static int done = 0;
    if (done)
        return;
    done = 1;

    /* If objectd is available, it owns the hive -- defaults already populated
     * in its startup path.  Don't double-write. */
    if (objectd_available())
        return;

    registry_populate_defaults();
}

/* Registry access rights (ignored in our implementation) */
#define KEY_READ        0x20019
#define KEY_WRITE       0x20006
#define KEY_ALL_ACCESS  0xF003F

/* Registry options */
#define REG_OPTION_NON_VOLATILE     0
#define REG_OPTION_VOLATILE         1

/* Disposition */
#define REG_CREATED_NEW_KEY     1
#define REG_OPENED_EXISTING_KEY 2

WINAPI_EXPORT LONG RegOpenKeyExA(
    HKEY hKey,
    LPCSTR lpSubKey,
    DWORD ulOptions,
    DWORD samDesired,
    HKEY *phkResult)
{
    (void)ulOptions;
    (void)samDesired;

    if (objectd_available()) {
        uint64_t parent = (uint64_t)(uintptr_t)hKey;
        uint64_t child = 0;
        int ret = objectd_reg_open(parent, lpSubKey, &child);
        if (ret == OBJ_STATUS_OK) {
            *phkResult = (HKEY)(uintptr_t)child;
            return ERROR_SUCCESS;
        }
        if (ret == OBJ_STATUS_NOT_FOUND)
            return ERROR_FILE_NOT_FOUND;
        /* Broker returned error -- fall through to local */
    }

    return registry_open_key(hKey, lpSubKey, phkResult);
}

WINAPI_EXPORT LONG RegOpenKeyExW(
    HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD ulOptions,
    DWORD samDesired,
    HKEY *phkResult)
{
    /* Convert wide to narrow */
    char narrow[4096];
    if (lpSubKey) {
        int i;
        for (i = 0; lpSubKey[i] && i < 4095; i++)
            narrow[i] = (char)(lpSubKey[i] & 0xFF);
        narrow[i] = '\0';
    } else {
        narrow[0] = '\0';
    }

    return RegOpenKeyExA(hKey, narrow, ulOptions, samDesired, phkResult);
}

WINAPI_EXPORT LONG RegCreateKeyExA(
    HKEY hKey,
    LPCSTR lpSubKey,
    DWORD Reserved,
    LPSTR lpClass,
    DWORD dwOptions,
    DWORD samDesired,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    HKEY *phkResult,
    LPDWORD lpdwDisposition)
{
    TRUST_CHECK_RET(TRUST_GATE_REGISTRY_WRITE, "RegCreateKeyExA", ERROR_ACCESS_DENIED);
    (void)Reserved;
    (void)lpClass;
    (void)dwOptions;
    (void)samDesired;
    (void)lpSecurityAttributes;

    if (objectd_available()) {
        uint64_t parent = (uint64_t)(uintptr_t)hKey;
        uint64_t child = 0;
        int ret = objectd_reg_create(parent, lpSubKey, &child);
        if (ret == OBJ_STATUS_OK) {
            *phkResult = (HKEY)(uintptr_t)child;
            if (lpdwDisposition)
                *lpdwDisposition = REG_CREATED_NEW_KEY;
            return ERROR_SUCCESS;
        }
        if (ret == OBJ_STATUS_ALREADY_EXISTS) {
            *phkResult = (HKEY)(uintptr_t)child;
            if (lpdwDisposition)
                *lpdwDisposition = REG_OPENED_EXISTING_KEY;
            return ERROR_SUCCESS;
        }
        /* Broker error -- fall through to local */
    }

    /* Try open first to determine disposition */
    HKEY temp;
    LONG ret = registry_open_key(hKey, lpSubKey, &temp);
    if (ret == ERROR_SUCCESS) {
        *phkResult = temp;
        if (lpdwDisposition)
            *lpdwDisposition = REG_OPENED_EXISTING_KEY;
        return ERROR_SUCCESS;
    }

    ret = registry_create_key(hKey, lpSubKey, phkResult);
    if (ret == ERROR_SUCCESS && lpdwDisposition)
        *lpdwDisposition = REG_CREATED_NEW_KEY;
    return ret;
}

WINAPI_EXPORT LONG RegCreateKeyExW(
    HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD Reserved,
    LPWSTR lpClass,
    DWORD dwOptions,
    DWORD samDesired,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    HKEY *phkResult,
    LPDWORD lpdwDisposition)
{
    (void)lpClass;
    char narrow[4096];
    if (lpSubKey) {
        int i;
        for (i = 0; lpSubKey[i] && i < 4095; i++)
            narrow[i] = (char)(lpSubKey[i] & 0xFF);
        narrow[i] = '\0';
    } else {
        narrow[0] = '\0';
    }

    return RegCreateKeyExA(hKey, narrow, Reserved, NULL, dwOptions, samDesired,
                           lpSecurityAttributes, phkResult, lpdwDisposition);
}

WINAPI_EXPORT LONG RegCloseKey(HKEY hKey)
{
    if (objectd_available()) {
        int ret = objectd_reg_close((uint64_t)(uintptr_t)hKey);
        if (ret == OBJ_STATUS_OK)
            return ERROR_SUCCESS;
        /* Broker error -- fall through to local */
    }

    return registry_close_key(hKey);
}

WINAPI_EXPORT LONG RegQueryValueExA(
    HKEY hKey,
    LPCSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData)
{
    (void)lpReserved;

    if (objectd_available()) {
        uint32_t type = 0;
        uint32_t len = lpcbData ? *lpcbData : 0;
        int ret = objectd_reg_get_value((uint64_t)(uintptr_t)hKey,
                                        lpValueName, &type, lpData, &len);
        if (ret == OBJ_STATUS_OK) {
            if (lpType) *lpType = type;
            if (lpcbData) *lpcbData = len;
            return ERROR_SUCCESS;
        }
        if (ret == OBJ_STATUS_NOT_FOUND)
            return ERROR_FILE_NOT_FOUND;
        /* Broker error -- fall through to local */
    }

    return registry_get_value(hKey, NULL, lpValueName, lpType, lpData, lpcbData);
}

WINAPI_EXPORT LONG RegQueryValueExW(
    HKEY hKey,
    LPCWSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData)
{
    char narrow[4096];
    if (lpValueName) {
        int i;
        for (i = 0; lpValueName[i] && i < 4095; i++)
            narrow[i] = (char)(lpValueName[i] & 0xFF);
        narrow[i] = '\0';
    } else {
        narrow[0] = '\0';
    }
    return RegQueryValueExA(hKey, narrow, lpReserved, lpType, lpData, lpcbData);
}

WINAPI_EXPORT LONG RegSetValueExA(
    HKEY hKey,
    LPCSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE *lpData,
    DWORD cbData)
{
    TRUST_CHECK_RET(TRUST_GATE_REGISTRY_WRITE, "RegSetValueExA", ERROR_ACCESS_DENIED);
    (void)Reserved;

    if (objectd_available()) {
        int ret = objectd_reg_set_value((uint64_t)(uintptr_t)hKey,
                                        lpValueName, dwType, lpData, cbData);
        if (ret == OBJ_STATUS_OK)
            return ERROR_SUCCESS;
        /* Broker error -- fall through to local */
    }

    return registry_set_value(hKey, lpValueName, dwType, lpData, cbData);
}

WINAPI_EXPORT LONG RegSetValueExW(
    HKEY hKey,
    LPCWSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE *lpData,
    DWORD cbData)
{
    char narrow[4096];
    if (lpValueName) {
        int i;
        for (i = 0; lpValueName[i] && i < 4095; i++)
            narrow[i] = (char)(lpValueName[i] & 0xFF);
        narrow[i] = '\0';
    } else {
        narrow[0] = '\0';
    }
    return RegSetValueExA(hKey, narrow, Reserved, dwType, lpData, cbData);
}

WINAPI_EXPORT LONG RegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey)
{
    TRUST_CHECK_RET(TRUST_GATE_REGISTRY_WRITE, "RegDeleteKeyA", ERROR_ACCESS_DENIED);

    if (objectd_available()) {
        int ret = objectd_reg_delete_key((uint64_t)(uintptr_t)hKey, lpSubKey);
        if (ret == OBJ_STATUS_OK)
            return ERROR_SUCCESS;
        if (ret == OBJ_STATUS_NOT_FOUND)
            return ERROR_FILE_NOT_FOUND;
        if (ret == OBJ_STATUS_ACCESS_DENIED)
            return ERROR_ACCESS_DENIED;
        /* Broker error -- fall through to local */
    }

    return registry_delete_key(hKey, lpSubKey);
}

WINAPI_EXPORT LONG RegDeleteValueA(HKEY hKey, LPCSTR lpValueName)
{
    TRUST_CHECK_RET(TRUST_GATE_REGISTRY_WRITE, "RegDeleteValueA", ERROR_ACCESS_DENIED);

    if (objectd_available()) {
        int ret = objectd_reg_delete_value((uint64_t)(uintptr_t)hKey, lpValueName);
        if (ret == OBJ_STATUS_OK)
            return ERROR_SUCCESS;
        if (ret == OBJ_STATUS_NOT_FOUND)
            return ERROR_FILE_NOT_FOUND;
        /* Broker error -- fall through to local */
    }

    return registry_delete_value(hKey, lpValueName);
}

WINAPI_EXPORT LONG RegEnumKeyA(HKEY hKey, DWORD dwIndex, LPSTR lpName, DWORD cchName)
{
    DWORD size = cchName;
    if (objectd_available()) {
        uint32_t len = cchName;
        int ret = objectd_reg_enum_key((uint64_t)(uintptr_t)hKey,
                                       dwIndex, lpName, &len);
        if (ret == OBJ_STATUS_OK)
            return ERROR_SUCCESS;
        if (ret == OBJ_STATUS_NOT_FOUND)
            return 259; /* ERROR_NO_MORE_ITEMS */
        /* Broker error -- fall through to local */
    }
    return registry_enum_key(hKey, dwIndex, lpName, &size);
}

WINAPI_EXPORT LONG RegEnumKeyExA(
    HKEY hKey,
    DWORD dwIndex,
    LPSTR lpName,
    LPDWORD lpcchName,
    LPDWORD lpReserved,
    LPSTR lpClass,
    LPDWORD lpcchClass,
    void *lpftLastWriteTime)
{
    (void)lpReserved;
    (void)lpClass;
    (void)lpcchClass;
    (void)lpftLastWriteTime;

    if (objectd_available()) {
        uint32_t len = lpcchName ? *lpcchName : 0;
        int ret = objectd_reg_enum_key((uint64_t)(uintptr_t)hKey,
                                       dwIndex, lpName, &len);
        if (ret == OBJ_STATUS_OK) {
            if (lpcchName) *lpcchName = len;
            return ERROR_SUCCESS;
        }
        if (ret == OBJ_STATUS_NOT_FOUND)
            return 259; /* ERROR_NO_MORE_ITEMS */
        /* Broker error -- fall through to local */
    }

    return registry_enum_key(hKey, dwIndex, lpName, lpcchName);
}

WINAPI_EXPORT LONG RegEnumValueA(
    HKEY hKey,
    DWORD dwIndex,
    LPSTR lpValueName,
    LPDWORD lpcchValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData)
{
    (void)lpReserved;

    if (objectd_available()) {
        uint32_t name_len = lpcchValueName ? *lpcchValueName : 0;
        uint32_t data_len = lpcbData ? *lpcbData : 0;
        uint32_t type = 0;
        int ret = objectd_reg_enum_value((uint64_t)(uintptr_t)hKey,
                                         dwIndex, lpValueName, &name_len,
                                         &type, lpData, &data_len);
        if (ret == OBJ_STATUS_OK) {
            if (lpcchValueName) *lpcchValueName = name_len;
            if (lpType) *lpType = type;
            if (lpcbData) *lpcbData = data_len;
            return ERROR_SUCCESS;
        }
        if (ret == OBJ_STATUS_NOT_FOUND)
            return 259; /* ERROR_NO_MORE_ITEMS */
        /* Broker error -- fall through to local */
    }

    return registry_enum_value(hKey, dwIndex, lpValueName, lpcchValueName,
                               lpType, lpData, lpcbData);
}

WINAPI_EXPORT LONG RegGetValueA(
    HKEY hKey,
    LPCSTR lpSubKey,
    LPCSTR lpValue,
    DWORD dwFlags,
    LPDWORD pdwType,
    PVOID pvData,
    LPDWORD pcbData)
{
    (void)dwFlags;

    if (objectd_available()) {
        /* If subkey is provided, open it first */
        uint64_t key_handle = (uint64_t)(uintptr_t)hKey;
        uint64_t sub_handle = 0;
        int need_close = 0;

        if (lpSubKey && lpSubKey[0]) {
            int ret = objectd_reg_open(key_handle, lpSubKey, &sub_handle);
            if (ret == OBJ_STATUS_OK) {
                key_handle = sub_handle;
                need_close = 1;
            } else if (ret == OBJ_STATUS_NOT_FOUND) {
                return ERROR_FILE_NOT_FOUND;
            } else {
                goto local_fallback;
            }
        }

        uint32_t type = 0;
        uint32_t len = pcbData ? *pcbData : 0;
        int ret = objectd_reg_get_value(key_handle, lpValue, &type, pvData, &len);

        if (need_close)
            objectd_reg_close(sub_handle);

        if (ret == OBJ_STATUS_OK) {
            if (pdwType) *pdwType = type;
            if (pcbData) *pcbData = len;
            return ERROR_SUCCESS;
        }
        if (ret == OBJ_STATUS_NOT_FOUND)
            return ERROR_FILE_NOT_FOUND;
        /* Broker error -- fall through to local */
    }

local_fallback:
    return registry_get_value(hKey, lpSubKey, lpValue, pdwType, pvData, pcbData);
}

WINAPI_EXPORT LONG RegQueryInfoKeyA(
    HKEY hKey,
    LPSTR lpClass,
    LPDWORD lpcchClass,
    LPDWORD lpReserved,
    LPDWORD lpcSubKeys,
    LPDWORD lpcbMaxSubKeyLen,
    LPDWORD lpcbMaxClassLen,
    LPDWORD lpcValues,
    LPDWORD lpcbMaxValueNameLen,
    LPDWORD lpcbMaxValueLen,
    LPDWORD lpcbSecurityDescriptor,
    void *lpftLastWriteTime)
{
    (void)lpReserved;
    (void)lpftLastWriteTime;

    if (lpClass && lpcchClass) {
        lpClass[0] = '\0';
        *lpcchClass = 0;
    }
    if (lpcbMaxClassLen) *lpcbMaxClassLen = 0;
    if (lpcbSecurityDescriptor) *lpcbSecurityDescriptor = 0;

    /* Count subkeys by enumerating until ERROR_NO_MORE_ITEMS */
    DWORD subkeys = 0, max_subkey_len = 0;
    if (lpcSubKeys || lpcbMaxSubKeyLen) {
        char name_buf[256];
        DWORD name_len;
        for (DWORD idx = 0; ; idx++) {
            name_len = sizeof(name_buf);
            LONG ret = registry_enum_key(hKey, idx, name_buf, &name_len);
            if (ret != ERROR_SUCCESS) break;
            subkeys++;
            if (name_len > max_subkey_len) max_subkey_len = name_len;
        }
    }
    if (lpcSubKeys) *lpcSubKeys = subkeys;
    if (lpcbMaxSubKeyLen) *lpcbMaxSubKeyLen = max_subkey_len;

    /* Count values by enumerating until ERROR_NO_MORE_ITEMS */
    DWORD values = 0, max_value_name_len = 0, max_value_len = 0;
    if (lpcValues || lpcbMaxValueNameLen || lpcbMaxValueLen) {
        char name_buf[256];
        DWORD name_len, data_len;
        for (DWORD idx = 0; ; idx++) {
            name_len = sizeof(name_buf);
            data_len = 0;
            LONG ret = registry_enum_value(hKey, idx, name_buf, &name_len,
                                           NULL, NULL, &data_len);
            if (ret != ERROR_SUCCESS) break;
            values++;
            if (name_len > max_value_name_len) max_value_name_len = name_len;
            if (data_len > max_value_len) max_value_len = data_len;
        }
    }
    if (lpcValues) *lpcValues = values;
    if (lpcbMaxValueNameLen) *lpcbMaxValueNameLen = max_value_name_len;
    if (lpcbMaxValueLen) *lpcbMaxValueLen = max_value_len;

    return ERROR_SUCCESS;
}

/* ---- Additional registry functions for SteamSetup ---- */

WINAPI_EXPORT LONG RegDeleteKeyW(HKEY hKey, const uint16_t *lpSubKey)
{
    char narrow[4096];
    if (lpSubKey) {
        int i;
        for (i = 0; lpSubKey[i] && i < 4095; i++)
            narrow[i] = (char)(lpSubKey[i] & 0xFF);
        narrow[i] = '\0';
    } else {
        narrow[0] = '\0';
    }
    return RegDeleteKeyA(hKey, narrow);
}

WINAPI_EXPORT LONG RegDeleteValueW(HKEY hKey, const uint16_t *lpValueName)
{
    char narrow[4096];
    if (lpValueName) {
        int i;
        for (i = 0; lpValueName[i] && i < 4095; i++)
            narrow[i] = (char)(lpValueName[i] & 0xFF);
        narrow[i] = '\0';
    } else {
        narrow[0] = '\0';
    }
    return RegDeleteValueA(hKey, narrow);
}

WINAPI_EXPORT LONG RegEnumKeyW(HKEY hKey, DWORD dwIndex, uint16_t *lpName, DWORD cchName)
{
    /* Delegate to A version, then widen */
    char narrow[4096];
    DWORD narrow_size = sizeof(narrow);
    LONG ret = registry_enum_key(hKey, dwIndex, narrow, &narrow_size);
    if (ret != 0 /* ERROR_SUCCESS */)
        return ret;

    /* narrow_size is the length without null terminator */
    if (cchName == 0 || cchName <= narrow_size)
        return 234; /* ERROR_MORE_DATA */

    /* Convert narrow result to wide */
    DWORD i;
    for (i = 0; i < narrow_size; i++)
        lpName[i] = (uint16_t)(unsigned char)narrow[i];
    lpName[i] = 0;

    return 0; /* ERROR_SUCCESS */
}

WINAPI_EXPORT LONG RegEnumKeyExW(HKEY hKey, DWORD dwIndex, uint16_t *lpName,
    DWORD *lpcchName, DWORD *lpReserved, uint16_t *lpClass,
    DWORD *lpcchClass, void *lpftLastWriteTime)
{
    (void)lpReserved;
    (void)lpClass;
    (void)lpcchClass;
    (void)lpftLastWriteTime;

    /* Delegate to A version via registry_enum_key, then widen */
    char narrow[4096];
    DWORD narrow_size = sizeof(narrow);
    LONG ret = registry_enum_key(hKey, dwIndex, narrow, &narrow_size);
    if (ret != 0 /* ERROR_SUCCESS */)
        return ret;

    /* narrow_size is the length without null terminator */
    DWORD needed = narrow_size;
    if (!lpcchName || *lpcchName <= needed) {
        if (lpcchName)
            *lpcchName = needed + 1;
        return 234; /* ERROR_MORE_DATA */
    }

    /* Convert narrow result to wide */
    DWORD i;
    for (i = 0; i < needed; i++)
        lpName[i] = (uint16_t)(unsigned char)narrow[i];
    lpName[i] = 0;

    *lpcchName = needed;
    return 0; /* ERROR_SUCCESS */
}

WINAPI_EXPORT LONG RegEnumValueW(HKEY hKey, DWORD dwIndex, uint16_t *lpValueName,
    DWORD *lpcchValueName, DWORD *lpReserved, DWORD *lpType,
    BYTE *lpData, DWORD *lpcbData)
{
    (void)lpReserved;

    /* Delegate to A version, then widen the value name */
    char narrow_name[4096];
    DWORD narrow_name_size = sizeof(narrow_name);
    DWORD data_size = lpcbData ? *lpcbData : 0;
    LONG ret = registry_enum_value(hKey, dwIndex, narrow_name, &narrow_name_size,
                                   lpType, lpData, lpcbData ? &data_size : NULL);
    if (ret != 0 /* ERROR_SUCCESS */)
        return ret;

    /* narrow_name_size is the length without null terminator */
    DWORD needed = narrow_name_size;
    if (!lpcchValueName || *lpcchValueName <= needed) {
        if (lpcchValueName)
            *lpcchValueName = needed + 1;
        return 234; /* ERROR_MORE_DATA */
    }

    /* Convert narrow name to wide */
    DWORD i;
    for (i = 0; i < needed; i++)
        lpValueName[i] = (uint16_t)(unsigned char)narrow_name[i];
    lpValueName[i] = 0;

    *lpcchValueName = needed;
    if (lpcbData)
        *lpcbData = data_size;
    return 0; /* ERROR_SUCCESS */
}

WINAPI_EXPORT BOOL SetFileSecurityW(const uint16_t *lpFileName,
    DWORD SecurityInformation, void *pSecurityDescriptor)
{
    (void)lpFileName; (void)SecurityInformation; (void)pSecurityDescriptor;
    return TRUE;
}

/* ---------- RegNotifyChangeKeyValue ---------- */

WINAPI_EXPORT LONG RegNotifyChangeKeyValue(
    HKEY hKey,
    BOOL bWatchSubtree,
    DWORD dwNotifyFilter,
    HANDLE hEvent,
    BOOL fAsynchronous)
{
    (void)hKey;
    (void)bWatchSubtree;
    (void)dwNotifyFilter;
    (void)hEvent;
    (void)fAsynchronous;
    /* Stub: pretend success but never actually notify */
    return 0; /* ERROR_SUCCESS */
}

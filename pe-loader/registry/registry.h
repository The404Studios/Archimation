/*
 * registry.h - Windows Registry emulation API
 *
 * File-backed registry tree stored under ~/.pe-compat/registry/
 */

#ifndef REGISTRY_H
#define REGISTRY_H

#include "common/dll_common.h"

/* Open an existing registry key */
LONG registry_open_key(HKEY hKey, const char *subkey, HKEY *result);

/* Create (or open) a registry key */
LONG registry_create_key(HKEY hKey, const char *subkey, HKEY *result);

/* Close an opened registry key */
LONG registry_close_key(HKEY hKey);

/* Set a value under a registry key */
LONG registry_set_value(HKEY hKey, const char *name, DWORD type,
                        const void *data, DWORD size);

/* Get a value from a registry key (with optional subkey) */
LONG registry_get_value(HKEY hKey, const char *subkey, const char *name,
                        DWORD *type, void *data, DWORD *size);

/* Delete a value */
LONG registry_delete_value(HKEY hKey, const char *name);

/* Delete a registry key (must be empty) */
LONG registry_delete_key(HKEY hKey, const char *subkey);

/* Enumerate subkeys */
LONG registry_enum_key(HKEY hKey, DWORD index, char *name, DWORD *name_size);

/* Enumerate values */
LONG registry_enum_value(HKEY hKey, DWORD index, char *name, DWORD *name_size,
                         DWORD *type, void *data, DWORD *data_size);

/* ---------------------------------------------------------------------- */
/* Fast-path bulk helpers (used by registry_defaults.c).                  */
/* These avoid the Reg* handle alloc/free cycle and take the registry    */
/* write lock exactly once per call instead of 3 times.                   */
/* ---------------------------------------------------------------------- */

/* Idempotent write: only writes when (subkey, name) is absent.
 * Returns 1 if the value was written, 0 if already present (or error). */
int registry_set_default(HKEY root, const char *subkey,
                         const char *name, DWORD type,
                         const void *data, DWORD size);

/* Force-write: always overwrites.  For volatile state like hostname. */
int registry_set_force(HKEY root, const char *subkey,
                       const char *name, DWORD type,
                       const void *data, DWORD size);

#endif /* REGISTRY_H */

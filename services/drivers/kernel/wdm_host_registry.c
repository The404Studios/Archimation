/*
 * wdm_host_registry.c - Windows registry access emulation
 *
 * Provides a simple in-kernel key-value store that emulates the Windows
 * registry for hosted .sys drivers.  Many Windows drivers read configuration
 * data from the registry during DriverEntry or device start; this subsystem
 * lets the host module pre-populate those values and allows drivers to store
 * new ones at runtime.
 *
 * Storage is a linked list of wdm_reg_entry structures protected by a mutex.
 * Keys are represented as "key_path\value_name" strings (max 512 bytes for
 * the composite key, 1024 bytes for value data).
 *
 * Copyright (c) 2026  WDM Host Project
 * SPDX-License-Identifier: GPL-2.0
 */

#include "wdm_host_internal.h"

/* ============================================================================
 * Windows registry value type constants
 * ============================================================================ */

#define WDM_REG_NONE       0   /* REG_NONE       */
#define WDM_REG_SZ         1   /* REG_SZ         */
#define WDM_REG_EXPAND_SZ  2   /* REG_EXPAND_SZ  */
#define WDM_REG_BINARY     3   /* REG_BINARY     */
#define WDM_REG_DWORD      4   /* REG_DWORD      */
#define WDM_REG_MULTI_SZ   7   /* REG_MULTI_SZ   */
#define WDM_REG_QWORD      11  /* REG_QWORD      */

/* ============================================================================
 * Internal data structures
 * ============================================================================ */

#define WDM_REG_KEY_MAX    512
#define WDM_REG_VALUE_MAX  1024

struct wdm_reg_entry {
	char             key[WDM_REG_KEY_MAX];    /* "key_path\value_name" */
	uint8_t          value[WDM_REG_VALUE_MAX]; /* Raw value data       */
	uint32_t         type;                      /* REG_* type constant  */
	size_t           data_len;                  /* Bytes stored in value */
	struct list_head list;                      /* Linkage in global list */
};

/* Global registry store */
static LIST_HEAD(wdm_reg_list);
static DEFINE_MUTEX(wdm_reg_lock);

/* ============================================================================
 * Internal helpers
 * ============================================================================ */

/*
 * build_full_key - Concatenate key_path and value_name into a single string
 *                  of the form "key_path\value_name".
 *
 * Returns 0 on success, -ENAMETOOLONG if the result would not fit.
 */
static int build_full_key(char *buf, size_t buf_len,
			  const char *key_path, const char *value_name)
{
	int ret;

	if (!key_path)
		key_path = "";
	if (!value_name)
		value_name = "";

	ret = snprintf(buf, buf_len, "%s\\%s", key_path, value_name);
	if (ret < 0 || (size_t)ret >= buf_len)
		return -ENAMETOOLONG;

	return 0;
}

/*
 * find_entry - Look up an entry by its composite key.
 *
 * Must be called with wdm_reg_lock held.
 */
static struct wdm_reg_entry *find_entry(const char *full_key)
{
	struct wdm_reg_entry *entry;

	list_for_each_entry(entry, &wdm_reg_list, list) {
		if (strcmp(entry->key, full_key) == 0)
			return entry;
	}
	return NULL;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

/*
 * wdm_registry_query - Read a value from the emulated registry.
 *
 * @key:        Registry key path (e.g. "HKLM\SYSTEM\CurrentControlSet\...")
 * @value_name: Value name within the key
 * @data:       Output buffer for the value data (caller-allocated)
 * @data_len:   [in/out] On input: size of @data buffer.
 *                        On output: actual bytes copied (or required size).
 *
 * Returns 0 on success, -ENOENT if the entry does not exist, or -ENOSPC if
 * the caller's buffer is too small (in which case *data_len is set to the
 * required size).
 */
int wdm_registry_query(const char *key, const char *value_name,
		        void *data, size_t *data_len)
{
	char full_key[WDM_REG_KEY_MAX];
	struct wdm_reg_entry *entry;
	int ret;

	if (!data_len)
		return -EINVAL;

	ret = build_full_key(full_key, sizeof(full_key), key, value_name);
	if (ret)
		return ret;

	mutex_lock(&wdm_reg_lock);
	entry = find_entry(full_key);
	if (!entry) {
		mutex_unlock(&wdm_reg_lock);
		pr_debug("wdm_host: registry query '%s' -> not found\n",
			 full_key);
		return -ENOENT;
	}

	/* Check that the caller's buffer is large enough */
	if (*data_len < entry->data_len) {
		*data_len = entry->data_len;
		mutex_unlock(&wdm_reg_lock);
		return -ENOSPC;
	}

	if (data)
		memcpy(data, entry->value, entry->data_len);

	*data_len = entry->data_len;
	mutex_unlock(&wdm_reg_lock);

	pr_debug("wdm_host: registry query '%s' -> %zu bytes (type %u)\n",
		 full_key, entry->data_len, entry->type);
	return 0;
}

/*
 * wdm_registry_set - Write a value to the emulated registry.
 *
 * @key:        Registry key path
 * @value_name: Value name within the key
 * @data:       Pointer to the value data
 * @data_len:   Length of @data in bytes (max WDM_REG_VALUE_MAX)
 *
 * If the entry already exists it is updated in place.  Otherwise a new entry
 * is allocated and appended to the registry list.
 *
 * Returns 0 on success.
 */
int wdm_registry_set(const char *key, const char *value_name,
		      const void *data, size_t data_len)
{
	char full_key[WDM_REG_KEY_MAX];
	struct wdm_reg_entry *entry;
	int ret;

	if (!data || data_len == 0)
		return -EINVAL;

	if (data_len > WDM_REG_VALUE_MAX) {
		pr_err("wdm_host: registry set '%s\\%s' value too large "
		       "(%zu > %d)\n", key ? key : "", value_name ? value_name : "",
		       data_len, WDM_REG_VALUE_MAX);
		return -ENOSPC;
	}

	ret = build_full_key(full_key, sizeof(full_key), key, value_name);
	if (ret)
		return ret;

	mutex_lock(&wdm_reg_lock);
	entry = find_entry(full_key);

	if (entry) {
		/* Update existing entry */
		memcpy(entry->value, data, data_len);
		entry->data_len = data_len;
		mutex_unlock(&wdm_reg_lock);

		pr_debug("wdm_host: registry update '%s' (%zu bytes)\n",
			 full_key, data_len);
		return 0;
	}

	/* Create a new entry */
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		mutex_unlock(&wdm_reg_lock);
		return -ENOMEM;
	}

	strscpy(entry->key, full_key, sizeof(entry->key));
	memcpy(entry->value, data, data_len);
	entry->data_len = data_len;
	entry->type     = WDM_REG_BINARY; /* default; callers may override */

	list_add_tail(&entry->list, &wdm_reg_list);
	mutex_unlock(&wdm_reg_lock);

	pr_debug("wdm_host: registry create '%s' (%zu bytes)\n",
		 full_key, data_len);
	return 0;
}

/* ============================================================================
 * Subsystem init / exit
 * ============================================================================ */

/*
 * wdm_registry_init - Initialise the registry subsystem.
 */
int wdm_registry_init(void)
{
	pr_info("wdm_host: registry subsystem initialised\n");
	return 0;
}

/*
 * wdm_registry_exit - Free all registry entries.
 */
void wdm_registry_exit(void)
{
	struct wdm_reg_entry *entry, *tmp;
	int count = 0;

	mutex_lock(&wdm_reg_lock);
	list_for_each_entry_safe(entry, tmp, &wdm_reg_list, list) {
		list_del(&entry->list);
		kfree(entry);
		count++;
	}
	mutex_unlock(&wdm_reg_lock);

	pr_info("wdm_host: registry subsystem exited (%d entries freed)\n",
		count);
}

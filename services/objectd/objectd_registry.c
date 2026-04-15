/*
 * objectd_registry.c - Registry hosting for pe-objectd
 *
 * Wraps the existing pe-loader/registry/registry.c functions and
 * exposes them over the object broker wire protocol.  The registry.c
 * code does the real work (file-backed tree under ~/.pe-compat/registry/).
 * This module handles request parsing, dispatch, and response encoding.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>

#include "objectd_protocol.h"
#include "registry.h"

/* Forward declaration - defined in registry_defaults.c */
extern void registry_populate_defaults(void);

/*
 * Maximum data payload for registry value get/set.
 * Kept at 4096 to avoid excessive stack allocation in REG_ENUM_VALUE
 * (val_data[REG_MAX_DATA] is on the stack).
 */
#define REG_MAX_DATA 4096

/* --------------------------------------------------------------------------
 * Initialization
 * -------------------------------------------------------------------------- */

static int g_registry_initialized = 0;

void objectd_registry_init(void)
{
    if (g_registry_initialized)
        return;

    fprintf(stderr, "[objectd] Initializing registry backend...\n");
    registry_populate_defaults();
    g_registry_initialized = 1;
    fprintf(stderr, "[objectd] Registry backend ready\n");
}

/* --------------------------------------------------------------------------
 * Request handlers
 *
 * Each handler:
 *   - Parses the payload from the client request
 *   - Calls the appropriate registry.c function
 *   - Builds a response (header + optional payload)
 *   - Returns the total response length via *resp_len
 * -------------------------------------------------------------------------- */

int objectd_registry_handle(uint8_t req_type, const void *payload,
                            uint16_t payload_len, uint32_t pid,
                            uint64_t sequence,
                            void *resp_buf, size_t resp_buf_size,
                            size_t *resp_len)
{
    /* Guard against undersized response buffer.  size_t underflow below
     * would produce a huge resp_data_max that later compares as "always
     * fits" and corrupt memory outside resp_buf. */
    if (resp_buf_size < sizeof(objectd_response_t) || !resp_buf || !resp_len) {
        if (resp_len) *resp_len = 0;
        return -1;
    }

    objectd_response_t *resp = (objectd_response_t *)resp_buf;
    uint8_t *resp_data = (uint8_t *)resp_buf + sizeof(objectd_response_t);
    size_t resp_data_max = resp_buf_size - sizeof(objectd_response_t);

    /* Initialize response header */
    memset(resp, 0, sizeof(*resp));
    resp->magic    = OBJECTD_MAGIC;
    resp->version  = OBJECTD_VERSION;
    resp->sequence = sequence;
    resp->shm_fd   = -1;
    resp->handle   = 0;
    resp->status   = OBJ_STATUS_OK;
    resp->payload_len = 0;

    (void)pid;  /* TODO: trust checks based on PID */

    switch (req_type) {

    /* ------------------------------------------------------------------ */
    case OBJ_REQ_REG_OPEN: {
        if (payload_len < sizeof(reg_open_payload_t)) {
            resp->status = OBJ_STATUS_INVALID;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }
        const reg_open_payload_t *p = (const reg_open_payload_t *)payload;
        HKEY parent = (HKEY)(uintptr_t)p->hkey;
        HKEY result = NULL;

        LONG ret = registry_open_key(parent, p->subkey, &result);
        if (ret != 0) {
            resp->status = OBJ_STATUS_NOT_FOUND;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }

        /* Return the HKEY as a uint64 in the handle field */
        resp->handle = (uint32_t)(uintptr_t)result;
        /* Also put full 64-bit value in payload for 64-bit safety */
        uint64_t hkey_val = (uint64_t)(uintptr_t)result;
        if (resp_data_max >= sizeof(hkey_val)) {
            memcpy(resp_data, &hkey_val, sizeof(hkey_val));
            resp->payload_len = sizeof(hkey_val);
        }

        *resp_len = sizeof(objectd_response_t) + resp->payload_len;
        return 0;
    }

    /* ------------------------------------------------------------------ */
    case OBJ_REQ_REG_CREATE: {
        if (payload_len < sizeof(reg_open_payload_t)) {
            resp->status = OBJ_STATUS_INVALID;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }
        const reg_open_payload_t *p = (const reg_open_payload_t *)payload;
        HKEY parent = (HKEY)(uintptr_t)p->hkey;
        HKEY result = NULL;

        LONG ret = registry_create_key(parent, p->subkey, &result);
        if (ret != 0) {
            resp->status = OBJ_STATUS_NO_MEMORY;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }

        resp->handle = (uint32_t)(uintptr_t)result;
        uint64_t hkey_val = (uint64_t)(uintptr_t)result;
        if (resp_data_max >= sizeof(hkey_val)) {
            memcpy(resp_data, &hkey_val, sizeof(hkey_val));
            resp->payload_len = sizeof(hkey_val);
        }

        *resp_len = sizeof(objectd_response_t) + resp->payload_len;
        return 0;
    }

    /* ------------------------------------------------------------------ */
    case OBJ_REQ_REG_CLOSE: {
        if (payload_len < sizeof(uint64_t)) {
            resp->status = OBJ_STATUS_INVALID;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }
        uint64_t hkey_val;
        memcpy(&hkey_val, payload, sizeof(hkey_val));
        HKEY hk = (HKEY)(uintptr_t)hkey_val;

        LONG ret = registry_close_key(hk);
        if (ret != 0)
            resp->status = OBJ_STATUS_INVALID;

        *resp_len = sizeof(objectd_response_t);
        return 0;
    }

    /* ------------------------------------------------------------------ */
    case OBJ_REQ_REG_SET_VALUE: {
        if (payload_len < sizeof(reg_set_value_payload_t)) {
            resp->status = OBJ_STATUS_INVALID;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }
        const reg_set_value_payload_t *p =
            (const reg_set_value_payload_t *)payload;
        HKEY hk = (HKEY)(uintptr_t)p->hkey;

        /* Data follows the fixed payload struct */
        const void *data = (const uint8_t *)payload + sizeof(*p);
        uint32_t data_len = p->data_len;
        if (sizeof(*p) + data_len > payload_len)
            data_len = payload_len - sizeof(*p);

        LONG ret = registry_set_value(hk, p->name, p->type, data, data_len);
        if (ret != 0) {
            resp->status = (ret == 5) ? OBJ_STATUS_ACCESS_DENIED
                                      : OBJ_STATUS_INVALID;
        }

        *resp_len = sizeof(objectd_response_t);
        return 0;
    }

    /* ------------------------------------------------------------------ */
    case OBJ_REQ_REG_GET_VALUE: {
        if (payload_len < sizeof(reg_get_value_payload_t)) {
            resp->status = OBJ_STATUS_INVALID;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }
        const reg_get_value_payload_t *p =
            (const reg_get_value_payload_t *)payload;
        HKEY hk = (HKEY)(uintptr_t)p->hkey;

        /* Allocate temporary buffer for value data */
        uint32_t buf_size = p->buf_size;
        if (buf_size > REG_MAX_DATA) buf_size = REG_MAX_DATA;
        if (buf_size == 0) buf_size = REG_MAX_DATA;

        uint8_t *tmp = malloc(buf_size);
        if (!tmp) {
            resp->status = OBJ_STATUS_NO_MEMORY;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }

        DWORD type = 0;
        DWORD size = buf_size;
        const char *subkey = (p->subkey[0] != '\0') ? p->subkey : NULL;

        LONG ret = registry_get_value(hk, subkey, p->name, &type, tmp, &size);
        if (ret != 0) {
            free(tmp);
            resp->status = (ret == 2) ? OBJ_STATUS_NOT_FOUND
                                      : OBJ_STATUS_INVALID;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }

        /* Build response: reg_get_value_response_t + data */
        reg_get_value_response_t val_resp;
        val_resp.type = type;
        val_resp.data_len = size;

        size_t needed = sizeof(val_resp) + size;
        if (needed > UINT16_MAX || needed > resp_data_max) {
            resp->status = OBJ_STATUS_NO_MEMORY;
        } else {
            memcpy(resp_data, &val_resp, sizeof(val_resp));
            if (size > 0)
                memcpy(resp_data + sizeof(val_resp), tmp, size);
            resp->payload_len = (uint16_t)needed;
        }

        free(tmp);
        *resp_len = sizeof(objectd_response_t) + resp->payload_len;
        return 0;
    }

    /* ------------------------------------------------------------------ */
    case OBJ_REQ_REG_ENUM_KEY: {
        if (payload_len < sizeof(reg_enum_payload_t)) {
            resp->status = OBJ_STATUS_INVALID;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }
        const reg_enum_payload_t *p = (const reg_enum_payload_t *)payload;
        HKEY hk = (HKEY)(uintptr_t)p->hkey;

        char name_buf[512];
        DWORD name_size = sizeof(name_buf);

        LONG ret = registry_enum_key(hk, p->index, name_buf, &name_size);
        if (ret == 259) { /* ERROR_NO_MORE_ITEMS */
            resp->status = OBJ_STATUS_NOT_FOUND;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }
        if (ret != 0) {
            resp->status = OBJ_STATUS_INVALID;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }

        /* Build response: reg_enum_key_response_t + name.
         * Clamp name_size so we never read past name_buf (registry_enum_key
         * is expected to honour the size cap, but a misbehaving backend
         * could set name_size == sizeof(name_buf) leaving no room for the
         * trailing NUL we memcpy below). */
        if (name_size >= sizeof(name_buf))
            name_size = sizeof(name_buf) - 1;
        name_buf[name_size] = '\0';

        reg_enum_key_response_t ek_resp;
        ek_resp.name_len = name_size;

        size_t needed = sizeof(ek_resp) + name_size + 1;
        if (needed > UINT16_MAX || needed > resp_data_max) {
            resp->status = OBJ_STATUS_NO_MEMORY;
        } else {
            memcpy(resp_data, &ek_resp, sizeof(ek_resp));
            memcpy(resp_data + sizeof(ek_resp), name_buf, name_size + 1);
            resp->payload_len = (uint16_t)needed;
        }

        *resp_len = sizeof(objectd_response_t) + resp->payload_len;
        return 0;
    }

    /* ------------------------------------------------------------------ */
    case OBJ_REQ_REG_ENUM_VALUE: {
        if (payload_len < sizeof(reg_enum_payload_t)) {
            resp->status = OBJ_STATUS_INVALID;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }
        const reg_enum_payload_t *p = (const reg_enum_payload_t *)payload;
        HKEY hk = (HKEY)(uintptr_t)p->hkey;

        char name_buf[512];
        DWORD name_size = sizeof(name_buf);
        DWORD val_type = 0;
        uint8_t val_data[REG_MAX_DATA];
        DWORD val_data_size = sizeof(val_data);

        LONG ret = registry_enum_value(hk, p->index, name_buf, &name_size,
                                        &val_type, val_data, &val_data_size);
        if (ret == 259) { /* ERROR_NO_MORE_ITEMS */
            resp->status = OBJ_STATUS_NOT_FOUND;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }
        if (ret != 0) {
            resp->status = OBJ_STATUS_INVALID;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }

        /* Clamp name_size / val_data_size so we never read past our stack
         * buffers.  If the registry backend mis-reports, the subsequent
         * memcpys would overflow name_buf or val_data. */
        if (name_size >= sizeof(name_buf))
            name_size = sizeof(name_buf) - 1;
        name_buf[name_size] = '\0';
        if (val_data_size > sizeof(val_data))
            val_data_size = sizeof(val_data);

        /* Build response: reg_enum_value_response_t + name + data */
        reg_enum_value_response_t ev_resp;
        ev_resp.name_len = name_size;
        ev_resp.type = val_type;
        ev_resp.data_len = val_data_size;

        size_t needed = sizeof(ev_resp) + name_size + 1 + val_data_size;
        if (needed > UINT16_MAX || needed > resp_data_max) {
            resp->status = OBJ_STATUS_NO_MEMORY;
        } else {
            uint8_t *wp = resp_data;
            memcpy(wp, &ev_resp, sizeof(ev_resp));
            wp += sizeof(ev_resp);
            memcpy(wp, name_buf, name_size + 1);
            wp += name_size + 1;
            if (val_data_size > 0)
                memcpy(wp, val_data, val_data_size);
            resp->payload_len = (uint16_t)needed;
        }

        *resp_len = sizeof(objectd_response_t) + resp->payload_len;
        return 0;
    }

    /* ------------------------------------------------------------------ */
    case OBJ_REQ_REG_DELETE_KEY: {
        if (payload_len < sizeof(reg_delete_payload_t)) {
            resp->status = OBJ_STATUS_INVALID;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }
        const reg_delete_payload_t *p = (const reg_delete_payload_t *)payload;
        HKEY hk = (HKEY)(uintptr_t)p->hkey;

        LONG ret = registry_delete_key(hk, p->name);
        if (ret != 0) {
            resp->status = (ret == 2) ? OBJ_STATUS_NOT_FOUND
                                      : OBJ_STATUS_ACCESS_DENIED;
        }

        *resp_len = sizeof(objectd_response_t);
        return 0;
    }

    /* ------------------------------------------------------------------ */
    case OBJ_REQ_REG_DELETE_VALUE: {
        if (payload_len < sizeof(reg_delete_payload_t)) {
            resp->status = OBJ_STATUS_INVALID;
            *resp_len = sizeof(objectd_response_t);
            return 0;
        }
        const reg_delete_payload_t *p = (const reg_delete_payload_t *)payload;
        HKEY hk = (HKEY)(uintptr_t)p->hkey;

        LONG ret = registry_delete_value(hk, p->name);
        if (ret != 0)
            resp->status = OBJ_STATUS_NOT_FOUND;

        *resp_len = sizeof(objectd_response_t);
        return 0;
    }

    /* ------------------------------------------------------------------ */
    default:
        fprintf(stderr, "[objectd] Unknown registry request type 0x%02x\n",
                req_type);
        resp->status = OBJ_STATUS_INVALID;
        *resp_len = sizeof(objectd_response_t);
        return -1;
    }
}

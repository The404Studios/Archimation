/*
 * objectd_namespace.h - Device namespace API
 */

#ifndef OBJECTD_NAMESPACE_H
#define OBJECTD_NAMESPACE_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    char win_path[512];    /* \Device\HarddiskVolume1 */
    char linux_path[512];  /* / */
    int  is_symlink;       /* 1 if this is a symlink to another win_path */
} ns_entry_t;

/* Initialize the namespace with default entries */
void namespace_init(void);

/* Shutdown and clear namespace */
void namespace_shutdown(void);

/* Resolve a Windows device path to a Linux path */
int namespace_resolve(const char *win_path, char *linux_path, size_t linux_path_size);

/* Create a symbolic link in the namespace */
int namespace_create_symlink(const char *link_name, const char *target);

/* Delete a symbolic link */
int namespace_delete_symlink(const char *link_name);

/* Enumerate entries matching a prefix (NULL = all) */
int namespace_enumerate(const char *prefix, ns_entry_t *out, int max_entries,
                        int *out_count);

/* Wire protocol handler */
int objectd_namespace_handle(uint8_t req_type, const void *payload,
                             uint16_t payload_len, uint64_t sequence,
                             void *resp_buf, size_t resp_buf_size,
                             size_t *resp_len);

#endif /* OBJECTD_NAMESPACE_H */

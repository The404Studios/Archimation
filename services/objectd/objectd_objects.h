/*
 * objectd_objects.h - Named object management API
 */

#ifndef OBJECTD_OBJECTS_H
#define OBJECTD_OBJECTS_H

#include <stdint.h>

/* Object types (mirrors OBJ_REQ_CREATE_* from protocol) */
#define OBJ_TYPE_MUTEX     0x01
#define OBJ_TYPE_EVENT     0x02
#define OBJ_TYPE_SEMAPHORE 0x03
#define OBJ_TYPE_MAPPING   0x04

#define MAX_NAMED_OBJECTS 4096

typedef struct {
    char     name[260];       /* Object name (MAX_PATH) */
    uint8_t  type;            /* OBJ_TYPE_* */
    uint8_t  active;          /* 1 if slot is in use */
    uint32_t owner_pid;       /* Creator PID */
    uint32_t ref_count;       /* Number of processes with handles */
    char     shm_name[64];   /* POSIX shm name (e.g., /pe-compat-obj-42) */
    int      shm_fd;          /* File descriptor for shared memory */
    void    *shm_ptr;         /* Mapped pointer (broker side) */
} named_object_t;

/* Initialize the object table */
void objects_init(void);

/* Shutdown and destroy all objects */
void objects_shutdown(void);

/*
 * Create a named object.
 * Returns the object index on success, or -1 on error.
 * Sets *status to OBJ_STATUS_ALREADY_EXISTS if name already taken.
 * Sets *out_shm_fd to the shm file descriptor for SCM_RIGHTS passing.
 */
int objects_create(const char *name, uint8_t type, int initial_state,
                   int manual_reset, int max_count, uint32_t pid,
                   uint8_t *status, int *out_shm_fd);

/*
 * Open an existing named object by name.
 * Returns the object index on success, or -1 on error.
 * Sets *out_shm_fd to the shm file descriptor.
 */
int objects_open(const char *name, uint8_t type, uint8_t *status, int *out_shm_fd);

/*
 * Close a reference to a named object.
 * Destroys the object when ref_count reaches zero.
 * Returns 0 on success, -1 on error.
 */
int objects_close(uint32_t handle, uint8_t *status);

/* Get statistics */
int objects_active_count(void);

#endif /* OBJECTD_OBJECTS_H */

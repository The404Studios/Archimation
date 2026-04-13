/*
 * objectd_shm.h - Shared memory layout and management API
 *
 * Defines the shared memory page layouts that PE processes mmap
 * and use futex() on directly for zero-overhead synchronization.
 */

#ifndef OBJECTD_SHM_H
#define OBJECTD_SHM_H

#include <stdint.h>

/* Shared memory layout for a named mutex */
typedef struct {
    _Atomic uint32_t  futex_word;   /* 0=unlocked, PID=locked */
    _Atomic uint32_t  owner_tid;
    _Atomic int32_t   recursion;
    uint32_t          _pad;
} shm_mutex_t;

/* Shared memory layout for a named event */
typedef struct {
    _Atomic uint32_t  futex_word;   /* 0=unsignaled, 1=signaled */
    uint32_t          manual_reset;
    uint32_t          _pad[2];
} shm_event_t;

/* Shared memory layout for a named semaphore */
typedef struct {
    _Atomic uint32_t  futex_word;   /* Current count */
    uint32_t          max_count;
    uint32_t          _pad[2];
} shm_semaphore_t;

/* Allocate a POSIX shared memory region (one page) */
int shm_alloc(const char *shm_name, int *out_fd, void **out_ptr);

/* Free (unmap + unlink) a shared memory region */
int shm_free(const char *shm_name, void *ptr);

/* Initialize shared page contents for each object type */
void shm_init_mutex(void *ptr, int initial_owner, uint32_t owner_pid);
void shm_init_event(void *ptr, int signaled, int manual_reset);
void shm_init_semaphore(void *ptr, int initial_count, int max_count);

#endif /* OBJECTD_SHM_H */

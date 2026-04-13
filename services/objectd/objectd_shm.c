/*
 * objectd_shm.c - Shared memory management for pe-objectd
 *
 * Allocates and manages POSIX shared memory pages for named sync objects.
 * Each named mutex/event/semaphore gets a 4096-byte shared page that PE
 * processes mmap and use futex() on directly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "objectd_protocol.h"
#include "objectd_shm.h"

#define SHM_PAGE_SIZE 4096

/*
 * shm_alloc - Create a named shared memory region
 *
 * @shm_name: POSIX shared memory name (e.g., "/pe-compat-obj-42")
 * @out_fd:   Receives the file descriptor for the shm region
 * @out_ptr:  Receives the mmap'd pointer (broker side)
 *
 * Returns 0 on success, -1 on failure.
 */
int shm_alloc(const char *shm_name, int *out_fd, void **out_ptr)
{
    int fd;
    void *ptr;

    if (!shm_name || !out_fd || !out_ptr) {
        fprintf(stderr, "[objectd] shm_alloc: invalid arguments\n");
        return -1;
    }

    /* Create shared memory object (O_CLOEXEC prevents fd leak to children) */
    fd = shm_open(shm_name, O_CREAT | O_RDWR | O_EXCL | O_CLOEXEC, 0666);
    if (fd < 0) {
        if (errno == EEXIST) {
            /*
             * Already exists -- open without O_EXCL and do NOT truncate,
             * since another process may be using the existing region.
             */
            fd = shm_open(shm_name, O_RDWR | O_CLOEXEC, 0666);
            if (fd < 0) {
                fprintf(stderr, "[objectd] shm_open(%s) failed: %s\n",
                        shm_name, strerror(errno));
                return -1;
            }
            /* Skip ftruncate -- use existing size */
            goto do_mmap;
        } else {
            fprintf(stderr, "[objectd] shm_open(%s) failed: %s\n",
                    shm_name, strerror(errno));
            return -1;
        }
    }

    /* Set size to one page (only for newly created regions) */
    if (ftruncate(fd, SHM_PAGE_SIZE) < 0) {
        fprintf(stderr, "[objectd] ftruncate(%s) failed: %s\n",
                shm_name, strerror(errno));
        close(fd);
        shm_unlink(shm_name);
        return -1;
    }

do_mmap:
    /* Map into broker's address space */
    ptr = mmap(NULL, SHM_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        fprintf(stderr, "[objectd] mmap(%s) failed: %s\n",
                shm_name, strerror(errno));
        close(fd);
        shm_unlink(shm_name);
        return -1;
    }

    /*
     * Only zero-initialize newly created pages.  If we took the EEXIST
     * path above, the region may already be in active use by other
     * processes; clobbering it would corrupt live futex state.
     */

    *out_fd = fd;
    *out_ptr = ptr;

    fprintf(stderr, "[objectd] shm_alloc: created %s (fd=%d)\n", shm_name, fd);
    return 0;
}

/*
 * shm_free - Destroy a shared memory region
 *
 * @shm_name: POSIX shared memory name
 * @ptr:      Mapped pointer to unmap
 *
 * Returns 0 on success, -1 on failure.
 */
int shm_free(const char *shm_name, void *ptr)
{
    int ret = 0;

    if (ptr && ptr != MAP_FAILED) {
        if (munmap(ptr, SHM_PAGE_SIZE) < 0) {
            fprintf(stderr, "[objectd] munmap(%s) failed: %s\n",
                    shm_name, strerror(errno));
            ret = -1;
        }
    }

    if (shm_name) {
        if (shm_unlink(shm_name) < 0 && errno != ENOENT) {
            fprintf(stderr, "[objectd] shm_unlink(%s) failed: %s\n",
                    shm_name, strerror(errno));
            ret = -1;
        }
    }

    if (ret == 0)
        fprintf(stderr, "[objectd] shm_free: destroyed %s\n", shm_name);

    return ret;
}

/*
 * shm_init_mutex - Initialize a shared mutex page
 *
 * @ptr: Mapped shared memory page
 */
void shm_init_mutex(void *ptr, int initial_owner, uint32_t owner_pid)
{
    shm_mutex_t *m = (shm_mutex_t *)ptr;
    memset(m, 0, sizeof(*m));

    if (initial_owner) {
        __atomic_store_n(&m->futex_word, owner_pid, __ATOMIC_RELEASE);
        __atomic_store_n(&m->owner_tid, owner_pid, __ATOMIC_RELEASE);
        __atomic_store_n(&m->recursion, 1, __ATOMIC_RELEASE);
    }
}

/*
 * shm_init_event - Initialize a shared event page
 *
 * @ptr:          Mapped shared memory page
 * @signaled:     Initial signal state (0 or 1)
 * @manual_reset: If nonzero, event requires manual reset
 */
void shm_init_event(void *ptr, int signaled, int manual_reset)
{
    shm_event_t *e = (shm_event_t *)ptr;
    memset(e, 0, sizeof(*e));

    __atomic_store_n(&e->futex_word, signaled ? 1 : 0, __ATOMIC_RELEASE);
    e->manual_reset = manual_reset ? 1 : 0;
}

/*
 * shm_init_semaphore - Initialize a shared semaphore page
 *
 * @ptr:           Mapped shared memory page
 * @initial_count: Initial semaphore count
 * @max_count:     Maximum semaphore count
 */
void shm_init_semaphore(void *ptr, int initial_count, int max_count)
{
    shm_semaphore_t *s = (shm_semaphore_t *)ptr;
    memset(s, 0, sizeof(*s));

    __atomic_store_n(&s->futex_word, (uint32_t)initial_count, __ATOMIC_RELEASE);
    s->max_count = (uint32_t)max_count;
}

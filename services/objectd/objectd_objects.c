/*
 * objectd_objects.c - Named object management for pe-objectd
 *
 * Manages the named object table: create, open, close, destroy.
 * Each named sync object (mutex, event, semaphore) is backed by a
 * shared memory page that PE processes mmap and futex() on directly.
 *
 * Hash table for O(1) name lookup, linear scan fallback for collisions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include "objectd_protocol.h"
#include "objectd_objects.h"
#include "objectd_shm.h"

/* --------------------------------------------------------------------------
 * Object table
 * -------------------------------------------------------------------------- */

static named_object_t g_objects[MAX_NAMED_OBJECTS];
static int            g_object_count = 0;
static pthread_mutex_t g_obj_lock = PTHREAD_MUTEX_INITIALIZER;

/* Simple hash table for name -> index lookup */
#define HASH_BUCKETS 4096
#define HASH_TOMBSTONE -2  /* Deleted slot -- continue probing past it */
static int g_hash_table[HASH_BUCKETS];  /* -1 = empty, -2 = tombstone, >=0 = object index */

/* djb2 hash */
static unsigned int hash_name(const char *name)
{
    unsigned int h = 5381;
    while (*name) {
        unsigned char c = (unsigned char)*name++;
        if (c >= 'A' && c <= 'Z') c += 32; /* Case-insensitive hash (Windows named objects are case-insensitive) */
        h = ((h << 5) + h) + c;
    }
    return h % HASH_BUCKETS;
}

/* --------------------------------------------------------------------------
 * Initialize / Shutdown
 * -------------------------------------------------------------------------- */

void objects_init(void)
{
    pthread_mutex_lock(&g_obj_lock);
    memset(g_objects, 0, sizeof(g_objects));
    g_object_count = 0;
    for (int i = 0; i < HASH_BUCKETS; i++)
        g_hash_table[i] = -1;
    pthread_mutex_unlock(&g_obj_lock);
    fprintf(stderr, "[objectd] Object table initialized (%d slots)\n",
            MAX_NAMED_OBJECTS);
}

void objects_shutdown(void)
{
    pthread_mutex_lock(&g_obj_lock);
    for (int i = 0; i < MAX_NAMED_OBJECTS; i++) {
        if (g_objects[i].active) {
            fprintf(stderr, "[objectd] Destroying object [%d] '%s' (refs=%u)\n",
                    i, g_objects[i].name, g_objects[i].ref_count);
            if (g_objects[i].shm_fd >= 0)
                close(g_objects[i].shm_fd);
            shm_free(g_objects[i].shm_name, g_objects[i].shm_ptr);
            g_objects[i].active = 0;
        }
    }
    g_object_count = 0;
    for (int i = 0; i < HASH_BUCKETS; i++)
        g_hash_table[i] = -1;
    pthread_mutex_unlock(&g_obj_lock);
    fprintf(stderr, "[objectd] Object table shut down\n");
}

/* --------------------------------------------------------------------------
 * Internal helpers (caller must hold g_obj_lock)
 * -------------------------------------------------------------------------- */

/* Find an object by name using open addressing with linear probing.
 * Returns index or -1. */
static int find_by_name_locked(const char *name)
{
    if (!name || !name[0])
        return -1;

    unsigned int bucket = hash_name(name);
    for (unsigned int step = 0; step < HASH_BUCKETS; step++) {
        unsigned int probe = (bucket + step) % HASH_BUCKETS;
        int idx = g_hash_table[probe];
        if (idx == -1)
            break;  /* Empty slot = end of probe chain */
        if (idx == HASH_TOMBSTONE)
            continue;  /* Deleted slot -- skip but continue probing */
        if (g_objects[idx].active &&
            strcasecmp(g_objects[idx].name, name) == 0) {
            return idx;
        }
        /* Occupied by a different name, keep probing */
    }
    return -1;
}

/* Find a free slot. Returns index or -1. */
static int find_free_slot_locked(void)
{
    for (int i = 0; i < MAX_NAMED_OBJECTS; i++) {
        if (!g_objects[i].active)
            return i;
    }
    return -1;
}

/* Build the shm name for a given object index */
static void make_shm_name(int index, char *buf, size_t bufsize)
{
    snprintf(buf, bufsize, "/pe-compat-obj-%d", index);
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

int objects_create(const char *name, uint8_t type, int initial_state,
                   int manual_reset, int max_count, uint32_t pid,
                   uint8_t *status, int *out_shm_fd)
{
    if (!name || !name[0]) {
        if (status) *status = OBJ_STATUS_INVALID;
        return -1;
    }

    pthread_mutex_lock(&g_obj_lock);

    /* Check if object already exists */
    int existing = find_by_name_locked(name);
    if (existing >= 0) {
        named_object_t *obj = &g_objects[existing];
        /* If same type, increment ref and return existing */
        if (obj->type == type) {
            obj->ref_count++;
            if (out_shm_fd) *out_shm_fd = obj->shm_fd;
            if (status) *status = OBJ_STATUS_ALREADY_EXISTS;
            fprintf(stderr, "[objectd] Object '%s' already exists, refs=%u\n",
                    name, obj->ref_count);
            pthread_mutex_unlock(&g_obj_lock);
            return existing;
        }
        /* Different type with same name */
        if (status) *status = OBJ_STATUS_INVALID;
        pthread_mutex_unlock(&g_obj_lock);
        return -1;
    }

    /* Find free slot */
    int idx = find_free_slot_locked();
    if (idx < 0) {
        if (status) *status = OBJ_STATUS_FULL;
        fprintf(stderr, "[objectd] Object table full (%d objects)\n",
                MAX_NAMED_OBJECTS);
        pthread_mutex_unlock(&g_obj_lock);
        return -1;
    }

    /* Allocate shared memory */
    named_object_t *obj = &g_objects[idx];
    make_shm_name(idx, obj->shm_name, sizeof(obj->shm_name));

    if (shm_alloc(obj->shm_name, &obj->shm_fd, &obj->shm_ptr) < 0) {
        if (status) *status = OBJ_STATUS_NO_MEMORY;
        pthread_mutex_unlock(&g_obj_lock);
        return -1;
    }

    /* Initialize shared memory contents based on type */
    switch (type) {
    case OBJ_TYPE_MUTEX:
        shm_init_mutex(obj->shm_ptr, initial_state, pid);
        break;
    case OBJ_TYPE_EVENT:
        shm_init_event(obj->shm_ptr, initial_state, manual_reset);
        break;
    case OBJ_TYPE_SEMAPHORE:
        shm_init_semaphore(obj->shm_ptr, initial_state,
                           max_count > 0 ? max_count : 1);
        break;
    default:
        fprintf(stderr, "[objectd] Unknown object type %u\n", type);
        shm_free(obj->shm_name, obj->shm_ptr);
        if (status) *status = OBJ_STATUS_INVALID;
        pthread_mutex_unlock(&g_obj_lock);
        return -1;
    }

    /* Fill in object metadata */
    strncpy(obj->name, name, sizeof(obj->name) - 1);
    obj->name[sizeof(obj->name) - 1] = '\0';
    obj->type = type;
    obj->active = 1;
    obj->owner_pid = pid;
    obj->ref_count = 1;

    /* Register in hash table using linear probing.
     * Both empty (-1) and tombstone (-2) slots are available for insertion. */
    unsigned int bucket = hash_name(name);
    int inserted = 0;
    for (unsigned int step = 0; step < HASH_BUCKETS; step++) {
        unsigned int probe = (bucket + step) % HASH_BUCKETS;
        if (g_hash_table[probe] == -1 || g_hash_table[probe] == HASH_TOMBSTONE) {
            g_hash_table[probe] = idx;
            inserted = 1;
            break;
        }
    }
    if (!inserted) {
        /* Hash table full — revert object allocation */
        obj->active = 0;
        if (obj->shm_fd >= 0) { close(obj->shm_fd); obj->shm_fd = -1; }
        if (status) *status = OBJ_STATUS_FULL;
        pthread_mutex_unlock(&g_obj_lock);
        return -1;
    }
    g_object_count++;

    if (out_shm_fd) *out_shm_fd = obj->shm_fd;
    if (status) *status = OBJ_STATUS_OK;

    fprintf(stderr, "[objectd] Created object [%d] '%s' type=%u pid=%u\n",
            idx, name, type, pid);

    pthread_mutex_unlock(&g_obj_lock);
    return idx;
}

int objects_open(const char *name, uint8_t type, uint8_t *status, int *out_shm_fd)
{
    if (!name || !name[0]) {
        if (status) *status = OBJ_STATUS_INVALID;
        return -1;
    }

    pthread_mutex_lock(&g_obj_lock);

    int idx = find_by_name_locked(name);
    if (idx < 0) {
        if (status) *status = OBJ_STATUS_NOT_FOUND;
        pthread_mutex_unlock(&g_obj_lock);
        return -1;
    }

    named_object_t *obj = &g_objects[idx];

    /* Type check (0 = any type) */
    if (type != 0 && obj->type != type) {
        if (status) *status = OBJ_STATUS_INVALID;
        pthread_mutex_unlock(&g_obj_lock);
        return -1;
    }

    obj->ref_count++;
    if (out_shm_fd) *out_shm_fd = obj->shm_fd;
    if (status) *status = OBJ_STATUS_OK;

    fprintf(stderr, "[objectd] Opened object [%d] '%s' refs=%u\n",
            idx, obj->name, obj->ref_count);

    pthread_mutex_unlock(&g_obj_lock);
    return idx;
}

int objects_close(uint32_t handle, uint8_t *status)
{
    if (handle >= MAX_NAMED_OBJECTS) {
        if (status) *status = OBJ_STATUS_INVALID;
        return -1;
    }

    pthread_mutex_lock(&g_obj_lock);

    named_object_t *obj = &g_objects[handle];
    if (!obj->active) {
        if (status) *status = OBJ_STATUS_NOT_FOUND;
        pthread_mutex_unlock(&g_obj_lock);
        return -1;
    }

    /* Guard against ref_count underflow */
    if (obj->ref_count == 0) {
        if (status) *status = OBJ_STATUS_INVALID;
        pthread_mutex_unlock(&g_obj_lock);
        return -1;
    }

    obj->ref_count--;
    fprintf(stderr, "[objectd] Close object [%u] '%s' refs=%u\n",
            handle, obj->name, obj->ref_count);

    if (obj->ref_count == 0) {
        /*
         * Destroy the object.
         *
         * Race condition note: another client may still have the shared
         * memory region mapped via a previously received fd (SCM_RIGHTS).
         * We mark the object destroyed and close our broker-side fd first,
         * then unlink the shm name.  Client-side mappings remain valid
         * until those processes munmap/close their own fds -- the kernel
         * keeps the shm segment alive until all references are gone.
         * We deliberately clear the name so no new clients can open it.
         */
        fprintf(stderr, "[objectd] Destroying object [%u] '%s'\n",
                handle, obj->name);

        /* Mark destroyed before any cleanup so concurrent lookups see it */
        obj->active = 0;

        /* Remove from hash table (linear probe to find the slot).
         * Use HASH_TOMBSTONE instead of -1 so subsequent lookups that
         * were inserted past this slot can still find their entries
         * via continued probing. */
        unsigned int bucket = hash_name(obj->name);
        for (unsigned int step = 0; step < HASH_BUCKETS; step++) {
            unsigned int probe = (bucket + step) % HASH_BUCKETS;
            if (g_hash_table[probe] == (int)handle) {
                g_hash_table[probe] = HASH_TOMBSTONE;
                break;
            }
            if (g_hash_table[probe] == -1)
                break;  /* Empty = end of chain, not found */
        }

        /* Close broker-side fd; clients with mapped copies are unaffected
         * because the kernel refcounts the underlying shm segment. */
        if (obj->shm_fd >= 0) {
            close(obj->shm_fd);
            obj->shm_fd = -1;
        }

        /* Unlink the shm name so no new processes can shm_open() it,
         * then unmap our broker-side mapping. */
        shm_free(obj->shm_name, obj->shm_ptr);
        obj->shm_ptr = NULL;

        /* Zero the name so stale lookups cannot match this slot */
        memset(obj->name, 0, sizeof(obj->name));
        g_object_count--;
    }

    if (status) *status = OBJ_STATUS_OK;
    pthread_mutex_unlock(&g_obj_lock);
    return 0;
}

int objects_active_count(void)
{
    int count;
    pthread_mutex_lock(&g_obj_lock);
    count = g_object_count;
    pthread_mutex_unlock(&g_obj_lock);
    return count;
}

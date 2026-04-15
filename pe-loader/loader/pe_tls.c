/*
 * pe_tls.c - Thread-Local Storage (TLS) initialization for PE images
 *
 * Windows PE images can have a TLS directory that specifies:
 *   - Raw data range to copy into each thread's TLS block
 *   - TLS index variable (updated by the loader)
 *   - TLS callback functions (called on DLL_PROCESS_ATTACH/DETACH)
 *
 * This module handles initializing TLS for loaded PE images.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "pe/pe_header.h"
#include "pe/pe_tls.h"
#include "win32/windef.h"
#include "win32/winnt.h"
#include "compat/abi_bridge.h"
#include "compat/env_setup.h"

/* Max number of PE images with TLS */
#define MAX_TLS_IMAGES 64

/* TLS callback reason codes (same as DLL notification) */
#define DLL_PROCESS_ATTACH  1
#define DLL_THREAD_ATTACH   2
#define DLL_THREAD_DETACH   3
#define DLL_PROCESS_DETACH  0

typedef struct {
    void     *raw_data_start;   /* Start of TLS template data */
    void     *raw_data_end;     /* End of TLS template data */
    uint32_t *tls_index_addr;   /* Address of the TLS index variable */
    void    **callbacks;        /* NULL-terminated list of TLS callbacks */
    void     *image_base;       /* Image base (HMODULE for callbacks) */
    DWORD     tls_index;        /* Assigned TLS index */
    size_t    zero_fill_size;   /* Bytes of zero fill after raw data */
    size_t    data_size;        /* Size of raw template data */
} tls_entry_t;

static tls_entry_t g_tls_entries[MAX_TLS_IMAGES];
static int g_tls_count = 0;
static pthread_key_t g_tls_keys[MAX_TLS_IMAGES];
static pthread_mutex_t g_tls_init_lock = PTHREAD_MUTEX_INITIALIZER;

/* TLS destructor: free TLS data when thread exits */
static void tls_destructor(void *data)
{
    free(data);
}

/* Initialize TLS for a PE image from its TLS directory */
int pe_tls_init(pe_image_t *image)
{
    if (!image || !image->mapped_base)
        return 0;

    /* Check if TLS directory exists */
    if (image->number_of_rva_and_sizes <= PE_DIR_TLS)
        return 0;

    uint32_t tls_rva = image->data_directory[PE_DIR_TLS].virtual_address;
    uint32_t tls_size = image->data_directory[PE_DIR_TLS].size;

    if (tls_rva == 0 || tls_size == 0)
        return 0;

    void *tls_dir_ptr = pe_rva_to_ptr(image, tls_rva);
    if (!tls_dir_ptr) {
        fprintf(stderr, "[tls] Invalid TLS directory RVA 0x%08X (out of bounds)\n", tls_rva);
        return -1;
    }

    pthread_mutex_lock(&g_tls_init_lock);

    if (g_tls_count >= MAX_TLS_IMAGES) {
        pthread_mutex_unlock(&g_tls_init_lock);
        fprintf(stderr, "[tls] Too many TLS images\n");
        return -1;
    }

    int idx = g_tls_count;

    /* Parse the TLS directory - handle both PE32 and PE32+ formats */
    tls_entry_t *entry = &g_tls_entries[idx];

    if (image->is_pe32plus) {
        pe_tls_directory64_t *dir = (pe_tls_directory64_t *)tls_dir_ptr;
        entry->raw_data_start = (void *)(uintptr_t)dir->start_address_of_raw_data;
        entry->raw_data_end = (void *)(uintptr_t)dir->end_address_of_raw_data;
        entry->tls_index_addr = (uint32_t *)(uintptr_t)dir->address_of_index;
        entry->callbacks = (void **)(uintptr_t)dir->address_of_callbacks;
        entry->zero_fill_size = dir->size_of_zero_fill;
    } else {
        pe_tls_directory32_t *dir = (pe_tls_directory32_t *)tls_dir_ptr;
        entry->raw_data_start = (void *)(uintptr_t)dir->start_address_of_raw_data;
        entry->raw_data_end = (void *)(uintptr_t)dir->end_address_of_raw_data;
        entry->tls_index_addr = (uint32_t *)(uintptr_t)dir->address_of_index;
        entry->callbacks = (void **)(uintptr_t)dir->address_of_callbacks;
        entry->zero_fill_size = dir->size_of_zero_fill;
    }

    /*
     * TLS directory stores Virtual Addresses (not RVAs).
     * If the image was relocated, adjust VAs by the delta.
     */
    int64_t delta = (int64_t)((uintptr_t)image->mapped_base - image->image_base);
    if (delta != 0) {
        entry->raw_data_start = (void *)((uintptr_t)entry->raw_data_start + delta);
        entry->raw_data_end = (void *)((uintptr_t)entry->raw_data_end + delta);
        if (entry->tls_index_addr)
            entry->tls_index_addr = (uint32_t *)((uintptr_t)entry->tls_index_addr + delta);
        if (entry->callbacks)
            entry->callbacks = (void **)((uintptr_t)entry->callbacks + delta);
    }

    if (entry->raw_data_end > entry->raw_data_start) {
        entry->data_size = (size_t)((uintptr_t)entry->raw_data_end -
                                     (uintptr_t)entry->raw_data_start);
    } else {
        entry->data_size = 0;
    }
    entry->image_base = image->mapped_base;
    entry->tls_index = (DWORD)idx;

    /* Create pthread key for this TLS slot */
    if (pthread_key_create(&g_tls_keys[idx], tls_destructor) != 0) {
        pthread_mutex_unlock(&g_tls_init_lock);
        fprintf(stderr, "[tls] Failed to create pthread key\n");
        return -1;
    }

    /* Write the TLS index back to the PE image */
    if (entry->tls_index_addr)
        *entry->tls_index_addr = entry->tls_index;

    g_tls_count++;
    pthread_mutex_unlock(&g_tls_init_lock);

    /* Allocate and initialize TLS data for the main thread */
    pe_tls_alloc_thread();

    /* Call TLS callbacks with DLL_PROCESS_ATTACH */
    pe_tls_call_callbacks(DLL_PROCESS_ATTACH);

    fprintf(stderr, "[tls] Initialized TLS index %d, data_size=%zu, zero_fill=%zu\n",
            idx, entry->data_size, entry->zero_fill_size);

    return 0;
}

/* Allocate TLS data for the current thread */
void pe_tls_alloc_thread(void)
{
    for (int i = 0; i < g_tls_count; i++) {
        tls_entry_t *entry = &g_tls_entries[i];
        size_t total_size;
        if (__builtin_add_overflow(entry->data_size, entry->zero_fill_size, &total_size) || total_size == 0) {
            continue;
        }

        if (pthread_getspecific(g_tls_keys[i]) != NULL)
            continue;

        void *data = calloc(1, total_size);
        if (!data)
            continue;

        /* Copy template data */
        if (entry->data_size > 0 && entry->raw_data_start)
            memcpy(data, entry->raw_data_start, entry->data_size);

        /* Zero fill is already done by calloc */

        pthread_setspecific(g_tls_keys[i], data);

        /* Also store in the TEB TLS slot array so gs:0x58 works */
        env_tls_set_slot(entry->tls_index, data);
    }
}

/* Free TLS data for the current thread */
void pe_tls_free_thread(void)
{
    for (int i = 0; i < g_tls_count; i++) {
        void *data = pthread_getspecific(g_tls_keys[i]);
        if (data) {
            free(data);
            pthread_setspecific(g_tls_keys[i], NULL);
        }
    }
}

/* Call TLS callbacks for all PE images */
void pe_tls_call_callbacks(DWORD reason)
{
    for (int i = 0; i < g_tls_count; i++) {
        tls_entry_t *entry = &g_tls_entries[i];
        if (!entry->callbacks)
            continue;

        /* Walk the NULL-terminated callback list */
        for (void **cb = entry->callbacks; *cb; cb++) {
            /*
             * TLS callback signature:
             * void NTAPI callback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
             */
            abi_call_win64_3(*cb,
                            (uint64_t)(uintptr_t)entry->image_base, /* DllHandle (HMODULE) */
                            (uint64_t)reason,
                            0); /* Reserved */
        }
    }
}

/* Get TLS data for a specific index and the current thread */
void *pe_tls_get_value(DWORD index)
{
    if (index >= (DWORD)g_tls_count)
        return NULL;
    return pthread_getspecific(g_tls_keys[index]);
}

/* Cleanup all TLS */
void pe_tls_cleanup(void)
{
    /* Call detach callbacks */
    pe_tls_call_callbacks(DLL_PROCESS_DETACH);

    for (int i = 0; i < g_tls_count; i++) {
        void *data = pthread_getspecific(g_tls_keys[i]);
        /* CRITICAL: clear the specific *before* freeing so tls_destructor
         * (still armed until pthread_key_delete) can't double-free the
         * same block if this thread's specific hook fires during exit.
         * Also stops other threads holding the same key from observing
         * a dangling pointer after we free their data below. */
        if (data) {
            pthread_setspecific(g_tls_keys[i], NULL);
            free(data);
        }
        pthread_key_delete(g_tls_keys[i]);
    }
    g_tls_count = 0;
}

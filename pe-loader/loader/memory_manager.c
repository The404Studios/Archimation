/*
 * memory_manager.c - Virtual memory reservation/commit tracking
 *
 * Tracks Windows-style reserve/commit semantics on top of Linux mmap.
 * Windows allows:
 *   1. MEM_RESERVE a range (no physical memory assigned)
 *   2. MEM_COMMIT parts of a reserved range
 *   3. MEM_DECOMMIT parts
 *   4. MEM_RELEASE the whole reservation
 *
 * On Linux, mmap with PROT_NONE simulates reserve; mprotect commits.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>

#include "pe/pe_header.h"
#include "win32/windef.h"
#include "win32/winnt.h"

/* A tracked memory region */
typedef struct mem_region {
    uintptr_t base;
    size_t    reserve_size;     /* Total reserved size */
    int       *commit_bitmap;   /* One bit per page: 1=committed, 0=reserved */
    size_t    page_count;
    DWORD     protect;          /* Protection at reservation time */
    struct mem_region *next;
} mem_region_t;

static mem_region_t *g_regions = NULL;
static pthread_mutex_t g_mem_lock = PTHREAD_MUTEX_INITIALIZER;
static long g_page_size = 0;

static void ensure_page_size(void)
{
    if (g_page_size == 0)
        g_page_size = sysconf(_SC_PAGESIZE);
}

static size_t align_up(size_t value, size_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

/* Convert Windows protection flags to Linux mmap prot */
static int win_prot_to_linux(DWORD protect)
{
    switch (protect & 0xFF) {
    case PAGE_NOACCESS:          return PROT_NONE;
    case PAGE_READONLY:          return PROT_READ;
    case PAGE_READWRITE:         return PROT_READ | PROT_WRITE;
    case PAGE_WRITECOPY:         return PROT_READ | PROT_WRITE;
    case PAGE_EXECUTE:           return PROT_EXEC;
    case PAGE_EXECUTE_READ:      return PROT_READ | PROT_EXEC;
    case PAGE_EXECUTE_READWRITE: return PROT_READ | PROT_WRITE | PROT_EXEC;
    case PAGE_EXECUTE_WRITECOPY: return PROT_READ | PROT_WRITE | PROT_EXEC;
    default:                     return PROT_READ | PROT_WRITE;
    }
}

/* Find region containing an address */
static mem_region_t *find_region(uintptr_t addr)
{
    for (mem_region_t *r = g_regions; r; r = r->next) {
        if (addr >= r->base && addr < r->base + r->reserve_size)
            return r;
    }
    return NULL;
}

void *mem_reserve(void *preferred, size_t size, DWORD protect)
{
    ensure_page_size();
    size = align_up(size, g_page_size);

    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    if (preferred)
        flags |= MAP_FIXED_NOREPLACE;

    void *addr = mmap(preferred, size, PROT_NONE, flags, -1, 0);
    if (addr == MAP_FAILED)
        return NULL;

    /* Track the reservation */
    mem_region_t *region = calloc(1, sizeof(mem_region_t));
    if (!region) {
        munmap(addr, size);
        return NULL;
    }

    region->base = (uintptr_t)addr;
    region->reserve_size = size;
    region->page_count = size / g_page_size;
    region->protect = protect;

    /* Bitmap: one int per 32 pages */
    size_t bitmap_size = (region->page_count + 31) / 32;
    region->commit_bitmap = calloc(bitmap_size, sizeof(int));
    if (!region->commit_bitmap) {
        free(region);
        munmap(addr, size);
        return NULL;
    }

    pthread_mutex_lock(&g_mem_lock);
    region->next = g_regions;
    g_regions = region;
    pthread_mutex_unlock(&g_mem_lock);

    return addr;
}

int mem_commit(void *addr, size_t size, DWORD protect)
{
    ensure_page_size();

    uintptr_t start = (uintptr_t)addr;
    start = start & ~(g_page_size - 1);
    size = align_up(size, g_page_size);

    pthread_mutex_lock(&g_mem_lock);

    mem_region_t *region = find_region(start);
    if (!region) {
        pthread_mutex_unlock(&g_mem_lock);
        /* Not in a reserved region - do a fresh mmap */
        void *result = mmap(addr, size, win_prot_to_linux(protect),
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                           -1, 0);
        return result != MAP_FAILED ? 0 : -1;
    }

    /* Mark pages as committed */
    size_t page_start = (start - region->base) / g_page_size;
    size_t page_count = size / g_page_size;

    /* Guard against out-of-bounds: page_start itself may exceed page_count */
    if (page_start >= region->page_count) {
        pthread_mutex_unlock(&g_mem_lock);
        return -1;
    }
    size_t max_pages = region->page_count - page_start;
    size_t page_end = page_start + (page_count < max_pages ? page_count : max_pages);
    for (size_t i = page_start; i < page_end; i++) {
        region->commit_bitmap[i / 32] |= (1 << (i % 32));
    }

    /* Clamp mprotect size to actual region bounds */
    size_t safe_size = (page_end - page_start) * g_page_size;

    pthread_mutex_unlock(&g_mem_lock);

    /* Apply protection */
    int prot = win_prot_to_linux(protect);
    return mprotect((void *)start, safe_size, prot);
}

int mem_decommit(void *addr, size_t size)
{
    ensure_page_size();

    uintptr_t start = (uintptr_t)addr;
    start = start & ~(g_page_size - 1);
    size = align_up(size, g_page_size);

    pthread_mutex_lock(&g_mem_lock);

    mem_region_t *region = find_region(start);
    if (region) {
        size_t page_start = (start - region->base) / g_page_size;
        size_t page_count = size / g_page_size;

        for (size_t i = page_start; i < page_start + page_count && i < region->page_count; i++) {
            region->commit_bitmap[i / 32] &= ~(1 << (i % 32));
        }
    }

    pthread_mutex_unlock(&g_mem_lock);

    /* Set PROT_NONE to decommit */
    mprotect((void *)start, size, PROT_NONE);
    /* Also use madvise to release physical pages */
    madvise((void *)start, size, MADV_DONTNEED);

    return 0;
}

int mem_release(void *addr)
{
    uintptr_t target = (uintptr_t)addr;

    pthread_mutex_lock(&g_mem_lock);

    mem_region_t *prev = NULL;
    mem_region_t *curr = g_regions;

    while (curr) {
        if (curr->base == target) {
            /* Remove from list */
            if (prev)
                prev->next = curr->next;
            else
                g_regions = curr->next;

            size_t size = curr->reserve_size;
            free(curr->commit_bitmap);
            free(curr);

            pthread_mutex_unlock(&g_mem_lock);

            munmap(addr, size);
            return 0;
        }
        prev = curr;
        curr = curr->next;
    }

    pthread_mutex_unlock(&g_mem_lock);

    /* Not tracked - try munmap anyway with a default size */
    munmap(addr, g_page_size);
    return 0;
}

int mem_protect(void *addr, size_t size, DWORD new_protect, DWORD *old_protect)
{
    ensure_page_size();

    if (old_protect)
        *old_protect = PAGE_READWRITE; /* Approximate */

    int prot = win_prot_to_linux(new_protect);
    size = align_up(size, g_page_size);

    return mprotect(addr, size, prot);
}

/* Query memory information (simplified) */
int mem_query(void *addr, void *info_buf, size_t info_size)
{
    ensure_page_size();

    if (info_size < 48) /* MEMORY_BASIC_INFORMATION is 48 bytes */
        return -1;

    typedef struct {
        PVOID  BaseAddress;
        PVOID  AllocationBase;
        DWORD  AllocationProtect;
        SIZE_T RegionSize;
        DWORD  State;
        DWORD  Protect;
        DWORD  Type;
    } MBI;

    MBI *mbi = (MBI *)info_buf;
    memset(mbi, 0, sizeof(*mbi));

    uintptr_t target = (uintptr_t)addr;

    pthread_mutex_lock(&g_mem_lock);
    mem_region_t *region = find_region(target);

    if (region) {
        mbi->BaseAddress = addr;
        mbi->AllocationBase = (PVOID)region->base;
        mbi->AllocationProtect = region->protect;
        mbi->RegionSize = region->reserve_size;

        /* Check if committed */
        size_t page = (target - region->base) / g_page_size;
        int committed = (region->commit_bitmap[page / 32] >> (page % 32)) & 1;

        mbi->State = committed ? MEM_COMMIT : MEM_RESERVE;
        mbi->Protect = committed ? region->protect : PAGE_NOACCESS;
        mbi->Type = 0x20000; /* MEM_PRIVATE */
    } else {
        mbi->BaseAddress = addr;
        mbi->RegionSize = g_page_size;
        mbi->State = 0x10000; /* MEM_FREE */
        mbi->Protect = PAGE_NOACCESS;
    }

    pthread_mutex_unlock(&g_mem_lock);
    return 0;
}

/*
 * kernel32_memory.c - Memory management stubs
 *
 * Maps VirtualAlloc/VirtualFree/HeapAlloc to mmap/munmap/malloc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <errno.h>
#include <malloc.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>

#include "common/dll_common.h"
#include "compat/trust_gate.h"

/* Simple allocation tracking for VirtualFree MEM_RELEASE */
#define MAX_TRACKED_ALLOCS 16384

typedef struct {
    void  *addr;
    size_t size;
} alloc_entry_t;

static alloc_entry_t g_alloc_table[MAX_TRACKED_ALLOCS];
static int g_alloc_count = 0;
static pthread_mutex_t g_alloc_lock = PTHREAD_MUTEX_INITIALIZER;

/* Monotonic generation bumped whenever g_alloc_table[] is mutated
 * (track_alloc append or find_and_remove_alloc swap-with-last). TLS
 * last-hit caches compare this under g_alloc_lock to detect invalidation
 * without per-thread coordination. */
static volatile unsigned int g_alloc_gen = 0;

/* TLS last-hit cache for find_and_remove_alloc(). Real-world PE apps
 * VirtualFree/UnmapViewOfFile in roughly reverse-allocation order or
 * in tight paired patterns — a 1-entry per-thread cache of the most
 * recently inserted index lets VirtualFree land on the tail without
 * scanning the table.
 *
 * Safety: read under g_alloc_lock. The cached index is only used if
 * (tls_gen == g_alloc_gen) — since both mutations and cache reads
 * happen under the lock, a stale index cannot be dereferenced into a
 * mismatched slot. */
static __thread unsigned int tls_alloc_gen     = (unsigned int)-1;
static __thread void         *tls_alloc_addr   = NULL;
static __thread int          tls_alloc_idx     = -1;

static void track_alloc(void *addr, size_t size)
{
    pthread_mutex_lock(&g_alloc_lock);
    if (g_alloc_count < MAX_TRACKED_ALLOCS) {
        int idx = g_alloc_count;
        g_alloc_table[idx].addr = addr;
        g_alloc_table[idx].size = size;
        g_alloc_count++;
        g_alloc_gen++;
        /* Seed TLS cache with the just-appended entry. Most apps free
         * their most recent allocation first (LIFO), so this hits often. */
        tls_alloc_gen  = g_alloc_gen;
        tls_alloc_addr = addr;
        tls_alloc_idx  = idx;
    } else {
        fprintf(stderr, "[kernel32] WARNING: allocation table full (%d entries), %p (%zu bytes) untracked!\n",
                MAX_TRACKED_ALLOCS, addr, size);
    }
    pthread_mutex_unlock(&g_alloc_lock);
}

static size_t find_and_remove_alloc(void *addr)
{
    pthread_mutex_lock(&g_alloc_lock);
    /* TLS fast path: last-touched address matches and gen is fresh */
    if (tls_alloc_gen == g_alloc_gen && tls_alloc_addr == addr &&
        tls_alloc_idx >= 0 && tls_alloc_idx < g_alloc_count &&
        g_alloc_table[tls_alloc_idx].addr == addr) {
        int i = tls_alloc_idx;
        size_t size = g_alloc_table[i].size;
        g_alloc_table[i] = g_alloc_table[--g_alloc_count];
        g_alloc_gen++;
        tls_alloc_addr = NULL;
        tls_alloc_idx = -1;
        pthread_mutex_unlock(&g_alloc_lock);
        return size;
    }
    for (int i = 0; i < g_alloc_count; i++) {
        if (g_alloc_table[i].addr == addr) {
            size_t size = g_alloc_table[i].size;
            g_alloc_table[i] = g_alloc_table[--g_alloc_count];
            g_alloc_gen++;
            tls_alloc_addr = NULL;
            tls_alloc_idx = -1;
            pthread_mutex_unlock(&g_alloc_lock);
            return size;
        }
    }
    pthread_mutex_unlock(&g_alloc_lock);
    return 0;
}

/* Convert Windows page protection to Linux mmap protection */
static int win_prot_to_linux(DWORD flProtect)
{
    switch (flProtect & 0xFF) {
    case PAGE_NOACCESS:           return PROT_NONE;
    case PAGE_READONLY:           return PROT_READ;
    case PAGE_READWRITE:          return PROT_READ | PROT_WRITE;
    case PAGE_WRITECOPY:          return PROT_READ | PROT_WRITE;
    case PAGE_EXECUTE:            return PROT_EXEC;
    case PAGE_EXECUTE_READ:       return PROT_READ | PROT_EXEC;
    case PAGE_EXECUTE_READWRITE:  return PROT_READ | PROT_WRITE | PROT_EXEC;
    case PAGE_EXECUTE_WRITECOPY:  return PROT_READ | PROT_WRITE | PROT_EXEC;
    default:                      return PROT_READ | PROT_WRITE;
    }
}

WINAPI_EXPORT LPVOID VirtualAlloc(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect)
{
    /* Trust gate: block executable memory allocation without trust */
    if ((flProtect & 0xFF) >= PAGE_EXECUTE) {
        TRUST_CHECK_RET(TRUST_GATE_MEMORY_EXEC, "VirtualAlloc", NULL);
    }

    int prot = win_prot_to_linux(flProtect);

    /* MEM_COMMIT without MEM_RESERVE on an existing address:
     * just change protection on previously reserved pages */
    if ((flAllocationType & MEM_COMMIT) && !(flAllocationType & MEM_RESERVE) && lpAddress) {
        if (mprotect(lpAddress, dwSize, prot) == 0) {
            return lpAddress;
        }
        /* mprotect failed -- fall through to mmap as a last resort */
    }

    int flags = MAP_PRIVATE | MAP_ANONYMOUS;

    if ((flAllocationType & MEM_RESERVE) && !(flAllocationType & MEM_COMMIT)) {
        /* Reserve only (without commit): no access yet */
        prot = PROT_NONE;
    }

    if (lpAddress != NULL) {
        flags |= MAP_FIXED_NOREPLACE;
    }

    void *result = mmap(lpAddress, dwSize, prot, flags, -1, 0);
    if (result == MAP_FAILED) {
        set_last_error(errno_to_win32_error(errno));
        return NULL;
    }

    /* Track allocation for VirtualFree MEM_RELEASE */
    if (flAllocationType & MEM_RESERVE) {
        track_alloc(result, dwSize);
    }

    return result;
}

WINAPI_EXPORT BOOL VirtualFree(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  dwFreeType)
{
    if (dwFreeType & MEM_RELEASE) {
        if (dwSize != 0) {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        size_t alloc_size = find_and_remove_alloc(lpAddress);
        if (alloc_size == 0) {
            alloc_size = 0x40000; /* 256KB fallback for untracked allocations */
            fprintf(stderr, "[kernel32] WARNING: VirtualFree(%p) untracked, using 256KB fallback\n", lpAddress);
        }
        munmap(lpAddress, alloc_size);
        return TRUE;
    }

    if (dwFreeType & MEM_DECOMMIT) {
        mprotect(lpAddress, dwSize, PROT_NONE);
        madvise(lpAddress, dwSize, MADV_DONTNEED);
        return TRUE;
    }

    set_last_error(ERROR_INVALID_PARAMETER);
    return FALSE;
}

WINAPI_EXPORT BOOL VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    DWORD *lpflOldProtect)
{
    /* Trust gate: block transition to executable memory without trust */
    if ((flNewProtect & 0xFF) >= PAGE_EXECUTE) {
        TRUST_CHECK(TRUST_GATE_MEMORY_EXEC, "VirtualProtect");
    }

    if (lpflOldProtect)
        *lpflOldProtect = PAGE_READWRITE; /* Simplified */

    int prot = win_prot_to_linux(flNewProtect);
    if (mprotect(lpAddress, dwSize, prot) < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }
    return TRUE;
}

/* ========== Real Heap Implementation ========== */

typedef struct {
    DWORD flags;           /* HEAP_NO_SERIALIZE, HEAP_GENERATE_EXCEPTIONS, etc. */
    SIZE_T initial_size;
    SIZE_T max_size;       /* 0 = growable */
    pthread_mutex_t lock;
    int valid;             /* Magic check */
} heap_data_t;

#define HEAP_MAGIC 0x48454150  /* 'HEAP' */
#define MAX_HEAPS 64
static heap_data_t *g_heaps[MAX_HEAPS];
static int g_heap_count = 0;
static pthread_mutex_t g_heap_list_lock = PTHREAD_MUTEX_INITIALIZER;
static heap_data_t g_process_heap;
static pthread_once_t g_process_heap_once = PTHREAD_ONCE_INIT;

static void do_init_process_heap(void)
{
    memset(&g_process_heap, 0, sizeof(g_process_heap));
    g_process_heap.valid = HEAP_MAGIC;
    pthread_mutex_init(&g_process_heap.lock, NULL);

    pthread_mutex_lock(&g_heap_list_lock);
    g_heaps[0] = &g_process_heap;
    if (g_heap_count == 0) g_heap_count = 1;
    pthread_mutex_unlock(&g_heap_list_lock);
}

static void ensure_process_heap(void)
{
    pthread_once(&g_process_heap_once, do_init_process_heap);
}

static int is_valid_heap(HANDLE hHeap)
{
    if (!hHeap || hHeap == INVALID_HANDLE_VALUE) return 0;
    /* Accept legacy sentinel for backwards compat */
    if ((uintptr_t)hHeap == 0xDEADBEEF) return 1;
    heap_data_t *h = (heap_data_t *)hHeap;
    return h->valid == HEAP_MAGIC;
}

WINAPI_EXPORT HANDLE HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
{
    ensure_process_heap();

    heap_data_t *heap = calloc(1, sizeof(heap_data_t));
    if (!heap) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    heap->flags = flOptions;
    heap->initial_size = dwInitialSize;
    heap->max_size = dwMaximumSize;
    heap->valid = HEAP_MAGIC;
    pthread_mutex_init(&heap->lock, NULL);

    pthread_mutex_lock(&g_heap_list_lock);
    if (g_heap_count < MAX_HEAPS)
        g_heaps[g_heap_count++] = heap;
    pthread_mutex_unlock(&g_heap_list_lock);

    return (HANDLE)heap;
}

WINAPI_EXPORT BOOL HeapDestroy(HANDLE hHeap)
{
    if (!is_valid_heap(hHeap) || (uintptr_t)hHeap == 0xDEADBEEF) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    /* Don't destroy process heap */
    if ((heap_data_t *)hHeap == &g_process_heap) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    heap_data_t *heap = (heap_data_t *)hHeap;
    pthread_mutex_lock(&g_heap_list_lock);
    for (int i = 0; i < g_heap_count; i++) {
        if (g_heaps[i] == heap) {
            g_heaps[i] = g_heaps[--g_heap_count];
            break;
        }
    }
    pthread_mutex_unlock(&g_heap_list_lock);

    heap->valid = 0;
    pthread_mutex_destroy(&heap->lock);
    free(heap);
    return TRUE;
}

WINAPI_EXPORT HANDLE GetProcessHeap(void)
{
    ensure_process_heap();
    return (HANDLE)&g_process_heap;
}

WINAPI_EXPORT DWORD GetProcessHeaps(DWORD NumberOfHeaps, HANDLE *ProcessHeaps)
{
    ensure_process_heap();
    pthread_mutex_lock(&g_heap_list_lock);
    DWORD count = (DWORD)g_heap_count;
    if (ProcessHeaps && NumberOfHeaps > 0) {
        DWORD copy = count < NumberOfHeaps ? count : NumberOfHeaps;
        for (DWORD i = 0; i < copy; i++)
            ProcessHeaps[i] = (HANDLE)g_heaps[i];
    }
    pthread_mutex_unlock(&g_heap_list_lock);
    return count;
}

WINAPI_EXPORT LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    (void)hHeap;
    void *ptr;

    if (dwBytes == 0) dwBytes = 1; /* Windows HeapAlloc(0) returns valid ptr */

    if (dwFlags & HEAP_ZERO_MEMORY)
        ptr = calloc(1, dwBytes);
    else
        ptr = malloc(dwBytes);

    if (!ptr) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        if (dwFlags & HEAP_GENERATE_EXCEPTIONS)
            abort();
    }

    return ptr;
}

WINAPI_EXPORT LPVOID HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
{
    (void)hHeap;

    if (!lpMem)
        return HeapAlloc(hHeap, dwFlags, dwBytes);

    if (dwBytes == 0)
        dwBytes = 1; /* Windows HeapReAlloc(0) returns valid ptr */

    /* HEAP_REALLOC_IN_PLACE_ONLY: cannot guarantee in-place with libc realloc */
    if (dwFlags & HEAP_REALLOC_IN_PLACE_ONLY) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    SIZE_T old_size = malloc_usable_size(lpMem);
    void *ptr = realloc(lpMem, dwBytes);
    if (!ptr) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    /* Zero new memory if requested */
    if ((dwFlags & HEAP_ZERO_MEMORY) && dwBytes > old_size)
        memset((char *)ptr + old_size, 0, dwBytes - old_size);

    return ptr;
}

WINAPI_EXPORT BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    (void)hHeap;
    (void)dwFlags;
    if (!lpMem) return TRUE; /* Freeing NULL is valid */
    free(lpMem);
    return TRUE;
}

WINAPI_EXPORT SIZE_T HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem)
{
    (void)hHeap;
    (void)dwFlags;
    if (!lpMem) return (SIZE_T)-1;
    return malloc_usable_size((void *)lpMem);
}

WINAPI_EXPORT BOOL HeapValidate(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem)
{
    (void)dwFlags;
    if (!is_valid_heap(hHeap)) return FALSE;
    if (lpMem) return lpMem != NULL; /* Basic check */
    return TRUE;
}

WINAPI_EXPORT SIZE_T HeapCompact(HANDLE hHeap, DWORD dwFlags)
{
    (void)hHeap; (void)dwFlags;
    return 0x10000; /* Report 64KB largest free block */
}

WINAPI_EXPORT BOOL HeapLock(HANDLE hHeap)
{
    if ((uintptr_t)hHeap == 0xDEADBEEF) {
        ensure_process_heap();
        hHeap = (HANDLE)&g_process_heap;
    }
    if (!is_valid_heap(hHeap)) return FALSE;
    heap_data_t *heap = (heap_data_t *)hHeap;
    pthread_mutex_lock(&heap->lock);
    return TRUE;
}

WINAPI_EXPORT BOOL HeapUnlock(HANDLE hHeap)
{
    if ((uintptr_t)hHeap == 0xDEADBEEF) {
        ensure_process_heap();
        hHeap = (HANDLE)&g_process_heap;
    }
    if (!is_valid_heap(hHeap)) return FALSE;
    heap_data_t *heap = (heap_data_t *)hHeap;
    pthread_mutex_unlock(&heap->lock);
    return TRUE;
}

WINAPI_EXPORT BOOL HeapWalk(HANDLE hHeap, void *lpEntry)
{
    (void)hHeap; (void)lpEntry;
    set_last_error(ERROR_NO_MORE_ITEMS);
    return FALSE;
}

WINAPI_EXPORT BOOL HeapQueryInformation(HANDLE hHeap, int HeapInformationClass,
                                         PVOID HeapInformation, SIZE_T HeapInformationLength,
                                         SIZE_T *ReturnLength)
{
    (void)hHeap;
    if (HeapInformationClass == 0) { /* HeapCompatibilityInformation */
        if (HeapInformation && HeapInformationLength >= sizeof(ULONG)) {
            *(ULONG *)HeapInformation = 0; /* Standard heap */
            if (ReturnLength) *ReturnLength = sizeof(ULONG);
            return TRUE;
        }
    }
    set_last_error(ERROR_INSUFFICIENT_BUFFER);
    return FALSE;
}

WINAPI_EXPORT BOOL HeapSetInformation(HANDLE hHeap, int HeapInformationClass,
                                       PVOID HeapInformation, SIZE_T HeapInformationLength)
{
    (void)hHeap; (void)HeapInformationClass;
    (void)HeapInformation; (void)HeapInformationLength;
    return TRUE; /* Accept but ignore */
}

/* GMEM/LMEM flags */
#define GMEM_FIXED      0x0000
#define GMEM_MOVEABLE   0x0002
#define GMEM_ZEROINIT   0x0040
#define GHND            (GMEM_MOVEABLE | GMEM_ZEROINIT)
#define GPTR            (GMEM_FIXED | GMEM_ZEROINIT)
#define LMEM_FIXED      0x0000
#define LMEM_MOVEABLE   0x0002
#define LMEM_ZEROINIT   0x0040

WINAPI_EXPORT HGLOBAL GlobalAlloc(UINT uFlags, SIZE_T dwBytes)
{
    SIZE_T size = dwBytes ? dwBytes : 1;
    if (uFlags & GMEM_ZEROINIT)
        return calloc(1, size);
    return malloc(size);
}

WINAPI_EXPORT HGLOBAL GlobalFree(HGLOBAL hMem)
{
    free(hMem);
    return NULL;
}

WINAPI_EXPORT HGLOBAL GlobalReAlloc(HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags)
{
    SIZE_T size = dwBytes ? dwBytes : 1;
    if (uFlags & GMEM_ZEROINIT) {
        SIZE_T old_size = hMem ? malloc_usable_size(hMem) : 0;
        void *ptr = realloc(hMem, size);
        if (ptr && size > old_size)
            memset((char *)ptr + old_size, 0, size - old_size);
        return ptr;
    }
    return realloc(hMem, size);
}

WINAPI_EXPORT SIZE_T GlobalSize(HGLOBAL hMem)
{
    if (!hMem) return 0;
    return malloc_usable_size(hMem);
}

WINAPI_EXPORT LPVOID GlobalLock(HGLOBAL hMem)
{
    return hMem; /* Global memory is always "locked" for us */
}

WINAPI_EXPORT BOOL GlobalUnlock(HGLOBAL hMem)
{
    (void)hMem;
    return TRUE;
}

WINAPI_EXPORT HLOCAL LocalAlloc(UINT uFlags, SIZE_T uBytes)
{
    SIZE_T size = uBytes ? uBytes : 1;
    if (uFlags & LMEM_ZEROINIT)
        return calloc(1, size);
    return malloc(size);
}

WINAPI_EXPORT HLOCAL LocalFree(HLOCAL hMem)
{
    return GlobalFree(hMem);
}

WINAPI_EXPORT LPVOID LocalLock(HLOCAL hMem)
{
    return hMem; /* Local memory is already a pointer */
}

WINAPI_EXPORT BOOL LocalUnlock(HLOCAL hMem)
{
    (void)hMem;
    return TRUE;
}

WINAPI_EXPORT HLOCAL LocalReAlloc(HLOCAL hMem, SIZE_T uBytes, UINT uFlags)
{
    return GlobalReAlloc(hMem, uBytes, uFlags);
}

WINAPI_EXPORT SIZE_T LocalSize(HLOCAL hMem)
{
    if (!hMem) return 0;
    return malloc_usable_size(hMem);
}

/* ---------- File Mapping (mmap-backed) ----------
 *
 * File-mapping family:  CreateFileMapping{A,W}, OpenFileMapping{A,W},
 * MapViewOfFile, MapViewOfFileEx, MapViewOfFile3, UnmapViewOfFile,
 * FlushViewOfFile.
 *
 * Semantics:
 *  - CreateFileMappingA registers (name -> HANDLE) in g_fmap_names so that
 *    OpenFileMappingA in the same process finds the existing mapping.
 *  - MapViewOfFile* page-aligns the user-supplied offset before mmap() and
 *    tracks (user_addr, mmap_base, mmap_len) in g_file_views so that
 *    UnmapViewOfFile can munmap the real aligned region.
 *  - UnmapViewOfFile looks up the view by user_addr; if not found, returns
 *    FALSE with ERROR_INVALID_ADDRESS (Windows semantics).
 *  - FlushViewOfFile uses msync(MS_SYNC); len=0 means "to end of view".
 *  - Session 23 contract: file_mapping_data_t layout is frozen.  fmd->fd
 *    holds the backing file's fd; the handle entry's fd is -1 so CloseHandle
 *    on the mapping does not close the backing file.
 */

/* ERROR_INVALID_ADDRESS is 487 on Windows and is not in winnt.h locally. */
#ifndef ERROR_INVALID_ADDRESS
#define ERROR_INVALID_ADDRESS  487
#endif

/* FILE_MAP_* (from WinNT.h x64). Windows uses SECTION_MAP_* aliases. */
#define FILE_MAP_COPY        0x00000001
#define FILE_MAP_WRITE       0x00000002
#define FILE_MAP_READ        0x00000004
#define FILE_MAP_ALL_ACCESS  0x000F001F
#define FILE_MAP_EXECUTE     0x00000020

typedef struct {
    int    fd;
    DWORD  protect;
    SIZE_T max_size;
} file_mapping_data_t;

/* ---- View tracking: addr returned to caller -> real mmap base/len.
 *
 * Separate from g_alloc_table because the caller-visible pointer may be
 * offset from the real mmap base by up to (page_size - 1) bytes due to
 * sub-page file-offset alignment.  UnmapViewOfFile/FlushViewOfFile need
 * the aligned base and full length to munmap/msync correctly. */
#define MAX_TRACKED_VIEWS 4096

typedef struct {
    void  *user_addr;   /* what MapViewOfFile returned */
    void  *real_base;   /* what mmap() returned (page-aligned) */
    size_t real_len;    /* length passed to mmap() (page-aligned + delta) */
} file_view_t;

static file_view_t g_file_views[MAX_TRACKED_VIEWS];
static int g_file_view_count = 0;
static pthread_mutex_t g_file_view_lock = PTHREAD_MUTEX_INITIALIZER;

/* Monotonic generation bumped whenever g_file_views[] is mutated. TLS
 * last-hit cache compares this under the lock to detect invalidation. */
static volatile unsigned int g_file_view_gen = 0;

/* TLS last-hit cache: FlushViewOfFile and UnmapViewOfFile are typically
 * called in LIFO order relative to MapViewOfFile (e.g. loading assets from
 * memory-mapped archives). A 1-entry cache eliminates the linear scan on
 * the common "free what I just mapped" pattern. */
static __thread unsigned int tls_fv_gen   = (unsigned int)-1;
static __thread const void   *tls_fv_addr = NULL;
static __thread int           tls_fv_idx  = -1;

static void track_file_view(void *user_addr, void *real_base, size_t real_len)
{
    pthread_mutex_lock(&g_file_view_lock);
    if (g_file_view_count < MAX_TRACKED_VIEWS) {
        int idx = g_file_view_count;
        g_file_views[idx].user_addr = user_addr;
        g_file_views[idx].real_base = real_base;
        g_file_views[idx].real_len  = real_len;
        g_file_view_count++;
        g_file_view_gen++;
        /* Seed TLS cache with the just-appended entry. */
        tls_fv_gen  = g_file_view_gen;
        tls_fv_addr = user_addr;
        tls_fv_idx  = idx;
    } else {
        fprintf(stderr, "[kernel32] WARNING: file view table full (%d entries), %p untracked!\n",
                MAX_TRACKED_VIEWS, user_addr);
    }
    pthread_mutex_unlock(&g_file_view_lock);
}

/* Look up a file view by the caller-visible address. If remove != 0, the
 * entry is removed from the table.  Returns 1 on hit (out_base/out_len set),
 * 0 on miss. */
static int find_file_view(const void *user_addr, int remove,
                          void **out_base, size_t *out_len)
{
    pthread_mutex_lock(&g_file_view_lock);

    /* TLS fast path: last-touched address matches and gen is fresh. */
    if (tls_fv_gen == g_file_view_gen && tls_fv_addr == user_addr &&
        tls_fv_idx >= 0 && tls_fv_idx < g_file_view_count &&
        g_file_views[tls_fv_idx].user_addr == user_addr) {
        int i = tls_fv_idx;
        if (out_base) *out_base = g_file_views[i].real_base;
        if (out_len)  *out_len  = g_file_views[i].real_len;
        if (remove) {
            g_file_views[i] = g_file_views[--g_file_view_count];
            g_file_view_gen++;
            tls_fv_addr = NULL;
            tls_fv_idx  = -1;
        }
        pthread_mutex_unlock(&g_file_view_lock);
        return 1;
    }

    for (int i = 0; i < g_file_view_count; i++) {
        if (g_file_views[i].user_addr == user_addr) {
            if (out_base) *out_base = g_file_views[i].real_base;
            if (out_len)  *out_len  = g_file_views[i].real_len;
            if (remove) {
                g_file_views[i] = g_file_views[--g_file_view_count];
                g_file_view_gen++;
                tls_fv_addr = NULL;
                tls_fv_idx  = -1;
            } else {
                tls_fv_gen  = g_file_view_gen;
                tls_fv_addr = user_addr;
                tls_fv_idx  = i;
            }
            pthread_mutex_unlock(&g_file_view_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_file_view_lock);
    return 0;
}

/* ---- Named file-mapping registry (intra-process).
 *
 * Cross-process sharing would need the Object Broker; for now OpenFileMapping
 * finds mappings created by CreateFileMapping in the same process.  This
 * mirrors the pattern used by kernel32_sync.c for named events/mutexes but
 * is local to avoid adding a public header (constraint: edit only this file). */
#define MAX_FMAP_NAMES 256

typedef struct {
    char   name[260];
    HANDLE handle;
} fmap_name_entry_t;

static fmap_name_entry_t g_fmap_names[MAX_FMAP_NAMES];
static int g_fmap_name_count = 0;
static pthread_mutex_t g_fmap_name_lock = PTHREAD_MUTEX_INITIALIZER;

/* "Global\\Foo" and "Local\\Foo" both map to bare "Foo" for lookup. */
static const char *strip_ns_prefix(const char *name)
{
    if (!name) return NULL;
    if (strncmp(name, "Global\\", 7) == 0) return name + 7;
    if (strncmp(name, "Local\\",  6) == 0) return name + 6;
    if (strncmp(name, "Session\\", 8) == 0) {
        /* Session\N\Foo -> Foo */
        const char *p = name + 8;
        while (*p && *p != '\\') p++;
        if (*p == '\\') return p + 1;
    }
    return name;
}

static HANDLE fmap_name_lookup(const char *name)
{
    if (!name || !name[0]) return NULL;
    const char *key = strip_ns_prefix(name);
    pthread_mutex_lock(&g_fmap_name_lock);
    for (int i = 0; i < g_fmap_name_count; i++) {
        /* Windows named objects are case-insensitive. Using strcmp() here
         * (as the original did) caused OpenFileMappingA("FOO") to miss a
         * mapping created via CreateFileMappingA("foo"), even though real
         * Windows would find it. strcasecmp matches NTSTATUS semantics. */
        if (strcasecmp(g_fmap_names[i].name, key) == 0) {
            HANDLE h = g_fmap_names[i].handle;
            pthread_mutex_unlock(&g_fmap_name_lock);
            return h;
        }
    }
    pthread_mutex_unlock(&g_fmap_name_lock);
    return NULL;
}

static void fmap_name_register(const char *name, HANDLE h)
{
    if (!name || !name[0] || !h) return;
    const char *key = strip_ns_prefix(name);
    pthread_mutex_lock(&g_fmap_name_lock);
    if (g_fmap_name_count < MAX_FMAP_NAMES) {
        fmap_name_entry_t *e = &g_fmap_names[g_fmap_name_count++];
        strncpy(e->name, key, sizeof(e->name) - 1);
        e->name[sizeof(e->name) - 1] = '\0';
        e->handle = h;
    }
    pthread_mutex_unlock(&g_fmap_name_lock);
}

WINAPI_EXPORT HANDLE CreateFileMappingA(
    HANDLE hFile,
    LPSECURITY_ATTRIBUTES lpAttributes,
    DWORD flProtect,
    DWORD dwMaximumSizeHigh,
    DWORD dwMaximumSizeLow,
    LPCSTR lpName)
{
    (void)lpAttributes;

    int fd = -1;
    if (hFile != INVALID_HANDLE_VALUE)
        fd = handle_get_fd(hFile);

    SIZE_T max_size = ((SIZE_T)dwMaximumSizeHigh << 32) | dwMaximumSizeLow;

    /* For anonymous mappings (fd == -1), max_size must be non-zero */
    if (fd < 0 && max_size == 0) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    /* If the name already exists, return an existing-handle + ERROR_ALREADY_EXISTS.
     * CreateFileMapping contract: returns the existing object, does not create. */
    if (lpName && lpName[0]) {
        HANDLE existing = fmap_name_lookup(lpName);
        if (existing) {
            set_last_error(ERROR_ALREADY_EXISTS);
            return existing;
        }
    }

    file_mapping_data_t *fmd = calloc(1, sizeof(file_mapping_data_t));
    if (!fmd) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    fmd->fd = fd;
    fmd->protect = flProtect;
    fmd->max_size = max_size;

    /* Store -1 as the handle's fd, not the backing file's fd.  The backing
     * fd is still owned by hFile; if we put it in entry->fd, CloseHandle on
     * this mapping would close the backing file out from under hFile. */
    HANDLE h = handle_alloc(HANDLE_TYPE_FILE_MAPPING, -1, fmd);
    if (h == INVALID_HANDLE_VALUE || h == NULL) {
        /* CreateFileMapping returns NULL on failure, not INVALID_HANDLE_VALUE */
        free(fmd);
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    if (lpName && lpName[0])
        fmap_name_register(lpName, h);

    return h;
}

/* Internal helper: convert FILE_MAP_* access DWORD to (prot, flags).
 * extra_flags is an out-param for MAP_PRIVATE vs MAP_SHARED selection. */
static void file_map_access_to_mmap(DWORD access, int *out_prot, int *out_flags)
{
    int prot = 0;
    int flags;

    /* FILE_MAP_ALL_ACCESS is the Windows "RW + everything" shorthand. */
    if ((access & FILE_MAP_ALL_ACCESS) == FILE_MAP_ALL_ACCESS)
        prot = PROT_READ | PROT_WRITE;

    if (access & FILE_MAP_READ)   prot |= PROT_READ;
    if (access & FILE_MAP_WRITE)  prot |= PROT_READ | PROT_WRITE;
    if (access & FILE_MAP_COPY)   prot |= PROT_READ | PROT_WRITE;
    if (access & FILE_MAP_EXECUTE) prot |= PROT_EXEC;

    /* No read/write bits at all: default to read-only (Windows treats
     * SECTION_QUERY as implied read). */
    if (prot == 0) prot = PROT_READ;

    /* FILE_MAP_COPY is copy-on-write, maps MAP_PRIVATE.  Everything else
     * maps MAP_SHARED so stores are visible to other views/the file. */
    if (access & FILE_MAP_COPY)
        flags = MAP_PRIVATE;
    else
        flags = MAP_SHARED;

    *out_prot = prot;
    *out_flags = flags;
}

/* Internal shared impl for MapViewOfFile / MapViewOfFileEx.
 *
 * hint != NULL means MapViewOfFileEx with a suggested base.  Windows
 * semantics require the view land exactly at hint or fail; we use
 * MAP_FIXED_NOREPLACE when available and verify the returned address. */
static LPVOID do_map_view(HANDLE hFileMappingObject,
                          DWORD  access,
                          DWORD  off_hi,
                          DWORD  off_lo,
                          SIZE_T len,
                          LPVOID hint)
{
    handle_entry_t *entry = handle_lookup(hFileMappingObject);
    if (!entry || entry->type != HANDLE_TYPE_FILE_MAPPING) {
        set_last_error(ERROR_INVALID_HANDLE);
        return NULL;
    }
    file_mapping_data_t *fmd = (file_mapping_data_t *)entry->data;
    if (!fmd) {
        set_last_error(ERROR_INVALID_HANDLE);
        return NULL;
    }

    uint64_t offset = ((uint64_t)off_hi << 32) | off_lo;

    /* Sanity: offset must not exceed the mapping size. */
    if (fmd->max_size && offset > (uint64_t)fmd->max_size) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    /* len == 0: map to end of mapping (Windows semantics). */
    if (len == 0) {
        if (fmd->max_size)
            len = fmd->max_size - (SIZE_T)offset;
        else
            len = 0x10000; /* anonymous mapping with unknown size: 64KB fallback */
    }

    int prot, flags;
    file_map_access_to_mmap(access, &prot, &flags);

    /* Anonymous (fd < 0) mappings must use MAP_ANONYMOUS + MAP_PRIVATE.
     * Linux mmap rejects MAP_SHARED|MAP_ANONYMOUS with fd=-1 on older
     * kernels; use MAP_PRIVATE for cross-kernel portability. */
    if (fmd->fd < 0) {
        flags = MAP_PRIVATE | MAP_ANONYMOUS;
    }

    /* Page-align the file offset.  mmap requires offset to be a multiple
     * of the system page size; we adjust by computing aligned_off and
     * bumping the map length by the delta, then returning real_base + delta.
     * Cached: page size is immutable per process; avoid the /proc auxv read. */
    static long cached_page = 0;
    long page = __atomic_load_n(&cached_page, __ATOMIC_ACQUIRE);
    if (page <= 0) {
        page = sysconf(_SC_PAGESIZE);
        if (page <= 0) page = 4096;
        __atomic_store_n(&cached_page, page, __ATOMIC_RELEASE);
    }

    uint64_t aligned_off = offset & ~((uint64_t)page - 1);
    uint64_t delta       = offset - aligned_off;
    size_t   real_len    = (size_t)(len + delta);

    /* Fixed-base request (MapViewOfFileEx with non-NULL hint).  Use
     * MAP_FIXED_NOREPLACE so we don't accidentally clobber an existing
     * mapping; fall back to hinted mmap if the kernel lacks the flag. */
    void *map_addr = NULL;
    if (hint) {
        /* Adjust the hint by -delta so that real_base + delta == hint. */
        map_addr = (void *)((uintptr_t)hint - (uintptr_t)delta);
#ifdef MAP_FIXED_NOREPLACE
        flags |= MAP_FIXED_NOREPLACE;
#endif
    }

    off_t moff = (off_t)aligned_off;
    void *real_base = mmap(map_addr, real_len, prot, flags,
                           (fmd->fd < 0) ? -1 : fmd->fd, moff);

    if (real_base == MAP_FAILED) {
#ifdef MAP_FIXED_NOREPLACE
        /* Older kernel may reject MAP_FIXED_NOREPLACE with EINVAL.  Retry
         * without the flag and verify the returned address. */
        if (hint && (errno == EINVAL || errno == ENOTSUP || errno == EOPNOTSUPP)) {
            flags &= ~MAP_FIXED_NOREPLACE;
            real_base = mmap(map_addr, real_len, prot, flags,
                             (fmd->fd < 0) ? -1 : fmd->fd, moff);
        }
#endif
        if (real_base == MAP_FAILED) {
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }
    }

    /* If caller requested a specific base, the kernel must have honored
     * it (either via MAP_FIXED_NOREPLACE success or just luck on hinted
     * mmap).  Otherwise undo and error. */
    if (hint && real_base != map_addr) {
        munmap(real_base, real_len);
        set_last_error(ERROR_INVALID_ADDRESS);
        return NULL;
    }

    void *user_addr = (void *)((uintptr_t)real_base + (uintptr_t)delta);
    track_file_view(user_addr, real_base, real_len);
    return user_addr;
}

WINAPI_EXPORT LPVOID MapViewOfFile(
    HANDLE hFileMappingObject,
    DWORD dwDesiredAccess,
    DWORD dwFileOffsetHigh,
    DWORD dwFileOffsetLow,
    SIZE_T dwNumberOfBytesToMap)
{
    return do_map_view(hFileMappingObject, dwDesiredAccess,
                       dwFileOffsetHigh, dwFileOffsetLow,
                       dwNumberOfBytesToMap, NULL);
}

WINAPI_EXPORT LPVOID MapViewOfFileEx(
    HANDLE hFileMappingObject,
    DWORD  dwDesiredAccess,
    DWORD  dwFileOffsetHigh,
    DWORD  dwFileOffsetLow,
    SIZE_T dwNumberOfBytesToMap,
    LPVOID lpBaseAddress)
{
    return do_map_view(hFileMappingObject, dwDesiredAccess,
                       dwFileOffsetHigh, dwFileOffsetLow,
                       dwNumberOfBytesToMap, lpBaseAddress);
}

WINAPI_EXPORT BOOL UnmapViewOfFile(LPCVOID lpBaseAddress)
{
    if (!lpBaseAddress) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    void  *real_base = NULL;
    size_t real_len  = 0;
    if (find_file_view(lpBaseAddress, 1 /* remove */, &real_base, &real_len)) {
        if (munmap(real_base, real_len) != 0) {
            set_last_error(errno_to_win32_error(errno));
            return FALSE;
        }
        return TRUE;
    }

    /* Fallback: caller may have mapped via MapViewOfFile3 path in older
     * builds that tracked via g_alloc_table, or passed a raw pointer from
     * another subsystem.  Try find_and_remove_alloc() as a best-effort
     * path before giving up. */
    size_t alloc_size = find_and_remove_alloc((void *)lpBaseAddress);
    if (alloc_size) {
        munmap((void *)lpBaseAddress, alloc_size);
        return TRUE;
    }

    set_last_error(ERROR_INVALID_ADDRESS);
    return FALSE;
}

WINAPI_EXPORT BOOL FlushViewOfFile(LPCVOID lpBaseAddress, SIZE_T dwNumberOfBytesToFlush)
{
    if (!lpBaseAddress) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    void  *real_base = NULL;
    size_t real_len  = 0;
    if (find_file_view(lpBaseAddress, 0 /* keep */, &real_base, &real_len)) {
        /* If caller specified a length, flush [lpBaseAddress, +len); else
         * flush from lpBaseAddress through end-of-view. */
        if (dwNumberOfBytesToFlush == 0) {
            uintptr_t delta = (uintptr_t)lpBaseAddress - (uintptr_t)real_base;
            if (delta > real_len) {
                set_last_error(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            dwNumberOfBytesToFlush = real_len - delta;
        }
        if (msync((void *)lpBaseAddress, dwNumberOfBytesToFlush, MS_SYNC) != 0) {
            set_last_error(errno_to_win32_error(errno));
            return FALSE;
        }
        return TRUE;
    }

    /* Untracked address: try direct msync on whatever the caller provided.
     * msync will page-align internally; if len == 0, fall back to one page. */
    size_t len = dwNumberOfBytesToFlush ? dwNumberOfBytesToFlush : 0x1000;
    if (msync((void *)lpBaseAddress, len, MS_SYNC) != 0) {
        set_last_error(ERROR_INVALID_ADDRESS);
        return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT HANDLE OpenFileMappingA(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName)
{
    (void)dwDesiredAccess;
    (void)bInheritHandle;

    if (!lpName || !lpName[0]) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    HANDLE h = fmap_name_lookup(lpName);
    if (!h) {
        set_last_error(ERROR_FILE_NOT_FOUND);
        return NULL;
    }

    /* Increment ref count on the underlying handle so caller can close
     * independently of the creator.  handle_lookup returns the same slot;
     * bumping ref_count keeps the entry alive through an extra close. */
    handle_entry_t *entry = handle_lookup(h);
    if (entry && entry->type == HANDLE_TYPE_FILE_MAPPING) {
        /* Intentionally reusing the existing handle; the handle-table
         * ref model treats repeated returns of the same HANDLE as refs
         * (the next CloseHandle on h drops one ref).  This mirrors what
         * OpenEvent/OpenMutex in kernel32_sync.c effectively do. */
        __sync_fetch_and_add(&entry->ref_count, 1);
        return h;
    }

    set_last_error(ERROR_INVALID_HANDLE);
    return NULL;
}

WINAPI_EXPORT HANDLE OpenFileMappingW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName)
{
    if (!lpName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    char narrow[260];
    size_t i;
    for (i = 0; i < sizeof(narrow) - 1 && lpName[i]; i++)
        narrow[i] = (char)(lpName[i] & 0x7F);
    narrow[i] = '\0';
    return OpenFileMappingA(dwDesiredAccess, bInheritHandle, narrow);
}

/* ---------- VirtualQuery ---------- */

typedef struct {
    PVOID  BaseAddress;
    PVOID  AllocationBase;
    DWORD  AllocationProtect;
    SIZE_T RegionSize;
    DWORD  State;
    DWORD  Protect;
    DWORD  Type;
} MEMORY_BASIC_INFORMATION;

WINAPI_EXPORT SIZE_T VirtualQuery(
    LPCVOID lpAddress,
    MEMORY_BASIC_INFORMATION *lpBuffer,
    SIZE_T dwLength)
{
    if (!lpBuffer || dwLength < sizeof(MEMORY_BASIC_INFORMATION)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    memset(lpBuffer, 0, sizeof(MEMORY_BASIC_INFORMATION));
    lpBuffer->BaseAddress = (PVOID)lpAddress;
    lpBuffer->AllocationBase = (PVOID)lpAddress;

    /* Parse /proc/self/maps to find the region containing lpAddress */
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) {
        /* Return a default "committed, read-write" region */
        lpBuffer->RegionSize = 0x1000;
        lpBuffer->State = MEM_COMMIT;
        lpBuffer->Protect = PAGE_READWRITE;
        lpBuffer->Type = 0x20000; /* MEM_PRIVATE */
        return sizeof(MEMORY_BASIC_INFORMATION);
    }

    uintptr_t addr = (uintptr_t)lpAddress;
    char line[512];
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        uintptr_t start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            if (addr >= start && addr < end) {
                lpBuffer->BaseAddress = (PVOID)start;
                lpBuffer->AllocationBase = (PVOID)start;
                lpBuffer->RegionSize = end - start;
                lpBuffer->State = MEM_COMMIT;

                DWORD prot = 0;
                if (perms[0] == 'r') prot |= PAGE_READONLY;
                if (perms[1] == 'w') prot = PAGE_READWRITE;
                if (perms[2] == 'x') {
                    if (perms[1] == 'w')
                        prot = PAGE_EXECUTE_READWRITE;
                    else
                        prot = PAGE_EXECUTE_READ;
                }
                if (prot == 0) prot = PAGE_NOACCESS;
                lpBuffer->Protect = prot;
                lpBuffer->AllocationProtect = prot;
                lpBuffer->Type = 0x20000; /* MEM_PRIVATE */
                found = 1;
                break;
            }
        }
    }

    fclose(f);

    if (!found) {
        lpBuffer->RegionSize = 0x1000;
        lpBuffer->State = 0x10000; /* MEM_FREE */
        lpBuffer->Protect = PAGE_NOACCESS;
    }

    return sizeof(MEMORY_BASIC_INFORMATION);
}

/* ---------- CreateFileMappingW ---------- */

WINAPI_EXPORT HANDLE CreateFileMappingW(
    HANDLE hFile,
    void *lpAttributes,
    DWORD flProtect,
    DWORD dwMaximumSizeHigh,
    DWORD dwMaximumSizeLow,
    LPCWSTR lpName)
{
    /* Narrow the UTF-16 name so the A version can register it in
     * g_fmap_names -- otherwise OpenFileMappingW can't find mappings
     * created by CreateFileMappingW. */
    char narrow_name[260];
    const char *name_ptr = NULL;
    if (lpName) {
        size_t i;
        for (i = 0; i < sizeof(narrow_name) - 1 && lpName[i]; i++)
            narrow_name[i] = (char)(lpName[i] & 0x7F);
        narrow_name[i] = '\0';
        if (narrow_name[0])
            name_ptr = narrow_name;
    }
    return CreateFileMappingA(hFile, (LPSECURITY_ATTRIBUTES)lpAttributes,
                              flProtect, dwMaximumSizeHigh, dwMaximumSizeLow,
                              name_ptr);
}

/* ---------- VirtualAlloc2 (Windows 10 1803+, used by UE5) ---------- */

WINAPI_EXPORT LPVOID VirtualAlloc2(
    HANDLE Process,
    LPVOID BaseAddress,
    SIZE_T Size,
    DWORD  AllocationType,
    DWORD  PageProtection,
    void  *ExtendedParameters,
    ULONG  ParameterCount)
{
    (void)Process;
    (void)ExtendedParameters;
    (void)ParameterCount;
    /* Ignore extended parameters (MEM_ADDRESS_REQUIREMENTS, etc.) */
    return VirtualAlloc(BaseAddress, Size, AllocationType, PageProtection);
}

/* ---------- MapViewOfFile3 (Windows 10 1803+, used by UE5) ---------- */

WINAPI_EXPORT LPVOID MapViewOfFile3(
    HANDLE FileMapping,
    HANDLE Process,
    LPVOID BaseAddress,
    uint64_t Offset,
    SIZE_T  ViewSize,
    DWORD   AllocationType,
    DWORD   PageProtection,
    void   *ExtendedParameters,
    ULONG   ParameterCount)
{
    (void)Process;
    (void)AllocationType;
    (void)ExtendedParameters;
    (void)ParameterCount;

    handle_entry_t *entry = handle_lookup(FileMapping);
    if (!entry || entry->type != HANDLE_TYPE_FILE_MAPPING) {
        set_last_error(ERROR_INVALID_HANDLE);
        return NULL;
    }

    file_mapping_data_t *fmd = (file_mapping_data_t *)entry->data;

    int prot = win_prot_to_linux(PageProtection);
    int flags = MAP_SHARED;

    if (fmd->fd < 0)
        flags = MAP_PRIVATE | MAP_ANONYMOUS;

    if (BaseAddress)
        flags |= MAP_FIXED_NOREPLACE;

    SIZE_T map_size = ViewSize;
    if (map_size == 0)
        map_size = fmd->max_size;

    void *ptr = mmap(BaseAddress, map_size, prot, flags, fmd->fd, (off_t)Offset);
    if (ptr == MAP_FAILED) {
        set_last_error(errno_to_win32_error(errno));
        return NULL;
    }

    /* Track in the file-view table so UnmapViewOfFile finds it.  MapViewOfFile3
     * takes a uint64_t Offset that Windows requires to be 64KB aligned, so no
     * sub-page delta to worry about here -- user_addr == real_base. */
    track_file_view(ptr, ptr, map_size);
    return ptr;
}

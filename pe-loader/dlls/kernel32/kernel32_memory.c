/*
 * kernel32_memory.c - Memory management stubs
 *
 * Maps VirtualAlloc/VirtualFree/HeapAlloc to mmap/munmap/malloc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <malloc.h>
#include <pthread.h>

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

static void track_alloc(void *addr, size_t size)
{
    pthread_mutex_lock(&g_alloc_lock);
    if (g_alloc_count < MAX_TRACKED_ALLOCS) {
        g_alloc_table[g_alloc_count].addr = addr;
        g_alloc_table[g_alloc_count].size = size;
        g_alloc_count++;
    } else {
        fprintf(stderr, "[kernel32] WARNING: allocation table full (%d entries), %p (%zu bytes) untracked!\n",
                MAX_TRACKED_ALLOCS, addr, size);
    }
    pthread_mutex_unlock(&g_alloc_lock);
}

static size_t find_and_remove_alloc(void *addr)
{
    pthread_mutex_lock(&g_alloc_lock);
    for (int i = 0; i < g_alloc_count; i++) {
        if (g_alloc_table[i].addr == addr) {
            size_t size = g_alloc_table[i].size;
            g_alloc_table[i] = g_alloc_table[--g_alloc_count];
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

/* ---------- File Mapping (mmap-backed) ---------- */

typedef struct {
    int    fd;
    DWORD  protect;
    SIZE_T max_size;
} file_mapping_data_t;

WINAPI_EXPORT HANDLE CreateFileMappingA(
    HANDLE hFile,
    LPSECURITY_ATTRIBUTES lpAttributes,
    DWORD flProtect,
    DWORD dwMaximumSizeHigh,
    DWORD dwMaximumSizeLow,
    LPCSTR lpName)
{
    (void)lpAttributes;
    (void)lpName;

    int fd = -1;
    if (hFile != INVALID_HANDLE_VALUE)
        fd = handle_get_fd(hFile);

    SIZE_T max_size = ((SIZE_T)dwMaximumSizeHigh << 32) | dwMaximumSizeLow;

    /* For anonymous mappings (fd == -1), max_size must be non-zero */
    if (fd < 0 && max_size == 0) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    file_mapping_data_t *fmd = calloc(1, sizeof(file_mapping_data_t));
    if (!fmd) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    fmd->fd = fd;
    fmd->protect = flProtect;
    fmd->max_size = max_size;

    HANDLE h = handle_alloc(HANDLE_TYPE_FILE_MAPPING, fd, fmd);
    if (h == INVALID_HANDLE_VALUE) {
        /* CreateFileMapping returns NULL on failure, not INVALID_HANDLE_VALUE */
        free(fmd);
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    return h;
}

WINAPI_EXPORT LPVOID MapViewOfFile(
    HANDLE hFileMappingObject,
    DWORD dwDesiredAccess,
    DWORD dwFileOffsetHigh,
    DWORD dwFileOffsetLow,
    SIZE_T dwNumberOfBytesToMap)
{
    handle_entry_t *entry = handle_lookup(hFileMappingObject);
    if (!entry || entry->type != HANDLE_TYPE_FILE_MAPPING) {
        set_last_error(ERROR_INVALID_HANDLE);
        return NULL;
    }

    file_mapping_data_t *fmd = (file_mapping_data_t *)entry->data;

    int prot = PROT_READ;
    int flags = MAP_SHARED;

    if (dwDesiredAccess & 0x0002) /* FILE_MAP_WRITE */
        prot |= PROT_WRITE;
    if (dwDesiredAccess & 0x0020) /* FILE_MAP_EXECUTE */
        prot |= PROT_EXEC;
    if (dwDesiredAccess & 0x0010) /* FILE_MAP_COPY */
        flags = MAP_PRIVATE;

    if (fmd->fd < 0)
        flags = MAP_PRIVATE | MAP_ANONYMOUS;

    off_t offset = ((off_t)dwFileOffsetHigh << 32) | dwFileOffsetLow;
    SIZE_T map_size = dwNumberOfBytesToMap;
    if (map_size == 0)
        map_size = fmd->max_size;

    void *ptr = mmap(NULL, map_size, prot, flags, fmd->fd, offset);
    if (ptr == MAP_FAILED) {
        set_last_error(errno_to_win32_error(errno));
        return NULL;
    }

    track_alloc(ptr, map_size);
    return ptr;
}

WINAPI_EXPORT BOOL UnmapViewOfFile(LPCVOID lpBaseAddress)
{
    if (!lpBaseAddress) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    size_t size = find_and_remove_alloc((void *)lpBaseAddress);
    if (size == 0)
        size = 0x10000; /* Fallback */

    munmap((void *)lpBaseAddress, size);
    return TRUE;
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
    (void)lpName; /* Name ignored - convert to A version */
    return CreateFileMappingA(hFile, (LPSECURITY_ATTRIBUTES)lpAttributes,
                              flProtect, dwMaximumSizeHigh, dwMaximumSizeLow,
                              NULL);
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

    track_alloc(ptr, map_size);
    return ptr;
}

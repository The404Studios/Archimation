/*
 * msvcrt_heap.c - MSVCRT/UCRT heap and aligned allocation functions
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include "common/dll_common.h"

/* _msize - get size of allocated block */
WINAPI_EXPORT size_t _msize(void *memblock)
{
    if (!memblock) return (size_t)-1;
    return malloc_usable_size(memblock);
}

/* Aligned allocation */
WINAPI_EXPORT void *_aligned_malloc(size_t size, size_t alignment)
{
    void *ptr = NULL;
    if (alignment == 0) alignment = 16;
    if (posix_memalign(&ptr, alignment, size) != 0)
        return NULL;
    return ptr;
}

WINAPI_EXPORT void *_aligned_realloc(void *memblock, size_t size, size_t alignment)
{
    if (!memblock) return _aligned_malloc(size, alignment);
    if (size == 0) {
        free(memblock);
        return NULL;
    }
    void *newptr = _aligned_malloc(size, alignment);
    if (newptr) {
        size_t old_size = malloc_usable_size(memblock);
        size_t copy_size = old_size < size ? old_size : size;
        memcpy(newptr, memblock, copy_size);
        free(memblock);
    }
    return newptr;
}

WINAPI_EXPORT void _aligned_free(void *memblock)
{
    free(memblock);
}

WINAPI_EXPORT void *_aligned_offset_malloc(size_t size, size_t alignment, size_t offset)
{
    (void)offset;
    return _aligned_malloc(size, alignment);
}

WINAPI_EXPORT void *_aligned_offset_realloc(void *memblock, size_t size,
                                             size_t alignment, size_t offset)
{
    (void)offset;
    return _aligned_realloc(memblock, size, alignment);
}

/* _malloc_crt - internal CRT malloc */
WINAPI_EXPORT void *_malloc_crt(size_t size)
{
    return malloc(size);
}

WINAPI_EXPORT void *_calloc_crt(size_t count, size_t size)
{
    return calloc(count, size);
}

WINAPI_EXPORT void *_realloc_crt(void *ptr, size_t size)
{
    return realloc(ptr, size);
}

WINAPI_EXPORT void _free_crt(void *ptr)
{
    free(ptr);
}

/* _expand - try to expand block in place */
WINAPI_EXPORT void *_expand(void *memblock, size_t size)
{
    (void)memblock; (void)size;
    /* Cannot expand in place with standard malloc */
    return NULL;
}

/* Debug CRT stubs */
WINAPI_EXPORT int _CrtSetDbgFlag(int newFlag)
{
    (void)newFlag;
    return 0;
}

WINAPI_EXPORT int _CrtSetReportMode(int reportType, int reportMode)
{
    (void)reportType; (void)reportMode;
    return 0;
}

WINAPI_EXPORT int _CrtDbgReport(int reportType, const char *filename,
                                 int linenumber, const char *moduleName,
                                 const char *format, ...)
{
    (void)reportType; (void)filename; (void)linenumber;
    (void)moduleName; (void)format;
    return 0;
}

WINAPI_EXPORT int _CrtSetReportFile(int reportType, void *reportFile)
{
    (void)reportType; (void)reportFile;
    return 0;
}

WINAPI_EXPORT void *_CrtSetReportHook(void *reportHook)
{
    (void)reportHook;
    return NULL;
}

WINAPI_EXPORT int _CrtCheckMemory(void)
{
    return 1; /* Always valid */
}

WINAPI_EXPORT int _CrtDumpMemoryLeaks(void)
{
    return 0; /* No leaks */
}

WINAPI_EXPORT int _CrtIsValidHeapPointer(const void *userData)
{
    return userData != NULL;
}

WINAPI_EXPORT int _CrtIsMemoryBlock(const void *userData, unsigned int size,
                                     long *requestNumber, char **filename,
                                     int *linenumber)
{
    (void)userData; (void)size; (void)requestNumber;
    (void)filename; (void)linenumber;
    return 1;
}

/* Debug allocation wrappers */
WINAPI_EXPORT void *_malloc_dbg(size_t size, int blockType,
                                 const char *filename, int linenumber)
{
    (void)blockType; (void)filename; (void)linenumber;
    return malloc(size);
}

WINAPI_EXPORT void *_calloc_dbg(size_t num, size_t size, int blockType,
                                 const char *filename, int linenumber)
{
    (void)blockType; (void)filename; (void)linenumber;
    return calloc(num, size);
}

WINAPI_EXPORT void *_realloc_dbg(void *userData, size_t newSize, int blockType,
                                  const char *filename, int linenumber)
{
    (void)blockType; (void)filename; (void)linenumber;
    return realloc(userData, newSize);
}

WINAPI_EXPORT void _free_dbg(void *userData, int blockType)
{
    (void)blockType;
    free(userData);
}

WINAPI_EXPORT size_t _msize_dbg(void *memblock, int blockType)
{
    (void)blockType;
    return _msize(memblock);
}

/* _recalloc - realloc + zero-fill new bytes */
WINAPI_EXPORT void *_recalloc(void *memblock, size_t count, size_t size)
{
    /* MSVC _recalloc(p, 0, 0) frees p and returns NULL (matches MS
     * realloc(p,0) semantics).  Without this the glibc realloc(p,0)
     * behavior is implementation-defined and may leak or alias. */
    size_t total = count * size;
    if (count && total / count != size) return NULL; /* overflow */
    if (total == 0) {
        if (memblock) free(memblock);
        return NULL;
    }
    if (!memblock) return calloc(count, size);
    size_t old_size = malloc_usable_size(memblock);
    void *ptr = realloc(memblock, total);
    if (ptr && total > old_size)
        memset((char *)ptr + old_size, 0, total - old_size);
    return ptr;
}

WINAPI_EXPORT void *_recalloc_dbg(void *memblock, size_t count, size_t size,
                                   int blockType, const char *filename, int linenumber)
{
    (void)blockType; (void)filename; (void)linenumber;
    return _recalloc(memblock, count, size);
}

/* _heapchk - validate heap consistency */
#define _HEAPOK       (-2)
#define _HEAPEMPTY    (-1)
#define _HEAPBADBEGIN (-3)
#define _HEAPBADNODE  (-4)
#define _HEAPEND      (-5)
#define _HEAPBADPTR   (-6)

WINAPI_EXPORT int _heapchk(void)
{
    return _HEAPOK;
}

WINAPI_EXPORT int _heapmin(void)
{
    /* Try to release free pages back to OS */
    malloc_trim(0);
    return 0;
}

WINAPI_EXPORT int _heapset(unsigned int fill)
{
    (void)fill;
    return _HEAPOK;
}

/* _HEAPINFO for _heapwalk */
typedef struct _heapinfo {
    int *_pentry;
    size_t _size;
    int _useflag;
} _HEAPINFO;

WINAPI_EXPORT int _heapwalk(_HEAPINFO *entryinfo)
{
    (void)entryinfo;
    return _HEAPEND; /* No more entries */
}

/* new handler */
typedef int (*_PNH)(size_t);
static _PNH g_new_handler = NULL;

WINAPI_EXPORT _PNH _set_new_handler(_PNH pNewHandler)
{
    _PNH old = g_new_handler;
    g_new_handler = pNewHandler;
    return old;
}

WINAPI_EXPORT _PNH _query_new_handler(void)
{
    return g_new_handler;
}

/* _callnewh - call the new handler when allocation fails */
WINAPI_EXPORT int _callnewh(size_t size)
{
    if (g_new_handler)
        return g_new_handler(size);
    return 0;
}

/* _aligned_msize */
WINAPI_EXPORT size_t _aligned_msize(void *memblock, size_t alignment, size_t offset)
{
    (void)alignment; (void)offset;
    if (!memblock) return (size_t)-1;
    return malloc_usable_size(memblock);
}

/* _aligned_recalloc */
WINAPI_EXPORT void *_aligned_recalloc(void *memblock, size_t count, size_t size,
                                       size_t alignment)
{
    size_t total = count * size;
    if (count && total / count != size) return NULL;
    if (total == 0) {
        if (memblock) _aligned_free(memblock);
        return NULL;
    }
    size_t old_size = memblock ? malloc_usable_size(memblock) : 0;
    void *ptr = _aligned_realloc(memblock, total, alignment);
    if (ptr && total > old_size)
        memset((char *)ptr + old_size, 0, total - old_size);
    return ptr;
}

/* _CrtSetAllocHook */
typedef int (*_CRT_ALLOC_HOOK)(int, void *, size_t, int, long, const unsigned char *, int);

WINAPI_EXPORT _CRT_ALLOC_HOOK _CrtSetAllocHook(_CRT_ALLOC_HOOK allocHook)
{
    (void)allocHook;
    return NULL;
}

/* _CrtSetDumpClient */
typedef void (*_CRT_DUMP_CLIENT)(void *, size_t);

WINAPI_EXPORT _CRT_DUMP_CLIENT _CrtSetDumpClient(_CRT_DUMP_CLIENT dumpClient)
{
    (void)dumpClient;
    return NULL;
}

/* _CrtMemCheckpoint / _CrtMemDifference */
typedef struct _CrtMemState {
    void *pBlockHeader;
    size_t lCounts[5];
    size_t lSizes[5];
    size_t lHighWaterCount;
    size_t lTotalCount;
} _CrtMemState;

WINAPI_EXPORT void _CrtMemCheckpoint(_CrtMemState *state)
{
    if (state) memset(state, 0, sizeof(*state));
}

WINAPI_EXPORT int _CrtMemDifference(_CrtMemState *stateDiff,
                                     const _CrtMemState *oldState,
                                     const _CrtMemState *newState)
{
    (void)oldState; (void)newState;
    if (stateDiff) memset(stateDiff, 0, sizeof(*stateDiff));
    return 0;
}

WINAPI_EXPORT void _CrtMemDumpStatistics(const _CrtMemState *state)
{
    (void)state;
}

WINAPI_EXPORT void _CrtMemDumpAllObjectsSince(const _CrtMemState *state)
{
    (void)state;
}

/* ================================================================
 * _o_ prefixed UCRT private function aliases for heap functions.
 * ================================================================ */
WINAPI_EXPORT size_t _o__msize(void *m) { return _msize(m); }
WINAPI_EXPORT void *_o__aligned_malloc(size_t s, size_t a) { return _aligned_malloc(s, a); }
WINAPI_EXPORT void *_o__aligned_realloc(void *m, size_t s, size_t a) { return _aligned_realloc(m, s, a); }
WINAPI_EXPORT void _o__aligned_free(void *m) { _aligned_free(m); }
WINAPI_EXPORT void *_o__aligned_offset_malloc(size_t s, size_t a, size_t o) { return _aligned_offset_malloc(s, a, o); }
WINAPI_EXPORT void *_o__aligned_offset_realloc(void *m, size_t s, size_t a, size_t o) { return _aligned_offset_realloc(m, s, a, o); }
WINAPI_EXPORT void *_o__malloc_crt(size_t s) { return _malloc_crt(s); }
WINAPI_EXPORT void *_o__calloc_crt(size_t c, size_t s) { return _calloc_crt(c, s); }
WINAPI_EXPORT void *_o__realloc_crt(void *p, size_t s) { return _realloc_crt(p, s); }
WINAPI_EXPORT void _o__free_crt(void *p) { _free_crt(p); }
WINAPI_EXPORT void *_o__expand(void *m, size_t s) { return _expand(m, s); }
WINAPI_EXPORT void *_o__recalloc(void *m, size_t c, size_t s) { return _recalloc(m, c, s); }
WINAPI_EXPORT int _o__heapchk(void) { return _heapchk(); }
WINAPI_EXPORT int _o__heapmin(void) { return _heapmin(); }
WINAPI_EXPORT void *_o_calloc(size_t c, size_t s) { return calloc(c, s); }
WINAPI_EXPORT void *_o_realloc(void *p, size_t s) { return realloc(p, s); }
WINAPI_EXPORT size_t _o__aligned_msize(void *m, size_t a, size_t o) { return _aligned_msize(m, a, o); }


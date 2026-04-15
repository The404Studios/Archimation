/*
 * dstorage_stubs.c - DirectStorage (dstorage.dll / dstoragecore.dll) stubs
 *
 * UE5 uses DirectStorage for fast asset streaming from NVMe drives.
 * We implement the COM interfaces with a synchronous pread() backend
 * so the game loads assets correctly, just without async IO.
 *
 * COM interfaces implemented:
 *   IDStorageFactory    - CreateQueue, OpenFile, CreateStatusArray
 *   IDStorageQueue      - EnqueueRequest, Submit, CancelRequestsWithTag, Close
 *   IDStorageFile       - wraps an open() fd
 *   IDStorageStatusArray - IsComplete (always TRUE), GetHResult (always S_OK)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <errno.h>

#include "common/dll_common.h"

#define DS_LOG "[dstorage] "

/* HRESULT codes */
#define S_OK          ((HRESULT)0x00000000)
#define E_INVALIDARG  ((HRESULT)0x80070057)
#define E_OUTOFMEMORY ((HRESULT)0x8007000E)
#define E_NOINTERFACE ((HRESULT)0x80004002)
#define E_NOTIMPL     ((HRESULT)0x80004001)
#define E_FAIL        ((HRESULT)0x80004005)

/* DSTORAGE_COMPRESSION_FORMAT */
#define DSTORAGE_COMPRESSION_FORMAT_NONE 0

/* ========== Forward declarations ========== */

typedef struct IDStorageFactory IDStorageFactory;
typedef struct IDStorageQueue IDStorageQueue;
typedef struct IDStorageFile IDStorageFile;
typedef struct IDStorageStatusArray IDStorageStatusArray;

/* ========== IDStorageFile ========== */

typedef struct {
    HRESULT (__attribute__((ms_abi)) *QueryInterface)(IDStorageFile *self, const GUID *riid, void **ppv);
    ULONG   (__attribute__((ms_abi)) *AddRef)(IDStorageFile *self);
    ULONG   (__attribute__((ms_abi)) *Release)(IDStorageFile *self);
    void    (__attribute__((ms_abi)) *Close)(IDStorageFile *self);
    HRESULT (__attribute__((ms_abi)) *GetFileInformation)(IDStorageFile *self, void *info);
} IDStorageFileVtbl;

struct IDStorageFile {
    IDStorageFileVtbl *lpVtbl;
    uint32_t ref_count;
    int fd;
    char path[512];
};

static const unsigned char IID_IUnknown_bytes[16] = {
    0x00,0x00,0x00,0x00, 0x00,0x00, 0x00,0x00,
    0xC0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46
};

static __attribute__((ms_abi)) HRESULT dsfile_QueryInterface(IDStorageFile *self, const GUID *riid, void **ppv)
{
    if (!ppv) return (HRESULT)0x80004003; /* E_POINTER */
    *ppv = NULL;
    if (!riid || memcmp(riid, IID_IUnknown_bytes, 16) == 0) {
        *ppv = self;
        __sync_add_and_fetch(&self->ref_count, 1);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) ULONG dsfile_AddRef(IDStorageFile *self)
{
    return __sync_add_and_fetch(&self->ref_count, 1);
}

static __attribute__((ms_abi)) ULONG dsfile_Release(IDStorageFile *self)
{
    uint32_t ref = __sync_sub_and_fetch(&self->ref_count, 1);
    if (ref == 0) {
        if (self->fd >= 0) close(self->fd);
        free(self->lpVtbl);
        free(self);
    }
    return ref;
}

static __attribute__((ms_abi)) void dsfile_Close(IDStorageFile *self)
{
    if (self->fd >= 0) {
        close(self->fd);
        self->fd = -1;
    }
}

/* BY_HANDLE_FILE_INFORMATION (simplified for our needs) */
typedef struct {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD dwVolumeSerialNumber;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD nNumberOfLinks;
    DWORD nFileIndexHigh;
    DWORD nFileIndexLow;
} BY_HANDLE_FILE_INFORMATION;

static __attribute__((ms_abi)) HRESULT dsfile_GetFileInformation(IDStorageFile *self, void *info)
{
    if (!info) return E_INVALIDARG;

    struct stat st;
    if (fstat(self->fd, &st) < 0) return E_FAIL;

    BY_HANDLE_FILE_INFORMATION *fi = (BY_HANDLE_FILE_INFORMATION *)info;
    memset(fi, 0, sizeof(*fi));
    fi->nFileSizeLow = (DWORD)(st.st_size & 0xFFFFFFFF);
    fi->nFileSizeHigh = (DWORD)(st.st_size >> 32);
    fi->nNumberOfLinks = (DWORD)st.st_nlink;
    fi->dwFileAttributes = 0x80; /* FILE_ATTRIBUTE_NORMAL */

    return S_OK;
}

static IDStorageFileVtbl *create_dsfile_vtbl(void)
{
    IDStorageFileVtbl *vtbl = calloc(1, sizeof(IDStorageFileVtbl));
    if (!vtbl) return NULL;
    vtbl->QueryInterface = dsfile_QueryInterface;
    vtbl->AddRef = dsfile_AddRef;
    vtbl->Release = dsfile_Release;
    vtbl->Close = dsfile_Close;
    vtbl->GetFileInformation = dsfile_GetFileInformation;
    return vtbl;
}

/* ========== IDStorageStatusArray ========== */

typedef struct {
    HRESULT (__attribute__((ms_abi)) *QueryInterface)(IDStorageStatusArray *self, const GUID *riid, void **ppv);
    ULONG   (__attribute__((ms_abi)) *AddRef)(IDStorageStatusArray *self);
    ULONG   (__attribute__((ms_abi)) *Release)(IDStorageStatusArray *self);
    BOOL    (__attribute__((ms_abi)) *IsComplete)(IDStorageStatusArray *self, uint32_t index);
    HRESULT (__attribute__((ms_abi)) *GetHResult)(IDStorageStatusArray *self, uint32_t index);
} IDStorageStatusArrayVtbl;

struct IDStorageStatusArray {
    IDStorageStatusArrayVtbl *lpVtbl;
    uint32_t ref_count;
    uint32_t capacity;
};

static __attribute__((ms_abi)) HRESULT dsstat_QueryInterface(IDStorageStatusArray *self, const GUID *riid, void **ppv)
{
    if (!ppv) return (HRESULT)0x80004003; /* E_POINTER */
    *ppv = NULL;
    if (!riid || memcmp(riid, IID_IUnknown_bytes, 16) == 0) {
        *ppv = self;
        __sync_add_and_fetch(&self->ref_count, 1);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) ULONG dsstat_AddRef(IDStorageStatusArray *self)
{
    return __sync_add_and_fetch(&self->ref_count, 1);
}

static __attribute__((ms_abi)) ULONG dsstat_Release(IDStorageStatusArray *self)
{
    uint32_t ref = __sync_sub_and_fetch(&self->ref_count, 1);
    if (ref == 0) {
        free(self->lpVtbl);
        free(self);
    }
    return ref;
}

static __attribute__((ms_abi)) BOOL dsstat_IsComplete(IDStorageStatusArray *self, uint32_t index)
{
    (void)self; (void)index;
    return TRUE; /* Synchronous — always complete */
}

static __attribute__((ms_abi)) HRESULT dsstat_GetHResult(IDStorageStatusArray *self, uint32_t index)
{
    (void)self; (void)index;
    return S_OK; /* All reads succeed */
}

static IDStorageStatusArrayVtbl *create_dsstat_vtbl(void)
{
    IDStorageStatusArrayVtbl *vtbl = calloc(1, sizeof(IDStorageStatusArrayVtbl));
    if (!vtbl) return NULL;
    vtbl->QueryInterface = dsstat_QueryInterface;
    vtbl->AddRef = dsstat_AddRef;
    vtbl->Release = dsstat_Release;
    vtbl->IsComplete = dsstat_IsComplete;
    vtbl->GetHResult = dsstat_GetHResult;
    return vtbl;
}

/* ========== IDStorageQueue ========== */

#define DS_QUEUE_MAX_REQUESTS 4096

typedef struct {
    int      fd;
    void    *dest;
    uint64_t offset;
    uint32_t size;
    uint32_t status_index;
} ds_request_t;

typedef struct {
    HRESULT (__attribute__((ms_abi)) *QueryInterface)(IDStorageQueue *self, const GUID *riid, void **ppv);
    ULONG   (__attribute__((ms_abi)) *AddRef)(IDStorageQueue *self);
    ULONG   (__attribute__((ms_abi)) *Release)(IDStorageQueue *self);
    void    (__attribute__((ms_abi)) *EnqueueRequest)(IDStorageQueue *self, const void *request);
    void    (__attribute__((ms_abi)) *EnqueueStatus)(IDStorageQueue *self, IDStorageStatusArray *statusArray, uint32_t index);
    void    (__attribute__((ms_abi)) *EnqueueSignal)(IDStorageQueue *self, void *fence, uint64_t value);
    void    (__attribute__((ms_abi)) *Submit)(IDStorageQueue *self);
    void    (__attribute__((ms_abi)) *CancelRequestsWithTag)(IDStorageQueue *self, uint64_t mask, uint64_t value);
    void    (__attribute__((ms_abi)) *Close)(IDStorageQueue *self);
    HRESULT (__attribute__((ms_abi)) *GetErrorEvent)(IDStorageQueue *self, void **event);
    void    (__attribute__((ms_abi)) *Query)(IDStorageQueue *self, void *info);
} IDStorageQueueVtbl;

struct IDStorageQueue {
    IDStorageQueueVtbl *lpVtbl;
    uint32_t ref_count;
    ds_request_t *requests;
    uint32_t request_count;
    uint32_t request_capacity;
    pthread_mutex_t lock;
};

/*
 * DSTORAGE_REQUEST layout (simplified — enough to extract the fields we need):
 *   Offset 0x00: DSTORAGE_REQUEST_OPTIONS (uint64_t)
 *   Offset 0x08: IDStorageFile *Source.File
 *   Offset 0x10: uint64_t Source.Offset
 *   Offset 0x18: uint32_t Source.Size
 *   Offset 0x20: uint64_t UncompressedSize
 *   Offset 0x28: void *Destination.Buffer
 *   Offset 0x30: uint32_t Destination.Size
 *   Offset 0x38: uint64_t CancellationTag
 *   Offset 0x40: char *Name (debug)
 */

static __attribute__((ms_abi)) HRESULT dsqueue_QueryInterface(IDStorageQueue *self, const GUID *riid, void **ppv)
{
    if (!ppv) return (HRESULT)0x80004003; /* E_POINTER */
    *ppv = NULL;
    if (!riid || memcmp(riid, IID_IUnknown_bytes, 16) == 0) {
        *ppv = self;
        __sync_add_and_fetch(&self->ref_count, 1);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) ULONG dsqueue_AddRef(IDStorageQueue *self)
{
    return __sync_add_and_fetch(&self->ref_count, 1);
}

static __attribute__((ms_abi)) ULONG dsqueue_Release(IDStorageQueue *self)
{
    uint32_t ref = __sync_sub_and_fetch(&self->ref_count, 1);
    if (ref == 0) {
        free(self->requests);
        pthread_mutex_destroy(&self->lock);
        free(self->lpVtbl);
        free(self);
    }
    return ref;
}

static __attribute__((ms_abi)) void dsqueue_EnqueueRequest(IDStorageQueue *self, const void *request)
{
    if (!request) return;

    /* Parse the DSTORAGE_REQUEST structure */
    const uint8_t *req = (const uint8_t *)request;

    IDStorageFile *file = *(IDStorageFile **)(req + 0x08);
    uint64_t offset     = *(uint64_t *)(req + 0x10);
    uint32_t src_size   = *(uint32_t *)(req + 0x18);
    void    *dest_buf   = *(void **)(req + 0x28);

    if (!file || !dest_buf || src_size == 0) return;

    pthread_mutex_lock(&self->lock);

    /* Grow request buffer if needed */
    if (self->request_count >= self->request_capacity) {
        uint32_t new_cap = self->request_capacity ? self->request_capacity * 2 : 256;
        if (new_cap > DS_QUEUE_MAX_REQUESTS) new_cap = DS_QUEUE_MAX_REQUESTS;
        ds_request_t *new_reqs = realloc(self->requests, new_cap * sizeof(ds_request_t));
        if (!new_reqs) {
            pthread_mutex_unlock(&self->lock);
            return;
        }
        self->requests = new_reqs;
        self->request_capacity = new_cap;
    }

    ds_request_t *r = &self->requests[self->request_count++];
    r->fd = file->fd;
    r->dest = dest_buf;
    r->offset = offset;
    r->size = src_size;
    r->status_index = 0;

    pthread_mutex_unlock(&self->lock);
}

static __attribute__((ms_abi)) void dsqueue_EnqueueStatus(IDStorageQueue *self, IDStorageStatusArray *statusArray, uint32_t index)
{
    (void)self; (void)statusArray; (void)index;
    /* Status tracking is a no-op — we complete synchronously on Submit */
}

static __attribute__((ms_abi)) void dsqueue_EnqueueSignal(IDStorageQueue *self, void *fence, uint64_t value)
{
    (void)self; (void)fence; (void)value;
    /* Fence signaling is a no-op — work completes synchronously */
}

static __attribute__((ms_abi)) void dsqueue_Submit(IDStorageQueue *self)
{
    pthread_mutex_lock(&self->lock);

    for (uint32_t i = 0; i < self->request_count; i++) {
        ds_request_t *r = &self->requests[i];
        if (r->fd < 0 || !r->dest || r->size == 0) continue;

        /* Loop pread until the full range is satisfied. Short reads from
         * network filesystems or interrupted syscalls were previously
         * padded with zeros, silently corrupting UE5 assets (Session 30
         * bug: Fortnite texture streaming mis-rendered bricks when NFS
         * returned EINTR mid-request). */
        uint32_t remaining = r->size;
        char    *dst       = (char *)r->dest;
        uint64_t offset    = r->offset;
        int      hard_fail = 0;
        while (remaining > 0) {
            ssize_t bytes = pread(r->fd, dst, remaining, (off_t)offset);
            if (bytes < 0) {
                if (errno == EINTR) continue;
                fprintf(stderr, DS_LOG "Submit: pread failed for fd=%d offset=%lu rem=%u: %s\n",
                        r->fd, (unsigned long)offset, remaining, strerror(errno));
                hard_fail = 1;
                break;
            }
            if (bytes == 0) {
                /* EOF before full read: zero-fill the remainder. */
                memset(dst, 0, remaining);
                break;
            }
            dst       += bytes;
            offset    += (uint64_t)bytes;
            remaining -= (uint32_t)bytes;
        }
        if (hard_fail && remaining > 0) {
            memset(dst, 0, remaining);
        }
    }

    self->request_count = 0;
    pthread_mutex_unlock(&self->lock);
}

static __attribute__((ms_abi)) void dsqueue_CancelRequestsWithTag(IDStorageQueue *self, uint64_t mask, uint64_t value)
{
    (void)mask; (void)value;
    pthread_mutex_lock(&self->lock);
    self->request_count = 0; /* Drop all pending */
    pthread_mutex_unlock(&self->lock);
}

static __attribute__((ms_abi)) void dsqueue_Close(IDStorageQueue *self)
{
    pthread_mutex_lock(&self->lock);
    self->request_count = 0;
    pthread_mutex_unlock(&self->lock);
}

static __attribute__((ms_abi)) HRESULT dsqueue_GetErrorEvent(IDStorageQueue *self, void **event)
{
    (void)self;
    if (event) *event = NULL;
    return S_OK;
}

static __attribute__((ms_abi)) void dsqueue_Query(IDStorageQueue *self, void *info)
{
    (void)self;
    /* DSTORAGE_QUEUE_INFO: zero it out — no pending requests */
    if (info) memset(info, 0, 32);
}

static IDStorageQueueVtbl *create_dsqueue_vtbl(void)
{
    IDStorageQueueVtbl *vtbl = calloc(1, sizeof(IDStorageQueueVtbl));
    if (!vtbl) return NULL;
    vtbl->QueryInterface = dsqueue_QueryInterface;
    vtbl->AddRef = dsqueue_AddRef;
    vtbl->Release = dsqueue_Release;
    vtbl->EnqueueRequest = dsqueue_EnqueueRequest;
    vtbl->EnqueueStatus = dsqueue_EnqueueStatus;
    vtbl->EnqueueSignal = dsqueue_EnqueueSignal;
    vtbl->Submit = dsqueue_Submit;
    vtbl->CancelRequestsWithTag = dsqueue_CancelRequestsWithTag;
    vtbl->Close = dsqueue_Close;
    vtbl->GetErrorEvent = dsqueue_GetErrorEvent;
    vtbl->Query = dsqueue_Query;
    return vtbl;
}

/* ========== IDStorageFactory ========== */

typedef struct {
    HRESULT (__attribute__((ms_abi)) *QueryInterface)(IDStorageFactory *self, const GUID *riid, void **ppv);
    ULONG   (__attribute__((ms_abi)) *AddRef)(IDStorageFactory *self);
    ULONG   (__attribute__((ms_abi)) *Release)(IDStorageFactory *self);
    HRESULT (__attribute__((ms_abi)) *CreateQueue)(IDStorageFactory *self, const void *desc, const GUID *riid, void **ppv);
    HRESULT (__attribute__((ms_abi)) *OpenFile)(IDStorageFactory *self, const uint16_t *path, const GUID *riid, void **ppv);
    HRESULT (__attribute__((ms_abi)) *CreateStatusArray)(IDStorageFactory *self, uint32_t capacity, const char *name, const GUID *riid, void **ppv);
    void    (__attribute__((ms_abi)) *SetDebugFlags)(IDStorageFactory *self, uint32_t flags);
    HRESULT (__attribute__((ms_abi)) *SetStagingBufferSize)(IDStorageFactory *self, uint32_t size);
} IDStorageFactoryVtbl;

struct IDStorageFactory {
    IDStorageFactoryVtbl *lpVtbl;
    uint32_t ref_count;
};

/* Forward decl — g_factory singleton lock is defined below; Release() needs it
 * to atomically clear g_factory when the last reference goes away, preventing
 * a Release-after-free race (Session 25 Agent 12 flagged). */
static pthread_mutex_t g_factory_lock;

static __attribute__((ms_abi)) HRESULT dsfactory_QueryInterface(IDStorageFactory *self, const GUID *riid, void **ppv)
{
    if (!ppv) return (HRESULT)0x80004003; /* E_POINTER */
    *ppv = NULL;
    if (!riid || memcmp(riid, IID_IUnknown_bytes, 16) == 0) {
        *ppv = self;
        __sync_add_and_fetch(&self->ref_count, 1);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static __attribute__((ms_abi)) ULONG dsfactory_AddRef(IDStorageFactory *self)
{
    return __sync_add_and_fetch(&self->ref_count, 1);
}

/* Forward decl of the singleton so Release can NULL it */
static IDStorageFactory *g_factory;

static __attribute__((ms_abi)) ULONG dsfactory_Release(IDStorageFactory *self)
{
    uint32_t ref = __sync_sub_and_fetch(&self->ref_count, 1);
    if (ref == 0) {
        /* Guard the singleton-NULL + free so that a concurrent
         * get_or_create_factory() cannot observe a dangling g_factory. */
        pthread_mutex_lock(&g_factory_lock);
        if (g_factory == self)
            g_factory = NULL;
        pthread_mutex_unlock(&g_factory_lock);

        free(self->lpVtbl);
        free(self);
    }
    return ref;
}

static __attribute__((ms_abi)) HRESULT dsfactory_CreateQueue(IDStorageFactory *self, const void *desc, const GUID *riid, void **ppv)
{
    (void)self; (void)desc; (void)riid;
    if (!ppv) return E_INVALIDARG;

    IDStorageQueue *queue = calloc(1, sizeof(IDStorageQueue));
    if (!queue) return E_OUTOFMEMORY;

    queue->lpVtbl = create_dsqueue_vtbl();
    if (!queue->lpVtbl) { free(queue); return E_OUTOFMEMORY; }

    queue->ref_count = 1;
    queue->requests = calloc(256, sizeof(ds_request_t));
    if (!queue->requests) {
        free(queue->lpVtbl);
        free(queue);
        return E_OUTOFMEMORY;
    }
    queue->request_capacity = 256;
    queue->request_count = 0;
    pthread_mutex_init(&queue->lock, NULL);

    fprintf(stderr, DS_LOG "CreateQueue: created synchronous queue\n");
    *ppv = queue;
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT dsfactory_OpenFile(IDStorageFactory *self, const uint16_t *path, const GUID *riid, void **ppv)
{
    (void)self; (void)riid;
    if (!ppv) return E_INVALIDARG;

    /* Convert UTF-16LE path to UTF-8 via the canonical helper so paths with
     * non-ASCII characters (user names, localized drives, etc.) resolve
     * correctly instead of being replaced by '_'. Session 30 fix. */
    char narrow_path[sizeof(((IDStorageFile*)0)->path)];
    if (path) {
        int r = utf16_to_utf8((const WCHAR *)path, -1, narrow_path, (int)sizeof(narrow_path));
        if (r <= 0) {
            /* Fall back to ASCII low-byte copy for badly encoded paths. */
            int i = 0;
            for (i = 0; i < (int)sizeof(narrow_path) - 1 && path[i]; i++)
                narrow_path[i] = (path[i] < 128) ? (char)path[i] : '_';
            narrow_path[i] = '\0';
        }
    } else {
        narrow_path[0] = '\0';
    }
    /* Guarantee NUL-termination regardless of helper behaviour. */
    narrow_path[sizeof(narrow_path) - 1] = '\0';

    /* Translate Windows path separators */
    for (int j = 0; narrow_path[j]; j++) {
        if (narrow_path[j] == '\\') narrow_path[j] = '/';
    }

    /* Use win_path_to_linux for proper path resolution */
    char linux_path[sizeof(narrow_path)];
    if (win_path_to_linux(narrow_path, linux_path, sizeof(linux_path)) != 0) {
        strncpy(linux_path, narrow_path, sizeof(linux_path) - 1);
        linux_path[sizeof(linux_path) - 1] = '\0';
    }

    /* O_CLOEXEC: don't leak the fd into child processes. DirectStorage
     * files are streaming data, we never want sub-processes to inherit. */
    int fd = open(linux_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        /* Try the original narrow path as fallback */
        fd = open(narrow_path, O_RDONLY | O_CLOEXEC);
    }

    if (fd < 0) {
        fprintf(stderr, DS_LOG "OpenFile: failed to open '%s'\n", narrow_path);
        *ppv = NULL;
        return E_FAIL;
    }

    IDStorageFile *file = calloc(1, sizeof(IDStorageFile));
    if (!file) { close(fd); return E_OUTOFMEMORY; }

    file->lpVtbl = create_dsfile_vtbl();
    if (!file->lpVtbl) { close(fd); free(file); return E_OUTOFMEMORY; }

    file->ref_count = 1;
    file->fd = fd;
    /* sizeof(file->path) - 1 = 511; guaranteed-NUL. */
    strncpy(file->path, narrow_path, sizeof(file->path) - 1);
    file->path[sizeof(file->path) - 1] = '\0';

    fprintf(stderr, DS_LOG "OpenFile: opened '%s' (fd=%d)\n", narrow_path, fd);
    *ppv = file;
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT dsfactory_CreateStatusArray(IDStorageFactory *self, uint32_t capacity, const char *name, const GUID *riid, void **ppv)
{
    (void)self; (void)name; (void)riid;
    if (!ppv) return E_INVALIDARG;

    IDStorageStatusArray *arr = calloc(1, sizeof(IDStorageStatusArray));
    if (!arr) return E_OUTOFMEMORY;

    arr->lpVtbl = create_dsstat_vtbl();
    if (!arr->lpVtbl) { free(arr); return E_OUTOFMEMORY; }

    arr->ref_count = 1;
    arr->capacity = capacity;

    *ppv = arr;
    return S_OK;
}

static __attribute__((ms_abi)) void dsfactory_SetDebugFlags(IDStorageFactory *self, uint32_t flags)
{
    (void)self; (void)flags;
}

static __attribute__((ms_abi)) HRESULT dsfactory_SetStagingBufferSize(IDStorageFactory *self, uint32_t size)
{
    (void)self; (void)size;
    return S_OK;
}

static IDStorageFactoryVtbl *create_dsfactory_vtbl(void)
{
    IDStorageFactoryVtbl *vtbl = calloc(1, sizeof(IDStorageFactoryVtbl));
    if (!vtbl) return NULL;
    vtbl->QueryInterface = dsfactory_QueryInterface;
    vtbl->AddRef = dsfactory_AddRef;
    vtbl->Release = dsfactory_Release;
    vtbl->CreateQueue = dsfactory_CreateQueue;
    vtbl->OpenFile = dsfactory_OpenFile;
    vtbl->CreateStatusArray = dsfactory_CreateStatusArray;
    vtbl->SetDebugFlags = dsfactory_SetDebugFlags;
    vtbl->SetStagingBufferSize = dsfactory_SetStagingBufferSize;
    return vtbl;
}

/* ========== Singleton factory ========== */

static IDStorageFactory *g_factory = NULL;
static pthread_mutex_t g_factory_lock = PTHREAD_MUTEX_INITIALIZER;

/* Returns the singleton with an extra reference already added (caller owns).
 * The lock/bump happens atomically so an over-releasing caller can't free
 * the factory between us handing it back and the caller's own AddRef. */
static IDStorageFactory *get_or_create_factory(void)
{
    pthread_mutex_lock(&g_factory_lock);
    if (!g_factory) {
        IDStorageFactory *f = calloc(1, sizeof(IDStorageFactory));
        if (f) {
            f->lpVtbl = create_dsfactory_vtbl();
            if (!f->lpVtbl) {
                free(f);
            } else {
                f->ref_count = 1;   /* initial reference returned to caller */
                g_factory = f;
                fprintf(stderr, DS_LOG "Factory created (synchronous pread backend)\n");
                pthread_mutex_unlock(&g_factory_lock);
                return f;
            }
        }
        pthread_mutex_unlock(&g_factory_lock);
        return NULL;
    }
    /* Reuse existing singleton. Bump under the lock so a racing Release
     * that would otherwise drop ref_count to 0 and NULL out g_factory
     * cannot observe us mid-handoff. */
    __sync_add_and_fetch(&g_factory->ref_count, 1);
    IDStorageFactory *result = g_factory;
    pthread_mutex_unlock(&g_factory_lock);
    return result;
}

/* ========== DLL Entry Points ========== */

WINAPI_EXPORT HRESULT DStorageCreateFactory(const GUID *riid, void **ppv)
{
    (void)riid;
    if (!ppv) return E_INVALIDARG;

    /* get_or_create_factory hands back the singleton with an extra reference
     * already applied atomically under g_factory_lock. */
    IDStorageFactory *factory = get_or_create_factory();
    if (!factory) return E_OUTOFMEMORY;

    *ppv = factory;
    return S_OK;
}

WINAPI_EXPORT HRESULT DStorageGetFactory(const GUID *riid, void **ppv)
{
    return DStorageCreateFactory(riid, ppv);
}

WINAPI_EXPORT HRESULT DStorageSetConfiguration(const void *config)
{
    (void)config;
    fprintf(stderr, DS_LOG "DStorageSetConfiguration: stub\n");
    return S_OK;
}

WINAPI_EXPORT HRESULT DStorageSetConfiguration1(const void *config)
{
    (void)config;
    return S_OK;
}

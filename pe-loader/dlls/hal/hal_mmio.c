/*
 * hal_mmio.c - HAL memory-mapped I/O.
 *
 * Implements MmMapIoSpace / MmMapIoSpaceEx / MmUnmapIoSpace by mapping
 * physical memory through /dev/mem.  Every call is gated through the
 * trust kernel at HAL_TRUST_MMIO band (TRUST_GATE_DRIVER_LOAD); when
 * the kernel module is unavailable we degrade to "deny" instead of
 * "permit" because /dev/mem is unconditional hardware access.
 *
 * Two backends:
 *   A) /dev/mem  (default).  Requires:
 *        - root (or CAP_SYS_RAWIO),
 *        - kernel cmdline `iomem=relaxed` for accesses outside the
 *          conventional RAM region (otherwise CONFIG_STRICT_DEVMEM
 *          rejects with -EPERM),
 *        - kernel cmdline `nokaslr` is NOT required.
 *   B) /dev/uioN MMIO map (future work).  Better isolation; the
 *        device must first be bound to vfio-pci / uio_pci_generic.
 *        The IRQ side already uses uio (hal_irq.c); a future iteration
 *        will plumb the BAR mapping through the same fd via mmap with
 *        the per-BAR offset documented in
 *        /sys/class/uio/uioN/maps/mapM/offset.
 *
 * Active mappings are tracked in a small table so MmUnmapIoSpace can
 * find the original size.  The table is bounded (256 mappings) -- if
 * a driver exceeds this we still munmap correctly via the size argument
 * the caller supplies, but we lose the audit/leak-tracking entry.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "hal_internal.h"

#define LOG_PREFIX "[hal/mmio] "
#define MAX_TRACKED_MAPPINGS 256

/* ===== Mapping table (best-effort leak audit) ======================= */

typedef struct {
    void   *base;
    size_t  size;
    uint64_t phys;
    int     in_use;
} hal_mmio_entry_t;

static hal_mmio_entry_t g_mappings[MAX_TRACKED_MAPPINGS];
static pthread_mutex_t  g_mappings_lock = PTHREAD_MUTEX_INITIALIZER;

static void hal_mmio_track(void *base, size_t size, uint64_t phys)
{
    pthread_mutex_lock(&g_mappings_lock);
    for (int i = 0; i < MAX_TRACKED_MAPPINGS; i++) {
        if (!g_mappings[i].in_use) {
            g_mappings[i].base   = base;
            g_mappings[i].size   = size;
            g_mappings[i].phys   = phys;
            g_mappings[i].in_use = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_mappings_lock);
}

static size_t hal_mmio_untrack(void *base)
{
    size_t size = 0;
    pthread_mutex_lock(&g_mappings_lock);
    for (int i = 0; i < MAX_TRACKED_MAPPINGS; i++) {
        if (g_mappings[i].in_use && g_mappings[i].base == base) {
            size = g_mappings[i].size;
            g_mappings[i].in_use = 0;
            g_mappings[i].base   = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&g_mappings_lock);
    return size;
}

/* ===== /dev/mem mapping core ======================================== */

static void *mmio_map_devmem(uint64_t phys, size_t size, int writable)
{
    int fd = open("/dev/mem", (writable ? O_RDWR : O_RDONLY) | O_SYNC);
    if (fd < 0) {
        if (getenv("HAL_DEBUG"))
            fprintf(stderr, LOG_PREFIX "open(/dev/mem): %s\n",
                    strerror(errno));
        return NULL;
    }

    /* Page-align the offset and round size up to the next page. */
    long pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize <= 0)
        pagesize = 4096;
    uint64_t page_mask = (uint64_t)(pagesize - 1);
    uint64_t aligned_phys = phys & ~page_mask;
    size_t   prefix       = (size_t)(phys - aligned_phys);
    size_t   aligned_size = ((size + prefix + pagesize - 1) / pagesize) * pagesize;

    int prot = PROT_READ | (writable ? PROT_WRITE : 0);
    void *base = mmap(NULL, aligned_size, prot, MAP_SHARED, fd,
                      (off_t)aligned_phys);
    close(fd);
    if (base == MAP_FAILED) {
        if (getenv("HAL_DEBUG"))
            fprintf(stderr, LOG_PREFIX "mmap(phys=0x%lx, sz=%zu): %s\n",
                    (unsigned long)aligned_phys, aligned_size,
                    strerror(errno));
        return NULL;
    }

    void *user = (char *)base + prefix;
    hal_mmio_track(base, aligned_size, aligned_phys);
    return user;
}

/* ===== MmMapIoSpace ================================================= */

WINAPI_EXPORT PVOID MmMapIoSpace(PHYSICAL_ADDRESS PhysicalAddress,
                                  SIZE_T NumberOfBytes,
                                  MEMORY_CACHING_TYPE CacheType)
{
    /* CacheType is advisory on Linux mmap; we honour MmNonCached by
     * adding O_SYNC (already done) and ignore the rest. */
    (void)CacheType;

    if (NumberOfBytes == 0)
        return NULL;

    char arg[64];
    snprintf(arg, sizeof(arg), "phys=0x%llx sz=%zu",
             (unsigned long long)PhysicalAddress.QuadPart,
             (size_t)NumberOfBytes);

    if (!hal_trust_check(HAL_TRUST_MMIO, "MmMapIoSpace", arg))
        return NULL;

    return mmio_map_devmem((uint64_t)PhysicalAddress.QuadPart,
                            (size_t)NumberOfBytes, /*writable=*/1);
}

/* MmMapIoSpaceEx: identical to MmMapIoSpace but takes a Protect bitmask
 * (PAGE_READWRITE etc).  We honour the read-only case to avoid
 * accidental writes to BARs the driver only wants to inspect. */
#ifndef PAGE_READONLY
#define PAGE_READONLY   0x02
#define PAGE_READWRITE  0x04
#define PAGE_NOCACHE    0x200
#endif

WINAPI_EXPORT PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS PhysicalAddress,
                                    SIZE_T NumberOfBytes,
                                    ULONG Protect)
{
    if (NumberOfBytes == 0)
        return NULL;

    int writable = (Protect & PAGE_READWRITE) ? 1 : 0;

    char arg[80];
    snprintf(arg, sizeof(arg), "phys=0x%llx sz=%zu prot=0x%x",
             (unsigned long long)PhysicalAddress.QuadPart,
             (size_t)NumberOfBytes, (unsigned)Protect);

    if (!hal_trust_check(HAL_TRUST_MMIO, "MmMapIoSpaceEx", arg))
        return NULL;

    return mmio_map_devmem((uint64_t)PhysicalAddress.QuadPart,
                            (size_t)NumberOfBytes, writable);
}

/* ===== MmUnmapIoSpace =============================================== */

WINAPI_EXPORT void MmUnmapIoSpace(PVOID BaseAddress, SIZE_T NumberOfBytes)
{
    if (BaseAddress == NULL)
        return;

    /* Compute the actual mmap base (re-align, since MmMapIoSpace returned
     * an offset within a page-aligned mapping).  Prefer the tracked
     * size; fall back to the caller's NumberOfBytes if we lost track. */
    long pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize <= 0)
        pagesize = 4096;
    uint64_t page_mask = (uint64_t)(pagesize - 1);
    void *aligned_base = (void *)((uintptr_t)BaseAddress & ~(uintptr_t)page_mask);

    size_t tracked = hal_mmio_untrack(aligned_base);
    size_t unmap_size = tracked ? tracked
                                : ((NumberOfBytes + pagesize - 1) / pagesize)
                                  * pagesize;
    if (unmap_size == 0)
        unmap_size = (size_t)pagesize;

    if (munmap(aligned_base, unmap_size) != 0) {
        if (getenv("HAL_DEBUG"))
            fprintf(stderr, LOG_PREFIX "munmap(%p, %zu): %s\n",
                    aligned_base, unmap_size, strerror(errno));
    }
}

/* ===== Diagnostic dump ============================================== */
/* Not in real Windows HAL; present so coherenced/observers can audit
 * leaked mappings.  Walks the table and prints each live entry. */

WINAPI_EXPORT ULONG HalDumpActiveMappings(void)
{
    ULONG live = 0;
    pthread_mutex_lock(&g_mappings_lock);
    for (int i = 0; i < MAX_TRACKED_MAPPINGS; i++) {
        if (g_mappings[i].in_use) {
            live++;
            if (getenv("HAL_DEBUG"))
                fprintf(stderr, LOG_PREFIX
                        "live mapping #%d: base=%p size=%zu phys=0x%lx\n",
                        i, g_mappings[i].base, g_mappings[i].size,
                        (unsigned long)g_mappings[i].phys);
        }
    }
    pthread_mutex_unlock(&g_mappings_lock);
    return live;
}

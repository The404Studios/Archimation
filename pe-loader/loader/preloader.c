/*
 * preloader.c - Reserve address space for PE image loading
 *
 * Before the dynamic linker maps our stub libraries, we need to
 * reserve the address range that the PE image wants to use
 * (typically starting at 0x00400000 for executables).
 *
 * This prevents the Linux dynamic linker from placing shared
 * libraries in the PE image's preferred address range.
 */

#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>

#define LOG_PREFIX "[preloader] "

/* Common PE image bases */
#define PE_DEFAULT_EXE_BASE     0x00400000
#define PE_DEFAULT_EXE_SIZE     0x10000000  /* 256MB reservation */
#define PE_DEFAULT_DLL_BASE     0x10000000
#define PE_DOS_AREA_START       0x00010000
#define PE_DOS_AREA_SIZE        0x00100000  /* 1MB DOS area */

/* Reserved region tracking (8 slots to handle split regions) */
static void *g_reserved_regions[8] = { NULL };
static size_t g_reserved_sizes[8] = { 0 };
static int g_num_reserved = 0;

static int reserve_region(uint64_t addr, size_t size, const char *label)
{
    void *mapped = mmap((void *)addr, size, PROT_NONE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                        -1, 0);

    if (mapped == MAP_FAILED) {
        printf(LOG_PREFIX "Could not reserve %s at 0x%lX (size 0x%lX) - already in use\n",
               label, (unsigned long)addr, (unsigned long)size);
        return -1;
    }

    printf(LOG_PREFIX "Reserved %s: 0x%lX - 0x%lX (0x%lX bytes)\n",
           label, (unsigned long)addr, (unsigned long)(addr + size),
           (unsigned long)size);

    if (g_num_reserved < 8) {
        g_reserved_regions[g_num_reserved] = mapped;
        g_reserved_sizes[g_num_reserved] = size;
        g_num_reserved++;
    } else {
        /* No tracking slots left — unmap immediately to avoid a leak */
        printf(LOG_PREFIX "No tracking slots for %s, releasing immediately\n", label);
        munmap(mapped, size);
        return -1;
    }

    return 0;
}

int preloader_reserve(void)
{
    /* Reserve the default PE exe load area (0x400000 - 0x10400000) */
    int primary_ok = (reserve_region(PE_DEFAULT_EXE_BASE, PE_DEFAULT_EXE_SIZE,
                                     "PE exe area") == 0);

    /* Optionally reserve the DOS area to catch null-page accesses */
    reserve_region(PE_DOS_AREA_START, PE_DOS_AREA_SIZE,
                   "DOS compatibility area");

    return primary_ok ? 0 : -1;
}

void preloader_release(void)
{
    for (int i = 0; i < g_num_reserved; i++) {
        if (g_reserved_regions[i]) {
            munmap(g_reserved_regions[i], g_reserved_sizes[i]);
            g_reserved_regions[i] = NULL;
        }
    }
    g_num_reserved = 0;
}

void preloader_release_range(uint64_t addr, size_t size)
{
    /*
     * Release a specific sub-range of our reservation so the PE mapper
     * can use it. We must also update our tracking so that
     * preloader_release() won't later munmap this range (which would
     * destroy the PE image mapped on top of it).
     *
     * Strategy: find the reservation containing [addr, addr+size),
     * split it into up to two remaining pieces (before and after).
     */
    for (int i = 0; i < g_num_reserved; i++) {
        if (!g_reserved_regions[i])
            continue;

        uint64_t reg_start = (uint64_t)(uintptr_t)g_reserved_regions[i];
        uint64_t reg_end = reg_start + g_reserved_sizes[i];

        if (addr >= reg_start && addr + size <= reg_end) {
            /* This reservation contains the range to release */
            munmap((void *)addr, size);

            /* Calculate the "before" piece: [reg_start, addr) */
            uint64_t before_start = reg_start;
            size_t before_size = (size_t)(addr - reg_start);

            /* Calculate the "after" piece: [addr+size, reg_end) */
            uint64_t after_start = addr + size;
            size_t after_size = (size_t)(reg_end - after_start);

            /* Replace this entry with the "before" piece (may be empty) */
            if (before_size > 0) {
                g_reserved_regions[i] = (void *)(uintptr_t)before_start;
                g_reserved_sizes[i] = before_size;
            } else {
                g_reserved_regions[i] = NULL;
                g_reserved_sizes[i] = 0;
            }

            /* Add the "after" piece if non-empty and we have space */
            if (after_size > 0 && g_num_reserved < 8) {
                g_reserved_regions[g_num_reserved] = (void *)(uintptr_t)after_start;
                g_reserved_sizes[g_num_reserved] = after_size;
                g_num_reserved++;
            } else if (after_size > 0) {
                /* No tracking space left; just unmap it now */
                munmap((void *)(uintptr_t)after_start, after_size);
            }

            return;
        }
    }

    /* Not tracked - just unmap directly */
    munmap((void *)addr, size);
}

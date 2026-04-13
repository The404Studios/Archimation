/*
 * pe_mapper.c - Map PE sections into virtual memory
 *
 * Maps each PE section at the correct virtual address using mmap,
 * applying appropriate memory protections.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

#include "pe/pe_header.h"
#include "pe/pe_types.h"

#define LOG_PREFIX "[pe_mapper] "

/* Convert PE section characteristics to mmap protection flags */
static int section_prot(uint32_t characteristics)
{
    int prot = 0;
    if (characteristics & PE_SCN_MEM_READ)
        prot |= PROT_READ;
    if (characteristics & PE_SCN_MEM_WRITE)
        prot |= PROT_WRITE;
    if (characteristics & PE_SCN_MEM_EXECUTE)
        prot |= PROT_EXEC;
    /* If no protection bits set, default to read */
    if (prot == 0)
        prot = PROT_READ;
    return prot;
}

/* Align a value up to the given alignment */
static uint64_t align_up(uint64_t value, uint64_t alignment)
{
    if (alignment == 0)
        return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

int pe_map_sections(pe_image_t *image)
{
    uint64_t base_addr = image->image_base;
    size_t total_size = align_up(image->size_of_image, 4096);

    if (total_size == 0) {
        fprintf(stderr, LOG_PREFIX "Invalid size_of_image: 0\n");
        return -1;
    }

    /*
     * Try to map at the preferred image base.
     * MAP_FIXED_NOREPLACE prevents silently clobbering existing mappings.
     * If the preferred address is taken, we fall back to any address
     * and apply base relocations later.
     */
    void *mapped = mmap((void *)base_addr, total_size,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                        -1, 0);

    if (mapped == MAP_FAILED) {
        /* Preferred base unavailable - map anywhere */
        printf(LOG_PREFIX "Preferred base 0x%lX unavailable, mapping at any address\n",
               (unsigned long)base_addr);
        mapped = mmap(NULL, total_size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS,
                      -1, 0);
        if (mapped == MAP_FAILED) {
            fprintf(stderr, LOG_PREFIX "Failed to map image: %s\n", strerror(errno));
            return -1;
        }
    }

    image->mapped_base = (uint8_t *)mapped;
    image->actual_base = (uint64_t)(uintptr_t)mapped;
    image->mapped_size = total_size;

    printf(LOG_PREFIX "Image mapped at 0x%lX (size=0x%lX, preferred=0x%lX)\n",
           (unsigned long)image->actual_base,
           (unsigned long)total_size,
           (unsigned long)image->image_base);

    /* Copy PE headers to the mapped region */
    if (lseek(image->fd, 0, SEEK_SET) < 0) {
        fprintf(stderr, LOG_PREFIX "Failed to seek to file start\n");
        return -1;
    }

    size_t headers_size = image->size_of_headers;
    if (headers_size > total_size)
        headers_size = total_size;
    if (headers_size > image->file_size)
        headers_size = image->file_size;

    ssize_t n = read(image->fd, image->mapped_base, headers_size);
    if (n < 0 || (size_t)n != headers_size) {
        fprintf(stderr, LOG_PREFIX "Failed to read PE headers into mapped region\n");
        return -1;
    }

    /* Map each section */
    for (uint16_t i = 0; i < image->num_sections; i++) {
        pe_section_header_t *sec = &image->sections[i];
        char name[9] = {0};
        memcpy(name, sec->name, 8);

        uint32_t va = sec->virtual_address;
        uint32_t vs = sec->virtual_size;
        uint32_t raw_size = sec->size_of_raw_data;
        uint32_t raw_offset = sec->pointer_to_raw_data;

        if (vs == 0 && raw_size == 0) {
            printf(LOG_PREFIX "  Section '%s': empty, skipping\n", name);
            continue;
        }

        /* The actual size to consider is the larger of virtual_size and raw_size */
        uint32_t section_size = vs > raw_size ? vs : raw_size;
        (void)section_size; /* Used for logging */

        /* Copy raw data from file into the mapped region */
        if (raw_size > 0 && raw_offset > 0) {
            if (lseek(image->fd, raw_offset, SEEK_SET) < 0) {
                fprintf(stderr, LOG_PREFIX "  Section '%s': failed to seek to raw data\n", name);
                return -1;
            }

            size_t copy_size = raw_size;
            if (va >= total_size)
                continue;  /* Malformed PE: section VA beyond image */
            if (copy_size > total_size - va)  /* Overflow-safe: total_size > va guaranteed */
                copy_size = total_size - va;

            n = read(image->fd, image->mapped_base + va, copy_size);
            if (n < 0 || (size_t)n != copy_size) {
                fprintf(stderr, LOG_PREFIX "  Section '%s': failed to read raw data\n", name);
                return -1;
            }
        }

        /* Zero-fill the remainder (BSS-like portion) */
        if (vs > raw_size) {
            uint64_t zero_start = (uint64_t)va + (uint64_t)raw_size;
            uint64_t zero_size = (uint64_t)vs - (uint64_t)raw_size;
            if (zero_start < total_size && zero_size <= total_size - zero_start)
                memset(image->mapped_base + zero_start, 0, (size_t)zero_size);
        }

        printf(LOG_PREFIX "  Section '%s': VA=0x%08X Size=0x%08X Raw=0x%08X Flags=0x%08X\n",
               name, va, vs, raw_size, sec->characteristics);
    }

    /*
     * NOTE: Do NOT apply section protections here. The image needs to remain
     * writable for relocation patching and import resolution (IAT writes).
     * pe_restore_section_protections() is called after those steps to set
     * the final per-section protections (e.g., .text=RX, .rdata=R, .data=RW).
     */

    return 0;
}

/*
 * pe_restore_section_protections - Re-apply per-section memory protections
 *
 * Called after relocation and import resolution, which temporarily set the
 * entire image to PROT_READ|PROT_WRITE|PROT_EXEC for patching. This restores
 * each section to its correct protection (e.g., .text = R-X, .rdata = R--).
 */
int pe_restore_section_protections(pe_image_t *image)
{
    if (!image || !image->mapped_base || !image->sections)
        return -1;

    for (uint16_t i = 0; i < image->num_sections; i++) {
        pe_section_header_t *sec = &image->sections[i];
        uint32_t va = sec->virtual_address;
        uint32_t vs = sec->virtual_size;

        if (vs == 0)
            continue;

        /* Bounds check: ensure section falls within mapped region */
        if ((uint64_t)va + (uint64_t)vs > image->mapped_size)
            continue;

        uint64_t page_start = (uint64_t)(uintptr_t)(image->mapped_base + va) & ~(uint64_t)0xFFF;
        uint64_t page_end = align_up((uint64_t)(uintptr_t)(image->mapped_base + va) + (uint64_t)vs, 4096);
        size_t page_size = page_end - page_start;

        int prot = section_prot(sec->characteristics);
        if (mprotect((void *)page_start, page_size, prot) < 0) {
            char name[9] = {0};
            memcpy(name, sec->name, 8);
            fprintf(stderr, LOG_PREFIX "  Restore '%s' protection failed: %s\n",
                    name, strerror(errno));
        }
    }

    return 0;
}

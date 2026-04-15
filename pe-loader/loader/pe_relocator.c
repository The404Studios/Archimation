/*
 * pe_relocator.c - Process PE base relocations
 *
 * When a PE image is loaded at a different address than its preferred
 * ImageBase, all absolute addresses in the code/data must be adjusted.
 * The relocation table tells us where these addresses are.
 */

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "pe/pe_header.h"
#include "pe/pe_reloc.h"
#include "pe/pe_types.h"

#define LOG_PREFIX "[pe_reloc] "

int pe_apply_relocations(pe_image_t *image)
{
    int64_t delta = (int64_t)(image->actual_base - image->image_base);

    /* No relocation needed if loaded at preferred base */
    if (delta == 0) {
        printf(LOG_PREFIX "Image loaded at preferred base, no relocations needed\n");
        return 0;
    }

    /* Check if relocation data exists */
    if (image->number_of_rva_and_sizes <= PE_DIR_BASERELOC) {
        fprintf(stderr, LOG_PREFIX "No relocation directory\n");
        return -1;
    }

    pe_data_directory_t *reloc_dir = &image->data_directory[PE_DIR_BASERELOC];
    if (reloc_dir->virtual_address == 0 || reloc_dir->size == 0) {
        /* Check if relocations were stripped */
        if (image->file_header.characteristics & PE_FILE_RELOCS_STRIPPED) {
            fprintf(stderr, LOG_PREFIX "Relocations stripped and base mismatch!\n");
            return -1;
        }
        printf(LOG_PREFIX "No relocation entries\n");
        return 0;
    }

    printf(LOG_PREFIX "Applying relocations (delta=0x%lX)\n", (unsigned long)delta);

    /* Temporarily make all sections writable for relocation patching */
    if (mprotect(image->mapped_base, image->mapped_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
        fprintf(stderr, LOG_PREFIX "Failed to make image writable for relocations\n");
        return -1;
    }

    uint8_t *reloc_base = (uint8_t *)pe_rva_to_ptr(image, reloc_dir->virtual_address);
    if (!reloc_base) {
        fprintf(stderr, LOG_PREFIX "Invalid relocation directory RVA\n");
        return -1;
    }
    if ((uint64_t)reloc_dir->virtual_address + (uint64_t)reloc_dir->size > (uint64_t)image->mapped_size) {
        fprintf(stderr, LOG_PREFIX "Relocation directory extends past mapped image\n");
        return -1;
    }

    uint32_t processed = 0;
    uint32_t total_entries = 0;
    uint32_t skipped = 0;
    uint8_t *ptr = reloc_base;

    while (processed < reloc_dir->size) {
        if (reloc_dir->size - processed < sizeof(pe_base_reloc_block_t))
            break;

        pe_base_reloc_block_t *block = (pe_base_reloc_block_t *)ptr;

        if (block->block_size == 0)
            break;

        if (block->block_size < sizeof(pe_base_reloc_block_t))
            break;

        if (block->block_size > reloc_dir->size - processed)
            break;

        uint32_t num_entries = (block->block_size - sizeof(pe_base_reloc_block_t)) / sizeof(uint16_t);
        uint16_t *entries = (uint16_t *)(ptr + sizeof(pe_base_reloc_block_t));

        /*
         * Hot-path fast case: block is PURELY PE_REL_BASED_DIR64 entries.
         *
         * Modern x64 PEs use DIR64 exclusively, with zero-padding ABSOLUTE
         * entries at block tails to reach 4-byte alignment.  We scan the
         * block once to verify it is a pure DIR64|ABSOLUTE block, then use
         * a tight unrolled loop that skips per-entry bounds-check overhead.
         *
         * Preserves the exact semantics of the general loop when it fires:
         *   - ABSOLUTE entries are no-ops (just padding)
         *   - DIR64 patches full 64-bit int at (block_base + offset)
         *
         * This is the dominant branch for Windows 10+ 64-bit binaries.
         */
        int pure_dir64 = 1;
        for (uint32_t i = 0; i < num_entries; i++) {
            uint8_t t = PE_RELOC_TYPE(entries[i]);
            if (t != PE_REL_BASED_DIR64 && t != PE_REL_BASED_ABSOLUTE) {
                pure_dir64 = 0;
                break;
            }
        }

        if (__builtin_expect(pure_dir64, 1)) {
            /* Pre-compute block base pointer once -- valid iff page_rva in-range. */
            if (block->page_rva >= image->mapped_size) {
                processed += block->block_size;
                ptr += block->block_size;
                continue;
            }
            uint8_t *block_base = image->mapped_base + block->page_rva;
            uint64_t block_page_limit = (uint64_t)image->mapped_size - block->page_rva;
            for (uint32_t i = 0; i < num_entries; i++) {
                uint16_t entry = entries[i];
                uint8_t type = PE_RELOC_TYPE(entry);
                if (type == PE_REL_BASED_ABSOLUTE) continue;
                /* DIR64: must have 8 bytes in-bounds at block_base+offset */
                uint16_t offset = PE_RELOC_OFFSET(entry);
                if (__builtin_expect((uint64_t)offset + 8u > block_page_limit, 0)) {
                    skipped++;
                    continue;
                }
                uint64_t *patch = (uint64_t *)(block_base + offset);
                *patch = (uint64_t)((int64_t)*patch + delta);
                total_entries++;
            }
            processed += block->block_size;
            ptr += block->block_size;
            continue;
        }

        for (uint32_t i = 0; i < num_entries; i++) {
            uint16_t entry = entries[i];
            uint8_t type = PE_RELOC_TYPE(entry);
            uint16_t offset = PE_RELOC_OFFSET(entry);
            if (offset > UINT32_MAX - block->page_rva) {
                /* Integer overflow in RVA calculation */
                skipped++;
                continue;
            }
            uint32_t target_rva = block->page_rva + offset;
            void *target = pe_rva_to_ptr(image, target_rva);

            if (!target) {
                fprintf(stderr, LOG_PREFIX "Relocation target out of bounds: RVA 0x%08X\n",
                        target_rva);
                continue;
            }

            switch (type) {
            case PE_REL_BASED_ABSOLUTE:
                /* Padding, skip */
                break;

            case PE_REL_BASED_HIGHLOW: {
                /* 32-bit field - check that delta fits in int32_t range */
                if (delta < INT32_MIN || delta > INT32_MAX) {
                    fprintf(stderr, LOG_PREFIX "HIGHLOW relocation skipped at RVA 0x%08X: "
                            "delta 0x%lX exceeds 32-bit range\n",
                            target_rva, (unsigned long)delta);
                    break;
                }
                uint32_t *patch = (uint32_t *)target;
                *patch += (uint32_t)delta;
                total_entries++;
                break;
            }

            case PE_REL_BASED_HIGHADJ: {
                /* HIGHADJ: high 16 bits adjusted by low 16 bits from next entry */
                if (i + 1 < num_entries) {
                    uint16_t next_entry_val = entries[i + 1];
                    uint16_t *patch = (uint16_t *)target;
                    int32_t adj = (int32_t)((uint32_t)*patch << 16) + (int32_t)next_entry_val + (int32_t)delta;
                    *patch = (uint16_t)((adj + 0x8000) >> 16);
                    i++; /* consume next entry */
                    total_entries++;
                }
                break;
            }

            case PE_REL_BASED_DIR64: {
                /* 64-bit field */
                uint64_t *patch = (uint64_t *)target;
                *patch = (uint64_t)((int64_t)*patch + delta);
                total_entries++;
                break;
            }

            case PE_REL_BASED_HIGH: {
                uint16_t *patch = (uint16_t *)target;
                *patch += (uint16_t)((delta >> 16) & 0xFFFF);
                total_entries++;
                break;
            }

            case PE_REL_BASED_LOW: {
                uint16_t *patch = (uint16_t *)target;
                *patch += (uint16_t)(delta & 0xFFFF);
                total_entries++;
                break;
            }

            default:
                fprintf(stderr, LOG_PREFIX "Unknown relocation type %d at RVA 0x%08X\n",
                        type, target_rva);
                break;
            }
        }

        processed += block->block_size;
        ptr += block->block_size;
    }

    printf(LOG_PREFIX "Applied %u relocation entries\n", total_entries);
    return 0;
}

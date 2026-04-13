#ifndef PE_RELOC_H
#define PE_RELOC_H

#include "pe_header.h"

#pragma pack(push, 1)

/* Base Relocation Block header */
typedef struct {
    uint32_t page_rva;          /* RVA of the page this block covers */
    uint32_t block_size;        /* Total size of this block including header */
    /* Followed by (block_size - 8) / 2 type/offset entries */
} pe_base_reloc_block_t;

/*
 * Each relocation entry is a 16-bit value:
 *   bits 12-15: relocation type (PE_REL_BASED_*)
 *   bits 0-11:  offset within the page
 */
#define PE_RELOC_TYPE(entry)   ((entry) >> 12)
#define PE_RELOC_OFFSET(entry) ((entry) & 0x0FFF)

#pragma pack(pop)

/* Apply base relocations to a mapped PE image */
int pe_apply_relocations(pe_image_t *image);

#endif /* PE_RELOC_H */

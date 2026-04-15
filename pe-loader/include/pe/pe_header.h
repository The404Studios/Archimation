#ifndef PE_HEADER_H
#define PE_HEADER_H

#include "pe_types.h"

#pragma pack(push, 1)

/* DOS Header - 64 bytes, starts every PE file */
typedef struct {
    uint16_t e_magic;       /* 0x5A4D ("MZ") */
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;      /* Offset to PE signature */
} pe_dos_header_t;

/* COFF File Header - 20 bytes */
typedef struct {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
} pe_file_header_t;

/* Data Directory entry - 8 bytes */
typedef struct {
    uint32_t virtual_address;   /* RVA */
    uint32_t size;
} pe_data_directory_t;

/* PE32 Optional Header (32-bit) */
typedef struct {
    uint16_t magic;                     /* 0x010B */
    uint8_t  major_linker_version;
    uint8_t  minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint32_t base_of_data;
    uint32_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t size_of_stack_reserve;
    uint32_t size_of_stack_commit;
    uint32_t size_of_heap_reserve;
    uint32_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    pe_data_directory_t data_directory[PE_NUM_DATA_DIRECTORIES];
} pe_optional_header32_t;

/* PE32+ Optional Header (64-bit) */
typedef struct {
    uint16_t magic;                     /* 0x020B */
    uint8_t  major_linker_version;
    uint8_t  minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t size_of_stack_reserve;
    uint64_t size_of_stack_commit;
    uint64_t size_of_heap_reserve;
    uint64_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    pe_data_directory_t data_directory[PE_NUM_DATA_DIRECTORIES];
} pe_optional_header64_t;

/* Section Header - 40 bytes */
typedef struct {
    char     name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;       /* RVA */
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;   /* File offset */
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_linenumbers;
    uint16_t number_of_relocations;
    uint16_t number_of_linenumbers;
    uint32_t characteristics;
} pe_section_header_t;

#pragma pack(pop)

/* Internal image representation after parsing */
typedef struct {
    /* Raw headers */
    pe_dos_header_t     dos_header;
    pe_file_header_t    file_header;
    int                 is_pe32plus;        /* 1 = PE32+ (64-bit), 0 = PE32 */

    /* Normalized optional header fields (always stored as 64-bit) */
    uint64_t            image_base;
    uint32_t            section_alignment;
    uint32_t            file_alignment;
    uint32_t            address_of_entry_point;
    uint32_t            size_of_image;
    uint32_t            size_of_headers;
    uint16_t            subsystem;
    uint16_t            dll_characteristics;
    uint64_t            size_of_stack_reserve;
    uint64_t            size_of_stack_commit;
    uint32_t            number_of_rva_and_sizes;
    pe_data_directory_t data_directory[PE_NUM_DATA_DIRECTORIES];

    /* Section headers (dynamically allocated) */
    pe_section_header_t *sections;
    uint16_t            num_sections;

    /* Loaded image info */
    uint8_t             *mapped_base;       /* Actual base address after mapping */
    uint64_t            actual_base;        /* Actual base as uint64 */
    size_t              mapped_size;        /* Total mapped size */

    /* Source file */
    const char          *filename;
    int                 fd;                 /* File descriptor */
    size_t              file_size;
} pe_image_t;

/* Parse a PE file from disk into a pe_image_t */
int pe_parse_file(const char *filename, pe_image_t *image);

/* Free resources associated with a parsed PE image */
void pe_image_free(pe_image_t *image);

/* Get a pointer to data at an RVA within the mapped image.
 *
 * HOT: called in every import/ILT walk.  Marked pure + hot so the compiler
 * can CSE repeated calls with the same args; -O2 will typically inline it
 * across the TU boundary because it's small and the bounds check is
 * branch-predictable. */
void *pe_rva_to_ptr(const pe_image_t *image, uint32_t rva)
    __attribute__((pure));

/* Get the entry point address */
void *pe_get_entry_point(const pe_image_t *image);

#endif /* PE_HEADER_H */

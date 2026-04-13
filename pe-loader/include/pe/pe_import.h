#ifndef PE_IMPORT_H
#define PE_IMPORT_H

#include "pe_header.h"

#pragma pack(push, 1)

/* Import Directory Table entry */
typedef struct {
    uint32_t import_lookup_table_rva;   /* RVA to ILT (or characteristics) */
    uint32_t time_date_stamp;
    uint32_t forwarder_chain;
    uint32_t name_rva;                  /* RVA to DLL name string */
    uint32_t import_address_table_rva;  /* RVA to IAT */
} pe_import_descriptor_t;

/* Import Hint/Name entry */
typedef struct {
    uint16_t hint;          /* Index into export name pointer table */
    char     name[];        /* Null-terminated ASCII function name */
} pe_import_by_name_t;

/* Delay-load import descriptor */
typedef struct {
    uint32_t attributes;
    uint32_t name_rva;
    uint32_t module_handle_rva;
    uint32_t delay_iat_rva;
    uint32_t delay_int_rva;
    uint32_t bound_delay_iat_rva;
    uint32_t unload_delay_iat_rva;
    uint32_t time_date_stamp;
} pe_delay_import_descriptor_t;

#pragma pack(pop)

/* Resolve all imports for a PE image */
int pe_resolve_imports(pe_image_t *image);

#endif /* PE_IMPORT_H */

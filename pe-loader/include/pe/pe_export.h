#ifndef PE_EXPORT_H
#define PE_EXPORT_H

#include "pe_types.h"

#pragma pack(push, 1)

/* Export Directory Table */
typedef struct {
    uint32_t characteristics;
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t name_rva;                  /* RVA to DLL name */
    uint32_t ordinal_base;
    uint32_t number_of_functions;
    uint32_t number_of_names;
    uint32_t address_of_functions_rva;  /* RVA to Export Address Table */
    uint32_t address_of_names_rva;      /* RVA to Export Name Pointer Table */
    uint32_t address_of_name_ordinals_rva; /* RVA to Ordinal Table */
} pe_export_directory_t;

#pragma pack(pop)

#endif /* PE_EXPORT_H */

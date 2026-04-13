#ifndef PE_TLS_H
#define PE_TLS_H

#include <stdint.h>
#include "pe_header.h"

#pragma pack(push, 1)

/* TLS Directory (64-bit) */
typedef struct {
    uint64_t start_address_of_raw_data;
    uint64_t end_address_of_raw_data;
    uint64_t address_of_index;
    uint64_t address_of_callbacks;
    uint32_t size_of_zero_fill;
    uint32_t characteristics;
} pe_tls_directory64_t;

/* TLS Directory (32-bit) */
typedef struct {
    uint32_t start_address_of_raw_data;
    uint32_t end_address_of_raw_data;
    uint32_t address_of_index;
    uint32_t address_of_callbacks;
    uint32_t size_of_zero_fill;
    uint32_t characteristics;
} pe_tls_directory32_t;

#pragma pack(pop)

/* Initialize TLS for a PE image from its TLS directory */
int pe_tls_init(pe_image_t *image);

/* Allocate TLS data for the current thread */
void pe_tls_alloc_thread(void);

/* Free TLS data for the current thread */
void pe_tls_free_thread(void);

/* Call TLS callbacks for all PE images */
void pe_tls_call_callbacks(uint32_t reason);

/* Get TLS data for a specific index and the current thread */
void *pe_tls_get_value(uint32_t index);

/* Cleanup all TLS */
void pe_tls_cleanup(void);

#endif /* PE_TLS_H */

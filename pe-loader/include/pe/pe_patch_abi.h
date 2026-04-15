/*
 * pe_patch_abi.h - ms_abi entry-point declarations for patched CRT bodies
 *
 * The loader redirects PE IAT slots for a fixed set of CRT functions
 * (memcpy, memset, strlen, strcmp, memmove, memcmp, strncmp, strncpy,
 * strcpy, wcslen, wcscmp) to the addresses exposed here.  Every symbol is
 * ms_abi because the PE caller uses the Windows x64 register calling
 * convention (RCX/RDX/R8/R9); forwarding to sysv_abi libc would mis-pass
 * arguments and crash.
 *
 * Implementations live in pe_patch_crt.c.  The dispatch table in
 * pe_patch.c indexes into PE_PATCH_COUNT entries in the order defined by
 * the enum below -- do NOT reorder without bumping the patch cache version.
 */

#ifndef PE_PATCH_ABI_H
#define PE_PATCH_ABI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Index into the replacement table.  The on-disk cache stores this as
 * replacement_idx (u32); reordering breaks cached files.  Add new entries
 * at the tail and bump PE_PATCH_CACHE_VERSION in pe_patch.h. */
enum pe_patch_idx {
    PE_PATCH_IDX_MEMCPY   = 0,
    PE_PATCH_IDX_MEMSET   = 1,
    PE_PATCH_IDX_MEMMOVE  = 2,
    PE_PATCH_IDX_MEMCMP   = 3,
    PE_PATCH_IDX_STRLEN   = 4,
    PE_PATCH_IDX_STRCMP   = 5,
    PE_PATCH_IDX_STRNCMP  = 6,
    PE_PATCH_IDX_STRCPY   = 7,
    PE_PATCH_IDX_STRNCPY  = 8,
    PE_PATCH_IDX_WCSLEN   = 9,
    PE_PATCH_IDX_WCSCMP   = 10,
    PE_PATCH_COUNT        = 11
};

/* ms_abi function prototypes -- RCX/RDX/R8/R9 for the first 4 args. */
void   *__attribute__((ms_abi)) pe_patched_memcpy (void *dst, const void *src, size_t n);
void   *__attribute__((ms_abi)) pe_patched_memset (void *dst, int c, size_t n);
void   *__attribute__((ms_abi)) pe_patched_memmove(void *dst, const void *src, size_t n);
int     __attribute__((ms_abi)) pe_patched_memcmp (const void *a, const void *b, size_t n);
size_t  __attribute__((ms_abi)) pe_patched_strlen (const char *s);
int     __attribute__((ms_abi)) pe_patched_strcmp (const char *a, const char *b);
int     __attribute__((ms_abi)) pe_patched_strncmp(const char *a, const char *b, size_t n);
char   *__attribute__((ms_abi)) pe_patched_strcpy (char *d, const char *s);
char   *__attribute__((ms_abi)) pe_patched_strncpy(char *d, const char *s, size_t n);
size_t  __attribute__((ms_abi)) pe_patched_wcslen (const uint16_t *s);
int     __attribute__((ms_abi)) pe_patched_wcscmp (const uint16_t *a, const uint16_t *b);

/* Look up a replacement address by index.  Returns NULL if idx >= PE_PATCH_COUNT.
 * Defined in pe_patch_crt.c so the table lives next to the bodies. */
void *pe_patch_replacement_by_idx(uint32_t idx);

/* Case-insensitive lookup of a CRT name (e.g. "memcpy", "MemCpy") to its
 * replacement index.  Returns -1 on miss.  Defined in pe_patch_crt.c. */
int pe_patch_lookup_name(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* PE_PATCH_ABI_H */

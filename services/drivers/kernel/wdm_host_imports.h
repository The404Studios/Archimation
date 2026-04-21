/* SPDX-License-Identifier: GPL-2.0 */
/*
 * wdm_host_imports.h - PE Import Address Table (IAT) resolution
 *
 * Walks the IMAGE_DIRECTORY_ENTRY_IMPORT data directory of a loaded
 * Windows .sys image and patches each FirstThunk slot with a kernel-side
 * function pointer pulled from wdm_kernel_exports[]. Unresolved symbols
 * are wired to a TRAP function that returns STATUS_NOT_IMPLEMENTED so a
 * driver call to a missing import logs a clear message instead of taking
 * a kernel oops on a NULL/garbage IAT entry.
 *
 * Owner: Session 65 wdm_host loader hardening.
 */

#ifndef WDM_HOST_IMPORTS_H
#define WDM_HOST_IMPORTS_H

#include <linux/types.h>

/* Layout of one kernel-resident export. The table in wdm_host_ntoskrnl.c
 * MUST be sorted ascending by `name` so the lookup can use bsearch(). */
struct wdm_kernel_export {
	const char *name;       /* exported symbol name (NUL terminated) */
	void       *func;       /* kernel function implementing the symbol */
	u16         ordinal;    /* 0 if this entry is name-only */
};

/* The single, sorted-by-name table of kernel-side ntoskrnl implementations.
 * Currently only ntoskrnl.exe imports are recognized; HAL/wdfldr/etc. fall
 * through to the trap stub. */
extern const struct wdm_kernel_export wdm_kernel_exports[];
extern const size_t wdm_kernel_exports_count;

/* Look up an export by name. Returns NULL if not present. Used by
 * wdm_resolve_imports() and by MmGetSystemRoutineAddress(). */
void *wdm_kernel_export_lookup(const char *name);

/* Trap thunk installed for any unresolved import. When a driver calls it,
 * it logs the driver name + missing symbol via pr_err and returns
 * STATUS_NOT_IMPLEMENTED (0xC0000002). */
long wdm_unresolved_import_trap(void);

/*
 * wdm_resolve_imports() - patch every IAT slot in the loaded image
 * @drv_name:      Driver display name (for diagnostics).
 * @image_base:    Mapped image base (vmalloc'd by the loader).
 * @size_of_image: Total size of the mapped image, for bounds checks.
 * @import_rva:    RVA of IMAGE_DIRECTORY_ENTRY_IMPORT directory.
 * @import_size:   Size of the import directory (bytes).
 * @is_64bit:      true for PE32+, false for PE32. Controls thunk width.
 *
 * On any structurally invalid descriptor, returns -EINVAL. A descriptor
 * that names an unknown symbol does NOT fail the load - the slot is
 * patched with the trap thunk and a pr_warn is emitted. Returns the
 * number of unresolved-but-trapped slots in @out_unresolved (may be NULL).
 *
 * Returns 0 on success, negative errno on structural failure.
 */
int wdm_resolve_imports(const char *drv_name,
			void *image_base,
			u32 size_of_image,
			u32 import_rva,
			u32 import_size,
			bool is_64bit,
			u32 *out_unresolved);

#endif /* WDM_HOST_IMPORTS_H */

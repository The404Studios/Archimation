// SPDX-License-Identifier: GPL-2.0
/*
 * wdm_host_imports.c - PE Import Address Table resolution
 *
 * Walks the IMAGE_DIRECTORY_ENTRY_IMPORT table of a freshly-mapped
 * Windows .sys image, looks up each named or ordinal import in the
 * kernel-resident export table (wdm_kernel_exports[]), and patches the
 * matching FirstThunk slot with the resolved function pointer.
 *
 * Unresolved imports are wired to wdm_unresolved_import_trap(); calling
 * a missing symbol then yields a clear pr_err + NTSTATUS_NOT_IMPLEMENTED
 * instead of dereferencing a NULL or garbage IAT slot.
 *
 * This file does NOT know about the PE optional header layout - the loader
 * computes the import directory RVA/size and hands them in. We only walk
 * IMAGE_IMPORT_DESCRIPTOR -> ILT/IAT -> IMAGE_IMPORT_BY_NAME structures.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/bsearch.h>
#include <linux/sort.h>

#include "wdm_host_internal.h"
#include "wdm_host_imports.h"

/* PE import descriptor (matches wdm_host_loader.c). Re-declared here so
 * we don't drag a private struct out of loader.c via the internal header. */
struct pe_import_descriptor_local {
	uint32_t original_first_thunk;  /* RVA of Import Lookup Table   */
	uint32_t time_date_stamp;
	uint32_t forwarder_chain;
	uint32_t name;                  /* RVA of DLL name (ASCII)      */
	uint32_t first_thunk;           /* RVA of Import Address Table  */
} __packed;

/* IMAGE_IMPORT_BY_NAME header (Hint + ASCII name).  The name follows
 * directly after the 16-bit hint and is NUL-terminated. */
struct pe_import_by_name {
	uint16_t hint;
	char     name[];
} __packed;

/* IMAGE_ORDINAL_FLAG bits select "import by ordinal" in a thunk slot. */
#define WDM_IMAGE_ORDINAL_FLAG64    0x8000000000000000ULL
#define WDM_IMAGE_ORDINAL_FLAG32    0x80000000U
#define WDM_IMAGE_ORDINAL_MASK      0xFFFFU

/* Hard upper bounds so a malformed PE cannot pin the kernel in a loop. */
#define WDM_MAX_IMPORT_DLLS         64
#define WDM_MAX_IMPORTS_PER_DLL     2048

/* NTSTATUS_NOT_IMPLEMENTED - paper Win32 NT status code. */
#define WDM_STATUS_NOT_IMPLEMENTED  0xC0000002L

/* Driver name slot for the trap stub.  We can only name ONE driver at a
 * time - if two drivers fire the trap concurrently this becomes ambiguous,
 * but pr_err already logs both events and the load order is serialized by
 * wdm_driver_lock anyway, so this is acceptable for a diagnostic aid. */
static char wdm_trap_last_driver[256];

/* Backed by a TRAP thunk: patched into IAT slots that we couldn't resolve.
 * The Windows ABI for kernel functions is the Microsoft x64 calling
 * convention; we declare ms_abi so the compiler emits the correct prologue
 * even though we ignore arguments. */
#ifdef __x86_64__
__attribute__((ms_abi))
#endif
static long wdm_iat_trap(void)
{
	pr_err("wdm_host: driver '%s' invoked an unresolved import "
	       "(returning STATUS_NOT_IMPLEMENTED)\n",
	       wdm_trap_last_driver[0] ? wdm_trap_last_driver : "<unknown>");
	return WDM_STATUS_NOT_IMPLEMENTED;
}

long wdm_unresolved_import_trap(void)
{
	return wdm_iat_trap();
}
EXPORT_SYMBOL_GPL(wdm_unresolved_import_trap);

/* bsearch comparator: key is a (const char *), entry has .name. */
static int wdm_export_cmp(const void *key, const void *elt)
{
	const char *k = key;
	const struct wdm_kernel_export *e = elt;

	return strcmp(k, e->name);
}

/* qsort comparator (used by sort_table_once below, NOT in hot path). */
static int wdm_export_qsort_cmp(const void *a, const void *b)
{
	const struct wdm_kernel_export *ea = a;
	const struct wdm_kernel_export *eb = b;

	return strcmp(ea->name, eb->name);
}

/* The exports table in wdm_host_ntoskrnl.c is hand-sorted by name; if a
 * future maintainer breaks the ordering, the first failed lookup will print
 * a one-shot warning and we fall back to a linear scan. We do NOT mutate
 * the .rodata table - we walk it linearly instead. */
static bool wdm_exports_sorted_known_good;
static bool wdm_exports_warned_unsorted;

static void wdm_check_table_sorted_once(void)
{
	size_t i;

	if (wdm_exports_sorted_known_good || wdm_exports_warned_unsorted)
		return;
	for (i = 1; i < wdm_kernel_exports_count; i++) {
		if (strcmp(wdm_kernel_exports[i - 1].name,
			   wdm_kernel_exports[i].name) >= 0) {
			pr_warn("wdm_host: kernel exports table is NOT "
				"sorted at index %zu ('%s' >= '%s'); falling "
				"back to linear scan\n",
				i, wdm_kernel_exports[i - 1].name,
				wdm_kernel_exports[i].name);
			wdm_exports_warned_unsorted = true;
			return;
		}
	}
	wdm_exports_sorted_known_good = true;
}

void *wdm_kernel_export_lookup(const char *name)
{
	const struct wdm_kernel_export *hit;
	size_t i;

	if (!name)
		return NULL;

	wdm_check_table_sorted_once();

	if (wdm_exports_sorted_known_good) {
		hit = bsearch(name, wdm_kernel_exports,
			      wdm_kernel_exports_count,
			      sizeof(wdm_kernel_exports[0]),
			      wdm_export_cmp);
		return hit ? hit->func : NULL;
	}

	/* Linear fallback when the table is unsorted (developer error path). */
	for (i = 0; i < wdm_kernel_exports_count; i++) {
		if (strcmp(name, wdm_kernel_exports[i].name) == 0)
			return wdm_kernel_exports[i].func;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(wdm_kernel_export_lookup);

/* Defensive accessor so unused-function warnings don't hit when sort is
 * never needed. Kept around as scaffolding for a future "auto-sort on
 * load" feature. */
static __maybe_unused void wdm_sort_table_once(struct wdm_kernel_export *t,
					       size_t n)
{
	sort(t, n, sizeof(*t), wdm_export_qsort_cmp, NULL);
}

/* Read an ASCII string out of the image, bounded by size_of_image and
 * by max_len. Returns the actual length on success or -EINVAL on overflow. */
static int wdm_image_strnlen_at(const u8 *image_base, u32 size_of_image,
				u32 rva, size_t max_len, size_t *out_len)
{
	size_t i;

	if (rva >= size_of_image)
		return -EINVAL;
	for (i = 0; i < max_len && (rva + i) < size_of_image; i++) {
		if (image_base[rva + i] == '\0') {
			*out_len = i;
			return 0;
		}
	}
	return -EINVAL;
}

int wdm_resolve_imports(const char *drv_name,
			void *image_base_void,
			u32 size_of_image,
			u32 import_rva,
			u32 import_size,
			bool is_64bit,
			u32 *out_unresolved)
{
	u8 *image_base = image_base_void;
	const struct pe_import_descriptor_local *imp;
	u32 desc_offset;
	u32 unresolved = 0;
	u32 resolved = 0;
	u32 dll_count = 0;

	if (out_unresolved)
		*out_unresolved = 0;

	if (!image_base || !drv_name)
		return -EINVAL;
	if (import_rva == 0 || import_size == 0) {
		/* No imports - nothing to resolve. Driver might be self-
		 * contained (uncommon for a real .sys but valid for tests). */
		pr_info("wdm_host: driver '%s' has no import directory\n",
			drv_name);
		return 0;
	}
	if (import_rva >= size_of_image ||
	    import_size > size_of_image ||
	    import_rva + import_size > size_of_image) {
		pr_err("wdm_host: driver '%s' import directory out of bounds "
		       "(rva=0x%x size=0x%x image=0x%x)\n",
		       drv_name, import_rva, import_size, size_of_image);
		return -EINVAL;
	}

	/* Tell the trap stub which driver is being loaded so an unresolved
	 * call later in this driver's lifetime can be attributed. */
	strscpy(wdm_trap_last_driver, drv_name, sizeof(wdm_trap_last_driver));

	for (desc_offset = import_rva;
	     desc_offset + sizeof(*imp) <= import_rva + import_size &&
	     dll_count < WDM_MAX_IMPORT_DLLS;
	     desc_offset += sizeof(*imp), dll_count++) {

		const char *dll_name = "<bad-rva>";
		u32 ilt_rva, iat_rva, name_rva;
		u32 thunk_idx;
		size_t dll_name_len = 0;

		imp = (const struct pe_import_descriptor_local *)
			(image_base + desc_offset);

		ilt_rva  = le32_to_cpu(imp->original_first_thunk);
		iat_rva  = le32_to_cpu(imp->first_thunk);
		name_rva = le32_to_cpu(imp->name);

		/* Null terminator: name == 0 AND first_thunk == 0. */
		if (name_rva == 0 && iat_rva == 0)
			break;

		if (iat_rva == 0 || iat_rva >= size_of_image) {
			pr_warn("wdm_host: '%s' import descriptor #%u has "
				"invalid IAT rva 0x%x; skipping\n",
				drv_name, dll_count, iat_rva);
			continue;
		}

		if (name_rva && name_rva < size_of_image) {
			if (wdm_image_strnlen_at(image_base, size_of_image,
						 name_rva, 256,
						 &dll_name_len) == 0)
				dll_name = (const char *)(image_base + name_rva);
		}

		/* Per the PE spec, ILT (OFT) is the read-only "name lookup"
		 * copy and IAT (FT) is the patched-at-load copy. If the
		 * compiler omitted the ILT (some old MSVC do), both point at
		 * the same array and we read names directly out of the IAT
		 * before we overwrite each slot. */
		if (ilt_rva == 0 || ilt_rva >= size_of_image)
			ilt_rva = iat_rva;

		for (thunk_idx = 0; thunk_idx < WDM_MAX_IMPORTS_PER_DLL;
		     thunk_idx++) {
			void *resolved_fn = NULL;
			const char *sym_name = NULL;
			u16 ordinal = 0;
			bool by_ordinal = false;

			if (is_64bit) {
				u64 *ilt = (u64 *)(image_base + ilt_rva)
					   + thunk_idx;
				u64 *iat = (u64 *)(image_base + iat_rva)
					   + thunk_idx;
				u64 thunk;

				if ((u8 *)(ilt + 1) >
				    image_base + size_of_image ||
				    (u8 *)(iat + 1) >
				    image_base + size_of_image)
					goto bad_iat_overflow;

				thunk = le64_to_cpu(*ilt);
				if (thunk == 0)
					break;

				if (thunk & WDM_IMAGE_ORDINAL_FLAG64) {
					by_ordinal = true;
					ordinal = (u16)(thunk &
							WDM_IMAGE_ORDINAL_MASK);
				} else {
					u32 hint_rva = (u32)thunk;
					size_t nlen;

					if (hint_rva + sizeof(uint16_t) >=
					    size_of_image)
						goto bad_iat_overflow;
					if (wdm_image_strnlen_at(image_base,
							size_of_image,
							hint_rva +
							offsetof(struct pe_import_by_name, name),
							256, &nlen) != 0)
						goto bad_iat_overflow;
					sym_name = (const char *)(image_base +
							hint_rva +
							offsetof(struct pe_import_by_name, name));
				}

				if (sym_name)
					resolved_fn =
						wdm_kernel_export_lookup(sym_name);

				/* Patch the IAT slot. NULL fn -> trap. */
				if (resolved_fn) {
					*iat = cpu_to_le64(
						(u64)(uintptr_t)resolved_fn);
					resolved++;
				} else {
					*iat = cpu_to_le64(
						(u64)(uintptr_t)wdm_iat_trap);
					unresolved++;
					if (by_ordinal)
						pr_warn("wdm_host:   '%s'!#%u "
							"-> TRAP "
							"(ordinal not in table)\n",
							dll_name, ordinal);
					else
						pr_warn("wdm_host:   '%s'!%s "
							"-> TRAP "
							"(no kernel impl)\n",
							dll_name,
							sym_name ? sym_name :
							"<bad-name>");
				}
			} else {
				u32 *ilt = (u32 *)(image_base + ilt_rva)
					   + thunk_idx;
				u32 *iat = (u32 *)(image_base + iat_rva)
					   + thunk_idx;
				u32 thunk;

				if ((u8 *)(ilt + 1) >
				    image_base + size_of_image ||
				    (u8 *)(iat + 1) >
				    image_base + size_of_image)
					goto bad_iat_overflow;

				thunk = le32_to_cpu(*ilt);
				if (thunk == 0)
					break;

				if (thunk & WDM_IMAGE_ORDINAL_FLAG32) {
					by_ordinal = true;
					ordinal = (u16)(thunk &
							WDM_IMAGE_ORDINAL_MASK);
				} else {
					u32 hint_rva = thunk;
					size_t nlen;

					if (hint_rva + sizeof(uint16_t) >=
					    size_of_image)
						goto bad_iat_overflow;
					if (wdm_image_strnlen_at(image_base,
							size_of_image,
							hint_rva +
							offsetof(struct pe_import_by_name, name),
							256, &nlen) != 0)
						goto bad_iat_overflow;
					sym_name = (const char *)(image_base +
							hint_rva +
							offsetof(struct pe_import_by_name, name));
				}

				if (sym_name)
					resolved_fn =
						wdm_kernel_export_lookup(sym_name);

				if (resolved_fn) {
					*iat = cpu_to_le32(
						(u32)(uintptr_t)resolved_fn);
					resolved++;
				} else {
					*iat = cpu_to_le32(
						(u32)(uintptr_t)wdm_iat_trap);
					unresolved++;
					if (by_ordinal)
						pr_warn("wdm_host:   '%s'!#%u "
							"-> TRAP\n",
							dll_name, ordinal);
					else
						pr_warn("wdm_host:   '%s'!%s "
							"-> TRAP\n",
							dll_name,
							sym_name ? sym_name :
							"<bad-name>");
				}
			}
			continue;

bad_iat_overflow:
			pr_err("wdm_host: '%s' import '%s' thunk #%u out of "
			       "image bounds; aborting resolution\n",
			       drv_name, dll_name, thunk_idx);
			return -EINVAL;
		}

		(void)dll_name_len;
	}

	if (out_unresolved)
		*out_unresolved = unresolved;

	pr_info("wdm_host: '%s' import resolution: %u resolved, %u trapped, "
		"%u DLLs walked\n",
		drv_name, resolved, unresolved, dll_count);
	return 0;
}
EXPORT_SYMBOL_GPL(wdm_resolve_imports);

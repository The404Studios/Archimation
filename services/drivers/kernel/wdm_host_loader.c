// SPDX-License-Identifier: GPL-2.0
/*
 * wdm_host_loader.c - Parse and load Windows .sys PE binaries into kernel memory
 *
 * This module reads a Windows driver (.sys) PE/COFF binary from the filesystem,
 * maps it into kernel virtual memory, processes base relocations, and registers
 * it in the global driver list for IRP dispatch and device management.
 *
 * Import resolution is NOT performed here; the WDM API stubs are linked
 * separately via the stub layer. Unresolved imports are logged as warnings.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/errno.h>

#include "wdm_host_internal.h"

/* ============================================================================
 * PE Format Constants
 * ============================================================================ */

#define PE_DOS_MAGIC    0x5A4D      /* 'MZ' */
#define PE_SIGNATURE    0x00004550  /* 'PE\0\0' */
#define PE_OPT_MAGIC_32 0x010B     /* PE32 */
#define PE_OPT_MAGIC_64 0x020B     /* PE32+ (64-bit) */

/* Relocation types */
#define IMAGE_REL_BASED_ABSOLUTE    0
#define IMAGE_REL_BASED_HIGHLOW     3   /* 32-bit relocation */
#define IMAGE_REL_BASED_DIR64       10  /* 64-bit relocation */

/* Data directory indices */
#define IMAGE_DIRECTORY_ENTRY_EXPORT    0
#define IMAGE_DIRECTORY_ENTRY_IMPORT    1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5

#define IMAGE_SCN_MEM_EXECUTE   0x20000000
#define IMAGE_SCN_MEM_READ      0x40000000
#define IMAGE_SCN_MEM_WRITE     0x80000000

/* Maximum number of PE sections we will process */
#define PE_MAX_SECTIONS 96

/* ============================================================================
 * PE Header Structures (simplified - only the fields we need)
 * ============================================================================ */

/* DOS header: only e_magic and e_lfanew matter */
struct pe_dos_header {
	uint16_t e_magic;       /* offset 0x00: MZ magic */
	uint16_t e_cblp;        /* offset 0x02 */
	uint16_t e_cp;          /* offset 0x04 */
	uint16_t e_crlc;        /* offset 0x06 */
	uint16_t e_cparhdr;     /* offset 0x08 */
	uint16_t e_minalloc;    /* offset 0x0A */
	uint16_t e_maxalloc;    /* offset 0x0C */
	uint16_t e_ss;          /* offset 0x0E */
	uint16_t e_sp;          /* offset 0x10 */
	uint16_t e_csum;        /* offset 0x12 */
	uint16_t e_ip;          /* offset 0x14 */
	uint16_t e_cs;          /* offset 0x16 */
	uint16_t e_lfarlc;      /* offset 0x18 */
	uint16_t e_ovno;        /* offset 0x1A */
	uint16_t e_res[4];      /* offset 0x1C */
	uint16_t e_oemid;       /* offset 0x24 */
	uint16_t e_oeminfo;     /* offset 0x26 */
	uint16_t e_res2[10];    /* offset 0x28 */
	int32_t  e_lfanew;      /* offset 0x3C: offset to PE signature */
} __packed;

/* COFF file header (immediately after PE signature) */
struct pe_coff_header {
	uint16_t machine;
	uint16_t number_of_sections;
	uint32_t time_date_stamp;
	uint32_t pointer_to_symbol_table;
	uint32_t number_of_symbols;
	uint16_t size_of_optional_header;
	uint16_t characteristics;
} __packed;

/* Data directory entry */
struct pe_data_directory {
	uint32_t virtual_address;
	uint32_t size;
} __packed;

/* PE32 optional header */
struct pe_optional_header_32 {
	uint16_t magic;                    /* PE_OPT_MAGIC_32 */
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
	struct pe_data_directory data_directory[];
} __packed;

/* PE32+ (64-bit) optional header */
struct pe_optional_header_64 {
	uint16_t magic;                    /* PE_OPT_MAGIC_64 */
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
	struct pe_data_directory data_directory[];
} __packed;

/* Section header */
struct pe_section_header {
	char     name[8];
	uint32_t virtual_size;
	uint32_t virtual_address;
	uint32_t size_of_raw_data;
	uint32_t pointer_to_raw_data;
	uint32_t pointer_to_relocations;
	uint32_t pointer_to_line_numbers;
	uint16_t number_of_relocations;
	uint16_t number_of_line_numbers;
	uint32_t characteristics;
} __packed;

/* Base relocation block header */
struct pe_base_reloc_block {
	uint32_t virtual_address;
	uint32_t size_of_block;
} __packed;

/* Import directory entry */
struct pe_import_descriptor {
	uint32_t original_first_thunk;  /* RVA to INT (Import Name Table) */
	uint32_t time_date_stamp;
	uint32_t forwarder_chain;
	uint32_t name;                  /* RVA to DLL name */
	uint32_t first_thunk;           /* RVA to IAT (Import Address Table) */
} __packed;

/* ============================================================================
 * Global Driver List - defined in wdm_host_main.c as wdm_driver_list and
 * wdm_driver_lock. We alias the lock name here for local readability.
 * ============================================================================ */

#define wdm_driver_list_lock wdm_driver_lock

/* ============================================================================
 * File I/O Helpers
 * ============================================================================ */

/**
 * read_file_to_buffer() - Read an entire file into a kmalloc'd buffer
 * @path:     Filesystem path to the file
 * @out_buf:  Receives pointer to allocated buffer on success
 * @out_size: Receives file size on success
 *
 * The caller must kfree() *out_buf when done.
 * Returns 0 on success, negative errno on failure.
 */
static int read_file_to_buffer(const char *path, void **out_buf,
			       size_t *out_size)
{
	struct file *filp;
	loff_t file_size;
	loff_t pos = 0;
	void *buf;
	ssize_t bytes_read;

	filp = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(filp)) {
		pr_err("[wdm_host] Failed to open file '%s': %ld\n",
		       path, PTR_ERR(filp));
		return PTR_ERR(filp);
	}

	file_size = i_size_read(file_inode(filp));
	if (file_size <= 0) {
		pr_err("[wdm_host] File '%s' is empty or unreadable\n", path);
		filp_close(filp, NULL);
		return -EINVAL;
	}

	if (file_size > (64 * 1024 * 1024)) {
		pr_err("[wdm_host] File '%s' too large (%lld bytes, max 64MB)\n",
		       path, file_size);
		filp_close(filp, NULL);
		return -EFBIG;
	}

	buf = vmalloc(file_size);
	if (!buf) {
		pr_err("[wdm_host] Failed to allocate %lld bytes for file '%s'\n",
		       file_size, path);
		filp_close(filp, NULL);
		return -ENOMEM;
	}

	bytes_read = kernel_read(filp, buf, file_size, &pos);
	filp_close(filp, NULL);

	if (bytes_read != file_size) {
		pr_err("[wdm_host] Short read on '%s': got %zd of %lld bytes\n",
		       path, bytes_read, file_size);
		vfree(buf);
		return -EIO;
	}

	*out_buf = buf;
	*out_size = (size_t)file_size;
	return 0;
}

/* ============================================================================
 * PE Validation and Parsing
 * ============================================================================ */

/**
 * validate_pe_headers() - Validate MZ and PE signatures
 * @data:      Pointer to file data
 * @data_size: Size of file data
 * @pe_offset: Receives the offset to the PE signature
 *
 * Returns 0 if valid, negative errno otherwise.
 */
static int validate_pe_headers(const void *data, size_t data_size,
			       uint32_t *pe_offset)
{
	const struct pe_dos_header *dos;
	const uint32_t *pe_sig;

	if (data_size < sizeof(struct pe_dos_header)) {
		pr_err("[wdm_host] File too small for DOS header (%zu bytes)\n",
		       data_size);
		return -EINVAL;
	}

	/* Step 1: Validate MZ magic at offset 0 */
	dos = (const struct pe_dos_header *)data;
	if (le16_to_cpu(dos->e_magic) != PE_DOS_MAGIC) {
		pr_err("[wdm_host] Invalid DOS magic: 0x%04X (expected 0x%04X)\n",
		       le16_to_cpu(dos->e_magic), PE_DOS_MAGIC);
		return -EINVAL;
	}

	/* Step 2: Read e_lfanew to find PE signature */
	*pe_offset = le32_to_cpu(dos->e_lfanew);
	if (*pe_offset + sizeof(uint32_t) > data_size) {
		pr_err("[wdm_host] e_lfanew (0x%X) points beyond file\n",
		       *pe_offset);
		return -EINVAL;
	}

	/* Step 3: Validate PE signature at e_lfanew */
	pe_sig = (const uint32_t *)((const uint8_t *)data + *pe_offset);
	if (le32_to_cpu(*pe_sig) != PE_SIGNATURE) {
		pr_err("[wdm_host] Invalid PE signature: 0x%08X (expected 0x%08X)\n",
		       le32_to_cpu(*pe_sig), PE_SIGNATURE);
		return -EINVAL;
	}

	return 0;
}

/* ============================================================================
 * Import Directory Logging (no resolution, just warnings)
 * ============================================================================ */

/**
 * log_unresolved_imports() - Walk the import directory and log each DLL
 * @image_base: Mapped image base
 * @import_rva: RVA of the import directory
 * @import_size: Size of the import directory
 * @size_of_image: Total size of the mapped image
 */
static void log_unresolved_imports(const uint8_t *image_base,
				   uint32_t import_rva,
				   uint32_t import_size,
				   uint32_t size_of_image)
{
	const struct pe_import_descriptor *imp;
	uint32_t offset;

	if (import_rva == 0 || import_size == 0)
		return;

	if (import_rva + import_size > size_of_image) {
		pr_warn("[wdm_host] Import directory extends beyond image\n");
		return;
	}

	offset = import_rva;
	while (offset + sizeof(struct pe_import_descriptor) <=
	       import_rva + import_size) {
		imp = (const struct pe_import_descriptor *)(image_base + offset);

		/* Null terminator entry */
		if (imp->name == 0 && imp->first_thunk == 0)
			break;

		if (le32_to_cpu(imp->name) < size_of_image) {
			const char *dll_name = (const char *)
				(image_base + le32_to_cpu(imp->name));
			pr_warn("[wdm_host]   Unresolved import DLL: %s "
				"(IAT RVA=0x%08X)\n",
				dll_name, le32_to_cpu(imp->first_thunk));
		} else {
			pr_warn("[wdm_host]   Unresolved import DLL name RVA "
				"0x%08X out of bounds\n",
				le32_to_cpu(imp->name));
		}

		offset += sizeof(struct pe_import_descriptor);
	}
}

/* ============================================================================
 * Base Relocation Processing
 * ============================================================================ */

/**
 * process_relocations() - Apply base relocations to the mapped image
 * @image_base:    Pointer to the mapped image
 * @reloc_rva:     RVA of the base relocation directory
 * @reloc_size:    Size of the base relocation directory
 * @size_of_image: Total size of the mapped image
 * @delta:         Difference between actual load address and preferred ImageBase
 * @is_64bit:      True if the PE is PE32+ (64-bit)
 *
 * Returns 0 on success, negative errno on failure.
 */
static int process_relocations(uint8_t *image_base, uint32_t reloc_rva,
			       uint32_t reloc_size, uint32_t size_of_image,
			       int64_t delta, bool is_64bit)
{
	uint32_t offset;
	uint32_t processed = 0;

	if (reloc_rva == 0 || reloc_size == 0) {
		if (delta != 0) {
			pr_warn("[wdm_host] No relocation data but image "
				"loaded at different base (delta=0x%llX)\n",
				(unsigned long long)delta);
		}
		return 0;
	}

	if (delta == 0) {
		pr_debug("[wdm_host] No relocations needed (delta=0)\n");
		return 0;
	}

	if (reloc_rva + reloc_size > size_of_image) {
		pr_err("[wdm_host] Relocation directory extends beyond image\n");
		return -EINVAL;
	}

	offset = reloc_rva;
	while (offset < reloc_rva + reloc_size) {
		const struct pe_base_reloc_block *block;
		uint32_t block_size;
		uint32_t num_entries;
		const uint16_t *entries;
		uint32_t i;

		block = (const struct pe_base_reloc_block *)
			(image_base + offset);
		block_size = le32_to_cpu(block->size_of_block);

		if (block_size < sizeof(struct pe_base_reloc_block) ||
		    block_size > reloc_size - (offset - reloc_rva)) {
			pr_debug("[wdm_host] Relocation block at 0x%X: "
				 "invalid size %u, stopping\n",
				 offset, block_size);
			break;
		}

		num_entries = (block_size - sizeof(struct pe_base_reloc_block))
			      / sizeof(uint16_t);
		entries = (const uint16_t *)
			  (image_base + offset +
			   sizeof(struct pe_base_reloc_block));

		for (i = 0; i < num_entries; i++) {
			uint16_t entry = le16_to_cpu(entries[i]);
			uint8_t type = entry >> 12;
			uint16_t rva_offset = entry & 0x0FFF;
			uint32_t target_rva =
				le32_to_cpu(block->virtual_address) + rva_offset;

			if (target_rva >= size_of_image)
				continue;

			switch (type) {
			case IMAGE_REL_BASED_ABSOLUTE:
				/* Padding - skip */
				break;

			case IMAGE_REL_BASED_HIGHLOW: {
				/* 32-bit relocation */
				uint32_t *patch =
					(uint32_t *)(image_base + target_rva);
				uint32_t val = le32_to_cpu(*patch);
				val += (uint32_t)(int32_t)delta;
				*patch = cpu_to_le32(val);
				processed++;
				break;
			}

			case IMAGE_REL_BASED_DIR64: {
				/* 64-bit relocation */
				uint64_t *patch =
					(uint64_t *)(image_base + target_rva);
				uint64_t val = le64_to_cpu(*patch);
				val += (uint64_t)delta;
				*patch = cpu_to_le64(val);
				processed++;
				break;
			}

			default:
				pr_warn("[wdm_host] Unsupported relocation "
					"type %d at RVA 0x%08X\n",
					type, target_rva);
				break;
			}
		}

		offset += block_size;
	}

	pr_debug("[wdm_host] Processed %u relocations (delta=0x%llX)\n",
		 processed, (unsigned long long)delta);
	return 0;
}

/* ============================================================================
 * Driver Loading
 * ============================================================================ */

/**
 * wdm_load_driver() - Load a Windows .sys driver from a file path
 * @path: Filesystem path to the .sys file
 * @name: Friendly name for the driver (used for lookup)
 *
 * Reads the PE binary, validates headers, maps sections into vmalloc'd memory,
 * processes relocations, and registers the driver in the global list.
 *
 * Returns 0 on success, negative errno on failure.
 */
int wdm_load_driver(const char *path, const char *name)
{
	void *file_data = NULL;
	size_t file_size = 0;
	uint32_t pe_offset;
	const struct pe_coff_header *coff;
	const void *opt_hdr;
	const struct pe_section_header *sections;
	uint8_t *image = NULL;
	struct wdm_driver *drv = NULL;
	uint32_t size_of_image;
	uint32_t address_of_entry_point;
	uint64_t preferred_image_base;
	uint32_t size_of_headers;
	uint32_t number_of_rva_and_sizes;
	const struct pe_data_directory *data_dirs;
	uint16_t opt_magic;
	uint16_t num_sections;
	bool is_64bit;
	int64_t delta;
	int ret;
	uint16_t i;

	if (!path || !name) {
		pr_err("[wdm_host] wdm_load_driver: NULL path or name\n");
		return -EINVAL;
	}

	pr_info("[wdm_host] Loading driver '%s' from '%s'\n", name, path);

	/* Check if a driver with this name is already loaded */
	if (wdm_find_driver(name)) {
		pr_err("[wdm_host] Driver '%s' is already loaded\n", name);
		return -EEXIST;
	}

	/* Step 1: Read the .sys file into memory */
	ret = read_file_to_buffer(path, &file_data, &file_size);
	if (ret)
		return ret;

	/* Steps 2-3: Validate MZ and PE signatures */
	ret = validate_pe_headers(file_data, file_size, &pe_offset);
	if (ret)
		goto fail_free_file;

	/* Step 4: Parse COFF header (after the 4-byte PE signature) */
	if (pe_offset + 4 + sizeof(struct pe_coff_header) > file_size) {
		pr_err("[wdm_host] File too small for COFF header\n");
		ret = -EINVAL;
		goto fail_free_file;
	}

	coff = (const struct pe_coff_header *)
		((const uint8_t *)file_data + pe_offset + 4);
	num_sections = le16_to_cpu(coff->number_of_sections);

	if (num_sections == 0 || num_sections > PE_MAX_SECTIONS) {
		pr_err("[wdm_host] Invalid number of sections: %u\n",
		       num_sections);
		ret = -EINVAL;
		goto fail_free_file;
	}

	if (le16_to_cpu(coff->size_of_optional_header) == 0) {
		pr_err("[wdm_host] No optional header present\n");
		ret = -EINVAL;
		goto fail_free_file;
	}

	pr_debug("[wdm_host] COFF: Machine=0x%04X, Sections=%u, "
		 "OptHdrSize=%u\n",
		 le16_to_cpu(coff->machine), num_sections,
		 le16_to_cpu(coff->size_of_optional_header));

	/* Step 5: Parse optional header */
	opt_hdr = (const uint8_t *)coff + sizeof(struct pe_coff_header);
	if ((const uint8_t *)opt_hdr + 2 >
	    (const uint8_t *)file_data + file_size) {
		pr_err("[wdm_host] File too small for optional header magic\n");
		ret = -EINVAL;
		goto fail_free_file;
	}

	opt_magic = le16_to_cpu(*(const uint16_t *)opt_hdr);

	if (opt_magic == PE_OPT_MAGIC_64) {
		const struct pe_optional_header_64 *opt64 = opt_hdr;

		is_64bit = true;
		address_of_entry_point = le32_to_cpu(opt64->address_of_entry_point);
		preferred_image_base = le64_to_cpu(opt64->image_base);
		size_of_image = le32_to_cpu(opt64->size_of_image);
		size_of_headers = le32_to_cpu(opt64->size_of_headers);
		number_of_rva_and_sizes = le32_to_cpu(opt64->number_of_rva_and_sizes);
		data_dirs = opt64->data_directory;

		pr_debug("[wdm_host] PE32+ (64-bit): ImageBase=0x%llX, "
			 "SizeOfImage=0x%X, EntryPoint=0x%X\n",
			 preferred_image_base, size_of_image,
			 address_of_entry_point);
	} else if (opt_magic == PE_OPT_MAGIC_32) {
		const struct pe_optional_header_32 *opt32 = opt_hdr;

		is_64bit = false;
		address_of_entry_point = le32_to_cpu(opt32->address_of_entry_point);
		preferred_image_base = le32_to_cpu(opt32->image_base);
		size_of_image = le32_to_cpu(opt32->size_of_image);
		size_of_headers = le32_to_cpu(opt32->size_of_headers);
		number_of_rva_and_sizes = le32_to_cpu(opt32->number_of_rva_and_sizes);
		data_dirs = opt32->data_directory;

		pr_debug("[wdm_host] PE32 (32-bit): ImageBase=0x%llX, "
			 "SizeOfImage=0x%X, EntryPoint=0x%X\n",
			 preferred_image_base, size_of_image,
			 address_of_entry_point);
	} else {
		pr_err("[wdm_host] Unknown optional header magic: 0x%04X\n",
		       opt_magic);
		ret = -EINVAL;
		goto fail_free_file;
	}

	if (size_of_image == 0 || size_of_image > (256 * 1024 * 1024)) {
		pr_err("[wdm_host] Invalid SizeOfImage: 0x%X\n", size_of_image);
		ret = -EINVAL;
		goto fail_free_file;
	}

	/* Step 6: Locate section headers */
	sections = (const struct pe_section_header *)
		   ((const uint8_t *)opt_hdr +
		    le16_to_cpu(coff->size_of_optional_header));

	if ((const uint8_t *)sections +
	    (num_sections * sizeof(struct pe_section_header)) >
	    (const uint8_t *)file_data + file_size) {
		pr_err("[wdm_host] Section headers extend beyond file\n");
		ret = -EINVAL;
		goto fail_free_file;
	}

	/* Step 7: Allocate image memory */
	image = vmalloc(size_of_image);
	if (!image) {
		pr_err("[wdm_host] Failed to allocate %u bytes for image\n",
		       size_of_image);
		ret = -ENOMEM;
		goto fail_free_file;
	}
	memset(image, 0, size_of_image);

	/* Step 8: Copy PE headers to the image */
	if (size_of_headers > file_size)
		size_of_headers = (uint32_t)file_size;
	if (size_of_headers > size_of_image)
		size_of_headers = size_of_image;
	memcpy(image, file_data, size_of_headers);

	/* Step 9: Map each section */
	for (i = 0; i < num_sections; i++) {
		uint32_t va = le32_to_cpu(sections[i].virtual_address);
		uint32_t raw_size = le32_to_cpu(sections[i].size_of_raw_data);
		uint32_t raw_ptr = le32_to_cpu(sections[i].pointer_to_raw_data);
		uint32_t virt_size = le32_to_cpu(sections[i].virtual_size);
		char sec_name[9];

		memcpy(sec_name, sections[i].name, 8);
		sec_name[8] = '\0';

		pr_debug("[wdm_host]   Section '%s': VA=0x%X, "
			 "VirtSize=0x%X, RawSize=0x%X, RawPtr=0x%X\n",
			 sec_name, va, virt_size, raw_size, raw_ptr);

		/* Validate section boundaries */
		if (va >= size_of_image) {
			pr_warn("[wdm_host]   Section '%s' VA beyond image, "
				"skipping\n", sec_name);
			continue;
		}

		/* Copy raw data if present */
		if (raw_size > 0 && raw_ptr > 0) {
			uint32_t copy_size = raw_size;

			if (raw_ptr + copy_size > file_size) {
				pr_warn("[wdm_host]   Section '%s' raw data "
					"truncated\n", sec_name);
				if (raw_ptr < file_size)
					copy_size = (uint32_t)(file_size - raw_ptr);
				else
					copy_size = 0;
			}

			if (va + copy_size > size_of_image)
				copy_size = size_of_image - va;

			if (copy_size > 0) {
				memcpy(image + va,
				       (const uint8_t *)file_data + raw_ptr,
				       copy_size);
			}
		}
	}

	/* Step 10: Process base relocations */
	delta = (int64_t)((uintptr_t)image) - (int64_t)preferred_image_base;
	if (number_of_rva_and_sizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
		uint32_t reloc_rva =
			le32_to_cpu(data_dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC]
				    .virtual_address);
		uint32_t reloc_size =
			le32_to_cpu(data_dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC]
				    .size);

		ret = process_relocations(image, reloc_rva, reloc_size,
					  size_of_image, delta, is_64bit);
		if (ret) {
			pr_err("[wdm_host] Failed to process relocations\n");
			goto fail_free_image;
		}
	} else if (delta != 0) {
		pr_warn("[wdm_host] No relocation directory but loaded at "
			"different base\n");
	}

	/* Step 11: Log unresolved imports (no resolution) */
	if (number_of_rva_and_sizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
		uint32_t import_rva =
			le32_to_cpu(data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT]
				    .virtual_address);
		uint32_t import_size =
			le32_to_cpu(data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT]
				    .size);

		if (import_rva != 0 && import_size != 0) {
			pr_warn("[wdm_host] Driver '%s' has unresolved "
				"imports (stub resolution separate):\n", name);
			log_unresolved_imports(image, import_rva,
					       import_size, size_of_image);
		}
	}

	/* Step 12: Find entry point */
	/* Step 13: Create wdm_driver struct */
	drv = kzalloc(sizeof(*drv), GFP_KERNEL);
	if (!drv) {
		pr_err("[wdm_host] Failed to allocate wdm_driver struct\n");
		ret = -ENOMEM;
		goto fail_free_image;
	}

	strscpy(drv->name, name, sizeof(drv->name));
	drv->image_base = image;
	drv->image_size = size_of_image;
	drv->entry_point = (address_of_entry_point < size_of_image)
			   ? (void *)(image + address_of_entry_point)
			   : NULL;
	drv->unload_func = NULL;
	drv->state = WDM_STATE_LOADED;
	(void)is_64bit;                 /* retained as local for relocation step */
	(void)preferred_image_base;     /* relocation delta already applied */
	INIT_LIST_HEAD(&drv->devices);
	INIT_LIST_HEAD(&drv->list);
	memset(drv->dispatch_table, 0, sizeof(drv->dispatch_table));

	/* Add to global list */
	mutex_lock(&wdm_driver_list_lock);
	list_add_tail(&drv->list, &wdm_driver_list);
	mutex_unlock(&wdm_driver_list_lock);

	/* Step 14: Log success */
	pr_info("[wdm_host] Loaded driver '%s' at %p, entry=%p\n",
		drv->name, drv->image_base, drv->entry_point);

	/* Free the temporary file buffer (image data already copied) */
	vfree(file_data);

	/* Step 15: Return success */
	return 0;

fail_free_image:
	vfree(image);
fail_free_file:
	vfree(file_data);
	return ret;
}
EXPORT_SYMBOL_GPL(wdm_load_driver);

/* ============================================================================
 * Driver Unloading
 * ============================================================================ */

/**
 * wdm_unload_driver() - Unload a previously loaded Windows driver
 * @name: Name of the driver to unload
 *
 * Finds the driver by name, calls its unload function if set, removes all
 * associated devices, frees the image memory, and removes it from the
 * global driver list.
 *
 * Returns 0 on success, -ENOENT if not found.
 */
int wdm_unload_driver(const char *name)
{
	struct wdm_driver *drv;
	struct wdm_device *dev, *tmp_dev;

	if (!name) {
		pr_err("[wdm_host] wdm_unload_driver: NULL name\n");
		return -EINVAL;
	}

	mutex_lock(&wdm_driver_list_lock);

	drv = NULL;
	{
		struct wdm_driver *iter;

		list_for_each_entry(iter, &wdm_driver_list, list) {
			if (strcmp(iter->name, name) == 0) {
				drv = iter;
				break;
			}
		}
	}

	if (!drv) {
		mutex_unlock(&wdm_driver_list_lock);
		pr_err("[wdm_host] Driver '%s' not found for unload\n", name);
		return -ENOENT;
	}

	/* Step 2: Call unload function if registered */
	if (drv->unload_func) {
		typedef void (*unload_fn_t)(void *);
		unload_fn_t unload = (unload_fn_t)drv->unload_func;

		pr_info("[wdm_host] Calling unload function for '%s'\n",
			drv->name);
		unload(drv);
	}

	/* Step 3: Delete all devices owned by this driver.
	 * Note: use wdm_delete_device() for proper cdev teardown; however
	 * here we only detach bookkeeping because device lifecycle is owned
	 * by wdm_host_device.c. Callers should have removed devices first.
	 */
	list_for_each_entry_safe(dev, tmp_dev, &drv->devices, driver_list) {
		pr_info("[wdm_host] Removing device '%s' from driver '%s'\n",
			dev->device_name, drv->name);
		list_del(&dev->driver_list);
		if (dev->device_extension)
			kfree(dev->device_extension);
		kfree(dev);
	}

	/* Step 4: Free image memory */
	if (drv->image_base) {
		vfree(drv->image_base);
		drv->image_base = NULL;
	}

	/* Step 5: Remove from list and free struct */
	list_del(&drv->list);
	mutex_unlock(&wdm_driver_list_lock);

	pr_info("[wdm_host] Unloaded driver '%s'\n", drv->name);
	kfree(drv);

	return 0;
}
EXPORT_SYMBOL_GPL(wdm_unload_driver);

/* ============================================================================
 * Driver Lookup
 * ============================================================================ */

/**
 * wdm_find_driver() - Find a loaded driver by name
 * @name: Name to search for
 *
 * Searches the global driver list. The caller must NOT hold
 * wdm_driver_list_lock.
 *
 * Returns pointer to the wdm_driver, or NULL if not found.
 * Note: The returned pointer is valid only while the driver remains loaded.
 */
struct wdm_driver *wdm_find_driver(const char *name)
{
	struct wdm_driver *drv = NULL;
	struct wdm_driver *iter;

	if (!name)
		return NULL;

	mutex_lock(&wdm_driver_list_lock);
	list_for_each_entry(iter, &wdm_driver_list, list) {
		if (strcmp(iter->name, name) == 0) {
			drv = iter;
			break;
		}
	}
	mutex_unlock(&wdm_driver_list_lock);

	return drv;
}
EXPORT_SYMBOL_GPL(wdm_find_driver);

/* ============================================================================
 * Module Init / Exit
 * ============================================================================ */

/**
 * wdm_host_loader_init() - Initialize the PE loader subsystem
 *
 * Returns 0 on success.
 */
int wdm_host_loader_init(void)
{
	pr_info("[wdm_host] PE loader subsystem initialized\n");
	return 0;
}

/**
 * wdm_host_loader_exit() - Clean up the PE loader subsystem
 *
 * Unloads all remaining drivers.
 */
void wdm_host_loader_exit(void)
{
	struct wdm_driver *drv, *tmp;

	pr_info("[wdm_host] PE loader subsystem shutting down\n");

	mutex_lock(&wdm_driver_list_lock);
	list_for_each_entry_safe(drv, tmp, &wdm_driver_list, list) {
		struct wdm_device *dev, *tmp_dev;

		pr_info("[wdm_host] Force-unloading driver '%s'\n", drv->name);

		/* Clean up devices */
		list_for_each_entry_safe(dev, tmp_dev, &drv->devices, driver_list) {
			list_del(&dev->driver_list);
			if (dev->device_extension)
				kfree(dev->device_extension);
			kfree(dev);
		}

		/* Free image */
		if (drv->image_base)
			vfree(drv->image_base);

		list_del(&drv->list);
		kfree(drv);
	}
	mutex_unlock(&wdm_driver_list_lock);

	pr_info("[wdm_host] PE loader subsystem exited\n");
}

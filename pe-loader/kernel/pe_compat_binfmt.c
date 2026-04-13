// SPDX-License-Identifier: GPL-2.0
/*
 * pe_compat_binfmt.c - Binary format handler for PE/COFF executables
 *
 * Registers a linux_binfmt that recognises PE files by their MZ+PE
 * signature.  When the kernel tries to exec(2) such a file, we redirect
 * execution to the userspace PE loader (/usr/bin/peloader) which does the
 * heavy lifting (section mapping, IAT patching, DLL loading, etc.).
 *
 * This is conceptually similar to how binfmt_misc works for Wine, but
 * built directly into the module so it is always available once pe_compat
 * is loaded.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/binfmts.h>
#include <linux/elf.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "pe_compat_internal.h"

/* The userspace loader that will actually handle the PE file */
#define PE_LOADER_PATH "/usr/bin/peloader"

/*
 * MZ header magic -- the first two bytes of every PE file.
 * The PE\0\0 signature lives at the offset stored in e_lfanew
 * (offset 0x3C in the DOS header).
 */
#define MZ_MAGIC_0 'M'
#define MZ_MAGIC_1 'Z'

#define PE_SIGNATURE_OFFSET 0x3C

/*
 * Minimum file size we're willing to inspect:
 *   DOS header (64 bytes) + at least 4 bytes for PE sig.
 */
#define PE_MIN_SIZE 68

static int pe_load_binary(struct linux_binprm *bprm)
{
	const unsigned char *buf = bprm->buf;
	u32 pe_offset;
	u32 pe_sig;
	struct file *loader_file;
	int ret;

	/*
	 * Quick rejection: check MZ magic.
	 * bprm->buf contains the first BINPRM_BUF_SIZE bytes.
	 */
	if (buf[0] != MZ_MAGIC_0 || buf[1] != MZ_MAGIC_1)
		return -ENOEXEC;

	/*
	 * Read the e_lfanew field at offset 0x3C.
	 * This tells us where the PE signature ("PE\0\0") lives.
	 */
	pe_offset = *(const u32 *)(buf + PE_SIGNATURE_OFFSET);

	/*
	 * Sanity check: pe_offset must be within the buffer we already
	 * have (BINPRM_BUF_SIZE is usually 256 bytes) and leave room
	 * for the 4-byte PE signature.
	 */
	if (pe_offset + 4 > BINPRM_BUF_SIZE)
		return -ENOEXEC;

	pe_sig = *(const u32 *)(buf + pe_offset);
	if (pe_sig != 0x00004550) /* "PE\0\0" */
		return -ENOEXEC;

	if (pe_debug >= 1)
		pr_info("detected PE executable: %s\n",
			bprm->filename);

	/*
	 * This is a valid PE file.  We do not load it ourselves; instead
	 * we re-exec the userspace loader, passing the PE file path as
	 * its first argument.
	 *
	 * The sequence is:
	 *   1. Open the loader binary.
	 *   2. Replace bprm's file and interpreter path.
	 *   3. Adjust argv so that argv[0] = loader, argv[1] = PE path.
	 *   4. Let the kernel proceed with loading the (ELF) loader.
	 */

	loader_file = open_exec(PE_LOADER_PATH);
	if (IS_ERR(loader_file)) {
		pr_err("cannot open PE loader %s: %ld\n",
		       PE_LOADER_PATH, PTR_ERR(loader_file));
		return PTR_ERR(loader_file);
	}

	/* Replace the executable with our loader */
	bprm->interpreter = loader_file;

	/*
	 * Prepend the loader path to the argument list.
	 * After this, argv looks like:
	 *   argv[0] = "/usr/bin/peloader"
	 *   argv[1] = "/path/to/program.exe"   (the original argv[0])
	 *   argv[2..] = original argv[1..]
	 */
	ret = remove_arg_zero(bprm);
	if (ret)
		return ret;

	ret = copy_string_kernel(bprm->filename, bprm);
	if (ret < 0)
		return ret;
	bprm->argc++;

	ret = copy_string_kernel(PE_LOADER_PATH, bprm);
	if (ret < 0)
		return ret;
	bprm->argc++;

	/*
	 * Now let the kernel re-examine bprm->interpreter, which is an
	 * ELF binary.  The normal ELF loader will take over from here.
	 */
	ret = bprm_change_interp(PE_LOADER_PATH, bprm);
	if (ret)
		return ret;

	return search_binary_handler(bprm);
}

static struct linux_binfmt pe_binfmt = {
	.module      = THIS_MODULE,
	.load_binary = pe_load_binary,
};

int pe_binfmt_register(void)
{
	register_binfmt(&pe_binfmt);
	pr_info("registered PE binary format handler\n");
	return 0;
}

void pe_binfmt_unregister(void)
{
	unregister_binfmt(&pe_binfmt);
	pr_info("unregistered PE binary format handler\n");
}

// SPDX-License-Identifier: GPL-2.0
/*
 * pe_compat_memory.c - Kernel-side memory management for PE processes
 *
 * Provides a fast path for VirtualAlloc / VirtualFree by performing
 * vm_mmap / vm_munmap directly from kernel space, avoiding the
 * overhead of going through the full userspace syscall dance.
 *
 * Accessed via PE_COMPAT_VALLOC and PE_COMPAT_VFREE ioctls on
 * /dev/pe_compat.
 *
 * The Windows memory protection flags are translated to their Linux
 * mmap(2) equivalents before the call is made.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/uaccess.h>
#include <linux/sched.h>

#include "pe_compat_internal.h"
#include <compat/pe_compat_ioctl.h>

/*
 * Translate Windows PAGE_* protection flags to Linux PROT_* flags.
 *
 * Windows flags are a bitmask but only one "base" protection is set at a
 * time (PAGE_READONLY, PAGE_READWRITE, etc.).  The modifiers (PAGE_GUARD,
 * PAGE_NOCACHE) are ORed on top.
 */
static unsigned long win_protect_to_linux(u32 protect)
{
	unsigned long prot = 0;

	switch (protect & 0xFF) {
	case PE_PAGE_NOACCESS:
		prot = PROT_NONE;
		break;
	case PE_PAGE_READONLY:
		prot = PROT_READ;
		break;
	case PE_PAGE_READWRITE:
	case PE_PAGE_WRITECOPY:
		prot = PROT_READ | PROT_WRITE;
		break;
	case PE_PAGE_EXECUTE:
		prot = PROT_EXEC;
		break;
	case PE_PAGE_EXECUTE_READ:
		prot = PROT_READ | PROT_EXEC;
		break;
	case PE_PAGE_EXECUTE_READWRITE:
	case PE_PAGE_EXECUTE_WRITECOPY:
		prot = PROT_READ | PROT_WRITE | PROT_EXEC;
		break;
	default:
		/* Unknown protection; default to RW */
		prot = PROT_READ | PROT_WRITE;
		break;
	}

	return prot;
}

/*
 * Determine mmap flags from the Windows allocation type.
 *
 * MEM_COMMIT  -> MAP_PRIVATE | MAP_ANONYMOUS
 * MEM_RESERVE -> MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE
 *
 * If a specific address is requested, we add MAP_FIXED_NOREPLACE so
 * we don't silently clobber existing mappings.
 */
static unsigned long win_alloc_to_mmap_flags(u32 alloc_type, u64 address)
{
	unsigned long flags = MAP_PRIVATE | MAP_ANONYMOUS;

	if (alloc_type & PE_MEM_RESERVE)
		flags |= MAP_NORESERVE;

	if (address)
		flags |= MAP_FIXED_NOREPLACE;

	return flags;
}

void pe_memory_init(void)
{
	pr_info("memory management subsystem ready\n");
}

/*
 * Handle PE_COMPAT_VALLOC ioctl.
 *
 * Allocates virtual memory in the calling process's address space,
 * translating Windows semantics to Linux vm_mmap().
 */
static long pe_memory_valloc(unsigned long arg)
{
	struct pe_valloc_request req;
	unsigned long prot, flags, addr;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	prot  = win_protect_to_linux(req.protect);
	flags = win_alloc_to_mmap_flags(req.alloc_type, req.address);

	/*
	 * vm_mmap() allocates memory in the *current* process's
	 * address space.  The caller must be the PE process itself
	 * (or a thread acting on its behalf via the ioctl).
	 */
	addr = vm_mmap(NULL, (unsigned long)req.address,
		       (unsigned long)req.size, prot, flags, 0);

	if (IS_ERR_VALUE(addr)) {
		if (pe_debug >= 1)
			pr_debug("valloc failed: addr=0x%llx size=0x%llx err=%ld\n",
				 req.address, req.size, (long)addr);
		return (long)addr;
	}

	if (pe_debug >= 2)
		pr_debug("valloc: 0x%lx size=0x%llx prot=0x%lx flags=0x%lx\n",
			 addr, req.size, prot, flags);

	/* Return the actual address to userspace */
	req.address = (u64)addr;
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;

	return 0;
}

/*
 * Handle PE_COMPAT_VFREE ioctl.
 *
 * Frees (unmaps) virtual memory in the calling process's address space.
 * Translates MEM_RELEASE / MEM_DECOMMIT to vm_munmap().
 */
static long pe_memory_vfree(unsigned long arg)
{
	struct pe_vfree_request req;
	int ret;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	if (!req.address)
		return -EINVAL;

	/*
	 * For MEM_RELEASE, Windows ignores the size parameter and frees
	 * the entire region.  We require the size to be passed (the
	 * userspace loader should track it) because Linux needs it.
	 * If size is 0, we use a reasonable default page size.
	 */
	if (req.size == 0 && (req.free_type & PE_MEM_RELEASE))
		req.size = PAGE_SIZE;

	ret = vm_munmap((unsigned long)req.address, (size_t)req.size);

	if (pe_debug >= 2)
		pr_debug("vfree: addr=0x%llx size=0x%llx type=0x%x ret=%d\n",
			 req.address, req.size, req.free_type, ret);

	return ret;
}

/*
 * Dispatch memory-related ioctls.
 * Called from pe_compat_ioctl.c when the command matches.
 */
long pe_memory_ioctl(unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case PE_COMPAT_VALLOC:
		return pe_memory_valloc(arg);
	case PE_COMPAT_VFREE:
		return pe_memory_vfree(arg);
	default:
		return -ENOTTY;
	}
}

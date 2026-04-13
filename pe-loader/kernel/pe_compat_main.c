// SPDX-License-Identifier: GPL-2.0
/*
 * pe_compat - Linux kernel module for transparent PE executable support
 *
 * This module provides:
 *   - binfmt handler so .exe files can be executed directly
 *   - /dev/pe_compat character device for loader <-> kernel communication
 *   - Optional kprobe-based NT syscall interception (fast path)
 *   - PE process tracking via /proc/pe_compat
 *
 * Copyright (c) 2025 Arch Linux AI Project
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "pe_compat_internal.h"
#include <compat/pe_compat_ioctl.h>

/* Module parameters */
int pe_debug;
module_param(pe_debug, int, 0644);
MODULE_PARM_DESC(pe_debug, "Debug verbosity level (0=off, 1=info, 2=verbose)");

int pe_syscall_mode;
module_param(pe_syscall_mode, int, 0644);
MODULE_PARM_DESC(pe_syscall_mode,
		 "Syscall interception mode (0=userspace only, 1=kprobe fast-path)");

static int __init pe_compat_init(void)
{
	int ret;

	pr_info("initializing PE compatibility layer v%d.%d\n",
		PE_COMPAT_VERSION_MAJOR, PE_COMPAT_VERSION_MINOR);

	/* Initialize process tracking first -- other subsystems query it */
	ret = pe_process_init();
	if (ret) {
		pr_err("failed to initialize process tracking: %d\n", ret);
		return ret;
	}

	/* Register the PE binfmt handler */
	ret = pe_binfmt_register();
	if (ret) {
		pr_err("failed to register binfmt handler: %d\n", ret);
		goto err_process;
	}

	/* Create /dev/pe_compat misc device */
	ret = pe_ioctl_init();
	if (ret) {
		pr_err("failed to create misc device: %d\n", ret);
		goto err_binfmt;
	}

	/* Initialize memory management helpers */
	pe_memory_init();

	/* Initialize optional syscall interception */
	if (pe_syscall_mode) {
		ret = pe_syscall_init();
		if (ret) {
			pr_warn("kprobe syscall interception unavailable: %d\n",
				ret);
			pr_warn("falling back to userspace-only mode\n");
			pe_syscall_mode = 0;
			/* Non-fatal: continue in userspace-only mode */
		}
	}

	pr_info("module loaded (debug=%d, syscall_mode=%d)\n",
		pe_debug, pe_syscall_mode);
	return 0;

err_binfmt:
	pe_binfmt_unregister();
err_process:
	pe_process_cleanup();
	return ret;
}

static void __exit pe_compat_exit(void)
{
	pr_info("unloading PE compatibility layer\n");

	if (pe_syscall_mode)
		pe_syscall_cleanup();

	pe_ioctl_cleanup();
	pe_binfmt_unregister();
	pe_process_cleanup();

	pr_info("module unloaded\n");
}

module_init(pe_compat_init);
module_exit(pe_compat_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arch Linux AI Project");
MODULE_DESCRIPTION("PE executable compatibility layer for Linux");
MODULE_VERSION("0.1");

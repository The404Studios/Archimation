// SPDX-License-Identifier: GPL-2.0
/*
 * pe_compat_ioctl.c - /dev/pe_compat character device
 *
 * Creates a misc device that serves as the communication channel
 * between the userspace PE loader and the kernel module.  The
 * device supports:
 *
 *   - ioctl:    process registration, status queries, memory ops
 *   - mmap:     (reserved for future shared-memory fast path)
 *   - open/release: per-fd bookkeeping
 *
 * See include/compat/pe_compat_ioctl.h for command definitions.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>

#include "pe_compat_internal.h"
#include <compat/pe_compat_ioctl.h>

/*
 * Per-open-fd state.  Each userspace peloader process opens
 * /dev/pe_compat once.  We track it here so we can auto-unregister
 * if the process exits without a clean UNREGISTER ioctl.
 */
struct pe_compat_fd {
	pid_t registered_pid;   /* PID registered through this fd, or 0 */
};

/* ------------------------------------------------------------------ */
/*  file_operations                                                    */
/* ------------------------------------------------------------------ */

static int pe_compat_open(struct inode *inode, struct file *filp)
{
	struct pe_compat_fd *fd_data;

	fd_data = kzalloc(sizeof(*fd_data), GFP_KERNEL);
	if (!fd_data)
		return -ENOMEM;

	filp->private_data = fd_data;

	if (pe_debug >= 2)
		pr_debug("device opened by pid %d\n", current->pid);

	return 0;
}

static int pe_compat_release(struct inode *inode, struct file *filp)
{
	struct pe_compat_fd *fd_data = filp->private_data;

	/*
	 * If the process registered itself but didn't explicitly
	 * unregister, clean up now.
	 */
	if (fd_data && fd_data->registered_pid) {
		if (pe_debug >= 1)
			pr_info("auto-unregistering pid %d on fd close\n",
				fd_data->registered_pid);
		pe_process_unregister(fd_data->registered_pid);
	}

	kfree(fd_data);
	return 0;
}

/* ------------------------------------------------------------------ */
/*  ioctl dispatch                                                     */
/* ------------------------------------------------------------------ */

static long pe_compat_ioctl_register(struct pe_compat_fd *fd_data,
				     unsigned long arg)
{
	struct pe_process_info info;
	int ret;

	if (copy_from_user(&info, (void __user *)arg, sizeof(info)))
		return -EFAULT;

	/* If pid is 0, use the caller's pid */
	if (info.pid == 0)
		info.pid = current->pid;

	ret = pe_process_register(info.pid, info.image_base, info.image_size,
				  info.subsystem, info.nt_version);
	if (ret)
		return ret;

	fd_data->registered_pid = info.pid;

	if (pe_debug >= 1)
		pr_info("registered PE process pid=%d base=0x%llx size=0x%llx\n",
			info.pid, info.image_base, info.image_size);

	return 0;
}

static long pe_compat_ioctl_unregister(struct pe_compat_fd *fd_data,
				       unsigned long arg)
{
	int32_t pid;

	if (copy_from_user(&pid, (void __user *)arg, sizeof(pid)))
		return -EFAULT;

	if (pid == 0)
		pid = current->pid;

	pe_process_unregister(pid);

	if (fd_data->registered_pid == pid)
		fd_data->registered_pid = 0;

	if (pe_debug >= 1)
		pr_info("unregistered PE process pid=%d\n", pid);

	return 0;
}

static long pe_compat_ioctl_status(unsigned long arg)
{
	struct pe_compat_status status = {
		.version_major       = PE_COMPAT_VERSION_MAJOR,
		.version_minor       = PE_COMPAT_VERSION_MINOR,
		.registered_processes = pe_process_count(),
		.intercepted_syscalls = pe_syscall_intercepted_count(),
		.flags               = pe_syscall_mode ? 1 : 0,
	};

	if (copy_to_user((void __user *)arg, &status, sizeof(status)))
		return -EFAULT;

	return 0;
}

static long pe_compat_ioctl_set_syscall_mode(unsigned long arg)
{
	struct pe_syscall_mode mode;

	if (copy_from_user(&mode, (void __user *)arg, sizeof(mode)))
		return -EFAULT;

	/*
	 * Switching modes at runtime:
	 *   0 -> 1: enable kprobe interception
	 *   1 -> 0: disable kprobe interception
	 *
	 * For now we only allow the global mode to be toggled.
	 * Per-process mode is planned for a future version.
	 */
	if (mode.mode == 1 && !pe_syscall_mode) {
		int ret = pe_syscall_init();

		if (ret)
			return ret;
		pe_syscall_mode = 1;
	} else if (mode.mode == 0 && pe_syscall_mode) {
		pe_syscall_cleanup();
		pe_syscall_mode = 0;
	}

	if (pe_debug >= 1)
		pr_info("syscall mode set to %u\n", mode.mode);

	return 0;
}

static long pe_compat_unlocked_ioctl(struct file *filp, unsigned int cmd,
				     unsigned long arg)
{
	struct pe_compat_fd *fd_data = filp->private_data;

	switch (cmd) {
	case PE_COMPAT_REGISTER_PROCESS:
		return pe_compat_ioctl_register(fd_data, arg);

	case PE_COMPAT_UNREGISTER_PROCESS:
		return pe_compat_ioctl_unregister(fd_data, arg);

	case PE_COMPAT_QUERY_STATUS:
		return pe_compat_ioctl_status(arg);

	case PE_COMPAT_SET_SYSCALL_MODE:
		return pe_compat_ioctl_set_syscall_mode(arg);

	case PE_COMPAT_VALLOC:
	case PE_COMPAT_VFREE:
		return pe_memory_ioctl(cmd, arg);

	default:
		return -ENOTTY;
	}
}

/* ------------------------------------------------------------------ */
/*  mmap (reserved for future shared-memory fast path)                 */
/* ------------------------------------------------------------------ */

static int pe_compat_mmap(struct file *filp, struct vm_area_struct *vma)
{
	/*
	 * Not yet implemented.  A future version will use this to
	 * set up a shared ring buffer between the kernel module and
	 * the userspace loader for high-frequency syscall forwarding.
	 */
	return -ENOSYS;
}

/* ------------------------------------------------------------------ */
/*  Device registration                                                */
/* ------------------------------------------------------------------ */

static const struct file_operations pe_compat_fops = {
	.owner          = THIS_MODULE,
	.open           = pe_compat_open,
	.release        = pe_compat_release,
	.unlocked_ioctl = pe_compat_unlocked_ioctl,
	.compat_ioctl   = pe_compat_unlocked_ioctl,
	.mmap           = pe_compat_mmap,
};

static struct miscdevice pe_compat_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "pe_compat",
	.fops  = &pe_compat_fops,
	.mode  = 0666,
};

int pe_ioctl_init(void)
{
	int ret;

	ret = misc_register(&pe_compat_dev);
	if (ret) {
		pr_err("failed to register /dev/pe_compat: %d\n", ret);
		return ret;
	}

	pr_info("created /dev/pe_compat (minor %d)\n", pe_compat_dev.minor);
	return 0;
}

void pe_ioctl_cleanup(void)
{
	misc_deregister(&pe_compat_dev);
	pr_info("removed /dev/pe_compat\n");
}

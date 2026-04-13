// SPDX-License-Identifier: GPL-2.0
/*
 * pe_compat_syscall.c - Optional NT syscall interception via kprobes
 *
 * When pe_syscall_mode=1, this module installs a kprobe on the kernel's
 * syscall entry path.  For processes that have been registered as PE
 * executables (via the /dev/pe_compat ioctl), we inspect the syscall
 * number in RAX.  If it falls in the NT syscall range, we signal the
 * userspace handler through the pe_compat device rather than letting
 * the kernel return -ENOSYS.
 *
 * This is entirely optional.  The default (pe_syscall_mode=0) lets
 * the userspace loader handle everything via signal trampolines.
 *
 * NT syscall numbers used here are from Windows 10 21H2 (64-bit).
 * See include/compat/syscall_map.h for the full table.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/sched.h>

#include "pe_compat_internal.h"

/*
 * NT syscall numbers of interest.
 * We only intercept the most performance-critical ones at kernel level;
 * everything else goes through the userspace fast-path.
 */
#define NT_ALLOCATE_VIRTUAL_MEMORY  0x0018
#define NT_FREE_VIRTUAL_MEMORY      0x001E
#define NT_CREATE_FILE              0x0055
#define NT_READ_FILE                0x0006
#define NT_WRITE_FILE               0x0008
#define NT_CLOSE                    0x000F
#define NT_QUERY_SYSTEM_INFO        0x0036

/*
 * The highest NT syscall number we will ever try to intercept.
 * Anything above this is definitely not an NT syscall.
 */
#define NT_SYSCALL_MAX 0x0200

static struct kprobe pe_kprobe;
static bool kprobe_registered;
static atomic64_t syscall_intercept_count = ATOMIC64_INIT(0);

u64 pe_syscall_intercepted_count(void)
{
	return atomic64_read(&syscall_intercept_count);
}

/*
 * Pre-handler: called before the probed instruction executes.
 *
 * We check whether the current process is a registered PE process
 * and whether RAX contains something that looks like an NT syscall
 * number.  If so, we can optionally short-circuit it.
 *
 * In this initial implementation we simply log the event and let
 * the normal path continue.  A future version will redirect to
 * the userspace handler via a completion/eventfd mechanism.
 */
static int pe_kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long syscall_nr;
	pid_t pid;

	pid = current->pid;

	/* Fast path: skip if this process is not a PE executable */
	if (!pe_process_is_pe(pid))
		return 0;

	syscall_nr = regs->ax;

	/* Filter: only consider plausible NT syscall numbers */
	if (syscall_nr > NT_SYSCALL_MAX)
		return 0;

	if (pe_debug >= 2)
		pr_debug("pid %d: NT syscall 0x%lx (rcx=0x%lx rdx=0x%lx)\n",
			 pid, syscall_nr,
			 regs->cx, regs->dx);

	/*
	 * Count the interception and let it fall through to the userspace
	 * handler. A future version could handle fast-path syscalls
	 * (VirtualAlloc, VirtualFree) directly here by modifying regs->ax
	 * with the return value and returning 1 to skip the instruction.
	 */
	atomic64_inc(&syscall_intercept_count);

	return 0;
}

int pe_syscall_init(void)
{
	int ret;

	/*
	 * We probe the syscall entry point.  The symbol name varies
	 * between kernel versions:
	 *   - "do_syscall_64" (5.x+)
	 *   - "__x64_sys_call" (some 6.x)
	 *
	 * Try the most common one first.
	 */
	pe_kprobe.pre_handler = pe_kprobe_pre_handler;
	pe_kprobe.symbol_name = "do_syscall_64";

	ret = register_kprobe(&pe_kprobe);
	if (ret < 0) {
		pr_warn("failed to register kprobe on do_syscall_64: %d\n",
			ret);
		return ret;
	}

	kprobe_registered = true;
	pr_info("kprobe syscall interception active on <%s+0x%lx>\n",
		pe_kprobe.symbol_name,
		(unsigned long)pe_kprobe.offset);

	return 0;
}

void pe_syscall_cleanup(void)
{
	if (kprobe_registered) {
		unregister_kprobe(&pe_kprobe);
		kprobe_registered = false;
		pr_info("kprobe syscall interception removed\n");
	}
}

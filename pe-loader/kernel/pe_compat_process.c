// SPDX-License-Identifier: GPL-2.0
/*
 * pe_compat_process.c - PE process tracking
 *
 * Maintains a list of processes that are currently executing PE
 * binaries.  This is used by:
 *
 *   - pe_compat_syscall.c to decide whether to intercept syscalls
 *   - /proc/pe_compat to expose status information
 *   - pe_compat_ioctl.c for status queries
 *
 * The list is protected by a spinlock for the fast lookup path
 * (pe_process_is_pe) and a mutex for structural modifications.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/hashtable.h>

#include "pe_compat_internal.h"
#include <compat/pe_compat_ioctl.h>

/*
 * Hash table size: 2^PE_PROC_HASH_BITS buckets.
 * 8 bits = 256 buckets, good enough for typical workloads.
 */
#define PE_PROC_HASH_BITS 8

struct pe_proc_entry {
	struct hlist_node  hash_node;
	pid_t              pid;
	u64                image_base;
	u64                image_size;
	u32                subsystem;
	u32                nt_version;
	ktime_t            start_time;
};

static DEFINE_HASHTABLE(pe_proc_table, PE_PROC_HASH_BITS);
static DEFINE_SPINLOCK(pe_proc_lock);
static DEFINE_MUTEX(pe_proc_modify_lock);
static u32 pe_proc_count;

static struct proc_dir_entry *pe_proc_dir;

/* ------------------------------------------------------------------ */
/*  Lookup helpers                                                     */
/* ------------------------------------------------------------------ */

/*
 * Look up a process by PID.  Must be called with pe_proc_lock held
 * (read side) or pe_proc_modify_lock held (write side).
 */
static struct pe_proc_entry *pe_proc_find_locked(pid_t pid)
{
	struct pe_proc_entry *entry;

	hash_for_each_possible(pe_proc_table, entry, hash_node, pid) {
		if (entry->pid == pid)
			return entry;
	}
	return NULL;
}

bool pe_process_is_pe(pid_t pid)
{
	bool found;

	rcu_read_lock();
	spin_lock(&pe_proc_lock);
	found = pe_proc_find_locked(pid) != NULL;
	spin_unlock(&pe_proc_lock);
	rcu_read_unlock();

	return found;
}

u32 pe_process_count(void)
{
	return READ_ONCE(pe_proc_count);
}

/* ------------------------------------------------------------------ */
/*  Registration / unregistration                                      */
/* ------------------------------------------------------------------ */

int pe_process_register(pid_t pid, u64 image_base, u64 image_size,
			u32 subsystem, u32 nt_version)
{
	struct pe_proc_entry *entry;

	mutex_lock(&pe_proc_modify_lock);

	/* Check for duplicate */
	spin_lock(&pe_proc_lock);
	if (pe_proc_find_locked(pid)) {
		spin_unlock(&pe_proc_lock);
		mutex_unlock(&pe_proc_modify_lock);
		return -EEXIST;
	}
	spin_unlock(&pe_proc_lock);

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		mutex_unlock(&pe_proc_modify_lock);
		return -ENOMEM;
	}

	entry->pid        = pid;
	entry->image_base = image_base;
	entry->image_size = image_size;
	entry->subsystem  = subsystem;
	entry->nt_version = nt_version;
	entry->start_time = ktime_get();

	spin_lock(&pe_proc_lock);
	hash_add(pe_proc_table, &entry->hash_node, pid);
	pe_proc_count++;
	spin_unlock(&pe_proc_lock);

	mutex_unlock(&pe_proc_modify_lock);

	if (pe_debug >= 1)
		pr_info("tracking PE process pid=%d base=0x%llx\n",
			pid, image_base);

	return 0;
}

int pe_process_unregister(pid_t pid)
{
	struct pe_proc_entry *entry;

	mutex_lock(&pe_proc_modify_lock);

	spin_lock(&pe_proc_lock);
	entry = pe_proc_find_locked(pid);
	if (!entry) {
		spin_unlock(&pe_proc_lock);
		mutex_unlock(&pe_proc_modify_lock);
		return -ESRCH;
	}

	hash_del(&entry->hash_node);
	pe_proc_count--;
	spin_unlock(&pe_proc_lock);

	mutex_unlock(&pe_proc_modify_lock);

	if (pe_debug >= 1)
		pr_info("stopped tracking PE process pid=%d\n", pid);

	kfree(entry);
	return 0;
}

/* ------------------------------------------------------------------ */
/*  /proc/pe_compat                                                    */
/* ------------------------------------------------------------------ */

static int pe_proc_show(struct seq_file *m, void *v)
{
	struct pe_proc_entry *entry;
	unsigned int bkt;

	seq_printf(m, "PE Compatibility Layer v%d.%d\n",
		   PE_COMPAT_VERSION_MAJOR, PE_COMPAT_VERSION_MINOR);
	seq_printf(m, "Syscall mode: %s\n",
		   pe_syscall_mode ? "kprobe" : "userspace");
	seq_printf(m, "Debug level: %d\n", pe_debug);
	seq_printf(m, "Registered processes: %u\n\n",
		   pe_process_count());

	seq_puts(m, "PID       IMAGE_BASE       IMAGE_SIZE  SUBSYS  NTVER  AGE(ms)\n");
	seq_puts(m, "--------- ---------------- ----------- ------- ------ --------\n");

	spin_lock(&pe_proc_lock);
	hash_for_each(pe_proc_table, bkt, entry, hash_node) {
		s64 age_ms = ktime_ms_delta(ktime_get(), entry->start_time);

		seq_printf(m, "%-9d 0x%014llx 0x%09llx %-7u 0x%04x %lld\n",
			   entry->pid,
			   entry->image_base,
			   entry->image_size,
			   entry->subsystem,
			   entry->nt_version,
			   age_ms);
	}
	spin_unlock(&pe_proc_lock);

	return 0;
}

static int pe_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, pe_proc_show, NULL);
}

static const struct proc_ops pe_proc_ops = {
	.proc_open    = pe_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ------------------------------------------------------------------ */
/*  Init / cleanup                                                     */
/* ------------------------------------------------------------------ */

int pe_process_init(void)
{
	hash_init(pe_proc_table);
	pe_proc_count = 0;

	pe_proc_dir = proc_create("pe_compat", 0444, NULL, &pe_proc_ops);
	if (!pe_proc_dir) {
		pr_err("failed to create /proc/pe_compat\n");
		return -ENOMEM;
	}

	pr_info("process tracking initialized (/proc/pe_compat)\n");
	return 0;
}

void pe_process_cleanup(void)
{
	struct pe_proc_entry *entry;
	struct hlist_node *tmp;
	unsigned int bkt;

	/* Remove proc entry first to stop new readers */
	if (pe_proc_dir)
		proc_remove(pe_proc_dir);

	/* Free all tracked processes */
	mutex_lock(&pe_proc_modify_lock);
	spin_lock(&pe_proc_lock);
	hash_for_each_safe(pe_proc_table, bkt, tmp, entry, hash_node) {
		hash_del(&entry->hash_node);
		kfree(entry);
	}
	pe_proc_count = 0;
	spin_unlock(&pe_proc_lock);
	mutex_unlock(&pe_proc_modify_lock);

	pr_info("process tracking cleaned up\n");
}

/*
 * trust_compat.h - Kernel-version compatibility shims for trust.ko
 *
 * Session 49 (2026-04-18, Agent E): kernel 6.18+ no longer exports
 * find_task_by_vpid() to modules.  We provide an exported-API equivalent
 * built on find_get_pid() + get_pid_task(), both of which ARE exported.
 *
 * The returned task_struct (when non-NULL) carries a +1 task refcount that
 * the caller MUST release with put_task_struct().  The transient pid
 * refcount taken by find_get_pid() is released inside the helper.
 *
 * This is the Option-A (refactor-to-exported-APIs) path from the Session 49
 * playbook.  No kallsyms tricks, no kprobe ABI abuse — purely the GPL-safe
 * exported pid API, so the module remains loadable on stock distro kernels
 * with no boot-time symbol probing.
 */

#ifndef TRUST_COMPAT_H
#define TRUST_COMPAT_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/pid.h>

/*
 * trust_find_task_by_vpid_get - resolve a virtual PID to a task with a held ref
 * @vpid:  virtual PID (in caller's PID namespace, via find_get_pid semantics)
 *
 * Returns a task_struct* with one task reference held, or NULL if no such
 * task exists.  The caller must release the reference with put_task_struct().
 *
 * Lifetime:
 *   find_get_pid(vpid)         -> +1 pid ref on the struct pid
 *   get_pid_task(p, PIDTYPE_PID) -> +1 task ref on the task_struct
 *   put_pid(p)                 -> -1 pid ref (always done before return)
 *   caller's put_task_struct() -> -1 task ref (caller responsibility)
 *
 * Safe to call from process context with no locks held.  May sleep
 * (RCU-readers in get_pid_task may briefly contend); do NOT call from
 * atomic context — but neither could the original find_task_by_vpid()
 * usage in trust_memory.c, which already executed under rcu_read_lock()
 * solely to gate get_task_struct(), not because the surrounding code
 * was atomic.
 */
static inline struct task_struct *trust_find_task_by_vpid_get(pid_t vpid)
{
	struct pid *p;
	struct task_struct *t;

	if (vpid <= 0)
		return NULL;

	p = find_get_pid(vpid);
	if (!p)
		return NULL;

	t = get_pid_task(p, PIDTYPE_PID);
	put_pid(p);
	return t;
}

#endif /* TRUST_COMPAT_H */

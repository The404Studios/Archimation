/*
 * trust_syscall.c - Syscall interception for trust-tracked PE processes
 *
 * Hooks key syscall entry points via kprobes and emits events when
 * trust-tracked PE processes make interesting calls. This allows the
 * AI to see what Windows APIs the PE is trying to use at the Linux
 * syscall level.
 *
 * Architecture:
 *   - PID bitmap for O(1) "is this PID traced?" checks in hot path
 *   - Per-PID ring buffer of recent syscall events (TSC_RING_SIZE entries)
 *   - Per-PID syscall frequency counters (indexed by NR)
 *   - kprobes on __x64_sys_openat, __x64_sys_read, __x64_sys_write,
 *     __x64_sys_ioctl, __x64_sys_socket, __x64_sys_connect,
 *     __x64_sys_bind, __x64_sys_mmap, __x64_sys_clone
 *   - kretprobes to capture return values
 *   - Netlink socket pushes events to userspace AI daemon
 *
 * Part of the Root of Authority kernel module (trust.ko).
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/bitmap.h>
#include <linux/hashtable.h>
#include <linux/cache.h>
#include <net/sock.h>

#include "trust_internal.h"
#include "trust_syscall.h"

/* ========================================================================
 * Global TSC state
 * ======================================================================== */

/*
 * PID bitmap for O(1) "is this PID traced?" checks.
 * Linux PIDs are limited to PID_MAX_LIMIT (usually 4194304).
 * We use a bitmap covering the common range (32768 default).
 * For PIDs above the bitmap range, fall back to linear scan.
 */
#define TSC_PID_BITMAP_SIZE     32768

/*
 * False-sharing layout:
 *   - `enabled` and `slots`/`max_slots`/`pid_bitmap` are read on the hot
 *     path (kprobe handler, once per traced syscall) from every CPU.
 *   - `event_seq` is incremented (atomic_inc_return) on every emitted
 *     event — every CPU that hits a kprobe writes it.  If it sits in
 *     the same cacheline as the read-mostly pointers/flags, every write
 *     invalidates every CPU's next hot-path read.
 * Split event_seq onto its own cacheline so the pointer/flag cluster
 * stays shared-clean across all CPUs.
 */
static struct {
    struct tsc_pid_slot *slots;         /* Array of TSC_MAX_SUBJECTS slots */
    u32                  max_slots;
    unsigned long       *pid_bitmap;    /* O(1) PID lookup */
    struct sock         *nl_sock;       /* Netlink socket for events */
    bool                 enabled;
    /* event_seq: written by every CPU on every emitted syscall event. */
    atomic_t             event_seq      ____cacheline_aligned_in_smp;
} g_tsc;

/* ========================================================================
 * PID lookup (hot path -- must be fast)
 * ======================================================================== */

/*
 * Check if a PID is being traced. O(1) for PIDs in bitmap range.
 */
int tsc_is_pid_traced(pid_t pid)
{
    if (!g_tsc.enabled || !g_tsc.pid_bitmap)
        return 0;

    if (pid < TSC_PID_BITMAP_SIZE)
        return test_bit(pid, g_tsc.pid_bitmap) ? 1 : 0;

    /* Fallback: linear scan for large PIDs */
    return tsc_find_slot_by_pid(pid) != NULL;
}

/*
 * Find the tracking slot for a given PID.
 * Returns NULL if not found or not active.
 */
struct tsc_pid_slot *tsc_find_slot_by_pid(pid_t pid)
{
    u32 i;

    if (!g_tsc.slots)
        return NULL;

    for (i = 0; i < g_tsc.max_slots; i++) {
        if (g_tsc.slots[i].active && g_tsc.slots[i].pid == pid)
            return &g_tsc.slots[i];
    }
    return NULL;
}

/*
 * Find a free slot in the tracking array.
 */
static struct tsc_pid_slot *tsc_find_free_slot(void)
{
    u32 i;

    if (!g_tsc.slots)
        return NULL;

    for (i = 0; i < g_tsc.max_slots; i++) {
        if (!g_tsc.slots[i].active)
            return &g_tsc.slots[i];
    }
    return NULL;
}

/* ========================================================================
 * Event recording
 * ======================================================================== */

/*
 * Record a syscall event into the per-PID ring buffer and emit via netlink.
 */
static void tsc_record_event(struct tsc_pid_slot *slot, u16 syscall_nr,
                              u8 category, u64 arg0, u64 arg1, u64 arg2,
                              s64 retval)
{
    struct tsc_event *ev;
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    struct tsc_event_msg *msg;
    int msg_size;
    pid_t caller_pid = current->pid;
    u64 ts_ns;              /* Local copy: ev is invalid after unlock. */
    u32 slot_subject_id;
    pid_t slot_pid;

    /* Record in ring buffer */
    spin_lock(&slot->lock);
    /*
     * Re-verify slot identity under the lock.  Between the caller's
     * tsc_find_slot_by_pid() and this spin_lock(), tsc_stop_trace()
     * followed by tsc_start_trace() can reuse the slot for a different
     * PID — writing the event then would pollute another PID's ring.
     */
    if (!slot->active || slot->pid != caller_pid) {
        spin_unlock(&slot->lock);
        return;
    }

    /* Check category filter under lock (category_mask may be updated). */
    if (!(slot->category_mask & category)) {
        spin_unlock(&slot->lock);
        return;
    }

    ev = &slot->ring[slot->ring_head % TSC_RING_SIZE];
    ev->subject_id = slot->subject_id;
    ev->pid = slot->pid;
    ev->syscall_nr = syscall_nr;
    ev->category = category;
    ev->arg0 = arg0;
    ev->arg1 = arg1;
    ev->arg2 = arg2;
    ev->return_value = retval;
    ts_ns = ktime_get_ns();
    ev->timestamp_ns = ts_ns;
    slot->ring_head = (slot->ring_head + 1) % TSC_RING_SIZE;
    if (slot->ring_count < TSC_RING_SIZE)
        slot->ring_count++;

    /* Update stats counter */
    if (syscall_nr < 512)
        slot->stats[syscall_nr]++;

    /* Snapshot slot identity for the netlink message: after we drop
     * slot->lock the slot can be racily reused by tsc_stop_trace/
     * tsc_start_trace and overwritten. */
    slot_subject_id = slot->subject_id;
    slot_pid = slot->pid;
    spin_unlock(&slot->lock);

    /* Emit via netlink */
    if (!g_tsc.nl_sock)
        return;

    msg_size = sizeof(struct tsc_event_msg);
    skb = nlmsg_new(msg_size, GFP_ATOMIC);
    if (!skb)
        return;

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, msg_size, 0);
    if (!nlh) {
        kfree_skb(skb);
        return;
    }

    msg = nlmsg_data(nlh);
    memset(msg, 0, sizeof(*msg));
    msg->seq = (u32)atomic_inc_return(&g_tsc.event_seq);
    msg->subject_id = slot_subject_id;
    msg->pid = slot_pid;
    msg->syscall_nr = syscall_nr;
    msg->category = category;
    msg->arg0 = arg0;
    msg->arg1 = arg1;
    msg->arg2 = arg2;
    msg->return_value = retval;
    msg->timestamp_ns = ts_ns;

    NETLINK_CB(skb).dst_group = TSC_NETLINK_GROUP;
    nlmsg_multicast(g_tsc.nl_sock, skb, 0, TSC_NETLINK_GROUP, GFP_ATOMIC);
}

/* ========================================================================
 * kprobe handlers
 *
 * x86_64 System V ABI: arg0=rdi, arg1=rsi, arg2=rdx, arg3=rcx, arg4=r8
 *
 * For __x64_sys_* functions, the kernel passes a pointer to struct pt_regs
 * in rdi. The actual syscall arguments are in the *inner* pt_regs:
 *   arg0=inner->di, arg1=inner->si, arg2=inner->dx,
 *   arg3=inner->r10, arg4=inner->r8, arg5=inner->r9
 *
 * We use the outer regs->di to get the inner pt_regs pointer, then read
 * arguments from there. In kprobe pre-handlers we cannot safely
 * dereference that pointer (it could fault), so we read the outer
 * pt_regs arguments directly. For __x64_sys_* wrappers, the kernel
 * passes the user-side pt_regs in rdi, so we cast and read.
 * ======================================================================== */

/*
 * Helper: get the inner pt_regs from a __x64_sys_* kprobe.
 * Returns NULL if the pointer looks invalid.
 */
static inline struct pt_regs *tsc_get_inner_regs(struct pt_regs *regs)
{
    struct pt_regs *inner = (struct pt_regs *)regs->di;

    /* Basic sanity: must be a kernel address */
    if ((unsigned long)inner < PAGE_OFFSET)
        return NULL;
    return inner;
}

/* --- __x64_sys_openat(int dfd, const char __user *filename, int flags, umode_t mode) --- */
static int tsc_kp_openat_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct tsc_pid_slot *slot;
    struct pt_regs *inner;
    pid_t pid;

    (void)p;
    if (!g_tsc.enabled)
        return 0;

    pid = current->pid;
    if (!tsc_is_pid_traced(pid))
        return 0;

    slot = tsc_find_slot_by_pid(pid);
    if (!slot)
        return 0;

    inner = tsc_get_inner_regs(regs);
    if (inner) {
        /* arg0=dfd(di), arg1=filename(si), arg2=flags(dx) */
        tsc_record_event(slot, TSC_NR_OPENAT, TSC_CAT_FILE,
                          inner->di, inner->si, inner->dx, 0);
    }
    return 0;
}

/* --- __x64_sys_read(unsigned int fd, char __user *buf, size_t count) --- */
static int tsc_kp_read_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct tsc_pid_slot *slot;
    struct pt_regs *inner;
    pid_t pid;

    (void)p;
    if (!g_tsc.enabled)
        return 0;

    pid = current->pid;
    if (!tsc_is_pid_traced(pid))
        return 0;

    slot = tsc_find_slot_by_pid(pid);
    if (!slot)
        return 0;

    inner = tsc_get_inner_regs(regs);
    if (inner) {
        /* arg0=fd(di), arg1=buf(si), arg2=count(dx) */
        tsc_record_event(slot, TSC_NR_READ, TSC_CAT_FILE,
                          inner->di, 0, inner->dx, 0);
    }
    return 0;
}

/* --- __x64_sys_write(unsigned int fd, const char __user *buf, size_t count) --- */
static int tsc_kp_write_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct tsc_pid_slot *slot;
    struct pt_regs *inner;
    pid_t pid;

    (void)p;
    if (!g_tsc.enabled)
        return 0;

    pid = current->pid;
    if (!tsc_is_pid_traced(pid))
        return 0;

    slot = tsc_find_slot_by_pid(pid);
    if (!slot)
        return 0;

    inner = tsc_get_inner_regs(regs);
    if (inner) {
        /* arg0=fd(di), arg1=buf(si), arg2=count(dx) */
        tsc_record_event(slot, TSC_NR_WRITE, TSC_CAT_FILE,
                          inner->di, 0, inner->dx, 0);
    }
    return 0;
}

/* --- __x64_sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg) --- */
static int tsc_kp_ioctl_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct tsc_pid_slot *slot;
    struct pt_regs *inner;
    pid_t pid;

    (void)p;
    if (!g_tsc.enabled)
        return 0;

    pid = current->pid;
    if (!tsc_is_pid_traced(pid))
        return 0;

    slot = tsc_find_slot_by_pid(pid);
    if (!slot)
        return 0;

    inner = tsc_get_inner_regs(regs);
    if (inner) {
        /* arg0=fd(di), arg1=cmd(si), arg2=arg(dx) */
        tsc_record_event(slot, TSC_NR_IOCTL, TSC_CAT_FILE,
                          inner->di, inner->si, inner->dx, 0);
    }
    return 0;
}

/* --- __x64_sys_socket(int family, int type, int protocol) --- */
static int tsc_kp_socket_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct tsc_pid_slot *slot;
    struct pt_regs *inner;
    pid_t pid;

    (void)p;
    if (!g_tsc.enabled)
        return 0;

    pid = current->pid;
    if (!tsc_is_pid_traced(pid))
        return 0;

    slot = tsc_find_slot_by_pid(pid);
    if (!slot)
        return 0;

    inner = tsc_get_inner_regs(regs);
    if (inner) {
        /* arg0=family(di), arg1=type(si), arg2=protocol(dx) */
        tsc_record_event(slot, TSC_NR_SOCKET, TSC_CAT_NETWORK,
                          inner->di, inner->si, inner->dx, 0);
    }
    return 0;
}

/* --- __x64_sys_connect(int fd, struct sockaddr __user *addr, int addrlen) --- */
static int tsc_kp_connect_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct tsc_pid_slot *slot;
    struct pt_regs *inner;
    pid_t pid;

    (void)p;
    if (!g_tsc.enabled)
        return 0;

    pid = current->pid;
    if (!tsc_is_pid_traced(pid))
        return 0;

    slot = tsc_find_slot_by_pid(pid);
    if (!slot)
        return 0;

    inner = tsc_get_inner_regs(regs);
    if (inner) {
        /* arg0=fd(di), arg1=addr(si), arg2=addrlen(dx) */
        tsc_record_event(slot, TSC_NR_CONNECT, TSC_CAT_NETWORK,
                          inner->di, inner->si, inner->dx, 0);
    }
    return 0;
}

/* --- __x64_sys_bind(int fd, struct sockaddr __user *addr, int addrlen) --- */
static int tsc_kp_bind_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct tsc_pid_slot *slot;
    struct pt_regs *inner;
    pid_t pid;

    (void)p;
    if (!g_tsc.enabled)
        return 0;

    pid = current->pid;
    if (!tsc_is_pid_traced(pid))
        return 0;

    slot = tsc_find_slot_by_pid(pid);
    if (!slot)
        return 0;

    inner = tsc_get_inner_regs(regs);
    if (inner) {
        /* arg0=fd(di), arg1=addr(si), arg2=addrlen(dx) */
        tsc_record_event(slot, TSC_NR_BIND, TSC_CAT_NETWORK,
                          inner->di, inner->si, inner->dx, 0);
    }
    return 0;
}

/* --- __x64_sys_mmap (via do_mmap -- already tracked by TMS, add syscall context) --- */
static int tsc_kp_mmap_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct tsc_pid_slot *slot;
    struct pt_regs *inner;
    pid_t pid;

    (void)p;
    if (!g_tsc.enabled)
        return 0;

    pid = current->pid;
    if (!tsc_is_pid_traced(pid))
        return 0;

    slot = tsc_find_slot_by_pid(pid);
    if (!slot)
        return 0;

    inner = tsc_get_inner_regs(regs);
    if (inner) {
        /* arg0=addr(di), arg1=len(si), arg2=prot(dx) */
        tsc_record_event(slot, TSC_NR_MMAP, TSC_CAT_MEMORY,
                          inner->di, inner->si, inner->dx, 0);
    }
    return 0;
}

/* --- __x64_sys_clone(unsigned long flags, ...) --- */
static int tsc_kp_clone_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct tsc_pid_slot *slot;
    struct pt_regs *inner;
    pid_t pid;

    (void)p;
    if (!g_tsc.enabled)
        return 0;

    pid = current->pid;
    if (!tsc_is_pid_traced(pid))
        return 0;

    slot = tsc_find_slot_by_pid(pid);
    if (!slot)
        return 0;

    inner = tsc_get_inner_regs(regs);
    if (inner) {
        /* arg0=clone_flags(di), arg1=newsp(si), arg2=parent_tidptr(dx) */
        tsc_record_event(slot, TSC_NR_CLONE, TSC_CAT_PROCESS,
                          inner->di, inner->si, inner->dx, 0);
    }
    return 0;
}

/* ========================================================================
 * kretprobe handlers — capture return values
 *
 * Each kretprobe stores the PID + syscall_nr at entry, then updates
 * the most recent ring entry for that PID on return.
 * ======================================================================== */

struct tsc_retprobe_data {
    pid_t   pid;
    u16     syscall_nr;
};

static int tsc_kretp_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tsc_retprobe_data *data;

    (void)regs;

    if (!g_tsc.enabled)
        return 1;  /* Skip this instance */

    if (!tsc_is_pid_traced(current->pid))
        return 1;

    data = (struct tsc_retprobe_data *)ri->data;
    data->pid = current->pid;
    return 0;
}

static int tsc_kretp_openat_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tsc_retprobe_data *data = (struct tsc_retprobe_data *)ri->data;
    struct tsc_pid_slot *slot;
    struct tsc_event *ev;
    u32 prev_idx;

    slot = tsc_find_slot_by_pid(data->pid);
    if (!slot || !slot->ring_count)
        return 0;

    spin_lock(&slot->lock);
    /* Update the most recent event's return value */
    prev_idx = (slot->ring_head + TSC_RING_SIZE - 1) % TSC_RING_SIZE;
    ev = &slot->ring[prev_idx];
    if (ev->pid == data->pid && ev->syscall_nr == TSC_NR_OPENAT)
        ev->return_value = (s64)regs_return_value(regs);
    spin_unlock(&slot->lock);
    return 0;
}

static int tsc_kretp_read_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tsc_retprobe_data *data = (struct tsc_retprobe_data *)ri->data;
    struct tsc_pid_slot *slot;
    struct tsc_event *ev;
    u32 prev_idx;

    slot = tsc_find_slot_by_pid(data->pid);
    if (!slot || !slot->ring_count)
        return 0;

    spin_lock(&slot->lock);
    prev_idx = (slot->ring_head + TSC_RING_SIZE - 1) % TSC_RING_SIZE;
    ev = &slot->ring[prev_idx];
    if (ev->pid == data->pid && ev->syscall_nr == TSC_NR_READ)
        ev->return_value = (s64)regs_return_value(regs);
    spin_unlock(&slot->lock);
    return 0;
}

static int tsc_kretp_write_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tsc_retprobe_data *data = (struct tsc_retprobe_data *)ri->data;
    struct tsc_pid_slot *slot;
    struct tsc_event *ev;
    u32 prev_idx;

    slot = tsc_find_slot_by_pid(data->pid);
    if (!slot || !slot->ring_count)
        return 0;

    spin_lock(&slot->lock);
    prev_idx = (slot->ring_head + TSC_RING_SIZE - 1) % TSC_RING_SIZE;
    ev = &slot->ring[prev_idx];
    if (ev->pid == data->pid && ev->syscall_nr == TSC_NR_WRITE)
        ev->return_value = (s64)regs_return_value(regs);
    spin_unlock(&slot->lock);
    return 0;
}

static int tsc_kretp_ioctl_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tsc_retprobe_data *data = (struct tsc_retprobe_data *)ri->data;
    struct tsc_pid_slot *slot;
    struct tsc_event *ev;
    u32 prev_idx;

    slot = tsc_find_slot_by_pid(data->pid);
    if (!slot || !slot->ring_count)
        return 0;

    spin_lock(&slot->lock);
    prev_idx = (slot->ring_head + TSC_RING_SIZE - 1) % TSC_RING_SIZE;
    ev = &slot->ring[prev_idx];
    if (ev->pid == data->pid && ev->syscall_nr == TSC_NR_IOCTL)
        ev->return_value = (s64)regs_return_value(regs);
    spin_unlock(&slot->lock);
    return 0;
}

static int tsc_kretp_socket_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tsc_retprobe_data *data = (struct tsc_retprobe_data *)ri->data;
    struct tsc_pid_slot *slot;
    struct tsc_event *ev;
    u32 prev_idx;

    slot = tsc_find_slot_by_pid(data->pid);
    if (!slot || !slot->ring_count)
        return 0;

    spin_lock(&slot->lock);
    prev_idx = (slot->ring_head + TSC_RING_SIZE - 1) % TSC_RING_SIZE;
    ev = &slot->ring[prev_idx];
    if (ev->pid == data->pid && ev->syscall_nr == TSC_NR_SOCKET)
        ev->return_value = (s64)regs_return_value(regs);
    spin_unlock(&slot->lock);
    return 0;
}

static int tsc_kretp_connect_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tsc_retprobe_data *data = (struct tsc_retprobe_data *)ri->data;
    struct tsc_pid_slot *slot;
    struct tsc_event *ev;
    u32 prev_idx;

    slot = tsc_find_slot_by_pid(data->pid);
    if (!slot || !slot->ring_count)
        return 0;

    spin_lock(&slot->lock);
    prev_idx = (slot->ring_head + TSC_RING_SIZE - 1) % TSC_RING_SIZE;
    ev = &slot->ring[prev_idx];
    if (ev->pid == data->pid && ev->syscall_nr == TSC_NR_CONNECT)
        ev->return_value = (s64)regs_return_value(regs);
    spin_unlock(&slot->lock);
    return 0;
}

static int tsc_kretp_clone_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tsc_retprobe_data *data = (struct tsc_retprobe_data *)ri->data;
    struct tsc_pid_slot *slot;
    struct tsc_event *ev;
    u32 prev_idx;

    slot = tsc_find_slot_by_pid(data->pid);
    if (!slot || !slot->ring_count)
        return 0;

    spin_lock(&slot->lock);
    prev_idx = (slot->ring_head + TSC_RING_SIZE - 1) % TSC_RING_SIZE;
    ev = &slot->ring[prev_idx];
    if (ev->pid == data->pid && ev->syscall_nr == TSC_NR_CLONE)
        ev->return_value = (s64)regs_return_value(regs);
    spin_unlock(&slot->lock);
    return 0;
}

/* ========================================================================
 * kprobe/kretprobe definitions
 * ======================================================================== */

static struct kprobe tsc_kp_openat = {
    .symbol_name = "__x64_sys_openat",
    .pre_handler = tsc_kp_openat_pre,
};

static struct kprobe tsc_kp_read = {
    .symbol_name = "__x64_sys_read",
    .pre_handler = tsc_kp_read_pre,
};

static struct kprobe tsc_kp_write = {
    .symbol_name = "__x64_sys_write",
    .pre_handler = tsc_kp_write_pre,
};

static struct kprobe tsc_kp_ioctl = {
    .symbol_name = "__x64_sys_ioctl",
    .pre_handler = tsc_kp_ioctl_pre,
};

static struct kprobe tsc_kp_socket = {
    .symbol_name = "__x64_sys_socket",
    .pre_handler = tsc_kp_socket_pre,
};

static struct kprobe tsc_kp_connect = {
    .symbol_name = "__x64_sys_connect",
    .pre_handler = tsc_kp_connect_pre,
};

static struct kprobe tsc_kp_bind = {
    .symbol_name = "__x64_sys_bind",
    .pre_handler = tsc_kp_bind_pre,
};

static struct kprobe tsc_kp_mmap = {
    .symbol_name = "__x64_sys_mmap",
    .pre_handler = tsc_kp_mmap_pre,
};

static struct kprobe tsc_kp_clone = {
    .symbol_name = "__x64_sys_clone",
    .pre_handler = tsc_kp_clone_pre,
};

/* kretprobes for return value capture */
#define TSC_MAXACTIVE 32  /* Max simultaneous instances per retprobe */

static struct kretprobe tsc_kretp_openat = {
    .handler = tsc_kretp_openat_ret,
    .entry_handler = tsc_kretp_entry,
    .data_size = sizeof(struct tsc_retprobe_data),
    .maxactive = TSC_MAXACTIVE,
    .kp.symbol_name = "__x64_sys_openat",
};

static struct kretprobe tsc_kretp_read = {
    .handler = tsc_kretp_read_ret,
    .entry_handler = tsc_kretp_entry,
    .data_size = sizeof(struct tsc_retprobe_data),
    .maxactive = TSC_MAXACTIVE,
    .kp.symbol_name = "__x64_sys_read",
};

static struct kretprobe tsc_kretp_write = {
    .handler = tsc_kretp_write_ret,
    .entry_handler = tsc_kretp_entry,
    .data_size = sizeof(struct tsc_retprobe_data),
    .maxactive = TSC_MAXACTIVE,
    .kp.symbol_name = "__x64_sys_write",
};

static struct kretprobe tsc_kretp_ioctl = {
    .handler = tsc_kretp_ioctl_ret,
    .entry_handler = tsc_kretp_entry,
    .data_size = sizeof(struct tsc_retprobe_data),
    .maxactive = TSC_MAXACTIVE,
    .kp.symbol_name = "__x64_sys_ioctl",
};

static struct kretprobe tsc_kretp_socket = {
    .handler = tsc_kretp_socket_ret,
    .entry_handler = tsc_kretp_entry,
    .data_size = sizeof(struct tsc_retprobe_data),
    .maxactive = TSC_MAXACTIVE,
    .kp.symbol_name = "__x64_sys_socket",
};

static struct kretprobe tsc_kretp_connect = {
    .handler = tsc_kretp_connect_ret,
    .entry_handler = tsc_kretp_entry,
    .data_size = sizeof(struct tsc_retprobe_data),
    .maxactive = TSC_MAXACTIVE,
    .kp.symbol_name = "__x64_sys_connect",
};

static struct kretprobe tsc_kretp_clone = {
    .handler = tsc_kretp_clone_ret,
    .entry_handler = tsc_kretp_entry,
    .data_size = sizeof(struct tsc_retprobe_data),
    .maxactive = TSC_MAXACTIVE,
    .kp.symbol_name = "__x64_sys_clone",
};

/* Arrays for batch registration */
static struct kprobe *tsc_kprobes[] = {
    &tsc_kp_openat,
    &tsc_kp_read,
    &tsc_kp_write,
    &tsc_kp_ioctl,
    &tsc_kp_socket,
    &tsc_kp_connect,
    &tsc_kp_bind,
    &tsc_kp_mmap,
    &tsc_kp_clone,
};
#define TSC_NUM_KPROBES ARRAY_SIZE(tsc_kprobes)

static struct kretprobe *tsc_kretprobes[] = {
    &tsc_kretp_openat,
    &tsc_kretp_read,
    &tsc_kretp_write,
    &tsc_kretp_ioctl,
    &tsc_kretp_socket,
    &tsc_kretp_connect,
    &tsc_kretp_clone,
};
#define TSC_NUM_KRETPROBES ARRAY_SIZE(tsc_kretprobes)

/* Track which probes were successfully registered for clean teardown */
static bool tsc_kp_registered[TSC_NUM_KPROBES];
static bool tsc_kretp_registered[TSC_NUM_KRETPROBES];

/* ========================================================================
 * Public API: trace start/stop
 * ======================================================================== */

/*
 * tsc_start_trace - Begin tracing syscalls for a PE process.
 *
 * Associates a trust subject ID with a PID and starts recording.
 * Only PIDs that have a trust subject registered should be traced.
 *
 * Returns 0 on success, -ENOSPC if no free slots, -EEXIST if already traced.
 */
int tsc_start_trace(u32 subject_id, pid_t pid, u8 category_mask)
{
    struct tsc_pid_slot *slot;
    u8 final_mask;

    if (!g_tsc.enabled)
        return -ENODEV;

    /* Check if already traced */
    slot = tsc_find_slot_by_pid(pid);
    if (slot)
        return -EEXIST;

    /* Find a free slot */
    slot = tsc_find_free_slot();
    if (!slot)
        return -ENOSPC;

    final_mask = category_mask ? category_mask : TSC_CAT_ALL;

    spin_lock(&slot->lock);
    slot->pid = pid;
    slot->subject_id = subject_id;
    slot->category_mask = final_mask;
    slot->ring_head = 0;
    slot->ring_count = 0;
    memset(slot->stats, 0, sizeof(slot->stats));
    memset(slot->ring, 0, sizeof(slot->ring));
    slot->active = true;
    spin_unlock(&slot->lock);

    /* Set PID in bitmap for O(1) lookup */
    if (pid < TSC_PID_BITMAP_SIZE && g_tsc.pid_bitmap)
        set_bit(pid, g_tsc.pid_bitmap);

    pr_info("trust: TSC started tracing pid %d (subject %u, categories 0x%02x)\n",
            pid, subject_id, final_mask);
    return 0;
}

/*
 * tsc_stop_trace - Stop tracing syscalls for a PID.
 *
 * Clears the slot and removes the PID from the bitmap.
 */
void tsc_stop_trace(pid_t pid)
{
    struct tsc_pid_slot *slot;

    if (!g_tsc.enabled)
        return;

    slot = tsc_find_slot_by_pid(pid);
    if (!slot)
        return;

    spin_lock(&slot->lock);
    slot->active = false;
    slot->pid = 0;
    slot->subject_id = 0;
    spin_unlock(&slot->lock);

    /* Clear PID in bitmap */
    if (pid < TSC_PID_BITMAP_SIZE && g_tsc.pid_bitmap)
        clear_bit(pid, g_tsc.pid_bitmap);

    pr_info("trust: TSC stopped tracing pid %d\n", pid);
}

/* ========================================================================
 * ioctl handler
 * ======================================================================== */

/*
 * tsc_ioctl - Handle TSC-specific ioctl commands.
 *
 * Dispatched from trust_core.c's trust_ioctl().
 */
long tsc_ioctl(unsigned int cmd, unsigned long arg)
{
    switch (cmd) {

    case TRUST_IOC_TSC_START_TRACE: {
        tsc_ioc_trace_t req;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        req.result = tsc_start_trace(req.subject_id, req.pid,
                                      req.category_mask);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_TSC_STOP_TRACE: {
        tsc_ioc_trace_t req;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        tsc_stop_trace(req.pid);
        req.result = 0;
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_TSC_GET_STATS: {
        tsc_ioc_stats_t req;
        struct tsc_pid_slot *slot;
        u64 *stats_snap;
        u32 count;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        slot = tsc_find_slot_by_pid(req.pid);
        if (!slot)
            return -ENOENT;

        count = req.max_entries;
        if (count > 512)
            count = 512;

        /* Snapshot stats under lock, then copy_to_user outside lock */
        stats_snap = kvmalloc_array(count, sizeof(u64), GFP_KERNEL);
        if (!stats_snap)
            return -ENOMEM;

        spin_lock(&slot->lock);
        memcpy(stats_snap, slot->stats, count * sizeof(u64));
        spin_unlock(&slot->lock);

        if (copy_to_user((void __user *)req.buf, stats_snap,
                          count * sizeof(u64))) {
            kvfree(stats_snap);
            return -EFAULT;
        }
        kvfree(stats_snap);

        req.returned = count;
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_TSC_GET_EVENTS: {
        tsc_ioc_events_t req;
        struct tsc_pid_slot *slot;
        struct tsc_event *events_snap;
        u32 count, i, idx;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        slot = tsc_find_slot_by_pid(req.pid);
        if (!slot)
            return -ENOENT;

        /* Snapshot events under lock, then copy_to_user outside lock */
        spin_lock(&slot->lock);
        count = slot->ring_count;
        if (count > req.max_events)
            count = req.max_events;
        req.total = slot->ring_count;
        spin_unlock(&slot->lock);

        if (count == 0) {
            req.returned = 0;
            if (copy_to_user((void __user *)arg, &req, sizeof(req)))
                return -EFAULT;
            return 0;
        }

        events_snap = kvmalloc_array(count, sizeof(struct tsc_event),
                                     GFP_KERNEL);
        if (!events_snap)
            return -ENOMEM;

        spin_lock(&slot->lock);
        /* Re-check count in case it changed */
        if (slot->ring_count < count)
            count = slot->ring_count;
        for (i = 0; i < count; i++) {
            idx = (slot->ring_head + TSC_RING_SIZE - count + i) % TSC_RING_SIZE;
            events_snap[i] = slot->ring[idx];
        }
        spin_unlock(&slot->lock);

        for (i = 0; i < count; i++) {
            if (copy_to_user((void __user *)req.buf +
                             i * sizeof(struct tsc_event),
                             &events_snap[i],
                             sizeof(struct tsc_event))) {
                kvfree(events_snap);
                return -EFAULT;
            }
        }
        kvfree(events_snap);

        req.returned = count;
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    default:
        return -ENOTTY;
    }
}

/* ========================================================================
 * Netlink socket creation
 * ======================================================================== */

static void tsc_netlink_recv(struct sk_buff *skb)
{
    /* We only send events to userspace; inbound messages are ignored. */
    (void)skb;
}

static int tsc_netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = tsc_netlink_recv,
        .groups = TSC_NETLINK_GROUP,
    };

    g_tsc.nl_sock = netlink_kernel_create(&init_net, TSC_NETLINK_PROTO, &cfg);
    if (!g_tsc.nl_sock) {
        pr_warn("trust: TSC netlink socket creation failed "
                "(non-fatal, events disabled)\n");
        return -ENOMEM;
    }
    return 0;
}

static void tsc_netlink_cleanup(void)
{
    if (g_tsc.nl_sock) {
        netlink_kernel_release(g_tsc.nl_sock);
        g_tsc.nl_sock = NULL;
    }
}

/* ========================================================================
 * Module init / cleanup
 * ======================================================================== */

/*
 * tsc_init - Initialize the Trust Syscall Tracer subsystem.
 *
 * Allocates per-PID tracking array, PID bitmap, registers kprobes/kretprobes,
 * creates netlink socket.
 * Called from trust_core.c trust_init().
 *
 * Returns 0 on success, negative errno on failure.
 */
int tsc_init(void)
{
    u32 i;
    int ret;

    memset(&g_tsc, 0, sizeof(g_tsc));
    g_tsc.max_slots = TSC_MAX_SUBJECTS;
    atomic_set(&g_tsc.event_seq, 0);

    /* Allocate tracking slot array */
    g_tsc.slots = vzalloc(g_tsc.max_slots * sizeof(struct tsc_pid_slot));
    if (!g_tsc.slots) {
        pr_err("trust: TSC failed to allocate slot array (%zu bytes)\n",
               (size_t)(g_tsc.max_slots * sizeof(struct tsc_pid_slot)));
        return -ENOMEM;
    }

    for (i = 0; i < g_tsc.max_slots; i++) {
        spin_lock_init(&g_tsc.slots[i].lock);
        g_tsc.slots[i].active = false;
    }

    /* Allocate PID bitmap for O(1) lookups */
    g_tsc.pid_bitmap = vzalloc(BITS_TO_LONGS(TSC_PID_BITMAP_SIZE) *
                                sizeof(unsigned long));
    if (!g_tsc.pid_bitmap) {
        pr_warn("trust: TSC failed to allocate PID bitmap "
                "(non-fatal, using linear scan)\n");
    }

    /* Create netlink socket (non-fatal if it fails) */
    tsc_netlink_init();

    /* Register kprobes (each failure is non-fatal) */
    memset(tsc_kp_registered, 0, sizeof(tsc_kp_registered));
    for (i = 0; i < TSC_NUM_KPROBES; i++) {
        ret = register_kprobe(tsc_kprobes[i]);
        if (ret < 0) {
            pr_warn("trust: TSC kprobe %s failed (%d)\n",
                    tsc_kprobes[i]->symbol_name, ret);
        } else {
            tsc_kp_registered[i] = true;
        }
    }

    /* Register kretprobes (each failure is non-fatal) */
    memset(tsc_kretp_registered, 0, sizeof(tsc_kretp_registered));
    for (i = 0; i < TSC_NUM_KRETPROBES; i++) {
        ret = register_kretprobe(tsc_kretprobes[i]);
        if (ret < 0) {
            pr_warn("trust: TSC kretprobe %s failed (%d)\n",
                    tsc_kretprobes[i]->kp.symbol_name, ret);
        } else {
            tsc_kretp_registered[i] = true;
        }
    }

    g_tsc.enabled = true;

    pr_info("trust: TSC initialized: %u subject slots, PID bitmap %s, "
            "netlink proto %d\n",
            g_tsc.max_slots,
            g_tsc.pid_bitmap ? "active" : "disabled",
            TSC_NETLINK_PROTO);
    return 0;
}

/*
 * tsc_cleanup - Tear down the Trust Syscall Tracer subsystem.
 *
 * Unregisters kprobes/kretprobes, frees memory.
 * Called from trust_core.c trust_exit().
 */
void tsc_cleanup(void)
{
    u32 i;

    g_tsc.enabled = false;

    /* Unregister kretprobes first (they depend on kprobes) */
    for (i = 0; i < TSC_NUM_KRETPROBES; i++) {
        if (tsc_kretp_registered[i])
            unregister_kretprobe(tsc_kretprobes[i]);
    }

    /* Unregister kprobes */
    for (i = 0; i < TSC_NUM_KPROBES; i++) {
        if (tsc_kp_registered[i])
            unregister_kprobe(tsc_kprobes[i]);
    }

    /* Free slot array */
    if (g_tsc.slots) {
        vfree(g_tsc.slots);
        g_tsc.slots = NULL;
    }

    /* Free PID bitmap */
    if (g_tsc.pid_bitmap) {
        vfree(g_tsc.pid_bitmap);
        g_tsc.pid_bitmap = NULL;
    }

    tsc_netlink_cleanup();

    pr_info("trust: TSC cleaned up\n");
}

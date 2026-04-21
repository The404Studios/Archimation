/*
 * trust_algedonic.c — Beer VSM algedonic bypass: /dev/trust_algedonic.
 *
 * S74 Agent 8 (Cluster 2B). Implements the sub-millisecond kernel->
 * userspace "pain/pleasure" channel that short-circuits the normal
 * perception->decision pipeline during emergencies. Userspace (the AI
 * cortex) opens the miscdevice, blocks on read(), and receives 40-byte
 * trust_algedonic_packet structures as emergencies are emitted from
 * any kernel context (task, softirq, or hard-IRQ).
 *
 * Wire protocol:
 *   - Each read() returns exactly one packet (EINVAL on short buffer).
 *   - poll() reports POLLIN when >=1 packet is queued.
 *   - Ring is 64 slots; if full we drop the OLDEST (newest is always
 *     delivered — emergencies must not be silently lost under flood).
 *
 * Based on:
 *   Stafford Beer (1972) "Brain of the Firm", VSM System 3-star / 4-star algedonic channel.
 *   Roberts/Eli/Leelee (2026) Zenodo 18710335 §Algedonic short-circuit.
 */

#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/ktime.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/errno.h>
#endif

#include <trust_algedonic.h>

/* --- Ring buffer ------------------------------------------------------ */

#define TRUST_ALG_RING_SLOTS  64  /* power of two */
#define TRUST_ALG_RING_MASK   (TRUST_ALG_RING_SLOTS - 1)

struct trust_alg_ring {
    struct trust_algedonic_packet slot[TRUST_ALG_RING_SLOTS];
    u32                           head;   /* next write */
    u32                           tail;   /* next read  */
    u32                           count;  /* 0..TRUST_ALG_RING_SLOTS */
};

static struct trust_alg_ring  g_ring;
static spinlock_t             g_ring_lock;
static wait_queue_head_t      g_read_wq;

/* Counters (sysfs). */
static atomic_t    g_reader_count = ATOMIC_INIT(0);
static atomic64_t  g_emitted      = ATOMIC64_INIT(0);
static atomic64_t  g_dropped      = ATOMIC64_INIT(0);

/* --- Emit (kernel-side API) ------------------------------------------ */

int trust_algedonic_emit(__u32 subject_pid, __u16 severity, __u16 reason,
                         const __u64 data[3])
{
    struct trust_algedonic_packet *p;
    unsigned long flags;
    int dropped = 0;

    spin_lock_irqsave(&g_ring_lock, flags);

    if (g_ring.count == TRUST_ALG_RING_SLOTS) {
        /* Full — evict oldest. This is intentional: an emergency arriving
         * now is more valuable than one the cortex failed to drain. */
        g_ring.tail = (g_ring.tail + 1) & TRUST_ALG_RING_MASK;
        g_ring.count--;
        dropped = 1;
        atomic64_inc(&g_dropped);
    }

    p = &g_ring.slot[g_ring.head];
    p->ts_ns       = ktime_get_ns();
    p->subject_pid = subject_pid;
    p->severity    = severity;
    p->reason      = reason;
    if (data) {
        p->data[0] = data[0];
        p->data[1] = data[1];
        p->data[2] = data[2];
    } else {
        p->data[0] = p->data[1] = p->data[2] = 0;
    }

    g_ring.head = (g_ring.head + 1) & TRUST_ALG_RING_MASK;
    g_ring.count++;
    atomic64_inc(&g_emitted);

    spin_unlock_irqrestore(&g_ring_lock, flags);

    wake_up_interruptible(&g_read_wq);
    return dropped ? -ENOSPC : 0;
}
EXPORT_SYMBOL_GPL(trust_algedonic_emit);

/* --- File ops --------------------------------------------------------- */

static int trust_alg_open(struct inode *inode, struct file *filp)
{
    (void)inode; (void)filp;
    atomic_inc(&g_reader_count);
    return 0;
}

static int trust_alg_release(struct inode *inode, struct file *filp)
{
    (void)inode; (void)filp;
    atomic_dec(&g_reader_count);
    return 0;
}

static ssize_t trust_alg_read(struct file *filp, char __user *buf,
                              size_t len, loff_t *ppos)
{
    struct trust_algedonic_packet pkt;
    unsigned long flags;
    int rc;

    (void)ppos;

    if (len < sizeof(pkt))
        return -EINVAL;

    /* Block until a packet shows up (or non-blocking caller bails out). */
    if (filp->f_flags & O_NONBLOCK) {
        spin_lock_irqsave(&g_ring_lock, flags);
        if (g_ring.count == 0) {
            spin_unlock_irqrestore(&g_ring_lock, flags);
            return -EAGAIN;
        }
        spin_unlock_irqrestore(&g_ring_lock, flags);
    } else {
        rc = wait_event_interruptible(g_read_wq, g_ring.count > 0);
        if (rc)
            return rc;
    }

    spin_lock_irqsave(&g_ring_lock, flags);
    if (g_ring.count == 0) {
        spin_unlock_irqrestore(&g_ring_lock, flags);
        return -EAGAIN;  /* raced with another reader */
    }
    pkt = g_ring.slot[g_ring.tail];
    g_ring.tail = (g_ring.tail + 1) & TRUST_ALG_RING_MASK;
    g_ring.count--;
    spin_unlock_irqrestore(&g_ring_lock, flags);

    if (copy_to_user(buf, &pkt, sizeof(pkt)))
        return -EFAULT;

    return sizeof(pkt);
}

static __poll_t trust_alg_poll(struct file *filp, poll_table *wait)
{
    __poll_t mask = 0;
    unsigned long flags;

    poll_wait(filp, &g_read_wq, wait);

    spin_lock_irqsave(&g_ring_lock, flags);
    if (g_ring.count > 0)
        mask |= POLLIN | POLLRDNORM;
    spin_unlock_irqrestore(&g_ring_lock, flags);

    return mask;
}

static const struct file_operations trust_alg_fops = {
    .owner   = THIS_MODULE,
    .open    = trust_alg_open,
    .release = trust_alg_release,
    .read    = trust_alg_read,
    .poll    = trust_alg_poll,
    .llseek  = no_llseek,
};

static struct miscdevice trust_alg_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "trust_algedonic",
    .fops  = &trust_alg_fops,
    .mode  = 0440,   /* group-readable only — cortex daemon reads via a group */
};

/* --- sysfs surface ---------------------------------------------------- */

static ssize_t pending_show(struct kobject *k, struct kobj_attribute *a,
                            char *buf)
{
    unsigned long flags;
    u32 n;

    (void)k; (void)a;
    spin_lock_irqsave(&g_ring_lock, flags);
    n = g_ring.count;
    spin_unlock_irqrestore(&g_ring_lock, flags);
    return sysfs_emit(buf, "%u\n", n);
}

static ssize_t dropped_show(struct kobject *k, struct kobj_attribute *a,
                            char *buf)
{
    (void)k; (void)a;
    return sysfs_emit(buf, "%lld\n", (long long)atomic64_read(&g_dropped));
}

static ssize_t emitted_show(struct kobject *k, struct kobj_attribute *a,
                            char *buf)
{
    (void)k; (void)a;
    return sysfs_emit(buf, "%lld\n", (long long)atomic64_read(&g_emitted));
}

static ssize_t reader_count_show(struct kobject *k, struct kobj_attribute *a,
                                 char *buf)
{
    (void)k; (void)a;
    return sysfs_emit(buf, "%d\n", atomic_read(&g_reader_count));
}

static struct kobj_attribute attr_pending      = __ATTR(pending, 0444, pending_show, NULL);
static struct kobj_attribute attr_dropped      = __ATTR(dropped, 0444, dropped_show, NULL);
static struct kobj_attribute attr_emitted      = __ATTR(emitted, 0444, emitted_show, NULL);
static struct kobj_attribute attr_reader_count = __ATTR(reader_count, 0444, reader_count_show, NULL);

static struct attribute *alg_attrs[] = {
    &attr_pending.attr,
    &attr_dropped.attr,
    &attr_emitted.attr,
    &attr_reader_count.attr,
    NULL,
};

static const struct attribute_group alg_group = {
    .attrs = alg_attrs,
};

static struct kobject *g_alg_kobj;

/* --- Init/exit -------------------------------------------------------- */

int trust_algedonic_init(void)
{
    int ret;

    memset(&g_ring, 0, sizeof(g_ring));
    spin_lock_init(&g_ring_lock);
    init_waitqueue_head(&g_read_wq);

    ret = misc_register(&trust_alg_misc);
    if (ret) {
        pr_err("trust_algedonic: misc_register failed (%d)\n", ret);
        return ret;
    }

    g_alg_kobj = kobject_create_and_add("algedonic", kernel_kobj);
    if (!g_alg_kobj) {
        pr_warn("trust_algedonic: /sys/kernel/algedonic unavailable\n");
    } else {
        ret = sysfs_create_group(g_alg_kobj, &alg_group);
        if (ret) {
            pr_warn("trust_algedonic: sysfs_create_group failed (%d)\n", ret);
            kobject_put(g_alg_kobj);
            g_alg_kobj = NULL;
        }
    }

    pr_info("trust_algedonic: /dev/trust_algedonic ring=%d slots packet=%zu B\n",
            TRUST_ALG_RING_SLOTS, sizeof(struct trust_algedonic_packet));
    return 0;
}

void trust_algedonic_exit(void)
{
    if (g_alg_kobj) {
        sysfs_remove_group(g_alg_kobj, &alg_group);
        kobject_put(g_alg_kobj);
        g_alg_kobj = NULL;
    }
    misc_deregister(&trust_alg_misc);
    /* Drain waiters so they don't sleep forever on unload. */
    wake_up_interruptible_all(&g_read_wq);
}

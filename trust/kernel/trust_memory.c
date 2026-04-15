/*
 * trust_memory.c - Trust Memory Scanner (TMS)
 *
 * Tracks memory regions for trust-tracked PE processes. Hooks mmap/mprotect/
 * munmap via kprobes to build a real-time memory map per subject. Emits events
 * to userspace when interesting memory operations happen (executable pages in
 * heap, protection changes on known sections, new mappings in PE address space).
 *
 * The scanner also supports configurable byte-pattern matching on mapped
 * regions, used for detecting IAT hooks, shellcode, debug flags, etc.
 *
 * Architecture:
 *   - Per-subject rbtree of memory regions keyed by VA (O(log n) lookup)
 *   - kprobe handlers on do_mmap, do_munmap, do_mprotect filter to tracked PIDs
 *   - Netlink socket pushes events to userspace AI observer
 *   - Pattern scanning uses mask-based byte matching on mapped regions
 *
 * Part of the Root of Authority kernel module (trust.ko).
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <net/sock.h>

#include "trust_internal.h"
#include "trust_memory.h"

/* ========================================================================
 * Global TMS state
 * ======================================================================== */

static struct {
    struct tms_subject_map *maps;       /* Array of TMS_MAX_SUBJECTS maps */
    u32                     max_subjects;
    struct tms_pattern      patterns[TMS_MAX_PATTERNS];
    u32                     pattern_count;
    spinlock_t              pattern_lock;
    struct sock            *nl_sock;    /* Netlink socket for events */
    atomic_t                event_seq;  /* Monotonic event sequence number */
    bool                    enabled;
} g_tms;

/* Forward declarations for kprobe handlers */
static int tms_kp_mmap_pre(struct kprobe *p, struct pt_regs *regs);
static int tms_kp_munmap_pre(struct kprobe *p, struct pt_regs *regs);
static int tms_kp_mprotect_pre(struct kprobe *p, struct pt_regs *regs);

/* Kprobes */
static struct kprobe tms_kp_mmap = {
    .symbol_name = "do_mmap",
    .pre_handler = tms_kp_mmap_pre,
};

static struct kprobe tms_kp_munmap = {
    .symbol_name = "__do_munmap",
    .pre_handler = tms_kp_munmap_pre,
};

static struct kprobe tms_kp_mprotect = {
    .symbol_name = "do_mprotect_pkey",
    .pre_handler = tms_kp_mprotect_pre,
};

/* ========================================================================
 * Internal helpers
 * ======================================================================== */

/*
 * Find the subject map for a given subject_id.
 * Returns NULL if not found or not active.
 * Caller must not hold any TMS locks.
 */
static struct tms_subject_map *tms_find_map_by_subject(u32 subject_id)
{
    u32 i;

    if (!g_tms.maps)
        return NULL;

    for (i = 0; i < g_tms.max_subjects; i++) {
        if (g_tms.maps[i].active &&
            g_tms.maps[i].subject_id == subject_id)
            return &g_tms.maps[i];
    }
    return NULL;
}

/*
 * Find the subject map for a given PID.
 * Returns NULL if not found or not active.
 */
static struct tms_subject_map *tms_find_map_by_pid(pid_t pid)
{
    u32 i;

    if (!g_tms.maps)
        return NULL;

    for (i = 0; i < g_tms.max_subjects; i++) {
        if (g_tms.maps[i].active &&
            g_tms.maps[i].pid == pid)
            return &g_tms.maps[i];
    }
    return NULL;
}

/*
 * Find an empty slot in the maps array.
 * Returns NULL if all slots are in use.
 */
static struct tms_subject_map *tms_find_free_slot(void)
{
    u32 i;

    if (!g_tms.maps)
        return NULL;

    for (i = 0; i < g_tms.max_subjects; i++) {
        if (!g_tms.maps[i].active)
            return &g_tms.maps[i];
    }
    return NULL;
}

/*
 * Allocate and initialize a new region node.
 */
static struct tms_region *tms_alloc_region(u64 va_start, u64 va_end,
                                            u32 prot, enum tms_region_tag tag,
                                            const char *label)
{
    struct tms_region *r;

    r = kzalloc(sizeof(*r), GFP_ATOMIC);
    if (!r)
        return NULL;

    RB_CLEAR_NODE(&r->node);
    r->va_start = va_start;
    r->va_end = va_end;
    r->prot = prot;
    r->tag = tag;
    r->load_time_ns = ktime_get_ns();
    r->pattern_hits = 0;

    if (label)
        strscpy(r->label, label, sizeof(r->label));

    return r;
}

/*
 * Insert a region into the per-subject rbtree.
 * Returns 0 on success, -EEXIST if an overlapping region exists.
 * Caller must hold map->lock.
 */
static int tms_rbtree_insert(struct tms_subject_map *map, struct tms_region *new)
{
    struct rb_node **link = &map->regions.rb_node;
    struct rb_node *parent = NULL;
    struct tms_region *entry;

    while (*link) {
        parent = *link;
        entry = rb_entry(parent, struct tms_region, node);

        if (new->va_end <= entry->va_start) {
            link = &parent->rb_left;
        } else if (new->va_start >= entry->va_end) {
            link = &parent->rb_right;
        } else {
            /* Overlapping region -- update existing instead of failing */
            entry->prot = new->prot;
            if (new->tag != TMS_TAG_UNKNOWN)
                entry->tag = new->tag;
            if (new->label[0])
                strscpy(entry->label, new->label, sizeof(entry->label));
            return -EEXIST;
        }
    }

    rb_link_node(&new->node, parent, link);
    rb_insert_color(&new->node, &map->regions);
    map->region_count++;
    return 0;
}

/*
 * Look up a region containing the given virtual address.
 * Returns NULL if no region contains va.
 * Caller must hold map->lock.
 */
static struct tms_region *tms_rbtree_find(struct tms_subject_map *map, u64 va)
{
    struct rb_node *n = map->regions.rb_node;
    struct tms_region *entry;

    while (n) {
        entry = rb_entry(n, struct tms_region, node);

        if (va < entry->va_start)
            n = n->rb_left;
        else if (va >= entry->va_end)
            n = n->rb_right;
        else
            return entry;  /* va is within [va_start, va_end) */
    }
    return NULL;
}

/*
 * Find the first region that overlaps [start, end).
 * Caller must hold map->lock.
 */
static struct tms_region *tms_rbtree_find_overlap(struct tms_subject_map *map,
                                                    u64 start, u64 end)
{
    struct rb_node *n = map->regions.rb_node;
    struct tms_region *entry;

    while (n) {
        entry = rb_entry(n, struct tms_region, node);

        if (end <= entry->va_start)
            n = n->rb_left;
        else if (start >= entry->va_end)
            n = n->rb_right;
        else
            return entry;  /* Overlap found */
    }
    return NULL;
}

/*
 * Remove a region from the rbtree and free it.
 * Caller must hold map->lock.
 */
static void tms_rbtree_remove(struct tms_subject_map *map,
                               struct tms_region *region)
{
    rb_erase(&region->node, &map->regions);
    map->region_count--;
    kfree(region);
}

/*
 * Destroy all regions in a subject map.
 * Caller must hold map->lock.
 */
static void tms_rbtree_destroy(struct tms_subject_map *map)
{
    struct rb_node *n;
    struct tms_region *region;

    while ((n = rb_first(&map->regions)) != NULL) {
        region = rb_entry(n, struct tms_region, node);
        rb_erase(n, &map->regions);
        kfree(region);
    }
    map->region_count = 0;
}

/* ========================================================================
 * Netlink event emission
 * ======================================================================== */

/*
 * tms_emit_event - Send an event to userspace via netlink.
 *
 * Non-blocking. If netlink is not available or allocation fails,
 * the event is silently dropped (no backpressure on kernel path).
 */
static void tms_emit_event(u32 type, u32 subject_id, pid_t pid,
                            u64 va, u64 size, u32 prot,
                            u32 pattern_id, enum tms_region_tag tag,
                            const char *label)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    struct tms_event_msg *msg;
    int msg_size;

    if (!g_tms.nl_sock)
        return;

    msg_size = sizeof(struct tms_event_msg);
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
    msg->seq = (u32)atomic_inc_return(&g_tms.event_seq);
    msg->type = type;
    msg->subject_id = subject_id;
    msg->pid = pid;
    msg->va = va;
    msg->size = size;
    msg->prot = prot;
    msg->pattern_id = pattern_id;
    msg->tag = tag;
    if (label)
        strscpy(msg->label, label, sizeof(msg->label));

    NETLINK_CB(skb).dst_group = TMS_NETLINK_GROUP;
    nlmsg_multicast(g_tms.nl_sock, skb, 0, TMS_NETLINK_GROUP, GFP_ATOMIC);
    /* nlmsg_multicast consumes skb regardless of success/failure */
}

/* ========================================================================
 * Public API: subject registration
 * ======================================================================== */

/*
 * tms_register_subject - Start tracking memory for a PE process.
 *
 * Called when a trust subject that represents a PE process is registered.
 * Allocates a per-subject memory map slot.
 *
 * Returns 0 on success, -ENOSPC if no free slots, -EEXIST if already tracked.
 */
int tms_register_subject(u32 subject_id, pid_t pid)
{
    struct tms_subject_map *map;

    if (!g_tms.enabled)
        return -ENODEV;

    /* Check if already registered */
    map = tms_find_map_by_subject(subject_id);
    if (map)
        return -EEXIST;

    /* Find a free slot */
    map = tms_find_free_slot();
    if (!map)
        return -ENOSPC;

    spin_lock(&map->lock);
    map->subject_id = subject_id;
    map->pid = pid;
    map->regions = RB_ROOT;
    map->region_count = 0;
    map->active = true;
    spin_unlock(&map->lock);

    pr_debug("trust: TMS registered subject %u (pid %d)\n",
             subject_id, pid);
    return 0;
}

/*
 * tms_unregister_subject - Stop tracking memory for a PE process.
 *
 * Destroys all tracked regions and frees the map slot.
 */
void tms_unregister_subject(u32 subject_id)
{
    struct tms_subject_map *map;

    if (!g_tms.enabled)
        return;

    map = tms_find_map_by_subject(subject_id);
    if (!map)
        return;

    spin_lock(&map->lock);
    tms_rbtree_destroy(map);
    map->active = false;
    map->subject_id = 0;
    map->pid = 0;
    spin_unlock(&map->lock);

    pr_debug("trust: TMS unregistered subject %u\n", subject_id);
}

/* ========================================================================
 * Public API: PE section registration
 * ======================================================================== */

/*
 * tms_register_section - Register a known PE section with the TMS.
 *
 * Called by the PE loader after mapping a section (e.g. .text, .data, .rdata).
 * This tags the region so the TMS knows what kind of memory it is and can
 * detect anomalous protection changes (e.g. .text becoming writable).
 *
 * Returns 0 on success, -ENOENT if subject not tracked, -ENOMEM on alloc failure.
 */
int tms_register_section(u32 subject_id, u64 va_start, u64 size,
                          enum tms_region_tag tag, const char *label)
{
    struct tms_subject_map *map;
    struct tms_region *region;
    u32 prot;
    int ret;

    if (!g_tms.enabled)
        return -ENODEV;

    map = tms_find_map_by_subject(subject_id);
    if (!map)
        return -ENOENT;

    /* Infer default protection from section tag */
    switch (tag) {
    case TMS_TAG_TEXT:
        prot = PROT_READ | PROT_EXEC;
        break;
    case TMS_TAG_RDATA:
        prot = PROT_READ;
        break;
    case TMS_TAG_DATA:
    case TMS_TAG_BSS:
    case TMS_TAG_HEAP:
    case TMS_TAG_STACK:
    case TMS_TAG_TLS:
        prot = PROT_READ | PROT_WRITE;
        break;
    case TMS_TAG_IAT:
        prot = PROT_READ | PROT_WRITE;  /* IAT is writable during import resolution */
        break;
    default:
        prot = PROT_READ;
        break;
    }

    region = tms_alloc_region(va_start, va_start + size, prot, tag, label);
    if (!region)
        return -ENOMEM;

    pid_t snap_pid;
    spin_lock(&map->lock);
    if (map->region_count >= TMS_MAX_REGIONS_PER_SUBJECT) {
        spin_unlock(&map->lock);
        kfree(region);
        return -ENOSPC;
    }
    ret = tms_rbtree_insert(map, region);
    if (ret == -EEXIST) {
        /* Overlapping region was updated in-place; free the new node */
        kfree(region);
        ret = 0;  /* Not an error: region was updated */
    }
    snap_pid = map->pid;
    spin_unlock(&map->lock);

    tms_emit_event(TMS_EVENT_SECTION, subject_id, snap_pid,
                   va_start, size, prot, 0, tag, label);

    pr_debug("trust: TMS section registered: subject=%u va=%llx-%llx tag=%d label=%s\n",
             subject_id, va_start, va_start + size, tag, label ? label : "");
    return ret;
}

/* ========================================================================
 * Memory operation handlers (called from kprobes)
 * ======================================================================== */

/*
 * tms_on_mmap - Handle a new memory mapping for a tracked process.
 *
 * Inserts the new region into the subject's rbtree. If the mapping
 * has executable permission in a heap-tagged region, emits an alert.
 */
void tms_on_mmap(pid_t pid, u64 addr, u64 len, u32 prot)
{
    struct tms_subject_map *map;
    struct tms_region *region;
    struct tms_region *existing;
    u32 snap_subject_id;
    int ret;

    bool exec_heap_alert = false;
    char alert_label[32] = {0};

    if (!g_tms.enabled || !addr || !len)
        return;

    map = tms_find_map_by_pid(pid);
    if (!map)
        return;

    region = tms_alloc_region(addr, addr + len, prot,
                               TMS_TAG_UNKNOWN, NULL);
    if (!region)
        return;

    spin_lock(&map->lock);

    if (map->region_count >= TMS_MAX_REGIONS_PER_SUBJECT) {
        spin_unlock(&map->lock);
        kfree(region);
        return;
    }

    /* Snapshot subject_id under lock; after unlock the slot may be reused. */
    snap_subject_id = map->subject_id;

    /* Check if this mapping overlaps a known section */
    existing = tms_rbtree_find(map, addr);
    if (existing) {
        /* Update the existing region's protection */
        existing->prot = prot;
        /* Snapshot fields needed for emit before releasing the lock. */
        if (existing->tag == TMS_TAG_HEAP && (prot & PROT_EXEC)) {
            exec_heap_alert = true;
            strscpy(alert_label, existing->label, sizeof(alert_label));
        }
        spin_unlock(&map->lock);
        kfree(region);

        if (exec_heap_alert) {
            tms_emit_event(TMS_EVENT_EXEC_HEAP, snap_subject_id, pid,
                           addr, len, prot, 0, TMS_TAG_HEAP,
                           alert_label);
        }
        return;
    }

    ret = tms_rbtree_insert(map, region);
    spin_unlock(&map->lock);

    if (ret == -EEXIST)
        kfree(region);

    tms_emit_event(TMS_EVENT_MAP, snap_subject_id, pid,
                   addr, len, prot, 0, TMS_TAG_UNKNOWN, NULL);
}

/*
 * tms_on_munmap - Handle a memory unmapping for a tracked process.
 *
 * Removes all regions that overlap [addr, addr+len) from the rbtree.
 */
void tms_on_munmap(pid_t pid, u64 addr, u64 len)
{
    struct tms_subject_map *map;
    struct tms_region *region;
    u32 snap_subject_id;
    u64 end = addr + len;

    if (!g_tms.enabled || !addr || !len)
        return;

    map = tms_find_map_by_pid(pid);
    if (!map)
        return;

    spin_lock(&map->lock);
    snap_subject_id = map->subject_id;
    while ((region = tms_rbtree_find_overlap(map, addr, end)) != NULL) {
        tms_rbtree_remove(map, region);
    }
    spin_unlock(&map->lock);

    tms_emit_event(TMS_EVENT_UNMAP, snap_subject_id, pid,
                   addr, len, 0, 0, TMS_TAG_UNKNOWN, NULL);
}

/*
 * tms_on_mprotect - Handle a protection change for a tracked process.
 *
 * Updates the protection flags on all regions in [addr, addr+len).
 * Emits an alert if:
 *   - .text section gains PROT_WRITE (potential code patching)
 *   - Heap region gains PROT_EXEC (potential shellcode execution)
 */
void tms_on_mprotect(pid_t pid, u64 addr, u64 len, u32 prot)
{
    struct tms_subject_map *map;
    struct tms_region *region;
    struct rb_node *n;
    u32 snap_subject_id;
    u64 end = addr + len;

    if (!g_tms.enabled || !addr || !len)
        return;

    map = tms_find_map_by_pid(pid);
    if (!map)
        return;

    /*
     * Capture fields we need for post-unlock emit_event into locals before
     * dropping map->lock — the region pointer itself is not stable once the
     * lock is released (another thread's munmap handler can free it).
     */
    u32 alert_event = 0;
    enum tms_region_tag alert_tag = TMS_TAG_UNKNOWN;
    u64 alert_va = 0, alert_size = 0;
    char alert_label[32] = {0};

    spin_lock(&map->lock);
    snap_subject_id = map->subject_id;

    /* Walk the tree and update all overlapping regions */
    for (n = rb_first(&map->regions); n; n = rb_next(n)) {
        region = rb_entry(n, struct tms_region, node);

        /* Skip regions entirely before our range */
        if (region->va_end <= addr)
            continue;
        /* Stop if we have passed our range */
        if (region->va_start >= end)
            break;

        /* This region overlaps [addr, end) */
        u32 old_prot = region->prot;
        region->prot = prot;

        /* Detect suspicious protection changes — snapshot fields, emit
         * after releasing the lock to avoid blocking the mprotect fast path
         * and to keep region dereferences strictly under the lock. */
        if (region->tag == TMS_TAG_TEXT && (prot & PROT_WRITE) &&
            !(old_prot & PROT_WRITE)) {
            alert_event = TMS_EVENT_W_TEXT;
            alert_tag = TMS_TAG_TEXT;
            alert_va = region->va_start;
            alert_size = region->va_end - region->va_start;
            strscpy(alert_label, region->label, sizeof(alert_label));
            break;
        }

        if (region->tag == TMS_TAG_HEAP && (prot & PROT_EXEC) &&
            !(old_prot & PROT_EXEC)) {
            alert_event = TMS_EVENT_EXEC_HEAP;
            alert_tag = TMS_TAG_HEAP;
            alert_va = region->va_start;
            alert_size = region->va_end - region->va_start;
            strscpy(alert_label, region->label, sizeof(alert_label));
            break;
        }
    }

    spin_unlock(&map->lock);

    if (alert_event)
        tms_emit_event(alert_event, snap_subject_id, pid,
                       alert_va, alert_size, prot, 0, alert_tag, alert_label);

    tms_emit_event(TMS_EVENT_PROTECT, snap_subject_id, pid,
                   addr, len, prot, 0, TMS_TAG_UNKNOWN, NULL);
}

/* ========================================================================
 * Pattern scanning
 * ======================================================================== */

/*
 * tms_add_pattern - Add a byte pattern to the global scan list.
 *
 * Returns 0 on success, -ENOSPC if pattern table is full, -EINVAL on bad args.
 */
int tms_add_pattern(const u8 *bytes, const u8 *mask, u16 len,
                     const char *name, u16 id, enum tms_region_tag tag)
{
    struct tms_pattern *p;

    if (!bytes || !mask || len == 0 || len > TMS_PATTERN_MAX_LEN)
        return -EINVAL;

    spin_lock(&g_tms.pattern_lock);
    if (g_tms.pattern_count >= TMS_MAX_PATTERNS) {
        spin_unlock(&g_tms.pattern_lock);
        return -ENOSPC;
    }

    p = &g_tms.patterns[g_tms.pattern_count];
    memcpy(p->bytes, bytes, len);
    memcpy(p->mask, mask, len);
    p->len = len;
    p->id = id;
    p->scan_in = tag;
    if (name)
        strscpy(p->name, name, sizeof(p->name));
    else
        p->name[0] = '\0';

    g_tms.pattern_count++;
    spin_unlock(&g_tms.pattern_lock);

    pr_debug("trust: TMS pattern added: id=%u name=%s len=%u tag=%d\n",
             id, name ? name : "", len, tag);
    return 0;
}

/*
 * Match a single pattern against a buffer.
 * Returns true if the pattern is found anywhere in [buf, buf+buf_len).
 */
static bool tms_pattern_match(const struct tms_pattern *pat,
                               const u8 *buf, size_t buf_len)
{
    size_t i, j;

    if (pat->len > buf_len)
        return false;

    for (i = 0; i <= buf_len - pat->len; i++) {
        bool found = true;
        for (j = 0; j < pat->len; j++) {
            if ((buf[i + j] & pat->mask[j]) != (pat->bytes[j] & pat->mask[j])) {
                found = false;
                break;
            }
        }
        if (found)
            return true;
    }
    return false;
}

/*
 * tms_scan_region - Scan a memory range for all registered patterns.
 *
 * This reads the target process memory page-by-page using the kernel
 * page table walk (get_user_pages). Only scans pages that are present
 * and readable.
 *
 * Returns the number of pattern hits found, or negative errno.
 */
int tms_scan_region(u32 subject_id, u64 va_start, u64 va_end)
{
    struct tms_subject_map *map;
    struct tms_region *region;
    struct task_struct *task;
    struct mm_struct *mm;
    struct page *page;
    u8 *kaddr;
    u64 addr;
    int hits = 0;
    u32 i;
    /*
     * Snapshot of the region found at va_start so we can filter patterns
     * and emit events without holding map->lock across the scan.  The
     * rbtree node itself must NOT be dereferenced after releasing the
     * lock — a concurrent munmap handler can free it.
     */
    bool region_present = false;
    enum tms_region_tag region_tag = TMS_TAG_UNKNOWN;
    u64 region_va_start = 0;

    if (!g_tms.enabled)
        return -ENODEV;

    /* Validate range: must be non-empty and cap scan size at 256 MiB so
     * a malicious/broken caller can't pin a CPU for arbitrary time
     * inside the page-by-page scan. */
    if (va_start >= va_end)
        return -EINVAL;
    if (va_end - va_start > (256ULL << 20))
        return -EINVAL;

    map = tms_find_map_by_subject(subject_id);
    if (!map)
        return -ENOENT;

    /* Snapshot region metadata for pattern filtering, plus map->pid which
     * can be zeroed by a concurrent tms_unregister_subject(). */
    pid_t snap_pid;
    spin_lock(&map->lock);
    region = tms_rbtree_find(map, va_start);
    if (region) {
        region_present = true;
        region_tag = region->tag;
        region_va_start = region->va_start;
    }
    snap_pid = map->pid;
    spin_unlock(&map->lock);
    region = NULL;  /* do not dereference outside the lock */

    if (snap_pid == 0)
        return -ESRCH;

    /* Find the target task */
    rcu_read_lock();
    task = find_task_by_vpid(snap_pid);
    if (task)
        get_task_struct(task);
    rcu_read_unlock();

    if (!task)
        return -ESRCH;

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return -ESRCH;

    /* Scan page by page */
    for (addr = va_start & PAGE_MASK; addr < va_end; addr += PAGE_SIZE) {
        int got;
        size_t scan_offset, scan_len;

        mmap_read_lock(mm);
        got = get_user_pages_remote(mm, addr, 1, 0, &page, NULL);
        mmap_read_unlock(mm);

        if (got <= 0)
            continue;

        kaddr = kmap(page);
        if (!kaddr) {
            put_page(page);
            continue;
        }

        /* Compute the actual range within this page to scan */
        scan_offset = (addr < va_start) ? (va_start - addr) : 0;
        scan_len = PAGE_SIZE - scan_offset;
        if (addr + PAGE_SIZE > va_end)
            scan_len = va_end - (addr + scan_offset);
        if (scan_len > PAGE_SIZE - scan_offset)
            scan_len = PAGE_SIZE - scan_offset;

        /* Check each pattern */
        spin_lock(&g_tms.pattern_lock);
        for (i = 0; i < g_tms.pattern_count; i++) {
            struct tms_pattern *pat = &g_tms.patterns[i];

            /* Filter by tag if the pattern requests it */
            if (pat->scan_in != TMS_TAG_UNKNOWN && region_present &&
                pat->scan_in != region_tag)
                continue;

            if (tms_pattern_match(pat, kaddr + scan_offset, scan_len)) {
                hits++;
                spin_unlock(&g_tms.pattern_lock);

                /* Update the region's hit counter — re-lookup under the
                 * lock since the original pointer is not stable across
                 * the unlocked scan. */
                if (region_present) {
                    struct tms_region *r;
                    spin_lock(&map->lock);
                    r = tms_rbtree_find(map, region_va_start);
                    if (r)
                        r->pattern_hits++;
                    spin_unlock(&map->lock);
                }

                tms_emit_event(TMS_EVENT_PATTERN, subject_id, snap_pid,
                               addr + scan_offset, scan_len, 0,
                               pat->id,
                               region_present ? region_tag : TMS_TAG_UNKNOWN,
                               pat->name);

                spin_lock(&g_tms.pattern_lock);
            }
        }
        spin_unlock(&g_tms.pattern_lock);

        kunmap(page);
        put_page(page);
    }

    mmput(mm);
    return hits;
}

/* ========================================================================
 * kprobe handlers
 *
 * These filter to only trust-tracked PIDs and extract the relevant
 * arguments from the registers before calling the tms_on_* functions.
 *
 * x86_64 calling convention (System V ABI):
 *   arg0=rdi, arg1=rsi, arg2=rdx, arg3=rcx, arg4=r8, arg5=r9
 * ======================================================================== */

/*
 * do_mmap(struct file *file, unsigned long addr, unsigned long len,
 *         unsigned long prot, unsigned long flags, ...)
 *
 * We extract: addr (rsi), len (rdx), prot (rcx).
 */
static int tms_kp_mmap_pre(struct kprobe *p, struct pt_regs *regs)
{
    pid_t pid;
    u64 addr, len;
    u32 prot;

    (void)p;

    if (!g_tms.enabled)
        return 0;

    pid = current->pid;

    /* Quick check: is this PID tracked? */
    if (!tms_find_map_by_pid(pid))
        return 0;

    addr = regs->si;    /* addr */
    len  = regs->dx;    /* len */
    prot = (u32)regs->cx; /* prot */

    tms_on_mmap(pid, addr, len, prot);
    return 0;
}

/*
 * __do_munmap(struct mm_struct *mm, unsigned long start, size_t len,
 *             struct list_head *uf, bool downgrade)
 *
 * We extract: start (rsi), len (rdx).
 */
static int tms_kp_munmap_pre(struct kprobe *p, struct pt_regs *regs)
{
    pid_t pid;
    u64 addr, len;

    (void)p;

    if (!g_tms.enabled)
        return 0;

    pid = current->pid;
    if (!tms_find_map_by_pid(pid))
        return 0;

    addr = regs->si;    /* start */
    len  = regs->dx;    /* len */

    tms_on_munmap(pid, addr, len);
    return 0;
}

/*
 * do_mprotect_pkey(unsigned long start, size_t len, unsigned long prot, int pkey)
 *
 * We extract: start (rdi), len (rsi), prot (rdx).
 */
static int tms_kp_mprotect_pre(struct kprobe *p, struct pt_regs *regs)
{
    pid_t pid;
    u64 addr, len;
    u32 prot;

    (void)p;

    if (!g_tms.enabled)
        return 0;

    pid = current->pid;
    if (!tms_find_map_by_pid(pid))
        return 0;

    addr = regs->di;    /* start */
    len  = regs->si;    /* len */
    prot = (u32)regs->dx; /* prot */

    tms_on_mprotect(pid, addr, len, prot);
    return 0;
}

/* ========================================================================
 * ioctl handler
 * ======================================================================== */

/*
 * tms_ioctl - Handle TMS-specific ioctl commands.
 *
 * Dispatched from trust_core.c's trust_ioctl().
 */
long tms_ioctl(unsigned int cmd, unsigned long arg)
{
    switch (cmd) {

    case TRUST_IOC_TMS_QUERY_MAP: {
        tms_ioc_query_map_t req;
        struct tms_subject_map *map;
        tms_ioc_region_info_t *snap;
        struct rb_node *n;
        u32 count, max, i;
        u64 __user *ubuf;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        map = tms_find_map_by_subject(req.subject_id);
        if (!map)
            return -ENOENT;

        max = req.max_regions;
        if (max == 0 || max > TMS_MAX_REGIONS_PER_SUBJECT)
            max = TMS_MAX_REGIONS_PER_SUBJECT;

        /*
         * Snapshot region metadata into a kernel buffer under map->lock,
         * then copy_to_user outside the lock.  Iterating the rbtree while
         * periodically releasing the lock lets a concurrent munmap free
         * the node pointed to by `n`, causing rb_next(freed) UAF.
         */
        snap = kvmalloc_array(max, sizeof(*snap), GFP_KERNEL | __GFP_ZERO);
        if (!snap)
            return -ENOMEM;

        count = 0;
        spin_lock(&map->lock);
        req.total = map->region_count;

        for (n = rb_first(&map->regions); n && count < max; n = rb_next(n)) {
            struct tms_region *r = rb_entry(n, struct tms_region, node);
            tms_ioc_region_info_t *info = &snap[count];

            info->va_start = r->va_start;
            info->va_end = r->va_end;
            info->prot = r->prot;
            info->tag = r->tag;
            strscpy(info->label, r->label, sizeof(info->label));
            info->load_time_ns = r->load_time_ns;
            info->pattern_hits = r->pattern_hits;
            count++;
        }
        spin_unlock(&map->lock);

        ubuf = (u64 __user *)req.buf;
        for (i = 0; i < count; i++) {
            if (copy_to_user((void __user *)ubuf +
                             i * sizeof(tms_ioc_region_info_t),
                             &snap[i], sizeof(snap[i]))) {
                kvfree(snap);
                return -EFAULT;
            }
        }
        kvfree(snap);

        req.returned = count;
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_TMS_REGISTER_SECTION: {
        tms_ioc_register_section_t req;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        req.label[sizeof(req.label) - 1] = '\0';
        req.result = tms_register_section(req.subject_id, req.va_start,
                                           req.size, (enum tms_region_tag)req.tag,
                                           req.label);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_TMS_ADD_PATTERN: {
        tms_ioc_add_pattern_t req;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        req.name[sizeof(req.name) - 1] = '\0';
        req.result = tms_add_pattern(req.bytes, req.mask, req.len,
                                      req.name, req.id,
                                      (enum tms_region_tag)req.scan_in);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case TRUST_IOC_TMS_SCAN_REGION: {
        tms_ioc_scan_region_t req;
        int ret;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        ret = tms_scan_region(req.subject_id, req.va_start, req.va_end);
        if (ret < 0) {
            req.result = ret;
            req.hits = 0;
        } else {
            req.result = 0;
            req.hits = (u32)ret;
        }
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

static void tms_netlink_recv(struct sk_buff *skb)
{
    /* We only send events to userspace; inbound messages are ignored. */
    (void)skb;
}

static int tms_netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = tms_netlink_recv,
        .groups = TMS_NETLINK_GROUP,
    };

    g_tms.nl_sock = netlink_kernel_create(&init_net, TMS_NETLINK_PROTO, &cfg);
    if (!g_tms.nl_sock) {
        pr_warn("trust: TMS netlink socket creation failed "
                "(non-fatal, events disabled)\n");
        return -ENOMEM;
    }
    return 0;
}

static void tms_netlink_cleanup(void)
{
    if (g_tms.nl_sock) {
        netlink_kernel_release(g_tms.nl_sock);
        g_tms.nl_sock = NULL;
    }
}

/* ========================================================================
 * Module init / cleanup
 * ======================================================================== */

/*
 * tms_init - Initialize the Trust Memory Scanner subsystem.
 *
 * Allocates per-subject map array, registers kprobes, creates netlink socket.
 * Called from trust_core.c trust_init().
 *
 * Returns 0 on success, negative errno on failure.
 */
int tms_init(void)
{
    int ret;
    u32 i;

    memset(&g_tms, 0, sizeof(g_tms));
    g_tms.max_subjects = TMS_MAX_SUBJECTS;
    atomic_set(&g_tms.event_seq, 0);
    spin_lock_init(&g_tms.pattern_lock);

    /* Allocate subject map array */
    g_tms.maps = vzalloc(g_tms.max_subjects * sizeof(struct tms_subject_map));
    if (!g_tms.maps) {
        pr_err("trust: TMS failed to allocate subject maps (%zu bytes)\n",
               (size_t)(g_tms.max_subjects * sizeof(struct tms_subject_map)));
        return -ENOMEM;
    }

    for (i = 0; i < g_tms.max_subjects; i++) {
        spin_lock_init(&g_tms.maps[i].lock);
        g_tms.maps[i].regions = RB_ROOT;
        g_tms.maps[i].active = false;
    }

    /* Create netlink socket (non-fatal if it fails) */
    tms_netlink_init();

    /* Register kprobes */
    ret = register_kprobe(&tms_kp_mmap);
    if (ret < 0) {
        pr_warn("trust: TMS kprobe do_mmap failed (%d), "
                "mmap tracking disabled\n", ret);
        /* Non-fatal: TMS still works for explicit registration */
    }

    ret = register_kprobe(&tms_kp_munmap);
    if (ret < 0) {
        pr_warn("trust: TMS kprobe __do_munmap failed (%d), "
                "munmap tracking disabled\n", ret);
    }

    ret = register_kprobe(&tms_kp_mprotect);
    if (ret < 0) {
        pr_warn("trust: TMS kprobe do_mprotect_pkey failed (%d), "
                "mprotect tracking disabled\n", ret);
    }

    g_tms.enabled = true;

    pr_info("trust: TMS initialized: %u subject slots, %u max patterns, "
            "netlink proto %d\n",
            g_tms.max_subjects, TMS_MAX_PATTERNS, TMS_NETLINK_PROTO);
    return 0;
}

/*
 * tms_cleanup - Tear down the Trust Memory Scanner subsystem.
 *
 * Unregisters kprobes, destroys all tracked regions, frees memory.
 * Called from trust_core.c trust_exit().
 */
void tms_cleanup(void)
{
    u32 i;

    g_tms.enabled = false;

    /* Unregister kprobes (safe to call even if registration failed) */
    if (tms_kp_mmap.addr)
        unregister_kprobe(&tms_kp_mmap);
    if (tms_kp_munmap.addr)
        unregister_kprobe(&tms_kp_munmap);
    if (tms_kp_mprotect.addr)
        unregister_kprobe(&tms_kp_mprotect);

    /* Destroy all tracked regions */
    if (g_tms.maps) {
        for (i = 0; i < g_tms.max_subjects; i++) {
            if (g_tms.maps[i].active) {
                spin_lock(&g_tms.maps[i].lock);
                tms_rbtree_destroy(&g_tms.maps[i]);
                g_tms.maps[i].active = false;
                spin_unlock(&g_tms.maps[i].lock);
            }
        }
        vfree(g_tms.maps);
        g_tms.maps = NULL;
    }

    tms_netlink_cleanup();

    pr_info("trust: TMS cleaned up\n");
}

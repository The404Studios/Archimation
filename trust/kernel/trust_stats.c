/*
 * trust_stats.c - Runtime instrumentation for the dispatcher
 *
 * Per-CPU counters aggregated on demand via sysfs.  The counters are the
 * hot-path write set; keeping them per-CPU avoids any atomic RMW or
 * shared cacheline ping-pong on the dispatcher's fast path.  Reads
 * walk online CPUs and sum (O(NR_CPUS), invoked from sysfs show
 * handler which is rare).
 *
 * Exported sysfs surface (registered in trust_stats_register()):
 *
 *   /sys/kernel/trust/stats   (0444)   KEY=VALUE lines
 *   /sys/kernel/trust/caps    (0444)   hex bitmap of TRUST_CAP_BIT_*
 *
 * Both files are read-only to userspace (mode 0444).  Writes are
 * rejected (no .store attribute is registered).  The files live under
 * a kobject rooted at kernel_kobj which is owned by root by default,
 * so an unprivileged read is still allowed but write via `echo > ...`
 * returns -EACCES at the VFS layer before it ever reaches us.
 *
 * Lock discipline: none.  All counters are __this_cpu_inc/add.  The
 * sysfs readers are serialized by sysfs itself; no additional lock
 * needed.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/cpumask.h>
#include <linux/ktime.h>
#include <linux/slab.h>

#include "trust_internal.h"
#include "trust_isa.h"

/* ==================================================================
 * Per-CPU counters.
 *
 * All u64.  Initialized to zero by the percpu allocator at load.
 * Saturating arithmetic would be nice but overflow at u64 is not a
 * realistic concern (at 1ns/op, 2^64 ns ~ 584 years).
 * ================================================================== */

DEFINE_PER_CPU(u64, trust_stat_dispatch_total);
DEFINE_PER_CPU(u64, trust_stat_scalar_fallback);
DEFINE_PER_CPU(u64, trust_stat_predicate_skips);
DEFINE_PER_CPU(u64, trust_stat_fused_hits);
DEFINE_PER_CPU(u64, trust_stat_vec_hits);
DEFINE_PER_CPU(u64, trust_stat_dispatch_time_ns);
DEFINE_PER_CPU(u64, trust_stat_cmdbuf_bytes_in);
DEFINE_PER_CPU(u64, trust_stat_cmdbuf_bytes_varlen);

/* Session 34 R34: counts instructions rejected at dispatch time because
 * their context_mask did not include the current context bit.  Bumped
 * from trust_dispatch.c via trust_stats_record_context_mask_reject();
 * aggregated into /sys/kernel/trust/stats as
 * `context_mask_rejects=N`. */
DEFINE_PER_CPU(u64, trust_stat_context_mask_rejects);

/* One counter slot per family (0..7); index 0-5 are legacy, 6=VEC, 7=FUSED.
 *
 * We use a percpu struct so `per_cpu_ptr(&g_fam_stats, cpu)` returns a
 * clean pointer-to-struct and `->slot[f]` addresses each family
 * individually.  Using DEFINE_PER_CPU(u64[N], ...) works at the
 * DEFINE site but the per_cpu_ptr() invocation type-decays awkwardly
 * on some compilers; wrapping in a struct avoids the ambiguity. */
struct trust_fam_stats {
	u64 slot[TRUST_STAT_FAMILY_SLOTS];
};
DEFINE_PER_CPU(struct trust_fam_stats, trust_stat_dispatch_by_family);

/*
 * VEC rolling average of `nops` (batch size).  Stored as fixed-point
 * 16.16 accumulator plus a sample count; readable as (acc / samples)
 * shifted by 16 for the integer mean.  Kept per-CPU to avoid lock
 * contention; summed on read.
 */
DEFINE_PER_CPU(u64, trust_stat_vec_batch_acc_q16);
DEFINE_PER_CPU(u64, trust_stat_vec_batch_samples);

/* ==================================================================
 * Capability bitmap (advertised to userspace).  Populated at module
 * init in trust_stats_register(); const after that.  Bits align with
 * TRUST_STAT_CAP_BIT_* in trust_internal.h.
 * ================================================================== */

static u64 trust_caps_bitmap_value;

u64 trust_stats_caps_bitmap(void)
{
	return trust_caps_bitmap_value;
}
EXPORT_SYMBOL_GPL(trust_stats_caps_bitmap);

/* ==================================================================
 * Aggregation helpers.  Called from sysfs read path only.
 * ================================================================== */

static u64 agg_percpu_u64(u64 __percpu *var)
{
	u64 sum = 0;
	int cpu;
	for_each_possible_cpu(cpu)
		sum += *per_cpu_ptr(var, cpu);
	return sum;
}

static u64 agg_family(unsigned int fam)
{
	u64 sum = 0;
	int cpu;
	if (fam >= TRUST_STAT_FAMILY_SLOTS)
		return 0;
	for_each_possible_cpu(cpu) {
		struct trust_fam_stats *fs =
			per_cpu_ptr(&trust_stat_dispatch_by_family, cpu);
		sum += fs->slot[fam];
	}
	return sum;
}

/*
 * Average batch size (q16 fixed point).  Returns integer mean in the
 * output's low bits; caller can divide by samples themselves for
 * higher precision. To keep the sysfs line simple, we emit the
 * fixed-point value AND samples so userspace can do the division.
 */
static void agg_vec_avg(u64 *out_acc_q16, u64 *out_samples)
{
	u64 acc = 0, samples = 0;
	int cpu;
	for_each_possible_cpu(cpu) {
		acc     += *per_cpu_ptr(&trust_stat_vec_batch_acc_q16, cpu);
		samples += *per_cpu_ptr(&trust_stat_vec_batch_samples, cpu);
	}
	if (out_acc_q16) *out_acc_q16 = acc;
	if (out_samples) *out_samples = samples;
}

/* ==================================================================
 * sysfs show handlers.
 *
 * 4096 byte PAGE_SIZE is the hard limit for a single attribute's
 * buffer.  Our output is well under that (< 512 bytes).
 * ================================================================== */

static ssize_t stats_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	ssize_t n = 0;
	u64 vec_avg_acc = 0, vec_avg_samples = 0;
	u64 fam[TRUST_STAT_FAMILY_SLOTS];
	unsigned int i;

	(void)kobj; (void)attr;

	for (i = 0; i < TRUST_STAT_FAMILY_SLOTS; i++)
		fam[i] = agg_family(i);

	agg_vec_avg(&vec_avg_acc, &vec_avg_samples);

	n += scnprintf(buf + n, PAGE_SIZE - n,
		       "dispatch_total=%llu\n",
		       (unsigned long long)agg_percpu_u64(&trust_stat_dispatch_total));
	n += scnprintf(buf + n, PAGE_SIZE - n,
		       "dispatch_by_family_auth=%llu\n",  (unsigned long long)fam[0]);
	n += scnprintf(buf + n, PAGE_SIZE - n,
		       "dispatch_by_family_trust=%llu\n", (unsigned long long)fam[1]);
	n += scnprintf(buf + n, PAGE_SIZE - n,
		       "dispatch_by_family_gate=%llu\n",  (unsigned long long)fam[2]);
	n += scnprintf(buf + n, PAGE_SIZE - n,
		       "dispatch_by_family_res=%llu\n",   (unsigned long long)fam[3]);
	n += scnprintf(buf + n, PAGE_SIZE - n,
		       "dispatch_by_family_life=%llu\n",  (unsigned long long)fam[4]);
	n += scnprintf(buf + n, PAGE_SIZE - n,
		       "dispatch_by_family_meta=%llu\n",  (unsigned long long)fam[5]);
	n += scnprintf(buf + n, PAGE_SIZE - n,
		       "dispatch_by_family_vec=%llu\n",   (unsigned long long)fam[6]);
	n += scnprintf(buf + n, PAGE_SIZE - n,
		       "dispatch_by_family_fused=%llu\n", (unsigned long long)fam[7]);
	n += scnprintf(buf + n, PAGE_SIZE - n,
		       "fused_hits=%llu\n",
		       (unsigned long long)agg_percpu_u64(&trust_stat_fused_hits));
	n += scnprintf(buf + n, PAGE_SIZE - n,
		       "vec_hits=%llu\n",
		       (unsigned long long)agg_percpu_u64(&trust_stat_vec_hits));
	/* Emit both the fixed-point accumulator and the sample count.
	 * Userspace computes the mean as (acc_q16 / samples) / 65536.
	 * For convenience also emit an integer mean (floor) on the next
	 * line so simple grep parsers get a usable number. */
	{
		u64 mean_q16 = 0;
		if (vec_avg_samples)
			mean_q16 = vec_avg_acc / vec_avg_samples;
		n += scnprintf(buf + n, PAGE_SIZE - n,
			       "vec_avg_batch_size_q16=%llu\n",
			       (unsigned long long)mean_q16);
		n += scnprintf(buf + n, PAGE_SIZE - n,
			       "vec_avg_batch_size_samples=%llu\n",
			       (unsigned long long)vec_avg_samples);
		n += scnprintf(buf + n, PAGE_SIZE - n,
			       "vec_avg_batch_size=%llu\n",
			       (unsigned long long)(mean_q16 >> 16));
	}
	n += scnprintf(buf + n, PAGE_SIZE - n,
		       "scalar_fallback=%llu\n",
		       (unsigned long long)agg_percpu_u64(&trust_stat_scalar_fallback));
	n += scnprintf(buf + n, PAGE_SIZE - n,
		       "predicate_skips=%llu\n",
		       (unsigned long long)agg_percpu_u64(&trust_stat_predicate_skips));
	n += scnprintf(buf + n, PAGE_SIZE - n,
		       "dispatch_time_ns=%llu\n",
		       (unsigned long long)agg_percpu_u64(&trust_stat_dispatch_time_ns));
	n += scnprintf(buf + n, PAGE_SIZE - n,
		       "cmdbuf_bytes_in=%llu\n",
		       (unsigned long long)agg_percpu_u64(&trust_stat_cmdbuf_bytes_in));
	n += scnprintf(buf + n, PAGE_SIZE - n,
		       "cmdbuf_bytes_varlen=%llu\n",
		       (unsigned long long)agg_percpu_u64(&trust_stat_cmdbuf_bytes_varlen));
	n += scnprintf(buf + n, PAGE_SIZE - n,
		       "context_mask_rejects=%llu\n",
		       (unsigned long long)agg_percpu_u64(&trust_stat_context_mask_rejects));

	return n;
}

static ssize_t caps_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	(void)kobj; (void)attr;
	return scnprintf(buf, PAGE_SIZE, "0x%016llx\n",
			 (unsigned long long)trust_caps_bitmap_value);
}

/*
 * opcodes_show - Emit one line per (family, opcode) with context mask.
 *
 * Format:
 *     FAMILY.OPCODE  ctx=NORMAL|DEGRADED|...  (0xNN)
 *
 * Read-only (0444).  Implemented in trust_dispatch_tables.c so the
 * metadata stays next to the table itself; we just forward the
 * sysfs buffer.
 */
static ssize_t opcodes_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	(void)kobj; (void)attr;
	return trust_opcode_meta_show_sysfs(buf, PAGE_SIZE);
}

/* ==================================================================
 * sysfs kobject + attribute wiring
 * ================================================================== */

static struct kobj_attribute trust_stats_attr =
	__ATTR(stats, 0444, stats_show, NULL);
static struct kobj_attribute trust_caps_attr =
	__ATTR(caps,  0444, caps_show,  NULL);
static struct kobj_attribute trust_opcodes_attr =
	__ATTR(opcodes, 0444, opcodes_show, NULL);

static struct attribute *trust_stats_attrs[] = {
	&trust_stats_attr.attr,
	&trust_caps_attr.attr,
	&trust_opcodes_attr.attr,
	NULL,
};

static const struct attribute_group trust_stats_group = {
	.attrs = trust_stats_attrs,
};

static struct kobject *trust_stats_kobj;

int trust_stats_register(void)
{
	int ret;

	/* Populate the capability bitmap. These bits are what libtrust
	 * checks via /sys/kernel/trust/caps and TRUST_IOC_QUERY_CAPS.
	 * They stay in sync because both paths read
	 * trust_stats_caps_bitmap(). */
	trust_caps_bitmap_value =
		(1ULL << TRUST_STAT_CAP_BIT_VEC)    |
		(1ULL << TRUST_STAT_CAP_BIT_FUSED)  |
		(1ULL << TRUST_STAT_CAP_BIT_VARLEN) |
		(1ULL << TRUST_STAT_CAP_BIT_PRED)   |
		(1ULL << TRUST_STAT_CAP_BIT_EVT_BIN);

	trust_stats_kobj = kobject_create_and_add("trust", kernel_kobj);
	if (!trust_stats_kobj)
		return -ENOMEM;

	ret = sysfs_create_group(trust_stats_kobj, &trust_stats_group);
	if (ret) {
		kobject_put(trust_stats_kobj);
		trust_stats_kobj = NULL;
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(trust_stats_register);

void trust_stats_unregister(void)
{
	if (trust_stats_kobj) {
		sysfs_remove_group(trust_stats_kobj, &trust_stats_group);
		kobject_put(trust_stats_kobj);
		trust_stats_kobj = NULL;
	}
}
EXPORT_SYMBOL_GPL(trust_stats_unregister);

/* ==================================================================
 * Hot-path counter helpers (inline-friendly).  These are the points
 * the dispatcher hits on every instruction.
 * ================================================================== */

void trust_stats_record_dispatch(unsigned int family)
{
	this_cpu_inc(trust_stat_dispatch_total);
	if (family < TRUST_STAT_FAMILY_SLOTS) {
		struct trust_fam_stats *fs =
			this_cpu_ptr(&trust_stat_dispatch_by_family);
		fs->slot[family]++;
	}
}
EXPORT_SYMBOL_GPL(trust_stats_record_dispatch);

void trust_stats_record_fused_hit(void)
{
	this_cpu_inc(trust_stat_fused_hits);
}
EXPORT_SYMBOL_GPL(trust_stats_record_fused_hit);

void trust_stats_record_vec_hit(u32 nops)
{
	this_cpu_inc(trust_stat_vec_hits);
	/* q16 accumulator; samples += 1 per VEC op dispatched. */
	this_cpu_add(trust_stat_vec_batch_acc_q16, ((u64)nops) << 16);
	this_cpu_inc(trust_stat_vec_batch_samples);
}
EXPORT_SYMBOL_GPL(trust_stats_record_vec_hit);

void trust_stats_record_scalar_fallback(void)
{
	this_cpu_inc(trust_stat_scalar_fallback);
}
EXPORT_SYMBOL_GPL(trust_stats_record_scalar_fallback);

void trust_stats_record_predicate_skip(void)
{
	this_cpu_inc(trust_stat_predicate_skips);
}
EXPORT_SYMBOL_GPL(trust_stats_record_predicate_skip);

void trust_stats_record_dispatch_time(u64 ns)
{
	this_cpu_add(trust_stat_dispatch_time_ns, ns);
}
EXPORT_SYMBOL_GPL(trust_stats_record_dispatch_time);

void trust_stats_record_cmdbuf_in(u32 total_bytes, u32 varlen_bytes)
{
	if (total_bytes)
		this_cpu_add(trust_stat_cmdbuf_bytes_in, total_bytes);
	if (varlen_bytes)
		this_cpu_add(trust_stat_cmdbuf_bytes_varlen, varlen_bytes);
}
EXPORT_SYMBOL_GPL(trust_stats_record_cmdbuf_in);

void trust_stats_record_context_mask_reject(void)
{
	this_cpu_inc(trust_stat_context_mask_rejects);
}
EXPORT_SYMBOL_GPL(trust_stats_record_context_mask_reject);

MODULE_LICENSE("GPL");

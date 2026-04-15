/*
 * proc_reader_priv.h — PRIVATE to the measurement layer.
 *
 * Not installed; included only by measurement.c and proc_reader.c. Keeps the
 * public measurement.h free of implementation detail while still letting us
 * keep the /proc parsing in a dedicated translation unit.
 */
#ifndef COH_PROC_READER_PRIV_H
#define COH_PROC_READER_PRIV_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
	uint64_t busy_jiffies;
	uint64_t idle_jiffies;
} pr_cpu_sample_t;

/* Generic: slurp up to `cap` bytes from `fd` via pread, NUL-terminate.
 * Returns byte count or -errno. */
ssize_t pr_slurp_fd(int fd, char *buf, size_t cap);

/* Parsing primitives. */
const char *pr_parse_u64(const char *p, const char *end, uint64_t *value);
const char *pr_skip_ws(const char *p, const char *end);
const char *pr_skip_line(const char *p, const char *end);

/* /proc/stat → per-cpu busy/idle + aggregate ctxt count.
 * Returns number of CPU entries parsed, or -errno. */
int pr_parse_proc_stat(const char *buf, size_t len,
                       pr_cpu_sample_t *cpus, int cpu_cap,
                       uint64_t *ctxt_total_out);

/* /proc/schedstat → aggregate migrations since boot. */
int pr_parse_schedstat(const char *buf, size_t len, uint64_t *migrations_out);

/* /proc/interrupts → per-cpu column totals summed across all IRQ rows.
 * Returns number of CPU columns parsed (clamped to cpu_cap), or -errno. */
int pr_parse_interrupts(const char *buf, size_t len,
                        uint64_t *per_cpu_totals, int cpu_cap);

#endif /* COH_PROC_READER_PRIV_H */

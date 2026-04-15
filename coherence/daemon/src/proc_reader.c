/*
 * proc_reader.c — Small, allocation-free helpers for /proc fast-path reads.
 *
 * All functions here are single-threaded, called from measurement_sample().
 * They handle partial reads (pseudo-files are NOT block-buffered — a single
 * read() may return less than the logical file size even at offset 0).
 *
 * The public API is not exposed through measurement.h; these are
 * translation-unit-local to the measurement layer. We declare them in a
 * tiny private header embedded below so measurement.c can pick them up.
 *
 * SIZING:
 *   /proc/stat on a 64-CPU host is ~5 KB (each "cpuN" line is <80 bytes).
 *   /proc/interrupts on a 64-CPU host with ~300 IRQs is ~30 KB; we cap to
 *   16 KB per the spec, which matches most desktops (single NUMA, <64 CPUs,
 *   ~200 IRQs). We emit a warning bit on truncation and use whatever we got.
 *   /proc/schedstat is ~1 KB.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "proc_reader_priv.h"

/* ===== Generic bounded read from a pseudo-file ===== */

/*
 * Read as much as possible from `fd` into `buf` (size `cap`). Uses pread
 * with offset 0 so we never need to seek. Returns number of bytes read,
 * or -errno on failure. On EOF before cap bytes, returns short count.
 *
 * /proc pseudo-files can return less than a full "snapshot" in a single
 * read. We loop until we hit EOF or fill the buffer. Each iteration
 * advances the pread offset so we capture contiguous bytes.
 *
 * NOTE: callers guarantee `cap` is within their pre-allocated static buffer
 * so there is never malloc on the hot path.
 */
ssize_t pr_slurp_fd(int fd, char *buf, size_t cap)
{
	if (fd < 0 || !buf || cap == 0)
		return -EINVAL;

	size_t off = 0;
	while (off < cap) {
		ssize_t n = pread(fd, buf + off, cap - off, (off_t)off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			break;
		off += (size_t)n;
	}

	/* Always NUL-terminate one byte past the last data byte if room, else
	 * overwrite the final byte. This keeps string scanners safe. */
	if (off < cap)
		buf[off] = '\0';
	else
		buf[cap - 1] = '\0';

	return (ssize_t)off;
}

/* ===== Minimal integer parsers (no libc scanf) ===== */

/*
 * Parse an unsigned 64-bit decimal from the span [p, end).
 * Returns pointer to the first non-digit (may equal `end`). On no digits,
 * *value is set to 0 and the original p is returned.
 */
const char *pr_parse_u64(const char *p, const char *end, uint64_t *value)
{
	uint64_t v = 0;
	const char *q = p;
	while (q < end && *q >= '0' && *q <= '9') {
		v = v * 10u + (uint64_t)(*q - '0');
		q++;
	}
	*value = v;
	return q;
}

/*
 * Skip zero or more ASCII whitespace chars (space, tab). Newlines are
 * deliberately NOT skipped here — callers want to detect end-of-line.
 */
const char *pr_skip_ws(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t'))
		p++;
	return p;
}

/*
 * Advance to the next '\n' (inclusive of the newline). Returns pointer just
 * past '\n', or `end` if no newline present.
 */
const char *pr_skip_line(const char *p, const char *end)
{
	while (p < end && *p != '\n')
		p++;
	if (p < end)
		p++;
	return p;
}

/* ===== /proc/stat parser =====
 *
 * Layout (excerpt):
 *   cpu  user nice sys idle iowait irq softirq steal guest guest_nice
 *   cpu0 user nice sys idle iowait irq softirq steal guest guest_nice
 *   ...
 *   intr ...
 *   ctxt N
 *   btime N
 *   processes N
 *
 * We compute per-CPU busy/idle delta since the prior snapshot. "Idle" for
 * our purposes is (idle + iowait); everything else is busy.
 *
 * Returns number of per-CPU entries populated (also the caller's cpu_count
 * upper bound). On parse failure returns -EINVAL but does NOT clobber `out`
 * — caller will carry forward last-known values.
 */
int pr_parse_proc_stat(const char *buf, size_t len,
                       pr_cpu_sample_t *cpus, int cpu_cap,
                       uint64_t *ctxt_total_out)
{
	if (!buf || len == 0 || !cpus || cpu_cap <= 0)
		return -EINVAL;

	const char *p = buf;
	const char *end = buf + len;
	int cpu_n = 0;
	uint64_t ctxt = 0;
	int have_ctxt = 0;

	while (p < end) {
		/* Skip the aggregate "cpu " line — only per-cpu "cpuN" are kept. */
		if (p + 4 < end && p[0] == 'c' && p[1] == 'p' && p[2] == 'u') {
			const char *q = p + 3;
			if (q < end && *q >= '0' && *q <= '9') {
				/* per-cpu line: "cpuN user nice sys idle iowait irq softirq steal guest guest_nice" */
				uint64_t cpu_idx = 0;
				q = pr_parse_u64(q, end, &cpu_idx);
				if ((int)cpu_idx < cpu_cap) {
					uint64_t u = 0, n = 0, s = 0, idle = 0, iow = 0;
					uint64_t irqv = 0, sirq = 0, steal = 0, guest = 0, gn = 0;
					q = pr_skip_ws(q, end); q = pr_parse_u64(q, end, &u);
					q = pr_skip_ws(q, end); q = pr_parse_u64(q, end, &n);
					q = pr_skip_ws(q, end); q = pr_parse_u64(q, end, &s);
					q = pr_skip_ws(q, end); q = pr_parse_u64(q, end, &idle);
					q = pr_skip_ws(q, end); q = pr_parse_u64(q, end, &iow);
					q = pr_skip_ws(q, end); q = pr_parse_u64(q, end, &irqv);
					q = pr_skip_ws(q, end); q = pr_parse_u64(q, end, &sirq);
					q = pr_skip_ws(q, end); q = pr_parse_u64(q, end, &steal);
					q = pr_skip_ws(q, end); q = pr_parse_u64(q, end, &guest);
					q = pr_skip_ws(q, end); q = pr_parse_u64(q, end, &gn);

					uint64_t busy = u + n + s + irqv + sirq + steal;
					uint64_t idle_total = idle + iow;

					/* steal/guest are included in 'user' on modern kernels
					 * so we subtract guest/gn from busy to avoid double
					 * count. */
					if (busy >= (guest + gn))
						busy -= (guest + gn);

					cpus[cpu_idx].busy_jiffies = busy;
					cpus[cpu_idx].idle_jiffies = idle_total;
					if ((int)cpu_idx + 1 > cpu_n)
						cpu_n = (int)cpu_idx + 1;
				}
			}
			/* "cpu " aggregate line or cpu entry beyond cap — skip. */
		} else if (p + 5 <= end && p[0] == 'c' && p[1] == 't' && p[2] == 'x' &&
		           p[3] == 't' && p[4] == ' ') {
			const char *q = p + 5;
			q = pr_skip_ws(q, end);
			q = pr_parse_u64(q, end, &ctxt);
			have_ctxt = 1;
			(void)q;
		}
		p = pr_skip_line(p, end);
	}

	if (ctxt_total_out && have_ctxt)
		*ctxt_total_out = ctxt;

	return cpu_n;
}

/* ===== /proc/schedstat parser =====
 *
 * Per man/kernel doc, "cpu<N>" lines have 9 fields; field index 5 (1-based)
 * is "# of tasks moved to this runqueue" — i.e. migrations-INTO. Summed
 * across CPUs this gives total migrations since boot. We report the delta.
 *
 * Format:
 *   cpuN yld_cnt _ _ _ sched_cnt sched_goidle ttwu_cnt ttwu_local ...
 * With kernel 2.6.23+ schedstat version 15 the relevant layout is:
 *   version 15
 *   timestamp ...
 *   cpu0 A B C D E F G H I ...
 * where E (5th numeric) is the migration count.
 *
 * For portability we accept a simple rule: sum the 5th whitespace-separated
 * field on every line starting with "cpu".
 */
int pr_parse_schedstat(const char *buf, size_t len, uint64_t *migrations_out)
{
	if (!buf || len == 0 || !migrations_out)
		return -EINVAL;

	const char *p = buf;
	const char *end = buf + len;
	uint64_t total = 0;

	while (p < end) {
		if (p + 3 < end && p[0] == 'c' && p[1] == 'p' && p[2] == 'u' &&
		    (p[3] >= '0' && p[3] <= '9')) {
			/* Skip "cpuN" token. */
			const char *q = p + 3;
			while (q < end && *q >= '0' && *q <= '9')
				q++;
			/* Read 5 whitespace-separated unsigned ints; keep the 5th. */
			uint64_t v = 0;
			for (int i = 0; i < 5 && q < end; i++) {
				q = pr_skip_ws(q, end);
				v = 0;
				q = pr_parse_u64(q, end, &v);
			}
			total += v;
		}
		p = pr_skip_line(p, end);
	}

	*migrations_out = total;
	return 0;
}

/* ===== /proc/interrupts parser =====
 *
 * First line is a header with "CPU0 CPU1 ...". Subsequent rows start with
 * an IRQ number or name followed by per-CPU counts. We sum the N-th column
 * across all rows to yield per-CPU interrupt counts.
 *
 * Because /proc/interrupts is expensive, we cap input at 16 KB. If the file
 * is longer we silently drop the tail; per-CPU totals will undercount
 * slightly but stay proportional.
 */
int pr_parse_interrupts(const char *buf, size_t len,
                        uint64_t *per_cpu_totals, int cpu_cap)
{
	if (!buf || len == 0 || !per_cpu_totals || cpu_cap <= 0)
		return -EINVAL;

	const char *p = buf;
	const char *end = buf + len;

	/* Parse header to count CPU columns; assume header line starts with
	 * optional whitespace followed by "CPU". */
	int ncols = 0;
	{
		const char *q = pr_skip_ws(p, end);
		while (q < end && *q != '\n') {
			if (q + 3 <= end && q[0] == 'C' && q[1] == 'P' && q[2] == 'U') {
				ncols++;
				/* skip "CPU<digits>" */
				q += 3;
				while (q < end && *q >= '0' && *q <= '9')
					q++;
			} else {
				q++;
			}
		}
		p = pr_skip_line(p, end);
	}
	if (ncols <= 0)
		return -EINVAL;
	if (ncols > cpu_cap)
		ncols = cpu_cap;

	/* Zero totals. */
	for (int i = 0; i < ncols; i++)
		per_cpu_totals[i] = 0;

	/* Iterate data rows. Each row: "  <irq>: <n0> <n1> ... <nCOL-1>  <kind> <name>" */
	while (p < end) {
		const char *q = pr_skip_ws(p, end);
		/* Skip IRQ label — everything up to ':' or whitespace. */
		/* IRQ label may contain letters (NMI, LOC, etc.) so we scan until ':' */
		while (q < end && *q != ':' && *q != '\n')
			q++;
		if (q >= end || *q == '\n') {
			p = pr_skip_line(p, end);
			continue;
		}
		q++; /* past ':' */

		for (int col = 0; col < ncols && q < end; col++) {
			q = pr_skip_ws(q, end);
			if (q >= end || *q == '\n')
				break;
			uint64_t v = 0;
			q = pr_parse_u64(q, end, &v);
			per_cpu_totals[col] += v;
		}
		p = pr_skip_line(p, end);
	}

	return ncols;
}

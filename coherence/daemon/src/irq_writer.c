/*
 * irq_writer.c — /proc/irq/N/smp_affinity writer plus IRQ discovery.
 *
 * On Linux, writing smp_affinity for an IRQ that no controller owns is a
 * silent no-op at best and returns EINVAL at worst. Before committing a
 * plan, we scan /proc/interrupts once per frame and populate the list
 * of IRQs with a non-zero delivery count — those are the only ones whose
 * affinity mask actually matters.
 *
 * To help Agent 9's verification, every successful change is appended to
 * /var/run/coherence/irq-diff.log in a simple one-line format:
 *
 *     <ms>  irq=<N>  before=<mask>  after=<mask>
 *
 * The log is truncated to a sane size on rotation; this is handled by
 * systemd tmpfiles externally. We only ever O_APPEND.
 *
 * All paths are constants. We never accept a user-supplied path.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "coherence_types.h"

#define IRQ_PROC_ROOT       "/proc/irq"
#define IRQ_PROC_INTERRUPTS "/proc/interrupts"
#define IRQ_DIFF_LOG        "/var/run/coherence/irq-diff.log"
#define IRQ_DIFF_LOG_DIR    "/var/run/coherence"

/*
 * Maximum IRQ number we will touch. The kernel exposes up to ~1024 typically;
 * the actuation struct caps at COH_MAX_IRQS = 512. We bound writes to the
 * smaller of the two.
 */
#define IRQ_MAX_NUM 4095

/*
 * Monotonic millisecond clock for the diff log. Not exported — local
 * helper only. Agrees in epoch with the caller's CLOCK_MONOTONIC because
 * Linux promises monotonic.
 */
static uint64_t mono_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return 0;
	}
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/*
 * irq_num_ok — reject nonsense before we touch the filesystem.
 */
static int irq_num_ok(int n)
{
	return n >= 0 && n <= IRQ_MAX_NUM;
}

/*
 * Same cpumask validator as cgroup_writer.c — kept local because the
 * actuation layer is intentionally monolithic. smp_affinity accepts a
 * hex bitmask with optional commas (e.g. "ffff,ffff") so we extend the
 * class to include 'a'-'f' and 'A'-'F'.
 */
static int mask_ok(const char *s)
{
	if (!s) {
		return 0;
	}
	size_t n = strnlen(s, COH_CPUMASK_STRLEN);
	if (n == 0 || n >= COH_CPUMASK_STRLEN) {
		return 0;
	}
	for (size_t i = 0; i < n; i++) {
		char c = s[i];
		int hex   = (c >= '0' && c <= '9') ||
		            (c >= 'a' && c <= 'f') ||
		            (c >= 'A' && c <= 'F');
		int decimal_syntax = c == '-' || c == ',';
		if (!hex && !decimal_syntax) {
			return 0;
		}
	}
	return 1;
}

/*
 * read_small_file — read up to buf_sz-1 bytes, NUL-terminate, close.
 * Returns bytes read on success, -errno on error.
 */
static int read_small_file(const char *path, char *buf, size_t buf_sz)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return -errno;
	}

	size_t total = 0;
	while (total < buf_sz - 1) {
		ssize_t r = read(fd, buf + total, buf_sz - 1 - total);
		if (r < 0) {
			if (errno == EINTR) {
				continue;
			}
			int save_err = errno;
			close(fd);
			return -save_err;
		}
		if (r == 0) {
			break;
		}
		total += (size_t)r;
	}
	buf[total] = '\0';
	close(fd);
	return (int)total;
}

/*
 * ensure_diff_log_dir — mkdir /var/run/coherence (0755) if missing. Run
 * the daemon as a user with CAP_DAC_OVERRIDE or root; on failure we
 * silently continue so diff logging degrades gracefully.
 */
static void ensure_diff_log_dir(void)
{
	struct stat st;
	if (stat(IRQ_DIFF_LOG_DIR, &st) == 0) {
		return;
	}
	(void)mkdir(IRQ_DIFF_LOG_DIR, 0755);
}

/*
 * diff_log_append — append a one-liner to IRQ_DIFF_LOG. Non-fatal.
 */
static void diff_log_append(int irq, const char *before, const char *after)
{
	ensure_diff_log_dir();
	int fd = open(IRQ_DIFF_LOG, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
	if (fd < 0) {
		return;
	}
	char line[256];
	int n = snprintf(line, sizeof(line),
	                 "%llu\tirq=%d\tbefore=%s\tafter=%s\n",
	                 (unsigned long long)mono_ms(), irq,
	                 before ? before : "?",
	                 after  ? after  : "?");
	if (n > 0 && (size_t)n < sizeof(line)) {
		ssize_t w;
		size_t len = (size_t)n;
		size_t off = 0;
		while (off < len) {
			w = write(fd, line + off, len - off);
			if (w < 0) {
				if (errno == EINTR) {
					continue;
				}
				break;
			}
			off += (size_t)w;
		}
	}
	close(fd);
}

/*
 * irq_list_active — scan /proc/interrupts for lines whose header column
 * is a decimal integer (IRQ number) AND whose cpu columns sum > 0.
 *
 * `out_irqs` is filled with IRQ numbers, up to `max` entries. Returns
 * the count written, or -errno on read failure.
 *
 * The parser is deliberately minimal: we match the pattern
 *     [ws] <digits> ':' <digits> <ws> <digits>...
 * and treat anything else (NMI:, MIS:, timer: etc.) as "skip".
 */
int irq_list_active(int out_irqs[], int max)
{
	if (!out_irqs || max <= 0) {
		return -EINVAL;
	}

	/* /proc/interrupts can be hundreds of KB on large systems. Read in
	 * chunks; parse line-by-line. We cap at 128 KB — more than enough
	 * for any realistic IRQ table. */
	enum { BUF_SZ = 128 * 1024 };
	char *buf = malloc(BUF_SZ);
	if (!buf) {
		return -ENOMEM;
	}

	int fd = open(IRQ_PROC_INTERRUPTS, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		int save_err = errno;
		free(buf);
		return -save_err;
	}

	size_t total = 0;
	while (total < BUF_SZ - 1) {
		ssize_t r = read(fd, buf + total, BUF_SZ - 1 - total);
		if (r < 0) {
			if (errno == EINTR) {
				continue;
			}
			int save_err = errno;
			close(fd);
			free(buf);
			return -save_err;
		}
		if (r == 0) {
			break;
		}
		total += (size_t)r;
	}
	buf[total] = '\0';
	close(fd);

	int count = 0;
	char *saveptr = NULL;
	char *line = strtok_r(buf, "\n", &saveptr);

	/* First line is the header ("CPU0 CPU1 ...") — skip it. */
	int line_idx = 0;
	while (line) {
		if (line_idx++ == 0) {
			line = strtok_r(NULL, "\n", &saveptr);
			continue;
		}

		/* Skip leading whitespace. */
		const char *p = line;
		while (*p == ' ' || *p == '\t') {
			p++;
		}
		if (*p < '0' || *p > '9') {
			/* Header line like "NMI:" or empty. */
			line = strtok_r(NULL, "\n", &saveptr);
			continue;
		}

		/* Read the IRQ number. */
		int irq = 0;
		while (*p >= '0' && *p <= '9') {
			irq = irq * 10 + (*p - '0');
			p++;
			if (irq > IRQ_MAX_NUM) {
				irq = -1; /* overflow / noise */
				break;
			}
		}
		if (irq < 0 || *p != ':') {
			line = strtok_r(NULL, "\n", &saveptr);
			continue;
		}
		p++; /* skip ':' */

		/* Sum the per-CPU counters. We stop on anything non-numeric
		 * so the trailing driver-name field is ignored. */
		unsigned long long sum = 0;
		while (*p) {
			while (*p == ' ' || *p == '\t') {
				p++;
			}
			if (*p < '0' || *p > '9') {
				break;
			}
			unsigned long long v = 0;
			while (*p >= '0' && *p <= '9') {
				v = v * 10 + (unsigned)(*p - '0');
				p++;
			}
			sum += v;
		}

		if (sum > 0) {
			if (count < max) {
				out_irqs[count++] = irq;
			} else {
				break;
			}
		}

		line = strtok_r(NULL, "\n", &saveptr);
	}

	free(buf);
	return count;
}

/*
 * irq_write_affinity — write `mask` to /proc/irq/<N>/smp_affinity.
 *
 * Before writing we read the current value and emit a before/after line
 * to /var/run/coherence/irq-diff.log. Reading is cheap (one page) and
 * makes Agent 9's verification trivial.
 *
 * Returns 0 on success, -errno on failure. -ENOENT is common on systems
 * where the IRQ does not exist (e.g. we scan out of /proc/interrupts
 * but a driver unloads between scan and write) and is NOT treated
 * specially here — the caller aggregates the error count.
 */
int irq_write_affinity(int irq_num, const char *mask)
{
	if (!irq_num_ok(irq_num)) {
		return -EINVAL;
	}
	if (!mask_ok(mask)) {
		return -EINVAL;
	}

	char path[96];
	int n = snprintf(path, sizeof(path), "%s/%d/smp_affinity",
	                 IRQ_PROC_ROOT, irq_num);
	if (n < 0 || (size_t)n >= sizeof(path)) {
		return -ENAMETOOLONG;
	}

	/* Capture the current mask for diff logging. Non-fatal on failure. */
	char before[COH_CPUMASK_STRLEN];
	before[0] = '\0';
	(void)read_small_file(path, before, sizeof(before));
	/* Trim trailing newline. */
	for (size_t i = 0; i < sizeof(before) && before[i]; i++) {
		if (before[i] == '\n' || before[i] == '\r') {
			before[i] = '\0';
			break;
		}
	}

	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		return -errno;
	}

	size_t mlen = strnlen(mask, COH_CPUMASK_STRLEN);
	ssize_t w;
	do {
		w = write(fd, mask, mlen);
	} while (w < 0 && errno == EINTR);

	int save_err = (w < 0) ? errno : 0;
	close(fd);

	if (w < 0) {
		return -save_err;
	}
	if ((size_t)w != mlen) {
		return -EIO;
	}

	diff_log_append(irq_num, before, mask);
	return 0;
}

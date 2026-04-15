/*
 * sysfs_reader.c — Tiny, allocation-free helpers for /sys pseudo-files.
 *
 * Responsibilities split from /proc helpers because the access patterns are
 * different: most /sys files are single-line scalars that MUST be re-opened
 * per read to get a fresh value on some kernels, but on current Linux (>=5.4)
 * a kept-open fd + pread(offset=0) returns a fresh value.
 *
 * The measurement layer caches FDs across samples per spec ("open once,
 * reuse"). If a particular kernel misbehaves we can fall back to re-open
 * without changing the public API.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sysfs_reader_priv.h"

/* Read up to cap-1 bytes; NUL-terminate. Returns count or -errno. */
ssize_t sf_pread_line(int fd, char *buf, size_t cap)
{
	if (fd < 0 || !buf || cap < 2)
		return -EINVAL;

	size_t off = 0;
	while (off + 1 < cap) {
		ssize_t n = pread(fd, buf + off, cap - 1 - off, (off_t)off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			break;
		off += (size_t)n;
	}
	buf[off] = '\0';
	return (ssize_t)off;
}

/*
 * Parse the entire buffer as a signed 64-bit decimal (with optional leading
 * '-' and trailing whitespace/newline). Returns 0 on success, -EINVAL if no
 * digits found.
 */
int sf_parse_i64(const char *buf, size_t len, int64_t *out)
{
	if (!buf || !out)
		return -EINVAL;

	size_t i = 0;
	int neg = 0;

	/* Strip leading whitespace. */
	while (i < len && (buf[i] == ' ' || buf[i] == '\t'))
		i++;
	if (i < len && (buf[i] == '-' || buf[i] == '+')) {
		neg = (buf[i] == '-');
		i++;
	}

	uint64_t v = 0;
	int have = 0;
	while (i < len && buf[i] >= '0' && buf[i] <= '9') {
		v = v * 10u + (uint64_t)(buf[i] - '0');
		i++;
		have = 1;
	}
	if (!have)
		return -EINVAL;

	*out = neg ? -(int64_t)v : (int64_t)v;
	return 0;
}

/*
 * Open a /sys scalar file O_RDONLY | O_CLOEXEC. Returns fd or -errno.
 * The path MUST be a full absolute path; we never concatenate caller-supplied
 * substrings to prevent accidental traversal.
 */
int sf_open_scalar(const char *path)
{
	if (!path)
		return -EINVAL;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	return fd;
}

/*
 * Existence probe for a /sys directory. Returns 1 if present, 0 if not,
 * -errno on other stat failure.
 */
int sf_path_exists(const char *path)
{
	struct stat st;
	if (!path)
		return -EINVAL;
	if (stat(path, &st) < 0) {
		if (errno == ENOENT)
			return 0;
		return -errno;
	}
	return 1;
}

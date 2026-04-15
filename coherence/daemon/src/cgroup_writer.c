/*
 * cgroup_writer.c — cgroup v2 cpuset writer.
 *
 * We write unified-hierarchy cpuset.cpus files under /sys/fs/cgroup. The
 * slice name is a daemon-supplied constant (e.g. "game.slice"); user input
 * never reaches this file. No path traversal is possible because we build
 * the path from a fixed prefix plus a slice identifier that is validated
 * against a strict character class.
 *
 * sysfs files do not keep per-open state — each write is an isolated
 * transaction on the kernel side. We therefore open-write-close every
 * call. This keeps the code simple and lets the kernel reject invalid
 * masks via its normal write-path error path.
 *
 * All paths are constants. All strings are bounded.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "coherence_types.h"

/* Fixed cgroup v2 root. If the daemon ever needs to support cgroup v1
 * hybrid mode, this is the single point of change. */
#define CGROUP_V2_ROOT "/sys/fs/cgroup"

/*
 * Maximum slice-name length. "game.slice" is 10; we allow up to 64 to
 * leave room for nested hierarchies like "user.slice/app-123.scope".
 * The buffer in the caller's struct is larger than this; we copy in.
 */
#define MAX_SLICE_NAME_LEN 64

/*
 * Conservative slice-name character class — letters, digits, '.', '-',
 * '_', and '/'. '/' is permitted because cgroup hierarchy is path-shaped,
 * but we reject ".." and leading '/' to pin us under CGROUP_V2_ROOT.
 */
static int slice_name_ok(const char *s)
{
	if (!s || !*s) {
		return 0;
	}
	if (s[0] == '/') {
		return 0; /* must be relative to CGROUP_V2_ROOT */
	}

	size_t len = 0;
	for (const char *p = s; *p; p++) {
		len++;
		if (len >= MAX_SLICE_NAME_LEN) {
			return 0;
		}
		char c = *p;
		int alnum = (c >= 'a' && c <= 'z') ||
		            (c >= 'A' && c <= 'Z') ||
		            (c >= '0' && c <= '9');
		if (!alnum && c != '.' && c != '-' && c != '_' && c != '/') {
			return 0;
		}
	}
	/* Reject "..": no traversal. */
	if (strstr(s, "..")) {
		return 0;
	}
	return 1;
}

/*
 * Validate a cpumask string. Accepts the "0-3,8,10-11" syntax that
 * cpuset.cpus expects. We are intentionally lax — the kernel does the
 * authoritative parse — but we refuse control characters so a stray
 * NUL in the caller's buffer cannot be exploited.
 */
static int cpumask_ok(const char *s)
{
	if (!s) {
		return 0;
	}
	/* Empty string is a legitimate "no CPUs" mask for cpuset.cpus. */
	size_t n = strnlen(s, COH_CPUMASK_STRLEN);
	if (n >= COH_CPUMASK_STRLEN) {
		return 0; /* not NUL-terminated within bounds */
	}
	for (size_t i = 0; i < n; i++) {
		char c = s[i];
		int ok = (c >= '0' && c <= '9') ||
		         c == '-' || c == ',' || c == ' ';
		if (!ok) {
			return 0;
		}
	}
	return 1;
}

/*
 * Build "/sys/fs/cgroup/<slice>/cpuset.cpus" into `out`. Returns 0 on
 * success, -errno on overflow.
 */
static int build_cpuset_path(char *out, size_t out_len, const char *slice)
{
	int n = snprintf(out, out_len, "%s/%s/cpuset.cpus",
	                 CGROUP_V2_ROOT, slice);
	if (n < 0) {
		return -EIO;
	}
	if ((size_t)n >= out_len) {
		return -ENAMETOOLONG;
	}
	return 0;
}

/*
 * cgroup_ensure_slice — mkdir the slice directory under the cgroup v2
 * root if absent. Equivalent to systemd creating a transient slice. We
 * never `rmdir` — that is a systemd/user responsibility.
 *
 * Returns 0 if the slice dir exists after the call (whether we created
 * it or it was already present). Returns -errno otherwise.
 */
int cgroup_ensure_slice(const char *slice)
{
	if (!slice_name_ok(slice)) {
		return -EINVAL;
	}

	char path[256];
	int n = snprintf(path, sizeof(path), "%s/%s",
	                 CGROUP_V2_ROOT, slice);
	if (n < 0 || (size_t)n >= sizeof(path)) {
		return -ENAMETOOLONG;
	}

	if (mkdir(path, 0755) == 0) {
		return 0;
	}
	if (errno == EEXIST) {
		/* Already present — verify it is a directory. */
		struct stat st;
		if (stat(path, &st) != 0) {
			return -errno;
		}
		if (!S_ISDIR(st.st_mode)) {
			return -ENOTDIR;
		}
		return 0;
	}
	return -errno;
}

/*
 * cgroup_write_cpuset — write a cpumask string to the slice's cpuset.cpus.
 * The kernel parses the mask and returns EINVAL if it does not fit the
 * allowed-set of the parent cgroup. We return that errno verbatim.
 *
 * Empty cpuset.cpus ("") clears the mask — this is a legal runtime state
 * for cgroup v2 but only meaningful for non-root groups. We allow it.
 */
int cgroup_write_cpuset(const char *slice, const char *mask)
{
	if (!slice_name_ok(slice)) {
		return -EINVAL;
	}
	if (!cpumask_ok(mask)) {
		return -EINVAL;
	}

	char path[256];
	int rc = build_cpuset_path(path, sizeof(path), slice);
	if (rc < 0) {
		return rc;
	}

	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		/* ENOENT handled gracefully — the slice may not be created yet. */
		return -errno;
	}

	size_t mask_len = strnlen(mask, COH_CPUMASK_STRLEN);
	ssize_t w;
	do {
		w = write(fd, mask, mask_len);
	} while (w < 0 && errno == EINTR);

	int save_err = (w < 0) ? errno : 0;
	close(fd);

	if (w < 0) {
		return -save_err;
	}
	if ((size_t)w != mask_len) {
		return -EIO;
	}
	return 0;
}

/*
 * iouring_writer.c — io_uring SQPOLL retarget coordination.
 *
 * A subtle Linux detail: the SQPOLL thread's CPU affinity is set at
 * io_uring_setup() time via the `sq_thread_cpu` field of struct
 * io_uring_params. Once the ring is created, there is no ioctl, no
 * prctl, no cgroup knob that will migrate the kernel SQPOLL thread to
 * a different CPU without tearing the ring down and recreating it.
 *
 * Rather than do that dance from a C daemon (which does not own the
 * rings), we write a tiny coordination file at
 *
 *     /var/run/coherence/sqpoll-target
 *
 * containing a single decimal CPU id terminated by '\n'. The AI daemon's
 * io_uring bridge (ai-control/daemon/iouring.py, referred to as R32 in
 * the session log) watches this file with inotify IN_MODIFY|IN_CLOSE_WRITE
 * and, on change, drains + tears down its rings and recreates them
 * pinned to the new CPU. That is the only code path that actually owns
 * the rings, so it is the only code path that can retarget.
 *
 * This file is therefore a *signal*, not a live configuration. We use
 * rename(2) for atomic publication: write to sqpoll-target.tmp, rename
 * on top of sqpoll-target. inotify delivers IN_MOVED_TO on the target,
 * and readers always see a complete line.
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

#define SQPOLL_TARGET_DIR  "/var/run/coherence"
#define SQPOLL_TARGET_PATH SQPOLL_TARGET_DIR "/sqpoll-target"
#define SQPOLL_TARGET_TMP  SQPOLL_TARGET_DIR "/sqpoll-target.tmp"

/*
 * Ensure /var/run/coherence exists. Non-fatal — if mkdir fails we just
 * let the subsequent open(2) return -errno which the caller logs.
 */
static void ensure_dir(void)
{
	struct stat st;
	if (stat(SQPOLL_TARGET_DIR, &st) == 0) {
		return;
	}
	(void)mkdir(SQPOLL_TARGET_DIR, 0755);
}

/*
 * iouring_retarget_sqpoll — publish a new target CPU for the SQPOLL
 * thread to the AI daemon's iouring bridge.
 *
 * new_cpu must be in [0, COH_MAX_CPUS). A negative value means "no
 * affinity" — we write "-1" which the Python side interprets as
 * "let the kernel pick".
 *
 * Returns 0 on success, -errno on failure.
 */
int iouring_retarget_sqpoll(int new_cpu)
{
	if (new_cpu >= COH_MAX_CPUS) {
		return -EINVAL;
	}

	ensure_dir();

	/* Open the temp file with O_TRUNC so a partial previous attempt
	 * cannot poison the next rename. O_CLOEXEC so a forked child
	 * cannot leak the fd. */
	int fd = open(SQPOLL_TARGET_TMP,
	              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
	              0644);
	if (fd < 0) {
		return -errno;
	}

	char buf[16];
	int n = snprintf(buf, sizeof(buf), "%d\n", new_cpu);
	if (n <= 0 || (size_t)n >= sizeof(buf)) {
		close(fd);
		return -EIO;
	}

	ssize_t off = 0;
	while (off < n) {
		ssize_t w = write(fd, buf + off, (size_t)(n - off));
		if (w < 0) {
			if (errno == EINTR) {
				continue;
			}
			int save_err = errno;
			close(fd);
			(void)unlink(SQPOLL_TARGET_TMP);
			return -save_err;
		}
		off += w;
	}

	/* fsync is overkill for a tmpfs file whose purpose is inotify
	 * signalling; skip it. rename() gives the reader an atomic view. */
	if (close(fd) != 0) {
		int save_err = errno;
		(void)unlink(SQPOLL_TARGET_TMP);
		return -save_err;
	}

	if (rename(SQPOLL_TARGET_TMP, SQPOLL_TARGET_PATH) != 0) {
		int save_err = errno;
		(void)unlink(SQPOLL_TARGET_TMP);
		return -save_err;
	}
	return 0;
}

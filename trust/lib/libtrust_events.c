/*
 * libtrust_events.c - Binary event stream reader + compressed event log.
 *
 * Exposes:
 *   trust_events_open/read/close  - Binary event fd from kernel
 *   trust_log_open/append/rotate/close - Rotating zstd-compressed log
 *
 * Ownership:
 *   - Events fd: process-global inside this module, opened by
 *     trust_events_open, closed by trust_events_close or trust_cleanup.
 *   - trust_log_t: caller owns via opaque handle.
 *
 * Thread-safety:
 *   - Events reader: single consumer (guarded by g_evt_lock).
 *   - trust_log_t: NOT safe for concurrent use — wrap externally.
 *
 * Fallback:
 *   - If TRUST_FEAT_EVT_BINARY is missing or TRUST_IOC_EVT_OPEN is not
 *     implemented, trust_events_open returns -1 with errno=ENOTSUP.
 *   - If libzstd is not linked (extremely unlikely — it's in base Arch),
 *     compressed rotation is a no-op and rotated segments stay uncompressed.
 *     We detect this at build time with HAVE_ZSTD.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <stdint.h>
#include <dirent.h>
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include "libtrust.h"
#include "../include/trust_ioctl.h"
#include "../include/trust_isa.h"

#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

extern int trust_fd_snapshot(void);   /* implemented in libtrust.c */

/* ========================================================================
 * Events fd
 * ======================================================================== */

static pthread_mutex_t g_evt_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_evt_fd = -1;
/* Absolute time base: the moment we opened the fd. Kernel's first event
 * delta_ts_ns is relative to our open time (contract in trust_isa.h). */
static uint64_t g_evt_time_base_ns = 0;
/* Running cursor used to reconstruct absolute timestamps from deltas. */
static uint64_t g_evt_ts_cursor_ns = 0;

static uint64_t now_ns(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) < 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int trust_events_open(void)
{
	int fd = trust_fd_snapshot();
	trust_ioc_evt_open_t req;
	int evt_fd;

	if (fd < 0) {
		errno = ENODEV;
		return -1;
	}

	pthread_mutex_lock(&g_evt_lock);
	if (g_evt_fd >= 0) {
		pthread_mutex_unlock(&g_evt_lock);
		return 0;
	}

	memset(&req, 0, sizeof(req));
	if (ioctl(fd, TRUST_IOC_EVT_OPEN, &req) < 0) {
		int saved = errno;
		pthread_mutex_unlock(&g_evt_lock);
		/* Normalize: kernel without this ioctl returns ENOTTY. Surface
		 * ENOTSUP to callers so they know to use get_audit() polling. */
		if (saved == ENOTTY || saved == EINVAL)
			errno = ENOTSUP;
		else
			errno = saved;
		return -1;
	}
	evt_fd = req.evt_fd;
	if (evt_fd < 0) {
		pthread_mutex_unlock(&g_evt_lock);
		errno = EIO;
		return -1;
	}
	/* Hand ownership to libtrust. Set CLOEXEC just in case the kernel
	 * didn't. */
	{
		int flags = fcntl(evt_fd, F_GETFD);
		if (flags >= 0)
			(void)fcntl(evt_fd, F_SETFD, flags | FD_CLOEXEC);
	}
	g_evt_fd = evt_fd;
	g_evt_time_base_ns = now_ns();
	g_evt_ts_cursor_ns = g_evt_time_base_ns;
	pthread_mutex_unlock(&g_evt_lock);
	return 0;
}

int trust_events_read(trust_event_t *ev, int max_events)
{
	int fd;
	ssize_t n;
	size_t want;
	int i;
	trust_event_packed_t buf[128];  /* 128 * 8 = 1 KiB stack */

	if (!ev || max_events <= 0) {
		errno = EINVAL;
		return -1;
	}
	if (max_events > 128)
		max_events = 128;

	/* Snapshot the fd under the lock, then release it BEFORE read(). The
	 * read can block for the configured kernel poll interval; previously
	 * we held g_evt_lock across it, which deadlocked trust_events_close()
	 * and serialized every reader thread. The kernel guarantees atomic
	 * record-sized reads on the event fd, so concurrent readers just see
	 * interleaved record batches — which is semantically fine because
	 * each record is self-contained. */
	pthread_mutex_lock(&g_evt_lock);
	fd = g_evt_fd;
	pthread_mutex_unlock(&g_evt_lock);
	if (fd < 0) {
		errno = EBADF;
		return -1;
	}

	want = (size_t)max_events * sizeof(trust_event_packed_t);
	n = read(fd, buf, want);
	if (n < 0)
		return -1;
	/* Discard partial record tail — keep the reader aligned. */
	n -= n % (ssize_t)sizeof(trust_event_packed_t);
	{
		int got = (int)(n / (ssize_t)sizeof(trust_event_packed_t));
		/* Re-acquire the lock only to mutate the shared cursor. */
		pthread_mutex_lock(&g_evt_lock);
		for (i = 0; i < got; i++) {
			if (buf[i].flags & TRUST_EVF_TS_ROLLOVER) {
				/* Kernel signaled cursor resync; re-base to
				 * current monotonic. */
				g_evt_ts_cursor_ns = now_ns();
			} else {
				g_evt_ts_cursor_ns +=
					(uint64_t)buf[i].delta_ts_ns;
			}
			ev[i].type    = buf[i].type;
			ev[i].flags   = buf[i].flags;
			ev[i]._padding = 0;
			ev[i].subject = (uint32_t)buf[i].subject_id;
			ev[i].cost    = (uint32_t)buf[i].cost;
			ev[i].ts_ns   = g_evt_ts_cursor_ns;
		}
		pthread_mutex_unlock(&g_evt_lock);
		return got;
	}
}

void trust_events_close(void)
{
	int fd;
	pthread_mutex_lock(&g_evt_lock);
	fd = g_evt_fd;
	g_evt_fd = -1;
	pthread_mutex_unlock(&g_evt_lock);
	if (fd >= 0)
		close(fd);
}

/* ========================================================================
 * Rotating, optionally-compressed event log
 *
 * Directory layout at `path`:
 *    trust.evt.current       <- active segment (raw, append-only)
 *    trust.evt.NNN           <- rotated segment (raw), kept if not compressed
 *    trust.evt.NNN.zst       <- rotated segment (zstd-compressed)
 *
 * Rotation happens on append when current segment size + sizeof(record)
 * exceeds rotate_bytes.
 * ======================================================================== */

struct trust_log {
	char    *dir_path;
	int      flags;         /* TRUST_LOG_* */
	size_t   rotate_bytes;
	int      current_fd;
	size_t   current_size;
	uint32_t seq;           /* rotation sequence */
};

static size_t env_size(const char *name, size_t fallback)
{
	const char *s = getenv(name);
	long v;
	char *end;
	if (!s || !*s) return fallback;
	v = strtol(s, &end, 10);
	if (end == s || v <= 0) return fallback;
	return (size_t)v;
}

/* Find the highest existing segment number in the directory so we
 * continue the sequence after a crash/restart. */
static uint32_t scan_max_seq(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	uint32_t max_seq = 0;

	if (!d) return 0;
	while ((de = readdir(d))) {
		if (strncmp(de->d_name, "trust.evt.", 10) != 0)
			continue;
		if (strcmp(de->d_name + 10, "current") == 0)
			continue;
		{
			unsigned long v;
			char *end;
			v = strtoul(de->d_name + 10, &end, 10);
			if (end != de->d_name + 10 && v <= UINT32_MAX) {
				if ((uint32_t)v > max_seq)
					max_seq = (uint32_t)v;
			}
		}
	}
	closedir(d);
	return max_seq;
}

trust_log_t *trust_log_open(const char *path, int flags)
{
	trust_log_t *l;
	struct stat st;
	char *current_path;
	size_t pl;

	if (!path || !*path) {
		errno = EINVAL;
		return NULL;
	}
	/* Create the directory if missing. */
	if (mkdir(path, 0700) < 0 && errno != EEXIST)
		return NULL;
	if (stat(path, &st) < 0)
		return NULL;
	if (!S_ISDIR(st.st_mode)) {
		errno = ENOTDIR;
		return NULL;
	}

	l = calloc(1, sizeof(*l));
	if (!l) return NULL;
	l->dir_path = strdup(path);
	if (!l->dir_path) {
		free(l);
		return NULL;
	}
	l->flags = flags;
	l->rotate_bytes = env_size("LIBTRUST_LOG_ROTATE_BYTES",
	                           TRUST_LOG_DEFAULT_ROTATE);
	l->current_fd = -1;
	l->seq = scan_max_seq(path);

	pl = strlen(path);
	current_path = malloc(pl + sizeof("/trust.evt.current"));
	if (!current_path) {
		free(l->dir_path);
		free(l);
		return NULL;
	}
	memcpy(current_path, path, pl);
	memcpy(current_path + pl, "/trust.evt.current",
	       sizeof("/trust.evt.current"));

	{
		int oflags = O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC;
		if (flags & TRUST_LOG_TRUNCATE)
			oflags |= O_TRUNC;
		l->current_fd = open(current_path, oflags, 0600);
	}
	free(current_path);
	if (l->current_fd < 0) {
		free(l->dir_path);
		free(l);
		return NULL;
	}

	/* Fill current_size from stat for rotation bookkeeping. */
	if (fstat(l->current_fd, &st) == 0)
		l->current_size = (size_t)st.st_size;
	return l;
}

/* Compress `in_path` to `out_path` (appending ".zst" is caller's job).
 * Returns 0 on success, -1 on failure. When libzstd isn't linked this
 * function just renames in_path to out_path without compression. */
static int compress_segment(const char *in_path, const char *out_path)
{
#ifdef HAVE_ZSTD
	int in_fd, out_fd;
	size_t in_cap, out_cap;
	void *in_buf = NULL, *out_buf = NULL;
	ZSTD_CCtx *cctx;
	int level = 3;   /* level 3: ~300 MB/s on old HW, 3-5x shrink */
	int ret = -1;
	struct stat st;

	in_fd = open(in_path, O_RDONLY | O_CLOEXEC);
	if (in_fd < 0) return -1;
	if (fstat(in_fd, &st) < 0) {
		close(in_fd);
		return -1;
	}
	/* Empty segment: nothing to do. */
	if (st.st_size == 0) {
		close(in_fd);
		(void)unlink(in_path);
		return 0;
	}

	in_cap = (size_t)st.st_size;
	out_cap = ZSTD_compressBound(in_cap);
	in_buf = malloc(in_cap);
	out_buf = malloc(out_cap);
	if (!in_buf || !out_buf) goto done;

	{
		ssize_t n = read(in_fd, in_buf, in_cap);
		if (n != (ssize_t)in_cap) goto done;
	}

	cctx = ZSTD_createCCtx();
	if (!cctx) goto done;
	{
		size_t csize = ZSTD_compressCCtx(cctx, out_buf, out_cap,
		                                 in_buf, in_cap, level);
		ZSTD_freeCCtx(cctx);
		if (ZSTD_isError(csize)) goto done;

		out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		              0600);
		if (out_fd < 0) goto done;
		{
			ssize_t w = write(out_fd, out_buf, csize);
			close(out_fd);
			if (w != (ssize_t)csize) {
				(void)unlink(out_path);
				goto done;
			}
		}
	}
	/* Success: unlink the uncompressed source. */
	(void)unlink(in_path);
	ret = 0;
done:
	free(in_buf);
	free(out_buf);
	close(in_fd);
	return ret;
#else
	/* No zstd linked: just rename to out_path (caller passes .zst so
	 * downstream tools will gracefully skip). Better: keep as raw. */
	(void)out_path;
	(void)in_path;
	errno = ENOSYS;
	return -1;
#endif
}

int trust_log_rotate(trust_log_t *l)
{
	char path_current[PATH_MAX];
	char path_rotated[PATH_MAX];
	char path_compressed[PATH_MAX];
	struct stat st;
	int n;

	if (!l) {
		errno = EINVAL;
		return -1;
	}
	if (l->current_fd < 0) {
		errno = EBADF;
		return -1;
	}

	n = snprintf(path_current, sizeof(path_current),
	             "%s/trust.evt.current", l->dir_path);
	if (n < 0 || (size_t)n >= sizeof(path_current)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	if (fstat(l->current_fd, &st) < 0)
		return -1;
	/* Empty: no rotate needed. */
	if (st.st_size == 0)
		return 0;

	l->seq++;
	n = snprintf(path_rotated, sizeof(path_rotated),
	             "%s/trust.evt.%u", l->dir_path, l->seq);
	if (n < 0 || (size_t)n >= sizeof(path_rotated)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	/* Close + rename atomically. Open a new current afterwards. */
	if (close(l->current_fd) < 0)
		return -1;
	l->current_fd = -1;
	if (rename(path_current, path_rotated) < 0)
		return -1;

	/* Re-open current for future appends. */
	l->current_fd = open(path_current,
	                     O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
	if (l->current_fd < 0)
		return -1;
	l->current_size = 0;

	/* Compress if requested. */
	if (l->flags & TRUST_LOG_ZSTD) {
		n = snprintf(path_compressed, sizeof(path_compressed),
		             "%s/trust.evt.%u.zst", l->dir_path, l->seq);
		if (n < 0 || (size_t)n >= sizeof(path_compressed)) {
			/* leave rotated segment uncompressed; don't fail */
			return 0;
		}
		(void)compress_segment(path_rotated, path_compressed);
	}
	return 0;
}

int trust_log_append(trust_log_t *l, const trust_event_t *ev)
{
	trust_event_packed_t rec;
	ssize_t n;

	if (!l || !ev) {
		errno = EINVAL;
		return -1;
	}
	if (l->current_fd < 0) {
		errno = EBADF;
		return -1;
	}

	/* Build a standalone record. Logs are self-describing so we fill
	 * in an absolute-ts-from-base delta (cannot represent >64K ns
	 * without rollover — if the caller provides a much later event
	 * we write TS_ROLLOVER and reset). */
	rec.type    = ev->type;
	rec.flags   = ev->flags;
	rec.subject_id = (uint16_t)(ev->subject & 0xFFFFU);
	rec.cost    = (ev->cost > 0xFFFFU) ? 0xFFFFU : (uint16_t)ev->cost;

	{
		/* Pack a short delta from the last appended ts. Log records
		 * use absolute ts since we don't track cursor in the log. */
		static __thread uint64_t thr_last_ts;
		uint64_t delta = (ev->ts_ns > thr_last_ts)
		               ? (ev->ts_ns - thr_last_ts) : 0;
		if (thr_last_ts == 0 || delta > 0xFFFFU) {
			rec.delta_ts_ns = 0;
			rec.flags |= TRUST_EVF_TS_ROLLOVER;
		} else {
			rec.delta_ts_ns = (uint16_t)delta;
		}
		thr_last_ts = ev->ts_ns;
	}

	/* Rotate BEFORE appending if we'd exceed the threshold. */
	if (l->current_size + sizeof(rec) > l->rotate_bytes) {
		if (trust_log_rotate(l) < 0) {
			/* best-effort: keep appending; the segment gets large
			 * but we don't lose events. */
		}
	}

	n = write(l->current_fd, &rec, sizeof(rec));
	if (n != (ssize_t)sizeof(rec)) {
		if (n >= 0) errno = EIO;
		return -1;
	}
	l->current_size += sizeof(rec);
	if (l->flags & TRUST_LOG_SYNC)
		(void)fdatasync(l->current_fd);
	return 0;
}

void trust_log_close(trust_log_t *l)
{
	if (!l) return;
	if (l->current_fd >= 0)
		close(l->current_fd);
	free(l->dir_path);
	free(l);
}

/*
 * iouring_stats.c — Thin HTTP client to the AI daemon's /iouring/stats
 * endpoint, plus a 250ms cache so we don't hammer the loopback socket.
 *
 * No libcurl. Raw socket + blocking connect with SO_RCVTIMEO/SO_SNDTIMEO
 * short timeouts so sample() never stalls longer than ~5ms even if the
 * daemon is partially responsive. If the daemon is down we return zeros
 * and flag the health bit; downstream derivation code treats io_pressure=0
 * as "no information".
 *
 * We ALSO have an analogous thermal getter here — same pattern, different
 * endpoint (/thermal/packed returns 24 bytes binary). Kept in this file to
 * avoid yet another TU; both clients share the same connect helper.
 *
 * HTTP payload parsed: a permissive JSON scan for two keys, "sq_depth" and
 * "sq_latency_us", taking the first numeric run after each key name. This
 * avoids pulling in a JSON library for two scalar fields.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "iouring_stats_priv.h"

#define AI_DAEMON_HOST_V4      "127.0.0.1"
#define AI_DAEMON_PORT          8420
#define CACHE_TTL_MS              250

#define HTTP_BUF_CAP             2048   /* fits generous JSON payload */
#define CONNECT_TIMEOUT_MS        2
#define IO_TIMEOUT_MS             2

static struct {
	uint64_t  last_fetch_ms;
	int       last_was_ok;
	double    sq_depth;
	double    sq_latency_us;
} g_iouring_cache;

static struct {
	uint64_t  last_fetch_ms;
	int       last_was_ok;
	double    temp_c;
} g_thermal_cache;

/* Reuse pattern: connect a blocking socket to the AI daemon with short
 * rcv/snd timeouts and TCP_NODELAY. Returns fd or -errno. */
static int ai_connect(void)
{
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	int one = 1;
	(void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	struct timeval tv = {
		.tv_sec  = IO_TIMEOUT_MS / 1000,
		.tv_usec = (IO_TIMEOUT_MS % 1000) * 1000,
	};
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port   = htons(AI_DAEMON_PORT);
	if (inet_pton(AF_INET, AI_DAEMON_HOST_V4, &sa.sin_addr) != 1) {
		close(fd);
		return -EINVAL;
	}

	/* Non-blocking connect with poll — but we already have SO_SNDTIMEO so
	 * a blocking connect is bounded. Use blocking path for simplicity. */
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		int e = errno;
		close(fd);
		return -e;
	}
	return fd;
}

/* Write `buf` (`len` bytes) entirely or fail. */
static int ai_write_all(int fd, const char *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			return -EPIPE;
		off += (size_t)n;
	}
	return 0;
}

/* Read up to cap-1 bytes. Returns count or -errno. NUL-terminates. */
static ssize_t ai_read_some(int fd, char *buf, size_t cap)
{
	size_t off = 0;
	while (off + 1 < cap) {
		ssize_t n = recv(fd, buf + off, cap - 1 - off, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break; /* RCVTIMEO fired — take what we have */
			return -errno;
		}
		if (n == 0)
			break;
		off += (size_t)n;
	}
	buf[off] = '\0';
	return (ssize_t)off;
}

/* Locate the HTTP body (after CRLF CRLF). Returns pointer or NULL. */
static const char *http_body(const char *buf, size_t len)
{
	/* Search for "\r\n\r\n" or "\n\n". */
	for (size_t i = 0; i + 3 < len; i++) {
		if (buf[i] == '\r' && buf[i+1] == '\n' &&
		    buf[i+2] == '\r' && buf[i+3] == '\n')
			return buf + i + 4;
	}
	for (size_t i = 0; i + 1 < len; i++) {
		if (buf[i] == '\n' && buf[i+1] == '\n')
			return buf + i + 2;
	}
	return NULL;
}

/*
 * Find the first numeric run after the substring `key` in `body`. Handles
 * standard JSON forms: "key":123, "key": 12.5, "key" : 0.
 * Returns 0 on success, -ENOENT if key missing, -EINVAL on parse fail.
 */
static int find_json_number(const char *body, const char *key, double *out)
{
	if (!body || !key || !out)
		return -EINVAL;

	const char *p = strstr(body, key);
	if (!p)
		return -ENOENT;

	p += strlen(key);
	/* Skip quote, colon, whitespace. */
	while (*p && (*p == '"' || *p == ':' || *p == ' ' || *p == '\t' ||
	              *p == '\r' || *p == '\n'))
		p++;

	/* Optional sign. */
	int neg = 0;
	if (*p == '-') { neg = 1; p++; }
	else if (*p == '+') { p++; }

	int have_digit = 0;
	double intp = 0.0;
	while (*p >= '0' && *p <= '9') {
		intp = intp * 10.0 + (double)(*p - '0');
		p++;
		have_digit = 1;
	}
	double frac = 0.0, div = 1.0;
	if (*p == '.') {
		p++;
		while (*p >= '0' && *p <= '9') {
			frac = frac * 10.0 + (double)(*p - '0');
			div *= 10.0;
			p++;
			have_digit = 1;
		}
	}
	if (!have_digit)
		return -EINVAL;

	double val = intp + (frac / div);
	if (neg) val = -val;
	*out = val;
	return 0;
}

/* Compose HTTP request; simple fixed buffer. */
static int ai_http_get(const char *path, char *reply, size_t reply_cap)
{
	int fd = ai_connect();
	if (fd < 0)
		return fd;

	char req[256];
	int req_len = snprintf(req, sizeof(req),
		"GET %s HTTP/1.1\r\n"
		"Host: 127.0.0.1\r\n"
		"Accept: */*\r\n"
		"Connection: close\r\n"
		"\r\n", path);
	if (req_len < 0 || (size_t)req_len >= sizeof(req)) {
		close(fd);
		return -EINVAL;
	}

	int wrc = ai_write_all(fd, req, (size_t)req_len);
	if (wrc < 0) {
		close(fd);
		return wrc;
	}

	ssize_t rrc = ai_read_some(fd, reply, reply_cap);
	close(fd);
	if (rrc < 0)
		return (int)rrc;

	/* Check for "HTTP/1.1 200". We only care about 2xx. */
	if (rrc < 12)
		return -EIO;
	if (!(reply[0] == 'H' && reply[1] == 'T' && reply[2] == 'T' &&
	      reply[3] == 'P'))
		return -EPROTO;
	/* Position 9..11 is the 3-char status code for HTTP/1.1. */
	if (reply[9] != '2')
		return -EIO;

	return (int)rrc;
}

static uint64_t now_ms_monotonic(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* ===== Public API ===== */

int iouring_stats_fetch(double *sq_depth_out, double *sq_lat_us_out)
{
	if (!sq_depth_out || !sq_lat_us_out)
		return -EINVAL;

	uint64_t now = now_ms_monotonic();
	if (g_iouring_cache.last_fetch_ms != 0 &&
	    now - g_iouring_cache.last_fetch_ms < CACHE_TTL_MS) {
		*sq_depth_out  = g_iouring_cache.sq_depth;
		*sq_lat_us_out = g_iouring_cache.sq_latency_us;
		return g_iouring_cache.last_was_ok ? 0 : -EAGAIN;
	}

	/* Stamp "we tried at now" so failures also debounce by 250ms. */
	g_iouring_cache.last_fetch_ms = now;

	char buf[HTTP_BUF_CAP];
	int n = ai_http_get("/iouring/stats", buf, sizeof(buf));
	if (n < 0) {
		g_iouring_cache.last_was_ok = 0;
		*sq_depth_out  = g_iouring_cache.sq_depth;
		*sq_lat_us_out = g_iouring_cache.sq_latency_us;
		return n;
	}

	const char *body = http_body(buf, (size_t)n);
	if (!body) {
		g_iouring_cache.last_was_ok = 0;
		*sq_depth_out  = g_iouring_cache.sq_depth;
		*sq_lat_us_out = g_iouring_cache.sq_latency_us;
		return -EPROTO;
	}

	double depth = 0.0, lat = 0.0;
	int e1 = find_json_number(body, "sq_depth",       &depth);
	int e2 = find_json_number(body, "sq_latency_us",  &lat);
	if (e1 < 0 && e2 < 0) {
		g_iouring_cache.last_was_ok = 0;
		*sq_depth_out  = g_iouring_cache.sq_depth;
		*sq_lat_us_out = g_iouring_cache.sq_latency_us;
		return -EPROTO;
	}

	/* Accept partial — if only one key present, use last good for the other. */
	if (e1 == 0) g_iouring_cache.sq_depth = depth;
	if (e2 == 0) g_iouring_cache.sq_latency_us = lat;
	g_iouring_cache.last_was_ok = 1;

	*sq_depth_out  = g_iouring_cache.sq_depth;
	*sq_lat_us_out = g_iouring_cache.sq_latency_us;
	return 0;
}

int iouring_stats_reset_cache(void)
{
	memset(&g_iouring_cache, 0, sizeof(g_iouring_cache));
	memset(&g_thermal_cache, 0, sizeof(g_thermal_cache));
	return 0;
}

/*
 * Thermal bridge — fetch from the AI daemon's R32 ThermalOrchestrator
 * endpoint /thermal/packed. Spec says it's a 24-byte binary payload; we
 * attempt to decode it as:
 *   [ 0.. 7]  uint64_t t_ms
 *   [ 8..15]  double   temp_c
 *   [16..23]  uint64_t reserved
 * If the payload isn't exactly 24 bytes we fall back to ENOTSUP (caller
 * then tries /sys/class/thermal). Cached for 250 ms.
 */
int thermal_packed_fetch(double *temp_c_out)
{
	if (!temp_c_out)
		return -EINVAL;

	uint64_t now = now_ms_monotonic();
	if (g_thermal_cache.last_fetch_ms != 0 &&
	    now - g_thermal_cache.last_fetch_ms < CACHE_TTL_MS) {
		*temp_c_out = g_thermal_cache.temp_c;
		return g_thermal_cache.last_was_ok ? 0 : -EAGAIN;
	}
	g_thermal_cache.last_fetch_ms = now;

	char buf[HTTP_BUF_CAP];
	int n = ai_http_get("/thermal/packed", buf, sizeof(buf));
	if (n < 0) {
		g_thermal_cache.last_was_ok = 0;
		*temp_c_out = g_thermal_cache.temp_c;
		return n;
	}

	const char *body = http_body(buf, (size_t)n);
	if (!body) {
		g_thermal_cache.last_was_ok = 0;
		*temp_c_out = g_thermal_cache.temp_c;
		return -EPROTO;
	}
	size_t body_len = (size_t)n - (size_t)(body - buf);

	if (body_len >= 16) {
		/* Binary layout: u64 t_ms || f64 temp_c || ... */
		double t;
		memcpy(&t, body + 8, sizeof(t));
		/* Sanity-check: plausible CPU temps are [-40, 150] C. */
		if (t > -40.0 && t < 150.0) {
			g_thermal_cache.temp_c = t;
			g_thermal_cache.last_was_ok = 1;
			*temp_c_out = t;
			return 0;
		}
	}

	/* Fall back: look for "temp_c" JSON key if the endpoint returns JSON. */
	double t_json = 0.0;
	if (find_json_number(body, "temp_c", &t_json) == 0 &&
	    t_json > -40.0 && t_json < 150.0) {
		g_thermal_cache.temp_c = t_json;
		g_thermal_cache.last_was_ok = 1;
		*temp_c_out = t_json;
		return 0;
	}

	g_thermal_cache.last_was_ok = 0;
	*temp_c_out = g_thermal_cache.temp_c;
	return -ENOTSUP;
}

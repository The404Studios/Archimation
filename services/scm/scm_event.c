/*
 * scm_event.c - Service event emission to the AI cortex
 *
 * Sends service lifecycle events as UDP datagrams to the cortex via
 * /run/pe-compat/events.sock.  Uses the pe_event_header_t wire format
 * so the cortex can demux SCM events alongside PE runtime, object broker,
 * and trust events.
 *
 * All sends are non-blocking and fire-and-forget.  If the cortex is down
 * or the socket buffer is full, the event is silently dropped.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <errno.h>
#include <stdatomic.h>

#include "scm_event.h"

/* ========================================================================
 * Wire format constants (must match pe_event.h exactly)
 * ======================================================================== */

#define EVENT_MAGIC    0x45564E54  /* "EVNT" */
#define EVENT_VERSION  1
#define EVENT_SRC_SCM  3

#define EVENT_SOCKET_PATH "/run/pe-compat/events.sock"

/* 64-byte event header -- binary-compatible with pe_event_header_t */
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint8_t  source_layer;
    uint8_t  event_type;
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tid;
    uint32_t subject_id;
    uint64_t sequence;
    uint16_t payload_len;
    uint16_t flags;
    uint8_t  reserved[24];
} scm_wire_header_t;

_Static_assert(sizeof(scm_wire_header_t) == 64, "Wire header must be 64 bytes");

/* ========================================================================
 * Module state
 * ======================================================================== */

static int g_event_fd = -1;
static struct sockaddr_un g_event_addr;
static _Atomic uint64_t g_event_seq = 0;

/* ========================================================================
 * Helpers
 * ======================================================================== */

static uint64_t get_boottime_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_BOOTTIME, &ts) < 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ========================================================================
 * Public API
 * ======================================================================== */

int scm_event_init(void)
{
    g_event_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (g_event_fd < 0) {
        fprintf(stderr, "[scm_event] socket() failed: %s (events disabled)\n",
                strerror(errno));
        return -1;
    }

    /* Make the socket non-blocking so sendto() never stalls the daemon */
    int flags = fcntl(g_event_fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(g_event_fd, F_SETFL, flags | O_NONBLOCK);

    /* Prevent leaking fd to child processes */
    fcntl(g_event_fd, F_SETFD, FD_CLOEXEC);

    memset(&g_event_addr, 0, sizeof(g_event_addr));
    g_event_addr.sun_family = AF_UNIX;
    strncpy(g_event_addr.sun_path, EVENT_SOCKET_PATH,
            sizeof(g_event_addr.sun_path) - 1);

    g_event_seq = 0;

    fprintf(stderr, "[scm_event] Event emission initialized -> %s\n",
            EVENT_SOCKET_PATH);
    return 0;
}

void scm_event_shutdown(void)
{
    if (g_event_fd >= 0) {
        close(g_event_fd);
        g_event_fd = -1;
    }
    fprintf(stderr, "[scm_event] Event emission shut down (%" PRIu64
            " events sent)\n", g_event_seq);
}

void scm_event_emit(uint8_t event_type, uint32_t pid,
                    const char *service_name, int32_t exit_code,
                    uint32_t restart_count)
{
    if (g_event_fd < 0)
        return;  /* Events not available -- silent drop */

    /* Build the wire frame: header + payload */
    uint8_t buf[64 + sizeof(scm_event_payload_t)];
    memset(buf, 0, sizeof(buf));

    scm_wire_header_t *hdr = (scm_wire_header_t *)buf;
    hdr->magic        = EVENT_MAGIC;
    hdr->version      = EVENT_VERSION;
    hdr->source_layer = EVENT_SRC_SCM;
    hdr->event_type   = event_type;
    hdr->timestamp_ns = get_boottime_ns();
    hdr->pid          = pid;
    hdr->tid          = 0;
    hdr->subject_id   = 0;
    hdr->sequence     = g_event_seq++;
    hdr->payload_len  = (uint16_t)sizeof(scm_event_payload_t);
    hdr->flags        = 0;

    /* Mark crashes as urgent so cortex can prioritize */
    if (event_type == SVC_EVT_CRASH || event_type == SVC_EVT_DEPENDENCY_FAIL)
        hdr->flags = 0x0001;  /* PE_EVENT_FLAG_URGENT */

    scm_event_payload_t *payload = (scm_event_payload_t *)(buf + 64);
    if (service_name)
        strncpy(payload->service_name, service_name,
                sizeof(payload->service_name) - 1);
    payload->exit_code     = exit_code;
    payload->restart_count = restart_count;
    payload->uptime_sec    = 0;  /* Caller can fill in if known */

    /* Fire-and-forget: sendto() may fail with ENOENT if cortex socket is
     * not yet bound, or EAGAIN if the kernel buffer is full.  We never
     * retry -- the next event will succeed if the cortex comes back. */
    ssize_t n = sendto(g_event_fd, buf, sizeof(buf), MSG_DONTWAIT,
                       (struct sockaddr *)&g_event_addr,
                       sizeof(g_event_addr));
    (void)n;  /* Intentionally ignoring return value */
}

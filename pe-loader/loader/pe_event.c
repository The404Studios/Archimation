/* Need _GNU_SOURCE for gettid() on glibc 2.30+ */
#define _GNU_SOURCE

/*
 * pe_event.c - Lock-free event emitter for PE runtime
 *
 * Implements a multi-producer, single-consumer ring buffer that drains
 * events to the AI Cortex via a Unix datagram socket.  The design
 * guarantees that PE process execution is NEVER blocked by the event
 * system:
 *
 *   - Ring buffer: 4096 slots, each PE_EVENT_MAX_SIZE (4096) bytes.
 *     Global atomic write index allows multiple threads to emit events
 *     concurrently without locks.
 *
 *   - Drain thread: wakes every 1ms, reads events from the ring buffer,
 *     and sends them as datagrams to /run/pe-compat/events.sock.
 *     If sendto() fails (cortex not listening), events are silently dropped.
 *
 *   - Graceful degradation: if the socket doesn't exist at init time,
 *     g_events_available is set to 0 and all pe_event_emit() calls
 *     return immediately with -1.  Zero overhead in this path.
 *
 * Socket protocol: each datagram is a pe_event_header_t (64 bytes)
 * followed by the payload.  No framing needed since datagrams preserve
 * message boundaries.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdatomic.h>

#include "eventbus/pe_event.h"

/* ========================================================================
 * Configuration
 * ======================================================================== */

/* 1024 slots * 4KB each = 4MB total ring buffer.
 * Sized to avoid excessive memory use while still buffering bursts.
 * Must be a power of 2 for bitmask wrap-around. */
#define RING_SIZE       1024
#define RING_MASK       (RING_SIZE - 1)
#define SLOT_SIZE       PE_EVENT_MAX_SIZE      /* Bytes per slot */
#define DRAIN_INTERVAL_NS  1000000            /* 1ms between drain iterations */

#define CORTEX_SOCK_PATH   "/run/pe-compat/events.sock"

/* ========================================================================
 * Ring buffer
 *
 * Multi-producer: each emitter atomically increments g_write_idx to
 * claim a slot, then writes the event into that slot and sets the
 * slot's 'ready' flag.
 *
 * Single-consumer: the drain thread reads from g_read_idx up to
 * g_write_idx, skipping slots that aren't ready yet (producer still
 * writing).  After sending, the ready flag is cleared.
 * ======================================================================== */

typedef struct {
    _Atomic uint32_t ready;                    /* 1 = data valid, 0 = empty */
    uint32_t         len;                      /* Total bytes (header + payload) */
    uint8_t          data[SLOT_SIZE];          /* Event frame */
} ring_slot_t;

static ring_slot_t     *g_ring       = NULL;   /* Heap-allocated ring buffer */
static _Atomic uint64_t g_write_idx  = 0;      /* Next slot for producers */
static uint64_t         g_read_idx   = 0;      /* Next slot for drain thread */

/* ========================================================================
 * Global state
 * ======================================================================== */

static _Atomic int      g_events_available = 0; /* 1 = socket connected */
static int              g_sock_fd          = -1; /* Datagram socket */
static struct sockaddr_un g_cortex_addr;         /* Cortex socket address */
static socklen_t        g_cortex_addrlen   = 0;

static pthread_t        g_drain_thread;
static _Atomic int      g_drain_running    = 0;  /* 1 = thread should run */
static _Atomic int      g_initialized      = 0;

static _Atomic uint64_t g_sequence         = 0;  /* Monotonic event counter */
static _Atomic uint64_t g_dropped          = 0;  /* Events dropped (ring full) */

/* ========================================================================
 * Internal helpers
 * ======================================================================== */

/* Get CLOCK_BOOTTIME timestamp in nanoseconds.
 * CLOCK_BOOTTIME includes time spent in suspend, giving a stable
 * monotonic timeline that the cortex can correlate across sleep/wake. */
static uint64_t now_boottime_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Get current thread ID.
 * gettid() is available since glibc 2.30 / Linux 4.x.
 * Fall back to getpid() on older systems. */
static uint32_t get_tid(void)
{
#if defined(__linux__)
    return (uint32_t)gettid();
#else
    return (uint32_t)getpid();
#endif
}

/* ========================================================================
 * Drain thread
 *
 * Runs in the background, reading events from the ring buffer and
 * sending them as datagrams to the cortex socket.  Sleeps 1ms between
 * iterations to avoid busy-spinning while still providing low latency.
 *
 * If sendto() fails (e.g., cortex not running, socket buffer full),
 * the event is silently dropped.  The drain thread never blocks the
 * PE process.
 * ======================================================================== */

static void *drain_thread_fn(void *arg)
{
    (void)arg;
    struct timespec sleep_ts = {
        .tv_sec  = 0,
        .tv_nsec = DRAIN_INTERVAL_NS
    };

    /* Per-slot stall counter: bounded retries distinguish "producer is
     * still writing" (retry next tick) from "slot was dropped and will
     * never be ready" (skip to unstick the drain). */
    uint32_t stall_count = 0;

    while (atomic_load(&g_drain_running)) {
        /* Drain all available events */
        uint64_t write_snapshot = atomic_load(&g_write_idx);

        while (g_read_idx < write_snapshot) {
            uint32_t slot_idx = (uint32_t)(g_read_idx & RING_MASK);
            ring_slot_t *slot = &g_ring[slot_idx];

            if (!atomic_load(&slot->ready)) {
                /* Either producer is still writing, or the slot was
                 * dropped (producer saw ready==1 and returned without
                 * setting ready). After a few ticks with no progress,
                 * treat as dropped to avoid permanent drain stall. */
                if (++stall_count >= 4) {
                    g_read_idx++;
                    stall_count = 0;
                    continue;
                }
                break;
            }
            stall_count = 0;

            /* Send the event as a datagram */
            if (g_sock_fd >= 0) {
                sendto(g_sock_fd, slot->data, slot->len, MSG_DONTWAIT,
                       (struct sockaddr *)&g_cortex_addr, g_cortex_addrlen);
                /* Ignore sendto errors - fire and forget */
            }

            /* Mark slot as consumed */
            atomic_store(&slot->ready, 0);
            g_read_idx++;
        }

        nanosleep(&sleep_ts, NULL);
    }

    /* Final drain: flush any remaining events before shutdown */
    uint64_t write_snapshot = atomic_load(&g_write_idx);
    while (g_read_idx < write_snapshot) {
        uint32_t slot_idx = (uint32_t)(g_read_idx & RING_MASK);
        ring_slot_t *slot = &g_ring[slot_idx];

        if (!atomic_load(&slot->ready)) {
            /* Skip not-ready slots on final drain so we exit promptly
             * rather than wait forever on a dropped slot. */
            g_read_idx++;
            continue;
        }

        if (g_sock_fd >= 0) {
            sendto(g_sock_fd, slot->data, slot->len, MSG_DONTWAIT,
                   (struct sockaddr *)&g_cortex_addr, g_cortex_addrlen);
        }

        atomic_store(&slot->ready, 0);
        g_read_idx++;
    }

    return NULL;
}

/* ========================================================================
 * Public API
 * ======================================================================== */

__attribute__((visibility("default")))
int pe_event_init(void)
{
    /* Use atomic CAS to prevent double-init races between threads */
    int expected = 0;
    if (!atomic_compare_exchange_strong(&g_initialized, &expected, 1))
        return atomic_load(&g_events_available) ? 0 : -1;

    /* Allocate ring buffer.
     * calloc zeroes the memory, so all ready flags start at 0. */
    g_ring = calloc(RING_SIZE, sizeof(ring_slot_t));
    if (!g_ring) {
        fprintf(stderr, "[pe_event] Failed to allocate ring buffer (%zu bytes)\n",
                (size_t)RING_SIZE * sizeof(ring_slot_t));
        atomic_store(&g_events_available, 0);
        atomic_store(&g_initialized, 0);
        return -1;
    }

    /* Create a Unix datagram socket (non-blocking) */
    g_sock_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (g_sock_fd < 0) {
        fprintf(stderr, "[pe_event] Failed to create socket: %s\n",
                strerror(errno));
        free(g_ring);
        g_ring = NULL;
        atomic_store(&g_events_available, 0);
        atomic_store(&g_initialized, 0);
        return -1;
    }

    /* Set up the cortex socket address.
     * We don't connect() - just sendto() each datagram.  If the socket
     * doesn't exist yet, sendto() will fail silently. */
    memset(&g_cortex_addr, 0, sizeof(g_cortex_addr));
    g_cortex_addr.sun_family = AF_UNIX;
    strncpy(g_cortex_addr.sun_path, CORTEX_SOCK_PATH,
            sizeof(g_cortex_addr.sun_path) - 1);
    g_cortex_addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path)
                                    + strlen(g_cortex_addr.sun_path) + 1);

    /* Check if the cortex socket exists.
     * If it doesn't, we still initialize (socket may appear later),
     * but we log a note for debugging. */
    if (access(CORTEX_SOCK_PATH, F_OK) != 0) {
        fprintf(stderr, "[pe_event] Cortex socket not found at %s "
                "(events will be buffered/dropped until cortex starts)\n",
                CORTEX_SOCK_PATH);
    }

    /* Mark events as available - the drain thread will handle sendto
     * failures gracefully even if the cortex isn't listening yet. */
    atomic_store(&g_events_available, 1);

    /* Start the drain thread */
    atomic_store(&g_drain_running, 1);
    if (pthread_create(&g_drain_thread, NULL, drain_thread_fn, NULL) != 0) {
        fprintf(stderr, "[pe_event] Failed to create drain thread: %s\n",
                strerror(errno));
        close(g_sock_fd);
        g_sock_fd = -1;
        free(g_ring);
        g_ring = NULL;
        atomic_store(&g_events_available, 0);
        atomic_store(&g_drain_running, 0);
        atomic_store(&g_initialized, 0);
        return -1;
    }

    /* Detach is not needed - we join on shutdown */

    /* g_initialized already set to 1 by CAS above */
    return 0;
}

__attribute__((visibility("default")))
void pe_event_shutdown(void)
{
    if (!atomic_load(&g_initialized))
        return;

    /* Prevent new events from being emitted FIRST (atomic) */
    int was_available = atomic_exchange(&g_events_available, 0);

    /* Signal the drain thread to stop and wait for it */
    if (was_available) {
        atomic_store(&g_drain_running, 0);
        pthread_join(g_drain_thread, NULL);
    }

    /* Close the socket */
    if (g_sock_fd >= 0) {
        close(g_sock_fd);
        g_sock_fd = -1;
    }

    /* Free the ring buffer (safe now: no emitters, drain thread joined) */
    if (g_ring) {
        free(g_ring);
        g_ring = NULL;
    }

    uint64_t dropped = atomic_load(&g_dropped);
    if (dropped > 0) {
        fprintf(stderr, "[pe_event] Shutdown: %" PRIu64 " events dropped "
                "(ring full)\n", dropped);
    }

    atomic_store(&g_initialized, 0);
}

__attribute__((visibility("default")))
int pe_event_emit(uint8_t event_type, const void *payload, uint16_t payload_len)
{
    return pe_event_emit_flags(event_type, payload, payload_len, 0);
}

__attribute__((visibility("default")))
int pe_event_emit_flags(uint8_t event_type, const void *payload,
                        uint16_t payload_len, uint16_t flags)
{
    /* Fast exit: if event system is not available, return immediately */
    if (!atomic_load(&g_events_available))
        return -1;

    /* Validate payload size */
    uint32_t total_len = sizeof(pe_event_header_t) + payload_len;
    if (total_len > SLOT_SIZE) {
        /* Payload too large - truncate to fit */
        payload_len = (uint16_t)(SLOT_SIZE - sizeof(pe_event_header_t));
        total_len = SLOT_SIZE;
    }

    /* Claim a ring buffer slot (atomic increment, never blocks) */
    uint64_t idx = atomic_fetch_add(&g_write_idx, 1);
    uint32_t slot_idx = (uint32_t)(idx & RING_MASK);
    ring_slot_t *slot = &g_ring[slot_idx];

    /* If the slot is still occupied (ready==1), the drain thread hasn't
     * consumed it yet.  Rather than overwriting (MPSC race: another
     * producer could also be targeting this slot), we DROP this event.
     * The atomic write index has already advanced, so the drain thread
     * will see ready==0 for this slot and skip it.  This is safe. */
    if (atomic_load(&slot->ready)) {
        atomic_fetch_add(&g_dropped, 1);
        return -1;
    }

    /* Fill the event header */
    pe_event_header_t *hdr = (pe_event_header_t *)slot->data;
    memset(hdr, 0, sizeof(*hdr));

    hdr->magic        = PE_EVENT_MAGIC;
    hdr->version      = PE_EVENT_VERSION;
    hdr->source_layer = PE_EVENT_SRC_RUNTIME;
    hdr->event_type   = event_type;
    hdr->timestamp_ns = now_boottime_ns();
    hdr->pid          = (uint32_t)getpid();
    hdr->tid          = get_tid();
    hdr->subject_id   = (uint32_t)getpid();  /* Trust subject ID = PID */
    hdr->sequence     = atomic_fetch_add(&g_sequence, 1);
    hdr->payload_len  = payload_len;
    hdr->flags        = flags;

    /* Copy payload after header */
    if (payload && payload_len > 0) {
        memcpy(slot->data + sizeof(pe_event_header_t), payload, payload_len);
    }

    slot->len = total_len;

    /* Memory fence: ensure all writes to the slot are visible before
     * we set the ready flag that the drain thread reads. */
    atomic_store(&slot->ready, 1);

    return 0;
}

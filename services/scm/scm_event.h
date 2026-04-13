/*
 * scm_event.h - Service event emission to the AI cortex
 *
 * Sends service lifecycle events as UDP datagrams to
 * /run/pe-compat/events.sock using the pe_event_header_t wire format
 * defined in pe_event.h.
 *
 * All emission is fire-and-forget: if the cortex is not listening or the
 * socket send fails, the event is silently dropped.  The SCM never blocks.
 */

#ifndef SCM_EVENT_H
#define SCM_EVENT_H

#include <stdint.h>

/* Service event types (match pe_event.h SVC_EVT_*) */
#define SVC_EVT_INSTALL          0x01
#define SVC_EVT_START            0x02
#define SVC_EVT_STOP             0x03
#define SVC_EVT_CRASH            0x04
#define SVC_EVT_RESTART          0x05
#define SVC_EVT_DEPENDENCY_FAIL  0x06
#define SVC_EVT_HEALTH_OK        0x07

/* Service event payload (follows the 64-byte pe_event_header_t) */
typedef struct {
    char     service_name[256];
    int32_t  exit_code;
    uint32_t restart_count;
    uint32_t uptime_sec;         /* seconds since service started */
} scm_event_payload_t;

/* Initialize the event emission socket.
 * Opens a SOCK_DGRAM AF_UNIX socket pointed at /run/pe-compat/events.sock.
 * Returns 0 on success, -1 on failure (non-fatal; events are just dropped). */
int scm_event_init(void);

/* Close the event socket.  Safe to call even if init failed. */
void scm_event_shutdown(void);

/* Emit a service event to the cortex (fire-and-forget, never blocks).
 * event_type: one of SVC_EVT_*
 * pid:        PID of the service process (0 for non-running events)
 * service_name: Windows service name
 * exit_code:  exit code of the process (0 for start/install events)
 * restart_count: number of consecutive restarts (0 if not applicable)
 */
void scm_event_emit(uint8_t event_type, uint32_t pid,
                    const char *service_name, int32_t exit_code,
                    uint32_t restart_count);

#endif /* SCM_EVENT_H */

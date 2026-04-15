/*
 * ioctl_bridge.c - DeviceIoControl translation bridge
 *
 * Translates Windows DeviceIoControl() calls into dispatches to the
 * appropriate registered driver handler function running in userspace.
 *
 * Windows IOCTL codes are 32-bit values encoding:
 *   Bits 31-16: Device type
 *   Bits 15-14: Required access (FILE_ANY_ACCESS, FILE_READ_ACCESS, etc.)
 *   Bits 13-2:  Function code (driver-defined)
 *   Bits 1-0:   Transfer method (METHOD_BUFFERED, METHOD_IN_DIRECT, etc.)
 *
 * The bridge maintains a registry of driver handlers. When a DeviceIoControl
 * call arrives (via the PE loader or syscall translation), the bridge:
 *   1. Parses the IOCTL code to extract device type and function
 *   2. Finds the registered driver handler for that device type
 *   3. Manages input/output buffers according to the transfer method
 *   4. Dispatches to the driver's handler function
 *   5. Returns results to the caller
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#define IOCTL_LOG_PREFIX    "[ioctl_bridge] "
#define MAX_DRIVERS         64
#define MAX_PENDING_IOCTLS  256

/* IOCTL code field extraction macros (matching Windows CTL_CODE layout) */
#define IOCTL_DEVICE_TYPE(code)     (((code) >> 16) & 0xFFFF)
#define IOCTL_ACCESS(code)          (((code) >> 14) & 0x3)
#define IOCTL_FUNCTION(code)        (((code) >> 2) & 0xFFF)
#define IOCTL_METHOD(code)          ((code) & 0x3)

/* CTL_CODE macro for constructing IOCTL codes */
#define CTL_CODE(dev_type, func, method, access) \
    ((unsigned long)(((dev_type) << 16) | ((access) << 14) | ((func) << 2) | (method)))

/* Transfer methods */
#define METHOD_BUFFERED         0
#define METHOD_IN_DIRECT        1
#define METHOD_OUT_DIRECT       2
#define METHOD_NEITHER          3

/* Required access */
#define FILE_ANY_ACCESS         0
#define FILE_READ_ACCESS        1
#define FILE_WRITE_ACCESS       2
#define FILE_READ_WRITE_ACCESS  3

/* Common device types */
#define FILE_DEVICE_UNKNOWN     0x0022
#define FILE_DEVICE_NETWORK     0x0012
#define FILE_DEVICE_DISK        0x0007
#define FILE_DEVICE_KEYBOARD    0x000B
#define FILE_DEVICE_MOUSE       0x000F
#define FILE_DEVICE_VIDEO       0x0023
#define FILE_DEVICE_SOUND       0x001D

/* Windows-compatible status codes */
#define STATUS_SUCCESS              0x00000000
#define STATUS_INVALID_PARAMETER    0xC000000D
#define STATUS_NOT_IMPLEMENTED      0xC0000002
#define STATUS_BUFFER_TOO_SMALL     0xC0000023
#define STATUS_ACCESS_DENIED        0xC0000022
#define STATUS_INVALID_DEVICE_REQUEST 0xC0000010

/* IOCTL request structure passed to driver handlers */
typedef struct {
    unsigned long   ioctl_code;         /* Raw IOCTL code */
    unsigned int    device_type;        /* Extracted device type */
    unsigned int    function;           /* Extracted function code */
    unsigned int    method;             /* Transfer method */
    unsigned int    access;             /* Required access */

    void            *input_buffer;      /* Input data from caller */
    unsigned long   input_length;       /* Size of input buffer */
    void            *output_buffer;     /* Output buffer for results */
    unsigned long   output_length;      /* Size of output buffer */
    unsigned long   *bytes_returned;    /* Actual bytes written to output */

    void            *driver_context;    /* Driver-specific context */
} ioctl_request_t;

/*
 * Driver IOCTL handler function prototype.
 * Returns a Windows NTSTATUS-compatible value.
 */
typedef unsigned long (*ioctl_handler_fn)(ioctl_request_t *request);

/*
 * Registered driver entry in the IOCTL bridge.
 */
typedef struct {
    char                name[256];          /* Driver name */
    unsigned int        device_type;        /* Device type this driver handles */
    ioctl_handler_fn    handler;            /* IOCTL dispatch function */
    void                *driver_context;    /* Opaque driver context */
    int                 active;             /* Whether this registration is active */
    unsigned long       calls_handled;      /* Statistics: total calls dispatched */
    unsigned long       calls_failed;       /* Statistics: total failed calls */
} ioctl_driver_t;

static ioctl_driver_t   g_drivers[MAX_DRIVERS];
static int              g_num_drivers = 0;
static pthread_mutex_t  g_ioctl_lock = PTHREAD_MUTEX_INITIALIZER;
static int              g_bridge_initialized = 0;
static unsigned long    g_total_dispatches = 0;

/* Forward declarations */
static ioctl_driver_t  *find_driver_by_type(unsigned int device_type);
static unsigned long    dispatch_buffered(ioctl_driver_t *drv,
                                          ioctl_request_t *req);
static unsigned long    dispatch_direct_in(ioctl_driver_t *drv,
                                           ioctl_request_t *req);
static unsigned long    dispatch_direct_out(ioctl_driver_t *drv,
                                            ioctl_request_t *req);
static unsigned long    dispatch_neither(ioctl_driver_t *drv,
                                         ioctl_request_t *req);
static const char      *status_to_string(unsigned long status);
static const char      *method_to_string(unsigned int method);

/*
 * find_driver_by_type - Locate a registered driver by device type.
 * Must be called with g_ioctl_lock held.
 */
static ioctl_driver_t *find_driver_by_type(unsigned int device_type)
{
    for (int i = 0; i < g_num_drivers; i++) {
        if (g_drivers[i].active && g_drivers[i].device_type == device_type)
            return &g_drivers[i];
    }
    return NULL;
}

/*
 * dispatch_buffered - Handle METHOD_BUFFERED IOCTL.
 *
 * Windows behavior: the I/O manager allocates a single system buffer
 * large enough for both input and output. Input data is copied in,
 * driver writes output to the same buffer, then output is copied back.
 */
static unsigned long dispatch_buffered(ioctl_driver_t *drv,
                                       ioctl_request_t *req)
{
    /* Allocate a combined buffer (max of input and output sizes) */
    unsigned long buf_size = req->input_length;
    if (req->output_length > buf_size)
        buf_size = req->output_length;

    if (buf_size == 0) {
        /* No buffer needed, just dispatch */
        return drv->handler(req);
    }

    void *system_buffer = calloc(1, buf_size);
    if (!system_buffer) {
        fprintf(stderr, IOCTL_LOG_PREFIX
                "Failed to allocate system buffer (%lu bytes)\n", buf_size);
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Copy input data into system buffer */
    if (req->input_buffer && req->input_length > 0)
        memcpy(system_buffer, req->input_buffer, req->input_length);

    /* Save original pointers and replace with system buffer */
    void *orig_input = req->input_buffer;
    void *orig_output = req->output_buffer;
    req->input_buffer = system_buffer;
    req->output_buffer = system_buffer;

    unsigned long status = drv->handler(req);

    /* Copy output from system buffer back to caller's output buffer */
    if (status == STATUS_SUCCESS && orig_output && req->bytes_returned) {
        unsigned long to_copy = *req->bytes_returned;
        if (to_copy > req->output_length)
            to_copy = req->output_length;
        memcpy(orig_output, system_buffer, to_copy);
    }

    /* Restore original pointers */
    req->input_buffer = orig_input;
    req->output_buffer = orig_output;

    free(system_buffer);
    return status;
}

/*
 * dispatch_direct_in - Handle METHOD_IN_DIRECT IOCTL.
 *
 * Windows behavior: input buffer is buffered (system buffer allocated),
 * output buffer is locked in memory and mapped directly (MDL).
 * For userspace emulation, we pass pointers through directly since
 * both caller and driver share the same address space.
 */
static unsigned long dispatch_direct_in(ioctl_driver_t *drv,
                                        ioctl_request_t *req)
{
    void *system_buffer = NULL;

    /* Buffer the input data */
    if (req->input_length > 0 && req->input_buffer) {
        system_buffer = malloc(req->input_length);
        if (!system_buffer) {
            fprintf(stderr, IOCTL_LOG_PREFIX
                    "Failed to allocate input buffer (%lu bytes)\n",
                    req->input_length);
            return STATUS_BUFFER_TOO_SMALL;
        }
        memcpy(system_buffer, req->input_buffer, req->input_length);
    }

    void *orig_input = req->input_buffer;
    if (system_buffer)
        req->input_buffer = system_buffer;

    /* Output buffer passes through directly (simulating MDL mapping) */
    unsigned long status = drv->handler(req);

    req->input_buffer = orig_input;
    free(system_buffer);

    return status;
}

/*
 * dispatch_direct_out - Handle METHOD_OUT_DIRECT IOCTL.
 *
 * Windows behavior: input buffer is buffered (system buffer allocated),
 * output buffer is locked and mapped via MDL for direct writing.
 * Similar to METHOD_IN_DIRECT but for output direction.
 */
static unsigned long dispatch_direct_out(ioctl_driver_t *drv,
                                         ioctl_request_t *req)
{
    void *system_buffer = NULL;

    /* Buffer the input data */
    if (req->input_length > 0 && req->input_buffer) {
        system_buffer = malloc(req->input_length);
        if (!system_buffer) {
            fprintf(stderr, IOCTL_LOG_PREFIX
                    "Failed to allocate input buffer (%lu bytes)\n",
                    req->input_length);
            return STATUS_BUFFER_TOO_SMALL;
        }
        memcpy(system_buffer, req->input_buffer, req->input_length);
    }

    void *orig_input = req->input_buffer;
    if (system_buffer)
        req->input_buffer = system_buffer;

    /* Output buffer passes through directly */
    unsigned long status = drv->handler(req);

    req->input_buffer = orig_input;
    free(system_buffer);

    return status;
}

/*
 * dispatch_neither - Handle METHOD_NEITHER IOCTL.
 *
 * Windows behavior: no buffering at all. The driver receives the raw
 * user-mode pointers. In our userspace emulation this is trivial since
 * both sides share the address space.
 */
static unsigned long dispatch_neither(ioctl_driver_t *drv,
                                      ioctl_request_t *req)
{
    /* Pass through directly - no buffer management needed in userspace */
    return drv->handler(req);
}

/*
 * status_to_string - Convert NTSTATUS code to a human-readable string.
 */
static const char *status_to_string(unsigned long status)
{
    switch (status) {
    case STATUS_SUCCESS:                return "SUCCESS";
    case STATUS_INVALID_PARAMETER:      return "INVALID_PARAMETER";
    case STATUS_NOT_IMPLEMENTED:        return "NOT_IMPLEMENTED";
    case STATUS_BUFFER_TOO_SMALL:       return "BUFFER_TOO_SMALL";
    case STATUS_ACCESS_DENIED:          return "ACCESS_DENIED";
    case STATUS_INVALID_DEVICE_REQUEST: return "INVALID_DEVICE_REQUEST";
    default:                            return "UNKNOWN";
    }
}

/*
 * method_to_string - Convert transfer method to string.
 */
static const char *method_to_string(unsigned int method)
{
    switch (method) {
    case METHOD_BUFFERED:       return "BUFFERED";
    case METHOD_IN_DIRECT:      return "IN_DIRECT";
    case METHOD_OUT_DIRECT:     return "OUT_DIRECT";
    case METHOD_NEITHER:        return "NEITHER";
    default:                    return "UNKNOWN";
    }
}

/*
 * ioctl_bridge_init - Initialize the IOCTL bridge subsystem.
 *
 * Must be called before any other ioctl_bridge_* functions.
 * Returns 0 on success, -1 on failure.
 */
int ioctl_bridge_init(void)
{
    pthread_mutex_lock(&g_ioctl_lock);

    if (g_bridge_initialized) {
        fprintf(stderr, IOCTL_LOG_PREFIX "Bridge already initialized\n");
        pthread_mutex_unlock(&g_ioctl_lock);
        return 0;
    }

    memset(g_drivers, 0, sizeof(g_drivers));
    g_num_drivers = 0;
    g_total_dispatches = 0;
    g_bridge_initialized = 1;

    fprintf(stderr, IOCTL_LOG_PREFIX "IOCTL bridge initialized\n");

    pthread_mutex_unlock(&g_ioctl_lock);
    return 0;
}

/*
 * ioctl_bridge_register_driver - Register a driver's IOCTL handler.
 *
 * name:            Driver name for identification and logging
 * device_type:     The device type code this driver handles
 * handler:         Function to call for IOCTL dispatch
 * driver_context:  Opaque pointer passed to the handler in each request
 *
 * Returns 0 on success, -1 on failure (table full, duplicate type, etc.).
 */
int ioctl_bridge_register_driver(const char *name, unsigned int device_type,
                                 ioctl_handler_fn handler,
                                 void *driver_context)
{
    if (!name || !handler) {
        fprintf(stderr, IOCTL_LOG_PREFIX "register: NULL argument\n");
        return -1;
    }

    pthread_mutex_lock(&g_ioctl_lock);

    if (!g_bridge_initialized) {
        fprintf(stderr, IOCTL_LOG_PREFIX "Bridge not initialized\n");
        pthread_mutex_unlock(&g_ioctl_lock);
        return -1;
    }

    /* Check for duplicate device type registration */
    ioctl_driver_t *existing = find_driver_by_type(device_type);
    if (existing) {
        fprintf(stderr, IOCTL_LOG_PREFIX
                "Device type 0x%04x already registered by '%s'\n",
                device_type, existing->name);
        pthread_mutex_unlock(&g_ioctl_lock);
        return -1;
    }

    /* Find an empty slot (prefer reusing inactive slots) */
    int slot = -1;
    for (int i = 0; i < g_num_drivers; i++) {
        if (!g_drivers[i].active) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        if (g_num_drivers >= MAX_DRIVERS) {
            fprintf(stderr, IOCTL_LOG_PREFIX
                    "Driver table full (%d/%d)\n", g_num_drivers, MAX_DRIVERS);
            pthread_mutex_unlock(&g_ioctl_lock);
            return -1;
        }
        slot = g_num_drivers++;
    }

    ioctl_driver_t *drv = &g_drivers[slot];
    memset(drv, 0, sizeof(*drv));
    strncpy(drv->name, name, sizeof(drv->name) - 1);
    drv->device_type = device_type;
    drv->handler = handler;
    drv->driver_context = driver_context;
    drv->active = 1;

    fprintf(stderr, IOCTL_LOG_PREFIX
            "Registered driver '%s' for device type 0x%04x (slot %d)\n",
            name, device_type, slot);

    pthread_mutex_unlock(&g_ioctl_lock);
    return 0;
}

/*
 * ioctl_bridge_unregister_driver - Remove a driver's IOCTL handler registration.
 *
 * name: Name of the driver to unregister.
 *
 * Returns 0 on success, -1 if driver not found.
 */
int ioctl_bridge_unregister_driver(const char *name)
{
    if (!name) return -1;

    pthread_mutex_lock(&g_ioctl_lock);

    for (int i = 0; i < g_num_drivers; i++) {
        if (g_drivers[i].active && strcasecmp(g_drivers[i].name, name) == 0) {
            fprintf(stderr, IOCTL_LOG_PREFIX
                    "Unregistering driver '%s' (type 0x%04x, "
                    "%lu calls handled, %lu failed)\n",
                    name, g_drivers[i].device_type,
                    g_drivers[i].calls_handled,
                    g_drivers[i].calls_failed);
            g_drivers[i].active = 0;
            pthread_mutex_unlock(&g_ioctl_lock);
            return 0;
        }
    }

    fprintf(stderr, IOCTL_LOG_PREFIX
            "Driver '%s' not found for unregister\n", name);
    pthread_mutex_unlock(&g_ioctl_lock);
    return -1;
}

/*
 * ioctl_bridge_dispatch - Dispatch a DeviceIoControl call.
 *
 * This is the main entry point called by the PE loader's syscall translation
 * when a Windows program calls DeviceIoControl().
 *
 * ioctl_code:      The IOCTL control code
 * input_buffer:    Pointer to input data (may be NULL)
 * input_length:    Size of input data in bytes
 * output_buffer:   Pointer to output buffer (may be NULL)
 * output_length:   Size of output buffer in bytes
 * bytes_returned:  Receives the actual bytes written to output
 *
 * Returns a Windows NTSTATUS-compatible value.
 */
unsigned long ioctl_bridge_dispatch(unsigned long ioctl_code,
                                    void *input_buffer,
                                    unsigned long input_length,
                                    void *output_buffer,
                                    unsigned long output_length,
                                    unsigned long *bytes_returned)
{
    unsigned int device_type = IOCTL_DEVICE_TYPE(ioctl_code);
    unsigned int function    = IOCTL_FUNCTION(ioctl_code);
    unsigned int method      = IOCTL_METHOD(ioctl_code);
    unsigned int access      = IOCTL_ACCESS(ioctl_code);

    fprintf(stderr, IOCTL_LOG_PREFIX
            "Dispatch: code=0x%08lx type=0x%04x func=0x%03x "
            "method=%s access=%d in=%lu out=%lu\n",
            ioctl_code, device_type, function,
            method_to_string(method), access,
            input_length, output_length);

    pthread_mutex_lock(&g_ioctl_lock);

    if (!g_bridge_initialized) {
        fprintf(stderr, IOCTL_LOG_PREFIX "Bridge not initialized\n");
        pthread_mutex_unlock(&g_ioctl_lock);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    ioctl_driver_t *drv = find_driver_by_type(device_type);
    if (!drv) {
        fprintf(stderr, IOCTL_LOG_PREFIX
                "No driver registered for device type 0x%04x\n", device_type);
        pthread_mutex_unlock(&g_ioctl_lock);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    g_total_dispatches++;

    /*
     * Snapshot handler + context under the lock. This avoids a TOCTOU where
     * another thread unregisters/re-registers the driver while we are
     * running the handler with the lock released. The slot itself remains
     * stable (slots are reused, not freed), so using the slot index for
     * stats writes after re-acquiring the lock is safe.
     */
    ioctl_handler_fn handler_snap = drv->handler;
    void *context_snap = drv->driver_context;
    int slot_idx = (int)(drv - g_drivers);

    /* Build the request structure */
    unsigned long actual_returned = 0;
    ioctl_request_t req;
    memset(&req, 0, sizeof(req));
    req.ioctl_code      = ioctl_code;
    req.device_type     = device_type;
    req.function        = function;
    req.method          = method;
    req.access          = access;
    req.input_buffer    = input_buffer;
    req.input_length    = input_length;
    req.output_buffer   = output_buffer;
    req.output_length   = output_length;
    req.bytes_returned  = bytes_returned ? bytes_returned : &actual_returned;
    req.driver_context  = context_snap;

    /* Build a temporary driver struct for the dispatch_* helpers */
    ioctl_driver_t local_drv;
    memset(&local_drv, 0, sizeof(local_drv));
    strncpy(local_drv.name, drv->name, sizeof(local_drv.name) - 1);
    local_drv.device_type = device_type;
    local_drv.handler = handler_snap;
    local_drv.driver_context = context_snap;
    local_drv.active = 1;

    /* Release the lock during handler execution to allow concurrent IOCTLs */
    pthread_mutex_unlock(&g_ioctl_lock);

    /* Dispatch based on transfer method */
    unsigned long status;
    switch (method) {
    case METHOD_BUFFERED:
        status = dispatch_buffered(&local_drv, &req);
        break;
    case METHOD_IN_DIRECT:
        status = dispatch_direct_in(&local_drv, &req);
        break;
    case METHOD_OUT_DIRECT:
        status = dispatch_direct_out(&local_drv, &req);
        break;
    case METHOD_NEITHER:
        status = dispatch_neither(&local_drv, &req);
        break;
    default:
        fprintf(stderr, IOCTL_LOG_PREFIX
                "Unknown transfer method %d\n", method);
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    /* Update statistics on the real slot, guarded by the lock */
    pthread_mutex_lock(&g_ioctl_lock);
    if (slot_idx >= 0 && slot_idx < MAX_DRIVERS) {
        g_drivers[slot_idx].calls_handled++;
        if (status != STATUS_SUCCESS)
            g_drivers[slot_idx].calls_failed++;
    }
    pthread_mutex_unlock(&g_ioctl_lock);

    fprintf(stderr, IOCTL_LOG_PREFIX
            "Dispatch result: %s (0x%08lx), returned %lu bytes\n",
            status_to_string(status), status,
            bytes_returned ? *bytes_returned : 0);

    return status;
}

/*
 * ioctl_bridge_get_stats - Print bridge statistics to the given stream.
 */
void ioctl_bridge_get_stats(FILE *output)
{
    if (!output) output = stdout;

    pthread_mutex_lock(&g_ioctl_lock);

    fprintf(output, "IOCTL Bridge Statistics:\n");
    fprintf(output, "  Total dispatches: %lu\n", g_total_dispatches);
    fprintf(output, "  Registered drivers: %d\n", g_num_drivers);
    fprintf(output, "\n");

    fprintf(output, "  %-20s %-12s %-12s %-12s %s\n",
            "DRIVER", "DEV TYPE", "HANDLED", "FAILED", "STATUS");
    fprintf(output, "  %-20s %-12s %-12s %-12s %s\n",
            "------", "--------", "-------", "------", "------");

    for (int i = 0; i < g_num_drivers; i++) {
        if (!g_drivers[i].active) continue;
        fprintf(output, "  %-20s 0x%04x       %-12lu %-12lu %s\n",
                g_drivers[i].name,
                g_drivers[i].device_type,
                g_drivers[i].calls_handled,
                g_drivers[i].calls_failed,
                g_drivers[i].active ? "ACTIVE" : "INACTIVE");
    }

    pthread_mutex_unlock(&g_ioctl_lock);
}

/*
 * ioctl_bridge_cleanup - Shut down the IOCTL bridge and release resources.
 *
 * All registered drivers are unregistered. Any in-flight IOCTLs must have
 * completed before calling this function.
 */
void ioctl_bridge_cleanup(void)
{
    pthread_mutex_lock(&g_ioctl_lock);

    if (!g_bridge_initialized) {
        pthread_mutex_unlock(&g_ioctl_lock);
        return;
    }

    fprintf(stderr, IOCTL_LOG_PREFIX
            "Shutting down IOCTL bridge (%lu total dispatches)\n",
            g_total_dispatches);

    for (int i = 0; i < g_num_drivers; i++) {
        if (g_drivers[i].active) {
            fprintf(stderr, IOCTL_LOG_PREFIX
                    "  Deregistering '%s' (type 0x%04x, %lu/%lu calls)\n",
                    g_drivers[i].name, g_drivers[i].device_type,
                    g_drivers[i].calls_handled, g_drivers[i].calls_failed);
            g_drivers[i].active = 0;
        }
    }

    g_num_drivers = 0;
    g_bridge_initialized = 0;

    pthread_mutex_unlock(&g_ioctl_lock);

    fprintf(stderr, IOCTL_LOG_PREFIX "IOCTL bridge shut down\n");
}

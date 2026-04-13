/*
 * windrv_manager.h - Windows driver IRP dispatch manager
 *
 * Manages loaded Windows drivers and provides IPC for
 * userspace applications to communicate with them.
 */

#ifndef WINDRV_MANAGER_H
#define WINDRV_MANAGER_H

#include "win32/wdm.h"
#include "pe/pe_header.h"

/* IPC command types */
#define WINDRV_CMD_OPEN     1
#define WINDRV_CMD_CLOSE    2
#define WINDRV_CMD_READ     3
#define WINDRV_CMD_WRITE    4
#define WINDRV_CMD_IOCTL    5
#define WINDRV_CMD_UNLOAD   6

/* IPC request (sent by client) */
typedef struct {
    uint32_t cmd;
    uint32_t ioctl_code;
    uint32_t input_size;
    uint32_t output_size;
    /* Followed by input_size bytes of input data */
} windrv_request_t;

/* IPC response (sent by driver host) */
typedef struct {
    int32_t  status;        /* NTSTATUS */
    uint32_t output_size;   /* Actual output bytes */
    /* Followed by output_size bytes of output data */
} windrv_response_t;

/*
 * Initialize and run the driver entry point, then enter the IRP
 * dispatch loop. Returns the driver's exit status.
 */
int windrv_run_driver(pe_image_t *image, void *entry, const char *driver_name);

#endif /* WINDRV_MANAGER_H */

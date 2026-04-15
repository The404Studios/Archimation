/*
 * windrv_manager.c - Windows driver IRP dispatch manager
 *
 * Creates a DRIVER_OBJECT, calls DriverEntry, then enters a loop
 * accepting IRP requests over a Unix domain socket.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include "windrv_manager.h"
#include "compat/abi_bridge.h"

extern size_t wcslen16(const uint16_t *s);

#define LOG_PREFIX "[windrv] "

/* Maximum buffer size from IPC requests (prevent OOM from malicious client) */
#define WINDRV_MAX_BUFFER (4 * 1024 * 1024)  /* 4 MiB */

/* Default dispatch for unhandled IRP major functions */
static NTSTATUS __attribute__((ms_abi)) default_dispatch(
    PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    (void)DeviceObject;
    Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
    Irp->IoStatus.Information = 0;
    Irp->PendingReturned = TRUE;
    return STATUS_NOT_IMPLEMENTED;
}

/* Build an IRP for a given request */
static PIRP build_irp(UCHAR major_function,
                       void *input_buf, uint32_t input_len,
                       void *output_buf, uint32_t output_len,
                       uint32_t ioctl_code,
                       PDEVICE_OBJECT device)
{
    PIRP irp = (PIRP)calloc(1, sizeof(IRP));
    if (!irp)
        return NULL;

    irp->Type = IO_TYPE_IRP;
    irp->Size = sizeof(IRP);
    irp->StackCount = 1;
    irp->CurrentLocation = 0;

    /* Set up the system buffer for METHOD_BUFFERED.
     * Use calloc so the output region (beyond input_len) is zeroed —
     * drivers that read uninitialized bytes would otherwise leak heap memory. */
    if (input_len > 0 && input_buf) {
        uint32_t sys_len = input_len > output_len ? input_len : output_len;
        irp->AssociatedIrp_SystemBuffer = calloc(1, sys_len);
        if (irp->AssociatedIrp_SystemBuffer)
            memcpy(irp->AssociatedIrp_SystemBuffer, input_buf, input_len);
    } else if (output_len > 0) {
        irp->AssociatedIrp_SystemBuffer = calloc(1, output_len);
    }

    irp->UserBuffer = output_buf;

    /* Set up the IO_STACK_LOCATION */
    PIO_STACK_LOCATION stack = &irp->Stack[0];
    stack->MajorFunction = major_function;
    stack->DeviceObject = device;

    switch (major_function) {
    case IRP_MJ_DEVICE_CONTROL:
        stack->Parameters.DeviceIoControl.IoControlCode = ioctl_code;
        stack->Parameters.DeviceIoControl.InputBufferLength = input_len;
        stack->Parameters.DeviceIoControl.OutputBufferLength = output_len;
        break;
    case IRP_MJ_READ:
        stack->Parameters.Read.Length = output_len;
        break;
    case IRP_MJ_WRITE:
        stack->Parameters.Write.Length = input_len;
        break;
    default:
        break;
    }

    return irp;
}

/* Dispatch an IRP to the driver */
static NTSTATUS dispatch_irp(PDRIVER_OBJECT driver, PDEVICE_OBJECT device,
                              PIRP irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    UCHAR major = stack->MajorFunction;

    if (major > IRP_MJ_MAXIMUM_FUNCTION)
        return STATUS_INVALID_PARAMETER;

    PDRIVER_DISPATCH dispatch = driver->MajorFunction[major];
    if (!dispatch)
        return STATUS_NOT_IMPLEMENTED;

    /* Call the driver's dispatch function via ABI bridge */
    return (NTSTATUS)abi_call_win64_2((void *)dispatch,
        (uint64_t)(uintptr_t)device,
        (uint64_t)(uintptr_t)irp);
}

/* Handle one client connection */
static void handle_client(int client_fd, PDRIVER_OBJECT driver,
                           PDEVICE_OBJECT device)
{
    windrv_request_t req;
    ssize_t n;

    while ((n = recv(client_fd, &req, sizeof(req), MSG_WAITALL)) == sizeof(req)) {
        uint8_t *input_data = NULL;
        uint8_t *output_data = NULL;
        windrv_response_t resp;
        memset(&resp, 0, sizeof(resp));

        /* Enforce buffer size limits (C1 audit fix) */
        if (req.input_size > WINDRV_MAX_BUFFER ||
            req.output_size > WINDRV_MAX_BUFFER) {
            resp.status = STATUS_INVALID_PARAMETER;
            send(client_fd, &resp, sizeof(resp), MSG_NOSIGNAL);
            continue;
        }

        /* Read input data if present */
        if (req.input_size > 0) {
            input_data = (uint8_t *)malloc(req.input_size);
            if (!input_data) {
                resp.status = STATUS_INSUFFICIENT_RESOURCES;
                send(client_fd, &resp, sizeof(resp), MSG_NOSIGNAL);
                continue;
            }
            if (recv(client_fd, input_data, req.input_size, MSG_WAITALL)
                != (ssize_t)req.input_size) {
                free(input_data);
                break;
            }
        }

        /* Allocate output buffer */
        if (req.output_size > 0)
            output_data = (uint8_t *)calloc(1, req.output_size);

        /* Map command to IRP major function */
        UCHAR major;
        switch (req.cmd) {
        case WINDRV_CMD_OPEN:   major = IRP_MJ_CREATE; break;
        case WINDRV_CMD_CLOSE:  major = IRP_MJ_CLOSE; break;
        case WINDRV_CMD_READ:   major = IRP_MJ_READ; break;
        case WINDRV_CMD_WRITE:  major = IRP_MJ_WRITE; break;
        case WINDRV_CMD_IOCTL:  major = IRP_MJ_DEVICE_CONTROL; break;
        case WINDRV_CMD_UNLOAD:
            printf(LOG_PREFIX "Unload requested\n");
            if (driver->DriverUnload) {
                abi_call_win64_1((void *)driver->DriverUnload,
                    (uint64_t)(uintptr_t)driver);
            }
            resp.status = STATUS_SUCCESS;
            send(client_fd, &resp, sizeof(resp), MSG_NOSIGNAL);
            free(input_data);
            free(output_data);
            close(client_fd);
            return;
        default:
            resp.status = STATUS_INVALID_PARAMETER;
            send(client_fd, &resp, sizeof(resp), MSG_NOSIGNAL);
            free(input_data);
            free(output_data);
            continue;
        }

        /* Build and dispatch the IRP */
        PIRP irp = build_irp(major, input_data, req.input_size,
                              output_data, req.output_size,
                              req.ioctl_code, device);

        if (!irp) {
            resp.status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            resp.status = dispatch_irp(driver, device, irp);

            /* Copy output from system buffer */
            if (output_data && irp->AssociatedIrp_SystemBuffer &&
                req.output_size > 0) {
                uint32_t copy_size = (uint32_t)irp->IoStatus.Information;
                if (copy_size > req.output_size)
                    copy_size = req.output_size;
                memcpy(output_data, irp->AssociatedIrp_SystemBuffer, copy_size);
                resp.output_size = copy_size;
            }

            free(irp->AssociatedIrp_SystemBuffer);
            free(irp);
        }

        /* Send response header */
        send(client_fd, &resp, sizeof(resp), MSG_NOSIGNAL);

        /* Send output data */
        if (resp.output_size > 0 && output_data)
            send(client_fd, output_data, resp.output_size, MSG_NOSIGNAL);

        free(input_data);
        free(output_data);
    }

    close(client_fd);
}

/* Main dispatch loop: accept connections and process requests */
static int windrv_serve(PDRIVER_OBJECT driver, const char *name)
{
    /* Find the first device created by the driver */
    PDEVICE_OBJECT device = driver->DeviceObject;
    if (!device) {
        printf(LOG_PREFIX "Driver created no devices, entering idle\n");
        /* Just wait for signal */
        pause();
        return 0;
    }

    /* Create Unix domain socket */
    char sock_path[256];
    snprintf(sock_path, sizeof(sock_path), "/tmp/windrv_%s.sock", name);
    unlink(sock_path);

    int server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server_fd < 0) {
        fprintf(stderr, LOG_PREFIX "Failed to create socket: %s\n",
                strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, LOG_PREFIX "Failed to bind %s: %s\n",
                sock_path, strerror(errno));
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, 5) < 0) {
        fprintf(stderr, LOG_PREFIX "Failed to listen: %s\n", strerror(errno));
        close(server_fd);
        return -1;
    }

    printf(LOG_PREFIX "Driver '%s' serving on %s\n", name, sock_path);
    printf(LOG_PREFIX "Device: %p (type=0x%x)\n",
           (void *)device, device->DeviceType);

    /* Accept loop */
    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        handle_client(client_fd, driver, device);
    }

    close(server_fd);
    unlink(sock_path);
    return 0;
}

/* ===== Public API ===== */

int windrv_run_driver(pe_image_t *image, void *entry, const char *driver_name)
{
    /* Heap-allocate DRIVER_OBJECT and DRIVER_EXTENSION (C2 audit fix:
     * stack allocation would dangle if driver spawns threads) */
    PDRIVER_OBJECT drv_obj = (PDRIVER_OBJECT)calloc(1, sizeof(DRIVER_OBJECT));
    PDRIVER_EXTENSION drv_ext = (PDRIVER_EXTENSION)calloc(1, sizeof(DRIVER_EXTENSION));
    uint16_t *drv_name_buf = (uint16_t *)calloc(256, sizeof(uint16_t));
    uint16_t *reg_path_buf = (uint16_t *)calloc(512, sizeof(uint16_t));

    if (!drv_obj || !drv_ext || !drv_name_buf || !reg_path_buf) {
        fprintf(stderr, LOG_PREFIX "Failed to allocate DRIVER_OBJECT\n");
        free(drv_obj); free(drv_ext); free(drv_name_buf); free(reg_path_buf);
        return -1;
    }

    drv_obj->Type = IO_TYPE_DRIVER;
    drv_obj->Size = sizeof(DRIVER_OBJECT);
    drv_obj->DriverStart = image->mapped_base;
    drv_obj->DriverSize = image->size_of_image;
    drv_obj->DriverInit = entry;
    drv_obj->DriverExtension = drv_ext;
    drv_ext->DriverObject = drv_obj;

    /* Set up driver name: \Driver\<name> (build UTF-16LE manually) */
    {
        char narrow[256];
        snprintf(narrow, sizeof(narrow), "\\Driver\\%s", driver_name);
        size_t i;
        for (i = 0; narrow[i] && i < 255; i++)
            drv_name_buf[i] = (uint16_t)(unsigned char)narrow[i];
        drv_name_buf[i] = 0;
    }
    drv_obj->DriverName.Length = (USHORT)(wcslen16(drv_name_buf) * sizeof(WCHAR));
    drv_obj->DriverName.MaximumLength = drv_obj->DriverName.Length + sizeof(WCHAR);
    drv_obj->DriverName.Buffer = drv_name_buf;

    /* Set up registry path: \Registry\Machine\System\...\Services\<name> */
    {
        char narrow[512];
        snprintf(narrow, sizeof(narrow),
                 "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s",
                 driver_name);
        size_t i;
        for (i = 0; narrow[i] && i < 511; i++)
            reg_path_buf[i] = (uint16_t)(unsigned char)narrow[i];
        reg_path_buf[i] = 0;
    }
    UNICODE_STRING *reg_path = (UNICODE_STRING *)calloc(1, sizeof(UNICODE_STRING));
    if (!reg_path) {
        free(drv_obj); free(drv_ext); free(drv_name_buf); free(reg_path_buf);
        return -1;
    }
    reg_path->Length = (USHORT)(wcslen16(reg_path_buf) * sizeof(WCHAR));
    reg_path->MaximumLength = reg_path->Length + sizeof(WCHAR);
    reg_path->Buffer = reg_path_buf;

    /* Initialize all MajorFunction entries to default dispatcher */
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        drv_obj->MajorFunction[i] = default_dispatch;

    printf(LOG_PREFIX "Calling DriverEntry for '%s'...\n", driver_name);
    printf(LOG_PREFIX "  DriverObject: %p\n", (void *)drv_obj);
    /* Print registry path as narrow string */
    {
        char rp_narrow[512];
        size_t ri;
        for (ri = 0; reg_path_buf[ri] && ri < 511; ri++)
            rp_narrow[ri] = (char)(reg_path_buf[ri] & 0xFF);
        rp_narrow[ri] = '\0';
        printf(LOG_PREFIX "  RegistryPath: '%s'\n", rp_narrow);
    }

    /* Call DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING) */
    NTSTATUS status = (NTSTATUS)abi_call_win64_2(entry,
        (uint64_t)(uintptr_t)drv_obj,
        (uint64_t)(uintptr_t)reg_path);

    if (!NT_SUCCESS(status)) {
        fprintf(stderr, LOG_PREFIX "DriverEntry FAILED: NTSTATUS 0x%08X\n",
                (unsigned)status);
        free(drv_obj); free(drv_ext); free(drv_name_buf);
        free(reg_path_buf); free(reg_path);
        return (int)status;
    }

    printf(LOG_PREFIX "DriverEntry returned STATUS_SUCCESS\n");

    /* Report loaded devices */
    PDEVICE_OBJECT dev = drv_obj->DeviceObject;
    int dev_count = 0;
    while (dev) {
        dev_count++;
        printf(LOG_PREFIX "  Device %d: %p type=0x%x ext=%p\n",
               dev_count, (void *)dev, dev->DeviceType, dev->DeviceExtension);
        dev = dev->NextDevice;
    }
    printf(LOG_PREFIX "%d device(s) created\n", dev_count);

    if (drv_obj->DriverUnload)
        printf(LOG_PREFIX "DriverUnload: %p\n", (void *)drv_obj->DriverUnload);

    /* RegistryPath is transient -- drivers that need it must copy. Free now
     * before the (potentially long-running) dispatch loop to avoid a leak
     * over the driver's lifetime. */
    free(reg_path_buf);
    free(reg_path);

    /* Enter IRP dispatch loop (drv_obj stays heap-allocated for driver lifetime) */
    return windrv_serve(drv_obj, driver_name);
}

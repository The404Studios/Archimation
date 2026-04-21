// SPDX-License-Identifier: GPL-2.0
/*
 * wdm_host_irp_driverapi.c - Windows-driver-facing IRP framework
 *
 * Implements IoAllocateIrp / IoFreeIrp / IoGet*StackLocation / IoCallDriver /
 * IofCompleteRequest on the Windows-shaped structures exposed to hosted
 * .sys drivers. This sits above the wdm_host_irp.c ioctl bridge: a
 * DEVICE_CONTROL coming from /dev/wdm_host ioctl is translated by the
 * thunk into a wdm_irp_hdr, which is then walked through this file's
 * dispatch helpers into the driver's MajorFunction[] slot.
 *
 * Compiles both inside the kernel (with linux/slab.h etc. via a thin
 * shim) and standalone userspace (for preflight) because all allocations
 * go through host_alloc/host_free.
 *
 * Session 74 Tier-3 driver foundation.
 */

#include "wdm_host_irp_driverapi.h"

#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Host allocator shim
 *
 * In-kernel: redefine to kzalloc/kfree. Userland preflight: use calloc/free.
 * The kernel-module build can override these by compiling with
 * -DWDM_HOST_KERNEL=1.
 * ============================================================================ */

#ifdef WDM_HOST_KERNEL
#  include <linux/slab.h>
#  define HOST_ALLOC(sz)   kzalloc((sz), GFP_KERNEL)
#  define HOST_FREE(p)     kfree(p)
#  define HOST_LOG(fmt, ...) pr_debug("wdm_host_irp: " fmt, ##__VA_ARGS__)
#  define HOST_WARN(fmt, ...) pr_warn("wdm_host_irp: " fmt, ##__VA_ARGS__)
#else
#  include <stdio.h>
#  define HOST_ALLOC(sz)   calloc(1, (sz))
#  define HOST_FREE(p)     free(p)
#  define HOST_LOG(fmt, ...) /* silenced in preflight */
#  define HOST_WARN(fmt, ...) fprintf(stderr, "wdm_host_irp: " fmt, ##__VA_ARGS__)
#endif

#define IRP_TYPE       6
#define DRIVER_TYPE    4

/* ============================================================================
 * Default dispatch stub
 *
 * Any major function slot left NULL by DriverEntry is routed here. The
 * returned IRP is completed STATUS_NOT_IMPLEMENTED; the driver thread
 * sees a sane completion rather than a kernel oops on a NULL jump.
 * ============================================================================ */

static int32_t wdm_default_dispatch(void *device, void *irp_in)
{
	struct wdm_irp_hdr *irp = (struct wdm_irp_hdr *)irp_in;

	(void)device;
	if (!irp)
		return WDMAPI_STATUS_INVALID_PARAMETER;

	irp->IoStatus.Status = WDMAPI_STATUS_NOT_IMPLEMENTED;
	irp->IoStatus.Information = 0;
	WdmIofCompleteRequest(irp, 0);
	return WDMAPI_STATUS_NOT_IMPLEMENTED;
}

void WdmIoInstallDefaultDispatch(struct wdm_driver_object *drv)
{
	unsigned i;

	if (!drv)
		return;

	for (i = 0; i < WDM_IRP_MJ_TABLE_LEN; i++)
		drv->MajorFunction[i] = wdm_default_dispatch;

	drv->Type = DRIVER_TYPE;
	drv->Size = (uint16_t)sizeof(*drv);
}

/* ============================================================================
 * IRP allocation
 * ============================================================================ */

struct wdm_irp_hdr *WdmIoAllocateIrp(uint8_t stack_size, int charge_quota)
{
	struct wdm_irp_hdr *irp;

	(void)charge_quota;

	if (stack_size == 0 || stack_size > WDM_IO_STACK_MAX) {
		HOST_WARN("WdmIoAllocateIrp: invalid stack_size=%u (max=%u)\n",
			  (unsigned)stack_size, (unsigned)WDM_IO_STACK_MAX);
		return NULL;
	}

	irp = (struct wdm_irp_hdr *)HOST_ALLOC(sizeof(*irp));
	if (!irp)
		return NULL;

	irp->Type = IRP_TYPE;
	irp->Size = (uint16_t)sizeof(*irp);
	irp->StackCount = stack_size;
	irp->CurrentStackIndex = stack_size;  /* one past the top */
	irp->IoStatus.Status = WDMAPI_STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	return irp;
}

void WdmIoFreeIrp(struct wdm_irp_hdr *irp)
{
	if (!irp)
		return;
	/* Zero type field so use-after-free in buggy drivers is detectable. */
	irp->Type = 0xDEAD;
	HOST_FREE(irp);
}

/* ============================================================================
 * Stack-location navigation
 * ============================================================================ */

struct wdm_io_stack_location *WdmIoGetCurrentIrpStackLocation(struct wdm_irp_hdr *irp)
{
	if (!irp || irp->CurrentStackIndex >= irp->StackCount)
		return NULL;
	return &irp->Stack[irp->CurrentStackIndex];
}

struct wdm_io_stack_location *WdmIoGetNextIrpStackLocation(struct wdm_irp_hdr *irp)
{
	if (!irp || irp->CurrentStackIndex == 0)
		return NULL;
	return &irp->Stack[irp->CurrentStackIndex - 1];
}

/* ============================================================================
 * Dispatch + completion
 * ============================================================================ */

int32_t WdmIoDispatchToDriver(struct wdm_driver_object *drv,
			      void *device,
			      struct wdm_irp_hdr *irp)
{
	struct wdm_io_stack_location *sl;
	uint8_t major;
	int32_t (*fn)(void *, void *);

	if (!drv || !irp)
		return WDMAPI_STATUS_INVALID_PARAMETER;

	sl = WdmIoGetCurrentIrpStackLocation(irp);
	if (!sl) {
		/* No stack location set yet; pop one. */
		if (irp->CurrentStackIndex > 0)
			irp->CurrentStackIndex--;
		sl = WdmIoGetCurrentIrpStackLocation(irp);
	}
	if (!sl) {
		irp->IoStatus.Status = WDMAPI_STATUS_INVALID_PARAMETER;
		return WDMAPI_STATUS_INVALID_PARAMETER;
	}

	major = sl->MajorFunction;
	if (major >= WDM_IRP_MJ_TABLE_LEN) {
		irp->IoStatus.Status = WDMAPI_STATUS_INVALID_PARAMETER;
		return WDMAPI_STATUS_INVALID_PARAMETER;
	}

	fn = drv->MajorFunction[major];
	if (!fn)
		fn = wdm_default_dispatch;

	return fn(device, irp);
}

int32_t WdmIoCallDriver(void *target_device, struct wdm_irp_hdr *irp)
{
	/* Pop one level of the stack; caller is expected to have set up the
	 * *next* stack location via WdmIoGetNextIrpStackLocation. */
	if (!irp)
		return WDMAPI_STATUS_INVALID_PARAMETER;

	if (irp->CurrentStackIndex > 0)
		irp->CurrentStackIndex--;

	(void)target_device;  /* upper driver wiring is a future patch */
	return WDMAPI_STATUS_PENDING;
}

void WdmIofCompleteRequest(struct wdm_irp_hdr *irp, int8_t priority_boost)
{
	struct wdm_io_stack_location *sl;
	int32_t rc;

	(void)priority_boost;

	if (!irp)
		return;

	/* Run completion routines from inner-most up. */
	while (irp->CurrentStackIndex < irp->StackCount) {
		sl = &irp->Stack[irp->CurrentStackIndex];
		if (sl->CompletionRoutine) {
			rc = sl->CompletionRoutine(sl->DeviceObject,
						   irp,
						   sl->CompletionContext);
			/* STATUS_MORE_PROCESSING_REQUIRED (0xC0000016)
			 * halts the walk - the upper driver has taken
			 * ownership of completion. */
			if (rc == (int32_t)0xC0000016)
				return;
		}
		irp->CurrentStackIndex++;
	}
}

#ifndef WDM_HOST_KERNEL
/* Userland preflight self-test: exercises allocation, dispatch, completion. */
int wdm_irp_driverapi_selftest(void)
{
	struct wdm_driver_object drv;
	struct wdm_irp_hdr *irp;
	struct wdm_io_stack_location *sl;
	int32_t rc;

	memset(&drv, 0, sizeof(drv));
	WdmIoInstallDefaultDispatch(&drv);

	irp = WdmIoAllocateIrp(4, 0);
	if (!irp)
		return -1;

	sl = WdmIoGetNextIrpStackLocation(irp);
	if (!sl) {
		WdmIoFreeIrp(irp);
		return -2;
	}
	sl->MajorFunction = IRP_MJ_DEVICE_CONTROL;
	sl->Parameters.DeviceIoControl.IoControlCode = 0x1234;
	irp->CurrentStackIndex--;

	rc = WdmIoDispatchToDriver(&drv, NULL, irp);
	if (rc != WDMAPI_STATUS_NOT_IMPLEMENTED) {
		WdmIoFreeIrp(irp);
		return -3;
	}

	/* Completion routine (if any) ran in WdmIofCompleteRequest inside
	 * the default dispatch; IRP storage is ours to release. */
	WdmIoFreeIrp(irp);
	return 0;
}
#endif

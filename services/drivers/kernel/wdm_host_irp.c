// SPDX-License-Identifier: GPL-2.0
/*
 * wdm_host_irp.c - IRP (I/O Request Packet) dispatch emulation
 *
 * Emulates the Windows I/O Request Packet mechanism within the Linux kernel.
 * Provides IRP allocation, dispatch to driver dispatch tables, and convenience
 * functions for common IRP types (CREATE, CLOSE, DEVICE_CONTROL).
 *
 * Dispatch calls are bridged through the ABI thunk (wdm_host_thunk.c) which
 * converts the Linux System V AMD64 calling convention to Windows x64,
 * builds minimal Windows-compatible structures, and invokes the driver's
 * dispatch function.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

#include "wdm_host_internal.h"

/* ============================================================================
 * WDM Status Constants (Windows NTSTATUS values as int32_t)
 * ============================================================================ */

#define WDM_STATUS_SUCCESS          ((int32_t)0x00000000)
#define WDM_STATUS_NOT_SUPPORTED    ((int32_t)0xC00000BB)  /* -0x3FFFFF45 */
#define WDM_STATUS_PENDING          ((int32_t)0x00000103)

/* IRP Major Function Codes */
#define WDM_IRP_MJ_CREATE                  0x00
#define WDM_IRP_MJ_CLOSE                   0x02
#define WDM_IRP_MJ_READ                    0x03
#define WDM_IRP_MJ_WRITE                   0x04
#define WDM_IRP_MJ_DEVICE_CONTROL          0x0E
#define WDM_IRP_MJ_INTERNAL_DEVICE_CONTROL 0x0F
#define WDM_IRP_MJ_PNP                     0x1B

/*
 * Maximum valid IRP major function index.
 * WDM_IRP_MJ_COUNT is defined in wdm_host_internal.h as the array size
 * (IRP_MJ_MAXIMUM_FUNCTION + 1 = 28); valid indices are 0..27.
 */
#define WDM_IRP_MJ_MAX (WDM_IRP_MJ_COUNT - 1)

/* ============================================================================
 * IRP Allocation and Lifetime
 * ============================================================================ */

/**
 * wdm_create_irp() - Allocate and initialize a new IRP
 * @major: IRP major function code
 * @minor: IRP minor function code
 *
 * Allocates a wdm_irp structure with kzalloc and initializes it with
 * the given major/minor function codes. All other fields are zeroed.
 *
 * Returns pointer to new wdm_irp, or NULL on allocation failure.
 */
struct wdm_irp *wdm_create_irp(uint8_t major, uint8_t minor)
{
	struct wdm_irp *irp;

	irp = kzalloc(sizeof(*irp), GFP_KERNEL);
	if (!irp) {
		pr_err("[wdm_host] Failed to allocate IRP (major=%u, minor=%u)\n",
		       major, minor);
		return NULL;
	}

	irp->major_function = major;
	irp->minor_function = minor;
	irp->status = WDM_STATUS_SUCCESS;
	irp->information = 0;
	irp->system_buffer = NULL;
	irp->user_buffer = NULL;
	irp->buffer_length = 0;
	irp->output_length = 0;
	irp->ioctl_code = 0;

	pr_debug("[wdm_host] Created IRP %p (major=%u, minor=%u)\n",
		 irp, major, minor);
	return irp;
}
EXPORT_SYMBOL_GPL(wdm_create_irp);

/**
 * wdm_free_irp() - Free an IRP
 * @irp: IRP to free (may be NULL)
 *
 * Frees the wdm_irp structure. Does NOT free the system_buffer or
 * user_buffer - the caller is responsible for those.
 */
void wdm_free_irp(struct wdm_irp *irp)
{
	if (!irp)
		return;

	pr_debug("[wdm_host] Freeing IRP %p (major=%u)\n",
		 irp, irp->major_function);
	kfree(irp);
}
EXPORT_SYMBOL_GPL(wdm_free_irp);

/* ============================================================================
 * IRP Dispatch
 * ============================================================================ */

/**
 * wdm_dispatch_irp() - Dispatch an IRP to a device's driver
 * @dev: Target WDM device
 * @irp: IRP to dispatch
 *
 * Validates the device and IRP, looks up the dispatch function in the
 * driver's dispatch table for the given major function code, and invokes it.
 *
 * Dispatch is performed through the ABI thunk (wdm_host_thunk.c) which
 * handles calling convention differences between Linux and Windows.
 *
 * Returns 0 on success, negative errno on failure.
 */
int wdm_dispatch_irp(struct wdm_device *dev, struct wdm_irp *irp)
{
	/* Step 1: Validate parameters */
	if (!dev) {
		pr_err("[wdm_host] wdm_dispatch_irp: NULL device\n");
		return -EINVAL;
	}

	if (!irp) {
		pr_err("[wdm_host] wdm_dispatch_irp: NULL IRP\n");
		return -EINVAL;
	}

	if (!dev->driver) {
		pr_err("[wdm_host] wdm_dispatch_irp: device '%s' has no "
		       "driver\n", dev->device_name);
		irp->status = WDM_STATUS_NOT_SUPPORTED;
		return -ENODEV;
	}

	/* Step 2: Bounds check major function code */
	if (irp->major_function > WDM_IRP_MJ_MAX) {
		pr_err("[wdm_host] wdm_dispatch_irp: major function %u out "
		       "of bounds (max %u)\n",
		       irp->major_function, WDM_IRP_MJ_MAX);
		irp->status = WDM_STATUS_NOT_SUPPORTED;
		return -EINVAL;
	}

	/* Step 3: Log the dispatch */
	pr_debug("[wdm_host] Dispatching IRP major=%d to device '%s'\n",
		 irp->major_function, dev->device_name);

	/*
	 * Step 6: Dispatch through the ABI thunk
	 *
	 * The thunk bridges the Linux System V AMD64 ABI to the Windows x64
	 * calling convention. It builds minimal Windows-compatible
	 * DEVICE_OBJECT and IRP structures, then calls the driver's dispatch
	 * function with arguments in RCX/RDX (Windows convention) instead
	 * of RDI/RSI (Linux convention).
	 */
	{
		int thunk_ret = wdm_thunk_dispatch(dev, irp);
		if (thunk_ret < 0) {
			pr_warn("[wdm_host] IRP major=%u on device '%s': "
				"thunk dispatch failed (%d)\n",
				irp->major_function, dev->device_name, thunk_ret);
			return thunk_ret;
		}
	}

	pr_debug("[wdm_host] IRP major=%u on device '%s' completed "
		 "(status=0x%08X, info=%zu)\n",
		 irp->major_function, dev->device_name, irp->status,
		 irp->information);

	return 0;
}
EXPORT_SYMBOL_GPL(wdm_dispatch_irp);

/* ============================================================================
 * Convenience IRP Handlers
 * ============================================================================ */

/**
 * wdm_handle_create_irp() - Handle IRP_MJ_CREATE (device open)
 * @dev: Target WDM device
 *
 * Creates and dispatches an IRP_MJ_CREATE request, which corresponds
 * to a process opening a handle to the device (CreateFile on Windows).
 *
 * Returns 0 on success, negative errno on failure.
 */
int wdm_handle_create_irp(struct wdm_device *dev)
{
	struct wdm_irp *irp;
	int ret;

	if (!dev) {
		pr_err("[wdm_host] wdm_handle_create_irp: NULL device\n");
		return -EINVAL;
	}

	pr_debug("[wdm_host] Handling IRP_MJ_CREATE for device '%s'\n",
		 dev->device_name);

	irp = wdm_create_irp(WDM_IRP_MJ_CREATE, 0);
	if (!irp)
		return -ENOMEM;

	ret = wdm_dispatch_irp(dev, irp);

	if (ret == 0)
		pr_debug("[wdm_host] IRP_MJ_CREATE completed for '%s' "
			 "(status=0x%08X)\n", dev->device_name, irp->status);

	wdm_free_irp(irp);
	return ret;
}
EXPORT_SYMBOL_GPL(wdm_handle_create_irp);

/**
 * wdm_handle_close_irp() - Handle IRP_MJ_CLOSE (device close)
 * @dev: Target WDM device
 *
 * Creates and dispatches an IRP_MJ_CLOSE request, which corresponds
 * to a process closing its handle to the device (CloseHandle on Windows).
 *
 * Returns 0 on success, negative errno on failure.
 */
int wdm_handle_close_irp(struct wdm_device *dev)
{
	struct wdm_irp *irp;
	int ret;

	if (!dev) {
		pr_err("[wdm_host] wdm_handle_close_irp: NULL device\n");
		return -EINVAL;
	}

	pr_debug("[wdm_host] Handling IRP_MJ_CLOSE for device '%s'\n",
		 dev->device_name);

	irp = wdm_create_irp(WDM_IRP_MJ_CLOSE, 0);
	if (!irp)
		return -ENOMEM;

	ret = wdm_dispatch_irp(dev, irp);

	if (ret == 0)
		pr_debug("[wdm_host] IRP_MJ_CLOSE completed for '%s' "
			 "(status=0x%08X)\n", dev->device_name, irp->status);

	wdm_free_irp(irp);
	return ret;
}
EXPORT_SYMBOL_GPL(wdm_handle_close_irp);

/**
 * wdm_handle_ioctl_irp() - Handle IRP_MJ_DEVICE_CONTROL (IOCTL)
 * @dev:     Target WDM device
 * @code:    IOCTL control code
 * @in_buf:  Input buffer (user data to driver), may be NULL
 * @in_len:  Size of input buffer in bytes
 * @out_buf: Output buffer (driver data to user), may be NULL
 * @out_len: Size of output buffer in bytes
 *
 * Emulates a buffered I/O device control request. Allocates a system
 * buffer (METHOD_BUFFERED style), copies input data, dispatches the
 * IRP, and copies output data back if the driver produced any.
 *
 * Returns the NTSTATUS from the IRP (as int32_t), or a negative
 * Linux errno on infrastructure failure.
 */
int32_t wdm_handle_ioctl_irp(struct wdm_device *dev, uint32_t code,
			      void *in_buf, size_t in_len,
			      void *out_buf, size_t out_len)
{
	struct wdm_irp *irp = NULL;
	void *system_buffer = NULL;
	size_t alloc_size;
	int dispatch_ret;
	int32_t result;

	if (!dev) {
		pr_err("[wdm_host] wdm_handle_ioctl_irp: NULL device\n");
		return -EINVAL;
	}

	pr_debug("[wdm_host] Handling IRP_MJ_DEVICE_CONTROL for device '%s' "
		 "(code=0x%08X, in=%zu, out=%zu)\n",
		 dev->device_name, code, in_len, out_len);

	/* Step 1: Allocate system buffer (METHOD_BUFFERED semantics) */
	alloc_size = (in_len > out_len) ? in_len : out_len;
	if (alloc_size > 0) {
		system_buffer = kzalloc(alloc_size, GFP_KERNEL);
		if (!system_buffer) {
			pr_err("[wdm_host] Failed to allocate system buffer "
			       "(%zu bytes)\n", alloc_size);
			return -ENOMEM;
		}

		/* Step 2: Copy input data to system buffer */
		if (in_buf && in_len > 0)
			memcpy(system_buffer, in_buf, in_len);
	}

	/* Step 3: Create the IRP */
	irp = wdm_create_irp(WDM_IRP_MJ_DEVICE_CONTROL, 0);
	if (!irp) {
		kfree(system_buffer);
		return -ENOMEM;
	}

	/* Step 4: Set up IRP fields for IOCTL */
	irp->ioctl_code = code;
	irp->system_buffer = system_buffer;
	irp->buffer_length = (uint32_t)in_len;
	irp->output_length = (uint32_t)out_len;

	/* Step 5: Dispatch the IRP */
	dispatch_ret = wdm_dispatch_irp(dev, irp);
	result = irp->status;

	/* Step 6: Copy output data if the driver produced any */
	if (dispatch_ret == 0 && out_buf && irp->information > 0) {
		size_t copy_len = irp->information;

		if (copy_len > out_len)
			copy_len = out_len;
		if (copy_len > alloc_size)
			copy_len = alloc_size;
		if (system_buffer && copy_len > 0)
			memcpy(out_buf, system_buffer, copy_len);

		pr_debug("[wdm_host] IOCTL copied %zu bytes to output buffer\n",
			 copy_len);
	}

	pr_debug("[wdm_host] IRP_MJ_DEVICE_CONTROL for '%s' completed "
		 "(status=0x%08X)\n", dev->device_name, result);

	/* Step 7: Clean up */
	kfree(system_buffer);
	wdm_free_irp(irp);

	return result;
}
EXPORT_SYMBOL_GPL(wdm_handle_ioctl_irp);

/* ============================================================================
 * Module Init / Exit
 * ============================================================================ */

/**
 * wdm_irp_init() - Initialize IRP tracking subsystem
 *
 * Returns 0 on success.
 */
int wdm_irp_init(void)
{
	pr_info("[wdm_host] IRP dispatch subsystem initialized\n");
	return 0;
}

/**
 * wdm_irp_exit() - Clean up IRP tracking subsystem
 */
void wdm_irp_exit(void)
{
	pr_info("[wdm_host] IRP dispatch subsystem exited\n");
}

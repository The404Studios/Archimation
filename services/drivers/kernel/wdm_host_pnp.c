/*
 * wdm_host_pnp.c - Plug and Play manager emulation
 *
 * Provides a minimal PnP manager for hosted Windows .sys drivers.  When a
 * driver registers a dispatch routine for IRP_MJ_PNP (0x1B) the PnP manager
 * can synthesise start-device and remove-device IRPs to drive the driver
 * through the standard WDM lifecycle.
 *
 * Currently the "enumeration" step is a stub -- real hardware enumeration
 * would be needed when binding a hosted driver to a physical PCI/USB device.
 *
 * Copyright (c) 2026  WDM Host Project
 * SPDX-License-Identifier: GPL-2.0
 */

#include "wdm_host_internal.h"

/* ============================================================================
 * IRP major / minor function codes used by the PnP subsystem
 * ============================================================================ */

#define WDM_IRP_MJ_PNP             0x1B

#define WDM_IRP_MN_START_DEVICE    0x00
#define WDM_IRP_MN_REMOVE_DEVICE   0x02

/* Device state flag set when PnP has successfully started the device */
#define WDM_DEVICE_FLAG_STARTED    0x80000000

/* ============================================================================
 * Internal helpers
 * ============================================================================ */

/*
 * pnp_dispatch_irp - Build and dispatch a PnP IRP to a driver.
 *
 * Constructs a wdm_irp with IRP_MJ_PNP and the given minor function, then
 * calls wdm_dispatch_irp().  Returns the dispatch result (0 on success).
 */
static int pnp_dispatch_irp(struct wdm_device *dev, uint8_t minor_func)
{
	struct wdm_irp irp;

	memset(&irp, 0, sizeof(irp));
	irp.major_function = WDM_IRP_MJ_PNP;
	irp.minor_function = minor_func;

	return wdm_dispatch_irp(dev, &irp);
}

/* ============================================================================
 * Public PnP operations
 * ============================================================================ */

/*
 * wdm_pnp_start_device - Start a PnP device.
 *
 * If the owning driver has an IRP_MJ_PNP dispatch entry, an
 * IRP_MN_START_DEVICE IRP is synthesised and dispatched.  Otherwise the
 * device is simply marked as started.
 */
int wdm_pnp_start_device(struct wdm_device *dev)
{
	struct wdm_driver *drv;
	int ret = 0;

	if (!dev)
		return -EINVAL;

	drv = dev->driver;
	if (!drv)
		return -EINVAL;

	pr_info("wdm_host: Starting PnP device: %s\n", dev->device_name);

	if (drv->dispatch_table[WDM_IRP_MJ_PNP]) {
		ret = pnp_dispatch_irp(dev, WDM_IRP_MN_START_DEVICE);
		if (ret) {
			pr_err("wdm_host: IRP_MN_START_DEVICE failed for '%s' "
			       "(err %d)\n", dev->device_name, ret);
			return ret;
		}
	}

	/* Mark the device as started regardless of whether an IRP was sent */
	dev->flags |= WDM_DEVICE_FLAG_STARTED;

	pr_info("wdm_host: PnP device '%s' started\n", dev->device_name);
	return 0;
}

/*
 * wdm_pnp_remove_device - Remove a PnP device.
 *
 * If the owning driver has an IRP_MJ_PNP dispatch entry, an
 * IRP_MN_REMOVE_DEVICE IRP is sent first.  Then the device is deleted via
 * wdm_delete_device().
 */
int wdm_pnp_remove_device(struct wdm_device *dev)
{
	struct wdm_driver *drv;

	if (!dev)
		return -EINVAL;

	drv = dev->driver;
	if (!drv)
		return -EINVAL;

	pr_info("wdm_host: Removing PnP device: %s\n", dev->device_name);

	if (drv->dispatch_table[WDM_IRP_MJ_PNP]) {
		int ret = pnp_dispatch_irp(dev, WDM_IRP_MN_REMOVE_DEVICE);

		if (ret)
			pr_warn("wdm_host: IRP_MN_REMOVE_DEVICE failed for "
				"'%s' (err %d), removing anyway\n",
				dev->device_name, ret);
	}

	wdm_delete_device(dev);
	return 0;
}

/*
 * wdm_pnp_enumerate - Enumerate devices for a driver (stub).
 *
 * In a full implementation this would query hardware (PCI, USB, ...) and
 * create device objects for each matching device.  For now it only logs
 * and returns success.
 *
 * Static because this is not yet exposed to other translation units; when
 * real enumeration is wired up add a declaration to wdm_host_internal.h.
 */
static int __maybe_unused wdm_pnp_enumerate(struct wdm_driver *drv)
{
	if (!drv)
		return -EINVAL;

	pr_info("wdm_host: Enumerating devices for driver: %s\n", drv->name);

	/* Stub: real enumeration would scan bus resources here */
	return 0;
}

/* ============================================================================
 * Subsystem init / exit
 * ============================================================================ */

/*
 * wdm_pnp_init - Initialise the PnP subsystem.
 */
int wdm_pnp_init(void)
{
	pr_info("wdm_host: PnP manager initialised\n");
	return 0;
}

/*
 * wdm_pnp_exit - Tear down the PnP subsystem.
 */
void wdm_pnp_exit(void)
{
	pr_info("wdm_host: PnP manager exited\n");
}

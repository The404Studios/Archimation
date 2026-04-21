/* SPDX-License-Identifier: GPL-2.0 */
/*
 * wdm_host_hid.h - HID class driver bridge
 *
 * When a hosted HID minidriver reports input through its class-driver
 * entry points, we translate the HID report into Linux evdev events via
 * /dev/uinput so that downstream X11/Wayland stacks consume the keyboard,
 * mouse, or gamepad naturally.
 *
 * Session 74 Tier-3.
 *
 * IOCTLs surfaced to the minidriver (a subset of the Windows HID class):
 *   - IOCTL_HID_GET_REPORT_DESCRIPTOR
 *   - IOCTL_HID_GET_DEVICE_ATTRIBUTES
 *   - IOCTL_HID_READ_REPORT    (async pull of input report)
 *   - IOCTL_HID_WRITE_REPORT   (output report to device)
 *
 * Devices enabled by this scaffold (contingent on the minidriver itself
 * loading correctly and populating a plausible report descriptor):
 *   - Generic Desktop / Keyboard
 *   - Generic Desktop / Mouse (X,Y rel + button bitmap)
 *   - Generic Desktop / Gamepad (thumbsticks + triggers + d-pad + buttons)
 *   - Consumer Control (volume / media keys)
 *   - Vendor-defined (Razer, Logitech G-Hub, Corsair iCue mousepads) -
 *       only the standard HID usages are passed through; vendor OUT
 *       reports are bounced via IOCTL_HID_SET_FEATURE when implemented.
 */

#ifndef WDM_HOST_HID_H
#define WDM_HOST_HID_H

#include <stdint.h>
#include <stddef.h>

/* ============================================================================
 * Windows HID IOCTL codes (match hidclass.h).
 * ============================================================================ */

#define IOCTL_HID_GET_REPORT_DESCRIPTOR  0x000B0000
#define IOCTL_HID_GET_DEVICE_ATTRIBUTES  0x000B0080
#define IOCTL_HID_GET_DEVICE_DESCRIPTOR  0x000B0084
#define IOCTL_HID_READ_REPORT            0x000B0004
#define IOCTL_HID_WRITE_REPORT           0x000B0008
#define IOCTL_HID_GET_FEATURE            0x000B0192
#define IOCTL_HID_SET_FEATURE            0x000B0190

/* HID_DEVICE_ATTRIBUTES (hidclass.h). */
struct wdm_hid_device_attributes {
	uint32_t Size;
	uint16_t VendorID;
	uint16_t ProductID;
	uint16_t VersionNumber;
	uint16_t Reserved[11];
};

/* ============================================================================
 * Class-driver function table registered by the minidriver via
 * HidRegisterMinidriver (simplified).
 * ============================================================================ */

struct wdm_hid_minidriver_registration {
	uint32_t Revision;                        /* HID_REVISION = 1 */
	void    *DriverObject;                    /* DRIVER_OBJECT * */
	void    *RegistryPath;                    /* UNICODE_STRING * */
	size_t   DeviceExtensionSize;
	uint8_t  DevicesArePolled;
	uint8_t  _pad[7];
};

/* ============================================================================
 * Device instance book-keeping (opaque to minidrivers).
 * ============================================================================ */

#define WDM_HID_MAX_DEVICES  16

struct wdm_hid_device {
	int      in_use;
	int      uinput_fd;
	char     name[64];
	struct wdm_hid_device_attributes attrs;
	uint8_t  report_descriptor[4096];
	size_t   report_descriptor_len;
	/* Parsed capabilities after report-descriptor walk. */
	int      has_keyboard;
	int      has_mouse;
	int      has_gamepad;
	int      abs_x_min, abs_x_max, abs_y_min, abs_y_max;
	/* Input-report bookkeeping. */
	uint8_t  last_buttons;
};

/* ============================================================================
 * API
 * ============================================================================ */

/* Minidriver registration (shim for HidRegisterMinidriver). */
int32_t WdmHidRegisterMinidriver(struct wdm_hid_minidriver_registration *reg);

/* Allocate a HID device slot, create the backing /dev/uinput node.
 * Returns a device handle index or negative on failure. */
int WdmHidAttachDevice(const char *name,
		       uint16_t vendor_id,
		       uint16_t product_id);

/* Detach: closes uinput, releases the slot. */
void WdmHidDetachDevice(int handle);

/* Load a report descriptor, parse it minimally to learn which input
 * kinds (keyboard/mouse/gamepad) to wire up in uinput. */
int WdmHidSetReportDescriptor(int handle,
			      const uint8_t *descriptor,
			      size_t len);

/* Feed an input report (from the minidriver's interrupt IN pipe). */
int WdmHidSubmitInputReport(int handle, const uint8_t *report, size_t len);

/* IOCTL entry point - invoked by the IRP dispatch layer for IRP_MJ_
 * INTERNAL_DEVICE_CONTROL on a HID device. */
int32_t WdmHidInternalIoctl(int handle,
			    uint32_t ioctl_code,
			    void *in_buf, size_t in_len,
			    void *out_buf, size_t out_len,
			    size_t *bytes_returned);

#endif /* WDM_HOST_HID_H */

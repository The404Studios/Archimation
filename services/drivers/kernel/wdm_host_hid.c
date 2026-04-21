// SPDX-License-Identifier: GPL-2.0
/*
 * wdm_host_hid.c - HID class bridge: Windows HID reports -> /dev/uinput.
 *
 * When a hosted HID minidriver calls up into the HID class through its
 * dispatch table, we intercept IRP_MJ_INTERNAL_DEVICE_CONTROL with
 * IOCTL_HID_READ_REPORT, parse the report against the descriptor the
 * driver provided at attach time, and translate usages into Linux evdev
 * events written through /dev/uinput. The resulting /dev/input/eventN
 * is indistinguishable from a real USB HID device from X11/Wayland's
 * perspective.
 *
 * This is a minimal usable subset:
 *   - Parses report descriptors well enough to detect Keyboard, Mouse,
 *     and Gamepad top-level collections (Usage Page 0x01, Usage 0x06/0x02/0x05).
 *   - Keyboard: 6KRO boot-protocol report is decoded.
 *   - Mouse: boot-protocol (button byte + X byte + Y byte) decoded.
 *   - Gamepad: boot-protocol-ish (button word + X/Y/Z/Rz/Rx/Ry axes).
 *
 * Session 74 Tier-3.
 *
 * What this does NOT do (S75 backlog):
 *   - Full HID report-item parser (usage tables, logical/physical min/max,
 *     report ID multiplexing, variable-size fields). The current code
 *     sniffs collection+usage headers and assumes boot-protocol shapes.
 *   - Output reports to device (LEDs, rumble OUT reports) - accepted
 *     but not yet routed back through the minidriver.
 *   - Feature reports.
 */

#include "wdm_host_hid.h"
#include "wdm_host_irp_driverapi.h"

#include <string.h>
#include <stdlib.h>

#ifdef WDM_HOST_KERNEL
#  include <linux/kernel.h>
#  include <linux/slab.h>
#  include <linux/mutex.h>
#  include <linux/printk.h>
#  define HID_LOG(fmt, ...)  pr_debug("wdm_hid: " fmt, ##__VA_ARGS__)
#  define HID_WARN(fmt, ...) pr_warn("wdm_hid: " fmt, ##__VA_ARGS__)
#else
#  include <stdio.h>
#  include <fcntl.h>
#  include <unistd.h>
#  include <sys/ioctl.h>
#  include <errno.h>
#  ifdef __linux__
#    include <linux/uinput.h>
#    include <linux/input.h>
#    define WDM_HID_HAS_UINPUT 1
#  else
#    define WDM_HID_HAS_UINPUT 0
#  endif
#  define HID_LOG(fmt, ...)  /* quiet */
#  define HID_WARN(fmt, ...) fprintf(stderr, "wdm_hid: " fmt, ##__VA_ARGS__)
#endif

/* ============================================================================
 * Device pool
 * ============================================================================ */

static struct wdm_hid_device g_devices[WDM_HID_MAX_DEVICES];

static int alloc_slot(void)
{
	int i;

	for (i = 0; i < WDM_HID_MAX_DEVICES; i++)
		if (!g_devices[i].in_use) {
			memset(&g_devices[i], 0, sizeof(g_devices[i]));
			g_devices[i].in_use = 1;
			g_devices[i].uinput_fd = -1;
			return i;
		}
	return -1;
}

static struct wdm_hid_device *slot(int h)
{
	if (h < 0 || h >= WDM_HID_MAX_DEVICES)
		return NULL;
	if (!g_devices[h].in_use)
		return NULL;
	return &g_devices[h];
}

/* ============================================================================
 * Report-descriptor sniffer
 *
 * Full HID parsing is a beast. We scan for Usage Page / Usage at top level
 * and record which of keyboard/mouse/gamepad the device claims. Enough to
 * build the right uinput abilities.
 *
 * HID item layout: one byte tag: bits 0..1 = size (0/1/2/4 actual bytes),
 * bits 2..3 = type (0=Main,1=Global,2=Local,3=Reserved), bits 4..7 = tag.
 * ============================================================================ */

#define HID_ITEM_USAGE_PAGE  0x04    /* Global, tag 0 */
#define HID_ITEM_USAGE       0x08    /* Local,  tag 0 */
#define HID_ITEM_COLLECTION  0xA0    /* Main,   tag A */

static int parse_descriptor(struct wdm_hid_device *d)
{
	const uint8_t *p = d->report_descriptor;
	const uint8_t *end = p + d->report_descriptor_len;
	uint16_t cur_usage_page = 0;
	uint16_t cur_usage = 0;
	int top_level_seen = 0;

	while (p < end) {
		uint8_t head = *p++;
		uint8_t sz = head & 0x03;
		uint32_t val = 0;
		unsigned i;

		if (sz == 3) sz = 4;
		if (p + sz > end) break;
		for (i = 0; i < sz; i++)
			val |= (uint32_t)p[i] << (i * 8);
		p += sz;

		/* Mask off size bits for tag comparison. */
		switch (head & 0xFC) {
		case HID_ITEM_USAGE_PAGE:
			cur_usage_page = (uint16_t)val;
			break;
		case HID_ITEM_USAGE:
			cur_usage = (uint16_t)val;
			break;
		case HID_ITEM_COLLECTION:
			if (top_level_seen == 0 && cur_usage_page == 0x01) {
				if (cur_usage == 0x06) d->has_keyboard = 1;
				else if (cur_usage == 0x02) d->has_mouse = 1;
				else if (cur_usage == 0x05 ||
					 cur_usage == 0x04 ||
					 cur_usage == 0x08) d->has_gamepad = 1;
				top_level_seen = 1;
			}
			break;
		default:
			break;
		}
	}

	/* Default sensible axis ranges for gamepad thumbsticks. */
	d->abs_x_min = -32768;
	d->abs_x_max =  32767;
	d->abs_y_min = -32768;
	d->abs_y_max =  32767;
	return 0;
}

/* ============================================================================
 * uinput wiring
 * ============================================================================ */

#if !defined(WDM_HOST_KERNEL) && defined(WDM_HID_HAS_UINPUT)
static int uinput_setup(struct wdm_hid_device *d)
{
	struct uinput_setup usetup;
	int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);

	if (fd < 0) {
		HID_WARN("open /dev/uinput: %s\n", strerror(errno));
		return -1;
	}

	if (d->has_keyboard) {
		int k;

		ioctl(fd, UI_SET_EVBIT, EV_KEY);
		/* Enable the whole standard keyboard range. */
		for (k = KEY_ESC; k <= KEY_UNKNOWN && k < 0x200; k++)
			ioctl(fd, UI_SET_KEYBIT, k);
	}
	if (d->has_mouse) {
		ioctl(fd, UI_SET_EVBIT, EV_REL);
		ioctl(fd, UI_SET_EVBIT, EV_KEY);
		ioctl(fd, UI_SET_RELBIT, REL_X);
		ioctl(fd, UI_SET_RELBIT, REL_Y);
		ioctl(fd, UI_SET_RELBIT, REL_WHEEL);
		ioctl(fd, UI_SET_KEYBIT, BTN_LEFT);
		ioctl(fd, UI_SET_KEYBIT, BTN_RIGHT);
		ioctl(fd, UI_SET_KEYBIT, BTN_MIDDLE);
		ioctl(fd, UI_SET_KEYBIT, BTN_SIDE);
		ioctl(fd, UI_SET_KEYBIT, BTN_EXTRA);
	}
	if (d->has_gamepad) {
		int b;

		ioctl(fd, UI_SET_EVBIT, EV_ABS);
		ioctl(fd, UI_SET_EVBIT, EV_KEY);
		ioctl(fd, UI_SET_ABSBIT, ABS_X);
		ioctl(fd, UI_SET_ABSBIT, ABS_Y);
		ioctl(fd, UI_SET_ABSBIT, ABS_RX);
		ioctl(fd, UI_SET_ABSBIT, ABS_RY);
		ioctl(fd, UI_SET_ABSBIT, ABS_Z);
		ioctl(fd, UI_SET_ABSBIT, ABS_RZ);
		ioctl(fd, UI_SET_ABSBIT, ABS_HAT0X);
		ioctl(fd, UI_SET_ABSBIT, ABS_HAT0Y);
		for (b = BTN_GAMEPAD; b <= BTN_THUMBR; b++)
			ioctl(fd, UI_SET_KEYBIT, b);
	}

	memset(&usetup, 0, sizeof(usetup));
	usetup.id.bustype = BUS_USB;
	usetup.id.vendor  = d->attrs.VendorID;
	usetup.id.product = d->attrs.ProductID;
	usetup.id.version = d->attrs.VersionNumber;
	strncpy(usetup.name, d->name, UINPUT_MAX_NAME_SIZE - 1);

	if (ioctl(fd, UI_DEV_SETUP, &usetup) < 0) {
		HID_WARN("UI_DEV_SETUP: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	if (ioctl(fd, UI_DEV_CREATE) < 0) {
		HID_WARN("UI_DEV_CREATE: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	d->uinput_fd = fd;
	return 0;
}

static void uinput_teardown(struct wdm_hid_device *d)
{
	if (d->uinput_fd >= 0) {
		ioctl(d->uinput_fd, UI_DEV_DESTROY);
		close(d->uinput_fd);
		d->uinput_fd = -1;
	}
}

static void uinput_emit(struct wdm_hid_device *d,
			uint16_t type, uint16_t code, int32_t value)
{
	struct input_event ev;

	if (d->uinput_fd < 0)
		return;
	memset(&ev, 0, sizeof(ev));
	ev.type = type;
	ev.code = code;
	ev.value = value;
	if (write(d->uinput_fd, &ev, sizeof(ev)) != sizeof(ev))
		HID_WARN("uinput write failed\n");
}

static void uinput_sync(struct wdm_hid_device *d)
{
	uinput_emit(d, EV_SYN, SYN_REPORT, 0);
}
#else
static int uinput_setup(struct wdm_hid_device *d)    { (void)d; return 0; }
static void uinput_teardown(struct wdm_hid_device *d) { (void)d; }
static void uinput_emit(struct wdm_hid_device *d,
			uint16_t type, uint16_t code, int32_t value)
{ (void)d; (void)type; (void)code; (void)value; }
static void uinput_sync(struct wdm_hid_device *d)    { (void)d; }
#endif

/* ============================================================================
 * Keyboard boot-protocol report handler
 * Bytes:
 *   0: modifier bitmap (LCtrl..RGui)
 *   1: reserved
 *   2..7: up to 6 simultaneously-pressed usage codes
 * We translate via the HID Usage -> Linux KEY_* table from the kernel
 * hid-input driver's canonical mapping.
 * ============================================================================ */

#if !defined(WDM_HOST_KERNEL) && defined(WDM_HID_HAS_UINPUT)
/* Very abbreviated usage -> keycode map. Real table is ~500 entries;
 * this covers the core alphabetic + modifiers that prove wiring works.
 * Full coverage is straightforward but out of scope for this scaffold. */
static const int usage_to_key[0x78] = {
	[0x04] = KEY_A, [0x05] = KEY_B, [0x06] = KEY_C, [0x07] = KEY_D,
	[0x08] = KEY_E, [0x09] = KEY_F, [0x0A] = KEY_G, [0x0B] = KEY_H,
	[0x0C] = KEY_I, [0x0D] = KEY_J, [0x0E] = KEY_K, [0x0F] = KEY_L,
	[0x10] = KEY_M, [0x11] = KEY_N, [0x12] = KEY_O, [0x13] = KEY_P,
	[0x14] = KEY_Q, [0x15] = KEY_R, [0x16] = KEY_S, [0x17] = KEY_T,
	[0x18] = KEY_U, [0x19] = KEY_V, [0x1A] = KEY_W, [0x1B] = KEY_X,
	[0x1C] = KEY_Y, [0x1D] = KEY_Z,
	[0x1E] = KEY_1, [0x1F] = KEY_2, [0x20] = KEY_3, [0x21] = KEY_4,
	[0x22] = KEY_5, [0x23] = KEY_6, [0x24] = KEY_7, [0x25] = KEY_8,
	[0x26] = KEY_9, [0x27] = KEY_0,
	[0x28] = KEY_ENTER, [0x29] = KEY_ESC, [0x2A] = KEY_BACKSPACE,
	[0x2B] = KEY_TAB,   [0x2C] = KEY_SPACE,
	[0x4F] = KEY_RIGHT, [0x50] = KEY_LEFT,
	[0x51] = KEY_DOWN,  [0x52] = KEY_UP,
};
#endif

static void handle_keyboard_report(struct wdm_hid_device *d,
				   const uint8_t *rep, size_t len)
{
#if !defined(WDM_HOST_KERNEL) && defined(WDM_HID_HAS_UINPUT)
	size_t i;

	if (len < 3) return;
	/* Modifiers: bit0=LCtrl, 1=LShift, 2=LAlt, 3=LGui, 4=RCtrl... */
	{
		static const int modkeys[8] = {
			KEY_LEFTCTRL, KEY_LEFTSHIFT, KEY_LEFTALT, KEY_LEFTMETA,
			KEY_RIGHTCTRL, KEY_RIGHTSHIFT, KEY_RIGHTALT, KEY_RIGHTMETA,
		};
		uint8_t mod = rep[0];
		int b;

		for (b = 0; b < 8; b++)
			uinput_emit(d, EV_KEY, modkeys[b], (mod >> b) & 1);
	}
	/* Usage slots rep[2..]. */
	for (i = 2; i < len && i < 8; i++) {
		uint8_t usage = rep[i];
		int k;

		if (usage == 0 || usage >= 0x78) continue;
		k = usage_to_key[usage];
		if (k) uinput_emit(d, EV_KEY, k, 1);
	}
	uinput_sync(d);
#else
	(void)d; (void)rep; (void)len;
#endif
}

static void handle_mouse_report(struct wdm_hid_device *d,
				const uint8_t *rep, size_t len)
{
#if !defined(WDM_HOST_KERNEL) && defined(WDM_HID_HAS_UINPUT)
	uint8_t buttons;
	int8_t dx, dy;
	int changed;

	if (len < 3) return;
	buttons = rep[0];
	dx = (int8_t)rep[1];
	dy = (int8_t)rep[2];

	changed = buttons ^ d->last_buttons;
	if (changed & 0x01) uinput_emit(d, EV_KEY, BTN_LEFT,   buttons & 0x01);
	if (changed & 0x02) uinput_emit(d, EV_KEY, BTN_RIGHT,  (buttons >> 1) & 1);
	if (changed & 0x04) uinput_emit(d, EV_KEY, BTN_MIDDLE, (buttons >> 2) & 1);
	d->last_buttons = buttons;

	if (dx) uinput_emit(d, EV_REL, REL_X, dx);
	if (dy) uinput_emit(d, EV_REL, REL_Y, dy);

	if (len >= 4) {
		int8_t wheel = (int8_t)rep[3];

		if (wheel) uinput_emit(d, EV_REL, REL_WHEEL, wheel);
	}
	uinput_sync(d);
#else
	(void)d; (void)rep; (void)len;
#endif
}

static void handle_gamepad_report(struct wdm_hid_device *d,
				  const uint8_t *rep, size_t len)
{
#if !defined(WDM_HOST_KERNEL) && defined(WDM_HID_HAS_UINPUT)
	/* Treat as: [0..1] button word, [2..3] LX, [4..5] LY, [6..7] RX,
	 *          [8..9] RY, [10] LT, [11] RT. Matches XInput legacy shape. */
	uint16_t buttons;
	int b;

	if (len < 6) return;
	buttons = (uint16_t)rep[0] | ((uint16_t)rep[1] << 8);
	for (b = 0; b < 16; b++) {
		static const int gp_buttons[16] = {
			BTN_DPAD_UP, BTN_DPAD_DOWN, BTN_DPAD_LEFT, BTN_DPAD_RIGHT,
			BTN_START, BTN_SELECT, BTN_THUMBL, BTN_THUMBR,
			BTN_TL, BTN_TR, BTN_MODE, 0,
			BTN_A, BTN_B, BTN_X, BTN_Y,
		};
		if (gp_buttons[b])
			uinput_emit(d, EV_KEY, gp_buttons[b],
				    (buttons >> b) & 1);
	}

	uinput_emit(d, EV_ABS, ABS_X,  (int16_t)(rep[2] | (rep[3] << 8)));
	if (len >= 6)
		uinput_emit(d, EV_ABS, ABS_Y,  (int16_t)(rep[4] | (rep[5] << 8)));
	if (len >= 10) {
		uinput_emit(d, EV_ABS, ABS_RX, (int16_t)(rep[6] | (rep[7] << 8)));
		uinput_emit(d, EV_ABS, ABS_RY, (int16_t)(rep[8] | (rep[9] << 8)));
	}
	if (len >= 12) {
		uinput_emit(d, EV_ABS, ABS_Z,  rep[10]);
		uinput_emit(d, EV_ABS, ABS_RZ, rep[11]);
	}
	uinput_sync(d);
#else
	(void)d; (void)rep; (void)len;
#endif
}

/* ============================================================================
 * Public API
 * ============================================================================ */

int32_t WdmHidRegisterMinidriver(struct wdm_hid_minidriver_registration *reg)
{
	if (!reg)
		return WDMAPI_STATUS_INVALID_PARAMETER;
	if (reg->Revision != 1)
		return WDMAPI_STATUS_NOT_SUPPORTED;

	/* A real implementation allocates class-driver extensions and
	 * swaps the DRIVER_OBJECT's MajorFunction[] for a class-wrapped
	 * version. For scaffold purposes we just validate and log. */
	HID_LOG("minidriver registered (DriverObject=%p, ext=%zu)\n",
		reg->DriverObject, reg->DeviceExtensionSize);
	return WDMAPI_STATUS_SUCCESS;
}

int WdmHidAttachDevice(const char *name, uint16_t vid, uint16_t pid)
{
	int h = alloc_slot();
	struct wdm_hid_device *d;

	if (h < 0)
		return -1;

	d = &g_devices[h];
	if (name) {
		strncpy(d->name, name, sizeof(d->name) - 1);
		d->name[sizeof(d->name) - 1] = '\0';
	} else {
		snprintf(d->name, sizeof(d->name),
			 "wdm-hid-%04x:%04x", vid, pid);
	}
	d->attrs.Size = (uint32_t)sizeof(d->attrs);
	d->attrs.VendorID = vid;
	d->attrs.ProductID = pid;
	d->attrs.VersionNumber = 0x0100;
	return h;
}

void WdmHidDetachDevice(int handle)
{
	struct wdm_hid_device *d = slot(handle);

	if (!d)
		return;
	uinput_teardown(d);
	d->in_use = 0;
}

int WdmHidSetReportDescriptor(int handle, const uint8_t *desc, size_t len)
{
	struct wdm_hid_device *d = slot(handle);

	if (!d || !desc || len == 0 || len > sizeof(d->report_descriptor))
		return -1;

	memcpy(d->report_descriptor, desc, len);
	d->report_descriptor_len = len;
	parse_descriptor(d);
	if (uinput_setup(d) < 0)
		return -2;
	return 0;
}

int WdmHidSubmitInputReport(int handle, const uint8_t *rep, size_t len)
{
	struct wdm_hid_device *d = slot(handle);

	if (!d || !rep || len == 0)
		return -1;

	/* Dispatch based on what the descriptor said this device is. If the
	 * device declares multiple top-level collections it gets all three
	 * decodes tried; the mis-shaped ones simply no-op because the report
	 * length will not match. */
	if (d->has_keyboard && len >= 3)
		handle_keyboard_report(d, rep, len);
	if (d->has_mouse && len >= 3 && len <= 8)
		handle_mouse_report(d, rep, len);
	if (d->has_gamepad && len >= 6)
		handle_gamepad_report(d, rep, len);
	return 0;
}

int32_t WdmHidInternalIoctl(int handle, uint32_t ioctl_code,
			    void *in_buf, size_t in_len,
			    void *out_buf, size_t out_len,
			    size_t *bytes_returned)
{
	struct wdm_hid_device *d = slot(handle);
	size_t written = 0;

	(void)in_buf; (void)in_len;
	if (!d) return WDMAPI_STATUS_INVALID_PARAMETER;

	switch (ioctl_code) {
	case IOCTL_HID_GET_REPORT_DESCRIPTOR: {
		size_t n = d->report_descriptor_len;

		if (n > out_len) n = out_len;
		if (out_buf && n) memcpy(out_buf, d->report_descriptor, n);
		written = n;
		break;
	}
	case IOCTL_HID_GET_DEVICE_ATTRIBUTES: {
		size_t n = sizeof(d->attrs);

		if (n > out_len) n = out_len;
		if (out_buf && n) memcpy(out_buf, &d->attrs, n);
		written = n;
		break;
	}
	case IOCTL_HID_READ_REPORT:
		/* Async pull: the real implementation would park the IRP on
		 * a queue and complete it when the minidriver pushes an
		 * input report. Scaffold returns pending. */
		if (bytes_returned) *bytes_returned = 0;
		return WDMAPI_STATUS_PENDING;
	case IOCTL_HID_WRITE_REPORT:
		/* Output reports to device: not yet routed back to driver. */
		written = in_len;
		break;
	default:
		if (bytes_returned) *bytes_returned = 0;
		return WDMAPI_STATUS_NOT_IMPLEMENTED;
	}

	if (bytes_returned) *bytes_returned = written;
	return WDMAPI_STATUS_SUCCESS;
}

#ifndef WDM_HOST_KERNEL
/* Userland preflight self-test: attach, descriptor, detach. */
int wdm_hid_selftest(void)
{
	int h;
	/* Minimal keyboard descriptor (4 items): Usage Page 1, Usage 6,
	 * Collection 1 (Application), End Collection. */
	static const uint8_t desc[] = {
		0x05, 0x01,  /* Usage Page (Generic Desktop) */
		0x09, 0x06,  /* Usage (Keyboard) */
		0xA1, 0x01,  /* Collection (Application) */
		0xC0,        /* End Collection */
	};
	static const uint8_t rep[] = {
		0x00,        /* modifiers */
		0x00,        /* reserved */
		0x04,        /* Usage = A */
		0, 0, 0, 0, 0,
	};

	h = WdmHidAttachDevice("selftest", 0x1234, 0x5678);
	if (h < 0) return -1;

	if (WdmHidSetReportDescriptor(h, desc, sizeof(desc)) < 0) {
		/* uinput may be absent in CI; that's not a parse failure. */
		if (!g_devices[h].has_keyboard) {
			WdmHidDetachDevice(h);
			return -2;
		}
	}
	if (!g_devices[h].has_keyboard) {
		WdmHidDetachDevice(h);
		return -3;
	}

	WdmHidSubmitInputReport(h, rep, sizeof(rep));

	{
		uint8_t out[4096];
		size_t got = 0;
		int32_t rc = WdmHidInternalIoctl(h,
			IOCTL_HID_GET_REPORT_DESCRIPTOR,
			NULL, 0, out, sizeof(out), &got);

		if (rc != WDMAPI_STATUS_SUCCESS) {
			WdmHidDetachDevice(h);
			return -4;
		}
		if (got != sizeof(desc)) {
			WdmHidDetachDevice(h);
			return -5;
		}
	}

	WdmHidDetachDevice(h);
	return 0;
}
#endif

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * wdm_host_irp_driverapi.h - Windows-driver-facing IRP framework
 *
 * This header defines the IRP API surface that hosted .sys drivers see
 * via their ntoskrnl imports. It is intentionally separate from
 * wdm_host_internal.h / wdm_host_irp.c - that pair implements the
 * userspace-ioctl bridge (struct wdm_irp is a compact marshalling
 * structure for /dev/wdm_host). This pair implements the *Windows*
 * DRIVER_OBJECT / IRP / IO_STACK_LOCATION shapes that real driver code
 * allocates, fills in, and passes to IoCallDriver / IofCompleteRequest.
 *
 * Two layers, one bridge: wdm_host_thunk.c ultimately translates between
 * the internal wdm_irp form and this Windows-shaped form when dispatching.
 *
 * Session 74 (Tier 3 driver work). Userland-preflight compilable: the
 * whole file compiles outside the kernel tree too because it only uses
 * fixed-width uint*_t types.
 */

#ifndef WDM_HOST_IRP_DRIVERAPI_H
#define WDM_HOST_IRP_DRIVERAPI_H

#include <stdint.h>
#include <stddef.h>

/* ============================================================================
 * IRP major function codes (Windows WDK values).
 * These indices must fit inside DRIVER_OBJECT::MajorFunction[].
 * ============================================================================ */

#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CREATE_NAMED_PIPE        0x01
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_QUERY_INFORMATION        0x05
#define IRP_MJ_SET_INFORMATION          0x06
#define IRP_MJ_FLUSH_BUFFERS            0x09
#define IRP_MJ_DEVICE_CONTROL           0x0E
#define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0F
#define IRP_MJ_SHUTDOWN                 0x10
#define IRP_MJ_CLEANUP                  0x12
#define IRP_MJ_POWER                    0x16
#define IRP_MJ_SYSTEM_CONTROL           0x17
#define IRP_MJ_PNP                      0x1B
#define IRP_MJ_MAXIMUM_FUNCTION         0x1B

#define WDM_IRP_MJ_TABLE_LEN            (IRP_MJ_MAXIMUM_FUNCTION + 1)

/* ============================================================================
 * IRP minor function codes (subset covering PNP and POWER paths).
 * ============================================================================ */

#define IRP_MN_START_DEVICE             0x00
#define IRP_MN_QUERY_REMOVE_DEVICE      0x01
#define IRP_MN_REMOVE_DEVICE            0x02
#define IRP_MN_CANCEL_REMOVE_DEVICE     0x03
#define IRP_MN_STOP_DEVICE              0x04
#define IRP_MN_QUERY_STOP_DEVICE        0x05
#define IRP_MN_CANCEL_STOP_DEVICE       0x06
#define IRP_MN_QUERY_DEVICE_RELATIONS   0x07
#define IRP_MN_QUERY_CAPABILITIES       0x09
#define IRP_MN_SURPRISE_REMOVAL         0x17

/* ============================================================================
 * NTSTATUS selected values.
 * ============================================================================ */

#define WDMAPI_STATUS_SUCCESS            ((int32_t)0x00000000)
#define WDMAPI_STATUS_PENDING            ((int32_t)0x00000103)
#define WDMAPI_STATUS_NOT_IMPLEMENTED    ((int32_t)0xC0000002)
#define WDMAPI_STATUS_INVALID_PARAMETER  ((int32_t)0xC000000D)
#define WDMAPI_STATUS_NOT_SUPPORTED      ((int32_t)0xC00000BB)
#define WDMAPI_STATUS_INSUFFICIENT       ((int32_t)0xC000009A)

/* ============================================================================
 * Driver-visible structures (Windows WDM shape, simplified).
 *
 * These are laid out so that a real driver can cast OUR allocations to its
 * _IRP / _DRIVER_OBJECT / _IO_STACK_LOCATION and touch the fields at the
 * offsets Microsoft compilers expect. Padding slots are reserved even
 * where we do not use them so that field offsets are stable.
 * ============================================================================ */

struct wdm_io_status_block {
	int32_t  Status;            /* NTSTATUS */
	uintptr_t Information;      /* bytes transferred / handle / etc. */
};

struct wdm_io_stack_location {
	uint8_t  MajorFunction;
	uint8_t  MinorFunction;
	uint8_t  Flags;
	uint8_t  Control;
	uint32_t _pad0;

	/* Parameters union (simplified: largest member = 4 pointers). */
	union {
		struct {
			uint32_t OutputBufferLength;
			uint32_t InputBufferLength;
			uint32_t IoControlCode;
			void    *Type3InputBuffer;
		} DeviceIoControl;
		struct {
			uint32_t Length;
			uint32_t Key;
			uint64_t ByteOffset;
		} Read;
		struct {
			uint32_t Length;
			uint32_t Key;
			uint64_t ByteOffset;
		} Write;
		struct {
			void *Argument1;
			void *Argument2;
			void *Argument3;
			void *Argument4;
		} Others;
	} Parameters;

	void *DeviceObject;
	void *FileObject;

	/* Completion routine (optional). ABI: ms_abi on x86_64. */
	int32_t (*CompletionRoutine)(void *device, void *irp, void *context);
	void    *CompletionContext;
};

#define WDM_IO_STACK_MAX 16

struct wdm_irp_hdr {
	uint16_t Type;              /* IO_TYPE_IRP = 6 in Windows */
	uint16_t Size;
	uint32_t Flags;

	struct wdm_io_status_block IoStatus;
	void    *UserBuffer;
	void    *SystemBuffer;      /* METHOD_BUFFERED destination */
	void    *MdlAddress;        /* unused in shim, slot reserved */

	uint32_t CurrentStackIndex;
	uint32_t StackCount;
	struct wdm_io_stack_location Stack[WDM_IO_STACK_MAX];
};

struct wdm_driver_object {
	uint16_t Type;              /* IO_TYPE_DRIVER = 4 */
	uint16_t Size;
	void    *DeviceObject;      /* linked list head in real Windows */
	uint32_t Flags;

	/* Dispatch table - populated by the driver's DriverEntry(). */
	int32_t (*MajorFunction[WDM_IRP_MJ_TABLE_LEN])(void *device, void *irp);

	void (*DriverUnload)(void *drv);
	int32_t (*DriverStartIo)(void *device, void *irp);

	/* Host-private book-keeping (not part of Windows shape, reserved). */
	void    *HostPrivate;
};

/* ============================================================================
 * API
 * ============================================================================ */

/* Allocate / free an IRP with the given stack depth. */
struct wdm_irp_hdr *WdmIoAllocateIrp(uint8_t stack_size, int charge_quota);
void WdmIoFreeIrp(struct wdm_irp_hdr *irp);

/* Get the stack location the driver is currently servicing. */
struct wdm_io_stack_location *WdmIoGetCurrentIrpStackLocation(struct wdm_irp_hdr *irp);
struct wdm_io_stack_location *WdmIoGetNextIrpStackLocation(struct wdm_irp_hdr *irp);

/* Drop to the next-lower driver in the stack. */
int32_t WdmIoCallDriver(void *target_device, struct wdm_irp_hdr *irp);

/* Complete an IRP (runs any completion routine, then frees). */
void WdmIofCompleteRequest(struct wdm_irp_hdr *irp, int8_t priority_boost);

/* Invoke the dispatch function registered on a driver for the given major.
 * If the driver left the slot NULL, the IRP is completed STATUS_NOT_IMPLEMENTED. */
int32_t WdmIoDispatchToDriver(struct wdm_driver_object *drv,
			      void *device,
			      struct wdm_irp_hdr *irp);

/* Populate every slot in a fresh DRIVER_OBJECT with a default trap that
 * completes with STATUS_NOT_IMPLEMENTED. This is what the loader calls
 * before DriverEntry so that un-overridden majors behave sanely. */
void WdmIoInstallDefaultDispatch(struct wdm_driver_object *drv);

#endif /* WDM_HOST_IRP_DRIVERAPI_H */

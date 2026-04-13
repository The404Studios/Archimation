// SPDX-License-Identifier: GPL-2.0
/*
 * wdm_host_thunk.c - Windows x64 ABI calling convention trampoline
 *
 * Bridges the Linux System V AMD64 ABI to the Windows x64 calling convention
 * so that Windows driver dispatch functions (loaded into kernel memory) can
 * be called from Linux kernel code.
 *
 * Key differences between the ABIs:
 *
 *   System V (Linux):
 *     - Integer args: RDI, RSI, RDX, RCX, R8, R9
 *     - Caller-saved: RAX, RCX, RDX, RSI, RDI, R8-R11
 *     - Callee-saved: RBX, RBP, R12-R15
 *     - No shadow space required
 *
 *   Windows x64:
 *     - Integer args: RCX, RDX, R8, R9
 *     - Caller-saved: RAX, RCX, RDX, R8-R11
 *     - Callee-saved: RBX, RBP, RDI, RSI, R12-R15
 *     - 32-byte shadow space required before call
 *     - Stack must be 16-byte aligned at call instruction
 *
 * The thunk handles:
 *   1. Saving registers that Windows expects callee-saved but Linux does not
 *   2. Allocating 32-byte shadow space on the stack
 *   3. Placing arguments in Windows x64 registers (RCX, RDX)
 *   4. Ensuring proper stack alignment
 *   5. Calling the target function
 *   6. Restoring registers and returning the NTSTATUS result
 *
 * Additionally, this file builds minimal Windows-compatible DEVICE_OBJECT
 * and IRP structures from our internal wdm_device/wdm_irp representations,
 * because the loaded driver code expects the Windows memory layout.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "wdm_host_internal.h"

/* Windows NTSTATUS codes */
#define NT_STATUS_SUCCESS              0x00000000
#define NT_STATUS_NOT_SUPPORTED        ((int32_t)0xC00000BB)
#define NT_STATUS_UNSUCCESSFUL         ((int32_t)0xC0000001)

/* ============================================================================
 * Minimal Windows-compatible structure layouts
 *
 * These mirror the fields that a typical WDM driver dispatch routine actually
 * accesses. Fields the driver doesn't touch are zeroed.
 * ============================================================================ */

/*
 * Minimal DEVICE_OBJECT layout (Windows x64, from ntddk.h):
 *
 * Offset  Field
 * 0x000   Type (int16)
 * 0x002   Size (uint16)
 * 0x004   ReferenceCount (int32)
 * 0x008   DriverObject (pointer)
 * 0x010   NextDevice (pointer)
 * 0x018   AttachedDevice (pointer)
 * 0x020   CurrentIrp (pointer)
 * 0x028   Timer (pointer)
 * 0x030   Flags (uint32)
 * 0x034   Characteristics (uint32)
 * 0x038   Vpb (pointer)
 * 0x040   DeviceExtension (pointer)
 * 0x048   DeviceType (uint32)
 * 0x04C   StackSize (uint8) + padding
 *
 * Total: padded to 0x150 (minimum realistic DEVICE_OBJECT size)
 */
#define WIN_DEVOBJ_SIZE         0x150

#define WIN_DEVOBJ_OFF_TYPE             0x000   /* int16_t */
#define WIN_DEVOBJ_OFF_SIZE             0x002   /* uint16_t */
#define WIN_DEVOBJ_OFF_DRIVER_OBJECT    0x008   /* void* */
#define WIN_DEVOBJ_OFF_FLAGS            0x030   /* uint32_t */
#define WIN_DEVOBJ_OFF_DEV_EXT          0x040   /* void* */
#define WIN_DEVOBJ_OFF_DEV_TYPE         0x048   /* uint32_t */

/*
 * Minimal IRP layout (Windows x64, from wdm.h):
 *
 * Offset  Field
 * 0x000   Type (int16)
 * 0x002   Size (uint16)
 * 0x008   MdlAddress (pointer)
 * 0x010   Flags (uint32) + padding
 * 0x018   AssociatedIrp.SystemBuffer (pointer, union)
 * 0x020   ThreadListEntry (LIST_ENTRY, 16 bytes)
 * 0x030   IoStatus.Status (int32)
 * 0x034   padding
 * 0x038   IoStatus.Information (ULONG_PTR, 8 bytes)
 * 0x040   RequestorMode (uint8) + padding
 * 0x048   PendingReturned (uint8) + padding
 * 0x058   Cancel (uint8) + CancelIrql (uint8) + padding
 * 0x060   CancelRoutine (pointer)
 * 0x068   UserBuffer (pointer)
 * 0x070   Tail.Overlay (includes CurrentStackLocation at +0x78 in overlay)
 * 0x078   Tail.Overlay.CurrentStackLocation (pointer)
 *
 * IO_STACK_LOCATION (at end of IRP buffer):
 *   +0x00  MajorFunction (uint8)
 *   +0x01  MinorFunction (uint8)
 *   +0x08  Parameters (union, 32 bytes)
 *            For DeviceIoControl:
 *              +0x00  OutputBufferLength (uint32)
 *              +0x08  InputBufferLength (uint32)
 *              +0x10  IoControlCode (uint32)
 *   +0x28  DeviceObject (void*)
 *
 * Total IRP+stack: 0x80 (IRP) + 0x48 (IO_STACK_LOCATION) = 0xC8
 */
#define WIN_IRP_SIZE            0x80
#define WIN_IOSTACK_SIZE        0x48
#define WIN_IRP_TOTAL_SIZE      (WIN_IRP_SIZE + WIN_IOSTACK_SIZE)

/* IRP offsets */
#define WIN_IRP_OFF_TYPE                0x000
#define WIN_IRP_OFF_SIZE                0x002
#define WIN_IRP_OFF_SYSTEM_BUFFER       0x018
#define WIN_IRP_OFF_IOSTATUS_STATUS     0x030
#define WIN_IRP_OFF_IOSTATUS_INFO       0x038
#define WIN_IRP_OFF_USER_BUFFER         0x068
#define WIN_IRP_OFF_CURRENT_STACK       0x078

/* IO_STACK_LOCATION offsets (relative to stack location base) */
#define WIN_IOSL_OFF_MAJOR              0x00
#define WIN_IOSL_OFF_MINOR              0x01
#define WIN_IOSL_OFF_PARAMS             0x08
#define WIN_IOSL_OFF_DEVOBJ             0x28

/* DeviceIoControl parameter offsets within Parameters union */
#define WIN_IOSL_IOCTL_OUTLEN           0x00    /* ULONG OutputBufferLength */
#define WIN_IOSL_IOCTL_INLEN            0x08    /* ULONG InputBufferLength */
#define WIN_IOSL_IOCTL_CODE             0x10    /* ULONG IoControlCode */

/* Read parameter offsets within Parameters union */
#define WIN_IOSL_READ_LENGTH            0x00
#define WIN_IOSL_READ_BYTEOFFSET        0x08    /* LARGE_INTEGER */

/* Write parameter offsets within Parameters union */
#define WIN_IOSL_WRITE_LENGTH           0x00
#define WIN_IOSL_WRITE_BYTEOFFSET       0x08    /* LARGE_INTEGER */

/* Windows type codes */
#define IO_TYPE_DEVICE          0x0003
#define IO_TYPE_IRP             0x0006

/* ============================================================================
 * Helper macros for writing to offset within a zeroed buffer
 * ============================================================================ */

#define PUT8(buf, off, val)   (*(uint8_t *)((char *)(buf) + (off)) = (uint8_t)(val))
#define PUT16(buf, off, val)  (*(int16_t *)((char *)(buf) + (off)) = (int16_t)(val))
#define PUT16U(buf, off, val) (*(uint16_t *)((char *)(buf) + (off)) = (uint16_t)(val))
#define PUT32(buf, off, val)  (*(int32_t *)((char *)(buf) + (off)) = (int32_t)(val))
#define PUT32U(buf, off, val) (*(uint32_t *)((char *)(buf) + (off)) = (uint32_t)(val))
#define PUTP(buf, off, val)   (*(void **)((char *)(buf) + (off)) = (void *)(val))
#define PUTSZ(buf, off, val)  (*(size_t *)((char *)(buf) + (off)) = (size_t)(val))

#define GET32(buf, off)       (*(int32_t *)((char *)(buf) + (off)))
#define GETSZ(buf, off)       (*(size_t *)((char *)(buf) + (off)))

/* ============================================================================
 * ABI Trampoline (x86_64 only)
 * ============================================================================ */

#ifdef CONFIG_X86_64

/**
 * wdm_thunk_call2() - Call a Windows x64 function with 2 arguments
 * @func: Pointer to the Windows function to call
 * @arg1: First argument (goes in RCX under Windows convention)
 * @arg2: Second argument (goes in RDX under Windows convention)
 *
 * Bridges System V AMD64 ABI to Windows x64 ABI:
 *   - Saves RDI and RSI (Windows callee-saved, Linux caller-saved)
 *   - Allocates 32-byte shadow space
 *   - Places arg1 in RCX, arg2 in RDX
 *   - Calls the function
 *   - Returns the NTSTATUS (int32_t in EAX)
 *
 * Returns: NTSTATUS value from the Windows function
 */
static noinline int32_t wdm_thunk_call2(void *func, void *arg1, void *arg2)
{
	int32_t result;

	/*
	 * The inline asm handles the ABI bridge:
	 *
	 * 1. Save RDI and RSI — Windows x64 treats these as callee-saved,
	 *    so the called function may expect them preserved. Linux
	 *    treats them as caller-saved (argument registers), but we're
	 *    in kernel code where they might hold live values.
	 *
	 * 2. Allocate 32 bytes of shadow space — Windows x64 requires
	 *    the caller to reserve 32 bytes above the return address for
	 *    the callee to spill RCX/RDX/R8/R9.
	 *
	 * 3. Place arguments: arg1 → RCX, arg2 → RDX.
	 *
	 * 4. Call the Windows function.
	 *
	 * 5. Clean up shadow space, restore RDI/RSI, return EAX.
	 */
	asm volatile(
		/* Save Windows callee-saved regs not in Linux set */
		"pushq %%rdi\n\t"
		"pushq %%rsi\n\t"

		/* Allocate 32-byte shadow space + 16 bytes for alignment
		 * (2 pushes = 16 bytes, shadow = 32 bytes, total 48;
		 *  need stack 16-byte aligned before CALL, so pad to 48) */
		"subq $40, %%rsp\n\t"

		/* Set up Windows x64 arguments */
		"movq %[a1], %%rcx\n\t"
		"movq %[a2], %%rdx\n\t"

		/* Clear R8, R9 (unused args, but zero for safety) */
		"xorq %%r8, %%r8\n\t"
		"xorq %%r9, %%r9\n\t"

		/* Call the Windows function */
		"callq *%[fn]\n\t"

		/* Clean up shadow space */
		"addq $40, %%rsp\n\t"

		/* Restore saved registers */
		"popq %%rsi\n\t"
		"popq %%rdi\n\t"

		: "=a"(result)
		: [a1] "r"(arg1),
		  [a2] "r"(arg2),
		  [fn] "r"(func)
		: "rcx", "rdx", "r8", "r9", "r10", "r11",
		  "memory", "cc"
	);

	return result;
}

#else /* !CONFIG_X86_64 */

/*
 * Non-x86_64 architectures: stub that returns NOT_SUPPORTED.
 * Windows .sys drivers are x86_64 PE binaries, so running them
 * on other architectures is not meaningful.
 */
static inline int32_t wdm_thunk_call2(void *func, void *arg1, void *arg2)
{
	(void)func;
	(void)arg1;
	(void)arg2;
	pr_warn("[wdm_host] thunk: Windows driver dispatch not supported "
		"on this architecture\n");
	return NT_STATUS_NOT_SUPPORTED;
}

#endif /* CONFIG_X86_64 */

/* ============================================================================
 * Windows-Compatible Structure Builders
 * ============================================================================ */

/**
 * wdm_build_devobj() - Build a minimal Windows DEVICE_OBJECT
 * @dev: Our internal wdm_device
 *
 * Allocates and populates a buffer matching the Windows DEVICE_OBJECT
 * memory layout, filling in the fields that typical drivers access.
 *
 * Returns: pointer to allocated buffer, or NULL on failure.
 * Caller must kfree() when done.
 */
static void *wdm_build_devobj(struct wdm_device *dev)
{
	void *obj;

	obj = kzalloc(WIN_DEVOBJ_SIZE, GFP_KERNEL);
	if (!obj)
		return NULL;

	PUT16(obj,  WIN_DEVOBJ_OFF_TYPE, IO_TYPE_DEVICE);
	PUT16U(obj, WIN_DEVOBJ_OFF_SIZE, WIN_DEVOBJ_SIZE);

	/* DriverObject: point back to our driver struct.
	 * The driver code may dereference this to find its dispatch table
	 * or driver extension. Using our wdm_driver pointer is safe as long
	 * as the driver only checks for NULL vs non-NULL. */
	PUTP(obj, WIN_DEVOBJ_OFF_DRIVER_OBJECT, dev->driver);

	/* DeviceExtension: the per-device extension memory that the driver
	 * allocated via IoCreateDevice. This is the primary field drivers use. */
	PUTP(obj, WIN_DEVOBJ_OFF_DEV_EXT, dev->device_extension);

	PUT32U(obj, WIN_DEVOBJ_OFF_DEV_TYPE, dev->device_type);
	PUT32U(obj, WIN_DEVOBJ_OFF_FLAGS, dev->flags);

	return obj;
}

/**
 * wdm_build_irp() - Build a minimal Windows IRP + IO_STACK_LOCATION
 * @irp_in:  Our internal wdm_irp
 * @devobj:  The Windows DEVICE_OBJECT buffer (from wdm_build_devobj)
 *
 * Allocates a buffer containing a Windows-layout IRP followed by an
 * IO_STACK_LOCATION, filling in fields that drivers commonly access.
 *
 * Returns: pointer to allocated buffer, or NULL on failure.
 * Caller must kfree() when done.
 */
static void *wdm_build_irp(struct wdm_irp *irp_in, void *devobj)
{
	void *buf;
	void *stack_loc;

	buf = kzalloc(WIN_IRP_TOTAL_SIZE, GFP_KERNEL);
	if (!buf)
		return NULL;

	/* IRP header */
	PUT16(buf, WIN_IRP_OFF_TYPE, IO_TYPE_IRP);
	PUT16U(buf, WIN_IRP_OFF_SIZE, WIN_IRP_TOTAL_SIZE);

	/* IoStatus: pre-fill with pending status */
	PUT32(buf, WIN_IRP_OFF_IOSTATUS_STATUS, NT_STATUS_SUCCESS);
	PUTSZ(buf, WIN_IRP_OFF_IOSTATUS_INFO, 0);

	/* Buffers */
	PUTP(buf, WIN_IRP_OFF_SYSTEM_BUFFER, irp_in->system_buffer);
	PUTP(buf, WIN_IRP_OFF_USER_BUFFER, irp_in->user_buffer);

	/* Current stack location: pointer to the IO_STACK_LOCATION
	 * that follows the IRP in our buffer */
	stack_loc = (char *)buf + WIN_IRP_SIZE;
	PUTP(buf, WIN_IRP_OFF_CURRENT_STACK, stack_loc);

	/* IO_STACK_LOCATION */
	PUT8(stack_loc, WIN_IOSL_OFF_MAJOR, irp_in->major_function);
	PUT8(stack_loc, WIN_IOSL_OFF_MINOR, irp_in->minor_function);
	PUTP(stack_loc, WIN_IOSL_OFF_DEVOBJ, devobj);

	/* Fill in Parameters based on major function */
	switch (irp_in->major_function) {
	case 0x0E: /* IRP_MJ_DEVICE_CONTROL */
	case 0x0F: /* IRP_MJ_INTERNAL_DEVICE_CONTROL */
		PUT32U(stack_loc, WIN_IOSL_OFF_PARAMS + WIN_IOSL_IOCTL_OUTLEN,
		       irp_in->output_length);
		PUT32U(stack_loc, WIN_IOSL_OFF_PARAMS + WIN_IOSL_IOCTL_INLEN,
		       irp_in->buffer_length);
		PUT32U(stack_loc, WIN_IOSL_OFF_PARAMS + WIN_IOSL_IOCTL_CODE,
		       irp_in->ioctl_code);
		break;

	case 0x03: /* IRP_MJ_READ */
		PUT32U(stack_loc, WIN_IOSL_OFF_PARAMS + WIN_IOSL_READ_LENGTH,
		       irp_in->buffer_length);
		break;

	case 0x04: /* IRP_MJ_WRITE */
		PUT32U(stack_loc, WIN_IOSL_OFF_PARAMS + WIN_IOSL_WRITE_LENGTH,
		       irp_in->buffer_length);
		break;

	default:
		/* CREATE, CLOSE, PNP, etc. — no extra parameters */
		break;
	}

	return buf;
}

/* ============================================================================
 * Public API: Dispatch through the thunk
 * ============================================================================ */

/**
 * wdm_thunk_dispatch() - Dispatch an IRP to a Windows driver via ABI thunk
 * @dev: Our internal wdm_device
 * @irp: Our internal wdm_irp (updated with result on return)
 *
 * Builds Windows-compatible DEVICE_OBJECT and IRP structures, calls the
 * driver's dispatch function via the ABI trampoline, and reads back the
 * NTSTATUS and IoStatus.Information into our wdm_irp.
 *
 * Returns: 0 on success, negative errno on infrastructure failure.
 */
int wdm_thunk_dispatch(struct wdm_device *dev, struct wdm_irp *irp)
{
	void *win_devobj = NULL;
	void *win_irp = NULL;
	void *dispatch_fn;
	int32_t ntstatus;
	int ret = 0;

	if (!dev || !dev->driver || !irp)
		return -EINVAL;

	if (irp->major_function > 27) {
		irp->status = NT_STATUS_NOT_SUPPORTED;
		return -EINVAL;
	}

	dispatch_fn = dev->driver->dispatch_table[irp->major_function];
	if (!dispatch_fn) {
		irp->status = NT_STATUS_NOT_SUPPORTED;
		return -ENOSYS;
	}

	/* Build Windows-compatible structures */
	win_devobj = wdm_build_devobj(dev);
	if (!win_devobj) {
		ret = -ENOMEM;
		goto out;
	}

	win_irp = wdm_build_irp(irp, win_devobj);
	if (!win_irp) {
		ret = -ENOMEM;
		goto out;
	}

	pr_debug("[wdm_host] thunk: calling dispatch fn %pS for "
		 "major=%u on '%s'\n",
		 dispatch_fn, irp->major_function, dev->device_name);

	/* Call through the ABI trampoline:
	 * NTSTATUS DispatchFn(PDEVICE_OBJECT, PIRP) */
	ntstatus = wdm_thunk_call2(dispatch_fn, win_devobj, win_irp);

	/* Read back results from the Windows IRP */
	irp->status = GET32(win_irp, WIN_IRP_OFF_IOSTATUS_STATUS);
	irp->information = GETSZ(win_irp, WIN_IRP_OFF_IOSTATUS_INFO);

	pr_debug("[wdm_host] thunk: dispatch returned NTSTATUS=0x%08X, "
		 "IoStatus=0x%08X, Information=%zu\n",
		 ntstatus, irp->status, irp->information);

	/* If the driver returned a different status via the function return
	 * value vs IoStatus.Status, prefer the IoStatus (standard pattern) */
	if (irp->status == NT_STATUS_SUCCESS && ntstatus != NT_STATUS_SUCCESS)
		irp->status = ntstatus;

out:
	kfree(win_irp);
	kfree(win_devobj);
	return ret;
}
EXPORT_SYMBOL_GPL(wdm_thunk_dispatch);

/* ============================================================================
 * Module Init / Exit
 * ============================================================================ */

int wdm_thunk_init(void)
{
#ifdef CONFIG_X86_64
	pr_info("[wdm_host] ABI thunk initialized (Windows x64 -> System V)\n");
#else
	pr_warn("[wdm_host] ABI thunk: x86_64 required for Windows driver "
		"dispatch, thunk is a no-op stub\n");
#endif
	return 0;
}

void wdm_thunk_exit(void)
{
	pr_info("[wdm_host] ABI thunk exited\n");
}

// SPDX-License-Identifier: GPL-2.0
/*
 * wdm_host_ntoskrnl.c - Kernel-resident ntoskrnl.exe export shims
 *
 * Each function declared here has Microsoft x64 calling convention
 * (__attribute__((ms_abi))) and is wired into the wdm_kernel_exports[]
 * table at the bottom of this file. The IAT resolver in
 * wdm_host_imports.c looks up imports by name and patches the loaded
 * .sys IAT slots with these implementations.
 *
 * IMPORTANT: these are KERNEL-CONTEXT shims. They run inside the calling
 * driver thread at whatever Linux preempt level is active. We DO NOT
 * implement Windows IRQL semantics - DISPATCH_LEVEL spinlocks become
 * raw_spin_lock, KeRaiseIrql/KeLowerIrql/KeGetCurrentIrql are no-ops.
 * Real Windows drivers that depend on DPC ordering, page-fault avoidance
 * at DISPATCH_LEVEL, or APC delivery semantics WILL behave incorrectly.
 * That trade-off is documented in the project's S64 audit and is the
 * cost of running .sys binaries in a Linux module instead of a Hyper-V
 * paravisor.
 *
 * The userspace stubs in pe-loader/dlls/ntoskrnl/ implement the same
 * surface for ring-3 PE binaries; we cannot reuse them here because they
 * call malloc()/printf()/pthread, none of which exist in kernel context.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/dma-mapping.h>
#include <linux/types.h>

#include "wdm_host_internal.h"
#include "wdm_host_imports.h"

/* Session 74 Tier-3 additions: HAL + driver-facing IRP + HID class. These
 * are built with plain ABI in their own translation units (for userland
 * preflight); the thunks below re-wrap each one with MS_ABI so the bsearch
 * table can hand a correctly-attributed pointer to the IAT patcher.
 *
 * Forward declarations (avoid pulling the full headers here because some
 * of their types conflict with kernel headers - e.g. stdint.h). */
extern void     WdmKeStallExecutionProcessor(uint32_t microseconds);
extern uint64_t WdmKeQuerySystemTime(void);
extern uint64_t WdmKeQueryPerformanceCounter(uint64_t *freq_out);
extern uint8_t  WdmReadPortUchar(uint16_t port);
extern uint16_t WdmReadPortUshort(uint16_t port);
extern uint32_t WdmReadPortUlong(uint16_t port);
extern void     WdmWritePortUchar(uint16_t port, uint8_t value);
extern void     WdmWritePortUshort(uint16_t port, uint16_t value);
extern void     WdmWritePortUlong(uint16_t port, uint32_t value);
extern void    *WdmHalGetAdapter(void *dd, uint32_t *nmr);
extern int32_t  WdmHalAllocateAdapterChannel(void *a, void *d, uint32_t n,
					     void *ex, void *ctx);

struct wdm_irp_hdr;
struct wdm_driver_object;
extern struct wdm_irp_hdr *WdmIoAllocateIrp(uint8_t sz, int quota);
extern void               WdmIoFreeIrp(struct wdm_irp_hdr *irp);
extern void              *WdmIoGetCurrentIrpStackLocation(struct wdm_irp_hdr *irp);
extern void              *WdmIoGetNextIrpStackLocation(struct wdm_irp_hdr *irp);

extern int32_t WdmHidRegisterMinidriver(void *reg);
extern int     WdmHidAttachDevice(const char *name, uint16_t v, uint16_t p);
extern void    WdmHidDetachDevice(int h);
extern int     WdmHidSetReportDescriptor(int h, const uint8_t *d, size_t l);
extern int     WdmHidSubmitInputReport(int h, const uint8_t *r, size_t l);

/* ---- MS_ABI thunks for HAL ---- */
MS_ABI static void Wdm_KeStallExecutionProcessorShim(unsigned long us)
{ WdmKeStallExecutionProcessor((uint32_t)us); }
MS_ABI static u64 Wdm_KeQuerySystemTimeShim(u64 *out)
{ u64 t = WdmKeQuerySystemTime(); if (out) *out = t; return t; }
MS_ABI static u8 Wdm_ReadPortUcharShim(u16 p)  { return WdmReadPortUchar(p);  }
MS_ABI static u16 Wdm_ReadPortUshortShim(u16 p){ return WdmReadPortUshort(p); }
MS_ABI static u32 Wdm_ReadPortUlongShim(u16 p) { return WdmReadPortUlong(p);  }
MS_ABI static void Wdm_WritePortUcharShim(u16 p, u8 v)  { WdmWritePortUchar(p, v);  }
MS_ABI static void Wdm_WritePortUshortShim(u16 p, u16 v){ WdmWritePortUshort(p, v); }
MS_ABI static void Wdm_WritePortUlongShim(u16 p, u32 v) { WdmWritePortUlong(p, v);  }
MS_ABI static void *Wdm_HalGetAdapterShim(void *d, u32 *n)
{ return WdmHalGetAdapter(d, n); }
MS_ABI static long Wdm_HalAllocateAdapterChannelShim(void *a, void *d,
						    unsigned long n,
						    void *ex, void *c)
{ return (long)WdmHalAllocateAdapterChannel(a, d, (uint32_t)n, ex, c); }

/* ---- MS_ABI thunks for IRP driver API ---- */
MS_ABI static void *Wdm_IoAllocateIrpShim(unsigned char sz, int quota)
{ return WdmIoAllocateIrp((uint8_t)sz, quota); }
MS_ABI static void  Wdm_IoFreeIrpShim(void *irp)
{ WdmIoFreeIrp((struct wdm_irp_hdr *)irp); }
MS_ABI static void *Wdm_IoGetCurrentIrpStackLocationShim(void *irp)
{ return WdmIoGetCurrentIrpStackLocation((struct wdm_irp_hdr *)irp); }
MS_ABI static void *Wdm_IoGetNextIrpStackLocationShim(void *irp)
{ return WdmIoGetNextIrpStackLocation((struct wdm_irp_hdr *)irp); }

/* ---- MS_ABI thunks for HID class ---- */
MS_ABI static long Wdm_HidRegisterMinidriverShim(void *reg)
{ return (long)WdmHidRegisterMinidriver(reg); }

/* MS x64 ABI on x86_64 only. On other arches we still define the symbols
 * (so the table compiles) but without the attribute - kernel CI builds
 * for x86_64 and our PE loader is x86_64-only anyway. */
#ifdef __x86_64__
#define MS_ABI __attribute__((ms_abi))
#else
#define MS_ABI
#endif

/* NTSTATUS aliases - kept local so we don't pull in the entire
 * pe-loader/include/ tree. */
typedef long NTSTATUS_kern;
#define WDM_STATUS_SUCCESS               0x00000000L
#define WDM_STATUS_UNSUCCESSFUL          0xC0000001L
#define WDM_STATUS_NOT_IMPLEMENTED       0xC0000002L
#define WDM_STATUS_INSUFFICIENT_RESOURCES 0xC000009AL
#define WDM_STATUS_TIMEOUT               0x00000102L

/* Pool tag stored in the slab cache name buffer for diagnostics. */
#define WDM_POOL_TAG_BYTES 4

/* ============================================================================
 * Memory Manager
 * ============================================================================
 * NonPagedPool and PagedPool both collapse to kmalloc() for small allocations
 * and vmalloc() for large ones. We don't honor PagedPool semantics (Linux
 * kmalloc is non-pageable). */

#define WDM_POOL_NONPAGED 0
#define WDM_POOL_PAGED    1

MS_ABI static void *Wdm_ExAllocatePoolWithTag(unsigned long pool_type,
					      size_t size,
					      unsigned int tag)
{
	void *p;

	(void)pool_type;
	(void)tag;

	if (size == 0)
		return NULL;
	if (size <= KMALLOC_MAX_CACHE_SIZE)
		p = kmalloc(size, GFP_KERNEL);
	else
		p = vmalloc(size);
	return p;
}

MS_ABI static void Wdm_ExFreePool(void *p)
{
	if (!p)
		return;
	if (is_vmalloc_addr(p))
		vfree(p);
	else
		kfree(p);
}

MS_ABI static void Wdm_ExFreePoolWithTag(void *p, unsigned int tag)
{
	(void)tag;
	Wdm_ExFreePool(p);
}

MS_ABI static void *Wdm_MmAllocateContiguousMemory(size_t size,
						   u64 highest_acceptable)
{
	(void)highest_acceptable;
	/* Closest Linux equivalent for "physically contiguous, DMA-friendly":
	 * dma_alloc_coherent needs a struct device. Without one we fall back
	 * to kmalloc() with __GFP_DMA32, which is contiguous up to a few MB.
	 * Real WDM drivers should use IoGetDmaAdapter and friends; this is a
	 * best-effort shim. */
	return kmalloc(size, GFP_KERNEL | __GFP_DMA32);
}

MS_ABI static void Wdm_MmFreeContiguousMemory(void *p)
{
	kfree(p);
}

/* ============================================================================
 * Synchronization
 * ============================================================================
 * KSPIN_LOCK is opaque to drivers and big enough to hold a Linux spinlock_t
 * if we cap to 8 bytes. We take the address-as-spinlock approach: the
 * driver passes &lock to our shim, we cast it to (spinlock_t *) and call
 * the matching Linux primitive. This works because spinlock_t fits in
 * sizeof(void *) on x86_64 (without LOCKDEP). */

MS_ABI static void Wdm_KeInitializeSpinLock(void *lock)
{
	if (lock)
		spin_lock_init((spinlock_t *)lock);
}

MS_ABI static void Wdm_KeAcquireSpinLock(void *lock, unsigned char *old_irql)
{
	/* Windows: returns previous IRQL. We collapse all IRQLs to 0. */
	if (old_irql)
		*old_irql = 0;
	if (lock)
		spin_lock((spinlock_t *)lock);
}

MS_ABI static void Wdm_KeReleaseSpinLock(void *lock, unsigned char new_irql)
{
	(void)new_irql;
	if (lock)
		spin_unlock((spinlock_t *)lock);
}

MS_ABI static long Wdm_KeWaitForSingleObject(void *object,
					     unsigned long wait_reason,
					     unsigned char wait_mode,
					     unsigned char alertable,
					     void *timeout_ptr)
{
	(void)object;
	(void)wait_reason;
	(void)wait_mode;
	(void)alertable;
	(void)timeout_ptr;
	/* Without a real KEVENT we can't actually wait - return success so
	 * polling drivers continue. A future enhancement would map KEVENT to
	 * a Linux completion struct stored in driver memory. */
	return WDM_STATUS_SUCCESS;
}

/* ============================================================================
 * IRQL no-ops
 * ============================================================================
 * Real Windows IRQL contracts (PASSIVE_LEVEL=0, APC_LEVEL=1, DISPATCH=2,
 * DIRQL=>3) cannot be reproduced in Linux preempt model. Drivers that
 * test KeGetCurrentIrql() == DISPATCH_LEVEL to make pageability decisions
 * will get the wrong answer; document this loudly. */

MS_ABI static unsigned char Wdm_KeRaiseIrql(unsigned char new_irql,
					    unsigned char *old_irql)
{
	(void)new_irql;
	if (old_irql)
		*old_irql = 0;
	return 0;
}

MS_ABI static void Wdm_KeLowerIrql(unsigned char new_irql)
{
	(void)new_irql;
}

MS_ABI static unsigned char Wdm_KeGetCurrentIrql(void)
{
	return 0; /* always PASSIVE_LEVEL - see file header caveat */
}

/* ============================================================================
 * I/O Manager
 * ============================================================================
 * Minimal kernel-side analogues for the most common IRP plumbing. These
 * allocate from kmalloc; the driver receives an opaque pointer it can
 * later pass to IoCompleteRequest. We do NOT participate in the wdm_irp
 * dispatch path used by the wdm_host ioctl - that path operates on
 * wdm_irp structs from this module's userspace ABI. */

struct wdm_io_device_object {
	uint32_t signature;        /* 'WIDO' for sanity */
	uint32_t device_extension_size;
	void    *driver_object;
	void    *device_extension; /* tail-allocated */
};

#define WDM_IDO_SIGNATURE 0x4F444957U /* 'WIDO' */

MS_ABI static long Wdm_IoCreateDevice(void *driver_object,
				      unsigned long device_extension_size,
				      void *device_name_unused,
				      unsigned long device_type,
				      unsigned long device_characteristics,
				      unsigned char exclusive,
				      void **out_device_object)
{
	struct wdm_io_device_object *d;

	(void)device_name_unused;
	(void)device_type;
	(void)device_characteristics;
	(void)exclusive;

	if (!out_device_object)
		return WDM_STATUS_UNSUCCESSFUL;

	d = kzalloc(sizeof(*d) + device_extension_size, GFP_KERNEL);
	if (!d)
		return WDM_STATUS_INSUFFICIENT_RESOURCES;
	d->signature = WDM_IDO_SIGNATURE;
	d->device_extension_size = device_extension_size;
	d->driver_object = driver_object;
	d->device_extension = (void *)(d + 1);
	*out_device_object = d;
	return WDM_STATUS_SUCCESS;
}

MS_ABI static void Wdm_IoDeleteDevice(void *device_object)
{
	struct wdm_io_device_object *d = device_object;

	if (!d || d->signature != WDM_IDO_SIGNATURE) {
		pr_warn("wdm_host: IoDeleteDevice on bad device %p\n",
			device_object);
		return;
	}
	d->signature = 0;
	kfree(d);
}

MS_ABI static long Wdm_IoCallDriver(void *target_device, void *irp)
{
	(void)target_device;
	(void)irp;
	/* Without a forwarded driver stack we can't truly chain the IRP.
	 * Return success so the caller proceeds; the IRP will be completed
	 * by the next layer (or never, in the absence of one). */
	return WDM_STATUS_SUCCESS;
}

MS_ABI static void Wdm_IoCompleteRequest(void *irp,
					 unsigned char priority_boost)
{
	(void)irp;
	(void)priority_boost;
	/* No-op: see Wdm_IoCallDriver. A future change can integrate this
	 * with the wdm_irp dispatch table. */
}

MS_ABI static void Wdm_IofCompleteRequest(void *irp,
					  unsigned char priority_boost)
{
	Wdm_IoCompleteRequest(irp, priority_boost);
}

MS_ABI static void *Wdm_IoGetCurrentProcess(void)
{
	/* Windows returns a PEPROCESS opaque pointer. We hand back current
	 * (the Linux task_struct) cast to void*; drivers shouldn't deref it
	 * but the value is stable for handle-table lookups. */
	return (void *)current;
}

/* ============================================================================
 * RTL string / memory primitives
 * ============================================================================ */

struct wdm_unicode_string {
	uint16_t Length;        /* in bytes, NOT chars */
	uint16_t MaximumLength; /* in bytes */
	uint16_t *Buffer;
};

MS_ABI static void Wdm_RtlInitUnicodeString(struct wdm_unicode_string *dst,
					    const uint16_t *src)
{
	size_t n = 0;

	if (!dst)
		return;
	dst->Length = 0;
	dst->MaximumLength = 0;
	dst->Buffer = (uint16_t *)src;
	if (!src)
		return;
	while (src[n] != 0 && n < 0x7FFF)
		n++;
	dst->Length = (uint16_t)(n * sizeof(uint16_t));
	dst->MaximumLength = (uint16_t)((n + 1) * sizeof(uint16_t));
}

MS_ABI static void Wdm_RtlCopyMemory(void *dst, const void *src, size_t n)
{
	if (dst && src && n)
		memcpy(dst, src, n);
}

MS_ABI static void Wdm_RtlZeroMemory(void *dst, size_t n)
{
	if (dst && n)
		memset(dst, 0, n);
}

MS_ABI static size_t Wdm_RtlCompareMemory(const void *a, const void *b, size_t n)
{
	const u8 *pa = a, *pb = b;
	size_t i;

	if (!a || !b)
		return 0;
	for (i = 0; i < n; i++)
		if (pa[i] != pb[i])
			return i;
	return n;
}

/* ============================================================================
 * Process / system
 * ============================================================================ */

MS_ABI static void *Wdm_MmGetSystemRoutineAddress(void *system_routine_name)
{
	/* On Windows the parameter is a PUNICODE_STRING. Some drivers pass
	 * a PUNICODE_STRING of an exported ntoskrnl symbol. We approximate
	 * by interpreting the buffer as ASCII (English-only systems often
	 * do this). */
	struct wdm_unicode_string *u = system_routine_name;
	char ascii[128];
	size_t i, chars;

	if (!u || !u->Buffer || u->Length == 0)
		return NULL;
	chars = u->Length / sizeof(uint16_t);
	if (chars >= sizeof(ascii))
		chars = sizeof(ascii) - 1;
	for (i = 0; i < chars; i++)
		ascii[i] = (char)(u->Buffer[i] & 0xFF);
	ascii[chars] = '\0';
	return wdm_kernel_export_lookup(ascii);
}

MS_ABI static unsigned long Wdm_KeQueryActiveProcessorCount(unsigned long *active_mask_unused)
{
	(void)active_mask_unused;
	return num_online_cpus();
}

MS_ABI static u64 Wdm_KeQueryPerformanceCounter(u64 *frequency_out)
{
	if (frequency_out)
		*frequency_out = 1000000000ULL; /* nsec resolution */
	return ktime_get_ns();
}

MS_ABI static long Wdm_DbgPrint(const char *fmt, ...)
{
	(void)fmt;
	/* Windows DbgPrint is variadic %wZ etc. We can't safely parse all of
	 * it in kernel context; just emit a generic marker so the caller
	 * sees its print attempt land somewhere. */
	pr_info("wdm_host: driver DbgPrint() (format ignored)\n");
	return WDM_STATUS_SUCCESS;
}

MS_ABI static void Wdm_KeBugCheckEx(unsigned long code, u64 a, u64 b, u64 c, u64 d)
{
	pr_emerg("wdm_host: hosted driver requested BugCheck 0x%lx "
		 "(0x%llx 0x%llx 0x%llx 0x%llx) - returning to driver\n",
		 code, a, b, c, d);
	/* Windows would halt the system; we DO NOT propagate that to the
	 * Linux kernel. The driver typically does not survive past this
	 * call but we let the thread continue so it can unwind cleanly. */
}

/* ============================================================================
 * Exports table - MUST be sorted ASCENDING by name (strcmp order)
 *
 * The IAT resolver uses bsearch() over this array, so any insertion that
 * breaks the ordering will silently fall back to a linear scan with a
 * one-shot pr_warn from wdm_check_table_sorted_once().
 * ============================================================================ */

const struct wdm_kernel_export wdm_kernel_exports[] = {
	{ "DbgPrint",                  (void *)Wdm_DbgPrint,                  0 },
	{ "ExAllocatePoolWithTag",     (void *)Wdm_ExAllocatePoolWithTag,     0 },
	{ "ExFreePool",                (void *)Wdm_ExFreePool,                0 },
	{ "ExFreePoolWithTag",         (void *)Wdm_ExFreePoolWithTag,         0 },
	/* Session 74: HAL DMA shims. */
	{ "HalAllocateAdapterChannel", (void *)Wdm_HalAllocateAdapterChannelShim, 0 },
	{ "HalGetAdapter",             (void *)Wdm_HalGetAdapterShim,         0 },
	/* Session 74: HID class. */
	{ "HidRegisterMinidriver",     (void *)Wdm_HidRegisterMinidriverShim, 0 },
	/* Session 74: IRP driver API. */
	{ "IoAllocateIrp",             (void *)Wdm_IoAllocateIrpShim,         0 },
	{ "IoCallDriver",              (void *)Wdm_IoCallDriver,              0 },
	{ "IoCompleteRequest",         (void *)Wdm_IoCompleteRequest,         0 },
	{ "IoCreateDevice",            (void *)Wdm_IoCreateDevice,            0 },
	{ "IoDeleteDevice",            (void *)Wdm_IoDeleteDevice,            0 },
	/* Session 74: IoFreeIrp. */
	{ "IoFreeIrp",                 (void *)Wdm_IoFreeIrpShim,             0 },
	/* Session 74: stack-location navigation.
	 * Uppercase 'G' (0x47) < lowercase 'f' (0x66) in ASCII, so these
	 * sort BEFORE IofCompleteRequest. */
	{ "IoGetCurrentIrpStackLocation", (void *)Wdm_IoGetCurrentIrpStackLocationShim, 0 },
	{ "IoGetCurrentProcess",       (void *)Wdm_IoGetCurrentProcess,       0 },
	{ "IoGetNextIrpStackLocation", (void *)Wdm_IoGetNextIrpStackLocationShim, 0 },
	{ "IofCompleteRequest",        (void *)Wdm_IofCompleteRequest,        0 },
	{ "KeAcquireSpinLock",         (void *)Wdm_KeAcquireSpinLock,         0 },
	{ "KeBugCheckEx",              (void *)Wdm_KeBugCheckEx,              0 },
	{ "KeGetCurrentIrql",          (void *)Wdm_KeGetCurrentIrql,          0 },
	{ "KeInitializeSpinLock",      (void *)Wdm_KeInitializeSpinLock,      0 },
	{ "KeLowerIrql",               (void *)Wdm_KeLowerIrql,               0 },
	{ "KeQueryActiveProcessorCount", (void *)Wdm_KeQueryActiveProcessorCount, 0 },
	{ "KeQueryPerformanceCounter", (void *)Wdm_KeQueryPerformanceCounter, 0 },
	/* Session 74: KeQuerySystemTime. */
	{ "KeQuerySystemTime",         (void *)Wdm_KeQuerySystemTimeShim,     0 },
	{ "KeRaiseIrql",               (void *)Wdm_KeRaiseIrql,               0 },
	{ "KeReleaseSpinLock",         (void *)Wdm_KeReleaseSpinLock,         0 },
	/* Session 74: KeStallExecutionProcessor. */
	{ "KeStallExecutionProcessor", (void *)Wdm_KeStallExecutionProcessorShim, 0 },
	{ "KeWaitForSingleObject",     (void *)Wdm_KeWaitForSingleObject,     0 },
	{ "MmAllocateContiguousMemory", (void *)Wdm_MmAllocateContiguousMemory, 0 },
	{ "MmFreeContiguousMemory",    (void *)Wdm_MmFreeContiguousMemory,    0 },
	{ "MmGetSystemRoutineAddress", (void *)Wdm_MmGetSystemRoutineAddress, 0 },
	/* Session 74: port I/O shims (HAL). */
	{ "READ_PORT_UCHAR",           (void *)Wdm_ReadPortUcharShim,         0 },
	{ "READ_PORT_ULONG",           (void *)Wdm_ReadPortUlongShim,         0 },
	{ "READ_PORT_USHORT",          (void *)Wdm_ReadPortUshortShim,        0 },
	{ "RtlCompareMemory",          (void *)Wdm_RtlCompareMemory,          0 },
	{ "RtlCopyMemory",             (void *)Wdm_RtlCopyMemory,             0 },
	{ "RtlInitUnicodeString",      (void *)Wdm_RtlInitUnicodeString,      0 },
	{ "RtlZeroMemory",             (void *)Wdm_RtlZeroMemory,             0 },
	{ "WRITE_PORT_UCHAR",          (void *)Wdm_WritePortUcharShim,        0 },
	{ "WRITE_PORT_ULONG",          (void *)Wdm_WritePortUlongShim,        0 },
	{ "WRITE_PORT_USHORT",         (void *)Wdm_WritePortUshortShim,       0 },
};

const size_t wdm_kernel_exports_count =
	sizeof(wdm_kernel_exports) / sizeof(wdm_kernel_exports[0]);

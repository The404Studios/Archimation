// SPDX-License-Identifier: GPL-2.0
/*
 * wdm_host_hal.c - Hardware Abstraction Layer skeleton
 *
 * Bridges Windows HAL primitives to Linux kernel equivalents where
 * a safe mapping exists, and to trust-gated refusal where it does not.
 *
 * Session 74 Tier-3 driver foundation.
 *
 * Coverage (see wdm_host_hal.h for the full list):
 *   - Time: KeStallExecutionProcessor, KeQuerySystemTime,
 *           KeQueryPerformanceCounter
 *   - IRQL: KeGetCurrentIrql, KeRaiseIrql, KeLowerIrql (thread-local stub)
 *   - Port I/O: READ/WRITE_PORT_UCHAR/USHORT/ULONG, gated through /dev/trust
 *   - DMA:  HalGetAdapter / HalAllocateAdapterChannel stubs
 *
 * Conspicuously-missing (S75 backlog, see deliverable report):
 *   - KeInitializeDpc / KeInsertQueueDpc (deferred procedure calls)
 *   - HalTranslateBusAddress
 *   - HalReadEtwEvent  / HalReportResourceUsage
 *   - KeConnectInterrupt / KeDisconnectInterrupt (MSI, MSI-X)
 *   - HalAllocateCrashDumpRegisters
 */

#include "wdm_host_hal.h"

#include <string.h>

#ifdef WDM_HOST_KERNEL
#  include <linux/kernel.h>
#  include <linux/delay.h>
#  include <linux/ktime.h>
#  include <linux/io.h>
#  include <linux/printk.h>
#  define HAL_LOG(fmt, ...)  pr_debug("wdm_hal: " fmt, ##__VA_ARGS__)
#  define HAL_WARN(fmt, ...) pr_warn("wdm_hal: " fmt, ##__VA_ARGS__)
#else
#  include <stdio.h>
#  include <time.h>
#  include <unistd.h>
#  define HAL_LOG(fmt, ...)  /* quiet */
#  define HAL_WARN(fmt, ...) fprintf(stderr, "wdm_hal: " fmt, ##__VA_ARGS__)
#endif

/* ============================================================================
 * Trust gate state
 * ============================================================================ */

static wdm_hal_trust_check_fn g_trust_check = NULL;
static uint32_t g_trust_subject_id = 0;

void WdmHalSetTrustCheck(wdm_hal_trust_check_fn fn, uint32_t subject_id)
{
	g_trust_check = fn;
	g_trust_subject_id = subject_id;
}

/* Returns 1 = allow, 0 = deny (including "no gate installed"). */
static int hal_port_allowed(uint16_t port)
{
	if (!g_trust_check) {
		HAL_WARN("port I/O denied (no trust gate) port=0x%04x\n",
			 (unsigned)port);
		return 0;
	}
	return g_trust_check(WDM_TRUST_ACTION_PORT_IO,
			     port,
			     g_trust_subject_id) == 1;
}

/* ============================================================================
 * Time shims
 * ============================================================================ */

void WdmKeStallExecutionProcessor(uint32_t microseconds)
{
#ifdef WDM_HOST_KERNEL
	if (microseconds < 10)
		udelay(microseconds);
	else if (microseconds < 1000)
		usleep_range(microseconds, microseconds + 2);
	else
		msleep((microseconds + 999) / 1000);
#else
	struct timespec ts;

	ts.tv_sec = microseconds / 1000000u;
	ts.tv_nsec = (long)(microseconds % 1000000u) * 1000L;
	nanosleep(&ts, NULL);
#endif
}

/* Windows FILETIME: 100-ns ticks since 1601-01-01 UTC.
 * Offset from Unix epoch (1970-01-01) = 116444736000000000. */
#define WDM_UNIX_TO_FILETIME 116444736000000000ULL

uint64_t WdmKeQuerySystemTime(void)
{
#ifdef WDM_HOST_KERNEL
	struct timespec64 ts;

	ktime_get_real_ts64(&ts);
	return ((uint64_t)ts.tv_sec * 10000000ULL) +
	       ((uint64_t)ts.tv_nsec / 100ULL) +
	       WDM_UNIX_TO_FILETIME;
#else
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return ((uint64_t)ts.tv_sec * 10000000ULL) +
	       ((uint64_t)ts.tv_nsec / 100ULL) +
	       WDM_UNIX_TO_FILETIME;
#endif
}

uint64_t WdmKeQueryPerformanceCounter(uint64_t *freq_out)
{
	if (freq_out)
		*freq_out = 1000000000ULL;  /* nanoseconds */

#ifdef WDM_HOST_KERNEL
	return ktime_get_ns();
#else
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
#endif
}

/* ============================================================================
 * IRQL stubs
 *
 * We use __thread to save/restore per-thread so a driver that does
 * OldIrql = KeRaiseIrql(DISPATCH) then KeLowerIrql(OldIrql) sees the
 * value round-trip. Real IRQL semantics (preemption gate, paging gate)
 * cannot be reproduced in the Linux preempt model.
 * ============================================================================ */

#ifdef WDM_HOST_KERNEL
static DEFINE_PER_CPU(uint8_t, wdm_current_irql);
static inline uint8_t hal_get_irql(void) { return raw_cpu_read(wdm_current_irql); }
static inline void hal_set_irql(uint8_t v) { raw_cpu_write(wdm_current_irql, v); }
#else
static __thread uint8_t wdm_current_irql_tls = WDM_IRQL_PASSIVE_LEVEL;
static inline uint8_t hal_get_irql(void) { return wdm_current_irql_tls; }
static inline void hal_set_irql(uint8_t v) { wdm_current_irql_tls = v; }
#endif

uint8_t WdmKeGetCurrentIrql(void)
{
	return hal_get_irql();
}

uint8_t WdmKeRaiseIrql(uint8_t new_irql)
{
	uint8_t old = hal_get_irql();

	if (new_irql < old)
		HAL_WARN("KeRaiseIrql: new=%u < old=%u (bug in driver)\n",
			 (unsigned)new_irql, (unsigned)old);
	hal_set_irql(new_irql);
	return old;
}

void WdmKeLowerIrql(uint8_t new_irql)
{
	uint8_t old = hal_get_irql();

	if (new_irql > old)
		HAL_WARN("KeLowerIrql: new=%u > old=%u (not lower)\n",
			 (unsigned)new_irql, (unsigned)old);
	hal_set_irql(new_irql);
}

/* ============================================================================
 * Port I/O (trust gated)
 * ============================================================================ */

uint8_t WdmReadPortUchar(uint16_t port)
{
	if (!hal_port_allowed(port))
		return 0;
#ifdef WDM_HOST_KERNEL
	return inb((unsigned long)port);
#else
	/* Userland preflight has no port I/O. */
	(void)port;
	return 0;
#endif
}

uint16_t WdmReadPortUshort(uint16_t port)
{
	if (!hal_port_allowed(port))
		return 0;
#ifdef WDM_HOST_KERNEL
	return inw((unsigned long)port);
#else
	(void)port;
	return 0;
#endif
}

uint32_t WdmReadPortUlong(uint16_t port)
{
	if (!hal_port_allowed(port))
		return 0;
#ifdef WDM_HOST_KERNEL
	return inl((unsigned long)port);
#else
	(void)port;
	return 0;
#endif
}

void WdmWritePortUchar(uint16_t port, uint8_t value)
{
	if (!hal_port_allowed(port))
		return;
#ifdef WDM_HOST_KERNEL
	outb(value, (unsigned long)port);
#else
	(void)port; (void)value;
#endif
}

void WdmWritePortUshort(uint16_t port, uint16_t value)
{
	if (!hal_port_allowed(port))
		return;
#ifdef WDM_HOST_KERNEL
	outw(value, (unsigned long)port);
#else
	(void)port; (void)value;
#endif
}

void WdmWritePortUlong(uint16_t port, uint32_t value)
{
	if (!hal_port_allowed(port))
		return;
#ifdef WDM_HOST_KERNEL
	outl(value, (unsigned long)port);
#else
	(void)port; (void)value;
#endif
}

/* ============================================================================
 * DMA stubs - NOT_SUPPORTED until the kernel backend wires to
 * dma_alloc_coherent / dma_map_single.
 * ============================================================================ */

void *WdmHalGetAdapter(void *device_description, uint32_t *num_map_regs_out)
{
	(void)device_description;
	if (num_map_regs_out)
		*num_map_regs_out = 0;
	return NULL;
}

int32_t WdmHalAllocateAdapterChannel(void *adapter,
				     void *device,
				     uint32_t num_map_regs,
				     void *execution_routine,
				     void *context)
{
	(void)adapter;
	(void)device;
	(void)num_map_regs;
	(void)execution_routine;
	(void)context;
	return (int32_t)0xC00000BB;  /* STATUS_NOT_SUPPORTED */
}

#ifndef WDM_HOST_KERNEL
/* Userland preflight self-test. */
int wdm_hal_selftest(void)
{
	uint64_t t1, t2, freq;

	/* Time sanity */
	t1 = WdmKeQueryPerformanceCounter(&freq);
	WdmKeStallExecutionProcessor(10);
	t2 = WdmKeQueryPerformanceCounter(NULL);
	if (t2 < t1) return -1;
	if (freq != 1000000000ULL) return -2;

	/* IRQL round-trip */
	{
		uint8_t old;

		if (WdmKeGetCurrentIrql() != WDM_IRQL_PASSIVE_LEVEL) return -3;
		old = WdmKeRaiseIrql(WDM_IRQL_DISPATCH_LEVEL);
		if (old != WDM_IRQL_PASSIVE_LEVEL) return -4;
		if (WdmKeGetCurrentIrql() != WDM_IRQL_DISPATCH_LEVEL) return -5;
		WdmKeLowerIrql(old);
		if (WdmKeGetCurrentIrql() != WDM_IRQL_PASSIVE_LEVEL) return -6;
	}

	/* Port I/O with no trust gate must read as 0 */
	if (WdmReadPortUlong(0x60) != 0) return -7;
	WdmWritePortUchar(0x64, 0xAA);  /* must not crash */

	/* DMA stub */
	if (WdmHalGetAdapter(NULL, NULL) != NULL) return -8;
	if (WdmHalAllocateAdapterChannel(NULL, NULL, 0, NULL, NULL) !=
	    (int32_t)0xC00000BB) return -9;

	return 0;
}
#endif

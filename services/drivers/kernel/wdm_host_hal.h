/* SPDX-License-Identifier: GPL-2.0 */
/*
 * wdm_host_hal.h - Hardware Abstraction Layer skeleton for hosted drivers
 *
 * Windows drivers call into HAL (hal.dll) for timing, IRQL management,
 * port I/O, and DMA adapter acquisition. We ship best-effort shims
 * that either map to equivalent Linux primitives (KeStallExecutionProcessor
 * -> usleep_range) or fall back to a safe refusal gated through /dev/trust.
 *
 * Port I/O is trust-gated: TRUST_ACTION_PORT_IO must authorize each port
 * read/write or the call is no-op'd. This is the anchor point that keeps
 * hosted drivers from poking devices their subject does not own.
 *
 * Userland preflight: compiles standalone via WDM_HOST_KERNEL guard.
 * Session 74 Tier-3.
 */

#ifndef WDM_HOST_HAL_H
#define WDM_HOST_HAL_H

#include <stdint.h>
#include <stddef.h>

/* IRQL contract values (Windows). */
#define WDM_IRQL_PASSIVE_LEVEL   0
#define WDM_IRQL_APC_LEVEL       1
#define WDM_IRQL_DISPATCH_LEVEL  2
#define WDM_IRQL_DIRQL_MIN       3

/* Trust-gate action identifier (must match trust/include/trust_uapi.h). */
#define WDM_TRUST_ACTION_PORT_IO 0x00000131u

/* HAL-time shims. */
void     WdmKeStallExecutionProcessor(uint32_t microseconds);
uint64_t WdmKeQuerySystemTime(void);
uint64_t WdmKeQueryPerformanceCounter(uint64_t *freq_out);

/* IRQL shims. Linux has no IRQL; we thread-local a "current" level so
 * drivers that round-trip through KeRaise/KeLower observe consistent
 * save/restore semantics. We DO NOT actually disable preemption, so
 * drivers that rely on DISPATCH_LEVEL to skip pageable locks are
 * incorrect under this shim - documented loudly in wdm_host_ntoskrnl.c. */
uint8_t WdmKeGetCurrentIrql(void);
uint8_t WdmKeRaiseIrql(uint8_t new_irql);
void    WdmKeLowerIrql(uint8_t new_irql);

/* Port I/O shims. Every call is authz-checked through /dev/trust; a
 * denied call returns 0 (for reads) or is silently dropped (for writes)
 * and is logged once per port. */
uint8_t  WdmReadPortUchar(uint16_t port);
uint16_t WdmReadPortUshort(uint16_t port);
uint32_t WdmReadPortUlong(uint16_t port);
void     WdmWritePortUchar(uint16_t port, uint8_t  value);
void     WdmWritePortUshort(uint16_t port, uint16_t value);
void     WdmWritePortUlong(uint16_t port, uint32_t value);

/* DMA adapter stubs - return NULL / NOT_SUPPORTED until wired to
 * dma_alloc_coherent in the kernel backend. */
void    *WdmHalGetAdapter(void *device_description, uint32_t *num_map_regs_out);
int32_t  WdmHalAllocateAdapterChannel(void *adapter_object,
				      void *device_object,
				      uint32_t number_of_map_registers,
				      void *execution_routine,
				      void *context);

/* Install the trust-gate function pointer. When NULL, all port I/O
 * is denied (safe default). Invoked by the wdm_host module init with
 * a function that marshals to /dev/trust TRUST_IOC_AUTHZ_CHECK. */
typedef int (*wdm_hal_trust_check_fn)(uint32_t action,
				      uint16_t port,
				      uint32_t subject_id);
void WdmHalSetTrustCheck(wdm_hal_trust_check_fn fn, uint32_t subject_id);

#endif /* WDM_HOST_HAL_H */

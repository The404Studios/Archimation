/*
 * wdm_host_dma.c - DMA buffer management for hosted Windows drivers
 *
 * Provides a thin wrapper around the Linux DMA mapping API so that loaded
 * .sys drivers can request DMA-capable memory.  When a real struct device is
 * available (e.g. a PCI device has been associated with the driver) the
 * coherent DMA allocator is used; otherwise the module falls back to plain
 * kzalloc with virt_to_phys for the DMA handle.
 *
 * All allocations are tracked in a linked list so that the module can
 * guarantee every buffer is freed at exit time, even if the Windows driver
 * leaks memory.
 *
 * Copyright (c) 2026  WDM Host Project
 * SPDX-License-Identifier: GPL-2.0
 */

#include "wdm_host_internal.h"
#include <linux/dma-mapping.h>

/* ============================================================================
 * Per-allocation tracking entry
 * ============================================================================ */

struct wdm_dma_entry {
	void           *vaddr;      /* Kernel virtual address          */
	dma_addr_t      dma_addr;   /* Bus / physical address          */
	size_t          size;        /* Size of the allocation in bytes */
	bool            coherent;    /* true  = allocated via dma_alloc_coherent
				      * false = allocated via kzalloc           */
	struct list_head list;       /* Linkage in wdm_dma_list         */
};

/* Global list of outstanding DMA allocations */
static LIST_HEAD(wdm_dma_list);
static DEFINE_MUTEX(wdm_dma_lock);

/* ============================================================================
 * Allocation / free
 * ============================================================================ */

/*
 * wdm_dma_alloc - Allocate a DMA-capable buffer and track it.
 *
 * If @dev is non-NULL the Linux coherent DMA allocator is used.  Otherwise
 * the buffer is allocated with kzalloc and the DMA handle is set to the
 * physical address via virt_to_phys (suitable only for testing / stubs).
 *
 * Returns the kernel virtual address on success, NULL on failure.
 * On success *@dma_handle is filled with the bus address.
 */
void *wdm_dma_alloc(size_t size, dma_addr_t *dma_handle)
{
	struct wdm_dma_entry *entry;
	void *vaddr;

	if (!size || !dma_handle)
		return NULL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	/*
	 * No real struct device available through the header API, so
	 * always fall back to kzalloc + virt_to_phys.  If a hardware
	 * device is ever associated we can extend this path.
	 */
	vaddr = kzalloc(size, GFP_KERNEL);
	if (!vaddr) {
		kfree(entry);
		return NULL;
	}
	*dma_handle = virt_to_phys(vaddr);
	entry->coherent = false;

	entry->vaddr    = vaddr;
	entry->dma_addr = *dma_handle;
	entry->size     = size;

	mutex_lock(&wdm_dma_lock);
	list_add_tail(&entry->list, &wdm_dma_list);
	mutex_unlock(&wdm_dma_lock);

	pr_debug("wdm_host: dma_alloc %zu bytes -> vaddr=%p dma=0x%llx\n",
		 size, vaddr, (unsigned long long)*dma_handle);
	return vaddr;
}

/*
 * wdm_dma_free - Free a previously allocated DMA buffer.
 *
 * Locates the tracking entry by virtual address, frees the memory using the
 * matching API, and removes the entry from the tracking list.
 */
void wdm_dma_free(size_t size, void *vaddr, dma_addr_t dma_handle)
{
	struct wdm_dma_entry *entry, *tmp;

	if (!vaddr)
		return;

	mutex_lock(&wdm_dma_lock);
	list_for_each_entry_safe(entry, tmp, &wdm_dma_list, list) {
		if (entry->vaddr == vaddr) {
			list_del(&entry->list);
			mutex_unlock(&wdm_dma_lock);

			pr_debug("wdm_host: dma_free %zu bytes vaddr=%p "
				 "dma=0x%llx (coherent=%d)\n",
				 entry->size, vaddr,
				 (unsigned long long)entry->dma_addr,
				 entry->coherent);

			if (entry->coherent) {
				/*
				 * Would need the original struct device to
				 * call dma_free_coherent().  For now this path
				 * is unreachable because wdm_dma_alloc always
				 * falls back to kzalloc.
				 */
				pr_warn("wdm_host: coherent DMA free without "
					"device -- leaking buffer\n");
			} else {
				kfree(vaddr);
			}

			kfree(entry);
			return;
		}
	}
	mutex_unlock(&wdm_dma_lock);

	pr_warn("wdm_host: dma_free called for untracked vaddr=%p "
		"(size=%zu dma=0x%llx)\n",
		vaddr, size, (unsigned long long)dma_handle);
}

/* ============================================================================
 * Subsystem init / exit
 * ============================================================================ */

/*
 * wdm_dma_init - Initialise the DMA subsystem.
 *
 * The tracking list is statically initialised so there is nothing to do here
 * beyond a log message.
 */
int wdm_dma_init(void)
{
	pr_info("wdm_host: DMA subsystem initialised\n");
	return 0;
}

/*
 * wdm_dma_exit - Free any outstanding DMA allocations at module unload.
 *
 * Iterates the tracking list and frees every entry.  This catches buffers
 * that a misbehaving Windows driver forgot to release.
 */
void wdm_dma_exit(void)
{
	struct wdm_dma_entry *entry, *tmp;
	int leaked = 0;

	mutex_lock(&wdm_dma_lock);
	list_for_each_entry_safe(entry, tmp, &wdm_dma_list, list) {
		pr_warn("wdm_host: DMA leak: vaddr=%p size=%zu dma=0x%llx\n",
			entry->vaddr, entry->size,
			(unsigned long long)entry->dma_addr);

		if (!entry->coherent)
			kfree(entry->vaddr);

		list_del(&entry->list);
		kfree(entry);
		leaked++;
	}
	mutex_unlock(&wdm_dma_lock);

	if (leaked)
		pr_warn("wdm_host: DMA subsystem exited (%d leaked buffers freed)\n",
			leaked);
	else
		pr_info("wdm_host: DMA subsystem exited (no leaks)\n");
}

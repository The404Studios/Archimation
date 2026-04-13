/*
 * ndis_stubs.c - Network Driver Interface Specification (NDIS) Stub Implementations
 *
 * Userspace stubs emulating NDIS APIs on Linux. NDIS is the Windows network
 * driver framework used by network-level anti-cheat components (e.g., packet
 * inspection drivers). These stubs provide enough surface area for such drivers
 * to initialize and perform basic operations.
 *
 * Compile with: gcc -c ndis_stubs.c -o ndis_stubs.o -Wall -Wextra
 */

#include "wdm_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Logging
 * ============================================================================ */

#define NDIS_LOG(fmt, ...) \
    fprintf(stderr, "[NDIS_STUB] %s: " fmt "\n", __func__, ##__VA_ARGS__)

/* ============================================================================
 * NDIS Types and Constants
 * ============================================================================ */

/* NDIS status codes (alias NTSTATUS in NDIS 6.x+) */
typedef NTSTATUS NDIS_STATUS;

#define NDIS_STATUS_SUCCESS             STATUS_SUCCESS
#define NDIS_STATUS_FAILURE             STATUS_UNSUCCESSFUL
#define NDIS_STATUS_RESOURCES           STATUS_INSUFFICIENT_RESOURCES
#define NDIS_STATUS_INVALID_PARAMETER   STATUS_INVALID_PARAMETER
#define NDIS_STATUS_NOT_SUPPORTED       STATUS_NOT_SUPPORTED
#define NDIS_STATUS_PENDING             STATUS_PENDING
#define NDIS_STATUS_CLOSING             ((NDIS_STATUS)0xC0010002)
#define NDIS_STATUS_RESET_IN_PROGRESS   ((NDIS_STATUS)0xC001000D)

/* NDIS handle types */
typedef PVOID NDIS_HANDLE;
typedef NDIS_HANDLE *PNDIS_HANDLE;

/* NDIS object header */
typedef struct _NDIS_OBJECT_HEADER {
    UCHAR   Type;
    UCHAR   Revision;
    USHORT  Size;
} NDIS_OBJECT_HEADER, *PNDIS_OBJECT_HEADER;

/* NDIS object header type values */
#define NDIS_OBJECT_TYPE_PROTOCOL_DRIVER_CHARACTERISTICS    0x84
#define NDIS_OBJECT_TYPE_OPEN_PARAMETERS                    0x83
#define NDIS_OBJECT_TYPE_DEFAULT                             0x80

/* ============================================================================
 * NET_BUFFER_LIST and NET_BUFFER (simplified)
 *
 * These are the core NDIS data structures for network packets.
 * Real implementations are complex; these stubs provide the minimal surface.
 * ============================================================================ */

typedef struct _NET_BUFFER {
    struct _NET_BUFFER     *Next;
    MDL                    *CurrentMdl;
    ULONG                   CurrentMdlOffset;
    ULONG                   DataLength;
    MDL                    *MdlChain;
    ULONG                   DataOffset;
    PVOID                   ProtocolReserved[6];
} NET_BUFFER, *PNET_BUFFER;

typedef struct _NET_BUFFER_LIST {
    struct _NET_BUFFER_LIST *Next;
    NET_BUFFER             *FirstNetBuffer;
    PVOID                   Context;
    PVOID                   ParentNetBufferList;
    NDIS_HANDLE             NdisPoolHandle;
    PVOID                   ProtocolReserved[4];
    PVOID                   MiniportReserved[2];
    PVOID                   Scratch;
    NDIS_HANDLE             SourceHandle;
    ULONG                   NblFlags;
    LONG                    ChildRefCount;
    ULONG                   Flags;
    NDIS_STATUS             Status;
} NET_BUFFER_LIST, *PNET_BUFFER_LIST;

/* Send flags */
#define NDIS_SEND_FLAGS_DISPATCH_LEVEL      0x00000001
#define NDIS_SEND_FLAGS_CHECK_FOR_LOOPBACK  0x00000002

/* Return flags */
#define NDIS_RETURN_FLAGS_DISPATCH_LEVEL    0x00000001

/* ============================================================================
 * NDIS Protocol Driver Characteristics (simplified)
 * ============================================================================ */

typedef void (*PROTOCOL_BIND_ADAPTER_HANDLER_EX)(
    NDIS_HANDLE ProtocolDriverContext,
    NDIS_HANDLE BindContext,
    PVOID BindParameters);

typedef NDIS_STATUS (*PROTOCOL_UNBIND_ADAPTER_HANDLER_EX)(
    NDIS_HANDLE UnbindContext,
    NDIS_HANDLE ProtocolBindingContext);

typedef void (*PROTOCOL_OPEN_ADAPTER_COMPLETE_HANDLER_EX)(
    NDIS_HANDLE ProtocolBindingContext,
    NDIS_STATUS Status);

typedef void (*PROTOCOL_CLOSE_ADAPTER_COMPLETE_HANDLER_EX)(
    NDIS_HANDLE ProtocolBindingContext);

typedef void (*PROTOCOL_RECEIVE_NET_BUFFER_LISTS_HANDLER)(
    NDIS_HANDLE ProtocolBindingContext,
    PNET_BUFFER_LIST NetBufferLists,
    ULONG PortNumber,
    ULONG NumberOfNetBufferLists,
    ULONG ReceiveFlags);

typedef void (*PROTOCOL_SEND_NET_BUFFER_LISTS_COMPLETE_HANDLER)(
    NDIS_HANDLE ProtocolBindingContext,
    PNET_BUFFER_LIST NetBufferList,
    ULONG SendCompleteFlags);

typedef void (*PROTOCOL_STATUS_HANDLER_EX)(
    NDIS_HANDLE ProtocolBindingContext,
    PVOID StatusIndication);

typedef struct _NDIS_PROTOCOL_DRIVER_CHARACTERISTICS {
    NDIS_OBJECT_HEADER                              Header;
    UCHAR                                           MajorNdisVersion;
    UCHAR                                           MinorNdisVersion;
    UCHAR                                           MajorDriverVersion;
    UCHAR                                           MinorDriverVersion;
    ULONG                                           Flags;
    UNICODE_STRING                                  Name;
    PROTOCOL_BIND_ADAPTER_HANDLER_EX                BindAdapterHandlerEx;
    PROTOCOL_UNBIND_ADAPTER_HANDLER_EX              UnbindAdapterHandlerEx;
    PROTOCOL_OPEN_ADAPTER_COMPLETE_HANDLER_EX       OpenAdapterCompleteHandlerEx;
    PROTOCOL_CLOSE_ADAPTER_COMPLETE_HANDLER_EX      CloseAdapterCompleteHandlerEx;
    PROTOCOL_RECEIVE_NET_BUFFER_LISTS_HANDLER       ReceiveNetBufferListsHandler;
    PROTOCOL_SEND_NET_BUFFER_LISTS_COMPLETE_HANDLER SendNetBufferListsCompleteHandler;
    PROTOCOL_STATUS_HANDLER_EX                      StatusHandlerEx;
    PVOID                                           OidRequestCompleteHandler;
    PVOID                                           DirectOidRequestCompleteHandler;
    PVOID                                           UninstallHandler;
} NDIS_PROTOCOL_DRIVER_CHARACTERISTICS, *PNDIS_PROTOCOL_DRIVER_CHARACTERISTICS;

/* ============================================================================
 * NDIS Open Parameters (simplified)
 * ============================================================================ */

typedef struct _NDIS_OPEN_PARAMETERS {
    NDIS_OBJECT_HEADER  Header;
    PUNICODE_STRING     AdapterName;
    PVOID               MediumArray;
    ULONG               MediumArraySize;
    PULONG              SelectedMediumIndex;
    PVOID               FrameTypeArray;
    ULONG               FrameTypeArraySize;
} NDIS_OPEN_PARAMETERS, *PNDIS_OPEN_PARAMETERS;

/* ============================================================================
 * NDIS Memory Tag Priority
 * ============================================================================ */

typedef enum _EX_POOL_PRIORITY {
    LowPoolPriority         = 0,
    LowPoolPriorityMustSucceed = 1,
    NormalPoolPriority       = 16,
    NormalPoolPriorityMustSucceed = 17,
    HighPoolPriority         = 32,
    HighPoolPriorityMustSucceed = 33
} EX_POOL_PRIORITY;

/* ============================================================================
 * Internal State Tracking
 * ============================================================================ */

#define MAX_NDIS_PROTOCOLS  8

typedef struct _NDIS_PROTOCOL_ENTRY {
    int                                 in_use;
    NDIS_HANDLE                         handle;
    NDIS_PROTOCOL_DRIVER_CHARACTERISTICS chars;
} NDIS_PROTOCOL_ENTRY;

static NDIS_PROTOCOL_ENTRY g_ndis_protocols[MAX_NDIS_PROTOCOLS] = {{0}};
static uintptr_t g_ndis_next_handle = 0x20000;

static NDIS_HANDLE ndis_alloc_handle(const char *type)
{
    NDIS_HANDLE handle = (PVOID)g_ndis_next_handle;
    g_ndis_next_handle += 0x100;
    NDIS_LOG("Allocated %s handle: %p", type, handle);
    return handle;
}

/* ============================================================================
 * NDIS Protocol Driver Functions
 * ============================================================================ */

/*
 * NdisRegisterProtocolDriver - Registers a protocol driver with NDIS.
 * Anti-cheat network drivers register here to inspect/filter network traffic.
 */
NDIS_STATUS NdisRegisterProtocolDriver(
    PVOID ProtocolDriverContext,
    PNDIS_PROTOCOL_DRIVER_CHARACTERISTICS ProtocolCharacteristics,
    void **NdisProtocolHandle)
{
    int i;

    NDIS_LOG("ProtocolDriverContext=%p", ProtocolDriverContext);

    if (!ProtocolCharacteristics || !NdisProtocolHandle) {
        NDIS_LOG("Invalid parameters");
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    NDIS_LOG("  NDIS Version: %u.%u  Driver Version: %u.%u",
             (unsigned)ProtocolCharacteristics->MajorNdisVersion,
             (unsigned)ProtocolCharacteristics->MinorNdisVersion,
             (unsigned)ProtocolCharacteristics->MajorDriverVersion,
             (unsigned)ProtocolCharacteristics->MinorDriverVersion);

    NDIS_LOG("  BindAdapter=%p UnbindAdapter=%p",
             (void *)(uintptr_t)ProtocolCharacteristics->BindAdapterHandlerEx,
             (void *)(uintptr_t)ProtocolCharacteristics->UnbindAdapterHandlerEx);
    NDIS_LOG("  ReceiveNBL=%p SendComplete=%p",
             (void *)(uintptr_t)ProtocolCharacteristics->ReceiveNetBufferListsHandler,
             (void *)(uintptr_t)ProtocolCharacteristics->SendNetBufferListsCompleteHandler);

    /* Find a free slot */
    for (i = 0; i < MAX_NDIS_PROTOCOLS; i++) {
        if (!g_ndis_protocols[i].in_use) {
            g_ndis_protocols[i].in_use = 1;
            g_ndis_protocols[i].handle = ndis_alloc_handle("NDIS_PROTOCOL");
            memcpy(&g_ndis_protocols[i].chars, ProtocolCharacteristics,
                   sizeof(NDIS_PROTOCOL_DRIVER_CHARACTERISTICS));

            *NdisProtocolHandle = g_ndis_protocols[i].handle;
            NDIS_LOG("  Registered as protocol handle %p in slot %d",
                     g_ndis_protocols[i].handle, i);
            return NDIS_STATUS_SUCCESS;
        }
    }

    NDIS_LOG("  WARNING: Maximum protocol registrations reached");
    return NDIS_STATUS_RESOURCES;
}

/*
 * NdisDeregisterProtocolDriver - Deregisters a previously registered protocol driver.
 */
void NdisDeregisterProtocolDriver(NDIS_HANDLE NdisProtocolHandle)
{
    int i;

    NDIS_LOG("Handle=%p", NdisProtocolHandle);

    for (i = 0; i < MAX_NDIS_PROTOCOLS; i++) {
        if (g_ndis_protocols[i].in_use &&
            g_ndis_protocols[i].handle == NdisProtocolHandle) {
            g_ndis_protocols[i].in_use = 0;
            memset(&g_ndis_protocols[i].chars, 0,
                   sizeof(NDIS_PROTOCOL_DRIVER_CHARACTERISTICS));
            NDIS_LOG("  Deregistered protocol at slot %d", i);
            return;
        }
    }

    NDIS_LOG("  WARNING: Protocol handle not found");
}

/* ============================================================================
 * NDIS Adapter Functions
 * ============================================================================ */

/*
 * NdisOpenAdapterEx - Opens a binding to an underlying miniport adapter.
 * Used by protocol drivers to attach to network adapters for packet inspection.
 */
NDIS_STATUS NdisOpenAdapterEx(
    NDIS_HANDLE NdisProtocolHandle,
    NDIS_HANDLE ProtocolBindingContext,
    PNDIS_OPEN_PARAMETERS OpenParameters,
    NDIS_HANDLE BindContext,
    void **NdisBindingHandle)
{
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    UNREFERENCED_PARAMETER(BindContext);

    NDIS_LOG("ProtocolHandle=%p", NdisProtocolHandle);

    if (!OpenParameters || !NdisBindingHandle) {
        NDIS_LOG("Invalid parameters");
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    if (OpenParameters->AdapterName) {
        NDIS_LOG("  AdapterName length=%u", (unsigned)OpenParameters->AdapterName->Length);
    }

    *NdisBindingHandle = ndis_alloc_handle("NDIS_BINDING");
    NDIS_LOG("  Opened adapter binding: %p", *NdisBindingHandle);

    /* Return pending to simulate async completion (common in NDIS) */
    return NDIS_STATUS_SUCCESS;
}

/*
 * NdisCloseAdapterEx - Closes a previously opened adapter binding.
 */
NDIS_STATUS NdisCloseAdapterEx(NDIS_HANDLE NdisBindingHandle)
{
    NDIS_LOG("BindingHandle=%p", NdisBindingHandle);

    /* In real NDIS, this may pend; we complete immediately */
    return NDIS_STATUS_SUCCESS;
}

/* ============================================================================
 * NDIS Send/Receive Functions
 * ============================================================================ */

/*
 * NdisSendNetBufferLists - Sends network data through the binding.
 * Anti-cheat may use this to send heartbeat packets or responses.
 */
void NdisSendNetBufferLists(
    NDIS_HANDLE NdisBindingHandle,
    PNET_BUFFER_LIST NetBufferList,
    ULONG PortNumber,
    ULONG SendFlags)
{
    ULONG count = 0;
    PNET_BUFFER_LIST nbl;

    NDIS_LOG("BindingHandle=%p Port=%u SendFlags=0x%x",
             NdisBindingHandle, (unsigned)PortNumber, (unsigned)SendFlags);

    /* Count the NBLs in the chain */
    for (nbl = NetBufferList; nbl != NULL; nbl = nbl->Next) {
        count++;
    }
    NDIS_LOG("  NBL count: %u", (unsigned)count);

    /*
     * In a real implementation, we would pass packets to the network stack.
     * For stub purposes, we immediately complete them with success.
     * The protocol driver's SendComplete handler would be called here.
     */
    for (nbl = NetBufferList; nbl != NULL; nbl = nbl->Next) {
        nbl->Status = NDIS_STATUS_SUCCESS;
    }

    NDIS_LOG("  All NBLs marked as sent (stub - no actual transmission)");
}

/*
 * NdisReturnNetBufferLists - Returns received NBLs to the miniport.
 * Called after the protocol driver has finished processing received packets.
 */
void NdisReturnNetBufferLists(
    NDIS_HANDLE NdisBindingHandle,
    PNET_BUFFER_LIST NetBufferLists,
    ULONG ReturnFlags)
{
    ULONG count = 0;
    PNET_BUFFER_LIST nbl;

    NDIS_LOG("BindingHandle=%p ReturnFlags=0x%x",
             NdisBindingHandle, (unsigned)ReturnFlags);

    for (nbl = NetBufferLists; nbl != NULL; nbl = nbl->Next) {
        count++;
    }
    NDIS_LOG("  Returned %u NBLs", (unsigned)count);
}

/* ============================================================================
 * NDIS Memory Functions
 * ============================================================================ */

/*
 * NdisAllocateMemoryWithTagPriority - Allocates memory from the NDIS pool.
 */
NDIS_STATUS NdisAllocateMemoryWithTagPriority(
    NDIS_HANDLE NdisHandle,
    ULONG Length,
    ULONG Tag,
    EX_POOL_PRIORITY Priority,
    PVOID *VirtualAddress)
{
    UNREFERENCED_PARAMETER(NdisHandle);
    UNREFERENCED_PARAMETER(Priority);

    NDIS_LOG("Length=%u Tag=0x%08x Priority=%d",
             (unsigned)Length, (unsigned)Tag, (int)Priority);

    if (!VirtualAddress) {
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    *VirtualAddress = calloc(1, Length);
    if (!*VirtualAddress) {
        NDIS_LOG("  Allocation failed");
        return NDIS_STATUS_RESOURCES;
    }

    NDIS_LOG("  Allocated at %p", *VirtualAddress);
    return NDIS_STATUS_SUCCESS;
}

/*
 * NdisFreeMemory - Frees memory previously allocated with NdisAllocateMemory*.
 */
void NdisFreeMemory(PVOID VirtualAddress, ULONG Length, ULONG MemoryFlags)
{
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(MemoryFlags);

    NDIS_LOG("VirtualAddress=%p Length=%u", VirtualAddress, (unsigned)Length);
    free(VirtualAddress);
}

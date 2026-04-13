/*
 * iphlpapi_net.c - IP Helper API stubs
 *
 * Covers iphlpapi.dll exports used by network-aware applications and
 * anti-cheat systems: GetAdaptersInfo, GetAdaptersAddresses,
 * GetNetworkParams, routing/interface tables, ICMP handles.
 *
 * Most buffer-query functions return ERROR_BUFFER_OVERFLOW on the first
 * call (reporting a required size) so callers allocate and retry.
 * We provide minimal synthetic adapter data on the second call where
 * feasible, or just keep returning overflow for tables we don't populate.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common/dll_common.h"

/* Windows error codes used by IP Helper */
#define NO_ERROR                    0
#define ERROR_BUFFER_OVERFLOW       111
#define ERROR_INSUFFICIENT_BUFFER   122
#define ERROR_INVALID_PARAMETER     87
#define ERROR_NOT_SUPPORTED         50
#define ERROR_NO_DATA               232

/* Fake handle for ICMP */
static HANDLE iphlpapi_fake_icmp = (HANDLE)(uintptr_t)0xBB002000;

/* ------------------------------------------------------------------ */
/*  Minimal Windows structures (just enough for basic population)     */
/* ------------------------------------------------------------------ */

/* IP_ADDR_STRING - linked list of IP addresses */
typedef struct _IP_ADDR_STRING {
    struct _IP_ADDR_STRING *Next;
    char                    IpAddress[16];
    char                    IpMask[16];
    DWORD                   Context;
} IP_ADDR_STRING;

/* IP_ADAPTER_INFO (simplified) */
typedef struct _IP_ADAPTER_INFO {
    struct _IP_ADAPTER_INFO *Next;
    DWORD                    ComboIndex;
    char                     AdapterName[260];
    char                     Description[132];
    UINT                     AddressLength;
    BYTE                     Address[8];
    DWORD                    Index;
    UINT                     Type;
    UINT                     DhcpEnabled;
    IP_ADDR_STRING          *CurrentIpAddress;
    IP_ADDR_STRING           IpAddressList;
    IP_ADDR_STRING           GatewayList;
    IP_ADDR_STRING           DhcpServer;
    BOOL                     HaveWins;
    IP_ADDR_STRING           PrimaryWinsServer;
    IP_ADDR_STRING           SecondaryWinsServer;
    DWORD                    LeaseObtained;
    DWORD                    LeaseExpires;
} IP_ADAPTER_INFO;

/* Required size we report for adapter-info queries */
#define ADAPTER_INFO_SIZE   sizeof(IP_ADAPTER_INFO)

/* ------------------------------------------------------------------ */
/*  Helper: populate a synthetic adapter from the first non-lo iface  */
/* ------------------------------------------------------------------ */

static int fill_adapter_info(IP_ADAPTER_INFO *info)
{
    struct ifaddrs *ifa_list = NULL, *ifa;

    if (getifaddrs(&ifa_list) != 0)
        return -1;

    memset(info, 0, sizeof(*info));
    info->Next = NULL;
    info->Index = 1;
    info->Type = 6;  /* MIB_IF_TYPE_ETHERNET */
    info->AddressLength = 6;
    /* Fake MAC: 02:00:00:00:00:01 (locally administered) */
    info->Address[0] = 0x02;
    info->Address[5] = 0x01;

    strncpy(info->AdapterName, "eth0", sizeof(info->AdapterName) - 1);
    strncpy(info->Description, "PE-Compat Ethernet Adapter",
            sizeof(info->Description) - 1);

    /* Find the first AF_INET address on a non-loopback interface */
    for (ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;
        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (ifa->ifa_flags & IFF_LOOPBACK)
            continue;

        struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
        inet_ntop(AF_INET, &sin->sin_addr,
                  info->IpAddressList.IpAddress,
                  sizeof(info->IpAddressList.IpAddress));

        if (ifa->ifa_netmask) {
            struct sockaddr_in *mask = (struct sockaddr_in *)ifa->ifa_netmask;
            inet_ntop(AF_INET, &mask->sin_addr,
                      info->IpAddressList.IpMask,
                      sizeof(info->IpAddressList.IpMask));
        }

        strncpy(info->AdapterName, ifa->ifa_name,
                sizeof(info->AdapterName) - 1);

        freeifaddrs(ifa_list);
        return 0;
    }

    /* Fallback if nothing found */
    strncpy(info->IpAddressList.IpAddress, "192.168.1.100",
            sizeof(info->IpAddressList.IpAddress) - 1);
    strncpy(info->IpAddressList.IpMask, "255.255.255.0",
            sizeof(info->IpAddressList.IpMask) - 1);

    freeifaddrs(ifa_list);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  GetAdaptersInfo                                                   */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT DWORD GetAdaptersInfo(void *info, ULONG *size)
{
    fprintf(stderr, "[iphlpapi] GetAdaptersInfo(%p, %p)\n", info, (void *)size);

    if (!size)
        return ERROR_INVALID_PARAMETER;

    if (!info || *size < ADAPTER_INFO_SIZE) {
        *size = (ULONG)ADAPTER_INFO_SIZE;
        fprintf(stderr, "[iphlpapi]   -> ERROR_BUFFER_OVERFLOW (need %lu)\n",
                (unsigned long)ADAPTER_INFO_SIZE);
        return ERROR_BUFFER_OVERFLOW;
    }

    IP_ADAPTER_INFO *ai = (IP_ADAPTER_INFO *)info;
    if (fill_adapter_info(ai) < 0) {
        /* Couldn't query interfaces; still provide something */
        memset(ai, 0, sizeof(*ai));
        strncpy(ai->AdapterName, "eth0", sizeof(ai->AdapterName) - 1);
        strncpy(ai->IpAddressList.IpAddress, "192.168.1.100",
                sizeof(ai->IpAddressList.IpAddress) - 1);
        strncpy(ai->IpAddressList.IpMask, "255.255.255.0",
                sizeof(ai->IpAddressList.IpMask) - 1);
    }

    fprintf(stderr, "[iphlpapi]   -> NO_ERROR (adapter=%s ip=%s)\n",
            ai->AdapterName, ai->IpAddressList.IpAddress);
    return NO_ERROR;
}

/* ------------------------------------------------------------------ */
/*  GetAdaptersAddresses                                              */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT ULONG GetAdaptersAddresses(ULONG family, ULONG flags,
                                         void *reserved, void *addrs,
                                         ULONG *size)
{
    fprintf(stderr, "[iphlpapi] GetAdaptersAddresses(family=%lu, flags=0x%lx, "
            "addrs=%p, size=%p)\n",
            (unsigned long)family, (unsigned long)flags, addrs, (void *)size);
    (void)reserved;

    if (!size)
        return ERROR_INVALID_PARAMETER;

    /* IP_ADAPTER_ADDRESSES is very large and complex (each entry ~376 bytes
     * with variable-length strings appended).  Returning ERROR_NO_DATA
     * tells callers "no adapters available" which every well-behaved app
     * handles gracefully.  Returning NO_ERROR with a zeroed buffer is
     * DANGEROUS: callers treat the buffer as a non-NULL linked list head
     * and crash dereferencing NULL string pointers inside the struct.    */
    fprintf(stderr, "[iphlpapi]   -> ERROR_NO_DATA (no adapters)\n");
    return ERROR_NO_DATA;
}

/* ------------------------------------------------------------------ */
/*  GetNetworkParams                                                  */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT DWORD GetNetworkParams(void *info, ULONG *size)
{
    fprintf(stderr, "[iphlpapi] GetNetworkParams(%p, %p)\n",
            info, (void *)size);

    if (!size)
        return ERROR_INVALID_PARAMETER;

    /* FIXED_INFO structure is ~576 bytes; always report overflow first */
    if (!info || *size < 576) {
        *size = 576;
        return ERROR_BUFFER_OVERFLOW;
    }

    /* Populate minimal valid FIXED_INFO.
     * Layout (offsets): HostName[132]=0, DomainName[132]=132,
     * DnsServerList(IP_ADDR_STRING)=264, NodeType(UINT)=304, ...
     * DnsServerList.Next must be NULL; IpAddress must be a valid string. */
    memset(info, 0, 576);
    char *p = (char *)info;
    strncpy(p + 0, "DESKTOP-PE", 131);             /* HostName */
    /* DnsServerList.Next is at offset 264, already zeroed (NULL) */
    /* DnsServerList.IpAddress is at offset 264 + sizeof(void*) */
    strncpy(p + 264 + sizeof(void *), "8.8.8.8", 15); /* DnsServerList.IpAddress */
    return NO_ERROR;
}

/* ------------------------------------------------------------------ */
/*  Routing / interface / connection tables                           */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT DWORD GetIpForwardTable(void *table, ULONG *size, BOOL order)
{
    fprintf(stderr, "[iphlpapi] GetIpForwardTable(%p, %p, %d)\n",
            table, (void *)size, order);
    (void)order;

    if (!size)
        return ERROR_INVALID_PARAMETER;

    if (!table || *size < 1024) {
        *size = 1024;
        return ERROR_BUFFER_OVERFLOW;
    }

    /* Return empty table: MIB_IPFORWARDTABLE starts with dwNumEntries=0 */
    memset(table, 0, *size < 1024 ? *size : 1024);
    return NO_ERROR;
}

WINAPI_EXPORT DWORD GetIfTable(void *table, ULONG *size, BOOL order)
{
    fprintf(stderr, "[iphlpapi] GetIfTable(%p, %p, %d)\n",
            table, (void *)size, order);
    (void)order;

    if (!size)
        return ERROR_INVALID_PARAMETER;

    if (!table || *size < 1024) {
        *size = 1024;
        return ERROR_BUFFER_OVERFLOW;
    }

    /* Return empty table: MIB_IFTABLE starts with dwNumEntries=0 */
    memset(table, 0, *size < 1024 ? *size : 1024);
    return NO_ERROR;
}

WINAPI_EXPORT DWORD GetBestRoute(DWORD dest, DWORD source, void *route)
{
    fprintf(stderr, "[iphlpapi] GetBestRoute(0x%x, 0x%x, %p) -> NO_ERROR\n",
            (unsigned)dest, (unsigned)source, route);

    if (route)
        memset(route, 0, 64);  /* MIB_IPFORWARDROW is ~56 bytes */

    return NO_ERROR;
}

WINAPI_EXPORT DWORD GetBestInterface(DWORD dest, DWORD *index)
{
    fprintf(stderr, "[iphlpapi] GetBestInterface(0x%x, %p)\n",
            (unsigned)dest, (void *)index);

    if (index)
        *index = 1;

    return NO_ERROR;
}

WINAPI_EXPORT DWORD GetNumberOfInterfaces(DWORD *count)
{
    fprintf(stderr, "[iphlpapi] GetNumberOfInterfaces(%p)\n", (void *)count);

    if (count)
        *count = 2;  /* loopback + one Ethernet */

    return NO_ERROR;
}

WINAPI_EXPORT DWORD GetTcpTable(void *table, DWORD *size, BOOL order)
{
    fprintf(stderr, "[iphlpapi] GetTcpTable(%p, %p, %d)\n",
            table, (void *)size, order);
    (void)order;

    if (!size)
        return ERROR_INVALID_PARAMETER;

    if (!table || *size < 512) {
        *size = 512;
        return ERROR_BUFFER_OVERFLOW;
    }

    /* Return empty table: MIB_TCPTABLE starts with dwNumEntries=0 */
    memset(table, 0, *size < 512 ? *size : 512);
    return NO_ERROR;
}

WINAPI_EXPORT DWORD GetUdpTable(void *table, DWORD *size, BOOL order)
{
    fprintf(stderr, "[iphlpapi] GetUdpTable(%p, %p, %d)\n",
            table, (void *)size, order);
    (void)order;

    if (!size)
        return ERROR_INVALID_PARAMETER;

    if (!table || *size < 512) {
        *size = 512;
        return ERROR_BUFFER_OVERFLOW;
    }

    /* Return empty table: MIB_UDPTABLE starts with dwNumEntries=0 */
    memset(table, 0, *size < 512 ? *size : 512);
    return NO_ERROR;
}

/* ------------------------------------------------------------------ */
/*  ICMP handle stubs                                                 */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT HANDLE IcmpCreateFile(void)
{
    fprintf(stderr, "[iphlpapi] IcmpCreateFile() -> %p\n", iphlpapi_fake_icmp);
    return iphlpapi_fake_icmp;
}

WINAPI_EXPORT BOOL IcmpCloseHandle(HANDLE h)
{
    fprintf(stderr, "[iphlpapi] IcmpCloseHandle(%p) -> TRUE\n", h);
    (void)h;
    return TRUE;
}

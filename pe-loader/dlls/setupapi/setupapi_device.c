/*
 * setupapi_device.c - SetupAPI device setup and driver installation stubs
 *
 * Anti-cheat and hardware enumeration software queries device info
 * via SetupDi* and CM_* functions. We return empty device lists
 * so callers see "no devices" rather than crashing.
 */

#include <stdio.h>
#include <string.h>

#include "common/dll_common.h"

/* Fake HDEVINFO handle returned by SetupDiGetClassDevs* */
#define FAKE_HDEVINFO   ((HANDLE)(intptr_t)0x1000)

/* Configuration Manager return codes */
#define CR_SUCCESS      0
#define CR_FAILURE      13

/* Error codes needed for SetupDi enumeration */
#ifndef ERROR_NO_MORE_ITEMS
#define ERROR_NO_MORE_ITEMS 259
#endif

/* -----------------------------------------------------------------------
 * SetupDiGetClassDevsA / SetupDiGetClassDevsW
 *
 * Return a fake HDEVINFO set. Callers will enumerate with
 * SetupDiEnumDeviceInfo which immediately returns FALSE (no devices).
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT HANDLE SetupDiGetClassDevsA(
    void *classGuid,
    LPCSTR enumerator,
    HWND parent,
    DWORD flags)
{
    (void)classGuid;
    (void)enumerator;
    (void)parent;
    (void)flags;

    fprintf(stderr, "[setupapi] SetupDiGetClassDevsA(enumerator='%s', flags=0x%x)\n",
            enumerator ? enumerator : "(null)", flags);

    return FAKE_HDEVINFO;
}

WINAPI_EXPORT HANDLE SetupDiGetClassDevsW(
    void *classGuid,
    LPCWSTR enumerator,
    HWND parent,
    DWORD flags)
{
    (void)classGuid;
    (void)enumerator;
    (void)parent;
    (void)flags;

    fprintf(stderr, "[setupapi] SetupDiGetClassDevsW(flags=0x%x)\n", flags);

    return FAKE_HDEVINFO;
}

/* -----------------------------------------------------------------------
 * SetupDiEnumDeviceInfo
 *
 * Always returns FALSE — the fake device info set is empty.
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT BOOL SetupDiEnumDeviceInfo(
    HANDLE devInfo,
    DWORD index,
    void *devInfoData)
{
    (void)devInfo;
    (void)index;
    (void)devInfoData;

    fprintf(stderr, "[setupapi] SetupDiEnumDeviceInfo(index=%u) -> no devices\n", index);

    set_last_error(ERROR_NO_MORE_ITEMS);
    return FALSE;
}

/* -----------------------------------------------------------------------
 * SetupDiGetDeviceRegistryPropertyA / W
 *
 * Return FALSE — no device properties available.
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT BOOL SetupDiGetDeviceRegistryPropertyA(
    HANDLE devInfo,
    void *devInfoData,
    DWORD property,
    DWORD *regDataType,
    BYTE *buffer,
    DWORD bufSize,
    DWORD *requiredSize)
{
    (void)devInfo;
    (void)devInfoData;
    (void)property;
    (void)regDataType;
    (void)buffer;
    (void)bufSize;
    (void)requiredSize;

    fprintf(stderr, "[setupapi] SetupDiGetDeviceRegistryPropertyA(property=%u)\n", property);

    return FALSE;
}

WINAPI_EXPORT BOOL SetupDiGetDeviceRegistryPropertyW(
    HANDLE devInfo,
    void *devInfoData,
    DWORD property,
    DWORD *regDataType,
    BYTE *buffer,
    DWORD bufSize,
    DWORD *requiredSize)
{
    (void)devInfo;
    (void)devInfoData;
    (void)property;
    (void)regDataType;
    (void)buffer;
    (void)bufSize;
    (void)requiredSize;

    fprintf(stderr, "[setupapi] SetupDiGetDeviceRegistryPropertyW(property=%u)\n", property);

    return FALSE;
}

/* -----------------------------------------------------------------------
 * SetupDiDestroyDeviceInfoList
 *
 * Always succeeds — nothing to free.
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT BOOL SetupDiDestroyDeviceInfoList(HANDLE devInfo)
{
    (void)devInfo;

    fprintf(stderr, "[setupapi] SetupDiDestroyDeviceInfoList()\n");

    return TRUE;
}

/* -----------------------------------------------------------------------
 * SetupDiEnumDeviceInterfaces
 *
 * Return FALSE — no device interfaces present.
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT BOOL SetupDiEnumDeviceInterfaces(
    HANDLE devInfo,
    void *devInfoData,
    void *interfaceClassGuid,
    DWORD memberIndex,
    void *devInterfaceData)
{
    (void)devInfo;
    (void)devInfoData;
    (void)interfaceClassGuid;
    (void)memberIndex;
    (void)devInterfaceData;

    fprintf(stderr, "[setupapi] SetupDiEnumDeviceInterfaces(index=%u) -> no interfaces\n",
            memberIndex);

    set_last_error(ERROR_NO_MORE_ITEMS);
    return FALSE;
}

/* -----------------------------------------------------------------------
 * SetupDiGetDeviceInterfaceDetailA
 *
 * Return FALSE — no interface detail available.
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT BOOL SetupDiGetDeviceInterfaceDetailA(
    HANDLE devInfo,
    void *devInterfaceData,
    void *devInterfaceDetailData,
    DWORD detailSize,
    DWORD *requiredSize,
    void *devInfoData)
{
    (void)devInfo;
    (void)devInterfaceData;
    (void)devInterfaceDetailData;
    (void)detailSize;
    (void)devInfoData;

    fprintf(stderr, "[setupapi] SetupDiGetDeviceInterfaceDetailA()\n");

    if (requiredSize)
        *requiredSize = 0;
    set_last_error(ERROR_NO_MORE_ITEMS);
    return FALSE;
}

WINAPI_EXPORT BOOL SetupDiGetDeviceInterfaceDetailW(
    HANDLE devInfo,
    void *devInterfaceData,
    void *devInterfaceDetailData,
    DWORD detailSize,
    DWORD *requiredSize,
    void *devInfoData)
{
    (void)devInfo;
    (void)devInterfaceData;
    (void)devInterfaceDetailData;
    (void)detailSize;
    (void)devInfoData;

    fprintf(stderr, "[setupapi] SetupDiGetDeviceInterfaceDetailW()\n");

    if (requiredSize)
        *requiredSize = 0;
    set_last_error(ERROR_NO_MORE_ITEMS);
    return FALSE;
}

/* -----------------------------------------------------------------------
 * SetupDiCreateDeviceInfoList
 *
 * Return a fake HDEVINFO.
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT HANDLE SetupDiCreateDeviceInfoList(void *classGuid, HWND parent)
{
    (void)classGuid;
    (void)parent;

    fprintf(stderr, "[setupapi] SetupDiCreateDeviceInfoList()\n");

    return FAKE_HDEVINFO;
}

/* -----------------------------------------------------------------------
 * SetupDiOpenDevRegKey
 *
 * Return INVALID_HANDLE_VALUE — we don't expose device registry keys.
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT HANDLE SetupDiOpenDevRegKey(
    HANDLE devInfo,
    void *devInfoData,
    DWORD scope,
    DWORD hwProfile,
    DWORD keyType,
    DWORD samDesired)
{
    (void)devInfo;
    (void)devInfoData;
    (void)scope;
    (void)hwProfile;
    (void)keyType;
    (void)samDesired;

    fprintf(stderr, "[setupapi] SetupDiOpenDevRegKey() -> INVALID_HANDLE_VALUE\n");

    return INVALID_HANDLE_VALUE;
}

/* -----------------------------------------------------------------------
 * CM_Get_Device_IDA
 *
 * Return CR_FAILURE (13) — no Configuration Manager support.
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT DWORD CM_Get_Device_IDA(
    DWORD devInst,
    LPSTR buffer,
    ULONG bufLen,
    ULONG flags)
{
    (void)devInst;
    (void)buffer;
    (void)bufLen;
    (void)flags;

    fprintf(stderr, "[setupapi] CM_Get_Device_IDA(devInst=%u) -> CR_FAILURE\n", devInst);

    return CR_FAILURE;
}

/* -----------------------------------------------------------------------
 * CM_Get_DevNode_Status
 *
 * Return CR_FAILURE (13).
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT DWORD CM_Get_DevNode_Status(
    ULONG *status,
    ULONG *problem,
    DWORD devInst,
    ULONG flags)
{
    (void)status;
    (void)problem;
    (void)devInst;
    (void)flags;

    fprintf(stderr, "[setupapi] CM_Get_DevNode_Status(devInst=%u) -> CR_FAILURE\n", devInst);

    return CR_FAILURE;
}

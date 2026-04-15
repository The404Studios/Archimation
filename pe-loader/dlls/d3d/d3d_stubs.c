/*
 * d3d_stubs.c - DirectX / Direct3D / DXGI / XInput minimal stubs
 *
 * Games and multimedia apps probe for GPU acceleration via Direct3D 9/11,
 * DXGI factory creation, DirectDraw, and XInput controller APIs.
 * We return clean "not available" errors so callers can fall back
 * to software rendering or skip GPU features gracefully.
 *
 * For actual GPU acceleration under Linux, use DXVK / VKD3D-Proton
 * which translate D3D calls to Vulkan.
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>

#include "common/dll_common.h"

/* HRESULT codes */
#define S_OK            ((HRESULT)0x00000000)
#define E_NOTIMPL       ((HRESULT)0x80004001)
#define E_FAIL          ((HRESULT)0x80004005)
#define DXGI_ERROR_UNSUPPORTED ((HRESULT)0x887A0004)

/* XInput error */
#define ERROR_DEVICE_NOT_CONNECTED  1167

/* -----------------------------------------------------------------------
 * DXVK / VKD3D-Proton Runtime Probing
 *
 * When DXVK or VKD3D-Proton .so files are installed, we forward D3D
 * calls to them for real GPU acceleration via Vulkan. No Wine needed.
 * ----------------------------------------------------------------------- */

/* g_dxvk_d3d9 and g_dxvk_d3d9_tried are defined in d3d9_device.c */
extern void *g_dxvk_d3d9;
/* Note: d3d9_device.c uses g_dxvk_tried (not g_dxvk_d3d9_tried) */
extern int   g_dxvk_tried;

static void *g_dxvk_d3d11 = NULL;
/* Session 30: plain 'tried' flags were raced by concurrent D3D init from
 * the UI thread + Unity job system. Replace with pthread_once so each
 * backend is probed exactly once even under thundering-herd startup. */
static pthread_once_t g_dxvk_d3d11_once = PTHREAD_ONCE_INIT;

/* g_dxvk_dxgi and g_dxvk_dxgi_tried are defined in dxgi_factory.c */
extern void *g_dxvk_dxgi;
extern int   g_dxvk_dxgi_tried;

static void *g_vkd3d_d3d12 = NULL;
static pthread_once_t g_vkd3d_d3d12_once = PTHREAD_ONCE_INIT;

static void *try_dlopen_paths(const char *name, const char **paths, int npaths)
{
    void *h = dlopen(name, RTLD_NOW | RTLD_GLOBAL);
    if (h) return h;
    for (int i = 0; i < npaths; i++) {
        char buf[512];
        snprintf(buf, sizeof(buf), "%s/%s", paths[i], name);
        h = dlopen(buf, RTLD_NOW | RTLD_GLOBAL);
        if (h) return h;
    }
    return NULL;
}

static const char *g_dxvk_search_paths[] = {
    "/usr/lib/dxvk",
    "/usr/lib/x86_64-linux-gnu/dxvk",
    "/usr/lib64/dxvk",
    "/opt/dxvk/lib",
    "./dlls/dxvk",
    "~/.pe-compat/dxvk"
};
#define DXVK_NPATHS (sizeof(g_dxvk_search_paths)/sizeof(g_dxvk_search_paths[0]))

static const char *g_vkd3d_search_paths[] = {
    "/usr/lib/vkd3d-proton",
    "/usr/lib/x86_64-linux-gnu/vkd3d-proton",
    "/usr/lib64/vkd3d-proton",
    "/opt/vkd3d-proton/lib",
    "./dlls/vkd3d",
    "~/.pe-compat/vkd3d"
};
#define VKD3D_NPATHS (sizeof(g_vkd3d_search_paths)/sizeof(g_vkd3d_search_paths[0]))

static __attribute__((unused)) void *get_dxvk_d3d9(void)
{
    if (!g_dxvk_tried) {
        g_dxvk_tried = 1;
        g_dxvk_d3d9 = try_dlopen_paths("d3d9.so", g_dxvk_search_paths, DXVK_NPATHS);
        if (g_dxvk_d3d9)
            fprintf(stderr, "[d3d] DXVK D3D9 found and loaded\n");
    }
    return g_dxvk_d3d9;
}

static void dxvk_d3d11_probe_once(void)
{
    g_dxvk_d3d11 = try_dlopen_paths("d3d11.so", g_dxvk_search_paths, DXVK_NPATHS);
    if (g_dxvk_d3d11)
        fprintf(stderr, "[d3d] DXVK D3D11 found and loaded\n");
}

static void *get_dxvk_d3d11(void)
{
    pthread_once(&g_dxvk_d3d11_once, dxvk_d3d11_probe_once);
    return g_dxvk_d3d11;
}

static void *get_dxvk_dxgi(void)
{
    if (!g_dxvk_dxgi_tried) {
        g_dxvk_dxgi_tried = 1;
        g_dxvk_dxgi = try_dlopen_paths("dxgi.so", g_dxvk_search_paths, DXVK_NPATHS);
        if (g_dxvk_dxgi)
            fprintf(stderr, "[d3d] DXVK DXGI found and loaded\n");
    }
    return g_dxvk_dxgi;
}

static void vkd3d_d3d12_probe_once(void)
{
    g_vkd3d_d3d12 = try_dlopen_paths("libvkd3d-proton-d3d12.so",
                                       g_vkd3d_search_paths, VKD3D_NPATHS);
    if (!g_vkd3d_d3d12)
        g_vkd3d_d3d12 = try_dlopen_paths("d3d12.so",
                                          g_vkd3d_search_paths, VKD3D_NPATHS);
    if (g_vkd3d_d3d12)
        fprintf(stderr, "[d3d] VKD3D-Proton D3D12 found and loaded\n");
}

static void *get_vkd3d_d3d12(void)
{
    pthread_once(&g_vkd3d_d3d12_once, vkd3d_d3d12_probe_once);
    return g_vkd3d_d3d12;
}

/* Direct3DCreate9/Ex moved to d3d9_device.c (has full DXVK probe + stub vtable fallback) */

/* -----------------------------------------------------------------------
 * Direct3D 11 - Forward to DXVK if available
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT HRESULT D3D11CreateDevice(
    void *adapter, UINT driverType, HANDLE software, UINT flags,
    void *featureLevels, UINT numFeatureLevels, UINT sdkVersion,
    void **device, void *featureLevel, void **deviceContext)
{
    void *dxvk = get_dxvk_d3d11();
    if (dxvk) {
        typedef HRESULT (__attribute__((ms_abi)) *fn_t)(void*, UINT, HANDLE, UINT, void*, UINT, UINT, void**, void*, void**);
        fn_t fn = (fn_t)dlsym(dxvk, "D3D11CreateDevice");
        if (fn) return fn(adapter, driverType, software, flags, featureLevels,
                         numFeatureLevels, sdkVersion, device, featureLevel, deviceContext);
    }
    fprintf(stderr, "[d3d] D3D11CreateDevice(): no DXVK - install dxvk for GPU acceleration\n");
    if (device) *device = NULL;
    if (deviceContext) *deviceContext = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3D11CreateDeviceAndSwapChain(
    void *adapter, UINT driverType, HANDLE software, UINT flags,
    void *featureLevels, UINT numFeatureLevels, UINT sdkVersion,
    void *swapChainDesc, void **swapChain, void **device,
    void *featureLevel, void **deviceContext)
{
    void *dxvk = get_dxvk_d3d11();
    if (dxvk) {
        typedef HRESULT (__attribute__((ms_abi)) *fn_t)(void*, UINT, HANDLE, UINT, void*, UINT, UINT, void*, void**, void**, void*, void**);
        fn_t fn = (fn_t)dlsym(dxvk, "D3D11CreateDeviceAndSwapChain");
        if (fn) return fn(adapter, driverType, software, flags, featureLevels,
                         numFeatureLevels, sdkVersion, swapChainDesc, swapChain,
                         device, featureLevel, deviceContext);
    }
    fprintf(stderr, "[d3d] D3D11CreateDeviceAndSwapChain(): no DXVK\n");
    if (swapChain) *swapChain = NULL;
    if (device) *device = NULL;
    if (deviceContext) *deviceContext = NULL;
    return E_NOTIMPL;
}

/* -----------------------------------------------------------------------
 * Direct3D 12 - Forward to VKD3D-Proton if available
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT HRESULT D3D12CreateDevice(
    void *pAdapter, int MinimumFeatureLevel, const GUID *riid, void **ppDevice)
{
    void *vkd3d = get_vkd3d_d3d12();
    if (vkd3d) {
        typedef HRESULT (__attribute__((ms_abi)) *fn_t)(void*, int, const GUID*, void**);
        fn_t fn = (fn_t)dlsym(vkd3d, "D3D12CreateDevice");
        if (fn) return fn(pAdapter, MinimumFeatureLevel, riid, ppDevice);
    }
    fprintf(stderr, "[d3d] D3D12CreateDevice(): no VKD3D-Proton - install vkd3d-proton for DX12\n");
    if (ppDevice) *ppDevice = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3D12GetDebugInterface(const GUID *riid, void **ppvDebug)
{
    void *vkd3d = get_vkd3d_d3d12();
    if (vkd3d) {
        typedef HRESULT (__attribute__((ms_abi)) *fn_t)(const GUID*, void**);
        fn_t fn = (fn_t)dlsym(vkd3d, "D3D12GetDebugInterface");
        if (fn) return fn(riid, ppvDebug);
    }
    if (ppvDebug) *ppvDebug = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3D12SerializeRootSignature(
    void *pRootSignature, int Version, void **ppBlob, void **ppErrorBlob)
{
    void *vkd3d = get_vkd3d_d3d12();
    if (vkd3d) {
        typedef HRESULT (__attribute__((ms_abi)) *fn_t)(void*, int, void**, void**);
        fn_t fn = (fn_t)dlsym(vkd3d, "D3D12SerializeRootSignature");
        if (fn) return fn(pRootSignature, Version, ppBlob, ppErrorBlob);
    }
    if (ppBlob) *ppBlob = NULL;
    if (ppErrorBlob) *ppErrorBlob = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3D12SerializeVersionedRootSignature(
    void *pRootSignature, void **ppBlob, void **ppErrorBlob)
{
    void *vkd3d = get_vkd3d_d3d12();
    if (vkd3d) {
        typedef HRESULT (__attribute__((ms_abi)) *fn_t)(void*, void**, void**);
        fn_t fn = (fn_t)dlsym(vkd3d, "D3D12SerializeVersionedRootSignature");
        if (fn) return fn(pRootSignature, ppBlob, ppErrorBlob);
    }
    if (ppBlob) *ppBlob = NULL;
    if (ppErrorBlob) *ppErrorBlob = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3D12CreateRootSignatureDeserializer(
    const void *pSrcData, SIZE_T SrcDataSizeInBytes, const GUID *riid, void **ppRootSignature)
{
    void *vkd3d = get_vkd3d_d3d12();
    if (vkd3d) {
        typedef HRESULT (__attribute__((ms_abi)) *fn_t)(const void*, SIZE_T, const GUID*, void**);
        fn_t fn = (fn_t)dlsym(vkd3d, "D3D12CreateRootSignatureDeserializer");
        if (fn) return fn(pSrcData, SrcDataSizeInBytes, riid, ppRootSignature);
    }
    if (ppRootSignature) *ppRootSignature = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3D12EnableExperimentalFeatures(
    UINT NumFeatures, const GUID *pIIDs, void *pConfigurationStructs,
    UINT *pConfigurationStructSizes)
{
    (void)NumFeatures; (void)pIIDs; (void)pConfigurationStructs;
    (void)pConfigurationStructSizes;
    return E_NOTIMPL;
}

/* CreateDXGIFactory/1/2 moved to dxgi_factory.c (has full DXVK probe + stub vtable fallback) */

static __attribute__((unused)) HRESULT dxgi_placeholder_unused(void) {
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT DXGIGetDebugInterface(void *riid, void **debug)
{
    void *dxvk = get_dxvk_dxgi();
    if (dxvk) {
        typedef HRESULT (__attribute__((ms_abi)) *fn_t)(void*, void**);
        fn_t fn = (fn_t)dlsym(dxvk, "DXGIGetDebugInterface");
        if (fn) return fn(riid, debug);
    }
    if (debug) *debug = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT DXGIGetDebugInterface1(UINT Flags, void *riid, void **debug)
{
    void *dxvk = get_dxvk_dxgi();
    if (dxvk) {
        typedef HRESULT (__attribute__((ms_abi)) *fn_t)(UINT, void*, void**);
        fn_t fn = (fn_t)dlsym(dxvk, "DXGIGetDebugInterface1");
        if (fn) return fn(Flags, riid, debug);
    }
    if (debug) *debug = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT DXGIDeclareAdapterRemovalSupport(void)
{
    return S_OK;
}

/* -----------------------------------------------------------------------
 * DirectDraw (legacy)
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT HRESULT DirectDrawCreate(void *guid, void **dd, void *unknown)
{
    (void)guid;
    (void)unknown;

    fprintf(stderr, "[d3d] DirectDrawCreate(): "
            "DirectDraw not available in PE compat layer. "
            "Use Vulkan/DXVK.\n");

    if (dd)
        *dd = NULL;

    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT DirectDrawCreateEx(
    void *guid,
    void **dd,
    void *iid,
    void *unknown)
{
    (void)guid;
    (void)iid;
    (void)unknown;

    fprintf(stderr, "[d3d] DirectDrawCreateEx(): "
            "DirectDraw not available in PE compat layer. "
            "Use Vulkan/DXVK.\n");

    if (dd)
        *dd = NULL;

    return E_NOTIMPL;
}

/* -----------------------------------------------------------------------
 * D3DX Utility (D3DX9 / D3DX10 / D3DX11)
 * ----------------------------------------------------------------------- */

WINAPI_EXPORT HRESULT D3DXCreateTextureFromFileA(
    void *device,
    LPCSTR srcFile,
    void **texture)
{
    (void)device;

    fprintf(stderr, "[d3d] D3DXCreateTextureFromFileA('%s'): "
            "GPU acceleration not available in PE compat layer.\n",
            srcFile ? srcFile : "(null)");

    if (texture)
        *texture = NULL;

    return E_NOTIMPL;
}

/* -----------------------------------------------------------------------
 * XInput (gamepad / controller) via Linux evdev
 *
 * Real implementation: scans /dev/input/event* for gamepad devices,
 * reads axis/button state via ioctl, and sends force-feedback rumble
 * via the EV_FF subsystem. Supports up to 4 controllers.
 *
 * Axis values are normalized from the device's actual min/max range
 * (obtained via EVIOCGABS) to XInput's expected ranges:
 *   - Thumbsticks: -32768..32767 (Y axes inverted: Linux Y+ = down)
 *   - Triggers:    0..255
 *
 * Button codes are mapped from Linux BTN_* to XINPUT_GAMEPAD_* bits.
 * ----------------------------------------------------------------------- */

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/input.h>

/* Ensure input-event-codes are available (included transitively via
   linux/input.h on modern kernels, but define fallbacks just in case) */
#ifndef BTN_SOUTH
#define BTN_SOUTH   0x130
#endif
#ifndef BTN_EAST
#define BTN_EAST    0x131
#endif
#ifndef BTN_NORTH
#define BTN_NORTH   0x133
#endif
#ifndef BTN_WEST
#define BTN_WEST    0x132
#endif
#ifndef BTN_A
#define BTN_A       BTN_SOUTH
#endif
#ifndef BTN_B
#define BTN_B       BTN_EAST
#endif
#ifndef BTN_X
#define BTN_X       BTN_WEST
#endif
#ifndef BTN_Y
#define BTN_Y       BTN_NORTH
#endif
#ifndef BTN_TL
#define BTN_TL      0x136
#endif
#ifndef BTN_TR
#define BTN_TR      0x137
#endif
#ifndef BTN_SELECT
#define BTN_SELECT  0x13a
#endif
#ifndef BTN_START
#define BTN_START   0x13b
#endif
#ifndef BTN_MODE
#define BTN_MODE    0x13c
#endif
#ifndef BTN_THUMBL
#define BTN_THUMBL  0x13d
#endif
#ifndef BTN_THUMBR
#define BTN_THUMBR  0x13e
#endif
#ifndef BTN_GAMEPAD
#define BTN_GAMEPAD 0x130
#endif
/* BTN_BACK is not a standard Linux define; some drivers use BTN_SELECT */
#ifndef BTN_BACK
#define BTN_BACK    BTN_SELECT
#endif

/* Force feedback constants */
#ifndef FF_RUMBLE
#define FF_RUMBLE   0x50
#endif
#ifndef FF_MAX
#define FF_MAX      0x7f
#endif

#define XUSER_MAX_COUNT 4

/* XInput button bitmask constants */
#define XINPUT_GAMEPAD_DPAD_UP        0x0001
#define XINPUT_GAMEPAD_DPAD_DOWN      0x0002
#define XINPUT_GAMEPAD_DPAD_LEFT      0x0004
#define XINPUT_GAMEPAD_DPAD_RIGHT     0x0008
#define XINPUT_GAMEPAD_START          0x0010
#define XINPUT_GAMEPAD_BACK           0x0020
#define XINPUT_GAMEPAD_LEFT_THUMB     0x0040
#define XINPUT_GAMEPAD_RIGHT_THUMB    0x0080
#define XINPUT_GAMEPAD_LEFT_SHOULDER  0x0100
#define XINPUT_GAMEPAD_RIGHT_SHOULDER 0x0200
#define XINPUT_GAMEPAD_GUIDE          0x0400  /* unofficial but widely used */
#define XINPUT_GAMEPAD_A              0x1000
#define XINPUT_GAMEPAD_B              0x2000
#define XINPUT_GAMEPAD_X              0x4000
#define XINPUT_GAMEPAD_Y              0x8000

/* XInput device types */
#define XINPUT_DEVTYPE_GAMEPAD        0x01
#define XINPUT_DEVSUBTYPE_GAMEPAD     0x01

/* XInput capability flags */
#define XINPUT_CAPS_FFB_SUPPORTED     0x0001

/* Battery */
#define BATTERY_TYPE_WIRED            0x01
#define BATTERY_LEVEL_FULL            0x03

/* Windows error codes */
#define ERROR_SUCCESS                 0
#define ERROR_EMPTY                   0x048F  /* 1167 decimal for keystroke */

typedef struct {
    WORD  wButtons;
    BYTE  bLeftTrigger;
    BYTE  bRightTrigger;
    SHORT sThumbLX;
    SHORT sThumbLY;
    SHORT sThumbRX;
    SHORT sThumbRY;
} XINPUT_GAMEPAD_T;

typedef struct {
    DWORD dwPacketNumber;
    XINPUT_GAMEPAD_T Gamepad;
} XINPUT_STATE_T;

typedef struct {
    WORD wLeftMotorSpeed;
    WORD wRightMotorSpeed;
} XINPUT_VIBRATION_T;

typedef struct {
    BYTE Type;
    BYTE SubType;
    WORD Flags;
    XINPUT_GAMEPAD_T Gamepad;
    XINPUT_VIBRATION_T Vibration;
} XINPUT_CAPABILITIES_T;

typedef struct {
    BYTE BatteryType;
    BYTE BatteryLevel;
} XINPUT_BATTERY_INFORMATION_T;

/* Cached axis calibration data from EVIOCGABS */
typedef struct {
    int minimum;
    int maximum;
    int has_data;  /* whether the ioctl succeeded at init */
} axis_cal_t;

/* Axis indices for calibration cache */
enum {
    CAL_ABS_X = 0,
    CAL_ABS_Y,
    CAL_ABS_RX,
    CAL_ABS_RY,
    CAL_ABS_Z,         /* left trigger (primary) */
    CAL_ABS_RZ,        /* right trigger (primary) */
    CAL_ABS_HAT2X,     /* left trigger (alternate) */
    CAL_ABS_HAT2Y,     /* right trigger (alternate) */
    CAL_ABS_HAT0X,     /* d-pad X */
    CAL_ABS_HAT0Y,     /* d-pad Y */
    CAL_NUM_AXES
};

/* Linux ABS codes corresponding to each calibration index */
static const int g_cal_abs_codes[CAL_NUM_AXES] = {
    ABS_X, ABS_Y, ABS_RX, ABS_RY,
    ABS_Z, ABS_RZ,
    ABS_HAT2X, ABS_HAT2Y,
    ABS_HAT0X, ABS_HAT0Y
};

/* Per-controller state */
typedef struct {
    int fd;                          /* evdev file descriptor (-1 = not connected) */
    char path[64];                   /* /dev/input/eventN */
    DWORD packet;                    /* incrementing packet number */
    int has_ff;                      /* device supports EV_FF with FF_RUMBLE */
    int ff_id;                       /* uploaded FF effect id (-1 = none) */
    axis_cal_t cal[CAL_NUM_AXES];    /* cached axis calibration */
    XINPUT_GAMEPAD_T last_state;     /* last read gamepad state for change detection */
} xinput_pad_t;

static xinput_pad_t g_pads[XUSER_MAX_COUNT];
static int g_xinput_scanned = 0;
static int g_xinput_enabled = 1;

/* ---- Helper: normalize a centered axis (thumbstick) to -32768..32767 ---- */
static SHORT normalize_axis_centered(int value, int amin, int amax)
{
    /* Avoid division by zero */
    int range = amax - amin;
    if (range <= 0) return 0;

    int center = (amin + amax) / 2;
    int half = range / 2;
    if (half == 0) return 0;

    int64_t normalized = (int64_t)(value - center) * 32767 / half;

    /* Clamp to valid range */
    if (normalized > 32767) normalized = 32767;
    if (normalized < -32768) normalized = -32768;

    return (SHORT)normalized;
}

/* ---- Helper: normalize a one-sided axis (trigger) to 0..255 ---- */
static BYTE normalize_axis_trigger(int value, int amin, int amax)
{
    int range = amax - amin;
    if (range <= 0) return 0;

    int64_t normalized = (int64_t)(value - amin) * 255 / range;

    if (normalized > 255) normalized = 255;
    if (normalized < 0) normalized = 0;

    return (BYTE)normalized;
}

/* ---- Bit-test helper for evdev bitmask arrays ---- */
#define EVDEV_BIT_TEST(array, bit) \
    ((array)[(bit) / (sizeof((array)[0]) * 8)] & \
     (1UL << ((bit) % (sizeof((array)[0]) * 8))))

/* ---- Check if an evdev device is a gamepad ---- */
static int is_gamepad(int fd)
{
    unsigned long evbits[(EV_MAX + 8 * sizeof(unsigned long) - 1) / (8 * sizeof(unsigned long))];
    memset(evbits, 0, sizeof(evbits));
    if (ioctl(fd, EVIOCGBIT(0, sizeof(evbits)), evbits) < 0)
        return 0;

    /* Must have EV_ABS (absolute axes) and EV_KEY (buttons) */
    if (!EVDEV_BIT_TEST(evbits, EV_ABS) || !EVDEV_BIT_TEST(evbits, EV_KEY))
        return 0;

    /* Check for joystick axes: need ABS_X and ABS_Y (left thumbstick) */
    unsigned long absbits[(ABS_MAX + 8 * sizeof(unsigned long) - 1) / (8 * sizeof(unsigned long))];
    memset(absbits, 0, sizeof(absbits));
    if (ioctl(fd, EVIOCGBIT(EV_ABS, sizeof(absbits)), absbits) < 0)
        return 0;

    int has_sticks = EVDEV_BIT_TEST(absbits, ABS_X) && EVDEV_BIT_TEST(absbits, ABS_Y);
    if (!has_sticks)
        return 0;

    /* Check for gamepad buttons: BTN_GAMEPAD (== BTN_SOUTH) or BTN_A */
    unsigned long keybits[(KEY_MAX + 8 * sizeof(unsigned long) - 1) / (8 * sizeof(unsigned long))];
    memset(keybits, 0, sizeof(keybits));
    if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(keybits)), keybits) < 0)
        return 0;

    if (EVDEV_BIT_TEST(keybits, BTN_GAMEPAD) || EVDEV_BIT_TEST(keybits, BTN_SOUTH))
        return 1;

    return 0;
}

/* ---- Cache axis calibration data for a pad ---- */
static void xinput_cache_calibration(xinput_pad_t *pad)
{
    for (int i = 0; i < CAL_NUM_AXES; i++) {
        struct input_absinfo abs;
        if (ioctl(pad->fd, EVIOCGABS(g_cal_abs_codes[i]), &abs) == 0) {
            pad->cal[i].minimum = abs.minimum;
            pad->cal[i].maximum = abs.maximum;
            pad->cal[i].has_data = 1;
        } else {
            pad->cal[i].minimum = 0;
            pad->cal[i].maximum = 0;
            pad->cal[i].has_data = 0;
        }
    }
}

/* ---- Check if device supports FF_RUMBLE ---- */
static int xinput_check_ff(int fd)
{
    unsigned long evbits[(EV_MAX + 8 * sizeof(unsigned long) - 1) / (8 * sizeof(unsigned long))];
    memset(evbits, 0, sizeof(evbits));
    if (ioctl(fd, EVIOCGBIT(0, sizeof(evbits)), evbits) < 0)
        return 0;

    if (!EVDEV_BIT_TEST(evbits, EV_FF))
        return 0;

    unsigned long ffbits[(FF_MAX + 8 * sizeof(unsigned long) - 1) / (8 * sizeof(unsigned long))];
    memset(ffbits, 0, sizeof(ffbits));
    if (ioctl(fd, EVIOCGBIT(EV_FF, sizeof(ffbits)), ffbits) < 0)
        return 0;

    return EVDEV_BIT_TEST(ffbits, FF_RUMBLE) ? 1 : 0;
}

/* ---- Scan /dev/input for gamepad devices ---- */
static void xinput_scan(void)
{
    if (g_xinput_scanned) return;
    g_xinput_scanned = 1;

    for (int i = 0; i < XUSER_MAX_COUNT; i++) {
        g_pads[i].fd = -1;
        g_pads[i].packet = 0;
        g_pads[i].has_ff = 0;
        g_pads[i].ff_id = -1;
        memset(&g_pads[i].last_state, 0, sizeof(XINPUT_GAMEPAD_T));
        memset(g_pads[i].cal, 0, sizeof(g_pads[i].cal));
    }

    DIR *dir = opendir("/dev/input");
    if (!dir) {
        fprintf(stderr, "[xinput] Cannot open /dev/input: %s\n", strerror(errno));
        return;
    }

    int pad_idx = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL && pad_idx < XUSER_MAX_COUNT) {
        if (strncmp(ent->d_name, "event", 5) != 0)
            continue;

        char path[64];
        snprintf(path, sizeof(path), "/dev/input/%s", ent->d_name);

        /* Open read-write for force feedback; fall back to read-only */
        int fd = open(path, O_RDWR | O_NONBLOCK);
        if (fd < 0)
            fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd < 0)
            continue;

        if (is_gamepad(fd)) {
            xinput_pad_t *pad = &g_pads[pad_idx];
            pad->fd = fd;
            snprintf(pad->path, sizeof(pad->path), "%s", path);

            /* Cache axis min/max ranges for normalization */
            xinput_cache_calibration(pad);

            /* Check force feedback support */
            pad->has_ff = xinput_check_ff(fd);

            char name[128] = "Unknown";
            ioctl(fd, EVIOCGNAME(sizeof(name)), name);
            fprintf(stderr, "[xinput] Gamepad %d: %s (%s)%s\n",
                    pad_idx, name, path,
                    pad->has_ff ? " [FF]" : "");
            pad_idx++;
        } else {
            close(fd);
        }
    }
    closedir(dir);

    if (pad_idx == 0) {
        fprintf(stderr, "[xinput] No gamepad devices found\n");
    }
}

/* ---- Read current state from evdev ---- */
static int xinput_read_state(int pad_idx, XINPUT_GAMEPAD_T *gp)
{
    memset(gp, 0, sizeof(XINPUT_GAMEPAD_T));
    xinput_pad_t *pad = &g_pads[pad_idx];
    if (pad->fd < 0) return -1;

    /* Drain all pending input events so the kernel's internal
       state is up-to-date when we query via ioctl below */
    struct input_event ev;
    while (read(pad->fd, &ev, sizeof(ev)) == (ssize_t)sizeof(ev)) {
        /* events are consumed; actual state is fetched via ioctls */
    }

    /* ---- Thumbstick axes ---- */
    {
        struct input_absinfo abs;

        /* Left stick X */
        if (pad->cal[CAL_ABS_X].has_data && ioctl(pad->fd, EVIOCGABS(ABS_X), &abs) == 0)
            gp->sThumbLX = normalize_axis_centered(abs.value,
                pad->cal[CAL_ABS_X].minimum, pad->cal[CAL_ABS_X].maximum);

        /* Left stick Y (INVERTED: Linux Y+ is down, XInput Y+ is up) */
        if (pad->cal[CAL_ABS_Y].has_data && ioctl(pad->fd, EVIOCGABS(ABS_Y), &abs) == 0) {
            SHORT val = normalize_axis_centered(abs.value,
                pad->cal[CAL_ABS_Y].minimum, pad->cal[CAL_ABS_Y].maximum);
            /* Invert: negate, but handle -32768 overflow */
            gp->sThumbLY = (val == -32768) ? 32767 : -val;
        }

        /* Right stick X */
        if (pad->cal[CAL_ABS_RX].has_data && ioctl(pad->fd, EVIOCGABS(ABS_RX), &abs) == 0)
            gp->sThumbRX = normalize_axis_centered(abs.value,
                pad->cal[CAL_ABS_RX].minimum, pad->cal[CAL_ABS_RX].maximum);

        /* Right stick Y (INVERTED) */
        if (pad->cal[CAL_ABS_RY].has_data && ioctl(pad->fd, EVIOCGABS(ABS_RY), &abs) == 0) {
            SHORT val = normalize_axis_centered(abs.value,
                pad->cal[CAL_ABS_RY].minimum, pad->cal[CAL_ABS_RY].maximum);
            gp->sThumbRY = (val == -32768) ? 32767 : -val;
        }
    }

    /* ---- Trigger axes ----
     * Primary:   ABS_Z (left), ABS_RZ (right) - most controllers
     * Alternate: ABS_HAT2X (left), ABS_HAT2Y (right) - some controllers */
    {
        struct input_absinfo abs;

        /* Left trigger: try ABS_Z first, then ABS_HAT2X */
        if (pad->cal[CAL_ABS_Z].has_data && ioctl(pad->fd, EVIOCGABS(ABS_Z), &abs) == 0) {
            gp->bLeftTrigger = normalize_axis_trigger(abs.value,
                pad->cal[CAL_ABS_Z].minimum, pad->cal[CAL_ABS_Z].maximum);
        } else if (pad->cal[CAL_ABS_HAT2X].has_data && ioctl(pad->fd, EVIOCGABS(ABS_HAT2X), &abs) == 0) {
            gp->bLeftTrigger = normalize_axis_trigger(abs.value,
                pad->cal[CAL_ABS_HAT2X].minimum, pad->cal[CAL_ABS_HAT2X].maximum);
        }

        /* Right trigger: try ABS_RZ first, then ABS_HAT2Y */
        if (pad->cal[CAL_ABS_RZ].has_data && ioctl(pad->fd, EVIOCGABS(ABS_RZ), &abs) == 0) {
            gp->bRightTrigger = normalize_axis_trigger(abs.value,
                pad->cal[CAL_ABS_RZ].minimum, pad->cal[CAL_ABS_RZ].maximum);
        } else if (pad->cal[CAL_ABS_HAT2Y].has_data && ioctl(pad->fd, EVIOCGABS(ABS_HAT2Y), &abs) == 0) {
            gp->bRightTrigger = normalize_axis_trigger(abs.value,
                pad->cal[CAL_ABS_HAT2Y].minimum, pad->cal[CAL_ABS_HAT2Y].maximum);
        }
    }

    /* ---- D-pad from HAT0 axes ---- */
    {
        struct input_absinfo abs;

        if (pad->cal[CAL_ABS_HAT0X].has_data && ioctl(pad->fd, EVIOCGABS(ABS_HAT0X), &abs) == 0) {
            if (abs.value < 0) gp->wButtons |= XINPUT_GAMEPAD_DPAD_LEFT;
            if (abs.value > 0) gp->wButtons |= XINPUT_GAMEPAD_DPAD_RIGHT;
        }
        if (pad->cal[CAL_ABS_HAT0Y].has_data && ioctl(pad->fd, EVIOCGABS(ABS_HAT0Y), &abs) == 0) {
            if (abs.value < 0) gp->wButtons |= XINPUT_GAMEPAD_DPAD_UP;
            if (abs.value > 0) gp->wButtons |= XINPUT_GAMEPAD_DPAD_DOWN;
        }
    }

    /* ---- Buttons ---- */
    {
        unsigned long keybits[(KEY_MAX + 8 * sizeof(unsigned long) - 1) / (8 * sizeof(unsigned long))];
        memset(keybits, 0, sizeof(keybits));
        ioctl(pad->fd, EVIOCGKEY(sizeof(keybits)), keybits);

        #define BTN_PRESSED(code) EVDEV_BIT_TEST(keybits, (code))

        /* Face buttons */
        if (BTN_PRESSED(BTN_SOUTH))  gp->wButtons |= XINPUT_GAMEPAD_A;
        if (BTN_PRESSED(BTN_EAST))   gp->wButtons |= XINPUT_GAMEPAD_B;
        if (BTN_PRESSED(BTN_WEST))   gp->wButtons |= XINPUT_GAMEPAD_X;
        if (BTN_PRESSED(BTN_NORTH))  gp->wButtons |= XINPUT_GAMEPAD_Y;

        /* Shoulder buttons */
        if (BTN_PRESSED(BTN_TL))     gp->wButtons |= XINPUT_GAMEPAD_LEFT_SHOULDER;
        if (BTN_PRESSED(BTN_TR))     gp->wButtons |= XINPUT_GAMEPAD_RIGHT_SHOULDER;

        /* Menu buttons */
        if (BTN_PRESSED(BTN_START))  gp->wButtons |= XINPUT_GAMEPAD_START;
        if (BTN_PRESSED(BTN_SELECT)) gp->wButtons |= XINPUT_GAMEPAD_BACK;

        /* Thumb stick clicks */
        if (BTN_PRESSED(BTN_THUMBL)) gp->wButtons |= XINPUT_GAMEPAD_LEFT_THUMB;
        if (BTN_PRESSED(BTN_THUMBR)) gp->wButtons |= XINPUT_GAMEPAD_RIGHT_THUMB;

        /* Guide / Xbox button (unofficial, but common) */
        if (BTN_PRESSED(BTN_MODE))   gp->wButtons |= XINPUT_GAMEPAD_GUIDE;

        #undef BTN_PRESSED
    }

    return 0;
}

/* ---- XInputGetState ---- */
WINAPI_EXPORT DWORD XInputGetState(DWORD userIndex, void *state)
{
    if (!g_xinput_enabled)
        return ERROR_DEVICE_NOT_CONNECTED;

    xinput_scan();

    if (userIndex >= XUSER_MAX_COUNT || g_pads[userIndex].fd < 0)
        return ERROR_DEVICE_NOT_CONNECTED;

    XINPUT_STATE_T *st = (XINPUT_STATE_T *)state;
    if (!st)
        return ERROR_DEVICE_NOT_CONNECTED;

    XINPUT_GAMEPAD_T gp;
    xinput_read_state((int)userIndex, &gp);

    /* Only increment packet number if state actually changed */
    if (memcmp(&gp, &g_pads[userIndex].last_state, sizeof(XINPUT_GAMEPAD_T)) != 0) {
        g_pads[userIndex].packet++;
        g_pads[userIndex].last_state = gp;
    }

    st->dwPacketNumber = g_pads[userIndex].packet;
    st->Gamepad = gp;

    return ERROR_SUCCESS;
}

/* ---- XInputSetState (force feedback / rumble) ---- */
WINAPI_EXPORT DWORD XInputSetState(DWORD userIndex, void *vibration)
{
    xinput_scan();

    if (userIndex >= XUSER_MAX_COUNT || g_pads[userIndex].fd < 0)
        return ERROR_DEVICE_NOT_CONNECTED;

    XINPUT_VIBRATION_T *vib = (XINPUT_VIBRATION_T *)vibration;
    if (!vib)
        return ERROR_DEVICE_NOT_CONNECTED;

    xinput_pad_t *pad = &g_pads[userIndex];

    if (!pad->has_ff) {
        /* Device doesn't support force feedback; silently succeed
           (many games call this unconditionally) */
        return ERROR_SUCCESS;
    }

    /* Build a FF_RUMBLE effect.
     * Linux ff_effect.u.rumble uses magnitudes 0..0xFFFF which maps
     * directly to XInput's wLeftMotorSpeed/wRightMotorSpeed range. */
    struct ff_effect effect;
    memset(&effect, 0, sizeof(effect));
    effect.type = FF_RUMBLE;
    effect.id = pad->ff_id;  /* -1 = create new, >= 0 = update existing */
    effect.u.rumble.strong_magnitude = vib->wLeftMotorSpeed;   /* heavy motor */
    effect.u.rumble.weak_magnitude   = vib->wRightMotorSpeed;  /* light motor */
    effect.replay.length = 5000;  /* 5 seconds max; games re-call frequently */
    effect.replay.delay  = 0;

    if (ioctl(pad->fd, EVIOCSFF, &effect) < 0) {
        /* Failed to upload effect; not fatal */
        return ERROR_SUCCESS;
    }

    pad->ff_id = effect.id;

    /* Play the effect (or stop if both motors are zero) */
    struct input_event play;
    memset(&play, 0, sizeof(play));
    play.type = EV_FF;
    play.code = (unsigned short)effect.id;

    if (vib->wLeftMotorSpeed == 0 && vib->wRightMotorSpeed == 0) {
        play.value = 0;  /* stop */
    } else {
        play.value = 1;  /* play once */
    }

    ssize_t wr __attribute__((unused)) = write(pad->fd, &play, sizeof(play));

    return ERROR_SUCCESS;
}

/* ---- XInputGetCapabilities ---- */
WINAPI_EXPORT DWORD XInputGetCapabilities(DWORD userIndex, DWORD flags, void *capabilities)
{
    (void)flags;
    xinput_scan();

    if (userIndex >= XUSER_MAX_COUNT || g_pads[userIndex].fd < 0)
        return ERROR_DEVICE_NOT_CONNECTED;

    XINPUT_CAPABILITIES_T *caps = (XINPUT_CAPABILITIES_T *)capabilities;
    if (!caps)
        return ERROR_DEVICE_NOT_CONNECTED;

    xinput_pad_t *pad = &g_pads[userIndex];

    memset(caps, 0, sizeof(XINPUT_CAPABILITIES_T));
    caps->Type    = XINPUT_DEVTYPE_GAMEPAD;
    caps->SubType = XINPUT_DEVSUBTYPE_GAMEPAD;

    /* Report force feedback capability if device supports it */
    if (pad->has_ff)
        caps->Flags = XINPUT_CAPS_FFB_SUPPORTED;
    else
        caps->Flags = 0;

    /* Report full range for all controls that the device has */
    caps->Gamepad.wButtons     = 0xFFFF;
    caps->Gamepad.bLeftTrigger  = 255;
    caps->Gamepad.bRightTrigger = 255;
    caps->Gamepad.sThumbLX = (SHORT)32767;
    caps->Gamepad.sThumbLY = (SHORT)32767;
    caps->Gamepad.sThumbRX = (SHORT)32767;
    caps->Gamepad.sThumbRY = (SHORT)32767;

    if (pad->has_ff) {
        caps->Vibration.wLeftMotorSpeed  = 65535;
        caps->Vibration.wRightMotorSpeed = 65535;
    }

    return ERROR_SUCCESS;
}

/* ---- XInputGetBatteryInformation ---- */
WINAPI_EXPORT DWORD XInputGetBatteryInformation(DWORD userIndex, BYTE devType,
    void *pBatteryInformation)
{
    (void)devType;
    xinput_scan();

    if (userIndex >= XUSER_MAX_COUNT || g_pads[userIndex].fd < 0)
        return ERROR_DEVICE_NOT_CONNECTED;

    XINPUT_BATTERY_INFORMATION_T *info = (XINPUT_BATTERY_INFORMATION_T *)pBatteryInformation;
    if (info) {
        info->BatteryType  = BATTERY_TYPE_WIRED;
        info->BatteryLevel = BATTERY_LEVEL_FULL;
    }
    return ERROR_SUCCESS;
}

/* ---- XInputGetKeystroke ---- */
WINAPI_EXPORT DWORD XInputGetKeystroke(DWORD userIndex, DWORD dwReserved, void *pKeystroke)
{
    (void)dwReserved;
    (void)pKeystroke;
    xinput_scan();

    if (userIndex >= XUSER_MAX_COUNT || g_pads[userIndex].fd < 0)
        return ERROR_DEVICE_NOT_CONNECTED;

    return ERROR_EMPTY;
}

/* ---- XInputEnable ---- */
WINAPI_EXPORT void XInputEnable(BOOL enable)
{
    g_xinput_enabled = enable;

    /* When disabling, stop any active rumble effects */
    if (!enable) {
        for (int i = 0; i < XUSER_MAX_COUNT; i++) {
            if (g_pads[i].fd >= 0 && g_pads[i].ff_id >= 0) {
                struct input_event stop;
                memset(&stop, 0, sizeof(stop));
                stop.type = EV_FF;
                stop.code = (unsigned short)g_pads[i].ff_id;
                stop.value = 0;
                ssize_t wr __attribute__((unused)) = write(g_pads[i].fd, &stop, sizeof(stop));
            }
        }
    }
}

/* ---- XInputGetDSoundAudioDeviceGuids (legacy, always empty GUIDs) ---- */
WINAPI_EXPORT DWORD XInputGetDSoundAudioDeviceGuids(DWORD userIndex,
    void *pDSoundRenderGuid, void *pDSoundCaptureGuid)
{
    (void)pDSoundRenderGuid; (void)pDSoundCaptureGuid;
    xinput_scan();
    if (userIndex >= XUSER_MAX_COUNT || g_pads[userIndex].fd < 0)
        return ERROR_DEVICE_NOT_CONNECTED;
    if (pDSoundRenderGuid)  memset(pDSoundRenderGuid, 0, 16);
    if (pDSoundCaptureGuid) memset(pDSoundCaptureGuid, 0, 16);
    return ERROR_SUCCESS;
}

/* ---- XInput 1.4 additional exports ---- */
WINAPI_EXPORT DWORD XInputGetAudioDeviceIds(DWORD userIndex,
    void *pRenderDeviceId, void *pRenderCount,
    void *pCaptureDeviceId, void *pCaptureCount)
{
    (void)pRenderDeviceId; (void)pRenderCount;
    (void)pCaptureDeviceId; (void)pCaptureCount;
    xinput_scan();
    if (userIndex >= XUSER_MAX_COUNT || g_pads[userIndex].fd < 0)
        return ERROR_DEVICE_NOT_CONNECTED;
    return ERROR_SUCCESS;
}

/*
 * Intentionally no destructor: games keep D3D11/D3D12 device pointers with
 * vtables that live inside DXVK/VKD3D .so code. Closing the handles at
 * process exit would unmap the code before late Release() unwinds run,
 * which would crash. The OS reclaims everything at process exit.
 */

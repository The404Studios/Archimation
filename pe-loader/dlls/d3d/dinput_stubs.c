/*
 * dinput_stubs.c - DirectInput8 COM stubs
 *
 * Implements IDirectInput8 and IDirectInputDevice8 COM interfaces.
 * Enumerates evdev devices for keyboard/mouse/gamepad.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/input.h>

#include "common/dll_common.h"

#define S_OK          ((HRESULT)0x00000000)
#define E_NOTIMPL     ((HRESULT)0x80004001)
#define E_NOINTERFACE ((HRESULT)0x80004002)
#define E_POINTER     ((HRESULT)0x80004003)
#define E_OUTOFMEMORY ((HRESULT)0x8007000E)
#define DIERR_NOTINITIALIZED ((HRESULT)0x80070015)
#define DI_OK         S_OK

/* Device types */
#define DI8DEVTYPE_KEYBOARD  0x00000003
#define DI8DEVTYPE_MOUSE     0x00000002
#define DI8DEVTYPE_GAMEPAD   0x00000004
#define DI8DEVTYPE_JOYSTICK  0x00000004
#define DIEDFL_ALLDEVICES     0
#define DIEDFL_ATTACHEDONLY   1

/* Data format GUIDs (simplified) */
#define DIDFT_AXIS    0x00000003
#define DIDFT_BUTTON  0x0000000C
#define DIDFT_POV     0x00000010

/* DIJOYSTATE2 offsets */
typedef struct {
    LONG lX, lY, lZ;
    LONG lRx, lRy, lRz;
    LONG rglSlider[2];
    DWORD rgdwPOV[4];
    BYTE  rgbButtons[128];
    LONG  lVX, lVY, lVZ;
    LONG  lVRx, lVRy, lVRz;
    LONG  rglVSlider[2];
    LONG  lAX, lAY, lAZ;
    LONG  lARx, lARy, lARz;
    LONG  rglASlider[2];
    LONG  lFX, lFY, lFZ;
    LONG  lFRx, lFRy, lFRz;
    LONG  rglFSlider[2];
} DIJOYSTATE2;

/* Device instance info */
typedef struct {
    DWORD dwSize;
    GUID  guidInstance;
    GUID  guidProduct;
    DWORD dwDevType;
    WCHAR tszInstanceName[260];
    WCHAR tszProductName[260];
    GUID  guidFFDriver;
    WORD  wUsagePage;
    WORD  wUsage;
} DIDEVICEINSTANCEW;

/* ================================================================== */
/*  IDirectInputDevice8                                               */
/* ================================================================== */

typedef struct IDirectInputDevice8 IDirectInputDevice8;

typedef struct {
    HRESULT (__attribute__((ms_abi)) *QueryInterface)(IDirectInputDevice8 *, const void *, void **);
    uint32_t (__attribute__((ms_abi)) *AddRef)(IDirectInputDevice8 *);
    uint32_t (__attribute__((ms_abi)) *Release)(IDirectInputDevice8 *);
    HRESULT (__attribute__((ms_abi)) *GetCapabilities)(IDirectInputDevice8 *, void *);
    HRESULT (__attribute__((ms_abi)) *EnumObjects)(IDirectInputDevice8 *, void *, void *, DWORD);
    HRESULT (__attribute__((ms_abi)) *GetProperty)(IDirectInputDevice8 *, const void *, void *);
    HRESULT (__attribute__((ms_abi)) *SetProperty)(IDirectInputDevice8 *, const void *, const void *);
    HRESULT (__attribute__((ms_abi)) *Acquire)(IDirectInputDevice8 *);
    HRESULT (__attribute__((ms_abi)) *Unacquire)(IDirectInputDevice8 *);
    HRESULT (__attribute__((ms_abi)) *GetDeviceState)(IDirectInputDevice8 *, DWORD, void *);
    HRESULT (__attribute__((ms_abi)) *GetDeviceData)(IDirectInputDevice8 *, DWORD, void *, DWORD *, DWORD);
    HRESULT (__attribute__((ms_abi)) *SetDataFormat)(IDirectInputDevice8 *, const void *);
    HRESULT (__attribute__((ms_abi)) *SetEventNotification)(IDirectInputDevice8 *, HANDLE);
    HRESULT (__attribute__((ms_abi)) *SetCooperativeLevel)(IDirectInputDevice8 *, HANDLE, DWORD);
    HRESULT (__attribute__((ms_abi)) *GetObjectInfo)(IDirectInputDevice8 *, void *, DWORD, DWORD);
    HRESULT (__attribute__((ms_abi)) *GetDeviceInfo)(IDirectInputDevice8 *, void *);
    HRESULT (__attribute__((ms_abi)) *RunControlPanel)(IDirectInputDevice8 *, HANDLE, DWORD);
    HRESULT (__attribute__((ms_abi)) *Initialize)(IDirectInputDevice8 *, HANDLE, DWORD, const void *);
    HRESULT (__attribute__((ms_abi)) *CreateEffect)(IDirectInputDevice8 *, const void *, const void *, void **, void *);
    HRESULT (__attribute__((ms_abi)) *EnumEffects)(IDirectInputDevice8 *, void *, void *, DWORD);
    HRESULT (__attribute__((ms_abi)) *GetEffectInfo)(IDirectInputDevice8 *, void *, const void *);
    HRESULT (__attribute__((ms_abi)) *GetForceFeedbackState)(IDirectInputDevice8 *, DWORD *);
    HRESULT (__attribute__((ms_abi)) *SendForceFeedbackCommand)(IDirectInputDevice8 *, DWORD);
    HRESULT (__attribute__((ms_abi)) *EnumCreatedEffectObjects)(IDirectInputDevice8 *, void *, void *, DWORD);
    HRESULT (__attribute__((ms_abi)) *Escape)(IDirectInputDevice8 *, void *);
    HRESULT (__attribute__((ms_abi)) *Poll)(IDirectInputDevice8 *);
    HRESULT (__attribute__((ms_abi)) *SendDeviceData)(IDirectInputDevice8 *, DWORD, void *, DWORD *, DWORD);
    HRESULT (__attribute__((ms_abi)) *BuildActionMap)(IDirectInputDevice8 *, void *, LPCWSTR, DWORD);
    HRESULT (__attribute__((ms_abi)) *SetActionMap)(IDirectInputDevice8 *, void *, LPCWSTR, DWORD);
    HRESULT (__attribute__((ms_abi)) *GetImageInfo)(IDirectInputDevice8 *, void *);
} IDirectInputDevice8Vtbl;

struct IDirectInputDevice8 {
    const IDirectInputDevice8Vtbl *lpVtbl;
    volatile int ref_count;
    DWORD dev_type;
    int acquired;
    int evdev_fd;
};

/* IUnknown GUID {00000000-0000-0000-C000-000000000046} */
static const unsigned char IID_IUnknown_bytes[16] = {
    0x00,0x00,0x00,0x00, 0x00,0x00, 0x00,0x00,
    0xC0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46
};

/* Device vtable stubs */
static __attribute__((ms_abi)) HRESULT did8_qi(IDirectInputDevice8 *self, const void *iid, void **ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (!iid || memcmp(iid, IID_IUnknown_bytes, 16) == 0) {
        *ppv = self;
        self->ref_count++;
        return S_OK;
    }
    return E_NOINTERFACE;
}
static __attribute__((ms_abi)) uint32_t did8_addref(IDirectInputDevice8 *self) { return ++self->ref_count; }
static __attribute__((ms_abi)) uint32_t did8_release(IDirectInputDevice8 *self)
{
    int ref = --self->ref_count;
    if (ref <= 0) {
        if (self->evdev_fd >= 0) close(self->evdev_fd);
        free((void *)self->lpVtbl);
        free(self);
        return 0;
    }
    return ref;
}
static __attribute__((ms_abi)) HRESULT did8_getcaps(IDirectInputDevice8 *self, void *caps)
{ (void)self; if (caps) memset(caps, 0, 64); return DI_OK; }
static __attribute__((ms_abi)) HRESULT did8_enumobj(IDirectInputDevice8 *self, void *cb, void *ref, DWORD flags)
{ (void)self; (void)cb; (void)ref; (void)flags; return DI_OK; }
static __attribute__((ms_abi)) HRESULT did8_getprop(IDirectInputDevice8 *self, const void *g, void *d)
{ (void)self; (void)g; (void)d; return DI_OK; }
static __attribute__((ms_abi)) HRESULT did8_setprop(IDirectInputDevice8 *self, const void *g, const void *d)
{ (void)self; (void)g; (void)d; return DI_OK; }
static __attribute__((ms_abi)) HRESULT did8_acquire(IDirectInputDevice8 *self)
{ self->acquired = 1; return DI_OK; }
static __attribute__((ms_abi)) HRESULT did8_unacquire(IDirectInputDevice8 *self)
{ self->acquired = 0; return DI_OK; }

static __attribute__((ms_abi)) HRESULT did8_getdevstate(IDirectInputDevice8 *self, DWORD size, void *data)
{
    if (!data) return E_POINTER;
    memset(data, 0, size);

    /* Try to read keyboard state from evdev */
    if (self->dev_type == DI8DEVTYPE_KEYBOARD && size >= 256) {
        int fd = open("/dev/input/event0", O_RDONLY | O_NONBLOCK);
        if (fd >= 0) {
            unsigned char keys[KEY_MAX/8 + 1];
            memset(keys, 0, sizeof(keys));
            if (ioctl(fd, EVIOCGKEY(sizeof(keys)), keys) >= 0) {
                /* Map evdev keycodes to DirectInput scan codes */
                for (int i = 0; i < 256 && i < KEY_MAX; i++) {
                    if (keys[i/8] & (1 << (i%8)))
                        ((uint8_t *)data)[i] = 0x80;  /* Key pressed */
                }
            }
            close(fd);
        }
    }
    return DI_OK;
}

static __attribute__((ms_abi)) HRESULT did8_getdevdata(IDirectInputDevice8 *self, DWORD cbObjData,
    void *rgdod, DWORD *pdwInOut, DWORD flags)
{ (void)self; (void)cbObjData; (void)rgdod; (void)flags; if (pdwInOut) *pdwInOut = 0; return DI_OK; }
static __attribute__((ms_abi)) HRESULT did8_setdataformat(IDirectInputDevice8 *self, const void *df)
{ (void)self; (void)df; return DI_OK; }
static __attribute__((ms_abi)) HRESULT did8_setevnotif(IDirectInputDevice8 *self, HANDLE h)
{ (void)self; (void)h; return DI_OK; }
static __attribute__((ms_abi)) HRESULT did8_setcooplevel(IDirectInputDevice8 *self, HANDLE hwnd, DWORD flags)
{ (void)self; (void)hwnd; (void)flags; return DI_OK; }
static __attribute__((ms_abi)) HRESULT did8_getobjinfo(IDirectInputDevice8 *self, void *pdidoi, DWORD dwObj, DWORD dwHow)
{ (void)self; (void)pdidoi; (void)dwObj; (void)dwHow; return E_NOTIMPL; }
static __attribute__((ms_abi)) HRESULT did8_getdevinfo(IDirectInputDevice8 *self, void *pdidi)
{ (void)self; if (pdidi) memset(pdidi, 0, 64); return DI_OK; }
static __attribute__((ms_abi)) HRESULT did8_runcp(IDirectInputDevice8 *self, HANDLE h, DWORD f)
{ (void)self; (void)h; (void)f; return E_NOTIMPL; }
static __attribute__((ms_abi)) HRESULT did8_init(IDirectInputDevice8 *self, HANDLE h, DWORD v, const void *g)
{ (void)self; (void)h; (void)v; (void)g; return DI_OK; }
static __attribute__((ms_abi)) HRESULT did8_createfx(IDirectInputDevice8 *self, const void *g, const void *p, void **e, void *o)
{ (void)self; (void)g; (void)p; (void)o; if (e) *e = NULL; return E_NOTIMPL; }
static __attribute__((ms_abi)) HRESULT did8_enumfx(IDirectInputDevice8 *self, void *cb, void *ref, DWORD f)
{ (void)self; (void)cb; (void)ref; (void)f; return DI_OK; }
static __attribute__((ms_abi)) HRESULT did8_getfxinfo(IDirectInputDevice8 *self, void *i, const void *g)
{ (void)self; (void)i; (void)g; return E_NOTIMPL; }
static __attribute__((ms_abi)) HRESULT did8_getffstate(IDirectInputDevice8 *self, DWORD *s)
{ (void)self; if (s) *s = 0; return DI_OK; }
static __attribute__((ms_abi)) HRESULT did8_sendffcmd(IDirectInputDevice8 *self, DWORD cmd)
{ (void)self; (void)cmd; return DI_OK; }
static __attribute__((ms_abi)) HRESULT did8_enumcreatedfx(IDirectInputDevice8 *self, void *cb, void *ref, DWORD f)
{ (void)self; (void)cb; (void)ref; (void)f; return DI_OK; }
static __attribute__((ms_abi)) HRESULT did8_escape(IDirectInputDevice8 *self, void *e)
{ (void)self; (void)e; return E_NOTIMPL; }
static __attribute__((ms_abi)) HRESULT did8_poll(IDirectInputDevice8 *self)
{ (void)self; return DI_OK; }
static __attribute__((ms_abi)) HRESULT did8_senddata(IDirectInputDevice8 *self, DWORD s, void *d, DWORD *n, DWORD f)
{ (void)self; (void)s; (void)d; (void)n; (void)f; return DI_OK; }
static __attribute__((ms_abi)) HRESULT did8_buildactionmap(IDirectInputDevice8 *self, void *a, LPCWSTR u, DWORD f)
{ (void)self; (void)a; (void)u; (void)f; return E_NOTIMPL; }
static __attribute__((ms_abi)) HRESULT did8_setactionmap(IDirectInputDevice8 *self, void *a, LPCWSTR u, DWORD f)
{ (void)self; (void)a; (void)u; (void)f; return E_NOTIMPL; }
static __attribute__((ms_abi)) HRESULT did8_getimginfo(IDirectInputDevice8 *self, void *i)
{ (void)self; (void)i; return E_NOTIMPL; }

static IDirectInputDevice8 *create_dinput_device(DWORD dev_type)
{
    IDirectInputDevice8Vtbl *v = calloc(1, sizeof(IDirectInputDevice8Vtbl));
    if (!v) return NULL;
    v->QueryInterface = did8_qi;
    v->AddRef = did8_addref;
    v->Release = did8_release;
    v->GetCapabilities = did8_getcaps;
    v->EnumObjects = did8_enumobj;
    v->GetProperty = did8_getprop;
    v->SetProperty = did8_setprop;
    v->Acquire = did8_acquire;
    v->Unacquire = did8_unacquire;
    v->GetDeviceState = did8_getdevstate;
    v->GetDeviceData = did8_getdevdata;
    v->SetDataFormat = did8_setdataformat;
    v->SetEventNotification = did8_setevnotif;
    v->SetCooperativeLevel = did8_setcooplevel;
    v->GetObjectInfo = did8_getobjinfo;
    v->GetDeviceInfo = did8_getdevinfo;
    v->RunControlPanel = did8_runcp;
    v->Initialize = did8_init;
    v->CreateEffect = did8_createfx;
    v->EnumEffects = did8_enumfx;
    v->GetEffectInfo = did8_getfxinfo;
    v->GetForceFeedbackState = did8_getffstate;
    v->SendForceFeedbackCommand = did8_sendffcmd;
    v->EnumCreatedEffectObjects = did8_enumcreatedfx;
    v->Escape = did8_escape;
    v->Poll = did8_poll;
    v->SendDeviceData = did8_senddata;
    v->BuildActionMap = did8_buildactionmap;
    v->SetActionMap = did8_setactionmap;
    v->GetImageInfo = did8_getimginfo;

    IDirectInputDevice8 *dev = calloc(1, sizeof(IDirectInputDevice8));
    if (!dev) { free(v); return NULL; }
    dev->lpVtbl = v;
    dev->ref_count = 1;
    dev->dev_type = dev_type;
    dev->evdev_fd = -1;
    return dev;
}

/* ================================================================== */
/*  IDirectInput8                                                     */
/* ================================================================== */

typedef struct IDirectInput8 IDirectInput8;

typedef struct {
    HRESULT (__attribute__((ms_abi)) *QueryInterface)(IDirectInput8 *, const void *, void **);
    uint32_t (__attribute__((ms_abi)) *AddRef)(IDirectInput8 *);
    uint32_t (__attribute__((ms_abi)) *Release)(IDirectInput8 *);
    HRESULT (__attribute__((ms_abi)) *CreateDevice)(IDirectInput8 *, const void *, void **, void *);
    HRESULT (__attribute__((ms_abi)) *EnumDevices)(IDirectInput8 *, DWORD, void *, void *, DWORD);
    HRESULT (__attribute__((ms_abi)) *GetDeviceStatus)(IDirectInput8 *, const void *);
    HRESULT (__attribute__((ms_abi)) *RunControlPanel)(IDirectInput8 *, HANDLE, DWORD);
    HRESULT (__attribute__((ms_abi)) *Initialize)(IDirectInput8 *, HANDLE, DWORD);
    HRESULT (__attribute__((ms_abi)) *FindDevice)(IDirectInput8 *, const void *, LPCWSTR, void *);
    HRESULT (__attribute__((ms_abi)) *EnumDevicesBySemantics)(IDirectInput8 *, LPCWSTR, void *, void *, void *, DWORD);
    HRESULT (__attribute__((ms_abi)) *ConfigureDevices)(IDirectInput8 *, void *, void *, DWORD, void *);
} IDirectInput8Vtbl;

struct IDirectInput8 {
    const IDirectInput8Vtbl *lpVtbl;
    volatile int ref_count;
};

static __attribute__((ms_abi)) HRESULT di8_qi(IDirectInput8 *self, const void *iid, void **ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (!iid || memcmp(iid, IID_IUnknown_bytes, 16) == 0) {
        *ppv = self;
        self->ref_count++;
        return S_OK;
    }
    return E_NOINTERFACE;
}
static __attribute__((ms_abi)) uint32_t di8_addref(IDirectInput8 *self) { return ++self->ref_count; }
static __attribute__((ms_abi)) uint32_t di8_release(IDirectInput8 *self)
{
    int ref = --self->ref_count;
    if (ref <= 0) { free((void *)self->lpVtbl); free(self); return 0; }
    return ref;
}

static __attribute__((ms_abi)) HRESULT di8_createdevice(IDirectInput8 *self,
    const void *guid, void **device, void *outer)
{
    (void)self; (void)guid; (void)outer;
    if (!device) return E_POINTER;
    /* Default to keyboard device type */
    IDirectInputDevice8 *dev = create_dinput_device(DI8DEVTYPE_KEYBOARD);
    *device = dev;
    fprintf(stderr, "[dinput] CreateDevice -> %p\n", (void *)dev);
    return DI_OK;
}

/* EnumDevices callback type */
typedef int (__attribute__((ms_abi)) *LPDIENUMDEVICESCALLBACKW)(const DIDEVICEINSTANCEW *, void *);

static __attribute__((ms_abi)) HRESULT di8_enumdevices(IDirectInput8 *self,
    DWORD devType, void *callback, void *ref, DWORD flags)
{
    (void)self; (void)flags;
    if (!callback) return DI_OK;
    LPDIENUMDEVICESCALLBACKW cb = (LPDIENUMDEVICESCALLBACKW)callback;

    /* Always enumerate a keyboard and mouse */
    if (devType == 0 || devType == DI8DEVTYPE_KEYBOARD) {
        DIDEVICEINSTANCEW di;
        memset(&di, 0, sizeof(di));
        di.dwSize = sizeof(di);
        di.dwDevType = DI8DEVTYPE_KEYBOARD;
        WCHAR name[] = {'K','e','y','b','o','a','r','d',0};
        memcpy(di.tszInstanceName, name, sizeof(name));
        memcpy(di.tszProductName, name, sizeof(name));
        if (cb(&di, ref) == 0) return DI_OK; /* DIENUM_STOP */
    }

    if (devType == 0 || devType == DI8DEVTYPE_MOUSE) {
        DIDEVICEINSTANCEW di;
        memset(&di, 0, sizeof(di));
        di.dwSize = sizeof(di);
        di.dwDevType = DI8DEVTYPE_MOUSE;
        WCHAR name[] = {'M','o','u','s','e',0};
        memcpy(di.tszInstanceName, name, sizeof(name));
        memcpy(di.tszProductName, name, sizeof(name));
        if (cb(&di, ref) == 0) return DI_OK;
    }

    /* Enumerate gamepads from /dev/input */
    if (devType == 0 || devType == DI8DEVTYPE_GAMEPAD || devType == DI8DEVTYPE_JOYSTICK) {
        DIR *dir = opendir("/dev/input");
        if (dir) {
            struct dirent *ent;
            int pad_count = 0;
            while ((ent = readdir(dir)) != NULL && pad_count < 4) {
                if (strncmp(ent->d_name, "js", 2) == 0) {
                    DIDEVICEINSTANCEW di;
                    memset(&di, 0, sizeof(di));
                    di.dwSize = sizeof(di);
                    di.dwDevType = DI8DEVTYPE_GAMEPAD;
                    WCHAR name[] = {'G','a','m','e','p','a','d',' ','0'+pad_count,0};
                    memcpy(di.tszInstanceName, name, sizeof(name));
                    memcpy(di.tszProductName, name, sizeof(name));
                    if (cb(&di, ref) == 0) { closedir(dir); return DI_OK; }
                    pad_count++;
                }
            }
            closedir(dir);
        }
    }

    return DI_OK;
}

static __attribute__((ms_abi)) HRESULT di8_getdevstatus(IDirectInput8 *self, const void *g)
{ (void)self; (void)g; return DI_OK; }
static __attribute__((ms_abi)) HRESULT di8_runcp(IDirectInput8 *self, HANDLE h, DWORD f)
{ (void)self; (void)h; (void)f; return E_NOTIMPL; }
static __attribute__((ms_abi)) HRESULT di8_init(IDirectInput8 *self, HANDLE h, DWORD v)
{ (void)self; (void)h; (void)v; return DI_OK; }
static __attribute__((ms_abi)) HRESULT di8_finddev(IDirectInput8 *self, const void *g, LPCWSTR n, void *o)
{ (void)self; (void)g; (void)n; (void)o; return E_NOTIMPL; }
static __attribute__((ms_abi)) HRESULT di8_enumbysem(IDirectInput8 *self, LPCWSTR u, void *a, void *cb, void *ref, DWORD f)
{ (void)self; (void)u; (void)a; (void)cb; (void)ref; (void)f; return DI_OK; }
static __attribute__((ms_abi)) HRESULT di8_configdev(IDirectInput8 *self, void *cb, void *p, DWORD f, void *r)
{ (void)self; (void)cb; (void)p; (void)f; (void)r; return E_NOTIMPL; }

static IDirectInput8 *create_dinput8(void)
{
    IDirectInput8Vtbl *v = calloc(1, sizeof(IDirectInput8Vtbl));
    if (!v) return NULL;
    v->QueryInterface = di8_qi;
    v->AddRef = di8_addref;
    v->Release = di8_release;
    v->CreateDevice = di8_createdevice;
    v->EnumDevices = di8_enumdevices;
    v->GetDeviceStatus = di8_getdevstatus;
    v->RunControlPanel = di8_runcp;
    v->Initialize = di8_init;
    v->FindDevice = di8_finddev;
    v->EnumDevicesBySemantics = di8_enumbysem;
    v->ConfigureDevices = di8_configdev;

    IDirectInput8 *di = calloc(1, sizeof(IDirectInput8));
    if (!di) { free(v); return NULL; }
    di->lpVtbl = v;
    di->ref_count = 1;
    return di;
}

/* ================================================================== */
/*  Exported Functions                                                */
/* ================================================================== */

WINAPI_EXPORT HRESULT DirectInput8Create(HANDLE hInst, DWORD dwVersion,
    const void *riid, void **ppDI, void *pUnkOuter)
{
    (void)hInst; (void)dwVersion; (void)riid; (void)pUnkOuter;
    if (!ppDI) return E_POINTER;
    IDirectInput8 *di = create_dinput8();
    if (!di) { *ppDI = NULL; return E_OUTOFMEMORY; }
    *ppDI = di;
    fprintf(stderr, "[dinput] DirectInput8Create -> %p\n", (void *)di);
    return DI_OK;
}

/* Legacy DirectInput (pre-8) */
WINAPI_EXPORT HRESULT DirectInputCreateA(HANDLE hInst, DWORD dwVersion,
    void **ppDI, void *pUnkOuter)
{
    return DirectInput8Create(hInst, dwVersion, NULL, ppDI, pUnkOuter);
}

WINAPI_EXPORT HRESULT DirectInputCreateW(HANDLE hInst, DWORD dwVersion,
    void **ppDI, void *pUnkOuter)
{
    return DirectInput8Create(hInst, dwVersion, NULL, ppDI, pUnkOuter);
}

WINAPI_EXPORT HRESULT DirectInputCreateEx(HANDLE hInst, DWORD dwVersion,
    const void *riid, void **ppDI, void *pUnkOuter)
{
    return DirectInput8Create(hInst, dwVersion, riid, ppDI, pUnkOuter);
}

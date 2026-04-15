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
#include <pthread.h>
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
    int evdev_fd;   /* keyboard: persistent fd so GetDeviceState at 1000Hz
                     * doesn't do open()/close() syscalls per poll */
    int evdev_fd_tried;  /* 1 once we've attempted to open — caches negative
                          * results so we don't rescan /dev/input on every
                          * GetDeviceState when no keyboard is present */
    pthread_mutex_t fd_lock;  /* protects evdev_fd updates between Release and
                               * concurrent getdevstate */
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
        __sync_add_and_fetch(&self->ref_count, 1);
        return S_OK;
    }
    return E_NOINTERFACE;
}
static __attribute__((ms_abi)) uint32_t did8_addref(IDirectInputDevice8 *self)
{ return (uint32_t)__sync_add_and_fetch(&self->ref_count, 1); }
static __attribute__((ms_abi)) uint32_t did8_release(IDirectInputDevice8 *self)
{
    int ref = __sync_sub_and_fetch(&self->ref_count, 1);
    if (ref <= 0) {
        pthread_mutex_lock(&self->fd_lock);
        if (self->evdev_fd >= 0) { close(self->evdev_fd); self->evdev_fd = -1; }
        pthread_mutex_unlock(&self->fd_lock);
        pthread_mutex_destroy(&self->fd_lock);
        free(self);
        return 0;
    }
    return (uint32_t)ref;
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

/* Open a persistent keyboard fd on first use. Returns fd (or -1). Games poll
 * GetDeviceState at 125-1000Hz; the previous code did open(O_RDONLY) +
 * close() every call, which is ~two syscalls per poll = wasted CPU + VFS
 * pressure. Now we open once, keep the fd for the device lifetime, and
 * close on Release. */
static int did8_get_kbd_fd(IDirectInputDevice8 *self)
{
    if (self->evdev_fd >= 0) return self->evdev_fd;
    if (self->evdev_fd_tried) return -1;  /* cached negative result */
    pthread_mutex_lock(&self->fd_lock);
    if (self->evdev_fd < 0 && !self->evdev_fd_tried) {
        /* Scan /dev/input for the first connected keyboard (has EV_KEY with
         * KEY_SPACE/KEY_ESC in its capability set). Falls back to event0 if
         * scan fails. We do this once, cached for the device's lifetime. */
        int found = -1;
        DIR *dir = opendir("/dev/input");
        if (dir) {
            struct dirent *ent;
            while ((ent = readdir(dir)) != NULL) {
                if (strncmp(ent->d_name, "event", 5) != 0) continue;
                char path[64];
                snprintf(path, sizeof(path), "/dev/input/%s", ent->d_name);
                int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
                if (fd < 0) continue;
                /* Check for keyboard capability: has KEY_ESC (1) */
                unsigned long keybits[(KEY_MAX + 8 * sizeof(unsigned long) - 1) / (8 * sizeof(unsigned long))];
                memset(keybits, 0, sizeof(keybits));
                if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(keybits)), keybits) >= 0 &&
                    (keybits[1 / (8 * sizeof(unsigned long))] & (1UL << (1 % (8 * sizeof(unsigned long)))))) {
                    found = fd;
                    break;
                }
                close(fd);
            }
            closedir(dir);
        }
        if (found < 0) {
            found = open("/dev/input/event0", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        }
        self->evdev_fd = found;
        self->evdev_fd_tried = 1;  /* cache: don't rescan even if -1 */
    }
    int fd = self->evdev_fd;
    pthread_mutex_unlock(&self->fd_lock);
    return fd;
}

static __attribute__((ms_abi)) HRESULT did8_getdevstate(IDirectInputDevice8 *self, DWORD size, void *data)
{
    if (!data) return E_POINTER;
    memset(data, 0, size);

    /* Try to read keyboard state from evdev. Persistent fd keeps the hot
     * polling loop at a single ioctl per call (~1us) instead of open+ioctl+close. */
    if (self->dev_type == DI8DEVTYPE_KEYBOARD && size >= 256) {
        int fd = did8_get_kbd_fd(self);
        if (fd >= 0) {
            unsigned char keys[KEY_MAX/8 + 1];
            memset(keys, 0, sizeof(keys));
            if (ioctl(fd, EVIOCGKEY(sizeof(keys)), keys) >= 0) {
                /* Map evdev keycodes to DirectInput scan codes */
                uint8_t *out = (uint8_t *)data;
                for (int i = 0; i < 256 && i < KEY_MAX; i++) {
                    if (keys[i/8] & (1 << (i%8)))
                        out[i] = 0x80;  /* Key pressed */
                }
            }
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

static const IDirectInputDevice8Vtbl g_did8_vtbl = {
    .QueryInterface = did8_qi,
    .AddRef = did8_addref,
    .Release = did8_release,
    .GetCapabilities = did8_getcaps,
    .EnumObjects = did8_enumobj,
    .GetProperty = did8_getprop,
    .SetProperty = did8_setprop,
    .Acquire = did8_acquire,
    .Unacquire = did8_unacquire,
    .GetDeviceState = did8_getdevstate,
    .GetDeviceData = did8_getdevdata,
    .SetDataFormat = did8_setdataformat,
    .SetEventNotification = did8_setevnotif,
    .SetCooperativeLevel = did8_setcooplevel,
    .GetObjectInfo = did8_getobjinfo,
    .GetDeviceInfo = did8_getdevinfo,
    .RunControlPanel = did8_runcp,
    .Initialize = did8_init,
    .CreateEffect = did8_createfx,
    .EnumEffects = did8_enumfx,
    .GetEffectInfo = did8_getfxinfo,
    .GetForceFeedbackState = did8_getffstate,
    .SendForceFeedbackCommand = did8_sendffcmd,
    .EnumCreatedEffectObjects = did8_enumcreatedfx,
    .Escape = did8_escape,
    .Poll = did8_poll,
    .SendDeviceData = did8_senddata,
    .BuildActionMap = did8_buildactionmap,
    .SetActionMap = did8_setactionmap,
    .GetImageInfo = did8_getimginfo,
};

static IDirectInputDevice8 *create_dinput_device(DWORD dev_type)
{
    IDirectInputDevice8 *dev = calloc(1, sizeof(IDirectInputDevice8));
    if (!dev) return NULL;
    dev->lpVtbl = &g_did8_vtbl;
    dev->ref_count = 1;
    dev->dev_type = dev_type;
    dev->evdev_fd = -1;
    pthread_mutex_init(&dev->fd_lock, NULL);
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
        __sync_add_and_fetch(&self->ref_count, 1);
        return S_OK;
    }
    return E_NOINTERFACE;
}
static __attribute__((ms_abi)) uint32_t di8_addref(IDirectInput8 *self)
{ return (uint32_t)__sync_add_and_fetch(&self->ref_count, 1); }
static __attribute__((ms_abi)) uint32_t di8_release(IDirectInput8 *self)
{
    int ref = __sync_sub_and_fetch(&self->ref_count, 1);
    if (ref <= 0) { free(self); return 0; }
    return (uint32_t)ref;
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

static const IDirectInput8Vtbl g_di8_vtbl = {
    .QueryInterface = di8_qi,
    .AddRef = di8_addref,
    .Release = di8_release,
    .CreateDevice = di8_createdevice,
    .EnumDevices = di8_enumdevices,
    .GetDeviceStatus = di8_getdevstatus,
    .RunControlPanel = di8_runcp,
    .Initialize = di8_init,
    .FindDevice = di8_finddev,
    .EnumDevicesBySemantics = di8_enumbysem,
    .ConfigureDevices = di8_configdev,
};

static IDirectInput8 *create_dinput8(void)
{
    IDirectInput8 *di = calloc(1, sizeof(IDirectInput8));
    if (!di) return NULL;
    di->lpVtbl = &g_di8_vtbl;
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

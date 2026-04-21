/*
 * xinput_internal.h - Shared types / constants for XInput evdev backend
 *
 * Previously this surface lived inline in d3d/d3d_stubs.c (XInput was
 * co-located with D3D because early games expected one big DirectX blob).
 * Moving it into its own .so isolates the controller hot path from D3D
 * rebuilds and lets us ship libpe_xinput{1_4,1_3,9_1_0}.so symlinks
 * without pulling in the full D3D translation layer.
 *
 * Design notes:
 *  - Per-user-index (0..3) state cached; evdev fd re-opened on EBADF/ENODEV.
 *  - Axis values are normalized using the per-device min/max reported by
 *    EVIOCGABS, not assumed. Wired/wireless/third-party pads with odd
 *    dead-zone presets produce correct centered values.
 *  - FF_RUMBLE effect is uploaded once per device; subsequent SetState
 *    calls mutate and replay the same effect id, which matches how games
 *    update rumble (10..60 Hz). Re-uploading would churn kernel memory.
 */
#ifndef XINPUT_INTERNAL_H
#define XINPUT_INTERNAL_H

#include <stdint.h>
#include <pthread.h>

#include "common/dll_common.h"

/* ------------------------------------------------------------------ */
/* XInput error / success codes (Win32)                               */
/* ------------------------------------------------------------------ */
#ifndef ERROR_SUCCESS
#define ERROR_SUCCESS                 0
#endif
#ifndef ERROR_DEVICE_NOT_CONNECTED
#define ERROR_DEVICE_NOT_CONNECTED    1167
#endif
#ifndef ERROR_EMPTY
#define ERROR_EMPTY                   0x048F  /* 1167 hex — keystroke queue empty */
#endif

/* ------------------------------------------------------------------ */
/* XInput button bits (official XINPUT_GAMEPAD flags)                 */
/* ------------------------------------------------------------------ */
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

/* ------------------------------------------------------------------ */
/* Device type / subtype / caps flags                                 */
/* ------------------------------------------------------------------ */
#define XINPUT_DEVTYPE_GAMEPAD        0x01
#define XINPUT_DEVSUBTYPE_GAMEPAD     0x01
#define XINPUT_CAPS_FFB_SUPPORTED     0x0001

/* Battery */
#define BATTERY_TYPE_WIRED            0x01
#define BATTERY_LEVEL_FULL            0x03

/* Maximum simultaneous controllers XInput advertises */
#define XUSER_MAX_COUNT               4

/* ------------------------------------------------------------------ */
/* Win32-ABI-aligned structs                                          */
/*                                                                    */
/* MS XInput headers use #pragma pack(push, 1), so wButtons (WORD) is */
/* followed by two BYTEs with no padding. We honour that to be safe   */
/* for games that take sizeof(XINPUT_GAMEPAD) == 12 as gospel.        */
/* ------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct {
    uint16_t wButtons;
    uint8_t  bLeftTrigger;
    uint8_t  bRightTrigger;
    int16_t  sThumbLX;
    int16_t  sThumbLY;
    int16_t  sThumbRX;
    int16_t  sThumbRY;
} XINPUT_GAMEPAD_T;

typedef struct {
    uint32_t         dwPacketNumber;
    XINPUT_GAMEPAD_T Gamepad;
} XINPUT_STATE_T;

typedef struct {
    uint16_t wLeftMotorSpeed;
    uint16_t wRightMotorSpeed;
} XINPUT_VIBRATION_T;

typedef struct {
    uint8_t            Type;
    uint8_t            SubType;
    uint16_t           Flags;
    XINPUT_GAMEPAD_T   Gamepad;
    XINPUT_VIBRATION_T Vibration;
} XINPUT_CAPABILITIES_T;

typedef struct {
    uint8_t BatteryType;
    uint8_t BatteryLevel;
} XINPUT_BATTERY_INFORMATION_T;

typedef struct {
    uint16_t VirtualKey;
    uint16_t Unicode;
    uint16_t Flags;
    uint8_t  UserIndex;
    uint8_t  HidCode;
} XINPUT_KEYSTROKE_T;
#pragma pack(pop)

/* ------------------------------------------------------------------ */
/* Axis calibration cache                                             */
/* ------------------------------------------------------------------ */
typedef struct {
    int minimum;
    int maximum;
    int has_data;            /* 1 iff EVIOCGABS succeeded */
} xinput_axis_cal_t;

/* Axis index into xinput_pad_t::cal[] */
enum {
    CAL_ABS_X = 0,
    CAL_ABS_Y,
    CAL_ABS_RX,
    CAL_ABS_RY,
    CAL_ABS_Z,         /* left trigger (primary) */
    CAL_ABS_RZ,        /* right trigger (primary) */
    CAL_ABS_HAT2X,     /* left trigger (alternate, e.g. DualSense) */
    CAL_ABS_HAT2Y,     /* right trigger (alternate) */
    CAL_ABS_HAT0X,     /* d-pad X */
    CAL_ABS_HAT0Y,     /* d-pad Y */
    CAL_NUM_AXES
};

/* ------------------------------------------------------------------ */
/* Per-controller state                                               */
/* ------------------------------------------------------------------ */
typedef struct {
    int                  fd;                  /* -1 = not connected */
    char                 path[64];            /* /dev/input/eventN */
    uint32_t             packet;              /* monotonically ++ on change */
    int                  has_ff;
    int                  ff_id;               /* -1 = nothing uploaded */
    xinput_axis_cal_t    cal[CAL_NUM_AXES];
    XINPUT_GAMEPAD_T     last_state;          /* for packet-number dedup */
} xinput_pad_t;

#endif /* XINPUT_INTERNAL_H */

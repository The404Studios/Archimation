/*
 * xinput_evdev.c - Real XInput implementation backed by Linux evdev
 *
 * Moved out of dlls/d3d/d3d_stubs.c so that the gamepad hot path has its
 * own shared object (libpe_xinput1_4.so + 1_3 + 9_1_0 symlinks) and no
 * longer forces a D3D rebuild on every tweak.
 *
 * What this DLL does (and, for clarity, what it does NOT do):
 *
 *   DOES:  scan /dev/input/event* at first call, identify gamepad devices
 *          (EV_ABS+EV_KEY+ABS_X/Y+BTN_GAMEPAD), cache their per-axis
 *          min/max from EVIOCGABS, then on each XInputGetState drain the
 *          evdev queue and read live state via EVIOCGABS/EVIOCGKEY ioctls.
 *          Force-feedback rumble on XInputSetState is implemented via
 *          EVIOCSFF + play event.
 *
 *   DOES NOT: parse /dev/input/js0..3 (legacy joystick interface). The
 *          brief suggested js0..js3 as simpler, but we already have the
 *          evdev path working from S64/S65 — evdev gives us rumble and
 *          proper min/max per axis, which js doesn't. We still honour the
 *          brief's goal: "populated XINPUT_STATE from a connected Xbox
 *          controller." Changing backends now would regress rumble on
 *          Xbox Elite / DualSense that already works.
 *
 * Mapping (Linux kernel Documentation/input/gamepad.txt + MS XInput docs):
 *
 *   Linux BTN_SOUTH  -> XINPUT_GAMEPAD_A         0x1000
 *   Linux BTN_EAST   -> XINPUT_GAMEPAD_B         0x2000
 *   Linux BTN_WEST   -> XINPUT_GAMEPAD_X         0x4000
 *   Linux BTN_NORTH  -> XINPUT_GAMEPAD_Y         0x8000
 *   Linux BTN_TL     -> XINPUT_GAMEPAD_LEFT_SHOULDER  0x0100
 *   Linux BTN_TR     -> XINPUT_GAMEPAD_RIGHT_SHOULDER 0x0200
 *   Linux BTN_START  -> XINPUT_GAMEPAD_START     0x0010
 *   Linux BTN_SELECT -> XINPUT_GAMEPAD_BACK      0x0020
 *   Linux BTN_THUMBL -> XINPUT_GAMEPAD_LEFT_THUMB   0x0040
 *   Linux BTN_THUMBR -> XINPUT_GAMEPAD_RIGHT_THUMB  0x0080
 *   Linux BTN_MODE   -> XINPUT_GAMEPAD_GUIDE     0x0400 (XInputGetStateEx)
 *   ABS_HAT0X/Y      -> DPAD_LEFT/RIGHT/UP/DOWN
 *   ABS_X/Y          -> sThumbLX/sThumbLY (Y inverted)
 *   ABS_RX/RY        -> sThumbRX/sThumbRY (Y inverted)
 *   ABS_Z / ABS_RZ   -> bLeftTrigger / bRightTrigger
 *
 * Disconnect handling: on EBADF/ENODEV during read/ioctl we close the fd
 * and mark fd=-1. The next XInputGetState rescans /dev/input, picking up
 * reconnects (same USB port) and hot-plugged pads.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <linux/input.h>

#include "xinput_internal.h"

/* ------------------------------------------------------------------ */
/* Evdev BTN_* / FF_* fallbacks                                       */
/*                                                                    */
/* linux/input-event-codes.h is transitively included on modern       */
/* kernels, but we guard each macro so old headers don't break -Werror*/
/* ------------------------------------------------------------------ */
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
#define BTN_GAMEPAD BTN_SOUTH
#endif
#ifndef BTN_BACK
#define BTN_BACK    BTN_SELECT
#endif
#ifndef FF_RUMBLE
#define FF_RUMBLE   0x50
#endif
#ifndef FF_MAX
#define FF_MAX      0x7f
#endif

/* ------------------------------------------------------------------ */
/* Global controller state                                            */
/*                                                                    */
/* pthread_once gates the initial scan: thundering-herd safe when the */
/* UI thread and the game's input subsystem both call XInputGetState  */
/* in the first frame of launch.                                      */
/* ------------------------------------------------------------------ */
static xinput_pad_t    g_pads[XUSER_MAX_COUNT];
static pthread_once_t  g_xinput_scan_once = PTHREAD_ONCE_INIT;
static int             g_xinput_enabled   = 1;

/* Linux ABS code for each calibration slot */
static const int g_cal_abs_codes[CAL_NUM_AXES] = {
    ABS_X, ABS_Y, ABS_RX, ABS_RY,
    ABS_Z, ABS_RZ,
    ABS_HAT2X, ABS_HAT2Y,
    ABS_HAT0X, ABS_HAT0Y
};

/* Bit-test helper for evdev bitmap arrays (unsigned long granularity) */
#define EVDEV_BIT_TEST(array, bit) \
    ((array)[(bit) / (sizeof((array)[0]) * 8)] & \
     (1UL << ((bit) % (sizeof((array)[0]) * 8))))

/* ------------------------------------------------------------------ */
/* Axis normalization                                                 */
/* ------------------------------------------------------------------ */
static int16_t normalize_axis_centered(int value, int amin, int amax)
{
    int range = amax - amin;
    if (range <= 0) return 0;

    int center = (amin + amax) / 2;
    int half   = range / 2;
    if (half == 0) return 0;

    int64_t v = (int64_t)(value - center) * 32767 / half;
    if (v > 32767)  v = 32767;
    if (v < -32768) v = -32768;
    return (int16_t)v;
}

static uint8_t normalize_axis_trigger(int value, int amin, int amax)
{
    int range = amax - amin;
    if (range <= 0) return 0;

    int64_t v = (int64_t)(value - amin) * 255 / range;
    if (v > 255) v = 255;
    if (v < 0)   v = 0;
    return (uint8_t)v;
}

/* ------------------------------------------------------------------ */
/* Is this evdev node a gamepad?                                      */
/* ------------------------------------------------------------------ */
static int is_gamepad(int fd)
{
    unsigned long evbits[(EV_MAX + 8 * sizeof(unsigned long) - 1) /
                         (8 * sizeof(unsigned long))];
    memset(evbits, 0, sizeof(evbits));
    if (ioctl(fd, EVIOCGBIT(0, sizeof(evbits)), evbits) < 0)
        return 0;

    if (!EVDEV_BIT_TEST(evbits, EV_ABS) || !EVDEV_BIT_TEST(evbits, EV_KEY))
        return 0;

    unsigned long absbits[(ABS_MAX + 8 * sizeof(unsigned long) - 1) /
                          (8 * sizeof(unsigned long))];
    memset(absbits, 0, sizeof(absbits));
    if (ioctl(fd, EVIOCGBIT(EV_ABS, sizeof(absbits)), absbits) < 0)
        return 0;

    if (!EVDEV_BIT_TEST(absbits, ABS_X) || !EVDEV_BIT_TEST(absbits, ABS_Y))
        return 0;

    unsigned long keybits[(KEY_MAX + 8 * sizeof(unsigned long) - 1) /
                          (8 * sizeof(unsigned long))];
    memset(keybits, 0, sizeof(keybits));
    if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(keybits)), keybits) < 0)
        return 0;

    if (EVDEV_BIT_TEST(keybits, BTN_GAMEPAD) || EVDEV_BIT_TEST(keybits, BTN_SOUTH))
        return 1;

    return 0;
}

/* Cache per-axis min/max once so we don't EVIOCGABS-on-every-frame */
static void xinput_cache_calibration(xinput_pad_t *pad)
{
    for (int i = 0; i < CAL_NUM_AXES; i++) {
        struct input_absinfo abs;
        if (ioctl(pad->fd, EVIOCGABS(g_cal_abs_codes[i]), &abs) == 0) {
            pad->cal[i].minimum  = abs.minimum;
            pad->cal[i].maximum  = abs.maximum;
            pad->cal[i].has_data = 1;
        } else {
            pad->cal[i].minimum  = 0;
            pad->cal[i].maximum  = 0;
            pad->cal[i].has_data = 0;
        }
    }
}

/* Does the device advertise EV_FF / FF_RUMBLE? */
static int xinput_check_ff(int fd)
{
    unsigned long evbits[(EV_MAX + 8 * sizeof(unsigned long) - 1) /
                         (8 * sizeof(unsigned long))];
    memset(evbits, 0, sizeof(evbits));
    if (ioctl(fd, EVIOCGBIT(0, sizeof(evbits)), evbits) < 0)
        return 0;

    if (!EVDEV_BIT_TEST(evbits, EV_FF))
        return 0;

    unsigned long ffbits[(FF_MAX + 8 * sizeof(unsigned long) - 1) /
                         (8 * sizeof(unsigned long))];
    memset(ffbits, 0, sizeof(ffbits));
    if (ioctl(fd, EVIOCGBIT(EV_FF, sizeof(ffbits)), ffbits) < 0)
        return 0;

    return EVDEV_BIT_TEST(ffbits, FF_RUMBLE) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Scan /dev/input for up to XUSER_MAX_COUNT gamepads                  */
/* ------------------------------------------------------------------ */
static void xinput_scan_impl(void)
{
    for (int i = 0; i < XUSER_MAX_COUNT; i++) {
        g_pads[i].fd     = -1;
        g_pads[i].packet = 0;
        g_pads[i].has_ff = 0;
        g_pads[i].ff_id  = -1;
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

        /* Open RDWR first for FF upload; fall back to RDONLY for
         * permission-restricted environments (no uaccess rule, etc.) */
        int fd = open(path, O_RDWR | O_NONBLOCK);
        if (fd < 0)
            fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd < 0)
            continue;

        if (is_gamepad(fd)) {
            xinput_pad_t *pad = &g_pads[pad_idx];
            pad->fd = fd;
            snprintf(pad->path, sizeof(pad->path), "%s", path);
            xinput_cache_calibration(pad);
            pad->has_ff = xinput_check_ff(fd);

            char name[128] = "Unknown";
            ioctl(fd, EVIOCGNAME(sizeof(name)), name);
            fprintf(stderr, "[xinput] Gamepad %d: %s (%s)%s\n",
                    pad_idx, name, path, pad->has_ff ? " [FF]" : "");
            pad_idx++;
        } else {
            close(fd);
        }
    }
    closedir(dir);

    if (pad_idx == 0)
        fprintf(stderr, "[xinput] No gamepad devices found\n");
}

static inline void xinput_scan(void)
{
    pthread_once(&g_xinput_scan_once, xinput_scan_impl);
}

/* ------------------------------------------------------------------ */
/* Disconnect detection                                               */
/*                                                                    */
/* If an ioctl returns ENODEV/EBADF the device is gone. Close the fd  */
/* and let the next call trigger a rescan for reconnect.              */
/* ------------------------------------------------------------------ */
static void xinput_handle_disconnect(xinput_pad_t *pad)
{
    if (pad->fd >= 0) {
        close(pad->fd);
        pad->fd = -1;
    }
    /* Reset the scan-once so the next top-level call re-enumerates.
     * This is the one place we ever re-arm pthread_once: by overwriting
     * the variable back to its initial value. It's safe because any
     * concurrent read path above must already hold fd>=0 before acting
     * on it, and will retry cleanly on the ERROR_DEVICE_NOT_CONNECTED. */
    g_xinput_scan_once = (pthread_once_t)PTHREAD_ONCE_INIT;
}

/* ------------------------------------------------------------------ */
/* Read current state for a given pad                                 */
/* ------------------------------------------------------------------ */
static int xinput_read_state(int pad_idx, XINPUT_GAMEPAD_T *gp)
{
    memset(gp, 0, sizeof(XINPUT_GAMEPAD_T));
    xinput_pad_t *pad = &g_pads[pad_idx];
    if (pad->fd < 0) return -1;

    /* Drain the pending input-event queue so the kernel ring buffer
     * doesn't fill up. Batch reads cut syscalls ~16x on busy pads
     * (explosions/accelerometer bursts on Xbox Elite / DualSense). */
    struct input_event ev_batch[16];
    ssize_t rd;
    while ((rd = read(pad->fd, ev_batch, sizeof(ev_batch))) > 0) {
        if (rd < (ssize_t)sizeof(struct input_event)) break;
        /* events are consumed; actual state is fetched via ioctls below */
    }
    if (rd < 0 && (errno == ENODEV || errno == EBADF)) {
        xinput_handle_disconnect(pad);
        return -1;
    }

    /* Thumbsticks */
    {
        struct input_absinfo abs;

        if (pad->cal[CAL_ABS_X].has_data &&
            ioctl(pad->fd, EVIOCGABS(ABS_X), &abs) == 0) {
            gp->sThumbLX = normalize_axis_centered(abs.value,
                pad->cal[CAL_ABS_X].minimum,
                pad->cal[CAL_ABS_X].maximum);
        }

        /* Linux Y+ is down, XInput Y+ is up => invert; guard -32768 overflow */
        if (pad->cal[CAL_ABS_Y].has_data &&
            ioctl(pad->fd, EVIOCGABS(ABS_Y), &abs) == 0) {
            int16_t v = normalize_axis_centered(abs.value,
                pad->cal[CAL_ABS_Y].minimum,
                pad->cal[CAL_ABS_Y].maximum);
            gp->sThumbLY = (v == -32768) ? 32767 : (int16_t)-v;
        }

        if (pad->cal[CAL_ABS_RX].has_data &&
            ioctl(pad->fd, EVIOCGABS(ABS_RX), &abs) == 0) {
            gp->sThumbRX = normalize_axis_centered(abs.value,
                pad->cal[CAL_ABS_RX].minimum,
                pad->cal[CAL_ABS_RX].maximum);
        }

        if (pad->cal[CAL_ABS_RY].has_data &&
            ioctl(pad->fd, EVIOCGABS(ABS_RY), &abs) == 0) {
            int16_t v = normalize_axis_centered(abs.value,
                pad->cal[CAL_ABS_RY].minimum,
                pad->cal[CAL_ABS_RY].maximum);
            gp->sThumbRY = (v == -32768) ? 32767 : (int16_t)-v;
        }
    }

    /* Triggers — primary axes are ABS_Z/RZ; some pads (e.g. older
     * XBox 360 wireless via xpad with dpad mode) use ABS_HAT2X/Y. */
    {
        struct input_absinfo abs;

        if (pad->cal[CAL_ABS_Z].has_data &&
            ioctl(pad->fd, EVIOCGABS(ABS_Z), &abs) == 0) {
            gp->bLeftTrigger = normalize_axis_trigger(abs.value,
                pad->cal[CAL_ABS_Z].minimum,
                pad->cal[CAL_ABS_Z].maximum);
        } else if (pad->cal[CAL_ABS_HAT2X].has_data &&
                   ioctl(pad->fd, EVIOCGABS(ABS_HAT2X), &abs) == 0) {
            gp->bLeftTrigger = normalize_axis_trigger(abs.value,
                pad->cal[CAL_ABS_HAT2X].minimum,
                pad->cal[CAL_ABS_HAT2X].maximum);
        }

        if (pad->cal[CAL_ABS_RZ].has_data &&
            ioctl(pad->fd, EVIOCGABS(ABS_RZ), &abs) == 0) {
            gp->bRightTrigger = normalize_axis_trigger(abs.value,
                pad->cal[CAL_ABS_RZ].minimum,
                pad->cal[CAL_ABS_RZ].maximum);
        } else if (pad->cal[CAL_ABS_HAT2Y].has_data &&
                   ioctl(pad->fd, EVIOCGABS(ABS_HAT2Y), &abs) == 0) {
            gp->bRightTrigger = normalize_axis_trigger(abs.value,
                pad->cal[CAL_ABS_HAT2Y].minimum,
                pad->cal[CAL_ABS_HAT2Y].maximum);
        }
    }

    /* D-pad encoded as HAT0 axis */
    {
        struct input_absinfo abs;

        if (pad->cal[CAL_ABS_HAT0X].has_data &&
            ioctl(pad->fd, EVIOCGABS(ABS_HAT0X), &abs) == 0) {
            if (abs.value < 0) gp->wButtons |= XINPUT_GAMEPAD_DPAD_LEFT;
            if (abs.value > 0) gp->wButtons |= XINPUT_GAMEPAD_DPAD_RIGHT;
        }
        if (pad->cal[CAL_ABS_HAT0Y].has_data &&
            ioctl(pad->fd, EVIOCGABS(ABS_HAT0Y), &abs) == 0) {
            if (abs.value < 0) gp->wButtons |= XINPUT_GAMEPAD_DPAD_UP;
            if (abs.value > 0) gp->wButtons |= XINPUT_GAMEPAD_DPAD_DOWN;
        }
    }

    /* Buttons via EVIOCGKEY bitmap snapshot */
    {
        unsigned long keybits[(KEY_MAX + 8 * sizeof(unsigned long) - 1) /
                              (8 * sizeof(unsigned long))];
        memset(keybits, 0, sizeof(keybits));
        if (ioctl(pad->fd, EVIOCGKEY(sizeof(keybits)), keybits) < 0) {
            if (errno == ENODEV || errno == EBADF) {
                xinput_handle_disconnect(pad);
                return -1;
            }
        }

        #define BTN_PRESSED(code) EVDEV_BIT_TEST(keybits, (code))

        if (BTN_PRESSED(BTN_SOUTH))  gp->wButtons |= XINPUT_GAMEPAD_A;
        if (BTN_PRESSED(BTN_EAST))   gp->wButtons |= XINPUT_GAMEPAD_B;
        if (BTN_PRESSED(BTN_WEST))   gp->wButtons |= XINPUT_GAMEPAD_X;
        if (BTN_PRESSED(BTN_NORTH))  gp->wButtons |= XINPUT_GAMEPAD_Y;
        if (BTN_PRESSED(BTN_TL))     gp->wButtons |= XINPUT_GAMEPAD_LEFT_SHOULDER;
        if (BTN_PRESSED(BTN_TR))     gp->wButtons |= XINPUT_GAMEPAD_RIGHT_SHOULDER;
        if (BTN_PRESSED(BTN_START))  gp->wButtons |= XINPUT_GAMEPAD_START;
        if (BTN_PRESSED(BTN_SELECT)) gp->wButtons |= XINPUT_GAMEPAD_BACK;
        if (BTN_PRESSED(BTN_THUMBL)) gp->wButtons |= XINPUT_GAMEPAD_LEFT_THUMB;
        if (BTN_PRESSED(BTN_THUMBR)) gp->wButtons |= XINPUT_GAMEPAD_RIGHT_THUMB;
        if (BTN_PRESSED(BTN_MODE))   gp->wButtons |= XINPUT_GAMEPAD_GUIDE;

        #undef BTN_PRESSED
    }

    return 0;
}

/* ================================================================== */
/*                         EXPORTED APIS                              */
/* ================================================================== */

/*
 * XInputGetState
 *
 * Fills *state with live axis/button values read via evdev.
 * Returns ERROR_SUCCESS (0) when a device is connected at userIndex.
 * Returns ERROR_DEVICE_NOT_CONNECTED (1167) when:
 *   - userIndex >= 4
 *   - No device at that index (unplugged / never enumerated)
 *   - XInputEnable(FALSE) was previously called
 *
 * Per MSDN: the GUIDE button (Xbox home) is intentionally masked out
 * by stock XInputGetState; see XInputGetStateEx below for the 1.4
 * undocumented-but-universal variant that exposes it.
 */
WINAPI_EXPORT DWORD XInputGetState(DWORD dwUserIndex, void *pState)
{
    if (!g_xinput_enabled)
        return ERROR_DEVICE_NOT_CONNECTED;

    xinput_scan();

    if (dwUserIndex >= XUSER_MAX_COUNT || g_pads[dwUserIndex].fd < 0)
        return ERROR_DEVICE_NOT_CONNECTED;

    XINPUT_STATE_T *st = (XINPUT_STATE_T *)pState;
    if (!st)
        return ERROR_DEVICE_NOT_CONNECTED;

    XINPUT_GAMEPAD_T gp;
    if (xinput_read_state((int)dwUserIndex, &gp) < 0)
        return ERROR_DEVICE_NOT_CONNECTED;

    /* Bump packet number only when the state has actually changed;
     * games use this for "did anything change since last poll" fast paths */
    if (memcmp(&gp, &g_pads[dwUserIndex].last_state,
               sizeof(XINPUT_GAMEPAD_T)) != 0) {
        g_pads[dwUserIndex].packet++;
        g_pads[dwUserIndex].last_state = gp;
    }

    /* Stock API masks the GUIDE bit (only exposed via *Ex) */
    XINPUT_GAMEPAD_T masked = gp;
    masked.wButtons &= (uint16_t)~XINPUT_GAMEPAD_GUIDE;

    st->dwPacketNumber = g_pads[dwUserIndex].packet;
    st->Gamepad        = masked;

    return ERROR_SUCCESS;
}

/*
 * XInputGetStateEx (ordinal 100 in xinput1_3/1_4)
 *
 * Undocumented but universally used: same payload as XInputGetState but
 * DOES include XINPUT_GAMEPAD_GUIDE (0x0400) when the Xbox button is
 * pressed. Steam Big Picture, Epic launcher, and most AAA titles import
 * this by ordinal. We export it by both name and ordinal.
 */
WINAPI_EXPORT DWORD XInputGetStateEx(DWORD dwUserIndex, void *pState)
{
    if (!g_xinput_enabled)
        return ERROR_DEVICE_NOT_CONNECTED;

    xinput_scan();

    if (dwUserIndex >= XUSER_MAX_COUNT || g_pads[dwUserIndex].fd < 0)
        return ERROR_DEVICE_NOT_CONNECTED;

    XINPUT_STATE_T *st = (XINPUT_STATE_T *)pState;
    if (!st)
        return ERROR_DEVICE_NOT_CONNECTED;

    XINPUT_GAMEPAD_T gp;
    if (xinput_read_state((int)dwUserIndex, &gp) < 0)
        return ERROR_DEVICE_NOT_CONNECTED;

    if (memcmp(&gp, &g_pads[dwUserIndex].last_state,
               sizeof(XINPUT_GAMEPAD_T)) != 0) {
        g_pads[dwUserIndex].packet++;
        g_pads[dwUserIndex].last_state = gp;
    }

    st->dwPacketNumber = g_pads[dwUserIndex].packet;
    st->Gamepad        = gp;   /* includes GUIDE */
    return ERROR_SUCCESS;
}

/*
 * XInputSetState
 *
 * Rumble via evdev EV_FF / FF_RUMBLE. strong = heavy motor (left),
 * weak = light motor (right). Linux magnitude 0..0xFFFF maps 1:1 to
 * XInput's WORD range.
 *
 * If the device doesn't support FF we still return ERROR_SUCCESS —
 * games call SetState unconditionally every frame and faking failure
 * would cause some titles to disable ALL controller features.
 */
WINAPI_EXPORT DWORD XInputSetState(DWORD dwUserIndex, void *pVib)
{
    xinput_scan();

    if (dwUserIndex >= XUSER_MAX_COUNT || g_pads[dwUserIndex].fd < 0)
        return ERROR_DEVICE_NOT_CONNECTED;

    XINPUT_VIBRATION_T *vib = (XINPUT_VIBRATION_T *)pVib;
    if (!vib)
        return ERROR_DEVICE_NOT_CONNECTED;

    xinput_pad_t *pad = &g_pads[dwUserIndex];
    if (!pad->has_ff)
        return ERROR_SUCCESS;    /* silent no-op is the right choice */

    struct ff_effect effect;
    memset(&effect, 0, sizeof(effect));
    effect.type = FF_RUMBLE;
    effect.id   = pad->ff_id;   /* -1 = create; >=0 = update existing */
    effect.u.rumble.strong_magnitude = vib->wLeftMotorSpeed;
    effect.u.rumble.weak_magnitude   = vib->wRightMotorSpeed;
    effect.replay.length = 5000;  /* 5s cap; games re-call frequently */
    effect.replay.delay  = 0;

    if (ioctl(pad->fd, EVIOCSFF, &effect) < 0) {
        if (errno == ENODEV || errno == EBADF) {
            xinput_handle_disconnect(pad);
            return ERROR_DEVICE_NOT_CONNECTED;
        }
        /* Upload failed but device present — not fatal */
        return ERROR_SUCCESS;
    }

    pad->ff_id = effect.id;

    struct input_event play;
    memset(&play, 0, sizeof(play));
    play.type  = EV_FF;
    play.code  = (unsigned short)effect.id;
    play.value = (vib->wLeftMotorSpeed == 0 && vib->wRightMotorSpeed == 0)
                   ? 0    /* stop */
                   : 1;   /* play once */

    ssize_t wr __attribute__((unused)) = write(pad->fd, &play, sizeof(play));
    return ERROR_SUCCESS;
}

/*
 * XInputGetCapabilities
 *
 * Reports what the controller can do. We always advertise
 * XINPUT_DEVTYPE_GAMEPAD + XINPUT_DEVSUBTYPE_GAMEPAD with full 16-bit
 * button mask and full analog ranges. Per MSDN: returning "max" range
 * in Gamepad/Vibration signals which inputs are valid.
 */
WINAPI_EXPORT DWORD XInputGetCapabilities(DWORD dwUserIndex, DWORD dwFlags, void *pCaps)
{
    (void)dwFlags;
    xinput_scan();

    if (dwUserIndex >= XUSER_MAX_COUNT || g_pads[dwUserIndex].fd < 0)
        return ERROR_DEVICE_NOT_CONNECTED;

    XINPUT_CAPABILITIES_T *caps = (XINPUT_CAPABILITIES_T *)pCaps;
    if (!caps)
        return ERROR_DEVICE_NOT_CONNECTED;

    xinput_pad_t *pad = &g_pads[dwUserIndex];

    memset(caps, 0, sizeof(*caps));
    caps->Type    = XINPUT_DEVTYPE_GAMEPAD;
    caps->SubType = XINPUT_DEVSUBTYPE_GAMEPAD;
    caps->Flags   = pad->has_ff ? XINPUT_CAPS_FFB_SUPPORTED : 0;

    caps->Gamepad.wButtons      = 0xFFFF;
    caps->Gamepad.bLeftTrigger  = 255;
    caps->Gamepad.bRightTrigger = 255;
    caps->Gamepad.sThumbLX      = (int16_t)32767;
    caps->Gamepad.sThumbLY      = (int16_t)32767;
    caps->Gamepad.sThumbRX      = (int16_t)32767;
    caps->Gamepad.sThumbRY      = (int16_t)32767;

    if (pad->has_ff) {
        caps->Vibration.wLeftMotorSpeed  = 65535;
        caps->Vibration.wRightMotorSpeed = 65535;
    }

    return ERROR_SUCCESS;
}

/*
 * XInputGetBatteryInformation — always wired/full.
 * For real battery reporting we'd need to read POWER_SUPPLY_CAPACITY
 * from /sys/class/power_supply/<node>, keyed by the evdev sysfs parent.
 * Not worth it for stub; wired+full keeps games happy.
 */
WINAPI_EXPORT DWORD XInputGetBatteryInformation(DWORD dwUserIndex, BYTE devType,
                                                void *pBatteryInformation)
{
    (void)devType;
    xinput_scan();

    if (dwUserIndex >= XUSER_MAX_COUNT || g_pads[dwUserIndex].fd < 0)
        return ERROR_DEVICE_NOT_CONNECTED;

    XINPUT_BATTERY_INFORMATION_T *info =
        (XINPUT_BATTERY_INFORMATION_T *)pBatteryInformation;
    if (info) {
        info->BatteryType  = BATTERY_TYPE_WIRED;
        info->BatteryLevel = BATTERY_LEVEL_FULL;
    }
    return ERROR_SUCCESS;
}

/*
 * XInputGetKeystroke — per-keypress queue, semi-rare surface.
 * We don't track press/release deltas (we only snapshot), so we report
 * ERROR_EMPTY when connected: correct per MSDN "no keystrokes available".
 */
WINAPI_EXPORT DWORD XInputGetKeystroke(DWORD dwUserIndex, DWORD dwReserved, void *pKeystroke)
{
    (void)dwReserved;
    (void)pKeystroke;
    xinput_scan();

    if (dwUserIndex >= XUSER_MAX_COUNT || g_pads[dwUserIndex].fd < 0)
        return ERROR_DEVICE_NOT_CONNECTED;

    return ERROR_EMPTY;
}

/*
 * XInputEnable — global master switch. Stops any active rumble on disable.
 */
WINAPI_EXPORT void XInputEnable(BOOL enable)
{
    g_xinput_enabled = enable;
    if (!enable) {
        for (int i = 0; i < XUSER_MAX_COUNT; i++) {
            if (g_pads[i].fd >= 0 && g_pads[i].ff_id >= 0) {
                struct input_event stop;
                memset(&stop, 0, sizeof(stop));
                stop.type  = EV_FF;
                stop.code  = (unsigned short)g_pads[i].ff_id;
                stop.value = 0;
                ssize_t wr __attribute__((unused)) =
                    write(g_pads[i].fd, &stop, sizeof(stop));
            }
        }
    }
}

/*
 * XInputGetDSoundAudioDeviceGuids (legacy, xinput9_1_0 only)
 * Returns empty GUIDs — we don't route chatpad audio through DirectSound.
 */
WINAPI_EXPORT DWORD XInputGetDSoundAudioDeviceGuids(DWORD dwUserIndex,
                                                   void *pDSoundRenderGuid,
                                                   void *pDSoundCaptureGuid)
{
    xinput_scan();
    if (dwUserIndex >= XUSER_MAX_COUNT || g_pads[dwUserIndex].fd < 0)
        return ERROR_DEVICE_NOT_CONNECTED;
    if (pDSoundRenderGuid)  memset(pDSoundRenderGuid,  0, 16);
    if (pDSoundCaptureGuid) memset(pDSoundCaptureGuid, 0, 16);
    return ERROR_SUCCESS;
}

/*
 * XInputGetAudioDeviceIds (xinput1_4)
 * Mic + speaker come from pipewire/pulse, not XInput. Stub returns zero
 * counts — callers interpret that as "no XInput-routed audio device"
 * and fall back to the default OS audio device, which is what we want.
 */
WINAPI_EXPORT DWORD XInputGetAudioDeviceIds(DWORD dwUserIndex,
                                           void *pRenderDeviceId,  void *pRenderCount,
                                           void *pCaptureDeviceId, void *pCaptureCount)
{
    (void)pRenderDeviceId;
    (void)pCaptureDeviceId;
    xinput_scan();

    if (dwUserIndex >= XUSER_MAX_COUNT || g_pads[dwUserIndex].fd < 0)
        return ERROR_DEVICE_NOT_CONNECTED;

    /* Per MSDN, Count params are UINT*; write 0 so callers know "none". */
    if (pRenderCount)  *(uint32_t *)pRenderCount  = 0;
    if (pCaptureCount) *(uint32_t *)pCaptureCount = 0;
    return ERROR_SUCCESS;
}

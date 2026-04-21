/*
 * user32_input.c - Input handling stubs
 *
 * Implements keyboard and mouse input APIs: GetKeyState, GetAsyncKeyState,
 * GetKeyboardState, GetCursorPos, SetCursorPos, ShowCursor, SetCapture,
 * ReleaseCapture, MessageBoxA/W.
 *
 * Includes VK_* virtual key code constants and X11 keysym mapping.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "common/dll_common.h"
#include "../../graphics/gfx_backend.h"

/* --------------------------------------------------------------------------
 * Virtual Key Code constants (VK_*)
 * -------------------------------------------------------------------------- */

#define VK_LBUTTON      0x01
#define VK_RBUTTON      0x02
#define VK_CANCEL       0x03
#define VK_MBUTTON      0x04
#define VK_XBUTTON1     0x05
#define VK_XBUTTON2     0x06
#define VK_BACK         0x08
#define VK_TAB          0x09
#define VK_CLEAR        0x0C
#define VK_RETURN       0x0D
#define VK_SHIFT        0x10
#define VK_CONTROL      0x11
#define VK_MENU         0x12
#define VK_PAUSE        0x13
#define VK_CAPITAL      0x14
#define VK_KANA         0x15
#define VK_JUNJA        0x17
#define VK_FINAL        0x18
#define VK_HANJA        0x19
#define VK_KANJI        0x19
#define VK_ESCAPE       0x1B
#define VK_CONVERT      0x1C
#define VK_NONCONVERT   0x1D
#define VK_ACCEPT       0x1E
#define VK_MODECHANGE   0x1F
#define VK_SPACE        0x20
#define VK_PRIOR        0x21
#define VK_NEXT         0x22
#define VK_END          0x23
#define VK_HOME         0x24
#define VK_LEFT         0x25
#define VK_UP           0x26
#define VK_RIGHT        0x27
#define VK_DOWN         0x28
#define VK_SELECT       0x29
#define VK_PRINT        0x2A
#define VK_EXECUTE      0x2B
#define VK_SNAPSHOT     0x2C
#define VK_INSERT       0x2D
#define VK_DELETE       0x2E
#define VK_HELP         0x2F

/* 0-9 are 0x30-0x39, A-Z are 0x41-0x5A (same as ASCII) */

#define VK_LWIN         0x5B
#define VK_RWIN         0x5C
#define VK_APPS         0x5D
#define VK_SLEEP        0x5F
#define VK_NUMPAD0      0x60
#define VK_NUMPAD1      0x61
#define VK_NUMPAD2      0x62
#define VK_NUMPAD3      0x63
#define VK_NUMPAD4      0x64
#define VK_NUMPAD5      0x65
#define VK_NUMPAD6      0x66
#define VK_NUMPAD7      0x67
#define VK_NUMPAD8      0x68
#define VK_NUMPAD9      0x69
#define VK_MULTIPLY     0x6A
#define VK_ADD          0x6B
#define VK_SEPARATOR    0x6C
#define VK_SUBTRACT     0x6D
#define VK_DECIMAL      0x6E
#define VK_DIVIDE       0x6F
#define VK_F1           0x70
#define VK_F2           0x71
#define VK_F3           0x72
#define VK_F4           0x73
#define VK_F5           0x74
#define VK_F6           0x75
#define VK_F7           0x76
#define VK_F8           0x77
#define VK_F9           0x78
#define VK_F10          0x79
#define VK_F11          0x7A
#define VK_F12          0x7B
#define VK_F13          0x7C
#define VK_F14          0x7D
#define VK_F15          0x7E
#define VK_F16          0x7F
#define VK_F17          0x80
#define VK_F18          0x81
#define VK_F19          0x82
#define VK_F20          0x83
#define VK_F21          0x84
#define VK_F22          0x85
#define VK_F23          0x86
#define VK_F24          0x87
#define VK_NUMLOCK      0x90
#define VK_SCROLL       0x91
#define VK_LSHIFT       0xA0
#define VK_RSHIFT       0xA1
#define VK_LCONTROL     0xA2
#define VK_RCONTROL     0xA3
#define VK_LMENU        0xA4
#define VK_RMENU        0xA5
#define VK_BROWSER_BACK         0xA6
#define VK_BROWSER_FORWARD      0xA7
#define VK_BROWSER_REFRESH      0xA8
#define VK_BROWSER_STOP         0xA9
#define VK_BROWSER_SEARCH       0xAA
#define VK_BROWSER_FAVORITES    0xAB
#define VK_BROWSER_HOME         0xAC
#define VK_VOLUME_MUTE          0xAD
#define VK_VOLUME_DOWN          0xAE
#define VK_VOLUME_UP            0xAF
#define VK_MEDIA_NEXT_TRACK     0xB0
#define VK_MEDIA_PREV_TRACK     0xB1
#define VK_MEDIA_STOP           0xB2
#define VK_MEDIA_PLAY_PAUSE     0xB3
#define VK_LAUNCH_MAIL          0xB4
#define VK_LAUNCH_MEDIA_SELECT  0xB5
#define VK_LAUNCH_APP1          0xB6
#define VK_LAUNCH_APP2          0xB7
#define VK_OEM_1        0xBA    /* ;: */
#define VK_OEM_PLUS     0xBB    /* =+ */
#define VK_OEM_COMMA    0xBC    /* ,< */
#define VK_OEM_MINUS    0xBD    /* -_ */
#define VK_OEM_PERIOD   0xBE    /* .> */
#define VK_OEM_2        0xBF    /* /? */
#define VK_OEM_3        0xC0    /* `~ */
#define VK_OEM_4        0xDB    /* [{ */
#define VK_OEM_5        0xDC    /* \| */
#define VK_OEM_6        0xDD    /* ]} */
#define VK_OEM_7        0xDE    /* '" */
#define VK_OEM_8        0xDF
#define VK_OEM_102      0xE2    /* <> on 102-key keyboard */
#define VK_PROCESSKEY   0xE5
#define VK_ATTN         0xF6
#define VK_CRSEL        0xF7
#define VK_EXSEL        0xF8
#define VK_EREOF        0xF9
#define VK_PLAY         0xFA
#define VK_ZOOM         0xFB
#define VK_NONAME       0xFC
#define VK_PA1          0xFD
#define VK_OEM_CLEAR    0xFE

/* --------------------------------------------------------------------------
 * Keyboard state
 *
 * Each byte: high bit (0x80) = currently pressed
 *            low bit (0x01) = toggled (for lock keys)
 * -------------------------------------------------------------------------- */

static BYTE g_key_state[256];
static int g_key_state_initialized = 0;

static void ensure_key_state_init(void)
{
    if (!g_key_state_initialized) {
        memset(g_key_state, 0, sizeof(g_key_state));
        g_key_state_initialized = 1;
    }
}

/* Called by the message pump to update key state (internal use) */
void user32_update_key_state(UINT vk, int pressed)
{
    ensure_key_state_init();
    if (vk > 255)
        return;

    if (pressed) {
        g_key_state[vk] |= 0x80;
        /* Toggle state for lock keys */
        if (vk == VK_CAPITAL || vk == VK_NUMLOCK || vk == VK_SCROLL)
            g_key_state[vk] ^= 0x01;
    } else {
        g_key_state[vk] &= ~0x80;
    }
}

/* --------------------------------------------------------------------------
 * Mouse state
 * -------------------------------------------------------------------------- */

static int g_cursor_x = 0;
static int g_cursor_y = 0;
static int g_cursor_visible = 1;
static int g_cursor_show_count = 0;
static HWND g_capture_hwnd = NULL;

/* Called by the message pump to update mouse state (internal use) */
void user32_update_mouse_state(int x, int y)
{
    g_cursor_x = x;
    g_cursor_y = y;
}

/* --------------------------------------------------------------------------
 * GetKeyState / GetAsyncKeyState / GetKeyboardState
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT SHORT GetKeyState(int nVirtKey)
{
    ensure_key_state_init();
    if (nVirtKey < 0 || nVirtKey > 255)
        return 0;

    SHORT result = 0;
    if (g_key_state[nVirtKey] & 0x80)
        result |= (SHORT)0x8000;   /* Key is pressed */
    if (g_key_state[nVirtKey] & 0x01)
        result |= 0x0001;          /* Key is toggled */

    return result;
}

WINAPI_EXPORT SHORT GetAsyncKeyState(int vKey)
{
    /*
     * GetAsyncKeyState checks the physical key state at call time.
     * We use the same state as GetKeyState since we don't have
     * a separate async mechanism.
     */
    ensure_key_state_init();
    if (vKey < 0 || vKey > 255)
        return 0;

    SHORT result = 0;
    if (g_key_state[vKey] & 0x80)
        result |= (SHORT)0x8000;

    return result;
}

WINAPI_EXPORT BOOL GetKeyboardState(LPBYTE lpKeyState)
{
    if (!lpKeyState)
        return FALSE;

    ensure_key_state_init();
    memcpy(lpKeyState, g_key_state, 256);
    return TRUE;
}

WINAPI_EXPORT BOOL SetKeyboardState(LPBYTE lpKeyState)
{
    if (!lpKeyState)
        return FALSE;

    ensure_key_state_init();
    memcpy(g_key_state, lpKeyState, 256);
    return TRUE;
}

/* --------------------------------------------------------------------------
 * Keyboard mapping
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT UINT MapVirtualKeyA(UINT uCode, UINT uMapType)
{
    switch (uMapType) {
    case 0:  /* VK to scan code */
        return uCode;  /* Simplified: 1:1 mapping */
    case 1:  /* Scan code to VK */
        return uCode;
    case 2:  /* VK to unshifted char */
        if (uCode >= 0x30 && uCode <= 0x39) return uCode;         /* 0-9 */
        if (uCode >= 0x41 && uCode <= 0x5A) return uCode + 0x20;  /* a-z */
        if (uCode == VK_SPACE)  return ' ';
        if (uCode == VK_RETURN) return '\r';
        if (uCode == VK_TAB)    return '\t';
        return 0;
    case 3:  /* Scan code to VK (distinguish left/right) */
        return uCode;
    default:
        return 0;
    }
}

WINAPI_EXPORT UINT MapVirtualKeyW(UINT uCode, UINT uMapType)
{
    return MapVirtualKeyA(uCode, uMapType);
}

WINAPI_EXPORT int ToAscii(UINT uVirtKey, UINT uScanCode, const BYTE *lpKeyState,
                          LPWORD lpChar, UINT uFlags)
{
    (void)uScanCode;
    (void)lpKeyState;
    (void)uFlags;

    if (!lpChar)
        return 0;

    /* Simple mapping for printable ASCII */
    if (uVirtKey >= 0x20 && uVirtKey <= 0x7E) {
        *lpChar = (WORD)uVirtKey;
        /* If shift is not pressed and it's a letter, lowercase it */
        if (uVirtKey >= 0x41 && uVirtKey <= 0x5A) {
            int shift = (lpKeyState && (lpKeyState[VK_SHIFT] & 0x80));
            int caps = (lpKeyState && (lpKeyState[VK_CAPITAL] & 0x01));
            if (!shift && !caps)
                *lpChar = (WORD)(uVirtKey + 0x20);
        }
        return 1;
    }

    return 0;
}

WINAPI_EXPORT int ToUnicode(UINT wVirtKey, UINT wScanCode, const BYTE *lpKeyState,
                            LPWSTR pwszBuff, int cchBuff, UINT wFlags)
{
    (void)wScanCode;
    (void)wFlags;

    if (!pwszBuff || cchBuff <= 0)
        return 0;

    /* pwszBuff is LPWSTR (4-byte wchar_t on Linux) but represents Windows'
     * 2-byte WCHAR -- callers expect uint16_t slots.  Write through a
     * uint16_t* to avoid the wchar_t (4) vs uint16_t (2) size mismatch. */
    uint16_t *out = (uint16_t *)pwszBuff;
    WORD ch;
    int result = ToAscii(wVirtKey, wScanCode, lpKeyState, &ch, 0);
    if (result > 0) {
        out[0] = (uint16_t)ch;
        /* Windows leaves the buffer non-terminated after N chars; however,
         * many callers expect a trailing NUL when cchBuff > result to safely
         * use the buffer as a C string.  Write a terminator when space
         * permits. */
        if (cchBuff > 1)
            out[1] = 0;
        return 1;
    }
    /* No chars produced: ensure caller can't read uninitialized memory if
     * they treat pwszBuff as a string. */
    if (cchBuff > 0)
        out[0] = 0;
    return 0;
}

WINAPI_EXPORT SHORT VkKeyScanA(CHAR ch)
{
    /* Return VK code for a character */
    if (ch >= 'a' && ch <= 'z')
        return (SHORT)(ch - 'a' + 0x41);
    if (ch >= 'A' && ch <= 'Z')
        return (SHORT)(ch - 'A' + 0x41) | 0x0100;  /* Shift flag */
    if (ch >= '0' && ch <= '9')
        return (SHORT)(ch);
    if (ch == ' ')
        return VK_SPACE;

    return -1;
}

/* --------------------------------------------------------------------------
 * GetCursorPos / SetCursorPos / ShowCursor
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL GetCursorPos(LPPOINT lpPoint)
{
    if (!lpPoint)
        return FALSE;

    lpPoint->x = g_cursor_x;
    lpPoint->y = g_cursor_y;
    return TRUE;
}

WINAPI_EXPORT BOOL SetCursorPos(int X, int Y)
{
    g_cursor_x = X;
    g_cursor_y = Y;

    /* Ideally we'd call XWarpPointer here, but we don't have the display.
     * The position will be updated on next mouse event from X11. */
    return TRUE;
}

WINAPI_EXPORT int ShowCursor(BOOL bShow)
{
    if (bShow)
        g_cursor_show_count++;
    else
        g_cursor_show_count--;

    g_cursor_visible = (g_cursor_show_count >= 0) ? 1 : 0;
    return g_cursor_show_count;
}

/* --------------------------------------------------------------------------
 * SetCapture / ReleaseCapture / GetCapture
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HWND SetCapture(HWND hWnd)
{
    HWND old = g_capture_hwnd;
    g_capture_hwnd = hWnd;
    return old;
}

WINAPI_EXPORT BOOL ReleaseCapture(void)
{
    g_capture_hwnd = NULL;
    return TRUE;
}

WINAPI_EXPORT HWND GetCapture(void)
{
    return g_capture_hwnd;
}

/* --------------------------------------------------------------------------
 * Misc input stubs
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL TrackMouseEvent(void *lpEventTrack)
{
    (void)lpEventTrack;
    return TRUE;
}

WINAPI_EXPORT UINT GetDoubleClickTime(void)
{
    return 500;  /* Default 500ms */
}

WINAPI_EXPORT BOOL SwapMouseButton(BOOL fSwap)
{
    (void)fSwap;
    return FALSE;  /* Was not swapped */
}

WINAPI_EXPORT BOOL SystemParametersInfoA(UINT uiAction, UINT uiParam,
                                          LPVOID pvParam, UINT fWinIni)
{
    (void)uiAction;
    (void)uiParam;
    (void)pvParam;
    (void)fWinIni;
    /* Stub - most queries will just return default values */
    return TRUE;
}

WINAPI_EXPORT BOOL SystemParametersInfoW(UINT uiAction, UINT uiParam,
                                          LPVOID pvParam, UINT fWinIni)
{
    return SystemParametersInfoA(uiAction, uiParam, pvParam, fWinIni);
}

/* --------------------------------------------------------------------------
 * DPI awareness stubs
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL SetProcessDPIAware(void)
{
    return TRUE;
}

/* S68: shcore exports these when libpe_shcore.so is loaded. Declared weak
 * so user32 links cleanly in headless/unit-test builds where shcore isn't
 * pulled in. At runtime the dynamic loader resolves them as soon as
 * libpe_shcore.so is dlopen'd (all DLL stubs are loaded up front). */
extern UINT shcore_get_dpi_for_hwnd(HWND hwnd) __attribute__((weak));
extern int  pe_dpi_get_for_xwindow(unsigned long xw, uint32_t *dpiX, uint32_t *dpiY)
    __attribute__((weak));

WINAPI_EXPORT UINT GetDpiForWindow(HWND hwnd)
{
    if (shcore_get_dpi_for_hwnd)
        return shcore_get_dpi_for_hwnd(hwnd);
    return 96;  /* Headless fallback */
}

WINAPI_EXPORT UINT GetDpiForSystem(void)
{
    if (shcore_get_dpi_for_hwnd)
        return shcore_get_dpi_for_hwnd(NULL);
    return 96;
}

/* --------------------------------------------------------------------------
 * Input / locale functions (notepad.exe wide-char support)
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HANDLE GetKeyboardLayout(DWORD idThread)
{
    (void)idThread;
    /* Return US English keyboard layout (0x04090409) */
    return (HANDLE)(uintptr_t)0x04090409;
}

WINAPI_EXPORT LPWSTR CharNextW(LPCWSTR lpsz)
{
    if (!lpsz)
        return NULL;
    if (*lpsz)
        return (LPWSTR)(lpsz + 1);
    return (LPWSTR)lpsz;
}

WINAPI_EXPORT LPWSTR CharUpperW(LPWSTR lpsz)
{
    if (!lpsz)
        return NULL;
    /* If high word is zero, it's a single character in the low word */
    if ((uintptr_t)lpsz < 0x10000) {
        WCHAR ch = (WCHAR)(uintptr_t)lpsz;
        if (ch >= L'a' && ch <= L'z')
            ch -= 32;
        return (LPWSTR)(uintptr_t)ch;
    }
    /* Otherwise it's a pointer to a string - uppercase in place */
    LPWSTR p = lpsz;
    while (*p) {
        if (*p >= L'a' && *p <= L'z')
            *p -= 32;
        p++;
    }
    return lpsz;
}

WINAPI_EXPORT BOOL MessageBeep(UINT uType)
{
    (void)uType;
    return TRUE;
}

WINAPI_EXPORT BOOL IsIconic(HWND hWnd)
{
    (void)hWnd;
    return FALSE;
}

/* --------------------------------------------------------------------------
 * Input injection functions
 * -------------------------------------------------------------------------- */

/* INPUT structure for SendInput */
#define INPUT_MOUSE     0
#define INPUT_KEYBOARD  1
#define INPUT_HARDWARE  2

typedef struct {
    DWORD type;
    union {
        struct {
            LONG dx, dy;
            DWORD mouseData;
            DWORD dwFlags;
            DWORD time;
            ULONG_PTR dwExtraInfo;
        } mi;
        struct {
            WORD wVk;
            WORD wScan;
            DWORD dwFlags;
            DWORD time;
            ULONG_PTR dwExtraInfo;
        } ki;
    };
} INPUT_T;

WINAPI_EXPORT UINT SendInput(UINT cInputs, void *pInputs, int cbSize)
{
    (void)pInputs; (void)cbSize;
    return cInputs; /* Pretend all inputs were sent */
}

WINAPI_EXPORT void mouse_event(DWORD dwFlags, DWORD dx, DWORD dy,
                                 DWORD dwData, ULONG_PTR dwExtraInfo)
{
    (void)dwFlags; (void)dx; (void)dy; (void)dwData; (void)dwExtraInfo;
}

WINAPI_EXPORT void keybd_event(BYTE bVk, BYTE bScan, DWORD dwFlags,
                                 ULONG_PTR dwExtraInfo)
{
    (void)bVk; (void)bScan; (void)dwFlags; (void)dwExtraInfo;
}

WINAPI_EXPORT BOOL BlockInput(BOOL fBlockIt)
{
    (void)fBlockIt;
    return TRUE;
}

WINAPI_EXPORT BOOL RegisterHotKey(HWND hWnd, int id, UINT fsModifiers, UINT vk)
{
    (void)hWnd; (void)id; (void)fsModifiers; (void)vk;
    return TRUE;
}

WINAPI_EXPORT BOOL UnregisterHotKey(HWND hWnd, int id)
{
    (void)hWnd; (void)id;
    return TRUE;
}

WINAPI_EXPORT SHORT VkKeyScanW(WCHAR ch)
{
    /* Same as VkKeyScanA for ASCII range */
    if (ch >= 'a' && ch <= 'z') return (SHORT)(0x0000 | (ch - 'a' + 0x41));
    if (ch >= 'A' && ch <= 'Z') return (SHORT)(0x0100 | (ch - 'A' + 0x41));
    if (ch >= '0' && ch <= '9') return (SHORT)ch;
    return -1;
}

WINAPI_EXPORT int GetKeyNameTextA(LONG lParam, LPSTR lpString, int cchSize)
{
    if (!lpString || cchSize <= 0) return 0;
    /* Extract scan code from bits 16-23 */
    unsigned scanCode = (lParam >> 16) & 0xFF;
    const char *name = "Unknown";
    if (scanCode <= 0x39) {
        static const char *names[] = {
            "", "Escape", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0",
            "-", "=", "Backspace", "Tab", "Q", "W", "E", "R", "T", "Y", "U",
            "I", "O", "P", "[", "]", "Enter", "Ctrl", "A", "S", "D", "F",
            "G", "H", "J", "K", "L", ";", "'", "`", "Shift", "\\", "Z",
            "X", "C", "V", "B", "N", "M", ",", ".", "/", "Right Shift",
            "Num *", "Alt", "Space"
        };
        name = names[scanCode];
    }
    strncpy(lpString, name, cchSize - 1);
    lpString[cchSize - 1] = '\0';
    return (int)strlen(lpString);
}

WINAPI_EXPORT int GetKeyNameTextW(LONG lParam, LPWSTR lpString, int cchSize)
{
    char buf[256];
    int len = GetKeyNameTextA(lParam, buf, sizeof(buf));
    if (!lpString || cchSize <= 0) return 0;
    int i;
    for (i = 0; i < len && i < cchSize - 1; i++)
        lpString[i] = (WCHAR)(unsigned char)buf[i];
    lpString[i] = 0;
    return i;
}

/* Raw input stubs */
WINAPI_EXPORT UINT GetRawInputData(HANDLE hRawInput, UINT uiCommand,
                                     LPVOID pData, UINT * pcbSize, UINT cbSizeHeader)
{
    (void)hRawInput; (void)uiCommand; (void)pData; (void)cbSizeHeader;
    if (pcbSize) *pcbSize = 0;
    return 0;
}

WINAPI_EXPORT BOOL RegisterRawInputDevices(const void *pRawInputDevices,
                                             UINT uiNumDevices, UINT cbSize)
{
    (void)pRawInputDevices; (void)uiNumDevices; (void)cbSize;
    return TRUE;
}

WINAPI_EXPORT UINT GetRawInputDeviceList(void *pRawInputDeviceList,
                                           UINT * puiNumDevices, UINT cbSize)
{
    (void)pRawInputDeviceList; (void)cbSize;
    if (puiNumDevices) *puiNumDevices = 0;
    return 0;
}

WINAPI_EXPORT UINT GetRawInputDeviceInfoA(HANDLE hDevice, UINT uiCommand,
                                            LPVOID pData, UINT * pcbSize)
{
    (void)hDevice; (void)uiCommand; (void)pData;
    if (pcbSize) *pcbSize = 0;
    return (UINT)-1;
}

WINAPI_EXPORT UINT GetRawInputDeviceInfoW(HANDLE hDevice, UINT uiCommand,
                                            LPVOID pData, UINT * pcbSize)
{
    return GetRawInputDeviceInfoA(hDevice, uiCommand, pData, pcbSize);
}

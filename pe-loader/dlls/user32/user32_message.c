/*
 * user32_message.c - Win32 message handling stubs
 *
 * Implements the Windows message pump: GetMessage, PeekMessage,
 * TranslateMessage, DispatchMessage, PostMessage, SendMessage,
 * PostQuitMessage.
 *
 * Translates gfx_event_t from the graphics backend into Win32
 * MSG structures with proper WM_* message codes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "common/dll_common.h"
#include "../../graphics/gfx_backend.h"

/* --------------------------------------------------------------------------
 * WM_* message constants
 * -------------------------------------------------------------------------- */

#define WM_NULL             0x0000
#define WM_CREATE           0x0001
#define WM_DESTROY          0x0002
#define WM_MOVE             0x0003
#define WM_SIZE             0x0005
#define WM_ACTIVATE         0x0006
#define WM_SETFOCUS         0x0007
#define WM_KILLFOCUS        0x0008
#define WM_ENABLE           0x000A
#define WM_SETTEXT          0x000C
#define WM_GETTEXT          0x000D
#define WM_GETTEXTLENGTH    0x000E
#define WM_PAINT            0x000F
#define WM_CLOSE            0x0010
#define WM_QUERYENDSESSION  0x0011
#define WM_QUIT             0x0012
#define WM_ERASEBKGND       0x0014
#define WM_SHOWWINDOW       0x0018
#define WM_ACTIVATEAPP      0x001C
#define WM_SETCURSOR        0x0020
#define WM_MOUSEACTIVATE    0x0021
#define WM_GETMINMAXINFO    0x0024
#define WM_WINDOWPOSCHANGING 0x0046
#define WM_WINDOWPOSCHANGED  0x0047
#define WM_NCCREATE         0x0081
#define WM_NCDESTROY        0x0082
#define WM_NCCALCSIZE       0x0083
#define WM_NCHITTEST        0x0084
#define WM_NCPAINT          0x0085
#define WM_NCACTIVATE       0x0086
#define WM_KEYDOWN          0x0100
#define WM_KEYUP            0x0101
#define WM_CHAR             0x0102
#define WM_DEADCHAR         0x0103
#define WM_SYSKEYDOWN       0x0104
#define WM_SYSKEYUP         0x0105
#define WM_SYSCHAR          0x0106
#define WM_COMMAND          0x0111
#define WM_SYSCOMMAND       0x0112
#define WM_TIMER            0x0113
#define WM_HSCROLL          0x0114
#define WM_VSCROLL          0x0115
#define WM_INITDIALOG       0x0110
#define WM_MOUSEMOVE        0x0200
#define WM_LBUTTONDOWN      0x0201
#define WM_LBUTTONUP        0x0202
#define WM_LBUTTONDBLCLK    0x0203
#define WM_RBUTTONDOWN      0x0204
#define WM_RBUTTONUP        0x0205
#define WM_RBUTTONDBLCLK    0x0206
#define WM_MBUTTONDOWN      0x0207
#define WM_MBUTTONUP        0x0208
#define WM_MBUTTONDBLCLK    0x0209
#define WM_MOUSEWHEEL       0x020A
#define WM_SIZING           0x0214
#define WM_MOVING           0x0216
#define WM_ENTERSIZEMOVE    0x0231
#define WM_EXITSIZEMOVE     0x0232
#define WM_USER             0x0400
#define WM_APP              0x8000

/* PeekMessage flags */
#define PM_NOREMOVE         0x0000
#define PM_REMOVE           0x0001
#define PM_NOYIELD          0x0002

/* Error codes */
#ifndef ERROR_NO_SYSTEM_RESOURCES
#define ERROR_NO_SYSTEM_RESOURCES 1450
#endif

/* Forward declaration for timer check (defined later in this file) */
void user32_check_timers(void);

/* --------------------------------------------------------------------------
 * MSG structure
 * -------------------------------------------------------------------------- */

#ifndef _MSG_DEFINED
#define _MSG_DEFINED
typedef struct tagMSG {
    HWND    hwnd;
    UINT    message;
    WPARAM  wParam;
    LPARAM  lParam;
    DWORD   time;
    POINT   pt;
} MSG, *PMSG, *LPMSG;
#endif

/* --------------------------------------------------------------------------
 * WNDPROC type (must match user32_window.c definition)
 * -------------------------------------------------------------------------- */

#ifndef _WNDPROC_DEFINED
#define _WNDPROC_DEFINED
typedef LRESULT (__attribute__((ms_abi)) *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
#endif

/* External references to window layer */
extern gfx_window_t *hwnd_to_gfx(HWND hwnd);
extern HWND gfx_to_hwnd(gfx_window_t *win);
extern WNDPROC hwnd_get_wndproc(HWND hwnd);

/* --------------------------------------------------------------------------
 * Message queue (simple linked list per-thread)
 * -------------------------------------------------------------------------- */

typedef struct msg_node {
    MSG              msg;
    struct msg_node *next;
} msg_node_t;

/* Thread-safe message queue */
static msg_node_t *g_msg_queue_head = NULL;
static msg_node_t *g_msg_queue_tail = NULL;
static int g_quit_posted = 0;
static int g_quit_code = 0;
static pthread_mutex_t g_msg_lock = PTHREAD_MUTEX_INITIALIZER;

static void msg_queue_push(const MSG *msg)
{
    msg_node_t *node = calloc(1, sizeof(msg_node_t));
    if (!node)
        return;

    node->msg = *msg;
    node->next = NULL;

    pthread_mutex_lock(&g_msg_lock);
    if (g_msg_queue_tail) {
        g_msg_queue_tail->next = node;
        g_msg_queue_tail = node;
    } else {
        g_msg_queue_head = node;
        g_msg_queue_tail = node;
    }
    pthread_mutex_unlock(&g_msg_lock);
}

static int msg_queue_pop(MSG *msg)
{
    pthread_mutex_lock(&g_msg_lock);
    if (!g_msg_queue_head) {
        pthread_mutex_unlock(&g_msg_lock);
        return 0;
    }

    msg_node_t *node = g_msg_queue_head;
    *msg = node->msg;
    g_msg_queue_head = node->next;
    if (!g_msg_queue_head)
        g_msg_queue_tail = NULL;
    pthread_mutex_unlock(&g_msg_lock);

    free(node);
    return 1;
}

static int msg_queue_peek(MSG *msg)
{
    pthread_mutex_lock(&g_msg_lock);
    if (!g_msg_queue_head) {
        pthread_mutex_unlock(&g_msg_lock);
        return 0;
    }

    *msg = g_msg_queue_head->msg;
    pthread_mutex_unlock(&g_msg_lock);
    return 1;
}

static int msg_queue_empty(void)
{
    pthread_mutex_lock(&g_msg_lock);
    int empty = (g_msg_queue_head == NULL);
    pthread_mutex_unlock(&g_msg_lock);
    return empty;
}

/* --------------------------------------------------------------------------
 * Translate gfx_event_t to MSG
 * -------------------------------------------------------------------------- */

static DWORD get_tick_count(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (DWORD)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static int translate_gfx_event_to_msg(const gfx_event_t *event, MSG *msg)
{
    memset(msg, 0, sizeof(*msg));

    if (!event->window)
        return 0;

    msg->hwnd = gfx_to_hwnd(event->window);
    if (!msg->hwnd)
        return 0;

    msg->time = get_tick_count();
    msg->pt.x = event->mouse_x_screen;
    msg->pt.y = event->mouse_y_screen;

    switch (event->type) {
    case GFX_EVENT_PAINT:
        msg->message = WM_PAINT;
        msg->wParam = 0;
        msg->lParam = 0;
        return 1;

    case GFX_EVENT_KEY_DOWN:
        msg->message = WM_KEYDOWN;
        msg->wParam = event->keycode;
        /* lParam: repeat count (1), scan code, extended flag, etc. */
        msg->lParam = 1 | ((LPARAM)(event->scancode & 0xFF) << 16);
        return 1;

    case GFX_EVENT_KEY_UP:
        msg->message = WM_KEYUP;
        msg->wParam = event->keycode;
        msg->lParam = 1 | ((LPARAM)(event->scancode & 0xFF) << 16) |
                      (1L << 30) | (1L << 31);  /* Previous state + transition */
        return 1;

    case GFX_EVENT_CHAR:
        msg->message = WM_CHAR;
        msg->wParam = event->character;
        msg->lParam = 1;
        return 1;

    case GFX_EVENT_MOUSE_MOVE:
        msg->message = WM_MOUSEMOVE;
        msg->wParam = 0;
        if (event->modifiers & 0x01) msg->wParam |= 0x04;  /* MK_SHIFT */
        if (event->modifiers & 0x02) msg->wParam |= 0x08;  /* MK_CONTROL */
        msg->lParam = ((LPARAM)(event->mouse_y & 0xFFFF) << 16) |
                      (event->mouse_x & 0xFFFF);
        return 1;

    case GFX_EVENT_MOUSE_LBUTTON_DOWN:
        msg->message = WM_LBUTTONDOWN;
        msg->wParam = 0x0001;  /* MK_LBUTTON */
        msg->lParam = ((LPARAM)(event->mouse_y & 0xFFFF) << 16) |
                      (event->mouse_x & 0xFFFF);
        return 1;

    case GFX_EVENT_MOUSE_LBUTTON_UP:
        msg->message = WM_LBUTTONUP;
        msg->wParam = 0;
        msg->lParam = ((LPARAM)(event->mouse_y & 0xFFFF) << 16) |
                      (event->mouse_x & 0xFFFF);
        return 1;

    case GFX_EVENT_MOUSE_RBUTTON_DOWN:
        msg->message = WM_RBUTTONDOWN;
        msg->wParam = 0x0002;  /* MK_RBUTTON */
        msg->lParam = ((LPARAM)(event->mouse_y & 0xFFFF) << 16) |
                      (event->mouse_x & 0xFFFF);
        return 1;

    case GFX_EVENT_MOUSE_RBUTTON_UP:
        msg->message = WM_RBUTTONUP;
        msg->wParam = 0;
        msg->lParam = ((LPARAM)(event->mouse_y & 0xFFFF) << 16) |
                      (event->mouse_x & 0xFFFF);
        return 1;

    case GFX_EVENT_MOUSE_MBUTTON_DOWN:
        msg->message = WM_MBUTTONDOWN;
        msg->wParam = 0x0010;  /* MK_MBUTTON */
        msg->lParam = ((LPARAM)(event->mouse_y & 0xFFFF) << 16) |
                      (event->mouse_x & 0xFFFF);
        return 1;

    case GFX_EVENT_MOUSE_MBUTTON_UP:
        msg->message = WM_MBUTTONUP;
        msg->wParam = 0;
        msg->lParam = ((LPARAM)(event->mouse_y & 0xFFFF) << 16) |
                      (event->mouse_x & 0xFFFF);
        return 1;

    case GFX_EVENT_RESIZE:
        msg->message = WM_SIZE;
        msg->wParam = 0;  /* SIZE_RESTORED */
        msg->lParam = ((LPARAM)(event->height & 0xFFFF) << 16) |
                      (event->width & 0xFFFF);
        return 1;

    case GFX_EVENT_MOVE:
        msg->message = WM_MOVE;
        msg->wParam = 0;
        msg->lParam = ((LPARAM)(event->y & 0xFFFF) << 16) |
                      (event->x & 0xFFFF);
        return 1;

    case GFX_EVENT_CLOSE:
        msg->message = WM_CLOSE;
        msg->wParam = 0;
        msg->lParam = 0;
        return 1;

    case GFX_EVENT_DESTROY:
        msg->message = WM_DESTROY;
        msg->wParam = 0;
        msg->lParam = 0;
        return 1;

    case GFX_EVENT_FOCUS_IN:
        msg->message = WM_SETFOCUS;
        msg->wParam = 0;
        msg->lParam = 0;
        return 1;

    case GFX_EVENT_FOCUS_OUT:
        msg->message = WM_KILLFOCUS;
        msg->wParam = 0;
        msg->lParam = 0;
        return 1;

    case GFX_EVENT_TIMER:
        msg->message = WM_TIMER;
        msg->wParam = event->timer_id;
        msg->lParam = 0;
        return 1;

    default:
        return 0;
    }
}

/* --------------------------------------------------------------------------
 * Pump events from the graphics backend into the message queue
 * -------------------------------------------------------------------------- */

static void pump_gfx_events(int blocking)
{
    gfx_backend_t *backend = gfx_get_backend();
    if (!backend) {
        /* Headless: no events to pump, sleep briefly to avoid busy spin */
        if (blocking) {
            struct timespec ts = { 0, 50000000 }; /* 50ms */
            nanosleep(&ts, NULL);
        }
        return;
    }

    gfx_event_t event;
    MSG msg;

    if (blocking && msg_queue_empty() && !g_quit_posted) {
        /* Block until we get at least one event */
        if (backend->process_events(backend, &event, 1)) {
            if (translate_gfx_event_to_msg(&event, &msg)) {
                msg_queue_push(&msg);
            }

            /* Also check for any pending character event */
            if (event.type == GFX_EVENT_KEY_DOWN && event.character) {
                MSG char_msg;
                memset(&char_msg, 0, sizeof(char_msg));
                char_msg.hwnd = msg.hwnd;
                char_msg.message = WM_CHAR;
                char_msg.wParam = event.character;
                char_msg.lParam = 1;
                char_msg.time = msg.time;
                char_msg.pt = msg.pt;
                msg_queue_push(&char_msg);
            }
        }
    }

    /* Drain any remaining non-blocking events */
    while (backend->process_events(backend, &event, 0)) {
        if (translate_gfx_event_to_msg(&event, &msg)) {
            msg_queue_push(&msg);
        }
        if (event.type == GFX_EVENT_KEY_DOWN && event.character) {
            MSG char_msg;
            memset(&char_msg, 0, sizeof(char_msg));
            char_msg.hwnd = msg.hwnd;
            char_msg.message = WM_CHAR;
            char_msg.wParam = event.character;
            char_msg.lParam = 1;
            char_msg.time = msg.time;
            char_msg.pt = msg.pt;
            msg_queue_push(&char_msg);
        }
    }
}

/* --------------------------------------------------------------------------
 * GetMessage
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL GetMessageA(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax)
{
    (void)hWnd;
    (void)wMsgFilterMin;
    (void)wMsgFilterMax;

    if (!lpMsg)
        return FALSE;

    /* If quit was posted and queue is empty, deliver WM_QUIT */
    if (g_quit_posted && msg_queue_empty()) {
        memset(lpMsg, 0, sizeof(*lpMsg));
        lpMsg->message = WM_QUIT;
        lpMsg->wParam = g_quit_code;
        lpMsg->time = get_tick_count();
        g_quit_posted = 0;
        return FALSE;  /* WM_QUIT -> return 0 */
    }

    /* Check timers before blocking */
    user32_check_timers();

    /* Pump events, blocking if queue is empty */
    while (msg_queue_empty() && !g_quit_posted) {
        pump_gfx_events(1);  /* blocking */
        user32_check_timers();
    }

    /* Check quit again after pumping */
    if (g_quit_posted && msg_queue_empty()) {
        memset(lpMsg, 0, sizeof(*lpMsg));
        lpMsg->message = WM_QUIT;
        lpMsg->wParam = g_quit_code;
        lpMsg->time = get_tick_count();
        g_quit_posted = 0;
        return FALSE;
    }

    /* Pop next message */
    if (msg_queue_pop(lpMsg)) {
        /* Filter by hWnd if specified */
        if (hWnd && lpMsg->hwnd != hWnd) {
            /* Re-queue and try again -- simplified, just return it */
        }
        return TRUE;
    }

    return FALSE;  /* No message available (stub -- real impl would block) */
}

WINAPI_EXPORT BOOL GetMessageW(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax)
{
    /* Wide version delegates to ANSI version for now */
    return GetMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax);
}

/* --------------------------------------------------------------------------
 * PeekMessage
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL PeekMessageA(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin,
                                UINT wMsgFilterMax, UINT wRemoveMsg)
{
    (void)hWnd;
    (void)wMsgFilterMin;
    (void)wMsgFilterMax;

    if (!lpMsg)
        return FALSE;

    /* Pump non-blocking events + check timers */
    pump_gfx_events(0);
    user32_check_timers();

    /* Check quit */
    if (g_quit_posted && msg_queue_empty()) {
        memset(lpMsg, 0, sizeof(*lpMsg));
        lpMsg->message = WM_QUIT;
        lpMsg->wParam = g_quit_code;
        lpMsg->time = get_tick_count();
        if (wRemoveMsg & PM_REMOVE)
            g_quit_posted = 0;
        return TRUE;
    }

    if (msg_queue_empty())
        return FALSE;

    if (wRemoveMsg & PM_REMOVE) {
        return msg_queue_pop(lpMsg) ? TRUE : FALSE;
    } else {
        return msg_queue_peek(lpMsg) ? TRUE : FALSE;
    }
}

WINAPI_EXPORT BOOL PeekMessageW(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin,
                                UINT wMsgFilterMax, UINT wRemoveMsg)
{
    return PeekMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
}

/* --------------------------------------------------------------------------
 * TranslateMessage
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL TranslateMessage(const MSG *lpMsg)
{
    if (!lpMsg)
        return FALSE;

    /*
     * TranslateMessage converts WM_KEYDOWN into WM_CHAR messages
     * for printable characters. Our pump already generates WM_CHAR
     * from the gfx_event character field, so this is mostly a no-op.
     */

    if (lpMsg->message == WM_KEYDOWN || lpMsg->message == WM_SYSKEYDOWN) {
        /* Character generation was handled in the event pump */
        return TRUE;
    }

    return FALSE;
}

/* --------------------------------------------------------------------------
 * DispatchMessage
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT LRESULT DispatchMessageA(const MSG *lpMsg)
{
    if (!lpMsg)
        return 0;

    if (lpMsg->message == WM_QUIT)
        return 0;

    /* Find the window procedure */
    WNDPROC wndproc = hwnd_get_wndproc(lpMsg->hwnd);
    if (wndproc) {
        return wndproc(lpMsg->hwnd, lpMsg->message, lpMsg->wParam, lpMsg->lParam);
    }

    /* No wndproc -- call DefWindowProc */
    /* Forward declare */
    LRESULT DefWindowProcA(HWND, UINT, WPARAM, LPARAM);
    return DefWindowProcA(lpMsg->hwnd, lpMsg->message, lpMsg->wParam, lpMsg->lParam);
}

WINAPI_EXPORT LRESULT DispatchMessageW(const MSG *lpMsg)
{
    return DispatchMessageA(lpMsg);
}

/* --------------------------------------------------------------------------
 * PostMessage / SendMessage
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL PostMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    MSG msg;
    memset(&msg, 0, sizeof(msg));
    msg.hwnd = hWnd;
    msg.message = Msg;
    msg.wParam = wParam;
    msg.lParam = lParam;
    msg.time = get_tick_count();

    msg_queue_push(&msg);
    return TRUE;
}

WINAPI_EXPORT BOOL PostMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    return PostMessageA(hWnd, Msg, wParam, lParam);
}

WINAPI_EXPORT LRESULT SendMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    /* NULL HWND is valid for broadcast — just return 0 for safety */
    if (!hWnd)
        return 0;

    /* SendMessage delivers synchronously */
    WNDPROC wndproc = hwnd_get_wndproc(hWnd);
    if (wndproc) {
        return wndproc(hWnd, Msg, wParam, lParam);
    }

    LRESULT DefWindowProcA(HWND, UINT, WPARAM, LPARAM);
    return DefWindowProcA(hWnd, Msg, wParam, lParam);
}

WINAPI_EXPORT LRESULT SendMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    return SendMessageA(hWnd, Msg, wParam, lParam);
}

/* --------------------------------------------------------------------------
 * PostQuitMessage
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT void PostQuitMessage(int nExitCode)
{
    pthread_mutex_lock(&g_msg_lock);
    g_quit_posted = 1;
    g_quit_code = nExitCode;
    pthread_mutex_unlock(&g_msg_lock);
    fprintf(stderr, "user32: PostQuitMessage(%d)\n", nExitCode);
}

/* --------------------------------------------------------------------------
 * Misc message-related stubs
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL WaitMessage(void)
{
    /* Block until a message is available.
     * In headless mode pump_gfx_events(1) sleeps briefly and returns,
     * so this won't hang forever but also won't deliver real events. */
    pump_gfx_events(1);
    return TRUE;
}

WINAPI_EXPORT BOOL ReplyMessage(LRESULT lResult)
{
    (void)lResult;
    return TRUE;
}

WINAPI_EXPORT BOOL InSendMessage(void)
{
    return FALSE;
}

WINAPI_EXPORT DWORD GetQueueStatus(UINT flags)
{
    (void)flags;
    pump_gfx_events(0);
    return msg_queue_empty() ? 0 : 1;
}

/* Shared counter for RegisterWindowMessage A/W to avoid duplicate IDs */
static UINT g_next_registered_msg = 0xC000;
/* g_msg_lock already defined above (line 143) -- reuse it for registered messages */

WINAPI_EXPORT UINT RegisterWindowMessageA(LPCSTR lpString)
{
    (void)lpString;
    /* Return a unique message ID in the registered range */
    pthread_mutex_lock(&g_msg_lock);
    UINT id = g_next_registered_msg++;
    pthread_mutex_unlock(&g_msg_lock);
    return id;
}

WINAPI_EXPORT UINT RegisterWindowMessageW(LPCWSTR lpString)
{
    (void)lpString;
    pthread_mutex_lock(&g_msg_lock);
    UINT id = g_next_registered_msg++;
    pthread_mutex_unlock(&g_msg_lock);
    return id;
}

/* --------------------------------------------------------------------------
 * LoadIcon / LoadCursor / LoadImage stubs
 * -------------------------------------------------------------------------- */

/* Standard icon IDs */
#define IDI_APPLICATION     ((LPCSTR)32512)
#define IDI_ERROR           ((LPCSTR)32513)
#define IDI_QUESTION        ((LPCSTR)32514)
#define IDI_WARNING         ((LPCSTR)32515)
#define IDI_INFORMATION     ((LPCSTR)32516)

#define IDC_ARROW           ((LPCSTR)32512)
#define IDC_IBEAM           ((LPCSTR)32513)
#define IDC_WAIT            ((LPCSTR)32514)
#define IDC_CROSS           ((LPCSTR)32515)
#define IDC_UPARROW         ((LPCSTR)32516)
#define IDC_HAND            ((LPCSTR)32649)

WINAPI_EXPORT HICON LoadIconA(HINSTANCE hInstance, LPCSTR lpIconName)
{
    (void)hInstance;
    (void)lpIconName;
    /* Return a non-NULL dummy handle */
    return (HICON)(uintptr_t)0xDEAD0001;
}

WINAPI_EXPORT HICON LoadIconW(HINSTANCE hInstance, LPCWSTR lpIconName)
{
    (void)hInstance;
    (void)lpIconName;
    return (HICON)(uintptr_t)0xDEAD0001;
}

WINAPI_EXPORT HCURSOR LoadCursorA(HINSTANCE hInstance, LPCSTR lpCursorName)
{
    (void)hInstance;
    (void)lpCursorName;
    return (HCURSOR)(uintptr_t)0xDEAD0002;
}

WINAPI_EXPORT HCURSOR LoadCursorW(HINSTANCE hInstance, LPCWSTR lpCursorName)
{
    (void)hInstance;
    (void)lpCursorName;
    return (HCURSOR)(uintptr_t)0xDEAD0002;
}

WINAPI_EXPORT HANDLE LoadImageA(HINSTANCE hInst, LPCSTR name, UINT type,
                                int cx, int cy, UINT fuLoad)
{
    (void)hInst; (void)name; (void)type;
    (void)cx; (void)cy; (void)fuLoad;
    return (HANDLE)(uintptr_t)0xDEAD0003;
}

WINAPI_EXPORT HANDLE LoadImageW(HINSTANCE hInst, LPCWSTR name, UINT type,
                                int cx, int cy, UINT fuLoad)
{
    (void)hInst; (void)name; (void)type;
    (void)cx; (void)cy; (void)fuLoad;
    return (HANDLE)(uintptr_t)0xDEAD0003;
}

WINAPI_EXPORT BOOL DestroyIcon(HICON hIcon)
{
    (void)hIcon;
    return TRUE;
}

WINAPI_EXPORT BOOL DestroyCursor(HCURSOR hCursor)
{
    (void)hCursor;
    return TRUE;
}

WINAPI_EXPORT HCURSOR SetCursor(HCURSOR hCursor)
{
    (void)hCursor;
    static HCURSOR current = NULL;
    HCURSOR old = current;
    current = hCursor;
    return old;
}

/* --------------------------------------------------------------------------
 * MessageBoxA / MessageBoxW
 * -------------------------------------------------------------------------- */

#define MB_OK                   0x00000000
#define MB_OKCANCEL             0x00000001
#define MB_YESNO                0x00000004
#define MB_YESNOCANCEL          0x00000003
#define IDOK                    1
#define IDCANCEL                2
#define IDYES                   6
#define IDNO                    7

WINAPI_EXPORT int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    (void)hWnd;
    (void)uType;

    fprintf(stderr, "[MessageBox] %s: %s\n",
            lpCaption ? lpCaption : "(null)",
            lpText ? lpText : "(null)");

    /* Always return IDOK for now */
    return IDOK;
}

WINAPI_EXPORT int MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    (void)hWnd;
    (void)lpText;
    (void)lpCaption;
    (void)uType;
    fprintf(stderr, "[MessageBox] (wide string)\n");
    return IDOK;
}

/* --------------------------------------------------------------------------
 * SetTimer / KillTimer
 *
 * Timer entries are checked by GetMessage/PeekMessage to inject WM_TIMER.
 * TIMERPROC callbacks are also supported (called directly).
 * -------------------------------------------------------------------------- */

#include <signal.h>

typedef void (__attribute__((ms_abi)) *TIMERPROC)(HWND, UINT, UINT_PTR, DWORD);

#define MAX_TIMERS 128

typedef struct {
    HWND       hwnd;
    UINT_PTR   id;
    UINT       interval_ms;   /* period in ms */
    TIMERPROC  proc;
    int        used;
    struct timespec next_fire; /* absolute time of next fire */
} timer_entry_t;

static timer_entry_t g_timers[MAX_TIMERS] = {{0}};
static pthread_mutex_t g_timer_lock = PTHREAD_MUTEX_INITIALIZER;
static UINT_PTR g_next_timer_id = 1000;

static void timer_set_next(timer_entry_t *t)
{
    clock_gettime(CLOCK_MONOTONIC, &t->next_fire);
    t->next_fire.tv_sec  += t->interval_ms / 1000;
    t->next_fire.tv_nsec += (long)(t->interval_ms % 1000) * 1000000L;
    if (t->next_fire.tv_nsec >= 1000000000L) {
        t->next_fire.tv_sec++;
        t->next_fire.tv_nsec -= 1000000000L;
    }
}

/* Called from GetMessage/PeekMessage to fire elapsed timers */
void user32_check_timers(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    pthread_mutex_lock(&g_timer_lock);
    for (int i = 0; i < MAX_TIMERS; i++) {
        timer_entry_t *t = &g_timers[i];
        if (!t->used)
            continue;

        /* Check if timer has fired */
        if (now.tv_sec > t->next_fire.tv_sec ||
            (now.tv_sec == t->next_fire.tv_sec &&
             now.tv_nsec >= t->next_fire.tv_nsec)) {

            HWND hwnd = t->hwnd;
            UINT_PTR id = t->id;
            TIMERPROC proc = t->proc;
            timer_set_next(t);  /* re-arm before releasing lock */
            pthread_mutex_unlock(&g_timer_lock);

            if (proc) {
                /* Direct callback -- enforce ms_abi at call site */
                typedef void (__attribute__((ms_abi)) *TIMERPROC_MSABI)(HWND, UINT, UINT_PTR, DWORD);
                ((TIMERPROC_MSABI)proc)(hwnd, WM_TIMER, id, (DWORD)(now.tv_sec * 1000 + now.tv_nsec / 1000000));
            } else {
                /* Post WM_TIMER to message queue */
                MSG tmsg = {0};
                tmsg.hwnd = hwnd;
                tmsg.message = WM_TIMER;
                tmsg.wParam = (WPARAM)id;
                tmsg.lParam = 0;
                tmsg.time = (DWORD)(now.tv_sec * 1000 + now.tv_nsec / 1000000);
                msg_queue_push(&tmsg);
            }

            pthread_mutex_lock(&g_timer_lock);
        }
    }
    pthread_mutex_unlock(&g_timer_lock);
}

WINAPI_EXPORT UINT_PTR SetTimer(HWND hWnd, UINT_PTR nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc)
{
    if (uElapse < 10) uElapse = 10;  /* Windows clamps to ~10ms minimum */

    pthread_mutex_lock(&g_timer_lock);

    /* If hWnd is non-NULL and id != 0, try to reuse existing timer */
    if (hWnd && nIDEvent != 0) {
        for (int i = 0; i < MAX_TIMERS; i++) {
            if (g_timers[i].used &&
                g_timers[i].hwnd == hWnd &&
                g_timers[i].id == nIDEvent) {
                /* Update existing */
                g_timers[i].interval_ms = uElapse;
                g_timers[i].proc = lpTimerFunc;
                timer_set_next(&g_timers[i]);
                pthread_mutex_unlock(&g_timer_lock);
                return nIDEvent;
            }
        }
    }

    /* Allocate new slot */
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (!g_timers[i].used) {
            g_timers[i].used = 1;
            g_timers[i].hwnd = hWnd;
            g_timers[i].id = (hWnd && nIDEvent) ? nIDEvent : g_next_timer_id++;
            g_timers[i].interval_ms = uElapse;
            g_timers[i].proc = lpTimerFunc;
            timer_set_next(&g_timers[i]);
            UINT_PTR ret = g_timers[i].id;
            pthread_mutex_unlock(&g_timer_lock);
            return ret;
        }
    }

    pthread_mutex_unlock(&g_timer_lock);
    set_last_error(ERROR_NO_SYSTEM_RESOURCES);
    return 0;
}

WINAPI_EXPORT BOOL KillTimer(HWND hWnd, UINT_PTR uIDEvent)
{
    pthread_mutex_lock(&g_timer_lock);
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (g_timers[i].used &&
            g_timers[i].hwnd == hWnd &&
            g_timers[i].id == uIDEvent) {
            g_timers[i].used = 0;
            pthread_mutex_unlock(&g_timer_lock);
            return TRUE;
        }
    }
    pthread_mutex_unlock(&g_timer_lock);
    set_last_error(ERROR_INVALID_PARAMETER);
    return FALSE;
}

/* --------------------------------------------------------------------------
 * Clipboard
 * Simple in-process clipboard backed by malloc'd buffers.
 * -------------------------------------------------------------------------- */

#define CF_TEXT         1
#define CF_BITMAP       2
#define CF_DIB          8
#define CF_UNICODETEXT  13
#define CF_HDROP        15

#define MAX_CLIPBOARD_FORMATS 16

typedef struct {
    UINT   format;
    void  *data;
    SIZE_T size;
} clipboard_entry_t;

static clipboard_entry_t g_clipboard[MAX_CLIPBOARD_FORMATS];
static int g_clipboard_count = 0;
static pthread_mutex_t g_clipboard_lock = PTHREAD_MUTEX_INITIALIZER;
static HWND g_clipboard_owner = NULL;
static int  g_clipboard_open  = 0;
static UINT g_next_clipboard_format = 0xC000;

WINAPI_EXPORT BOOL OpenClipboard(HWND hWndNewOwner)
{
    pthread_mutex_lock(&g_clipboard_lock);
    g_clipboard_open = 1;
    g_clipboard_owner = hWndNewOwner;
    pthread_mutex_unlock(&g_clipboard_lock);
    return TRUE;
}

WINAPI_EXPORT BOOL CloseClipboard(void)
{
    pthread_mutex_lock(&g_clipboard_lock);
    g_clipboard_open = 0;
    pthread_mutex_unlock(&g_clipboard_lock);
    return TRUE;
}

WINAPI_EXPORT BOOL EmptyClipboard(void)
{
    pthread_mutex_lock(&g_clipboard_lock);
    for (int i = 0; i < g_clipboard_count; i++) {
        free(g_clipboard[i].data);
        g_clipboard[i].data = NULL;
    }
    g_clipboard_count = 0;
    pthread_mutex_unlock(&g_clipboard_lock);
    return TRUE;
}

WINAPI_EXPORT HANDLE SetClipboardData(UINT uFormat, HANDLE hMem)
{
    if (!hMem) return NULL;

    pthread_mutex_lock(&g_clipboard_lock);

    /* Replace existing format if present */
    for (int i = 0; i < g_clipboard_count; i++) {
        if (g_clipboard[i].format == uFormat) {
            /* Guard against caller passing the same pointer back
             * (e.g. SetClipboardData(fmt, GetClipboardData(fmt))) —
             * freeing it first would make hMem point to freed memory. */
            if (g_clipboard[i].data != hMem)
                free(g_clipboard[i].data);
            /* hMem is a HGLOBAL — treat as a pointer for simplicity */
            g_clipboard[i].data = hMem;
            g_clipboard[i].size = 0; /* size unknown without GlobalSize */
            pthread_mutex_unlock(&g_clipboard_lock);
            return hMem;
        }
    }

    /* Add new format */
    if (g_clipboard_count < MAX_CLIPBOARD_FORMATS) {
        g_clipboard[g_clipboard_count].format = uFormat;
        g_clipboard[g_clipboard_count].data   = hMem;
        g_clipboard[g_clipboard_count].size   = 0;
        g_clipboard_count++;
    }
    pthread_mutex_unlock(&g_clipboard_lock);
    return hMem;
}

WINAPI_EXPORT HANDLE GetClipboardData(UINT uFormat)
{
    pthread_mutex_lock(&g_clipboard_lock);
    for (int i = 0; i < g_clipboard_count; i++) {
        if (g_clipboard[i].format == uFormat) {
            HANDLE h = g_clipboard[i].data;
            pthread_mutex_unlock(&g_clipboard_lock);
            return h;
        }
    }
    pthread_mutex_unlock(&g_clipboard_lock);
    set_last_error(ERROR_INVALID_PARAMETER);
    return NULL;
}

WINAPI_EXPORT BOOL IsClipboardFormatAvailable(UINT format)
{
    pthread_mutex_lock(&g_clipboard_lock);
    for (int i = 0; i < g_clipboard_count; i++) {
        if (g_clipboard[i].format == format) {
            pthread_mutex_unlock(&g_clipboard_lock);
            return TRUE;
        }
    }
    pthread_mutex_unlock(&g_clipboard_lock);
    return FALSE;
}

WINAPI_EXPORT UINT RegisterClipboardFormatA(LPCSTR lpszFormat)
{
    if (!lpszFormat) return 0;
    /* Return a unique value in the registered format range */
    return g_next_clipboard_format++;
}

WINAPI_EXPORT UINT RegisterClipboardFormatW(LPCWSTR lpszFormat)
{
    (void)lpszFormat;
    return g_next_clipboard_format++;
}

WINAPI_EXPORT INT GetClipboardFormatNameA(UINT format, LPSTR lpszFormatName, int cchMaxCount)
{
    (void)format;
    if (lpszFormatName && cchMaxCount > 0)
        lpszFormatName[0] = '\0';
    return 0;
}

WINAPI_EXPORT HWND GetClipboardOwner(void)
{
    return g_clipboard_owner;
}

WINAPI_EXPORT UINT CountClipboardFormats(void)
{
    return (UINT)g_clipboard_count;
}

WINAPI_EXPORT UINT EnumClipboardFormats(UINT format)
{
    pthread_mutex_lock(&g_clipboard_lock);
    if (format == 0) {
        UINT first = g_clipboard_count > 0 ? g_clipboard[0].format : 0;
        pthread_mutex_unlock(&g_clipboard_lock);
        return first;
    }
    for (int i = 0; i < g_clipboard_count - 1; i++) {
        if (g_clipboard[i].format == format) {
            UINT next = g_clipboard[i + 1].format;
            pthread_mutex_unlock(&g_clipboard_lock);
            return next;
        }
    }
    pthread_mutex_unlock(&g_clipboard_lock);
    return 0; /* no more formats */
}

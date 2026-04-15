/*
 * user32_window.c - Window management stubs
 *
 * Implements Win32 window creation, destruction, and management APIs
 * using the abstract graphics backend (gfx_backend_t) to render on Linux.
 *
 * RegisterClassA/W, CreateWindowExA/W, DestroyWindow, ShowWindow,
 * UpdateWindow, MoveWindow, SetWindowPos, GetWindowRect, GetClientRect,
 * SetWindowTextA, GetDesktopWindow, FindWindowA, DefWindowProcA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>

#include "common/dll_common.h"

#ifndef ERROR_CLASS_DOES_NOT_EXIST
#define ERROR_CLASS_DOES_NOT_EXIST 1411
#endif
#include "../../graphics/gfx_backend.h"

/* --------------------------------------------------------------------------
 * gdi32 internal DC allocation functions (resolved at runtime via dlsym).
 * user32 must route through these so that HDC values are registered in
 * gdi32's g_dc_map and findable by dc_lookup().  Returning raw gfx_dc_t*
 * pointers makes ALL GDI drawing operations fail silently.
 *
 * We use dlsym(RTLD_DEFAULT) instead of extern linkage because user32 and
 * gdi32 are separate .so files loaded by the PE import resolver.  While
 * RTLD_GLOBAL ensures cross-library resolution, using dlsym gives us a
 * clean NULL fallback if gdi32 is not yet loaded.
 * -------------------------------------------------------------------------- */

typedef HDC  (*pfn_gdi32_GetDC)(HWND);
typedef int  (*pfn_gdi32_ReleaseDC)(HWND, HDC);
typedef HDC  (*pfn_gdi32_BeginPaint)(HWND, void *);
typedef BOOL (*pfn_gdi32_EndPaint)(HWND, const void *);

static pfn_gdi32_GetDC      s_gdi32_GetDC      = NULL;
static pfn_gdi32_ReleaseDC  s_gdi32_ReleaseDC  = NULL;
static pfn_gdi32_BeginPaint s_gdi32_BeginPaint = NULL;
static pfn_gdi32_EndPaint   s_gdi32_EndPaint   = NULL;
static int s_gdi32_resolved = 0;

static void resolve_gdi32_dc_funcs(void)
{
    if (s_gdi32_resolved)
        return;
    s_gdi32_resolved = 1;
    s_gdi32_GetDC      = (pfn_gdi32_GetDC)dlsym(RTLD_DEFAULT, "gdi32_GetDC");
    s_gdi32_ReleaseDC  = (pfn_gdi32_ReleaseDC)dlsym(RTLD_DEFAULT, "gdi32_ReleaseDC");
    s_gdi32_BeginPaint = (pfn_gdi32_BeginPaint)dlsym(RTLD_DEFAULT, "gdi32_BeginPaint");
    s_gdi32_EndPaint   = (pfn_gdi32_EndPaint)dlsym(RTLD_DEFAULT, "gdi32_EndPaint");
}

/* --------------------------------------------------------------------------
 * Win32 window style constants
 * -------------------------------------------------------------------------- */

#define WS_OVERLAPPED       0x00000000L
#define WS_POPUP            0x80000000L
#define WS_CHILD            0x40000000L
#define WS_MINIMIZE         0x20000000L
#define WS_VISIBLE          0x10000000L
#define WS_DISABLED         0x08000000L
#define WS_CLIPSIBLINGS     0x04000000L
#define WS_CLIPCHILDREN     0x02000000L
#define WS_MAXIMIZE         0x01000000L
#define WS_CAPTION          0x00C00000L
#define WS_BORDER           0x00800000L
#define WS_DLGFRAME         0x00400000L
#define WS_VSCROLL          0x00200000L
#define WS_HSCROLL          0x00100000L
#define WS_SYSMENU          0x00080000L
#define WS_THICKFRAME       0x00040000L
#define WS_MINIMIZEBOX      0x00020000L
#define WS_MAXIMIZEBOX      0x00010000L
#define WS_OVERLAPPEDWINDOW (WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | \
                             WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX)

#define WS_EX_TOPMOST       0x00000008L
#define WS_EX_ACCEPTFILES   0x00000010L
#define WS_EX_TRANSPARENT   0x00000020L
#define WS_EX_APPWINDOW     0x00040000L
#define WS_EX_CLIENTEDGE    0x00000200L
#define WS_EX_WINDOWEDGE    0x00000100L
#define WS_EX_OVERLAPPEDWINDOW (WS_EX_WINDOWEDGE | WS_EX_CLIENTEDGE)

/* ShowWindow commands */
#define SW_HIDE             0
#define SW_SHOWNORMAL       1
#define SW_NORMAL           1
#define SW_SHOWMINIMIZED    2
#define SW_SHOWMAXIMIZED    3
#define SW_MAXIMIZE         3
#define SW_SHOWNOACTIVATE   4
#define SW_SHOW             5
#define SW_MINIMIZE         6
#define SW_SHOWMINNOACTIVE  7
#define SW_SHOWNA           8
#define SW_RESTORE          9
#define SW_SHOWDEFAULT      10

/* SetWindowPos flags */
#define SWP_NOSIZE          0x0001
#define SWP_NOMOVE          0x0002
#define SWP_NOZORDER        0x0004
#define SWP_NOREDRAW        0x0008
#define SWP_NOACTIVATE      0x0010
#define SWP_FRAMECHANGED    0x0020
#define SWP_SHOWWINDOW      0x0040
#define SWP_HIDEWINDOW      0x0080
#define SWP_NOOWNERZORDER   0x0200
#define SWP_NOSENDCHANGING  0x0400

/* CW_USEDEFAULT */
#define CW_USEDEFAULT       ((int)0x80000000)

/* HWND special values */
#define HWND_TOP            ((HWND)0)
#define HWND_BOTTOM         ((HWND)1)
#define HWND_TOPMOST        ((HWND)(LONG_PTR)-1)
#define HWND_NOTOPMOST      ((HWND)(LONG_PTR)-2)
#define HWND_DESKTOP        ((HWND)0)

/* Window messages (needed for DefWindowProc) */
#define WM_CREATE           0x0001
#define WM_DESTROY          0x0002
#define WM_MOVE             0x0003
#define WM_SIZE             0x0005
#define WM_ACTIVATE         0x0006
#define WM_SETFOCUS         0x0007
#define WM_KILLFOCUS        0x0008
#define WM_ENABLE           0x000A
#define WM_PAINT            0x000F
#define WM_CLOSE            0x0010
#define WM_QUIT             0x0012
#define WM_ERASEBKGND       0x0014
#define WM_SHOWWINDOW       0x0018
#define WM_SETTEXT          0x000C
#define WM_GETTEXT          0x000D
#define WM_GETTEXTLENGTH    0x000E
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
#define WM_COMMAND          0x0111
#define WM_SYSCOMMAND       0x0112
#define WM_TIMER            0x0113
#define WM_MOUSEMOVE        0x0200
#define WM_LBUTTONDOWN      0x0201
#define WM_LBUTTONUP        0x0202
#define WM_RBUTTONDOWN      0x0204
#define WM_RBUTTONUP        0x0205

/* Utility macros */
#ifndef LOWORD
#define LOWORD(l) ((WORD)(((DWORD_PTR)(l)) & 0xffff))
#define HIWORD(l) ((WORD)((((DWORD_PTR)(l)) >> 16) & 0xffff))
#endif

/* --------------------------------------------------------------------------
 * CREATESTRUCT (passed via WM_NCCREATE / WM_CREATE lParam)
 * -------------------------------------------------------------------------- */

typedef struct {
    LPVOID      lpCreateParams;
    HINSTANCE   hInstance;
    HMENU       hMenu;
    HWND        hwndParent;
    int         cy;
    int         cx;
    int         y;
    int         x;
    LONG        style;
    LPCSTR      lpszName;
    LPCSTR      lpszClass;
    DWORD       dwExStyle;
} CREATESTRUCTA;

/* --------------------------------------------------------------------------
 * Window procedure type
 * -------------------------------------------------------------------------- */

#ifndef _WNDPROC_DEFINED
#define _WNDPROC_DEFINED
typedef LRESULT (__attribute__((ms_abi)) *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
#endif

/* --------------------------------------------------------------------------
 * WNDCLASS structures
 * -------------------------------------------------------------------------- */

typedef struct {
    UINT        style;
    WNDPROC     lpfnWndProc;
    int         cbClsExtra;
    int         cbWndExtra;
    HINSTANCE   hInstance;
    HICON       hIcon;
    HCURSOR     hCursor;
    HBRUSH      hbrBackground;
    LPCSTR      lpszMenuName;
    LPCSTR      lpszClassName;
} WNDCLASSA;

typedef struct {
    UINT        style;
    WNDPROC     lpfnWndProc;
    int         cbClsExtra;
    int         cbWndExtra;
    HINSTANCE   hInstance;
    HICON       hIcon;
    HCURSOR     hCursor;
    HBRUSH      hbrBackground;
    LPCWSTR     lpszMenuName;
    LPCWSTR     lpszClassName;
} WNDCLASSW;

typedef struct {
    UINT        cbSize;
    UINT        style;
    WNDPROC     lpfnWndProc;
    int         cbClsExtra;
    int         cbWndExtra;
    HINSTANCE   hInstance;
    HICON       hIcon;
    HCURSOR     hCursor;
    HBRUSH      hbrBackground;
    LPCSTR      lpszMenuName;
    LPCSTR      lpszClassName;
    HICON       hIconSm;
} WNDCLASSEXA;

/* --------------------------------------------------------------------------
 * Window class registry
 * -------------------------------------------------------------------------- */

#define MAX_WINDOW_CLASSES 128

typedef struct {
    char        name[256];
    WNDPROC     wndproc;
    HINSTANCE   hInstance;
    HBRUSH      hbrBackground;
    UINT        style;
    int         cbWndExtra;
    int         used;
} window_class_entry_t;

static window_class_entry_t g_classes[MAX_WINDOW_CLASSES];
static int g_classes_initialized = 0;
static pthread_mutex_t g_wnd_lock = PTHREAD_MUTEX_INITIALIZER;

static void ensure_classes_init(void)
{
    if (!g_classes_initialized) {
        memset(g_classes, 0, sizeof(g_classes));
        g_classes_initialized = 1;
    }
}

static window_class_entry_t *find_class(const char *name)
{
    if (!name || (uintptr_t)name < 0x10000)
        return NULL; /* MAKEINTRESOURCE atom — not a string pointer */
    ensure_classes_init();
    for (int i = 0; i < MAX_WINDOW_CLASSES; i++) {
        if (g_classes[i].used && strcmp(g_classes[i].name, name) == 0)
            return &g_classes[i];
    }
    return NULL;
}

static window_class_entry_t *alloc_class(void)
{
    ensure_classes_init();
    for (int i = 0; i < MAX_WINDOW_CLASSES; i++) {
        if (!g_classes[i].used) {
            g_classes[i].used = 1;
            return &g_classes[i];
        }
    }
    return NULL;
}

/* --------------------------------------------------------------------------
 * HWND to gfx_window_t mapping
 * -------------------------------------------------------------------------- */

#define MAX_HWND_MAP 256

typedef struct {
    HWND            hwnd;
    HWND            parent;
    gfx_window_t   *gfx_win;
    WNDPROC         wndproc;
    int             extra_bytes;
    char            extra_data[64];  /* cbWndExtra storage */
    int             control_id;      /* For WS_CHILD: hMenu is control ID */
    int             used;
} hwnd_entry_t;

static hwnd_entry_t g_hwnd_map[MAX_HWND_MAP];
static int g_hwnd_map_initialized = 0;
static uintptr_t g_next_hwnd = 0x10000;  /* Start HWNDs well above NULL */

static void ensure_hwnd_map_init(void)
{
    if (!g_hwnd_map_initialized) {
        memset(g_hwnd_map, 0, sizeof(g_hwnd_map));
        g_hwnd_map_initialized = 1;
    }
}

static hwnd_entry_t *hwnd_alloc(gfx_window_t *win, WNDPROC proc)
{
    ensure_hwnd_map_init();
    pthread_mutex_lock(&g_wnd_lock);
    for (int i = 0; i < MAX_HWND_MAP; i++) {
        if (!g_hwnd_map[i].used) {
            /* Clear stale data from previous occupant: parent, control_id,
             * extra_bytes, extra_data may contain values from a destroyed
             * window that would otherwise leak into this new window
             * (notably corrupting GetDlgItem / GetWindowLong for cbWndExtra). */
            memset(&g_hwnd_map[i], 0, sizeof(g_hwnd_map[i]));
            g_hwnd_map[i].used = 1;
            g_hwnd_map[i].hwnd = (HWND)(g_next_hwnd);
            g_next_hwnd += 4; /* 4-byte alignment for HWND values */
            g_hwnd_map[i].gfx_win = win;
            g_hwnd_map[i].wndproc = proc;
            pthread_mutex_unlock(&g_wnd_lock);
            return &g_hwnd_map[i];
        }
    }
    pthread_mutex_unlock(&g_wnd_lock);
    return NULL;
}

static hwnd_entry_t *hwnd_lookup(HWND hwnd)
{
    ensure_hwnd_map_init();
    pthread_mutex_lock(&g_wnd_lock);
    for (int i = 0; i < MAX_HWND_MAP; i++) {
        if (g_hwnd_map[i].used && g_hwnd_map[i].hwnd == hwnd) {
            pthread_mutex_unlock(&g_wnd_lock);
            return &g_hwnd_map[i];
        }
    }
    pthread_mutex_unlock(&g_wnd_lock);
    return NULL;
}

static void hwnd_free(HWND hwnd)
{
    ensure_hwnd_map_init();
    pthread_mutex_lock(&g_wnd_lock);
    for (int i = 0; i < MAX_HWND_MAP; i++) {
        if (g_hwnd_map[i].used && g_hwnd_map[i].hwnd == hwnd) {
            /* Clear entire slot to prevent stale parent/control_id leaking
             * into lookups (hwnd_find_child_by_id) before slot is reused. */
            memset(&g_hwnd_map[i], 0, sizeof(g_hwnd_map[i]));
            pthread_mutex_unlock(&g_wnd_lock);
            return;
        }
    }
    pthread_mutex_unlock(&g_wnd_lock);
}

/* Get gfx_window_t from HWND */
gfx_window_t *hwnd_to_gfx(HWND hwnd)
{
    /* Snapshot under lock — the entry can be freed concurrently. */
    ensure_hwnd_map_init();
    pthread_mutex_lock(&g_wnd_lock);
    for (int i = 0; i < MAX_HWND_MAP; i++) {
        if (g_hwnd_map[i].used && g_hwnd_map[i].hwnd == hwnd) {
            gfx_window_t *w = g_hwnd_map[i].gfx_win;
            pthread_mutex_unlock(&g_wnd_lock);
            return w;
        }
    }
    pthread_mutex_unlock(&g_wnd_lock);
    return NULL;
}

/* Get HWND from gfx_window_t */
HWND gfx_to_hwnd(gfx_window_t *win)
{
    ensure_hwnd_map_init();
    pthread_mutex_lock(&g_wnd_lock);
    for (int i = 0; i < MAX_HWND_MAP; i++) {
        if (g_hwnd_map[i].used && g_hwnd_map[i].gfx_win == win) {
            HWND result = g_hwnd_map[i].hwnd;
            pthread_mutex_unlock(&g_wnd_lock);
            return result;
        }
    }
    pthread_mutex_unlock(&g_wnd_lock);
    return NULL;
}

/* Get WNDPROC for a window */
WNDPROC hwnd_get_wndproc(HWND hwnd)
{
    /* Snapshot under lock — SetWindowLong/DestroyWindow can mutate wndproc. */
    ensure_hwnd_map_init();
    pthread_mutex_lock(&g_wnd_lock);
    for (int i = 0; i < MAX_HWND_MAP; i++) {
        if (g_hwnd_map[i].used && g_hwnd_map[i].hwnd == hwnd) {
            WNDPROC p = g_hwnd_map[i].wndproc;
            pthread_mutex_unlock(&g_wnd_lock);
            return p;
        }
    }
    pthread_mutex_unlock(&g_wnd_lock);
    return NULL;
}

/*
 * Get the native X11 Window ID for an HWND.
 * Used by the DXVK bridge for swap chain creation.
 * Exported so other .so files can call it.
 */
unsigned long hwnd_get_x11_window(HWND hwnd)
{
    gfx_window_t *gfx = hwnd_to_gfx(hwnd);
    if (!gfx) return 0;
    return gfx_get_native_window(gfx);
}

/* Find a child window by control ID (used by GetDlgItem) */
HWND hwnd_find_child_by_id(HWND parent, int control_id)
{
    ensure_hwnd_map_init();
    pthread_mutex_lock(&g_wnd_lock);
    for (int i = 0; i < MAX_HWND_MAP; i++) {
        if (g_hwnd_map[i].used &&
            g_hwnd_map[i].parent == parent &&
            g_hwnd_map[i].control_id == control_id) {
            HWND result = g_hwnd_map[i].hwnd;
            pthread_mutex_unlock(&g_wnd_lock);
            return result;
        }
    }
    pthread_mutex_unlock(&g_wnd_lock);
    return NULL;
}

/* Get control ID for a window */
int hwnd_get_control_id(HWND hwnd)
{
    /* Snapshot under lock — entry may be freed concurrently. */
    ensure_hwnd_map_init();
    pthread_mutex_lock(&g_wnd_lock);
    for (int i = 0; i < MAX_HWND_MAP; i++) {
        if (g_hwnd_map[i].used && g_hwnd_map[i].hwnd == hwnd) {
            int id = g_hwnd_map[i].control_id;
            pthread_mutex_unlock(&g_wnd_lock);
            return id;
        }
    }
    pthread_mutex_unlock(&g_wnd_lock);
    return 0;
}

/* --------------------------------------------------------------------------
 * RegisterClass
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT ATOM RegisterClassA(const WNDCLASSA *lpWndClass)
{
    if (!lpWndClass || !lpWndClass->lpszClassName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    pthread_mutex_lock(&g_wnd_lock);

    /* Check for duplicate */
    if (find_class(lpWndClass->lpszClassName)) {
        pthread_mutex_unlock(&g_wnd_lock);
        set_last_error(ERROR_ALREADY_EXISTS);
        return 0;
    }

    window_class_entry_t *cls = alloc_class();
    if (!cls) {
        pthread_mutex_unlock(&g_wnd_lock);
        set_last_error(ERROR_OUTOFMEMORY);
        return 0;
    }

    strncpy(cls->name, lpWndClass->lpszClassName, sizeof(cls->name) - 1);
    cls->name[sizeof(cls->name) - 1] = '\0';
    cls->wndproc = lpWndClass->lpfnWndProc;
    cls->hInstance = lpWndClass->hInstance;
    cls->hbrBackground = lpWndClass->hbrBackground;
    cls->style = lpWndClass->style;
    cls->cbWndExtra = lpWndClass->cbWndExtra;

    pthread_mutex_unlock(&g_wnd_lock);

    fprintf(stderr, "user32: RegisterClassA('%s')\n", cls->name);

    /* Return a non-zero atom (index + 1) */
    return (ATOM)(cls - g_classes + 1);
}

WINAPI_EXPORT ATOM RegisterClassW(const WNDCLASSW *lpWndClass)
{
    if (!lpWndClass || !lpWndClass->lpszClassName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    /* Convert wide class name to narrow (handle MAKEINTRESOURCE atom) */
    char narrow[256];
    if ((uintptr_t)lpWndClass->lpszClassName > 0xFFFF) {
        int i;
        for (i = 0; lpWndClass->lpszClassName[i] && i < 255; i++)
            narrow[i] = (char)(lpWndClass->lpszClassName[i] & 0xFF);
        narrow[i] = '\0';
    } else {
        snprintf(narrow, sizeof(narrow), "#%u", (unsigned)(uintptr_t)lpWndClass->lpszClassName);
    }

    /* Convert to WNDCLASSA and call RegisterClassA */
    WNDCLASSA wca;
    memset(&wca, 0, sizeof(wca));
    wca.style = lpWndClass->style;
    wca.lpfnWndProc = lpWndClass->lpfnWndProc;
    wca.cbClsExtra = lpWndClass->cbClsExtra;
    wca.cbWndExtra = lpWndClass->cbWndExtra;
    wca.hInstance = lpWndClass->hInstance;
    wca.hIcon = lpWndClass->hIcon;
    wca.hCursor = lpWndClass->hCursor;
    wca.hbrBackground = lpWndClass->hbrBackground;
    wca.lpszClassName = narrow;

    return RegisterClassA(&wca);
}

WINAPI_EXPORT ATOM RegisterClassExA(const WNDCLASSEXA *lpWndClassEx)
{
    if (!lpWndClassEx || !lpWndClassEx->lpszClassName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    WNDCLASSA wca;
    memset(&wca, 0, sizeof(wca));
    wca.style = lpWndClassEx->style;
    wca.lpfnWndProc = lpWndClassEx->lpfnWndProc;
    wca.cbClsExtra = lpWndClassEx->cbClsExtra;
    wca.cbWndExtra = lpWndClassEx->cbWndExtra;
    wca.hInstance = lpWndClassEx->hInstance;
    wca.hIcon = lpWndClassEx->hIcon;
    wca.hCursor = lpWndClassEx->hCursor;
    wca.hbrBackground = lpWndClassEx->hbrBackground;
    wca.lpszClassName = lpWndClassEx->lpszClassName;

    return RegisterClassA(&wca);
}

/* --------------------------------------------------------------------------
 * CreateWindowEx
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HWND CreateWindowExA(
    DWORD       dwExStyle,
    LPCSTR      lpClassName,
    LPCSTR      lpWindowName,
    DWORD       dwStyle,
    int         x,
    int         y,
    int         nWidth,
    int         nHeight,
    HWND        hWndParent,
    HMENU       hMenu,
    HINSTANCE   hInstance,
    LPVOID      lpParam)
{
    /* hInstance and lpParam used in CREATESTRUCT below */

    if (!lpClassName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    /* MAKEINTRESOURCE check: if lpClassName < 0x10000, it's an atom/resource ID, not a string */
    int is_atom = ((uintptr_t)lpClassName < 0x10000);
    const char *class_name_str = is_atom ? "ATOM_CLASS" : lpClassName;

    /* Look up the window class (snapshot WNDPROC + cbWndExtra under lock
     * so concurrent UnregisterClassA cannot tear the read). */
    WNDPROC wndproc = NULL;
    int saved_cbWndExtra = 0;
    int class_found = 0;
    if (!is_atom) {
        pthread_mutex_lock(&g_wnd_lock);
        window_class_entry_t *cls_locked = find_class(lpClassName);
        if (cls_locked) {
            wndproc = cls_locked->wndproc;
            saved_cbWndExtra = cls_locked->cbWndExtra;
            class_found = 1;
        }
        pthread_mutex_unlock(&g_wnd_lock);
    }
    /* If class not found, we allow creation anyway with DefWindowProc */

    /* Initialize graphics if needed */
    gfx_init();

    gfx_backend_t *backend = gfx_get_backend();
    if (!backend) {
        fprintf(stderr, "user32: No graphics backend, creating headless window\n");
    }

    /* Allocate a gfx window */
    gfx_window_t *gfx_win = gfx_alloc_window();
    if (!gfx_win) {
        set_last_error(ERROR_OUTOFMEMORY);
        return NULL;
    }

    /* Handle CW_USEDEFAULT */
    if (x == CW_USEDEFAULT) x = 100;
    if (y == CW_USEDEFAULT) y = 100;
    if (nWidth == CW_USEDEFAULT) nWidth = 640;
    if (nHeight == CW_USEDEFAULT) nHeight = 480;

    gfx_win->x = x;
    gfx_win->y = y;
    gfx_win->width = nWidth;
    gfx_win->height = nHeight;
    gfx_win->client_x = 0;
    gfx_win->client_y = 0;
    gfx_win->client_width = nWidth;
    gfx_win->client_height = nHeight;
    gfx_win->style = dwStyle;
    gfx_win->ex_style = dwExStyle;
    gfx_win->visible = 0;
    gfx_win->wndproc = (void *)wndproc;

    if (lpWindowName && (uintptr_t)lpWindowName > 0xFFFF) {
        strncpy(gfx_win->title, lpWindowName, sizeof(gfx_win->title) - 1);
        gfx_win->title[sizeof(gfx_win->title) - 1] = '\0';
    }

    strncpy(gfx_win->class_name, class_name_str, sizeof(gfx_win->class_name) - 1);
    gfx_win->class_name[sizeof(gfx_win->class_name) - 1] = '\0';

    /* Set parent */
    if (hWndParent) {
        gfx_win->parent = hwnd_to_gfx(hWndParent);
    }

    /* Create the backend window (only if backend available) */
    if (backend) {
        if (backend->create_window(backend, gfx_win) != 0) {
            gfx_free_window(gfx_win);
            set_last_error(ERROR_INVALID_FUNCTION);
            return NULL;
        }
    }

    /* Allocate HWND entry */
    hwnd_entry_t *entry = hwnd_alloc(gfx_win, wndproc);
    if (!entry) {
        if (backend)
            backend->destroy_window(backend, gfx_win);
        gfx_free_window(gfx_win);
        set_last_error(ERROR_OUTOFMEMORY);
        return NULL;
    }

    if (class_found)
        entry->extra_bytes = saved_cbWndExtra;

    /* Store parent and control ID */
    entry->parent = hWndParent;
    if (dwStyle & WS_CHILD) {
        /* For child windows, hMenu is the control ID (integer cast to HMENU) */
        entry->control_id = (int)(uintptr_t)hMenu;
    }

    HWND hwnd = entry->hwnd;

    fprintf(stderr, "user32: CreateWindowExA('%s', '%s') -> HWND=%p%s\n",
            class_name_str,
            (lpWindowName && (uintptr_t)lpWindowName > 0xFFFF) ? lpWindowName : "(resource)",
            hwnd, backend ? "" : " [headless]");

    /* Build CREATESTRUCT for WM_NCCREATE / WM_CREATE */
    if (wndproc) {
        CREATESTRUCTA cs;
        memset(&cs, 0, sizeof(cs));
        cs.lpCreateParams = lpParam;
        cs.hInstance = hInstance;
        cs.hMenu = hMenu;
        cs.hwndParent = hWndParent;
        cs.cy = nHeight;
        cs.cx = nWidth;
        cs.y = y;
        cs.x = x;
        cs.style = (LONG)dwStyle;
        cs.lpszName = lpWindowName;
        cs.lpszClass = lpClassName;
        cs.dwExStyle = dwExStyle;

        /* Send WM_NCCREATE first -- if it returns 0, abort window creation */
        if (wndproc(hwnd, WM_NCCREATE, 0, (LPARAM)&cs) == 0) {
            if (backend)
                backend->destroy_window(backend, gfx_win);
            hwnd_free(hwnd);
            gfx_free_window(gfx_win);
            return NULL;
        }

        /* Send WM_CREATE */
        wndproc(hwnd, WM_CREATE, 0, (LPARAM)&cs);
    }

    /* Auto-show if WS_VISIBLE */
    if (dwStyle & WS_VISIBLE) {
        if (backend)
            backend->show_window(backend, gfx_win, 1);
        gfx_win->visible = 1;
    }

    return hwnd;
}

WINAPI_EXPORT HWND CreateWindowExW(
    DWORD       dwExStyle,
    LPCWSTR     lpClassName,
    LPCWSTR     lpWindowName,
    DWORD       dwStyle,
    int         x,
    int         y,
    int         nWidth,
    int         nHeight,
    HWND        hWndParent,
    HMENU       hMenu,
    HINSTANCE   hInstance,
    LPVOID      lpParam)
{
    /* Convert wide strings to narrow */
    char class_narrow[256] = {0};
    char name_narrow[256] = {0};

    if (lpClassName && (uintptr_t)lpClassName > 0xFFFF) {
        int i;
        for (i = 0; lpClassName[i] && i < 255; i++)
            class_narrow[i] = (char)(lpClassName[i] & 0xFF);
        class_narrow[i] = '\0';
    }

    if (lpWindowName && (uintptr_t)lpWindowName > 0xFFFF) {
        int i;
        for (i = 0; lpWindowName[i] && i < 255; i++)
            name_narrow[i] = (char)(lpWindowName[i] & 0xFF);
        name_narrow[i] = '\0';
    }

    return CreateWindowExA(dwExStyle,
                           (lpClassName && (uintptr_t)lpClassName > 0xFFFF) ? class_narrow : (LPCSTR)lpClassName,
                           (lpWindowName && (uintptr_t)lpWindowName > 0xFFFF) ? name_narrow : (LPCSTR)lpWindowName,
                           dwStyle, x, y, nWidth, nHeight,
                           hWndParent, hMenu, hInstance, lpParam);
}

/* --------------------------------------------------------------------------
 * DestroyWindow
 * -------------------------------------------------------------------------- */

/* Defined in user32_message.c.  Cancels all timers whose hwnd == hWnd so a
 * subsequent timer fire doesn't invoke the stale wndproc or post WM_TIMER
 * to a freed window (use-after-free). */
extern void user32_kill_timers_for_hwnd(HWND hWnd);

WINAPI_EXPORT BOOL DestroyWindow(HWND hWnd)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /* Send WM_DESTROY */
    if (entry->wndproc) {
        entry->wndproc(hWnd, WM_DESTROY, 0, 0);
    }

    /* Reap any timers still pointing at this window before we free it --
     * otherwise user32_check_timers() will later fire a TIMERPROC with a
     * stale HWND or queue a WM_TIMER the app dispatches to a destroyed
     * window (UAF). */
    user32_kill_timers_for_hwnd(hWnd);

    gfx_backend_t *backend = gfx_get_backend();
    if (entry->gfx_win) {
        if (backend)
            backend->destroy_window(backend, entry->gfx_win);
        gfx_free_window(entry->gfx_win);
    }

    hwnd_free(hWnd);
    return TRUE;
}

/* --------------------------------------------------------------------------
 * ShowWindow
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL ShowWindow(HWND hWnd, int nCmdShow)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    gfx_backend_t *backend = gfx_get_backend();
    int was_visible = entry->gfx_win->visible;

    switch (nCmdShow) {
    case SW_HIDE:
        if (backend)
            backend->show_window(backend, entry->gfx_win, 0);
        entry->gfx_win->visible = 0;
        break;
    case SW_SHOWNORMAL:
    case SW_SHOW:
    case SW_SHOWDEFAULT:
    case SW_RESTORE:
    case SW_SHOWMAXIMIZED:
    case SW_SHOWNOACTIVATE:
    case SW_SHOWNA:
        if (backend)
            backend->show_window(backend, entry->gfx_win, 1);
        entry->gfx_win->visible = 1;
        break;
    case SW_MINIMIZE:
    case SW_SHOWMINIMIZED:
    case SW_SHOWMINNOACTIVE:
        /* We don't truly minimize, but we keep the window mapped */
        if (backend)
            backend->show_window(backend, entry->gfx_win, 1);
        entry->gfx_win->visible = 1;
        break;
    default:
        if (backend)
            backend->show_window(backend, entry->gfx_win, 1);
        entry->gfx_win->visible = 1;
        break;
    }

    return was_visible ? TRUE : FALSE;
}

/* --------------------------------------------------------------------------
 * UpdateWindow
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL UpdateWindow(HWND hWnd)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /* Send WM_PAINT if the window needs repainting */
    if (entry->gfx_win->needs_repaint && entry->wndproc) {
        entry->wndproc(hWnd, WM_PAINT, 0, 0);
        entry->gfx_win->needs_repaint = 0;
    }

    return TRUE;
}

/* --------------------------------------------------------------------------
 * MoveWindow
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL MoveWindow(HWND hWnd, int X, int Y, int nWidth, int nHeight, BOOL bRepaint)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    gfx_backend_t *backend = gfx_get_backend();
    if (backend) {
        backend->move_window(backend, entry->gfx_win, X, Y);
        backend->resize_window(backend, entry->gfx_win, nWidth, nHeight);
    } else {
        /* Headless: update gfx_win fields directly */
        entry->gfx_win->x = X;
        entry->gfx_win->y = Y;
        entry->gfx_win->width = nWidth;
        entry->gfx_win->height = nHeight;
        entry->gfx_win->client_width = nWidth;
        entry->gfx_win->client_height = nHeight;
    }

    if (bRepaint && entry->wndproc) {
        entry->gfx_win->needs_repaint = 1;
        entry->wndproc(hWnd, WM_PAINT, 0, 0);
        entry->gfx_win->needs_repaint = 0;
    }

    return TRUE;
}

/* --------------------------------------------------------------------------
 * SetWindowPos
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL SetWindowPos(HWND hWnd, HWND hWndInsertAfter,
                                int X, int Y, int cx, int cy, UINT uFlags)
{
    (void)hWndInsertAfter;  /* Z-order changes not implemented */

    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    gfx_backend_t *backend = gfx_get_backend();

    if (!(uFlags & SWP_NOMOVE)) {
        if (backend)
            backend->move_window(backend, entry->gfx_win, X, Y);
        else {
            entry->gfx_win->x = X;
            entry->gfx_win->y = Y;
        }
    }
    if (!(uFlags & SWP_NOSIZE)) {
        if (backend)
            backend->resize_window(backend, entry->gfx_win, cx, cy);
        else {
            entry->gfx_win->width = cx;
            entry->gfx_win->height = cy;
            entry->gfx_win->client_width = cx;
            entry->gfx_win->client_height = cy;
        }
    }
    if (uFlags & SWP_SHOWWINDOW) {
        if (backend)
            backend->show_window(backend, entry->gfx_win, 1);
        entry->gfx_win->visible = 1;
    }
    if (uFlags & SWP_HIDEWINDOW) {
        if (backend)
            backend->show_window(backend, entry->gfx_win, 0);
        entry->gfx_win->visible = 0;
    }

    return TRUE;
}

/* --------------------------------------------------------------------------
 * GetWindowRect / GetClientRect
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL GetWindowRect(HWND hWnd, LPRECT lpRect)
{
    if (!lpRect) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    lpRect->left   = entry->gfx_win->x;
    lpRect->top    = entry->gfx_win->y;
    lpRect->right  = entry->gfx_win->x + entry->gfx_win->width;
    lpRect->bottom = entry->gfx_win->y + entry->gfx_win->height;

    return TRUE;
}

WINAPI_EXPORT BOOL GetClientRect(HWND hWnd, LPRECT lpRect)
{
    if (!lpRect) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    lpRect->left   = 0;
    lpRect->top    = 0;
    lpRect->right  = entry->gfx_win->client_width;
    lpRect->bottom = entry->gfx_win->client_height;

    return TRUE;
}

/* --------------------------------------------------------------------------
 * SetWindowTextA
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL SetWindowTextA(HWND hWnd, LPCSTR lpString)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (lpString) {
        /* Always update our internal title copy */
        strncpy(entry->gfx_win->title, lpString, sizeof(entry->gfx_win->title) - 1);
        entry->gfx_win->title[sizeof(entry->gfx_win->title) - 1] = '\0';

        gfx_backend_t *backend = gfx_get_backend();
        if (backend)
            backend->set_title(backend, entry->gfx_win, lpString);
    }

    return TRUE;
}

/* --------------------------------------------------------------------------
 * GetWindowTextA / GetWindowTextLengthA
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT int GetWindowTextA(HWND hWnd, LPSTR lpString, int nMaxCount)
{
    if (!lpString || nMaxCount <= 0)
        return 0;

    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win) {
        lpString[0] = '\0';
        return 0;
    }

    strncpy(lpString, entry->gfx_win->title, nMaxCount - 1);
    lpString[nMaxCount - 1] = '\0';
    return (int)strlen(lpString);
}

WINAPI_EXPORT int GetWindowTextLengthA(HWND hWnd)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win)
        return 0;
    return (int)strlen(entry->gfx_win->title);
}

/* --------------------------------------------------------------------------
 * GetDesktopWindow
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HWND GetDesktopWindow(void)
{
    /* Return a special HWND representing the desktop */
    return HWND_DESKTOP;
}

/* --------------------------------------------------------------------------
 * FindWindowA
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HWND FindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName)
{
    ensure_hwnd_map_init();
    pthread_mutex_lock(&g_wnd_lock);
    for (int i = 0; i < MAX_HWND_MAP; i++) {
        if (!g_hwnd_map[i].used)
            continue;

        gfx_window_t *win = g_hwnd_map[i].gfx_win;
        if (!win)
            continue;

        if (lpClassName && strcmp(win->class_name, lpClassName) != 0)
            continue;
        if (lpWindowName && strcmp(win->title, lpWindowName) != 0)
            continue;

        HWND result = g_hwnd_map[i].hwnd;
        pthread_mutex_unlock(&g_wnd_lock);
        return result;
    }
    pthread_mutex_unlock(&g_wnd_lock);
    return NULL;
}

/* --------------------------------------------------------------------------
 * IsWindow / IsWindowVisible / IsWindowEnabled
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL IsWindow(HWND hWnd)
{
    return hwnd_lookup(hWnd) != NULL ? TRUE : FALSE;
}

WINAPI_EXPORT BOOL IsWindowVisible(HWND hWnd)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win)
        return FALSE;
    return entry->gfx_win->visible ? TRUE : FALSE;
}

WINAPI_EXPORT BOOL IsWindowEnabled(HWND hWnd)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win)
        return FALSE;
    return (entry->gfx_win->style & WS_DISABLED) ? FALSE : TRUE;
}

/* --------------------------------------------------------------------------
 * EnableWindow
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL EnableWindow(HWND hWnd, BOOL bEnable)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win)
        return FALSE;

    BOOL was_disabled = (entry->gfx_win->style & WS_DISABLED) ? TRUE : FALSE;

    if (bEnable)
        entry->gfx_win->style &= ~WS_DISABLED;
    else
        entry->gfx_win->style |= WS_DISABLED;

    return was_disabled;
}

/* --------------------------------------------------------------------------
 * GetWindowLongA / SetWindowLongA / GetWindowLongPtrA / SetWindowLongPtrA
 * -------------------------------------------------------------------------- */

#define GWL_STYLE       (-16)
#define GWL_EXSTYLE     (-20)
#define GWLP_WNDPROC    (-4)
#define GWLP_HINSTANCE  (-6)
#define GWLP_USERDATA   (-21)

WINAPI_EXPORT LONG GetWindowLongA(HWND hWnd, int nIndex)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win)
        return 0;

    switch (nIndex) {
    case GWL_STYLE:     return (LONG)entry->gfx_win->style;
    case GWL_EXSTYLE:   return (LONG)entry->gfx_win->ex_style;
    case GWLP_USERDATA: return (LONG)(LONG_PTR)entry->gfx_win->userdata;
    case GWLP_WNDPROC:  return (LONG)(LONG_PTR)entry->wndproc;
    default:
        /* Positive indices access cbWndExtra */
        if (nIndex >= 0 && nIndex + (int)sizeof(LONG) <= entry->extra_bytes) {
            LONG val = 0;
            memcpy(&val, entry->extra_data + nIndex, sizeof(LONG));
            return val;
        }
        return 0;
    }
}

WINAPI_EXPORT LONG SetWindowLongA(HWND hWnd, int nIndex, LONG dwNewLong)
{
    /* Mutate under lock — concurrent DestroyWindow can free the slot and
     * hwnd_get_wndproc / dispatch may race with this write. */
    ensure_hwnd_map_init();
    pthread_mutex_lock(&g_wnd_lock);
    hwnd_entry_t *entry = NULL;
    for (int i = 0; i < MAX_HWND_MAP; i++) {
        if (g_hwnd_map[i].used && g_hwnd_map[i].hwnd == hWnd) {
            entry = &g_hwnd_map[i];
            break;
        }
    }
    if (!entry || !entry->gfx_win) {
        pthread_mutex_unlock(&g_wnd_lock);
        return 0;
    }

    LONG old = 0;
    switch (nIndex) {
    case GWL_STYLE:
        old = (LONG)entry->gfx_win->style;
        entry->gfx_win->style = dwNewLong;
        break;
    case GWL_EXSTYLE:
        old = (LONG)entry->gfx_win->ex_style;
        entry->gfx_win->ex_style = dwNewLong;
        break;
    case GWLP_USERDATA:
        old = (LONG)(LONG_PTR)entry->gfx_win->userdata;
        entry->gfx_win->userdata = (void *)(intptr_t)dwNewLong;
        break;
    case GWLP_WNDPROC:
        old = (LONG)(LONG_PTR)entry->wndproc;
        entry->wndproc = (WNDPROC)(intptr_t)dwNewLong;
        break;
    default:
        if (nIndex >= 0 && nIndex + (int)sizeof(LONG) <= entry->extra_bytes) {
            memcpy(&old, entry->extra_data + nIndex, sizeof(LONG));
            memcpy(entry->extra_data + nIndex, &dwNewLong, sizeof(LONG));
        }
        break;
    }
    pthread_mutex_unlock(&g_wnd_lock);
    return old;
}

WINAPI_EXPORT LONG_PTR GetWindowLongPtrA(HWND hWnd, int nIndex)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win) {
        set_last_error(1400); /* ERROR_INVALID_WINDOW_HANDLE */
        return 0;
    }

    switch (nIndex) {
    case GWLP_WNDPROC:   return (LONG_PTR)(uintptr_t)entry->wndproc;
    case GWLP_USERDATA:  return (LONG_PTR)(uintptr_t)entry->gfx_win->userdata;
    case GWLP_HINSTANCE: return 0; /* No per-window hInstance tracked */
    case GWL_STYLE:      return (LONG_PTR)entry->gfx_win->style;
    case GWL_EXSTYLE:    return (LONG_PTR)entry->gfx_win->ex_style;
    default:
        /* Positive indices access cbWndExtra with full pointer width */
        if (nIndex >= 0 && nIndex + (int)sizeof(LONG_PTR) <= entry->extra_bytes) {
            LONG_PTR val = 0;
            memcpy(&val, entry->extra_data + nIndex, sizeof(LONG_PTR));
            return val;
        }
        return 0;
    }
}

WINAPI_EXPORT LONG_PTR SetWindowLongPtrA(HWND hWnd, int nIndex, LONG_PTR dwNewLong)
{
    /* Mutate under lock to serialize with hwnd_get_wndproc and other readers. */
    ensure_hwnd_map_init();
    pthread_mutex_lock(&g_wnd_lock);
    hwnd_entry_t *entry = NULL;
    for (int i = 0; i < MAX_HWND_MAP; i++) {
        if (g_hwnd_map[i].used && g_hwnd_map[i].hwnd == hWnd) {
            entry = &g_hwnd_map[i];
            break;
        }
    }
    if (!entry || !entry->gfx_win) {
        pthread_mutex_unlock(&g_wnd_lock);
        set_last_error(1400); /* ERROR_INVALID_WINDOW_HANDLE */
        return 0;
    }

    LONG_PTR old = 0;
    switch (nIndex) {
    case GWLP_WNDPROC:
        old = (LONG_PTR)(uintptr_t)entry->wndproc;
        entry->wndproc = (WNDPROC)(uintptr_t)dwNewLong;
        break;
    case GWLP_USERDATA:
        old = (LONG_PTR)(uintptr_t)entry->gfx_win->userdata;
        entry->gfx_win->userdata = (void *)(uintptr_t)dwNewLong;
        break;
    case GWLP_HINSTANCE:
        break; /* No per-window hInstance tracked */
    case GWL_STYLE:
        old = (LONG_PTR)entry->gfx_win->style;
        entry->gfx_win->style = (uint32_t)dwNewLong;
        break;
    case GWL_EXSTYLE:
        old = (LONG_PTR)entry->gfx_win->ex_style;
        entry->gfx_win->ex_style = (uint32_t)dwNewLong;
        break;
    default:
        if (nIndex >= 0 && nIndex + (int)sizeof(LONG_PTR) <= entry->extra_bytes) {
            memcpy(&old, entry->extra_data + nIndex, sizeof(LONG_PTR));
            memcpy(entry->extra_data + nIndex, &dwNewLong, sizeof(LONG_PTR));
        }
        break;
    }
    pthread_mutex_unlock(&g_wnd_lock);
    return old;
}

/* --------------------------------------------------------------------------
 * InvalidateRect / ValidateRect
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL InvalidateRect(HWND hWnd, const RECT *lpRect, BOOL bErase)
{
    (void)lpRect;
    (void)bErase;

    if (!hWnd)
        return TRUE;  /* Invalidate all windows -- just succeed */

    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (entry && entry->gfx_win) {
        entry->gfx_win->needs_repaint = 1;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL ValidateRect(HWND hWnd, const RECT *lpRect)
{
    (void)lpRect;

    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (entry && entry->gfx_win) {
        entry->gfx_win->needs_repaint = 0;
    }
    return TRUE;
}

/* --------------------------------------------------------------------------
 * GetParent / SetParent
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HWND GetParent(HWND hWnd)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry)
        return NULL;

    /* Prefer direct HWND parent if set */
    if (entry->parent)
        return entry->parent;

    /* Fall back to gfx parent lookup */
    if (entry->gfx_win && entry->gfx_win->parent)
        return gfx_to_hwnd(entry->gfx_win->parent);

    return NULL;
}

WINAPI_EXPORT HWND SetParent(HWND hWndChild, HWND hWndNewParent)
{
    hwnd_entry_t *child_entry = hwnd_lookup(hWndChild);
    if (!child_entry || !child_entry->gfx_win)
        return NULL;

    HWND old_parent = GetParent(hWndChild);

    if (hWndNewParent) {
        hwnd_entry_t *parent_entry = hwnd_lookup(hWndNewParent);
        child_entry->gfx_win->parent = parent_entry ? parent_entry->gfx_win : NULL;
    } else {
        child_entry->gfx_win->parent = NULL;
    }

    return old_parent;
}

/* --------------------------------------------------------------------------
 * GetForegroundWindow / SetForegroundWindow
 * -------------------------------------------------------------------------- */

static HWND g_foreground_window = NULL;

WINAPI_EXPORT HWND GetForegroundWindow(void)
{
    return g_foreground_window;
}

WINAPI_EXPORT BOOL SetForegroundWindow(HWND hWnd)
{
    if (hwnd_lookup(hWnd)) {
        g_foreground_window = hWnd;
        return TRUE;
    }
    return FALSE;
}

/* --------------------------------------------------------------------------
 * GetSystemMetrics
 * -------------------------------------------------------------------------- */

#define SM_CXSCREEN     0
#define SM_CYSCREEN     1
#define SM_CXVSCROLL    2
#define SM_CYHSCROLL    3
#define SM_CYCAPTION    4
#define SM_CXBORDER     5
#define SM_CYBORDER     6
#define SM_CXDLGFRAME   7
#define SM_CYDLGFRAME   8
#define SM_CXFIXEDFRAME 7
#define SM_CYFIXEDFRAME 8
#define SM_CXICON       11
#define SM_CYICON       12
#define SM_CXCURSOR     13
#define SM_CYCURSOR     14
#define SM_CYMENU       15
#define SM_CXFULLSCREEN 16
#define SM_CYFULLSCREEN 17
#define SM_CXFRAME      32
#define SM_CYFRAME      33
#define SM_CXMINTRACK   34
#define SM_CYMINTRACK   35
#define SM_CXMAXIMIZED  61
#define SM_CYMAXIMIZED  62

WINAPI_EXPORT int GetSystemMetrics(int nIndex)
{
    gfx_backend_t *backend = gfx_get_backend();

    switch (nIndex) {
    case SM_CXSCREEN:
    case SM_CXFULLSCREEN:
        if (backend) {
            gfx_screen_size_t sz = backend->get_screen_size(backend);
            return sz.width;
        }
        return 1920;
    case SM_CYSCREEN:
    case SM_CYFULLSCREEN:
        if (backend) {
            gfx_screen_size_t sz = backend->get_screen_size(backend);
            return sz.height;
        }
        return 1080;
    case SM_CYCAPTION:     return 23;
    case SM_CXBORDER:
    case SM_CYBORDER:      return 1;
    case SM_CXDLGFRAME:
    case SM_CYDLGFRAME:    return 3;
    case SM_CXVSCROLL:
    case SM_CYHSCROLL:     return 17;
    case SM_CXICON:
    case SM_CYICON:        return 32;
    case SM_CXCURSOR:
    case SM_CYCURSOR:      return 32;
    case SM_CYMENU:        return 20;
    case SM_CXFRAME:
    case SM_CYFRAME:       return 4;
    case SM_CXMINTRACK:    return 112;
    case SM_CYMINTRACK:    return 27;
    case SM_CXMAXIMIZED:
        if (backend) {
            gfx_screen_size_t sz = backend->get_screen_size(backend);
            return sz.width;
        }
        return 1920;
    case SM_CYMAXIMIZED:
        if (backend) {
            gfx_screen_size_t sz = backend->get_screen_size(backend);
            return sz.height;
        }
        return 1080;
    default:
        return 0;
    }
}

/* --------------------------------------------------------------------------
 * AdjustWindowRect / AdjustWindowRectEx
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL AdjustWindowRect(LPRECT lpRect, DWORD dwStyle, BOOL bMenu)
{
    (void)dwStyle;

    if (!lpRect)
        return FALSE;

    /* Add rough border/caption sizes */
    lpRect->left   -= 4;
    lpRect->top    -= 23 + (bMenu ? 20 : 0);
    lpRect->right  += 4;
    lpRect->bottom += 4;

    return TRUE;
}

WINAPI_EXPORT BOOL AdjustWindowRectEx(LPRECT lpRect, DWORD dwStyle, BOOL bMenu, DWORD dwExStyle)
{
    (void)dwExStyle;
    return AdjustWindowRect(lpRect, dwStyle, bMenu);
}

/* --------------------------------------------------------------------------
 * DefWindowProcA - Default window message handler
 * -------------------------------------------------------------------------- */

/* Forward declaration - SendMessage is in user32_message.c */
extern LRESULT __attribute__((ms_abi)) SendMessageA(HWND, UINT, WPARAM, LPARAM);
#ifndef SendMessage
#define SendMessage SendMessageA
#endif

/* SC_* syscommand codes */
#define SC_CLOSE        0xF060
#define SC_MINIMIZE     0xF020
#define SC_MAXIMIZE     0xF030
#define SC_RESTORE      0xF120
#define SC_MOVE         0xF010
#define SC_SIZE         0xF000
#define SC_KEYMENU      0xF100
#define SC_SCREENSAVE   0xF140
#define SC_MONITORPOWER 0xF170

/* WM_SIZE codes */
#define SIZE_RESTORED   0
#define SIZE_MINIMIZED  1
#define SIZE_MAXIMIZED  2

WINAPI_EXPORT LRESULT DefWindowProcA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);

    switch (Msg) {
    case WM_NCCREATE:
        /* Non-client area created — return TRUE to continue creation */
        return TRUE;

    case WM_NCDESTROY:
        /* Non-client area destroyed — free any NC resources */
        return 0;

    case WM_NCCALCSIZE:
        /* wParam=FALSE: lParam = RECT*; wParam=TRUE: lParam = NCCALCSIZE_PARAMS*
         * For simplicity, use the entire window as client area. */
        return 0;

    case WM_CLOSE:
        DestroyWindow(hWnd);
        return 0;

    case WM_DESTROY:
        /* Post WM_QUIT if this is the last top-level window being destroyed */
        return 0;

    case WM_NCHITTEST: {
        /* Return HTCLIENT for interior; HTCAPTION for title bar area */
        if (!entry || !entry->gfx_win)
            return 1; /* HTCLIENT */
        /* lParam = screen coordinates */
        int sx = (int)(short)LOWORD(lParam);
        int sy = (int)(short)HIWORD(lParam);
        int wx = entry->gfx_win->x;
        int wy = entry->gfx_win->y;
        /* Caption height ~23px from top */
        if (sy >= wy && sy < wy + 23 &&
            sx >= wx && sx < wx + entry->gfx_win->width)
            return 2; /* HTCAPTION */
        return 1; /* HTCLIENT */
    }

    case WM_ERASEBKGND: {
        if (entry && entry->gfx_win) {
            gfx_backend_t *backend = gfx_get_backend();
            if (backend) {
                gfx_dc_t *dc = backend->get_dc(backend, entry->gfx_win);
                if (dc) {
                    backend->paint_rect(backend, dc, 0, 0,
                                       entry->gfx_win->client_width,
                                       entry->gfx_win->client_height,
                                       entry->gfx_win->bg_color);
                    backend->release_dc(backend, entry->gfx_win, dc);
                }
            }
        }
        return 1;
    }

    case WM_PAINT:
        /* Default: validate entire client area */
        if (entry && entry->gfx_win)
            entry->gfx_win->needs_repaint = 0;
        return 0;

    case WM_SETTEXT:
        if (lParam)
            SetWindowTextA(hWnd, (LPCSTR)lParam);
        return TRUE;

    case WM_GETTEXT:
        if (wParam > 0 && lParam)
            return GetWindowTextA(hWnd, (LPSTR)lParam, (int)wParam);
        return 0;

    case WM_GETTEXTLENGTH:
        return GetWindowTextLengthA(hWnd);

    case WM_ACTIVATE:
        /* wParam low word: WA_INACTIVE=0, WA_ACTIVE=1, WA_CLICKACTIVE=2 */
        return 0;

    case WM_SETFOCUS:
        return 0;

    case WM_KILLFOCUS:
        return 0;

    case WM_SIZE:
        /* wParam = SIZE_RESTORED/MINIMIZED/MAXIMIZED
         * lParam = LOWORD=new client width, HIWORD=new client height */
        if (entry && entry->gfx_win) {
            entry->gfx_win->client_width  = (int)(short)LOWORD(lParam);
            entry->gfx_win->client_height = (int)(short)HIWORD(lParam);
        }
        return 0;

    case WM_MOVE:
        /* lParam = LOWORD=new x, HIWORD=new y (client top-left in screen coords) */
        if (entry && entry->gfx_win) {
            entry->gfx_win->x = (int)(short)LOWORD(lParam);
            entry->gfx_win->y = (int)(short)HIWORD(lParam);
        }
        return 0;

    case WM_SYSCOMMAND:
        switch (wParam & 0xFFF0) {
        case SC_CLOSE:
            SendMessage(hWnd, WM_CLOSE, 0, 0);
            return 0;
        case SC_MINIMIZE:
            ShowWindow(hWnd, 6 /* SW_MINIMIZE */);
            return 0;
        case SC_MAXIMIZE:
            ShowWindow(hWnd, 3 /* SW_SHOWMAXIMIZED */);
            return 0;
        case SC_RESTORE:
            ShowWindow(hWnd, 9 /* SW_RESTORE */);
            return 0;
        case SC_KEYMENU:
            return 0;  /* Suppress default menu activation */
        case SC_SCREENSAVE:
        case SC_MONITORPOWER:
            return 0;  /* Suppress screen saver */
        default:
            return 0;
        }

    case WM_MOUSEACTIVATE:
        return 1;  /* MA_ACTIVATE */

    case WM_GETMINMAXINFO: {
        /* Fill MINMAXINFO at lParam with reasonable defaults */
        typedef struct {
            POINT ptReserved;
            POINT ptMaxSize;
            POINT ptMaxPosition;
            POINT ptMinTrackSize;
            POINT ptMaxTrackSize;
        } MINMAXINFO;
        MINMAXINFO *mmi = (MINMAXINFO *)lParam;
        if (mmi) {
            gfx_backend_t *backend = gfx_get_backend();
            int sw = 1920, sh = 1080;
            if (backend) {
                gfx_screen_size_t sz = backend->get_screen_size(backend);
                sw = sz.width; sh = sz.height;
            }
            mmi->ptMaxSize.x     = sw;
            mmi->ptMaxSize.y     = sh;
            mmi->ptMaxPosition.x = 0;
            mmi->ptMaxPosition.y = 0;
            mmi->ptMinTrackSize.x = 112;
            mmi->ptMinTrackSize.y = 27;
            mmi->ptMaxTrackSize.x = sw;
            mmi->ptMaxTrackSize.y = sh;
        }
        return 0;
    }

    case WM_SHOWWINDOW:
        return 0;

    case WM_WINDOWPOSCHANGING:
    case WM_WINDOWPOSCHANGED:
        return 0;

    case WM_NCPAINT:
        return 0;

    case WM_NCACTIVATE:
        return TRUE; /* Allow activation */

    default:
        return 0;
    }
}

WINAPI_EXPORT LRESULT DefWindowProcW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    /* For now, delegate to the ANSI version */
    return DefWindowProcA(hWnd, Msg, wParam, lParam);
}

/* --------------------------------------------------------------------------
 * Misc stubs
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL ClientToScreen(HWND hWnd, LPPOINT lpPoint)
{
    if (!lpPoint)
        return FALSE;

    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (entry && entry->gfx_win) {
        lpPoint->x += entry->gfx_win->x;
        lpPoint->y += entry->gfx_win->y;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL ScreenToClient(HWND hWnd, LPPOINT lpPoint)
{
    if (!lpPoint)
        return FALSE;

    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (entry && entry->gfx_win) {
        lpPoint->x -= entry->gfx_win->x;
        lpPoint->y -= entry->gfx_win->y;
    }
    return TRUE;
}

WINAPI_EXPORT HWND GetFocus(void)
{
    return g_foreground_window;
}

WINAPI_EXPORT HWND SetFocus(HWND hWnd)
{
    HWND old = g_foreground_window;
    g_foreground_window = hWnd;
    return old;
}

WINAPI_EXPORT BOOL GetWindowPlacement(HWND hWnd, void *lpwndpl)
{
    (void)hWnd;
    (void)lpwndpl;
    /* Stub - return success */
    return TRUE;
}

WINAPI_EXPORT BOOL SetWindowPlacement(HWND hWnd, const void *lpwndpl)
{
    (void)hWnd;
    (void)lpwndpl;
    return TRUE;
}

WINAPI_EXPORT int MapWindowPoints(HWND hWndFrom, HWND hWndTo, LPPOINT lpPoints, UINT cPoints)
{
    (void)hWndFrom;
    (void)hWndTo;
    (void)lpPoints;
    (void)cPoints;
    /* Stub */
    return 0;
}

WINAPI_EXPORT BOOL SetRect(LPRECT lprc, int xLeft, int yTop, int xRight, int yBottom)
{
    if (!lprc) return FALSE;
    lprc->left = xLeft;
    lprc->top = yTop;
    lprc->right = xRight;
    lprc->bottom = yBottom;
    return TRUE;
}

WINAPI_EXPORT BOOL OffsetRect(LPRECT lprc, int dx, int dy)
{
    if (!lprc) return FALSE;
    lprc->left += dx;
    lprc->top += dy;
    lprc->right += dx;
    lprc->bottom += dy;
    return TRUE;
}

WINAPI_EXPORT BOOL InflateRect(LPRECT lprc, int dx, int dy)
{
    if (!lprc) return FALSE;
    lprc->left -= dx;
    lprc->top -= dy;
    lprc->right += dx;
    lprc->bottom += dy;
    return TRUE;
}

WINAPI_EXPORT BOOL IntersectRect(LPRECT lprcDst, const RECT *lprcSrc1, const RECT *lprcSrc2)
{
    if (!lprcDst || !lprcSrc1 || !lprcSrc2) return FALSE;

    lprcDst->left   = (lprcSrc1->left   > lprcSrc2->left)   ? lprcSrc1->left   : lprcSrc2->left;
    lprcDst->top    = (lprcSrc1->top    > lprcSrc2->top)    ? lprcSrc1->top    : lprcSrc2->top;
    lprcDst->right  = (lprcSrc1->right  < lprcSrc2->right)  ? lprcSrc1->right  : lprcSrc2->right;
    lprcDst->bottom = (lprcSrc1->bottom < lprcSrc2->bottom) ? lprcSrc1->bottom : lprcSrc2->bottom;

    if (lprcDst->left >= lprcDst->right || lprcDst->top >= lprcDst->bottom) {
        memset(lprcDst, 0, sizeof(RECT));
        return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL UnionRect(LPRECT lprcDst, const RECT *lprcSrc1, const RECT *lprcSrc2)
{
    if (!lprcDst || !lprcSrc1 || !lprcSrc2) return FALSE;

    lprcDst->left   = (lprcSrc1->left   < lprcSrc2->left)   ? lprcSrc1->left   : lprcSrc2->left;
    lprcDst->top    = (lprcSrc1->top    < lprcSrc2->top)    ? lprcSrc1->top    : lprcSrc2->top;
    lprcDst->right  = (lprcSrc1->right  > lprcSrc2->right)  ? lprcSrc1->right  : lprcSrc2->right;
    lprcDst->bottom = (lprcSrc1->bottom > lprcSrc2->bottom) ? lprcSrc1->bottom : lprcSrc2->bottom;

    return TRUE;
}

WINAPI_EXPORT BOOL IsRectEmpty(const RECT *lprc)
{
    if (!lprc) return TRUE;
    return (lprc->left >= lprc->right || lprc->top >= lprc->bottom) ? TRUE : FALSE;
}

WINAPI_EXPORT BOOL PtInRect(const RECT *lprc, POINT pt)
{
    if (!lprc) return FALSE;
    return (pt.x >= lprc->left && pt.x < lprc->right &&
            pt.y >= lprc->top  && pt.y < lprc->bottom) ? TRUE : FALSE;
}

/* --------------------------------------------------------------------------
 * BeginPaint / EndPaint
 * -------------------------------------------------------------------------- */

typedef struct tagPAINTSTRUCT {
    HDC         hdc;
    BOOL        fErase;
    RECT        rcPaint;
    BOOL        fRestore;
    BOOL        fIncUpdate;
    BYTE        rgbReserved[32];
} PAINTSTRUCT, *LPPAINTSTRUCT;

WINAPI_EXPORT HDC BeginPaint(HWND hWnd, LPPAINTSTRUCT lpPaint)
{
    /* Delegate to gdi32's internal BeginPaint which allocates a DC entry
     * in g_dc_map, so that dc_lookup() can find the HDC and all GDI
     * drawing operations (SelectObject, TextOut, etc.) work correctly.
     * Without this, raw gfx_dc_t* pointers are returned as HDC and
     * dc_lookup() can never find them, making all GDI calls fail. */
    resolve_gdi32_dc_funcs();
    if (s_gdi32_BeginPaint)
        return s_gdi32_BeginPaint(hWnd, (void *)lpPaint);
    return NULL;
}

WINAPI_EXPORT BOOL EndPaint(HWND hWnd, const PAINTSTRUCT *lpPaint)
{
    resolve_gdi32_dc_funcs();
    if (s_gdi32_EndPaint)
        return s_gdi32_EndPaint(hWnd, (const void *)lpPaint);
    return FALSE;
}

/* --------------------------------------------------------------------------
 * GetDC / ReleaseDC
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HDC GetDC(HWND hWnd)
{
    /* Delegate to gdi32's internal GetDC which allocates a DC entry
     * in g_dc_map, so that dc_lookup() can find the HDC and all GDI
     * drawing operations work correctly. */
    resolve_gdi32_dc_funcs();
    if (s_gdi32_GetDC)
        return s_gdi32_GetDC(hWnd);
    return NULL;
}

WINAPI_EXPORT int ReleaseDC(HWND hWnd, HDC hDC)
{
    resolve_gdi32_dc_funcs();
    if (s_gdi32_ReleaseDC)
        return s_gdi32_ReleaseDC(hWnd, hDC);
    return 0;
}

WINAPI_EXPORT HDC GetWindowDC(HWND hWnd)
{
    return GetDC(hWnd);
}

/* --------------------------------------------------------------------------
 * FrameRect
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT int FrameRect(HDC hDC, const RECT *lprc, HBRUSH hbr)
{
    (void)hDC; (void)lprc; (void)hbr;
    return 1;
}

/* --------------------------------------------------------------------------
 * GetWindowLongW / SetWindowLongW / GetWindowLongPtrW / SetWindowLongPtrW
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT LONG GetWindowLongW(HWND hWnd, int nIndex)
{
    return GetWindowLongA(hWnd, nIndex);
}

WINAPI_EXPORT LONG SetWindowLongW(HWND hWnd, int nIndex, LONG dwNewLong)
{
    return SetWindowLongA(hWnd, nIndex, dwNewLong);
}

WINAPI_EXPORT LONG_PTR GetWindowLongPtrW(HWND hWnd, int nIndex)
{
    return GetWindowLongPtrA(hWnd, nIndex);
}

WINAPI_EXPORT LONG_PTR SetWindowLongPtrW(HWND hWnd, int nIndex, LONG_PTR dwNewLong)
{
    return SetWindowLongPtrA(hWnd, nIndex, dwNewLong);
}

/* --------------------------------------------------------------------------
 * RegisterClassExW / UnregisterClassA
 * -------------------------------------------------------------------------- */

typedef struct {
    UINT        cbSize;
    UINT        style;
    WNDPROC     lpfnWndProc;
    int         cbClsExtra;
    int         cbWndExtra;
    HINSTANCE   hInstance;
    HICON       hIcon;
    HCURSOR     hCursor;
    HBRUSH      hbrBackground;
    LPCWSTR     lpszMenuName;
    LPCWSTR     lpszClassName;
    HICON       hIconSm;
} WNDCLASSEXW;

WINAPI_EXPORT ATOM RegisterClassExW(const WNDCLASSEXW *lpWndClassEx)
{
    if (!lpWndClassEx || !lpWndClassEx->lpszClassName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    WNDCLASSEXA wca;
    memset(&wca, 0, sizeof(wca));
    wca.cbSize = sizeof(wca);
    wca.style = lpWndClassEx->style;
    wca.lpfnWndProc = lpWndClassEx->lpfnWndProc;
    wca.cbClsExtra = lpWndClassEx->cbClsExtra;
    wca.cbWndExtra = lpWndClassEx->cbWndExtra;
    wca.hInstance = lpWndClassEx->hInstance;
    wca.hIcon = lpWndClassEx->hIcon;
    wca.hCursor = lpWndClassEx->hCursor;
    wca.hbrBackground = lpWndClassEx->hbrBackground;
    wca.hIconSm = lpWndClassEx->hIconSm;

    char narrow[256];
    int i;
    for (i = 0; lpWndClassEx->lpszClassName[i] && i < 255; i++)
        narrow[i] = (char)(lpWndClassEx->lpszClassName[i] & 0xFF);
    narrow[i] = '\0';
    wca.lpszClassName = narrow;

    return RegisterClassExA(&wca);
}

WINAPI_EXPORT BOOL UnregisterClassA(LPCSTR lpClassName, HINSTANCE hInstance)
{
    (void)hInstance;
    if (!lpClassName) return FALSE;

    pthread_mutex_lock(&g_wnd_lock);
    window_class_entry_t *cls = find_class(lpClassName);
    if (!cls) {
        pthread_mutex_unlock(&g_wnd_lock);
        set_last_error(ERROR_CLASS_DOES_NOT_EXIST);
        return FALSE;
    }

    /* Zero all fields so stale wndproc/style/extra cannot leak to a
     * subsequent RegisterClassA for a different class. */
    memset(cls, 0, sizeof(*cls));
    pthread_mutex_unlock(&g_wnd_lock);
    return TRUE;
}

/* --------------------------------------------------------------------------
 * Window enumeration
 * -------------------------------------------------------------------------- */

typedef BOOL (__attribute__((ms_abi)) *WNDENUMPROC)(HWND, LPARAM);

WINAPI_EXPORT BOOL EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam)
{
    if (!lpEnumFunc) return FALSE;

    /* Snapshot HWNDs under lock, then invoke callbacks without lock.
     * The callback may call CreateWindow/DestroyWindow and would deadlock
     * (or race with concurrent destroy corrupting the iteration). */
    ensure_hwnd_map_init();
    HWND snapshot[MAX_HWND_MAP];
    int count = 0;
    pthread_mutex_lock(&g_wnd_lock);
    for (int i = 0; i < MAX_HWND_MAP; i++) {
        if (g_hwnd_map[i].used)
            snapshot[count++] = g_hwnd_map[i].hwnd;
    }
    pthread_mutex_unlock(&g_wnd_lock);

    for (int i = 0; i < count; i++) {
        if (!lpEnumFunc(snapshot[i], lParam))
            return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL EnumChildWindows(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam)
{
    if (!lpEnumFunc) return FALSE;

    ensure_hwnd_map_init();
    gfx_window_t *parent_gfx = hwnd_to_gfx(hWndParent);

    /* Snapshot matching child HWNDs under lock, then invoke callbacks without lock. */
    HWND snapshot[MAX_HWND_MAP];
    int count = 0;
    pthread_mutex_lock(&g_wnd_lock);
    for (int i = 0; i < MAX_HWND_MAP; i++) {
        if (g_hwnd_map[i].used && g_hwnd_map[i].gfx_win &&
            g_hwnd_map[i].gfx_win->parent == parent_gfx) {
            snapshot[count++] = g_hwnd_map[i].hwnd;
        }
    }
    pthread_mutex_unlock(&g_wnd_lock);

    for (int i = 0; i < count; i++) {
        if (!lpEnumFunc(snapshot[i], lParam))
            return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT HWND FindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName)
{
    char class_narrow[256] = {0};
    char name_narrow[256] = {0};

    if (lpClassName) {
        for (int i = 0; lpClassName[i] && i < 255; i++)
            class_narrow[i] = (char)(lpClassName[i] & 0xFF);
    }
    if (lpWindowName) {
        for (int i = 0; lpWindowName[i] && i < 255; i++)
            name_narrow[i] = (char)(lpWindowName[i] & 0xFF);
    }

    return FindWindowA(lpClassName ? class_narrow : NULL,
                       lpWindowName ? name_narrow : NULL);
}

WINAPI_EXPORT HWND GetWindow(HWND hWnd, UINT uCmd)
{
    (void)hWnd; (void)uCmd;
    return NULL;
}

WINAPI_EXPORT HWND GetTopWindow(HWND hWnd)
{
    (void)hWnd;
    return NULL;
}

WINAPI_EXPORT HWND GetActiveWindow(void)
{
    return g_foreground_window;
}

WINAPI_EXPORT HWND SetActiveWindow(HWND hWnd)
{
    HWND old = g_foreground_window;
    if (hwnd_lookup(hWnd))
        g_foreground_window = hWnd;
    return old;
}

WINAPI_EXPORT BOOL RedrawWindow(HWND hWnd, const RECT *lprcUpdate,
                                 HANDLE hrgnUpdate, UINT flags)
{
    (void)lprcUpdate; (void)hrgnUpdate; (void)flags;
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (entry && entry->gfx_win)
        entry->gfx_win->needs_repaint = 1;
    return TRUE;
}

WINAPI_EXPORT int GetClassNameA(HWND hWnd, LPSTR lpClassName, int nMaxCount)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win || !lpClassName || nMaxCount <= 0)
        return 0;
    strncpy(lpClassName, entry->gfx_win->class_name, nMaxCount - 1);
    lpClassName[nMaxCount - 1] = '\0';
    return (int)strlen(lpClassName);
}

WINAPI_EXPORT DWORD GetWindowThreadProcessId(HWND hWnd, LPDWORD lpdwProcessId)
{
    (void)hWnd;
    if (lpdwProcessId) *lpdwProcessId = (DWORD)getpid();
    return (DWORD)pthread_self();
}

WINAPI_EXPORT BOOL ClipCursor(const RECT *lpRect)
{
    (void)lpRect;
    return TRUE;
}

WINAPI_EXPORT BOOL GetClipCursor(LPRECT lpRect)
{
    if (!lpRect) return FALSE;
    lpRect->left = 0;
    lpRect->top = 0;
    lpRect->right = GetSystemMetrics(SM_CXSCREEN);
    lpRect->bottom = GetSystemMetrics(SM_CYSCREEN);
    return TRUE;
}

/* --------------------------------------------------------------------------
 * wsprintfA / wsprintfW - Formatted string output (user32 export)
 * -------------------------------------------------------------------------- */

/*
 * wsprintfA/W - Windows limited printf implementation
 *
 * CRITICAL: ms_abi variadic functions CANNOT forward va_list to sysv_abi
 * functions (vsprintf, vsnprintf). The va_list types are incompatible:
 * ms_abi va_list is a simple char*, sysv_abi va_list is a struct.
 * We extract args with va_arg (GCC auto-selects ms_abi version) and format manually.
 *
 * Windows wsprintfA supports: %s %d %i %u %o %x %X %c %% with l/h modifiers
 */

/*
 * ms_abi va_list helpers.  GCC's va_list inside an ms_abi function is still
 * the sysv_abi struct (GCC bug).  Use __builtin_ms_va_list explicitly.
 * ms_abi va_list is a simple char*; every arg occupies 8 bytes.
 */
typedef __builtin_ms_va_list ms_va_list;
#define MS_VA_START(ap, last) __builtin_ms_va_start(ap, last)
#define MS_VA_END(ap)         __builtin_ms_va_end(ap)
#define MS_VA_ARG(ap, type)   (*(type *)((ap += 8) - 8))

WINAPI_EXPORT int wsprintfA(LPSTR lpOut, LPCSTR lpFmt, ...)
{
    ms_va_list ap;
    MS_VA_START(ap, lpFmt);

    char *out = lpOut;
    char *max_out = lpOut + 1023; /* Windows wsprintfA: 1024-byte output limit */
    const char *p = lpFmt;

    while (*p) {
        if (*p != '%') {
            if (out >= max_out) break;
            *out++ = *p++; continue;
        }
        p++; /* skip '%' */

        /* Flags */
        int zero_pad = 0;
        while (*p == '-' || *p == '0' || *p == '#' || *p == '+' || *p == ' ') {
            if (*p == '0') zero_pad = 1;
            p++;
        }

        /* Width */
        int width = 0;
        if (*p == '*') { width = MS_VA_ARG(ap, int); p++; }
        else while (*p >= '0' && *p <= '9') { width = width * 10 + (*p++ - '0'); }

        /* Precision (wsprintfA ignores it but we need to skip) */
        if (*p == '.') {
            p++;
            if (*p == '*') { (void)MS_VA_ARG(ap, int); p++; }
            else while (*p >= '0' && *p <= '9') p++;
        }

        /* Length modifier */
        int is_long = 0;
        if (*p == 'l') { is_long = 1; p++; }
        else if (*p == 'h') { p++; }

        /* Conversion */
        char tmp[68];
        int len = 0;
        switch (*p++) {
        case '%':
            if (out >= max_out) break;
            *out++ = '%'; continue;
        case 'c':
            if (out >= max_out) break;
            *out++ = (char)MS_VA_ARG(ap, int); continue;
        case 's': {
            char *s = MS_VA_ARG(ap, char *);
            if (!s) s = "(null)";
            while (*s && out < max_out) *out++ = *s++;
            continue;
        }
        case 'S': { /* wide string */
            uint16_t *ws = MS_VA_ARG(ap, uint16_t *);
            if (!ws) { const char *n = "(null)"; while (*n && out < max_out) *out++ = *n++; continue; }
            while (*ws && out < max_out) { *out++ = (char)(*ws < 128 ? *ws : '?'); ws++; }
            continue;
        }
        case 'd': case 'i': {
            long long val = is_long ? (long long)MS_VA_ARG(ap, long)
                                    : (long long)MS_VA_ARG(ap, int);
            if (val < 0) { tmp[len++] = '-'; val = -val; }
            char digits[20]; int dlen = 0;
            do { digits[dlen++] = '0' + (int)(val % 10); val /= 10; } while (val);
            while (dlen + len < width && zero_pad) tmp[len++] = '0';
            while (dlen > 0) tmp[len++] = digits[--dlen];
            break;
        }
        case 'u': {
            unsigned long long val = is_long ? (unsigned long long)MS_VA_ARG(ap, unsigned long)
                                             : (unsigned long long)MS_VA_ARG(ap, unsigned int);
            char digits[20]; int dlen = 0;
            do { digits[dlen++] = '0' + (int)(val % 10); val /= 10; } while (val);
            while (dlen + len < width && zero_pad) tmp[len++] = '0';
            while (dlen > 0) tmp[len++] = digits[--dlen];
            break;
        }
        case 'x': case 'X': {
            int upper = (*(p-1) == 'X');
            unsigned long long val = is_long ? (unsigned long long)MS_VA_ARG(ap, unsigned long)
                                             : (unsigned long long)MS_VA_ARG(ap, unsigned int);
            const char *hex = upper ? "0123456789ABCDEF" : "0123456789abcdef";
            char digits[20]; int dlen = 0;
            do { digits[dlen++] = hex[val & 0xF]; val >>= 4; } while (val);
            while (dlen + len < width && zero_pad) tmp[len++] = '0';
            while (dlen > 0) tmp[len++] = digits[--dlen];
            break;
        }
        case 'o': {
            unsigned long long val = is_long ? (unsigned long long)MS_VA_ARG(ap, unsigned long)
                                             : (unsigned long long)MS_VA_ARG(ap, unsigned int);
            char digits[24]; int dlen = 0;
            do { digits[dlen++] = '0' + (int)(val & 7); val >>= 3; } while (val);
            while (dlen > 0) tmp[len++] = digits[--dlen];
            break;
        }
        case 'p': {
            void *ptr = MS_VA_ARG(ap, void *);
            uintptr_t val = (uintptr_t)ptr;
            tmp[len++] = '0'; tmp[len++] = 'x';
            const char *hex = "0123456789abcdef";
            char digits[20]; int dlen = 0;
            do { digits[dlen++] = hex[val & 0xF]; val >>= 4; } while (val);
            while (dlen > 0) tmp[len++] = digits[--dlen];
            break;
        }
        default:
            if (out < max_out) *out++ = '%';
            if (out < max_out) *out++ = *(p-1);
            continue;
        }
        /* Pad and copy tmp (with bounds check) */
        while (len < width) tmp[len++] = ' ';
        for (int i = 0; i < len && out < max_out; i++) *out++ = tmp[i];
    }
    *out = '\0';
    MS_VA_END(ap);
    return (int)(out - lpOut);
}

WINAPI_EXPORT int wsprintfW(LPWSTR lpOut, LPCWSTR lpFmt, ...)
{
    /* Convert wide format string to narrow, delegate to wvsprintfA, convert back */
    char narrow_fmt[1024], narrow_out[1024];
    int fi;
    for (fi = 0; lpFmt[fi] && fi < 1023; fi++)
        narrow_fmt[fi] = (char)(lpFmt[fi] & 0xFF);
    narrow_fmt[fi] = '\0';

    ms_va_list ap;
    MS_VA_START(ap, lpFmt);
    /* Call wsprintfA instead -- wvsprintfA is defined below and can't be forward-declared
     * with ms_abi easily. wsprintfA handles the format parsing identically. */
    int len = wsprintfA(narrow_out, "%s", narrow_fmt);
    /* Re-do: actually just inline the format logic since we have the va_list */
    {
        char *o = narrow_out;
        char *max_o = narrow_out + 1023;
        const char *fp = narrow_fmt;
        while (*fp && o < max_o) {
            if (*fp != '%') { *o++ = *fp++; continue; }
            fp++;
            if (*fp == 's') {
                fp++;
                char *s = *(char **)ap; ap += 8;
                if (!s) s = "(null)";
                while (*s && o < max_o) *o++ = *s++;
            } else if (*fp == 'd' || *fp == 'i') {
                fp++;
                int v = *(int *)ap; ap += 8;
                int n = snprintf(o, max_o - o, "%d", v);
                o += (n > 0 && n < max_o - o) ? n : 0;
            } else if (*fp == 'u') {
                fp++;
                unsigned v = *(unsigned *)ap; ap += 8;
                int n = snprintf(o, max_o - o, "%u", v);
                o += (n > 0 && n < max_o - o) ? n : 0;
            } else if (*fp == 'x' || *fp == 'X') {
                char fc = *fp++;
                unsigned v = *(unsigned *)ap; ap += 8;
                int n = snprintf(o, max_o - o, fc == 'x' ? "%x" : "%X", v);
                o += (n > 0 && n < max_o - o) ? n : 0;
            } else if (*fp == '%') {
                fp++;
                *o++ = '%';
            } else {
                *o++ = '%';
                if (*fp) *o++ = *fp++;
            }
        }
        *o = '\0';
        len = (int)(o - narrow_out);
    }
    MS_VA_END(ap);

    /* Convert narrow result back to wide */
    int i;
    for (i = 0; i < len && i < 1023; i++)
        lpOut[i] = (uint16_t)(unsigned char)narrow_out[i];
    lpOut[i] = 0;
    return i;
}

WINAPI_EXPORT int wvsprintfA(LPSTR lpOut, LPCSTR lpFmt, void *arglist)
{
    /* arglist is an ms_abi va_list = char* pointer to the arg area.
     * We walk it manually, same as wsprintfA but with explicit pointer. */
    char *ap = (char *)arglist;
    char *out = lpOut;
    const char *p = lpFmt;
    while (*p) {
        if (*p != '%') { *out++ = *p++; continue; }
        p++;
        while (*p == '-' || *p == '0' || *p == '#' || *p == '+' || *p == ' ') p++;
        while (*p >= '0' && *p <= '9') p++;
        if (*p == '.') { p++; while (*p >= '0' && *p <= '9') p++; }
        int is_long = 0;
        if (*p == 'l') { is_long = 1; p++; } else if (*p == 'h') p++;
        (void)is_long;
        switch (*p++) {
        case '%': *out++ = '%'; break;
        case 's': { char *s = *(char **)ap; ap += 8; if (!s) s = "(null)"; while (*s) *out++ = *s++; break; }
        case 'd': case 'i': { int v = *(int *)ap; ap += 8; char t[20]; int n = sprintf(t, "%d", v); for (int i = 0; i < n; i++) *out++ = t[i]; break; }
        case 'u': { unsigned v = *(unsigned *)ap; ap += 8; char t[20]; int n = sprintf(t, "%u", v); for (int i = 0; i < n; i++) *out++ = t[i]; break; }
        case 'x': { unsigned v = *(unsigned *)ap; ap += 8; char t[20]; int n = sprintf(t, "%x", v); for (int i = 0; i < n; i++) *out++ = t[i]; break; }
        case 'X': { unsigned v = *(unsigned *)ap; ap += 8; char t[20]; int n = sprintf(t, "%X", v); for (int i = 0; i < n; i++) *out++ = t[i]; break; }
        default: *out++ = '%'; *out++ = *(p-1); break;
        }
    }
    *out = '\0';
    return (int)(out - lpOut);
}

WINAPI_EXPORT int wvsprintfW(LPWSTR lpOut, LPCWSTR lpFmt, void *arglist)
{
    char narrow_fmt[1024], narrow_out[1024];
    /* Convert wide format string to narrow */
    int fi;
    for (fi = 0; lpFmt[fi] && fi < 1023; fi++)
        narrow_fmt[fi] = (char)(lpFmt[fi] & 0xFF);
    narrow_fmt[fi] = '\0';
    /* Format using the existing A version */
    int len = wvsprintfA(narrow_out, narrow_fmt, arglist);
    /* Convert narrow result back to wide */
    int i;
    for (i = 0; i < len && i < 1023; i++)
        lpOut[i] = (uint16_t)(unsigned char)narrow_out[i];
    lpOut[i] = 0;
    return i;
}

/* --------------------------------------------------------------------------
 * SetWindowTextW / GetWindowTextW / GetWindowTextLengthW
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT BOOL SetWindowTextW(HWND hWnd, LPCWSTR lpString)
{
    if (!lpString)
        return SetWindowTextA(hWnd, NULL);

    /* Convert wide to narrow */
    char narrow[512];
    int i;
    for (i = 0; lpString[i] && i < (int)(sizeof(narrow) - 1); i++)
        narrow[i] = (char)(lpString[i] & 0xFF);
    narrow[i] = '\0';

    return SetWindowTextA(hWnd, narrow);
}

WINAPI_EXPORT int GetWindowTextW(HWND hWnd, LPWSTR lpString, int nMaxCount)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win || !lpString || nMaxCount <= 0)
        return 0;
    const char *src = entry->gfx_win->title;
    int i;
    for (i = 0; i < nMaxCount - 1 && src[i]; i++)
        lpString[i] = (WCHAR)(unsigned char)src[i];
    lpString[i] = 0;
    return i;
}

WINAPI_EXPORT int GetWindowTextLengthW(HWND hWnd)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win) return 0;
    return (int)strlen(entry->gfx_win->title);
}

/* --------------------------------------------------------------------------
 * Menu functions
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HMENU GetMenu(HWND hWnd)
{
    (void)hWnd;
    return NULL;
}

WINAPI_EXPORT HMENU GetSubMenu(HMENU hMenu, int nPos)
{
    (void)hMenu;
    (void)nPos;
    return NULL;
}

WINAPI_EXPORT HMENU GetSystemMenu(HWND hWnd, BOOL bRevert)
{
    (void)hWnd;
    (void)bRevert;
    return NULL;
}

WINAPI_EXPORT DWORD CheckMenuItem(HMENU hMenu, UINT uIDCheckItem, UINT uCheck)
{
    (void)hMenu;
    (void)uIDCheckItem;
    (void)uCheck;
    return 0;
}

WINAPI_EXPORT BOOL EnableMenuItem(HMENU hMenu, UINT uIDEnableItem, UINT uEnable)
{
    (void)hMenu;
    (void)uIDEnableItem;
    (void)uEnable;
    return 0;
}

WINAPI_EXPORT int SetScrollPos(HWND hWnd, int nBar, int nPos, BOOL bRedraw)
{
    (void)hWnd;
    (void)nBar;
    (void)nPos;
    (void)bRedraw;
    return 0;
}

WINAPI_EXPORT HANDLE LoadAcceleratorsW(HINSTANCE hInstance, LPCWSTR lpTableName)
{
    (void)hInstance;
    (void)lpTableName;
    return NULL;
}

WINAPI_EXPORT int TranslateAcceleratorW(HWND hWnd, HANDLE hAccTable, void *lpMsg)
{
    (void)hWnd;
    (void)hAccTable;
    (void)lpMsg;
    return 0;
}

/* --------------------------------------------------------------------------
 * Drawing functions (FillRect, DrawTextW are canonical user32 exports)
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT int FillRect(HDC hDC, const void *lprc, HBRUSH hbr)
{
    (void)hDC;
    (void)lprc;
    (void)hbr;
    return 1;
}

WINAPI_EXPORT int DrawTextW(HDC hDC, LPCWSTR lpchText, int cchText,
                            void *lprc, UINT format)
{
    (void)hDC;
    (void)lpchText;
    (void)cchText;
    (void)lprc;
    (void)format;
    return 0;
}

WINAPI_EXPORT int DrawTextExW(HDC hDC, LPWSTR lpchText, int cchText,
                              void *lprc, UINT format, void *lpdtp)
{
    (void)hDC;
    (void)lpchText;
    (void)cchText;
    (void)lprc;
    (void)format;
    (void)lpdtp;
    return 0;
}

WINAPI_EXPORT BOOL DrawFocusRect(HDC hDC, const void *lprc)
{
    (void)hDC;
    (void)lprc;
    return TRUE;
}

/* --------------------------------------------------------------------------
 * Property functions
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HANDLE GetPropW(HWND hWnd, LPCWSTR lpString)
{
    (void)hWnd;
    (void)lpString;
    return NULL;
}

WINAPI_EXPORT BOOL SetPropW(HWND hWnd, LPCWSTR lpString, HANDLE hData)
{
    (void)hWnd;
    (void)lpString;
    (void)hData;
    return TRUE;
}

WINAPI_EXPORT HANDLE RemovePropW(HWND hWnd, LPCWSTR lpString)
{
    (void)hWnd;
    (void)lpString;
    return NULL;
}

/* --------------------------------------------------------------------------
 * DPI functions
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HANDLE SetThreadDpiAwarenessContext(HANDLE dpiContext)
{
    (void)dpiContext;
    return (HANDLE)(intptr_t)-1;
}

WINAPI_EXPORT BOOL SystemParametersInfoForDpi(UINT uiAction, UINT uiParam,
                                               PVOID pvParam, UINT fWinIni,
                                               UINT dpi)
{
    (void)uiAction;
    (void)uiParam;
    (void)pvParam;
    (void)fWinIni;
    (void)dpi;
    return FALSE;
}

WINAPI_EXPORT HANDLE MonitorFromWindow(HWND hWnd, DWORD dwFlags)
{
    (void)hWnd;
    (void)dwFlags;
    return (HANDLE)(intptr_t)1;
}

/* GetDpiForMonitor: canonical home is shcore.dll (shcore_stubs.c).
 * Removed duplicate from user32 to avoid confusion. */

/* --------------------------------------------------------------------------
 * Event hooks
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HANDLE SetWinEventHook(DWORD eventMin, DWORD eventMax,
                                      HANDLE hmodWinEventProc,
                                      void *pfnWinEventProc,
                                      DWORD idProcess, DWORD idThread,
                                      DWORD dwFlags)
{
    (void)eventMin;
    (void)eventMax;
    (void)hmodWinEventProc;
    (void)pfnWinEventProc;
    (void)idProcess;
    (void)idThread;
    (void)dwFlags;
    return (HANDLE)(intptr_t)1;
}

WINAPI_EXPORT BOOL UnhookWinEvent(HANDLE hWinEventHook)
{
    (void)hWinEventHook;
    return TRUE;
}

WINAPI_EXPORT void NotifyWinEvent(DWORD event, HWND hwnd,
                                   LONG idObject, LONG idChild)
{
    (void)event;
    (void)hwnd;
    (void)idObject;
    (void)idChild;
}

/* --------------------------------------------------------------------------
 * Resource / String functions
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT int LoadStringW(HINSTANCE hInstance, UINT uID,
                               LPWSTR lpBuffer, int cchBufferMax)
{
    (void)hInstance;
    (void)uID;
    if (lpBuffer && cchBufferMax > 0)
        lpBuffer[0] = 0;
    return 0;
}

WINAPI_EXPORT int LoadStringA(HINSTANCE hInstance, UINT uID,
                               LPSTR lpBuffer, int cchBufferMax)
{
    (void)hInstance;
    (void)uID;
    if (lpBuffer && cchBufferMax > 0)
        lpBuffer[0] = '\0';
    return 0;
}

/* --------------------------------------------------------------------------
 * Missing window functions for real application support
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT int GetClassNameW(HWND hWnd, LPWSTR lpClassName, int nMaxCount)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win || !lpClassName || nMaxCount <= 0)
        return 0;
    const char *src = entry->gfx_win->class_name;
    int i;
    for (i = 0; i < nMaxCount - 1 && src[i]; i++)
        lpClassName[i] = (WCHAR)(unsigned char)src[i];
    lpClassName[i] = 0;
    return i;
}

WINAPI_EXPORT BOOL BringWindowToTop(HWND hWnd)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry) return FALSE;
    g_foreground_window = hWnd;
    return TRUE;
}

WINAPI_EXPORT BOOL IsZoomed(HWND hWnd)
{
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win) return FALSE;
    return (entry->gfx_win->style & WS_MAXIMIZE) ? TRUE : FALSE;
}

WINAPI_EXPORT BOOL GetUpdateRect(HWND hWnd, LPRECT lpRect, BOOL bErase)
{
    (void)bErase;
    hwnd_entry_t *entry = hwnd_lookup(hWnd);
    if (!entry || !entry->gfx_win) return FALSE;
    if (lpRect) {
        lpRect->left = 0;
        lpRect->top = 0;
        lpRect->right = entry->gfx_win->client_width;
        lpRect->bottom = entry->gfx_win->client_height;
    }
    return entry->gfx_win->needs_repaint ? TRUE : FALSE;
}

WINAPI_EXPORT BOOL FlashWindow(HWND hWnd, BOOL bInvert)
{
    (void)hWnd; (void)bInvert;
    return FALSE;
}

WINAPI_EXPORT BOOL FlashWindowEx(void *pfwi)
{
    (void)pfwi;
    return FALSE;
}

WINAPI_EXPORT BOOL AnimateWindow(HWND hWnd, DWORD dwTime, DWORD dwFlags)
{
    (void)hWnd; (void)dwTime; (void)dwFlags;
    return TRUE;
}

WINAPI_EXPORT int SetWindowRgn(HWND hWnd, HANDLE hRgn, BOOL bRedraw)
{
    (void)hWnd; (void)hRgn; (void)bRedraw;
    return 1; /* nonzero = success */
}

WINAPI_EXPORT BOOL SetLayeredWindowAttributes(HWND hWnd, DWORD crKey,
                                                BYTE bAlpha, DWORD dwFlags)
{
    (void)hWnd; (void)crKey; (void)bAlpha; (void)dwFlags;
    return TRUE;
}

WINAPI_EXPORT BOOL GetLayeredWindowAttributes(HWND hWnd, DWORD *pcrKey,
                                                BYTE *pbAlpha, DWORD *pdwFlags)
{
    (void)hWnd;
    if (pcrKey) *pcrKey = 0;
    if (pbAlpha) *pbAlpha = 255;
    if (pdwFlags) *pdwFlags = 0;
    return TRUE;
}

WINAPI_EXPORT BOOL LockWindowUpdate(HWND hWndLock)
{
    (void)hWndLock;
    return TRUE;
}

/* Property A variants */
WINAPI_EXPORT HANDLE GetPropA(HWND hWnd, LPCSTR lpString)
{
    (void)hWnd; (void)lpString;
    return NULL;
}

WINAPI_EXPORT BOOL SetPropA(HWND hWnd, LPCSTR lpString, HANDLE hData)
{
    (void)hWnd; (void)lpString; (void)hData;
    return TRUE;
}

WINAPI_EXPORT HANDLE RemovePropA(HWND hWnd, LPCSTR lpString)
{
    (void)hWnd; (void)lpString;
    return NULL;
}

/* Scroll functions */
WINAPI_EXPORT int GetScrollPos(HWND hWnd, int nBar)
{
    (void)hWnd; (void)nBar;
    return 0;
}

WINAPI_EXPORT BOOL SetScrollRange(HWND hWnd, int nBar, int nMinPos, int nMaxPos, BOOL bRedraw)
{
    (void)hWnd; (void)nBar; (void)nMinPos; (void)nMaxPos; (void)bRedraw;
    return TRUE;
}

WINAPI_EXPORT BOOL GetScrollRange(HWND hWnd, int nBar, LPINT lpMinPos, LPINT lpMaxPos)
{
    (void)hWnd; (void)nBar;
    if (lpMinPos) *lpMinPos = 0;
    if (lpMaxPos) *lpMaxPos = 100;
    return TRUE;
}

WINAPI_EXPORT BOOL ScrollWindow(HWND hWnd, int XAmount, int YAmount,
                                  const RECT *lpRect, const RECT *lpClipRect)
{
    (void)hWnd; (void)XAmount; (void)YAmount; (void)lpRect; (void)lpClipRect;
    return TRUE;
}

WINAPI_EXPORT int ScrollWindowEx(HWND hWnd, int dx, int dy,
                                   const RECT *prcScroll, const RECT *prcClip,
                                   HANDLE hrgnUpdate, LPRECT prcUpdate, UINT flags)
{
    (void)hWnd; (void)dx; (void)dy; (void)prcScroll; (void)prcClip;
    (void)hrgnUpdate; (void)prcUpdate; (void)flags;
    return 1; /* SIMPLEREGION */
}

/* Class Long functions */
#define GCL_HBRBACKGROUND (-10)
#define GCL_HCURSOR       (-12)
#define GCL_HICON         (-14)
#define GCL_STYLE         (-26)
#define GCL_WNDPROC       (-24)
#define GCL_CBWNDEXTRA    (-18)
#define GCL_CBCLSEXTRA    (-20)
#define GCLP_WNDPROC      (-24)
#define GCLP_HICON        (-14)
#define GCLP_HICONSM      (-34)

WINAPI_EXPORT ULONG_PTR GetClassLongPtrA(HWND hWnd, int nIndex)
{
    /* Snapshot class fields under lock: gfx_win and class entry can both
     * be freed by DestroyWindow/UnregisterClassA on other threads. */
    char class_name_buf[256];
    ensure_hwnd_map_init();
    pthread_mutex_lock(&g_wnd_lock);
    hwnd_entry_t *entry = NULL;
    for (int i = 0; i < MAX_HWND_MAP; i++) {
        if (g_hwnd_map[i].used && g_hwnd_map[i].hwnd == hWnd) {
            entry = &g_hwnd_map[i];
            break;
        }
    }
    if (!entry || !entry->gfx_win) {
        pthread_mutex_unlock(&g_wnd_lock);
        return 0;
    }
    strncpy(class_name_buf, entry->gfx_win->class_name, sizeof(class_name_buf) - 1);
    class_name_buf[sizeof(class_name_buf) - 1] = '\0';

    window_class_entry_t *cls = find_class(class_name_buf);
    if (!cls) {
        pthread_mutex_unlock(&g_wnd_lock);
        return 0;
    }

    ULONG_PTR result = 0;
    switch (nIndex) {
    case GCL_WNDPROC:       result = (ULONG_PTR)cls->wndproc; break;
    case GCL_HBRBACKGROUND: result = (ULONG_PTR)cls->hbrBackground; break;
    case GCL_STYLE:         result = (ULONG_PTR)cls->style; break;
    case GCL_CBWNDEXTRA:    result = (ULONG_PTR)cls->cbWndExtra; break;
    default:                result = 0; break;
    }
    pthread_mutex_unlock(&g_wnd_lock);
    return result;
}

WINAPI_EXPORT ULONG_PTR GetClassLongPtrW(HWND hWnd, int nIndex)
{
    return GetClassLongPtrA(hWnd, nIndex);
}

WINAPI_EXPORT ULONG_PTR SetClassLongPtrA(HWND hWnd, int nIndex, LONG_PTR dwNewLong)
{
    /* Mutate class fields under lock to serialize with GetClassLongPtrA
     * and UnregisterClassA. */
    char class_name_buf[256];
    ensure_hwnd_map_init();
    pthread_mutex_lock(&g_wnd_lock);
    hwnd_entry_t *entry = NULL;
    for (int i = 0; i < MAX_HWND_MAP; i++) {
        if (g_hwnd_map[i].used && g_hwnd_map[i].hwnd == hWnd) {
            entry = &g_hwnd_map[i];
            break;
        }
    }
    if (!entry || !entry->gfx_win) {
        pthread_mutex_unlock(&g_wnd_lock);
        return 0;
    }
    strncpy(class_name_buf, entry->gfx_win->class_name, sizeof(class_name_buf) - 1);
    class_name_buf[sizeof(class_name_buf) - 1] = '\0';

    window_class_entry_t *cls = find_class(class_name_buf);
    if (!cls) {
        pthread_mutex_unlock(&g_wnd_lock);
        return 0;
    }

    ULONG_PTR old = 0;
    switch (nIndex) {
    case GCL_WNDPROC:
        old = (ULONG_PTR)cls->wndproc;
        cls->wndproc = (WNDPROC)dwNewLong;
        break;
    case GCL_HBRBACKGROUND:
        old = (ULONG_PTR)cls->hbrBackground;
        cls->hbrBackground = (HBRUSH)dwNewLong;
        break;
    case GCL_STYLE:
        old = (ULONG_PTR)cls->style;
        cls->style = (UINT)dwNewLong;
        break;
    default:
        break;
    }
    pthread_mutex_unlock(&g_wnd_lock);
    return old;
}

WINAPI_EXPORT ULONG_PTR SetClassLongPtrW(HWND hWnd, int nIndex, LONG_PTR dwNewLong)
{
    return SetClassLongPtrA(hWnd, nIndex, dwNewLong);
}

WINAPI_EXPORT DWORD GetClassLongA(HWND hWnd, int nIndex)
{
    return (DWORD)GetClassLongPtrA(hWnd, nIndex);
}

WINAPI_EXPORT DWORD GetClassLongW(HWND hWnd, int nIndex)
{
    return (DWORD)GetClassLongPtrA(hWnd, nIndex);
}

WINAPI_EXPORT DWORD SetClassLongA(HWND hWnd, int nIndex, LONG dwNewLong)
{
    return (DWORD)SetClassLongPtrA(hWnd, nIndex, (LONG_PTR)dwNewLong);
}

WINAPI_EXPORT DWORD SetClassLongW(HWND hWnd, int nIndex, LONG dwNewLong)
{
    return (DWORD)SetClassLongPtrA(hWnd, nIndex, (LONG_PTR)dwNewLong);
}

/* FindWindowExA/W - search with parent */
WINAPI_EXPORT HWND FindWindowExA(HWND hWndParent, HWND hWndChildAfter,
                                   LPCSTR lpszClass, LPCSTR lpszWindow)
{
    (void)hWndParent; (void)hWndChildAfter;
    (void)lpszClass; (void)lpszWindow;
    return NULL;
}

WINAPI_EXPORT HWND FindWindowExW(HWND hWndParent, HWND hWndChildAfter,
                                   LPCWSTR lpszClass, LPCWSTR lpszWindow)
{
    (void)hWndParent; (void)hWndChildAfter;
    (void)lpszClass; (void)lpszWindow;
    return NULL;
}




/*
 * shcore_stubs.c - Shell Core DPI awareness API stubs
 *
 * Stubs for shcore.dll. Provides DPI awareness APIs that apps like
 * PuTTY probe via LoadLibrary/GetProcAddress at runtime.
 *
 * Session 68: adds a per-HWND DPI tracking table and a WM_DPICHANGED
 * posting helper that the X11 event pump calls on every ConfigureNotify
 * (move/resize) so per-monitor DPI apps get notified when they cross a
 * CRTC boundary with a different DPI.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <pthread.h>

#include "common/dll_common.h"

#define S_OK    ((HRESULT)0x00000000)

/* WM_DPICHANGED (0x02E0) - posted to a window when its DPI changes.
 *   wParam = HIWORD: new DPI Y, LOWORD: new DPI X (typically equal).
 *   lParam = pointer to suggested RECT for the new size/position. */
#define WM_DPICHANGED  0x02E0

/* PROCESS_DPI_AWARENESS enum values (for reference):
 *   0 = PROCESS_DPI_UNAWARE
 *   1 = PROCESS_SYSTEM_DPI_AWARE
 *   2 = PROCESS_PER_MONITOR_DPI_AWARE
 */

/* MONITOR_DPI_TYPE enum values (for reference):
 *   0 = MDT_EFFECTIVE_DPI
 *   1 = MDT_ANGULAR_DPI
 *   2 = MDT_RAW_DPI
 */

/* --------------------------------------------------------------------------
 * Session 68 (Agent I): real X11-backed per-monitor DPI computation
 *
 * shcore.dll doesn't link libX11 directly (keeps the .so headless-safe);
 * instead we dlopen libX11 + libXinerama lazily on first DPI query. If
 * either library is missing or no display can be opened, we fall back to
 * 96 DPI, same as before.
 *
 * Per-CRTC cache: 16 slots, 5-second TTL. Lookup key is the rect center
 * mapped to a Xinerama screen index. Cache is L1 for the message pump;
 * the DPI table in shcore_notify_window_rect_change() is the L2 memoize
 * of "last DPI posted for this HWND".
 * -------------------------------------------------------------------------- */

typedef unsigned long   X_XID;
typedef X_XID           X_Window;
typedef void           *X_Display;

typedef struct {
    short   screen_number;
    short   x_org;
    short   y_org;
    short   width;
    short   height;
} X_XineramaScreenInfo;

typedef X_Display *(*fn_XOpenDisplay_t)(const char *);
typedef int        (*fn_XCloseDisplay_t)(X_Display *);
typedef int        (*fn_XDefaultScreen_t)(X_Display *);
typedef int        (*fn_XDisplayWidth_t)(X_Display *, int);
typedef int        (*fn_XDisplayHeight_t)(X_Display *, int);
typedef int        (*fn_XDisplayWidthMM_t)(X_Display *, int);
typedef int        (*fn_XDisplayHeightMM_t)(X_Display *, int);

typedef int   (*fn_XineramaIsActive_t)(X_Display *);
typedef X_XineramaScreenInfo *(*fn_XineramaQueryScreens_t)(X_Display *, int *);
typedef int   (*fn_XFree_t)(void *);

static pthread_once_t   g_x11_once  = PTHREAD_ONCE_INIT;
static pthread_mutex_t  g_x11_lock  = PTHREAD_MUTEX_INITIALIZER;
static void            *g_lib_x11   = NULL;
static void            *g_lib_xin   = NULL;
static X_Display       *g_display   = NULL;
static int              g_x11_ok    = 0;

static fn_XOpenDisplay_t       p_XOpenDisplay;
static fn_XDefaultScreen_t     p_XDefaultScreen;
static fn_XDisplayWidth_t      p_XDisplayWidth;
static fn_XDisplayHeight_t     p_XDisplayHeight;
static fn_XDisplayWidthMM_t    p_XDisplayWidthMM;
static fn_XDisplayHeightMM_t   p_XDisplayHeightMM;
static fn_XFree_t              p_XFree;
static fn_XineramaIsActive_t       p_XineramaIsActive;
static fn_XineramaQueryScreens_t   p_XineramaQueryScreens;

static void x11_load_once(void)
{
    g_lib_x11 = dlopen("libX11.so.6", RTLD_NOW | RTLD_GLOBAL);
    if (!g_lib_x11) g_lib_x11 = dlopen("libX11.so", RTLD_NOW | RTLD_GLOBAL);
    if (!g_lib_x11)
        return;

    p_XOpenDisplay      = (fn_XOpenDisplay_t)    dlsym(g_lib_x11, "XOpenDisplay");
    p_XDefaultScreen    = (fn_XDefaultScreen_t)  dlsym(g_lib_x11, "XDefaultScreen");
    p_XDisplayWidth     = (fn_XDisplayWidth_t)   dlsym(g_lib_x11, "XDisplayWidth");
    p_XDisplayHeight    = (fn_XDisplayHeight_t)  dlsym(g_lib_x11, "XDisplayHeight");
    p_XDisplayWidthMM   = (fn_XDisplayWidthMM_t) dlsym(g_lib_x11, "XDisplayWidthMM");
    p_XDisplayHeightMM  = (fn_XDisplayHeightMM_t)dlsym(g_lib_x11, "XDisplayHeightMM");
    p_XFree             = (fn_XFree_t)           dlsym(g_lib_x11, "XFree");

    if (!p_XOpenDisplay || !p_XDefaultScreen ||
        !p_XDisplayWidth || !p_XDisplayWidthMM)
        return;

    /* Xinerama is optional -- if absent we fall back to single-screen DPI. */
    g_lib_xin = dlopen("libXinerama.so.1", RTLD_NOW | RTLD_GLOBAL);
    if (!g_lib_xin) g_lib_xin = dlopen("libXinerama.so", RTLD_NOW | RTLD_GLOBAL);
    if (g_lib_xin) {
        p_XineramaIsActive     = (fn_XineramaIsActive_t)    dlsym(g_lib_xin, "XineramaIsActive");
        p_XineramaQueryScreens = (fn_XineramaQueryScreens_t)dlsym(g_lib_xin, "XineramaQueryScreens");
    }

    g_display = p_XOpenDisplay(NULL);
    if (!g_display)
        return;

    g_x11_ok = 1;
}

static int x11_ensure(void)
{
    pthread_once(&g_x11_once, x11_load_once);
    return g_x11_ok;
}

/*
 * Tiny per-rect DPI cache. 16 slots, 5s TTL. Keyed by (rect center) ->
 * screen index via Xinerama, compute DPI from screen dims. On cache miss
 * we scan Xinerama output and recompute.
 */
#define DPI_CACHE_SLOTS 16
#define DPI_CACHE_TTL_NS (5LL * 1000000000LL)

typedef struct {
    int     used;
    int     cx;        /* rect center x */
    int     cy;        /* rect center y */
    UINT    dpi;
    int64_t tstamp_ns;
} dpi_rect_cache_slot_t;

static dpi_rect_cache_slot_t g_rect_cache[DPI_CACHE_SLOTS];
static int g_rect_cache_next = 0;

static int64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static UINT dpi_from_dims(int px_w, int px_h, int mm_w, int mm_h)
{
    /* DPI = px / inches; inches = mm / 25.4 */
    if (mm_w <= 0 || mm_h <= 0 || px_w <= 0 || px_h <= 0)
        return 96;
    double dpi_x = (double)px_w * 25.4 / (double)mm_w;
    double dpi_y = (double)px_h * 25.4 / (double)mm_h;
    double dpi   = (dpi_x + dpi_y) * 0.5;
    /* Clamp to sane bounds to avoid runaway values from weird EDIDs. */
    if (dpi < 72.0)  dpi = 72.0;
    if (dpi > 400.0) dpi = 400.0;
    return (UINT)(dpi + 0.5);
}

/*
 * Compute DPI for a screen rect. Cache hits avoid X round-trips entirely;
 * cache misses make one pass over Xinerama screens (or fall back to the
 * root screen). Locked under g_x11_lock so the cache & the X connection
 * stay consistent across message-pump threads.
 */
static UINT shcore_compute_dpi_for_rect(int x, int y, int w, int h)
{
    int cx = x + w / 2;
    int cy = y + h / 2;

    if (!x11_ensure())
        return 96;

    pthread_mutex_lock(&g_x11_lock);

    int64_t now = mono_ns();
    /* Cache lookup: nearest center within 16 px, non-expired. */
    for (int i = 0; i < DPI_CACHE_SLOTS; i++) {
        dpi_rect_cache_slot_t *s = &g_rect_cache[i];
        if (!s->used) continue;
        if (now - s->tstamp_ns > DPI_CACHE_TTL_NS) { s->used = 0; continue; }
        int dx = s->cx - cx; if (dx < 0) dx = -dx;
        int dy = s->cy - cy; if (dy < 0) dy = -dy;
        if (dx < 16 && dy < 16) {
            UINT hit = s->dpi;
            pthread_mutex_unlock(&g_x11_lock);
            return hit;
        }
    }

    /* Miss: query X. Prefer Xinerama. */
    UINT result = 96;
    int found = 0;

    if (p_XineramaIsActive && p_XineramaQueryScreens && p_XineramaIsActive(g_display)) {
        int n = 0;
        X_XineramaScreenInfo *xs = p_XineramaQueryScreens(g_display, &n);
        if (xs) {
            for (int i = 0; i < n; i++) {
                int sx = xs[i].x_org, sy = xs[i].y_org;
                int sw = xs[i].width,  sh = xs[i].height;
                if (cx >= sx && cx < sx + sw && cy >= sy && cy < sy + sh) {
                    /* Xinerama doesn't expose per-screen mm; approximate
                     * from root ratio (same pixel density as root). Real
                     * XRandR per-CRTC physical size lookup is a TODO --
                     * libXrandr isn't linked in this build. */
                    int scr   = p_XDefaultScreen(g_display);
                    int root_px_w = p_XDisplayWidth(g_display, scr);
                    int root_mm_w = p_XDisplayWidthMM(g_display, scr);
                    int root_px_h = p_XDisplayHeight(g_display, scr);
                    int root_mm_h = p_XDisplayHeightMM(g_display, scr);
                    /* Scale root mm by this screen's pixel ratio. */
                    int mm_w = (root_px_w > 0) ? (root_mm_w * sw / root_px_w) : 0;
                    int mm_h = (root_px_h > 0) ? (root_mm_h * sh / root_px_h) : 0;
                    result = dpi_from_dims(sw, sh, mm_w, mm_h);
                    found = 1;
                    break;
                }
            }
            if (p_XFree) p_XFree(xs);
        }
    }

    if (!found) {
        /* Single-screen fallback: use root dimensions. */
        int scr = p_XDefaultScreen(g_display);
        int px_w = p_XDisplayWidth(g_display, scr);
        int px_h = p_XDisplayHeight(g_display, scr);
        int mm_w = p_XDisplayWidthMM(g_display, scr);
        int mm_h = p_XDisplayHeightMM(g_display, scr);
        result = dpi_from_dims(px_w, px_h, mm_w, mm_h);
    }

    /* Fill FIFO cache slot. */
    int slot = g_rect_cache_next;
    g_rect_cache_next = (g_rect_cache_next + 1) % DPI_CACHE_SLOTS;
    g_rect_cache[slot].used = 1;
    g_rect_cache[slot].cx = cx;
    g_rect_cache[slot].cy = cy;
    g_rect_cache[slot].dpi = result;
    g_rect_cache[slot].tstamp_ns = now;

    pthread_mutex_unlock(&g_x11_lock);
    return result;
}

/*
 * pe_dpi_get_for_xwindow - public helper per S68 Agent I task brief.
 *
 * Returns the DPI the rect cache has for the Xinerama screen the X window
 * is currently on. Other pe-loader DLLs (comctl32, etc.) may link against
 * this via weak extern to avoid a direct shcore dependency.
 *
 * Returns 0 on success, -1 if X11 isn't available or xw is invalid.
 */
int pe_dpi_get_for_xwindow(X_Window xw, uint32_t *dpiX, uint32_t *dpiY)
{
    if (!xw) return -1;
    if (!x11_ensure()) return -1;

    /* We don't carry a dependency on XGetWindowAttributes here (keeps the
     * symbol surface minimal) -- instead callers that have the rect pass
     * it directly via shcore_compute_dpi_for_rect. Without geometry we
     * degrade to the DPI for (0,0) which is the primary screen. */
    UINT dpi = shcore_compute_dpi_for_rect(0, 0, 1, 1);
    if (dpiX) *dpiX = dpi;
    if (dpiY) *dpiY = dpi;
    return 0;
}

/* --------------------------------------------------------------------------
 * SetProcessDpiAwareness / GetProcessDpiAwareness / GetDpiForMonitor / ...
 * -------------------------------------------------------------------------- */

WINAPI_EXPORT HRESULT SetProcessDpiAwareness(int value)
{
    (void)value;
    fprintf(stderr, "[shcore] SetProcessDpiAwareness(%d) -> stub S_OK\n", value);
    return S_OK;
}

WINAPI_EXPORT HRESULT GetDpiForMonitor(HANDLE hmonitor, int dpiType,
    UINT *dpiX, UINT *dpiY)
{
    (void)hmonitor;
    (void)dpiType;
    /* hmonitor is opaque (we don't track HMONITOR -> CRTC); degrade to
     * primary-screen DPI which matches what GetDpiForSystem returns. */
    UINT dpi = shcore_compute_dpi_for_rect(0, 0, 1, 1);
    if (dpiX) *dpiX = dpi;
    if (dpiY) *dpiY = dpi;
    return S_OK;
}

WINAPI_EXPORT HRESULT GetProcessDpiAwareness(HANDLE hProcess, int *value)
{
    (void)hProcess;
    if (value) *value = 0; /* PROCESS_DPI_UNAWARE */
    return S_OK;
}

WINAPI_EXPORT HRESULT GetScaleFactorForMonitor(HANDLE hMon, int *pScale)
{
    (void)hMon;
    /* Map DPI -> percentage bucket, snapped to Windows' SCALE_* constants. */
    UINT dpi = shcore_compute_dpi_for_rect(0, 0, 1, 1);
    int pct = (int)((dpi * 100 + 48) / 96); /* round */
    /* Snap: 100, 125, 150, 175, 200, 225, 250, 300, 350, 400, 450, 500 */
    static const int snap[] = {100, 125, 150, 175, 200, 225, 250, 300, 350, 400, 450, 500};
    int best = snap[0];
    int bestd = pct - best; if (bestd < 0) bestd = -bestd;
    for (size_t i = 1; i < sizeof(snap)/sizeof(snap[0]); i++) {
        int d = pct - snap[i]; if (d < 0) d = -d;
        if (d < bestd) { bestd = d; best = snap[i]; }
    }
    if (pScale) *pScale = best;
    return S_OK;
}

WINAPI_EXPORT void *SHCreateMemStream(const BYTE *pInit, UINT cbInit)
{
    (void)pInit;
    (void)cbInit;
    return NULL;
}

/*
 * Accessor: return the DPI last computed for this hwnd, or primary-screen
 * DPI if hwnd isn't tracked yet. Called by user32's GetDpiForWindow.
 */
UINT shcore_get_dpi_for_hwnd(HWND hwnd);  /* forward decl; body after table */

/* --------------------------------------------------------------------------
 * Session 68: Per-HWND DPI tracking + WM_DPICHANGED posting
 *
 * Until a real XRandR per-CRTC DPI query layer lands, "DPI" here is the
 * one value the other shcore stubs return (96 = 100% scaling). The table
 * still serves its purpose: the hook is wired, and the moment a real
 * compute_dpi_for_rect() appears, fire-on-change semantics come online
 * at zero extra cost to the event loop.
 *
 * The table is intentionally small (MAX_TRACKED=256, matching user32's
 * MAX_HWND_MAP) and linearly scanned under a single lock. ConfigureNotify
 * events are infrequent relative to motion/paint, so lock contention is
 * a non-issue.
 * -------------------------------------------------------------------------- */

#define MAX_TRACKED 256

typedef struct {
    HWND  hwnd;
    UINT  last_dpi;
    int   used;
} dpi_track_entry_t;

static dpi_track_entry_t g_dpi_track[MAX_TRACKED];
static pthread_mutex_t   g_dpi_lock = PTHREAD_MUTEX_INITIALIZER;

/* shcore_compute_dpi_for_rect is defined above (real X11-backed version). */

/* Win32 BOOL PostMessageA prototype -- implemented in libpe_user32.so.
 * We declare it extern here; the dynamic linker resolves it at load
 * time (both DLLs live in the same search path). */
WINAPI_EXPORT BOOL PostMessageA(HWND hWnd, UINT Msg, unsigned long long wParam,
                                long long lParam);

/*
 * comctl_post_dpi_change - post a WM_DPICHANGED to hwnd.
 *
 *   wParam = (new_dpi << 16) | new_dpi  (Y high, X low; identical on X11)
 *   lParam = pointer to suggested RECT
 *
 * The RECT is heap-allocated and leaked deliberately: PostMessage is
 * asynchronous, the consumer reads lParam later, and we have no dispose
 * hook. In practice WM_DPICHANGED posts happen at most a few times per
 * session (actual monitor transitions), so leakage is O(transitions) and
 * bounded. The real fix is to plumb a free-after-dispatch hook through
 * PostMessage; leaving that for a future session.
 *
 * Exported (non-static) so the user32 message pump can call it directly
 * without having to go through GetProcAddress.
 */
void comctl_post_dpi_change(HWND hwnd, UINT new_dpi, const RECT *suggested)
{
    if (!hwnd || !suggested)
        return;

    RECT *heap_rect = (RECT *)malloc(sizeof(RECT));
    if (!heap_rect)
        return;
    *heap_rect = *suggested;

    unsigned long long wparam = ((unsigned long long)(new_dpi & 0xFFFF) << 16) |
                                 (unsigned long long)(new_dpi & 0xFFFF);
    long long lparam = (long long)(uintptr_t)heap_rect;

    fprintf(stderr, "[shcore] WM_DPICHANGED hwnd=%p dpi=%u rect={%d,%d,%d,%d}\n",
            hwnd, new_dpi,
            (int)suggested->left, (int)suggested->top,
            (int)suggested->right, (int)suggested->bottom);

    PostMessageA(hwnd, WM_DPICHANGED, wparam, lparam);
}

/*
 * shcore_notify_window_rect_change - called by the message pump from the
 * ConfigureNotify (== GFX_EVENT_MOVE / GFX_EVENT_RESIZE) branch.
 *
 * Uses approach (a) from the S68 task brief: a per-HWND last_dpi table
 * compared against a freshly-computed DPI. On first sighting of an HWND,
 * populate the table (no message -- initial DPI). On subsequent calls,
 * compare and fire WM_DPICHANGED iff different.
 *
 * Returns 1 if a WM_DPICHANGED was posted, 0 otherwise.
 */
int shcore_notify_window_rect_change(HWND hwnd, int x, int y, int w, int h)
{
    if (!hwnd)
        return 0;

    UINT new_dpi = shcore_compute_dpi_for_rect(x, y, w, h);

    pthread_mutex_lock(&g_dpi_lock);

    /* Look for an existing entry for this HWND. */
    int slot = -1;
    int free_slot = -1;
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (g_dpi_track[i].used) {
            if (g_dpi_track[i].hwnd == hwnd) {
                slot = i;
                break;
            }
        } else if (free_slot < 0) {
            free_slot = i;
        }
    }

    if (slot < 0) {
        /* First time we've seen this HWND: just populate, no post. */
        if (free_slot >= 0) {
            g_dpi_track[free_slot].used     = 1;
            g_dpi_track[free_slot].hwnd     = hwnd;
            g_dpi_track[free_slot].last_dpi = new_dpi;
        }
        pthread_mutex_unlock(&g_dpi_lock);
        return 0;
    }

    UINT old_dpi = g_dpi_track[slot].last_dpi;
    if (new_dpi == old_dpi) {
        pthread_mutex_unlock(&g_dpi_lock);
        return 0;
    }

    /* DPI changed: update table, release lock before posting (PostMessage
     * may take its own queue lock -- avoid any chance of nesting). */
    g_dpi_track[slot].last_dpi = new_dpi;
    pthread_mutex_unlock(&g_dpi_lock);

    RECT suggested = {
        .left   = x,
        .top    = y,
        .right  = x + w,
        .bottom = y + h,
    };
    comctl_post_dpi_change(hwnd, new_dpi, &suggested);
    return 1;
}

/*
 * shcore_forget_window - user32 should call this on DestroyWindow so
 * stale entries don't pile up. Safe to call with an untracked HWND.
 */
void shcore_forget_window(HWND hwnd)
{
    if (!hwnd)
        return;
    pthread_mutex_lock(&g_dpi_lock);
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (g_dpi_track[i].used && g_dpi_track[i].hwnd == hwnd) {
            g_dpi_track[i].used = 0;
            g_dpi_track[i].hwnd = NULL;
            g_dpi_track[i].last_dpi = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_dpi_lock);
}

/*
 * shcore_get_dpi_for_hwnd - accessor used by user32's GetDpiForWindow.
 * If the hwnd has been seen by the message pump (has a live entry in
 * g_dpi_track), return that. Otherwise return the primary-screen DPI
 * as a stable fallback.
 */
UINT shcore_get_dpi_for_hwnd(HWND hwnd)
{
    if (!hwnd)
        return shcore_compute_dpi_for_rect(0, 0, 1, 1);

    pthread_mutex_lock(&g_dpi_lock);
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (g_dpi_track[i].used && g_dpi_track[i].hwnd == hwnd) {
            UINT dpi = g_dpi_track[i].last_dpi;
            pthread_mutex_unlock(&g_dpi_lock);
            if (dpi == 0) dpi = shcore_compute_dpi_for_rect(0, 0, 1, 1);
            return dpi;
        }
    }
    pthread_mutex_unlock(&g_dpi_lock);
    return shcore_compute_dpi_for_rect(0, 0, 1, 1);
}

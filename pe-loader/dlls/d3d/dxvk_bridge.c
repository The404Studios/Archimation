/*
 * dxvk_bridge.c - HWND to X11 Window bridge for DXVK
 *
 * DXVK needs real X11 Window handles for Vulkan swap chain creation.
 * This module provides the bridge between our HWND handles and X11.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>

#include "common/dll_common.h"

/* X11 types */
typedef unsigned long XID;
typedef XID Window;
typedef void *Display;

/* X11 function pointers */
typedef Display *(*XOpenDisplay_fn)(const char *);
typedef int (*XCloseDisplay_fn)(Display *);
typedef Window (*XCreateSimpleWindow_fn)(Display *, Window, int, int, unsigned int,
                                          unsigned int, unsigned int, unsigned long, unsigned long);
typedef int (*XMapWindow_fn)(Display *, Window);
typedef int (*XDestroyWindow_fn)(Display *, Window);
typedef Window (*XDefaultRootWindow_fn)(Display *);
typedef int (*XFlush_fn)(Display *);

static void *g_x11_lib = NULL;
static int g_x11_tried = 0;
static Display *g_display = NULL;

static XOpenDisplay_fn        p_XOpenDisplay;
static XCloseDisplay_fn       p_XCloseDisplay;
static XCreateSimpleWindow_fn p_XCreateSimpleWindow;
static XMapWindow_fn          p_XMapWindow;
static XDestroyWindow_fn      p_XDestroyWindow;
static XDefaultRootWindow_fn  p_XDefaultRootWindow;
static XFlush_fn              p_XFlush;

/* HWND -> X11 Window mapping */
#define MAX_WINDOW_MAP 256

typedef struct {
    void *hwnd;       /* Windows HWND handle */
    Window x11_win;   /* X11 Window ID */
    int width;
    int height;
    int valid;
} window_mapping_t;

static window_mapping_t g_window_map[MAX_WINDOW_MAP];
static pthread_mutex_t g_map_lock = PTHREAD_MUTEX_INITIALIZER;

static int x11_load(void)
{
    if (g_x11_tried) return g_x11_lib ? 0 : -1;
    g_x11_tried = 1;

    g_x11_lib = dlopen("libX11.so.6", RTLD_NOW);
    if (!g_x11_lib) g_x11_lib = dlopen("libX11.so", RTLD_NOW);
    if (!g_x11_lib) {
        fprintf(stderr, "[dxvk_bridge] libX11 not found\n");
        return -1;
    }

    p_XOpenDisplay        = (XOpenDisplay_fn)dlsym(g_x11_lib, "XOpenDisplay");
    p_XCloseDisplay       = (XCloseDisplay_fn)dlsym(g_x11_lib, "XCloseDisplay");
    p_XCreateSimpleWindow = (XCreateSimpleWindow_fn)dlsym(g_x11_lib, "XCreateSimpleWindow");
    p_XMapWindow          = (XMapWindow_fn)dlsym(g_x11_lib, "XMapWindow");
    p_XDestroyWindow      = (XDestroyWindow_fn)dlsym(g_x11_lib, "XDestroyWindow");
    p_XDefaultRootWindow  = (XDefaultRootWindow_fn)dlsym(g_x11_lib, "XDefaultRootWindow");
    p_XFlush              = (XFlush_fn)dlsym(g_x11_lib, "XFlush");

    if (!p_XOpenDisplay || !p_XCreateSimpleWindow) {
        fprintf(stderr, "[dxvk_bridge] libX11 missing required functions\n");
        dlclose(g_x11_lib);
        g_x11_lib = NULL;
        return -1;
    }

    return 0;
}

static Display *get_display(void)
{
    if (!g_display) {
        if (x11_load() < 0) return NULL;
        g_display = p_XOpenDisplay(NULL);
        if (!g_display)
            fprintf(stderr, "[dxvk_bridge] Cannot open X11 display\n");
    }
    return g_display;
}

/*
 * dxvk_bridge_init - Set up environment for DXVK
 */
void dxvk_bridge_init(void)
{
    /* Set VK_ICD_FILENAMES if not already set */
    if (!getenv("VK_ICD_FILENAMES")) {
        /* Let Vulkan loader find ICDs automatically */
    }

    /* Ensure DISPLAY is set */
    if (!getenv("DISPLAY")) {
        setenv("DISPLAY", ":0", 0);
    }

    /* Tell DXVK to use X11 */
    setenv("DXVK_WSI", "x11", 0);

    fprintf(stderr, "[dxvk_bridge] Initialized (DISPLAY=%s)\n",
            getenv("DISPLAY") ? getenv("DISPLAY") : "unset");
}

/*
 * dxvk_register_window - Associate an HWND with an X11 Window
 */
void dxvk_register_window(void *hwnd, unsigned long x11_window, int width, int height)
{
    pthread_mutex_lock(&g_map_lock);
    for (int i = 0; i < MAX_WINDOW_MAP; i++) {
        if (!g_window_map[i].valid) {
            g_window_map[i].hwnd = hwnd;
            g_window_map[i].x11_win = (Window)x11_window;
            g_window_map[i].width = width;
            g_window_map[i].height = height;
            g_window_map[i].valid = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_map_lock);
}

/*
 * dxvk_unregister_window - Remove an HWND mapping
 */
void dxvk_unregister_window(void *hwnd)
{
    pthread_mutex_lock(&g_map_lock);
    for (int i = 0; i < MAX_WINDOW_MAP; i++) {
        if (g_window_map[i].valid && g_window_map[i].hwnd == hwnd) {
            g_window_map[i].valid = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_map_lock);
}

/*
 * Get the X11 Window from user32's window management.
 * This is defined in user32_window.c and exported from libpe_user32.so.
 */
extern unsigned long hwnd_get_x11_window(void *hwnd) __attribute__((weak));

/*
 * dxvk_get_x11_window - Get the X11 Window for an HWND
 */
unsigned long dxvk_get_x11_window(void *hwnd)
{
    /* First, check our explicit mapping table */
    pthread_mutex_lock(&g_map_lock);
    for (int i = 0; i < MAX_WINDOW_MAP; i++) {
        if (g_window_map[i].valid && g_window_map[i].hwnd == hwnd) {
            unsigned long win = (unsigned long)g_window_map[i].x11_win;
            pthread_mutex_unlock(&g_map_lock);
            return win;
        }
    }
    pthread_mutex_unlock(&g_map_lock);

    /* Try to get the real X11 window from user32's gfx backend */
    if (hwnd_get_x11_window) {
        unsigned long x11_win = hwnd_get_x11_window(hwnd);
        if (x11_win) {
            dxvk_register_window(hwnd, x11_win, 0, 0);
            fprintf(stderr, "[dxvk_bridge] Got X11 window %lu from user32 for HWND %p\n",
                    x11_win, hwnd);
            return x11_win;
        }
    }

    /* Last resort: create a temporary X11 window */
    Display *dpy = get_display();
    if (!dpy) return 0;

    Window root = p_XDefaultRootWindow(dpy);
    Window win = p_XCreateSimpleWindow(dpy, root, 0, 0, 800, 600, 0, 0, 0);
    if (win) {
        p_XMapWindow(dpy, win);
        p_XFlush(dpy);
        dxvk_register_window(hwnd, (unsigned long)win, 800, 600);
        fprintf(stderr, "[dxvk_bridge] Created fallback X11 window %lu for HWND %p\n",
                (unsigned long)win, hwnd);
    }
    return (unsigned long)win;
}

/*
 * dxvk_get_window_size - Get the size of a mapped window
 */
int dxvk_get_window_size(void *hwnd, int *width, int *height)
{
    pthread_mutex_lock(&g_map_lock);
    for (int i = 0; i < MAX_WINDOW_MAP; i++) {
        if (g_window_map[i].valid && g_window_map[i].hwnd == hwnd) {
            if (width) *width = g_window_map[i].width;
            if (height) *height = g_window_map[i].height;
            pthread_mutex_unlock(&g_map_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_map_lock);
    if (width) *width = 800;
    if (height) *height = 600;
    return -1;
}

/*
 * dxvk_bridge_shutdown - Clean up X11 resources
 *
 * Destroys all fallback X11 windows created by dxvk_get_x11_window(),
 * closes the X11 display connection, and dlcloses libX11.
 * Called at process exit to prevent resource leaks.
 */
__attribute__((destructor))
void dxvk_bridge_shutdown(void)
{
    pthread_mutex_lock(&g_map_lock);
    if (g_display && p_XDestroyWindow) {
        for (int i = 0; i < MAX_WINDOW_MAP; i++) {
            if (g_window_map[i].valid && g_window_map[i].x11_win) {
                p_XDestroyWindow(g_display, g_window_map[i].x11_win);
                g_window_map[i].valid = 0;
            }
        }
    }
    pthread_mutex_unlock(&g_map_lock);

    if (g_display && p_XCloseDisplay) {
        p_XCloseDisplay(g_display);
        g_display = NULL;
    }

    if (g_x11_lib) {
        dlclose(g_x11_lib);
        g_x11_lib = NULL;
        g_x11_tried = 0;
    }
}

/*
 * gfx_wayland.c - Wayland backend stub for the graphics subsystem
 *
 * Auto-detects Wayland availability by checking the WAYLAND_DISPLAY
 * environment variable and attempting to connect via dlopen/dlsym.
 * No Wayland headers are needed - all function calls go through dlsym.
 *
 * This backend implements the gfx_backend_t interface defined in
 * gfx_backend.h, providing window management, drawing, and event
 * processing stubs that can be filled in as Wayland support matures.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "gfx_backend.h"

/* --------------------------------------------------------------------------
 * Wayland function types (loaded via dlsym)
 *
 * We define only the function signatures we need, avoiding any dependency
 * on wayland-client.h or other Wayland development headers.
 * -------------------------------------------------------------------------- */

/* Opaque Wayland types (we only use pointers) */
typedef void wl_display;
typedef void wl_registry;
typedef void wl_compositor;
typedef void wl_surface;
typedef void wl_shell;
typedef void wl_shell_surface;
typedef void wl_shm;
typedef void wl_shm_pool;
typedef void wl_buffer;
typedef void wl_callback;

/* Function pointer types for Wayland client library */
typedef wl_display *(*fn_wl_display_connect)(const char *name);
typedef void        (*fn_wl_display_disconnect)(wl_display *display);
typedef int         (*fn_wl_display_dispatch)(wl_display *display);
typedef int         (*fn_wl_display_dispatch_pending)(wl_display *display);
typedef int         (*fn_wl_display_roundtrip)(wl_display *display);
typedef int         (*fn_wl_display_flush)(wl_display *display);
typedef int         (*fn_wl_display_get_fd)(wl_display *display);
typedef wl_registry *(*fn_wl_display_get_registry)(wl_display *display);
typedef void        (*fn_wl_proxy_destroy)(void *proxy);

/* --------------------------------------------------------------------------
 * Wayland backend private data
 * -------------------------------------------------------------------------- */

typedef struct {
    /* Library handle */
    void *lib_handle;

    /* Wayland connection */
    wl_display      *display;
    wl_registry     *registry;
    wl_compositor   *compositor;
    wl_shell        *shell;
    wl_shm          *shm;

    /* Function pointers */
    fn_wl_display_connect           wl_display_connect;
    fn_wl_display_disconnect        wl_display_disconnect;
    fn_wl_display_dispatch          wl_display_dispatch;
    fn_wl_display_dispatch_pending  wl_display_dispatch_pending;
    fn_wl_display_roundtrip         wl_display_roundtrip;
    fn_wl_display_flush             wl_display_flush;
    fn_wl_display_get_fd            wl_display_get_fd;
    fn_wl_display_get_registry      wl_display_get_registry;
    fn_wl_proxy_destroy             wl_proxy_destroy;

    int initialized;
} wayland_backend_data_t;

/* --------------------------------------------------------------------------
 * Per-window Wayland data
 * -------------------------------------------------------------------------- */

typedef struct {
    wl_surface          *surface;
    wl_shell_surface    *shell_surface;
    wl_buffer           *buffer;

    /* Shared memory framebuffer */
    uint32_t            *framebuffer;
    int                  fb_width;
    int                  fb_height;
    int                  fb_fd;     /* Shared memory file descriptor */
} wayland_window_data_t;

/* --------------------------------------------------------------------------
 * Per-DC Wayland data
 * -------------------------------------------------------------------------- */

typedef struct {
    wayland_window_data_t *win_data;
} wayland_dc_data_t;

/* --------------------------------------------------------------------------
 * Library loading
 * -------------------------------------------------------------------------- */

static int wayland_load_functions(wayland_backend_data_t *wl)
{
    const char *libs[] = {
        "libwayland-client.so",
        "libwayland-client.so.0",
        NULL
    };

    for (int i = 0; libs[i]; i++) {
        wl->lib_handle = dlopen(libs[i], RTLD_LAZY);
        if (wl->lib_handle)
            break;
    }

    if (!wl->lib_handle) {
        fprintf(stderr, "gfx_wayland: Cannot load libwayland-client.so: %s\n",
                dlerror());
        return -1;
    }

    /* Load required function pointers */
    wl->wl_display_connect = (fn_wl_display_connect)
        dlsym(wl->lib_handle, "wl_display_connect");
    wl->wl_display_disconnect = (fn_wl_display_disconnect)
        dlsym(wl->lib_handle, "wl_display_disconnect");
    wl->wl_display_dispatch = (fn_wl_display_dispatch)
        dlsym(wl->lib_handle, "wl_display_dispatch");
    wl->wl_display_dispatch_pending = (fn_wl_display_dispatch_pending)
        dlsym(wl->lib_handle, "wl_display_dispatch_pending");
    wl->wl_display_roundtrip = (fn_wl_display_roundtrip)
        dlsym(wl->lib_handle, "wl_display_roundtrip");
    wl->wl_display_flush = (fn_wl_display_flush)
        dlsym(wl->lib_handle, "wl_display_flush");
    wl->wl_display_get_fd = (fn_wl_display_get_fd)
        dlsym(wl->lib_handle, "wl_display_get_fd");
    wl->wl_display_get_registry = (fn_wl_display_get_registry)
        dlsym(wl->lib_handle, "wl_display_get_registry");
    wl->wl_proxy_destroy = (fn_wl_proxy_destroy)
        dlsym(wl->lib_handle, "wl_proxy_destroy");

    if (!wl->wl_display_connect || !wl->wl_display_disconnect) {
        fprintf(stderr, "gfx_wayland: Missing required Wayland symbols\n");
        dlclose(wl->lib_handle);
        wl->lib_handle = NULL;
        return -1;
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * gfx_wayland_available - check if Wayland compositor is reachable
 * -------------------------------------------------------------------------- */

int gfx_wayland_available(void)
{
    return (getenv("WAYLAND_DISPLAY") != NULL) ? 1 : 0;
}

/* --------------------------------------------------------------------------
 * Backend interface: init / cleanup
 * -------------------------------------------------------------------------- */

static int wayland_init(gfx_backend_t *self)
{
    wayland_backend_data_t *wl = calloc(1, sizeof(wayland_backend_data_t));
    if (!wl)
        return -1;

    /* Load Wayland client library */
    if (wayland_load_functions(wl) < 0) {
        free(wl);
        return -1;
    }

    /* Connect to Wayland display */
    wl->display = wl->wl_display_connect(NULL);
    if (!wl->display) {
        fprintf(stderr, "gfx_wayland: Cannot connect to Wayland display\n");
        dlclose(wl->lib_handle);
        free(wl);
        return -1;
    }

    /*
     * Full implementation would:
     * 1. Get the registry
     * 2. Bind to wl_compositor, wl_shell/xdg_wm_base, wl_shm
     * 3. Create shared memory pools for framebuffers
     *
     * For now, we just confirm connectivity.
     */

    wl->initialized = 1;
    self->private_data = wl;

    fprintf(stderr, "gfx_wayland: Connected to Wayland display\n");
    return 0;
}

static void wayland_cleanup(gfx_backend_t *self)
{
    wayland_backend_data_t *wl = self->private_data;
    if (!wl)
        return;

    if (wl->display && wl->wl_display_disconnect)
        wl->wl_display_disconnect(wl->display);

    if (wl->lib_handle)
        dlclose(wl->lib_handle);

    wl->initialized = 0;
    free(wl);
    self->private_data = NULL;
}

/* --------------------------------------------------------------------------
 * Backend interface: window management
 * -------------------------------------------------------------------------- */

static int wayland_create_window(gfx_backend_t *self, gfx_window_t *win)
{
    wayland_backend_data_t *wl = self->private_data;
    if (!wl || !wl->initialized)
        return -1;

    wayland_window_data_t *wd = calloc(1, sizeof(wayland_window_data_t));
    if (!wd)
        return -1;

    wd->fb_width = (win->width > 0) ? win->width : 640;
    wd->fb_height = (win->height > 0) ? win->height : 480;
    wd->fb_fd = -1;

    /*
     * Full implementation would:
     * 1. wl_compositor_create_surface()
     * 2. xdg_wm_base_get_xdg_surface() or wl_shell_get_shell_surface()
     * 3. Create shared memory buffer for the framebuffer
     * 4. Attach buffer to surface and commit
     */

    fprintf(stderr, "gfx_wayland: create_window(%ux%u) - stub\n",
            wd->fb_width, wd->fb_height);

    win->backend_data = wd;
    return 0;
}

static void wayland_destroy_window(gfx_backend_t *self, gfx_window_t *win)
{
    wayland_backend_data_t *wl = self->private_data;
    (void)wl;

    wayland_window_data_t *wd = win->backend_data;
    if (!wd)
        return;

    if (wd->framebuffer) {
        free(wd->framebuffer);
        wd->framebuffer = NULL;
    }

    /* Full implementation would destroy wl_surface, shell_surface, buffer */

    free(wd);
    win->backend_data = NULL;
}

static void wayland_show_window(gfx_backend_t *self, gfx_window_t *win, int show)
{
    wayland_backend_data_t *wl = self->private_data;
    (void)wl;

    /*
     * Wayland surfaces are shown by attaching a buffer and committing.
     * Hiding is done by attaching a NULL buffer.
     */
    win->visible = show;

    fprintf(stderr, "gfx_wayland: show_window(%s) - stub\n",
            show ? "show" : "hide");
}

static void wayland_move_window(gfx_backend_t *self, gfx_window_t *win, int x, int y)
{
    (void)self;

    /*
     * Wayland does not allow clients to position their own top-level windows.
     * The compositor controls window placement. We just update our internal
     * tracking state.
     */
    win->x = x;
    win->y = y;
}

static void wayland_resize_window(gfx_backend_t *self, gfx_window_t *win, int w, int h)
{
    wayland_backend_data_t *wl = self->private_data;
    (void)wl;

    if (w < 1) w = 1;
    if (h < 1) h = 1;

    wayland_window_data_t *wd = win->backend_data;
    if (wd) {
        /* Reallocate framebuffer if size changed */
        if (w != wd->fb_width || h != wd->fb_height) {
            wd->fb_width = w;
            wd->fb_height = h;

            if (wd->framebuffer) {
                free(wd->framebuffer);
                wd->framebuffer = NULL;
            }

            /* Full implementation would create new wl_shm buffer */
        }
    }

    win->width = w;
    win->height = h;
    win->client_width = w;
    win->client_height = h;
}

static void wayland_set_title(gfx_backend_t *self, gfx_window_t *win, const char *title)
{
    (void)self;

    /* Full implementation: xdg_toplevel_set_title() */
    strncpy(win->title, title, sizeof(win->title) - 1);
    win->title[sizeof(win->title) - 1] = '\0';
}

/* --------------------------------------------------------------------------
 * Backend interface: device contexts
 * -------------------------------------------------------------------------- */

static gfx_dc_t *wayland_get_dc(gfx_backend_t *self, gfx_window_t *win)
{
    (void)self;

    gfx_dc_t *dc = gfx_alloc_dc();
    if (!dc)
        return NULL;

    wayland_dc_data_t *dd = calloc(1, sizeof(wayland_dc_data_t));
    if (!dd) {
        gfx_free_dc(dc);
        return NULL;
    }

    dc->window = win;
    dc->text_color = GFX_RGB(0, 0, 0);
    dc->bg_color = GFX_RGB(255, 255, 255);
    dc->bg_mode = 2;  /* OPAQUE */
    dc->is_memory_dc = 0;

    if (win && win->backend_data) {
        dd->win_data = (wayland_window_data_t *)win->backend_data;
    }

    dc->backend_data = dd;
    return dc;
}

static void wayland_release_dc(gfx_backend_t *self, gfx_window_t *win, gfx_dc_t *dc)
{
    (void)self;
    (void)win;

    if (!dc)
        return;

    wayland_dc_data_t *dd = dc->backend_data;
    if (dd)
        free(dd);

    gfx_free_dc(dc);
}

/* --------------------------------------------------------------------------
 * Backend interface: drawing operations
 * -------------------------------------------------------------------------- */

static void wayland_paint_rect(gfx_backend_t *self, gfx_dc_t *dc,
                                int x, int y, int w, int h,
                                gfx_color_t color)
{
    (void)self;

    if (!dc || !dc->backend_data)
        return;

    wayland_dc_data_t *dd = dc->backend_data;
    wayland_window_data_t *wd = dd->win_data;

    if (!wd || !wd->framebuffer)
        return;

    /* Convert COLORREF (0x00BBGGRR) to ARGB (0xAARRGGBB) for Wayland shm */
    uint32_t r = GFX_GetRValue(color);
    uint32_t g = GFX_GetGValue(color);
    uint32_t b = GFX_GetBValue(color);
    uint32_t pixel = 0xFF000000 | (r << 16) | (g << 8) | b;

    /* Clamp to framebuffer bounds */
    int x0 = (x < 0) ? 0 : x;
    int y0 = (y < 0) ? 0 : y;
    int x1 = (x + w > wd->fb_width) ? wd->fb_width : x + w;
    int y1 = (y + h > wd->fb_height) ? wd->fb_height : y + h;

    for (int row = y0; row < y1; row++) {
        for (int col = x0; col < x1; col++) {
            wd->framebuffer[row * wd->fb_width + col] = pixel;
        }
    }

    /*
     * Full implementation would:
     * 1. Mark the damaged region: wl_surface_damage()
     * 2. Commit the surface: wl_surface_commit()
     */
}

static void wayland_draw_text(gfx_backend_t *self, gfx_dc_t *dc,
                               int x, int y, const char *text, int len)
{
    (void)self;
    (void)dc;
    (void)x;
    (void)y;
    (void)text;
    (void)len;

    /* Text rendering requires a font rasterizer (FreeType/fontconfig).
     * This is a stub that does nothing. */
}

static void wayland_blit_bitmap(gfx_backend_t *self, gfx_dc_t *dst,
                                 int dst_x, int dst_y, int w, int h,
                                 gfx_dc_t *src, int src_x, int src_y,
                                 uint32_t rop)
{
    (void)self;
    (void)dst;
    (void)dst_x;
    (void)dst_y;
    (void)w;
    (void)h;
    (void)src;
    (void)src_x;
    (void)src_y;
    (void)rop;

    /* Stub - full implementation would copy between framebuffers */
}

/* --------------------------------------------------------------------------
 * Backend interface: event processing
 * -------------------------------------------------------------------------- */

static int wayland_process_events(gfx_backend_t *self, gfx_event_t *event,
                                   int blocking)
{
    wayland_backend_data_t *wl = self->private_data;

    if (!wl || !wl->initialized || !wl->display)
        return 0;

    memset(event, 0, sizeof(*event));
    event->type = GFX_EVENT_NONE;

    /*
     * Full implementation would:
     * 1. wl_display_dispatch() or wl_display_dispatch_pending()
     * 2. Process Wayland events (keyboard, pointer, touch)
     * 3. Translate to gfx_event_t
     *
     * For now, just flush and dispatch pending events.
     */
    if (wl->wl_display_flush)
        wl->wl_display_flush(wl->display);

    if (blocking) {
        if (wl->wl_display_dispatch)
            wl->wl_display_dispatch(wl->display);
    } else {
        if (wl->wl_display_dispatch_pending)
            wl->wl_display_dispatch_pending(wl->display);
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * Backend interface: screen info
 * -------------------------------------------------------------------------- */

static gfx_screen_size_t wayland_get_screen_size(gfx_backend_t *self)
{
    wayland_backend_data_t *wl = self->private_data;
    (void)wl;

    /*
     * Wayland reports screen size through the wl_output interface.
     * Full implementation would track wl_output.geometry and wl_output.mode
     * events. For now, return a sensible default.
     */
    gfx_screen_size_t size = { 1920, 1080 };
    return size;
}

/* --------------------------------------------------------------------------
 * Public API: init helper and backend factory
 * -------------------------------------------------------------------------- */

int gfx_wayland_init(void)
{
    /* Quick check: is Wayland compositor reachable? */
    if (!gfx_wayland_available()) {
        fprintf(stderr, "gfx_wayland: WAYLAND_DISPLAY not set\n");
        return -1;
    }

    /* Try to load Wayland client library and connect */
    wayland_backend_data_t test = {0};
    if (wayland_load_functions(&test) < 0)
        return -1;

    wl_display *display = test.wl_display_connect(NULL);
    if (!display) {
        fprintf(stderr, "gfx_wayland: Cannot connect to Wayland display\n");
        dlclose(test.lib_handle);
        return -1;
    }

    /* Success - disconnect test connection */
    test.wl_display_disconnect(display);
    dlclose(test.lib_handle);

    fprintf(stderr, "gfx_wayland: Wayland display available\n");
    return 0;
}

gfx_backend_t *gfx_wayland_create(void)
{
    gfx_backend_t *backend = calloc(1, sizeof(gfx_backend_t));
    if (!backend)
        return NULL;

    backend->name           = "wayland";
    backend->init           = wayland_init;
    backend->cleanup        = wayland_cleanup;
    backend->create_window  = wayland_create_window;
    backend->destroy_window = wayland_destroy_window;
    backend->show_window    = wayland_show_window;
    backend->move_window    = wayland_move_window;
    backend->resize_window  = wayland_resize_window;
    backend->set_title      = wayland_set_title;
    backend->get_dc         = wayland_get_dc;
    backend->release_dc     = wayland_release_dc;
    backend->paint_rect     = wayland_paint_rect;
    backend->draw_text      = wayland_draw_text;
    backend->blit_bitmap    = wayland_blit_bitmap;
    backend->process_events = wayland_process_events;
    backend->get_screen_size = wayland_get_screen_size;
    backend->private_data   = NULL;

    return backend;
}

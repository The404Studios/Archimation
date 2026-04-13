/*
 * gfx_x11.c - X11 backend implementation
 *
 * Implements the gfx_backend_t interface using Xlib, allowing Win32 GUI
 * applications to render windows, handle input, and draw via X11.
 *
 * X11 events are translated to the abstract gfx_event_t format, which
 * the user32 message layer then maps to Windows WM_* messages.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <X11/Xatom.h>
#endif

#include "gfx_backend.h"

/* --------------------------------------------------------------------------
 * X11-specific private data
 * -------------------------------------------------------------------------- */

#ifdef __linux__

typedef struct {
    Display    *display;
    int         screen;
    Window      root;
    Atom        wm_delete_window;   /* WM_DELETE_WINDOW protocol atom */
    Atom        wm_protocols;       /* WM_PROTOCOLS atom */
    GC          default_gc;
    int         initialized;
} x11_backend_data_t;

typedef struct {
    Window      xwindow;
    GC          gc;
    Pixmap      backbuffer;         /* Double-buffer pixmap */
    int         backbuffer_w;
    int         backbuffer_h;
} x11_window_data_t;

typedef struct {
    GC          gc;
    Pixmap      pixmap;             /* For memory DCs */
    int         pixmap_w;
    int         pixmap_h;
} x11_dc_data_t;

/* --------------------------------------------------------------------------
 * X11 keysym to VK code mapping
 * -------------------------------------------------------------------------- */

/* Virtual key codes (matching Windows VK_* values) */
#define VK_BACK     0x08
#define VK_TAB      0x09
#define VK_RETURN   0x0D
#define VK_SHIFT    0x10
#define VK_CONTROL  0x11
#define VK_MENU     0x12    /* Alt */
#define VK_PAUSE    0x13
#define VK_CAPITAL  0x14
#define VK_ESCAPE   0x1B
#define VK_SPACE    0x20
#define VK_PRIOR    0x21    /* Page Up */
#define VK_NEXT     0x22    /* Page Down */
#define VK_END      0x23
#define VK_HOME     0x24
#define VK_LEFT     0x25
#define VK_UP       0x26
#define VK_RIGHT    0x27
#define VK_DOWN     0x28
#define VK_INSERT   0x2D
#define VK_DELETE   0x2E
#define VK_F1       0x70
#define VK_F2       0x71
#define VK_F3       0x72
#define VK_F4       0x73
#define VK_F5       0x74
#define VK_F6       0x75
#define VK_F7       0x76
#define VK_F8       0x77
#define VK_F9       0x78
#define VK_F10      0x79
#define VK_F11      0x7A
#define VK_F12      0x7B
#define VK_LSHIFT   0xA0
#define VK_RSHIFT   0xA1
#define VK_LCONTROL 0xA2
#define VK_RCONTROL 0xA3
#define VK_LMENU    0xA4
#define VK_RMENU    0xA5

static uint32_t x11_keysym_to_vk(KeySym ks)
{
    /* Letters A-Z map directly to 0x41-0x5A */
    if (ks >= XK_a && ks <= XK_z)
        return 0x41 + (ks - XK_a);
    if (ks >= XK_A && ks <= XK_Z)
        return 0x41 + (ks - XK_A);

    /* Digits 0-9 map to 0x30-0x39 */
    if (ks >= XK_0 && ks <= XK_9)
        return 0x30 + (ks - XK_0);

    /* Function keys */
    if (ks >= XK_F1 && ks <= XK_F12)
        return VK_F1 + (ks - XK_F1);

    switch (ks) {
    case XK_BackSpace:      return VK_BACK;
    case XK_Tab:            return VK_TAB;
    case XK_Return:         return VK_RETURN;
    case XK_Escape:         return VK_ESCAPE;
    case XK_space:          return VK_SPACE;
    case XK_Delete:         return VK_DELETE;
    case XK_Insert:         return VK_INSERT;
    case XK_Home:           return VK_HOME;
    case XK_End:            return VK_END;
    case XK_Page_Up:        return VK_PRIOR;
    case XK_Page_Down:      return VK_NEXT;
    case XK_Left:           return VK_LEFT;
    case XK_Up:             return VK_UP;
    case XK_Right:          return VK_RIGHT;
    case XK_Down:           return VK_DOWN;
    case XK_Shift_L:        return VK_LSHIFT;
    case XK_Shift_R:        return VK_RSHIFT;
    case XK_Control_L:      return VK_LCONTROL;
    case XK_Control_R:      return VK_RCONTROL;
    case XK_Alt_L:          return VK_LMENU;
    case XK_Alt_R:          return VK_RMENU;
    case XK_Caps_Lock:      return VK_CAPITAL;
    case XK_Pause:          return VK_PAUSE;
    default:                return 0;
    }
}

/*
 * Get modifier state from X11 event state field
 */
static uint32_t x11_modifiers(unsigned int state)
{
    uint32_t mods = 0;
    if (state & ShiftMask)   mods |= 0x01;
    if (state & ControlMask) mods |= 0x02;
    if (state & Mod1Mask)    mods |= 0x04;  /* Alt */
    return mods;
}

/* --------------------------------------------------------------------------
 * X11 window lookup
 * -------------------------------------------------------------------------- */

/* We maintain a simple mapping from X11 Window IDs to gfx_window_t */
#define MAX_X11_WINDOWS GFX_MAX_WINDOWS

static struct {
    Window          xwin;
    gfx_window_t   *gfx_win;
} x11_window_map[MAX_X11_WINDOWS];
static int x11_window_count = 0;

static void x11_register_window(Window xwin, gfx_window_t *gfx_win)
{
    if (x11_window_count < MAX_X11_WINDOWS) {
        x11_window_map[x11_window_count].xwin = xwin;
        x11_window_map[x11_window_count].gfx_win = gfx_win;
        x11_window_count++;
    }
}

static void x11_unregister_window(Window xwin)
{
    for (int i = 0; i < x11_window_count; i++) {
        if (x11_window_map[i].xwin == xwin) {
            x11_window_map[i] = x11_window_map[x11_window_count - 1];
            x11_window_count--;
            return;
        }
    }
}

static gfx_window_t *x11_find_window(Window xwin)
{
    for (int i = 0; i < x11_window_count; i++) {
        if (x11_window_map[i].xwin == xwin)
            return x11_window_map[i].gfx_win;
    }
    return NULL;
}

/* --------------------------------------------------------------------------
 * Backend interface implementations
 * -------------------------------------------------------------------------- */

static int x11_init(gfx_backend_t *self)
{
    x11_backend_data_t *x11 = calloc(1, sizeof(x11_backend_data_t));
    if (!x11)
        return -1;

    x11->display = XOpenDisplay(NULL);
    if (!x11->display) {
        fprintf(stderr, "gfx_x11: Cannot open X display\n");
        free(x11);
        return -1;
    }

    x11->screen = DefaultScreen(x11->display);
    x11->root = RootWindow(x11->display, x11->screen);
    x11->wm_delete_window = XInternAtom(x11->display, "WM_DELETE_WINDOW", False);
    x11->wm_protocols = XInternAtom(x11->display, "WM_PROTOCOLS", False);
    x11->default_gc = DefaultGC(x11->display, x11->screen);
    x11->initialized = 1;

    self->private_data = x11;
    x11_window_count = 0;

    fprintf(stderr, "gfx_x11: Initialized on display %s, screen %d\n",
            DisplayString(x11->display), x11->screen);
    return 0;
}

static void x11_cleanup(gfx_backend_t *self)
{
    x11_backend_data_t *x11 = self->private_data;
    if (!x11)
        return;

    if (x11->display) {
        XCloseDisplay(x11->display);
        x11->display = NULL;
    }
    x11->initialized = 0;
    free(x11);
    self->private_data = NULL;
}

static int x11_create_window(gfx_backend_t *self, gfx_window_t *win)
{
    x11_backend_data_t *x11 = self->private_data;
    if (!x11 || !x11->display)
        return -1;

    x11_window_data_t *wd = calloc(1, sizeof(x11_window_data_t));
    if (!wd)
        return -1;

    /* Determine parent X window */
    Window parent_xwin = x11->root;
    if (win->parent && win->parent->backend_data) {
        x11_window_data_t *pwd = win->parent->backend_data;
        parent_xwin = pwd->xwindow;
    }

    /* Background color */
    unsigned long bg_pixel = WhitePixel(x11->display, x11->screen);

    /* Create the X11 window */
    wd->xwindow = XCreateSimpleWindow(
        x11->display,
        parent_xwin,
        win->x, win->y,
        (win->width > 0) ? win->width : 640,
        (win->height > 0) ? win->height : 480,
        1,  /* border width */
        BlackPixel(x11->display, x11->screen),  /* border */
        bg_pixel                                  /* background */
    );

    if (!wd->xwindow) {
        free(wd);
        return -1;
    }

    /* Create a graphics context for this window */
    wd->gc = XCreateGC(x11->display, wd->xwindow, 0, NULL);
    if (!wd->gc) {
        /* GC creation failed — clean up and return error */
        XDestroyWindow(x11->display, wd->xwindow);
        free(wd);
        return -1;
    }

    /* Subscribe to events */
    XSelectInput(x11->display, wd->xwindow,
                 ExposureMask | KeyPressMask | KeyReleaseMask |
                 ButtonPressMask | ButtonReleaseMask | PointerMotionMask |
                 StructureNotifyMask | FocusChangeMask);

    /* Register for WM_DELETE_WINDOW so close button works */
    XSetWMProtocols(x11->display, wd->xwindow, &x11->wm_delete_window, 1);

    /* Set window title */
    if (win->title[0]) {
        XStoreName(x11->display, wd->xwindow, win->title);
    }

    /* Set size hints */
    XSizeHints hints;
    memset(&hints, 0, sizeof(hints));
    hints.flags = PPosition | PSize;
    hints.x = win->x;
    hints.y = win->y;
    hints.width = win->width;
    hints.height = win->height;
    XSetWMNormalHints(x11->display, wd->xwindow, &hints);

    win->backend_data = wd;

    /* Register in our lookup table */
    x11_register_window(wd->xwindow, win);

    XFlush(x11->display);
    return 0;
}

static void x11_destroy_window(gfx_backend_t *self, gfx_window_t *win)
{
    x11_backend_data_t *x11 = self->private_data;
    x11_window_data_t *wd = win->backend_data;

    if (!x11 || !x11->display || !wd)
        return;

    x11_unregister_window(wd->xwindow);

    if (wd->backbuffer)
        XFreePixmap(x11->display, wd->backbuffer);
    if (wd->gc)
        XFreeGC(x11->display, wd->gc);
    XDestroyWindow(x11->display, wd->xwindow);
    XFlush(x11->display);

    free(wd);
    win->backend_data = NULL;
}

static void x11_show_window(gfx_backend_t *self, gfx_window_t *win, int show)
{
    x11_backend_data_t *x11 = self->private_data;
    x11_window_data_t *wd = win->backend_data;

    if (!x11 || !x11->display || !wd)
        return;

    if (show) {
        XMapWindow(x11->display, wd->xwindow);
        XRaiseWindow(x11->display, wd->xwindow);
        win->visible = 1;
    } else {
        XUnmapWindow(x11->display, wd->xwindow);
        win->visible = 0;
    }
    XFlush(x11->display);
}

static void x11_move_window(gfx_backend_t *self, gfx_window_t *win, int x, int y)
{
    x11_backend_data_t *x11 = self->private_data;
    x11_window_data_t *wd = win->backend_data;

    if (!x11 || !x11->display || !wd)
        return;

    XMoveWindow(x11->display, wd->xwindow, x, y);
    win->x = x;
    win->y = y;
    XFlush(x11->display);
}

static void x11_resize_window(gfx_backend_t *self, gfx_window_t *win, int w, int h)
{
    x11_backend_data_t *x11 = self->private_data;
    x11_window_data_t *wd = win->backend_data;

    if (!x11 || !x11->display || !wd)
        return;

    if (w < 1) w = 1;
    if (h < 1) h = 1;

    XResizeWindow(x11->display, wd->xwindow, w, h);
    win->width = w;
    win->height = h;
    win->client_width = w;
    win->client_height = h;
    XFlush(x11->display);
}

static void x11_set_title(gfx_backend_t *self, gfx_window_t *win, const char *title)
{
    x11_backend_data_t *x11 = self->private_data;
    x11_window_data_t *wd = win->backend_data;

    if (!x11 || !x11->display || !wd)
        return;

    XStoreName(x11->display, wd->xwindow, title);
    strncpy(win->title, title, sizeof(win->title) - 1);
    win->title[sizeof(win->title) - 1] = '\0';
    XFlush(x11->display);
}

static gfx_dc_t *x11_get_dc(gfx_backend_t *self, gfx_window_t *win)
{
    x11_backend_data_t *x11 = self->private_data;

    if (!x11 || !x11->display)
        return NULL;

    gfx_dc_t *dc = gfx_alloc_dc();
    if (!dc)
        return NULL;

    x11_dc_data_t *dd = calloc(1, sizeof(x11_dc_data_t));
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
        x11_window_data_t *wd = win->backend_data;
        dd->gc = XCreateGC(x11->display, wd->xwindow, 0, NULL);
    } else {
        dd->gc = XCreateGC(x11->display, x11->root, 0, NULL);
    }
    if (!dd->gc) {
        free(dd);
        return NULL;
    }

    dc->backend_data = dd;
    return dc;
}

static void x11_release_dc(gfx_backend_t *self, gfx_window_t *win, gfx_dc_t *dc)
{
    x11_backend_data_t *x11 = self->private_data;
    (void)win;

    if (!x11 || !x11->display || !dc)
        return;

    x11_dc_data_t *dd = dc->backend_data;
    if (dd) {
        if (dd->gc)
            XFreeGC(x11->display, dd->gc);
        if (dd->pixmap)
            XFreePixmap(x11->display, dd->pixmap);
        free(dd);
    }

    gfx_free_dc(dc);
}

static void x11_paint_rect(gfx_backend_t *self, gfx_dc_t *dc,
                            int x, int y, int w, int h, gfx_color_t color)
{
    x11_backend_data_t *x11 = self->private_data;

    if (!x11 || !x11->display || !dc || !dc->backend_data)
        return;

    x11_dc_data_t *dd = dc->backend_data;

    /* Convert COLORREF (0x00BBGGRR) to X11 pixel (0x00RRGGBB) */
    unsigned long pixel =
        ((unsigned long)GFX_GetRValue(color) << 16) |
        ((unsigned long)GFX_GetGValue(color) << 8) |
        ((unsigned long)GFX_GetBValue(color));

    XSetForeground(x11->display, dd->gc, pixel);

    if (dc->window && dc->window->backend_data) {
        x11_window_data_t *wd = dc->window->backend_data;
        XFillRectangle(x11->display, wd->xwindow, dd->gc, x, y, w, h);
    } else if (dd->pixmap) {
        XFillRectangle(x11->display, dd->pixmap, dd->gc, x, y, w, h);
    }

    XFlush(x11->display);
}

static void x11_draw_text(gfx_backend_t *self, gfx_dc_t *dc,
                           int x, int y, const char *text, int len)
{
    x11_backend_data_t *x11 = self->private_data;

    if (!x11 || !x11->display || !dc || !dc->backend_data || !text)
        return;

    x11_dc_data_t *dd = dc->backend_data;

    /* Set text foreground color */
    unsigned long fg_pixel =
        ((unsigned long)GFX_GetRValue(dc->text_color) << 16) |
        ((unsigned long)GFX_GetGValue(dc->text_color) << 8) |
        ((unsigned long)GFX_GetBValue(dc->text_color));
    XSetForeground(x11->display, dd->gc, fg_pixel);

    /* Draw background if opaque mode */
    if (dc->bg_mode == 2) {  /* OPAQUE */
        unsigned long bg_pixel =
            ((unsigned long)GFX_GetRValue(dc->bg_color) << 16) |
            ((unsigned long)GFX_GetGValue(dc->bg_color) << 8) |
            ((unsigned long)GFX_GetBValue(dc->bg_color));
        XSetBackground(x11->display, dd->gc, bg_pixel);
    }

    if (len < 0)
        len = strlen(text);

    Drawable drawable = 0;
    if (dc->window && dc->window->backend_data) {
        x11_window_data_t *wd = dc->window->backend_data;
        drawable = wd->xwindow;
    } else if (dd->pixmap) {
        drawable = dd->pixmap;
    }

    if (drawable) {
        XDrawString(x11->display, drawable, dd->gc, x, y, text, len);
    }

    XFlush(x11->display);
}

static void x11_blit_bitmap(gfx_backend_t *self, gfx_dc_t *dst,
                             int dst_x, int dst_y, int w, int h,
                             gfx_dc_t *src, int src_x, int src_y,
                             uint32_t rop)
{
    x11_backend_data_t *x11 = self->private_data;
    (void)rop;

    if (!x11 || !x11->display || !dst || !src)
        return;

    x11_dc_data_t *src_dd = src->backend_data;
    x11_dc_data_t *dst_dd = dst->backend_data;

    if (!src_dd || !dst_dd)
        return;

    /* Determine source and destination drawables */
    Drawable src_drawable = 0;
    Drawable dst_drawable = 0;

    if (src->window && src->window->backend_data) {
        x11_window_data_t *wd = src->window->backend_data;
        src_drawable = wd->xwindow;
    } else if (src_dd->pixmap) {
        src_drawable = src_dd->pixmap;
    }

    if (dst->window && dst->window->backend_data) {
        x11_window_data_t *wd = dst->window->backend_data;
        dst_drawable = wd->xwindow;
    } else if (dst_dd->pixmap) {
        dst_drawable = dst_dd->pixmap;
    }

    if (src_drawable && dst_drawable) {
        XCopyArea(x11->display, src_drawable, dst_drawable, dst_dd->gc,
                  src_x, src_y, w, h, dst_x, dst_y);
        XFlush(x11->display);
    }
}

static int x11_process_events(gfx_backend_t *self, gfx_event_t *event, int blocking)
{
    x11_backend_data_t *x11 = self->private_data;

    if (!x11 || !x11->display)
        return 0;

    memset(event, 0, sizeof(*event));
    event->type = GFX_EVENT_NONE;

    /* Check if events are pending */
    if (!blocking && !XPending(x11->display))
        return 0;

    XEvent xev;
    if (blocking) {
        XNextEvent(x11->display, &xev);
    } else {
        if (XPending(x11->display)) {
            XNextEvent(x11->display, &xev);
        } else {
            return 0;
        }
    }

    /* Find the associated gfx_window_t */
    gfx_window_t *win = NULL;
    switch (xev.type) {
    case Expose:
    case KeyPress:
    case KeyRelease:
    case ButtonPress:
    case ButtonRelease:
    case MotionNotify:
    case ConfigureNotify:
    case FocusIn:
    case FocusOut:
        win = x11_find_window(xev.xany.window);
        break;
    case ClientMessage:
        win = x11_find_window(xev.xclient.window);
        break;
    case DestroyNotify:
        win = x11_find_window(xev.xdestroywindow.window);
        break;
    default:
        return 0;
    }

    event->window = win;

    switch (xev.type) {
    case Expose:
        if (xev.xexpose.count == 0) {
            event->type = GFX_EVENT_PAINT;
            if (win) {
                event->x = 0;
                event->y = 0;
                event->width = win->width;
                event->height = win->height;
            }
        }
        break;

    case KeyPress: {
        KeySym ks;
        char buf[32];
        int len = XLookupString(&xev.xkey, buf, sizeof(buf), &ks, NULL);

        event->type = GFX_EVENT_KEY_DOWN;
        event->keycode = x11_keysym_to_vk(ks);
        event->scancode = xev.xkey.keycode;
        event->modifiers = x11_modifiers(xev.xkey.state);

        /* If this produced a printable character, also report it */
        if (len > 0 && buf[0] >= 0x20) {
            event->character = (uint32_t)(unsigned char)buf[0];
        }
        break;
    }

    case KeyRelease: {
        KeySym ks;
        XLookupString(&xev.xkey, NULL, 0, &ks, NULL);

        event->type = GFX_EVENT_KEY_UP;
        event->keycode = x11_keysym_to_vk(ks);
        event->scancode = xev.xkey.keycode;
        event->modifiers = x11_modifiers(xev.xkey.state);
        break;
    }

    case ButtonPress:
        switch (xev.xbutton.button) {
        case Button1: event->type = GFX_EVENT_MOUSE_LBUTTON_DOWN; break;
        case Button2: event->type = GFX_EVENT_MOUSE_MBUTTON_DOWN; break;
        case Button3: event->type = GFX_EVENT_MOUSE_RBUTTON_DOWN; break;
        default: return 0;
        }
        event->mouse_x = xev.xbutton.x;
        event->mouse_y = xev.xbutton.y;
        event->mouse_x_screen = xev.xbutton.x_root;
        event->mouse_y_screen = xev.xbutton.y_root;
        event->modifiers = x11_modifiers(xev.xbutton.state);
        break;

    case ButtonRelease:
        switch (xev.xbutton.button) {
        case Button1: event->type = GFX_EVENT_MOUSE_LBUTTON_UP; break;
        case Button2: event->type = GFX_EVENT_MOUSE_MBUTTON_UP; break;
        case Button3: event->type = GFX_EVENT_MOUSE_RBUTTON_UP; break;
        default: return 0;
        }
        event->mouse_x = xev.xbutton.x;
        event->mouse_y = xev.xbutton.y;
        event->mouse_x_screen = xev.xbutton.x_root;
        event->mouse_y_screen = xev.xbutton.y_root;
        event->modifiers = x11_modifiers(xev.xbutton.state);
        break;

    case MotionNotify:
        event->type = GFX_EVENT_MOUSE_MOVE;
        event->mouse_x = xev.xmotion.x;
        event->mouse_y = xev.xmotion.y;
        event->mouse_x_screen = xev.xmotion.x_root;
        event->mouse_y_screen = xev.xmotion.y_root;
        event->modifiers = x11_modifiers(xev.xmotion.state);
        break;

    case ConfigureNotify:
        if (win) {
            int moved = (xev.xconfigure.x != win->x || xev.xconfigure.y != win->y);
            int resized = (xev.xconfigure.width != win->width ||
                          xev.xconfigure.height != win->height);

            win->x = xev.xconfigure.x;
            win->y = xev.xconfigure.y;
            win->width = xev.xconfigure.width;
            win->height = xev.xconfigure.height;
            win->client_width = win->width;
            win->client_height = win->height;

            if (resized) {
                event->type = GFX_EVENT_RESIZE;
                event->width = win->width;
                event->height = win->height;
            } else if (moved) {
                event->type = GFX_EVENT_MOVE;
                event->x = win->x;
                event->y = win->y;
            }
        }
        break;

    case FocusIn:
        event->type = GFX_EVENT_FOCUS_IN;
        break;

    case FocusOut:
        event->type = GFX_EVENT_FOCUS_OUT;
        break;

    case DestroyNotify:
        event->type = GFX_EVENT_DESTROY;
        break;

    case ClientMessage:
        if ((Atom)xev.xclient.data.l[0] == x11->wm_delete_window) {
            event->type = GFX_EVENT_CLOSE;
        }
        break;

    default:
        return 0;
    }

    return (event->type != GFX_EVENT_NONE) ? 1 : 0;
}

static gfx_screen_size_t x11_get_screen_size(gfx_backend_t *self)
{
    x11_backend_data_t *x11 = self->private_data;
    gfx_screen_size_t size = { 1920, 1080 };  /* Fallback defaults */

    if (x11 && x11->display) {
        size.width = DisplayWidth(x11->display, x11->screen);
        size.height = DisplayHeight(x11->display, x11->screen);
    }

    return size;
}

/* --------------------------------------------------------------------------
 * Backend factory
 * -------------------------------------------------------------------------- */

gfx_backend_t *gfx_x11_create(void)
{
    gfx_backend_t *backend = calloc(1, sizeof(gfx_backend_t));
    if (!backend)
        return NULL;

    backend->name           = "x11";
    backend->init           = x11_init;
    backend->cleanup        = x11_cleanup;
    backend->create_window  = x11_create_window;
    backend->destroy_window = x11_destroy_window;
    backend->show_window    = x11_show_window;
    backend->move_window    = x11_move_window;
    backend->resize_window  = x11_resize_window;
    backend->set_title      = x11_set_title;
    backend->get_dc         = x11_get_dc;
    backend->release_dc     = x11_release_dc;
    backend->paint_rect     = x11_paint_rect;
    backend->draw_text      = x11_draw_text;
    backend->blit_bitmap    = x11_blit_bitmap;
    backend->process_events = x11_process_events;
    backend->get_screen_size = x11_get_screen_size;
    backend->private_data   = NULL;

    return backend;
}

#else /* !__linux__ */

/* Stub for non-Linux builds */
gfx_backend_t *gfx_x11_create(void)
{
    fprintf(stderr, "gfx_x11: X11 backend not available on this platform\n");
    return NULL;
}

#endif /* __linux__ */

/* --------------------------------------------------------------------------
 * Global graphics subsystem state
 * -------------------------------------------------------------------------- */

static gfx_backend_t *g_backend = NULL;
static gfx_window_t   g_windows[GFX_MAX_WINDOWS];
static int             g_window_used[GFX_MAX_WINDOWS];
static uint32_t        g_next_window_id = 1;

int gfx_init(void)
{
    if (g_backend)
        return 0;  /* Already initialized */

    memset(g_windows, 0, sizeof(g_windows));
    memset(g_window_used, 0, sizeof(g_window_used));

    /* Try X11 backend */
    g_backend = gfx_x11_create();
    if (g_backend) {
        if (g_backend->init(g_backend) == 0) {
            fprintf(stderr, "gfx: Initialized %s backend\n", g_backend->name);
            return 0;
        }
        free(g_backend);
        g_backend = NULL;
    }

    fprintf(stderr, "gfx: No graphics backend available\n");
    return -1;
}

void gfx_cleanup(void)
{
    if (g_backend) {
        /* Destroy all windows */
        for (int i = 0; i < GFX_MAX_WINDOWS; i++) {
            if (g_window_used[i] && g_windows[i].backend_data) {
                g_backend->destroy_window(g_backend, &g_windows[i]);
            }
            g_window_used[i] = 0;
        }

        g_backend->cleanup(g_backend);
        free(g_backend);
        g_backend = NULL;
    }
}

gfx_backend_t *gfx_get_backend(void)
{
    return g_backend;
}

gfx_window_t *gfx_alloc_window(void)
{
    for (int i = 0; i < GFX_MAX_WINDOWS; i++) {
        if (!g_window_used[i]) {
            g_window_used[i] = 1;
            memset(&g_windows[i], 0, sizeof(gfx_window_t));
            g_windows[i].id = g_next_window_id++;
            g_windows[i].bg_color = GFX_RGB(255, 255, 255);
            return &g_windows[i];
        }
    }
    return NULL;
}

void gfx_free_window(gfx_window_t *win)
{
    if (!win)
        return;
    for (int i = 0; i < GFX_MAX_WINDOWS; i++) {
        if (&g_windows[i] == win) {
            g_window_used[i] = 0;
            memset(&g_windows[i], 0, sizeof(gfx_window_t));
            return;
        }
    }
}

gfx_window_t *gfx_find_window_by_id(uint32_t id)
{
    for (int i = 0; i < GFX_MAX_WINDOWS; i++) {
        if (g_window_used[i] && g_windows[i].id == id)
            return &g_windows[i];
    }
    return NULL;
}

/* DC pool */
#define GFX_MAX_DCS 256
static gfx_dc_t g_dcs[GFX_MAX_DCS];
static int g_dc_used[GFX_MAX_DCS];

gfx_dc_t *gfx_alloc_dc(void)
{
    for (int i = 0; i < GFX_MAX_DCS; i++) {
        if (!g_dc_used[i]) {
            g_dc_used[i] = 1;
            memset(&g_dcs[i], 0, sizeof(gfx_dc_t));
            return &g_dcs[i];
        }
    }
    return NULL;
}

void gfx_free_dc(gfx_dc_t *dc)
{
    if (!dc)
        return;
    for (int i = 0; i < GFX_MAX_DCS; i++) {
        if (&g_dcs[i] == dc) {
            g_dc_used[i] = 0;
            memset(&g_dcs[i], 0, sizeof(gfx_dc_t));
            return;
        }
    }
}

/*
 * Get the native X11 Window ID for a gfx_window_t.
 * Returns the X11 Window or 0 if not an X11 window.
 * This is used by the DXVK bridge for swap chain creation.
 */
unsigned long gfx_get_native_window(gfx_window_t *win)
{
#ifdef __linux__
    if (!win || !win->backend_data)
        return 0;
    x11_window_data_t *wd = (x11_window_data_t *)win->backend_data;
    return (unsigned long)wd->xwindow;
#else
    (void)win;
    return 0;
#endif
}

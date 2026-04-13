/*
 * gfx_backend.h - Abstract graphics backend interface
 *
 * Provides a backend-agnostic interface for window management, drawing,
 * and event processing. The X11 backend implements this interface to allow
 * Win32 GUI applications to render on Linux.
 */

#ifndef GFX_BACKEND_H
#define GFX_BACKEND_H

#include <stdint.h>
#include <stddef.h>

/* Forward declarations */
typedef struct gfx_backend  gfx_backend_t;
typedef struct gfx_window   gfx_window_t;
typedef struct gfx_dc       gfx_dc_t;
typedef struct gfx_event    gfx_event_t;

/*
 * Graphics event types (mapped from backend-native events)
 */
typedef enum {
    GFX_EVENT_NONE = 0,
    GFX_EVENT_PAINT,
    GFX_EVENT_KEY_DOWN,
    GFX_EVENT_KEY_UP,
    GFX_EVENT_CHAR,
    GFX_EVENT_MOUSE_MOVE,
    GFX_EVENT_MOUSE_LBUTTON_DOWN,
    GFX_EVENT_MOUSE_LBUTTON_UP,
    GFX_EVENT_MOUSE_RBUTTON_DOWN,
    GFX_EVENT_MOUSE_RBUTTON_UP,
    GFX_EVENT_MOUSE_MBUTTON_DOWN,
    GFX_EVENT_MOUSE_MBUTTON_UP,
    GFX_EVENT_RESIZE,
    GFX_EVENT_MOVE,
    GFX_EVENT_CLOSE,
    GFX_EVENT_DESTROY,
    GFX_EVENT_FOCUS_IN,
    GFX_EVENT_FOCUS_OUT,
    GFX_EVENT_TIMER,
} gfx_event_type_t;

/*
 * Graphics event structure
 */
struct gfx_event {
    gfx_event_type_t    type;
    gfx_window_t       *window;
    uint32_t            keycode;        /* Virtual key code */
    uint32_t            scancode;       /* Hardware scan code */
    uint32_t            character;      /* Translated character (for CHAR events) */
    int                 mouse_x;        /* Mouse X in window coords */
    int                 mouse_y;        /* Mouse Y in window coords */
    int                 mouse_x_screen; /* Mouse X in screen coords */
    int                 mouse_y_screen; /* Mouse Y in screen coords */
    int                 width;          /* New width (for RESIZE) */
    int                 height;         /* New height (for RESIZE) */
    int                 x;              /* New x (for MOVE) */
    int                 y;              /* New y (for MOVE) */
    uint32_t            modifiers;      /* Modifier key state */
    uint32_t            timer_id;       /* Timer ID (for TIMER events) */
};

/*
 * Color (COLORREF-compatible: 0x00BBGGRR)
 */
typedef uint32_t gfx_color_t;

#define GFX_RGB(r, g, b)    ((gfx_color_t)(((uint8_t)(r)) | ((uint16_t)((uint8_t)(g)) << 8) | ((uint32_t)((uint8_t)(b)) << 16)))
#define GFX_GetRValue(c)    ((uint8_t)(c))
#define GFX_GetGValue(c)    ((uint8_t)((c) >> 8))
#define GFX_GetBValue(c)    ((uint8_t)((c) >> 16))

/*
 * Window structure - represents a single GUI window
 */
struct gfx_window {
    uint32_t            id;             /* Unique window identifier */
    int                 x;              /* Window X position */
    int                 y;              /* Window Y position */
    int                 width;          /* Window width */
    int                 height;         /* Window height */
    char                title[256];     /* Window title */
    int                 visible;        /* Is window visible? */
    gfx_window_t       *parent;         /* Parent window (NULL for top-level) */
    void               *backend_data;   /* Backend-specific data (X11 Window, etc.) */

    /* Window class info */
    char                class_name[256];
    void               *wndproc;        /* Window procedure (WNDPROC) */
    uint32_t            style;          /* Window style (WS_*) */
    uint32_t            ex_style;       /* Extended window style (WS_EX_*) */

    /* Client area */
    int                 client_x;
    int                 client_y;
    int                 client_width;
    int                 client_height;

    /* Drawing state */
    gfx_color_t         bg_color;       /* Background color */
    int                 needs_repaint;  /* Dirty flag */

    /* User data */
    void               *userdata;
};

/*
 * Device context structure
 */
struct gfx_dc {
    gfx_window_t       *window;         /* Associated window (NULL for memory DCs) */
    void               *backend_data;   /* Backend-specific GC/context */

    /* Current drawing state */
    gfx_color_t         text_color;
    gfx_color_t         bg_color;
    int                 bg_mode;        /* TRANSPARENT=1, OPAQUE=2 */
    int                 text_align;

    /* Selected objects */
    void               *current_brush;
    void               *current_pen;
    void               *current_font;
    void               *current_bitmap;

    /* Memory DC bitmap data */
    uint8_t            *bitmap_data;
    int                 bitmap_width;
    int                 bitmap_height;
    int                 bitmap_bpp;

    int                 is_memory_dc;   /* 1 if this is a CreateCompatibleDC */
};

/*
 * Screen size
 */
typedef struct {
    int width;
    int height;
} gfx_screen_size_t;

/*
 * Graphics backend interface - function pointers for backend operations
 */
struct gfx_backend {
    const char *name;   /* Backend name (e.g., "x11") */

    /* Lifecycle */
    int  (*init)(gfx_backend_t *self);
    void (*cleanup)(gfx_backend_t *self);

    /* Window management */
    int  (*create_window)(gfx_backend_t *self, gfx_window_t *win);
    void (*destroy_window)(gfx_backend_t *self, gfx_window_t *win);
    void (*show_window)(gfx_backend_t *self, gfx_window_t *win, int show);
    void (*move_window)(gfx_backend_t *self, gfx_window_t *win, int x, int y);
    void (*resize_window)(gfx_backend_t *self, gfx_window_t *win, int w, int h);
    void (*set_title)(gfx_backend_t *self, gfx_window_t *win, const char *title);

    /* Device contexts */
    gfx_dc_t *(*get_dc)(gfx_backend_t *self, gfx_window_t *win);
    void      (*release_dc)(gfx_backend_t *self, gfx_window_t *win, gfx_dc_t *dc);

    /* Drawing operations */
    void (*paint_rect)(gfx_backend_t *self, gfx_dc_t *dc,
                       int x, int y, int w, int h, gfx_color_t color);
    void (*draw_text)(gfx_backend_t *self, gfx_dc_t *dc,
                      int x, int y, const char *text, int len);
    void (*blit_bitmap)(gfx_backend_t *self, gfx_dc_t *dst,
                        int dst_x, int dst_y, int w, int h,
                        gfx_dc_t *src, int src_x, int src_y, uint32_t rop);

    /* Event processing */
    int  (*process_events)(gfx_backend_t *self, gfx_event_t *event, int blocking);

    /* Screen info */
    gfx_screen_size_t (*get_screen_size)(gfx_backend_t *self);

    /* Backend-private data */
    void *private_data;
};

/*
 * Maximum number of windows
 */
#define GFX_MAX_WINDOWS 256

/*
 * Global API
 */

/* Initialize the graphics subsystem (selects and starts a backend) */
int gfx_init(void);

/* Clean up the graphics subsystem */
void gfx_cleanup(void);

/* Get the active backend */
gfx_backend_t *gfx_get_backend(void);

/* Window management helpers */
gfx_window_t *gfx_alloc_window(void);
void gfx_free_window(gfx_window_t *win);
gfx_window_t *gfx_find_window_by_id(uint32_t id);

/* DC management helpers */
gfx_dc_t *gfx_alloc_dc(void);
void gfx_free_dc(gfx_dc_t *dc);

/*
 * Backend registration
 */
typedef gfx_backend_t *(*gfx_backend_create_fn)(void);

/* Register a backend factory (called at library load time) */
void gfx_register_backend(const char *name, gfx_backend_create_fn factory);

/* X11 backend factory */
gfx_backend_t *gfx_x11_create(void);

/* Get the native X11 Window ID for a gfx window (0 if not X11) */
unsigned long gfx_get_native_window(gfx_window_t *win);

#endif /* GFX_BACKEND_H */

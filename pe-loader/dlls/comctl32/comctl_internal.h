/*
 * comctl_internal.h - Shared declarations for comctl32 widget implementations.
 *
 * Each widget file (comctl32_button.c, comctl32_listview.c, etc.) defines a
 * RegisterClass helper plus an ms_abi WNDPROC.  InitCommonControlsEx in
 * comctl32_controls.c calls the registered helpers based on the dwICC mask.
 *
 * All drawing happens via the public gdi32 API (CreateSolidBrush, FillRect,
 * Rectangle, MoveToEx, LineTo, TextOutA, etc.) and public user32 API
 * (BeginPaint/EndPaint, GetClientRect, DefWindowProcA, InvalidateRect).
 * We never reach into user32/gdi32 internals — those are other agents' turf.
 */

#ifndef COMCTL_INTERNAL_H
#define COMCTL_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include "common/dll_common.h"

/* MSABI marker for WNDPROC compatibility — must match user32's WNDPROC */
#define MSABI __attribute__((ms_abi))

#ifndef _WNDPROC_DEFINED
#define _WNDPROC_DEFINED
typedef LRESULT (MSABI *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
#endif

/* WNDCLASSA mirror — only the fields we use to register a class. */
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
} WNDCLASSA_local;

/* PAINTSTRUCT mirror */
typedef struct tagPAINTSTRUCT_local {
    HDC         hdc;
    BOOL        fErase;
    RECT        rcPaint;
    BOOL        fRestore;
    BOOL        fIncUpdate;
    BYTE        rgbReserved[32];
} PAINTSTRUCT_local;

/* user32 / gdi32 imports we'll dlsym at first use */
typedef WORD  (MSABI *pfn_RegisterClassA)(const WNDCLASSA_local *);
typedef HDC   (MSABI *pfn_BeginPaint)(HWND, PAINTSTRUCT_local *);
typedef BOOL  (MSABI *pfn_EndPaint)(HWND, const PAINTSTRUCT_local *);
typedef BOOL  (MSABI *pfn_GetClientRect)(HWND, LPRECT);
typedef LRESULT (MSABI *pfn_DefWindowProcA)(HWND, UINT, WPARAM, LPARAM);
typedef BOOL  (MSABI *pfn_InvalidateRect)(HWND, const RECT *, BOOL);

typedef HBRUSH  (MSABI *pfn_CreateSolidBrush)(DWORD);
typedef HPEN    (MSABI *pfn_CreatePen)(int, int, DWORD);
typedef HGDIOBJ (MSABI *pfn_SelectObject)(HDC, HGDIOBJ);
typedef BOOL    (MSABI *pfn_DeleteObject)(HGDIOBJ);
typedef int     (MSABI *pfn_FillRect)(HDC, const void *, HBRUSH);
typedef BOOL    (MSABI *pfn_Rectangle)(HDC, int, int, int, int);
typedef BOOL    (MSABI *pfn_MoveToEx)(HDC, int, int, LPPOINT);
typedef BOOL    (MSABI *pfn_LineTo)(HDC, int, int);
typedef BOOL    (MSABI *pfn_TextOutA)(HDC, int, int, LPCSTR, int);
typedef int     (MSABI *pfn_SetBkMode)(HDC, int);
typedef DWORD   (MSABI *pfn_SetTextColor)(HDC, DWORD);

/* Notify-path / parent-discovery / scrolling imports */
typedef LRESULT (MSABI *pfn_SendMessageA)(HWND, UINT, WPARAM, LPARAM);
typedef HWND    (MSABI *pfn_GetParent)(HWND);
typedef int     (MSABI *pfn_GetDlgCtrlID)(HWND);
typedef int     (MSABI *pfn_SetScrollInfo)(HWND, int, const void *, BOOL);
typedef BOOL    (MSABI *pfn_GetScrollInfo)(HWND, int, void *);
typedef LONG    (MSABI *pfn_GetWindowLongA)(HWND, int);
typedef LONG    (MSABI *pfn_SetWindowLongA)(HWND, int, LONG);

/* GradientFill (msimg32 alias also exported from gdi32) */
typedef struct tagTRIVERTEX {
    LONG    x;
    LONG    y;
    USHORT  Red;
    USHORT  Green;
    USHORT  Blue;
    USHORT  Alpha;
} TRIVERTEX;

typedef struct _GRADIENT_RECT {
    ULONG UpperLeft;
    ULONG LowerRight;
} GRADIENT_RECT;

#define GRADIENT_FILL_RECT_H    0x00000000
#define GRADIENT_FILL_RECT_V    0x00000001
#define GRADIENT_FILL_TRIANGLE  0x00000002

typedef BOOL (MSABI *pfn_GradientFill)(HDC, TRIVERTEX *, ULONG, void *, ULONG, ULONG);

typedef struct {
    int resolved;
    pfn_RegisterClassA   RegisterClassA;
    pfn_BeginPaint       BeginPaint;
    pfn_EndPaint         EndPaint;
    pfn_GetClientRect    GetClientRect;
    pfn_DefWindowProcA   DefWindowProcA;
    pfn_InvalidateRect   InvalidateRect;
    pfn_CreateSolidBrush CreateSolidBrush;
    pfn_CreatePen        CreatePen;
    pfn_SelectObject     SelectObject;
    pfn_DeleteObject     DeleteObject;
    pfn_FillRect         FillRect;
    pfn_Rectangle        Rectangle;
    pfn_MoveToEx         MoveToEx;
    pfn_LineTo           LineTo;
    pfn_TextOutA         TextOutA;
    pfn_SetBkMode        SetBkMode;
    pfn_SetTextColor     SetTextColor;
    pfn_SendMessageA     SendMessageA;
    pfn_GetParent        GetParent;
    pfn_GetDlgCtrlID     GetDlgCtrlID;
    pfn_SetScrollInfo    SetScrollInfo;
    pfn_GetScrollInfo    GetScrollInfo;
    pfn_GetWindowLongA   GetWindowLongA;
    pfn_SetWindowLongA   SetWindowLongA;
    pfn_GradientFill     GradientFill;
} comctl_imports_t;

/* SCROLLINFO mirror — only the fields user32's stub will read.  Keeping
 * this local avoids pulling user32 headers into comctl. */
typedef struct tagSCROLLINFO_local {
    UINT cbSize;
    UINT fMask;
    int  nMin;
    int  nMax;
    UINT nPage;
    int  nPos;
    int  nTrackPos;
} SCROLLINFO_local;

#define SIF_RANGE         0x0001
#define SIF_PAGE          0x0002
#define SIF_POS           0x0004
#define SIF_DISABLENOSCROLL 0x0008
#define SIF_TRACKPOS      0x0010
#define SIF_ALL           (SIF_RANGE | SIF_PAGE | SIF_POS | SIF_TRACKPOS)

#define SB_HORZ           0
#define SB_VERT           1

#define SB_LINEUP         0
#define SB_LINELEFT       0
#define SB_LINEDOWN       1
#define SB_LINERIGHT      1
#define SB_PAGEUP         2
#define SB_PAGEDOWN       3
#define SB_THUMBPOSITION  4
#define SB_THUMBTRACK     5
#define SB_TOP            6
#define SB_BOTTOM         7
#define SB_ENDSCROLL      8

/* Returns a pointer to the singleton imports table; resolves on first call. */
const comctl_imports_t *comctl_get_imports(void);

/* Read the Activation Context v6 flag set by pe_resource.c during EXE load. */
int comctl32_v6(void);

/* ------------------------------------------------------------------
 * Per-HWND control state.
 *
 * Each widget keeps its own private state struct allocated in a small
 * fixed-size table keyed by HWND.  Slot count chosen large enough for
 * typical apps (ListView * many columns) but bounded.  Lookup is linear;
 * widget message rates are negligible compared to draw costs.
 * ------------------------------------------------------------------ */

#define COMCTL_MAX_INSTANCES 256

typedef enum {
    COMCTL_KIND_NONE = 0,
    COMCTL_KIND_BUTTON,
    COMCTL_KIND_PROGRESS,
    COMCTL_KIND_LISTVIEW,
    COMCTL_KIND_TREEVIEW,
    COMCTL_KIND_TAB,
    COMCTL_KIND_STATUSBAR,
    COMCTL_KIND_TOOLBAR,
} comctl_kind_t;

/* Generic widget table — each widget allocates its own state pointer and
 * hooks it via comctl_state_set().  This is the only shared global so we
 * don't end up with N separate per-widget tables. */
void *comctl_state_get(HWND hwnd, comctl_kind_t kind);
void  comctl_state_set(HWND hwnd, comctl_kind_t kind, void *state);
void  comctl_state_free(HWND hwnd);

/* Parent-notification helpers (defined in comctl_runtime.c). */
void  comctl_notify_command(HWND hwnd, UINT notify_code);
void  comctl_notify_parent (HWND hwnd, UINT notify_code);

/* Per-widget registration entry points (one per file). */
void register_button_class(void);
void register_progress_class(void);
void register_listview_class(void);
void register_treeview_class(void);
void register_tab_class(void);
void register_statusbar_class(void);
void register_toolbar_class(void);

/* ------------------------------------------------------------------
 * Class name constants.
 * ------------------------------------------------------------------ */
#define WC_BUTTON_A         "Button"
#define WC_LISTVIEW_A       "SysListView32"
#define WC_TREEVIEW_A       "SysTreeView32"
#define WC_TABCONTROL_A     "SysTabControl32"
#define PROGRESS_CLASS_A    "msctls_progress32"
#define STATUSCLASSNAME_A   "msctls_statusbar32"
#define TOOLBARCLASSNAME_A  "ToolbarWindow32"

/* ------------------------------------------------------------------
 * Common control message ranges.
 *
 * Just the ones we actually handle — full Win32 has hundreds.
 * ------------------------------------------------------------------ */

/* Button (BM_*) */
#define BM_GETCHECK         0x00F0
#define BM_SETCHECK         0x00F1
#define BM_GETSTATE         0x00F2
#define BM_SETSTATE         0x00F3
#define BM_SETSTYLE         0x00F4
#define BM_CLICK            0x00F5
#define BM_GETIMAGE         0x00F6
#define BM_SETIMAGE         0x00F7

/* Button styles */
#define BS_PUSHBUTTON       0x00000000L
#define BS_DEFPUSHBUTTON    0x00000001L
#define BS_CHECKBOX         0x00000002L
#define BS_AUTOCHECKBOX     0x00000003L
#define BS_RADIOBUTTON      0x00000004L
#define BS_AUTORADIOBUTTON  0x00000009L
#define BS_GROUPBOX         0x00000007L
#define BS_TYPEMASK         0x0000000FL

/* Progress bar */
#define PBM_SETRANGE        (WM_USER + 1)
#define PBM_SETPOS          (WM_USER + 2)
#define PBM_DELTAPOS        (WM_USER + 3)
#define PBM_SETSTEP         (WM_USER + 4)
#define PBM_STEPIT          (WM_USER + 5)
#define PBM_SETRANGE32      (WM_USER + 6)
#define PBM_GETRANGE        (WM_USER + 7)
#define PBM_GETPOS          (WM_USER + 8)
#define PBM_SETBARCOLOR     (WM_USER + 9)
#define PBM_SETBKCOLOR      0x2001  /* CCM_SETBKCOLOR */

/* WM_USER */
#ifndef WM_USER
#define WM_USER             0x0400
#endif

/* ListView (LVM_*) — uses LVM_FIRST */
#define LVM_FIRST           0x1000
#define LVM_GETITEMCOUNT    (LVM_FIRST + 4)
#define LVM_DELETEITEM      (LVM_FIRST + 8)
#define LVM_DELETEALLITEMS  (LVM_FIRST + 9)
#define LVM_INSERTITEMA     (LVM_FIRST + 7)
#define LVM_SETITEMTEXTA    (LVM_FIRST + 46)
#define LVM_INSERTCOLUMNA   (LVM_FIRST + 27)
#define LVM_GETCOLUMNCOUNT  (LVM_FIRST + 100)
#define LVM_SETBKCOLOR      (LVM_FIRST + 1)
#define LVM_GETBKCOLOR      (LVM_FIRST + 0)

/* ListView styles */
#define LVS_REPORT          0x0001
#define LVS_LIST            0x0003
#define LVS_TYPEMASK        0x0003

/* TreeView (TVM_*) — uses TV_FIRST */
#define TV_FIRST            0x1100
#define TVM_INSERTITEMA     (TV_FIRST + 0)
#define TVM_DELETEITEM      (TV_FIRST + 1)
#define TVM_EXPAND          (TV_FIRST + 2)
#define TVM_GETITEMRECT     (TV_FIRST + 4)
#define TVM_GETCOUNT        (TV_FIRST + 5)
#define TVM_DELETEALLITEMS  (TV_FIRST + 1)  /* TVI_ROOT delete */

/* TreeView expand codes */
#define TVE_COLLAPSE        0x0001
#define TVE_EXPAND          0x0002
#define TVE_TOGGLE          0x0003

/* TabControl (TCM_*) */
#define TCM_FIRST           0x1300
#define TCM_GETIMAGELIST    (TCM_FIRST + 2)
#define TCM_SETIMAGELIST    (TCM_FIRST + 3)
#define TCM_GETITEMCOUNT    (TCM_FIRST + 4)
#define TCM_GETITEMA        (TCM_FIRST + 5)
#define TCM_SETITEMA        (TCM_FIRST + 6)
#define TCM_INSERTITEMA     (TCM_FIRST + 7)
#define TCM_DELETEITEM      (TCM_FIRST + 8)
#define TCM_DELETEALLITEMS  (TCM_FIRST + 9)
#define TCM_GETCURSEL       (TCM_FIRST + 11)
#define TCM_SETCURSEL       (TCM_FIRST + 12)

/* StatusBar (SB_*) */
#define SB_SETTEXTA         0x0401
#define SB_GETTEXTA         0x0402
#define SB_GETTEXTLENGTHA   0x0403
#define SB_SETPARTS         0x0404
#define SB_GETPARTS         0x0406
#define SB_GETBORDERS       0x0407
#define SB_SETMINHEIGHT     0x0408
#define SB_SIMPLE           0x0409

/* ToolBar (TB_*) */
#define TB_ENABLEBUTTON     (WM_USER + 1)
#define TB_BUTTONSTRUCTSIZE (WM_USER + 30)
#define TB_ADDBUTTONSA      (WM_USER + 20)
#define TB_INSERTBUTTONA    (WM_USER + 21)
#define TB_AUTOSIZE         (WM_USER + 33)
#define TB_BUTTONCOUNT      (WM_USER + 24)
#define TB_GETBUTTONSIZE    (WM_USER + 58)

/* InitCommonControlsEx flags */
#define ICC_LISTVIEW_CLASSES   0x00000001
#define ICC_TREEVIEW_CLASSES   0x00000002
#define ICC_BAR_CLASSES        0x00000004
#define ICC_TAB_CLASSES        0x00000008
#define ICC_UPDOWN_CLASS       0x00000010
#define ICC_PROGRESS_CLASS     0x00000020
#define ICC_HOTKEY_CLASS       0x00000040
#define ICC_ANIMATE_CLASS      0x00000080
#define ICC_WIN95_CLASSES      0x000000FF
#define ICC_DATE_CLASSES       0x00000100
#define ICC_USEREX_CLASSES     0x00000200
#define ICC_COOL_CLASSES       0x00000400
#define ICC_INTERNET_CLASSES   0x00000800
#define ICC_PAGESCROLLER_CLASS 0x00001000
#define ICC_NATIVEFNTCTL_CLASS 0x00002000
#define ICC_STANDARD_CLASSES   0x00004000
#define ICC_LINK_CLASS         0x00008000

typedef struct tagINITCOMMONCONTROLSEX {
    DWORD dwSize;
    DWORD dwICC;
} INITCOMMONCONTROLSEX, *LPINITCOMMONCONTROLSEX;

/* WM_* messages we use in widget WndProcs (mirror user32's defines so we
 * don't pull in user32 headers).  Defined locally to keep this file
 * self-contained. */
#ifndef WM_CREATE
#define WM_CREATE       0x0001
#define WM_NCCREATE     0x0081
#define WM_DESTROY      0x0002
#define WM_PAINT        0x000F
#define WM_SETTEXT      0x000C
#define WM_GETTEXT      0x000D
#define WM_GETTEXTLENGTH 0x000E
#define WM_ERASEBKGND   0x0014
#define WM_LBUTTONDOWN  0x0201
#define WM_LBUTTONUP    0x0202
#define WM_SIZE         0x0005
#define WM_NCDESTROY    0x0082
#define WM_COMMAND      0x0111
#define WM_NOTIFY       0x004E
#define WM_HSCROLL      0x0114
#define WM_VSCROLL      0x0115
#define WM_MOUSEWHEEL   0x020A
#endif

#ifndef MAKEWPARAM
#define MAKEWPARAM(lo, hi) ((WPARAM)(((WORD)((lo) & 0xFFFF)) | (((DWORD)((WORD)((hi) & 0xFFFF))) << 16)))
#endif
#ifndef MAKELPARAM
#define MAKELPARAM(lo, hi) ((LPARAM)(((WORD)((lo) & 0xFFFF)) | (((DWORD)((WORD)((hi) & 0xFFFF))) << 16)))
#endif
#ifndef LOWORD
#define LOWORD(l)       ((WORD)((DWORD_PTR)(l) & 0xFFFF))
#define HIWORD(l)       ((WORD)(((DWORD_PTR)(l) >> 16) & 0xFFFF))
#endif

/* WM_COMMAND notification codes */
#define BN_CLICKED      0
#define BN_PUSHED       1
#define BN_UNPUSHED     2

/* WM_NOTIFY header */
typedef struct tagNMHDR {
    HWND     hwndFrom;
    UINT_PTR idFrom;
    UINT     code;
} NMHDR;

/* ListView notification codes (WM_NOTIFY) */
#define NM_FIRST          (0U - 0U)
#define NM_CLICK          ((UINT)(0U - 2U))
#define NM_DBLCLK         ((UINT)(0U - 3U))
#define NM_RCLICK         ((UINT)(0U - 5U))
#define LVN_FIRST         ((UINT)(0U - 100U))
#define LVN_ITEMCHANGED   ((UINT)(LVN_FIRST - 1U))
#define LVN_ITEMACTIVATE  ((UINT)(LVN_FIRST - 14U))

/* TreeView notification codes (WM_NOTIFY) */
#define TVN_FIRST          ((UINT)(0U - 400U))
#define TVN_SELCHANGEDA    ((UINT)(TVN_FIRST - 2U))
#define TVN_ITEMEXPANDEDA  ((UINT)(TVN_FIRST - 6U))

/* TabControl notification codes */
#define TCN_FIRST          ((UINT)(0U - 550U))
#define TCN_SELCHANGE      ((UINT)(TCN_FIRST - 1U))

/* Window styles (subset for scrollbar tracking) */
#ifndef WS_VSCROLL
#define WS_VSCROLL          0x00200000L
#define WS_HSCROLL          0x00100000L
#endif

/* GWLP indices we read via GetWindowLongPtrA (note: GWLP_HWNDPARENT/ID
 * are not currently honored by our user32 stub, so we use GetParent/
 * GetDlgCtrlID instead).  Keep these defines for future parity. */
#ifndef GWLP_HWNDPARENT
#define GWLP_HWNDPARENT (-8)
#define GWLP_ID         (-12)
#endif

/* GWL_* indices we actually read via GetWindowLongA (style bits at
 * create-time are needed so we can set up scrollbar range eagerly). */
#ifndef GWL_STYLE
#define GWL_STYLE       (-16)
#define GWL_EXSTYLE     (-20)
#endif

/* ListView item-state flags (subset — just what the notify path uses). */
#define LVIS_SELECTED       0x0002
#define LVIS_FOCUSED        0x0001
#define LVIF_STATE          0x0008
#define LVIF_PARAM          0x0004

/* NMLISTVIEW — WM_NOTIFY payload for LVN_ITEMCHANGED + click events.
 * Mirrors the on-wire Win32 struct; parent code reads .iItem/.lParam. */
typedef struct tagNMLISTVIEW {
    NMHDR   hdr;
    int     iItem;
    int     iSubItem;
    UINT    uNewState;
    UINT    uOldState;
    UINT    uChanged;
    POINT   ptAction;
    LPARAM  lParam;
} NMLISTVIEW;

/* NMTREEVIEW — WM_NOTIFY payload for TVN_SELCHANGEDA.  Each embedded
 * TVITEM carries the user lParam plumbed in at TVM_INSERTITEMA. */
typedef struct tagTVITEM_nm {
    UINT    mask;
    HANDLE  hItem;
    UINT    state;
    UINT    stateMask;
    char   *pszText;
    int     cchTextMax;
    int     iImage;
    int     iSelectedImage;
    int     cChildren;
    LPARAM  lParam;
} TVITEM_nm;

typedef struct tagNMTREEVIEW {
    NMHDR     hdr;
    UINT      action;
    TVITEM_nm itemOld;
    TVITEM_nm itemNew;
    POINT     ptDrag;
} NMTREEVIEW;

/* TVN_SELCHANGED action codes (cause field) */
#define TVC_UNKNOWN        0x0000
#define TVC_BYMOUSE        0x0001
#define TVC_BYKEYBOARD     0x0002

#endif /* COMCTL_INTERNAL_H */

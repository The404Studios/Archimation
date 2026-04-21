/*
 * listview_columns.c -- LVM_INSERTCOLUMNA bound-check regression guard.
 *
 * Surface tested:
 *   comctl32!InitCommonControls, user32!CreateWindowExA (WC_LISTVIEWA),
 *   comctl32!SendMessageA with LVM_INSERTCOLUMNA
 *   pe-loader/dlls/comctl32/listview.c (S68 OOB bound fix)
 *
 * Rationale:
 *   S68 added a bound check on LVM_INSERTCOLUMNA so inserts past
 *   LV_MAX_COLS (16) are rejected with a negative index rather than
 *   writing past the fixed-size column array (which used to corrupt
 *   adjacent state and could crash on the next SendMessage).
 *
 *   We attempt to insert 20 columns.  A healthy loader caps at 16
 *   successful inserts and rejects the remaining 4.  A pre-fix loader
 *   either (a) accepts all 20 and scribbles over the next heap block
 *   (observed as a later segfault) or (b) accepts all 20 silently with
 *   in-band heap corruption.  A stub loader that doesn't implement the
 *   ListView common control at all -- or can't even create the window
 *   -- falls through to the STUB path.
 *
 * Harness expectation: outputs-any:LISTVIEW_COLUMNS_OK,LISTVIEW_COLUMNS_STUB
 */

#include <windows.h>
#include <commctrl.h>
#include <stdio.h>

#define LV_MAX_COLS 16

int main(void) {
    InitCommonControls();

    HWND hwnd = CreateWindowExA(
        0,
        WC_LISTVIEWA,
        "lvtest",
        LVS_REPORT | WS_CHILD,
        0, 0, 200, 200,
        NULL, NULL, NULL, NULL);

    if (!hwnd) {
        printf("LISTVIEW_COLUMNS_STUB: CreateWindowExA(WC_LISTVIEWA) "
               "returned NULL\n");
        fflush(stdout);
        return 0;
    }

    LVCOLUMNA col;
    memset(&col, 0, sizeof(col));
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    col.cx = 50;

    int ok_count = 0;
    for (int i = 0; i < 20; i++) {
        char name[16];
        snprintf(name, sizeof(name), "c%d", i);
        col.pszText = name;
        LRESULT r = SendMessageA(hwnd, LVM_INSERTCOLUMNA,
                                 (WPARAM)i, (LPARAM)&col);
        int idx = (int)r;
        if (idx >= 0) {
            ok_count++;
        }
    }

    DestroyWindow(hwnd);

    if (ok_count > LV_MAX_COLS) {
        fprintf(stderr,
                "FAIL: LVM_INSERTCOLUMNA accepted %d inserts; "
                "bound check regressed (expected <=%d)\n",
                ok_count, LV_MAX_COLS);
        return 1;
    }
    if (ok_count == 0) {
        printf("LISTVIEW_COLUMNS_STUB: no column inserts succeeded "
               "(comctl32 not wired)\n");
        fflush(stdout);
        return 0;
    }
    if (ok_count < LV_MAX_COLS) {
        printf("LISTVIEW_COLUMNS_STUB: only %d of %d inserts succeeded "
               "(partial comctl32)\n", ok_count, LV_MAX_COLS);
        fflush(stdout);
        return 0;
    }

    printf("LISTVIEW_COLUMNS_OK: LVM_INSERTCOLUMNA capped at %d "
           "with no crash\n", ok_count);
    fflush(stdout);
    return 0;
}

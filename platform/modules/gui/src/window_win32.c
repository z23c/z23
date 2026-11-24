/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Win32 window backend (user32 + gdi32 only): per-monitor DPI v2,
 * message pump with zero idle CPU, UTF-16 text input, CPU framebuffer
 * presented with SetDIBitsToDevice, clipboard, cursor, fullscreen and raw
 * relative mouse. GL windows are created by window_win32_gl.c. */
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <windowsx.h>

#include <stdio.h>
#include <string.h>

#include "base/safe_alloc.h"
#include "gui/ui.h"
#include "gui_internal.h"

#define WM_GUI_WAKE (WM_APP + 1)
#define LIVE_TIMER_ID 0x5a23u /* modal size/move loop tick */
#define LIVE_TIMER_MS 16u

/* The stock cursor ids spelled out so the file builds with and without UNICODE:
 * the IDC_* macros are char * unless UNICODE is defined. */
#define CURSOR_ARROW MAKEINTRESOURCEW(32512)
#define CURSOR_IBEAM MAKEINTRESOURCEW(32513)
#define CURSOR_WAIT MAKEINTRESOURCEW(32514)
#define CURSOR_HAND MAKEINTRESOURCEW(32649)
#define WHEEL_STEP 120.0f

struct w32 {
    HWND hwnd;
    UINT dpi;
    bool gl;
    bool fullscreen, resizable;
    WINDOWPLACEMENT saved;
    DWORD saved_style;
    wchar_t hi_surrogate;
    DWORD last_click_ms;
    int32_t last_x, last_y;
    uint8_t last_button, clicks;
    enum gui_mouse_mode mouse_mode;
    bool raw_registered, cursor_hidden;
    bool modal; /* inside the OS size/move loop */
    enum gui_cursor cursor;
};

static struct w32 *st(const struct gui_window *w) { return (struct w32 *)w->be; }

typedef UINT (WINAPI *get_dpi_for_window_fn)(HWND);
typedef UINT (WINAPI *get_dpi_for_system_fn)(void);
typedef BOOL (WINAPI *adjust_rect_dpi_fn)(LPRECT, DWORD, BOOL, DWORD, UINT);
typedef BOOL (WINAPI *set_dpi_ctx_fn)(HANDLE);

static FARPROC user32_proc(const char *name)
{
    HMODULE u = GetModuleHandleW(L"user32.dll");
    return u ? GetProcAddress(u, name) : NULL;
}

static UINT dpi_of(HWND h)
{
    get_dpi_for_window_fn f = GUI_FN_CAST(get_dpi_for_window_fn, user32_proc("GetDpiForWindow"));
    UINT d = f && h ? f(h) : 0;
    if (!d) {
        get_dpi_for_system_fn s = GUI_FN_CAST(get_dpi_for_system_fn, user32_proc("GetDpiForSystem"));
        d = s ? s() : 96;
    }
    return d ? d : 96;
}

static void make_dpi_aware(void)
{
    static bool done;
    if (done) return;
    done = true;
    set_dpi_ctx_fn f = GUI_FN_CAST(set_dpi_ctx_fn, user32_proc("SetProcessDpiAwarenessContext"));
    if (f && f((HANDLE)-4)) return; /* PER_MONITOR_AWARE_V2 */
    SetProcessDPIAware();
}

/* AltGr reports as Ctrl+Alt; on layouts that have it the right Alt arrives with
 * a synthetic left Ctrl, and neither is a shortcut modifier then. */
static uint32_t cur_mods(void)
{
    uint32_t m = 0;
    bool altgr = (GetKeyState(VK_RMENU) & 0x8000) && (GetKeyState(VK_LCONTROL) & 0x8000) &&
                 !(GetKeyState(VK_RCONTROL) & 0x8000);
    if (GetKeyState(VK_SHIFT) & 0x8000) m |= GUI_MOD_SHIFT;
    if (!altgr && (GetKeyState(VK_CONTROL) & 0x8000)) m |= GUI_MOD_CTRL;
    if (!altgr && (GetKeyState(VK_MENU) & 0x8000)) m |= GUI_MOD_ALT;
    if ((GetKeyState(VK_LWIN) | GetKeyState(VK_RWIN)) & 0x8000) m |= GUI_MOD_SUPER;
    return m;
}

static enum gui_key map_vk(WPARAM vk)
{
    static const struct { WPARAM vk; enum gui_key key; } k_vk[] = {
        { VK_TAB, GUI_KEY_TAB }, { VK_RETURN, GUI_KEY_ENTER }, { VK_ESCAPE, GUI_KEY_ESCAPE },
        { VK_BACK, GUI_KEY_BACKSPACE }, { VK_DELETE, GUI_KEY_DELETE }, { VK_LEFT, GUI_KEY_LEFT },
        { VK_RIGHT, GUI_KEY_RIGHT }, { VK_UP, GUI_KEY_UP }, { VK_DOWN, GUI_KEY_DOWN },
        { VK_HOME, GUI_KEY_HOME }, { VK_END, GUI_KEY_END }, { VK_PRIOR, GUI_KEY_PAGE_UP },
        { VK_NEXT, GUI_KEY_PAGE_DOWN }, { VK_SPACE, GUI_KEY_SPACE },
    };
    for (size_t i = 0; i < sizeof(k_vk) / sizeof(k_vk[0]); i++)
        if (k_vk[i].vk == vk) return k_vk[i].key;
    if (vk >= VK_F1 && vk <= VK_F12) return (enum gui_key)(GUI_KEY_F1 + (vk - VK_F1));
    if (vk >= 'A' && vk <= 'Z') return (enum gui_key)(GUI_KEY_A + (vk - 'A'));
    if (vk >= '0' && vk <= '9') return (enum gui_key)(GUI_KEY_0 + (vk - '0'));
    return GUI_KEY_NONE;
}

static void push_key(struct gui_window *w, WPARAM vk, LPARAM lp, bool down)
{
    enum gui_key k = map_vk(vk);
    if (k == GUI_KEY_NONE) return;
    struct gui_event e = { .type = GUI_EV_KEY, .mods = cur_mods(),
        .key = { k, (uint32_t)((lp >> 16) & 0xFF), down, down && (lp & (1 << 30)) } };
    gui_ring_push(w, &e);
}

static void push_text(struct gui_window *w, uint32_t cp)
{
    if (cp < 0x20u || cp == 0x7Fu) return; /* Tab/Enter arrive as keys */
    struct gui_event e = { .type = GUI_EV_TEXT, .mods = cur_mods(), .text = { cp } };
    gui_ring_push(w, &e);
}

static void on_char(struct gui_window *w, wchar_t c)
{
    struct w32 *s = st(w);
    if (c >= 0xD800 && c <= 0xDBFF) { s->hi_surrogate = c; return; }
    if (c >= 0xDC00 && c <= 0xDFFF) {
        if (s->hi_surrogate)
            push_text(w, 0x10000u + (((uint32_t)s->hi_surrogate - 0xD800u) << 10) +
                             ((uint32_t)c - 0xDC00u));
        s->hi_surrogate = 0;
        return;
    }
    s->hi_surrogate = 0;
    push_text(w, c);
}

static void on_button(struct gui_window *w, LPARAM lp, uint8_t button, bool down)
{
    struct w32 *s = st(w);
    int32_t x = GET_X_LPARAM(lp), y = GET_Y_LPARAM(lp);
    uint8_t clicks = 1;
    if (down) {
        DWORD now = GetTickCount();
        int dx = GetSystemMetrics(SM_CXDOUBLECLK) / 2, dy = GetSystemMetrics(SM_CYDOUBLECLK) / 2;
        if (s->last_button == button && now - s->last_click_ms <= GetDoubleClickTime() &&
            abs(x - s->last_x) <= dx && abs(y - s->last_y) <= dy && s->clicks < 3)
            clicks = (uint8_t)(s->clicks + 1);
        s->last_click_ms = now;
        s->last_x = x;
        s->last_y = y;
        s->last_button = button;
        s->clicks = clicks;
        SetCapture(s->hwnd);
    } else {
        clicks = s->clicks ? s->clicks : 1;
        if (!(GetKeyState(VK_LBUTTON) & 0x8000) && !(GetKeyState(VK_RBUTTON) & 0x8000) &&
            !(GetKeyState(VK_MBUTTON) & 0x8000))
            ReleaseCapture();
    }
    struct gui_event e = { .type = GUI_EV_MOUSE_BUTTON, .mods = cur_mods(),
                           .button = { x, y, button, down, clicks } };
    gui_ring_push(w, &e);
}

static void on_wheel(struct gui_window *w, WPARAM wp, LPARAM lp, bool horizontal)
{
    POINT p = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
    ScreenToClient(st(w)->hwnd, &p);
    float d = (float)GET_WHEEL_DELTA_WPARAM(wp) / WHEEL_STEP;
    struct gui_event e = { .type = GUI_EV_MOUSE_WHEEL, .mods = cur_mods(),
        .wheel = { p.x, p.y, horizontal ? d : 0.0f, horizontal ? 0.0f : d } };
    gui_ring_push(w, &e);
}

static void on_raw_input(struct gui_window *w, LPARAM lp)
{
    RAWINPUT ri;
    UINT sz = sizeof(ri);
    if (GetRawInputData((HRAWINPUT)lp, RID_INPUT, &ri, &sz, sizeof(RAWINPUTHEADER)) == (UINT)-1)
        return;
    if (ri.header.dwType != RIM_TYPEMOUSE || st(w)->mouse_mode != GUI_MOUSE_RELATIVE) return;
    struct gui_event e = { .type = GUI_EV_MOUSE_RELATIVE,
        .rel = { (float)ri.data.mouse.lLastX, (float)ri.data.mouse.lLastY } };
    gui_ring_push(w, &e);
}

static void on_size(struct gui_window *w, WPARAM wp)
{
    if (wp == SIZE_MINIMIZED) return;
    RECT rc;
    GetClientRect(st(w)->hwnd, &rc);
    int32_t cw = rc.right - rc.left, ch = rc.bottom - rc.top;
    if (cw <= 0 || ch <= 0 || (cw == w->w && ch == w->h)) return;
    w->w = cw;
    w->h = ch;
    struct gui_event e = { .type = GUI_EV_RESIZE, .size = { cw, ch, w->scale } };
    gui_ring_push(w, &e);
}

static void on_dpi(struct gui_window *w, WPARAM wp, LPARAM lp)
{
    struct w32 *s = st(w);
    s->dpi = HIWORD(wp) ? HIWORD(wp) : 96;
    w->scale = (float)s->dpi / 96.0f;
    const RECT *r = (const RECT *)lp;
    SetWindowPos(s->hwnd, NULL, r->left, r->top, r->right - r->left,
                 r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
    struct gui_event e = { .type = GUI_EV_SCALE, .size = { w->w, w->h, w->scale } };
    gui_ring_push(w, &e);
}

static void blit(struct gui_window *w, HDC dc, struct gui_rect r)
{
    if (!w->fb || !gui_rect_clip_frame(&r, w->fb_w, w->fb_h)) return;
    BITMAPINFO bmi;
    memset(&bmi, 0, sizeof(bmi));
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = w->fb_w;
    bmi.bmiHeader.biHeight = -w->fb_h; /* top-down */
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    SetDIBitsToDevice(dc, r.x, r.y, (DWORD)r.w, (DWORD)r.h, r.x, gui_dib_src_y(w->fb_h, &r), 0,
                      (UINT)w->fb_h, w->fb, &bmi, DIB_RGB_COLORS);
}

static LPCWSTR cursor_id(enum gui_cursor c)
{
    switch (c) {
    case GUI_CURSOR_IBEAM: return CURSOR_IBEAM;
    case GUI_CURSOR_HAND: return CURSOR_HAND;
    case GUI_CURSOR_WAIT: return CURSOR_WAIT;
    default: return CURSOR_ARROW;
    }
}

/* Paint what the framebuffer covers, then fill the rest of the dirty rectangle
 * (newly exposed area while a drag-resize is ahead of the app) with the screen
 * background instead of leaving whatever the window held. */
static void on_paint(struct gui_window *w, HWND h)
{
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(h, &ps);
    if (w->surface == GUI_SURFACE_CPU) {
        blit(w, dc, (struct gui_rect){ ps.rcPaint.left, ps.rcPaint.top,
            ps.rcPaint.right - ps.rcPaint.left, ps.rcPaint.bottom - ps.rcPaint.top });
        if (w->fb) ExcludeClipRect(dc, 0, 0, w->fb_w, w->fb_h);
        uint32_t bg = gui_theme(GS_SCREEN)->bg;
        HBRUSH br = CreateSolidBrush(RGB((bg >> 16) & 0xFF, (bg >> 8) & 0xFF, bg & 0xFF));
        if (br) {
            FillRect(dc, &ps.rcPaint, br);
            DeleteObject(br);
        }
    }
    EndPaint(h, &ps);
    struct gui_event e = { .type = GUI_EV_EXPOSE };
    gui_ring_push(w, &e);
}

static void on_minmax(struct gui_window *w, HWND h, LPARAM lp)
{
    MINMAXINFO *mm = (MINMAXINFO *)lp;
    if (w->min_w <= 0 || w->min_h <= 0) return;
    RECT r = { 0, 0, w->min_w, w->min_h };
    AdjustWindowRectEx(&r, (DWORD)GetWindowLongPtrW(h, GWL_STYLE), FALSE,
                       (DWORD)GetWindowLongPtrW(h, GWL_EXSTYLE));
    mm->ptMinTrackSize.x = r.right - r.left;
    mm->ptMinTrackSize.y = r.bottom - r.top;
}

static void push_simple(struct gui_window *w, struct gui_event e) { gui_ring_push(w, &e); }

/* The OS runs its own loop while the user drags a border or the title bar:
 * the app loop is starved, so a timer ticks the live hook (render, drain
 * events, run the app timers) until WM_EXITSIZEMOVE. */
static void modal_enter(struct gui_window *w, HWND h)
{
    st(w)->modal = true;
    SetCoalescableTimer(h, LIVE_TIMER_ID, LIVE_TIMER_MS, NULL, TIMERV_NO_COALESCING);
}

static void modal_exit(struct gui_window *w, HWND h)
{
    KillTimer(h, LIVE_TIMER_ID);
    st(w)->modal = false;
    gui_live_tick(w); /* settle on the final size */
}

/* Size and move messages, including the OS modal loop. */
static LRESULT size_msg(struct gui_window *w, HWND h, UINT m, WPARAM wp, bool *handled)
{
    *handled = true;
    switch (m) {
    case WM_SIZE:
        on_size(w, wp);
        if (st(w)->modal) gui_live_tick(w);
        return 0;
    case WM_ENTERSIZEMOVE: modal_enter(w, h); return 0;
    case WM_EXITSIZEMOVE: modal_exit(w, h); return 0;
    case WM_TIMER:
        if (wp != LIVE_TIMER_ID) break;
        if (st(w)->modal) gui_live_tick(w);
        return 0;
    default: break;
    }
    *handled = false;
    return 0;
}

/* Window-state messages. *handled is false when the default procedure runs. */
static LRESULT win_msg(struct gui_window *w, HWND h, UINT m, WPARAM wp, LPARAM lp, bool *handled)
{
    *handled = true;
    switch (m) {
    case WM_CLOSE: push_simple(w, (struct gui_event){ .type = GUI_EV_CLOSE }); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: on_paint(w, h); return 0;
    case WM_DPICHANGED: on_dpi(w, wp, lp); return 0;
    case WM_GETMINMAXINFO: on_minmax(w, h, lp); return 0;
    case WM_SETFOCUS:
    case WM_KILLFOCUS:
        push_simple(w, (struct gui_event){ .type = GUI_EV_FOCUS, .focus = { m == WM_SETFOCUS } });
        return 0;
    case WM_SETCURSOR:
        if (LOWORD(lp) != HTCLIENT) break;
        SetCursor(st(w)->mouse_mode == GUI_MOUSE_NORMAL ? LoadCursorW(NULL, cursor_id(st(w)->cursor)) : NULL);
        return TRUE;
    case WM_GUI_WAKE: return 0;
    default: break;
    }
    *handled = false;
    return 0;
}

static LRESULT key_msg(struct gui_window *w, HWND h, UINT m, WPARAM wp, LPARAM lp, bool *handled)
{
    *handled = true;
    switch (m) {
    case WM_KEYDOWN:
    case WM_SYSKEYDOWN:
        push_key(w, wp, lp, true);
        return m == WM_SYSKEYDOWN && wp != VK_F10 ? DefWindowProcW(h, m, wp, lp) : 0;
    case WM_KEYUP:
    case WM_SYSKEYUP:
        push_key(w, wp, lp, false);
        return m == WM_SYSKEYUP ? DefWindowProcW(h, m, wp, lp) : 0;
    case WM_CHAR: on_char(w, (wchar_t)wp); return 0;
    case WM_UNICHAR:
        if (wp == UNICODE_NOCHAR) return TRUE;
        push_text(w, (uint32_t)wp);
        return FALSE;
    default: break;
    }
    *handled = false;
    return 0;
}

static LRESULT mouse_msg(struct gui_window *w, HWND h, UINT m, WPARAM wp, LPARAM lp, bool *handled)
{
    static const struct { UINT msg; uint8_t button; bool down; } k_buttons[] = {
        { WM_LBUTTONDOWN, 1, true }, { WM_LBUTTONUP, 1, false }, { WM_RBUTTONDOWN, 2, true },
        { WM_RBUTTONUP, 2, false }, { WM_MBUTTONDOWN, 3, true }, { WM_MBUTTONUP, 3, false },
    };
    *handled = true;
    for (size_t i = 0; i < sizeof(k_buttons) / sizeof(k_buttons[0]); i++)
        if (m == k_buttons[i].msg) {
            on_button(w, lp, k_buttons[i].button, k_buttons[i].down);
            return 0;
        }
    switch (m) {
    case WM_MOUSEMOVE:
        push_simple(w, (struct gui_event){ .type = GUI_EV_MOUSE_MOVE, .mods = cur_mods(),
                    .move = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) } });
        return 0;
    case WM_MOUSEWHEEL: on_wheel(w, wp, lp, false); return 0;
    case WM_MOUSEHWHEEL: on_wheel(w, wp, lp, true); return 0;
    case WM_INPUT: on_raw_input(w, lp); return DefWindowProcW(h, m, wp, lp);
    default: break;
    }
    *handled = false;
    return 0;
}

static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    if (m == WM_NCCREATE) {
        const CREATESTRUCTW *cs = (const CREATESTRUCTW *)lp;
        SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)cs->lpCreateParams);
        return DefWindowProcW(h, m, wp, lp);
    }
    struct gui_window *w = (struct gui_window *)GetWindowLongPtrW(h, GWLP_USERDATA);
    if (!w || !w->be) return DefWindowProcW(h, m, wp, lp);
    bool handled = false;
    LRESULT r = size_msg(w, h, m, wp, &handled);
    if (!handled) r = win_msg(w, h, m, wp, lp, &handled);
    if (!handled) r = key_msg(w, h, m, wp, lp, &handled);
    if (!handled) r = mouse_msg(w, h, m, wp, lp, &handled);
    return handled ? r : DefWindowProcW(h, m, wp, lp);
}

static bool register_class(const wchar_t *name, bool own_dc)
{
    WNDCLASSEXW wc;
    if (GetClassInfoExW(GetModuleHandleW(NULL), name, &wc)) return true;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.style = own_dc ? CS_OWNDC : 0;
    wc.lpfnWndProc = wndproc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, CURSOR_ARROW);
    wc.lpszClassName = name;
    return RegisterClassExW(&wc) != 0;
}

void gui_win32_err_last(char *err, size_t cap, const char *what)
{
    if (err && cap) snprintf(err, cap, "%s (Windows error %lu)", what, GetLastError());
}

static bool w32_open(struct gui_window *w, const struct gui_window_desc *d,
                     char *err, size_t cap)
{
    make_dpi_aware();
    struct w32 *s = zcl_calloc(1, sizeof(*s), "gui_win32");
    if (!s) {
        if (err && cap) snprintf(err, cap, "out of memory opening window");
        return false;
    }
    w->be = s;
    s->gl = d->surface == GUI_SURFACE_GL;
    s->resizable = (d->flags & GUI_WINDOW_RESIZABLE) != 0;
    const wchar_t *cls = s->gl ? L"Z23GuiGl" : L"Z23GuiCpu";
    if (!register_class(cls, s->gl)) {
        gui_win32_err_last(err, cap, "cannot register window class");
        free(s);
        w->be = NULL;
        return false;
    }
    s->dpi = dpi_of(NULL);
    float sc = (float)s->dpi / 96.0f;
    DWORD style = s->resizable ? WS_OVERLAPPEDWINDOW : (WS_OVERLAPPEDWINDOW & ~(DWORD)(WS_THICKFRAME | WS_MAXIMIZEBOX));
    RECT r = { 0, 0, (LONG)((float)d->width * sc + 0.5f), (LONG)((float)d->height * sc + 0.5f) };
    adjust_rect_dpi_fn adj = GUI_FN_CAST(adjust_rect_dpi_fn, user32_proc("AdjustWindowRectExForDpi"));
    if (adj) adj(&r, style, FALSE, 0, s->dpi); else AdjustWindowRectEx(&r, style, FALSE, 0);
    wchar_t title[256];
    gui_win32_utf8_to_wide(d->title_utf8 ? d->title_utf8 : "Z23", d->title_utf8 ? strlen(d->title_utf8) : 3, title, 256);
    s->hwnd = CreateWindowExW(0, cls, title, style, CW_USEDEFAULT, CW_USEDEFAULT,
                              r.right - r.left, r.bottom - r.top, NULL, NULL,
                              GetModuleHandleW(NULL), w);
    if (!s->hwnd) {
        gui_win32_err_last(err, cap, "cannot create window");
        free(s);
        w->be = NULL;
        return false;
    }
    s->dpi = dpi_of(s->hwnd);
    w->scale = (float)s->dpi / 96.0f;
    GetClientRect(s->hwnd, &r);
    w->w = r.right - r.left;
    w->h = r.bottom - r.top;
    if (s->gl && !gui_win32_gl_create(w, s->hwnd, d->gl, err, cap)) {
        DestroyWindow(s->hwnd);
        free(s);
        w->be = NULL;
        return false;
    }
    if (d->flags & GUI_WINDOW_FULLSCREEN) gui_window_set_fullscreen(w, true);
    if (!(d->flags & GUI_WINDOW_HIDDEN)) {
        ShowWindow(s->hwnd, SW_SHOW);
        UpdateWindow(s->hwnd);
    }
    return true;
}

static void w32_close(struct gui_window *w)
{
    struct w32 *s = st(w);
    if (!s) return;
    if (s->cursor_hidden) ShowCursor(TRUE);
    if (s->mouse_mode == GUI_MOUSE_RELATIVE) ClipCursor(NULL);
    if (s->raw_registered) {
        RAWINPUTDEVICE rid = { 1, 2, RIDEV_REMOVE, NULL };
        RegisterRawInputDevices(&rid, 1, sizeof(rid));
    }
    if (s->gl) gui_win32_gl_destroy(w);
    if (s->hwnd) DestroyWindow(s->hwnd);
    free(s);
    w->be = NULL;
}

static void pump(void)
{
    MSG msg;
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

static void w32_wait(struct gui_window *w, int32_t ms)
{
    if (st(w)->modal) return; /* the OS loop already pumps; never nest a pump inside it */
    pump();
    if (w->count || atomic_load(&w->wake_pending) || ms == 0) return;
    MsgWaitForMultipleObjectsEx(0, NULL, ms < 0 ? INFINITE : (DWORD)ms,
                                QS_ALLINPUT, MWMO_INPUTAVAILABLE);
    pump();
}

static void w32_wake(struct gui_window *w)
{
    struct w32 *s = st(w);
    if (s && s->hwnd) PostMessageW(s->hwnd, WM_GUI_WAKE, 0, 0);
}

static bool w32_present(struct gui_window *w, const struct gui_rect *rects, size_t n)
{
    struct w32 *s = st(w);
    HDC dc = GetDC(s->hwnd);
    if (!dc) return false;
    if (n == 0) blit(w, dc, (struct gui_rect){ 0, 0, w->fb_w, w->fb_h });
    for (size_t i = 0; i < n; i++) blit(w, dc, rects[i]);
    ReleaseDC(s->hwnd, dc);
    return true;
}

static bool w32_clip_set(struct gui_window *w, const char *utf8, size_t len)
{
    return gui_win32_clip_set(st(w)->hwnd, utf8, len);
}

static size_t w32_clip_get(struct gui_window *w, char *buf, size_t cap)
{
    return gui_win32_clip_get(st(w)->hwnd, buf, cap);
}

static void w32_title(struct gui_window *w, const char *utf8)
{
    wchar_t t[256];
    gui_win32_utf8_to_wide(utf8, strlen(utf8), t, 256);
    SetWindowTextW(st(w)->hwnd, t);
}

static void w32_cursor(struct gui_window *w, enum gui_cursor c)
{
    st(w)->cursor = c;
    SetCursor(LoadCursorW(NULL, cursor_id(c)));
}

static bool w32_mouse_mode(struct gui_window *w, enum gui_mouse_mode m)
{
    struct w32 *s = st(w);
    bool hide = m != GUI_MOUSE_NORMAL;
    if (hide != s->cursor_hidden) {
        ShowCursor(hide ? FALSE : TRUE);
        s->cursor_hidden = hide;
    }
    if (m == GUI_MOUSE_RELATIVE) {
        if (!s->raw_registered) {
            RAWINPUTDEVICE rid = { 1, 2, 0, s->hwnd };
            if (!RegisterRawInputDevices(&rid, 1, sizeof(rid))) return false;
            s->raw_registered = true;
        }
        RECT rc;
        POINT tl = { 0, 0 };
        GetClientRect(s->hwnd, &rc);
        ClientToScreen(s->hwnd, &tl);
        rc.left += tl.x; rc.right += tl.x; rc.top += tl.y; rc.bottom += tl.y;
        ClipCursor(&rc);
    } else if (s->mouse_mode == GUI_MOUSE_RELATIVE) {
        ClipCursor(NULL);
    }
    s->mouse_mode = m;
    return true;
}

static bool w32_fullscreen(struct gui_window *w, bool on)
{
    struct w32 *s = st(w);
    if (on == s->fullscreen) return true;
    if (on) {
        MONITORINFO mi;
        memset(&mi, 0, sizeof(mi));
        mi.cbSize = sizeof(mi);
        s->saved.length = sizeof(s->saved);
        s->saved_style = (DWORD)GetWindowLongPtrW(s->hwnd, GWL_STYLE);
        if (!GetWindowPlacement(s->hwnd, &s->saved) ||
            !GetMonitorInfoW(MonitorFromWindow(s->hwnd, MONITOR_DEFAULTTONEAREST), &mi))
            return false;
        SetWindowLongPtrW(s->hwnd, GWL_STYLE, (LONG_PTR)((s->saved_style & ~(DWORD)WS_OVERLAPPEDWINDOW) | WS_POPUP));
        SetWindowPos(s->hwnd, HWND_TOP, mi.rcMonitor.left, mi.rcMonitor.top,
                     mi.rcMonitor.right - mi.rcMonitor.left,
                     mi.rcMonitor.bottom - mi.rcMonitor.top,
                     SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
    } else {
        SetWindowLongPtrW(s->hwnd, GWL_STYLE, (LONG_PTR)s->saved_style);
        SetWindowPlacement(s->hwnd, &s->saved);
        SetWindowPos(s->hwnd, NULL, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
    }
    s->fullscreen = on;
    return true;
}

const struct gui_backend_ops gui_backend_win32 = {
    .open = w32_open, .close = w32_close, .wait_native = w32_wait,
    .wake = w32_wake, .present = w32_present, .clip_set = w32_clip_set,
    .clip_get = w32_clip_get, .set_title = w32_title, .set_cursor = w32_cursor,
    .set_mouse_mode = w32_mouse_mode, .set_fullscreen = w32_fullscreen,
    .gl_make_current = gui_win32_gl_make_current, .gl_swap = gui_win32_gl_swap,
    .gl_interval = gui_win32_gl_interval, .gl_proc = gui_win32_gl_proc,
};
#else
typedef int gui_window_win32_not_built; /* Windows-only translation unit */
#endif

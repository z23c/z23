/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Windows acceptance of the real Win32 CPU window: open (visible for
 * 300 ms), present a gradient, pump events, read the framebuffer back, check
 * the DPI scale, round-trip the clipboard, present a PARTIAL dirty rectangle
 * and read the window back with BitBlt to compare every pixel with the
 * framebuffer, drive the live-resize hook the way WM_ENTERSIZEMOVE, WM_SIZE and
 * WM_TIMER do inside the OS size loop, and close. Prints PASS or the failing
 * step and exits non-zero. A window the session cannot read back (locked
 * desktop, no display) prints SKIP for the readback step and still exits 0. */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/safe_alloc.h"
#include "gui/window.h"

#define TITLE_UTF8 "z23 gui acceptance"
#define TITLE_WIDE L"z23 gui acceptance"

static bool fail(const char *msg)
{
    printf("gui_window: FAIL %s\n", msg);
    return false;
}

static bool present_gradient(struct gui_window *w)
{
    struct gui_cpu_frame f;
    if (!gui_cpu_acquire(w, &f)) return fail("acquire");
    for (int32_t y = 0; y < f.height; y++)
        for (int32_t x = 0; x < f.width; x++)
            f.pixels[(size_t)y * (size_t)f.stride_px + (size_t)x] =
                ((uint32_t)(x * 255 / f.width) << 16) | ((uint32_t)(y * 255 / f.height) << 8) | 0x40u;
    return gui_cpu_present(w, NULL, 0) || fail("present");
}

static bool pump_and_timer(struct gui_window *w)
{
    struct gui_event ev;
    uint64_t t0 = gui_now_ns();
    while ((gui_now_ns() - t0) < 300000000ull) gui_window_wait(w, 20, &ev);
    gui_window_timer_set(w, 9, 10, false);
    for (int i = 0; i < 20; i++)
        if (gui_window_wait(w, 50, &ev) && ev.type == GUI_EV_TIMER) return true;
    return fail("timer event");
}

static bool readback_and_clipboard(struct gui_window *w)
{
    struct gui_cpu_frame f;
    if (!gui_cpu_acquire(w, &f) || f.pixels[0] != 0x40u) return fail("framebuffer readback");
    const char *text = "Z23 caf\xC3\xA9 \xE2\x82\xAC";
    char back[64] = "";
    if (!gui_clipboard_set_text(w, text, strlen(text))) return fail("clipboard set");
    if (gui_clipboard_get_text(w, back, sizeof(back)) != strlen(text) || strcmp(back, text) != 0)
        return fail("clipboard round trip");
    return true;
}

/* One colour per row and column: any row or column taken from the wrong place
 * (the mirrored-rows bug) shows up as a different pixel. */
static uint32_t pattern(int variant, int32_t x, int32_t y)
{
    uint32_t r = variant ? (uint32_t)(y * 53 + 101) : (uint32_t)(y * 37);
    uint32_t g = variant ? (uint32_t)(y * 29 + 3) : (uint32_t)(y * 91 + 17);
    uint32_t b = variant ? (uint32_t)(x * 7 + 200) : (uint32_t)(x * 13);
    return ((r & 255u) << 16) | ((g & 255u) << 8) | (b & 255u);
}

static void fill_pattern(const struct gui_cpu_frame *f, int variant)
{
    for (int32_t y = 0; y < f->height; y++)
        for (int32_t x = 0; x < f->width; x++)
            f->pixels[(size_t)y * (size_t)f->stride_px + (size_t)x] = pattern(variant, x, y);
}

/* Copy the client area through a top-down 32-bit DIB section and return it. */
static uint32_t *copy_dib(HDC mem, HDC wdc, const BITMAPINFO *bi, int32_t w, int32_t ht)
{
    void *bits = NULL;
    HBITMAP bm = CreateDIBSection(wdc, bi, DIB_RGB_COLORS, &bits, NULL, 0);
    uint32_t *out = NULL;
    if (bm && bits) {
        HGDIOBJ old = SelectObject(mem, bm);
        if (BitBlt(mem, 0, 0, w, ht, wdc, 0, 0, SRCCOPY)) {
            GdiFlush();
            out = zcl_malloc((size_t)w * (size_t)ht * 4u, "gui_acceptance_readback");
            if (out) memcpy(out, bits, (size_t)w * (size_t)ht * 4u);
        }
        SelectObject(mem, old);
    }
    if (bm) DeleteObject(bm);
    return out;
}

static uint32_t *read_window(HWND h, int32_t w, int32_t ht)
{
    HDC wdc = GetDC(h);
    HDC mem = wdc ? CreateCompatibleDC(wdc) : NULL;
    uint32_t *out = NULL;
    if (mem) {
        BITMAPINFO bi;
        memset(&bi, 0, sizeof(bi));
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = w;
        bi.bmiHeader.biHeight = -ht;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        out = copy_dib(mem, wdc, &bi, w, ht);
        DeleteDC(mem);
    }
    if (wdc) ReleaseDC(h, wdc);
    return out;
}

static void settle_ms(uint32_t ms)
{
    MSG m;
    uint64_t t0 = gui_now_ns();
    while (gui_now_ns() - t0 < (uint64_t)ms * 1000000ull) {
        while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) DispatchMessageW(&m);
        Sleep(5);
    }
}

static void settle(void) { settle_ms(100); }

static bool in_rect(const struct gui_rect *r, int32_t x, int32_t y)
{
    return x >= r->x && x < r->x + r->w && y >= r->y && y < r->y + r->h;
}

/* Pixels that differ from pattern 1 inside either rectangle and from pattern 0
 * outside them. */
static int64_t count_mismatch(const uint32_t *px, const struct gui_cpu_frame *f, const struct gui_rect *r, size_t n)
{
    int64_t bad = 0;
    for (int32_t y = 0; y < f->height; y++)
        for (int32_t x = 0; x < f->width; x++) {
            bool in = false;
            for (size_t i = 0; i < n; i++) in = in || in_rect(&r[i], x, y);
            uint32_t want = pattern(in ? 1 : 0, x, y);
            if ((px[(size_t)y * (size_t)f->width + (size_t)x] & 0xFFFFFFu) != want) bad++;
        }
    return bad;
}

/* Present pattern 0 in full, then pattern 1 for two rectangles only. The window must
 * show pattern 1 inside them and still pattern 0 everywhere else: GDI counts DIB
 * source rows from the bottom, and the old ySrc = r.y copied mirrored rows. */
static bool partial_present(struct gui_window *w)
{
    HWND h = FindWindowW(NULL, TITLE_WIDE);
    struct gui_cpu_frame f;
    if (!h || !gui_cpu_acquire(w, &f)) return fail("find or acquire for the partial present");
    SetWindowPos(h, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    fill_pattern(&f, 0);
    if (!gui_cpu_present(w, NULL, 0)) return fail("full present");
    settle();
    uint32_t *before = read_window(h, f.width, f.height);
    bool readable = before && count_mismatch(before, &f, NULL, 0) == 0;
    free(before);
    if (!readable) {
        printf("gui_window: SKIP partial present: the window cannot be read back in this session\n");
        return true;
    }
    fill_pattern(&f, 1);
    struct gui_rect dirty[2] = { { 20, 20, 60, 40 }, { f.width - 50, f.height - 30, 40, 20 } };
    if (!gui_cpu_present(w, dirty, 2)) return fail("partial present");
    uint32_t *after = read_window(h, f.width, f.height);
    SetWindowPos(h, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    if (!after) return fail("read the window back");
    int64_t bad = count_mismatch(after, &f, dirty, 2);
    free(after);
    if (bad != 0) {
        printf("gui_window: FAIL partial present: %lld pixels differ from the framebuffer\n", (long long)bad);
        return false;
    }
    return true;
}

/* The wallet calls the headless-only helpers on whatever window it opened. On a Win32
 * window they must be no-ops: they used to write the hold flag over the first byte of
 * the backend's HWND, after which every GetDC, PostMessage and GetClientRect failed. */
static bool headless_calls_are_inert(struct gui_window *w)
{
    gui_headless_set_hold(w, true);
    bool counts_zero = gui_headless_present_count(w) == 0 && gui_headless_presented_pixels(w) == 0;
    gui_headless_set_hold(w, false);
    HWND h = FindWindowW(NULL, TITLE_WIDE);
    RECT c;
    if (!h || !GetClientRect(h, &c)) return fail("find the window after the headless calls");
    if (!counts_zero) return fail("headless counters answered for a Win32 window");
    return gui_cpu_present(w, NULL, 0) || fail("present after headless calls on a Win32 window");
}

static int g_live_calls;

static void live_hook(void *user)
{
    struct gui_window *w = user;
    struct gui_event ev;
    g_live_calls++;
    while (gui_window_wait(w, 0, &ev)) {
    }
    struct gui_cpu_frame f;
    if (gui_cpu_acquire(w, &f)) {
        fill_pattern(&f, 1);
        gui_cpu_present(w, NULL, 0);
    }
}

/* WM_ENTERSIZEMOVE, a resize and WM_TIMER ticks, as the OS modal loop delivers them:
 * the hook must run on WM_SIZE and on its timer, render at the new size, and stop on
 * WM_EXITSIZEMOVE. */
static bool live_resize(struct gui_window *w)
{
    HWND h = FindWindowW(NULL, TITLE_WIDE);
    if (!h) return fail("find the window for the live resize");
    gui_window_set_live_hook(w, live_hook, w);
    SendMessageW(h, WM_ENTERSIZEMOVE, 0, 0);
    RECT r;
    GetWindowRect(h, &r);
    SetWindowPos(h, NULL, 0, 0, r.right - r.left + 40, r.bottom - r.top + 30,
                 SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    int after_size = g_live_calls;
    RECT c;
    GetClientRect(h, &c);
    struct gui_cpu_frame f;
    bool sized = after_size >= 1 && gui_cpu_acquire(w, &f) && f.width == c.right - c.left &&
                 f.height == c.bottom - c.top;
    settle_ms(300);
    int ticks = g_live_calls - after_size;
    SendMessageW(h, WM_EXITSIZEMOVE, 0, 0);
    int at_exit = g_live_calls;
    settle();
    gui_window_set_live_hook(w, NULL, NULL);
    if (!sized) return fail("live hook did not render at the new size inside the size loop");
    if (ticks < 5) return fail("live hook timer did not keep ticking inside the size loop");
    if (g_live_calls != at_exit) return fail("live hook kept running after WM_EXITSIZEMOVE");
    return true;
}

int main(void)
{
    struct gui_window_desc d = { .title_utf8 = TITLE_UTF8, .width = 320, .height = 200,
        .flags = GUI_WINDOW_RESIZABLE, .surface = GUI_SURFACE_CPU, .backend = GUI_BACKEND_WIN32 };
    struct gui_window *w = NULL;
    char err[160];
    if (!gui_window_open(&d, &w, err, sizeof(err))) {
        printf("gui_window: FAIL open: %s\n", err);
        return 1;
    }
    int32_t pw = 0, ph = 0;
    float scale = 0.0f;
    gui_window_size(w, &pw, &ph, &scale);
    bool ok = pw > 0 && ph > 0 && scale > 0.0f ? true : fail("window size or scale");
    ok = ok && present_gradient(w) && pump_and_timer(w) && readback_and_clipboard(w);
    ok = ok && partial_present(w) && headless_calls_are_inert(w) && live_resize(w);
    gui_window_close(w);
    if (ok) printf("gui_window: PASS scale=%.2f size=%dx%d\n", (double)scale, pw, ph);
    return ok ? 0 : 1;
}

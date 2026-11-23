/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Windows acceptance of the real Win32 CPU window: open (visible for
 * 300 ms), present a gradient, pump events, read the framebuffer back, check
 * the DPI scale, round-trip the clipboard and close. Prints PASS or the
 * failing step and exits non-zero. */
#include <stdio.h>
#include <string.h>

#include "gui/window.h"

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

int main(void)
{
    struct gui_window_desc d = { .title_utf8 = "z23 gui acceptance", .width = 320, .height = 200,
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
    gui_window_close(w);
    if (ok) printf("gui_window: PASS scale=%.2f size=%dx%d\n", (double)scale, pw, ph);
    return ok ? 0 : 1;
}

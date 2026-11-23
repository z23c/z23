/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Windows smoke test of the GPU surface interface: a hidden 64x64 GL
 * window, glClearColor(0, 0.5, 1, 1), glClear, glReadPixels one pixel,
 * SwapBuffers. Prints "SKIP gui_gl_smoke: <reason>" and exits 0 when no GL is
 * available (remote desktop, VM without a driver). */
#include <stdio.h>
#include <string.h>

#include "gui/window.h"

typedef void (*gl_clear_color_fn)(float, float, float, float);
typedef void (*gl_clear_fn)(unsigned);
typedef void (*gl_read_pixels_fn)(int, int, int, int, unsigned, unsigned, void *);
typedef void (*gl_finish_fn)(void);

#define GL_COLOR_BUFFER_BIT 0x00004000u
#define GL_RGBA 0x1908u
#define GL_UNSIGNED_BYTE 0x1401u

/* GetProcAddress results arrive as void *; copy the bits into a function pointer. */
#define AS_FN(T, p) __extension__({ void *gp_ = (p); T gf_; memcpy(&gf_, &gp_, sizeof gf_); gf_; })

int main(void)
{
    if (!gui_gl_available(GUI_BACKEND_WIN32)) {
        printf("SKIP gui_gl_smoke: opengl32.dll is not available\n");
        return 0;
    }
    struct gui_gl_desc g = { .major = 1, .minor = 1, .depth_bits = 24, .stencil_bits = 8 };
    struct gui_window_desc d = { .title_utf8 = "z23 gl smoke", .width = 64, .height = 64,
        .flags = GUI_WINDOW_HIDDEN, .surface = GUI_SURFACE_GL, .gl = &g, .backend = GUI_BACKEND_WIN32 };
    struct gui_window *w = NULL;
    char err[160];
    if (!gui_window_open(&d, &w, err, sizeof(err))) {
        printf("SKIP gui_gl_smoke: %s\n", err);
        return 0;
    }
    gl_clear_color_fn clear_color = AS_FN(gl_clear_color_fn, gui_gl_proc(w, "glClearColor"));
    gl_clear_fn clear = AS_FN(gl_clear_fn, gui_gl_proc(w, "glClear"));
    gl_read_pixels_fn read_px = AS_FN(gl_read_pixels_fn, gui_gl_proc(w, "glReadPixels"));
    gl_finish_fn finish = AS_FN(gl_finish_fn, gui_gl_proc(w, "glFinish"));
    if (!clear_color || !clear || !read_px || !finish || !gui_gl_make_current(w)) {
        printf("SKIP gui_gl_smoke: GL entry points are unavailable\n");
        gui_window_close(w);
        return 0;
    }
    clear_color(0.0f, 0.5f, 1.0f, 1.0f);
    clear(GL_COLOR_BUFFER_BIT);
    finish();
    unsigned char px[4] = { 0, 0, 0, 0 };
    read_px(32, 32, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, px);
    bool swapped = gui_gl_swap(w);
    gui_gl_set_swap_interval(w, 1);
    gui_window_close(w);
    /* 0.5 * 255 = 127.5; accept 120..135 for driver rounding. */
    if (px[0] > 8 || px[1] < 120 || px[1] > 135 || px[2] < 247 || !swapped) {
        printf("gui_gl_smoke: FAIL pixel=%u,%u,%u,%u swapped=%d\n", px[0], px[1], px[2], px[3], (int)swapped);
        return 1;
    }
    printf("gui_gl_smoke: PASS pixel=%u,%u,%u,%u\n", px[0], px[1], px[2], px[3]);
    return 0;
}

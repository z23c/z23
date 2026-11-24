/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: portable window, event and surface interface. A window presents
 * either a CPU framebuffer (ordinary UI) or an OpenGL surface (games). */
#ifndef ZCL_GUI_WINDOW_H
#define ZCL_GUI_WINDOW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum gui_backend_kind {
    GUI_BACKEND_AUTO,
    GUI_BACKEND_WIN32,
    GUI_BACKEND_X11,
    GUI_BACKEND_HEADLESS
};
enum gui_surface_kind { GUI_SURFACE_CPU = 1, GUI_SURFACE_GL = 2 };
enum { GUI_WINDOW_RESIZABLE = 1u, GUI_WINDOW_HIDDEN = 2u,
       GUI_WINDOW_FULLSCREEN = 4u };

struct gui_gl_desc {
    uint8_t major, minor;
    bool core_profile, debug, srgb;
    uint8_t depth_bits, stencil_bits, msaa_samples;
};

struct gui_window_desc {
    const char *title_utf8;
    int32_t width, height, min_width, min_height; /* logical px */
    uint32_t flags;
    enum gui_surface_kind surface;
    const struct gui_gl_desc *gl;
    enum gui_backend_kind backend;
};

struct gui_rect { int32_t x, y, w, h; };

/* XRGB8888: 0x00RRGGBB, top-down. */
struct gui_cpu_frame {
    uint32_t *pixels;
    int32_t width, height, stride_px;
    float scale;
};

enum gui_event_type {
    GUI_EV_NONE, GUI_EV_CLOSE, GUI_EV_RESIZE, GUI_EV_SCALE, GUI_EV_EXPOSE,
    GUI_EV_FOCUS, GUI_EV_KEY, GUI_EV_TEXT, GUI_EV_MOUSE_MOVE,
    GUI_EV_MOUSE_BUTTON, GUI_EV_MOUSE_WHEEL, GUI_EV_MOUSE_RELATIVE,
    GUI_EV_TIMER, GUI_EV_WAKE,
    GUI_EV_GAMEPAD /* reserved: never emitted in M1 */
};
enum { GUI_MOD_SHIFT = 1, GUI_MOD_CTRL = 2, GUI_MOD_ALT = 4,
       GUI_MOD_SUPER = 8 };

enum gui_key {
    GUI_KEY_NONE, GUI_KEY_TAB, GUI_KEY_ENTER, GUI_KEY_ESCAPE,
    GUI_KEY_BACKSPACE, GUI_KEY_DELETE, GUI_KEY_LEFT, GUI_KEY_RIGHT,
    GUI_KEY_UP, GUI_KEY_DOWN, GUI_KEY_HOME, GUI_KEY_END, GUI_KEY_PAGE_UP,
    GUI_KEY_PAGE_DOWN, GUI_KEY_SPACE,
    GUI_KEY_F1, GUI_KEY_F2, GUI_KEY_F3, GUI_KEY_F4, GUI_KEY_F5, GUI_KEY_F6,
    GUI_KEY_F7, GUI_KEY_F8, GUI_KEY_F9, GUI_KEY_F10, GUI_KEY_F11,
    GUI_KEY_F12,
    GUI_KEY_A, /* A..Z contiguous */
    GUI_KEY_B, GUI_KEY_C, GUI_KEY_D, GUI_KEY_E, GUI_KEY_F, GUI_KEY_G,
    GUI_KEY_H, GUI_KEY_I, GUI_KEY_J, GUI_KEY_K, GUI_KEY_L, GUI_KEY_M,
    GUI_KEY_N, GUI_KEY_O, GUI_KEY_P, GUI_KEY_Q, GUI_KEY_R, GUI_KEY_S,
    GUI_KEY_T, GUI_KEY_U, GUI_KEY_V, GUI_KEY_W, GUI_KEY_X, GUI_KEY_Y,
    GUI_KEY_Z,
    GUI_KEY_0, /* 0..9 contiguous */
    GUI_KEY_1, GUI_KEY_2, GUI_KEY_3, GUI_KEY_4, GUI_KEY_5, GUI_KEY_6,
    GUI_KEY_7, GUI_KEY_8, GUI_KEY_9,
    GUI_KEY_COUNT
};

struct gui_event {
    enum gui_event_type type;
    uint32_t mods;
    uint64_t time_ns;
    union {
        struct { int32_t w, h; float scale; } size; /* physical px */
        struct { bool gained; } focus;
        struct { enum gui_key key; uint32_t scancode; bool down, repeat; } key;
        struct { uint32_t codepoint; } text;
        struct { int32_t x, y; } move; /* physical px, client area */
        struct { int32_t x, y; uint8_t button; bool down; uint8_t clicks; }
            button; /* button 1 L, 2 R, 3 M */
        struct { int32_t x, y; float dx, dy; } wheel; /* dy +1 = notch up */
        struct { float dx, dy; } rel;
        struct { uint32_t id; } timer;
    };
};

enum gui_cursor { GUI_CURSOR_ARROW, GUI_CURSOR_IBEAM, GUI_CURSOR_HAND,
                  GUI_CURSOR_WAIT };
enum gui_mouse_mode { GUI_MOUSE_NORMAL, GUI_MOUSE_HIDDEN,
                      GUI_MOUSE_RELATIVE };

struct gui_window;

bool gui_window_open(const struct gui_window_desc *d, struct gui_window **out,
                     char *err, size_t err_cap);
void gui_window_close(struct gui_window *w);
/* timeout_ms -1 waits forever, 0 polls; false means timed out. */
bool gui_window_wait(struct gui_window *w, int32_t timeout_ms,
                     struct gui_event *ev);
void gui_window_wake(struct gui_window *w); /* thread-safe */
bool gui_window_timer_set(struct gui_window *w, uint32_t id, uint32_t ms,
                          bool repeat); /* up to 8 timers */
void gui_window_timer_cancel(struct gui_window *w, uint32_t id);
void gui_window_size(const struct gui_window *w, int32_t *pw, int32_t *ph,
                     float *scale);
void gui_window_set_title(struct gui_window *w, const char *utf8);
void gui_window_set_cursor(struct gui_window *w, enum gui_cursor c);
bool gui_window_set_mouse_mode(struct gui_window *w, enum gui_mouse_mode m);
bool gui_window_set_fullscreen(struct gui_window *w, bool on);
void gui_window_set_text_input(struct gui_window *w, bool on,
                               struct gui_rect caret);
bool gui_clipboard_set_text(struct gui_window *w, const char *utf8, size_t len);
size_t gui_clipboard_get_text(struct gui_window *w, char *buf, size_t cap);

/* Called by a backend while the OS holds the thread in a modal size or move
 * loop (a Win32 border drag), where the normal event loop does not run: the
 * hook drains events and renders so the window never shows stale or garbage
 * pixels and timers keep firing. NULL clears it. Never called from headless. */
typedef void (*gui_live_fn)(void *user);
void gui_window_set_live_hook(struct gui_window *w, gui_live_fn fn, void *user);

/* Present geometry shared by the backends, pure so every platform tests it.
 * gui_rect_clip_frame clips r to a w x h frame; false when nothing is left.
 * gui_dib_src_y is the ySrc for SetDIBitsToDevice with a top-down DIB of
 * fb_h rows: GDI counts source rows from the bottom whatever the sign of
 * biHeight, so rows r->y .. r->y + r->h - 1 start at fb_h - r->y - r->h. */
bool gui_rect_clip_frame(struct gui_rect *r, int32_t w, int32_t h);
int32_t gui_dib_src_y(int32_t fb_h, const struct gui_rect *r);

/* CPU surface. */
bool gui_cpu_acquire(struct gui_window *w, struct gui_cpu_frame *out);
bool gui_cpu_present(struct gui_window *w, const struct gui_rect *rects,
                     size_t n); /* n == 0 presents the whole frame */

/* GPU surface (interface; M1 proves context creation only). */
bool gui_gl_make_current(struct gui_window *w);
bool gui_gl_swap(struct gui_window *w);
bool gui_gl_set_swap_interval(struct gui_window *w, int interval);
void *gui_gl_proc(struct gui_window *w, const char *name);
bool gui_gl_available(enum gui_backend_kind b);

uint64_t gui_now_ns(void);

/* Headless backend: a memory framebuffer on a virtual clock. */
bool gui_headless_inject(struct gui_window *w, const struct gui_event *ev);
/* Resize (physical px) and rescale; queues GUI_EV_RESIZE. */
void gui_headless_set_size(struct gui_window *w, int32_t pw, int32_t ph,
                           float scale);
/* While held, waiting advances virtual time at real-time speed so replies
 * from worker threads keep pace; otherwise waiting jumps to the deadline. */
void gui_headless_set_hold(struct gui_window *w, bool hold);
/* Total pixels reported through gui_cpu_present (dirty-area accounting). */
uint64_t gui_headless_presented_pixels(const struct gui_window *w);
size_t gui_headless_present_count(const struct gui_window *w);

/* Scripted sessions. One command per line, '#' comments:
 *   size W H | scale F | move X Y | click X Y [right] | dclick X Y |
 *   wheel X Y DY | key NAME [shift|ctrl|alt] | text "s" | paste "s" |
 *   wait MS | until-idle | shot NAME
 * Limits: 4096 lines, 512 bytes per line. */
struct gui_script;
struct gui_script *gui_headless_script_load(const char *text, size_t len,
                                            char *err, size_t err_cap);
void gui_headless_script_free(struct gui_script *s);
enum gui_script_step {
    GUI_SCRIPT_DONE = 0,
    GUI_SCRIPT_RAN = 1,   /* input injected; keep pumping the window */
    GUI_SCRIPT_SHOT = 2,  /* caller must settle, then write shot_out */
    GUI_SCRIPT_IDLE = 3   /* caller must run until its work is idle */
};
enum gui_script_step gui_headless_script_step(struct gui_window *w,
                                              struct gui_script *s,
                                              char *shot_out, size_t shot_cap);

bool gui_frame_write_png(const struct gui_cpu_frame *f, const char *path_utf8);
void gui_frame_sha3(const struct gui_cpu_frame *f, uint8_t out[32]);

#endif

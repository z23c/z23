/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private backend vtable, event ring and timer table of gui windows. */
#ifndef ZCL_GUI_INTERNAL_H
#define ZCL_GUI_INTERNAL_H

#include <stdatomic.h>

#include "gui/window.h"

#define GUI_RING_CAP 256u
#define GUI_TIMER_CAP 8u
#define GUI_CLIP_CAP 65536u

struct gui_window;

struct gui_backend_ops {
    bool (*open)(struct gui_window *w, const struct gui_window_desc *d,
                 char *err, size_t cap);
    void (*close)(struct gui_window *w);
    /* Pump native messages into the ring, blocking at most ms (-1 forever). */
    void (*wait_native)(struct gui_window *w, int32_t ms);
    void (*wake)(struct gui_window *w);
    bool (*present)(struct gui_window *w, const struct gui_rect *r, size_t n);
    bool (*clip_set)(struct gui_window *w, const char *utf8, size_t len);
    size_t (*clip_get)(struct gui_window *w, char *buf, size_t cap);
    void (*set_title)(struct gui_window *w, const char *utf8);
    void (*set_cursor)(struct gui_window *w, enum gui_cursor c);
    bool (*set_mouse_mode)(struct gui_window *w, enum gui_mouse_mode m);
    bool (*set_fullscreen)(struct gui_window *w, bool on);
    bool (*gl_make_current)(struct gui_window *w);
    bool (*gl_swap)(struct gui_window *w);
    bool (*gl_interval)(struct gui_window *w, int interval);
    void *(*gl_proc)(struct gui_window *w, const char *name);
};

extern const struct gui_backend_ops gui_backend_headless;
#if defined(_WIN32)
extern const struct gui_backend_ops gui_backend_win32;
bool gui_win32_gl_probe(void);
/* GL half of the win32 backend (window_win32_gl.c). */
bool gui_win32_gl_create(struct gui_window *w, void *hwnd,
                         const struct gui_gl_desc *g, char *err, size_t cap);
void gui_win32_gl_destroy(struct gui_window *w);
bool gui_win32_gl_make_current(struct gui_window *w);
bool gui_win32_gl_swap(struct gui_window *w);
bool gui_win32_gl_interval(struct gui_window *w, int interval);
void *gui_win32_gl_proc(struct gui_window *w, const char *name);
#endif

#include <string.h>

/* Cast a GetProcAddress-style result to a function pointer without an ISO C
 * object/function pointer conversion. */
#define GUI_FN_CAST(T, p) __extension__({ __typeof__(p) gp_ = (p); T gf_; memcpy(&gf_, &gp_, sizeof gf_); gf_; })

struct gui_timer {
    bool used, repeat;
    uint32_t id, interval_ms;
    uint64_t due_ns;
};

struct gui_window {
    const struct gui_backend_ops *ops;
    enum gui_backend_kind kind;
    enum gui_surface_kind surface;
    struct gui_event ring[GUI_RING_CAP];
    size_t head, count;
    struct gui_timer timers[GUI_TIMER_CAP];
    int32_t w, h; /* client size, physical px */
    int32_t min_w, min_h;
    float scale;
    uint32_t *fb;
    int32_t fb_w, fb_h;
    atomic_bool wake_pending;
    void *be;     /* backend state */
    void *be_gl;  /* GL state (win32) */
};

/* Backends call this from the thread that pumps events. */
void gui_ring_push(struct gui_window *w, const struct gui_event *ev);
/* Virtual clock used by the headless backend. */
void gui_virtual_clock_set(bool on);
void gui_virtual_clock_advance(uint64_t ns);

#endif

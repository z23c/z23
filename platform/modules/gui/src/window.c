/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: backend selection, event ring, timers, wake, CPU frame, PNG and
 * SHA3 of frames shared by every window backend. */
#include "gui_internal.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "base/safe_alloc.h"
#include "sha3/sha3.h"
#include "util/png_writer.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

static atomic_bool g_virtual;
static _Atomic uint64_t g_virtual_ns;

void gui_virtual_clock_set(bool on) { atomic_store(&g_virtual, on); }
void gui_virtual_clock_advance(uint64_t ns)
{
    atomic_fetch_add(&g_virtual_ns, ns);
}

uint64_t gui_now_ns(void)
{
    if (atomic_load(&g_virtual)) return atomic_load(&g_virtual_ns);
#if defined(_WIN32)
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (uint64_t)((double)c.QuadPart * 1e9 / (double)f.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts); // platform-ok: the window layer is itself an OS seam (Win32 uses QueryPerformanceCounter above)
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

static void set_err(char *err, size_t cap, const char *msg)
{
    if (err && cap) snprintf(err, cap, "%s", msg);
}

bool gui_window_open(const struct gui_window_desc *d, struct gui_window **out,
                     char *err, size_t err_cap)
{
    if (!d || !out || d->width <= 0 || d->height <= 0) {
        set_err(err, err_cap, "invalid window description");
        return false;
    }
    enum gui_backend_kind kind = d->backend;
#if defined(_WIN32)
    if (kind == GUI_BACKEND_AUTO) kind = GUI_BACKEND_WIN32;
#endif
    if (kind == GUI_BACKEND_AUTO || kind == GUI_BACKEND_X11) {
        set_err(err, err_cap,
                "no window backend on this platform; use --backend=headless");
        return false;
    }
    if (kind == GUI_BACKEND_HEADLESS && d->surface == GUI_SURFACE_GL) {
        set_err(err, err_cap,
                "GL surfaces are not available on the headless backend");
        return false;
    }
    const struct gui_backend_ops *ops = &gui_backend_headless;
#if defined(_WIN32)
    if (kind == GUI_BACKEND_WIN32) ops = &gui_backend_win32;
#else
    if (kind == GUI_BACKEND_WIN32) {
        set_err(err, err_cap, "the win32 backend is not built on this platform");
        return false;
    }
#endif
    struct gui_window *w = zcl_calloc(1, sizeof(*w), "gui_window");
    if (!w) {
        set_err(err, err_cap, "out of memory opening a window");
        return false;
    }
    w->ops = ops;
    w->kind = kind;
    w->surface = d->surface ? d->surface : GUI_SURFACE_CPU;
    w->scale = 1.0f;
    w->min_w = d->min_width;
    w->min_h = d->min_height;
    atomic_init(&w->wake_pending, false);
    if (!ops->open(w, d, err, err_cap)) {
        free(w);
        return false;
    }
    *out = w;
    return true;
}

void gui_window_close(struct gui_window *w)
{
    if (!w) return;
    w->ops->close(w);
    free(w->fb);
    free(w);
}

void gui_ring_push(struct gui_window *w, const struct gui_event *ev)
{
    struct gui_event e = *ev;
    if (!e.time_ns) e.time_ns = gui_now_ns();
    if (w->count == GUI_RING_CAP) {
        /* Full: coalesce into the newest same-kind move, else drop; a close
         * request always replaces the newest entry. */
        size_t last = (w->head + w->count - 1) % GUI_RING_CAP;
        if (e.type == GUI_EV_CLOSE ||
            ((e.type == GUI_EV_MOUSE_MOVE || e.type == GUI_EV_MOUSE_RELATIVE) &&
             w->ring[last].type == e.type))
            w->ring[last] = e;
        return;
    }
    w->ring[(w->head + w->count) % GUI_RING_CAP] = e;
    w->count++;
}

bool gui_window_timer_set(struct gui_window *w, uint32_t id, uint32_t ms,
                          bool repeat)
{
    if (!w) return false;
    struct gui_timer *slot = NULL;
    for (size_t i = 0; i < GUI_TIMER_CAP; i++) {
        if (w->timers[i].used && w->timers[i].id == id) {
            slot = &w->timers[i];
            break;
        }
        if (!w->timers[i].used && !slot) slot = &w->timers[i];
    }
    if (!slot) return false;
    *slot = (struct gui_timer){ .used = true, .repeat = repeat, .id = id,
        .interval_ms = ms,
        .due_ns = gui_now_ns() + (uint64_t)ms * 1000000ull };
    return true;
}

void gui_window_timer_cancel(struct gui_window *w, uint32_t id)
{
    if (!w) return;
    for (size_t i = 0; i < GUI_TIMER_CAP; i++)
        if (w->timers[i].used && w->timers[i].id == id)
            w->timers[i].used = false;
}

/* Queue an event for the earliest expired timer. Returns true if queued. */
static bool timers_expire(struct gui_window *w, uint64_t now)
{
    struct gui_timer *best = NULL;
    for (size_t i = 0; i < GUI_TIMER_CAP; i++)
        if (w->timers[i].used && w->timers[i].due_ns <= now &&
            (!best || w->timers[i].due_ns < best->due_ns))
            best = &w->timers[i];
    if (!best) return false;
    struct gui_event e = { .type = GUI_EV_TIMER, .timer = { best->id } };
    gui_ring_push(w, &e);
    if (best->repeat) {
        uint64_t step = (uint64_t)(best->interval_ms ? best->interval_ms : 1) *
                        1000000ull;
        best->due_ns += step;
        if (best->due_ns <= now) best->due_ns = now + step;
    } else {
        best->used = false;
    }
    return true;
}

static bool pop(struct gui_window *w, struct gui_event *ev)
{
    if (!w->count) return false;
    if (ev) *ev = w->ring[w->head];
    w->head = (w->head + 1) % GUI_RING_CAP;
    w->count--;
    return true;
}

/* Milliseconds to block: the caller's remaining time bounded by the next
 * timer. -1 means no bound at all. */
static int64_t wait_budget(const struct gui_window *w, int64_t remain,
                           uint64_t now)
{
    for (size_t i = 0; i < GUI_TIMER_CAP; i++) {
        if (!w->timers[i].used) continue;
        int64_t d = w->timers[i].due_ns > now
            ? (int64_t)((w->timers[i].due_ns - now + 999999ull) / 1000000ull)
            : 0;
        if (remain < 0 || d < remain) remain = d;
    }
    return remain > INT32_MAX ? INT32_MAX : remain;
}

bool gui_window_wait(struct gui_window *w, int32_t timeout_ms,
                     struct gui_event *ev)
{
    if (!w) return false;
    uint64_t start = gui_now_ns();
    bool waited = false;
    for (;;) {
        if (pop(w, ev)) return true;
        if (atomic_exchange(&w->wake_pending, false)) {
            if (ev)
                *ev = (struct gui_event){ .type = GUI_EV_WAKE,
                                          .time_ns = gui_now_ns() };
            return true;
        }
        uint64_t now = gui_now_ns();
        if (timers_expire(w, now)) continue;
        int64_t remain = -1;
        if (timeout_ms >= 0) {
            remain = (int64_t)timeout_ms - (int64_t)((now - start) / 1000000ull);
            if (remain < 0) remain = 0;
            if (remain == 0 && waited) return false;
        }
        w->ops->wait_native(w, (int32_t)wait_budget(w, remain, now));
        waited = true;
    }
}

void gui_window_wake(struct gui_window *w)
{
    if (!w) return;
    atomic_store(&w->wake_pending, true);
    w->ops->wake(w);
}

void gui_window_size(const struct gui_window *w, int32_t *pw, int32_t *ph,
                     float *scale)
{
    if (!w) return;
    if (pw) *pw = w->w;
    if (ph) *ph = w->h;
    if (scale) *scale = w->scale;
}

void gui_window_set_title(struct gui_window *w, const char *utf8)
{
    if (w && utf8 && w->ops->set_title) w->ops->set_title(w, utf8);
}
void gui_window_set_cursor(struct gui_window *w, enum gui_cursor c)
{
    if (w && w->ops->set_cursor) w->ops->set_cursor(w, c);
}
bool gui_window_set_mouse_mode(struct gui_window *w, enum gui_mouse_mode m)
{
    return w && w->ops->set_mouse_mode && w->ops->set_mouse_mode(w, m);
}
bool gui_window_set_fullscreen(struct gui_window *w, bool on)
{
    return w && w->ops->set_fullscreen && w->ops->set_fullscreen(w, on);
}
void gui_window_set_text_input(struct gui_window *w, bool on,
                               struct gui_rect caret)
{
    (void)w; (void)on; (void)caret; /* IME position hint: later lane */
}
bool gui_clipboard_set_text(struct gui_window *w, const char *utf8, size_t len)
{
    return w && utf8 && len <= GUI_CLIP_CAP && w->ops->clip_set &&
           w->ops->clip_set(w, utf8, len);
}
size_t gui_clipboard_get_text(struct gui_window *w, char *buf, size_t cap)
{
    if (!w || !buf || !cap || !w->ops->clip_get) return 0;
    return w->ops->clip_get(w, buf, cap);
}

bool gui_cpu_acquire(struct gui_window *w, struct gui_cpu_frame *out)
{
    if (!w || !out || w->surface != GUI_SURFACE_CPU || w->w <= 0 || w->h <= 0)
        return false;
    if (!w->fb || w->fb_w != w->w || w->fb_h != w->h) {
        uint32_t *fb = zcl_calloc((size_t)w->w * (size_t)w->h, 4,
                                  "gui_framebuffer");
        if (!fb) {
            fprintf(stderr, "gui: cannot allocate %dx%d framebuffer\n", w->w,
                    w->h);
            return false;
        }
        free(w->fb);
        w->fb = fb;
        w->fb_w = w->w;
        w->fb_h = w->h;
    }
    *out = (struct gui_cpu_frame){ w->fb, w->fb_w, w->fb_h, w->fb_w, w->scale };
    return true;
}

bool gui_cpu_present(struct gui_window *w, const struct gui_rect *rects,
                     size_t n)
{
    if (!w || !w->fb || w->surface != GUI_SURFACE_CPU) return false;
    return w->ops->present(w, rects, n);
}

bool gui_gl_make_current(struct gui_window *w)
{
    return w && w->surface == GUI_SURFACE_GL && w->ops->gl_make_current &&
           w->ops->gl_make_current(w);
}
bool gui_gl_swap(struct gui_window *w)
{
    return w && w->surface == GUI_SURFACE_GL && w->ops->gl_swap &&
           w->ops->gl_swap(w);
}
bool gui_gl_set_swap_interval(struct gui_window *w, int interval)
{
    return w && w->ops->gl_interval && w->ops->gl_interval(w, interval);
}
void *gui_gl_proc(struct gui_window *w, const char *name)
{
    return (w && name && w->ops->gl_proc) ? w->ops->gl_proc(w, name) : NULL;
}
bool gui_gl_available(enum gui_backend_kind b)
{
#if defined(_WIN32)
    if (b == GUI_BACKEND_AUTO || b == GUI_BACKEND_WIN32)
        return gui_win32_gl_probe();
#else
    (void)b;
#endif
    return false;
}

void gui_frame_sha3(const struct gui_cpu_frame *f, uint8_t out[32])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    unsigned char hdr[8];
    for (int i = 0; i < 4; i++) {
        hdr[i] = (unsigned char)((uint32_t)f->width >> (8 * i));
        hdr[4 + i] = (unsigned char)((uint32_t)f->height >> (8 * i));
    }
    sha3_256_write(&c, hdr, 8);
    for (int32_t y = 0; y < f->height; y++) {
        unsigned char row[3 * 4096];
        for (int32_t x0 = 0; x0 < f->width; x0 += 4096) {
            int32_t n = f->width - x0 > 4096 ? 4096 : f->width - x0;
            for (int32_t x = 0; x < n; x++) {
                uint32_t p = f->pixels[(size_t)y * (size_t)f->stride_px +
                                       (size_t)(x0 + x)];
                row[3 * x] = (unsigned char)(p >> 16);
                row[3 * x + 1] = (unsigned char)(p >> 8);
                row[3 * x + 2] = (unsigned char)p;
            }
            sha3_256_write(&c, row, (size_t)n * 3u);
        }
    }
    sha3_256_finalize(&c, out);
}

static FILE *open_utf8(const char *path)
{
#if defined(_WIN32)
    wchar_t wp[1024];
    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wp, 1024) <= 0) return NULL;
    return _wfopen(wp, L"wb");
#else
    return fopen(path, "wb");
#endif
}

/* XRGB rows to packed RGB; the caller frees. NULL on allocation failure. */
static uint8_t *frame_to_rgb(const struct gui_cpu_frame *f)
{
    size_t px = (size_t)f->width * (size_t)f->height;
    uint8_t *rgb = zcl_malloc(px * 3u, "gui_png_rgb");
    if (!rgb) return NULL;
    for (int32_t y = 0; y < f->height; y++)
        for (int32_t x = 0; x < f->width; x++) {
            uint32_t p = f->pixels[(size_t)y * (size_t)f->stride_px + (size_t)x];
            uint8_t *o = rgb + ((size_t)y * (size_t)f->width + (size_t)x) * 3u;
            o[0] = (uint8_t)(p >> 16);
            o[1] = (uint8_t)(p >> 8);
            o[2] = (uint8_t)p;
        }
    return rgb;
}

/* Encode to a heap PNG (caller frees); *len is its size. */
static uint8_t *encode_png(const uint8_t *rgb, const struct gui_cpu_frame *f, size_t *len)
{
    size_t need = 0;
    if (!png_encode_rgb(rgb, (uint32_t)f->width, (uint32_t)f->height, NULL, 0, &need) || !need) return NULL;
    uint8_t *png = zcl_malloc(need, "gui_png_bytes");
    if (!png) return NULL;
    if (!png_encode_rgb(rgb, (uint32_t)f->width, (uint32_t)f->height, png, need, len)) {
        free(png);
        return NULL;
    }
    return png;
}

bool gui_frame_write_png(const struct gui_cpu_frame *f, const char *path_utf8)
{
    if (!f || !f->pixels || !path_utf8 || f->width <= 0 || f->height <= 0) return false;
    uint8_t *rgb = frame_to_rgb(f);
    size_t got = 0;
    uint8_t *png = rgb ? encode_png(rgb, f, &got) : NULL;
    bool ok = false;
    if (png) {
        FILE *fp = open_utf8(path_utf8);
        ok = fp && fwrite(png, 1, got, fp) == got;
        if (fp && fclose(fp) != 0) ok = false;
        if (!ok) fprintf(stderr, "gui: cannot write PNG %s\n", path_utf8);
    }
    free(png);
    free(rgb);
    return ok;
}

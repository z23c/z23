/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Darwin CPU window. AppKit, libobjc and CoreFoundation are loaded
 * at runtime so gui_window_open can present a frame without a new link
 * dependency. Other hosts compile only the stub. */
#if !defined(__APPLE__)
int gui_cocoa_backend_compiled_here(void)
{
    return 0;
}
#else
#include "gui_internal.h"

#include "base/safe_alloc.h"
#include "gui/draw.h"

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef struct objc_object *cocoa_id;
typedef struct objc_selector *cocoa_SEL;
typedef struct objc_class *cocoa_Class;
struct cocoa_rect { double x, y, w, h; };
struct cocoa_point { double x, y; };
struct cocoa_size { double w, h; };

struct cocoa_api {
    void *appkit;
    void *objc;
    void *cf;
    cocoa_id (*get_class)(const char *);
    cocoa_SEL (*sel)(const char *);
    void *msg;
    void *msg_stret;
    cocoa_Class (*alloc_class)(cocoa_Class, const char *, size_t);
    void (*register_class)(cocoa_Class);
    int (*add_method)(cocoa_Class, cocoa_SEL, void *, const char *);
    void (*cf_wake)(void *);
    void *(*cf_main)(void);
    cocoa_id color_space;
    cocoa_id run_mode;
};

struct cocoa_win {
    cocoa_id window;
    cocoa_id view;
    cocoa_id delegate;
    uint8_t *rgba;
    int32_t rgba_w, rgba_h;
    struct cocoa_rect saved_frame;
    unsigned long saved_style;
    bool fullscreen;
    bool presented;
};

static struct cocoa_api g_api;
static struct {
    cocoa_id delegate;
    struct gui_window *win;
} g_slot[4];

static void cocoa_err(char *err, size_t cap, const char *msg)
{
    if (err && cap) snprintf(err, cap, "%s", msg);
}

static bool cocoa_bind_fn(void *sym, void *dst, size_t n)
{
    if (!sym || !dst || sizeof(sym) != n) return false;
    memcpy(dst, &sym, n);
    return true;
}

static cocoa_id cocoa_symbol(void *lib, const char *name)
{
    void *sym = lib ? dlsym(lib, name) : NULL;
    cocoa_id value = NULL;
    if (!sym) return NULL;
    memcpy(&value, sym, sizeof value);
    return value;
}

static bool cocoa_open_libs(void)
{
    g_api.objc = dlopen("/usr/lib/libobjc.A.dylib", RTLD_NOW | RTLD_GLOBAL);
    g_api.appkit = dlopen("/System/Library/Frameworks/AppKit.framework/AppKit",
                          RTLD_NOW | RTLD_GLOBAL);
    g_api.cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
                      RTLD_NOW | RTLD_GLOBAL);
    return g_api.objc && g_api.appkit && g_api.cf;
}

static bool cocoa_bind_all(void)
{
    struct { void *lib; const char *name; void *dst; size_t n; } row[] = {
        { g_api.objc, "objc_msgSend", &g_api.msg, sizeof g_api.msg },
        { g_api.objc, "sel_registerName", &g_api.sel, sizeof g_api.sel },
        { g_api.objc, "objc_getClass", &g_api.get_class, sizeof g_api.get_class },
        { g_api.objc, "objc_allocateClassPair", &g_api.alloc_class, sizeof g_api.alloc_class },
        { g_api.objc, "objc_registerClassPair", &g_api.register_class, sizeof g_api.register_class },
        { g_api.objc, "class_addMethod", &g_api.add_method, sizeof g_api.add_method },
        { g_api.cf, "CFRunLoopWakeUp", &g_api.cf_wake, sizeof g_api.cf_wake },
        { g_api.cf, "CFRunLoopGetMain", &g_api.cf_main, sizeof g_api.cf_main },
    };
    for (size_t i = 0; i < sizeof row / sizeof row[0]; i++) {
        void *sym = row[i].lib ? dlsym(row[i].lib, row[i].name) : NULL;
        if (!cocoa_bind_fn(sym, row[i].dst, row[i].n)) return false;
    }
    return true;
}

/* Intel returns a 32-byte NSRect through objc_msgSend_stret. arm64 keeps
 * the struct return on objc_msgSend, and that symbol is absent there. */
static bool cocoa_bind_stret(void)
{
    void *sym = g_api.objc ? dlsym(g_api.objc, "objc_msgSend_stret") : NULL;
    if (!cocoa_bind_fn(sym, &g_api.msg_stret, sizeof g_api.msg_stret))
        g_api.msg_stret = g_api.msg;
    return g_api.msg_stret != NULL;
}

static bool cocoa_load(char *err, size_t cap)
{
    if (g_api.msg) return true;
    if (!cocoa_open_libs() || !cocoa_bind_all() || !cocoa_bind_stret()) {
        cocoa_err(err, cap, "Cocoa could not be loaded");
        return false;
    }
    g_api.color_space = cocoa_symbol(g_api.appkit, "NSDeviceRGBColorSpace");
    g_api.run_mode = cocoa_symbol(g_api.appkit, "NSDefaultRunLoopMode");
    if (!g_api.color_space || !g_api.run_mode) {
        cocoa_err(err, cap, "Cocoa could not be loaded");
        return false;
    }
    return true;
}

static cocoa_SEL cocoa_sel(const char *name) { return g_api.sel(name); }

static cocoa_id cocoa_msg(cocoa_id obj, const char *name)
{
    cocoa_id (*fn)(cocoa_id, cocoa_SEL);
    memcpy(&fn, &g_api.msg, sizeof fn);
    return fn(obj, cocoa_sel(name));
}

static void cocoa_void0(cocoa_id obj, const char *name)
{
    void (*fn)(cocoa_id, cocoa_SEL);
    memcpy(&fn, &g_api.msg, sizeof fn);
    fn(obj, cocoa_sel(name));
}

static void cocoa_void_id(cocoa_id obj, const char *name, cocoa_id arg)
{
    void (*fn)(cocoa_id, cocoa_SEL, cocoa_id);
    memcpy(&fn, &g_api.msg, sizeof fn);
    fn(obj, cocoa_sel(name), arg);
}

static void cocoa_void_long(cocoa_id obj, const char *name, long arg)
{
    void (*fn)(cocoa_id, cocoa_SEL, long);
    memcpy(&fn, &g_api.msg, sizeof fn);
    fn(obj, cocoa_sel(name), arg);
}

static void cocoa_void_ulong(cocoa_id obj, const char *name, unsigned long arg)
{
    void (*fn)(cocoa_id, cocoa_SEL, unsigned long);
    memcpy(&fn, &g_api.msg, sizeof fn);
    fn(obj, cocoa_sel(name), arg);
}

static void cocoa_void_bool(cocoa_id obj, const char *name, signed char arg)
{
    void (*fn)(cocoa_id, cocoa_SEL, signed char);
    memcpy(&fn, &g_api.msg, sizeof fn);
    fn(obj, cocoa_sel(name), arg);
}

static double cocoa_double(cocoa_id obj, const char *name)
{
    double (*fn)(cocoa_id, cocoa_SEL);
    memcpy(&fn, &g_api.msg, sizeof fn);
    return fn(obj, cocoa_sel(name));
}

static unsigned long cocoa_ulong(cocoa_id obj, const char *name)
{
    unsigned long (*fn)(cocoa_id, cocoa_SEL);
    memcpy(&fn, &g_api.msg, sizeof fn);
    return fn(obj, cocoa_sel(name));
}

static long cocoa_long(cocoa_id obj, const char *name)
{
    long (*fn)(cocoa_id, cocoa_SEL);
    memcpy(&fn, &g_api.msg, sizeof fn);
    return fn(obj, cocoa_sel(name));
}

static signed char cocoa_bool(cocoa_id obj, const char *name)
{
    signed char (*fn)(cocoa_id, cocoa_SEL);
    memcpy(&fn, &g_api.msg, sizeof fn);
    return fn(obj, cocoa_sel(name));
}

static const char *cocoa_utf8(cocoa_id obj, const char *name)
{
    const char *(*fn)(cocoa_id, cocoa_SEL);
    memcpy(&fn, &g_api.msg, sizeof fn);
    return fn(obj, cocoa_sel(name));
}

static struct cocoa_rect cocoa_bounds(cocoa_id view)
{
    struct cocoa_rect (*fn)(cocoa_id, cocoa_SEL);
    memcpy(&fn, &g_api.msg_stret, sizeof fn);
    return fn(view, cocoa_sel("bounds"));
}

static struct cocoa_point cocoa_location(cocoa_id ev)
{
    struct cocoa_point (*fn)(cocoa_id, cocoa_SEL);
    memcpy(&fn, &g_api.msg, sizeof fn);
    return fn(ev, cocoa_sel("locationInWindow"));
}

static struct cocoa_point cocoa_convert(cocoa_id view, struct cocoa_point p)
{
    struct cocoa_point (*fn)(cocoa_id, cocoa_SEL, struct cocoa_point, cocoa_id);
    memcpy(&fn, &g_api.msg, sizeof fn);
    return fn(view, cocoa_sel("convertPoint:fromView:"), p, NULL);
}

static cocoa_id cocoa_pool_push(void)
{
    cocoa_id pool = cocoa_msg(g_api.get_class("NSAutoreleasePool"), "alloc");
    return pool ? cocoa_msg(pool, "init") : NULL;
}

static void cocoa_release(cocoa_id obj)
{
    if (obj) cocoa_void0(obj, "release");
}

static struct gui_window *cocoa_for_delegate(cocoa_id delegate)
{
    for (size_t i = 0; i < sizeof g_slot / sizeof g_slot[0]; i++)
        if (g_slot[i].delegate == delegate) return g_slot[i].win;
    return NULL;
}

static void cocoa_sync_size(struct gui_window *w);

static signed char cocoa_should_close(cocoa_id self, cocoa_SEL cmd, cocoa_id sender)
{
    struct gui_window *w = cocoa_for_delegate(self);
    struct gui_event ev = { .type = GUI_EV_CLOSE };
    (void)cmd;
    (void)sender;
    if (w) gui_ring_push(w, &ev);
    return 0;
}

/* AppKit calls this inside setFrame and inside a live drag, before the
 * event wait returns. */
static void cocoa_did_resize(cocoa_id self, cocoa_SEL cmd, cocoa_id note)
{
    struct gui_window *w = cocoa_for_delegate(self);
    (void)cmd;
    (void)note;
    if (w) cocoa_sync_size(w);
}

static bool cocoa_delegate_class(void)
{
    static cocoa_Class klass;
    cocoa_Class made;
    void *imp = NULL;
    void *resize_imp = NULL;
    signed char (*method)(cocoa_id, cocoa_SEL, cocoa_id) = cocoa_should_close;
    void (*resize)(cocoa_id, cocoa_SEL, cocoa_id) = cocoa_did_resize;
    if (klass) return true;
    if (sizeof imp != sizeof method || sizeof resize_imp != sizeof resize) return false;
    memcpy(&imp, &method, sizeof imp);
    memcpy(&resize_imp, &resize, sizeof resize_imp);
    made = g_api.alloc_class((cocoa_Class)g_api.get_class("NSObject"),
                             "Z23GuiCocoaDelegate", 0);
    if (!made || !g_api.add_method(made, cocoa_sel("windowShouldClose:"),
                                   imp, "c@:@"))
        return false;
    if (!g_api.add_method(made, cocoa_sel("windowDidResize:"), resize_imp, "v@:@"))
        return false;
    g_api.register_class(made);
    klass = made;
    return true;
}

static bool cocoa_remember(struct gui_window *w, cocoa_id delegate)
{
    for (size_t i = 0; i < sizeof g_slot / sizeof g_slot[0]; i++) {
        if (g_slot[i].win) continue;
        g_slot[i].win = w;
        g_slot[i].delegate = delegate;
        return true;
    }
    return false;
}

static void cocoa_forget(struct gui_window *w)
{
    for (size_t i = 0; i < sizeof g_slot / sizeof g_slot[0]; i++) {
        if (g_slot[i].win != w) continue;
        g_slot[i].win = NULL;
        g_slot[i].delegate = NULL;
    }
}

static cocoa_id cocoa_string(const char *utf8)
{
    cocoa_id obj = cocoa_msg(g_api.get_class("NSString"), "alloc");
    cocoa_id (*fn)(cocoa_id, cocoa_SEL, const char *);
    if (!obj) return NULL;
    memcpy(&fn, &g_api.msg, sizeof fn);
    return fn(obj, cocoa_sel("initWithUTF8String:"), utf8 ? utf8 : "");
}

static struct cocoa_win *cocoa_state(const struct gui_window *w)
{
    return w ? (struct cocoa_win *)w->be : NULL;
}

static struct gui_window *cocoa_for_nswindow(cocoa_id nswin)
{
    size_t i;
    if (!nswin) return NULL;
    for (i = 0; i < sizeof g_slot / sizeof g_slot[0]; i++) {
        struct gui_window *gw = g_slot[i].win;
        struct cocoa_win *c = cocoa_state(gw);
        if (c && c->window == nswin) return gw;
    }
    return NULL;
}

static void cocoa_min_size(cocoa_id win, const struct gui_window *w)
{
    struct cocoa_size size;
    void (*fn)(cocoa_id, cocoa_SEL, struct cocoa_size);
    if (!w || w->min_w <= 0 || w->min_h <= 0) return;
    size.w = (double)w->min_w;
    size.h = (double)w->min_h;
    memcpy(&fn, &g_api.msg, sizeof fn);
    fn(win, cocoa_sel("setContentMinSize:"), size);
}

static int32_t cocoa_round_px(double v)
{
    if (v <= 0.0) return 0;
    if (v >= 8192.0) return 8192;
    return (int32_t)(v + 0.5);
}

static void cocoa_apply_size(struct gui_window *w, struct cocoa_rect bounds, double scale)
{
    int32_t pw, ph;
    struct gui_event ev = { .type = GUI_EV_RESIZE };
    if (!(scale > 0.0) || scale > 4.0) scale = 1.0;
    pw = cocoa_round_px(bounds.w * scale);
    ph = cocoa_round_px(bounds.h * scale);
    if (pw < 1 || ph < 1) return;
    if (w->w > 0 && (pw > w->w * 4 || ph > w->h * 4)) return;
    if (pw == w->w && ph == w->h && w->scale == (float)scale) return;
    w->w = pw;
    w->h = ph;
    w->scale = (float)scale;
    ev.size.w = pw;
    ev.size.h = ph;
    ev.size.scale = w->scale;
    gui_ring_push(w, &ev);
}

static void cocoa_sync_size(struct gui_window *w)
{
    struct cocoa_win *c = cocoa_state(w);
    if (!c || !c->view || !c->window) return;
    cocoa_apply_size(w, cocoa_bounds(c->view), cocoa_double(c->window, "backingScaleFactor"));
}

static bool cocoa_prepare(char *err, size_t cap)
{
    cocoa_id app;
    if (!cocoa_load(err, cap) || !cocoa_delegate_class()) {
        if (err && cap && !err[0]) cocoa_err(err, cap, "Cocoa could not be loaded");
        return false;
    }
    app = cocoa_msg(g_api.get_class("NSApplication"), "sharedApplication");
    if (!app) {
        cocoa_err(err, cap, "Cocoa could not be loaded");
        return false;
    }
    cocoa_void_long(app, "setActivationPolicy:", 0);
    return true;
}

static unsigned long cocoa_style(const struct gui_window_desc *d)
{
    unsigned long style = 1ul | 2ul | 4ul;
    if ((d->flags & GUI_WINDOW_RESIZABLE) != 0) style |= 8ul;
    return style;
}

static cocoa_id cocoa_new_window(struct cocoa_rect rect, unsigned long style)
{
    cocoa_id (*init_win)(cocoa_id, cocoa_SEL, struct cocoa_rect, unsigned long,
                         unsigned long, signed char);
    cocoa_id win = cocoa_msg(g_api.get_class("NSWindow"), "alloc");
    if (!win) return NULL;
    memcpy(&init_win, &g_api.msg, sizeof init_win);
    return init_win(win, cocoa_sel("initWithContentRect:styleMask:backing:defer:"),
                    rect, style, 2ul, 0);
}

static cocoa_id cocoa_new_view(struct cocoa_rect rect)
{
    cocoa_id (*init_view)(cocoa_id, cocoa_SEL, struct cocoa_rect);
    cocoa_id view = cocoa_msg(g_api.get_class("NSImageView"), "alloc");
    if (!view) return NULL;
    memcpy(&init_view, &g_api.msg, sizeof init_view);
    return init_view(view, cocoa_sel("initWithFrame:"), rect);
}

static cocoa_id cocoa_new_delegate(void)
{
    cocoa_id delegate = cocoa_msg((cocoa_id)g_api.get_class("Z23GuiCocoaDelegate"), "alloc");
    return delegate ? cocoa_msg(delegate, "init") : NULL;
}

static bool cocoa_keep(struct gui_window *w, struct cocoa_win *c, cocoa_id win,
                       cocoa_id view, cocoa_id delegate, char *err, size_t cap)
{
    if (!win || !view || !delegate || !cocoa_remember(w, delegate)) {
        cocoa_release(delegate);
        cocoa_release(view);
        cocoa_release(win);
        free(c);
        cocoa_err(err, cap, "Cocoa window could not be created");
        return false;
    }
    c->window = win;
    c->view = view;
    c->delegate = delegate;
    w->be = c;
    return true;
}

static void cocoa_show(struct cocoa_win *c, const struct gui_window_desc *d)
{
    cocoa_id app;
    if ((d->flags & GUI_WINDOW_HIDDEN) != 0) return;
    app = cocoa_msg(g_api.get_class("NSApplication"), "sharedApplication");
    cocoa_void_id(c->window, "makeKeyAndOrderFront:", NULL);
    cocoa_void_bool(app, "activateIgnoringOtherApps:", 1);
}

/* Win32 covers the monitor immediately. A Cocoa Space transition does not
 * finish before open returns, so fullscreen is a borderless screen frame. */
static struct cocoa_rect cocoa_rect(cocoa_id obj, const char *name)
{
    struct cocoa_rect (*fn)(cocoa_id, cocoa_SEL);
    memcpy(&fn, &g_api.msg_stret, sizeof fn);
    return fn(obj, cocoa_sel(name));
}

static void cocoa_set_frame(cocoa_id obj, const char *name, struct cocoa_rect frame)
{
    void (*fn)(cocoa_id, cocoa_SEL, struct cocoa_rect);
    memcpy(&fn, &g_api.msg, sizeof fn);
    fn(obj, cocoa_sel(name), frame);
}

static void cocoa_set_window_frame(cocoa_id win, struct cocoa_rect frame)
{
    void (*fn)(cocoa_id, cocoa_SEL, struct cocoa_rect, signed char);
    memcpy(&fn, &g_api.msg, sizeof fn);
    fn(win, cocoa_sel("setFrame:display:"), frame, 1);
}

/* Move the window frame and return. The delegate records the new content
 * size, so this does not read the view back itself. */
bool gui_cocoa_move_frame(struct gui_window *w, double width, double height)
{
    struct cocoa_win *c = cocoa_state(w);
    struct cocoa_rect frame;
    if (!c || !c->window || width < 1.0 || height < 1.0) return false;
    frame = cocoa_rect(c->window, "frame");
    frame.w = width;
    frame.h = height;
    cocoa_set_window_frame(c->window, frame);
    return true;
}

static bool cocoa_near(double got, double want)
{
    return got + 1.0 >= want;
}

/* Borderless content should fill the window, even when the old frame was
 * already as large as the screen. */
static bool cocoa_view_matches(struct cocoa_win *c)
{
    struct cocoa_rect bounds = cocoa_bounds(c->view);
    struct cocoa_rect frame = cocoa_rect(c->window, "frame");
    return cocoa_near(bounds.w, frame.w) && cocoa_near(bounds.h, frame.h);
}

/* Record a view size even when it jumps by more than the ordinary resize
 * guard. Fullscreen is that jump. */
static bool cocoa_commit_view(struct gui_window *w, struct cocoa_win *c)
{
    struct cocoa_rect bounds = cocoa_bounds(c->view);
    double scale = cocoa_double(c->window, "backingScaleFactor");
    int32_t pw, ph;
    struct gui_event ev = { .type = GUI_EV_RESIZE };
    if (!(scale > 0.0) || scale > 4.0) scale = 1.0;
    pw = cocoa_round_px(bounds.w * scale);
    ph = cocoa_round_px(bounds.h * scale);
    if (pw < 1 || ph < 1) return false;
    if (pw == w->w && ph == w->h && w->scale == (float)scale) return true;
    w->w = pw;
    w->h = ph;
    w->scale = (float)scale;
    ev.size.w = pw;
    ev.size.h = ph;
    ev.size.scale = (float)scale;
    gui_ring_push(w, &ev);
    return true;
}

static unsigned long g_present_saved;
static int g_present_count;

/* HideDock | HideMenuBar, added to options the process already set. Replacing
 * the set would clear an unrelated bit for the whole time the window covers
 * the screen. Auto-hide is the other value of each pair, and AppKit throws
 * if both are set, so those two bits are cleared only while the window is
 * up. The window stays at the normal level, so another app can cover it.
 * The options are process-wide, so the first entry saves them and the last
 * exit restores them. */
static void cocoa_present_enter(void)
{
    cocoa_id app = cocoa_msg(g_api.get_class("NSApplication"), "sharedApplication");
    unsigned long now = cocoa_ulong(app, "presentationOptions");
    if (g_present_count == 0)
        g_present_saved = now;
    g_present_count++;
    now &= ~(1ul | 4ul);
    cocoa_void_ulong(app, "setPresentationOptions:", now | 2ul | 8ul);
}

static void cocoa_present_leave(void)
{
    cocoa_id app;
    if (g_present_count <= 0) return;
    g_present_count--;
    if (g_present_count > 0) return;
    app = cocoa_msg(g_api.get_class("NSApplication"), "sharedApplication");
    cocoa_void_ulong(app, "setPresentationOptions:", g_present_saved);
}

unsigned long gui_cocoa_presentation(void)
{
    cocoa_id app = cocoa_msg(g_api.get_class("NSApplication"), "sharedApplication");
    if (!app) return 0;
    return cocoa_ulong(app, "presentationOptions");
}

void gui_cocoa_set_presentation(unsigned long options)
{
    cocoa_id app = cocoa_msg(g_api.get_class("NSApplication"), "sharedApplication");
    if (!app) return;
    cocoa_void_ulong(app, "setPresentationOptions:", options);
}

static bool cocoa_cover(struct cocoa_win *c)
{
    cocoa_id screen = cocoa_msg(c->window, "screen");
    struct cocoa_rect frame, view, now;
    if (!screen) screen = cocoa_msg(g_api.get_class("NSScreen"), "mainScreen");
    if (!screen) return false;
    frame = cocoa_rect(screen, "frame");
    if (frame.w < 1.0 || frame.h < 1.0) return false;
    c->saved_frame = cocoa_rect(c->window, "frame");
    c->saved_style = cocoa_ulong(c->window, "styleMask");
    cocoa_void_ulong(c->window, "setStyleMask:", 0ul);
    cocoa_set_window_frame(c->window, frame);
    view.x = 0.0;
    view.y = 0.0;
    view.w = frame.w;
    view.h = frame.h;
    cocoa_set_frame(c->view, "setFrame:", view);
    now = cocoa_rect(c->window, "frame");
    if (!cocoa_near(now.w, frame.w) || !cocoa_near(now.h, frame.h)) return false;
    return true;
}

static void cocoa_uncover(struct cocoa_win *c)
{
    cocoa_void_ulong(c->window, "setStyleMask:", c->saved_style);
    cocoa_set_window_frame(c->window, c->saved_frame);
}

static bool cocoa_fullscreen(struct gui_window *w, bool on)
{
    struct cocoa_win *c = cocoa_state(w);
    if (!c || !c->window || !c->view) return false;
    if (on == c->fullscreen) return true;
    if (on) {
        if (!cocoa_cover(c) || !cocoa_view_matches(c)) {
            if (c->saved_style) cocoa_uncover(c);
            return false;
        }
    } else {
        if (c->presented) cocoa_present_leave();
        c->presented = false;
        cocoa_uncover(c);
    }
    if (!cocoa_commit_view(w, c)) return false;
    /* A hidden window is not on screen, so it must not hide the Dock.
     * Only that window may restore the Dock when it leaves fullscreen. */
    if (on && cocoa_bool(c->window, "isVisible")) {
        cocoa_present_enter();
        c->presented = true;
    }
    c->fullscreen = on;
    return true;
}

static bool cocoa_open(struct gui_window *w, const struct gui_window_desc *d,
                       char *err, size_t cap)
{
    struct cocoa_win *c;
    cocoa_id win, view, delegate, title, pool;
    struct cocoa_rect rect;
    if (!cocoa_prepare(err, cap)) return false;
    c = zcl_calloc(1, sizeof(*c), "gui cocoa");
    if (!c) {
        cocoa_err(err, cap, "out of memory opening a cocoa window");
        return false;
    }
    pool = cocoa_pool_push();
    rect.x = 40;
    rect.y = 40;
    rect.w = d->width;
    rect.h = d->height;
    w->w = d->width;
    w->h = d->height;
    w->scale = 1.0f;
    win = cocoa_new_window(rect, cocoa_style(d));
    view = cocoa_new_view(rect);
    delegate = cocoa_new_delegate();
    if (!cocoa_keep(w, c, win, view, delegate, err, cap)) {
        cocoa_release(pool);
        return false;
    }
    title = cocoa_string(d->title_utf8);
    cocoa_void_id(win, "setTitle:", title);
    cocoa_release(title);
    cocoa_void_bool(win, "setReleasedWhenClosed:", 0);
    cocoa_void_id(win, "setDelegate:", delegate);
    cocoa_void_bool(win, "setAcceptsMouseMovedEvents:", 1);
    cocoa_min_size(win, w);
    cocoa_void_ulong(view, "setAutoresizingMask:", 18ul);
    cocoa_void_long(view, "setImageScaling:", 1);
    cocoa_void_id(win, "setContentView:", view);
    cocoa_sync_size(w);
    cocoa_show(c, d);
    if ((d->flags & GUI_WINDOW_FULLSCREEN) != 0)
        (void)gui_window_set_fullscreen(w, true);
    cocoa_release(pool);
    return true;
}

static void cocoa_close(struct gui_window *w)
{
    struct cocoa_win *c = cocoa_state(w);
    cocoa_id pool;
    if (!c) return;
    pool = cocoa_pool_push();
    if (c->fullscreen)
        (void)cocoa_fullscreen(w, false);
    cocoa_forget(w);
    if (c->view) cocoa_void_id(c->view, "setImage:", NULL);
    if (c->window) {
        cocoa_void_id(c->window, "setDelegate:", NULL);
        cocoa_void0(c->window, "close");
    }
    cocoa_release(c->delegate);
    cocoa_release(c->view);
    cocoa_release(c->window);
    free(c->rgba);
    free(c);
    w->be = NULL;
    cocoa_release(pool);
}

static enum gui_key cocoa_special(unsigned short code)
{
    static const unsigned short map[][2] = {
        {36, GUI_KEY_ENTER}, {76, GUI_KEY_ENTER}, {48, GUI_KEY_TAB},
        {51, GUI_KEY_BACKSPACE}, {53, GUI_KEY_ESCAPE}, {117, GUI_KEY_DELETE},
        {123, GUI_KEY_LEFT}, {124, GUI_KEY_RIGHT}, {125, GUI_KEY_DOWN},
        {126, GUI_KEY_UP}, {115, GUI_KEY_HOME}, {119, GUI_KEY_END},
        {116, GUI_KEY_PAGE_UP}, {121, GUI_KEY_PAGE_DOWN}, {49, GUI_KEY_SPACE},
        {122, GUI_KEY_F1}, {120, GUI_KEY_F2}, {99, GUI_KEY_F3}, {118, GUI_KEY_F4},
        {96, GUI_KEY_F5}, {97, GUI_KEY_F6}, {98, GUI_KEY_F7}, {100, GUI_KEY_F8},
        {101, GUI_KEY_F9}, {109, GUI_KEY_F10}, {103, GUI_KEY_F11}, {111, GUI_KEY_F12}
    };
    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++)
        if (map[i][0] == code) return (enum gui_key)map[i][1];
    return GUI_KEY_NONE;
}

static enum gui_key cocoa_key_of(unsigned short code, const char *utf8)
{
    enum gui_key key = cocoa_special(code);
    unsigned char ch;
    if (key != GUI_KEY_NONE) return key;
    if (!utf8 || utf8[1] != '\0') return GUI_KEY_NONE;
    ch = (unsigned char)utf8[0];
    if (ch >= 'a' && ch <= 'z') return (enum gui_key)(GUI_KEY_A + (ch - 'a'));
    if (ch >= 'A' && ch <= 'Z') return (enum gui_key)(GUI_KEY_A + (ch - 'A'));
    if (ch >= '0' && ch <= '9') return (enum gui_key)(GUI_KEY_0 + (ch - '0'));
    if (ch == ' ') return GUI_KEY_SPACE;
    return GUI_KEY_NONE;
}

static uint32_t cocoa_mods(unsigned long flags)
{
    uint32_t mods = 0;
    if ((flags & (1ul << 17)) != 0) mods |= GUI_MOD_SHIFT;
    if ((flags & (1ul << 18)) != 0) mods |= GUI_MOD_CTRL;
    if ((flags & (1ul << 19)) != 0) mods |= GUI_MOD_ALT;
    /* Command is the Mac shortcut modifier. Shared text commands read CTRL. */
    if ((flags & (1ul << 20)) != 0) mods |= GUI_MOD_SUPER | GUI_MOD_CTRL;
    return mods;
}

static void cocoa_point_px(struct gui_window *w, cocoa_id ev, int32_t *x, int32_t *y)
{
    struct cocoa_win *c = cocoa_state(w);
    struct cocoa_rect bounds = cocoa_bounds(c->view);
    struct cocoa_point p = cocoa_convert(c->view, cocoa_location(ev));
    double scale = w->scale > 0.0f ? (double)w->scale : 1.0;
    *x = cocoa_round_px(p.x * scale);
    *y = cocoa_round_px((bounds.h - p.y) * scale);
}

static bool cocoa_is_move(unsigned long type)
{
    return type == 5 || type == 6 || type == 7 || type == 27;
}

static bool cocoa_is_down(unsigned long type)
{
    return type == 1 || type == 3 || type == 25;
}

static uint8_t cocoa_button(unsigned long type)
{
    if (type == 3 || type == 4 || type == 7) return 2;
    if (type == 25 || type == 26) return 3;
    return 1;
}

static void cocoa_mouse(struct gui_window *w, cocoa_id ev, unsigned long type)
{
    struct gui_event out = {0};
    int32_t x = 0, y = 0;
    cocoa_point_px(w, ev, &x, &y);
    out.mods = cocoa_mods(cocoa_ulong(ev, "modifierFlags"));
    if (cocoa_is_move(type)) {
        out.type = GUI_EV_MOUSE_MOVE;
        out.move.x = x;
        out.move.y = y;
        gui_ring_push(w, &out);
        return;
    }
    out.type = GUI_EV_MOUSE_BUTTON;
    out.button.x = x;
    out.button.y = y;
    out.button.down = cocoa_is_down(type);
    out.button.button = cocoa_button(type);
    out.button.clicks = (uint8_t)cocoa_long(ev, "clickCount");
    gui_ring_push(w, &out);
}

static void cocoa_text(struct gui_window *w, cocoa_id ev, uint32_t mods)
{
    cocoa_id chars;
    const char *utf8;
    size_t i = 0, len;
    uint32_t cp;
    struct gui_event out;
    if ((mods & GUI_MOD_CTRL) != 0) return;
    chars = cocoa_msg(ev, "characters");
    utf8 = chars ? cocoa_utf8(chars, "UTF8String") : NULL;
    if (!utf8) return;
    len = strlen(utf8);
    cp = gui_utf8_next(utf8, len, &i);
    /* AppKit encodes arrows and function keys as U+F700..U+F8FF. */
    if (i != len || cp < 32u || cp == 0xFFFDu || (cp >= 0xF700u && cp <= 0xF8FFu))
        return;
    out = (struct gui_event){0};
    out.type = GUI_EV_TEXT;
    out.mods = mods;
    out.text.codepoint = cp;
    gui_ring_push(w, &out);
}

static void cocoa_key(struct gui_window *w, cocoa_id ev, bool down)
{
    cocoa_id chars = cocoa_msg(ev, "charactersIgnoringModifiers");
    const char *utf8 = chars ? cocoa_utf8(chars, "UTF8String") : NULL;
    unsigned short code = (unsigned short)cocoa_ulong(ev, "keyCode");
    struct gui_event out = {0};
    out.type = GUI_EV_KEY;
    out.mods = cocoa_mods(cocoa_ulong(ev, "modifierFlags"));
    out.key.key = cocoa_key_of(code, utf8);
    out.key.scancode = code;
    out.key.down = down;
    out.key.repeat = down && cocoa_bool(ev, "isARepeat") != 0;
    gui_ring_push(w, &out);
    if (down) cocoa_text(w, ev, out.mods);
}

static void cocoa_wheel(struct gui_window *w, cocoa_id ev)
{
    struct gui_event out = { .type = GUI_EV_MOUSE_WHEEL };
    double (*fn)(cocoa_id, cocoa_SEL);
    int32_t x = 0, y = 0;
    memcpy(&fn, &g_api.msg, sizeof fn);
    cocoa_point_px(w, ev, &x, &y);
    out.wheel.x = x;
    out.wheel.y = y;
    out.wheel.dy = gui_wheel_notch((float)fn(ev, cocoa_sel("scrollingDeltaY")),
                                   cocoa_bool(ev, "hasPreciseScrollingDeltas") != 0);
    out.mods = cocoa_mods(cocoa_ulong(ev, "modifierFlags"));
    gui_ring_push(w, &out);
}

static void cocoa_translate(struct gui_window *w, cocoa_id ev)
{
    unsigned long type = cocoa_ulong(ev, "type");
    if (type >= 1 && type <= 7) cocoa_mouse(w, ev, type);
    else if (type == 10 || type == 11) cocoa_key(w, ev, type == 10);
    else if (type == 22) cocoa_wheel(w, ev);
    else if (type == 25 || type == 26 || type == 27) cocoa_mouse(w, ev, type);
}

static void cocoa_wait(struct gui_window *w, int32_t ms)
{
    cocoa_id app = cocoa_msg(g_api.get_class("NSApplication"), "sharedApplication");
    cocoa_id until, ev, pool;
    cocoa_id (*next)(cocoa_id, cocoa_SEL, unsigned long, cocoa_id, cocoa_id, signed char);
    cocoa_id (*dated)(cocoa_id, cocoa_SEL, double);
    pool = cocoa_pool_push();
    if (ms < 0) until = cocoa_msg(g_api.get_class("NSDate"), "distantFuture");
    else {
        memcpy(&dated, &g_api.msg, sizeof dated);
        until = dated(g_api.get_class("NSDate"), cocoa_sel("dateWithTimeIntervalSinceNow:"),
                      (double)ms / 1000.0);
    }
    memcpy(&next, &g_api.msg, sizeof next);
    ev = next(app, cocoa_sel("nextEventMatchingMask:untilDate:inMode:dequeue:"),
              ~(unsigned long)0, until, g_api.run_mode, 1);
    if (ev) {
        cocoa_id owner = cocoa_msg(ev, "window");
        struct gui_window *dst = owner ? cocoa_for_nswindow(owner) : w;
        cocoa_void_id(app, "sendEvent:", ev);
        if (dst) {
            cocoa_translate(dst, ev);
            cocoa_sync_size(dst);
        }
    }
    cocoa_release(pool);
}

/* nextEvent does not return on CFRunLoopWakeUp. An application-defined
 * event posted at the front of the queue unblocks a wait from any thread. */
static cocoa_id cocoa_wake_event(void)
{
    cocoa_id (*other)(cocoa_id, cocoa_SEL, unsigned long, struct cocoa_point,
                      unsigned long, double, long, cocoa_id, short, long, long);
    struct cocoa_point origin = { 0, 0 };
    memcpy(&other, &g_api.msg, sizeof other);
    return other(g_api.get_class("NSEvent"),
                 cocoa_sel("otherEventWithType:location:modifierFlags:timestamp:"
                           "windowNumber:context:subtype:data1:data2:"),
                 15ul, origin, 0ul, 0.0, 0L, NULL, (short)0, 0L, 0L);
}

static void cocoa_wake(struct gui_window *w)
{
    cocoa_id app, ev, pool;
    void (*post)(cocoa_id, cocoa_SEL, cocoa_id, signed char);
    (void)w;
    if (!g_api.msg) return;
    pool = cocoa_pool_push();
    app = cocoa_msg(g_api.get_class("NSApplication"), "sharedApplication");
    ev = cocoa_wake_event();
    if (app && ev) {
        memcpy(&post, &g_api.msg, sizeof post);
        post(app, cocoa_sel("postEvent:atStart:"), ev, 1);
    }
    cocoa_release(pool);
}

static bool cocoa_dims_ok(const struct gui_window *w)
{
    if (!w->fb || w->fb_w <= 0 || w->fb_h <= 0) return false;
    if (w->fb_w > 8192 || w->fb_h > 8192) return false;
    if ((size_t)w->fb_w > (SIZE_MAX / 4u) / (size_t)w->fb_h) return false;
    return true;
}

static void cocoa_copy(const struct gui_window *w, uint8_t *dst)
{
    const uint32_t *src = w->fb;
    for (int32_t y = 0; y < w->fb_h; y++) {
        const uint32_t *row = src + (size_t)y * (size_t)w->fb_w;
        for (int32_t x = 0; x < w->fb_w; x++) {
            uint32_t px = row[x];
            dst[0] = (uint8_t)((px >> 16) & 255u);
            dst[1] = (uint8_t)((px >> 8) & 255u);
            dst[2] = (uint8_t)(px & 255u);
            dst[3] = 255u;
            dst += 4;
        }
    }
}

static uint8_t *cocoa_fill(struct gui_window *w, struct cocoa_win *c, bool *fresh)
{
    uint8_t *dst;
    *fresh = false;
    if (!cocoa_dims_ok(w)) return NULL;
    if (c->rgba && c->rgba_w == w->fb_w && c->rgba_h == w->fb_h) {
        cocoa_copy(w, c->rgba);
        return c->rgba;
    }
    dst = zcl_calloc((size_t)w->fb_w * (size_t)w->fb_h, 4u, "gui cocoa pixels");
    if (!dst) return NULL;
    *fresh = true;
    cocoa_copy(w, dst);
    return dst;
}

static cocoa_id cocoa_bitmap(struct gui_window *w, uint8_t *pix)
{
    unsigned char *planes[1];
    cocoa_id rep;
    cocoa_id (*init_rep)(cocoa_id, cocoa_SEL, unsigned char **, long, long, long, long,
                         signed char, signed char, cocoa_id, long, long);
    planes[0] = pix;
    rep = cocoa_msg(g_api.get_class("NSBitmapImageRep"), "alloc");
    if (!rep) return NULL;
    memcpy(&init_rep, &g_api.msg, sizeof init_rep);
    return init_rep(rep, cocoa_sel("initWithBitmapDataPlanes:pixelsWide:pixelsHigh:"
                                   "bitsPerSample:samplesPerPixel:hasAlpha:isPlanar:"
                                   "colorSpaceName:bytesPerRow:bitsPerPixel:"),
                    planes, w->fb_w, w->fb_h, 8, 4, 1, 0, g_api.color_space,
                    (long)w->fb_w * 4, 32);
}

static cocoa_id cocoa_image(struct gui_window *w, cocoa_id rep)
{
    struct cocoa_size size;
    cocoa_id image;
    cocoa_id (*init_image)(cocoa_id, cocoa_SEL, struct cocoa_size);
    double scale = w->scale > 0.0f ? (double)w->scale : 1.0;
    size.w = (double)w->fb_w / scale;
    size.h = (double)w->fb_h / scale;
    image = cocoa_msg(g_api.get_class("NSImage"), "alloc");
    if (!image) return NULL;
    memcpy(&init_image, &g_api.msg, sizeof init_image);
    image = init_image(image, cocoa_sel("initWithSize:"), size);
    if (!image) return NULL;
    cocoa_void_id(image, "addRepresentation:", rep);
    return image;
}

static void cocoa_adopt_pixels(struct cocoa_win *c, struct gui_window *w,
                               uint8_t *pix, bool fresh)
{
    if (!fresh) return;
    free(c->rgba);
    c->rgba = pix;
    c->rgba_w = w->fb_w;
    c->rgba_h = w->fb_h;
}

static bool cocoa_present(struct gui_window *w, const struct gui_rect *rects, size_t n)
{
    struct cocoa_win *c = cocoa_state(w);
    cocoa_id rep, image, pool;
    uint8_t *pix;
    bool fresh = false;
    (void)rects;
    (void)n;
    if (!c) return false;
    pix = cocoa_fill(w, c, &fresh);
    if (!pix) return false;
    pool = cocoa_pool_push();
    rep = cocoa_bitmap(w, pix);
    image = rep ? cocoa_image(w, rep) : NULL;
    cocoa_release(rep);
    if (!image) {
        if (fresh) free(pix);
        cocoa_release(pool);
        return false;
    }
    cocoa_void_id(c->view, "setImage:", image);
    cocoa_release(image);
    cocoa_adopt_pixels(c, w, pix, fresh);
    cocoa_void_bool(c->view, "setNeedsDisplay:", 1);
    cocoa_msg(c->window, "displayIfNeeded");
    cocoa_release(pool);
    return true;
}

static cocoa_id cocoa_string_n(const char *utf8, size_t len)
{
    char *tmp;
    cocoa_id text;
    if (!utf8 || len > GUI_CLIP_CAP) return NULL;
    tmp = zcl_calloc(len + 1u, 1u, "gui cocoa clip");
    if (!tmp) return NULL;
    if (len) memcpy(tmp, utf8, len);
    text = cocoa_string(tmp);
    free(tmp);
    return text;
}

/* Tests use a private board. The wallet build keeps the system pasteboard. */
static cocoa_id cocoa_pasteboard(void)
{
#if defined(ZCL_TESTING)
    cocoa_id name = cocoa_string("z23.gui.test");
    cocoa_id (*named)(cocoa_id, cocoa_SEL, cocoa_id);
    cocoa_id board;
    memcpy(&named, &g_api.msg, sizeof named);
    board = named(g_api.get_class("NSPasteboard"), cocoa_sel("pasteboardWithName:"), name);
    cocoa_release(name);
    return board;
#else
    return cocoa_msg(g_api.get_class("NSPasteboard"), "generalPasteboard");
#endif
}

static bool cocoa_clip_set(struct gui_window *w, const char *utf8, size_t len)
{
    cocoa_id pool, board, text, type;
    signed char (*set_str)(cocoa_id, cocoa_SEL, cocoa_id, cocoa_id);
    signed char ok;
    (void)w;
    if (!utf8 || len > GUI_CLIP_CAP || !cocoa_load(NULL, 0)) return false;
    pool = cocoa_pool_push();
    board = cocoa_pasteboard();
    text = cocoa_string_n(utf8, len);
    type = cocoa_string("public.utf8-plain-text");
    if (!board || !text || !type) {
        cocoa_release(text);
        cocoa_release(type);
        cocoa_release(pool);
        return false;
    }
    cocoa_void0(board, "clearContents");
    memcpy(&set_str, &g_api.msg, sizeof set_str);
    ok = set_str(board, cocoa_sel("setString:forType:"), text, type);
    cocoa_release(text);
    cocoa_release(type);
    cocoa_release(pool);
    return ok != 0;
}

static size_t cocoa_clip_get(struct gui_window *w, char *buf, size_t cap)
{
    cocoa_id pool, board, type, str = NULL;
    cocoa_id (*get)(cocoa_id, cocoa_SEL, cocoa_id);
    const char *utf8;
    size_t n = 0;
    (void)w;
    if (!buf || cap == 0 || !cocoa_load(NULL, 0)) return 0;
    pool = cocoa_pool_push();
    board = cocoa_pasteboard();
    type = cocoa_string("public.utf8-plain-text");
    if (board && type) {
        memcpy(&get, &g_api.msg, sizeof get);
        str = get(board, cocoa_sel("stringForType:"), type);
    }
    utf8 = str ? cocoa_utf8(str, "UTF8String") : NULL;
    if (utf8) {
        n = strlen(utf8);
        if (n >= cap) n = cap - 1u;
        memcpy(buf, utf8, n);
    }
    buf[n] = '\0';
    cocoa_release(type);
    cocoa_release(pool);
    return n;
}

static void cocoa_title(struct gui_window *w, const char *utf8)
{
    struct cocoa_win *c = cocoa_state(w);
    cocoa_id title, pool;
    if (!c || !c->window) return;
    pool = cocoa_pool_push();
    title = cocoa_string(utf8);
    cocoa_void_id(c->window, "setTitle:", title);
    cocoa_release(title);
    cocoa_release(pool);
}

const struct gui_backend_ops gui_backend_cocoa = {
    .open = cocoa_open,
    .close = cocoa_close,
    .wait_native = cocoa_wait,
    .wake = cocoa_wake,
    .present = cocoa_present,
    .clip_set = cocoa_clip_set,
    .clip_get = cocoa_clip_get,
    .set_title = cocoa_title,
    .set_fullscreen = cocoa_fullscreen,
};
#endif

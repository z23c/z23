/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Native live-window failure regression; built only with ZCL_TESTING. */
#if defined(__linux__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include "presentation/presentation.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#if defined(__APPLE__)
#include <objc/runtime.h>
#include <objc/message.h>

#elif defined(__linux__)
#include <X11/Xatom.h>
#include <X11/Xlib.h>
#include "platform/clock.h"
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#if !defined(ZCL_TESTING)
#error "live redraw fixture requires ZCL_TESTING"
#endif
void zcl_present_test_script(unsigned first, unsigned second, bool fail_redraw);
struct zcl_present_window_event_v1 zcl_present_test_result(void);
bool zcl_present_test_copy_matches(void);
bool zcl_present_test_form_paste(struct zcl_present_window_form_field_v1 *);
#if defined(__linux__)
bool zcl_present_test_x11_libraries_retired(void);
#endif
struct fixture { unsigned calls; bool confirm; };
static void update(void *context, const struct zcl_present_window_event_v1 *event,
                   bool close_requested, bool *redraw, bool *allow_close)
{
    struct fixture *f = context;
    (void)close_requested;
    ++f->calls;
    *redraw = event->action_index == 1;
    *allow_close = event->outcome == ZCL_PRESENT_WINDOW_ACTION && event->action_index != 1;
    if (event->action_index == 3) f->confirm = true;
}
static bool input(void *context, const struct zcl_present_input_v1 *event,
                  uint32_t *focus, uint32_t *action)
{
    (void)context;
    if (event->key != ZCL_PRESENT_INPUT_TEXT || event->character < '1' || event->character > '4') return false;
    *focus = event->character - '1';
    /* Scripted '3' changes only focus, like Tab in the native confirm view. */
    if (event->character != '3') *action = *focus;
    return true;
}
static bool run(unsigned first, bool fail, bool expected_ok,
                unsigned expected_calls, bool expected_confirm)
{
    static uint8_t pixels[16 * 16 * 3];
    struct zcl_present_window_v1 page = {
        .struct_size = sizeof(page), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "Live redraw regression", .pixels = pixels,
        .width = 16, .height = 16, .pixel_format = ZCL_PRESENT_RGB8,
    };
    struct zcl_present_window_pages_v1 pages = {
        .struct_size = sizeof(pages), .abi_version = ZCL_PRESENT_ABI_V1,
        .pages = &page, .page_count = 1,
    };
    struct fixture f = {0};
    const struct zcl_present_window_live_view_v1 live = {
        .owner = {.context = &f, .update = update}, .input = input,
    };
    char error[256] = {0};
    zcl_present_test_script(first, 3, fail);
    bool ok = zcl_present_window_run_live_view_v1(&pages, 4, &live, error, sizeof(error));
    struct zcl_present_window_event_v1 result = zcl_present_test_result();
#if defined(__linux__)
    if (!zcl_present_test_x11_libraries_retired()) {
        fprintf(stderr, "live redraw: last-window close retained X11 library state\n");
        return false;
    }
#endif
    if ((!expected_ok && (result.outcome != ZCL_PRESENT_WINDOW_DISMISSED || result.action_index != UINT32_MAX)) ||
        ok != expected_ok || f.calls != expected_calls || f.confirm != expected_confirm ||
        (!expected_ok && !strstr(error, "redraw"))) {
        fprintf(stderr, "live redraw: ok=%d calls=%u confirm=%d error=%s\n", ok, f.calls, f.confirm, error);
        return false;
    }
    return true;
}
#if defined(__APPLE__)
static bool initialization_failure(void)
{
    Class collision = objc_allocateClassPair(objc_getClass("NSObject"), "RGFWCustomView", 0);
    if (!collision) return false;
    objc_registerClassPair(collision);
    static uint8_t pixels[16 * 16 * 3];
    struct zcl_present_window_v1 page = {
        .struct_size = sizeof(page), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "Collision", .pixels = pixels, .width = 16, .height = 16,
        .pixel_format = ZCL_PRESENT_RGB8,
    };
    struct zcl_present_window_pages_v1 pages = {
        .struct_size = sizeof(pages), .abi_version = ZCL_PRESENT_ABI_V1,
        .pages = &page, .page_count = 1,
    };
    struct fixture f = {0};
    const struct zcl_present_window_live_view_v1 live = {
        .owner = {.context = &f, .update = update}, .input = input,
    };
    char error[256] = {0};
    bool ok = zcl_present_window_run_live_view_v1(&pages, 4, &live, error, sizeof(error));
    objc_disposeClassPair(collision);
    return !ok && f.calls == 0 && strstr(error, "initialization failed") != NULL;
}
#endif

#if defined(__linux__)
static bool failed_display(void)
{
    static uint8_t pixels[16 * 16 * 3];
    struct zcl_present_window_v1 page = {
        .struct_size = sizeof(page), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "Unavailable display", .pixels = pixels, .width = 16, .height = 16,
        .pixel_format = ZCL_PRESENT_RGB8,
    };
    struct zcl_present_window_event_v1 event = {0};
    char error[256] = {0};
    bool ok = zcl_present_window_run_actions_v1(&page, 1, NULL, NULL, &event, error, sizeof(error));
    return !ok && strstr(error, "initialization failed") && zcl_present_test_x11_libraries_retired();
}
static bool initialization_failure(void)
{
    const char *display = getenv("DISPLAY");
    char *saved = display ? strdup(display) : NULL;
    if (!saved) return false;
    bool ok = setenv("DISPLAY", ":invalid-display-regression", 1) == 0 &&
        failed_display() && failed_display();
    if (setenv("DISPLAY", saved, 1)) ok = false;
    free(saved);
    return ok;
}
#endif

 #if defined(__APPLE__) || defined(__linux__)
struct paste_probe { struct zcl_present_window_form_field_v1 field; bool copied; unsigned clock_mode, samples; };
#if defined(__linux__)
static int64_t paste_test_clock(void *context)
{
    struct paste_probe *p = context;
    return p->clock_mode == 2 && p->samples++ == 0 ? 1000000000LL : 0;
}
#endif
static void paste_ready(void *context)
{
    struct paste_probe *p = context;
#if defined(__linux__)
    const clock_iface_t *previous = clock_default();
    clock_iface_t zero = {.now_monotonic_ns = paste_test_clock, .now_wall_ms = paste_test_clock, .self = p};
    if (p->clock_mode) clock_set_default(&zero);
#endif
    p->copied = zcl_present_test_form_paste(&p->field);
#if defined(__linux__)
    if (p->clock_mode) clock_set_default(previous);
#endif
}
static bool paste_probe_run_clock(const char *prefix, bool expected, const char *value, unsigned clock_mode)
{
    static uint8_t pixels[16 * 16 * 3];
    struct zcl_present_window_v1 page = {.struct_size = sizeof(page), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "Paste fixture", .pixels = pixels, .width = 16, .height = 16, .pixel_format = ZCL_PRESENT_RGB8};
    struct paste_probe probe = {.clock_mode = clock_mode}; snprintf(probe.field.value, sizeof(probe.field.value), "%s", prefix);
    struct zcl_present_window_event_v1 event = {0}; char error[256] = {0};
    zcl_present_test_script(0, 0, false);
    bool ok = zcl_present_window_run_actions_v1(&page, 1, paste_ready, &probe, &event, error, sizeof(error));
    return ok && probe.copied == expected && !strcmp(probe.field.value, value);
}

static bool paste_probe_run(const char *prefix, bool expected, const char *value)
{ return paste_probe_run_clock(prefix, expected, value, false); }

 #endif

#if defined(__APPLE__) || defined(__linux__)
struct host_copy_probe { bool written, rejected, pasted; };
static void host_copy_ready(void *context)
{
    struct host_copy_probe *probe = context;
    static const char link[] = "http://example.onion/board/apps/v1";
    char over[ZCL_PRESENT_COPY_TEXT_MAX + 2u];
    memset(over, 'x', sizeof(over) - 1u); over[sizeof(over) - 1u] = 0;
    probe->written = zcl_present_window_copy_ascii_v1(link);
    probe->rejected = !zcl_present_window_copy_ascii_v1("") &&
        !zcl_present_window_copy_ascii_v1("caf\xc3\xa9") &&
        !zcl_present_window_copy_ascii_v1(over);
    struct zcl_present_window_form_field_v1 field = {0};
    probe->pasted = zcl_present_test_form_paste(&field) && !strcmp(field.value, link);
}
static bool host_copy_api_cases(void)
{
    if (zcl_present_window_copy_ascii_v1("outside-window")) return false;
    static uint8_t pixels[16 * 16 * 3]; struct host_copy_probe probe = {0};
    struct zcl_present_window_v1 page = {.struct_size = sizeof(page), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "Host link copy", .pixels = pixels, .width = 16, .height = 16, .pixel_format = ZCL_PRESENT_RGB8};
    struct zcl_present_window_event_v1 event = {0}; char error[256] = {0};
    zcl_present_test_script(0, 0, false);
    bool ok = zcl_present_window_run_actions_v1(&page, 1, host_copy_ready, &probe, &event, error, sizeof(error));
    return ok && probe.written && probe.rejected && probe.pasted;
}
struct text_copy_probe { bool unicode, control, maximum, over; };
static void text_copy_ready(void *context)
{
    struct text_copy_probe *probe = context;
    char text[ZCL_PRESENT_COPY_TEXT_MAX + 2u];
    probe->unicode = zcl_present_window_copy_text_v1("caf\xc3\xa9 / \xe2\x9c\x93");
    probe->control = zcl_present_window_copy_text_v1("line one\nline two\tend");
    memset(text, 'x', ZCL_PRESENT_COPY_TEXT_MAX);
    text[ZCL_PRESENT_COPY_TEXT_MAX] = 0;
    probe->maximum = zcl_present_window_copy_text_v1(text);
    text[ZCL_PRESENT_COPY_TEXT_MAX] = 'x'; text[ZCL_PRESENT_COPY_TEXT_MAX + 1u] = 0;
    probe->over = !zcl_present_window_copy_text_v1(text);
}
static bool text_copy_api_cases(void)
{
    if (zcl_present_window_copy_text_v1("outside-window") || zcl_present_window_copy_text_v1(NULL)) return false;
    static uint8_t pixels[16 * 16 * 3]; struct text_copy_probe probe = {0};
    struct zcl_present_window_v1 page = {.struct_size = sizeof(page), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "Text copy", .pixels = pixels, .width = 16, .height = 16, .pixel_format = ZCL_PRESENT_RGB8};
    struct zcl_present_window_event_v1 event = {0}; char error[256] = {0};
    zcl_present_test_script(0, 0, false);
    bool ok = zcl_present_window_run_actions_v1(&page, 1, text_copy_ready, &probe, &event, error, sizeof(error));
    return ok && probe.unicode && probe.control && probe.maximum && probe.over;
}
#endif

#if defined(__APPLE__)
struct mac_window_probe { id window; unsigned long matches; };
static void mac_window_ready(void *context)
{
    struct mac_window_probe *probe = context;
    id app = ((id (*)(id, SEL))objc_msgSend)((id)objc_getClass("NSApplication"), sel_registerName("sharedApplication"));
    id windows = ((id (*)(id, SEL))objc_msgSend)(app, sel_registerName("windows"));
    unsigned long count = ((unsigned long (*)(id, SEL))objc_msgSend)(windows, sel_registerName("count"));
    for (unsigned long i = 0; i < count; ++i) {
        id window = ((id (*)(id, SEL, unsigned long))objc_msgSend)(windows, sel_registerName("objectAtIndex:"), i);
        id title = ((id (*)(id, SEL))objc_msgSend)(window, sel_registerName("title"));
        const char *text = ((const char *(*)(id, SEL))objc_msgSend)(title, sel_registerName("UTF8String"));
        BOOL visible = ((BOOL (*)(id, SEL))objc_msgSend)(window, sel_registerName("isVisible"));
        if (!text || strcmp(text, "Window teardown") || !visible) continue;
        probe->window = window; ++probe->matches;
    }
    if (probe->matches == 1) ((id (*)(id, SEL))objc_msgSend)(probe->window, sel_registerName("retain"));
    else probe->window = nil;
}
static bool mac_window_closed(void)
{
    static uint8_t pixels[16 * 16 * 3]; struct mac_window_probe probe = {0};
    struct zcl_present_window_v1 page = {.struct_size = sizeof(page), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "Window teardown", .pixels = pixels, .width = 16, .height = 16, .pixel_format = ZCL_PRESENT_RGB8};
    struct zcl_present_window_event_v1 event = {0}; char error[256] = {0};
    zcl_present_test_script(0, 0, false);
    bool ok = zcl_present_window_run_actions_v1(&page, 1, mac_window_ready, &probe, &event, error, sizeof(error));
    bool hidden = probe.window && !((BOOL (*)(id, SEL))objc_msgSend)(probe.window, sel_registerName("isVisible"));
    if (!ok || !hidden) fprintf(stderr, "mac window teardown: ok=%d captured=%d matches=%lu hidden=%d error=%s\n",
        ok, probe.window != nil, probe.matches, hidden, error);

    if (probe.window) ((void (*)(id, SEL))objc_msgSend)(probe.window, sel_registerName("release"));
    return ok && hidden;
}
#endif
static bool clipboard_roundtrip(const char *text)
{
    static uint8_t pixels[16 * 16 * 3];
    struct zcl_present_window_v1 page = {
        .struct_size = sizeof(page), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "Clipboard text regression", .pixels = pixels,
        .width = 16, .height = 16, .pixel_format = ZCL_PRESENT_RGB8,
        .copy_text = text,
    };
    struct zcl_present_window_event_v1 event = {0};
    char error[256] = {0};
    zcl_present_test_script(UINT_MAX, 0, false);
    bool ok = zcl_present_window_run_actions_v1(&page, 1, NULL, NULL,
        &event, error, sizeof(error));
    if (!ok || !zcl_present_test_copy_matches()) {
        fprintf(stderr, "clipboard text roundtrip failed: %s\n", error);
        return false;
    }
    return true;
}
#if defined(__linux__)
/* A separate process owns RGFW's clipboard. The parent is a distinct X11
 * requestor, so this catches wire lengths that RGFW's own reader hides. */
static const char *clipboard_fixture(unsigned which, char maximum[ZCL_PRESENT_COPY_TEXT_MAX + 1u])
{
    if (which == 0) return "";
    if (which == 1 || which == 6) return "quoted \\\"path\\\" / caf\xc3\xa9 / \xe2\x9c\x93";
    if (which == 3 || which == 5) return "http://example.onion/board/apps/v1";
    if (which == 4 || which == 7) return "bad\nlink";
    memset(maximum, 'x', ZCL_PRESENT_COPY_TEXT_MAX); maximum[ZCL_PRESENT_COPY_TEXT_MAX] = 0;
    return maximum;
}
static void clipboard_api_owner_ready(void *context)
{
    const char *text = context;
    if (!zcl_present_window_copy_ascii_v1(text)) _exit(2);
}
static void clipboard_text_owner_ready(void *context)
{
    if (!zcl_present_window_copy_text_v1(context)) _exit(2);
}
static int clipboard_owner(unsigned which)
{
    static uint8_t pixels[16 * 16 * 3]; char maximum[ZCL_PRESENT_COPY_TEXT_MAX + 1u];
    struct zcl_present_window_v1 page = {
        .struct_size = sizeof(page), .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "External clipboard owner", .pixels = pixels,
        .width = 16, .height = 16, .pixel_format = ZCL_PRESENT_RGB8,
        .copy_text = which >= 5 ? NULL : clipboard_fixture(which, maximum),
    };
    const char *text = clipboard_fixture(which, maximum);
    struct zcl_present_window_event_v1 event = {0}; char error[256] = {0};
    /* C copies; the unrelated second key leaves the window running. */
    zcl_present_test_script(UINT_MAX, 200, false);
    return zcl_present_window_run_actions_v1(&page, 1,
        which == 5 ? clipboard_api_owner_ready : which >= 6 ? clipboard_text_owner_ready : NULL,
        (void *)text, &event, error, sizeof(error)) ? 0 : 1;
}
static bool clipboard_wait_owner(Display *d, Atom selection)
{
    for (unsigned i = 0; i < 100; ++i) {
        if (XGetSelectionOwner(d, selection) != None) return true;
        (void)poll(NULL, 0, 100); /* real-clock: bounded external X11 process */
    }
    return false;
}
static bool clipboard_wait_notify(Display *d, Window w, Atom selection, Atom target, Atom property)
{
    XConvertSelection(d, selection, target, property, w, CurrentTime); XFlush(d);
    for (unsigned i = 0; i < 100; ++i) {
        while (XPending(d)) {
            XEvent event; XNextEvent(d, &event);
            if (event.type == SelectionNotify && event.xselection.requestor == w &&
                event.xselection.selection == selection && event.xselection.target == target)
                return event.xselection.property == property;
        }
        struct pollfd fd = {.fd = ConnectionNumber(d), .events = POLLIN};
        int n = poll(&fd, 1, 100); /* real-clock: bounded external X11 response */
        if (n < 0 && errno != EINTR) return false;
    }
    return false;
}
static bool clipboard_value(Display *d, Window w, Atom property, Atom expected, const char *text)
{
    Atom type = None; int format = 0; unsigned long count = 0, remain = 0; unsigned char *value = NULL;
    int rc = XGetWindowProperty(d, w, property, 0, 2048, True, AnyPropertyType,
        &type, &format, &count, &remain, &value);
    size_t len = strlen(text);
    bool ok = rc == Success && type == expected && format == 8 && !remain && count == len &&
        (!len || (value && !memcmp(value, text, len)));
    if (value) XFree(value);
    return ok;
}
static bool clipboard_multiple(Display *d, Window w, Atom selection, Atom utf, const char *text)
{
    Atom multiple = XInternAtom(d, "MULTIPLE", False), pair = XInternAtom(d, "ATOM_PAIR", False);
    Atom request = XInternAtom(d, "Z23_TEST_MULTIPLE", False);
    Atom one = XInternAtom(d, "Z23_TEST_ONE", False), two = XInternAtom(d, "Z23_TEST_TWO", False);
    Atom values[] = {utf, one, utf, two};
    XChangeProperty(d, w, request, pair, 32, PropModeReplace, (const unsigned char *)values, 4);
    if (!clipboard_wait_notify(d, w, selection, multiple, request)) return false;
    Atom type = None; int format = 0; unsigned long count = 0, remain = 0; unsigned char *raw = NULL;
    int rc = XGetWindowProperty(d, w, request, 0, 4, True, AnyPropertyType,
        &type, &format, &count, &remain, &raw);
    bool ok = rc == Success && type == pair && format == 32 && count == 4 && !remain && raw &&
        !memcmp(raw, values, sizeof(values));
    if (raw) XFree(raw);
    return ok && clipboard_value(d, w, one, utf, text) && clipboard_value(d, w, two, utf, text);
}
static bool clipboard_paste_cases(unsigned which)
{
    bool pasted = (which == 3 || which == 5) ? paste_probe_run("keep", true, "keephttp://example.onion/board/apps/v1") :
        paste_probe_run("keep", false, "keep");
    if (which != 3 && which != 5) return pasted;
    char full[ZCL_PRESENT_WINDOW_FORM_VALUE_MAX + 1u];
    memset(full, 'x', sizeof(full) - 1); full[sizeof(full) - 1] = 0;
    return pasted && paste_probe_run(full, false, full) &&
        paste_probe_run("keep", true, "keephttp://example.onion/board/apps/v1") &&
        paste_probe_run_clock("keep", false, "keep", 1) && paste_probe_run_clock("keep", false, "keep", 2);
}
static bool clipboard_external(const char *executable, unsigned which)
{
    Display *d = XOpenDisplay(NULL); if (!d) return false;
    Atom selection = XInternAtom(d, "CLIPBOARD", False), utf = XInternAtom(d, "UTF8_STRING", False);
    Atom direct = XInternAtom(d, "Z23_TEST_DIRECT", False);
    Window w = XCreateSimpleWindow(d, DefaultRootWindow(d), 0, 0, 1, 1, 0, 0, 0);
    XSetSelectionOwner(d, selection, None, CurrentTime); XSync(d, False);
    char choice[4]; (void)snprintf(choice, sizeof(choice), "%u", which);
    pid_t child = fork();
    if (child == 0) { execl(executable, "live-redraw-test", "--clipboard-owner", choice, (char *)NULL); _exit(127); }
    char maximum[ZCL_PRESENT_COPY_TEXT_MAX + 1u]; const char *text = clipboard_fixture(which, maximum);
    bool ready = child > 0 && clipboard_wait_owner(d, selection);
    bool single = ready && clipboard_wait_notify(d, w, selection, utf, direct) &&
        clipboard_value(d, w, direct, utf, text);
    bool multiple = ready && clipboard_multiple(d, w, selection, utf, text);
    bool ok = single && multiple && clipboard_paste_cases(which);
    if (child > 0) {
        (void)kill(child, SIGKILL); int status;
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    }
    XDestroyWindow(d, w); XCloseDisplay(d);
    if (!ok) fprintf(stderr, "external X11 clipboard fixture %u: direct=%d multiple=%d\n", which, single, multiple);
    return ok;
}
static bool clipboard_unresponsive(bool flood)
{
    Display *d = XOpenDisplay(NULL); if (!d) return false;
    Atom selection = XInternAtom(d, "CLIPBOARD", False);
    XSetSelectionOwner(d, selection, None, CurrentTime); XSync(d, False);
    pid_t child = fork();
    if (child == 0) {
        (void)alarm(30);
        Display *owner = XOpenDisplay(NULL); if (!owner) _exit(2);
        Window w = XCreateSimpleWindow(owner, DefaultRootWindow(owner), 0, 0, 1, 1, 0, 0, 0);
        Atom clip = XInternAtom(owner, "CLIPBOARD", False);
        XSetSelectionOwner(owner, clip, w, CurrentTime); XFlush(owner);
        for (;;) {
            XEvent event; XNextEvent(owner, &event);
            if (flood && event.type == SelectionRequest) {
                XEvent irrelevant = {0}; irrelevant.xclient.type = ClientMessage;
                irrelevant.xclient.display = owner; irrelevant.xclient.window = event.xselectionrequest.requestor;
                irrelevant.xclient.message_type = XInternAtom(owner, "Z23_IRRELEVANT", False);
                irrelevant.xclient.format = 32;
                for (unsigned i = 0; i < 30000; ++i)
                    XSendEvent(owner, event.xselectionrequest.requestor, False, NoEventMask, &irrelevant);
                XFlush(owner);
            }
        }
    }
    bool ok = child > 0 && clipboard_wait_owner(d, selection) && paste_probe_run("keep", false, "keep");
    if (child > 0) { (void)kill(child, SIGKILL); int status; while (waitpid(child, &status, 0) < 0 && errno == EINTR) {} }
    XCloseDisplay(d); return ok;
}
#endif

#if defined(__linux__)
/* Bound even an Xlib call that never returns after a display reset. */
static void live_redraw_watchdog(int signal_number)
{
    (void)signal_number;
    static const char message[] = "live-redraw: X11 fixture watchdog expired\n";
    ssize_t written = write(STDERR_FILENO, message, sizeof(message) - 1u);
    (void)written;
    _exit(124);
}
#endif

#if defined(__linux__)
static bool linux_clipboard_cases(const char *executable)
{
    bool external_ok = true;
    for (unsigned i = 0; i < 9; ++i) {
        fprintf(stderr, "live-redraw: external clipboard case %u\n", i);
        if (!clipboard_external(executable, i)) external_ok = false;
    }
    fputs("live-redraw: silent and flooding clipboard owners\n", stderr);
    if (!external_ok || !clipboard_unresponsive(false) || !clipboard_unresponsive(true)) return false;
    puts("clipboard: external direct and MULTIPLE exact byte lengths");
    return true;
}
#endif

static bool clipboard_roundtrip_cases(void)
{
    if (!clipboard_roundtrip("{\"value\":\"last byte stays\"}")) return false;
    if (!clipboard_roundtrip("")) return false;
    if (!clipboard_roundtrip("quoted \"path\" / caf\xc3\xa9 / \xe2\x9c\x93")) return false;
    char maximum[ZCL_PRESENT_COPY_TEXT_MAX + 1u];
    memset(maximum, 'x', sizeof(maximum) - 1u); maximum[sizeof(maximum) - 1u] = 0;
    return clipboard_roundtrip(maximum);
}

static bool live_redraw_cases(void)
{
    return run(1, true, false, 1, false) && run(0, false, true, 1, false) &&
        run(1, false, true, 2, true) && run(2, true, false, 1, false) &&
        run(2, false, true, 2, true);
}
int main(int argc, char **argv)
{
#if defined(__linux__)
    if (signal(SIGALRM, live_redraw_watchdog) == SIG_ERR) return 1;
    (void)alarm(90);
    if (argc == 3 && !strcmp(argv[1], "--clipboard-owner")) {
        (void)alarm(30);
        unsigned which = (unsigned)strtoul(argv[2], NULL, 10);
        return which < 9 ? clipboard_owner(which) : 1;
    }
#else
    (void)argc; (void)argv;
#endif
#if defined(__APPLE__) || defined(__linux__)
    if (!initialization_failure()) { fputs("live-redraw: initialization failure case failed\n", stderr); return 1; }
#endif
#if defined(__linux__)
    fputs("live-redraw: native redraw cases\n", stderr);
#endif
    if (!live_redraw_cases()) { fputs("live-redraw: redraw cases failed\n", stderr); return 1; }
#if defined(__APPLE__)
    if (!mac_window_closed()) { fputs("live-redraw: mac window close case failed\n", stderr); return 1; }
#endif

#if defined(__linux__)
    fputs("live-redraw: clipboard owner round trips after window closes\n", stderr);
#endif
    if (!clipboard_roundtrip_cases()) { fputs("live-redraw: clipboard roundtrip cases failed\n", stderr); return 1; }
#if defined(__APPLE__) || defined(__linux__)
    if (!host_copy_api_cases()) { fputs("live-redraw: ASCII copy API cases failed\n", stderr); return 1; }
    if (!text_copy_api_cases()) { fputs("live-redraw: text copy API cases failed\n", stderr); return 1; }
#endif
#if defined(__APPLE__)
    if (!clipboard_roundtrip("http://example.onion/board/apps/v1") ||
        !paste_probe_run("keep", true, "keephttp://example.onion/board/apps/v1")) { fputs("live-redraw: link copy or paste failed\n", stderr); return 1; }
    char full[ZCL_PRESENT_WINDOW_FORM_VALUE_MAX + 1u];
    memset(full, 'x', sizeof(full) - 1); full[sizeof(full) - 1] = 0;
    if (!paste_probe_run(full, false, full)) { fputs("live-redraw: full paste refusal failed\n", stderr); return 1; }
#endif
#if defined(__linux__)
    if (!linux_clipboard_cases(argv[0])) { fputs("live-redraw: Linux clipboard cases failed\n", stderr); return 1; }
#endif
    puts("clipboard: JSON closing byte, empty, UTF8 and maximum text roundtrip exactly");
    puts("live redraw: failure and terminal cancel reject queued confirm; successful redraw proceeds");
    return 0;
}

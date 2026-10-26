/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: drive one bounded physical event into a native presentation window. */

#define _POSIX_C_SOURCE 200809L

#include <X11/Xlib.h>
#include <X11/keysym.h>
#include <X11/Xutil.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static unsigned int matching_windows(Display *display, Window window,
                                     const char *title, unsigned int depth,
                                     Window *first)
{
    unsigned int matches = 0;
    char *name = NULL;
    if (XFetchName(display, window, &name) && name) {
        if (strstr(name, title) != NULL) {
            if (*first == None)
                *first = window;
            matches++;
        }
        XFree(name);
    }
    if (depth > 0) {
        Window root = None, parent = None, *children = NULL;
        unsigned int child_count = 0;
        if (XQueryTree(display, window, &root, &parent,
                       &children, &child_count)) {
            for (unsigned int i = 0; i < child_count; i++)
                matches += matching_windows(display, children[i], title,
                                            depth - 1u, first);
            if (children)
                XFree(children);
        }
    }
    return matches;
}

static void sleep_20ms(void)
{
    struct timespec duration = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
    while (nanosleep(&duration, &duration) != 0) {}
}

static bool send_close(Display *display, Window window)
{
    Atom protocols = XInternAtom(display, "WM_PROTOCOLS", False);
    Atom close_window = XInternAtom(display, "WM_DELETE_WINDOW", False);
    if (protocols == None || close_window == None)
        return false;
    XEvent event;
    memset(&event, 0, sizeof(event));
    event.xclient.type = ClientMessage;
    event.xclient.display = display;
    event.xclient.window = window;
    event.xclient.message_type = protocols;
    event.xclient.format = 32;
    event.xclient.data.l[0] = (long)close_window;
    event.xclient.data.l[1] = CurrentTime;
    if (!XSendEvent(display, window, False, NoEventMask, &event))
        return false;
    (void)XSync(display, False);
    return true;
}

static bool send_key(Display *display, Window root, Window window,
                     KeySym key)
{
    KeyCode keycode = XKeysymToKeycode(display, key);
    if (keycode == 0)
        return false;
    XEvent event;
    memset(&event, 0, sizeof(event));
    event.xkey.type = KeyPress;
    event.xkey.display = display;
    event.xkey.window = window;
    event.xkey.root = root;
    event.xkey.subwindow = None;
    event.xkey.time = CurrentTime;
    event.xkey.x = 1;
    event.xkey.y = 1;
    event.xkey.x_root = 1;
    event.xkey.y_root = 1;
    event.xkey.same_screen = True;
    event.xkey.keycode = keycode;
    if (!XSendEvent(display, window, False, KeyPressMask, &event))
        return false;
    event.xkey.type = KeyRelease;
    if (!XSendEvent(display, window, False, KeyReleaseMask, &event))
        return false;
    (void)XSync(display, False);
    return true;
}

static XImage *capture_window(Display *display, Window window)
{
    XWindowAttributes attributes;
    if (window == None ||
        !XGetWindowAttributes(display, window, &attributes) ||
        attributes.width <= 0 || attributes.height <= 0)
        return NULL;
    return XGetImage(display, window, 0, 0,
                     (unsigned int)attributes.width,
                     (unsigned int)attributes.height,
                     AllPlanes, ZPixmap);
}

static bool image_differs(const XImage *before, const XImage *after)
{
    if (!before || !after || before->width != after->width ||
        before->height != after->height ||
        before->bytes_per_line != after->bytes_per_line)
        return false;
    size_t bytes = (size_t)before->bytes_per_line *
                   (size_t)before->height;
    return bytes > 0 && memcmp(before->data, after->data, bytes) != 0;
}

struct ui_driver_options {
    const char *title;
    const char *key;
    bool expect_count_set;
    unsigned int expected_count;
    unsigned int timeout_ms;
    bool expect_pixels_change;
};

static int parse_unsigned_in_range(const char *text, unsigned long lowest,
                                   unsigned long highest, unsigned int *value)
{
    char *end = NULL;
    unsigned long parsed = strtoul(text, &end, 10);
    if (!end || *end || parsed < lowest || parsed > highest)
        return -1;
    *value = (unsigned int)parsed;
    return 0;
}

static int parse_ui_driver_options(int argc, char **argv,
                                   struct ui_driver_options *options)
{
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--title=", 8) == 0)
            options->title = argv[i] + 8;
        else if (strncmp(argv[i], "--key=", 6) == 0)
            options->key = argv[i] + 6;
        else if (strncmp(argv[i], "--expect-count=", 15) == 0) {
            if (parse_unsigned_in_range(argv[i] + 15, 0, 1024,
                                        &options->expected_count) != 0)
                return -1;
            options->expect_count_set = true;
        }
        else if (strncmp(argv[i], "--timeout-ms=", 13) == 0) {
            if (parse_unsigned_in_range(argv[i] + 13, 20, 30000,
                                        &options->timeout_ms) != 0)
                return -1;
        } else if (strcmp(argv[i], "--expect-pixels-change") == 0) {
            options->expect_pixels_change = true;
        } else {
            return -1;
        }
    }
    return 0;
}

struct ui_driver_key_entry {
    const char *name;
    KeySym symbol;
};

static const struct ui_driver_key_entry ui_driver_key_table[] = {
    {"1", XK_1},
    {"tab", XK_Tab},
    {"enter", XK_Return},
    {"pagedown", XK_Page_Down},
    {"pageup", XK_Page_Up},
    {"left", XK_Left},
    {"right", XK_Right},
    {"up", XK_Up},
    {"down", XK_Down},
    {"escape", NoSymbol},
};

static const struct ui_driver_key_entry *find_ui_driver_key(const char *name)
{
    if (name == NULL)
        return NULL;
    size_t entries = sizeof(ui_driver_key_table) /
                     sizeof(ui_driver_key_table[0]);
    for (size_t i = 0; i < entries; i++)
        if (strcmp(name, ui_driver_key_table[i].name) == 0)
            return &ui_driver_key_table[i];
    return NULL;
}

static KeySym ui_driver_key_symbol(const char *name)
{
    const struct ui_driver_key_entry *entry = find_ui_driver_key(name);
    return entry ? entry->symbol : XK_Page_Up;
}

static bool ui_driver_options_usable(const struct ui_driver_options *options)
{
    if (!options->title || !options->title[0] ||
        (!!options->key == options->expect_count_set) ||
        (options->expect_pixels_change && !options->key))
        return false;
    return !options->key || find_ui_driver_key(options->key) != NULL;
}

static void wait_for_matching_windows(Display *display, Window root,
                                      const struct ui_driver_options *options,
                                      unsigned int attempts, Window *window,
                                      unsigned int *count)
{
    for (unsigned int i = 0; i <= attempts; i++) {
        *window = None;
        *count = matching_windows(display, root, options->title, 4u, window);
        if ((options->expect_count_set && *count == options->expected_count) ||
            (!options->expect_count_set && *window != None))
            break;
        if (i < attempts)
            sleep_20ms();
    }
}

static bool send_window_event(Display *display, Window root, Window window,
                              bool expect_pixels_change, XImage *before,
                              KeySym key_sym)
{
    if (window == None)
        return false;
    if (expect_pixels_change && before == NULL)
        return false;
    if (key_sym == NoSymbol)
        return send_close(display, window);
    return send_key(display, root, window, key_sym);
}

static bool pixels_changed_after_send(Display *display, Window window,
                                      XImage *before, unsigned int attempts,
                                      bool sent, bool expect_pixels_change)
{
    bool changed = !expect_pixels_change;
    if (sent && expect_pixels_change) {
        for (unsigned int i = 0; i <= attempts; i++) {
            XImage *after = capture_window(display, window);
            changed = image_differs(before, after);
            if (after)
                XDestroyImage(after);
            if (changed || i == attempts)
                break;
            sleep_20ms();
        }
    }
    return changed;
}

static int usage(const char *program)
{
    fprintf(stderr,
            "usage: %s --title=<substring> "
            "(--key=1|tab|enter|left|right|up|down|pagedown|pageup|escape "
            "| --expect-count=N) "
            "[--expect-pixels-change] [--timeout-ms=N]\n",
            program);
    return 2;
}

int main(int argc, char **argv)
{
    struct ui_driver_options options = {
        .title = NULL,
        .key = NULL,
        .expect_count_set = false,
        .expected_count = 0,
        .timeout_ms = 5000,
        .expect_pixels_change = false,
    };
    if (parse_ui_driver_options(argc, argv, &options) != 0)
        return usage(argv[0]);
    if (!ui_driver_options_usable(&options))
        return usage(argv[0]);
    const char *title = options.title;
    const char *key = options.key;
    bool expect_count_set = options.expect_count_set;
    bool expect_pixels_change = options.expect_pixels_change;
    unsigned int expected_count = options.expected_count;

    Display *display = XOpenDisplay(NULL);
    if (!display) {
        fprintf(stderr, "native_ui_driver: DISPLAY cannot be opened\n");
        return 1;
    }
    Window root = DefaultRootWindow(display);
    Window window = None;
    unsigned int count = 0;
    unsigned int attempts = options.timeout_ms / 20u;
    wait_for_matching_windows(display, root, &options, attempts, &window,
                              &count);
    if (expect_count_set) {
        (void)XCloseDisplay(display);
        if (count != expected_count) {
            fprintf(stderr,
                    "native_ui_driver: expected %u matching window(s), saw %u: %s\n",
                    expected_count, count, title);
            return 1;
        }
        printf("{\"schema\":\"zcl.native_ui_window_count.v1\","
               "\"title\":\"%s\",\"count\":%u,\"matched\":true}\n",
               title, count);
        return 0;
    }
    KeySym key_sym = ui_driver_key_symbol(key);
    XImage *before = expect_pixels_change
        ? capture_window(display, window) : NULL;
    bool sent = send_window_event(display, root, window, expect_pixels_change,
                                  before, key_sym);
    bool pixels_changed = pixels_changed_after_send(display, window, before,
                                                    attempts, sent,
                                                    expect_pixels_change);
    if (before)
        XDestroyImage(before);
    (void)XCloseDisplay(display);
    if (!sent || !pixels_changed) {
        fprintf(stderr,
                "native_ui_driver: window/key delivery failed or pixels did not change: %s\n",
                title);
        return 1;
    }
    printf("{\"schema\":\"zcl.native_ui_physical_event.v1\","
           "\"title\":\"%s\",\"key\":\"%s\",\"window\":%lu,"
           "\"delivered\":true,\"pixels_changed\":%s}\n",
           title, key, (unsigned long)window,
           expect_pixels_change ? "true" : "false");
    return 0;
}

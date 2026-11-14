/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Exercise real X11 capture readiness through the maintained UI driver. */
#define _POSIX_C_SOURCE 200809L
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum nur_mode { NUR_DELAYED, NUR_UNMAPPED, NUR_UNCHANGED, NUR_UNEXPECTED, NUR_RACE,
    NUR_NAME_RACE, NUR_TREE_RACE, NUR_NAME_UNEXPECTED, NUR_KEYS, NUR_REPLACED, NUR_NOT_REPLACED };
static struct {
    enum nur_mode mode;
    Display *owner;
    Window window, victim;
    GC gc;
    unsigned int sleeps, presses, releases, images;
    KeySym pressed[4], released[4];
    bool injected, first_null, count_ok;
} nur;

/* This hook establishes order, not a shorter wall-clock performance claim:
 * only the driver's first real polling wait permits the owner to map. */
static int nur_sleep(const struct timespec *duration, struct timespec *remaining)
{
    if (nur.mode == NUR_DELAYED && nur.sleeps == 0) {
        XMapWindow(nur.owner, nur.window);
        (void)XSync(nur.owner, False);
    }
    ++nur.sleeps;
    return nanosleep(duration, remaining);
}
static void nur_events(void)
{
    (void)XSync(nur.owner, False);
    while (XPending(nur.owner)) {
        XEvent event; XNextEvent(nur.owner, &event);
        if (event.xany.window != nur.window) continue;
        if (event.type == KeyPress) {
            if (nur.mode == NUR_KEYS && nur.presses < 4)
                nur.pressed[nur.presses] = XLookupKeysym(&event.xkey, 0);
            ++nur.presses;
            if (nur.mode == NUR_DELAYED || nur.mode == NUR_RACE ||
                nur.mode == NUR_NAME_RACE || nur.mode == NUR_TREE_RACE) {
                XSetForeground(nur.owner, nur.gc, WhitePixel(nur.owner, DefaultScreen(nur.owner)));
                XFillRectangle(nur.owner, nur.window, nur.gc, 0, 0, 80, 60);
            }
        }
        if (event.type == KeyRelease) {
            if (nur.mode == NUR_KEYS && nur.releases < 4)
                nur.released[nur.releases] = XLookupKeysym(&event.xkey, 0);
            ++nur.releases;
        }
    }
    (void)XSync(nur.owner, False);
}
static Status nur_send(Display *display, Window window, Bool propagate,
                       long mask, XEvent *event)
{
    Status result = XSendEvent(display, window, propagate, mask, event);
    (void)XSync(display, False);
    nur_events();
    if (nur.mode == NUR_REPLACED && event->type == KeyRelease) {
        char *name = NULL;
        if (XFetchName(nur.owner, nur.window, &name) && name) {
            int screen = DefaultScreen(nur.owner);
            XDestroyWindow(nur.owner, nur.window);
            nur.window = XCreateSimpleWindow(nur.owner, RootWindow(nur.owner, screen),
                8, 8, 80, 60, 0, 0, 0);
            XStoreName(nur.owner, nur.window, name);
            XSelectInput(nur.owner, nur.window, KeyPressMask | KeyReleaseMask);
            XMapWindow(nur.owner, nur.window);
            XFree(name);
            (void)XSync(nur.owner, False);
        }
    }
    return result;
}
static XImage *nur_image(Display *display, Drawable drawable, int x, int y,
                         unsigned int width, unsigned int height,
                         unsigned long planes, int format)
{
    ++nur.images;
    bool race = nur.mode == NUR_RACE && nur.images == 1;
    if (race) {
        /* Attributes already said viewable. Provoke the real server race. */
        XUnmapWindow(nur.owner, nur.window);
        (void)XSync(nur.owner, False);
    }
    if (nur.mode == NUR_UNEXPECTED) {
        nur.injected = true;
        drawable = None; /* Real server BadDrawable, not the retriable BadMatch. */
    }
    XImage *image = XGetImage(display, drawable, x, y, width, height, planes, format);
    if (race) {
        nur.first_null = image == NULL;
        XMapWindow(nur.owner, nur.window);
        (void)XSync(nur.owner, False);
    }
    return image;
}
static int nur_fetch_name(Display *display, Window window, char **name)
{
    if (window == nur.victim && !nur.injected &&
        (nur.mode == NUR_NAME_RACE || nur.mode == NUR_NAME_UNEXPECTED)) {
        nur.injected = true;
        if (nur.mode == NUR_NAME_UNEXPECTED) return XFetchName(display, None, name);
        XDestroyWindow(nur.owner, nur.victim); (void)XSync(nur.owner, False);
    }
    return XFetchName(display, window, name);
}
static Status nur_query_tree(Display *display, Window window, Window *root, Window *parent,
    Window **children, unsigned int *count)
{
    if (window == nur.victim && !nur.injected && nur.mode == NUR_TREE_RACE) {
        nur.injected = true;
        XDestroyWindow(nur.owner, nur.victim); (void)XSync(nur.owner, False);
    }
    return XQueryTree(display, window, root, parent, children, count);
}
/* This is the previous Xlib handler, so the capture hook must delegate here.
 * The isolated process exits distinctly only for the real injected request. */
static int nur_error(Display *display, XErrorEvent *error)
{
    (void)display;
    bool expected_image = nur.mode == NUR_UNEXPECTED && nur.injected && nur.images == 1 &&
        nur.presses == 0 && nur.releases == 0 && error->error_code == BadDrawable &&
        error->request_code == 73; /* X11 core GetImage opcode. */
    bool expected = expected_image || (nur.mode == NUR_NAME_UNEXPECTED && nur.injected &&
        error->error_code == BadWindow && error->request_code == 20 && error->resourceid == None);
    fprintf(stderr, "UI_DRIVER_FIXTURE xerror=%u opcode=%u delegated=%d\n",
            error->error_code, error->request_code, expected);
    fflush(stderr);
    _Exit(expected ? 77 : 78);
}

/* No replacement capture, image comparison, result predicate or event sender.
 * Each wrapper above calls Xlib; they only schedule mapping, paint as owner,
 * count delivered events and provoke one real error. No production test hook. */
#define nanosleep nur_sleep
#define XSendEvent nur_send
#define XGetImage nur_image
#define XFetchName nur_fetch_name
#define XQueryTree nur_query_tree
#define main native_ui_driver_main
#include "../../tools/native_ui_driver.c"
#undef main
#undef XQueryTree
#undef XFetchName
#undef XGetImage
#undef XSendEvent
#undef nanosleep

static bool nur_open(char title[96])
{
    nur.owner = XOpenDisplay(NULL);
    if (!nur.owner) return false;
    int screen = DefaultScreen(nur.owner);
    unsigned long black = BlackPixel(nur.owner, screen);
    (void)snprintf(title, 96, "z23-driver-readiness-%ld", (long)getpid());
    if (nur.mode == NUR_NAME_RACE || nur.mode == NUR_TREE_RACE || nur.mode == NUR_NAME_UNEXPECTED) {
        nur.victim = XCreateSimpleWindow(nur.owner, RootWindow(nur.owner, screen),
            8, 8, 80, 60, 0, black, black);
        if (nur.victim == None) return false;
        XStoreName(nur.owner, nur.victim, title);
        XMapWindow(nur.owner, nur.victim);
    }
    nur.window = XCreateSimpleWindow(nur.owner, RootWindow(nur.owner, screen),
        8, 8, 80, 60, 0, black, black);
    if (nur.window == None) return false;
    nur.gc = XCreateGC(nur.owner, nur.window, 0, NULL);
    if (!nur.gc) return false;
    XStoreName(nur.owner, nur.window, title);
    XSelectInput(nur.owner, nur.window, KeyPressMask | KeyReleaseMask);
    if (nur.mode == NUR_UNCHANGED || nur.mode == NUR_UNEXPECTED || nur.mode >= NUR_RACE)
        XMapWindow(nur.owner, nur.window);
    (void)XSync(nur.owner, False);
    return true;
}
static bool nur_recovered(int result)
{
    if (result != 0 || nur.presses != 1 || nur.releases != 1) return false;
    if (nur.mode == NUR_RACE)
        return nur.first_null && nur.sleeps >= 1 && nur.images >= 3;
    return nur.sleeps >= 1 && nur.images >= 2;
}
static bool nur_discovery_result(int result)
{
    return result == 0 && nur.injected && nur.count_ok && nur.presses == 1 && nur.releases == 1 && nur.images >= 2;
}
static bool nur_basic_result(int result)
{
    if (nur.mode == NUR_DELAYED || nur.mode == NUR_RACE)
        return nur_recovered(result);
    if (nur.mode == NUR_UNMAPPED)
        return result == 1 && nur.sleeps >= 1 && nur.images == 0 &&
            nur.presses == 0 && nur.releases == 0;
    if (nur.mode == NUR_UNCHANGED)
        return result == 1 && nur.images >= 2 && nur.presses == 1 && nur.releases == 1;
    return false; /* Unexpected error must terminate through nur_error. */
}
static bool nur_result(int result)
{
    if (nur.mode == NUR_REPLACED || nur.mode == NUR_NOT_REPLACED)
        return result == (nur.mode == NUR_REPLACED ? 0 : 1) && nur.presses == 1 && nur.releases == 1;
    if (nur.mode == NUR_KEYS) return result == 0;
    if (nur.mode == NUR_NAME_RACE || nur.mode == NUR_TREE_RACE) return nur_discovery_result(result);
    return nur_basic_result(result);
}
static bool nur_mode_parse(const char *name)
{
    static const char *const modes[] = {"delayed", "unmapped", "unchanged", "unexpected", "race",
        "name-race", "tree-race", "name-unexpected", "keys", "replaced", "not-replaced"};
    for (size_t i = 0; i < sizeof(modes)/sizeof(modes[0]); ++i)
        if (!strcmp(name, modes[i])) { nur.mode = (enum nur_mode)i; return true; }
    return false;
}
static bool nur_keys(const char *option)
{
    static const char *const keys[] = {"--key=1", "--key=2", "--key=3", "--key=4"};
    static const KeySym expected[] = {XK_1, XK_2, XK_3, XK_4};
    for (size_t i = 0; i < 4; ++i) {
        char *args[] = {"native_ui_driver", (char *)option, (char *)keys[i], "--timeout-ms=200", NULL};
        if (native_ui_driver_main(4, args) != 0 || nur.presses != i + 1 || nur.releases != i + 1 ||
            nur.pressed[i] != expected[i] || nur.released[i] != expected[i]) return false;
    }
    char *invalid[] = {"native_ui_driver", (char *)option, "--key=5", "--timeout-ms=200", NULL};
    return native_ui_driver_main(4, invalid) == 2 && nur.presses == 4 && nur.releases == 4;
}
static int nur_run_driver(char *option)
{
    char *args[] = {"native_ui_driver", option, "--key=tab", "--expect-pixels-change", "--timeout-ms=200", NULL};
    char *replace_args[] = {"native_ui_driver", option, "--key=1", "--expect-window-replaced", "--timeout-ms=200", NULL};
    if (nur.mode == NUR_KEYS) return nur_keys(option) ? 0 : 1;
    return nur.mode >= NUR_REPLACED ? native_ui_driver_main(5, replace_args) : native_ui_driver_main(5, args);
}
int main(int argc, char **argv)
{
    if (argc != 2 || !nur_mode_parse(argv[1])) return 2;
    char title[96], option[112];
    bool ready = nur_open(title);
    int result = -1;
    if (ready) {
        (void)snprintf(option, sizeof(option), "--title=%s", title);
        XErrorHandler previous = XSetErrorHandler(nur_error);
        if (nur.mode == NUR_NAME_RACE || nur.mode == NUR_TREE_RACE) {
            char *count_args[] = {"native_ui_driver", option, "--expect-count=1", "--timeout-ms=200", NULL};
            nur.count_ok = native_ui_driver_main(4, count_args) == 0;
        }
        result = nur_run_driver(option);
        (void)XSetErrorHandler(previous);
    }
    bool ok = ready && nur_result(result);
    printf("UI_DRIVER_FIXTURE mode=%s driver_exit=%d presses=%u releases=%u images=%u sleeps=%u first_null=%d passed=%d\n",
        argv[1], result, nur.presses, nur.releases, nur.images, nur.sleeps, nur.first_null, ok);
    if (nur.gc) XFreeGC(nur.owner, nur.gc);
    if (nur.victim != None && !nur.injected) XDestroyWindow(nur.owner, nur.victim);
    if (nur.window != None) XDestroyWindow(nur.owner, nur.window);
    if (nur.owner) XCloseDisplay(nur.owner);
    return ok ? 0 : 1;
}

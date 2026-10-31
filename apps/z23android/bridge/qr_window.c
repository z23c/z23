/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "qrcodegen.h"
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef ZAPP_QR_NO_X11
#include <X11/Xlib.h>
#endif

#define TEXT_MAX 2332u
#define QUIET_MODULES 4
#define MIN_PIXELS 480
#define TITLE_MAX 256
#define TIMEOUT_MAX 86400L

struct qr {
    int count;
    uint8_t code[qrcodegen_BUFFER_LEN_MAX], temp[qrcodegen_BUFFER_LEN_MAX];
};
struct options { const char *title, *dump; long timeout; };
static const char usage[] =
    "Usage: z23-qr-window [--title=TEXT] [--timeout=SECONDS] [--dump=FILE] < text\n";

static int scale_for(int count)
{
    int modules = count + 2 * QUIET_MODULES;
    return (MIN_PIXELS + modules - 1) / modules;
}
static int side_for(int count)
{ return (count + 2 * QUIET_MODULES) * scale_for(count); }

/* Reads at most cap bytes of text from standard input; empty, NUL-containing or longer text is refused. */
static bool read_text(char *text, size_t cap, size_t *size)
{
    *size = fread(text, 1, cap, stdin);
    if (ferror(stdin) || *size == 0 || *size > TEXT_MAX) {
        fputs("z23-qr-window: standard input must hold 1 to 2332 bytes of text\n", stderr);
        return false;
    }
    if (memchr(text, 0, *size)) {
        fputs("z23-qr-window: text must not contain NUL bytes\n", stderr);
        return false;
    }
    text[*size] = 0;
    return true;
}
/* Medium error correction when the text fits it, otherwise low. */
static bool encode(const char *text, struct qr *code)
{
    static const enum qrcodegen_Ecc levels[] = {qrcodegen_Ecc_MEDIUM, qrcodegen_Ecc_LOW};
    for (size_t i = 0; i < sizeof(levels) / sizeof(levels[0]); ++i) {
        if (!qrcodegen_encodeText(text, code->temp, code->code, levels[i], qrcodegen_VERSION_MIN,
                                  qrcodegen_VERSION_MAX, qrcodegen_Mask_AUTO, false)) continue;
        code->count = qrcodegen_getSize(code->code);
        return true;
    }
    return false;
}
/* Sets the bits of one dark module's pixels in packed PBM rows, most significant bit first. */
static void set_module(unsigned char *pixels, size_t row, int mx, int my, int scale)
{
    for (int py = 0; py < scale; ++py) for (int px = 0; px < scale; ++px) {
        size_t x = (size_t)((mx + QUIET_MODULES) * scale + px), y = (size_t)((my + QUIET_MODULES) * scale + py);
        pixels[y * row + x / 8] |= (unsigned char)(0x80u >> (x % 8));
    }
}
/* Writes the code as a binary PBM with 1 for black. Returns the byte count, or 0 when out is too small. */
static size_t pbm_write(const struct qr *code, unsigned char *out, size_t cap)
{
    int side = side_for(code->count), scale = scale_for(code->count);
    size_t row = ((size_t)side + 7) / 8, body = row * (size_t)side;
    int head = snprintf((char *)out, cap, "P4\n%d %d\n", side, side);
    if (head <= 0 || (size_t)head + body > cap) return 0;
    unsigned char *pixels = out + head;
    memset(pixels, 0, body);
    for (int my = 0; my < code->count; ++my) for (int mx = 0; mx < code->count; ++mx)
        if (qrcodegen_getModule(code->code, mx, my)) set_module(pixels, row, mx, my, scale);
    return (size_t)head + body;
}
static bool dump_pbm(const struct qr *code, const char *path)
{
    int side = side_for(code->count);
    size_t row = ((size_t)side + 7) / 8, cap = 32 + row * (size_t)side;
    unsigned char *out = calloc(1, cap);
    size_t n = out ? pbm_write(code, out, cap) : 0;
    FILE *f = n ? fopen(path, "wb") : NULL;
    bool ok = f && fwrite(out, 1, n, f) == n;
    if (f && fclose(f) != 0) ok = false;
    free(out);
    if (!ok) fprintf(stderr, "z23-qr-window: could not write %s\n", path);
    return ok;
}
#ifdef ZAPP_QR_NO_X11
static bool show_code(const struct qr *code, const char *title, long timeout)
{
    (void)code; (void)title; (void)timeout;
    fputs("z23-qr-window: this build has no window support; use --dump\n", stderr);
    return false;
}
#else
struct window {
    Display *display;
    Window window;
    GC dark, light;
    Atom close;
    const struct qr *code;
    int side, scale;
};
/* Draws the same modules as pbm_write: a black square per dark module on a white background. */
static void paint(const struct window *w)
{
    unsigned side = (unsigned)w->side, scale = (unsigned)w->scale;
    XFillRectangle(w->display, w->window, w->light, 0, 0, side, side);
    for (int my = 0; my < w->code->count; ++my) for (int mx = 0; mx < w->code->count; ++mx)
        if (qrcodegen_getModule(w->code->code, mx, my))
            XFillRectangle(w->display, w->window, w->dark, (mx + QUIET_MODULES) * w->scale,
                           (my + QUIET_MODULES) * w->scale, scale, scale);
}
/* True when the event asks the window to close. */
static bool handle(const struct window *w, const XEvent *event)
{
    switch (event->type) {
    case Expose:
        if (event->xexpose.count == 0) paint(w);
        return false;
    case KeyPress:
        return true;
    case ClientMessage:
        return (Atom)event->xclient.data.l[0] == w->close;
    default:
        return false;
    }
}
static void wait_for_close(const struct window *w, long timeout)
{
    struct timespec start, now, nap = {0, 20000000};
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        while (XPending(w->display)) {
            XEvent event;
            XNextEvent(w->display, &event);
            if (handle(w, &event)) return;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (timeout && now.tv_sec - start.tv_sec >= timeout) return;
        nanosleep(&nap, NULL);
    }
}
static bool open_window(struct window *w, const struct qr *code, const char *title)
{
    w->display = XOpenDisplay(NULL);
    if (!w->display) {
        fputs("z23-qr-window: DISPLAY is not set or the X server refused the connection\n", stderr);
        return false;
    }
    int screen = DefaultScreen(w->display);
    unsigned long black = BlackPixel(w->display, screen), white = WhitePixel(w->display, screen);
    w->code = code; w->side = side_for(code->count); w->scale = scale_for(code->count);
    w->window = XCreateSimpleWindow(w->display, RootWindow(w->display, screen), 0, 0,
                                    (unsigned)w->side, (unsigned)w->side, 0, black, white);
    XStoreName(w->display, w->window, title);
    w->close = XInternAtom(w->display, "WM_DELETE_WINDOW", False);
    XSetWMProtocols(w->display, w->window, &w->close, 1);
    XSelectInput(w->display, w->window, ExposureMask | KeyPressMask);
    w->dark = XCreateGC(w->display, w->window, 0, NULL);
    w->light = XCreateGC(w->display, w->window, 0, NULL);
    XSetForeground(w->display, w->dark, black);
    XSetForeground(w->display, w->light, white);
    XMapWindow(w->display, w->window);
    XFlush(w->display);
    return true;
}
static bool show_code(const struct qr *code, const char *title, long timeout)
{
    struct window w = {0};
    if (!open_window(&w, code, title)) return false;
    wait_for_close(&w, timeout);
    XFreeGC(w.display, w.dark);
    XFreeGC(w.display, w.light);
    XDestroyWindow(w.display, w.window);
    XCloseDisplay(w.display);
    return true;
}
#endif
static bool set_option(int c, struct options *o)
{
    char *end = NULL;
    switch (c) {
    case 't': o->title = optarg; return strlen(optarg) < TITLE_MAX;
    case 'd': o->dump = optarg; return optarg[0] != 0;
    case 's':
        o->timeout = strtol(optarg, &end, 10);
        return end != optarg && !*end && o->timeout >= 0 && o->timeout <= TIMEOUT_MAX;
    default: return false;
    }
}
static bool parse(int argc, char **argv, struct options *o)
{
    static const struct option longs[] = {{"title", 1, 0, 't'}, {"timeout", 1, 0, 's'},
        {"dump", 1, 0, 'd'}, {0, 0, 0, 0}};
    *o = (struct options){.title = "Z23 QR code", .timeout = 0};
    for (int c; (c = getopt_long(argc, argv, "", longs, NULL)) != -1;)
        if (!set_option(c, o)) return false;
    return optind == argc;
}
int main(int argc, char **argv)
{
    static char text[TEXT_MAX + 2];
    static struct qr code;
    struct options o;
    size_t size = 0;
    if (!parse(argc, argv, &o)) { fputs(usage, stderr); return 2; }
    if (!read_text(text, TEXT_MAX + 1, &size)) return 1;
    if (!encode(text, &code)) {
        fputs("z23-qr-window: the text does not fit in a QR code\n", stderr);
        return 1;
    }
    if (o.dump) return dump_pbm(&code, o.dump) ? 0 : 1;
    return show_code(&code, o.title, o.timeout) ? 0 : 1;
}

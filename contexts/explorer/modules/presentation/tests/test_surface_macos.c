/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Native macOS regression: software blits must not modify caller pixels. */
#define RGFW_NO_API
#define RGFW_NO_IOKIT
#define RGFWDEF extern
#include "RGFW.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(__APPLE__)
enum { WIDTH = 32, HEIGHT = 24, GUARD = WIDTH * HEIGHT + 64,
       CAPACITY = WIDTH * HEIGHT * 4 + GUARD };

#include <objc/message.h>
#include <objc/runtime.h>
#include <stdbool.h>

/* Read the actual image attached by RGFW before AppKit's event pump can
 * replace layer contents. This is backing-image evidence, not a screenshot. */
static bool bitmap_is_kind(id object, const char *class_name)
{
    BOOL (*is_kind)(id, SEL, Class) = (BOOL (*)(id, SEL, Class))objc_msgSend;
    Class cls = objc_getClass(class_name);
    return object && cls && is_kind(object, sel_registerName("isKindOfClass:"), cls);
}

static id retained_bitmap_rep(RGFW_window *window)
{
    id (*get_object)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id native_window = (id)RGFW_window_getWindow_OSX(window);
    id view = get_object(native_window, sel_registerName("contentView"));
    id layer = get_object(view, sel_registerName("layer"));
    id image = get_object(layer, sel_registerName("contents"));
    if (!bitmap_is_kind(image, "NSImage")) {
        fprintf(stderr, "macOS blit: layer contents is not an NSImage\n");
        return NULL;
    }
    id reps = get_object(image, sel_registerName("representations"));
    unsigned long count = ((unsigned long (*)(id, SEL))objc_msgSend)(reps, sel_registerName("count"));
    if (!count) { fprintf(stderr, "macOS blit: image has no representation\n"); return NULL; }
    id rep = ((id (*)(id, SEL, unsigned long))objc_msgSend)(reps, sel_registerName("objectAtIndex:"), 0ul);
    if (!bitmap_is_kind(rep, "NSBitmapImageRep")) {
        fprintf(stderr, "macOS blit: representation is not an NSBitmapImageRep\n");
        return NULL;
    }
    return rep;
}

struct retained_bitmap { const uint8_t *pixels; long width, height, stride; };

static bool retained_bitmap_geometry(RGFW_window *window, id rep, struct retained_bitmap *bitmap)
{
    long (*number)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
    bitmap->width = number(rep, sel_registerName("pixelsWide"));
    bitmap->height = number(rep, sel_registerName("pixelsHigh"));
    bitmap->stride = number(rep, sel_registerName("bytesPerRow"));
    bitmap->pixels = ((unsigned char *(*)(id, SEL))objc_msgSend)(rep, sel_registerName("bitmapData"));
    i32 width = 0, height = 0;
    if (!RGFW_window_getSize(window, &width, &height)) return false;
    long clipped_width = width < WIDTH ? width : WIDTH;
    long clipped_height = height < HEIGHT ? height : HEIGHT;
    bool valid = bitmap->pixels && bitmap->width == clipped_width && bitmap->height == clipped_height &&
        bitmap->width >= 1 && bitmap->height >= 2 && bitmap->stride >= bitmap->width * 4 &&
        number(rep, sel_registerName("samplesPerPixel")) == 4 &&
        number(rep, sel_registerName("bitsPerSample")) == 8;
    if (!valid) fprintf(stderr, "macOS blit: invalid bitmap dimensions or storage\n");
    return valid;
}

static bool retained_bitmap_samples(const struct retained_bitmap *bitmap,
                                    RGFW_format format, const uint8_t *source)
{
    static const unsigned char channels[6][4] = {
        {0,1,2,3}, {2,1,0,3}, {0,1,2,3},
        {1,2,3,0}, {2,1,0,3}, {3,2,1,0}
    };
    size_t depth = format >= RGFW_formatRGBA8 ? 4u : 3u;
    const long positions[2][2] = { {0, 0}, {bitmap->width - 1, 1} };
    for (size_t i = 0; i < 2; ++i) {
        size_t x = (size_t)positions[i][0], y = (size_t)positions[i][1];
        const uint8_t *src = source + (y * WIDTH + x) * depth;
        const uint8_t *actual = bitmap->pixels + y * (size_t)bitmap->stride + x * 4u;
        for (size_t c = 0; c < 4; ++c) {
            uint8_t expected = c == 3 && depth == 3 ? 255u : src[channels[format][c]];
            if (actual[c] != expected) {
                fprintf(stderr, "macOS blit: format %u pixel %zu channel %zu differs\n",
                        (unsigned)format, i, c);
                return false;
            }
        }
    }
    return true;
}

static bool retained_bitmap_matches(RGFW_window *window, RGFW_format format, const uint8_t *source)
{
    id rep = retained_bitmap_rep(window);
    struct retained_bitmap bitmap = {0};
    return rep && retained_bitmap_geometry(window, rep, &bitmap) &&
        retained_bitmap_samples(&bitmap, format, source);
}

static int blit_format(RGFW_window *window, RGFW_format format)
{
    uint8_t pixels[CAPACITY], before[CAPACITY];
    size_t channels = format >= RGFW_formatRGBA8 ? 4u : 3u;
    size_t bytes = WIDTH * HEIGHT * channels;
    for (size_t i = 0; i < bytes; ++i) pixels[i] = (uint8_t)(i * 37u + 11u);
    memset(pixels + bytes, 0xa5, sizeof(pixels) - bytes);
    memcpy(before, pixels, sizeof(pixels));
    RGFW_surface *surface = RGFW_createSurface(pixels, WIDTH, HEIGHT, format);
    if (!surface) { fprintf(stderr, "macOS surface allocation failed\n"); return 1; }
    RGFW_window_blitSurface(window, surface);
    bool retained = retained_bitmap_matches(window, format, before);
    RGFW_event event;
    for (unsigned i = 0; i < 16 && RGFW_window_checkEvent(window, &event); ++i) {}
    RGFW_surface_free(surface);
    if (memcmp(pixels, before, sizeof(pixels)) != 0) {
        fprintf(stderr, "macOS blit modified source or guard for format %u\n", (unsigned)format);
        return 1;
    }
    return retained ? 0 : 1;
}

int main(void)
{
    RGFW_window *window = RGFW_createWindow("Z23 bitmap smoke", 0, 0, 24, 18, 0);
    if (!window) { fprintf(stderr, "macOS smoke could not create a window\n"); return 1; }
    int failures = 0;
    const RGFW_format formats[] = { RGFW_formatRGB8, RGFW_formatBGR8,
        RGFW_formatRGBA8, RGFW_formatARGB8, RGFW_formatBGRA8, RGFW_formatABGR8 };
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i)
        failures += blit_format(window, formats[i]);
    RGFW_window_close(window);
    if (!failures) puts("macOS surface smoke: six formats preserve source pixels and guards");
    return failures ? 1 : 0;
}
#else
#error "This native smoke test requires macOS"
#endif

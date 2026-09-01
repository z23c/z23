/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: clipped RGB software drawing primitives for native presentation. */

#include "presentation/canvas.h"

#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

/* GCC 16 can fold stb_truetype's `(float)sqrt(double_expression)` into the
 * host's new sqrtf ABI even when the release link targets the pinned older
 * glibc sysroot. Keep the vendored renderer on the long-established double
 * sqrt symbol; volatile blocks that unsafe cross-ABI narrowing transform. */
static double canvas_sqrt_compat(double value)
{
    volatile double exact = value;
    return sqrt(exact);
}

/* The pinned upstream implementation compares float intermediates with a few
 * unsuffixed math constants. Keep the project's -Werror contract on our code
 * while containing that third-party-only -Wdouble-promotion diagnostic. */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdouble-promotion"
#endif
#define STBTT_sqrt(x) canvas_sqrt_compat(x)
#define STBTT_pow(x, y) pow((x), (y))
#define STB_TRUETYPE_IMPLEMENTATION
#include "../../../vendor/typography/stb_truetype.h"
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
#include "../../../vendor/typography/noto_sans_ascii.inc"

static void canvas_pixel(struct zcl_present_canvas *canvas, int32_t x,
                         int32_t y, struct zcl_present_color color)
{
    if (!canvas || !canvas->pixels || x < 0 || y < 0 ||
        (uint32_t)x >= canvas->width || (uint32_t)y >= canvas->height)
        return;
    size_t at = (size_t)y * canvas->stride + (size_t)x * 3u;
    canvas->pixels[at] = color.r;
    canvas->pixels[at + 1u] = color.g;
    canvas->pixels[at + 2u] = color.b;
}

bool zcl_present_canvas_init(struct zcl_present_canvas *canvas,
                             uint8_t *pixels, size_t pixels_cap,
                             uint32_t width, uint32_t height)
{
    if (!canvas) return false; // raw-return-ok:pure bounded initializer
    *canvas = (struct zcl_present_canvas){0};
    if (!pixels || width == 0 || height == 0 ||
        width > ZCL_PRESENT_CANVAS_DIMENSION_MAX ||
        height > ZCL_PRESENT_CANVAS_DIMENSION_MAX ||
        pixels_cap < (size_t)width * height * 3u)
        return false; // raw-return-ok:pure bounded initializer
    canvas->pixels = pixels;
    canvas->width = width;
    canvas->height = height;
    canvas->stride = (size_t)width * 3u;
    return true;
}

void zcl_present_canvas_clear(struct zcl_present_canvas *canvas,
                              struct zcl_present_color color)
{
    if (!canvas) return;
    zcl_present_canvas_fill_rect(canvas, 0, 0, canvas->width, canvas->height,
                                 color);
}

void zcl_present_canvas_fill_rect(struct zcl_present_canvas *canvas,
                                  int32_t x, int32_t y,
                                  uint32_t width, uint32_t height,
                                  struct zcl_present_color color)
{
    if (!canvas || !canvas->pixels || width == 0 || height == 0) return;
    int64_t left = x;
    int64_t top = y;
    int64_t right = left + width;
    int64_t bottom = top + height;
    if (left < 0) left = 0;
    if (top < 0) top = 0;
    if (right > canvas->width) right = canvas->width;
    if (bottom > canvas->height) bottom = canvas->height;
    if (left >= right || top >= bottom) return;
    for (int64_t py = top; py < bottom; py++) {
        for (int64_t px = left; px < right; px++)
            canvas_pixel(canvas, (int32_t)px, (int32_t)py, color);
    }
}

void zcl_present_canvas_stroke_rect(struct zcl_present_canvas *canvas,
                                    int32_t x, int32_t y,
                                    uint32_t width, uint32_t height,
                                    uint32_t thickness,
                                    struct zcl_present_color color)
{
    if (thickness == 0) return;
    zcl_present_canvas_fill_rect(canvas, x, y, width, thickness, color);
    zcl_present_canvas_fill_rect(canvas, x, y, thickness, height, color);
    int64_t right = (int64_t)x + width - thickness;
    int64_t bottom = (int64_t)y + height - thickness;
    if (right >= INT32_MIN && right <= INT32_MAX)
        zcl_present_canvas_fill_rect(canvas, (int32_t)right, y, thickness,
                                     height, color);
    if (bottom >= INT32_MIN && bottom <= INT32_MAX)
        zcl_present_canvas_fill_rect(canvas, x, (int32_t)bottom, width,
                                     thickness, color);
}

void zcl_present_canvas_line(struct zcl_present_canvas *canvas,
                             int32_t x0, int32_t y0,
                             int32_t x1, int32_t y1,
                             struct zcl_present_color color)
{
    int64_t x = x0;
    int64_t y = y0;
    int64_t dx = x1 >= x0 ? (int64_t)x1 - x0 : (int64_t)x0 - x1;
    int64_t sx = x0 < x1 ? 1 : -1;
    int64_t dy = y1 >= y0 ? (int64_t)y0 - y1 : (int64_t)y1 - y0;
    int64_t sy = y0 < y1 ? 1 : -1;
    int64_t error = dx + dy;
    for (;;) {
        canvas_pixel(canvas, (int32_t)x, (int32_t)y, color);
        if (x == x1 && y == y1) break;
        int64_t twice = error * 2;
        if (twice >= dy) { error += dy; x += sx; }
        if (twice <= dx) { error += dx; y += sy; }
    }
}

void zcl_present_canvas_blit_rgba(struct zcl_present_canvas *canvas,
                                  int32_t x, int32_t y,
                                  const uint8_t *rgba,
                                  uint32_t width, uint32_t height)
{
    if (!canvas || !rgba) return;
    for (uint32_t py = 0; py < height; py++) {
        for (uint32_t px = 0; px < width; px++) {
            size_t src = ((size_t)py * width + px) * 4u;
            uint8_t alpha = rgba[src + 3u];
            int64_t dx = (int64_t)x + px;
            int64_t dy = (int64_t)y + py;
            if (alpha == 0 || dx < 0 || dy < 0 ||
                dx >= canvas->width || dy >= canvas->height)
                continue;
            size_t dst = (size_t)dy * canvas->stride + (size_t)dx * 3u;
            for (size_t channel = 0; channel < 3u; channel++) {
                uint32_t mixed = (uint32_t)rgba[src + channel] * alpha +
                    (uint32_t)canvas->pixels[dst + channel] * (255u - alpha);
                canvas->pixels[dst + channel] = (uint8_t)((mixed + 127u) / 255u);
            }
        }
    }
}

static bool canvas_font(stbtt_fontinfo *font)
{
    if (!font || g_zcl_noto_sans_ascii_len == 0) return false;
    int offset = stbtt_GetFontOffsetForIndex(g_zcl_noto_sans_ascii, 0);
    return offset >= 0 &&
           stbtt_InitFont(font, g_zcl_noto_sans_ascii, offset) != 0;
}

static int canvas_codepoint(unsigned char ch)
{
    return ch >= 32u && ch <= 126u ? ch : '?';
}

static int canvas_text_advance(const stbtt_fontinfo *font, int codepoint,
                               int next, float scale)
{
    int advance = 0;
    int bearing = 0;
    stbtt_GetCodepointHMetrics(font, codepoint, &advance, &bearing);
    (void)bearing;
    int kern = next ? stbtt_GetCodepointKernAdvance(font, codepoint, next) : 0;
    float pixels = (float)(advance + kern) * scale;
    return pixels > 0.0f ? (int)(pixels + 0.5f) : 0;
}

uint32_t zcl_present_canvas_text_width(const char *text, size_t text_len,
                                       uint32_t pixel_height)
{
    if (!text || pixel_height < 8u || pixel_height > 96u) return 0;
    stbtt_fontinfo font;
    if (!canvas_font(&font)) return 0;
    float scale = stbtt_ScaleForPixelHeight(&font, (float)pixel_height);
    uint64_t width = 0;
    for (size_t i = 0; i < text_len; i++) {
        int ch = canvas_codepoint((unsigned char)text[i]);
        int next = i + 1u < text_len
            ? canvas_codepoint((unsigned char)text[i + 1u]) : 0;
        width += (uint32_t)canvas_text_advance(&font, ch, next, scale);
        if (width > UINT32_MAX) return UINT32_MAX;
    }
    return (uint32_t)width;
}

void zcl_present_canvas_text(struct zcl_present_canvas *canvas,
                             int32_t x, int32_t y,
                             const char *text, size_t text_len,
                             uint32_t pixel_height,
                             struct zcl_present_color color)
{
    if (!canvas || !text || pixel_height < 8u || pixel_height > 96u) return;
    stbtt_fontinfo font;
    if (!canvas_font(&font)) return;
    float scale = stbtt_ScaleForPixelHeight(&font, (float)pixel_height);
    int ascent = 0;
    int descent = 0;
    int line_gap = 0;
    stbtt_GetFontVMetrics(&font, &ascent, &descent, &line_gap);
    (void)descent;
    (void)line_gap;
    int32_t baseline = y + (int32_t)((float)ascent * scale + 0.5f);
    int32_t pen_x = x;
    for (size_t i = 0; i < text_len; i++) {
        int ch = canvas_codepoint((unsigned char)text[i]);
        int next = i + 1u < text_len
            ? canvas_codepoint((unsigned char)text[i + 1u]) : 0;
        int x0 = 0;
        int y0 = 0;
        int x1 = 0;
        int y1 = 0;
        stbtt_GetCodepointBitmapBox(&font, ch, scale, scale,
                                    &x0, &y0, &x1, &y1);
        int glyph_width = x1 - x0;
        int glyph_height = y1 - y0;
        if (glyph_width > 0 && glyph_height > 0 &&
            glyph_width <= 128 && glyph_height <= 128) {
            uint8_t bitmap[128u * 128u];
            memset(bitmap, 0, sizeof(bitmap));
            stbtt_MakeCodepointBitmap(&font, bitmap, glyph_width, glyph_height,
                                      128, scale, scale, ch);
            for (int row = 0; row < glyph_height; row++) {
                for (int col = 0; col < glyph_width; col++) {
                    uint8_t alpha = bitmap[(size_t)row * 128u + (size_t)col];
                    int32_t px = pen_x + x0 + col;
                    int32_t py = baseline + y0 + row;
                    if (alpha == 0 || px < 0 || py < 0 ||
                        (uint32_t)px >= canvas->width ||
                        (uint32_t)py >= canvas->height)
                        continue;
                    size_t dst = (size_t)py * canvas->stride +
                                 (size_t)px * 3u;
                    const uint8_t source[3] = {color.r, color.g, color.b};
                    for (size_t channel = 0; channel < 3u; channel++) {
                        uint32_t mixed = (uint32_t)source[channel] * alpha +
                            (uint32_t)canvas->pixels[dst + channel] *
                            (255u - alpha);
                        canvas->pixels[dst + channel] =
                            (uint8_t)((mixed + 127u) / 255u);
                    }
                }
            }
        }
        int advance = canvas_text_advance(&font, ch, next, scale);
        if (advance > INT32_MAX - pen_x) break;
        pen_x += advance;
    }
}

/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Prepare presentation bitmaps for display and image clipboard formats. */
#include "presentation_bitmap_internal.h"
#include "util/png_writer.h"
#include "base/serialize_le.h"
#include <stdlib.h>
#include <string.h>

bool zcl_present_bitmap_encode_bmp_v1(
    const struct zcl_present_window_v1 *page,
    uint8_t *output, size_t output_cap, size_t *written)
{
    if (!page || !written || !page->pixels || page->width == 0 ||
        page->height == 0 ||
        (page->pixel_format != ZCL_PRESENT_RGB8 &&
         page->pixel_format != ZCL_PRESENT_RGBA8))
        return false;
    uint64_t row_bytes = ((uint64_t)page->width * 3u + 3u) & ~UINT64_C(3);
    uint64_t pixel_bytes = row_bytes * page->height;
    uint64_t total = 54u + pixel_bytes;
    if (row_bytes > SIZE_MAX || total > SIZE_MAX || total > UINT32_MAX)
        return false;
    *written = (size_t)total;
    if (!output) return true;
    if (output_cap < (size_t)total) return false;
    uint8_t *bmp = output;
    memset(bmp, 0, (size_t)total);
    bmp[0] = 'B';
    bmp[1] = 'M';
    zcl_write_u32_le(bmp + 2, (uint32_t)total);
    zcl_write_u32_le(bmp + 10, 54u);
    zcl_write_u32_le(bmp + 14, 40u);
    zcl_write_u32_le(bmp + 18, page->width);
    zcl_write_u32_le(bmp + 22, page->height);
    zcl_write_u16_le(bmp + 26, 1u);
    zcl_write_u16_le(bmp + 28, 24u);
    zcl_write_u32_le(bmp + 34, (uint32_t)pixel_bytes);
    uint32_t channels = (uint32_t)page->pixel_format;
    for (uint32_t y = 0; y < page->height; y++) {
        uint32_t source_y = page->height - 1u - y;
        const uint8_t *source = page->pixels +
            (size_t)source_y * page->width * channels;
        uint8_t *target = bmp + 54u + (size_t)y * (size_t)row_bytes;
        for (uint32_t x = 0; x < page->width; x++) {
            target[x * 3u] = source[x * channels + 2u];
            target[x * 3u + 1u] = source[x * channels + 1u];
            target[x * 3u + 2u] = source[x * channels];
        }
    }
    return true;
}

#if defined(_WIN32) || defined(__linux__)
bool present_bmp_encode(
    const struct zcl_present_window_v1 *page,
    uint8_t **encoded, size_t *encoded_len)
{
    size_t required = 0;
    if (!encoded || !encoded_len ||
        !zcl_present_bitmap_encode_bmp_v1(
            page, NULL, 0u, &required))
        return false;
    uint8_t *bmp = malloc(required); // raw-alloc-ok:standalone-presentation-package
    if (!bmp) return false;
    if (!zcl_present_bitmap_encode_bmp_v1(
            page, bmp, required, encoded_len)) {
        free(bmp);
        return false;
    }
    *encoded = bmp;
    return true;
}
#endif

bool present_png_encode(
    const struct zcl_present_window_v1 *page,
    uint8_t **encoded, size_t *encoded_len)
{
    size_t required = 0;
    bool sized = page && encoded && encoded_len &&
        (page->pixel_format == ZCL_PRESENT_RGB8
            ? png_encode_rgb(page->pixels, page->width, page->height,
                             NULL, 0u, &required)
            : png_encode_rgba(page->pixels, page->width, page->height,
                              NULL, 0u, &required));
    if (!sized) return false;
    uint8_t *png = malloc(required); // raw-alloc-ok:standalone-presentation-package
    if (!png) return false;
    bool ok = page->pixel_format == ZCL_PRESENT_RGB8
        ? png_encode_rgb(page->pixels, page->width, page->height,
                         png, required, encoded_len)
        : png_encode_rgba(page->pixels, page->width, page->height,
                          png, required, encoded_len);
    if (!ok) {
        free(png);
        return false;
    }
    *encoded = png;
    return true;
}

bool present_scale_bitmap(const struct zcl_present_window_v1 *request,
                                 int32_t target_width, int32_t target_height,
                                 uint8_t **out)
{
    *out = NULL;
    if (target_width <= 0 || target_height <= 0 ||
        target_width > 4096 || target_height > 4096)
        return false;
    uint32_t channels = (uint32_t)request->pixel_format;
    uint64_t bytes = (uint64_t)(uint32_t)target_width *
                     (uint32_t)target_height * channels;
    if (bytes == 0 || bytes > SIZE_MAX) return false;
    uint8_t *pixels = malloc((size_t)bytes); // raw-alloc-ok:standalone-presentation-package
    if (!pixels) return false;
    for (uint64_t i = 0; i < bytes; i += channels) {
        pixels[i] = 0x20;
        pixels[i + 1u] = 0x20;
        pixels[i + 2u] = 0x22;
        if (channels == 4u) pixels[i + 3u] = 0xff;
    }

    uint32_t draw_width = (uint32_t)target_width;
    uint32_t draw_height = (uint32_t)((uint64_t)draw_width *
                                      request->height / request->width);
    if (draw_height > (uint32_t)target_height) {
        draw_height = (uint32_t)target_height;
        draw_width = (uint32_t)((uint64_t)draw_height *
                                request->width / request->height);
    }
    if (draw_width == 0 || draw_height == 0) {
        free(pixels);
        return false;
    }
    uint32_t x0 = ((uint32_t)target_width - draw_width) / 2u;
    uint32_t y0 = ((uint32_t)target_height - draw_height) / 2u;
    for (uint32_t y = 0; y < draw_height; y++) {
        uint32_t source_y = (uint32_t)((uint64_t)y * request->height /
                                       draw_height);
        for (uint32_t x = 0; x < draw_width; x++) {
            uint32_t source_x = (uint32_t)((uint64_t)x * request->width /
                                           draw_width);
            size_t source = ((size_t)source_y * request->width + source_x) *
                            channels;
            size_t target = ((size_t)(y0 + y) * (uint32_t)target_width +
                             x0 + x) * channels;
            memcpy(pixels + target, request->pixels + source, channels);
        }
    }
    *out = pixels;
    return true;
}

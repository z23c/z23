/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "camera_access.h"
#include <stdint.h>

static bool camera_size_valid(int format, int type, int width, int height)
{
    return format == 35 && type == 0 && width > 0 && height > 0 && width <= 4096 && height <= 4096;
}
static int64_t camera_distance(int64_t a, int64_t b)
{
    return a > b ? a - b : b - a;
}
static bool camera_better(int64_t score, int64_t shape, int64_t best_score, int64_t best_shape, bool found)
{
    return !found || score < best_score || (score == best_score && shape < best_shape);
}

bool zapp_camera_choose_size(const int32_t *entries, size_t count, int wanted_width, int wanted_height,
                             int *width, int *height)
{
    if (!entries || count % 4 || wanted_width <= 0 || wanted_height <= 0 || !width || !height) return false;
    const int64_t wanted_area = (int64_t)wanted_width * wanted_height;
    int64_t best_score = INT64_MAX, best_shape = INT64_MAX;
    bool found = false;
    for (size_t i = 0; i < count; i += 4) {
        int32_t w = entries[i + 1], h = entries[i + 2];
        if (!camera_size_valid(entries[i], entries[i + 3], w, h)) continue;
        int64_t score = camera_distance((int64_t)w * h, wanted_area);
        int64_t shape = camera_distance(w, wanted_width) + camera_distance(h, wanted_height);
        if (camera_better(score, shape, best_score, best_shape, found)) {
            *width = w; *height = h; best_score = score; best_shape = shape; found = true;
        }
    }
    return found;
}

/* Offset of the last luma sample. False when the product does not fit in int64. */
static bool span_offset(int count, int step, int64_t *out)
{
    if (count <= 1) { *out = 0; return true; }
    if ((int64_t)(count - 1) > INT64_MAX / step) return false;
    *out = (int64_t)(count - 1) * step;
    return true;
}
bool zapp_camera_luma_fits(int width, int height, int stride, int pixel_stride, int length)
{
    int64_t row = 0, col = 0;
    if (width <= 0 || height <= 0 || stride <= 0 || pixel_stride <= 0 || length < 0) return false;
    if (!span_offset(height, stride, &row) || !span_offset(width, pixel_stride, &col)) return false;
    if (row > INT64_MAX - col) return false;
    return row + col < (int64_t)length;
}

enum zapp_camera_access zapp_camera_access_state(bool granted, bool rationale, bool asked_before)
{
    if (granted) return ZAPP_CAMERA_GRANTED;
    if (!asked_before) return ZAPP_CAMERA_ASK;
    return rationale ? ZAPP_CAMERA_ASK_AGAIN : ZAPP_CAMERA_SETTINGS;
}

/* The wait goes on while the dialog is up. It ends when the dialog has reported its result, and when no pause has
 * shown the dialog within the first second: Android shows no dialog after a permanent denial. */
bool zapp_camera_wait_goes_on(unsigned tick, bool paused, bool dialog)
{
    return dialog && (paused || tick < 5);
}

struct zapp_camera_screen zapp_camera_screen(enum zapp_camera_access access)
{
    if (access != ZAPP_CAMERA_SETTINGS) return (struct zapp_camera_screen){ .preview = true, .hint = "Point your camera at a QR code." };
    return (struct zapp_camera_screen){
        .text = "Camera access is off. Open Settings to allow it, or paste an address.",
        .open = "Open settings",
        .paste = "Paste instead",
    };
}

bool zapp_camera_run_frames(void *ctx, bool (*next)(void *),
                            bool (*stopped)(void *), void (*pause)(void *))
{
    while (!stopped(ctx)) {
        if (next(ctx)) return true;
        pause(ctx);
    }
    return false;
}

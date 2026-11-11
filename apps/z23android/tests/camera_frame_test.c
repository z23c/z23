/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "camera.c"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* The first sample is not black, so a letterbox margin cannot be confused with it. */
static uint8_t pixels[] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120};
static AImage image_fixture(void)
{
    return (AImage){.width = 2, .height = 2, .stride = 2, .pixel_stride = 1, .length = 12, .data = pixels};
}
static void render(AImage *image, int width, int height)
{
    preview_ready = false;
    memset(preview, 0, sizeof(preview));
    scanning = true;
    struct quirc *qr = quirc_new();
    assert(qr && quirc_resize(qr, width, height) == 0);
    char result[64] = {0};
    (void)frame(image, qr, width, height, result, sizeof(result));
    quirc_destroy(qr);
}
static void check_preview(const uint8_t expected[4])
{
    assert(preview_ready);
    /* A 2x2 frame is centered with 40 black columns on each side. Stretching it would paint the margin. */
    assert(preview[79 * PREVIEW_W + 0] == 0 && preview[79 * PREVIEW_W + 319] == 0);
    assert(preview[79 * PREVIEW_W + 40] == expected[0]);
    assert(preview[79 * PREVIEW_W + 160] == expected[1]);
    assert(preview[159 * PREVIEW_W + 40] == expected[2]);
    assert(preview[159 * PREVIEW_W + 160] == expected[3]);
    unsigned char *bmp = NULL;
    size_t length = 0;
    assert(zapp_camera_preview(&bmp, &length));
    assert(length == 54 + PREVIEW_W * PREVIEW_H * 3);
    const size_t margin = 54 + (160 * PREVIEW_W + 0) * 3;
    assert(bmp[margin] == 0 && bmp[margin + 1] == 0 && bmp[margin + 2] == 0);
    const size_t offsets[] = {
        54 + (160 * PREVIEW_W + 40) * 3,
        54 + (160 * PREVIEW_W + 160) * 3,
        54 + (80 * PREVIEW_W + 40) * 3,
        54 + (80 * PREVIEW_W + 160) * 3,
    };
    for (size_t i = 0; i < 4; ++i) for (size_t channel = 0; channel < 3; ++channel)
        assert(bmp[offsets[i] + channel] == expected[i]);
    free(bmp);
}
static void accepted_frame_draws_preview(void)
{
    AImage image = image_fixture();
    render(&image, 2, 2);
    check_preview(pixels);
}
static void padded_frame_strides_are_honored(void)
{
    AImage image = image_fixture();
    image.stride = 6;
    image.pixel_stride = 2;
    render(&image, 2, 2);
    const uint8_t expected[] = {pixels[0], pixels[2], pixels[6], pixels[8]};
    check_preview(expected);
}
static void dimension_mismatch_stops_before_plane_access(void)
{
    AImage image = image_fixture();
    image.width = 3;
    render(&image, 2, 2);
    assert(!preview_ready && !image.plane_calls && !image.row_calls && !image.pixel_calls);
    image = image_fixture();
    image.height = 3;
    render(&image, 2, 2);
    assert(!preview_ready && !image.plane_calls && !image.row_calls && !image.pixel_calls);
}
static void image_failures_stop_at_their_step(void)
{
    AImage image = image_fixture();
    image.fail_width = true;
    render(&image, 2, 2);
    assert(!preview_ready && !image.height_calls && !image.plane_calls);
    image = image_fixture();
    image.fail_height = true;
    render(&image, 2, 2);
    assert(!preview_ready && !image.plane_calls);
    image = image_fixture();
    image.fail_plane = true;
    render(&image, 2, 2);
    assert(!preview_ready && !image.row_calls && !image.pixel_calls);
    image = image_fixture();
    image.fail_row = true;
    render(&image, 2, 2);
    assert(!preview_ready && !image.pixel_calls);
    image = image_fixture();
    image.fail_pixel = true;
    render(&image, 2, 2);
    assert(!preview_ready);
}
static void invalid_plane_and_short_buffer_are_rejected(void)
{
    AImage image = image_fixture();
    image.data = NULL;
    render(&image, 2, 2);
    assert(!preview_ready);
    image = image_fixture();
    image.length = 3;
    render(&image, 2, 2);
    assert(!preview_ready);
    image.length = 4;
    render(&image, 2, 2);
    check_preview(pixels);
    image = image_fixture();
    image.stride = 0;
    render(&image, 2, 2);
    assert(!preview_ready);
    image = image_fixture();
    image.pixel_stride = 0;
    render(&image, 2, 2);
    assert(!preview_ready);
    image = image_fixture();
    image.length = -1;
    render(&image, 2, 2);
    assert(!preview_ready);
}
int main(void)
{
    accepted_frame_draws_preview();
    padded_frame_strides_are_honored();
    dimension_mismatch_stops_before_plane_access();
    image_failures_stop_at_their_step();
    invalid_plane_and_short_buffer_are_rejected();
    puts("camera frame tests passed");
    return 0;
}

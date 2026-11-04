/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "view_hit.h"
#include <assert.h>
#include <stdio.h>

/* The Receive page on a 1080 x 2160 phone, opened and not scrolled: the scroll view shows window rows 0 to 1938 and the
 * fixed bar under it holds Back at rows 1949 to 2119. */
#define VIEWPORT_BOTTOM 1938

/* Back in the fixed bar, all of it on screen. */
static const struct zapp_view_box back = {
    .left = 55, .top = 1949, .width = 970, .height = 170, .shown = true, .visible = true,
    .part_left = 55, .part_top = 1949, .part_right = 1025, .part_bottom = 2119, .part_origin_x = 55, .part_origin_y = 1949,
};

/* Set amount laid out under the bar: its window bounds lie below the scroll view, and none of it is on screen. */
static const struct zapp_view_box hidden_set_amount = {
    .left = 55, .top = 1960, .width = 970, .height = 170, .shown = true, .visible = false,
};

/* A tap on Back reaches Back and not the page button that the scroll view has cut away beneath it. */
static void scrolled_out_button_takes_no_tap(void)
{
    assert(zapp_view_hit(&back, 540.0f, 2030.0f));
    assert(!zapp_view_hit(&hidden_set_amount, 540.0f, 2030.0f));
    assert(!zapp_view_hit(&hidden_set_amount, 540.0f, 1965.0f));
}

/* A button half under the bottom edge of the scroll view takes taps on its visible part only. */
static void partly_visible_button_takes_its_visible_part(void)
{
    struct zapp_view_box half = {
        .left = 55, .top = 1850, .width = 970, .height = 170, .shown = true, .visible = true,
        .part_left = 55, .part_top = 1850, .part_right = 1025, .part_bottom = VIEWPORT_BOTTOM, .part_origin_x = 55, .part_origin_y = 1850,
    };
    assert(zapp_view_hit(&half, 540.0f, 1900.0f));
    assert(zapp_view_hit(&half, 540.0f, 1937.0f));
    assert(!zapp_view_hit(&half, 540.0f, 1938.0f));
    assert(!zapp_view_hit(&half, 540.0f, 2000.0f));
    assert(!zapp_view_hit(&half, 20.0f, 1900.0f));
}

/* The visible part is reported in coordinates whose origin may differ from the window's: it is moved by the view origin
 * before the touch point, a window point, is compared with it. */
static void visible_part_is_moved_into_the_window(void)
{
    struct zapp_view_box shifted = {
        .left = 100, .top = 300, .width = 200, .height = 100, .shown = true, .visible = true,
        .part_left = 100, .part_top = 250, .part_right = 300, .part_bottom = 300, .part_origin_x = 100, .part_origin_y = 250,
    };
    assert(zapp_view_hit(&shifted, 150.0f, 320.0f));
    assert(zapp_view_hit(&shifted, 150.0f, 349.0f));
    assert(!zapp_view_hit(&shifted, 150.0f, 350.0f));
    assert(!zapp_view_hit(&shifted, 150.0f, 260.0f));
}

/* A view that is hidden, or whose screen is hidden, takes no tap wherever its bounds are. */
static void hidden_view_takes_no_tap(void)
{
    struct zapp_view_box gone = back;
    gone.shown = false;
    assert(!zapp_view_hit(&gone, 540.0f, 2030.0f));
}

int main(void)
{
    scrolled_out_button_takes_no_tap();
    partly_visible_button_takes_its_visible_part();
    visible_part_is_moved_into_the_window();
    hidden_view_takes_no_tap();
    puts("view hit tests passed");
    return 0;
}

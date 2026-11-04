/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_VIEW_HIT_H
#define ZAPP_VIEW_HIT_H
#include <stdbool.h>

/* What Android reports of one view, read on the UI thread. left, top, width and height are its bounds in the window
 * (getLocationInWindow, getWidth, getHeight); shown is isShown. visible and the part_ fields are what getGlobalVisibleRect
 * returns: whether any of the view is on screen, that part clipped by every ancestor (a ScrollView cuts away what is
 * scrolled out), and the view's origin in the coordinates of that part. */
struct zapp_view_box {
    int left, top, width, height;
    bool shown, visible;
    int part_left, part_top, part_right, part_bottom, part_origin_x, part_origin_y;
};

/* Whether a touch at window point (x, y) reaches the view: the point lies in the view and in the part of it that is on
 * screen. A button scrolled under a fixed bar keeps window bounds below the scroll view, but has no part there, so a tap
 * on the bar never reaches it. */
bool zapp_view_hit(const struct zapp_view_box *box, float x, float y);
#endif

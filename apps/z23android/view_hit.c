/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "view_hit.h"

static bool inside(float x, float y, float left, float top, float right, float bottom)
{
    return x >= left && y >= top && x < right && y < bottom;
}

bool zapp_view_hit(const struct zapp_view_box *box, float x, float y)
{
    /* The visible part is moved from its own coordinates into the window's, where the touch point is. */
    float dx = (float)box->left - (float)box->part_origin_x, dy = (float)box->top - (float)box->part_origin_y;
    bool in_view = inside(x, y, (float)box->left, (float)box->top, (float)box->left + (float)box->width, (float)box->top + (float)box->height);
    bool on_screen = box->visible && inside(x, y, (float)box->part_left + dx, (float)box->part_top + dy,
                                            (float)box->part_right + dx, (float)box->part_bottom + dy);
    return box->shown && in_view && on_screen;
}

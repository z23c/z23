/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_INPUT_VIEW_H
#define SKY_COMBAT_INPUT_VIEW_H

#include "../models/input_model.h"
#include <raylib.h>

// View for displaying input state
typedef struct input_view_s input_view_t;

// Create/destroy view
input_view_t* input_view_create(void);
void input_view_destroy(input_view_t* view);

// Draw input state overlay
void input_view_draw_overlay(input_view_t* view, 
                            const validated_input_t* input,
                            const game_actions_t* actions,
                            int screen_width,
                            int screen_height);

// Draw controller diagram
void input_view_draw_controller(input_view_t* view,
                               const validated_input_t* input,
                               int x, int y);

// Draw error messages
void input_view_draw_error(input_view_t* view,
                          const char* error,
                          int screen_width,
                          int screen_height);

#endif // SKY_COMBAT_INPUT_VIEW_H
/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_INPUT_CONTROLLER_H
#define SKY_COMBAT_INPUT_CONTROLLER_H

#include "../models/input_model.h"
#include "../views/input_view.h"
#include <stdbool.h>

// Controller manages input flow
typedef struct input_controller_s input_controller_t;

// Create/destroy controller
input_controller_t* input_controller_create(void);
void input_controller_destroy(input_controller_t* controller);

// Initialize joystick connection
bool input_controller_init_joystick(input_controller_t* controller);

// Update input state (called each frame)
void input_controller_update(input_controller_t* controller);

// Get current game actions
game_actions_t input_controller_get_actions(input_controller_t* controller);

// Get validated input for display
const validated_input_t* input_controller_get_validated_input(input_controller_t* controller);

// Check if joystick is connected
bool input_controller_is_connected(input_controller_t* controller);

// Get any validation errors
const char* input_controller_get_error(input_controller_t* controller);

// Draw input overlay (delegates to view)
void input_controller_draw_overlay(input_controller_t* controller,
                                  int screen_width,
                                  int screen_height);

// Enable/disable debug display
void input_controller_set_debug_mode(input_controller_t* controller, bool enabled);

#endif // SKY_COMBAT_INPUT_CONTROLLER_H
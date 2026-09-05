/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_INPUT_H
#define SKY_COMBAT_INPUT_H

#include <stdbool.h>

// Joystick axis mappings
#define AXIS_LEFT_X 0
#define AXIS_LEFT_Y 1
#define AXIS_RIGHT_X 2
#define AXIS_RIGHT_Y 5
#define AXIS_L2 3
#define AXIS_R2 4

// Button mappings (ASTRO C40) - moved to input_model.h to avoid conflicts

// Forward declaration
typedef struct joystick_s joystick_t;

typedef struct {
    float move_x;
    float move_y;
    float camera_x;
    float camera_y;
    bool fire_guns;
    bool fire_missiles;
    bool barrel_roll_left;
    bool barrel_roll_right;
    bool speed_boost;
    bool brake;
} input_state_t;

// Input system
joystick_t* input_create(void);
void input_destroy(joystick_t* joy);
void input_update(joystick_t* joy);
input_state_t input_get_state(joystick_t* joy);

// Utility functions
float input_normalize_axis(short value);
bool input_is_connected(joystick_t* joy);

// Debug functions
void input_set_debug_mode(joystick_t* joy, bool enabled);
void input_draw_debug_overlay(joystick_t* joy, int screen_width, int screen_height);

#endif // SKY_COMBAT_INPUT_H
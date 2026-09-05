/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/controllers/input.h"
#include "sky_combat/controllers/input_controller.h"
#include <raylib.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <math.h>

// Include joystick after raylib to avoid conflicts
#define KEY_RESERVED 0
#include <linux/joystick.h>

// Private structure to wrap MVC controller
struct joystick_s {
    input_controller_t* controller;  // MVC controller
    int fd;                         // For compatibility
    bool connected;                 // For compatibility
    short axes[6];                  // For compatibility
    short buttons[16];              // For compatibility
};

joystick_t* input_create(void) {
    joystick_t* joy = calloc(1, sizeof(joystick_t));
    if (!joy) return NULL;
    
    // Create MVC controller
    joy->controller = input_controller_create();
    if (!joy->controller) {
        free(joy);
        return NULL;
    }
    
    // Initialize joystick through MVC controller
    joy->connected = input_controller_init_joystick(joy->controller);
    joy->fd = joy->connected ? 1 : -1; // Dummy value for compatibility
    
    return joy;
}

void input_destroy(joystick_t* joy) {
    if (!joy) return;
    
    if (joy->controller) {
        input_controller_destroy(joy->controller);
    }
    free(joy);
}

void input_update(joystick_t* joy) {
    if (!joy || !joy->controller) return;
    
    // Update through MVC controller
    input_controller_update(joy->controller);
    
    // Update compatibility fields
    joy->connected = input_controller_is_connected(joy->controller);
    
    // Get validated input for compatibility
    const validated_input_t* validated = input_controller_get_validated_input(joy->controller);
    if (validated && validated->is_valid) {
        // Copy raw axes for compatibility
        for (int i = 0; i < 6; i++) {
            joy->axes[i] = validated->raw_axes[i];
        }
        // Copy button states
        for (int i = 0; i < 16; i++) {
            joy->buttons[i] = validated->buttons[i] ? 1 : 0;
        }
    }
}

float input_normalize_axis(short value) {
    if (fabsf(value) < 3000) return 0;
    // Clamp to avoid overflow
    float normalized = value / 32767.0f;
    if (normalized > 1.0f) normalized = 1.0f;
    if (normalized < -1.0f) normalized = -1.0f;
    return normalized;
}

input_state_t input_get_state(joystick_t* joy) {
    input_state_t state = {0};
    
    if (!joy || !joy->controller) return state;
    
    // Get actions from MVC controller
    game_actions_t actions = input_controller_get_actions(joy->controller);
    
    // Convert MVC actions to legacy input_state_t
    state.move_x = actions.move_x;
    state.move_y = actions.move_y;
    state.camera_x = actions.camera_x;
    state.camera_y = actions.camera_y;
    state.fire_guns = actions.fire_guns;
    state.fire_missiles = actions.fire_missiles;
    state.barrel_roll_left = actions.barrel_roll_left;
    state.barrel_roll_right = actions.barrel_roll_right;
    state.speed_boost = actions.speed_boost;
    state.brake = actions.brake;
    
    return state;
}

bool input_is_connected(joystick_t* joy) {
    if (!joy) return false;
    return input_controller_is_connected(joy->controller);
}

void input_set_debug_mode(joystick_t* joy, bool enabled) {
    if (!joy) return;
    input_controller_set_debug_mode(joy->controller, enabled);
}

void input_draw_debug_overlay(joystick_t* joy, int screen_width, int screen_height) {
    if (!joy) return;
    input_controller_draw_overlay(joy->controller, screen_width, screen_height);
}
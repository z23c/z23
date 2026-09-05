/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/controllers/input_astro_direct.h"
#include <fcntl.h>
#include <unistd.h>
#include <linux/joystick.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

#define AXIS_MAX 32767.0f
#define DEAD_ZONE 8000

// Initialize controller
int input_astro_init(input_astro_state_t *state) {
    memset(state, 0, sizeof(input_astro_state_t));
    
    // Try to open joystick device
    state->fd = open("/dev/input/js0", O_RDONLY | O_NONBLOCK);
    if (state->fd < 0) {
        return -1;
    }
    
    // Get controller info
    ioctl(state->fd, JSIOCGAXES, &state->num_axes);
    ioctl(state->fd, JSIOCGBUTTONS, &state->num_buttons);
    ioctl(state->fd, JSIOCGNAME(256), state->name);
    
    return 0;
}

// Update controller state
void input_astro_update(input_astro_state_t *state) {
    if (state->fd < 0) return;
    
    struct js_event e;
    while (read(state->fd, &e, sizeof(e)) > 0) {
        e.type &= ~JS_EVENT_INIT;
        
        if (e.type == JS_EVENT_AXIS && e.number < 16) {
            state->axes[e.number] = e.value;
        } else if (e.type == JS_EVENT_BUTTON && e.number < 32) {
            state->buttons[e.number] = e.value;
        }
    }
    
    // Update normalized values
    state->left_stick_x = state->axes[0] / AXIS_MAX;
    state->left_stick_y = state->axes[1] / AXIS_MAX;
    state->right_stick_x = state->axes[2] / AXIS_MAX;
    state->right_stick_y = state->axes[5] / AXIS_MAX;
    
    // ASTRO C40 specific: triggers use different ranges
    state->left_trigger = (state->axes[3] + 32767) / 65534.0f;
    state->right_trigger = (state->axes[4] + 32767) / 32767.0f;  // R2 goes to 0 when pressed
}

// Close controller
void input_astro_close(input_astro_state_t *state) {
    if (state->fd >= 0) {
        close(state->fd);
        state->fd = -1;
    }
}

// Convert to game input
input_state_fast_t input_astro_to_game_input(const input_astro_state_t *state) {
    input_state_fast_t input = {0};
    
    // Movement
    input.move_x = fabsf(state->left_stick_x) > 0.1f ? state->left_stick_x : 0;
    input.move_y = fabsf(state->left_stick_y) > 0.1f ? state->left_stick_y : 0;
    
    // Camera
    input.camera_x = fabsf(state->right_stick_x) > 0.1f ? state->right_stick_x : 0;
    input.camera_y = fabsf(state->right_stick_y) > 0.1f ? state->right_stick_y : 0;
    
    // Actions
    input.fire_guns = state->axes[4] > -16000;  // R2 trigger
    input.fire_missiles = state->left_trigger > 0.5f;  // L2 trigger
    
    // Barrel rolls
    input.barrel_roll_left = state->buttons[4];  // L1
    input.barrel_roll_right = state->buttons[5];  // R1
    
    // Speed control via paddles (RE-SWAPPED for new layout)
    input.speed_boost = state->buttons[3];  // Triangle (UR paddle) - now throttle
    input.brake = state->buttons[2];  // Square (UL paddle) - now boost
    
    return input;
}
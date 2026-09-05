/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_INPUT_ASTRO_DIRECT_H
#define SKY_COMBAT_INPUT_ASTRO_DIRECT_H

#include <stdint.h>
#include "../models/input_model_fast.h"
#include "../views/input_view_fast.h"

// Direct ASTRO controller state - matches astro_controller_viewer exactly
typedef struct {
    int fd;
    char name[256];
    int num_axes;
    int num_buttons;
    
    // Axis values (-32767 to 32767)
    int16_t axes[16];
    // Button states
    uint8_t buttons[32];
    
    // Normalized values
    float left_stick_x;
    float left_stick_y;
    float right_stick_x;
    float right_stick_y;
    float left_trigger;
    float right_trigger;
} input_astro_state_t;

// Initialize controller
int input_astro_init(input_astro_state_t *state);

// Update controller state
void input_astro_update(input_astro_state_t *state);

// Close controller
void input_astro_close(input_astro_state_t *state);

// Convert to game input
input_state_fast_t input_astro_to_game_input(const input_astro_state_t *state);

#endif // SKY_COMBAT_INPUT_ASTRO_DIRECT_H
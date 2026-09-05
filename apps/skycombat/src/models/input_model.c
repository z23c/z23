/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/models/input_model.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

// Dead zone for analog sticks
#define AXIS_DEADZONE 3000
#define AXIS_MIN -32768
#define AXIS_MAX 32767

// ASTRO C40 specific trigger ranges
#define L2_TRIGGER_UNPRESSED -32767
#define L2_TRIGGER_PRESSED 32767
#define R2_TRIGGER_UNPRESSED -32767
#define R2_TRIGGER_PRESSED 0
#define R2_TRIGGER_THRESHOLD -16384

struct input_model_s {
    control_mapping_t mapping;
    char last_error[256];
};

input_model_t* input_model_create(void) {
    input_model_t* model = calloc(1, sizeof(input_model_t));
    if (!model) return NULL;
    
    // Initialize the LOCKED control mapping (ORIGINAL SCHEME)
    model->mapping.move_x_axis = AXIS_LEFT_STICK_X;
    model->mapping.move_y_axis = AXIS_LEFT_STICK_Y;
    model->mapping.camera_x_axis = AXIS_RIGHT_STICK_X;
    model->mapping.camera_y_axis = AXIS_RIGHT_STICK_Y;
    model->mapping.fire_missiles_axis = AXIS_R2_TRIGGER;  // R2 = Missiles (ORIGINAL)
    model->mapping.fire_guns_axis = AXIS_L2_TRIGGER;      // L2 = Guns (ORIGINAL)
    model->mapping.barrel_roll_left = BUTTON_L1;
    model->mapping.barrel_roll_right = BUTTON_R1;
    model->mapping.speed_boost = BUTTON_GAS;
    model->mapping.brake = BUTTON_BRAKE;
    
    return model;
}

void input_model_destroy(input_model_t* model) {
    free(model);
}

const control_mapping_t* input_model_get_mapping(const input_model_t* model) {
    return &model->mapping;
}

bool input_model_validate_axis_range(short value) {
    return value >= AXIS_MIN && value <= AXIS_MAX;
}

bool input_model_validate_l2_trigger(short value) {
    // L2: -32767 (unpressed) to 32767 (fully pressed)
    return value >= L2_TRIGGER_UNPRESSED && value <= L2_TRIGGER_PRESSED;
}

bool input_model_validate_r2_trigger(short value) {
    // R2: -32767 (unpressed) to 0 (fully pressed) - unique ASTRO C40 behavior
    return value >= R2_TRIGGER_UNPRESSED && value <= 0;
}

static float normalize_axis(short value) {
    if (abs(value) < AXIS_DEADZONE) return 0.0f;
    return value / 32767.0f;
}

validated_input_t input_model_validate(const input_model_t* model,
                                       const short* axes,
                                       const short* buttons) {
    validated_input_t result = {0};
    result.is_valid = true;
    
    // Clear error
    ((input_model_t*)model)->last_error[0] = '\0';
    
    // Validate all axes
    for (int i = 0; i < AXIS_COUNT; i++) {
        if (!input_model_validate_axis_range(axes[i])) {
            result.is_valid = false;
            snprintf(result.validation_error, sizeof(result.validation_error),
                     "Axis %d out of range: %d", i, axes[i]);
            strcpy(((input_model_t*)model)->last_error, result.validation_error);
            return result;
        }
        
        // Special validation for triggers
        if (i == AXIS_L2_TRIGGER && !input_model_validate_l2_trigger(axes[i])) {
            result.is_valid = false;
            snprintf(result.validation_error, sizeof(result.validation_error),
                     "L2 trigger invalid value: %d", axes[i]);
            strcpy(((input_model_t*)model)->last_error, result.validation_error);
            return result;
        }
        
        if (i == AXIS_R2_TRIGGER && !input_model_validate_r2_trigger(axes[i])) {
            result.is_valid = false;
            snprintf(result.validation_error, sizeof(result.validation_error),
                     "R2 trigger invalid value: %d (must be -32767 to 0)", axes[i]);
            strcpy(((input_model_t*)model)->last_error, result.validation_error);
            return result;
        }
        
        // Store raw values for special handling
        result.raw_axes[i] = axes[i];
        
        // Store normalized values
        result.axes[i] = normalize_axis(axes[i]);
    }
    
    // Validate critical buttons
    if (buttons[BUTTON_GAS] > 1 || buttons[BUTTON_BRAKE] > 1) {
        result.is_valid = false;
        snprintf(result.validation_error, sizeof(result.validation_error),
                 "Invalid button state for gas/brake");
        strcpy(((input_model_t*)model)->last_error, result.validation_error);
        return result;
    }
    
    // Copy button states
    for (int i = 0; i < BUTTON_COUNT; i++) {
        result.buttons[i] = buttons[i] > 0;
    }
    
    return result;
}

game_actions_t input_model_convert_to_actions(const input_model_t* model,
                                              const validated_input_t* input) {
    game_actions_t actions = {0};
    
    if (!input->is_valid) {
        return actions;  // Return zero actions if input invalid
    }
    
    // Movement from left stick
    actions.move_x = input->axes[model->mapping.move_x_axis];
    actions.move_y = input->axes[model->mapping.move_y_axis];
    
    // Camera from right stick
    actions.camera_x = input->axes[model->mapping.camera_x_axis];
    actions.camera_y = input->axes[model->mapping.camera_y_axis];
    
    // Weapons from triggers
    // L2: positive value = pressed
    actions.fire_missiles = (input->axes[model->mapping.fire_missiles_axis] > 0.0f);
    
    // R2: ASTRO C40 specific - use raw axis value for threshold check
    // R2 goes from -32767 (unpressed) to 0 (fully pressed)
    // Values closer to 0 mean more pressed, so we check if > threshold
    actions.fire_guns = (input->raw_axes[model->mapping.fire_guns_axis] > R2_TRIGGER_THRESHOLD);
    
    // Special moves
    actions.barrel_roll_left = input->buttons[model->mapping.barrel_roll_left];
    actions.barrel_roll_right = input->buttons[model->mapping.barrel_roll_right];
    
    // Speed control - CRITICAL LOCKED MAPPING
    actions.speed_boost = input->buttons[model->mapping.speed_boost];
    actions.brake = input->buttons[model->mapping.brake];
    
    return actions;
}

const char* input_model_get_last_error(const input_model_t* model) {
    return model->last_error;
}
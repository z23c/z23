/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_INPUT_MODEL_FAST_H
#define SKY_COMBAT_INPUT_MODEL_FAST_H

#include <stdint.h>
#include <stdbool.h>

// Fast MVC Model - Direct memory layout for zero-copy access
typedef struct {
    // Raw hardware state - directly updated by controller
    struct {
        int16_t axes[8];      // Direct from joystick
        uint8_t buttons[16];  // Direct from joystick
    } raw;
    
    // Processed state - computed once per frame
    struct {
        float move_x;         // Pre-normalized and curved
        float move_y;
        float camera_x;
        float camera_y;
        float left_trigger;
        float right_trigger;
    } normalized;
    
    // Game actions - direct bit flags for speed
    uint32_t actions;
    
    // Metadata
    bool connected;
    bool is_astro_c40;
    uint64_t frame_count;
    
    // Pre-computed constants
    float deadzone_threshold;
    float inv_axis_range;     // 1.0f / 32768.0f
    float response_curve;
} input_model_fast_t;

// Action bit flags for fast checking
enum {
    ACTION_FIRE_GUNS        = 1 << 0,
    ACTION_FIRE_MISSILES    = 1 << 1,
    ACTION_BARREL_ROLL_LEFT = 1 << 2,
    ACTION_BARREL_ROLL_RIGHT= 1 << 3,
    ACTION_SPEED_BOOST      = 1 << 4,
    ACTION_BRAKE            = 1 << 5,
};

// Inline functions for zero-overhead access
static inline bool input_model_fast_is_firing_guns(const input_model_fast_t* model) {
    return model->actions & ACTION_FIRE_GUNS;
}

static inline bool input_model_fast_is_firing_missiles(const input_model_fast_t* model) {
    return model->actions & ACTION_FIRE_MISSILES;
}

static inline float input_model_fast_get_move_x(const input_model_fast_t* model) {
    return model->normalized.move_x;
}

static inline float input_model_fast_get_move_y(const input_model_fast_t* model) {
    return model->normalized.move_y;
}

// Model functions
void input_model_fast_init(input_model_fast_t* model);
void input_model_fast_process(input_model_fast_t* model);  // Convert raw to normalized/actions

#endif // SKY_COMBAT_INPUT_MODEL_FAST_H
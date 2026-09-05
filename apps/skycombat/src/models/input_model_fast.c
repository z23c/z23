/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/models/input_model_fast.h"
#include "sky_combat/controllers/controls_permanent.h"
#include <math.h>
#include <string.h>

// Fast approximation for response curve using lookup table
static float response_curve_lut[256];
static bool lut_initialized = false;

static void init_response_curve_lut(float curve) {
    for (int i = 0; i < 256; i++) {
        float normalized = i / 255.0f;
        response_curve_lut[i] = powf(normalized, curve);
    }
    lut_initialized = true;
}

// Fast dead zone with smooth transition
static inline float fast_deadzone(float value, float threshold) {
    float abs_value = fabsf(value);
    if (abs_value < threshold) return 0.0f;
    
    // Branchless sign extraction
    float sign = value < 0 ? -1.0f : 1.0f;
    
    // Scale from threshold to 1.0
    float divisor = 1.0f - threshold;
    if (divisor <= 0.0f) return sign * abs_value;
    float scale = 1.0f / divisor;
    return sign * (abs_value - threshold) * scale;
}

// Fast response curve using LUT
static inline float fast_curve(float value) {
    float abs_value = fabsf(value);
    int index = (int)(abs_value * 255.0f);
    if (index > 255) index = 255;
    if (index < 0) index = 0;
    
    float sign = value < 0 ? -1.0f : 1.0f;
    return sign * response_curve_lut[index];
}

void input_model_fast_init(input_model_fast_t* model) {
    if (!model) return;
    memset(model, 0, sizeof(input_model_fast_t));
    
    // Pre-compute constants
    model->deadzone_threshold = 0.15f;
    model->inv_axis_range = 1.0f / 32768.0f;
    model->response_curve = 1.5f;
    
    // Initialize LUT if needed
    if (!lut_initialized) {
        init_response_curve_lut(model->response_curve);
    }
}

void input_model_fast_process(input_model_fast_t* model) {
    if (!model) return;
    
    // Skip if not connected
    if (!model->connected) {
        model->actions = 0;
        return;
    }
    
    // Process axes with optimized normalization
    float left_x = model->raw.axes[0] * model->inv_axis_range;
    float left_y = model->raw.axes[1] * model->inv_axis_range;
    float right_x = model->raw.axes[2] * model->inv_axis_range;
    float right_y = model->raw.axes[5] * model->inv_axis_range;
    
    // Apply dead zone and curve in one pass
    model->normalized.move_x = fast_curve(fast_deadzone(left_x, model->deadzone_threshold));
    model->normalized.move_y = fast_curve(fast_deadzone(left_y, model->deadzone_threshold));  // Don't invert - let aircraft_responsive handle it
    
    // Camera uses smaller dead zone and linear response
    float camera_threshold = model->deadzone_threshold * 0.5f;
    model->normalized.camera_x = fast_deadzone(right_x, camera_threshold);
    model->normalized.camera_y = fast_deadzone(right_y, camera_threshold);
    
    // Process triggers based on controller type
    if (model->is_astro_c40) {
        // ASTRO C40 specific trigger processing
        model->normalized.left_trigger = (model->raw.axes[3] + 32768) * (1.0f / 65535.0f);
        model->normalized.right_trigger = (model->raw.axes[4] + 32767) * (1.0f / 32767.0f);
    } else {
        // Standard controller
        model->normalized.left_trigger = (model->raw.axes[2] + 32768) * (1.0f / 65535.0f);
        model->normalized.right_trigger = (model->raw.axes[5] + 32768) * (1.0f / 65535.0f);
    }
    
    // Build action bit flags - branchless where possible
    model->actions = 0;
    
    // Trigger actions - R2 shoots, L2 missiles
    model->actions |= (model->normalized.right_trigger > 0.1f) ? ACTION_FIRE_GUNS : 0;
    model->actions |= (model->normalized.left_trigger > 0.1f) ? ACTION_FIRE_MISSILES : 0;
    
    // Button actions - using PERMANENT control mapping
    model->actions |= model->raw.buttons[BUTTON_L1] ? ACTION_BARREL_ROLL_LEFT : 0;
    model->actions |= model->raw.buttons[BUTTON_R1] ? ACTION_BARREL_ROLL_RIGHT : 0;
    
    // Speed controls - UR (Triangle) for throttle up, UL (Square) for brake
    model->actions |= model->raw.buttons[BUTTON_TRIANGLE] ? ACTION_SPEED_BOOST : 0;   // UR paddle
    model->actions |= model->raw.buttons[BUTTON_SQUARE] ? ACTION_BRAKE : 0;           // UL paddle
    
    model->frame_count++;
}
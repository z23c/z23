/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../../specifications/joystick_control_specs.h"
#include "../models/aircraft_input_model.c"
#include "../views/aircraft_input_view.c"
#include <raylib.h>

/* Controller: Coordinates model and view for aircraft input */

typedef struct {
    /* Configuration */
    bool show_debug_overlay;
    bool show_help;
    
    /* State tracking */
    bool initialized;
    uint32_t frame_count;
} aircraft_input_controller_t;

/* Singleton controller instance */
static aircraft_input_controller_t g_controller = {
    .show_debug_overlay = false,
    .show_help = true,
    .initialized = false,
    .frame_count = 0
};

/* Initialize the input system */
bool aircraft_input_controller_init(void) {
    if (g_controller.initialized) return true;
    
    /* Try to initialize joystick */
    bool has_joystick = aircraft_input_model_init_joystick();
    
    if (has_joystick) {
        printf("=== JOYSTICK DETECTED ===\n");
        printf("Aircraft controls mapped to joystick\n");
        printf("Left Stick: Pitch/Roll\n");
        printf("Right Stick: Yaw/Throttle\n");
        printf("A: Afterburner, B: Landing Gear\n");
        printf("R2: Fire Primary, L2: Fire Secondary\n\n");
    } else {
        printf("=== KEYBOARD CONTROLS ACTIVE ===\n");
        printf("No joystick detected, using keyboard\n");
        printf("WASD: Pitch/Roll\n");
        printf("Arrows: Yaw/Throttle\n");
        printf("Shift: Afterburner, G: Landing Gear\n");
        printf("Space: Fire Primary, Ctrl: Fire Secondary\n\n");
    }
    
    g_controller.initialized = true;
    return true;
}

/* Update input system */
void aircraft_input_controller_update(void) {
    if (!g_controller.initialized) return;
    
    /* Update model */
    aircraft_input_model_update();
    
    /* Handle UI controls */
    if (IsKeyPressed(KEY_F1)) {
        g_controller.show_help = !g_controller.show_help;
    }
    if (IsKeyPressed(KEY_F2)) {
        g_controller.show_debug_overlay = !g_controller.show_debug_overlay;
    }
    
    g_controller.frame_count++;
}

/* Apply input to aircraft */
void aircraft_input_controller_apply_to_aircraft(
    Vector3* position,
    Vector3* rotation,
    float* throttle,
    bool* afterburner,
    bool* landing_gear,
    float delta_time
) {
    const validated_joystick_input_t* input = aircraft_input_model_get_validated();
    if (!input || !input->is_valid) return;
    
    /* Apply rotation rates */
    rotation->x += input->pitch * MAX_PITCH_RATE * delta_time;
    rotation->y += input->yaw * MAX_YAW_RATE * delta_time;
    rotation->z += input->roll * MAX_ROLL_RATE * delta_time;
    
    /* Apply throttle based on gas/brake buttons */
    if (input->gas_button && !input->brake_button) {
        /* Accelerate */
        *throttle += MAX_THROTTLE_RATE * delta_time;
        if (*throttle > 1.0f) *throttle = 1.0f;
    } else if (input->brake_button && !input->gas_button) {
        /* Decelerate */
        *throttle -= MAX_THROTTLE_RATE * delta_time;
        if (*throttle < 0.0f) *throttle = 0.0f;
    }
    /* Otherwise maintain current throttle */
    
    /* Direct button states */
    *afterburner = input->afterburner;
    *landing_gear = input->landing_gear;
}

/* Get weapon states */
void aircraft_input_controller_get_weapons(bool* primary, bool* secondary) {
    const validated_joystick_input_t* input = aircraft_input_model_get_validated();
    if (!input || !input->is_valid) {
        *primary = false;
        *secondary = false;
        return;
    }
    
    *primary = input->fire_primary;
    *secondary = input->fire_secondary;
}

/* Draw input overlay */
void aircraft_input_controller_draw_overlay(void) {
    if (!g_controller.initialized) return;
    
    const validated_joystick_input_t* input = aircraft_input_model_get_validated();
    bool is_joystick = aircraft_input_model_is_joystick_connected();
    
    /* Help overlay */
    if (g_controller.show_help) {
        aircraft_input_view_draw_controls(is_joystick, 
                                        GetScreenWidth() - 330, 10);
    }
    
    /* Debug overlay */
    if (g_controller.show_debug_overlay) {
        /* Input state */
        aircraft_input_view_draw_state(input, 10, 100);
        
        /* Joystick visualization */
        aircraft_input_view_draw_joystick(input, 60, 350);
        
        /* Statistics */
        uint32_t total, failed;
        aircraft_input_model_get_stats(&total, &failed);
        aircraft_input_view_draw_stats(total, failed, 10, 450);
        
        /* Latency indicator */
        if (input) {
            uint32_t now = get_time_ms();
            aircraft_input_view_draw_latency(now, input->timestamp_ms, 10, 530);
        }
    }
    
    /* Control hints */
    DrawText("F1 - Toggle Help", 10, GetScreenHeight() - 40, 14, GRAY);
    DrawText("F2 - Toggle Debug", 10, GetScreenHeight() - 20, 14, GRAY);
}

/* Cleanup */
void aircraft_input_controller_cleanup(void) {
    if (!g_controller.initialized) return;
    
    aircraft_input_model_cleanup();
    g_controller.initialized = false;
}
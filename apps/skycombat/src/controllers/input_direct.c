/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/controllers/input_direct.h"
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/joystick.h>
#include <math.h>
#include <stdio.h>

struct input_system_s {
    int fd;
    bool connected;
    
    // Raw axis values
    int16_t axes[8];
    uint8_t buttons[16];
    
    // Configuration
    float deadzone;
    float response_curve;
    
    // ASTRO C40 specific
    bool is_astro_c40;
};

input_system_t* input_direct_create(void) {
    input_system_t* input = calloc(1, sizeof(input_system_t));
    if (!input) return NULL;
    
    // Try to open joystick
    input->fd = open("/dev/input/js0", O_RDONLY | O_NONBLOCK);
    if (input->fd < 0) {
        printf("No controller found at /dev/input/js0\n");
        input->connected = false;
    } else {
        input->connected = true;
        
        // Check if it's ASTRO C40
        char name[128] = {0};
        if (ioctl(input->fd, JSIOCGNAME(sizeof(name)), name) >= 0) {
            if (strstr(name, "ASTRO") && strstr(name, "C40")) {
                input->is_astro_c40 = true;
                printf("ASTRO C40 Controller detected - optimized controls enabled!\n");
            }
        }
    }
    
    // Default configuration
    input->deadzone = 0.15f;      // 15% dead zone
    input->response_curve = 1.5f;  // Slightly curved for better fine control
    
    return input;
}

void input_direct_destroy(input_system_t* input) {
    if (!input) return;
    if (input->fd >= 0) close(input->fd);
    free(input);
}

// Smooth dead zone function - no sudden jumps
static float apply_deadzone(float value, float deadzone) {
    float abs_value = fabsf(value);
    if (abs_value < deadzone) return 0.0f;
    
    // Smooth ramp from deadzone to 1.0
    float scaled = (abs_value - deadzone) / (1.0f - deadzone);
    return scaled * (value < 0 ? -1.0f : 1.0f);
}

// Response curve for better control feel
static float apply_curve(float value, float curve) {
    float sign = value < 0 ? -1.0f : 1.0f;
    return sign * powf(fabsf(value), curve);
}

input_direct_t input_direct_update(input_system_t* input, float dt) {
    input_direct_t state = {0};
    state.dt = dt;
    
    if (!input || !input->connected) {
        state.connected = false;
        return state;
    }
    
    state.connected = true;
    
    // Read all pending events (non-blocking)
    struct js_event event;
    while (read(input->fd, &event, sizeof(event)) > 0) {
        if (event.type & JS_EVENT_BUTTON) {
            if (event.number < 16) {
                input->buttons[event.number] = event.value;
            }
        } else if (event.type & JS_EVENT_AXIS) {
            if (event.number < 8) {
                input->axes[event.number] = event.value;
            }
        }
    }
    
    // Convert axes to normalized values with proper curves
    float left_x = input->axes[0] / 32768.0f;
    float left_y = input->axes[1] / 32768.0f;
    float right_x = input->axes[2] / 32768.0f;
    float right_y = input->axes[5] / 32768.0f;  // Y is on axis 5 for ASTRO
    
    // Apply dead zone and response curve
    state.move_x = apply_curve(apply_deadzone(left_x, input->deadzone), input->response_curve);
    state.move_y = apply_curve(apply_deadzone(left_y, input->deadzone), input->response_curve);
    state.camera_x = apply_curve(apply_deadzone(right_x, input->deadzone * 0.5f), 1.0f);  // Linear camera
    state.camera_y = apply_curve(apply_deadzone(right_y, input->deadzone * 0.5f), 1.0f);
    
    // Handle triggers with ASTRO C40 specific logic
    if (input->is_astro_c40) {
        // L2 goes from -32767 to 32767
        state.left_trigger = (input->axes[3] + 32768.0f) / 65535.0f;
        // R2 goes from -32767 to 0 (weird but true)
        state.right_trigger = (input->axes[4] + 32767.0f) / 32767.0f;
    } else {
        // Standard controller
        state.left_trigger = (input->axes[2] + 32768.0f) / 65535.0f;
        state.right_trigger = (input->axes[5] + 32768.0f) / 65535.0f;
    }
    
    // Direct button mapping - no abstraction layers
    state.fire_guns = state.left_trigger > 0.1f;
    state.fire_missiles = state.right_trigger > 0.1f;
    
    // Shoulder buttons
    state.barrel_roll_left = input->buttons[6];   // L1
    state.barrel_roll_right = input->buttons[7];  // R1
    
    // Face buttons for boost/brake (ASTRO C40 mapping)
    state.speed_boost = input->buttons[2];   // Button 2 (UL paddle)
    state.brake = input->buttons[3];         // Button 3 (UR paddle)
    
    return state;
}

void input_direct_set_deadzone(input_system_t* input, float deadzone) {
    if (input) {
        input->deadzone = fmaxf(0.0f, fminf(0.5f, deadzone));
    }
}

void input_direct_set_response_curve(input_system_t* input, float curve) {
    if (input) {
        input->response_curve = fmaxf(0.5f, fminf(3.0f, curve));
    }
}
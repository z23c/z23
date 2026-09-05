/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/controllers/input_controller.h"
#include <linux/joystick.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct input_controller_s {
    input_model_t* model;
    input_view_t* view;
    
    // Joystick state
    int joystick_fd;
    bool connected;
    short axes[AXIS_COUNT];
    short buttons[BUTTON_COUNT];
    
    // Processed state
    validated_input_t validated_input;
    game_actions_t actions;
    
    // Settings
    bool debug_mode;
};

input_controller_t* input_controller_create(void) {
    input_controller_t* controller = calloc(1, sizeof(input_controller_t));
    if (!controller) return NULL;
    
    controller->model = input_model_create();
    if (!controller->model) {
        free(controller);
        return NULL;
    }
    
    controller->view = input_view_create();
    if (!controller->view) {
        input_model_destroy(controller->model);
        free(controller);
        return NULL;
    }
    
    controller->joystick_fd = -1;
    controller->connected = false;
    controller->debug_mode = false;
    
    return controller;
}

void input_controller_destroy(input_controller_t* controller) {
    if (!controller) return;
    
    if (controller->joystick_fd >= 0) {
        close(controller->joystick_fd);
    }
    
    input_view_destroy(controller->view);
    input_model_destroy(controller->model);
    free(controller);
}

bool input_controller_init_joystick(input_controller_t* controller) {
    // Try to open joystick
    controller->joystick_fd = open("/dev/input/js0", O_RDONLY | O_NONBLOCK);
    
    if (controller->joystick_fd >= 0) {
        controller->connected = true;
        printf("ASTRO C40 Controller connected!\n");
        printf("Controls locked:\n");
        printf("  Button 2 (UL) = Gas\n");
        printf("  Button 3 (UR) = Brake\n");
        printf("  R2 = Missiles, L2 = Guns\n");
        return true;
    }
    
    controller->connected = false;
    printf("No controller found. Keyboard controls active.\n");
    return false;
}

void input_controller_update(input_controller_t* controller) {
    if (!controller->connected) {
        // Handle keyboard input
        memset(controller->axes, 0, sizeof(controller->axes));
        memset(controller->buttons, 0, sizeof(controller->buttons));
        
        // Initialize trigger axes to unpressed state
        controller->axes[AXIS_L2_TRIGGER] = -32767;  // L2 unpressed
        controller->axes[AXIS_R2_TRIGGER] = -32767;  // R2 unpressed
        
        // Map keyboard to controller inputs
        if (IsKeyDown(KEY_A) || IsKeyDown(KEY_LEFT)) {
            controller->axes[AXIS_LEFT_STICK_X] = -32767;
        }
        if (IsKeyDown(KEY_D) || IsKeyDown(KEY_RIGHT)) {
            controller->axes[AXIS_LEFT_STICK_X] = 32767;
        }
        if (IsKeyDown(KEY_W) || IsKeyDown(KEY_UP)) {
            controller->axes[AXIS_LEFT_STICK_Y] = -32767;
        }
        if (IsKeyDown(KEY_S) || IsKeyDown(KEY_DOWN)) {
            controller->axes[AXIS_LEFT_STICK_Y] = 32767;
        }
        
        // Weapon keys
        if (IsKeyDown(KEY_LEFT_CONTROL)) {
            controller->axes[AXIS_L2_TRIGGER] = 32767;  // L2 pressed
        }
        if (IsKeyDown(KEY_SPACE)) {
            controller->axes[AXIS_R2_TRIGGER] = -16000;  // R2 pressed
        }
        
        // Speed controls
        if (IsKeyDown(KEY_LEFT_SHIFT)) {
            controller->buttons[BUTTON_GAS] = 1;
        }
        if (IsKeyDown(KEY_Z)) {
            controller->buttons[BUTTON_BRAKE] = 1;
        }
    } else {
        // Read joystick events
        struct js_event event;
        while (read(controller->joystick_fd, &event, sizeof(event)) > 0) {
            if (event.type == JS_EVENT_AXIS && event.number < AXIS_COUNT) {
                controller->axes[event.number] = event.value;
            } else if (event.type == JS_EVENT_BUTTON && event.number < BUTTON_COUNT) {
                controller->buttons[event.number] = event.value;
            }
        }
    }
    
    // Validate input through model
    controller->validated_input = input_model_validate(controller->model, 
                                                      controller->axes, 
                                                      controller->buttons);
    
    // Convert to game actions
    controller->actions = input_model_convert_to_actions(controller->model,
                                                        &controller->validated_input);
}

game_actions_t input_controller_get_actions(input_controller_t* controller) {
    return controller->actions;
}

const validated_input_t* input_controller_get_validated_input(input_controller_t* controller) {
    return &controller->validated_input;
}

bool input_controller_is_connected(input_controller_t* controller) {
    return controller->connected;
}

const char* input_controller_get_error(input_controller_t* controller) {
    if (!controller->validated_input.is_valid) {
        return controller->validated_input.validation_error;
    }
    return NULL;
}

void input_controller_draw_overlay(input_controller_t* controller,
                                  int screen_width,
                                  int screen_height) {
    if (!controller->debug_mode) return;
    
    // Draw input state
    input_view_draw_overlay(controller->view,
                           &controller->validated_input,
                           &controller->actions,
                           screen_width,
                           screen_height);
    
    // Draw any errors
    const char* error = input_controller_get_error(controller);
    if (error) {
        input_view_draw_error(controller->view, error, screen_width, screen_height);
    }
}

void input_controller_set_debug_mode(input_controller_t* controller, bool enabled) {
    controller->debug_mode = enabled;
}
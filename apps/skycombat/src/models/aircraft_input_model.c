/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../../specifications/joystick_control_specs.h"
#include <raylib.h>
#include <linux/joystick.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>

/* Model: Pure data and business logic for aircraft input */

typedef struct {
    /* Joystick state */
    int joystick_fd;
    bool joystick_connected;
    int16_t axes[AXIS_COUNT];
    uint8_t buttons[BUTTON_COUNT];
    
    /* Keyboard state (fallback) */
    bool keyboard_active;
    
    /* Processed input */
    validated_joystick_input_t validated_input;
    
    /* Timing */
    uint32_t last_update_ms;
    
    /* Statistics */
    uint32_t total_updates;
    uint32_t failed_validations;
} aircraft_input_model_t;

/* Singleton instance */
static aircraft_input_model_t g_input_model = {
    .joystick_fd = -1,
    .joystick_connected = false,
    .keyboard_active = true
};

/* Get current time in milliseconds */
static uint32_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

/* Initialize joystick connection */
bool aircraft_input_model_init_joystick(void) {
    /* Enforce specifications at compile time */
    ENFORCE_JOYSTICK_CONTROLS();
    
    /* Try to open joystick */
    g_input_model.joystick_fd = open("/dev/input/js0", O_RDONLY | O_NONBLOCK);
    
    if (g_input_model.joystick_fd >= 0) {
        g_input_model.joystick_connected = true;
        g_input_model.keyboard_active = false;
        
        /* Initialize axes to center position */
        memset(g_input_model.axes, 0, sizeof(g_input_model.axes));
        g_input_model.axes[AXIS_R2] = JOYSTICK_AXIS_MIN;  /* Triggers start unpressed */
        g_input_model.axes[AXIS_L2] = JOYSTICK_AXIS_MIN;
        
        return true;
    }
    
    g_input_model.joystick_connected = false;
    g_input_model.keyboard_active = true;
    return false;
}

/* Read joystick events */
static void read_joystick_events(void) {
    if (g_input_model.joystick_fd < 0) return;
    
    struct js_event event;
    while (read(g_input_model.joystick_fd, &event, sizeof(event)) > 0) {
        if (event.type == JS_EVENT_AXIS && event.number < AXIS_COUNT) {
            g_input_model.axes[event.number] = event.value;
        } else if (event.type == JS_EVENT_BUTTON && event.number < BUTTON_COUNT) {
            g_input_model.buttons[event.number] = event.value;
        }
    }
}

/* Read keyboard as joystick emulation */
static void read_keyboard_as_joystick(void) {
    /* Reset state */
    memset(g_input_model.axes, 0, sizeof(g_input_model.axes));
    memset(g_input_model.buttons, 0, sizeof(g_input_model.buttons));
    
    /* Left stick = WASD for pitch/roll */
    if (IsKeyDown(KEY_A)) g_input_model.axes[AXIS_LEFT_X] = JOYSTICK_AXIS_MIN;
    if (IsKeyDown(KEY_D)) g_input_model.axes[AXIS_LEFT_X] = JOYSTICK_AXIS_MAX;
    if (IsKeyDown(KEY_W)) g_input_model.axes[AXIS_LEFT_Y] = JOYSTICK_AXIS_MIN;
    if (IsKeyDown(KEY_S)) g_input_model.axes[AXIS_LEFT_Y] = JOYSTICK_AXIS_MAX;
    
    /* Right stick = Q/E for yaw */
    if (IsKeyDown(KEY_Q)) g_input_model.axes[AXIS_RIGHT_X] = JOYSTICK_AXIS_MIN;
    if (IsKeyDown(KEY_E)) g_input_model.axes[AXIS_RIGHT_X] = JOYSTICK_AXIS_MAX;
    
    /* Gas/Brake buttons */
    if (IsKeyDown(KEY_LEFT_SHIFT)) g_input_model.buttons[2] = 1;  /* Gas (Button 2) */
    if (IsKeyDown(KEY_LEFT_CONTROL)) g_input_model.buttons[3] = 1;  /* Brake (Button 3) */
    
    /* Triggers */
    if (IsKeyDown(KEY_SPACE)) g_input_model.axes[AXIS_R2] = JOYSTICK_AXIS_MAX;
    else g_input_model.axes[AXIS_R2] = JOYSTICK_AXIS_MIN;
    
    if (IsKeyDown(KEY_Z)) g_input_model.axes[AXIS_L2] = JOYSTICK_AXIS_MAX;
    else g_input_model.axes[AXIS_L2] = JOYSTICK_AXIS_MIN;
    
    /* Other buttons */
    if (IsKeyDown(KEY_X)) g_input_model.buttons[BUTTON_A] = 1;  /* Afterburner */
    if (IsKeyDown(KEY_G)) g_input_model.buttons[BUTTON_B] = 1;  /* Landing gear */
}

/* Update input model */
void aircraft_input_model_update(void) {
    uint32_t now_ms = get_time_ms();
    
    /* Check response time requirement */
    uint32_t delta_ms = now_ms - g_input_model.last_update_ms;
    if (delta_ms > MAX_INPUT_LATENCY_MS) {
        g_input_model.failed_validations++;
    }
    
    /* Read input based on active device */
    if (g_input_model.joystick_connected) {
        read_joystick_events();
    } else {
        read_keyboard_as_joystick();
    }
    
    /* Validate input */
    g_input_model.validated_input = validate_joystick_input(
        g_input_model.axes,
        g_input_model.buttons,
        now_ms
    );
    
    /* Update statistics */
    g_input_model.last_update_ms = now_ms;
    g_input_model.total_updates++;
}

/* Get validated input */
const validated_joystick_input_t* aircraft_input_model_get_validated(void) {
    return &g_input_model.validated_input;
}

/* Get connection status */
bool aircraft_input_model_is_joystick_connected(void) {
    return g_input_model.joystick_connected;
}

/* Get statistics for debugging */
void aircraft_input_model_get_stats(uint32_t* total_updates, uint32_t* failed_validations) {
    if (total_updates) *total_updates = g_input_model.total_updates;
    if (failed_validations) *failed_validations = g_input_model.failed_validations;
}

/* Cleanup */
void aircraft_input_model_cleanup(void) {
    if (g_input_model.joystick_fd >= 0) {
        close(g_input_model.joystick_fd);
        g_input_model.joystick_fd = -1;
    }
    g_input_model.joystick_connected = false;
}
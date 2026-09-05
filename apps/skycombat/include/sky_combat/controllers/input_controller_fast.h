/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_INPUT_CONTROLLER_FAST_H
#define SKY_COMBAT_INPUT_CONTROLLER_FAST_H

#include "../models/input_model_fast.h"

// Fast controller - minimal overhead
typedef struct {
    int fd;                        // Joystick file descriptor
    input_model_fast_t* model;     // Direct pointer to model
    
    // Performance optimization
    bool use_event_batching;       // Read multiple events at once
    struct js_event* event_buffer; // Pre-allocated event buffer
    int buffer_size;
} input_controller_fast_t;

// Controller functions
input_controller_fast_t* input_controller_fast_create(input_model_fast_t* model);
void input_controller_fast_destroy(input_controller_fast_t* controller);

// Single update call - processes all pending events
void input_controller_fast_update(input_controller_fast_t* controller);

// Performance tuning
void input_controller_fast_set_batching(input_controller_fast_t* controller, bool enable, int buffer_size);

#endif // SKY_COMBAT_INPUT_CONTROLLER_FAST_H
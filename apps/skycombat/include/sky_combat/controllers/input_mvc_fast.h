/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_INPUT_MVC_FAST_H
#define SKY_COMBAT_INPUT_MVC_FAST_H

#include "../models/input_model_fast.h"
#include "../controllers/input_controller_fast.h"
#include "../views/input_view_fast.h"

// High-performance MVC system
typedef struct {
    input_model_fast_t model;
    input_controller_fast_t* controller;
    input_view_fast_t view;
} input_mvc_fast_t;

// Create/destroy
input_mvc_fast_t* input_mvc_fast_create(void);
void input_mvc_fast_destroy(input_mvc_fast_t* mvc);

// Single update call - returns view for immediate use
static inline input_view_fast_t input_mvc_fast_update(input_mvc_fast_t* mvc) {
    input_controller_fast_update(mvc->controller);
    return mvc->view;
}

// Direct state access for maximum performance
static inline const input_state_fast_t* input_mvc_fast_get_state_ptr(input_mvc_fast_t* mvc) {
    // Return direct pointer to normalized values - zero copy
    return (const input_state_fast_t*)&mvc->model.normalized;
}

// Configuration
static inline void input_mvc_fast_set_deadzone(input_mvc_fast_t* mvc, float deadzone) {
    mvc->model.deadzone_threshold = deadzone;
}

static inline void input_mvc_fast_set_curve(input_mvc_fast_t* mvc, float curve) {
    mvc->model.response_curve = curve;
    // Would need to reinit LUT here in real implementation
}

#endif // SKY_COMBAT_INPUT_MVC_FAST_H
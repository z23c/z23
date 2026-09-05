/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_INPUT_VIEW_FAST_H
#define SKY_COMBAT_INPUT_VIEW_FAST_H

#include "../models/input_model_fast.h"

// Fast view - Zero-copy access to model data
typedef struct {
    const input_model_fast_t* model;  // Read-only access
} input_view_fast_t;

// Inline accessors for zero overhead
static inline input_view_fast_t input_view_fast_create(const input_model_fast_t* model) {
    return (input_view_fast_t){ .model = model };
}

// Direct state access - no function call overhead
static inline float input_view_get_move_x(input_view_fast_t view) {
    return view.model->normalized.move_x;
}

static inline float input_view_get_move_y(input_view_fast_t view) {
    return view.model->normalized.move_y;
}

static inline bool input_view_is_firing(input_view_fast_t view) {
    return view.model->actions & (ACTION_FIRE_GUNS | ACTION_FIRE_MISSILES);
}

// Convenience structure for game code
typedef struct {
    float move_x, move_y;
    float camera_x, camera_y;
    bool fire_guns, fire_missiles;
    bool barrel_roll_left, barrel_roll_right;
    bool speed_boost, brake;
    bool speed_normal;  // UR paddle for normal forward speed
} input_state_fast_t;

// Single copy operation for when you need all state at once
static inline input_state_fast_t input_view_get_state(input_view_fast_t view) {
    const input_model_fast_t* m = view.model;
    return (input_state_fast_t){
        .move_x = m->normalized.move_x,
        .move_y = m->normalized.move_y,
        .camera_x = m->normalized.camera_x,
        .camera_y = m->normalized.camera_y,
        .fire_guns = (m->actions & ACTION_FIRE_GUNS) != 0,
        .fire_missiles = (m->actions & ACTION_FIRE_MISSILES) != 0,
        .barrel_roll_left = (m->actions & ACTION_BARREL_ROLL_LEFT) != 0,
        .barrel_roll_right = (m->actions & ACTION_BARREL_ROLL_RIGHT) != 0,
        .speed_boost = (m->actions & ACTION_SPEED_BOOST) != 0,
        .brake = (m->actions & ACTION_BRAKE) != 0
    };
}

#endif // SKY_COMBAT_INPUT_VIEW_FAST_H
/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_INPUT_DIRECT_H
#define SKY_COMBAT_INPUT_DIRECT_H

#include <stdbool.h>
#include <stdint.h>

// Direct input state - no MVC, just what we need
typedef struct {
    // Movement
    float move_x;       // -1 to 1
    float move_y;       // -1 to 1
    float camera_x;     // -1 to 1
    float camera_y;     // -1 to 1
    
    // Actions - direct button states
    bool fire_guns;
    bool fire_missiles;
    bool barrel_roll_left;
    bool barrel_roll_right;
    bool speed_boost;
    bool brake;
    
    // Raw values for fine control
    float left_trigger;   // 0 to 1
    float right_trigger;  // 0 to 1
    
    // Meta
    bool connected;
    float dt;  // Frame time for direct updates
} input_direct_t;

// Simplified input system
typedef struct input_system_s input_system_t;

// Create/destroy
input_system_t* input_direct_create(void);
void input_direct_destroy(input_system_t* input);

// Update - returns current state directly
input_direct_t input_direct_update(input_system_t* input, float dt);

// Configuration
void input_direct_set_deadzone(input_system_t* input, float deadzone);
void input_direct_set_response_curve(input_system_t* input, float curve); // 1.0 = linear, 2.0 = squared

#endif // SKY_COMBAT_INPUT_DIRECT_H
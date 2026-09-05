/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_INPUT_MODEL_H
#define SKY_COMBAT_INPUT_MODEL_H

#include <stdbool.h>

// ASTRO C40 Controller Constants - LOCKED DOWN
#define ASTRO_C40_VENDOR_ID 0x9886
#define ASTRO_C40_PRODUCT_ID 0x0025
#define ASTRO_C40_NAME "ASTRO Gaming C40 TR Controller"

// Axis mappings - IMMUTABLE
typedef enum {
    AXIS_LEFT_STICK_X = 0,
    AXIS_LEFT_STICK_Y = 1,
    AXIS_RIGHT_STICK_X = 2,
    AXIS_L2_TRIGGER = 3,
    AXIS_R2_TRIGGER = 4,
    AXIS_RIGHT_STICK_Y = 5,
    AXIS_COUNT = 6
} axis_id_t;

// Button mappings - IMMUTABLE
typedef enum {
    BUTTON_X = 0,           // Face button X
    BUTTON_CIRCLE = 1,      // Face button Circle
    BUTTON_GAS = 2,         // UL Paddle - LOCKED TO GAS
    BUTTON_BRAKE = 3,       // UR Paddle - LOCKED TO BRAKE
    BUTTON_L1 = 4,          // Left shoulder
    BUTTON_R1 = 5,          // Right shoulder
    BUTTON_L2 = 6,          // L2 digital
    BUTTON_R2 = 7,          // R2 digital
    BUTTON_SHARE = 8,       // Share button
    BUTTON_OPTIONS = 9,     // Options button
    BUTTON_PS = 10,         // PlayStation button
    BUTTON_L3 = 11,         // Left stick click
    BUTTON_R3 = 12,         // Right stick click
    BUTTON_COUNT = 16
} button_id_t;

// Validated input state - immutable once created
typedef struct {
    float axes[AXIS_COUNT];
    short raw_axes[AXIS_COUNT];  // Store raw values for special handling
    bool buttons[BUTTON_COUNT];
    bool is_valid;
    char validation_error[256];
} validated_input_t;

// Control mapping - what each input does
typedef struct {
    // Movement
    axis_id_t move_x_axis;      // Must be LEFT_STICK_X
    axis_id_t move_y_axis;      // Must be LEFT_STICK_Y
    
    // Camera
    axis_id_t camera_x_axis;    // Must be RIGHT_STICK_X
    axis_id_t camera_y_axis;    // Must be RIGHT_STICK_Y
    
    // Weapons - LOCKED MAPPING
    axis_id_t fire_missiles_axis;  // Must be L2_TRIGGER
    axis_id_t fire_guns_axis;      // Must be R2_TRIGGER
    
    // Special moves
    button_id_t barrel_roll_left;  // Must be L1
    button_id_t barrel_roll_right; // Must be R1
    
    // Speed control - LOCKED MAPPING
    button_id_t speed_boost;    // Must be BUTTON_GAS (2)
    button_id_t brake;          // Must be BUTTON_BRAKE (3)
} control_mapping_t;

// Input model - handles validation and state
typedef struct input_model_s input_model_t;

// Model creation/destruction
input_model_t* input_model_create(void);
void input_model_destroy(input_model_t* model);

// Get the locked control mapping
const control_mapping_t* input_model_get_mapping(const input_model_t* model);

// Validate raw input data
validated_input_t input_model_validate(const input_model_t* model, 
                                       const short* axes, 
                                       const short* buttons);

// Convert validated input to game actions
typedef struct {
    float move_x;           // -1.0 to 1.0
    float move_y;           // -1.0 to 1.0
    float camera_x;         // -1.0 to 1.0
    float camera_y;         // -1.0 to 1.0
    bool fire_guns;         // R2 pressed
    bool fire_missiles;     // L2 pressed
    bool barrel_roll_left;  // L1 pressed
    bool barrel_roll_right; // R1 pressed
    bool speed_boost;       // Button 2 (Gas)
    bool brake;             // Button 3 (Brake)
} game_actions_t;

game_actions_t input_model_convert_to_actions(const input_model_t* model,
                                              const validated_input_t* input);

// Validation rules
bool input_model_validate_axis_range(short value);
bool input_model_validate_l2_trigger(short value);
bool input_model_validate_r2_trigger(short value);

// Get last validation error
const char* input_model_get_last_error(const input_model_t* model);

#endif // SKY_COMBAT_INPUT_MODEL_H
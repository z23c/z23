/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_CONTROLS_PERMANENT_H
#define SKY_COMBAT_CONTROLS_PERMANENT_H

/*
 * PERMANENT CONTROL MAPPING - SET IN STONE
 * DO NOT MODIFY THESE MAPPINGS!
 * 
 * This file defines the FINAL control scheme for Sky Combat
 * Any changes to controls should be made through remapping,
 * NOT by changing these definitions.
 */

// ASTRO C40 Controller Button Mappings (Linux /dev/input/js0)
#define BUTTON_X            0   // Bottom face button
#define BUTTON_CIRCLE       1   // Right face button  
#define BUTTON_SQUARE       2   // Left face button
#define BUTTON_TRIANGLE     3   // Top face button
#define BUTTON_L1           4   // Left shoulder
#define BUTTON_R1           5   // Right shoulder
#define BUTTON_L2           6   // Left trigger (digital)
#define BUTTON_R2           7   // Right trigger (digital)
#define BUTTON_SHARE        8   // Share/Select
#define BUTTON_OPTIONS      9   // Options/Start
#define BUTTON_L3          10   // Left stick click
#define BUTTON_R3          11   // Right stick click
#define BUTTON_PS          12   // PlayStation/Home button
#define BUTTON_TOUCHPAD    13   // Touchpad click

// Programmable Paddles (appear as duplicates of mapped buttons)
// UL = Upper Left paddle
// UR = Upper Right paddle
// LL = Lower Left paddle  
// LR = Lower Right paddle

// ASTRO C40 Axis Mappings
#define AXIS_LEFT_X         0   // Left stick X (-32768 to 32767)
#define AXIS_LEFT_Y         1   // Left stick Y (-32768 to 32767)
#define AXIS_RIGHT_X        2   // Right stick X (-32768 to 32767)
#define AXIS_L2_TRIGGER     3   // L2 analog (-32767 unpressed to 32767 pressed)
#define AXIS_R2_TRIGGER     4   // R2 analog (-32767 unpressed to 0 pressed) WARNING: GOES TO ZERO!
#define AXIS_RIGHT_Y        5   // Right stick Y (-32768 to 32767)

// PERMANENT GAME CONTROL MAPPING
// FLIGHT CONTROLS
#define CONTROL_PITCH       AXIS_LEFT_Y      // Pull back to climb
#define CONTROL_ROLL        AXIS_LEFT_X      // Left/right to roll
#define CONTROL_YAW         AXIS_RIGHT_X     // Camera/rudder
#define CONTROL_CAMERA_Y    AXIS_RIGHT_Y     // Camera up/down

// SPEED CONTROLS - PADDLES
#define CONTROL_THROTTLE_UP    BUTTON_TRIANGLE  // UR paddle (mapped to Triangle)
#define CONTROL_THROTTLE_DOWN  BUTTON_SQUARE    // UL paddle (mapped to Square)

// COMBAT CONTROLS  
#define CONTROL_FIRE_PRIMARY   AXIS_R2_TRIGGER  // R2 - Primary weapon
#define CONTROL_FIRE_SECONDARY AXIS_L2_TRIGGER  // L2 - Missiles/secondary

// MANEUVERS
#define CONTROL_BARREL_LEFT    BUTTON_L1       // L1 - Barrel roll left
#define CONTROL_BARREL_RIGHT   BUTTON_R1       // R1 - Barrel roll right

// WEAPON SWITCHING
#define CONTROL_WEAPON_1       BUTTON_X         // Machine gun
#define CONTROL_WEAPON_2       BUTTON_CIRCLE    // Laser
#define CONTROL_WEAPON_3       BUTTON_L3        // Plasma
#define CONTROL_WEAPON_4       BUTTON_R3        // Spread

// SPECIAL SYSTEMS
#define CONTROL_OVERDRIVE      BUTTON_PS        // OVERDRIVE activation

// MENU/UI
#define CONTROL_PAUSE          BUTTON_OPTIONS   // Pause game
#define CONTROL_MAP            BUTTON_SHARE     // Toggle map/radar

// HELPER MACROS FOR CORRECT TRIGGER DETECTION
#define IS_R2_PRESSED(axis_value) ((axis_value) > -16000)  // R2 goes from -32767 to 0
#define IS_L2_PRESSED(axis_value) ((axis_value) > 0)       // L2 goes from -32767 to 32767

// DEAD ZONES
#define STICK_DEADZONE 8000
#define TRIGGER_DEADZONE 0.1f

/*
 * CONTROL SUMMARY:
 * 
 * FLYING:
 * - Left Stick: Pitch & Roll
 * - Right Stick: Camera
 * - UR (Triangle): Speed up / Throttle up
 * - UL (Square): Speed down / Brake
 * 
 * COMBAT:
 * - R2: Fire main weapon
 * - L2: Fire missiles
 * - L1/R1: Barrel rolls
 * - Face buttons: Switch weapons
 * - PS button: OVERDRIVE
 * 
 * This mapping is PERMANENT and should NEVER be changed.
 * All future versions must respect this layout.
 */

#endif // SKY_COMBAT_CONTROLS_PERMANENT_H
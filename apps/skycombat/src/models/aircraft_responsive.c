/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/models/aircraft.h"
#include <raylib.h>
#include <raymath.h>
#include <stdlib.h>
#include <math.h>

// More responsive aircraft update
void aircraft_update_responsive(aircraft_t* aircraft, float stick_x, float stick_y, float dt) {
    if (!aircraft) return;
    
    // Constants for SUPER responsive control
    const float MAX_ROLL = 80.0f;    // Was 60, more banking!
    const float MAX_PITCH = 60.0f;   // Was 45, more pitch!
    const float TURN_SPEED = 180.0f; // Was 90, DOUBLE turn rate!
    const float MIN_ALTITUDE = 10.0f;
    const float MAX_ALTITUDE = 500.0f;
    
    // Direct roll response - no lerping for immediate control
    // INVERTED: stick right = roll left (tilt left)
    float targetRoll = stick_x * MAX_ROLL;  // Removed negative to invert
    aircraft->roll = targetRoll;  // Direct assignment for instant response
    
    // Pitch with minimal smoothing (inverted for proper flight controls)
    float targetPitch = -stick_y * MAX_PITCH;  // Inverted: pull back to pitch up
    float pitch_rate = 12.0f;  // Even faster for instant response
    aircraft->pitch = Lerp(aircraft->pitch, targetPitch, pitch_rate * dt);
    
    // Turn rate based on roll - immediate response
    // INVERTED: positive roll (left tilt) should turn left (decrease yaw)
    float turn_rate = TURN_SPEED * sinf(aircraft->roll * DEG2RAD);
    aircraft->yaw -= turn_rate * dt;  // Changed from += to -= to match inverted roll
    
    // Speed handled by boost/brake in main game loop
    // Just apply movement based on current speed
    
    // Calculate movement
    float yaw_rad = aircraft->yaw * DEG2RAD;
    float pitch_rad = aircraft->pitch * DEG2RAD;
    
    Vector3 forward = {
        sinf(yaw_rad) * cosf(pitch_rad),
        -sinf(pitch_rad),
        cosf(yaw_rad) * cosf(pitch_rad)
    };
    
    Vector3 velocity = Vector3Scale(forward, aircraft->speed);
    aircraft->position = Vector3Add(aircraft->position, Vector3Scale(velocity, dt));
    
    // Altitude limits
    if (aircraft->position.y < MIN_ALTITUDE) {
        aircraft->position.y = MIN_ALTITUDE;
        if (aircraft->pitch < 0) aircraft->pitch = 0;
    }
    if (aircraft->position.y > MAX_ALTITUDE) {
        aircraft->position.y = MAX_ALTITUDE;
        if (aircraft->pitch > 0) aircraft->pitch = 0;
    }
    
    // Apply world wrapping
    aircraft_wrap_position(aircraft);
}

// Camera update function moved to camera_controller.c to avoid duplication

// Instant barrel roll - simplified for existing struct
void aircraft_barrel_roll_instant(aircraft_t* aircraft, float direction) {
    if (!aircraft) return;
    
    // We'll handle barrel roll in the main game logic
    // Just boost speed instantly
    aircraft->speed = fminf(aircraft->speed * 1.3f, AIRCRAFT_MAX_SPEED * 1.5f);
}

// For HUD - no smoothing
float aircraft_get_speed_percentage_instant(aircraft_t* aircraft) {
    if (!aircraft) return 0;
    
    float range = AIRCRAFT_MAX_SPEED - AIRCRAFT_MIN_SPEED;
    if (range <= 0) return 0;
    
    return (aircraft->speed - AIRCRAFT_MIN_SPEED) / range;
}
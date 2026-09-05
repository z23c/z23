/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/models/aircraft.h"
#include <stdlib.h>
#include <math.h>
#include <raymath.h>
#include <stdbool.h>

// The proven control values
#define AIRCRAFT_BASE_SPEED 60.0f
#define AIRCRAFT_MAX_SPEED 120.0f  
#define AIRCRAFT_MIN_SPEED 30.0f
#define AIRCRAFT_TURN_RATE 150.0f
#define AIRCRAFT_PITCH_RATE 100.0f
#define AIRCRAFT_BOOST_MULTIPLIER 3.0f
#define AIRCRAFT_DRIFT_MULTIPLIER 2.5f

// The struct is already defined in the header, no need to redefine

aircraft_t* aircraft_create(Vector3 start_pos) {
    aircraft_t* aircraft = calloc(1, sizeof(aircraft_t));
    if (!aircraft) return NULL;
    
    aircraft->position = start_pos;
    aircraft->speed = AIRCRAFT_BASE_SPEED;
    aircraft->altitude = start_pos.y;
    aircraft->score = 0;
    aircraft->rings = 0;
    
    return aircraft;
}

void aircraft_destroy(aircraft_t* aircraft) {
    free(aircraft);
}

void aircraft_update(aircraft_t* aircraft, float inputX, float inputY, float dt) {
    // Update aircraft with input
    aircraft->yaw += inputX * AIRCRAFT_TURN_RATE * dt;
    aircraft->pitch = Lerp(aircraft->pitch, inputY * 40.0f, 8.0f * dt);
    aircraft->roll = Lerp(aircraft->roll, -inputX * 35.0f, 5.0f * dt);
    
    // Speed control
    if (aircraft->pitch < 0) {
        aircraft->speed += (-aircraft->pitch / 30.0f) * 30.0f * dt;
    } else {
        aircraft->speed -= (aircraft->pitch / 30.0f) * 5.0f * dt;
    }
    
    aircraft->speed = Clamp(aircraft->speed, AIRCRAFT_MIN_SPEED, AIRCRAFT_MAX_SPEED);
    
    // Update position
    float yaw_rad = aircraft->yaw * DEG2RAD;
    float pitch_rad = aircraft->pitch * DEG2RAD;
    Vector3 forward = {
        sinf(yaw_rad) * cosf(pitch_rad),
        -sinf(pitch_rad),
        cosf(yaw_rad) * cosf(pitch_rad)
    };
    
    aircraft->position = Vector3Add(aircraft->position,
                                   Vector3Scale(forward, aircraft->speed * dt));
    aircraft->altitude = aircraft->position.y;
}

void aircraft_draw(aircraft_t* aircraft, float gameTime) {
    // Draw implementation would go here
}

void aircraft_barrel_roll_left(aircraft_t* aircraft, float dt) {
    aircraft->roll -= 360.0f * dt;
}

void aircraft_barrel_roll_right(aircraft_t* aircraft, float dt) {
    aircraft->roll += 360.0f * dt;
}

void aircraft_boost(aircraft_t* aircraft, float dt) {
    aircraft->speed = Clamp(aircraft->speed + 50.0f * dt, AIRCRAFT_MIN_SPEED, AIRCRAFT_MAX_SPEED);
}

void aircraft_brake(aircraft_t* aircraft, float dt) {
    aircraft->speed = Clamp(aircraft->speed - 60.0f * dt, AIRCRAFT_MIN_SPEED, AIRCRAFT_MAX_SPEED);
}

Vector3 aircraft_get_forward_vector(aircraft_t* aircraft) {
    float yaw_rad = aircraft->yaw * DEG2RAD;
    float pitch_rad = aircraft->pitch * DEG2RAD;
    return (Vector3){
        sinf(yaw_rad) * cosf(pitch_rad),
        -sinf(pitch_rad),
        cosf(yaw_rad) * cosf(pitch_rad)
    };
}

float aircraft_get_speed_percent(aircraft_t* aircraft) {
    return (aircraft->speed - AIRCRAFT_MIN_SPEED) / (AIRCRAFT_MAX_SPEED - AIRCRAFT_MIN_SPEED);
}

// Removed - using the real responsive implementation from aircraft_responsive.c

void aircraft_wrap_position(aircraft_t* aircraft) {
    if (aircraft->position.x > WORLD_HALF_SIZE) aircraft->position.x -= WORLD_SIZE;
    if (aircraft->position.x < -WORLD_HALF_SIZE) aircraft->position.x += WORLD_SIZE;
    if (aircraft->position.z > WORLD_HALF_SIZE) aircraft->position.z -= WORLD_SIZE;
    if (aircraft->position.z < -WORLD_HALF_SIZE) aircraft->position.z += WORLD_SIZE;
    
    if (aircraft->position.y < WORLD_MIN_HEIGHT) aircraft->position.y = WORLD_MIN_HEIGHT;
    if (aircraft->position.y > WORLD_MAX_HEIGHT) aircraft->position.y = WORLD_MAX_HEIGHT;
}

Vector3 aircraft_get_position(aircraft_t* aircraft) {
    return aircraft ? aircraft->position : (Vector3){0, 0, 0};
}

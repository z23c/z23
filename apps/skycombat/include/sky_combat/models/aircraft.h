/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_AIRCRAFT_H
#define SKY_COMBAT_AIRCRAFT_H

#include <raylib.h>

// Flight constants
#define AIRCRAFT_BASE_SPEED 60.0f   // Was 37.5, now even faster!
#define AIRCRAFT_MAX_SPEED 120.0f    // Was 75, much faster!
#define AIRCRAFT_MIN_SPEED 30.0f    // Was 22.5, higher minimum
#define AIRCRAFT_TURN_RATE 150.0f   // Was 90, much more agile!
#define AIRCRAFT_PITCH_RATE 100.0f   // Was 60, more responsive!
#define AIRCRAFT_GRAVITY 9.81f

// World boundaries (planet surface wrapping)
#define WORLD_SIZE 2000.0f
#define WORLD_HALF_SIZE (WORLD_SIZE / 2.0f)
#define WORLD_MIN_HEIGHT 10.0f
#define WORLD_MAX_HEIGHT 500.0f

typedef struct {
    Vector3 position;
    float yaw;         // left/right rotation
    float pitch;       // up/down angle
    float roll;        // banking angle
    float speed;       // forward speed
    float altitude;
    int score;
    int rings;
    float fireTimer;
    float missileTimer;
    int missileSide;   // -1 for left, 1 for right (alternates)
} aircraft_t;

// Aircraft operations
aircraft_t* aircraft_create(Vector3 start_pos);
void aircraft_destroy(aircraft_t* aircraft);
void aircraft_update(aircraft_t* aircraft, float inputX, float inputY, float dt);
void aircraft_draw(aircraft_t* aircraft, float gameTime);

// Control modifiers
void aircraft_barrel_roll_left(aircraft_t* aircraft, float dt);
void aircraft_barrel_roll_right(aircraft_t* aircraft, float dt);
void aircraft_boost(aircraft_t* aircraft, float dt);
void aircraft_brake(aircraft_t* aircraft, float dt);

// State queries
Vector3 aircraft_get_forward_vector(aircraft_t* aircraft);
float aircraft_get_speed_percent(aircraft_t* aircraft);

// Responsive control version
void aircraft_update_responsive(aircraft_t* aircraft, float stick_x, float stick_y, float dt);

// World wrapping
void aircraft_wrap_position(aircraft_t* aircraft);

// Getters for specification checks
Vector3 aircraft_get_position(aircraft_t* aircraft);

#endif // SKY_COMBAT_AIRCRAFT_H
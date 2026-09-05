/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_POWERUPS_H
#define SKY_COMBAT_POWERUPS_H

#include <raylib.h>
#include <stdbool.h>

// Powerup types
typedef enum {
    POWERUP_NONE = 0,
    POWERUP_SPEED_BOOST,      // Temporary max speed increase
    POWERUP_RAPID_FIRE,       // Triple fire rate
    POWERUP_SHIELD,           // Invincibility
    POWERUP_MAGNET,           // Attracts nearby rings
    POWERUP_SLOW_MOTION,      // Bullet time effect
    POWERUP_MEGA_MISSILE,     // Super homing missile
    POWERUP_BARREL_ROLL,      // Unlimited barrel rolls
    POWERUP_SCORE_MULTIPLIER, // 2x score for 30 seconds
    POWERUP_COUNT
} powerup_type_t;

typedef struct {
    Vector3 position;
    powerup_type_t type;
    bool active;
    float rotation;
    float bob_offset;
    float spawn_time;
} powerup_t;

typedef struct {
    float duration;
    float time_remaining;
    bool active;
} powerup_effect_t;

typedef struct {
    powerup_effect_t effects[POWERUP_COUNT];
    int score_multiplier;
    float speed_multiplier;
    float fire_rate_multiplier;
    bool has_shield;
    bool has_magnet;
    float slow_motion_factor;
} powerup_state_t;

// Powerup management
void powerup_spawn_random(powerup_t* powerup, Vector3 near_position);
void powerup_update(powerup_t* powerup, float delta_time);
void powerup_draw(powerup_t* powerup, float game_time);

// Powerup effects
void powerup_activate(powerup_state_t* state, powerup_type_t type);
void powerup_update_state(powerup_state_t* state, float delta_time);
bool powerup_is_active(powerup_state_t* state, powerup_type_t type);

// Visual effects
Color powerup_get_color(powerup_type_t type);
const char* powerup_get_name(powerup_type_t type);
void powerup_draw_effects(powerup_state_t* state, Vector3 position);

#endif // SKY_COMBAT_POWERUPS_H
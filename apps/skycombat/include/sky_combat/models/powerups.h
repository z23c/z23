/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_POWERUPS_H
#define SKY_COMBAT_POWERUPS_H

#include <raylib.h>
#include <stdbool.h>

typedef enum {
    POWERUP_HEALTH,         // Restore health
    POWERUP_SHIELD,         // Temporary invincibility
    POWERUP_RAPID_FIRE,     // Faster shooting
    POWERUP_MISSILE,        // Homing missiles
    POWERUP_LASER,          // Laser weapon
    POWERUP_SPEED_BOOST,    // Temporary speed increase
    POWERUP_DOUBLE_DAMAGE,  // Double damage output
    POWERUP_REPAIR_KIT,     // Full health restore
    POWERUP_TYPE_COUNT
} powerup_type_t;

typedef struct {
    powerup_type_t type;
    Vector3 position;
    float rotation;
    float bob_offset;       // For floating animation
    bool active;
    float respawn_timer;
    int spawn_point_id;
    
    // Visual properties
    Color color;
    float size;
    
    // Gameplay properties
    float duration;         // How long the effect lasts
    float value;           // Effect strength (health amount, damage multiplier, etc)
} powerup_t;

typedef struct {
    Vector3 position;
    powerup_type_t preferred_type;  // -1 for random
    float respawn_time;
} powerup_spawn_point_t;

typedef struct {
    powerup_t powerups[32];
    int powerup_count;
    
    powerup_spawn_point_t spawn_points[16];
    int spawn_point_count;
    
    float spawn_check_timer;
    float spawn_check_interval;
} powerup_manager_t;

// Power-up effects applied to aircraft
typedef struct {
    bool shield_active;
    float shield_timer;
    
    bool rapid_fire_active;
    float rapid_fire_timer;
    float fire_rate_multiplier;
    
    bool speed_boost_active;
    float speed_boost_timer;
    float speed_multiplier;
    
    bool double_damage_active;
    float double_damage_timer;
    
    int missile_count;
    bool laser_equipped;
    float laser_ammo;
} powerup_effects_t;

// Core functions
powerup_manager_t* powerup_manager_create(void);
void powerup_manager_destroy(powerup_manager_t* manager);

// Spawn point management
void powerup_manager_add_spawn_point(powerup_manager_t* manager, Vector3 position, powerup_type_t type, float respawn_time);
void powerup_manager_create_default_spawn_points(powerup_manager_t* manager);

// Update and spawning
void powerup_manager_update(powerup_manager_t* manager, float dt);
void powerup_manager_spawn_at_point(powerup_manager_t* manager, int spawn_point_id);
void powerup_manager_spawn_random(powerup_manager_t* manager);

// Collection
bool powerup_manager_check_collection(powerup_manager_t* manager, Vector3 position, float radius, powerup_type_t* collected_type);
void powerup_manager_collect(powerup_manager_t* manager, int powerup_id);

// Effects
void powerup_effects_init(powerup_effects_t* effects);
void powerup_effects_update(powerup_effects_t* effects, float dt);
void powerup_effects_apply(powerup_effects_t* effects, powerup_type_t type, float duration, float value);

// Properties
const char* powerup_get_name(powerup_type_t type);
Color powerup_get_color(powerup_type_t type);
float powerup_get_default_duration(powerup_type_t type);
float powerup_get_default_value(powerup_type_t type);

#endif
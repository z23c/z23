/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_ENEMIES_H
#define SKY_COMBAT_ENEMIES_H

#include <raylib.h>
#include <stdbool.h>
#include "../models/weapons.h"

// Enemy types
typedef enum {
    ENEMY_DRONE,         // Basic flying drone
    ENEMY_FIGHTER,       // Fast fighter jet
    ENEMY_TURRET,        // Stationary turret
    ENEMY_BOMBER,        // Heavy bomber
    ENEMY_SWARM,         // Small swarm unit
    ENEMY_BOSS_MECH,     // Giant flying mech
    ENEMY_BOSS_CARRIER,  // Massive carrier ship
} enemy_type_t;

// Enemy AI states
typedef enum {
    AI_PATROL,      // Flying in pattern
    AI_CHASE,       // Pursuing player
    AI_ATTACK,      // Actively firing
    AI_EVADE,       // Dodging fire
    AI_KAMIKAZE,    // Suicide run
    AI_FORMATION,   // Flying in group
} ai_state_t;

// Single enemy
typedef struct enemy_s {
    enemy_type_t type;
    ai_state_t state;
    
    // Transform
    Vector3 position;
    Vector3 velocity;
    Vector3 target_position;
    float yaw, pitch, roll;
    float scale;
    
    // Combat
    float health;
    float max_health;
    float fire_cooldown;
    float last_fire_time;
    bool has_shields;
    float shield_power;
    
    // Movement
    float speed;
    float turn_rate;
    float boost_fuel;
    
    // Visuals
    Color color;
    bool is_damaged;
    float damage_flash;
    
    // Behavior
    float aggression;     // 0-1, how aggressive
    float accuracy;       // 0-1, how accurate shots are
    float reaction_time;  // Time to react to player
    
    // Special abilities
    bool can_teleport;
    bool can_cloak;
    bool can_barrel_roll;
    float special_cooldown;
    
    // Death effects
    bool dying;
    float death_timer;
    int score_value;
    float explosion_radius;
    Color explosion_color;
    
    // Formation flying
    struct enemy_s* leader;
    Vector3 formation_offset;
    
} enemy_t;

// Enemy wave definitions
typedef struct {
    enemy_type_t type;
    int count;
    float spawn_delay;
    Vector3 spawn_position;
    bool in_formation;
} wave_spawn_t;

typedef struct {
    const char* name;
    wave_spawn_t* spawns;
    int spawn_count;
    float start_time;
    bool boss_wave;
} enemy_wave_t;

// Enemy projectile
typedef struct {
    Vector3 position;
    Vector3 velocity;
    float life;
    bool active;
    int damage;
    Color color;
    enemy_type_t from_enemy;
} enemy_projectile_t;

#define MAX_ENEMY_PROJECTILES 200

// Enemy manager
typedef struct {
    enemy_t* enemies;
    int max_enemies;
    int active_count;
    
    // Enemy weapons
    enemy_projectile_t projectiles[MAX_ENEMY_PROJECTILES];
    
    // Wave system
    enemy_wave_t* waves;
    int total_waves;
    int current_wave;
    float wave_timer;
    bool wave_active;
    
    // Combat stats
    int total_kills;
    int combo_count;
    float combo_timer;
    
    // Special effects
    bool slow_motion;
    float slow_mo_timer;
    
} enemy_manager_t;

// Enemy system
enemy_manager_t* enemies_create(int max_enemies);
void enemies_destroy(enemy_manager_t* manager);
void enemies_update(enemy_manager_t* manager, Vector3 player_pos, float dt);
void enemies_draw(enemy_manager_t* manager);

// Enemy spawning
void enemies_spawn(enemy_manager_t* manager, enemy_type_t type, Vector3 position);
void enemies_spawn_wave(enemy_manager_t* manager, int wave_index);
void enemies_spawn_formation(enemy_manager_t* manager, enemy_type_t type, Vector3 center, int count);
void enemies_spawn_practice_targets(enemy_manager_t* manager);

// Combat
bool enemies_check_hit(enemy_manager_t* manager, Vector3 position, float radius, float damage);
void enemies_damage(enemy_manager_t* manager, int index, float damage);
void enemies_explode(enemy_manager_t* manager, int index);

// AI behaviors
void enemy_ai_update(enemy_t* enemy, Vector3 player_pos, float dt);
void enemy_ai_patrol(enemy_t* enemy, float dt);
void enemy_ai_chase(enemy_t* enemy, Vector3 target, float dt);
void enemy_ai_attack(enemy_t* enemy, Vector3 target, enemy_manager_t* manager, float dt);
void enemy_ai_evade(enemy_t* enemy, Vector3 danger_pos, float dt);
void enemy_ai_formation(enemy_t* enemy, float dt);

// Enemy weapons
void enemy_fire_projectile(enemy_manager_t* manager, enemy_t* enemy, Vector3 target);
bool enemies_check_player_hit(enemy_manager_t* manager, Vector3 player_pos, float radius);

// Special moves
void enemy_barrel_roll(enemy_t* enemy);
void enemy_teleport(enemy_t* enemy, Vector3 new_pos);
void enemy_activate_cloak(enemy_t* enemy);
void enemy_boost(enemy_t* enemy, float power);

// Queries
int enemies_get_active_count(enemy_manager_t* manager);
enemy_t* enemies_get_nearest(enemy_manager_t* manager, Vector3 position);
bool enemies_wave_complete(enemy_manager_t* manager);

#endif // SKY_COMBAT_ENEMIES_H
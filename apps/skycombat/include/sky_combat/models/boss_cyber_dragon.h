/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_BOSS_CYBER_DRAGON_H
#define SKY_COMBAT_BOSS_CYBER_DRAGON_H

#include <raylib.h>
#include <stdbool.h>

// Epic Cyber Dragon Boss - Multi-phase aerial combat

typedef enum {
    DRAGON_PHASE_INTRO,      // Dramatic entrance
    DRAGON_PHASE_AERIAL,     // Flying attacks
    DRAGON_PHASE_RAGE,       // 50% health - faster, more aggressive
    DRAGON_PHASE_FINAL,      // 25% health - desperation attacks
    DRAGON_PHASE_DEATH       // Death animation
} dragon_phase_t;

typedef enum {
    DRAGON_IDLE,
    DRAGON_CIRCLING,         // Circle around player
    DRAGON_CHARGING,         // Direct charge attack
    DRAGON_LASER_SWEEP,      // Sweeping laser breath
    DRAGON_MISSILE_BARRAGE,  // Fire homing missiles
    DRAGON_TAIL_WHIP,        // Close range tail attack
    DRAGON_SUMMON_DRONES,    // Call reinforcements
    DRAGON_PLASMA_STORM,     // Area denial attack
    DRAGON_TELEPORT,         // Phase shift
    DRAGON_ULTIMATE          // Screen-filling attack
} dragon_attack_t;

// Dragon segment for serpentine body
typedef struct {
    Vector3 position;
    Vector3 velocity;
    float scale;
    Quaternion rotation;
} dragon_segment_t;

// Main boss structure
typedef struct {
    // Core stats
    float health;
    float max_health;
    dragon_phase_t phase;
    dragon_attack_t current_attack;
    float attack_timer;
    bool vulnerable;
    
    // Movement
    Vector3 position;
    Vector3 target_position;
    Vector3 velocity;
    float speed;
    float turn_rate;
    Quaternion rotation;
    
    // Serpentine body (20 segments)
    dragon_segment_t segments[20];
    float segment_spacing;
    float body_wave_offset;
    
    // Attack patterns
    float laser_charge;
    float laser_angle;
    int missiles_remaining;
    float summon_cooldown;
    
    // Visual state
    Color base_color;
    Color rage_color;
    float glow_intensity;
    float damage_flash;
    bool cloaked;
    
    // Weak points
    Vector3 weak_points[3];
    bool weak_points_exposed;
    float weak_point_timer;
    
    // Phase transitions
    bool phase_transitioning;
    float transition_timer;
    
    // Special effects
    float roar_timer;
    float screen_shake_intensity;
    
    // AI state
    float think_timer;
    float aggression;
    Vector3 last_player_pos;
    int consecutive_hits;
} cyber_dragon_t;

// Dragon projectile types
typedef struct {
    Vector3 position;
    Vector3 velocity;
    float damage;
    float radius;
    Color color;
    bool homing;
    float life;
    int type;  // 0=laser, 1=missile, 2=plasma
} dragon_projectile_t;

// Boss management
cyber_dragon_t* cyber_dragon_create(Vector3 spawn_pos);
void cyber_dragon_destroy(cyber_dragon_t* dragon);

// Core updates
void cyber_dragon_update(cyber_dragon_t* dragon, Vector3 player_pos, float dt);
void cyber_dragon_take_damage(cyber_dragon_t* dragon, float damage, Vector3 hit_pos);
void cyber_dragon_draw(cyber_dragon_t* dragon, Camera3D camera);

// Attack system
void cyber_dragon_start_attack(cyber_dragon_t* dragon, dragon_attack_t attack);
void cyber_dragon_update_attack(cyber_dragon_t* dragon, Vector3 player_pos, float dt);
bool cyber_dragon_is_attacking(cyber_dragon_t* dragon);

// Phase management
void cyber_dragon_enter_phase(cyber_dragon_t* dragon, dragon_phase_t phase);
void cyber_dragon_update_phase(cyber_dragon_t* dragon);

// Collision detection
bool cyber_dragon_check_collision(cyber_dragon_t* dragon, Vector3 point, float radius);
bool cyber_dragon_check_weak_point_hit(cyber_dragon_t* dragon, Vector3 point, float radius);

// Visual effects
void cyber_dragon_draw_effects(cyber_dragon_t* dragon, Camera3D camera);
void cyber_dragon_draw_health_bar(cyber_dragon_t* dragon);
void cyber_dragon_spawn_death_explosion(cyber_dragon_t* dragon);

// Audio cues
const char* cyber_dragon_get_roar_sound(cyber_dragon_t* dragon);
const char* cyber_dragon_get_attack_sound(dragon_attack_t attack);

#endif // SKY_COMBAT_BOSS_CYBER_DRAGON_H
/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_WEAPONS_H
#define SKY_COMBAT_WEAPONS_H

#include <raylib.h>
#include <stdbool.h>
#include "../models/course.h"

// Weapon constants
#define MAX_BULLETS 10000    // Effectively infinite for continuous stream
#define MAX_MISSILES 20
#define MAX_LASERS 50
#define MAX_PLASMA 30
#define BULLET_SPEED 450.0f          // 50% faster bullets
#define MISSILE_SPEED 375.0f          // 50% faster missiles
#define ROCKET_MISSILE_SPEED 1200.0f  // 50% faster rockets
#define LASER_SPEED 1000.0f          // Instant hit feel
#define PLASMA_SPEED 150.0f          // Slower but powerful
#define FIRE_RATE 0.01f              // Ultra rapid continuous stream (3x faster)
#define MISSILE_RATE 0.3f            // Faster missile rate
#define LASER_RATE 0.05f             // Very fast laser
#define PLASMA_RATE 0.4f             // Slower plasma

// Weapon types
typedef enum {
    WEAPON_MACHINE_GUN,
    WEAPON_MISSILES,
    WEAPON_LASER,
    WEAPON_PLASMA,
    WEAPON_RAILGUN,
    WEAPON_SPREAD,
    WEAPON_COUNT
} weapon_type_t;

// Weapon damage
#define BULLET_DAMAGE 10
#define MISSILE_DAMAGE 50
#define LASER_DAMAGE 15
#define PLASMA_DAMAGE 100
#define RAILGUN_DAMAGE 200

typedef struct bullet_s {
    Vector3 position;
    Vector3 velocity;
    Vector3 bend_force;  // Bending force applied by right stick
    float life;
    bool active;
    int damage;
    Color color;
    float size;
    struct bullet_s* next;
} bullet_t;

typedef struct {
    Vector3 position;
    Vector3 velocity;
    float life;
    bool active;
    ring_t* target;  // Can home on rings
    bool is_rocket;  // True for right-side "rocket" missiles
    int damage;
} missile_t;

typedef struct {
    Vector3 position;
    Vector3 velocity;
    Vector3 end_position;  // For beam weapons
    float life;
    bool active;
    int damage;
    float charge;  // For charge-up weapons
} laser_t;

typedef struct {
    Vector3 position;
    Vector3 velocity;
    float life;
    bool active;
    int damage;
    float size;
} plasma_t;

typedef enum {
    WEAPON_UPGRADE_NONE = 0,
    WEAPON_UPGRADE_RAPID_FIRE,    // Faster fire rate
    WEAPON_UPGRADE_SPREAD_SHOT,   // 3 bullets at once
    WEAPON_UPGRADE_EXPLOSIVE,     // Area damage
    WEAPON_UPGRADE_PIERCING,      // Goes through enemies
    WEAPON_UPGRADE_HOMING,        // Slight homing capability
    WEAPON_UPGRADE_COUNT
} weapon_upgrade_t;

typedef struct {
    bullet_t* bullets_head;  // Linked list for infinite bullets
    int bullet_count;        // Track active bullets
    missile_t missiles[MAX_MISSILES];
    laser_t lasers[MAX_LASERS];
    plasma_t plasma[MAX_PLASMA];
    
    // Weapon state
    weapon_type_t current_weapon;
    float fire_cooldown[WEAPON_COUNT];
    float weapon_heat[WEAPON_COUNT];
    int ammo[WEAPON_COUNT];
    
    // Upgrade system
    weapon_upgrade_t current_upgrade;
    float upgrade_timer;
    float damage_multiplier;
    float fire_rate_multiplier;
    
    // Effects
    float recoil_amount;
    float muzzle_flash_timer;
    Vector3 last_fire_position;
    Vector3 last_fire_direction;
    
    // Gun fine-tuning (controlled by right stick)
    float bullet_bend_x;         // -1.0 to 1.0, bends bullet stream left/right
    float bullet_bend_y;         // -1.0 to 1.0, bends bullet stream up/down
    float bend_strength;         // How much the bullets curve
} weapons_system_t;

// Weapon system management
weapons_system_t* weapons_create(void);
void weapons_destroy(weapons_system_t* weapons);
void weapons_update(weapons_system_t* weapons, float dt);
void weapons_draw(weapons_system_t* weapons);

// Firing operations
void weapons_fire_bullet(weapons_system_t* weapons, Vector3 position, Vector3 direction, float yaw);
void weapons_fire_missile(weapons_system_t* weapons, Vector3 position, Vector3 direction, float yaw, int side, ring_t* target);
void weapons_fire_laser(weapons_system_t* weapons, Vector3 position, Vector3 direction, float yaw);
void weapons_fire_plasma(weapons_system_t* weapons, Vector3 position, Vector3 direction, float yaw);
void weapons_fire_railgun(weapons_system_t* weapons, Vector3 position, Vector3 direction, float yaw);
void weapons_fire_spread(weapons_system_t* weapons, Vector3 position, Vector3 direction, float yaw);

// Weapon management
void weapons_switch_weapon(weapons_system_t* weapons, weapon_type_t type);
void weapons_cycle_weapon(weapons_system_t* weapons, int direction);
bool weapons_can_fire(weapons_system_t* weapons, weapon_type_t type);
float weapons_get_heat(weapons_system_t* weapons, weapon_type_t type);
float weapons_get_heat_percent(weapons_system_t* weapons);
int weapons_get_ammo(weapons_system_t* weapons, weapon_type_t type);

// Gun fine-tuning (does NOT change bullet trajectory)
void weapons_set_fine_tuning(weapons_system_t* weapons, float x_adjust, float y_adjust);

// Queries
int weapons_get_active_bullets(weapons_system_t* weapons);
int weapons_get_active_missiles(weapons_system_t* weapons);
int weapons_get_active_lasers(weapons_system_t* weapons);
int weapons_get_active_plasma(weapons_system_t* weapons);

// Effects
float weapons_get_recoil(weapons_system_t* weapons);
bool weapons_has_muzzle_flash(weapons_system_t* weapons);
Vector3 weapons_get_muzzle_position(weapons_system_t* weapons);

// Upgrade system
void weapons_apply_upgrade(weapons_system_t* weapons, weapon_upgrade_t upgrade, float duration);
void weapons_clear_upgrade(weapons_system_t* weapons);
const char* weapons_get_upgrade_name(weapon_upgrade_t upgrade);
Color weapons_get_upgrade_color(weapon_upgrade_t upgrade);

#endif // SKY_COMBAT_WEAPONS_H
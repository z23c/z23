/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/models/powerups.h"
#include <raymath.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

powerup_manager_t* powerup_manager_create(void) {
    powerup_manager_t* manager = calloc(1, sizeof(powerup_manager_t));
    if (!manager) return NULL;
    
    manager->spawn_check_interval = 5.0f;  // Check for spawning every 5 seconds
    manager->spawn_check_timer = 0.0f;
    
    return manager;
}

void powerup_manager_destroy(powerup_manager_t* manager) {
    free(manager);
}

void powerup_manager_add_spawn_point(powerup_manager_t* manager, Vector3 position, powerup_type_t type, float respawn_time) {
    if (!manager || manager->spawn_point_count >= 16) return;
    
    powerup_spawn_point_t* sp = &manager->spawn_points[manager->spawn_point_count];
    sp->position = position;
    sp->preferred_type = type;
    sp->respawn_time = respawn_time;
    
    manager->spawn_point_count++;
}

void powerup_manager_create_default_spawn_points(powerup_manager_t* manager) {
    if (!manager) return;
    
    // Create spawn points in strategic locations
    float radius = 400.0f;
    float height = 150.0f;
    
    // Center point - random power-up
    powerup_manager_add_spawn_point(manager, (Vector3){0, height, 0}, -1, 20.0f);
    
    // Cardinal directions - specific power-ups
    powerup_manager_add_spawn_point(manager, (Vector3){radius, height, 0}, POWERUP_HEALTH, 15.0f);
    powerup_manager_add_spawn_point(manager, (Vector3){-radius, height, 0}, POWERUP_SHIELD, 30.0f);
    powerup_manager_add_spawn_point(manager, (Vector3){0, height, radius}, POWERUP_RAPID_FIRE, 20.0f);
    powerup_manager_add_spawn_point(manager, (Vector3){0, height, -radius}, POWERUP_MISSILE, 25.0f);
    
    // Diagonal positions - mixed
    float diag = radius * 0.707f;
    powerup_manager_add_spawn_point(manager, (Vector3){diag, height + 50, diag}, POWERUP_SPEED_BOOST, 15.0f);
    powerup_manager_add_spawn_point(manager, (Vector3){-diag, height + 50, diag}, POWERUP_DOUBLE_DAMAGE, 30.0f);
    powerup_manager_add_spawn_point(manager, (Vector3){diag, height - 50, -diag}, POWERUP_LASER, 40.0f);
    powerup_manager_add_spawn_point(manager, (Vector3){-diag, height - 50, -diag}, POWERUP_REPAIR_KIT, 60.0f);
}

void powerup_manager_update(powerup_manager_t* manager, float dt) {
    if (!manager) return;
    
    // Update active powerups
    for (int i = 0; i < manager->powerup_count; i++) {
        powerup_t* p = &manager->powerups[i];
        if (!p->active) continue;
        
        // Animate powerup
        p->rotation += 90.0f * dt;
        p->bob_offset = sinf(p->rotation * DEG2RAD * 2.0f) * 5.0f;
    }
    
    // Check for spawning new powerups
    manager->spawn_check_timer += dt;
    if (manager->spawn_check_timer >= manager->spawn_check_interval) {
        manager->spawn_check_timer = 0.0f;
        
        // Check each spawn point
        for (int i = 0; i < manager->spawn_point_count; i++) {
            powerup_spawn_point_t* sp = &manager->spawn_points[i];
            
            // Check if this spawn point is occupied
            bool occupied = false;
            for (int j = 0; j < manager->powerup_count; j++) {
                if (manager->powerups[j].active && manager->powerups[j].spawn_point_id == i) {
                    occupied = true;
                    break;
                }
            }
            
            // Spawn if not occupied and random chance
            if (!occupied && GetRandomValue(0, 100) < 30) {  // 30% chance
                powerup_manager_spawn_at_point(manager, i);
            }
        }
    }
    
    // Update respawn timers for inactive powerups
    for (int i = 0; i < manager->powerup_count; i++) {
        powerup_t* p = &manager->powerups[i];
        if (!p->active && p->respawn_timer > 0) {
            p->respawn_timer -= dt;
            if (p->respawn_timer <= 0) {
                // Respawn at original spawn point
                if (p->spawn_point_id >= 0 && p->spawn_point_id < manager->spawn_point_count) {
                    powerup_spawn_point_t* sp = &manager->spawn_points[p->spawn_point_id];
                    p->position = sp->position;
                    p->active = true;
                    p->rotation = 0;
                    p->bob_offset = 0;
                }
            }
        }
    }
}

void powerup_manager_spawn_at_point(powerup_manager_t* manager, int spawn_point_id) {
    if (!manager || spawn_point_id < 0 || spawn_point_id >= manager->spawn_point_count) return;
    if (manager->powerup_count >= 32) return;
    
    powerup_spawn_point_t* sp = &manager->spawn_points[spawn_point_id];
    
    // Find inactive powerup slot or create new
    int slot = -1;
    for (int i = 0; i < manager->powerup_count; i++) {
        if (!manager->powerups[i].active) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        slot = manager->powerup_count++;
    }
    
    powerup_t* p = &manager->powerups[slot];
    
    // Determine type
    if (sp->preferred_type >= 0 && sp->preferred_type < POWERUP_TYPE_COUNT) {
        p->type = sp->preferred_type;
    } else {
        p->type = GetRandomValue(0, POWERUP_TYPE_COUNT - 1);
    }
    
    // Set properties
    p->position = sp->position;
    p->active = true;
    p->spawn_point_id = spawn_point_id;
    p->respawn_timer = 0;
    p->rotation = 0;
    p->bob_offset = 0;
    
    // Set type-specific properties
    p->color = powerup_get_color(p->type);
    p->size = 10.0f;
    p->duration = powerup_get_default_duration(p->type);
    p->value = powerup_get_default_value(p->type);
    
    printf("Spawned %s powerup at spawn point %d\n", powerup_get_name(p->type), spawn_point_id);
}

void powerup_manager_spawn_random(powerup_manager_t* manager) {
    if (!manager || manager->spawn_point_count == 0) return;
    
    int spawn_point = GetRandomValue(0, manager->spawn_point_count - 1);
    powerup_manager_spawn_at_point(manager, spawn_point);
}

bool powerup_manager_check_collection(powerup_manager_t* manager, Vector3 position, float radius, powerup_type_t* collected_type) {
    if (!manager) return false;
    
    float collection_radius = radius + 15.0f;  // Powerup collection radius
    
    for (int i = 0; i < manager->powerup_count; i++) {
        powerup_t* p = &manager->powerups[i];
        if (!p->active) continue;
        
        float dist = Vector3Distance(position, p->position);
        if (dist < collection_radius) {
            if (collected_type) *collected_type = p->type;
            powerup_manager_collect(manager, i);
            return true;
        }
    }
    
    return false;
}

void powerup_manager_collect(powerup_manager_t* manager, int powerup_id) {
    if (!manager || powerup_id < 0 || powerup_id >= manager->powerup_count) return;
    
    powerup_t* p = &manager->powerups[powerup_id];
    if (!p->active) return;
    
    p->active = false;
    
    // Set respawn timer based on spawn point
    if (p->spawn_point_id >= 0 && p->spawn_point_id < manager->spawn_point_count) {
        p->respawn_timer = manager->spawn_points[p->spawn_point_id].respawn_time;
    } else {
        p->respawn_timer = 20.0f;  // Default respawn time
    }
    
    printf("Collected %s powerup (respawn in %.1fs)\n", powerup_get_name(p->type), p->respawn_timer);
}

void powerup_effects_init(powerup_effects_t* effects) {
    if (!effects) return;
    
    memset(effects, 0, sizeof(powerup_effects_t));
    effects->fire_rate_multiplier = 1.0f;
    effects->speed_multiplier = 1.0f;
}

void powerup_effects_update(powerup_effects_t* effects, float dt) {
    if (!effects) return;
    
    // Update timers
    if (effects->shield_active) {
        effects->shield_timer -= dt;
        if (effects->shield_timer <= 0) {
            effects->shield_active = false;
        }
    }
    
    if (effects->rapid_fire_active) {
        effects->rapid_fire_timer -= dt;
        if (effects->rapid_fire_timer <= 0) {
            effects->rapid_fire_active = false;
            effects->fire_rate_multiplier = 1.0f;
        }
    }
    
    if (effects->speed_boost_active) {
        effects->speed_boost_timer -= dt;
        if (effects->speed_boost_timer <= 0) {
            effects->speed_boost_active = false;
            effects->speed_multiplier = 1.0f;
        }
    }
    
    if (effects->double_damage_active) {
        effects->double_damage_timer -= dt;
        if (effects->double_damage_timer <= 0) {
            effects->double_damage_active = false;
        }
    }
    
    // Drain laser ammo
    if (effects->laser_equipped && effects->laser_ammo > 0) {
        effects->laser_ammo -= dt * 10.0f;  // 10 ammo per second
        if (effects->laser_ammo <= 0) {
            effects->laser_equipped = false;
            effects->laser_ammo = 0;
        }
    }
}

void powerup_effects_apply(powerup_effects_t* effects, powerup_type_t type, float duration, float value) {
    if (!effects) return;
    
    switch (type) {
        case POWERUP_SHIELD:
            effects->shield_active = true;
            effects->shield_timer = duration;
            break;
            
        case POWERUP_RAPID_FIRE:
            effects->rapid_fire_active = true;
            effects->rapid_fire_timer = duration;
            effects->fire_rate_multiplier = value;
            break;
            
        case POWERUP_SPEED_BOOST:
            effects->speed_boost_active = true;
            effects->speed_boost_timer = duration;
            effects->speed_multiplier = value;
            break;
            
        case POWERUP_DOUBLE_DAMAGE:
            effects->double_damage_active = true;
            effects->double_damage_timer = duration;
            break;
            
        case POWERUP_MISSILE:
            effects->missile_count += (int)value;
            break;
            
        case POWERUP_LASER:
            effects->laser_equipped = true;
            effects->laser_ammo = value;
            break;
            
        default:
            break;
    }
}

const char* powerup_get_name(powerup_type_t type) {
    switch (type) {
        case POWERUP_HEALTH: return "Health";
        case POWERUP_SHIELD: return "Shield";
        case POWERUP_RAPID_FIRE: return "Rapid Fire";
        case POWERUP_MISSILE: return "Missiles";
        case POWERUP_LASER: return "Laser";
        case POWERUP_SPEED_BOOST: return "Speed Boost";
        case POWERUP_DOUBLE_DAMAGE: return "Double Damage";
        case POWERUP_REPAIR_KIT: return "Repair Kit";
        default: return "Unknown";
    }
}

Color powerup_get_color(powerup_type_t type) {
    switch (type) {
        case POWERUP_HEALTH: return GREEN;
        case POWERUP_SHIELD: return SKYBLUE;
        case POWERUP_RAPID_FIRE: return ORANGE;
        case POWERUP_MISSILE: return RED;
        case POWERUP_LASER: return PURPLE;
        case POWERUP_SPEED_BOOST: return YELLOW;
        case POWERUP_DOUBLE_DAMAGE: return MAROON;
        case POWERUP_REPAIR_KIT: return LIME;
        default: return WHITE;
    }
}

float powerup_get_default_duration(powerup_type_t type) {
    switch (type) {
        case POWERUP_SHIELD: return 10.0f;
        case POWERUP_RAPID_FIRE: return 15.0f;
        case POWERUP_SPEED_BOOST: return 12.0f;
        case POWERUP_DOUBLE_DAMAGE: return 20.0f;
        case POWERUP_LASER: return 100.0f;  // Ammo count, not duration
        default: return 0.0f;  // Instant effects
    }
}

float powerup_get_default_value(powerup_type_t type) {
    switch (type) {
        case POWERUP_HEALTH: return 25.0f;  // Restore 25 health
        case POWERUP_RAPID_FIRE: return 3.0f;  // 3x fire rate
        case POWERUP_MISSILE: return 5.0f;  // 5 missiles
        case POWERUP_LASER: return 100.0f;  // 100 laser ammo
        case POWERUP_SPEED_BOOST: return 1.5f;  // 1.5x speed
        case POWERUP_REPAIR_KIT: return 100.0f;  // Full health
        default: return 1.0f;
    }
}
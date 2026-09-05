/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file aircraft_manager.c
 * @brief Implementation of aircraft management system
 */

#include "sky_combat/models/aircraft_manager.h"
#include <raymath.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <assert.h>

/* Constants */
#define DEFAULT_SPAWN_RADIUS 300.0f
#define DEFAULT_SPAWN_HEIGHT 150.0f
#define SPAWN_HEIGHT_VARIANCE 50.0f
#define DEFAULT_COLLISION_RADIUS 10.0f
#define DEFAULT_PROJECTILE_RADIUS 15.0f
#define DEFAULT_MAX_HEALTH 100.0f
#define MIN_AI_SKILL 0.0f
#define MAX_AI_SKILL 1.0f
#define MIN_AI_AGGRESSION 0.3f
#define MAX_AI_AGGRESSION 1.0f

/* Forward declarations of internal functions */
static bool validate_manager(const aircraft_manager_t* manager);
static bool validate_aircraft_id(const aircraft_manager_t* manager, int id);
static void initialize_spawn_points(aircraft_manager_t* manager);
static void reset_aircraft_state(managed_aircraft_t* ma);

/*
 * Core Management Functions
 */

aircraft_manager_t* aircraft_manager_create(void) {
    aircraft_manager_t* manager = calloc(1, sizeof(aircraft_manager_t));
    if (!manager) {
        fprintf(stderr, "ERROR: Failed to allocate aircraft manager\n");
        return NULL;
    }
    
    /* Initialize collision parameters */
    manager->collision_radius = DEFAULT_COLLISION_RADIUS;
    manager->projectile_radius = DEFAULT_PROJECTILE_RADIUS;
    
    /* Initialize spawn points */
    initialize_spawn_points(manager);
    
    /* Verify initialization */
    assert(manager->aircraft_count == 0);
    assert(manager->spawn_count > 0);
    
    return manager;
}

void aircraft_manager_destroy(aircraft_manager_t* manager) {
    if (!manager) return;
    
    /* Clean up all aircraft */
    for (int i = 0; i < manager->aircraft_count; i++) {
        managed_aircraft_t* ma = &manager->aircraft[i];
        
        if (ma->aircraft) {
            aircraft_destroy(ma->aircraft);
            ma->aircraft = NULL;
        }
        
        if (ma->weapons) {
            weapons_destroy(ma->weapons);
            ma->weapons = NULL;
        }
    }
    
    /* Zero out sensitive data before freeing */
    memset(manager, 0, sizeof(aircraft_manager_t));
    free(manager);
}

/*
 * Aircraft Management Functions
 */

int aircraft_manager_add(aircraft_manager_t* manager, const char* name, 
                        Color color, bool is_ai, bool is_local) {
    return aircraft_manager_add_with_team(manager, name, color, is_ai, is_local, -1);
}

int aircraft_manager_add_with_team(aircraft_manager_t* manager, const char* name,
                                  Color color, bool is_ai, bool is_local, int team_id) {
    /* Validate inputs */
    if (!validate_manager(manager)) {
        fprintf(stderr, "ERROR: Invalid aircraft manager\n");
        return -1;
    }
    
    if (!name || strlen(name) == 0) {
        fprintf(stderr, "ERROR: Aircraft name cannot be empty\n");
        return -1;
    }
    
    if (manager->aircraft_count >= MAX_MANAGED_AIRCRAFT) {
        fprintf(stderr, "ERROR: Maximum aircraft limit reached (%d)\n", MAX_MANAGED_AIRCRAFT);
        return -1;
    }
    
    if (team_id < -1 || team_id > 3) {
        fprintf(stderr, "ERROR: Invalid team ID %d (must be -1 to 3)\n", team_id);
        return -1;
    }
    
    /* Cannot be both AI and local player */
    if (is_ai && is_local) {
        fprintf(stderr, "ERROR: Aircraft cannot be both AI and local player\n");
        return -1;
    }
    
    /* Get next available slot */
    int id = manager->aircraft_count;
    managed_aircraft_t* ma = &manager->aircraft[id];
    
    /* Reset state */
    reset_aircraft_state(ma);
    
    /* Create aircraft at spawn point */
    Vector3 spawn = aircraft_manager_get_spawn_point(manager);
    ma->aircraft = aircraft_create(spawn);
    if (!ma->aircraft) {
        fprintf(stderr, "ERROR: Failed to create aircraft\n");
        return -1;
    }
    
    /* Create weapons system */
    ma->weapons = weapons_create();
    if (!ma->weapons) {
        fprintf(stderr, "ERROR: Failed to create weapons system\n");
        aircraft_destroy(ma->aircraft);
        ma->aircraft = NULL;
        return -1;
    }
    
    /* Set identity */
    ma->id = id;
    strncpy(ma->name, name, AIRCRAFT_NAME_LENGTH - 1);
    ma->name[AIRCRAFT_NAME_LENGTH - 1] = '\0';
    ma->color = color;
    ma->is_ai = is_ai;
    ma->is_local_player = is_local;
    
    /* Initialize game state */
    ma->health = DEFAULT_MAX_HEALTH;
    ma->max_health = DEFAULT_MAX_HEALTH;
    ma->kills = 0;
    ma->deaths = 0;
    ma->assists = 0;
    
    /* Set team */
    ma->team_id = team_id;
    
    /* Initialize AI */
    ma->target_id = -1;
    if (is_ai) {
        /* Random skill level between 0.5 and 1.0 */
        ma->ai_skill = 0.5f + (float)GetRandomValue(0, 50) / 100.0f;
        ma->ai_skill = Clamp(ma->ai_skill, MIN_AI_SKILL, MAX_AI_SKILL);
        
        /* Random aggression between 0.3 and 1.0 */
        ma->ai_aggression = MIN_AI_AGGRESSION + (float)GetRandomValue(0, 70) / 100.0f;
        ma->ai_aggression = Clamp(ma->ai_aggression, MIN_AI_AGGRESSION, MAX_AI_AGGRESSION);
    } else {
        ma->ai_skill = 0.0f;
        ma->ai_aggression = 0.0f;
    }
    
    /* Initialize power-up effects */
    powerup_effects_init(&ma->powerup_effects);
    
    /* Increment count */
    manager->aircraft_count++;
    
    printf("Added aircraft: %s (ID: %d, Team: %d, AI: %s, Skill: %.2f)\n", 
           name, id, team_id, is_ai ? "yes" : "no", ma->ai_skill);
    
    return id;
}

void aircraft_manager_remove(aircraft_manager_t* manager, int id) {
    if (!validate_manager(manager) || !validate_aircraft_id(manager, id)) {
        return;
    }
    
    managed_aircraft_t* ma = &manager->aircraft[id];
    
    /* Clean up resources */
    if (ma->aircraft) {
        aircraft_destroy(ma->aircraft);
        ma->aircraft = NULL;
    }
    
    if (ma->weapons) {
        weapons_destroy(ma->weapons);
        ma->weapons = NULL;
    }
    
    /* Shift remaining aircraft down */
    for (int i = id; i < manager->aircraft_count - 1; i++) {
        manager->aircraft[i] = manager->aircraft[i + 1];
        manager->aircraft[i].id = i;  /* Update ID */
    }
    
    /* Clear last slot */
    reset_aircraft_state(&manager->aircraft[manager->aircraft_count - 1]);
    
    manager->aircraft_count--;
    
    printf("Removed aircraft ID %d (remaining: %d)\n", id, manager->aircraft_count);
}

managed_aircraft_t* aircraft_manager_get(aircraft_manager_t* manager, int id) {
    if (!validate_manager(manager) || !validate_aircraft_id(manager, id)) {
        return NULL;
    }
    return &manager->aircraft[id];
}

/*
 * Update Functions
 */

void aircraft_manager_update(aircraft_manager_t* manager, float dt) {
    if (!validate_manager(manager)) return;
    
    /* Clamp delta time to prevent instability */
    dt = Clamp(dt, 0.0f, 0.1f);
    
    /* Update all aircraft */
    for (int i = 0; i < manager->aircraft_count; i++) {
        managed_aircraft_t* ma = &manager->aircraft[i];
        
        /* Handle respawn timer */
        if (ma->respawn_timer > 0) {
            ma->respawn_timer -= dt;
            if (ma->respawn_timer <= 0) {
                /* Respawn now */
                ma->respawn_timer = 0;
                aircraft_manager_respawn(manager, i);
            }
            continue; /* Skip updates while dead */
        }
        
        /* Skip dead aircraft */
        if (ma->health <= 0) {
            continue;
        }
        
        /* Update AI behavior */
        if (ma->is_ai) {
            aircraft_manager_update_ai(manager, ma, dt);
        }
        
        /* Update weapons */
        if (ma->weapons) {
            weapons_update(ma->weapons, dt);
        }
        
        /* Update power-up effects */
        powerup_effects_update(&ma->powerup_effects, dt);
    }
    
    /* Check collisions after all updates */
    aircraft_manager_check_collisions(manager);
}

void aircraft_manager_update_ai(aircraft_manager_t* manager, managed_aircraft_t* ai, float dt) {
    if (!validate_manager(manager) || !ai || !ai->aircraft || !ai->is_ai) {
        return;
    }
    
    /* PAC-MAN GHOST AI - Simple and predictable */
    
    /* Each AI has a different behavior pattern based on ID */
    int ghost_type = ai->id % 4;
    
    switch (ghost_type) {
        case 0: /* Blinky - Direct chase (but slow) */
            if (ai->target_id < 0 || ai->target_id >= manager->aircraft_count || 
                manager->aircraft[ai->target_id].health <= 0) {
                ai->target_id = 0; /* Always chase player */
            }
            break;
            
        case 1: /* Pinky - Try to get ahead */
            /* Same target but different behavior */
            if (ai->target_id < 0) ai->target_id = 0;
            break;
            
        case 2: /* Inky - Erratic movement */
            /* Random wandering */
            break;
            
        case 3: /* Clyde - Lazy, maintains distance */
            if (ai->target_id < 0) ai->target_id = 0;
            break;
    }
    
    /* Simple patrol if no target */
    if (ai->target_id < 0 || ghost_type == 2) {
        /* Lazy circular patrol */
        float time = GetTime() + ai->id * 1.5f; /* Offset for each ghost */
        float patrol_x = sinf(time * 0.3f) * 0.5f;
        float patrol_y = cosf(time * 0.2f) * 0.2f;
        
        /* Slow, smooth movement */
        aircraft_update(ai->aircraft, patrol_x, patrol_y, dt);
        
        /* Keep speed low */
        ai->aircraft->speed = AIRCRAFT_MIN_SPEED * 1.2f;
        return;
    }
    
    /* Get target */
    managed_aircraft_t* target = &manager->aircraft[ai->target_id];
    if (!target->aircraft || target->health <= 0) {
        ai->target_id = -1;
        return;
    }
    
    /* Calculate direction to target */
    Vector3 to_target = Vector3Subtract(target->aircraft->position, ai->aircraft->position);
    float distance = Vector3Length(to_target);
    
    /* Ghost-specific behavior */
    if (ghost_type == 1) { /* Pinky - aim ahead */
        Vector3 ahead = Vector3Scale(aircraft_get_forward_vector(target->aircraft), 100.0f);
        to_target = Vector3Subtract(
            Vector3Add(target->aircraft->position, ahead),
            ai->aircraft->position
        );
    } else if (ghost_type == 3 && distance < 150.0f) { /* Clyde - run away when close */
        to_target = Vector3Scale(to_target, -1.0f); /* Reverse direction */
    }
    
    /* Calculate desired angles - but make turns SLOW */
    /* Avoid division by zero in Vector3Normalize */
    float target_length = Vector3Length(to_target);
    if (target_length < 0.001f) {
        /* If too close or at same position, just maintain current direction */
        to_target = (Vector3){0.0f, 0.0f, 1.0f};
    } else {
        to_target = Vector3Normalize(to_target);
    }
    float target_yaw = atan2f(to_target.x, to_target.z) * RAD2DEG;
    /* Clamp to_target.y to avoid domain error in asinf */
    float clamped_y = fmaxf(-1.0f, fminf(1.0f, to_target.y));
    float target_pitch = -asinf(clamped_y) * RAD2DEG;
    
    /* Calculate turn difference */
    float yaw_diff = target_yaw - ai->aircraft->yaw;
    while (yaw_diff > 180) yaw_diff -= 360;
    while (yaw_diff < -180) yaw_diff += 360;
    
    float pitch_diff = target_pitch - ai->aircraft->pitch;
    
    /* VERY SLOW turning - like ghosts changing direction */
    float turn_rate = 0.3f; /* Much slower than before */
    float input_x = Clamp(yaw_diff / 45.0f * turn_rate, -0.5f, 0.5f);
    float input_y = Clamp(pitch_diff / 30.0f * turn_rate, -0.3f, 0.3f);
    
    /* Add some wobble for ghost-like movement */
    float wobble = sinf(GetTime() * 2.0f + ai->id) * 0.1f;
    input_x += wobble;
    
    /* Update aircraft with slow inputs */
    aircraft_update(ai->aircraft, input_x, input_y, dt);
    
    /* Keep speed LOW - ghosts don't boost */
    ai->aircraft->speed = Clamp(ai->aircraft->speed, 
                                AIRCRAFT_MIN_SPEED, 
                                AIRCRAFT_BASE_SPEED * 0.8f); /* 80% of base speed max */
    
    /* No firing - ghosts just chase */
    /* No boosting - ghosts maintain steady speed */
}

/*
 * Combat Functions
 */

void aircraft_manager_fire_weapon(aircraft_manager_t* manager, int aircraft_id) {
    aircraft_manager_fire_weapon_aimed(manager, aircraft_id, 0.0f, 0.0f);
}

void aircraft_manager_fire_weapon_aimed(aircraft_manager_t* manager, int aircraft_id,
                                       float aim_x, float aim_y) {
    managed_aircraft_t* ma = aircraft_manager_get(manager, aircraft_id);
    if (!ma || !ma->aircraft || !ma->weapons) {
        return;
    }
    
    /* Apply power-up effects to fire rate */
    float fire_rate_mod = 1.0f;
    if (ma->powerup_effects.rapid_fire_active) {
        fire_rate_mod = ma->powerup_effects.fire_rate_multiplier;
    }
    
    /* Get firing position and direction */
    Vector3 pos = ma->aircraft->position;
    Vector3 dir = aircraft_get_forward_vector(ma->aircraft);
    
    /* Apply aiming adjustments */
    if (aim_x != 0.0f || aim_y != 0.0f) {
        /* Maximum aim adjustment in degrees */
        const float MAX_AIM_ANGLE = 15.0f;
        
        /* Calculate adjusted direction */
        float yaw_adjust = aim_x * MAX_AIM_ANGLE;
        float pitch_adjust = aim_y * MAX_AIM_ANGLE;
        
        /* Apply yaw adjustment */
        float adjusted_yaw = (ma->aircraft->yaw + yaw_adjust) * DEG2RAD;
        float adjusted_pitch = (ma->aircraft->pitch + pitch_adjust) * DEG2RAD;
        
        dir = (Vector3){
            sinf(adjusted_yaw) * cosf(adjusted_pitch),
            -sinf(adjusted_pitch),
            cosf(adjusted_yaw) * cosf(adjusted_pitch)
        };
        
        /* Fire with adjusted direction */
        weapons_fire_bullet(ma->weapons, pos, dir, ma->aircraft->yaw + yaw_adjust);
    } else {
        /* Fire normally */
        weapons_fire_bullet(ma->weapons, pos, dir, ma->aircraft->yaw);
    }
}

void aircraft_manager_check_collisions(aircraft_manager_t* manager) {
    if (!validate_manager(manager)) return;
    
    /* Check bullet-aircraft collisions */
    for (int i = 0; i < manager->aircraft_count; i++) {
        managed_aircraft_t* shooter = &manager->aircraft[i];
        if (!shooter->weapons) continue;
        
        /* Check each bullet in linked list */
        bullet_t* bullet = shooter->weapons->bullets_head;
        bullet_t* prev = NULL;
        
        while (bullet) {
            Vector3 bullet_pos = bullet->position;
            bool hit = false;
            
            /* Check against all other aircraft */
            for (int j = 0; j < manager->aircraft_count; j++) {
                if (i == j) continue;  /* Don't hit yourself */
                
                managed_aircraft_t* target = &manager->aircraft[j];
                if (!target->aircraft || target->health <= 0) continue;
                
                /* Skip friendly fire unless enabled */
                if (shooter->team_id >= 0 && shooter->team_id == target->team_id) {
                    continue;
                }
                
                /* Check distance */
                if (!target->aircraft) continue;
                float dist = Vector3Distance(bullet_pos, target->aircraft->position);
                if (dist < manager->projectile_radius) {
                    /* Hit! */
                    float damage = bullet->damage;
                    
                    /* Apply damage multipliers */
                    if (shooter->powerup_effects.double_damage_active) {
                        damage *= 2.0f;
                    }
                    
                    aircraft_manager_damage_aircraft(manager, j, damage, i);
                    hit = true;
                    break;
                }
            }
            
            if (hit) {
                /* Remove this bullet from the list */
                bullet_t* to_remove = bullet;
                if (prev) {
                    prev->next = bullet->next;
                } else {
                    shooter->weapons->bullets_head = bullet->next;
                }
                bullet = bullet->next;
                free(to_remove);
                shooter->weapons->bullet_count--;
            } else {
                prev = bullet;
                bullet = bullet->next;
            }
        }
    }
    
    /* Check aircraft-aircraft collisions */
    for (int i = 0; i < manager->aircraft_count; i++) {
        for (int j = i + 1; j < manager->aircraft_count; j++) {
            managed_aircraft_t* a1 = &manager->aircraft[i];
            managed_aircraft_t* a2 = &manager->aircraft[j];
            
            if (!a1->aircraft || !a2->aircraft) continue;
            if (a1->health <= 0 || a2->health <= 0) continue;
            
            float dist = Vector3Distance(a1->aircraft->position, a2->aircraft->position);
            if (dist < manager->collision_radius * 2) {
                /* Collision damage */
                aircraft_manager_damage_aircraft(manager, i, 50.0f, j);
                aircraft_manager_damage_aircraft(manager, j, 50.0f, i);
                
                /* Push aircraft apart */
                Vector3 diff = Vector3Subtract(a1->aircraft->position, a2->aircraft->position);
                float diff_length = Vector3Length(diff);
                Vector3 push;
                if (diff_length < 0.001f) {
                    /* If at exact same position, push in random direction */
                    push = (Vector3){1.0f, 0.0f, 0.0f};
                } else {
                    push = Vector3Normalize(diff);
                }
                a1->aircraft->position = Vector3Add(
                    a1->aircraft->position, 
                    Vector3Scale(push, manager->collision_radius)
                );
                a2->aircraft->position = Vector3Add(
                    a2->aircraft->position, 
                    Vector3Scale(push, -manager->collision_radius)
                );
            }
        }
    }
}

void aircraft_manager_damage_aircraft(aircraft_manager_t* manager, int id, 
                                    float damage, int attacker_id) {
    managed_aircraft_t* ma = aircraft_manager_get(manager, id);
    if (!ma || ma->health <= 0) return;
    
    /* Validate attacker */
    managed_aircraft_t* attacker = NULL;
    if (attacker_id >= 0) {
        attacker = aircraft_manager_get(manager, attacker_id);
    }
    
    /* Apply shield protection */
    if (ma->powerup_effects.shield_active) {
        damage *= 0.1f;  /* 90% damage reduction */
    }
    
    /* Apply damage */
    float old_health = ma->health;
    ma->health -= damage;
    ma->health = fmaxf(ma->health, 0.0f);
    
    /* Check if killed */
    if (old_health > 0 && ma->health <= 0) {
        ma->deaths++;
        
        /* Credit kill to attacker */
        if (attacker) {
            attacker->kills++;
            printf("%s destroyed %s! (K/D: %d/%d)\n", 
                   attacker->name, ma->name, attacker->kills, attacker->deaths);
        } else {
            printf("%s crashed! (environmental damage)\n", ma->name);
        }
        
        /* Schedule respawn with delay */
        ma->respawn_timer = 3.0f; /* 3 second respawn delay */
    }
}

void aircraft_manager_respawn(aircraft_manager_t* manager, int id) {
    managed_aircraft_t* ma = aircraft_manager_get(manager, id);
    if (!ma || !ma->aircraft) return;
    
    /* Get new spawn point */
    Vector3 spawn = aircraft_manager_get_spawn_point(manager);
    
    /* Reset aircraft state */
    ma->aircraft->position = spawn;
    ma->aircraft->yaw = (float)GetRandomValue(0, 360);
    ma->aircraft->pitch = 0;
    ma->aircraft->roll = 0;
    ma->aircraft->speed = AIRCRAFT_BASE_SPEED;
    
    /* Reset combat state */
    ma->health = ma->max_health;
    ma->target_id = -1;
    
    /* Clear some power-up effects */
    ma->powerup_effects.shield_active = false;
    ma->powerup_effects.shield_timer = 0;
    
    printf("%s respawned at (%.1f, %.1f, %.1f)\n", 
           ma->name, spawn.x, spawn.y, spawn.z);
}

/*
 * Utility Functions
 */

Vector3 aircraft_manager_get_spawn_point(aircraft_manager_t* manager) {
    if (!validate_manager(manager) || manager->spawn_count == 0) {
        return (Vector3){0, DEFAULT_SPAWN_HEIGHT, 0};
    }
    
    int index = GetRandomValue(0, manager->spawn_count - 1);
    return manager->spawn_points[index];
}

int aircraft_manager_find_nearest_enemy(aircraft_manager_t* manager, int aircraft_id) {
    managed_aircraft_t* ma = aircraft_manager_get(manager, aircraft_id);
    if (!ma || !ma->aircraft) return -1;
    
    int nearest_id = -1;
    float min_distance = INFINITY;
    
    for (int i = 0; i < manager->aircraft_count; i++) {
        if (i == aircraft_id) continue;
        
        managed_aircraft_t* other = &manager->aircraft[i];
        if (!other->aircraft || other->health <= 0) continue;
        
        /* Skip teammates */
        if (ma->team_id >= 0 && ma->team_id == other->team_id) continue;
        
        float dist = Vector3Distance(ma->aircraft->position, other->aircraft->position);
        if (dist < min_distance) {
            min_distance = dist;
            nearest_id = i;
        }
    }
    
    return nearest_id;
}

float aircraft_manager_distance_between(aircraft_manager_t* manager, int id1, int id2) {
    managed_aircraft_t* ma1 = aircraft_manager_get(manager, id1);
    managed_aircraft_t* ma2 = aircraft_manager_get(manager, id2);
    
    if (!ma1 || !ma2 || !ma1->aircraft || !ma2->aircraft) {
        return INFINITY;
    }
    
    return Vector3Distance(ma1->aircraft->position, ma2->aircraft->position);
}

/*
 * Internal Helper Functions
 */

static bool validate_manager(const aircraft_manager_t* manager) {
    return manager != NULL;
}

static bool validate_aircraft_id(const aircraft_manager_t* manager, int id) {
    return manager && id >= 0 && id < manager->aircraft_count;
}

static void initialize_spawn_points(aircraft_manager_t* manager) {
    assert(manager != NULL);
    
    /* Create spawn points in a circle */
    manager->spawn_count = 12;
    for (int i = 0; i < manager->spawn_count; i++) {
        float angle = (float)i * (2.0f * PI / manager->spawn_count);
        float height_variance = (float)GetRandomValue(-SPAWN_HEIGHT_VARIANCE, SPAWN_HEIGHT_VARIANCE);
        
        manager->spawn_points[i] = (Vector3){
            cosf(angle) * DEFAULT_SPAWN_RADIUS,
            DEFAULT_SPAWN_HEIGHT + height_variance,
            sinf(angle) * DEFAULT_SPAWN_RADIUS
        };
    }
}

static void reset_aircraft_state(managed_aircraft_t* ma) {
    assert(ma != NULL);
    
    /* Preserve pointers but clear everything else */
    aircraft_t* aircraft = ma->aircraft;
    weapons_system_t* weapons = ma->weapons;
    
    memset(ma, 0, sizeof(managed_aircraft_t));
    
    ma->aircraft = aircraft;
    ma->weapons = weapons;
    ma->target_id = -1;
    ma->team_id = -1;
}
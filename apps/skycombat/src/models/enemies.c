/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/models/enemies.h"
#include <raymath.h>
#include <stdlib.h>
#include <math.h>
#include <stdio.h>
#include "sky_combat/utils/safe_math.h"

// Safe Vector3 normalize that handles zero-magnitude vectors
static Vector3 SafeVector3Normalize(Vector3 v) {
    float length = Vector3Length(v);
    if (length < 0.0001f) {
        return (Vector3){0.0f, 0.0f, 1.0f};  // Return safe default direction
    }
    return Vector3Scale(v, 1.0f / length);
}

// Create enemy waves
static enemy_wave_t default_waves[] = {
    {
        .name = "Scout Patrol",
        .spawns = (wave_spawn_t[]){
            {ENEMY_DRONE, 3, 0.5f, {0, 50, 200}, true},
        },
        .spawn_count = 1,
        .start_time = 2.0f,
        .boss_wave = false
    },
    {
        .name = "Fighter Squadron",
        .spawns = (wave_spawn_t[]){
            {ENEMY_FIGHTER, 5, 0.3f, {-100, 80, 300}, true},
            {ENEMY_DRONE, 4, 0.2f, {100, 60, 250}, false},
        },
        .spawn_count = 2,
        .start_time = 10.0f,
        .boss_wave = false
    },
    {
        .name = "Turret Defense",
        .spawns = (wave_spawn_t[]){
            {ENEMY_TURRET, 8, 1.0f, {0, 0, 400}, false},
            {ENEMY_SWARM, 12, 0.1f, {0, 100, 350}, true},
        },
        .spawn_count = 2,
        .start_time = 20.0f,
        .boss_wave = false
    },
    {
        .name = "Boss Mech Attack",
        .spawns = (wave_spawn_t[]){
            {ENEMY_BOSS_MECH, 1, 0.0f, {0, 100, 500}, false},
            {ENEMY_DRONE, 6, 0.5f, {-50, 80, 400}, true},
        },
        .spawn_count = 2,
        .start_time = 35.0f,
        .boss_wave = true
    }
};

// Enemy properties by type - COLORFUL TARGET PLANES!
typedef struct {
    float health;
    float speed;
    float turn_rate;
    float fire_rate;
    float scale;
    Color color;
    int score;
} enemy_properties_t;

static const enemy_properties_t enemy_props[] = {
    [ENEMY_DRONE] = {20, 60, 2.0f, 0.0f, 3.0f, (Color){0, 255, 255, 255}, 100},      // Cyan planes
    [ENEMY_FIGHTER] = {30, 80, 3.0f, 0.0f, 4.0f, (Color){255, 0, 128, 255}, 250},    // Hot pink planes
    [ENEMY_TURRET] = {40, 40, 4.0f, 0.0f, 3.5f, (Color){255, 255, 0, 255}, 300},     // Yellow planes
    [ENEMY_BOMBER] = {50, 30, 1.0f, 0.0f, 6.0f, (Color){0, 255, 0, 255}, 500},       // Green planes
    [ENEMY_SWARM] = {10, 100, 5.0f, 0.0f, 2.0f, (Color){255, 128, 0, 255}, 50},      // Orange planes
    [ENEMY_BOSS_MECH] = {100, 50, 2.0f, 0.0f, 8.0f, (Color){128, 0, 255, 255}, 5000}, // Purple planes
    [ENEMY_BOSS_CARRIER] = {200, 20, 0.5f, 0.0f, 10.0f, (Color){255, 0, 255, 255}, 10000}, // Magenta planes
};

enemy_manager_t* enemies_create(int max_enemies) {
    if (max_enemies <= 0) return NULL;
    
    enemy_manager_t* manager = calloc(1, sizeof(enemy_manager_t));
    if (!manager) return NULL;
    
    manager->enemies = calloc(max_enemies, sizeof(enemy_t));
    if (!manager->enemies) {
        free(manager);
        return NULL;
    }
    manager->max_enemies = max_enemies;
    manager->active_count = 0;
    
    // Initialize projectiles
    for (int i = 0; i < MAX_ENEMY_PROJECTILES; i++) {
        manager->projectiles[i].active = false;
    }
    
    // Set up waves
    manager->waves = default_waves;
    manager->total_waves = sizeof(default_waves) / sizeof(default_waves[0]);
    manager->current_wave = 0;
    manager->wave_timer = 0;
    
    return manager;
}

void enemies_destroy(enemy_manager_t* manager) {
    if (!manager) return;
    if (manager->enemies) {
        free(manager->enemies);
    }
    free(manager);
}

void enemies_spawn(enemy_manager_t* manager, enemy_type_t type, Vector3 position) {
    if (manager->active_count >= manager->max_enemies) return;
    
    // Find inactive enemy slot
    enemy_t* enemy = NULL;
    for (int i = 0; i < manager->max_enemies; i++) {
        if (!manager->enemies[i].health) {
            enemy = &manager->enemies[i];
            break;
        }
    }
    
    if (!enemy) return;
    
    // Initialize enemy
    const enemy_properties_t* props = &enemy_props[type];
    enemy->type = type;
    enemy->state = AI_PATROL;
    enemy->position = position;
    enemy->velocity = (Vector3){0, 0, 0};
    enemy->health = props->health;
    enemy->max_health = props->health;
    enemy->speed = props->speed;
    enemy->turn_rate = props->turn_rate;
    enemy->scale = props->scale;
    enemy->color = props->color;
    enemy->score_value = props->score;
    
    // Initialize explosion data - BIGGER for visibility at distance!
    enemy->explosion_radius = props->scale * 5.0f;  // Much bigger explosions!
    // High contrast explosion colors
    switch(type) {
        case ENEMY_DRONE:
            enemy->explosion_color = (Color){255, 128, 0, 255};   // Bright orange
            break;
        case ENEMY_FIGHTER:
            enemy->explosion_color = (Color){0, 255, 255, 255};   // Cyan
            break;
        case ENEMY_TURRET:
            enemy->explosion_color = (Color){255, 0, 255, 255};   // Magenta
            break;
        case ENEMY_BOMBER:
            enemy->explosion_color = (Color){255, 255, 0, 255};   // Yellow
            break;
        case ENEMY_SWARM:
            enemy->explosion_color = (Color){0, 255, 0, 255};     // Bright green
            break;
        case ENEMY_BOSS_MECH:
        case ENEMY_BOSS_CARRIER:
            enemy->explosion_color = (Color){255, 0, 0, 255};     // Bright red
            break;
        default:
            enemy->explosion_color = (Color){255, 200, 100, 255}; // Default orange
            break;
    }
    
    // Random properties
    enemy->aggression = 0.5f + (float)(rand() % 50) / 100.0f;
    enemy->accuracy = 0.6f + (float)(rand() % 30) / 100.0f;
    enemy->reaction_time = 0.5f + (float)(rand() % 100) / 100.0f;
    
    // Special abilities
    if (type == ENEMY_FIGHTER) {
        enemy->can_barrel_roll = true;
        enemy->boost_fuel = 100.0f;
    } else if (type == ENEMY_BOSS_MECH) {
        enemy->can_teleport = true;
        enemy->has_shields = true;
        enemy->shield_power = 100.0f;
    }
    
    manager->active_count++;
}

void enemies_spawn_formation(enemy_manager_t* manager, enemy_type_t type, Vector3 center, int count) {
    if (count <= 0) return;  // Prevent division by zero
    
    float radius = 20.0f;
    for (int i = 0; i < count; i++) {
        float angle = (2.0f * PI * i) / count;
        Vector3 offset = {
            cosf(angle) * radius,
            0,
            sinf(angle) * radius
        };
        Vector3 pos = Vector3Add(center, offset);
        enemies_spawn(manager, type, pos);
        
        // Set formation leader
        if (i == 0 && manager->active_count > 0) {
            // First spawned is leader
            enemy_t* leader = NULL;
            for (int j = manager->max_enemies - 1; j >= 0; j--) {
                if (manager->enemies[j].health > 0) {
                    leader = &manager->enemies[j];
                    break;
                }
            }
            
            // Others follow
            for (int j = manager->max_enemies - 2; j >= 0; j--) {
                if (manager->enemies[j].health > 0 && 
                    manager->enemies[j].position.x == pos.x) {
                    manager->enemies[j].leader = leader;
                    manager->enemies[j].formation_offset = offset;
                    manager->enemies[j].state = AI_FORMATION;
                }
            }
        }
    }
}

void enemy_ai_update(enemy_t* enemy, Vector3 player_pos, float dt) {
    if (!enemy || enemy->health <= 0) return;
    
    // PRACTICE MODE - Enemies completely ignore the player!
    // They just stay in patrol mode forever
    enemy->state = AI_PATROL;
    
    // No state transitions - they never notice you
}

void enemy_ai_patrol(enemy_t* enemy, float dt) {
    // Simple circular patrol
    enemy->yaw += enemy->turn_rate * 0.5f * dt;
    
    Vector3 forward = {
        sinf(enemy->yaw),
        0,
        cosf(enemy->yaw)
    };
    
    enemy->velocity = Vector3Scale(forward, enemy->speed);
    enemy->position = Vector3Add(enemy->position, Vector3Scale(enemy->velocity, dt));
}

void enemy_ai_chase(enemy_t* enemy, Vector3 target, float dt) {
    Vector3 to_target = Vector3Subtract(target, enemy->position);
    to_target = SafeVector3Normalize(to_target);
    
    // Turn towards target
    float target_yaw = atan2f(to_target.x, to_target.z);
    float yaw_diff = target_yaw - enemy->yaw;
    
    // Normalize angle
    while (yaw_diff > PI) yaw_diff -= 2 * PI;
    while (yaw_diff < -PI) yaw_diff += 2 * PI;
    
    enemy->yaw += yaw_diff * enemy->turn_rate * dt;
    
    // Move forward
    Vector3 forward = {
        sinf(enemy->yaw),
        to_target.y * 0.5f,  // Some vertical tracking
        cosf(enemy->yaw)
    };
    
    enemy->velocity = Vector3Scale(forward, enemy->speed);
    enemy->position = Vector3Add(enemy->position, Vector3Scale(enemy->velocity, dt));
}

void enemy_barrel_roll(enemy_t* enemy) {
    if (!enemy->can_barrel_roll || enemy->special_cooldown > 0) return;
    
    enemy->roll += PI * 2;  // Full roll
    enemy->special_cooldown = 3.0f;
    
    // Dodge sideways
    Vector3 right = {
        cosf(enemy->yaw),
        0,
        -sinf(enemy->yaw)
    };
    enemy->position = Vector3Add(enemy->position, Vector3Scale(right, 20.0f));
}

void enemy_fire_projectile(enemy_manager_t* manager, enemy_t* enemy, Vector3 target) {
    if (!manager || !enemy || enemy->fire_cooldown > 0) return;
    
    // Find inactive projectile
    for (int i = 0; i < MAX_ENEMY_PROJECTILES; i++) {
        if (!manager->projectiles[i].active) {
            enemy_projectile_t* proj = &manager->projectiles[i];
            
            // Calculate firing direction with accuracy
            Vector3 to_target = Vector3Subtract(target, enemy->position);
            float distance = Vector3Length(to_target);
            to_target = SafeVector3Normalize(to_target);
            
            // Add inaccuracy based on enemy accuracy stat
            float spread = (1.0f - enemy->accuracy) * 0.2f;
            to_target.x += ((float)GetRandomValue(-100, 100) / 100.0f) * spread;
            to_target.y += ((float)GetRandomValue(-100, 100) / 100.0f) * spread;
            to_target.z += ((float)GetRandomValue(-100, 100) / 100.0f) * spread;
            to_target = SafeVector3Normalize(to_target);
            
            // Set projectile properties based on enemy type
            proj->position = enemy->position;
            proj->from_enemy = enemy->type;
            proj->active = true;
            
            switch (enemy->type) {
                case ENEMY_DRONE:
                    proj->velocity = Vector3Scale(to_target, 150.0f);
                    proj->damage = 10;
                    proj->color = GREEN;
                    proj->life = 3.0f;
                    enemy->fire_cooldown = 2.0f;
                    break;
                    
                case ENEMY_FIGHTER:
                    proj->velocity = Vector3Scale(to_target, 250.0f);
                    proj->damage = 20;
                    proj->color = RED;
                    proj->life = 2.5f;
                    enemy->fire_cooldown = 1.0f;
                    break;
                    
                case ENEMY_TURRET:
                    // Lead the target for turrets
                    Vector3 player_vel = {0, 0, 50}; // Estimate player velocity
                    float time_to_hit = distance / 200.0f;
                    Vector3 lead_pos = Vector3Add(target, Vector3Scale(player_vel, time_to_hit));
                    to_target = SafeVector3Normalize(Vector3Subtract(lead_pos, enemy->position));
                    
                    proj->velocity = Vector3Scale(to_target, 200.0f);
                    proj->damage = 30;
                    proj->color = ORANGE;
                    proj->life = 4.0f;
                    enemy->fire_cooldown = 0.5f;
                    break;
                    
                case ENEMY_BOSS_MECH:
                    // Boss fires spread of projectiles
                    for (int j = -1; j <= 1; j++) {
                        if (i + j >= 0 && i + j < MAX_ENEMY_PROJECTILES && !manager->projectiles[i + j].active) {
                            enemy_projectile_t* spread_proj = &manager->projectiles[i + j];
                            Vector3 spread_dir = to_target;
                            spread_dir.x += j * 0.1f;
                            spread_dir = SafeVector3Normalize(spread_dir);
                            
                            spread_proj->position = enemy->position;
                            spread_proj->velocity = Vector3Scale(spread_dir, 180.0f);
                            spread_proj->damage = 25;
                            spread_proj->color = PURPLE;
                            spread_proj->life = 3.5f;
                            spread_proj->active = true;
                            spread_proj->from_enemy = enemy->type;
                        }
                    }
                    enemy->fire_cooldown = 0.3f;
                    break;
                    
                default:
                    proj->velocity = Vector3Scale(to_target, 150.0f);
                    proj->damage = 15;
                    proj->color = YELLOW;
                    proj->life = 3.0f;
                    enemy->fire_cooldown = 1.5f;
                    break;
            }
            
            break;
        }
    }
}

void enemy_ai_attack(enemy_t* enemy, Vector3 target, enemy_manager_t* manager, float dt) {
    if (!enemy || !manager) return;
    
    // PRACTICE MODE - Enemies don't shoot back!
    // They just fly around as targets
    enemy_ai_chase(enemy, target, dt);
    
    // NO FIRING - These are practice targets only
    return;
}

void enemies_update(enemy_manager_t* manager, Vector3 player_pos, float dt) {
    if (!manager) return;
    
    // Update wave spawning
    manager->wave_timer += dt;
    if (manager->current_wave < manager->total_waves) {
        enemy_wave_t* wave = &manager->waves[manager->current_wave];
        if (manager->wave_timer >= wave->start_time && !manager->wave_active) {
            enemies_spawn_wave(manager, manager->current_wave);
            manager->wave_active = true;
        }
        
        // Check wave completion
        if (manager->wave_active && enemies_wave_complete(manager)) {
            manager->current_wave++;
            manager->wave_active = false;
        }
    }
    
    // Update enemies
    for (int i = 0; i < manager->max_enemies; i++) {
        enemy_t* enemy = &manager->enemies[i];
        if (enemy->health <= 0) continue;
        
        // Update AI
        enemy_ai_update(enemy, player_pos, dt);
        
        // Execute behavior
        switch (enemy->state) {
            case AI_PATROL:
                enemy_ai_patrol(enemy, dt);
                break;
            case AI_CHASE:
                enemy_ai_chase(enemy, player_pos, dt);
                break;
            case AI_ATTACK:
                enemy_ai_attack(enemy, player_pos, manager, dt);
                break;
            case AI_EVADE:
                // Evasive maneuvers
                if (enemy->can_barrel_roll && (rand() % 100) < 20) {
                    enemy_barrel_roll(enemy);
                }
                break;
            case AI_FORMATION:
                if (enemy->leader && enemy->leader->health > 0) {
                    Vector3 target = Vector3Add(enemy->leader->position, enemy->formation_offset);
                    enemy_ai_chase(enemy, target, dt);
                } else {
                    enemy->state = AI_CHASE;
                }
                break;
        }
        
        // Update visual effects
        if (enemy->damage_flash > 0) {
            enemy->damage_flash -= dt * 5.0f;
        }
        
        // Update death
        if (enemy->dying) {
            enemy->death_timer += dt;
            if (enemy->death_timer > 2.0f) {
                enemy->health = 0;
                manager->active_count--;
            }
        }
    }
    
    // Update combo
    if (manager->combo_timer > 0) {
        manager->combo_timer -= dt;
        if (manager->combo_timer <= 0) {
            manager->combo_count = 0;
        }
    }
    
    // Update enemy projectiles
    for (int i = 0; i < MAX_ENEMY_PROJECTILES; i++) {
        if (manager->projectiles[i].active) {
            enemy_projectile_t* proj = &manager->projectiles[i];
            
            // Update position
            proj->position = Vector3Add(proj->position, Vector3Scale(proj->velocity, dt));
            proj->life -= dt;
            
            if (proj->life <= 0) {
                proj->active = false;
            }
        }
    }
}

void enemies_draw(enemy_manager_t* manager) {
    if (!manager) return;
    
    for (int i = 0; i < manager->max_enemies; i++) {
        enemy_t* enemy = &manager->enemies[i];
        if (enemy->health <= 0) continue;
        
        // Flash when damaged
        Color color = enemy->color;
        if (enemy->damage_flash > 0) {
            color = WHITE;
        }
        
        // Draw all enemies as PLANE SHAPES with different colors
        // Basic plane shape for all enemy types
        
        // Fuselage (body)
        DrawCube(enemy->position, enemy->scale * 3, enemy->scale * 0.5f, enemy->scale * 0.5f, color);
        
        // Wings
        DrawCube((Vector3){enemy->position.x, enemy->position.y - enemy->scale * 0.1f, enemy->position.z}, 
                enemy->scale * 0.2f, enemy->scale * 0.1f, enemy->scale * 4, color);
        
        // Tail
        Vector3 tail_pos = {enemy->position.x - enemy->scale * 1.2f, enemy->position.y, enemy->position.z};
        DrawCube(tail_pos, enemy->scale * 0.3f, enemy->scale, enemy->scale * 0.1f, color);
        
        // Cockpit (darker shade)
        Color cockpit_color = {color.r/2, color.g/2, color.b/2, color.a};
        Vector3 cockpit_pos = {enemy->position.x + enemy->scale * 0.8f, enemy->position.y + enemy->scale * 0.2f, enemy->position.z};
        DrawCube(cockpit_pos, enemy->scale * 0.6f, enemy->scale * 0.3f, enemy->scale * 0.4f, cockpit_color);
        
        // Engine glow based on speed
        if (enemy->speed > 0) {
            Color engine_color = {255, 200, 100, 200};
            Vector3 engine_pos = {enemy->position.x - enemy->scale * 1.5f, enemy->position.y, enemy->position.z};
            DrawSphere(engine_pos, enemy->scale * 0.3f, engine_color);
        }
        
        // Draw shields
        if (enemy->has_shields && enemy->shield_power > 0) {
            Color shield_color = {100, 200, 255, (unsigned char)(enemy->shield_power * 1.5f)};
            DrawSphereWires(enemy->position, enemy->scale * 1.5f, 8, 8, shield_color);
        }
        
        // Health bar
        if (enemy->health < enemy->max_health && enemy->max_health > 0) {
            Vector3 bar_pos = enemy->position;
            bar_pos.y += enemy->scale * 2;
            
            float health_percent = safe_divide(enemy->health, enemy->max_health);
            Color health_color = health_percent > 0.5f ? GREEN : 
                                health_percent > 0.25f ? YELLOW : RED;
            
            DrawCube(bar_pos, enemy->scale * 2 * health_percent, 0.2f, 0.2f, health_color);
        }
    }
    
    // Draw enemy projectiles
    for (int i = 0; i < MAX_ENEMY_PROJECTILES; i++) {
        if (manager->projectiles[i].active) {
            enemy_projectile_t* proj = &manager->projectiles[i];
            
            // Draw projectile with trail effect
            Vector3 trail_start = Vector3Subtract(proj->position, 
                                                 Vector3Scale(SafeVector3Normalize(proj->velocity), 5.0f));
            
            // Different effects based on enemy type
            switch (proj->from_enemy) {
                case ENEMY_TURRET:
                    // Turret fires thick plasma bolts
                    DrawSphere(proj->position, 1.5f, proj->color);
                    DrawSphere(proj->position, 2.0f, Fade(proj->color, 0.3f));
                    DrawLine3D(proj->position, trail_start, proj->color);
                    break;
                    
                case ENEMY_BOSS_MECH:
                    // Boss fires energy orbs
                    float pulse = sinf(GetTime() * 20.0f) * 0.3f + 1.0f;
                    DrawSphere(proj->position, 2.0f * pulse, proj->color);
                    DrawSphere(proj->position, 3.0f * pulse, Fade(proj->color, 0.2f));
                    
                    // Energy particles
                    for (int j = 0; j < 3; j++) {
                        Vector3 particle_pos = Vector3Subtract(proj->position,
                            Vector3Scale(proj->velocity, j * 0.01f));
                        DrawSphere(particle_pos, 0.5f, Fade(WHITE, 0.8f - j * 0.2f));
                    }
                    break;
                    
                case ENEMY_FIGHTER:
                    // Fighter fires laser bolts
                    DrawCapsule(proj->position, trail_start, 0.3f, 4, 4, proj->color);
                    DrawSphere(proj->position, 0.5f, WHITE);
                    break;
                    
                default:
                    // Standard projectile
                    DrawSphere(proj->position, 0.8f, proj->color);
                    DrawLine3D(proj->position, trail_start, Fade(proj->color, 0.5f));
                    break;
            }
        }
    }
}

void enemies_spawn_wave(enemy_manager_t* manager, int wave_index) {
    if (wave_index >= manager->total_waves) return;
    
    enemy_wave_t* wave = &manager->waves[wave_index];
    
    for (int i = 0; i < wave->spawn_count; i++) {
        wave_spawn_t* spawn = &wave->spawns[i];
        
        if (spawn->in_formation) {
            enemies_spawn_formation(manager, spawn->type, spawn->spawn_position, spawn->count);
        } else {
            for (int j = 0; j < spawn->count; j++) {
                Vector3 pos = spawn->spawn_position;
                // Add some randomness
                pos.x += (rand() % 40) - 20;
                pos.y += (rand() % 20) - 10;
                pos.z += (rand() % 40) - 20;
                
                enemies_spawn(manager, spawn->type, pos);
            }
        }
    }
}

bool enemies_check_hit(enemy_manager_t* manager, Vector3 position, float radius, float damage) {
    bool hit = false;
    
    for (int i = 0; i < manager->max_enemies; i++) {
        enemy_t* enemy = &manager->enemies[i];
        if (enemy->health <= 0) continue;
        
        float distance = Vector3Distance(enemy->position, position);
        if (distance < radius + enemy->scale) {
            enemies_damage(manager, i, damage);
            hit = true;
        }
    }
    
    return hit;
}

void enemies_damage(enemy_manager_t* manager, int index, float damage) {
    if (index < 0 || index >= manager->max_enemies) return;
    
    enemy_t* enemy = &manager->enemies[index];
    if (enemy->health <= 0) return;
    
    // Apply shield first
    if (enemy->has_shields && enemy->shield_power > 0) {
        enemy->shield_power -= damage * 0.5f;
        damage *= 0.5f;  // Shields reduce damage
        if (enemy->shield_power < 0) {
            damage = -enemy->shield_power;
            enemy->shield_power = 0;
        }
    }
    
    enemy->health -= damage;
    enemy->damage_flash = 1.0f;
    
    if (enemy->health <= 0) {
        enemies_explode(manager, index);
        
        // Update score and combo
        manager->total_kills++;
        manager->combo_count++;
        manager->combo_timer = 2.0f;  // 2 seconds to maintain combo
    }
}

void enemies_explode(enemy_manager_t* manager, int index) {
    if (index < 0 || index >= manager->max_enemies) return;
    
    enemy_t* enemy = &manager->enemies[index];
    enemy->dying = true;
    enemy->death_timer = 0;
    
    // BIG VISIBLE EXPLOSIONS for long-range hunting!
    float explosion_radius = enemy->scale * 5.0f;  // 5x for visibility!
    
    // High contrast explosion colors based on enemy type
    Color explosion_color;
    switch(enemy->type) {
        case ENEMY_DRONE:
            explosion_color = (Color){255, 128, 0, 255};   // Bright orange
            break;
        case ENEMY_FIGHTER:
            explosion_color = (Color){0, 255, 255, 255};   // Cyan
            break;
        case ENEMY_TURRET:
            explosion_color = (Color){255, 0, 255, 255};   // Magenta
            break;
        case ENEMY_BOMBER:
            explosion_color = (Color){255, 255, 0, 255};   // Yellow
            break;
        case ENEMY_SWARM:
            explosion_color = (Color){0, 255, 0, 255};     // Bright green
            break;
        case ENEMY_BOSS_MECH:
        case ENEMY_BOSS_CARRIER:
            explosion_color = (Color){255, 0, 0, 255};     // Bright red
            break;
        default:
            explosion_color = (Color){255, 200, 100, 255}; // Default orange
            break;
    }
    
    // Store explosion data in enemy struct
    enemy->explosion_radius = explosion_radius;
    enemy->explosion_color = explosion_color;
}

int enemies_get_active_count(enemy_manager_t* manager) {
    return manager ? manager->active_count : 0;
}

enemy_t* enemies_get_nearest(enemy_manager_t* manager, Vector3 position) {
    if (!manager) return NULL;
    
    enemy_t* nearest = NULL;
    float min_distance = INFINITY;
    
    for (int i = 0; i < manager->max_enemies; i++) {
        enemy_t* enemy = &manager->enemies[i];
        if (enemy->health <= 0) continue;
        
        float distance = Vector3Distance(enemy->position, position);
        if (distance < min_distance) {
            min_distance = distance;
            nearest = enemy;
        }
    }
    
    return nearest;
}

bool enemies_wave_complete(enemy_manager_t* manager) {
    if (!manager || !manager->wave_active) return false;
    
    // Check if all enemies from current wave are defeated
    for (int i = 0; i < manager->max_enemies; i++) {
        if (manager->enemies[i].health > 0) {
            return false;
        }
    }
    
    return true;
}

bool enemies_check_player_hit(enemy_manager_t* manager, Vector3 player_pos, float radius) {
    if (!manager) return false;
    
    bool hit = false;
    
    // Check all enemy projectiles
    for (int i = 0; i < MAX_ENEMY_PROJECTILES; i++) {
        if (manager->projectiles[i].active) {
            enemy_projectile_t* proj = &manager->projectiles[i];
            
            float distance = Vector3Distance(proj->position, player_pos);
            if (distance < radius + 2.0f) { // Projectile has radius of ~2
                // Player hit! 
                hit = true;
                
                // Deactivate projectile
                proj->active = false;
                
                // TODO: Apply damage to player when player health system is implemented
                // For now, just return that we hit
            }
        }
    }
    
    return hit;
}

// Spawn MASSIVE WAVES of enemies FAR AWAY for target practice!
void enemies_spawn_massive_wave(enemy_manager_t* manager) {
    if (!manager || !manager->enemies) return;
    
    // Clear existing enemies
    for (int i = 0; i < manager->max_enemies; i++) {
        manager->enemies[i].health = 0;
    }
    manager->active_count = 0;
    
    // MASSIVE SWARM AHEAD - Fill the distant sky with enemies!
    int enemies_to_spawn = manager->max_enemies - 10; // Leave room for spawning more
    int current = 0;
    
    // Wave 1: Grid of drones FAR in the distance
    for (int x = -15; x <= 15 && current < enemies_to_spawn/4; x += 3) {
        for (int z = 20; z <= 40 && current < enemies_to_spawn/4; z += 4) {
            Vector3 pos = {x * 20.0f, 60.0f + (rand() % 40), z * 20.0f + 100.0f}; // Much closer!
            enemies_spawn(manager, ENEMY_DRONE, pos);
            current++;
        }
    }
    
    // Wave 2: Fighter squadrons in V formations - DISTANT
    for (int squad = 0; squad < 8 && current < enemies_to_spawn/2; squad++) {
        float base_x = -600.0f + squad * 150.0f;
        float base_z = 800.0f + squad * 100.0f;  // Very far!
        for (int i = 0; i < 7; i++) {
            Vector3 pos = {
                base_x + i * 30.0f - abs(i - 3) * 15.0f,
                150.0f + abs(i - 3) * 10.0f,
                base_z + abs(i - 3) * 30.0f
            };
            enemies_spawn(manager, ENEMY_FIGHTER, pos);
            current++;
        }
    }
    
    // Wave 3: High altitude bombers
    for (int x = -20; x <= 20 && current < 3*enemies_to_spawn/4; x += 2) {
        for (int z = 0; z <= 10 && current < 3*enemies_to_spawn/4; z++) {
            Vector3 pos = {x * 20.0f, 100.0f + (rand() % 50), z * 30.0f + 200.0f}; // Much closer!
            enemies_spawn(manager, ENEMY_BOMBER, pos);
            current++;
        }
    }
    
    // Wave 4: Swarm clouds scattered everywhere
    for (int i = 0; i < enemies_to_spawn - current; i++) {
        float angle = (float)(rand() % 360) * DEG2RAD;
        float radius = 80.0f + (rand() % 200);  // 80-280 units away - visible!
        float height = 50.0f + (rand() % 300);
        Vector3 pos = {
            cosf(angle) * radius,
            height,
            sinf(angle) * radius
        };
        enemies_spawn(manager, ENEMY_SWARM, pos);
    }
    
    printf("MASSIVE ENEMY WAVE SPAWNED: %d enemies!\n", manager->active_count);
}

// Original practice targets function
void enemies_spawn_practice_targets(enemy_manager_t* manager) {
    // Just call the massive wave function instead!
    enemies_spawn_massive_wave(manager);
    return;
    
    if (!manager || !manager->enemies) return;
    
    // Clear existing enemies
    for (int i = 0; i < manager->max_enemies; i++) {
        manager->enemies[i].health = 0;
    }
    manager->active_count = 0;
    
    // Pattern 1: Horizontal line of slow-moving drones
    for (int i = 0; i < 8; i++) {
        Vector3 pos = {-150.0f + i * 40.0f, 50.0f, 200.0f};
        enemies_spawn(manager, ENEMY_DRONE, pos);
        
        // Make them fly in straight line
        if (manager->active_count > 0 && manager->active_count <= manager->max_enemies) {
            int idx = manager->active_count - 1;
            if (idx >= 0 && idx < manager->max_enemies) {
                enemy_t* enemy = &manager->enemies[idx];
                enemy->state = AI_PATROL;
                enemy->velocity = (Vector3){20.0f, 0, 0};  // Slow horizontal movement
                enemy->max_health = 50.0f;  // Easy to destroy
                enemy->health = 50.0f;
            }
        }
    }
    
    // Pattern 2: Vertical line of stationary targets
    for (int i = 0; i < 6; i++) {
        Vector3 pos = {100.0f, 30.0f + i * 20.0f, 150.0f};
        enemies_spawn(manager, ENEMY_TURRET, pos);
        
        // Make them stationary
        if (manager->active_count > 0 && manager->active_count <= manager->max_enemies) {
            int idx = manager->active_count - 1;
            if (idx >= 0 && idx < manager->max_enemies) {
                enemy_t* enemy = &manager->enemies[idx];
                enemy->state = AI_PATROL;
                enemy->velocity = (Vector3){0, 0, 0};  // No movement
                enemy->max_health = 30.0f;  // Very easy
                enemy->health = 30.0f;
            }
        }
    }
    
    // Pattern 3: Circle of fighters
    float circle_radius = 100.0f;
    int circle_count = 12;
    for (int i = 0; i < circle_count; i++) {
        float angle = (i / (float)circle_count) * PI * 2.0f;
        Vector3 pos = {
            cosf(angle) * circle_radius,
            80.0f,
            200.0f + sinf(angle) * circle_radius
        };
        enemies_spawn(manager, ENEMY_FIGHTER, pos);
        
        // Make them orbit in a circle
        if (manager->active_count > 0 && manager->active_count <= manager->max_enemies) {
            int idx = manager->active_count - 1;
            if (idx >= 0 && idx < manager->max_enemies) {
                enemy_t* enemy = &manager->enemies[idx];
                enemy->state = AI_PATROL;
                // Velocity perpendicular to radius for circular motion
                enemy->velocity = (Vector3){
                    -sinf(angle) * 30.0f,  // Moderate speed
                    0,
                    cosf(angle) * 30.0f
                };
                enemy->max_health = 40.0f;
                enemy->health = 40.0f;
            }
        }
    }
    
    // Pattern 4: Figure-8 pattern
    for (int i = 0; i < 10; i++) {
        float t = (i / 10.0f) * PI * 2.0f;
        float x = sinf(t) * 80.0f;
        float z = sinf(2 * t) * 40.0f + 250.0f;
        Vector3 pos = {x, 60.0f, z};
        enemies_spawn(manager, ENEMY_SWARM, pos);
        
        if (manager->active_count > 0 && manager->active_count <= manager->max_enemies) {
            int idx = manager->active_count - 1;
            if (idx >= 0 && idx < manager->max_enemies) {
                enemy_t* enemy = &manager->enemies[idx];
                enemy->state = AI_PATROL;
                enemy->velocity = (Vector3){
                    cosf(t) * 40.0f,
                    0,
                    cosf(2 * t) * 80.0f
                };
                enemy->max_health = 20.0f;  // Very fragile
                enemy->health = 20.0f;
            }
        }
    }
}
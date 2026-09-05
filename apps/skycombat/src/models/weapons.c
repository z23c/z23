/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/models/weapons.h"
#include "sky_combat/utils/safety_macros.h"
#include <raylib.h>
#include <raymath.h>
#include <stdlib.h>
#include <math.h>

weapons_system_t* weapons_create(void) {
    weapons_system_t* weapons;
    SAFE_CALLOC(weapons, 1, sizeof(weapons_system_t));
    
    // Initialize linked list
    weapons->bullets_head = NULL;
    weapons->bullet_count = 0;
    
    for (int i = 0; i < MAX_MISSILES; i++) {
        weapons->missiles[i].active = false;
    }
    
    for (int i = 0; i < MAX_LASERS; i++) {
        weapons->lasers[i].active = false;
    }
    
    for (int i = 0; i < MAX_PLASMA; i++) {
        weapons->plasma[i].active = false;
    }
    
    // Initialize weapon state
    weapons->current_weapon = WEAPON_MACHINE_GUN;
    weapons->recoil_amount = 0.0f;
    weapons->muzzle_flash_timer = 0.0f;
    
    // Initialize upgrade state
    weapons->current_upgrade = WEAPON_UPGRADE_NONE;
    weapons->upgrade_timer = 0.0f;
    weapons->damage_multiplier = 1.0f;
    weapons->fire_rate_multiplier = 1.0f;
    
    // Initialize gun fine-tuning
    weapons->bullet_bend_x = 0.0f;        // No bend by default
    weapons->bullet_bend_y = 0.0f;        // No bend by default
    weapons->bend_strength = 450.0f;      // 15x stronger bend force (insane curves!)
    
    // Set unlimited ammo for now (can be changed later)
    for (int i = 0; i < WEAPON_COUNT; i++) {
        weapons->ammo[i] = -1; // -1 means unlimited
        weapons->fire_cooldown[i] = 0.0f;
        weapons->weapon_heat[i] = 0.0f;
    }
    
    return weapons;
}

void weapons_destroy(weapons_system_t* weapons) {
    if (!weapons) return;
    
    // Free all bullets in linked list
    bullet_t* current = weapons->bullets_head;
    while (current) {
        bullet_t* next = current->next;
        free(current);
        current = next;
    }
    
    free(weapons);
}

void weapons_update(weapons_system_t* weapons, float dt) {
    CHECK_NULL(weapons);
    // Update weapon cooldowns and effects
    for (int i = 0; i < WEAPON_COUNT; i++) {
        if (weapons->fire_cooldown[i] > 0) {
            weapons->fire_cooldown[i] -= dt;
        }
        // Cool down weapon heat
        if (weapons->weapon_heat[i] > 0) {
            weapons->weapon_heat[i] -= dt * 0.5f; // Cooling rate
            weapons->weapon_heat[i] = fmaxf(0.0f, weapons->weapon_heat[i]);
        }
    }
    
    // Update recoil
    if (weapons->recoil_amount > 0) {
        weapons->recoil_amount -= dt * 10.0f; // Recoil recovery speed
        weapons->recoil_amount = fmaxf(0.0f, weapons->recoil_amount);
    }
    
    // Update muzzle flash
    if (weapons->muzzle_flash_timer > 0) {
        weapons->muzzle_flash_timer -= dt;
    }
    
    // Update upgrade timer
    if (weapons->upgrade_timer > 0) {
        weapons->upgrade_timer -= dt;
        if (weapons->upgrade_timer <= 0) {
            weapons_clear_upgrade(weapons);
        }
    }
    
    // Update bullets - traverse linked list and remove expired ones
    bullet_t* current = weapons->bullets_head;
    bullet_t* prev = NULL;
    
    while (current) {
        // Apply bending force to velocity (curves the bullet path)
        current->velocity = Vector3Add(current->velocity, 
            Vector3Scale(current->bend_force, dt));
        
        // Update position with velocity
        current->position = Vector3Add(
            current->position, 
            Vector3Scale(current->velocity, dt)
        );
        current->life -= dt;
        
        if (current->life <= 0) {
            // Remove this bullet from the list
            bullet_t* to_remove = current;
            if (prev) {
                prev->next = current->next;
            } else {
                weapons->bullets_head = current->next;
            }
            current = current->next;
            free(to_remove);
            weapons->bullet_count--;
        } else {
            prev = current;
            current = current->next;
        }
    }
    
    // Update missiles with homing
    for (int i = 0; i < MAX_MISSILES; i++) {
        if (weapons->missiles[i].active) {
            // Home towards target if exists
            if (weapons->missiles[i].target && !weapons->missiles[i].target->collected) {
                Vector3 toTarget = Vector3Subtract(
                    weapons->missiles[i].target->position, 
                    weapons->missiles[i].position
                );
                float targetLength = Vector3Length(toTarget);
                Vector3 targetDir = toTarget;
                if (targetLength > 0.001f) {
                    SAFE_NORMALIZE(targetDir);
                } else {
                    targetDir = (Vector3){0, 0, 1};
                }
                
                // Rockets have much less homing (they're fast enough to not need it)
                float homingStrength = weapons->missiles[i].is_rocket ? 0.5f : 2.0f;
                float targetSpeed = weapons->missiles[i].is_rocket ? ROCKET_MISSILE_SPEED : MISSILE_SPEED;
                
                weapons->missiles[i].velocity = Vector3Lerp(
                    weapons->missiles[i].velocity, 
                    Vector3Scale(targetDir, targetSpeed),
                    CLAMP(homingStrength * dt, 0.0f, 1.0f)
                );
            }
            
            weapons->missiles[i].position = Vector3Add(
                weapons->missiles[i].position, 
                Vector3Scale(weapons->missiles[i].velocity, dt)
            );
            weapons->missiles[i].life -= dt;
            
            if (weapons->missiles[i].life <= 0) {
                weapons->missiles[i].active = false;
            }
        }
    }
    
    // Update lasers
    for (int i = 0; i < MAX_LASERS; i++) {
        if (weapons->lasers[i].active) {
            // Lasers are instant hit, just update life
            weapons->lasers[i].life -= dt;
            
            if (weapons->lasers[i].life <= 0) {
                weapons->lasers[i].active = false;
            }
        }
    }
    
    // Update plasma bolts
    for (int i = 0; i < MAX_PLASMA; i++) {
        if (weapons->plasma[i].active) {
            // Plasma has slight gravity effect
            weapons->plasma[i].velocity.y -= 20.0f * dt;
            
            weapons->plasma[i].position = Vector3Add(
                weapons->plasma[i].position, 
                Vector3Scale(weapons->plasma[i].velocity, dt)
            );
            weapons->plasma[i].life -= dt;
            
            // Plasma grows slightly as it travels
            weapons->plasma[i].size += dt * 2.0f;
            
            if (weapons->plasma[i].life <= 0) {
                weapons->plasma[i].active = false;
            }
        }
    }
}

void weapons_draw(weapons_system_t* weapons) {
    CHECK_NULL(weapons);
    // Draw muzzle flash
    if (weapons->muzzle_flash_timer > 0) {
        float flash_size = 8.0f * weapons->muzzle_flash_timer * 5.0f; // Larger flash
        Color flash_color = WHITE;
        if (weapons->current_weapon == WEAPON_PLASMA) {
            flash_color = PURPLE;
        } else if (weapons->current_weapon == WEAPON_LASER) {
            flash_color = SKYBLUE;
        }
        DrawSphere(weapons->last_fire_position, flash_size, Fade(flash_color, weapons->muzzle_flash_timer * 5.0f));
        DrawSphere(weapons->last_fire_position, flash_size * 0.7f, Fade(YELLOW, weapons->muzzle_flash_timer * 3.0f));
    }
    
    // Draw bullets with enhanced tracer effect - traverse linked list
    bullet_t* bullet = weapons->bullets_head;
    while (bullet) {
        // Enhanced tracer with multiple segments
        for (int j = 0; j < 5; j++) {
            Vector3 vel_norm = bullet->velocity;
            SAFE_NORMALIZE(vel_norm);
            Vector3 segment_start = Vector3Subtract(
                bullet->position, 
                Vector3Scale(vel_norm, j * 3)
            );
            Vector3 segment_end = Vector3Subtract(
                bullet->position, 
                Vector3Scale(vel_norm, (j + 1) * 3)
            );
            float alpha = 1.0f - (j * 0.2f);
            DrawLine3D(segment_start, segment_end, Fade(bullet->color, alpha));
        }
        
        // Glowing bullet head
        DrawSphere(bullet->position, bullet->size * 1.5f, 
                  Fade(bullet->color, 0.8f));
        DrawSphere(bullet->position, bullet->size, WHITE);
        
        bullet = bullet->next;
    }
    
    // Draw missiles
    for (int i = 0; i < MAX_MISSILES; i++) {
        if (weapons->missiles[i].active) {
            if (weapons->missiles[i].is_rocket) {
                // Rocket missile - skinny and fast!
                Vector3 missile_vel_norm = weapons->missiles[i].velocity;
                SAFE_NORMALIZE(missile_vel_norm);
                DrawCapsule(
                    weapons->missiles[i].position, 
                    Vector3Add(weapons->missiles[i].position, 
                        Vector3Scale(missile_vel_norm, -12)),
                    0.8f, 8, 8, ORANGE  // Much skinnier and longer
                );
                
                // Sleek flame trail for rockets
                for (int j = 0; j < 10; j++) {
                    Vector3 smokePos = Vector3Subtract(
                        weapons->missiles[i].position,
                        Vector3Scale(weapons->missiles[i].velocity, j * 0.01f)
                    );
                    Color flameColor = j < 3 ? YELLOW : ORANGE;
                    if (j > 7) flameColor = RED;
                    DrawSphere(smokePos, 1.5f + j * 0.3f, Fade(flameColor, 0.6f - j * 0.05f));
                }
            } else {
                // Normal missile - also skinnier
                Vector3 missile_vel_norm2 = weapons->missiles[i].velocity;
                SAFE_NORMALIZE(missile_vel_norm2);
                DrawCapsule(
                    weapons->missiles[i].position, 
                    Vector3Add(weapons->missiles[i].position, 
                        Vector3Scale(missile_vel_norm2, -8)),
                    0.6f, 8, 8, RED  // Skinnier
                );
                
                // Smaller smoke trail
                for (int j = 0; j < 6; j++) {
                    Vector3 smokePos = Vector3Subtract(
                        weapons->missiles[i].position,
                        Vector3Scale(weapons->missiles[i].velocity, j * 0.015f)
                    );
                    DrawSphere(smokePos, 1.0f + j * 0.3f, Fade(GRAY, 0.4f - j * 0.06f));
                }
            }
            
            // Target indicator (dimmer for rockets since they're less guided)
            if (weapons->missiles[i].target && !weapons->missiles[i].target->collected) {
                float alpha = weapons->missiles[i].is_rocket ? 0.15f : 0.3f;
                DrawLine3D(
                    weapons->missiles[i].position, 
                    weapons->missiles[i].target->position, 
                    Fade(RED, alpha)
                );
            }
        }
    }
    
    // Draw lasers
    for (int i = 0; i < MAX_LASERS; i++) {
        if (weapons->lasers[i].active) {
            // Draw laser beam with glow effect
            float beam_width = 2.0f + sinf(GetTime() * 20.0f) * 0.5f;
            
            // Outer glow
            DrawCylinderEx(weapons->lasers[i].position, weapons->lasers[i].end_position, 
                          beam_width * 2, beam_width * 2, 4, Fade(SKYBLUE, 0.3f));
            // Inner beam
            DrawCylinderEx(weapons->lasers[i].position, weapons->lasers[i].end_position, 
                          beam_width, beam_width, 4, Fade(WHITE, 0.8f));
            // Core
            DrawLine3D(weapons->lasers[i].position, weapons->lasers[i].end_position, SKYBLUE);
            
            // Hit effect at end
            DrawSphere(weapons->lasers[i].end_position, 5.0f, Fade(SKYBLUE, 0.5f));
            DrawSphere(weapons->lasers[i].end_position, 3.0f, WHITE);
        }
    }
    
    // Draw plasma bolts
    for (int i = 0; i < MAX_PLASMA; i++) {
        if (weapons->plasma[i].active) {
            // Plasma ball with energy effect
            float pulse = sinf(GetTime() * 10.0f + i) * 0.3f + 1.0f;
            
            // Outer energy field
            DrawSphere(weapons->plasma[i].position, weapons->plasma[i].size * 2 * pulse, 
                      Fade(PURPLE, 0.3f));
            // Middle layer
            DrawSphere(weapons->plasma[i].position, weapons->plasma[i].size * 1.5f, 
                      Fade(VIOLET, 0.6f));
            // Core
            DrawSphere(weapons->plasma[i].position, weapons->plasma[i].size, WHITE);
            
            // Energy trail
            for (int j = 0; j < 8; j++) {
                Vector3 trail_pos = Vector3Subtract(
                    weapons->plasma[i].position,
                    Vector3Scale(weapons->plasma[i].velocity, j * 0.02f)
                );
                float trail_size = weapons->plasma[i].size * (1.0f - j * 0.1f);
                DrawSphere(trail_pos, trail_size, Fade(PURPLE, 0.5f - j * 0.06f));
            }
        }
    }
}

void weapons_fire_bullet(weapons_system_t* weapons, Vector3 position, Vector3 direction, float yaw) {
    CHECK_NULL(weapons);
    // REMOVED cooldown check for continuous stream
    // if (!weapons_can_fire(weapons, WEAPON_MACHINE_GUN)) return;
    
    // NO COOLDOWN - Continuous firing!
    // But fine-tuning can make it even faster
    float effective_cooldown = 0.0f;  // No cooldown at all
    
    // Add recoil and muzzle flash
    weapons->recoil_amount += 0.5f;
    weapons->muzzle_flash_timer = 0.2f;
    weapons->last_fire_position = position;
    weapons->last_fire_direction = direction;
    
    // Fire bullets from wings with alternating pattern
    static int fire_pattern = 0;
    fire_pattern = (fire_pattern + 1) % 3;
    
    // Determine number of bullets based on upgrade
    int bullet_count = (weapons->current_upgrade == WEAPON_UPGRADE_SPREAD_SHOT) ? 3 : 1;
    
    for (int side = -1; side <= 1; side += 2) {
        // Skip one side based on pattern for more interesting fire (unless spread shot)
        if (weapons->current_upgrade != WEAPON_UPGRADE_SPREAD_SHOT) {
            if (fire_pattern == 1 && side == -1) continue;
            if (fire_pattern == 2 && side == 1) continue;
        }
        
        // Fire multiple bullets for spread shot
        for (int b = 0; b < bullet_count; b++) {
            // Create new bullet dynamically - INFINITE BULLETS!
            bullet_t* new_bullet = malloc(sizeof(bullet_t));
            if (!new_bullet) continue;  // Skip if allocation fails
            
            new_bullet->position = position;
            new_bullet->position.x += sinf((yaw + 90) * DEG2RAD) * side * 8;
            new_bullet->position.z += cosf((yaw + 90) * DEG2RAD) * side * 8;
            
            // Add spread based on upgrade
            float spread = 0;
            if (weapons->current_upgrade == WEAPON_UPGRADE_SPREAD_SHOT) {
                // Spread shot: -15, 0, +15 degrees
                spread = (b - 1) * 0.26f;  // ~15 degrees in radians
            } else {
                // Much tighter spread for continuous stream
                spread = ((float)GetRandomValue(-10, 10) / 100.0f) * 0.01f;  // 5x tighter
            }
            
            Vector3 spread_dir = direction;
            // Apply spread horizontally
            float cos_spread = cosf(spread);
            float sin_spread = sinf(spread);
            float new_x = spread_dir.x * cos_spread - spread_dir.z * sin_spread;
            float new_z = spread_dir.x * sin_spread + spread_dir.z * cos_spread;
            spread_dir.x = new_x;
            spread_dir.z = new_z;
            
            Vector3 norm_spread_dir = spread_dir;
            SAFE_NORMALIZE(norm_spread_dir);
            new_bullet->velocity = Vector3Scale(norm_spread_dir, BULLET_SPEED);
            
            // Set the bend force based on right stick input
            // Create a bend vector perpendicular to the velocity
            Vector3 right = Vector3CrossProduct(spread_dir, (Vector3){0, 1, 0});
            SAFE_NORMALIZE(right);
            Vector3 up = Vector3CrossProduct(right, spread_dir);
            SAFE_NORMALIZE(up);
            
            // Apply bend based on stick input
            new_bullet->bend_force = Vector3Add(
                Vector3Scale(right, weapons->bullet_bend_x * weapons->bend_strength),
                Vector3Scale(up, weapons->bullet_bend_y * weapons->bend_strength)
            );
            
            new_bullet->life = 10.0f;  // LONG RANGE for sniping distant enemies!
            new_bullet->active = true;
            new_bullet->damage = (int)(BULLET_DAMAGE * weapons->damage_multiplier);
            
            // Color based on upgrade
            switch (weapons->current_upgrade) {
                case WEAPON_UPGRADE_RAPID_FIRE:
                    new_bullet->color = ORANGE;
                    new_bullet->size = 2.0f;
                    break;
                case WEAPON_UPGRADE_EXPLOSIVE:
                    new_bullet->color = RED;
                    new_bullet->size = 2.0f;
                    break;
                case WEAPON_UPGRADE_PIERCING:
                    new_bullet->color = PURPLE;
                    new_bullet->size = 2.0f;
                    break;
                case WEAPON_UPGRADE_HOMING:
                    new_bullet->color = SKYBLUE;
                    new_bullet->size = 2.0f;
                    break;
                default:
                    new_bullet->color = YELLOW;
                    new_bullet->size = 2.0f;  // Larger bullets for better visibility
                    break;
            }
            
            // Add to linked list
            new_bullet->next = weapons->bullets_head;
            weapons->bullets_head = new_bullet;
            weapons->bullet_count++;
            
            // NO COOLDOWN for continuous stream
            weapons->fire_cooldown[WEAPON_MACHINE_GUN] = 0.0f;  // Always ready to fire
            weapons->weapon_heat[WEAPON_MACHINE_GUN] += 0.1f;
        }
    }
}

void weapons_fire_missile(weapons_system_t* weapons, Vector3 position, Vector3 direction, float yaw, int side, ring_t* target) {
    CHECK_NULL(weapons);
    if (!weapons_can_fire(weapons, WEAPON_MISSILES)) return;
    
    // Add recoil and muzzle flash
    weapons->recoil_amount += side > 0 ? 2.0f : 1.0f;  // Rockets have more kick
    weapons->muzzle_flash_timer = 0.3f;
    weapons->last_fire_position = position;
    weapons->last_fire_direction = direction;
    
    for (int i = 0; i < MAX_MISSILES; i++) {
        if (!weapons->missiles[i].active) {
            // Offset position based on which wing (side: -1 = left, 1 = right)
            weapons->missiles[i].position = position;
            weapons->missiles[i].position.x += sinf((yaw + 90) * DEG2RAD) * side * 12;  // Wider than bullets
            weapons->missiles[i].position.z += cosf((yaw + 90) * DEG2RAD) * side * 12;
            weapons->missiles[i].position.y -= 2;  // Under wing
            
            // Right missiles are rockets - much faster and longer range!
            if (side > 0) {  // Right side
                weapons->missiles[i].velocity = Vector3Scale(direction, ROCKET_MISSILE_SPEED);
                weapons->missiles[i].life = 20.0f;  // Super long range!
                weapons->missiles[i].is_rocket = true;
                weapons->missiles[i].damage = MISSILE_DAMAGE * 2;  // Rockets do more damage
            } else {  // Left side - normal missile
                weapons->missiles[i].velocity = Vector3Scale(direction, MISSILE_SPEED);
                weapons->missiles[i].life = 12.0f;  // Also longer range
                weapons->missiles[i].is_rocket = false;
                weapons->missiles[i].damage = MISSILE_DAMAGE;
            }
            
            weapons->missiles[i].active = true;
            weapons->missiles[i].target = target;
            
            // Update cooldown
            weapons->fire_cooldown[WEAPON_MISSILES] = MISSILE_RATE;
            weapons->weapon_heat[WEAPON_MISSILES] += 0.3f;
            
            break;
        }
    }
}

// New weapon firing functions
void weapons_fire_laser(weapons_system_t* weapons, Vector3 position, Vector3 direction, float yaw) {
    CHECK_NULL(weapons);
    if (!weapons_can_fire(weapons, WEAPON_LASER)) return;
    
    // Lasers are instant hit - trace to find hit point
    for (int i = 0; i < MAX_LASERS; i++) {
        if (!weapons->lasers[i].active) {
            weapons->lasers[i].position = position;
            weapons->lasers[i].end_position = Vector3Add(position, Vector3Scale(direction, 500.0f));
            weapons->lasers[i].life = 0.1f;  // Short burst
            weapons->lasers[i].active = true;
            weapons->lasers[i].damage = LASER_DAMAGE;
            
            // Laser effects
            weapons->recoil_amount += 0.3f;
            weapons->muzzle_flash_timer = 0.15f;
            weapons->last_fire_position = position;
            weapons->fire_cooldown[WEAPON_LASER] = LASER_RATE;
            weapons->weapon_heat[WEAPON_LASER] += 0.2f;
            
            break;
        }
    }
}

void weapons_fire_plasma(weapons_system_t* weapons, Vector3 position, Vector3 direction, float yaw) {
    CHECK_NULL(weapons);
    if (!weapons_can_fire(weapons, WEAPON_PLASMA)) return;
    
    for (int i = 0; i < MAX_PLASMA; i++) {
        if (!weapons->plasma[i].active) {
            weapons->plasma[i].position = position;
            weapons->plasma[i].velocity = Vector3Scale(direction, PLASMA_SPEED);
            weapons->plasma[i].life = 4.0f;
            weapons->plasma[i].active = true;
            weapons->plasma[i].damage = PLASMA_DAMAGE;
            weapons->plasma[i].size = 3.0f;
            
            // Plasma has big recoil
            weapons->recoil_amount += 3.0f;
            weapons->muzzle_flash_timer = 0.4f;
            weapons->last_fire_position = position;
            weapons->fire_cooldown[WEAPON_PLASMA] = PLASMA_RATE;
            weapons->weapon_heat[WEAPON_PLASMA] += 0.5f;
            
            break;
        }
    }
}

void weapons_fire_railgun(weapons_system_t* weapons, Vector3 position, Vector3 direction, float yaw) {
    CHECK_NULL(weapons);
    if (!weapons_can_fire(weapons, WEAPON_RAILGUN)) return;
    
    // Railgun is a powerful instant hit weapon
    for (int i = 0; i < MAX_LASERS; i++) {
        if (!weapons->lasers[i].active) {
            weapons->lasers[i].position = position;
            weapons->lasers[i].end_position = Vector3Add(position, Vector3Scale(direction, 1000.0f));
            weapons->lasers[i].life = 0.5f;  // Longer visible trail
            weapons->lasers[i].active = true;
            weapons->lasers[i].damage = RAILGUN_DAMAGE;
            weapons->lasers[i].charge = 1.0f;  // Full power shot
            
            // Massive recoil
            weapons->recoil_amount += 5.0f;
            weapons->muzzle_flash_timer = 0.6f;
            weapons->last_fire_position = position;
            weapons->fire_cooldown[WEAPON_RAILGUN] = 1.5f;  // Slow fire rate
            weapons->weapon_heat[WEAPON_RAILGUN] += 1.0f;
            
            break;
        }
    }
}

void weapons_fire_spread(weapons_system_t* weapons, Vector3 position, Vector3 direction, float yaw) {
    CHECK_NULL(weapons);
    if (!weapons_can_fire(weapons, WEAPON_SPREAD)) return;
    
    // Fire multiple bullets in a spread pattern
    for (int spread = -2; spread <= 2; spread++) {
        // Create new bullet dynamically
        bullet_t* new_bullet = malloc(sizeof(bullet_t));
        if (!new_bullet) continue;
        
        // Fixed spread angle for spread weapon
        float angle = spread * 0.1f;  // Spread angle
        Vector3 spread_dir = direction;
        
        // Rotate direction by spread angle
        float cos_a = cosf(angle);
        float sin_a = sinf(angle);
        spread_dir.x = direction.x * cos_a - direction.z * sin_a;
        spread_dir.z = direction.x * sin_a + direction.z * cos_a;
        
        new_bullet->position = position;
        Vector3 norm_spread = spread_dir;
        SAFE_NORMALIZE(norm_spread);
        new_bullet->velocity = Vector3Scale(norm_spread, BULLET_SPEED * 0.8f);
        
        // Apply same bend force to spread bullets
        Vector3 right = Vector3CrossProduct(spread_dir, (Vector3){0, 1, 0});
        SAFE_NORMALIZE(right);
        Vector3 up = Vector3CrossProduct(right, spread_dir);
        SAFE_NORMALIZE(up);
        new_bullet->bend_force = Vector3Add(
            Vector3Scale(right, weapons->bullet_bend_x * weapons->bend_strength),
            Vector3Scale(up, weapons->bullet_bend_y * weapons->bend_strength)
        );
        
        new_bullet->life = 2.0f;
        new_bullet->active = true;
        new_bullet->damage = BULLET_DAMAGE / 2;  // Less damage per bullet
        new_bullet->color = ORANGE;
        new_bullet->size = 0.8f;
        
        // Add to linked list
        new_bullet->next = weapons->bullets_head;
        weapons->bullets_head = new_bullet;
        weapons->bullet_count++;
    }
    
    // Shotgun-like recoil
    weapons->recoil_amount += 2.5f;
    weapons->muzzle_flash_timer = 0.3f;
    weapons->last_fire_position = position;
    weapons->fire_cooldown[WEAPON_SPREAD] = 0.6f;
    weapons->weapon_heat[WEAPON_SPREAD] += 0.4f;
}

// Weapon management functions
void weapons_switch_weapon(weapons_system_t* weapons, weapon_type_t type) {
    CHECK_NULL(weapons);
    if (type >= 0 && type < WEAPON_COUNT) {
        weapons->current_weapon = type;
    }
}

void weapons_cycle_weapon(weapons_system_t* weapons, int direction) {
    CHECK_NULL(weapons);
    int new_weapon = (int)weapons->current_weapon + direction;
    if (new_weapon < 0) new_weapon = WEAPON_COUNT - 1;
    if (new_weapon >= WEAPON_COUNT) new_weapon = 0;
    weapons->current_weapon = (weapon_type_t)new_weapon;
}

bool weapons_can_fire(weapons_system_t* weapons, weapon_type_t type) {
    CHECK_NULL_RETURN(weapons, false);
    // Check cooldown
    if (weapons->fire_cooldown[type] > 0) return false;
    
    // Check heat (weapons overheat at 2.0)
    if (weapons->weapon_heat[type] > 2.0f) return false;
    
    // Check ammo if not unlimited
    if (weapons->ammo[type] >= 0 && weapons->ammo[type] == 0) return false;
    
    return true;
}

float weapons_get_heat(weapons_system_t* weapons, weapon_type_t type) {
    CHECK_NULL_RETURN(weapons, 0.0f);
    if (type < 0 || type >= WEAPON_COUNT) return 0.0f;
    return SAFE_DIV_F(weapons->weapon_heat[type], 2.0f);  // Normalize to 0-1
}

int weapons_get_ammo(weapons_system_t* weapons, weapon_type_t type) {
    CHECK_NULL_RETURN(weapons, 0);
    if (type < 0 || type >= WEAPON_COUNT) return 0;
    return weapons->ammo[type];
}

// Query functions
int weapons_get_active_bullets(weapons_system_t* weapons) {
    CHECK_NULL_RETURN(weapons, 0);
    return weapons->bullet_count;
}

int weapons_get_active_missiles(weapons_system_t* weapons) {
    CHECK_NULL_RETURN(weapons, 0);
    int count = 0;
    for (int i = 0; i < MAX_MISSILES; i++) {
        if (weapons->missiles[i].active) count++;
    }
    return count;
}

int weapons_get_active_lasers(weapons_system_t* weapons) {
    CHECK_NULL_RETURN(weapons, 0);
    int count = 0;
    for (int i = 0; i < MAX_LASERS; i++) {
        if (weapons->lasers[i].active) count++;
    }
    return count;
}

int weapons_get_active_plasma(weapons_system_t* weapons) {
    CHECK_NULL_RETURN(weapons, 0);
    int count = 0;
    for (int i = 0; i < MAX_PLASMA; i++) {
        if (weapons->plasma[i].active) count++;
    }
    return count;
}

// Effect functions
float weapons_get_recoil(weapons_system_t* weapons) {
    CHECK_NULL_RETURN(weapons, 0.0f);
    return weapons->recoil_amount;
}

bool weapons_has_muzzle_flash(weapons_system_t* weapons) {
    CHECK_NULL_RETURN(weapons, false);
    return weapons->muzzle_flash_timer > 0;
}

Vector3 weapons_get_muzzle_position(weapons_system_t* weapons) {
    CHECK_NULL_RETURN(weapons, ((Vector3){0, 0, 0}));
    return weapons->last_fire_position;
}

// Upgrade system implementation
void weapons_apply_upgrade(weapons_system_t* weapons, weapon_upgrade_t upgrade, float duration) {
    CHECK_NULL(weapons);
    
    weapons->current_upgrade = upgrade;
    weapons->upgrade_timer = duration;
    
    // Apply upgrade effects
    switch (upgrade) {
        case WEAPON_UPGRADE_RAPID_FIRE:
            weapons->fire_rate_multiplier = 3.0f;
            weapons->damage_multiplier = 1.0f;
            break;
            
        case WEAPON_UPGRADE_SPREAD_SHOT:
            weapons->fire_rate_multiplier = 1.0f;
            weapons->damage_multiplier = 0.8f;  // Slightly less damage per bullet
            break;
            
        case WEAPON_UPGRADE_EXPLOSIVE:
            weapons->fire_rate_multiplier = 0.7f;  // Slower fire rate
            weapons->damage_multiplier = 2.5f;     // Much more damage
            break;
            
        case WEAPON_UPGRADE_PIERCING:
            weapons->fire_rate_multiplier = 1.0f;
            weapons->damage_multiplier = 1.5f;
            break;
            
        case WEAPON_UPGRADE_HOMING:
            weapons->fire_rate_multiplier = 0.8f;
            weapons->damage_multiplier = 1.2f;
            break;
            
        default:
            weapons->fire_rate_multiplier = 1.0f;
            weapons->damage_multiplier = 1.0f;
            break;
    }
}

void weapons_clear_upgrade(weapons_system_t* weapons) {
    CHECK_NULL(weapons);
    
    weapons->current_upgrade = WEAPON_UPGRADE_NONE;
    weapons->upgrade_timer = 0.0f;
    weapons->damage_multiplier = 1.0f;
    weapons->fire_rate_multiplier = 1.0f;
}

const char* weapons_get_upgrade_name(weapon_upgrade_t upgrade) {
    switch (upgrade) {
        case WEAPON_UPGRADE_RAPID_FIRE: return "Rapid Fire";
        case WEAPON_UPGRADE_SPREAD_SHOT: return "Spread Shot";
        case WEAPON_UPGRADE_EXPLOSIVE: return "Explosive";
        case WEAPON_UPGRADE_PIERCING: return "Piercing";
        case WEAPON_UPGRADE_HOMING: return "Homing";
        default: return "None";
    }
}

Color weapons_get_upgrade_color(weapon_upgrade_t upgrade) {
    switch (upgrade) {
        case WEAPON_UPGRADE_RAPID_FIRE: return ORANGE;
        case WEAPON_UPGRADE_SPREAD_SHOT: return YELLOW;
        case WEAPON_UPGRADE_EXPLOSIVE: return RED;
        case WEAPON_UPGRADE_PIERCING: return PURPLE;
        case WEAPON_UPGRADE_HOMING: return SKYBLUE;
        default: return WHITE;
    }
}

// Gun fine-tuning function - bends the bullet stream
void weapons_set_fine_tuning(weapons_system_t* weapons, float x_adjust, float y_adjust) {
    CHECK_NULL(weapons);
    
    // Right stick directly controls bullet bending
    // X axis bends bullets left/right
    weapons->bullet_bend_x = x_adjust;  // -1.0 to 1.0
    
    // Y axis bends bullets up/down
    weapons->bullet_bend_y = -y_adjust;  // Inverted for intuitive control
    
    // Clamp values
    weapons->bullet_bend_x = CLAMP(weapons->bullet_bend_x, -1.0f, 1.0f);
    weapons->bullet_bend_y = CLAMP(weapons->bullet_bend_y, -1.0f, 1.0f);
}
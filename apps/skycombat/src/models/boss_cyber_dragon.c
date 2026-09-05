/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/models/boss_cyber_dragon.h"
#include <raymath.h>
#include <stdlib.h>
#include <math.h>
#include <stdio.h>

#define DRAGON_MAX_HEALTH 1000.0f
#define DRAGON_SEGMENT_COUNT 20
#define DRAGON_BASE_SPEED 30.0f
#define DRAGON_BOOST_SPEED 60.0f
#define DRAGON_TURN_RATE 45.0f

cyber_dragon_t* cyber_dragon_create(Vector3 spawn_pos) {
    cyber_dragon_t* dragon = calloc(1, sizeof(cyber_dragon_t));
    if (!dragon) return NULL;
    
    // Initialize stats
    dragon->max_health = DRAGON_MAX_HEALTH;
    dragon->health = DRAGON_MAX_HEALTH;
    dragon->phase = DRAGON_PHASE_INTRO;
    dragon->current_attack = DRAGON_IDLE;
    
    // Position
    dragon->position = spawn_pos;
    dragon->target_position = spawn_pos;
    dragon->speed = DRAGON_BASE_SPEED;
    dragon->turn_rate = DRAGON_TURN_RATE;
    
    // Initialize body segments
    dragon->segment_spacing = 8.0f;
    for (int i = 0; i < DRAGON_SEGMENT_COUNT; i++) {
        dragon->segments[i].position = (Vector3){
            spawn_pos.x - i * dragon->segment_spacing,
            spawn_pos.y,
            spawn_pos.z
        };
        dragon->segments[i].scale = 1.0f - (i * 0.03f);  // Taper towards tail
        dragon->segments[i].rotation = QuaternionIdentity();
    }
    
    // Colors
    dragon->base_color = (Color){100, 200, 255, 255};  // Cyber blue
    dragon->rage_color = (Color){255, 50, 50, 255};    // Rage red
    dragon->glow_intensity = 1.0f;
    
    // Weak points (head, middle, tail)
    dragon->weak_points[0] = (Vector3){0, 5, 0};    // Head offset
    dragon->weak_points[1] = (Vector3){0, 0, 0};    // Middle offset
    dragon->weak_points[2] = (Vector3){0, -3, 0};   // Tail offset
    dragon->weak_points_exposed = false;
    
    // AI
    dragon->think_timer = 0;
    dragon->aggression = 0.5f;
    
    return dragon;
}

void cyber_dragon_destroy(cyber_dragon_t* dragon) {
    free(dragon);
}

void cyber_dragon_update(cyber_dragon_t* dragon, Vector3 player_pos, float dt) {
    if (!dragon) return;
    
    // Update timers
    if (dragon->attack_timer > 0) dragon->attack_timer -= dt;
    if (dragon->damage_flash > 0) dragon->damage_flash -= dt;
    if (dragon->weak_point_timer > 0) dragon->weak_point_timer -= dt;
    if (dragon->roar_timer > 0) dragon->roar_timer -= dt;
    
    // Phase management
    cyber_dragon_update_phase(dragon);
    
    // Movement AI
    if (dragon->phase != DRAGON_PHASE_DEATH) {
        // Update think timer
        dragon->think_timer += dt;
        if (dragon->think_timer > 2.0f) {
            dragon->think_timer = 0;
            dragon->last_player_pos = player_pos;
            
            // Choose new attack based on phase and distance
            float dist = Vector3Distance(dragon->position, player_pos);
            
            if (dragon->current_attack == DRAGON_IDLE) {
                if (dist > 100) {
                    cyber_dragon_start_attack(dragon, DRAGON_CHARGING);
                } else if (dist < 50) {
                    cyber_dragon_start_attack(dragon, DRAGON_TAIL_WHIP);
                } else {
                    // Random attack selection based on phase
                    int attack_choice = rand() % 4;
                    switch (dragon->phase) {
                        case DRAGON_PHASE_AERIAL:
                            if (attack_choice == 0) cyber_dragon_start_attack(dragon, DRAGON_LASER_SWEEP);
                            else if (attack_choice == 1) cyber_dragon_start_attack(dragon, DRAGON_MISSILE_BARRAGE);
                            else cyber_dragon_start_attack(dragon, DRAGON_CIRCLING);
                            break;
                            
                        case DRAGON_PHASE_RAGE:
                            if (attack_choice == 0) cyber_dragon_start_attack(dragon, DRAGON_PLASMA_STORM);
                            else if (attack_choice == 1) cyber_dragon_start_attack(dragon, DRAGON_SUMMON_DRONES);
                            else cyber_dragon_start_attack(dragon, DRAGON_TELEPORT);
                            break;
                            
                        case DRAGON_PHASE_FINAL:
                            if (rand() % 3 == 0) cyber_dragon_start_attack(dragon, DRAGON_ULTIMATE);
                            else cyber_dragon_start_attack(dragon, DRAGON_PLASMA_STORM);
                            break;
                            
                        default:
                            break;
                    }
                }
            }
        }
        
        // Update current attack
        cyber_dragon_update_attack(dragon, player_pos, dt);
        
        // Smooth movement towards target
        Vector3 direction = Vector3Subtract(dragon->target_position, dragon->position);
        float distance = Vector3Length(direction);
        
        if (distance > 1.0f) {
            direction = Vector3Normalize(direction);
            float move_speed = dragon->speed * dt;
            
            if (distance < move_speed) {
                dragon->position = dragon->target_position;
            } else {
                dragon->position = Vector3Add(dragon->position, Vector3Scale(direction, move_speed));
            }
            
            // Update rotation to face movement direction
            float target_yaw = atan2f(direction.x, direction.z) * RAD2DEG;
            dragon->rotation = QuaternionFromEuler(0, target_yaw * DEG2RAD, 0);
        }
        
        // Update body segments (serpentine motion)
        dragon->body_wave_offset += dt * 2.0f;
        
        for (int i = 0; i < DRAGON_SEGMENT_COUNT; i++) {
            if (i == 0) {
                // Head follows main position
                dragon->segments[i].position = dragon->position;
                dragon->segments[i].rotation = dragon->rotation;
            } else {
                // Each segment follows the previous one
                Vector3 target = dragon->segments[i-1].position;
                Vector3 to_target = Vector3Subtract(target, dragon->segments[i].position);
                float dist = Vector3Length(to_target);
                
                if (dist > dragon->segment_spacing) {
                    to_target = Vector3Normalize(to_target);
                    Vector3 new_pos = Vector3Add(target, Vector3Scale(to_target, -dragon->segment_spacing));
                    
                    // Add wave motion
                    float wave = sinf(dragon->body_wave_offset + i * 0.5f) * 2.0f;
                    new_pos.y += wave;
                    
                    dragon->segments[i].position = new_pos;
                    
                    // Orient segment
                    float yaw = atan2f(to_target.x, to_target.z) * RAD2DEG;
                    dragon->segments[i].rotation = QuaternionFromEuler(0, yaw * DEG2RAD, wave * 0.1f);
                }
            }
        }
    }
    
    // Update visual effects
    dragon->glow_intensity = 1.0f + sinf(GetTime() * 3.0f) * 0.3f;
    
    // Expose weak points periodically
    if (!dragon->weak_points_exposed && dragon->weak_point_timer <= 0) {
        if (rand() % 100 < 5) {  // 5% chance per frame
            dragon->weak_points_exposed = true;
            dragon->weak_point_timer = 5.0f;  // Exposed for 5 seconds
        }
    } else if (dragon->weak_points_exposed && dragon->weak_point_timer <= 0) {
        dragon->weak_points_exposed = false;
        dragon->weak_point_timer = 10.0f;  // Hidden for 10 seconds
    }
}

void cyber_dragon_start_attack(cyber_dragon_t* dragon, dragon_attack_t attack) {
    if (!dragon) return;
    
    dragon->current_attack = attack;
    dragon->attack_timer = 0;
    
    switch (attack) {
        case DRAGON_LASER_SWEEP:
            dragon->laser_charge = 0;
            dragon->laser_angle = -45.0f;
            break;
            
        case DRAGON_MISSILE_BARRAGE:
            dragon->missiles_remaining = 12;
            break;
            
        case DRAGON_PLASMA_STORM:
            dragon->screen_shake_intensity = 2.0f;
            break;
            
        case DRAGON_ULTIMATE:
            dragon->roar_timer = 2.0f;
            dragon->screen_shake_intensity = 5.0f;
            break;
            
        default:
            break;
    }
}

void cyber_dragon_update_attack(cyber_dragon_t* dragon, Vector3 player_pos, float dt) {
    if (!dragon) return;
    
    switch (dragon->current_attack) {
        case DRAGON_CIRCLING:
            // Circle around player
            {
                float angle = GetTime() * 0.5f;
                float radius = 80.0f;
                dragon->target_position = (Vector3){
                    player_pos.x + cosf(angle) * radius,
                    player_pos.y + 20.0f,
                    player_pos.z + sinf(angle) * radius
                };
                
                if (dragon->attack_timer > 5.0f) {
                    dragon->current_attack = DRAGON_IDLE;
                }
            }
            break;
            
        case DRAGON_CHARGING:
            // Direct charge at player
            {
                if (dragon->attack_timer < 1.0f) {
                    // Wind up
                    dragon->target_position = Vector3Add(dragon->position, 
                        Vector3Scale(Vector3Subtract(dragon->position, player_pos), 0.5f));
                } else if (dragon->attack_timer < 2.0f) {
                    // Charge!
                    dragon->target_position = player_pos;
                    dragon->speed = DRAGON_BOOST_SPEED;
                } else {
                    dragon->speed = DRAGON_BASE_SPEED;
                    dragon->current_attack = DRAGON_IDLE;
                }
            }
            break;
            
        case DRAGON_LASER_SWEEP:
            // Sweeping laser breath
            {
                dragon->laser_charge += dt;
                if (dragon->laser_charge > 1.0f) {
                    dragon->laser_angle += dt * 30.0f;  // 30 degrees per second
                    
                    if (dragon->laser_angle > 45.0f) {
                        dragon->current_attack = DRAGON_IDLE;
                    }
                }
            }
            break;
            
        case DRAGON_TAIL_WHIP:
            // Quick tail attack
            {
                if (dragon->attack_timer > 1.0f) {
                    dragon->current_attack = DRAGON_IDLE;
                }
            }
            break;
            
        case DRAGON_PLASMA_STORM:
            // Area denial attack
            {
                if (dragon->attack_timer > 5.0f) {
                    dragon->current_attack = DRAGON_IDLE;
                    dragon->screen_shake_intensity = 0;
                }
            }
            break;
            
        case DRAGON_ULTIMATE:
            // Screen-filling ultimate attack
            {
                if (dragon->attack_timer > 8.0f) {
                    dragon->current_attack = DRAGON_IDLE;
                    dragon->screen_shake_intensity = 0;
                }
            }
            break;
            
        default:
            break;
    }
    
    dragon->attack_timer += dt;
}

void cyber_dragon_take_damage(cyber_dragon_t* dragon, float damage, Vector3 hit_pos) {
    if (!dragon || dragon->phase == DRAGON_PHASE_DEATH) return;
    
    // Check if hit a weak point
    bool weak_point_hit = false;
    if (dragon->weak_points_exposed) {
        for (int i = 0; i < 3; i++) {
            Vector3 weak_pos = Vector3Add(dragon->segments[i * 7].position, dragon->weak_points[i]);
            if (Vector3Distance(hit_pos, weak_pos) < 10.0f) {
                weak_point_hit = true;
                damage *= 3.0f;  // Triple damage on weak points
                break;
            }
        }
    }
    
    dragon->health -= damage;
    dragon->damage_flash = 0.3f;
    dragon->consecutive_hits++;
    
    // Increase aggression when hit
    dragon->aggression = fminf(dragon->aggression + 0.1f, 1.0f);
    
    // Phase transitions
    float health_percent = dragon->health / dragon->max_health;
    
    if (health_percent <= 0) {
        cyber_dragon_enter_phase(dragon, DRAGON_PHASE_DEATH);
    } else if (health_percent <= 0.25f && dragon->phase != DRAGON_PHASE_FINAL) {
        cyber_dragon_enter_phase(dragon, DRAGON_PHASE_FINAL);
    } else if (health_percent <= 0.5f && dragon->phase == DRAGON_PHASE_AERIAL) {
        cyber_dragon_enter_phase(dragon, DRAGON_PHASE_RAGE);
    }
    
    // Roar on weak point hit
    if (weak_point_hit) {
        dragon->roar_timer = 1.0f;
        dragon->screen_shake_intensity = 3.0f;
    }
}

void cyber_dragon_enter_phase(cyber_dragon_t* dragon, dragon_phase_t phase) {
    if (!dragon) return;
    
    dragon->phase = phase;
    dragon->phase_transitioning = true;
    dragon->transition_timer = 2.0f;
    
    switch (phase) {
        case DRAGON_PHASE_AERIAL:
            printf("CYBER DRAGON: AERIAL COMBAT PHASE!\n");
            break;
            
        case DRAGON_PHASE_RAGE:
            printf("CYBER DRAGON: RAGE MODE ACTIVATED!\n");
            dragon->speed *= 1.5f;
            dragon->turn_rate *= 1.5f;
            dragon->aggression = 0.8f;
            break;
            
        case DRAGON_PHASE_FINAL:
            printf("CYBER DRAGON: FINAL DESPERATION PHASE!\n");
            dragon->speed *= 2.0f;
            dragon->aggression = 1.0f;
            dragon->weak_points_exposed = true;  // Permanent weak points
            break;
            
        case DRAGON_PHASE_DEATH:
            printf("CYBER DRAGON: DEFEATED!\n");
            dragon->current_attack = DRAGON_IDLE;
            cyber_dragon_spawn_death_explosion(dragon);
            break;
            
        default:
            break;
    }
}

void cyber_dragon_update_phase(cyber_dragon_t* dragon) {
    if (!dragon) return;
    
    if (dragon->phase_transitioning) {
        dragon->transition_timer -= GetFrameTime();
        if (dragon->transition_timer <= 0) {
            dragon->phase_transitioning = false;
            
            if (dragon->phase == DRAGON_PHASE_INTRO) {
                cyber_dragon_enter_phase(dragon, DRAGON_PHASE_AERIAL);
            }
        }
    }
}

void cyber_dragon_draw(cyber_dragon_t* dragon, Camera3D camera) {
    if (!dragon) return;
    
    // Determine color based on phase and damage
    Color body_color = dragon->base_color;
    
    if (dragon->phase == DRAGON_PHASE_RAGE || dragon->phase == DRAGON_PHASE_FINAL) {
        body_color = ColorLerp(dragon->base_color, dragon->rage_color, 
                              dragon->phase == DRAGON_PHASE_FINAL ? 0.8f : 0.5f);
    }
    
    if (dragon->damage_flash > 0) {
        body_color = WHITE;
    }
    
    // Draw body segments
    for (int i = DRAGON_SEGMENT_COUNT - 1; i >= 0; i--) {
        float segment_glow = dragon->glow_intensity * (1.0f - i * 0.03f);
        
        // Body segment
        DrawCube(dragon->segments[i].position, 
                6.0f * dragon->segments[i].scale,
                8.0f * dragon->segments[i].scale,
                6.0f * dragon->segments[i].scale,
                body_color);
        
        // Cybernetic details - glowing lines
        if (i % 2 == 0) {
            Color glow_color = (Color){0, 255, 255, (unsigned char)(segment_glow * 200)};
            DrawCubeWires(dragon->segments[i].position,
                         6.5f * dragon->segments[i].scale,
                         8.5f * dragon->segments[i].scale,
                         6.5f * dragon->segments[i].scale,
                         glow_color);
        }
        
        // Spikes on back
        if (i % 3 == 0) {
            Vector3 spike_pos = Vector3Add(dragon->segments[i].position, (Vector3){0, 4, 0});
            // Draw spike as elongated cube instead of cone
            DrawCube(spike_pos, 2.0f, 6.0f, 2.0f, body_color);
        }
    }
    
    // Draw head (special treatment)
    Vector3 head_pos = dragon->segments[0].position;
    
    // Main head
    DrawSphere(head_pos, 8.0f, body_color);
    
    // Eyes (glowing)
    Color eye_color = dragon->phase == DRAGON_PHASE_RAGE ? RED : SKYBLUE;
    eye_color.a = (unsigned char)(dragon->glow_intensity * 255);
    
    Vector3 left_eye = Vector3Add(head_pos, (Vector3){-3, 2, 5});
    Vector3 right_eye = Vector3Add(head_pos, (Vector3){3, 2, 5});
    DrawSphere(left_eye, 1.5f, eye_color);
    DrawSphere(right_eye, 1.5f, eye_color);
    
    // Jaw
    Vector3 jaw_pos = Vector3Add(head_pos, (Vector3){0, -2, 3});
    DrawCube(jaw_pos, 6, 3, 8, body_color);
    
    // Horns
    Vector3 left_horn = Vector3Add(head_pos, (Vector3){-4, 4, -2});
    Vector3 right_horn = Vector3Add(head_pos, (Vector3){4, 4, -2});
    // Draw horns as elongated cubes
    DrawCube(left_horn, 1.5f, 6.0f, 1.5f, body_color);
    DrawCube(right_horn, 1.5f, 6.0f, 1.5f, body_color);
    
    // Draw weak points when exposed
    if (dragon->weak_points_exposed) {
        for (int i = 0; i < 3; i++) {
            Vector3 weak_pos = Vector3Add(dragon->segments[i * 7].position, dragon->weak_points[i]);
            
            // Pulsing red sphere
            float pulse = sinf(GetTime() * 5.0f) * 0.5f + 0.5f;
            DrawSphere(weak_pos, 3.0f + pulse, RED);
            DrawSphereWires(weak_pos, 3.5f + pulse, 8, 8, WHITE);
        }
    }
    
    // Draw laser attack
    if (dragon->current_attack == DRAGON_LASER_SWEEP && dragon->laser_charge > 1.0f) {
        Vector3 laser_start = Vector3Add(head_pos, (Vector3){0, -2, 8});
        
        // Calculate laser end based on sweep angle
        float laser_length = 200.0f;
        float angle_rad = dragon->laser_angle * DEG2RAD;
        Vector3 laser_dir = {
            sinf(angle_rad),
            -0.2f,  // Slight downward angle
            cosf(angle_rad)
        };
        laser_dir = Vector3Normalize(laser_dir);
        Vector3 laser_end = Vector3Add(laser_start, Vector3Scale(laser_dir, laser_length));
        
        // Draw laser beam
        DrawCylinder(laser_start, 2.0f, 2.0f, laser_length, 8, RED);
        DrawSphere(laser_end, 5.0f, ORANGE);
        
        // Charge effect
        float charge_intensity = fminf(dragon->laser_charge, 1.0f);
        DrawSphere(laser_start, 5.0f * charge_intensity, ORANGE);
    }
}

void cyber_dragon_draw_effects(cyber_dragon_t* dragon, Camera3D camera) {
    if (!dragon) return;
    
    // Plasma storm effect
    if (dragon->current_attack == DRAGON_PLASMA_STORM) {
        float storm_radius = dragon->attack_timer * 30.0f;
        
        for (int i = 0; i < 20; i++) {
            float angle = (i / 20.0f) * PI * 2.0f + GetTime();
            Vector3 plasma_pos = {
                dragon->position.x + cosf(angle) * storm_radius,
                dragon->position.y + sinf(GetTime() * 3.0f + i) * 10.0f,
                dragon->position.z + sinf(angle) * storm_radius
            };
            
            DrawSphere(plasma_pos, 3.0f, PURPLE);
            
            // Lightning between plasma balls
            if (i % 2 == 0 && i < 19) {
                float next_angle = ((i + 1) / 20.0f) * PI * 2.0f + GetTime();
                Vector3 next_pos = {
                    dragon->position.x + cosf(next_angle) * storm_radius,
                    dragon->position.y + sinf(GetTime() * 3.0f + i + 1) * 10.0f,
                    dragon->position.z + sinf(next_angle) * storm_radius
                };
                
                DrawLine3D(plasma_pos, next_pos, VIOLET);
            }
        }
    }
    
    // Ultimate attack effect
    if (dragon->current_attack == DRAGON_ULTIMATE) {
        // Growing sphere of destruction
        float sphere_radius = dragon->attack_timer * 50.0f;
        Color destruction_color = (Color){255, 100, 0, 50};
        
        // Multiple expanding rings
        for (int i = 0; i < 5; i++) {
            float ring_radius = sphere_radius - i * 10.0f;
            if (ring_radius > 0) {
                DrawCircle3D(dragon->position, ring_radius, (Vector3){1, 0, 0}, 0, destruction_color);
                DrawCircle3D(dragon->position, ring_radius, (Vector3){0, 1, 0}, 0, destruction_color);
                DrawCircle3D(dragon->position, ring_radius, (Vector3){0, 0, 1}, 0, destruction_color);
            }
        }
        
        // Energy buildup at center
        float buildup = fminf(dragon->attack_timer / 3.0f, 1.0f);
        DrawSphere(dragon->position, 10.0f * buildup, ORANGE);
    }
}

void cyber_dragon_draw_health_bar(cyber_dragon_t* dragon) {
    if (!dragon || dragon->phase == DRAGON_PHASE_DEATH) return;
    
    // Boss health bar at top of screen
    int bar_width = 600;
    int bar_height = 30;
    int x = (GetScreenWidth() - bar_width) / 2;
    int y = 20;
    
    // Background
    DrawRectangle(x - 2, y - 2, bar_width + 4, bar_height + 4, BLACK);
    DrawRectangle(x, y, bar_width, bar_height, DARKGRAY);
    
    // Health fill
    float health_percent = dragon->health / dragon->max_health;
    int fill_width = (int)(bar_width * health_percent);
    
    Color health_color;
    if (health_percent > 0.5f) health_color = GREEN;
    else if (health_percent > 0.25f) health_color = ORANGE;
    else health_color = RED;
    
    DrawRectangle(x, y, fill_width, bar_height, health_color);
    
    // Phase markers
    DrawLine(x + bar_width / 2, y, x + bar_width / 2, y + bar_height, WHITE);
    DrawLine(x + bar_width / 4, y, x + bar_width / 4, y + bar_height, WHITE);
    
    // Boss name
    const char* phase_name = "";
    switch (dragon->phase) {
        case DRAGON_PHASE_AERIAL: phase_name = " - AERIAL PHASE"; break;
        case DRAGON_PHASE_RAGE: phase_name = " - RAGE MODE"; break;
        case DRAGON_PHASE_FINAL: phase_name = " - FINAL PHASE"; break;
        default: break;
    }
    
    char boss_text[64];
    snprintf(boss_text, sizeof(boss_text), "CYBER DRAGON%s", phase_name);
    DrawText(boss_text, x + 10, y + 5, 20, WHITE);
    
    // Current attack indicator
    if (dragon->current_attack != DRAGON_IDLE) {
        const char* attack_name = "";
        switch (dragon->current_attack) {
            case DRAGON_LASER_SWEEP: attack_name = "LASER BREATH"; break;
            case DRAGON_MISSILE_BARRAGE: attack_name = "MISSILE BARRAGE"; break;
            case DRAGON_PLASMA_STORM: attack_name = "PLASMA STORM"; break;
            case DRAGON_ULTIMATE: attack_name = "ULTIMATE ATTACK"; break;
            default: break;
        }
        
        if (attack_name[0]) {
            DrawText(attack_name, x + bar_width - 150, y + 5, 20, YELLOW);
        }
    }
}

void cyber_dragon_spawn_death_explosion(cyber_dragon_t* dragon) {
    if (!dragon) return;
    
    // This would trigger a massive explosion sequence
    // In a full implementation, this would spawn hundreds of particles,
    // screen effects, and a victory sequence
    
    printf("CYBER DRAGON DEATH EXPLOSION!\n");
}

bool cyber_dragon_check_collision(cyber_dragon_t* dragon, Vector3 point, float radius) {
    if (!dragon || dragon->phase == DRAGON_PHASE_DEATH) return false;
    
    // Check collision with each body segment
    for (int i = 0; i < DRAGON_SEGMENT_COUNT; i++) {
        float segment_radius = 4.0f * dragon->segments[i].scale;
        if (Vector3Distance(dragon->segments[i].position, point) < segment_radius + radius) {
            return true;
        }
    }
    
    return false;
}

bool cyber_dragon_check_weak_point_hit(cyber_dragon_t* dragon, Vector3 point, float radius) {
    if (!dragon || !dragon->weak_points_exposed) return false;
    
    for (int i = 0; i < 3; i++) {
        Vector3 weak_pos = Vector3Add(dragon->segments[i * 7].position, dragon->weak_points[i]);
        if (Vector3Distance(weak_pos, point) < 5.0f + radius) {
            return true;
        }
    }
    
    return false;
}
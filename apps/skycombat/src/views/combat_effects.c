/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/views/combat_effects.h"
#include "sky_combat/utils/zero_crash.h"
#include <raymath.h>
#include <stdlib.h>
#include <math.h>
#include <stdio.h>

#define MAX_EFFECTS 500
#define PARTICLES_PER_EFFECT 50

effects_manager_t* effects_create(int max_effects, int max_particles) {
    effects_manager_t* manager = calloc(1, sizeof(effects_manager_t));
    if (!manager) return NULL;
    
    manager->effects = calloc(max_effects, sizeof(visual_effect_t));
    manager->max_effects = max_effects;
    
    manager->global_particles = calloc(max_particles, sizeof(particle_t));
    manager->max_particles = max_particles;
    
    manager->feedbacks = calloc(100, sizeof(combat_feedback_t));
    manager->max_feedbacks = 100;
    
    manager->time_scale = 1.0f;
    
    // Pre-allocate particles for effects
    for (int i = 0; i < max_effects; i++) {
        manager->effects[i].particles = calloc(PARTICLES_PER_EFFECT, sizeof(particle_t));
    }
    
    // Create shared white texture for billboards
    Image white_img = GenImageColor(1, 1, WHITE);
    manager->white_texture = LoadTextureFromImage(white_img);
    UnloadImage(white_img);
    
    return manager;
}

void effects_destroy(effects_manager_t* manager) {
    if (!manager) return;
    
    for (int i = 0; i < manager->max_effects; i++) {
        free(manager->effects[i].particles);
    }
    
    // Unload shared texture
    UnloadTexture(manager->white_texture);
    
    free(manager->effects);
    free(manager->global_particles);
    free(manager->feedbacks);
    free(manager);
}

static visual_effect_t* get_free_effect(effects_manager_t* manager) {
    for (int i = 0; i < manager->max_effects; i++) {
        if (!manager->effects[i].active) {
            visual_effect_t* effect = &manager->effects[i];
            effect->elapsed = 0;
            effect->active = true;
            manager->active_effects++;
            return effect;
        }
    }
    return NULL;
}

static particle_t* spawn_particle(effects_manager_t* manager) {
    for (int i = 0; i < manager->max_particles; i++) {
        if (!manager->global_particles[i].active) {
            particle_t* p = &manager->global_particles[i];
            p->active = true;
            p->life = 1.0f;
            p->max_life = 1.0f;
            manager->active_particles++;
            return p;
        }
    }
    return NULL;
}

void effects_spawn_explosion(effects_manager_t* manager, Vector3 pos, float radius, Color color) {
    visual_effect_t* effect = get_free_effect(manager);
    if (!effect) return;
    
    effect->type = EFFECT_EXPLOSION;
    effect->position = pos;
    effect->radius = radius;
    effect->duration = 1.5f;
    effect->color_start = color;
    effect->color_end = (Color){color.r/2, color.g/2, color.b/2, 0};
    effect->intensity = 1.0f;
    effect->screen_shake = true;
    effect->shake_intensity = radius / 10.0f;
    
    // Create explosion particles
    effect->particle_count = PARTICLES_PER_EFFECT;
    for (int i = 0; i < effect->particle_count; i++) {
        particle_t* p = &effect->particles[i];
        p->active = true;
        p->position = pos;
        
        // Random explosion direction
        float angle = ((float)rand() / RAND_MAX) * 2 * PI;
        float pitch = ((float)rand() / RAND_MAX) * PI - PI/2;
        float speed = radius * (5.0f + (float)rand() / RAND_MAX * 10.0f);
        
        p->velocity = (Vector3){
            cosf(angle) * cosf(pitch) * speed,
            sinf(pitch) * speed,
            sinf(angle) * cosf(pitch) * speed
        };
        
        p->color = color;
        p->size = 2.0f + (float)rand() / RAND_MAX * 3.0f;
        p->life = 1.0f;
        p->max_life = 0.5f + (float)rand() / RAND_MAX * 0.5f;
        p->has_gravity = true;
        p->emits_light = true;
        p->glow_radius = radius / 2;
    }
    
    // Add debris particles instead of calling separate function
    for (int i = 0; i < (int)(radius / 5); i++) {
        particle_t* debris = spawn_particle(manager);
        if (!debris) break;
        
        debris->position = pos;
        debris->velocity = (Vector3){
            (float)(rand() % 40) - 20,
            (float)(rand() % 20) + 10,
            (float)(rand() % 40) - 20
        };
        debris->color = (Color){100, 100, 100, 255};
        debris->size = 1.0f + (float)rand() / RAND_MAX * 2.0f;
        debris->life = 1.5f;
        debris->max_life = 1.5f;
        debris->has_gravity = true;
    }
    
    // Screen effects
    effects_screen_shake(manager, effect->shake_intensity, 0.5f);
    effects_screen_flash(manager, (Color){255, 200, 100, 100}, 0.2f);
}

void effects_spawn_laser_hit(effects_manager_t* manager, Vector3 pos, Vector3 normal, Color color) {
    visual_effect_t* effect = get_free_effect(manager);
    if (!effect) return;
    
    effect->type = EFFECT_LASER_HIT;
    effect->position = pos;
    effect->duration = 0.5f;
    effect->color_start = color;
    effect->intensity = 2.0f;
    
    // Sparks flying away from hit point
    effect->particle_count = 20;
    for (int i = 0; i < effect->particle_count; i++) {
        particle_t* p = &effect->particles[i];
        p->active = true;
        p->position = pos;
        
        // Reflect off normal with some randomness
        Vector3 reflect_dir = Vector3Add(normal, (Vector3){
            ((float)rand() / RAND_MAX - 0.5f) * 0.5f,
            ((float)rand() / RAND_MAX - 0.5f) * 0.5f,
            ((float)rand() / RAND_MAX - 0.5f) * 0.5f
        });
        reflect_dir = Vector3Normalize(reflect_dir);
        
        float speed = 30.0f + (float)rand() / RAND_MAX * 50.0f;
        p->velocity = Vector3Scale(reflect_dir, speed);
        
        p->color = color;
        p->size = 0.5f + (float)rand() / RAND_MAX * 1.0f;
        p->life = 0.3f;
        p->max_life = 0.3f;
        p->has_gravity = false;
        p->emits_light = true;
        p->glow_radius = 5.0f;
    }
}

void effects_spawn_missile_trail(effects_manager_t* manager, Vector3 pos, Vector3 velocity) {
    // Smoke trail particle
    particle_t* p = spawn_particle(manager);
    if (!p) return;
    
    p->position = pos;
    p->velocity = Vector3Scale(velocity, -0.1f);  // Slight backward drift
    p->color = (Color){150, 150, 150, 200};
    p->size = 3.0f;
    p->life = 2.0f;
    p->max_life = 2.0f;
    p->has_gravity = false;
    
    // Fire particle
    if (rand() % 3 == 0) {
        particle_t* fire = spawn_particle(manager);
        if (fire) {
            fire->position = pos;
            fire->velocity = Vector3Scale(velocity, -0.2f);
            fire->color = (Color){255, 200, 50, 255};
            fire->size = 2.0f;
            fire->life = 0.5f;
            fire->max_life = 0.5f;
            fire->emits_light = true;
            fire->glow_radius = 10.0f;
        }
    }
}

void effects_spawn_shield_ripple(effects_manager_t* manager, Vector3 pos, float radius) {
    visual_effect_t* effect = get_free_effect(manager);
    if (!effect) return;
    
    effect->type = EFFECT_SHIELD_HIT;
    effect->position = pos;
    effect->radius = 0;
    effect->scale = (Vector3){radius, radius, radius};
    effect->duration = 0.8f;
    effect->color_start = (Color){100, 200, 255, 200};
    effect->color_end = (Color){50, 100, 200, 0};
    effect->intensity = 1.0f;
}

void effects_spawn_powerup_collect(effects_manager_t* manager, Vector3 pos, Color color) {
    visual_effect_t* effect = get_free_effect(manager);
    if (!effect) return;
    
    effect->type = EFFECT_POWERUP;
    effect->position = pos;
    effect->duration = 1.0f;
    effect->color_start = color;
    effect->intensity = 3.0f;
    
    // Spiral particles
    for (int i = 0; i < 30; i++) {
        particle_t* p = spawn_particle(manager);
        if (!p) break;
        
        float angle = (i / 30.0f) * 2 * PI;
        float height = (i / 30.0f) * 20;
        
        p->position = Vector3Add(pos, (Vector3){
            cosf(angle) * 5,
            -height,
            sinf(angle) * 5
        });
        
        p->velocity = (Vector3){
            cosf(angle) * 20,
            30,
            sinf(angle) * 20
        };
        
        p->color = color;
        p->size = 2.0f;
        p->life = 1.0f;
        p->emits_light = true;
        p->glow_radius = 15.0f;
    }
}

void effects_show_damage(effects_manager_t* manager, Vector3 pos, int damage, bool critical) {
    for (int i = 0; i < manager->max_feedbacks; i++) {
        if (manager->feedbacks[i].hit_timer <= 0) {
            combat_feedback_t* feedback = &manager->feedbacks[i];
            feedback->hit_position = pos;
            feedback->hit_timer = 1.5f;
            feedback->hit_critical = critical;
            feedback->damage_amount = damage;
            manager->active_feedbacks++;
            break;
        }
    }
}

void effects_activate_bullet_time(effects_manager_t* manager, float duration) {
    manager->bullet_time_active = true;
    manager->bullet_time_remaining = duration;
    manager->time_scale = 0.2f;
    
    // Visual feedback
    manager->chromatic_aberration = 0.02f;
    manager->motion_blur = 0.8f;
}

void effects_screen_shake(effects_manager_t* manager, float intensity, float duration) {
    manager->screen_shake = intensity;
    // Screen shake decays over time
}

void effects_screen_flash(effects_manager_t* manager, Color color, float duration) {
    manager->screen_flash = color;
    manager->flash_intensity = 1.0f;
}

void effects_update(effects_manager_t* manager, float dt) {
    if (!manager) return;
    
    // Apply time scaling
    dt *= manager->time_scale;
    
    // Update bullet time
    if (manager->bullet_time_active) {
        manager->bullet_time_remaining -= dt;
        if (manager->bullet_time_remaining <= 0) {
            manager->bullet_time_active = false;
            manager->time_scale = 1.0f;
            manager->chromatic_aberration = 0;
            manager->motion_blur = 0;
        }
    }
    
    // Update visual effects
    for (int i = 0; i < manager->max_effects; i++) {
        visual_effect_t* effect = &manager->effects[i];
        if (!effect->active) continue;
        
        effect->elapsed += dt;
        if (effect->elapsed >= effect->duration) {
            effect->active = false;
            manager->active_effects--;
            continue;
        }
        
        // Update effect-specific particles
        for (int j = 0; j < effect->particle_count; j++) {
            particle_t* p = &effect->particles[j];
            if (!p->active) continue;
            
            p->position = Vector3Add(p->position, Vector3Scale(p->velocity, dt));
            p->life -= dt / p->max_life;
            
            if (p->has_gravity) {
                p->velocity.y -= 50.0f * dt;  // Gravity
            }
            
            if (p->life <= 0) {
                p->active = false;
            }
        }
        
        // Special effect updates
        switch (effect->type) {
            case EFFECT_SHIELD_HIT:
                // Expanding ripple
                effect->radius = (effect->elapsed / effect->duration) * effect->scale.x;
                break;
                
            case EFFECT_EXPLOSION:
                // Expanding shockwave
                effect->intensity = 1.0f - (effect->elapsed / effect->duration);
                break;
        }
    }
    
    // Update global particles
    for (int i = 0; i < manager->max_particles; i++) {
        particle_t* p = &manager->global_particles[i];
        if (!p->active) continue;
        
        p->position = Vector3Add(p->position, Vector3Scale(p->velocity, dt));
        p->life -= dt / p->max_life;
        
        // Fade out
        p->color.a = (unsigned char)(p->life * 255);
        
        if (p->has_gravity) {
            p->velocity.y -= 30.0f * dt;
        }
        
        if (p->life <= 0) {
            p->active = false;
            manager->active_particles--;
        }
    }
    
    // Update combat feedback
    for (int i = 0; i < manager->max_feedbacks; i++) {
        combat_feedback_t* feedback = &manager->feedbacks[i];
        if (feedback->hit_timer > 0) {
            feedback->hit_timer -= dt;
            feedback->hit_position.y += 20.0f * dt;  // Float up
            
            if (feedback->hit_timer <= 0) {
                manager->active_feedbacks--;
            }
        }
        
        if (feedback->combo_timer > 0) {
            feedback->combo_timer -= dt;
        }
        
        if (feedback->score_timer > 0) {
            feedback->score_timer -= dt;
            feedback->score_position.y += 30.0f * dt;
        }
    }
    
    // Update screen effects
    if (manager->screen_shake > 0) {
        manager->screen_shake -= dt * 5.0f;
        if (manager->screen_shake < 0) manager->screen_shake = 0;
    }
    
    if (manager->flash_intensity > 0) {
        manager->flash_intensity -= dt * 5.0f;
        if (manager->flash_intensity < 0) manager->flash_intensity = 0;
    }
}

void effects_draw(effects_manager_t* manager, Camera3D camera) {
    if (!manager) return;
    
    // Draw effects
    BeginBlendMode(BLEND_ADDITIVE);
    
    for (int i = 0; i < manager->max_effects; i++) {
        visual_effect_t* effect = &manager->effects[i];
        if (!effect->active) continue;
        
        float progress = effect->elapsed / effect->duration;
        Color color = ColorLerp(effect->color_start, effect->color_end, progress);
        
        switch (effect->type) {
            case EFFECT_EXPLOSION:
                // Expanding sphere
                DrawSphereWires(effect->position, 
                    effect->radius * (1 + progress * 2), 
                    8, 8, color);
                break;
                
            case EFFECT_SHIELD_HIT:
                // Ripple effect
                DrawCircle3D(effect->position, effect->radius, 
                    (Vector3){0, 1, 0}, 90, color);
                break;
                
            case EFFECT_LASER_HIT:
                // Flash
                DrawSphere(effect->position, 2.0f * (1 - progress), color);
                break;
        }
        
        // Draw effect particles
        for (int j = 0; j < effect->particle_count; j++) {
            particle_t* p = &effect->particles[j];
            if (!p->active) continue;
            
            DrawCube(p->position, p->size, p->size, p->size, p->color);
            
            if (p->emits_light) {
                Color glow = p->color;
                glow.a = 50;
                DrawSphere(p->position, p->glow_radius * p->life, glow);
            }
        }
    }
    
    // Draw global particles
    for (int i = 0; i < manager->max_particles; i++) {
        particle_t* p = &manager->global_particles[i];
        if (!p->active) continue;
        
        if (p->size > 2.0f) {
            // Smoke particles as billboards using shared texture
            DrawBillboard(camera, 
                manager->white_texture,
                p->position, p->size, p->color);
        } else {
            // Small particles as cubes
            DrawCube(p->position, p->size, p->size, p->size, p->color);
        }
        
        if (p->emits_light) {
            Color glow = p->color;
            glow.a = (unsigned char)(20 * p->life);
            DrawSphere(p->position, p->glow_radius * p->life, glow);
        }
    }
    
    EndBlendMode();
}

void effects_draw_ui(effects_manager_t* manager, int screen_width, int screen_height) {
    if (!manager) return;
    
    // Screen shake offset - MATHEMATICALLY PROVEN SAFE
    int shake_x = 0, shake_y = 0;
    if (manager->screen_shake > 0) {
        CONSTRAINED(manager->screen_shake, "0.0 <= x <= 10.0");
        
        // Using SHAKE_TO_RANGE macro that guarantees >= 1
        int shake_range = SHAKE_TO_RANGE(manager->screen_shake);
        PROVES_UNREACHABLE("shake_range < 1");
        
        int shake_offset = (int)(manager->screen_shake * 10.0f);
        shake_x = (rand() % shake_range) - shake_offset;
        shake_y = (rand() % shake_range) - shake_offset;
    }
    
    // Draw damage numbers
    for (int i = 0; i < manager->max_feedbacks; i++) {
        combat_feedback_t* feedback = &manager->feedbacks[i];
        if (feedback->hit_timer > 0) {
            Vector2 screen_pos = GetWorldToScreen(feedback->hit_position, 
                (Camera){.position = {0, 0, 0}, .target = {0, 0, 1}});
            
            char damage_text[32];
            snprintf(damage_text, sizeof(damage_text), "%d", feedback->damage_amount);
            
            int font_size = feedback->hit_critical ? 40 : 24;
            Color text_color = feedback->hit_critical ? YELLOW : WHITE;
            text_color.a = (unsigned char)(feedback->hit_timer * 255);
            
            DrawText(damage_text, 
                (int)screen_pos.x + shake_x, 
                (int)screen_pos.y + shake_y, 
                font_size, text_color);
            
            if (feedback->hit_critical) {
                DrawText("CRITICAL!", 
                    (int)screen_pos.x + shake_x - 30, 
                    (int)screen_pos.y + shake_y + 30, 
                    20, ORANGE);
            }
        }
    }
    
    // Screen flash
    if (manager->flash_intensity > 0) {
        Color flash = manager->screen_flash;
        flash.a = (unsigned char)(manager->flash_intensity * flash.a);
        DrawRectangle(0, 0, screen_width, screen_height, flash);
    }
    
    // Bullet time indicator
    if (manager->bullet_time_active) {
        DrawText("BULLET TIME", 
            screen_width/2 - 100, 
            screen_height - 50, 
            30, SKYBLUE);
            
        // Time remaining bar
        float bar_width = 200 * (manager->bullet_time_remaining / 5.0f);
        DrawRectangle(screen_width/2 - 100, screen_height - 20, 
            (int)bar_width, 10, SKYBLUE);
        DrawRectangleLines(screen_width/2 - 100, screen_height - 20, 
            200, 10, WHITE);
    }
}

void effects_sonic_boom(effects_manager_t* manager, Vector3 pos, Vector3 direction) {
    visual_effect_t* effect = get_free_effect(manager);
    if (!effect) return;
    
    effect->type = EFFECT_SONIC_BOOM;
    effect->position = pos;
    effect->duration = 0.8f;
    effect->scale = Vector3Scale(direction, 50);
    
    // Cone of air particles
    for (int i = 0; i < 40; i++) {
        particle_t* p = spawn_particle(manager);
        if (!p) break;
        
        float spread = (float)i / 40 * 0.5f;
        Vector3 offset = {
            (float)(rand() % 100 - 50) / 100.0f * spread,
            (float)(rand() % 100 - 50) / 100.0f * spread,
            0
        };
        
        p->position = pos;
        p->velocity = Vector3Add(
            Vector3Scale(direction, 100),
            Vector3Scale(offset, 50)
        );
        
        p->color = (Color){200, 200, 255, 100};
        p->size = 3.0f;
        p->life = 0.5f;
    }
    
    effects_screen_shake(manager, 3.0f, 0.3f);
}

void effects_show_combo(effects_manager_t* manager, int combo, float multiplier) {
    // Find a free feedback slot for combo display
    for (int i = 0; i < manager->max_feedbacks; i++) {
        if (manager->feedbacks[i].combo_timer <= 0) {
            combat_feedback_t* feedback = &manager->feedbacks[i];
            feedback->combo_count = combo;
            feedback->combo_timer = 2.0f;
            feedback->combo_multiplier = multiplier;
            manager->active_feedbacks++;
            break;
        }
    }
}

void effects_show_achievement(effects_manager_t* manager, const char* text) {
    (void)text;  // Will be used when we add text rendering
    // Create a special powerup effect for achievements
    visual_effect_t* effect = get_free_effect(manager);
    if (!effect) return;
    
    effect->type = EFFECT_POWERUP;
    effect->position = (Vector3){0, 0, 0};  // Screen center
    effect->duration = 3.0f;
    effect->color_start = GOLD;
    effect->intensity = 5.0f;
    
    // Add celebration particles
    for (int i = 0; i < 50; i++) {
        particle_t* p = spawn_particle(manager);
        if (!p) break;
        
        float angle = (float)i / 50 * 2 * PI;
        
        p->position = (Vector3){0, 100, 0};
        p->velocity = (Vector3){
            cosf(angle) * 50,
            (float)(rand() % 50),
            sinf(angle) * 50
        };
        
        p->color = (rand() % 2) ? GOLD : YELLOW;
        p->size = 3.0f;
        p->life = 2.0f;
        p->max_life = 2.0f;
        p->emits_light = true;
        p->glow_radius = 20.0f;
    }
}
/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/models/overdrive.h"
#include <stdlib.h>
#include <math.h>
#include <stdio.h>

#define OVERDRIVE_MAX_ENERGY 100.0f
#define OVERDRIVE_DURATION 10.0f
#define OVERDRIVE_COOLDOWN 5.0f
#define OVERDRIVE_MIN_ENERGY 50.0f

overdrive_system_t* overdrive_create(void) {
    overdrive_system_t* overdrive = calloc(1, sizeof(overdrive_system_t));
    if (!overdrive) return NULL;
    
    // Initial state
    overdrive->energy = 0.0f;
    overdrive->charge_rate = 5.0f;  // 5% per second base rate
    overdrive->combo_bonus = 0.0f;
    
    // Power multipliers
    overdrive->damage_multiplier = 3.0f;
    overdrive->speed_multiplier = 1.5f;
    overdrive->fire_rate_bonus = 2.0f;
    overdrive->invincible = true;
    
    // Visual
    overdrive->trail_color = (Color){255, 100, 0, 255};  // Orange glow
    overdrive->particle_rate = 50.0f;
    
    return overdrive;
}

void overdrive_destroy(overdrive_system_t* overdrive) {
    free(overdrive);
}

void overdrive_update(overdrive_system_t* overdrive, float dt) {
    if (!overdrive) return;
    
    if (overdrive->active) {
        // Drain duration
        overdrive->duration -= dt;
        
        // Update effects
        overdrive->effect_intensity = sinf(overdrive->duration * 10.0f) * 0.5f + 0.5f;
        overdrive->screen_shake = (overdrive->duration > 2.0f) ? 0.5f : overdrive->duration * 0.25f;
        
        // Deactivate when done
        if (overdrive->duration <= 0) {
            overdrive_deactivate(overdrive);
        }
    } else {
        // Charge energy
        if (overdrive->cooldown > 0) {
            overdrive->cooldown -= dt;
        } else if (overdrive->energy < OVERDRIVE_MAX_ENERGY) {
            float charge = (overdrive->charge_rate + overdrive->combo_bonus) * dt;
            overdrive->energy = fminf(overdrive->energy + charge, OVERDRIVE_MAX_ENERGY);
        }
        
        // Decay combo bonus
        if (overdrive->combo_bonus > 0) {
            overdrive->combo_bonus -= dt * 2.0f;
            if (overdrive->combo_bonus < 0) overdrive->combo_bonus = 0;
        }
    }
}

void overdrive_charge(overdrive_system_t* overdrive, float amount) {
    if (!overdrive || overdrive->active || overdrive->cooldown > 0) return;
    
    overdrive->energy = fminf(overdrive->energy + amount, OVERDRIVE_MAX_ENERGY);
    
    // Combo bonus increases charge rate temporarily
    overdrive->combo_bonus = fminf(overdrive->combo_bonus + amount * 0.1f, 10.0f);
}

void overdrive_activate(overdrive_system_t* overdrive) {
    if (!overdrive || !overdrive_can_activate(overdrive)) return;
    
    overdrive->active = true;
    overdrive->duration = OVERDRIVE_DURATION;
    overdrive->energy = 0;  // Drain all energy
    overdrive->effect_intensity = 1.0f;
    overdrive->screen_shake = 2.0f;  // Big initial shake
    overdrive->sound_playing = true;
}

void overdrive_deactivate(overdrive_system_t* overdrive) {
    if (!overdrive) return;
    
    overdrive->active = false;
    overdrive->cooldown = OVERDRIVE_COOLDOWN;
    overdrive->effect_intensity = 0;
    overdrive->screen_shake = 0;
    overdrive->sound_playing = false;
    overdrive->combo_bonus = 0;  // Reset combo
}

bool overdrive_can_activate(overdrive_system_t* overdrive) {
    return overdrive && 
           !overdrive->active && 
           overdrive->cooldown <= 0 && 
           overdrive->energy >= OVERDRIVE_MIN_ENERGY;
}

float overdrive_get_charge_percent(overdrive_system_t* overdrive) {
    if (!overdrive) return 0;
    return (overdrive->energy / OVERDRIVE_MAX_ENERGY) * 100.0f;
}

bool overdrive_is_active(overdrive_system_t* overdrive) {
    return overdrive && overdrive->active;
}

float overdrive_get_damage_multiplier(overdrive_system_t* overdrive) {
    if (!overdrive || !overdrive->active) return 1.0f;
    return overdrive->damage_multiplier;
}

void overdrive_draw_effects(overdrive_system_t* overdrive, Vector3 position, Camera3D camera) {
    if (!overdrive || !overdrive->active) return;
    
    // Glowing aura around aircraft
    float pulse = overdrive->effect_intensity;
    Color aura = overdrive->trail_color;
    aura.a = (unsigned char)(pulse * 100);
    
    // Draw multiple expanding rings
    for (int i = 0; i < 3; i++) {
        float radius = 10.0f + i * 5.0f + pulse * 3.0f;
        DrawCircle3D(position, radius, (Vector3){1, 0, 0}, 0, aura);
        DrawCircle3D(position, radius, (Vector3){0, 1, 0}, 0, aura);
        DrawCircle3D(position, radius, (Vector3){0, 0, 1}, 0, aura);
    }
    
    // Energy particles
    for (int i = 0; i < 10; i++) {
        float angle = (overdrive->duration * 5.0f + i * 36.0f) * DEG2RAD;
        float dist = 15.0f + sinf(overdrive->duration * 3.0f + i) * 5.0f;
        
        Vector3 particle_pos = {
            position.x + cosf(angle) * dist,
            position.y + sinf(i * 0.5f) * 5.0f,
            position.z + sinf(angle) * dist
        };
        
        DrawSphere(particle_pos, 0.5f + pulse * 0.3f, overdrive->trail_color);
    }
    
    // Lightning bolts
    if (fmodf(overdrive->duration, 0.1f) < 0.05f) {
        for (int i = 0; i < 3; i++) {
            Vector3 end = {
                position.x + (rand() % 40 - 20),
                position.y + (rand() % 40 - 20),
                position.z + (rand() % 40 - 20)
            };
            DrawLine3D(position, end, WHITE);
        }
    }
}

void overdrive_draw_ui(overdrive_system_t* overdrive, int x, int y) {
    if (!overdrive) return;
    
    // Draw energy bar
    const int bar_width = 200;
    const int bar_height = 25;
    
    // Background
    DrawRectangle(x, y, bar_width, bar_height, DARKGRAY);
    
    // Energy fill
    if (overdrive->active) {
        // Active - show remaining duration
        float duration_pct = overdrive->duration / OVERDRIVE_DURATION;
        int fill_width = (int)(bar_width * duration_pct);
        
        // Flashing effect
        Color fill_color = overdrive->effect_intensity > 0.5f ? ORANGE : RED;
        DrawRectangle(x, y, fill_width, bar_height, fill_color);
        
        // "OVERDRIVE ACTIVE" text
        DrawText("OVERDRIVE ACTIVE!", x + 5, y + 3, 18, WHITE);
    } else if (overdrive->cooldown > 0) {
        // Cooldown
        float cooldown_pct = 1.0f - (overdrive->cooldown / OVERDRIVE_COOLDOWN);
        int fill_width = (int)(bar_width * cooldown_pct);
        DrawRectangle(x, y, fill_width, bar_height, DARKBLUE);
        DrawText("COOLDOWN", x + 5, y + 3, 18, LIGHTGRAY);
    } else {
        // Charging
        int fill_width = (int)(bar_width * (overdrive->energy / OVERDRIVE_MAX_ENERGY));
        
        // Color changes as it charges
        Color fill_color;
        if (overdrive->energy >= OVERDRIVE_MIN_ENERGY) {
            // Ready to activate - pulse effect
            float pulse = sinf(GetTime() * 5.0f) * 0.5f + 0.5f;
            fill_color = (Color){
                (unsigned char)(255 * pulse),
                (unsigned char)(200 * pulse),
                0,
                255
            };
        } else {
            fill_color = BLUE;
        }
        
        DrawRectangle(x, y, fill_width, bar_height, fill_color);
        
        // Text
        if (overdrive->energy >= OVERDRIVE_MIN_ENERGY) {
            DrawText("OVERDRIVE READY! (Press Y)", x + 5, y + 3, 18, WHITE);
        } else {
            char text[32];
            snprintf(text, sizeof(text), "OVERDRIVE: %d%%", (int)overdrive_get_charge_percent(overdrive));
            DrawText(text, x + 5, y + 3, 18, WHITE);
        }
    }
    
    // Border
    DrawRectangleLines(x, y, bar_width, bar_height, WHITE);
    
    // Combo indicator
    if (overdrive->combo_bonus > 0) {
        char combo_text[32];
        snprintf(combo_text, sizeof(combo_text), "+%.1fx", 1.0f + overdrive->combo_bonus / 10.0f);
        DrawText(combo_text, x + bar_width + 5, y + 3, 18, YELLOW);
    }
}
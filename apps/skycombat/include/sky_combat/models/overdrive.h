/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_OVERDRIVE_H
#define SKY_COMBAT_OVERDRIVE_H

#include <raylib.h>
#include <stdbool.h>

// Overdrive system - massive power boost mode
typedef struct {
    // State
    bool active;
    float energy;           // 0-100
    float duration;         // Time remaining
    float cooldown;         // Cooldown after use
    
    // Build-up
    float charge_rate;      // How fast it charges
    float combo_bonus;      // Extra charge from combos
    
    // Effects when active
    float damage_multiplier;
    float speed_multiplier;
    float fire_rate_bonus;
    bool invincible;
    
    // Visual state
    float effect_intensity;
    float screen_shake;
    Color trail_color;
    float particle_rate;
    
    // Audio
    bool sound_playing;
} overdrive_system_t;

// Create/destroy
overdrive_system_t* overdrive_create(void);
void overdrive_destroy(overdrive_system_t* overdrive);

// Update
void overdrive_update(overdrive_system_t* overdrive, float dt);
void overdrive_charge(overdrive_system_t* overdrive, float amount);
void overdrive_activate(overdrive_system_t* overdrive);
void overdrive_deactivate(overdrive_system_t* overdrive);

// Query
bool overdrive_can_activate(overdrive_system_t* overdrive);
float overdrive_get_charge_percent(overdrive_system_t* overdrive);
bool overdrive_is_active(overdrive_system_t* overdrive);
float overdrive_get_damage_multiplier(overdrive_system_t* overdrive);

// Visual effects
void overdrive_draw_effects(overdrive_system_t* overdrive, Vector3 position, Camera3D camera);
void overdrive_draw_ui(overdrive_system_t* overdrive, int x, int y);

#endif // SKY_COMBAT_OVERDRIVE_H
/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_COMBAT_EFFECTS_H
#define SKY_COMBAT_COMBAT_EFFECTS_H

#include <raylib.h>
#include <stdbool.h>

// Effect types
typedef enum {
    EFFECT_EXPLOSION,        // Big explosion
    EFFECT_LASER_HIT,       // Laser impact
    EFFECT_MISSILE_TRAIL,   // Smoke trail
    EFFECT_SHIELD_HIT,      // Shield ripple
    EFFECT_ENERGY_BURST,    // Energy shockwave
    EFFECT_DEBRIS,          // Flying debris
    EFFECT_SPARKS,          // Electric sparks
    EFFECT_PLASMA_BURN,     // Plasma damage
    EFFECT_TELEPORT,        // Teleport effect
    EFFECT_POWERUP,         // Powerup collection
    EFFECT_SONIC_BOOM,      // Speed burst
    EFFECT_MATRIX_DODGE,    // Bullet time dodge
} effect_type_t;

// Particle system
typedef struct {
    Vector3 position;
    Vector3 velocity;
    Color color;
    float size;
    float life;
    float max_life;
    bool active;
    bool has_gravity;
    bool emits_light;
    float glow_radius;
} particle_t;

// Visual effect
typedef struct {
    effect_type_t type;
    Vector3 position;
    Vector3 scale;
    float duration;
    float elapsed;
    bool active;
    
    // Visual properties
    Color color_start;
    Color color_end;
    float intensity;
    float radius;
    
    // Animation
    float animation_speed;
    int frame_count;
    int current_frame;
    
    // Particles
    particle_t* particles;
    int particle_count;
    
    // Special properties
    bool screen_shake;
    float shake_intensity;
    bool time_dilation;
    float slow_factor;
    
} visual_effect_t;

// Combat feedback
typedef struct {
    // Hit markers
    Vector3 hit_position;
    float hit_timer;
    bool hit_critical;
    int damage_amount;
    
    // Combo display
    int combo_count;
    float combo_timer;
    float combo_multiplier;
    
    // Score popup
    Vector3 score_position;
    int score_value;
    float score_timer;
    Color score_color;
    
} combat_feedback_t;

// Effects manager
typedef struct {
    visual_effect_t* effects;
    int max_effects;
    int active_effects;
    
    particle_t* global_particles;
    int max_particles;
    int active_particles;
    
    combat_feedback_t* feedbacks;
    int max_feedbacks;
    int active_feedbacks;
    
    // Screen effects
    float screen_shake;
    float motion_blur;
    float chromatic_aberration;
    Color screen_flash;
    float flash_intensity;
    
    // Time manipulation
    float time_scale;
    bool bullet_time_active;
    float bullet_time_remaining;
    
    // Shared resources
    Texture2D white_texture;  // Shared 1x1 white texture for billboards
    
} effects_manager_t;

// System management
effects_manager_t* effects_create(int max_effects, int max_particles);
void effects_destroy(effects_manager_t* manager);
void effects_update(effects_manager_t* manager, float dt);
void effects_draw(effects_manager_t* manager, Camera3D camera);
void effects_draw_ui(effects_manager_t* manager, int screen_width, int screen_height);

// Spawn effects
void effects_spawn_explosion(effects_manager_t* manager, Vector3 pos, float radius, Color color);
void effects_spawn_laser_hit(effects_manager_t* manager, Vector3 pos, Vector3 normal, Color color);
void effects_spawn_missile_trail(effects_manager_t* manager, Vector3 pos, Vector3 velocity);
void effects_spawn_shield_ripple(effects_manager_t* manager, Vector3 pos, float radius);
void effects_spawn_debris(effects_manager_t* manager, Vector3 pos, int count);
void effects_spawn_powerup_collect(effects_manager_t* manager, Vector3 pos, Color color);

// Combat feedback
void effects_show_damage(effects_manager_t* manager, Vector3 pos, int damage, bool critical);
void effects_show_combo(effects_manager_t* manager, int combo, float multiplier);
void effects_show_score(effects_manager_t* manager, Vector3 pos, int score);
void effects_show_achievement(effects_manager_t* manager, const char* text);

// Screen effects
void effects_screen_shake(effects_manager_t* manager, float intensity, float duration);
void effects_screen_flash(effects_manager_t* manager, Color color, float duration);
void effects_activate_bullet_time(effects_manager_t* manager, float duration);
void effects_set_motion_blur(effects_manager_t* manager, float amount);

// Special moves
void effects_sonic_boom(effects_manager_t* manager, Vector3 pos, Vector3 direction);
void effects_matrix_dodge(effects_manager_t* manager, Vector3 pos);
void effects_energy_surge(effects_manager_t* manager, Vector3 pos, float radius);
void effects_quantum_burst(effects_manager_t* manager, Vector3 pos);

#endif // SKY_COMBAT_COMBAT_EFFECTS_H
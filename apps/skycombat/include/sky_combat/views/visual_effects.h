/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_VISUAL_EFFECTS_H
#define SKY_COMBAT_VISUAL_EFFECTS_H

#include <raylib.h>
#include <stdbool.h>

// Advanced visual effects for making the game look awesome

// Motion blur effect
typedef struct {
    RenderTexture2D buffer[3];  // Triple buffering
    int current_buffer;
    float intensity;
    bool enabled;
} motion_blur_t;

// Volumetric trails
typedef struct {
    Vector3 position;
    Vector3 velocity;
    float life;
    float width;
    Color color;
    float fade_rate;
} trail_segment_t;

typedef struct {
    trail_segment_t* segments;
    int count;
    int capacity;
    float spawn_rate;
    float spawn_timer;
} volumetric_trail_t;

// Screen effects
typedef struct {
    // Chromatic aberration
    float chromatic_intensity;
    float chromatic_offset;
    
    // Screen shake
    float shake_intensity;
    float shake_duration;
    Vector2 shake_offset;
    
    // Speed lines
    bool speed_lines_active;
    float speed_intensity;
    
    // Damage vignette
    float damage_intensity;
    Color damage_color;
    
    // Bloom effect
    float bloom_threshold;
    float bloom_intensity;
    RenderTexture2D bloom_buffer;
} screen_effects_t;

// Engine glow
typedef struct {
    float base_intensity;
    float boost_intensity;
    Color base_color;
    Color boost_color;
    float flicker_rate;
    float current_intensity;
} engine_glow_t;

// Master visual effects system
typedef struct {
    motion_blur_t* motion_blur;
    volumetric_trail_t* missile_trails;
    volumetric_trail_t* engine_trails;
    volumetric_trail_t* bullet_trails;
    screen_effects_t* screen;
    engine_glow_t* engine_glow;
    
    // Performance settings
    int quality_level;  // 0=Low, 1=Medium, 2=High, 3=Ultra
    bool auto_adjust;   // Dynamically adjust for 60 FPS
} visual_effects_system_t;

// System management
visual_effects_system_t* vfx_create(int screen_width, int screen_height);
void vfx_destroy(visual_effects_system_t* vfx);
void vfx_update(visual_effects_system_t* vfx, float dt);
void vfx_set_quality(visual_effects_system_t* vfx, int level);

// Motion blur
void vfx_begin_motion_blur(visual_effects_system_t* vfx);
void vfx_end_motion_blur(visual_effects_system_t* vfx);
void vfx_draw_motion_blur(visual_effects_system_t* vfx);

// Trails
void vfx_spawn_missile_trail(visual_effects_system_t* vfx, Vector3 pos, Vector3 vel, Color color);
void vfx_spawn_engine_trail(visual_effects_system_t* vfx, Vector3 pos, Vector3 vel, float intensity);
void vfx_spawn_bullet_trail(visual_effects_system_t* vfx, Vector3 start, Vector3 end, Color color);
void vfx_draw_trails(visual_effects_system_t* vfx, Camera3D camera);

// Screen effects
void vfx_chromatic_aberration(visual_effects_system_t* vfx, float g_force);
void vfx_screen_shake(visual_effects_system_t* vfx, float intensity, float duration);
void vfx_damage_flash(visual_effects_system_t* vfx, float intensity);
void vfx_speed_lines(visual_effects_system_t* vfx, float speed);
void vfx_apply_screen_effects(visual_effects_system_t* vfx);

// Engine glow
void vfx_update_engine_glow(visual_effects_system_t* vfx, bool boosting, float throttle);
void vfx_draw_engine_glow(visual_effects_system_t* vfx, Vector3 pos, float yaw, Camera3D camera);

// Special effects
void vfx_explosion_distortion(visual_effects_system_t* vfx, Vector3 pos, float radius);
void vfx_sonic_boom(visual_effects_system_t* vfx, Vector3 pos, Vector3 direction);
void vfx_emp_pulse(visual_effects_system_t* vfx, Vector3 pos, float radius);

#endif // SKY_COMBAT_VISUAL_EFFECTS_H
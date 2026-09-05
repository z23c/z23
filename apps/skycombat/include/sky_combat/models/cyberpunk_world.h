/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_CYBERPUNK_WORLD_H
#define SKY_COMBAT_CYBERPUNK_WORLD_H

#include <raylib.h>
#include <stdbool.h>

// World element types
typedef enum {
    WORLD_NEON_BUILDING,      // Glowing neon skyscrapers
    WORLD_HOLOGRAM,           // Giant floating holograms
    WORLD_FLOATING_PLATFORM,  // Anti-gravity platforms
    WORLD_ENERGY_RING,        // Portal rings to fly through
    WORLD_LASER_GRID,         // Deadly laser grids
    WORLD_PLASMA_TOWER,       // Energy beam towers
    WORLD_CYBER_BILLBOARD,    // Animated billboards
    WORLD_QUANTUM_TUNNEL,     // Speed boost tunnels
    WORLD_FORCE_FIELD,        // Shield barriers
    WORLD_DATA_STREAM,        // Visual data flows
} world_element_type_t;

// Animated world element
typedef struct {
    world_element_type_t type;
    Vector3 position;
    Vector3 scale;
    Vector3 rotation;
    
    // Animation
    float animation_time;
    float pulse_speed;
    float glow_intensity;
    
    // Colors
    Color primary_color;
    Color secondary_color;
    Color emission_color;
    
    // Special properties
    bool is_interactive;
    bool is_hazard;
    bool gives_powerup;
    float effect_radius;
    
    // Neon effects
    float neon_flicker;
    bool has_trail;
    Vector3 trail_positions[10];
    
} world_element_t;

// Cyberpunk world manager
typedef struct {
    // City layout
    world_element_t* elements;
    int element_count;
    int max_elements;
    
    // Sky and atmosphere
    Color sky_gradient_top;
    Color sky_gradient_bottom;
    float fog_density;
    Color fog_color;
    
    // Lighting
    Vector3 sun_direction;
    Color ambient_light;
    float global_glow;
    
    // Particle effects
    Vector3* particle_positions;
    Vector3* particle_velocities;
    Color* particle_colors;
    int particle_count;
    
    // Dynamic elements
    float time;
    float weather_cycle;
    bool is_raining_data;  // Digital rain effect
    
    // Performance
    bool use_instancing;
    int visible_elements;
    
} cyberpunk_world_t;

// World creation
cyberpunk_world_t* cyberpunk_world_create(void);
void cyberpunk_world_destroy(cyberpunk_world_t* world);
void cyberpunk_world_generate(cyberpunk_world_t* world, int seed);

// World updates
void cyberpunk_world_update(cyberpunk_world_t* world, float dt);
void cyberpunk_world_draw(cyberpunk_world_t* world, Camera3D camera);
void cyberpunk_world_draw_skybox(cyberpunk_world_t* world);

// Element spawning
void cyberpunk_spawn_building(cyberpunk_world_t* world, Vector3 pos, float height);
void cyberpunk_spawn_hologram(cyberpunk_world_t* world, Vector3 pos, const char* text);
void cyberpunk_spawn_energy_ring(cyberpunk_world_t* world, Vector3 pos, float radius);
void cyberpunk_spawn_laser_grid(cyberpunk_world_t* world, Vector3 start, Vector3 end);

// Effects
void cyberpunk_add_neon_trail(cyberpunk_world_t* world, Vector3 pos, Color color);
void cyberpunk_trigger_glitch_effect(cyberpunk_world_t* world, Vector3 center);
void cyberpunk_create_data_rain(cyberpunk_world_t* world);
void cyberpunk_pulse_world_glow(cyberpunk_world_t* world, float intensity);

// Collision
bool cyberpunk_check_collision(cyberpunk_world_t* world, Vector3 pos, float radius);
world_element_t* cyberpunk_get_nearest_element(cyberpunk_world_t* world, Vector3 pos);

// Visual presets
void cyberpunk_set_theme_vaporwave(cyberpunk_world_t* world);
void cyberpunk_set_theme_matrix(cyberpunk_world_t* world);
void cyberpunk_set_theme_tron(cyberpunk_world_t* world);
void cyberpunk_set_theme_blade_runner(cyberpunk_world_t* world);

#endif // SKY_COMBAT_CYBERPUNK_WORLD_H
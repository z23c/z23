/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_EFFECTS_H
#define SKY_COMBAT_EFFECTS_H

#include <raylib.h>
#include <stdbool.h>

#define MAX_PARTICLES 1000
#define MAX_EXPLOSIONS 20
#define MAX_TRAILS 50

// Particle types for different effects
typedef enum {
    PARTICLE_SPARK,
    PARTICLE_SMOKE,
    PARTICLE_FIRE,
    PARTICLE_STAR,
    PARTICLE_RING_COLLECT,
    PARTICLE_SPEED_LINES,
    PARTICLE_RAINBOW,
    PARTICLE_CONFETTI
} particle_type_t;

typedef struct {
    Vector3 position;
    Vector3 velocity;
    Color color;
    float size;
    float life;
    float max_life;
    particle_type_t type;
    bool active;
} particle_t;

typedef struct {
    Vector3 position;
    float radius;
    float max_radius;
    float life;
    Color color;
    bool active;
} explosion_t;

typedef struct {
    Vector3 start;
    Vector3 end;
    Color color;
    float width;
    float life;
    float max_life;
    bool active;
} trail_t;

// Particle system
typedef struct {
    particle_t particles[MAX_PARTICLES];
    explosion_t explosions[MAX_EXPLOSIONS];
    trail_t trails[MAX_TRAILS];
    float screen_shake;
    float motion_blur;
    bool rainbow_mode;
} effects_system_t;

// Effect creation
void effects_init(effects_system_t* effects);
void effects_update(effects_system_t* effects, float delta_time);
void effects_draw(effects_system_t* effects);

// Specific effects
void effects_create_explosion(effects_system_t* effects, Vector3 position, float size, Color color);
void effects_create_trail(effects_system_t* effects, Vector3 start, Vector3 end, Color color);
void effects_create_sparkle(effects_system_t* effects, Vector3 position, int count);
void effects_create_boost(effects_system_t* effects, Vector3 position, Vector3 direction);
void effects_create_ring_collect(effects_system_t* effects, Vector3 position, Color ring_color);
void effects_create_speed_lines(effects_system_t* effects, Vector3 position, float speed);
void effects_create_fireworks(effects_system_t* effects, Vector3 position);
void effects_create_confetti(effects_system_t* effects, Vector3 position, int count);

// Screen effects
void effects_add_shake(effects_system_t* effects, float intensity);
void effects_set_motion_blur(effects_system_t* effects, float amount);
void effects_toggle_rainbow_mode(effects_system_t* effects);

// Utility
Color effects_get_rainbow_color(float time);
Color effects_fade_color(Color color, float alpha);

#endif // SKY_COMBAT_EFFECTS_H
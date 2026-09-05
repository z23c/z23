/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_EFFECTS_MULTIPLAYER_H
#define SKY_COMBAT_EFFECTS_MULTIPLAYER_H

/**
 * @file effects_multiplayer.h
 * @brief Visual effects system for multiplayer Sky Combat
 * 
 * Features:
 * - Particle effects (explosions, smoke, fire)
 * - Projectile trails
 * - Power-up collection effects
 * - Environmental effects
 * - Hit markers
 */

#include <raylib.h>
#include <stdbool.h>
#include "sky_combat/models/weapons.h"

/** Particle types */
typedef enum {
    PARTICLE_SMOKE,
    PARTICLE_FIRE,
    PARTICLE_SPARK,
    PARTICLE_DEBRIS,
    PARTICLE_ENERGY,
    PARTICLE_DUST
} particle_type_t;

/** Individual particle */
typedef struct {
    Vector3 position;           /**< World position */
    Vector3 velocity;           /**< Movement velocity */
    Color color;               /**< Particle color */
    float size;                /**< Particle size */
    float life;                /**< Remaining lifetime */
    float max_life;            /**< Total lifetime */
    particle_type_t type;      /**< Particle type */
    float rotation;            /**< Rotation angle */
    float rotation_speed;      /**< Rotation speed */
} particle_t;

/** Particle emitter */
typedef struct {
    Vector3 position;          /**< Emitter position */
    Vector3 direction;         /**< Emission direction */
    bool active;               /**< Is emitting */
    float emission_rate;       /**< Particles per second */
    float emission_timer;      /**< Emission accumulator */
    particle_type_t type;      /**< Particle type to emit */
    Color color_start;         /**< Starting color */
    Color color_end;           /**< Ending color */
    float size_start;          /**< Starting size */
    float size_end;            /**< Ending size */
    float speed_min;           /**< Minimum speed */
    float speed_max;           /**< Maximum speed */
    float lifetime;            /**< Particle lifetime */
    float spread_angle;        /**< Emission cone angle */
} particle_emitter_t;

/** Projectile trail */
typedef struct {
    Vector3 positions[20];     /**< Trail positions */
    float alphas[20];          /**< Trail alpha values */
    int head;                  /**< Current head index */
    bool active;               /**< Trail active */
    Color color;               /**< Trail color */
    float width;               /**< Trail width */
} projectile_trail_t;

/** Effect instance */
typedef struct {
    Vector3 position;          /**< Effect position */
    float scale;               /**< Effect scale */
    float duration;            /**< Total duration */
    float time;                /**< Current time */
    bool active;               /**< Is active */
    int type;                  /**< Effect type ID */
} effect_instance_t;

/**
 * @brief Effects system manager
 */
typedef struct {
    /* Particles */
    particle_t* particles;              /**< Particle pool */
    int particle_count;                 /**< Active particles */
    int max_particles;                  /**< Maximum particles */
    
    /* Emitters */
    particle_emitter_t emitters[50];    /**< Emitter pool */
    int emitter_count;                  /**< Active emitters */
    
    /* Projectile trails */
    projectile_trail_t trails[100];     /**< Trail pool */
    int trail_count;                    /**< Active trails */
    
    /* Effect instances */
    effect_instance_t effects[50];      /**< Effect pool */
    int effect_count;                   /**< Active effects */
    
    /* Resources */
    Texture2D particle_texture;         /**< Particle texture */
    Texture2D explosion_texture;        /**< Explosion texture */
    Shader particle_shader;             /**< Particle shader */
    
    /* Settings */
    float quality_level;                /**< Effect quality (0.0-1.0) */
    bool enable_particles;              /**< Enable particle effects */
    bool enable_trails;                 /**< Enable projectile trails */
    bool enable_screen_effects;         /**< Enable screen effects */
} effects_multiplayer_t;

/*
 * Core Functions
 */

/**
 * @brief Create effects system
 * @param max_particles Maximum particle count
 * @return Allocated effects system or NULL on failure
 */
effects_multiplayer_t* effects_multiplayer_create(int max_particles);

/**
 * @brief Destroy effects system
 * @param effects Effects system to destroy
 */
void effects_multiplayer_destroy(effects_multiplayer_t* effects);

/**
 * @brief Load effect resources
 * @param effects Effects system
 * @return true on success
 */
bool effects_multiplayer_load_resources(effects_multiplayer_t* effects);

/*
 * Update Functions
 */

/**
 * @brief Update all effects
 * @param effects Effects system
 * @param dt Delta time
 */
void effects_multiplayer_update(effects_multiplayer_t* effects, float dt);

/**
 * @brief Update particles
 * @param effects Effects system
 * @param dt Delta time
 */
void effects_update_particles(effects_multiplayer_t* effects, float dt);

/**
 * @brief Update emitters
 * @param effects Effects system
 * @param dt Delta time
 */
void effects_update_emitters(effects_multiplayer_t* effects, float dt);

/**
 * @brief Update trails
 * @param effects Effects system
 * @param dt Delta time
 */
void effects_update_trails(effects_multiplayer_t* effects, float dt);

/*
 * Effect Creation
 */

/**
 * @brief Create explosion effect
 * @param effects Effects system
 * @param position Explosion position
 * @param scale Explosion scale
 * @param color Explosion color
 */
void effects_create_explosion(effects_multiplayer_t* effects,
                            Vector3 position,
                            float scale,
                            Color color);

/**
 * @brief Create projectile impact
 * @param effects Effects system
 * @param position Impact position
 * @param normal Surface normal
 * @param projectile_type Type of projectile
 */
void effects_create_impact(effects_multiplayer_t* effects,
                         Vector3 position,
                         Vector3 normal,
                         weapon_type_t projectile_type);

/**
 * @brief Create continuous smoke
 * @param effects Effects system
 * @param position Smoke source
 * @param intensity Smoke intensity
 * @return Emitter ID for control
 */
int effects_create_smoke(effects_multiplayer_t* effects,
                        Vector3 position,
                        float intensity);

/**
 * @brief Create engine trail
 * @param effects Effects system
 * @param position Engine position
 * @param velocity Aircraft velocity
 * @param throttle Engine throttle (0.0-1.0)
 * @return Trail ID for updates
 */
int effects_create_engine_trail(effects_multiplayer_t* effects,
                              Vector3 position,
                              Vector3 velocity,
                              float throttle);

/**
 * @brief Create power-up collection effect
 * @param effects Effects system
 * @param position Collection position
 * @param powerup_color Power-up color
 */
void effects_create_powerup_collect(effects_multiplayer_t* effects,
                                  Vector3 position,
                                  Color powerup_color);

/**
 * @brief Update projectile trail
 * @param effects Effects system
 * @param trail_id Trail ID from creation
 * @param position New projectile position
 */
void effects_update_projectile_trail(effects_multiplayer_t* effects,
                                   int trail_id,
                                   Vector3 position);

/**
 * @brief Stop emitter
 * @param effects Effects system
 * @param emitter_id Emitter to stop
 */
void effects_stop_emitter(effects_multiplayer_t* effects, int emitter_id);

/*
 * Rendering
 */

/**
 * @brief Render all effects
 * @param effects Effects system
 * @param camera Camera for billboarding
 */
void effects_multiplayer_render(const effects_multiplayer_t* effects,
                              Camera3D camera);

/**
 * @brief Render particles
 * @param effects Effects system
 * @param camera Camera for billboarding
 */
void effects_render_particles(const effects_multiplayer_t* effects,
                            Camera3D camera);

/**
 * @brief Render trails
 * @param effects Effects system
 */
void effects_render_trails(const effects_multiplayer_t* effects);

/**
 * @brief Render screen effects (damage flash, etc)
 * @param effects Effects system
 * @param damage_flash Damage flash intensity
 */
void effects_render_screen(const effects_multiplayer_t* effects,
                         float damage_flash);

/*
 * Configuration
 */

/**
 * @brief Set effect quality level
 * @param effects Effects system
 * @param quality Quality level (0.0=low, 1.0=high)
 */
void effects_multiplayer_set_quality(effects_multiplayer_t* effects,
                                   float quality);

/**
 * @brief Enable/disable effect categories
 * @param effects Effects system
 * @param particles Enable particles
 * @param trails Enable trails
 * @param screen Enable screen effects
 */
void effects_multiplayer_set_enabled(effects_multiplayer_t* effects,
                                   bool particles,
                                   bool trails,
                                   bool screen);

/**
 * @brief Clear all active effects
 * @param effects Effects system
 */
void effects_multiplayer_clear(effects_multiplayer_t* effects);

#endif /* SKY_COMBAT_EFFECTS_MULTIPLAYER_H */
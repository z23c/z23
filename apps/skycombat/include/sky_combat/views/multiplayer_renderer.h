/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_MULTIPLAYER_RENDERER_H
#define SKY_COMBAT_MULTIPLAYER_RENDERER_H

/**
 * @file multiplayer_renderer.h
 * @brief Main renderer coordinating all view components for multiplayer
 * 
 * This is the integration layer that brings together:
 * - Camera system
 * - Aircraft rendering
 * - HUD system
 * - Visual effects
 * - World rendering
 */

#include <raylib.h>
#include <stdbool.h>
#include "sky_combat/views/camera_controller.h"
#include "sky_combat/views/aircraft_view.h"
#include "sky_combat/views/hud_multiplayer.h"
#include "sky_combat/views/effects_multiplayer.h"
#include "sky_combat/models/aircraft_manager.h"
#include "sky_combat/models/match_rules.h"
#include "sky_combat/models/powerups.h"
#include "sky_combat/models/cyberpunk_world.h"

/** Render settings */
typedef struct {
    /* Quality settings */
    int shadow_quality;         /**< Shadow map resolution (0=off, 1=low, 2=high) */
    bool enable_bloom;          /**< Post-process bloom */
    bool enable_motion_blur;    /**< Motion blur effect */
    bool enable_reflections;    /**< Water/building reflections */
    float render_distance;      /**< Far clipping distance */
    
    /* Performance */
    bool enable_frustum_culling; /**< Cull off-screen objects */
    bool enable_lod;            /**< Level of detail system */
    int max_rendered_aircraft;  /**< Limit rendered aircraft */
    
    /* Debug */
    bool show_fps;              /**< FPS counter */
    bool show_debug_info;       /**< Debug overlay */
    bool show_hitboxes;         /**< Collision boxes */
} render_settings_t;

/** Frame statistics */
typedef struct {
    float fps;                  /**< Current FPS */
    float frame_time;           /**< Frame time in ms */
    int draw_calls;             /**< Draw calls this frame */
    int particles_rendered;     /**< Particle count */
    int aircraft_visible;       /**< Visible aircraft */
} frame_stats_t;

/**
 * @brief Multiplayer renderer state
 */
typedef struct {
    /* View components */
    camera_controller_t* camera;        /**< Camera system */
    aircraft_view_t* aircraft_view;     /**< Aircraft renderer */
    hud_multiplayer_t* hud;            /**< HUD system */
    effects_multiplayer_t* effects;     /**< Effects system */
    
    /* World rendering */
    cyberpunk_world_t* world;          /**< World environment */
    Shader lighting_shader;            /**< Main lighting shader */
    RenderTexture2D shadow_map;        /**< Shadow map texture */
    
    /* Post-processing */
    RenderTexture2D frame_buffer;      /**< Main frame buffer */
    RenderTexture2D bloom_buffer;      /**< Bloom effect buffer */
    Shader post_shader;                /**< Post-process shader */
    
    /* Settings */
    render_settings_t settings;        /**< Render settings */
    int screen_width;                  /**< Screen width */
    int screen_height;                 /**< Screen height */
    
    /* Performance */
    frame_stats_t stats;               /**< Frame statistics */
    float stat_update_timer;           /**< Stats update timer */
    
    /* State */
    int local_player_id;               /**< Local player aircraft */
    bool initialized;                  /**< Initialization flag */
} multiplayer_renderer_t;

/*
 * Core Functions
 */

/**
 * @brief Create multiplayer renderer
 * @param screen_width Initial screen width
 * @param screen_height Initial screen height
 * @return Allocated renderer or NULL on failure
 */
multiplayer_renderer_t* multiplayer_renderer_create(int screen_width,
                                                  int screen_height);

/**
 * @brief Destroy multiplayer renderer
 * @param renderer Renderer to destroy
 */
void multiplayer_renderer_destroy(multiplayer_renderer_t* renderer);

/**
 * @brief Initialize renderer resources
 * @param renderer Renderer
 * @param world World to render
 * @return true on success
 */
bool multiplayer_renderer_init(multiplayer_renderer_t* renderer,
                             cyberpunk_world_t* world);

/**
 * @brief Set local player for camera and HUD
 * @param renderer Renderer
 * @param player_id Local player aircraft ID
 */
void multiplayer_renderer_set_player(multiplayer_renderer_t* renderer,
                                   int player_id);

/*
 * Update Functions
 */

/**
 * @brief Update renderer state
 * @param renderer Renderer
 * @param aircraft_mgr Aircraft manager
 * @param match Match state
 * @param powerup_mgr Power-up manager
 * @param dt Delta time
 */
void multiplayer_renderer_update(multiplayer_renderer_t* renderer,
                               const aircraft_manager_t* aircraft_mgr,
                               const match_state_t* match,
                               const powerup_manager_t* powerup_mgr,
                               float dt);

/**
 * @brief Handle window resize
 * @param renderer Renderer
 * @param width New width
 * @param height New height
 */
void multiplayer_renderer_resize(multiplayer_renderer_t* renderer,
                               int width, int height);

/*
 * Rendering Functions
 */

/**
 * @brief Render complete frame
 * @param renderer Renderer
 * @param aircraft_mgr Aircraft to render
 * @param match Match state
 * @param powerup_mgr Power-ups to render
 */
void multiplayer_renderer_render(multiplayer_renderer_t* renderer,
                               const aircraft_manager_t* aircraft_mgr,
                               const match_state_t* match,
                               const powerup_manager_t* powerup_mgr);

/**
 * @brief Render 3D world and objects
 * @param renderer Renderer
 * @param aircraft_mgr Aircraft manager
 * @param powerup_mgr Power-up manager
 */
void multiplayer_renderer_render_world(multiplayer_renderer_t* renderer,
                                     const aircraft_manager_t* aircraft_mgr,
                                     const powerup_manager_t* powerup_mgr);

/**
 * @brief Render 2D UI elements
 * @param renderer Renderer
 * @param aircraft_mgr Aircraft manager
 * @param match Match state
 * @param powerup_mgr Power-up manager
 */
void multiplayer_renderer_render_ui(multiplayer_renderer_t* renderer,
                                  const aircraft_manager_t* aircraft_mgr,
                                  const match_state_t* match,
                                  const powerup_manager_t* powerup_mgr);

/**
 * @brief Apply post-processing effects
 * @param renderer Renderer
 */
void multiplayer_renderer_post_process(multiplayer_renderer_t* renderer);

/*
 * Effect Triggers
 */

/**
 * @brief Trigger explosion effect
 * @param renderer Renderer
 * @param position Explosion position
 * @param scale Explosion scale
 */
void multiplayer_renderer_explosion(multiplayer_renderer_t* renderer,
                                  Vector3 position,
                                  float scale);

/**
 * @brief Trigger projectile hit
 * @param renderer Renderer
 * @param position Hit position
 * @param weapon_type Weapon that hit
 */
void multiplayer_renderer_projectile_hit(multiplayer_renderer_t* renderer,
                                       Vector3 position,
                                       weapon_type_t weapon_type);

/**
 * @brief Trigger power-up collection
 * @param renderer Renderer
 * @param position Collection position
 * @param powerup_type Type collected
 */
void multiplayer_renderer_powerup_collect(multiplayer_renderer_t* renderer,
                                        Vector3 position,
                                        powerup_type_t powerup_type);

/**
 * @brief Trigger kill notification
 * @param renderer Renderer
 * @param killer_name Killer name
 * @param victim_name Victim name
 * @param killer_color Killer color
 * @param victim_color Victim color
 */
void multiplayer_renderer_kill_event(multiplayer_renderer_t* renderer,
                                   const char* killer_name,
                                   const char* victim_name,
                                   Color killer_color,
                                   Color victim_color);

/*
 * Configuration
 */

/**
 * @brief Update render settings
 * @param renderer Renderer
 * @param settings New settings
 */
void multiplayer_renderer_set_settings(multiplayer_renderer_t* renderer,
                                     render_settings_t settings);

/**
 * @brief Set camera mode
 * @param renderer Renderer
 * @param mode Camera mode
 * @param transition_time Transition duration
 */
void multiplayer_renderer_set_camera_mode(multiplayer_renderer_t* renderer,
                                        camera_mode_t mode,
                                        float transition_time);

/**
 * @brief Get current frame statistics
 * @param renderer Renderer
 * @return Frame statistics
 */
frame_stats_t multiplayer_renderer_get_stats(const multiplayer_renderer_t* renderer);

/**
 * @brief Get camera for external use
 * @param renderer Renderer
 * @return Camera pointer
 */
Camera3D* multiplayer_renderer_get_camera(multiplayer_renderer_t* renderer);

#endif /* SKY_COMBAT_MULTIPLAYER_RENDERER_H */
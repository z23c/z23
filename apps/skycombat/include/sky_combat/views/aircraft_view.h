/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_AIRCRAFT_VIEW_H
#define SKY_COMBAT_AIRCRAFT_VIEW_H

/**
 * @file aircraft_view.h
 * @brief Aircraft rendering system for multiplayer Sky Combat
 * 
 * Features:
 * - Model rendering with team colors
 * - Damage visualization
 * - Power-up effects
 * - Engine trails
 * - Weapon effects
 */

#include <raylib.h>
#include <stdbool.h>
#include "sky_combat/models/aircraft_manager.h"

/** Aircraft visual state */
typedef struct {
    /* Model data */
    Model model;                        /**< 3D model */
    Texture2D texture;                  /**< Base texture */
    bool model_loaded;                  /**< Model loaded flag */
    
    /* Team coloring */
    Color team_color;                   /**< Team color overlay */
    Color engine_color;                 /**< Engine glow color */
    float color_intensity;              /**< Color blend factor */
    
    /* Damage visualization */
    float damage_flash;                 /**< Damage flash intensity */
    float damage_smoke;                 /**< Smoke particle density */
    bool show_fire;                     /**< Show fire effects */
    
    /* Power-up effects */
    bool shield_active;                 /**< Shield bubble visible */
    float shield_opacity;               /**< Shield transparency */
    Color powerup_glow;                 /**< Power-up glow color */
    float powerup_intensity;            /**< Glow intensity */
    
    /* Engine effects */
    Vector3 trail_positions[20];        /**< Trail history */
    int trail_index;                    /**< Current trail position */
    float afterburner_intensity;        /**< Afterburner effect */
    
    /* Animation */
    float propeller_angle;              /**< Propeller rotation */
    float aileron_angle;                /**< Control surface angle */
    float elevator_angle;               /**< Control surface angle */
    float rudder_angle;                 /**< Control surface angle */
} aircraft_visual_t;

/**
 * @brief Aircraft view manager
 */
typedef struct {
    /* Visual states for each aircraft */
    aircraft_visual_t visuals[MAX_MANAGED_AIRCRAFT];
    
    /* Shared resources */
    Model default_model;                /**< Default aircraft model */
    Texture2D default_texture;          /**< Default texture */
    Model shield_model;                 /**< Shield bubble model */
    Shader team_shader;                 /**< Team color shader */
    
    /* Effect settings */
    bool enable_trails;                 /**< Engine trail effect */
    bool enable_damage_effects;         /**< Damage visualization */
    bool enable_powerup_effects;        /**< Power-up glow */
    float effect_quality;               /**< Effect quality (0.0-1.0) */
    
    /* Performance */
    int visible_count;                  /**< Number of visible aircraft */
    float lod_distance;                 /**< Level of detail distance */
} aircraft_view_t;

/*
 * Core Functions
 */

/**
 * @brief Create aircraft view system
 * @return Allocated view system or NULL on failure
 */
aircraft_view_t* aircraft_view_create(void);

/**
 * @brief Destroy aircraft view system
 * @param view View system to destroy
 */
void aircraft_view_destroy(aircraft_view_t* view);

/**
 * @brief Load aircraft models and textures
 * @param view View system
 * @param model_path Path to aircraft model
 * @param texture_path Path to aircraft texture
 * @return true on success
 */
bool aircraft_view_load_resources(aircraft_view_t* view,
                                 const char* model_path,
                                 const char* texture_path);

/*
 * Update Functions
 */

/**
 * @brief Update aircraft visuals from model state
 * @param view View system
 * @param manager Aircraft manager with game state
 * @param dt Delta time
 */
void aircraft_view_update(aircraft_view_t* view,
                         const aircraft_manager_t* manager,
                         float dt);

/**
 * @brief Update visual effects for specific aircraft
 * @param view View system
 * @param aircraft_id Aircraft ID
 * @param visual Visual state to update
 * @param aircraft Aircraft data
 * @param dt Delta time
 */
void aircraft_view_update_effects(aircraft_view_t* view,
                                 int aircraft_id,
                                 aircraft_visual_t* visual,
                                 const managed_aircraft_t* aircraft,
                                 float dt);

/*
 * Rendering Functions
 */

/**
 * @brief Render all aircraft
 * @param view View system
 * @param manager Aircraft manager
 * @param camera_position Camera position for LOD
 */
void aircraft_view_render(const aircraft_view_t* view,
                         const aircraft_manager_t* manager,
                         Vector3 camera_position);

/**
 * @brief Render single aircraft
 * @param view View system
 * @param aircraft_id Aircraft ID
 * @param aircraft Aircraft data
 * @param visual Visual state
 * @param lod_level Level of detail (0=full, 1=medium, 2=low)
 */
void aircraft_view_render_aircraft(const aircraft_view_t* view,
                                  int aircraft_id,
                                  const managed_aircraft_t* aircraft,
                                  const aircraft_visual_t* visual,
                                  int lod_level);

/**
 * @brief Render aircraft effects (trails, shields, etc)
 * @param view View system
 * @param aircraft Aircraft data
 * @param visual Visual state
 */
void aircraft_view_render_effects(const aircraft_view_t* view,
                                 const managed_aircraft_t* aircraft,
                                 const aircraft_visual_t* visual);

/*
 * Effect Control
 */

/**
 * @brief Trigger damage effect
 * @param view View system
 * @param aircraft_id Aircraft that took damage
 * @param damage_amount Damage intensity
 */
void aircraft_view_damage_effect(aircraft_view_t* view,
                                int aircraft_id,
                                float damage_amount);

/**
 * @brief Trigger destruction effect
 * @param view View system
 * @param aircraft_id Aircraft that was destroyed
 * @param position Destruction position
 */
void aircraft_view_destruction_effect(aircraft_view_t* view,
                                     int aircraft_id,
                                     Vector3 position);

/**
 * @brief Set power-up visual effect
 * @param view View system
 * @param aircraft_id Aircraft with power-up
 * @param effect_color Power-up color
 * @param duration Effect duration
 */
void aircraft_view_powerup_effect(aircraft_view_t* view,
                                 int aircraft_id,
                                 Color effect_color,
                                 float duration);

/*
 * Configuration
 */

/**
 * @brief Set effect quality level
 * @param view View system
 * @param quality Quality level (0.0=low, 1.0=high)
 */
void aircraft_view_set_quality(aircraft_view_t* view, float quality);

/**
 * @brief Enable/disable specific effects
 * @param view View system
 * @param trails Enable engine trails
 * @param damage Enable damage effects
 * @param powerups Enable power-up effects
 */
void aircraft_view_set_effects(aircraft_view_t* view,
                              bool trails,
                              bool damage,
                              bool powerups);

/**
 * @brief Get aircraft screen position
 * @param view View system
 * @param aircraft Aircraft data
 * @param camera Camera for projection
 * @return Screen position or (-1,-1) if off-screen
 */
Vector2 aircraft_view_get_screen_pos(const aircraft_view_t* view,
                                    const managed_aircraft_t* aircraft,
                                    Camera3D camera);

#endif /* SKY_COMBAT_AIRCRAFT_VIEW_H */
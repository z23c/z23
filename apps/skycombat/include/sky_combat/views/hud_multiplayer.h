/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_HUD_MULTIPLAYER_H
#define SKY_COMBAT_HUD_MULTIPLAYER_H

/**
 * @file hud_multiplayer.h
 * @brief HUD system for 5-player Sky Combat
 * 
 * Features:
 * - Player status indicators
 * - Team scores
 * - Kill feed
 * - Radar system
 * - Power-up indicators
 * - Match status
 */

#include <raylib.h>
#include <stdbool.h>
#include "sky_combat/models/aircraft_manager.h"
#include "sky_combat/models/match_rules.h"
#include "sky_combat/models/powerups.h"

/** HUD element visibility */
typedef struct {
    bool health_bars;           /**< Show health bars */
    bool minimap;              /**< Show radar/minimap */
    bool score_board;          /**< Show scores */
    bool kill_feed;            /**< Show kill messages */
    bool power_ups;            /**< Show power-up status */
    bool weapon_status;        /**< Show weapon info */
    bool match_timer;          /**< Show match time */
    bool team_indicators;      /**< Show team status */
} hud_visibility_t;

/** Kill feed entry */
typedef struct {
    char killer_name[32];      /**< Killer name */
    char victim_name[32];      /**< Victim name */
    Color killer_color;        /**< Killer team color */
    Color victim_color;        /**< Victim team color */
    float display_time;        /**< Time remaining to show */
    bool is_suicide;          /**< Self-destruction */
} kill_feed_entry_t;

/** Radar blip */
typedef struct {
    Vector2 position;          /**< Relative position */
    Color color;              /**< Team color */
    bool is_enemy;            /**< Enemy indicator */
    bool is_locked;           /**< Locked by player */
    float distance;           /**< Distance to player */
} radar_blip_t;

/**
 * @brief HUD state manager
 */
typedef struct {
    /* Configuration */
    hud_visibility_t visibility;        /**< Element visibility */
    int local_player_id;               /**< Local player aircraft ID */
    
    /* Layout settings */
    int screen_width;                  /**< Screen width */
    int screen_height;                 /**< Screen height */
    float ui_scale;                    /**< UI scaling factor */
    Font font;                         /**< UI font */
    
    /* Kill feed */
    kill_feed_entry_t kill_feed[10];   /**< Recent kills */
    int kill_feed_count;               /**< Active entries */
    
    /* Radar */
    float radar_range;                 /**< Radar range in units */
    float radar_size;                  /**< Radar display size */
    Vector2 radar_position;            /**< Radar screen position */
    
    /* Animations */
    float damage_flash;                /**< Damage indicator flash */
    float kill_notification_time;      /**< Kill notification timer */
    char last_kill_message[64];        /**< Last kill message */
    
    /* Performance */
    float update_timer;                /**< Update rate limiter */
} hud_multiplayer_t;

/*
 * Core Functions
 */

/**
 * @brief Create HUD system
 * @param screen_width Screen width
 * @param screen_height Screen height
 * @return Allocated HUD system or NULL on failure
 */
hud_multiplayer_t* hud_multiplayer_create(int screen_width, int screen_height);

/**
 * @brief Destroy HUD system
 * @param hud HUD system to destroy
 */
void hud_multiplayer_destroy(hud_multiplayer_t* hud);

/**
 * @brief Set local player for HUD
 * @param hud HUD system
 * @param player_id Local player aircraft ID
 */
void hud_multiplayer_set_player(hud_multiplayer_t* hud, int player_id);

/**
 * @brief Resize HUD for new screen dimensions
 * @param hud HUD system
 * @param width New screen width
 * @param height New screen height
 */
void hud_multiplayer_resize(hud_multiplayer_t* hud, int width, int height);

/*
 * Update Functions
 */

/**
 * @brief Update HUD state
 * @param hud HUD system
 * @param dt Delta time
 */
void hud_multiplayer_update(hud_multiplayer_t* hud, float dt);

/**
 * @brief Add kill to feed
 * @param hud HUD system
 * @param killer_name Killer name
 * @param victim_name Victim name
 * @param killer_color Killer team color
 * @param victim_color Victim team color
 */
void hud_multiplayer_add_kill(hud_multiplayer_t* hud,
                             const char* killer_name,
                             const char* victim_name,
                             Color killer_color,
                             Color victim_color);

/**
 * @brief Trigger damage indicator
 * @param hud HUD system
 * @param intensity Damage intensity (0.0-1.0)
 */
void hud_multiplayer_damage_flash(hud_multiplayer_t* hud, float intensity);

/*
 * Rendering Functions
 */

/**
 * @brief Render complete HUD
 * @param hud HUD system
 * @param aircraft_mgr Aircraft manager
 * @param match Match state
 * @param powerup_mgr Power-up manager
 * @param camera Camera for world-to-screen
 */
void hud_multiplayer_render(const hud_multiplayer_t* hud,
                           const aircraft_manager_t* aircraft_mgr,
                           const match_state_t* match,
                           const powerup_manager_t* powerup_mgr,
                           Camera3D camera);

/**
 * @brief Render player status (health, ammo, etc)
 * @param hud HUD system
 * @param player Player aircraft data
 */
void hud_render_player_status(const hud_multiplayer_t* hud,
                             const managed_aircraft_t* player);

/**
 * @brief Render team scores
 * @param hud HUD system
 * @param match Match state with scores
 */
void hud_render_team_scores(const hud_multiplayer_t* hud,
                           const match_state_t* match);

/**
 * @brief Render minimap/radar
 * @param hud HUD system
 * @param aircraft_mgr Aircraft positions
 * @param player_pos Local player position
 * @param player_rotation Local player rotation
 */
void hud_render_radar(const hud_multiplayer_t* hud,
                     const aircraft_manager_t* aircraft_mgr,
                     Vector3 player_pos,
                     float player_rotation);

/**
 * @brief Render kill feed
 * @param hud HUD system
 */
void hud_render_kill_feed(const hud_multiplayer_t* hud);

/**
 * @brief Render match timer and status
 * @param hud HUD system
 * @param match Match state
 */
void hud_render_match_status(const hud_multiplayer_t* hud,
                            const match_state_t* match);

/**
 * @brief Render power-up indicators
 * @param hud HUD system
 * @param player Player with power-ups
 */
void hud_render_powerup_status(const hud_multiplayer_t* hud,
                              const managed_aircraft_t* player);

/**
 * @brief Render enemy indicators in 3D space
 * @param hud HUD system
 * @param aircraft_mgr Aircraft manager
 * @param camera Camera for projection
 */
void hud_render_world_indicators(const hud_multiplayer_t* hud,
                                const aircraft_manager_t* aircraft_mgr,
                                Camera3D camera);

/*
 * Configuration
 */

/**
 * @brief Set HUD element visibility
 * @param hud HUD system
 * @param visibility Visibility flags
 */
void hud_multiplayer_set_visibility(hud_multiplayer_t* hud,
                                   hud_visibility_t visibility);

/**
 * @brief Set UI scale factor
 * @param hud HUD system
 * @param scale Scale factor (1.0 = default)
 */
void hud_multiplayer_set_scale(hud_multiplayer_t* hud, float scale);

/**
 * @brief Set radar range
 * @param hud HUD system
 * @param range Range in world units
 */
void hud_multiplayer_set_radar_range(hud_multiplayer_t* hud, float range);

#endif /* SKY_COMBAT_HUD_MULTIPLAYER_H */
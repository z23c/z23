/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_AIRCRAFT_MANAGER_H
#define SKY_COMBAT_AIRCRAFT_MANAGER_H

/**
 * @file aircraft_manager.h
 * @brief Aircraft management system for Sky Combat multiplayer
 * 
 * This module provides a complete aircraft management system including:
 * - Aircraft lifecycle management (creation, destruction, respawning)
 * - Team assignment and management
 * - AI behavior and targeting
 * - Collision detection and damage handling
 * - Power-up effect integration
 * - Spawn point management
 */

#include "sky_combat/models/aircraft.h"
#include "sky_combat/models/weapons.h"
#include "sky_combat/models/powerups.h"
#include <raylib.h>
#include <stdbool.h>

/** Maximum number of aircraft that can be managed simultaneously */
#define MAX_MANAGED_AIRCRAFT 5

/** Maximum number of spawn points */
#define MAX_SPAWN_POINTS 20

/** Maximum length of aircraft name */
#define AIRCRAFT_NAME_LENGTH 32

/**
 * @brief Managed aircraft structure containing all aircraft state
 * 
 * This structure extends the basic aircraft_t with additional game state
 * including health, scoring, team assignment, AI behavior, and power-ups.
 */
typedef struct {
    aircraft_t* aircraft;           /**< Core aircraft model */
    weapons_system_t* weapons;      /**< Weapons system */
    
    /* Identity */
    int id;                         /**< Unique aircraft ID (0-based index) */
    char name[AIRCRAFT_NAME_LENGTH]; /**< Display name */
    Color color;                    /**< Aircraft color for rendering */
    bool is_ai;                     /**< True if AI controlled */
    bool is_local_player;           /**< True if controlled by local player */
    
    /* Game state */
    float health;                   /**< Current health (0-max_health) */
    float max_health;               /**< Maximum health (default 100) */
    int kills;                      /**< Number of enemy aircraft destroyed */
    int deaths;                     /**< Number of times destroyed */
    int assists;                    /**< Number of assists (damage without kill) */
    float respawn_timer;            /**< Time until respawn (0 = alive) */
    
    /* Team system */
    int team_id;                    /**< Team ID (-1 for no team/FFA) */
    
    /* AI behavior */
    int target_id;                  /**< Current target aircraft ID (-1 for none) */
    float ai_skill;                 /**< AI skill level (0.0-1.0) */
    float ai_aggression;            /**< Aggression level (0.0-1.0) */
    
    /* Power-up system */
    powerup_effects_t powerup_effects; /**< Active power-up effects */
} managed_aircraft_t;

/**
 * @brief Aircraft manager structure
 * 
 * Central management system for all aircraft in the game. Handles
 * spawning, updates, collisions, and lifecycle management.
 */
typedef struct {
    managed_aircraft_t aircraft[MAX_MANAGED_AIRCRAFT]; /**< Aircraft array */
    int aircraft_count;                                /**< Number of active aircraft */
    
    /* Spawn system */
    Vector3 spawn_points[MAX_SPAWN_POINTS];            /**< Available spawn locations */
    int spawn_count;                                   /**< Number of spawn points */
    
    /* Collision parameters */
    float collision_radius;                            /**< Aircraft-aircraft collision radius */
    float projectile_radius;                           /**< Projectile hit detection radius */
} aircraft_manager_t;

/*
 * Core Management Functions
 */

/**
 * @brief Create a new aircraft manager
 * @return Pointer to allocated manager or NULL on failure
 * @note Caller must call aircraft_manager_destroy() when done
 */
aircraft_manager_t* aircraft_manager_create(void);

/**
 * @brief Destroy an aircraft manager and all managed aircraft
 * @param manager Manager to destroy (can be NULL)
 */
void aircraft_manager_destroy(aircraft_manager_t* manager);

/*
 * Aircraft Management Functions
 */

/**
 * @brief Add a new aircraft without team assignment
 * @param manager Aircraft manager
 * @param name Display name (max 31 characters)
 * @param color Aircraft color
 * @param is_ai True for AI control, false for player
 * @param is_local True if controlled by local player
 * @return Aircraft ID (0-based) or -1 on failure
 */
int aircraft_manager_add(aircraft_manager_t* manager, const char* name, 
                        Color color, bool is_ai, bool is_local);

/**
 * @brief Add a new aircraft with team assignment
 * @param manager Aircraft manager
 * @param name Display name (max 31 characters)
 * @param color Aircraft color
 * @param is_ai True for AI control, false for player
 * @param is_local True if controlled by local player
 * @param team_id Team ID (0-3) or -1 for no team
 * @return Aircraft ID (0-based) or -1 on failure
 */
int aircraft_manager_add_with_team(aircraft_manager_t* manager, const char* name,
                                  Color color, bool is_ai, bool is_local, int team_id);

/**
 * @brief Remove an aircraft from management
 * @param manager Aircraft manager
 * @param id Aircraft ID to remove
 * @note IDs of remaining aircraft may change after removal
 */
void aircraft_manager_remove(aircraft_manager_t* manager, int id);

/**
 * @brief Get aircraft by ID
 * @param manager Aircraft manager
 * @param id Aircraft ID
 * @return Pointer to aircraft or NULL if invalid ID
 */
managed_aircraft_t* aircraft_manager_get(aircraft_manager_t* manager, int id);

/*
 * Update Functions
 */

/**
 * @brief Update all managed aircraft
 * @param manager Aircraft manager
 * @param dt Delta time in seconds
 * 
 * This function:
 * - Updates AI behavior
 * - Updates weapons and power-ups
 * - Checks collisions
 * - Handles respawning
 */
void aircraft_manager_update(aircraft_manager_t* manager, float dt);

/**
 * @brief Update AI behavior for a specific aircraft
 * @param manager Aircraft manager
 * @param ai Aircraft to update (must have is_ai = true)
 * @param dt Delta time in seconds
 */
void aircraft_manager_update_ai(aircraft_manager_t* manager, 
                               managed_aircraft_t* ai, float dt);

/*
 * Combat Functions
 */

/**
 * @brief Fire weapon for specified aircraft
 * @param manager Aircraft manager
 * @param aircraft_id Aircraft ID
 */
void aircraft_manager_fire_weapon(aircraft_manager_t* manager, int aircraft_id);

/**
 * @brief Fire weapon with aiming adjustment
 * @param manager Aircraft manager
 * @param aircraft_id Aircraft ID
 * @param aim_x Horizontal aim adjustment (-1 to 1)
 * @param aim_y Vertical aim adjustment (-1 to 1)
 */
void aircraft_manager_fire_weapon_aimed(aircraft_manager_t* manager, int aircraft_id,
                                       float aim_x, float aim_y);

/**
 * @brief Check all collisions (projectile-aircraft and aircraft-aircraft)
 * @param manager Aircraft manager
 */
void aircraft_manager_check_collisions(aircraft_manager_t* manager);

/**
 * @brief Apply damage to an aircraft
 * @param manager Aircraft manager
 * @param id Aircraft ID to damage
 * @param damage Amount of damage to apply
 * @param attacker_id ID of attacking aircraft (-1 for environmental)
 */
void aircraft_manager_damage_aircraft(aircraft_manager_t* manager, int id, 
                                    float damage, int attacker_id);

/**
 * @brief Respawn an aircraft at a random spawn point
 * @param manager Aircraft manager
 * @param id Aircraft ID to respawn
 */
void aircraft_manager_respawn(aircraft_manager_t* manager, int id);

/*
 * Utility Functions
 */

/**
 * @brief Get a random spawn point
 * @param manager Aircraft manager
 * @return Random spawn position
 */
Vector3 aircraft_manager_get_spawn_point(aircraft_manager_t* manager);

/**
 * @brief Find nearest enemy aircraft
 * @param manager Aircraft manager
 * @param aircraft_id Aircraft ID searching for enemy
 * @return Enemy aircraft ID or -1 if none found
 * @note Considers team assignments - teammates are not enemies
 */
int aircraft_manager_find_nearest_enemy(aircraft_manager_t* manager, int aircraft_id);

/**
 * @brief Calculate distance between two aircraft
 * @param manager Aircraft manager
 * @param id1 First aircraft ID
 * @param id2 Second aircraft ID
 * @return Distance in world units or INFINITY if invalid IDs
 */
float aircraft_manager_distance_between(aircraft_manager_t* manager, int id1, int id2);

#endif /* SKY_COMBAT_AIRCRAFT_MANAGER_H */
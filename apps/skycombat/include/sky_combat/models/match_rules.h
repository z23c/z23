/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_MATCH_RULES_H
#define SKY_COMBAT_MATCH_RULES_H

#include <stdbool.h>

typedef enum {
    MATCH_TYPE_DEATHMATCH,      // Free for all
    MATCH_TYPE_TEAM_DEATHMATCH, // Team vs team
    MATCH_TYPE_ELIMINATION,     // Last one standing, no respawn
    MATCH_TYPE_KING_OF_HILL,    // Control a zone
    MATCH_TYPE_CAPTURE_FLAG     // Capture the flag
} match_type_t;

typedef enum {
    TEAM_NONE = -1,
    TEAM_RED = 0,
    TEAM_BLUE = 1,
    TEAM_GREEN = 2,
    TEAM_YELLOW = 3
} team_id_t;

typedef struct {
    match_type_t type;
    
    // Win conditions
    int score_limit;        // First to X kills/points wins
    float time_limit;       // Match duration in seconds (0 = unlimited)
    
    // Respawn rules
    float respawn_time;     // Seconds until respawn
    bool allow_respawn;     // Can players respawn?
    int lives_per_player;   // Lives in elimination mode
    
    // Team settings
    bool teams_enabled;
    int team_count;         // Number of teams (2-4)
    bool friendly_fire;     // Can damage teammates
    
    // Scoring
    int points_per_kill;
    int points_per_death;   // Negative points
    int points_per_assist;
    int points_per_objective;
    
    // Zone control (for king of hill)
    float zone_capture_time;
    float zone_points_per_second;
    
} match_rules_t;

typedef struct {
    match_rules_t rules;
    
    // Match state
    float elapsed_time;
    bool match_started;
    bool match_ended;
    int winning_team;
    int winning_player;
    
    // Team scores
    int team_scores[4];
    
    // Zone control state
    int zone_controller;    // Team or player controlling zone
    float zone_control_time;
    float zone_contest_time;
    
} match_state_t;

// Core functions
match_state_t* match_state_create(match_type_t type);
void match_state_destroy(match_state_t* state);
void match_state_update(match_state_t* state, float dt);

// Rule presets
void match_rules_deathmatch(match_rules_t* rules, int score_limit);
void match_rules_team_deathmatch(match_rules_t* rules, int score_limit, int teams);
void match_rules_elimination(match_rules_t* rules, int lives);
void match_rules_king_of_hill(match_rules_t* rules, float time_limit);

// Score management
void match_add_score(match_state_t* state, int player_id, int team_id, int points);
void match_player_killed(match_state_t* state, int killer_id, int victim_id, int killer_team, int victim_team);

// Win condition checks
bool match_check_win_condition(match_state_t* state, int* winner_id, bool* is_team);
bool match_is_over(match_state_t* state);

// Team assignment
team_id_t match_assign_team(match_state_t* state, int current_players[4]);

#endif
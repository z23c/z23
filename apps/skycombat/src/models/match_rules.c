/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/models/match_rules.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

match_state_t* match_state_create(match_type_t type) {
    match_state_t* state = calloc(1, sizeof(match_state_t));
    if (!state) return NULL;
    
    state->rules.type = type;
    state->winning_team = -1;
    state->winning_player = -1;
    state->zone_controller = -1;
    
    // Set default rules based on type
    switch (type) {
        case MATCH_TYPE_DEATHMATCH:
            match_rules_deathmatch(&state->rules, 20);
            break;
        case MATCH_TYPE_TEAM_DEATHMATCH:
            match_rules_team_deathmatch(&state->rules, 30, 2);
            break;
        case MATCH_TYPE_ELIMINATION:
            match_rules_elimination(&state->rules, 3);
            break;
        case MATCH_TYPE_KING_OF_HILL:
            match_rules_king_of_hill(&state->rules, 300.0f); // 5 minutes
            break;
        case MATCH_TYPE_CAPTURE_FLAG:
            state->rules.score_limit = 3; // 3 captures to win
            state->rules.teams_enabled = true;
            state->rules.team_count = 2;
            break;
    }
    
    return state;
}

void match_state_destroy(match_state_t* state) {
    free(state);
}

void match_state_update(match_state_t* state, float dt) {
    if (!state->match_started || state->match_ended) return;
    
    state->elapsed_time += dt;
    
    // Check time limit
    if (state->rules.time_limit > 0 && state->elapsed_time >= state->rules.time_limit) {
        state->match_ended = true;
        
        // Determine winner by score
        if (state->rules.teams_enabled) {
            int max_score = -9999;
            for (int i = 0; i < state->rules.team_count; i++) {
                if (state->team_scores[i] > max_score) {
                    max_score = state->team_scores[i];
                    state->winning_team = i;
                }
            }
        }
    }
    
    // Update zone control
    if (state->rules.type == MATCH_TYPE_KING_OF_HILL && state->zone_controller >= 0) {
        state->zone_control_time += dt;
        
        // Award points for zone control
        float points = state->rules.zone_points_per_second * dt;
        if (state->rules.teams_enabled) {
            state->team_scores[state->zone_controller] += (int)points;
        }
    }
}

void match_rules_deathmatch(match_rules_t* rules, int score_limit) {
    rules->type = MATCH_TYPE_DEATHMATCH;
    rules->score_limit = score_limit;
    rules->time_limit = 0; // No time limit
    rules->respawn_time = 3.0f;
    rules->allow_respawn = true;
    rules->teams_enabled = false;
    rules->points_per_kill = 1;
    rules->points_per_death = 0;
    rules->points_per_assist = 0;
}

void match_rules_team_deathmatch(match_rules_t* rules, int score_limit, int teams) {
    rules->type = MATCH_TYPE_TEAM_DEATHMATCH;
    rules->score_limit = score_limit;
    rules->time_limit = 600.0f; // 10 minutes
    rules->respawn_time = 5.0f;
    rules->allow_respawn = true;
    rules->teams_enabled = true;
    rules->team_count = teams;
    rules->friendly_fire = false;
    rules->points_per_kill = 1;
    rules->points_per_death = 0;
    rules->points_per_assist = 0;
}

void match_rules_elimination(match_rules_t* rules, int lives) {
    rules->type = MATCH_TYPE_ELIMINATION;
    rules->score_limit = 1; // Last one standing
    rules->time_limit = 0;
    rules->allow_respawn = false;
    rules->lives_per_player = lives;
    rules->teams_enabled = false;
    rules->points_per_kill = 0; // Lives matter, not points
}

void match_rules_king_of_hill(match_rules_t* rules, float time_limit) {
    rules->type = MATCH_TYPE_KING_OF_HILL;
    rules->score_limit = 100; // First to 100 points
    rules->time_limit = time_limit;
    rules->respawn_time = 5.0f;
    rules->allow_respawn = true;
    rules->teams_enabled = true;
    rules->team_count = 2;
    rules->friendly_fire = false;
    rules->zone_capture_time = 3.0f;
    rules->zone_points_per_second = 1.0f;
    rules->points_per_kill = 5;
}

void match_add_score(match_state_t* state, int player_id, int team_id, int points) {
    if (state->rules.teams_enabled && team_id >= 0 && team_id < state->rules.team_count) {
        state->team_scores[team_id] += points;
        
        // Check win condition
        if (state->team_scores[team_id] >= state->rules.score_limit) {
            state->match_ended = true;
            state->winning_team = team_id;
        }
    }
}

void match_player_killed(match_state_t* state, int killer_id, int victim_id, int killer_team, int victim_team) {
    if (!state->match_started || state->match_ended) return;
    
    // Award points
    if (killer_id >= 0 && killer_id != victim_id) {
        if (state->rules.teams_enabled) {
            // Team kill check
            if (killer_team != victim_team || state->rules.friendly_fire) {
                match_add_score(state, killer_id, killer_team, state->rules.points_per_kill);
            }
        } else {
            // Free for all - killer gets points directly
            match_add_score(state, killer_id, -1, state->rules.points_per_kill);
        }
    }
    
    // Deduct points for death
    if (state->rules.points_per_death < 0) {
        match_add_score(state, victim_id, victim_team, state->rules.points_per_death);
    }
}

bool match_check_win_condition(match_state_t* state, int* winner_id, bool* is_team) {
    if (!state->match_ended) return false;
    
    if (state->rules.teams_enabled) {
        *winner_id = state->winning_team;
        *is_team = true;
    } else {
        *winner_id = state->winning_player;
        *is_team = false;
    }
    
    return true;
}

bool match_is_over(match_state_t* state) {
    return state->match_ended;
}

team_id_t match_assign_team(match_state_t* state, int current_players[4]) {
    if (!state->rules.teams_enabled) return TEAM_NONE;
    
    // Count players per team
    int min_count = 999;
    int min_team = 0;
    
    for (int i = 0; i < state->rules.team_count; i++) {
        if (current_players[i] < min_count) {
            min_count = current_players[i];
            min_team = i;
        }
    }
    
    return (team_id_t)min_team;
}
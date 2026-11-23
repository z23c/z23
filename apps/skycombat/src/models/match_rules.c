/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sky Combat: match scoring, teams and win conditions.
 */

/* GCC uses the build's -ffp-contract=off; Clang also enforces it here. */
#if defined(__clang__)
#pragma STDC FP_CONTRACT OFF
#endif

#include "sky_combat/models/match_rules.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <limits.h>

match_state_t* match_state_create(match_type_t type) {
    if ((unsigned)type > MATCH_TYPE_CAPTURE_FLAG) {
        fprintf(stderr, "match create: invalid type\n"); return NULL;
    }
    match_state_t* state = calloc(1, sizeof(match_state_t));
    if (!state) { fprintf(stderr, "match create: allocation failed\n"); return NULL; }
    
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

static int match_leader(const match_state_t *s) {
    int best = s->team_scores[0], winner = 0;
    for (int i = 1; i < s->rules.team_count; ++i) {
        if (s->team_scores[i] > best) { best = s->team_scores[i]; winner = i; }
        else if (s->team_scores[i] == best) winner = -1;
    }
    return winner;
}

static bool match_rules_valid(const match_rules_t *r) {
    const float f[] = {r->time_limit, r->respawn_time, r->zone_capture_time, r->zone_points_per_second};
    for (unsigned i = 0; i < sizeof(f)/sizeof(f[0]); ++i)
        if (!isfinite(f[i]) || signbit(f[i]) || f[i] > 1000000.0f) return false;
    return (unsigned)r->type <= MATCH_TYPE_CAPTURE_FLAG &&
        r->score_limit >= 1 && r->score_limit <= 1000000 && r->team_count >= 0 &&
        r->team_count <= 4 && (!r->teams_enabled || r->team_count >= 2);
}

bool match_state_begin(match_state_t *s) {
    if (!s || s->match_started || s->match_ended || s->elapsed_time != 0 ||
        s->winning_team != -1 || s->winning_player != -1 ||
        s->zone_control_time != 0 || s->zone_contest_time != 0) {
        fprintf(stderr, "match begin: no pristine ledger\n"); return false;
    }
    if (!match_rules_valid(&s->rules)) {
        fprintf(stderr, "match begin: invalid rules\n"); return false;
    }
    if (s->zone_controller < -1 || s->zone_controller >= (s->rules.teams_enabled ? s->rules.team_count : 5)) {
        fprintf(stderr, "match begin: invalid zone controller\n"); return false;
    }
    for (int i = 0; i < 4; ++i)
        if (s->team_scores[i] != 0) { fprintf(stderr, "match begin: nonzero scores\n"); return false; }
    s->match_started = true;
    return true;
}

bool match_state_finish(match_state_t *s) {
    if (!s || !s->match_started || s->match_ended) {
        fprintf(stderr, "match finish: no active match\n"); return false;
    }
    if (s->rules.teams_enabled) {
        if (s->rules.team_count < 2 || s->rules.team_count > 4) {
            fprintf(stderr, "match finish: invalid team count\n"); return false;
        }
        s->winning_team = match_leader(s);
    }
    s->match_ended = true;
    return true;
}

bool match_state_set_team_scores(match_state_t *s, const int scores[4]) {
    if (!s || !scores || !s->match_started || s->match_ended || !s->rules.teams_enabled ||
        s->rules.team_count < 2 || s->rules.team_count > 4) {
        fprintf(stderr, "match scores: no active team match\n"); return false;
    }
    for (int i = 0; i < 4; ++i) {
        if (scores[i] < 0 || scores[i] > 1000000 || (i >= s->rules.team_count && scores[i] != 0)) {
            fprintf(stderr, "match scores: invalid score\n"); return false;
        }
    }
    memmove(s->team_scores, scores, sizeof(s->team_scores));
    for (int i = 0; i < s->rules.team_count; ++i)
        if (scores[i] >= s->rules.score_limit) return match_state_finish(s);
    return true;
}

static void match_update_zone(match_state_t *s, float dt) {
    if (!s->rules.teams_enabled || s->zone_controller < 0 ||
        s->zone_controller >= s->rules.team_count || s->zone_controller >= 4) return;
    double points = (double)s->rules.zone_points_per_second * (double)dt;
    float time = s->zone_control_time + dt;
    if (!isfinite(points) || points < 0 || points >= (double)INT_MAX || !isfinite(time)) {
        fprintf(stderr, "match zone: unrepresentable award or time\n"); return;
    }
    s->zone_control_time = time;
    match_add_score(s, -1, s->zone_controller, (int)points);
}

void match_state_update(match_state_t* state, float dt) {
    if (!state || !state->match_started || state->match_ended) return;
    if (!isfinite(dt) || dt < 0 || !isfinite(state->elapsed_time + dt)) {
        fprintf(stderr, "match update: invalid timestep\n"); return;
    }
    
    state->elapsed_time += dt;
    
    // Check time limit
    if (state->rules.time_limit > 0 &&
        state->elapsed_time + 0.0001f >= state->rules.time_limit) {
        (void)match_state_finish(state);
        return;
    }
    
    // Keep zone awards inside the same checked score path.
    if (state->rules.type == MATCH_TYPE_KING_OF_HILL) match_update_zone(state, dt);
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

void match_add_score(match_state_t* state,[[maybe_unused]] int player_id, int team_id, int points) {
    if (!state || !state->match_started || state->match_ended) return;
    if (state->rules.teams_enabled && team_id >= 0 && team_id < state->rules.team_count) {
        if (team_id >= 4 || (points > 0 && state->team_scores[team_id] > INT_MAX - points) ||
            (points < 0 && state->team_scores[team_id] < INT_MIN - points)) {
            fprintf(stderr, "match score: overflow or invalid team\n"); return;
        }
        state->team_scores[team_id] += points;
        
        // Check win condition
        if (state->team_scores[team_id] >= state->rules.score_limit) {
            (void)match_state_finish(state);
        }
    }
}

void match_player_killed(match_state_t* state, int killer_id, int victim_id, int killer_team, int victim_team) {
    if (!state || !state->match_started || state->match_ended) return;
    
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
    if (!state || !winner_id || !is_team || !state->match_ended) return false;
    
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
    return state && state->match_ended;
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

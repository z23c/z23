/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_CHALLENGES_H
#define SKY_COMBAT_CHALLENGES_H

#include <raylib.h>
#include <stdbool.h>

// Challenge types for more fun gameplay
typedef enum {
    CHALLENGE_NONE = 0,
    CHALLENGE_TIME_TRIAL,      // Complete course in time limit
    CHALLENGE_PERFECT_RUN,     // Don't miss any rings
    CHALLENGE_SPEED_RUN,       // Maintain minimum speed
    CHALLENGE_TRICK_MASTER,    // Perform X barrel rolls
    CHALLENGE_SHARPSHOOTER,    // Hit all targets
    CHALLENGE_SLALOM,          // Fly through gates in order
    CHALLENGE_BOSS_FIGHT,      // Defeat sky fortress
    CHALLENGE_RACE,            // Race against AI planes
    CHALLENGE_SURVIVAL,        // Dodge obstacles
    CHALLENGE_COMBO_KING       // Maintain combo multiplier
} challenge_type_t;

typedef struct {
    challenge_type_t type;
    const char* name;
    const char* description;
    int target_value;
    int current_value;
    float time_limit;
    float time_elapsed;
    bool completed;
    bool failed;
    int reward_score;
} challenge_t;

// Special objects for challenges
typedef struct {
    Vector3 position;
    Vector3 size;
    Color color;
    bool hit;
    int points;
} target_t;

typedef struct {
    Vector3 position;
    Vector3 velocity;
    float rotation;
    float size;
    bool active;
} obstacle_t;

typedef struct {
    Vector3 position;
    Vector3 target;
    float speed;
    float roll;
    float skill_level;  // 0.0 to 1.0
    bool finished;
} ai_racer_t;

// Challenge management
challenge_t* challenge_create(challenge_type_t type, int difficulty);
void challenge_update(challenge_t* challenge, float delta_time);
void challenge_draw_hud(challenge_t* challenge);
bool challenge_check_completion(challenge_t* challenge);

// Special challenge objects
void target_spawn_pattern(target_t* targets, int count, Vector3 center);
void obstacle_create_field(obstacle_t* obstacles, int count, Vector3 center);
void ai_racer_init(ai_racer_t* racer, int skill_level);
void ai_racer_update(ai_racer_t* racer, Vector3 next_ring, float delta_time);

// Fun effects
void challenge_play_fanfare(challenge_t* challenge);
void challenge_spawn_fireworks(Vector3 position);
void challenge_create_rainbow_trail(Vector3 start, Vector3 end);

#endif // SKY_COMBAT_CHALLENGES_H
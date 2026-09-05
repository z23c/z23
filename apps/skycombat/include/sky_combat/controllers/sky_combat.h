/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_H
#define SKY_COMBAT_H

#include <raylib.h>

// Game constants
#define SKY_COMBAT_VERSION "1.0.0"
#define SKY_COMBAT_DEFAULT_WIDTH 1280
#define SKY_COMBAT_DEFAULT_HEIGHT 720

// Forward declarations
typedef struct sky_combat_game sky_combat_game_t;

// Game creation and lifecycle
sky_combat_game_t* sky_combat_create(int width, int height, const char* title);
void sky_combat_destroy(sky_combat_game_t* game);
void sky_combat_run(sky_combat_game_t* game);

// Game configuration
void sky_combat_set_course(sky_combat_game_t* game, int course_id);
void sky_combat_enable_joystick(sky_combat_game_t* game, bool enable);
void sky_combat_set_difficulty(sky_combat_game_t* game, int difficulty);

// Game state queries
int sky_combat_get_score(sky_combat_game_t* game);
int sky_combat_get_rings_collected(sky_combat_game_t* game);
float sky_combat_get_time_elapsed(sky_combat_game_t* game);
bool sky_combat_is_complete(sky_combat_game_t* game);

#endif // SKY_COMBAT_H
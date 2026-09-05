/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef BUILDING_SYSTEM_H
#define BUILDING_SYSTEM_H

#include "../specifications/3d_building_specs.h"

/* Forward declarations */
typedef struct game_building game_building_t;

/* Building management functions */
game_building_t* create_building(int type, float x, float z);
void destroy_building(game_building_t* building);
void generate_city_block(game_building_t** buildings, int* count);

/* Character interaction */
bool can_enter_building(const character_state_t* character, 
                       const building_spec_t* building,
                       const aabb_t* building_bounds);
                       
void update_character_in_building(character_state_t* character, 
                                 const game_building_t* building,
                                 float delta_time);
                                 
void transition_to_flying(character_state_t* character, 
                         const game_building_t* building);

/* Collision detection */
bool check_building_collision(const aabb_t* character_bounds,
                             const aabb_t* building_bounds);

/* Rendering hints */
void get_building_render_data(const game_building_t* building,
                             float* vertices, int* vertex_count,
                             int* indices, int* index_count);

#endif /* BUILDING_SYSTEM_H */
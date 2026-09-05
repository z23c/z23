/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef BUILDING_TYPES_H
#define BUILDING_TYPES_H

#include "../specifications/3d_building_specs.h"

/* Building types */
typedef enum {
    BUILDING_TOWER,
    BUILDING_WAREHOUSE,
    BUILDING_COMPLEX,
    BUILDING_FORTRESS
} building_type_t;

/* Game building structure */
typedef struct {
    building_spec_t spec;
    building_type_t type;
    float world_x;
    float world_z;
    uint32_t num_rooms;
    uint32_t num_stairs;
    uint32_t num_windows;
    bool has_elevator;
    bool has_rooftop_access;
    bool contains_powerup;
    bool is_capturable;
    uint32_t texture_id;
    uint32_t color_scheme;
} game_building_t;

#endif /* BUILDING_TYPES_H */
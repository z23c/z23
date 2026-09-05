/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../include/building_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>

/* Create a validated building */
game_building_t* create_building(int type, float x, float z) {
    game_building_t* building = calloc(1, sizeof(game_building_t));
    if (!building) return NULL;
    
    building->type = (building_type_t)type;
    building->world_x = x;
    building->world_z = z;
    
    /* Set dimensions based on type */
    switch (type) {
        case BUILDING_TOWER:
            building->spec.width = 20.0f;
            building->spec.depth = 20.0f;
            building->spec.height = 60.0f;
            building->spec.num_floors = 15;
            building->has_elevator = true;
            break;
            
        case BUILDING_WAREHOUSE:
            building->spec.width = 50.0f;
            building->spec.depth = 40.0f;
            building->spec.height = 12.0f;
            building->spec.num_floors = 2;
            building->has_elevator = false;
            break;
            
        case BUILDING_COMPLEX:
            building->spec.width = 35.0f;
            building->spec.depth = 35.0f;
            building->spec.height = 25.0f;
            building->spec.num_floors = 6;
            building->has_elevator = true;
            break;
            
        case BUILDING_FORTRESS:
            building->spec.width = 40.0f;
            building->spec.depth = 40.0f;
            building->spec.height = 30.0f;
            building->spec.num_floors = 5;
            building->has_rooftop_access = true;
            break;
    }
    
    /* All buildings MUST have interiors */
    building->spec.has_interior = true;
    building->spec.is_enterable = true;
    
    /* Calculate floor heights */
    float floor_height = (building->spec.height - FLOOR_THICKNESS) / building->spec.num_floors;
    for (uint32_t i = 0; i < building->spec.num_floors; i++) {
        building->spec.floor_heights[i] = i * floor_height + FLOOR_THICKNESS;
    }
    
    /* Validate the building meets ALL specifications */
    PROVE_BUILDING_VALID(&building->spec);
    PROVE_CHARACTER_FITS(&building->spec);
    
    /* Calculate interior volume to ensure it meets minimum */
    float interior_volume = building->spec.width * 
                           building->spec.depth * 
                           (building->spec.height - FLOOR_THICKNESS * building->spec.num_floors);
    
    assert(interior_volume >= BUILDING_MIN_INTERIOR_VOLUME);
    
    /* Set gameplay features */
    building->num_rooms = building->spec.num_floors * 4;
    building->num_stairs = building->spec.num_floors - 1;
    building->num_windows = building->spec.num_floors * 8;
    building->is_capturable = (type == BUILDING_FORTRESS);
    building->contains_powerup = (rand() % 100 < 20);
    
    printf("Created %s building: %.1fx%.1fx%.1f with %d floors\n",
           type == BUILDING_TOWER ? "TOWER" :
           type == BUILDING_WAREHOUSE ? "WAREHOUSE" :
           type == BUILDING_COMPLEX ? "COMPLEX" : "FORTRESS",
           building->spec.width, building->spec.depth, building->spec.height,
           building->spec.num_floors);
    
    return building;
}

/* Generate a city block with validated buildings */
void generate_city_block(game_building_t** buildings, int* count) {
    const int GRID_SIZE = 5;
    const float SPACING = 100.0f;
    
    *count = GRID_SIZE * GRID_SIZE;
    *buildings = calloc(*count, sizeof(game_building_t));
    
    int idx = 0;
    for (int x = 0; x < GRID_SIZE; x++) {
        for (int z = 0; z < GRID_SIZE; z++) {
            /* Mix of building types */
            building_type_t type = (building_type_t)(rand() % 4);
            
            /* Create and validate each building */
            game_building_t* building = create_building(type, 
                                                       x * SPACING, 
                                                       z * SPACING);
            if (building) {
                (*buildings)[idx++] = *building;
                free(building);
            }
        }
    }
    
    printf("\nGenerated city block with %d buildings\n", idx);
    printf("All buildings validated for 3D walkable interiors!\n");
}
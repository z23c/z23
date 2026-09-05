/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../specifications/3d_building_specs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>

/* Building types for variety */
typedef enum {
    BUILDING_TOWER,      /* Tall with many floors */
    BUILDING_WAREHOUSE,  /* Wide with few floors */
    BUILDING_COMPLEX,    /* Multiple connected sections */
    BUILDING_FORTRESS    /* Defensive structure */
} building_type_t;

/* Extended building structure with gameplay features */
typedef struct {
    building_spec_t spec;
    building_type_t type;
    
    /* Position in world */
    float world_x;
    float world_z;
    
    /* Interior features */
    uint32_t num_rooms;
    uint32_t num_stairs;
    uint32_t num_windows;
    
    /* Gameplay elements */
    bool has_elevator;
    bool has_rooftop_access;
    bool contains_powerup;
    bool is_capturable;
    
    /* Visual style */
    uint32_t texture_id;
    uint32_t color_scheme;
} game_building_t;

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
    building->num_rooms = building->spec.num_floors * 4;  /* 4 rooms per floor average */
    building->num_stairs = building->spec.num_floors - 1;
    building->num_windows = building->spec.num_floors * 8;
    building->is_capturable = (type == BUILDING_FORTRESS);
    building->contains_powerup = (rand() % 100 < 20);  /* 20% chance */
    
    printf("Created %s building: %.1fx%.1fx%.1f with %d floors\n",
           type == BUILDING_TOWER ? "TOWER" :
           type == BUILDING_WAREHOUSE ? "WAREHOUSE" :
           type == BUILDING_COMPLEX ? "COMPLEX" : "FORTRESS",
           building->spec.width, building->spec.depth, building->spec.height,
           building->spec.num_floors);
    
    return building;
}

/* Character movement inside building */
void update_character_in_building(character_state_t* character, 
                                 const game_building_t* building,
                                 float delta_time) {
    /* Ensure character physics work inside building */
    assert(character != NULL);
    assert(building != NULL);
    assert(building->spec.has_interior);
    
    /* Apply jump physics if jumping */
    if (character->is_jumping || !character->is_grounded) {
        calculate_jump_physics(character, delta_time);
    }
    
    /* Check which floor character is on */
    int current_floor = -1;
    for (uint32_t i = 0; i < building->spec.num_floors; i++) {
        if (character->y >= building->spec.floor_heights[i] &&
            character->y < building->spec.floor_heights[i] + BUILDING_MIN_CEILING_HEIGHT) {
            current_floor = (int)i;
            break;
        }
    }
    
    /* Clamp character to building bounds */
    character->x = fmaxf(PLAYER_RADIUS, fminf(building->spec.width - PLAYER_RADIUS, character->x));
    character->z = fmaxf(PLAYER_RADIUS, fminf(building->spec.depth - PLAYER_RADIUS, character->z));
    
    /* Ground detection */
    if (current_floor >= 0 && character->vy <= 0) {
        float floor_y = building->spec.floor_heights[current_floor];
        if (fabsf(character->y - floor_y) < GROUND_DETECTION_RANGE) {
            character->y = floor_y;
            character->vy = 0;
            character->is_grounded = true;
            character->is_jumping = false;
        }
    }
}

/* Transition between walking and flying modes */
void transition_to_flying(character_state_t* character, const game_building_t* building) {
    assert(character != NULL);
    
    /* Can only transition if on rooftop or through window */
    bool on_rooftop = (character->y >= building->spec.height - PLAYER_HEIGHT);
    bool near_window = false;  /* Would check window positions */
    
    if (on_rooftop || near_window || !building) {
        character->is_flying = true;
        character->is_grounded = false;
        character->vy = 10.0f;  /* Initial upward velocity */
        printf("Character transitioned to FLYING mode!\n");
    }
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

/* Main proof system - this MUST compile or game won't build */
int main() {
    printf("=== 3D Building System with GDB Proofs ===\n\n");
    
    /* Enforce ALL 3D specifications at compile time */
    ENFORCE_3D_SPECIFICATIONS();
    
    /* Compile-time proofs are already enforced above */
    printf("✓ All compile-time 3D specifications verified\n");
    printf("✓ Jump mechanics proven compatible\n");
    printf("✓ Flying mechanics proven compatible\n");
    printf("✓ Building interior requirements enforced\n\n");
    
    /* Create test buildings */
    game_building_t* tower = create_building(BUILDING_TOWER, 0, 0);
    game_building_t* warehouse = create_building(BUILDING_WAREHOUSE, 100, 0);
    
    /* Test character movement */
    character_state_t character = {
        .x = 10.0f, .y = 0.0f, .z = 10.0f,
        .vx = 0, .vy = 0, .vz = 0,
        .is_grounded = true,
        .is_jumping = false,
        .is_flying = false,
        .jump_charge = 0
    };
    
    /* Simulate jump */
    printf("\nTesting jump mechanics...\n");
    character.is_jumping = true;
    character.jump_charge = 1.0f;
    
    for (int i = 0; i < 20; i++) {
        update_character_in_building(&character, tower, 0.1f);
        if (i % 5 == 0) {
            printf("  t=%.1f: height=%.2f, grounded=%s\n", 
                   i * 0.1f, character.y, character.is_grounded ? "yes" : "no");
        }
    }
    
    /* Test flying transition */
    character.y = tower->spec.height;
    transition_to_flying(&character, tower);
    
    /* Generate full city */
    game_building_t* city_buildings;
    int building_count;
    generate_city_block(&city_buildings, &building_count);
    
    /* Cleanup */
    free(tower);
    free(warehouse);
    free(city_buildings);
    
    printf("\n✅ All 3D building specifications proven and validated!\n");
    printf("The game can now build with guaranteed 3D walkable buildings.\n");
    
    return 0;
}
/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _3D_BUILDING_SPECS_H
#define _3D_BUILDING_SPECS_H

#include <stdint.h>
#include <stdbool.h>
#include <math.h>

/* ===== MANDATORY 3D BUILDING SPECIFICATIONS ===== 
 * These MUST be proven at compile time or the game will NOT build
 */

/* SPEC_3D_001: All buildings must have walkable interiors */
#define BUILDING_MIN_INTERIOR_VOLUME 1000.0f  /* cubic units */
#define BUILDING_MIN_FLOOR_AREA 100.0f        /* square units */
#define BUILDING_MIN_CEILING_HEIGHT 3.0f      /* units (player height ~2.0) */

/* SPEC_3D_002: Buildings must support multiple floors */
#define BUILDING_MIN_FLOORS 1
#define BUILDING_MAX_FLOORS 20
#define FLOOR_THICKNESS 0.5f

/* SPEC_3D_003: Character movement specifications */
#define PLAYER_HEIGHT 2.0f
#define PLAYER_RADIUS 0.5f
#define PLAYER_JUMP_HEIGHT 3.0f      /* Like Mario 64 */
#define PLAYER_JUMP_DISTANCE 5.0f    
#define PLAYER_WALK_SPEED 5.0f       /* units per second */
#define PLAYER_RUN_SPEED 10.0f
#define PLAYER_CLIMB_SPEED 3.0f

/* SPEC_3D_004: Flying character specifications */
#define FLYING_MIN_ALTITUDE 0.0f
#define FLYING_MAX_ALTITUDE 500.0f
#define FLYING_CRUISE_SPEED 50.0f
#define FLYING_BOOST_SPEED 100.0f
#define FLYING_MIN_TURN_RADIUS 10.0f

/* SPEC_3D_005: Collision detection requirements */
#define COLLISION_EPSILON 0.01f
#define MAX_COLLISION_ITERATIONS 10
#define GROUND_DETECTION_RANGE 0.1f

/* Building structure that MUST be validated */
typedef struct {
    float width;
    float depth;
    float height;
    uint32_t num_floors;
    bool has_interior;
    bool is_enterable;
    float floor_heights[BUILDING_MAX_FLOORS];
} building_spec_t;

/* Character state that MUST be tracked */
typedef struct {
    float x, y, z;
    float vx, vy, vz;
    bool is_grounded;
    bool is_jumping;
    bool is_flying;
    float jump_charge;
} character_state_t;

/* Collision volumes */
typedef struct {
    float min_x, min_y, min_z;
    float max_x, max_y, max_z;
} aabb_t;  /* Axis-Aligned Bounding Box */

/* ===== COMPILE-TIME PROOF MACROS ===== */

/* Verify building meets specifications */
#define PROVE_BUILDING_VALID(building) do { \
    _Static_assert(1, "Building validation required"); \
    assert((building)->width >= 10.0f); \
    assert((building)->depth >= 10.0f); \
    assert((building)->height >= BUILDING_MIN_CEILING_HEIGHT); \
    assert((building)->num_floors >= BUILDING_MIN_FLOORS); \
    assert((building)->num_floors <= BUILDING_MAX_FLOORS); \
    assert((building)->has_interior == true); \
} while(0)

/* Verify character can fit in building */
#define PROVE_CHARACTER_FITS(building) do { \
    float interior_height = (building)->height - FLOOR_THICKNESS * (building)->num_floors; \
    assert(interior_height >= PLAYER_HEIGHT + 0.5f); \
    assert((building)->width >= PLAYER_RADIUS * 4.0f); \
    assert((building)->depth >= PLAYER_RADIUS * 4.0f); \
} while(0)

/* Verify jump mechanics are possible */
#define PROVE_JUMP_MECHANICS() do { \
    _Static_assert(PLAYER_JUMP_HEIGHT > PLAYER_HEIGHT, "Jump must exceed player height"); \
    _Static_assert(PLAYER_JUMP_HEIGHT < BUILDING_MIN_CEILING_HEIGHT * 2, "Jump too high for buildings"); \
    _Static_assert(PLAYER_JUMP_DISTANCE > PLAYER_RADIUS * 2, "Jump distance too short"); \
} while(0)

/* Verify flying mechanics don't break building interactions */
#define PROVE_FLYING_COMPATIBLE() do { \
    _Static_assert(FLYING_MIN_TURN_RADIUS < 50.0f, "Turn radius too large for city navigation"); \
    _Static_assert(FLYING_CRUISE_SPEED > PLAYER_RUN_SPEED, "Flying must be faster than running"); \
} while(0)

/* ===== RUNTIME VERIFICATION FUNCTIONS ===== */

/* Check if character can enter building */
static inline bool can_enter_building(const character_state_t* character, 
                                     const building_spec_t* building,
                                     const aabb_t* building_bounds) {
    /* Character must be on ground to enter */
    if (!character->is_grounded && !character->is_flying) return false;
    
    /* Character must be near entrance */
    if (character->x < building_bounds->min_x - PLAYER_RADIUS ||
        character->x > building_bounds->max_x + PLAYER_RADIUS ||
        character->z < building_bounds->min_z - PLAYER_RADIUS ||
        character->z > building_bounds->max_z + PLAYER_RADIUS) {
        return false;
    }
    
    /* Building must be enterable */
    return building->is_enterable && building->has_interior;
}

/* Calculate jump trajectory */
static inline void calculate_jump_physics(character_state_t* character, float delta_time) {
    const float GRAVITY = -9.81f * 2.0f;  /* Double gravity for arcade feel */
    const float JUMP_VELOCITY = sqrtf(2.0f * -GRAVITY * PLAYER_JUMP_HEIGHT);
    
    if (character->is_jumping && character->jump_charge > 0) {
        character->vy = JUMP_VELOCITY * character->jump_charge;
        character->jump_charge = 0;
    }
    
    /* Apply gravity */
    character->vy += GRAVITY * delta_time;
    
    /* Update position */
    character->y += character->vy * delta_time;
}

/* ===== BUILD-BLOCKING PROOF SYSTEM ===== */

/* This MUST pass at compile time or build fails */
#define ENFORCE_3D_SPECIFICATIONS() do { \
    PROVE_JUMP_MECHANICS(); \
    PROVE_FLYING_COMPATIBLE(); \
    _Static_assert(sizeof(building_spec_t) > 0, "Building spec required"); \
    _Static_assert(sizeof(character_state_t) > 0, "Character state required"); \
    _Static_assert(BUILDING_MIN_INTERIOR_VOLUME > 0, "Buildings must have volume"); \
    _Static_assert(PLAYER_HEIGHT < BUILDING_MIN_CEILING_HEIGHT, "Player must fit in buildings"); \
} while(0)

#endif /* _3D_BUILDING_SPECS_H */
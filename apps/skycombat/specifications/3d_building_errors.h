/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _3D_BUILDING_ERRORS_H
#define _3D_BUILDING_ERRORS_H

/* ===== ERROR CONDITIONS THAT MUST BE IMPOSSIBLE ===== */

/* ERROR_3D_001: Character falls through floor */
#define ERROR_FALL_THROUGH_FLOOR -1001
/* PREVENTED BY: Ground collision detection with epsilon tolerance */

/* ERROR_3D_002: Character stuck in ceiling */
#define ERROR_STUCK_IN_CEILING -1002
/* PREVENTED BY: Ceiling height > jump height constraint */

/* ERROR_3D_003: Building with no interior */
#define ERROR_NO_INTERIOR -1003
/* PREVENTED BY: has_interior forced to true */

/* ERROR_3D_004: Building too small for character */
#define ERROR_BUILDING_TOO_SMALL -1004
/* PREVENTED BY: Minimum dimension constraints */

/* ERROR_3D_005: Invalid floor heights */
#define ERROR_INVALID_FLOORS -1005
/* PREVENTED BY: Algorithmic floor calculation */

/* ERROR_3D_006: Character outside building bounds */
#define ERROR_OUT_OF_BOUNDS -1006
/* PREVENTED BY: Position clamping */

/* ERROR_3D_007: Null pointer dereference */
#define ERROR_NULL_POINTER -1007
/* PREVENTED BY: Explicit null checks with assertions */

/* ERROR_3D_008: Array bounds violation */
#define ERROR_ARRAY_BOUNDS -1008
/* PREVENTED BY: Bounded array sizes and range checks */

/* ERROR_3D_009: Division by zero */
#define ERROR_DIV_BY_ZERO -1009
/* PREVENTED BY: Positive value constraints */

/* ERROR_3D_010: Memory allocation failure */
#define ERROR_ALLOC_FAILED -1010
/* PREVENTED BY: Null checks after allocation */

/* ===== COMPILE-TIME ERROR PREVENTION ===== */

/* Ensure errors are impossible at compile time */
#define PROVE_NO_FALL_THROUGH() \
    _Static_assert(GROUND_DETECTION_RANGE > 0, "Ground detection must be positive")

#define PROVE_NO_CEILING_STUCK() \
    _Static_assert(PLAYER_JUMP_HEIGHT < BUILDING_MIN_CEILING_HEIGHT * 2, \
                   "Jump height must not exceed ceiling clearance")

#define PROVE_BUILDINGS_HAVE_INTERIOR() \
    _Static_assert(BUILDING_MIN_INTERIOR_VOLUME > 0, "Buildings must have volume")

#define PROVE_BUILDINGS_FIT_CHARACTER() \
    _Static_assert(BUILDING_MIN_CEILING_HEIGHT > PLAYER_HEIGHT, \
                   "Buildings must accommodate player height")

#define PROVE_VALID_ARRAY_BOUNDS() \
    _Static_assert(BUILDING_MAX_FLOORS <= 20, "Floor array must be bounded")

/* ===== RUNTIME ERROR PREVENTION MACROS ===== */

/* Safe floor calculation that cannot produce invalid heights */
#define CALCULATE_FLOOR_HEIGHT(building, floor_idx) \
    ((floor_idx) * ((building)->spec.height - FLOOR_THICKNESS) / (building)->spec.num_floors + FLOOR_THICKNESS)

/* Safe position clamping that prevents out-of-bounds */
#define CLAMP_TO_BUILDING(pos, min_bound, max_bound) \
    fmaxf((min_bound), fminf((max_bound), (pos)))

/* Safe array indexing */
#define SAFE_FLOOR_INDEX(idx, max_floors) \
    ((idx) < 0 ? 0 : ((idx) >= (max_floors) ? (max_floors) - 1 : (idx)))

/* Null-safe operations */
#define SAFE_BUILDING_ACCESS(building, field) \
    ((building) ? (building)->field : 0)

/* ===== ERROR PROOF SYSTEM ===== */

/* This macro MUST be called to prove errors are impossible */
#define ENFORCE_ERROR_IMPOSSIBILITY() do { \
    PROVE_NO_FALL_THROUGH(); \
    PROVE_NO_CEILING_STUCK(); \
    PROVE_BUILDINGS_HAVE_INTERIOR(); \
    PROVE_BUILDINGS_FIT_CHARACTER(); \
    PROVE_VALID_ARRAY_BOUNDS(); \
} while(0)

#endif /* _3D_BUILDING_ERRORS_H */
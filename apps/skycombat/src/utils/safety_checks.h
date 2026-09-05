/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_SAFETY_CHECKS_H
#define SKY_COMBAT_SAFETY_CHECKS_H

#include <assert.h>
#include <math.h>
#include <stdlib.h>

/* Compile-time assertions */
#define STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)

/* Runtime contracts */
#define REQUIRES(cond) assert(cond)
#define ENSURES(cond) assert(cond)
#define INVARIANT(cond) assert(cond)

/* Safe array access */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define SAFE_ARRAY_INDEX(arr, idx) \
    (REQUIRES((idx) >= 0 && (idx) < ARRAY_SIZE(arr)), (arr)[idx])

/* Null pointer checks */
#define NOT_NULL(ptr) (REQUIRES((ptr) != NULL), (ptr))

/* Range checks */
#define IN_RANGE(val, min, max) \
    (REQUIRES((val) >= (min) && (val) <= (max)), (val))

/* Float safety */
#define NOT_NAN(val) (REQUIRES(!isnan(val)), (val))
#define NOT_INF(val) (REQUIRES(!isinf(val)), (val))
#define NONZERO(val) (REQUIRES(fabs(val) > 0.00001f), (val))

/* Example usage:
 * 
 * float safe_divide(float a, float b) {
 *     return NOT_NAN(a) / NONZERO(b);
 * }
 * 
 * void update_aircraft(aircraft_t* aircraft, int id) {
 *     NOT_NULL(aircraft);
 *     IN_RANGE(id, 0, MAX_AIRCRAFT - 1);
 *     // ... rest of function
 * }
 */

#endif /* SKY_COMBAT_SAFETY_CHECKS_H */
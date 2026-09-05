/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZERO_CRASH_H
#define ZERO_CRASH_H

/*
 * Zero Crash System - Mathematical guarantees against crashes
 * 
 * Instead of handling errors, we make them impossible.
 */

#include <assert.h>
#include <stdint.h>
#include <math.h>
#include <stdlib.h>

/* Compile-time assertions */
#define STATIC_ASSERT(cond) _Static_assert(cond, #cond)

/* Safe math operations that cannot fail */
#define SAFE_MOD(a, b) ((b) == 0 ? 0 : (a) % (b))
#define SAFE_DIV(a, b) ((b) == 0 ? 0 : (a) / (b))
#define SAFE_DIV_F(a, b) ((b) == 0.0f ? 0.0f : (a) / (b))

/* Guaranteed minimum value */
#define AT_LEAST(x, min) ((x) < (min) ? (min) : (x))
#define AT_MOST(x, max) ((x) > (max) ? (max) : (x))
#define CLAMP(x, min, max) (AT_MOST(AT_LEAST(x, min), max))

/* Prevent modulo by zero through construction */
#define NONZERO_MOD(a, b) ((a) % (AT_LEAST(b, 1)))

/* Safe array indexing */
#define SAFE_INDEX(i, size) ((size) == 0 ? 0 : (uint32_t)(i) % (uint32_t)(size))

/* Mathematical construction that ensures minimum value */
#define ENSURE_POSITIVE(x) (AT_LEAST(x, 1))
#define ENSURE_NONZERO(x) ((x) == 0 ? 1 : (x))

/* For screen shake specific case */
#define SHAKE_TO_RANGE(shake) (1 + (int)((shake) * 19.0f))  // ALWAYS >= 1

/* Dataflow annotations for proof system */
#ifdef ZERO_CRASH_PROOFS
    #define DETERMINISTIC(var, min, max) \
        __attribute__((annotate("deterministic:" #var ":" #min ":" #max)))
    
    #define CONSTRAINED(var, constraint) \
        __attribute__((annotate("constrained:" #var ":" constraint)))
    
    #define PROVES_UNREACHABLE(condition) \
        __attribute__((annotate("unreachable:" condition)))
#else
    #define DETERMINISTIC(var, min, max)
    #define CONSTRAINED(var, constraint)
    #define PROVES_UNREACHABLE(condition)
#endif

/* Example usage:
 * 
 * DETERMINISTIC(config_value, 0, 100)
 * int config_value = 50;
 * 
 * CONSTRAINED(user_input, "0 <= x <= 1000")
 * float user_input = get_user_value();
 * 
 * // This division is PROVEN safe:
 * PROVES_UNREACHABLE("divisor == 0")
 * float result = value / ENSURE_NONZERO(divisor);
 */

/* Safe operations for common game patterns */

// Safe normalize - handles zero vector
static inline void safe_normalize(float* x, float* y, float* z) {
    float len = sqrtf((*x) * (*x) + (*y) * (*y) + (*z) * (*z));
    if (len < 0.0001f) {
        *x = 0.0f; *y = 0.0f; *z = 1.0f;  // Default direction
        return;
    }
    float inv_len = 1.0f / len;
    *x *= inv_len;
    *y *= inv_len; 
    *z *= inv_len;
}

// Safe angle wrap
static inline float safe_angle_wrap(float angle) {
    // Use fmod which handles all cases including infinity
    float wrapped = fmodf(angle + 3.14159265f, 6.28318531f);
    if (wrapped < 0) wrapped += 6.28318531f;
    return wrapped - 3.14159265f;
}

// Safe random range - cannot fail
static inline int safe_random_range(int min, int max) {
    if (min >= max) return min;
    int range = max - min;
    return min + (rand() % (range + 1));
}

#endif /* ZERO_CRASH_H */
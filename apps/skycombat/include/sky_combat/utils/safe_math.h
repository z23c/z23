/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_SAFE_MATH_H
#define SKY_COMBAT_SAFE_MATH_H

#include <math.h>
#include <float.h>

// Safe division to prevent floating point exceptions
static inline float safe_divide(float numerator, float denominator) {
    if (fabsf(denominator) < FLT_EPSILON) {
        return 0.0f;  // Return 0 instead of infinity/NaN
    }
    return numerator / denominator;
}

// Safe modulo to prevent division by zero
static inline int safe_modulo(int value, int divisor) {
    if (divisor == 0) {
        return 0;
    }
    return value % divisor;
}

// Safe normalization
static inline float safe_normalize(float value, float min, float max) {
    float range = max - min;
    if (fabsf(range) < FLT_EPSILON) {
        return 0.0f;
    }
    return (value - min) / range;
}

#endif // SKY_COMBAT_SAFE_MATH_H
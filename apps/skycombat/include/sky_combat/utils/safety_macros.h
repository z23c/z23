/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SAFETY_MACROS_H
#define SAFETY_MACROS_H

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

// Safe division macros
#define SAFE_DIV(a, b) ((b) != 0 ? (a) / (b) : 0)
#define SAFE_DIV_F(a, b) (fabsf(b) > 0.0001f ? (a) / (b) : 0.0f)

// Safe array access
#define SAFE_ARRAY_ACCESS(arr, index, size, default_val) \
    ((index) >= 0 && (index) < (size) ? (arr)[index] : (default_val))

// NULL check macros
#define CHECK_NULL(ptr) do { \
    if (!(ptr)) { \
        fprintf(stderr, "NULL pointer at %s:%d\n", __FILE__, __LINE__); \
        return; \
    } \
} while(0)

#define CHECK_NULL_RETURN(ptr, retval) do { \
    if (!(ptr)) { \
        fprintf(stderr, "NULL pointer at %s:%d\n", __FILE__, __LINE__); \
        return (retval); \
    } \
} while(0)

// Allocation with automatic NULL checking
#define SAFE_CALLOC(ptr, count, size) do { \
    (ptr) = calloc((count), (size)); \
    if (!(ptr)) { \
        fprintf(stderr, "Allocation failed at %s:%d\n", __FILE__, __LINE__); \
        return NULL; \
    } \
} while(0)

// Safe string operations
#define SAFE_STRNCPY(dest, src, size) do { \
    strncpy((dest), (src), (size) - 1); \
    (dest)[(size) - 1] = '\0'; \
} while(0)

// Float comparison with epsilon
#define FLOAT_EQUAL(a, b) (fabsf((a) - (b)) < 0.0001f)
#define FLOAT_ZERO(a) (fabsf(a) < 0.0001f)

// Safe normalization
#define SAFE_NORMALIZE(vec) do { \
    float _len = Vector3Length(vec); \
    if (_len > 0.0001f) { \
        (vec) = Vector3Scale((vec), 1.0f / _len); \
    } \
} while(0)

// Safe clamping
#define CLAMP(val, min, max) \
    ((val) < (min) ? (min) : ((val) > (max) ? (max) : (val)))

// Safe increment/decrement with overflow protection
#define SAFE_INCREMENT(val, max) do { \
    if ((val) < (max)) (val)++; \
} while(0)

#define SAFE_DECREMENT(val, min) do { \
    if ((val) > (min)) (val)--; \
} while(0)

// Bounds checking for common operations
#define IN_BOUNDS(val, min, max) ((val) >= (min) && (val) <= (max))
#define ARRAY_IN_BOUNDS(index, size) ((index) >= 0 && (index) < (size))

// Safe math operations
#define SAFE_ASIN(val) (asinf(CLAMP((val), -1.0f, 1.0f)))
#define SAFE_ACOS(val) (acosf(CLAMP((val), -1.0f, 1.0f)))
#define SAFE_SQRT(val) (sqrtf(fmaxf(0.0f, (val))))

// Debug assertions that get compiled out in release
#ifdef DEBUG
    #define DEBUG_ASSERT(cond) assert(cond)
#else
    #define DEBUG_ASSERT(cond) ((void)0)
#endif

// Static assertions for compile-time checks
#define STATIC_ASSERT(cond) _Static_assert(cond, #cond)

// Cleanup goto pattern helpers
#define CLEANUP_LABEL cleanup
#define GOTO_CLEANUP goto CLEANUP_LABEL

// Memory cleanup helpers
#define SAFE_FREE(ptr) do { \
    if (ptr) { \
        free(ptr); \
        (ptr) = NULL; \
    } \
} while(0)

// Function result checking
#define CHECK_RESULT(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "Check failed: %s at %s:%d\n", #expr, __FILE__, __LINE__); \
        GOTO_CLEANUP; \
    } \
} while(0)

#endif // SAFETY_MACROS_H
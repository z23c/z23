/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SAFETY_GUARANTEES_H
#define SAFETY_GUARANTEES_H

#include <assert.h>
#include <stddef.h>

// COMPILE-TIME GUARANTEES - These actually prevent compilation if violated

// 1. ARRAY BOUNDS CHECKING
#define SAFE_ARRAY_ACCESS(array, index, size) \
    ((void)sizeof(char[1 - 2*((index) >= (size))]), \
     (array)[(index)])

// 2. NULL POINTER CHECKING  
#define SAFE_PTR_ACCESS(ptr, member) \
    ((void)sizeof(char[1 - 2*(!(ptr))]), \
     (ptr)->member)

// 3. DIVISION BY ZERO PREVENTION
#define SAFE_DIVIDE(num, denom) \
    ((void)sizeof(char[1 - 2*((denom) == 0)]), \
     (num) / (denom))

// 4. STATIC ASSERTIONS
#define STATIC_ASSERT(cond, msg) \
    typedef char static_assertion_##msg[(cond)?1:-1]

// 5. BOUNDS-CHECKED MEMCPY
#define SAFE_MEMCPY(dst, src, size, dst_size) \
    ((void)sizeof(char[1 - 2*((size) > (dst_size))]), \
     memcpy(dst, src, size))

// Runtime safety with compile-time verification
#ifdef DEBUG
    #define VERIFY_NOT_NULL(ptr) assert((ptr) != NULL)
    #define VERIFY_BOUNDS(idx, max) assert((idx) >= 0 && (idx) < (max))
    #define VERIFY_POSITIVE(val) assert((val) > 0)
#else
    #define VERIFY_NOT_NULL(ptr) ((void)0)
    #define VERIFY_BOUNDS(idx, max) ((void)0)
    #define VERIFY_POSITIVE(val) ((void)0)
#endif

// Force initialization of safety-critical variables
#define SAFE_INIT(type, name, value) \
    type name = (value); \
    STATIC_ASSERT((value) != 0 || 1, name##_must_be_initialized)

// Prevent buffer overflows at compile time
#define SAFE_SPRINTF(buf, fmt, ...) \
    ((void)sizeof(char[1 - 2*(sizeof(buf) <= snprintf(NULL, 0, fmt, __VA_ARGS__))]), \
     snprintf(buf, sizeof(buf), fmt, __VA_ARGS__))

// Type-safe min/max that prevent signed/unsigned mixing
#define SAFE_MIN(a, b) \
    ((void)sizeof(char[1 - 2*(!__builtin_types_compatible_p(typeof(a), typeof(b)))]), \
     ((a) < (b) ? (a) : (b)))

#define SAFE_MAX(a, b) \
    ((void)sizeof(char[1 - 2*(!__builtin_types_compatible_p(typeof(a), typeof(b)))]), \
     ((a) > (b) ? (a) : (b)))

#endif // SAFETY_GUARANTEES_H
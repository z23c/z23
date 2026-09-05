/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SPECIFICATION_ENFORCEMENT_H
#define SPECIFICATION_ENFORCEMENT_H

#include <assert.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * SPECIFICATION ENFORCEMENT SYSTEM
 * 
 * This header provides compile-time and runtime enforcement of specifications.
 * If a specification can be violated, it's not properly enforced.
 */

// ============================================================================
// COMPILE-TIME SPECIFICATION ENFORCEMENT
// ============================================================================

// Compile-time assertion for specifications
#define SPEC_REQUIRE(condition, message) \
    _Static_assert(condition, "SPECIFICATION VIOLATION: " message)

// Ensure pointers can never be NULL at compile time
#define SPEC_NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))

// Ensure functions are always used
#define SPEC_MUST_USE __attribute__((warn_unused_result))

// Ensure parameters are within bounds
#define SPEC_BOUNDED(min, max) __attribute__((alloc_size(min, max)))

// ============================================================================
// RUNTIME SPECIFICATION MONITORS
// ============================================================================

// Runtime specification check with safe fallback
#define SPEC_ENSURE(condition, fallback_action) do { \
    if (!(condition)) { \
        spec_violation_handler(__FILE__, __LINE__, #condition); \
        fallback_action; \
    } \
} while(0)

// Monitor that a value stays within bounds
#define SPEC_MONITOR_RANGE(value, min, max) do { \
    SPEC_ENSURE((value) >= (min) && (value) <= (max), \
                value = CLAMP(value, min, max)); \
} while(0)

// Monitor that a pointer remains valid
#define SPEC_MONITOR_PTR(ptr) do { \
    SPEC_ENSURE((ptr) != NULL, return); \
} while(0)

// ============================================================================
// SPECIFICATION-DRIVEN SAFE OPERATIONS
// ============================================================================

// Safe division that CANNOT crash (specification: no div by zero)
#define SPEC_SAFE_DIV(a, b) \
    ((b) != 0 ? (a) / (b) : (spec_division_by_zero(), 0))

// Safe array access that CANNOT overflow (specification: bounds checking)
#define SPEC_SAFE_ARRAY(arr, idx, size) \
    ((idx) < (size) ? (arr)[idx] : (spec_array_overflow(), (arr)[0]))

// Safe pointer dereference (specification: no null derefs)
#define SPEC_SAFE_DEREF(ptr, member) \
    ((ptr) ? (ptr)->member : (spec_null_deref(), 0))

// ============================================================================
// SPECIFICATION CONTRACTS
// ============================================================================

// Function precondition specification
#define SPEC_REQUIRES(condition) do { \
    if (!(condition)) { \
        spec_precondition_failed(__FUNCTION__, #condition); \
        return; \
    } \
} while(0)

// Function postcondition specification  
#define SPEC_ENSURES(condition) do { \
    if (!(condition)) { \
        spec_postcondition_failed(__FUNCTION__, #condition); \
    } \
} while(0)

// Invariant that must always hold
#define SPEC_INVARIANT(condition) do { \
    assert(condition); \
    if (!(condition)) { \
        spec_invariant_violated(#condition); \
    } \
} while(0)

// ============================================================================
// SPECIFICATION VERIFICATION POINTS
// ============================================================================

// Mark critical specification points
#define SPEC_CRITICAL_SECTION_BEGIN(name) \
    spec_enter_critical(name)

#define SPEC_CRITICAL_SECTION_END(name) \
    spec_exit_critical(name)

// Verify specification at runtime
#define SPEC_VERIFY(spec_name, condition) \
    spec_verify_runtime(spec_name, condition)

// ============================================================================
// SPECIFICATION ENFORCEMENT FUNCTIONS
// ============================================================================

// Initialize specification monitoring system
void spec_enforcement_init(void);

// Specification violation handlers
void spec_violation_handler(const char* file, int line, const char* condition);
void spec_precondition_failed(const char* function, const char* condition);
void spec_postcondition_failed(const char* function, const char* condition);
void spec_invariant_violated(const char* condition);

// Specific violation handlers
void spec_division_by_zero(void);
void spec_array_overflow(void);
void spec_null_deref(void);

// Critical section monitoring
void spec_enter_critical(const char* name);
void spec_exit_critical(const char* name);

// Runtime verification
bool spec_verify_runtime(const char* spec_name, bool condition);

// ============================================================================
// SPECIFICATION-DRIVEN TYPE SYSTEM
// ============================================================================

// Non-null pointer type
#define SPEC_NONNULL_PTR(type) type* SPEC_NONNULL(1)

// Bounded integer type
typedef struct {
    int value;
    int min;
    int max;
} spec_bounded_int_t;

// Safe string with guaranteed null termination
typedef struct {
    char data[256];
    size_t length;
} spec_safe_string_t;

// ============================================================================
// COMPILE-TIME SPECIFICATION TESTS
// ============================================================================

// Verify specifications at compile time
SPEC_REQUIRE(sizeof(int) >= 4, "int must be at least 32 bits");
SPEC_REQUIRE(NULL == 0, "NULL must be zero");

#endif // SPECIFICATION_ENFORCEMENT_H
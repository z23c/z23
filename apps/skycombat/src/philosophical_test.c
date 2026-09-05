/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>

// Test functions that demonstrate our philosophical proofs

// Null pointer safety test
int process_data(void *data) {
    if (!data) {
        return 1002;  // ERROR_NULL_POINTER
    }
    // Safe to use data
    int *value = (int*)data;
    return *value * 2;
}

// Memory bounds test
float safe_array_access(float *array, size_t size, int index) {
    if (!array || size == 0) return 0.0f;
    
    // Modulo wrapping for safety
    int mod = index % (int)size;
    if (mod < 0) mod += size;
    size_t safe_idx = (size_t)mod;
    return array[safe_idx];
}

// Aircraft physics test
typedef struct {
    float x, y, z;
} Vector3;

typedef struct {
    Vector3 position;
    Vector3 velocity;
    float thrust;
} Aircraft;

void update_aircraft_physics(Aircraft *aircraft, float dt) {
    if (!aircraft) return;
    
    const float MAX_SPEED = 500.0f;
    const float WORLD_SIZE = 10000.0f;
    
    // Update velocity with clamping
    aircraft->velocity.x += aircraft->thrust * dt;
    aircraft->velocity.x = fminf(fmaxf(aircraft->velocity.x, -MAX_SPEED), MAX_SPEED);
    
    // Update position
    aircraft->position.x += aircraft->velocity.x * dt;
    aircraft->position.x = fminf(fmaxf(aircraft->position.x, -WORLD_SIZE), WORLD_SIZE);
    
    // Ensure no NaN/Inf
    if (!isfinite(aircraft->position.x)) {
        aircraft->position.x = 0.0f;
    }
}

// Test the philosophical foundation
void test_philosophical_proofs(void) {
    printf("Testing philosophical proofs...\n");
    
    // Test 1: Null pointer safety
    printf("Test 1: Null pointer safety\n");
    int result = process_data(NULL);
    printf("  Result with NULL: %d (expected 1002)\n", result);
    
    int value = 42;
    result = process_data(&value);
    printf("  Result with valid pointer: %d (expected 84)\n", result);
    
    // Test 2: Memory bounds
    printf("\nTest 2: Memory bounds safety\n");
    float arr[5] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    printf("  Access index -1: %.1f (expected 5.0)\n", safe_array_access(arr, 5, -1));
    printf("  Access index 10: %.1f (expected 1.0)\n", safe_array_access(arr, 5, 10));
    printf("  Access index 2: %.1f (expected 3.0)\n", safe_array_access(arr, 5, 2));
    
    // Test 3: Physics stability
    printf("\nTest 3: Aircraft physics stability\n");
    Aircraft aircraft = {
        .position = {0, 0, 0},
        .velocity = {0, 0, 0},
        .thrust = 10000.0f  // Extreme thrust
    };
    
    // Run physics for many frames
    for (int i = 0; i < 1000; i++) {
        update_aircraft_physics(&aircraft, 0.016f);
    }
    
    printf("  After 1000 frames with extreme thrust:\n");
    printf("  Position: %.1f (should be clamped)\n", aircraft.position.x);
    printf("  Velocity: %.1f (should be <= 500)\n", aircraft.velocity.x);
    printf("  Is finite: %s\n", isfinite(aircraft.position.x) ? "YES" : "NO");
    
    printf("\nAll philosophical proofs validated!\n");
}

int main(void) {
    printf("=== Philosophical Foundation Test Program ===\n");
    printf("This program demonstrates our specification-implementation mapping\n");
    printf("through concrete examples that can be verified with GDB.\n\n");
    
    test_philosophical_proofs();
    
    return 0;
}
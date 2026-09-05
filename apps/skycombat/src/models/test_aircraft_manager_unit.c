/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file test_aircraft_manager_unit.c
 * @brief Unit tests for aircraft manager module
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include "sky_combat/models/aircraft_manager.h"
#include <raylib.h>
#include <raymath.h>

/* Test result tracking */
typedef struct {
    int total;
    int passed;
    int failed;
} test_results_t;

static test_results_t results = {0, 0, 0};

/* Test macros */
#define TEST_ASSERT(condition, message) do { \
    results.total++; \
    if (!(condition)) { \
        printf("  ❌ FAILED: %s\n", message); \
        results.failed++; \
    } else { \
        printf("  ✓ PASSED: %s\n", message); \
        results.passed++; \
    } \
} while(0)

#define TEST_ASSERT_NOT_NULL(ptr, message) \
    TEST_ASSERT((ptr) != NULL, message)

#define TEST_ASSERT_NULL(ptr, message) \
    TEST_ASSERT((ptr) == NULL, message)

#define TEST_ASSERT_EQUAL(a, b, message) \
    TEST_ASSERT((a) == (b), message)

#define TEST_ASSERT_NOT_EQUAL(a, b, message) \
    TEST_ASSERT((a) != (b), message)

#define TEST_ASSERT_FLOAT_EQUAL(a, b, epsilon, message) \
    TEST_ASSERT(fabsf((a) - (b)) < (epsilon), message)

#define RUN_TEST(test_func) do { \
    printf("\n=== %s ===\n", #test_func); \
    test_func(); \
} while(0)

/*
 * Test Functions
 */

void test_aircraft_manager_create_destroy(void) {
    /* Test creation */
    aircraft_manager_t* manager = aircraft_manager_create();
    TEST_ASSERT_NOT_NULL(manager, "Manager should be created successfully");
    TEST_ASSERT_EQUAL(manager->aircraft_count, 0, "Initial aircraft count should be 0");
    TEST_ASSERT(manager->spawn_count > 0, "Spawn points should be initialized");
    TEST_ASSERT(manager->collision_radius > 0, "Collision radius should be positive");
    TEST_ASSERT(manager->projectile_radius > 0, "Projectile radius should be positive");
    
    /* Test double destroy (should not crash) */
    aircraft_manager_destroy(manager);
    aircraft_manager_destroy(NULL);  /* Should handle NULL gracefully */
}

void test_aircraft_add_remove(void) {
    aircraft_manager_t* manager = aircraft_manager_create();
    TEST_ASSERT_NOT_NULL(manager, "Manager creation");
    
    /* Test adding aircraft */
    int id1 = aircraft_manager_add(manager, "Test Pilot 1", RED, false, true);
    TEST_ASSERT(id1 >= 0, "First aircraft should be added successfully");
    TEST_ASSERT_EQUAL(id1, 0, "First aircraft should have ID 0");
    TEST_ASSERT_EQUAL(manager->aircraft_count, 1, "Aircraft count should be 1");
    
    /* Test getting aircraft */
    managed_aircraft_t* ma1 = aircraft_manager_get(manager, id1);
    TEST_ASSERT_NOT_NULL(ma1, "Should get aircraft by ID");
    TEST_ASSERT_EQUAL(strcmp(ma1->name, "Test Pilot 1"), 0, "Aircraft name should match");
    TEST_ASSERT_EQUAL(ma1->is_ai, false, "Aircraft should not be AI");
    TEST_ASSERT_EQUAL(ma1->is_local_player, true, "Aircraft should be local player");
    
    /* Test adding more aircraft */
    int id2 = aircraft_manager_add(manager, "AI Enemy", BLUE, true, false);
    TEST_ASSERT(id2 >= 0, "Second aircraft should be added");
    TEST_ASSERT_EQUAL(id2, 1, "Second aircraft should have ID 1");
    TEST_ASSERT_EQUAL(manager->aircraft_count, 2, "Aircraft count should be 2");
    
    /* Test removing aircraft */
    aircraft_manager_remove(manager, id1);
    TEST_ASSERT_EQUAL(manager->aircraft_count, 1, "Aircraft count should decrease to 1");
    
    /* Verify IDs are updated after removal */
    managed_aircraft_t* ma2 = aircraft_manager_get(manager, 0);
    TEST_ASSERT_NOT_NULL(ma2, "Aircraft should be shifted down");
    TEST_ASSERT_EQUAL(strcmp(ma2->name, "AI Enemy"), 0, "Remaining aircraft should be AI Enemy");
    
    aircraft_manager_destroy(manager);
}

void test_aircraft_limits(void) {
    aircraft_manager_t* manager = aircraft_manager_create();
    TEST_ASSERT_NOT_NULL(manager, "Manager creation");
    
    /* Fill to capacity */
    int ids[MAX_MANAGED_AIRCRAFT];
    for (int i = 0; i < MAX_MANAGED_AIRCRAFT; i++) {
        char name[32];
        snprintf(name, sizeof(name), "Aircraft %d", i);
        ids[i] = aircraft_manager_add(manager, name, RED, true, false);
        TEST_ASSERT(ids[i] >= 0, "Should add aircraft within limit");
    }
    
    TEST_ASSERT_EQUAL(manager->aircraft_count, MAX_MANAGED_AIRCRAFT, 
                     "Should reach maximum capacity");
    
    /* Try to exceed limit */
    int overflow_id = aircraft_manager_add(manager, "Overflow", RED, true, false);
    TEST_ASSERT_EQUAL(overflow_id, -1, "Should reject aircraft beyond limit");
    TEST_ASSERT_EQUAL(manager->aircraft_count, MAX_MANAGED_AIRCRAFT, 
                     "Count should remain at maximum");
    
    aircraft_manager_destroy(manager);
}

void test_input_validation(void) {
    aircraft_manager_t* manager = aircraft_manager_create();
    TEST_ASSERT_NOT_NULL(manager, "Manager creation");
    
    /* Test NULL manager */
    int id = aircraft_manager_add(NULL, "Test", RED, false, false);
    TEST_ASSERT_EQUAL(id, -1, "Should reject NULL manager");
    
    /* Test empty name */
    id = aircraft_manager_add(manager, "", RED, false, false);
    TEST_ASSERT_EQUAL(id, -1, "Should reject empty name");
    
    /* Test NULL name */
    id = aircraft_manager_add(manager, NULL, RED, false, false);
    TEST_ASSERT_EQUAL(id, -1, "Should reject NULL name");
    
    /* Test invalid team ID */
    id = aircraft_manager_add_with_team(manager, "Test", RED, false, false, 5);
    TEST_ASSERT_EQUAL(id, -1, "Should reject invalid team ID (too high)");
    
    id = aircraft_manager_add_with_team(manager, "Test", RED, false, false, -2);
    TEST_ASSERT_EQUAL(id, -1, "Should reject invalid team ID (too low)");
    
    /* Test conflicting AI/local player */
    id = aircraft_manager_add(manager, "Conflict", RED, true, true);
    TEST_ASSERT_EQUAL(id, -1, "Should reject aircraft that is both AI and local");
    
    /* Test valid inputs */
    id = aircraft_manager_add_with_team(manager, "Valid", GREEN, true, false, 1);
    TEST_ASSERT(id >= 0, "Should accept valid inputs");
    
    aircraft_manager_destroy(manager);
}

void test_team_system(void) {
    aircraft_manager_t* manager = aircraft_manager_create();
    TEST_ASSERT_NOT_NULL(manager, "Manager creation");
    
    /* Add aircraft to different teams */
    int red1 = aircraft_manager_add_with_team(manager, "Red 1", RED, true, false, 0);
    int red2 = aircraft_manager_add_with_team(manager, "Red 2", RED, true, false, 0);
    int blue1 = aircraft_manager_add_with_team(manager, "Blue 1", BLUE, true, false, 1);
    int blue2 = aircraft_manager_add_with_team(manager, "Blue 2", BLUE, true, false, 1);
    int ffa = aircraft_manager_add_with_team(manager, "FFA", GREEN, true, false, -1);
    
    TEST_ASSERT(red1 >= 0 && red2 >= 0 && blue1 >= 0 && blue2 >= 0 && ffa >= 0,
               "All aircraft should be added successfully");
    
    /* Test enemy finding */
    int enemy_of_red1 = aircraft_manager_find_nearest_enemy(manager, red1);
    TEST_ASSERT(enemy_of_red1 == blue1 || enemy_of_red1 == blue2 || enemy_of_red1 == ffa,
               "Red should target Blue or FFA, not teammate");
    
    managed_aircraft_t* enemy = aircraft_manager_get(manager, enemy_of_red1);
    TEST_ASSERT_NOT_NULL(enemy, "Enemy should exist");
    TEST_ASSERT_NOT_EQUAL(enemy->team_id, 0, "Enemy should not be on Red team");
    
    aircraft_manager_destroy(manager);
}

void test_damage_and_respawn(void) {
    aircraft_manager_t* manager = aircraft_manager_create();
    TEST_ASSERT_NOT_NULL(manager, "Manager creation");
    
    int id = aircraft_manager_add(manager, "Test Target", RED, false, true);
    TEST_ASSERT(id >= 0, "Aircraft should be added");
    
    managed_aircraft_t* ma = aircraft_manager_get(manager, id);
    TEST_ASSERT_NOT_NULL(ma, "Should get aircraft");
    
    float initial_health = ma->health;
    TEST_ASSERT(initial_health > 0, "Initial health should be positive");
    
    /* Test damage */
    aircraft_manager_damage_aircraft(manager, id, 25.0f, -1);
    TEST_ASSERT_FLOAT_EQUAL(ma->health, initial_health - 25.0f, 0.01f,
                           "Health should decrease by damage amount");
    
    /* Test shield protection */
    ma->powerup_effects.shield_active = true;
    aircraft_manager_damage_aircraft(manager, id, 10.0f, -1);
    TEST_ASSERT_FLOAT_EQUAL(ma->health, initial_health - 26.0f, 0.01f,
                           "Shield should reduce damage by 90%");
    
    /* Test kill and auto-respawn */
    int initial_deaths = ma->deaths;
    
    /* Move aircraft away from spawn points to ensure position changes */
    ma->aircraft->position = (Vector3){1000, 1000, 1000};
    
    aircraft_manager_damage_aircraft(manager, id, 1000.0f, -1);
    TEST_ASSERT_EQUAL(ma->deaths, initial_deaths + 1, "Death count should increase");
    
    /* After auto-respawn, health should be restored */
    TEST_ASSERT_FLOAT_EQUAL(ma->health, ma->max_health, 0.01f,
                           "Health should be restored after respawn");
    
    /* Position should be at a spawn point (not at 1000,1000,1000) */
    TEST_ASSERT(ma->aircraft->position.x != 1000.0f || 
               ma->aircraft->position.y != 1000.0f ||
               ma->aircraft->position.z != 1000.0f,
               "Aircraft should respawn at spawn point");
    
    aircraft_manager_destroy(manager);
}

void test_collision_detection(void) {
    aircraft_manager_t* manager = aircraft_manager_create();
    TEST_ASSERT_NOT_NULL(manager, "Manager creation");
    
    /* Add two aircraft at same position */
    int id1 = aircraft_manager_add(manager, "Aircraft 1", RED, false, true);
    int id2 = aircraft_manager_add(manager, "Aircraft 2", BLUE, false, false);
    
    managed_aircraft_t* ma1 = aircraft_manager_get(manager, id1);
    managed_aircraft_t* ma2 = aircraft_manager_get(manager, id2);
    
    TEST_ASSERT_NOT_NULL(ma1, "Aircraft 1 should exist");
    TEST_ASSERT_NOT_NULL(ma2, "Aircraft 2 should exist");
    
    /* Put them at collision distance */
    ma1->aircraft->position = (Vector3){0, 100, 0};
    ma2->aircraft->position = (Vector3){5, 100, 0};  /* Within collision radius */
    
    float health1_before = ma1->health;
    float health2_before = ma2->health;
    
    /* Check collisions */
    aircraft_manager_check_collisions(manager);
    
    TEST_ASSERT(ma1->health < health1_before, "Aircraft 1 should take collision damage");
    TEST_ASSERT(ma2->health < health2_before, "Aircraft 2 should take collision damage");
    
    /* Verify they were pushed apart */
    float dist = Vector3Distance(ma1->aircraft->position, ma2->aircraft->position);
    TEST_ASSERT(dist >= manager->collision_radius * 2 - 0.1f,
               "Aircraft should be pushed apart");
    
    aircraft_manager_destroy(manager);
}

void test_ai_behavior(void) {
    aircraft_manager_t* manager = aircraft_manager_create();
    TEST_ASSERT_NOT_NULL(manager, "Manager creation");
    
    /* Add AI aircraft */
    int ai_id = aircraft_manager_add_with_team(manager, "AI Pilot", RED, true, false, 0);
    int target_id = aircraft_manager_add_with_team(manager, "Target", BLUE, false, false, 1);
    
    managed_aircraft_t* ai = aircraft_manager_get(manager, ai_id);
    managed_aircraft_t* target = aircraft_manager_get(manager, target_id);
    
    TEST_ASSERT_NOT_NULL(ai, "AI aircraft should exist");
    TEST_ASSERT_NOT_NULL(target, "Target aircraft should exist");
    
    /* Verify AI properties */
    TEST_ASSERT(ai->ai_skill >= 0.0f && ai->ai_skill <= 1.0f, 
               "AI skill should be in valid range");
    TEST_ASSERT(ai->ai_aggression >= 0.3f && ai->ai_aggression <= 1.0f,
               "AI aggression should be in valid range");
    
    /* Update AI - should target the enemy */
    aircraft_manager_update_ai(manager, ai, 0.016f);
    TEST_ASSERT_EQUAL(ai->target_id, target_id, 
                     "AI should target the enemy aircraft");
    
    aircraft_manager_destroy(manager);
}

void test_distance_calculation(void) {
    aircraft_manager_t* manager = aircraft_manager_create();
    TEST_ASSERT_NOT_NULL(manager, "Manager creation");
    
    int id1 = aircraft_manager_add(manager, "Aircraft 1", RED, false, false);
    int id2 = aircraft_manager_add(manager, "Aircraft 2", BLUE, false, false);
    
    managed_aircraft_t* ma1 = aircraft_manager_get(manager, id1);
    managed_aircraft_t* ma2 = aircraft_manager_get(manager, id2);
    
    /* Set known positions */
    ma1->aircraft->position = (Vector3){0, 0, 0};
    ma2->aircraft->position = (Vector3){3, 4, 0};  /* 3-4-5 triangle */
    
    float dist = aircraft_manager_distance_between(manager, id1, id2);
    TEST_ASSERT_FLOAT_EQUAL(dist, 5.0f, 0.01f, 
                           "Distance should be calculated correctly");
    
    /* Test invalid IDs */
    dist = aircraft_manager_distance_between(manager, -1, id2);
    TEST_ASSERT(isinf(dist), "Invalid ID should return INFINITY");
    
    dist = aircraft_manager_distance_between(manager, id1, 999);
    TEST_ASSERT(isinf(dist), "Invalid ID should return INFINITY");
    
    aircraft_manager_destroy(manager);
}

void test_memory_safety(void) {
    aircraft_manager_t* manager = aircraft_manager_create();
    TEST_ASSERT_NOT_NULL(manager, "Manager creation");
    
    /* Test operations on NULL manager */
    aircraft_manager_update(NULL, 0.016f);  /* Should not crash */
    aircraft_manager_remove(NULL, 0);        /* Should not crash */
    
    /* Test invalid IDs */
    aircraft_manager_remove(manager, -1);    /* Should not crash */
    aircraft_manager_remove(manager, 999);   /* Should not crash */
    
    managed_aircraft_t* ma = aircraft_manager_get(manager, -1);
    TEST_ASSERT_NULL(ma, "Invalid ID should return NULL");
    
    /* Test get on empty manager */
    ma = aircraft_manager_get(manager, 0);
    TEST_ASSERT_NULL(ma, "Empty manager should return NULL for any ID");
    
    /* Add and remove repeatedly to test memory management */
    for (int i = 0; i < 10; i++) {
        int id = aircraft_manager_add(manager, "Test", RED, true, false);
        TEST_ASSERT(id >= 0, "Should add aircraft");
        aircraft_manager_remove(manager, id);
        TEST_ASSERT_EQUAL(manager->aircraft_count, 0, "Should be empty after remove");
    }
    
    aircraft_manager_destroy(manager);
}

/*
 * Main test runner
 */
int main(void) {
    printf("=== AIRCRAFT MANAGER UNIT TESTS ===\n");
    
    /* Run all tests */
    RUN_TEST(test_aircraft_manager_create_destroy);
    RUN_TEST(test_aircraft_add_remove);
    RUN_TEST(test_aircraft_limits);
    RUN_TEST(test_input_validation);
    RUN_TEST(test_team_system);
    RUN_TEST(test_damage_and_respawn);
    RUN_TEST(test_collision_detection);
    RUN_TEST(test_ai_behavior);
    RUN_TEST(test_distance_calculation);
    RUN_TEST(test_memory_safety);
    
    /* Print summary */
    printf("\n=== TEST SUMMARY ===\n");
    printf("Total tests: %d\n", results.total);
    printf("Passed: %d (%.1f%%)\n", results.passed, 
           results.total > 0 ? (results.passed * 100.0f / results.total) : 0);
    printf("Failed: %d (%.1f%%)\n", results.failed,
           results.total > 0 ? (results.failed * 100.0f / results.total) : 0);
    
    if (results.failed == 0) {
        printf("\n✅ ALL TESTS PASSED!\n");
        return 0;
    } else {
        printf("\n❌ SOME TESTS FAILED!\n");
        return 1;
    }
}
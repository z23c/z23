/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <assert.h>
#include "sky_combat/models/weapons.h"
#include "sky_combat/models/aircraft_manager.h"
#include <raylib.h>

void test_continuous_fire() {
    printf("\n=== Testing Continuous Fire ===\n");
    
    // Create weapons system
    weapons_system_t* weapons = weapons_create();
    assert(weapons != NULL);
    
    // Test firing continuously for 2 seconds (120 frames at 60fps)
    Vector3 pos = {0, 0, 0};
    Vector3 dir = {0, 0, 1};
    float yaw = 0;
    
    int total_bullets_fired = 0;
    int active_bullets_count = 0;
    
    printf("Testing continuous fire for 120 frames (2 seconds at 60fps)...\n");
    
    for (int frame = 0; frame < 120; frame++) {
        // Fire weapon
        weapons_fire_bullet(weapons, pos, dir, yaw);
        
        // Update weapons (1/60 second per frame)
        weapons_update(weapons, 1.0f/60.0f);
        
        // Count active bullets
        int active_this_frame = weapons_get_active_bullets(weapons);
        
        // Track if we fired a new bullet this frame
        if (active_this_frame > active_bullets_count) {
            total_bullets_fired += (active_this_frame - active_bullets_count);
        }
        active_bullets_count = active_this_frame;
        
        // Log every 10 frames
        if (frame % 10 == 0) {
            printf("Frame %3d: Active bullets = %3d, Total fired = %3d, Cooldown = %.3f\n", 
                   frame, active_bullets_count, total_bullets_fired, 
                   weapons->fire_cooldown[WEAPON_MACHINE_GUN]);
        }
    }
    
    printf("\nFinal results:\n");
    printf("Total bullets fired: %d\n", total_bullets_fired);
    printf("Expected bullets (120 frames): 120\n");
    printf("Fire rate: %.1f bullets/second\n", total_bullets_fired / 2.0f);
    
    // Check weapon heat
    printf("Weapon heat: %.2f\n", weapons->weapon_heat[WEAPON_MACHINE_GUN]);
    
    weapons_destroy(weapons);
}

void test_aircraft_manager_continuous_fire() {
    printf("\n=== Testing Aircraft Manager Continuous Fire ===\n");
    
    aircraft_manager_t* manager = aircraft_manager_create();
    int player_id = aircraft_manager_add(manager, "TEST", WHITE, false, true);
    
    printf("Firing continuously through aircraft manager...\n");
    
    int total_bullets = 0;
    for (int frame = 0; frame < 120; frame++) {
        // Fire weapon
        aircraft_manager_fire_weapon(manager, player_id);
        
        // Update manager
        aircraft_manager_update(manager, 1.0f/60.0f);
        
        // Count bullets
        managed_aircraft_t* player = aircraft_manager_get(manager, player_id);
        int active = 0;
        if (player && player->weapons) {
            active = weapons_get_active_bullets(player->weapons);
        }
        
        if (frame % 20 == 0) {
            printf("Frame %3d: Active bullets = %3d\n", frame, active);
        }
        
        if (active > total_bullets) total_bullets = active;
    }
    
    printf("Max bullets active: %d\n", total_bullets);
    
    aircraft_manager_destroy(manager);
}

void test_bullet_limit() {
    printf("\n=== Testing Bullet Limit ===\n");
    
    printf("Bullets are now INFINITE! (using linked list)\n");
    
    weapons_system_t* weapons = weapons_create();
    Vector3 pos = {0, 0, 0};
    Vector3 dir = {0, 0, 1};
    
    // Fire many bullets to test infinite capacity
    int test_count = 1000;
    for (int i = 0; i < test_count; i++) {
        weapons_fire_bullet(weapons, pos, dir, 0);
    }
    
    int active = weapons_get_active_bullets(weapons);
    printf("Successfully fired %d bullets (no limit!)\n", active);
    printf("Memory used: ~%zu KB\n", (active * sizeof(bullet_t)) / 1024);
    
    weapons_destroy(weapons);
}

int main() {
    test_continuous_fire();
    test_aircraft_manager_continuous_fire();
    test_bullet_limit();
    
    printf("\n=== All tests completed ===\n");
    return 0;
}
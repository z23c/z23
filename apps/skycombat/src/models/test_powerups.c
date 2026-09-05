/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include "sky_combat/models/powerups.h"
#include "sky_combat/models/aircraft_manager.h"
#include <raylib.h>

int main(void) {
    printf("=== SKY COMBAT POWER-UP TEST ===\n\n");
    
    // Initialize random seed
    srand(time(NULL));
    
    // Create managers
    powerup_manager_t* powerup_mgr = powerup_manager_create();
    aircraft_manager_t* aircraft_mgr = aircraft_manager_create();
    
    if (!powerup_mgr || !aircraft_mgr) {
        printf("Failed to create managers\n");
        return 1;
    }
    
    // Create default spawn points
    printf("Creating power-up spawn points...\n");
    powerup_manager_create_default_spawn_points(powerup_mgr);
    printf("Created %d spawn points\n\n", powerup_mgr->spawn_point_count);
    
    // Add test aircraft
    int player_id = aircraft_manager_add(aircraft_mgr, "Test Pilot", RED, false, true);
    managed_aircraft_t* player = aircraft_manager_get(aircraft_mgr, player_id);
    
    // Spawn some initial power-ups
    printf("Spawning initial power-ups...\n");
    for (int i = 0; i < 5; i++) {
        powerup_manager_spawn_random(powerup_mgr);
    }
    printf("Active power-ups: %d\n\n", powerup_mgr->powerup_count);
    
    // Simulate for 60 seconds
    float dt = 0.016f;
    float total_time = 0;
    float max_time = 60.0f;
    int collections = 0;
    
    printf("Starting simulation...\n\n");
    
    while (total_time < max_time) {
        // Update systems
        powerup_manager_update(powerup_mgr, dt);
        aircraft_manager_update(aircraft_mgr, dt);
        
        // Move aircraft around to collect power-ups
        if (player && player->aircraft) {
            // Simple circular movement
            float angle = total_time * 0.5f;
            float radius = 200.0f + sinf(total_time * 0.3f) * 100.0f;
            player->aircraft->position.x = cosf(angle) * radius;
            player->aircraft->position.z = sinf(angle) * radius;
            player->aircraft->position.y = 150.0f + sinf(total_time) * 30.0f;
            
            // Check for power-up collection
            powerup_type_t collected_type;
            if (powerup_manager_check_collection(powerup_mgr, player->aircraft->position, 10.0f, &collected_type)) {
                collections++;
                
                // Get power-up properties
                float duration = powerup_get_default_duration(collected_type);
                float value = powerup_get_default_value(collected_type);
                
                // Apply effect
                powerup_effects_apply(&player->powerup_effects, collected_type, duration, value);
                
                printf("[%.1fs] Collected %s! ", total_time, powerup_get_name(collected_type));
                
                // Show effect
                switch (collected_type) {
                    case POWERUP_HEALTH:
                        player->health = fminf(player->health + value, player->max_health);
                        printf("Health: %.0f/%.0f\n", player->health, player->max_health);
                        break;
                    case POWERUP_SHIELD:
                        printf("Shield active for %.1fs\n", duration);
                        break;
                    case POWERUP_RAPID_FIRE:
                        printf("Fire rate x%.1f for %.1fs\n", value, duration);
                        break;
                    case POWERUP_MISSILE:
                        printf("Got %d missiles (total: %d)\n", (int)value, player->powerup_effects.missile_count);
                        break;
                    case POWERUP_LASER:
                        printf("Laser equipped with %.0f ammo\n", value);
                        break;
                    case POWERUP_SPEED_BOOST:
                        printf("Speed x%.1f for %.1fs\n", value, duration);
                        break;
                    case POWERUP_DOUBLE_DAMAGE:
                        printf("Double damage for %.1fs\n", duration);
                        break;
                    case POWERUP_REPAIR_KIT:
                        player->health = player->max_health;
                        printf("Fully repaired!\n");
                        break;
                }
            }
        }
        
        // Status update every 10 seconds
        if ((int)(total_time * 10) % 100 == 0 && (int)((total_time - dt) * 10) % 100 != 0) {
            printf("\n[%.0fs] Status:\n", total_time);
            printf("  Active power-ups: %d\n", powerup_mgr->powerup_count);
            printf("  Collections: %d\n", collections);
            
            if (player) {
                printf("  Player effects:\n");
                if (player->powerup_effects.shield_active)
                    printf("    - Shield: %.1fs remaining\n", player->powerup_effects.shield_timer);
                if (player->powerup_effects.rapid_fire_active)
                    printf("    - Rapid Fire: %.1fs remaining (x%.1f)\n", 
                           player->powerup_effects.rapid_fire_timer,
                           player->powerup_effects.fire_rate_multiplier);
                if (player->powerup_effects.speed_boost_active)
                    printf("    - Speed Boost: %.1fs remaining (x%.1f)\n",
                           player->powerup_effects.speed_boost_timer,
                           player->powerup_effects.speed_multiplier);
                if (player->powerup_effects.double_damage_active)
                    printf("    - Double Damage: %.1fs remaining\n", 
                           player->powerup_effects.double_damage_timer);
                if (player->powerup_effects.missile_count > 0)
                    printf("    - Missiles: %d\n", player->powerup_effects.missile_count);
                if (player->powerup_effects.laser_equipped)
                    printf("    - Laser: %.0f ammo\n", player->powerup_effects.laser_ammo);
            }
            printf("\n");
        }
        
        total_time += dt;
    }
    
    // Final stats
    printf("\n=== SIMULATION COMPLETE ===\n");
    printf("Total collections: %d\n", collections);
    printf("Average collection rate: %.2f per minute\n", (float)collections / (max_time / 60.0f));
    
    // Count active powerups by type
    int type_counts[POWERUP_TYPE_COUNT] = {0};
    for (int i = 0; i < powerup_mgr->powerup_count; i++) {
        if (powerup_mgr->powerups[i].active) {
            type_counts[powerup_mgr->powerups[i].type]++;
        }
    }
    
    printf("\nActive power-ups by type:\n");
    for (int i = 0; i < POWERUP_TYPE_COUNT; i++) {
        if (type_counts[i] > 0) {
            printf("  %s: %d\n", powerup_get_name(i), type_counts[i]);
        }
    }
    
    // Cleanup
    powerup_manager_destroy(powerup_mgr);
    aircraft_manager_destroy(aircraft_mgr);
    
    printf("\nTest completed successfully!\n");
    return 0;
}
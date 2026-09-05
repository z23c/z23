/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include "sky_combat/models/aircraft_manager.h"
#include "sky_combat/models/match_rules.h"
#include "sky_combat/models/powerups.h"
#include <raylib.h>

// Test configuration
#define SIMULATION_TIME 120.0f  // 2 minutes
#define FRAME_RATE 60.0f
#define DT (1.0f / FRAME_RATE)

void print_match_status(match_state_t* match, aircraft_manager_t* aircraft_mgr, float time) {
    printf("\n[%.1fs] Match Status:\n", time);
    printf("  Score: Red %d - Blue %d\n", match->team_scores[0], match->team_scores[1]);
    
    printf("  Aircraft Status:\n");
    for (int i = 0; i < aircraft_mgr->aircraft_count; i++) {
        managed_aircraft_t* ma = &aircraft_mgr->aircraft[i];
        const char* team_name = ma->team_id == 0 ? "Red" : "Blue";
        printf("    %s (%s): Health %.0f%%, K/D: %d/%d", 
               ma->name, team_name, ma->health, ma->kills, ma->deaths);
        
        // Show active power-ups
        if (ma->powerup_effects.shield_active) printf(" [SHIELD]");
        if (ma->powerup_effects.rapid_fire_active) printf(" [RAPID]");
        if (ma->powerup_effects.speed_boost_active) printf(" [SPEED]");
        if (ma->powerup_effects.double_damage_active) printf(" [2xDAM]");
        if (ma->powerup_effects.missile_count > 0) printf(" [MSL:%d]", ma->powerup_effects.missile_count);
        if (ma->powerup_effects.laser_equipped) printf(" [LASER]");
        
        printf("\n");
    }
}

int main(void) {
    printf("=== SKY COMBAT COMPLETE MULTIPLAYER TEST ===\n");
    printf("Team Deathmatch: First to 10 kills wins\n\n");
    
    // Initialize
    srand(time(NULL));
    
    // Create systems
    aircraft_manager_t* aircraft_mgr = aircraft_manager_create();
    powerup_manager_t* powerup_mgr = powerup_manager_create();
    match_state_t* match = match_state_create(MATCH_TYPE_TEAM_DEATHMATCH);
    
    if (!aircraft_mgr || !powerup_mgr || !match) {
        printf("Failed to create game systems\n");
        return 1;
    }
    
    // Configure match
    match_rules_team_deathmatch(&match->rules, 10, 2);  // First to 10, 2 teams
    match->match_started = true;
    
    // Create spawn points for power-ups
    powerup_manager_create_default_spawn_points(powerup_mgr);
    
    // Add aircraft - 2v2 battle (MAX_MANAGED_AIRCRAFT is 5)
    printf("Creating teams...\n");
    aircraft_manager_add_with_team(aircraft_mgr, "Red Leader", RED, true, false, 0);
    aircraft_manager_add_with_team(aircraft_mgr, "Red Two", RED, true, false, 0);
    
    aircraft_manager_add_with_team(aircraft_mgr, "Blue Leader", BLUE, true, false, 1);
    aircraft_manager_add_with_team(aircraft_mgr, "Blue Two", BLUE, true, false, 1);
    
    // Spawn initial power-ups
    printf("\nSpawning initial power-ups...\n");
    for (int i = 0; i < 6; i++) {
        powerup_manager_spawn_random(powerup_mgr);
    }
    
    printf("\n=== BATTLE BEGINS ===\n");
    
    // Simulation variables
    float total_time = 0;
    int frame = 0;
    float last_kill_health[MAX_MANAGED_AIRCRAFT] = {100, 100, 100, 100, 100};
    int total_powerup_collections = 0;
    
    // Main simulation loop
    while (total_time < SIMULATION_TIME && !match_is_over(match)) {
        // Update systems
        aircraft_manager_update(aircraft_mgr, DT);
        powerup_manager_update(powerup_mgr, DT);
        match_state_update(match, DT);
        
        // Check for power-up collections
        for (int i = 0; i < aircraft_mgr->aircraft_count; i++) {
            managed_aircraft_t* ma = &aircraft_mgr->aircraft[i];
            if (ma->health <= 0 || !ma->aircraft) continue;
            
            powerup_type_t collected_type;
            if (powerup_manager_check_collection(powerup_mgr, ma->aircraft->position, 10.0f, &collected_type)) {
                total_powerup_collections++;
                
                // Apply power-up effect
                float duration = powerup_get_default_duration(collected_type);
                float value = powerup_get_default_value(collected_type);
                
                switch (collected_type) {
                    case POWERUP_HEALTH:
                        ma->health = fminf(ma->health + value, ma->max_health);
                        printf("[%.1fs] %s collected Health (+%.0f HP)\n", total_time, ma->name, value);
                        break;
                        
                    case POWERUP_REPAIR_KIT:
                        ma->health = ma->max_health;
                        printf("[%.1fs] %s collected Repair Kit (Full health)\n", total_time, ma->name);
                        break;
                        
                    default:
                        powerup_effects_apply(&ma->powerup_effects, collected_type, duration, value);
                        printf("[%.1fs] %s collected %s\n", total_time, ma->name, powerup_get_name(collected_type));
                        break;
                }
                
                // Apply weapon upgrade if it's a weapon power-up
                if (ma->weapons) {
                    switch (collected_type) {
                        case POWERUP_RAPID_FIRE:
                            weapons_apply_upgrade(ma->weapons, WEAPON_UPGRADE_RAPID_FIRE, duration);
                            break;
                        case POWERUP_DOUBLE_DAMAGE:
                            weapons_apply_upgrade(ma->weapons, WEAPON_UPGRADE_EXPLOSIVE, duration);
                            break;
                        case POWERUP_LASER:
                            weapons_apply_upgrade(ma->weapons, WEAPON_UPGRADE_HOMING, duration);
                            break;
                        default:
                            break;
                    }
                }
            }
        }
        
        // Check for kills and update match
        for (int i = 0; i < aircraft_mgr->aircraft_count; i++) {
            managed_aircraft_t* victim = &aircraft_mgr->aircraft[i];
            
            if (last_kill_health[i] > 0 && victim->health <= 0) {
                // Find killer (simplified - would need proper tracking)
                int killer_id = -1;
                for (int j = 0; j < aircraft_mgr->aircraft_count; j++) {
                    if (i != j && aircraft_mgr->aircraft[j].target_id == i) {
                        killer_id = j;
                        break;
                    }
                }
                
                if (killer_id >= 0) {
                    managed_aircraft_t* killer = &aircraft_mgr->aircraft[killer_id];
                    
                    // Debug: Print before calling match_player_killed
                    printf("[%.1fs] KILL: %s (team %d) killed %s (team %d)\n",
                           total_time, killer->name, killer->team_id, victim->name, victim->team_id);
                    
                    match_player_killed(match, killer_id, i, killer->team_id, victim->team_id);
                    
                    const char* killer_team = killer->team_id == 0 ? "Red" : "Blue";
                    const char* victim_team = victim->team_id == 0 ? "Red" : "Blue";
                    printf("         Score after kill: Red %d - Blue %d\n",
                           match->team_scores[0], match->team_scores[1]);
                }
            }
            last_kill_health[i] = victim->health;
        }
        
        // Status update every 15 seconds
        if ((int)(total_time) % 15 == 0 && (int)(total_time - DT) % 15 != 0) {
            print_match_status(match, aircraft_mgr, total_time);
        }
        
        total_time += DT;
        frame++;
    }
    
    // Match ended
    printf("\n=== MATCH ENDED ===\n");
    printf("Duration: %.1f seconds\n", total_time);
    
    // Determine winner
    int winner_id;
    bool is_team;
    if (match_check_win_condition(match, &winner_id, &is_team)) {
        if (is_team) {
            const char* winner = winner_id == 0 ? "Red Squadron" : "Blue Squadron";
            printf("\nWINNER: %s!\n", winner);
        }
    }
    
    // Final statistics
    printf("\nFinal Score: Red %d - Blue %d\n", match->team_scores[0], match->team_scores[1]);
    
    printf("\nIndividual Statistics:\n");
    int red_kills = 0, red_deaths = 0;
    int blue_kills = 0, blue_deaths = 0;
    
    for (int i = 0; i < aircraft_mgr->aircraft_count; i++) {
        managed_aircraft_t* ma = &aircraft_mgr->aircraft[i];
        const char* team = ma->team_id == 0 ? "Red" : "Blue";
        printf("  %s (%s): %d kills, %d deaths, K/D: %.2f\n", 
               ma->name, team, ma->kills, ma->deaths,
               ma->deaths > 0 ? (float)ma->kills / ma->deaths : (float)ma->kills);
        
        if (ma->team_id == 0) {
            red_kills += ma->kills;
            red_deaths += ma->deaths;
        } else {
            blue_kills += ma->kills;
            blue_deaths += ma->deaths;
        }
    }
    
    printf("\nTeam Statistics:\n");
    printf("  Red Squadron: %d kills, %d deaths\n", red_kills, red_deaths);
    printf("  Blue Squadron: %d kills, %d deaths\n", blue_kills, blue_deaths);
    
    printf("\nPower-up Statistics:\n");
    printf("  Total collections: %d\n", total_powerup_collections);
    printf("  Collection rate: %.2f per minute\n", 
           total_powerup_collections / (total_time / 60.0f));
    
    // Cleanup
    match_state_destroy(match);
    powerup_manager_destroy(powerup_mgr);
    aircraft_manager_destroy(aircraft_mgr);
    
    printf("\nMultiplayer systems test completed successfully!\n");
    return 0;
}
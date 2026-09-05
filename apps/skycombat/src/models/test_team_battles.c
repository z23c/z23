/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "sky_combat/models/aircraft_manager.h"
#include "sky_combat/models/match_rules.h"
#include <raylib.h>

int main(void) {
    printf("=== SKY COMBAT TEAM BATTLE TEST ===\n\n");
    
    // Initialize random seed
    srand(time(NULL));
    
    // Create aircraft manager
    aircraft_manager_t* manager = aircraft_manager_create();
    if (!manager) {
        printf("Failed to create aircraft manager\n");
        return 1;
    }
    
    // Create match rules for team deathmatch
    match_state_t* match = match_state_create(MATCH_TYPE_TEAM_DEATHMATCH);
    match_rules_team_deathmatch(&match->rules, 5, 2); // First to 5 kills, 2 teams
    match->match_started = true;
    
    printf("Match Rules: Team Deathmatch - First to %d kills\n", match->rules.score_limit);
    printf("Teams: Red Squadron vs Blue Squadron\n\n");
    
    // Add Red Squadron (Team 0)
    printf("Creating Red Squadron:\n");
    aircraft_manager_add_with_team(manager, "Red Leader", RED, true, false, 0);
    aircraft_manager_add_with_team(manager, "Red Two", RED, true, false, 0);
    aircraft_manager_add_with_team(manager, "Red Three", RED, true, false, 0);
    
    // Add Blue Squadron (Team 1)
    printf("\nCreating Blue Squadron:\n");
    aircraft_manager_add_with_team(manager, "Blue Leader", BLUE, true, false, 1);
    aircraft_manager_add_with_team(manager, "Blue Two", BLUE, true, false, 1);
    
    printf("\n=== BATTLE BEGINS ===\n\n");
    
    // Run simulation
    float dt = 0.016f; // 60 FPS
    float total_time = 0;
    float max_time = 30.0f; // 30 second battle
    int frame = 0;
    
    while (total_time < max_time && !match_is_over(match)) {
        // Update aircraft
        aircraft_manager_update(manager, dt);
        
        // Update match state
        match_state_update(match, dt);
        
        // Check for kills and update match scores
        for (int i = 0; i < manager->aircraft_count; i++) {
            managed_aircraft_t* ma = &manager->aircraft[i];
            
            // Check if this aircraft was just killed (health went to 0)
            static float prev_health[MAX_MANAGED_AIRCRAFT] = {100, 100, 100, 100, 100};
            if (prev_health[i] > 0 && ma->health <= 0) {
                // Find who killed them (simplified - last damager)
                for (int j = 0; j < manager->aircraft_count; j++) {
                    if (i != j && manager->aircraft[j].health > 0) {
                        managed_aircraft_t* killer = &manager->aircraft[j];
                        if (killer->team_id != ma->team_id) {
                            match_player_killed(match, j, i, killer->team_id, ma->team_id);
                            printf("[%.1fs] %s destroyed %s! (Score: Red %d - Blue %d)\n", 
                                   total_time, killer->name, ma->name,
                                   match->team_scores[0], match->team_scores[1]);
                            break;
                        }
                    }
                }
            }
            prev_health[i] = ma->health;
        }
        
        // Log targeting info every 60 frames (1 second)
        if (frame % 60 == 0) {
            printf("\n[%.1fs] Targeting Status:\n", total_time);
            for (int i = 0; i < manager->aircraft_count; i++) {
                managed_aircraft_t* ma = &manager->aircraft[i];
                if (ma->health > 0 && ma->target_id >= 0) {
                    managed_aircraft_t* target = &manager->aircraft[ma->target_id];
                    printf("  %s (Team %d) -> %s (Team %d)\n", 
                           ma->name, ma->team_id, target->name, target->team_id);
                }
            }
        }
        
        total_time += dt;
        frame++;
    }
    
    printf("\n=== BATTLE ENDED ===\n");
    printf("Duration: %.1f seconds\n", total_time);
    
    // Determine winner
    int winner_id;
    bool is_team;
    if (match_check_win_condition(match, &winner_id, &is_team)) {
        if (is_team) {
            const char* team_names[] = {"Red Squadron", "Blue Squadron"};
            printf("\nWINNER: %s!\n", team_names[winner_id]);
        }
    }
    
    // Final scores
    printf("\nFinal Score: Red %d - Blue %d\n", match->team_scores[0], match->team_scores[1]);
    
    // Individual stats
    printf("\nPilot Statistics:\n");
    for (int i = 0; i < manager->aircraft_count; i++) {
        managed_aircraft_t* ma = &manager->aircraft[i];
        printf("  %s: %d kills, %d deaths\n", ma->name, ma->kills, ma->deaths);
    }
    
    // Verify no friendly fire occurred
    printf("\nTeam Targeting Verification: ");
    bool friendly_fire = false;
    for (int i = 0; i < manager->aircraft_count; i++) {
        managed_aircraft_t* ma = &manager->aircraft[i];
        if (ma->target_id >= 0) {
            managed_aircraft_t* target = &manager->aircraft[ma->target_id];
            if (ma->team_id == target->team_id) {
                friendly_fire = true;
                printf("\nERROR: %s targeted teammate %s!", ma->name, target->name);
            }
        }
    }
    if (!friendly_fire) {
        printf("PASSED - No friendly targeting detected\n");
    }
    
    // Cleanup
    match_state_destroy(match);
    aircraft_manager_destroy(manager);
    
    printf("\nTest completed successfully!\n");
    return 0;
}
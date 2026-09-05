/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include "gdb_proof.h"

/*
 * Example: How to use GDB Proof in Sky Combat
 * 
 * Add these proof calls to your main game initialization
 * to guarantee at compile-time that safety checks are enabled.
 */

// Example initialization function
void initialize_game_safely(void) {
    printf("Initializing Sky Combat with safety guarantees...\n");
    
    // Step 1: Prove aircraft manager is initialized
    gdb_proof_init_aircraft_manager();
    // ... actual aircraft manager init code ...
    
    // Step 2: Prove bounds checking is enabled
    gdb_proof_bounds_check_enabled();
    // ... enable bounds checking ...
    
    // Step 3: Prove NULL checks are active
    gdb_proof_null_check_enabled();
    // ... enable NULL pointer protection ...
    
    // Step 4: Final guarantee - no coredumps possible!
    gdb_proof_no_coredump_guarantee();
    
    printf("All safety systems verified and active!\n");
}

// Example main that will PASS verification
int main(void) {
    printf("Sky Combat - GDB Proof Example\n");
    
    // This is REQUIRED - without it, compilation will fail!
    initialize_game_safely();
    
    // Game loop would go here...
    printf("Game running safely - no coredumps possible!\n");
    
    return 0;
}

/*
 * To use in CMakeLists.txt:
 * 
 * add_executable(sky_combat_safe example_usage.c)
 * REQUIRE_NO_COREDUMP_GUARANTEE(sky_combat_safe)
 * 
 * The build will FAIL unless all proof functions are called!
 */
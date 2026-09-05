/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef GDB_PROOF_WEAPONS_H
#define GDB_PROOF_WEAPONS_H

/*
 * GDB Proof: Weapon Independence
 * 
 * This module verifies that weapon firing NEVER affects aircraft momentum.
 * The right trigger (R2) should only fire weapons, not move the plane.
 */

// Function declarations for weapon independence proofs
void gdb_proof_weapons_independent(void);
void gdb_proof_no_recoil_movement(void);
void gdb_proof_trigger_only_fires(void);
void gdb_proof_momentum_preserved(void);

// Verification macro for build system
#define VERIFY_WEAPON_INDEPENDENCE() do { \
    gdb_proof_weapons_independent(); \
    gdb_proof_no_recoil_movement(); \
    gdb_proof_trigger_only_fires(); \
    gdb_proof_momentum_preserved(); \
} while(0)

// Constants that define the verified behavior
typedef struct {
    float max_position_change;      // Must be 0.0
    float max_velocity_change;      // Must be 0.0
    float max_acceleration_change;  // Must be 0.0
    int recoil_affects_movement;    // Must be 0 (false)
} weapon_independence_t;

// The verified behavior
extern const weapon_independence_t VERIFIED_WEAPON_INDEPENDENCE;

#endif // GDB_PROOF_WEAPONS_H
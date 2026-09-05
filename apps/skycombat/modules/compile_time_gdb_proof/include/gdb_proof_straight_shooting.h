/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef GDB_PROOF_STRAIGHT_SHOOTING_H
#define GDB_PROOF_STRAIGHT_SHOOTING_H

/*
 * GDB Proof: Straight Shooting
 * 
 * This module verifies that bullets ALWAYS shoot straight forward
 * from the aircraft, with NO aiming offset or spread adjustment.
 */

// Function declarations for straight shooting proofs
void gdb_proof_bullets_shoot_straight(void);
void gdb_proof_no_aim_offset_applied(void);
void gdb_proof_forward_vector_only(void);
void gdb_proof_no_spread_adjustment(void);

// Verification macro for build system
#define VERIFY_STRAIGHT_SHOOTING() do { \
    gdb_proof_bullets_shoot_straight(); \
    gdb_proof_no_aim_offset_applied(); \
    gdb_proof_forward_vector_only(); \
    gdb_proof_no_spread_adjustment(); \
} while(0)

// Constants that define the verified behavior
typedef struct {
    float max_aim_offset;        // Must be 0.0 degrees
    float max_spread_angle;      // Must be 0.0 degrees
    int allows_aim_adjustment;   // Must be 0 (false)
    int uses_aircraft_forward;   // Must be 1 (true)
} straight_shooting_t;

// The verified behavior
extern const straight_shooting_t VERIFIED_STRAIGHT_SHOOTING;

#endif // GDB_PROOF_STRAIGHT_SHOOTING_H
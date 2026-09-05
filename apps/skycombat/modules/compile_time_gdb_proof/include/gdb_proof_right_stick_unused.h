/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef GDB_PROOF_RIGHT_STICK_UNUSED_H
#define GDB_PROOF_RIGHT_STICK_UNUSED_H

/*
 * GDB Proof: Right Stick Unused
 * 
 * This module verifies that the right joystick has NO function.
 * It doesn't control camera OR gun aiming.
 */

// Function declarations for right stick unused proofs
void gdb_proof_right_stick_has_no_function(void);
void gdb_proof_camera_not_controlled_by_right_stick(void);
void gdb_proof_gun_aim_not_controlled_by_right_stick(void);
void gdb_proof_right_stick_input_ignored(void);

// Verification macro for build system
#define VERIFY_RIGHT_STICK_UNUSED() do { \
    gdb_proof_right_stick_has_no_function(); \
    gdb_proof_camera_not_controlled_by_right_stick(); \
    gdb_proof_gun_aim_not_controlled_by_right_stick(); \
    gdb_proof_right_stick_input_ignored(); \
} while(0)

// Constants that define the verified behavior
typedef struct {
    int controls_camera;      // Must be 0 (false)
    int controls_gun_aim;     // Must be 0 (false)
    int has_any_function;     // Must be 0 (false)
    int input_is_read;        // May be 1 (true) but unused
} right_stick_unused_t;

// The verified behavior
extern const right_stick_unused_t VERIFIED_RIGHT_STICK_UNUSED;

#endif // GDB_PROOF_RIGHT_STICK_UNUSED_H
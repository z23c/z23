/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef GDB_PROOF_RIGHT_STICK_AIM_H
#define GDB_PROOF_RIGHT_STICK_AIM_H

/*
 * GDB Proof: Right Stick Gun Aiming
 * 
 * This module verifies that the right joystick is used for gun aiming/spray control,
 * NOT camera movement. This is a compile-time enforcement.
 */

// Function declarations for right stick aim proofs
void gdb_proof_right_stick_controls_aim(void);
void gdb_proof_no_camera_on_right_stick(void);
void gdb_proof_aim_affects_bullet_spread(void);
void gdb_proof_aim_fine_tuning_enabled(void);

// Verification macro for build system
#define VERIFY_RIGHT_STICK_AIM() do { \
    gdb_proof_right_stick_controls_aim(); \
    gdb_proof_no_camera_on_right_stick(); \
    gdb_proof_aim_affects_bullet_spread(); \
    gdb_proof_aim_fine_tuning_enabled(); \
} while(0)

// Constants that define the verified behavior
typedef struct {
    int axis_aim_x;              // Must be 2 (right stick X)
    int axis_aim_y;              // Must be 3 or 5 (right stick Y)
    float max_spread_angle;      // Maximum gun spray angle in degrees
    float aim_sensitivity;       // Sensitivity for fine-tuning
    int camera_uses_right_stick; // Must be 0 (false)
} right_stick_aim_t;

// The verified behavior
extern const right_stick_aim_t VERIFIED_RIGHT_STICK_AIM;

#endif // GDB_PROOF_RIGHT_STICK_AIM_H
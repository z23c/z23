/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef GDB_PROOF_CONTROLS_H
#define GDB_PROOF_CONTROLS_H

/*
 * GDB Proof System for Control Scheme Lock
 * 
 * This ensures the joystick control mappings remain EXACTLY as configured
 * and cannot be changed accidentally.
 */

// Control verification functions that MUST be called
void gdb_proof_controls_locked(void);
void gdb_proof_verify_axis_mapping(void);
void gdb_proof_verify_button_mapping(void);
void gdb_proof_verify_trigger_behavior(void);

// Expected control mappings that MUST be verified
typedef struct {
    // Axis mappings
    int axis_roll;      // Must be 0 (left stick X)
    int axis_pitch;     // Must be 1 (left stick Y)  
    int axis_camera_x;  // Must be 2 (right stick X)
    int axis_l2;        // Must be 3 (L2 trigger)
    int axis_r2;        // Must be 4 (R2 trigger)
    int axis_camera_y;  // Must be 5 (right stick Y)
    
    // Button mappings
    int button_boost;   // Must be 2 (UL paddle)
    int button_brake;   // Must be 3 (UR paddle)
    int button_roll_l;  // Must be 4 (L1)
    int button_roll_r;  // Must be 5 (R1)
    
    // Control behavior
    int roll_inverted;  // Must be 1 (right = left)
    int pitch_inverted; // Must be 1 (pull back = up)
    int r2_range_min;   // Must be -32767
    int r2_range_max;   // Must be 0
} control_lock_t;

// The locked configuration
extern const control_lock_t LOCKED_CONTROLS;

// Verification macro
#define VERIFY_CONTROL_LOCK() \
    do { \
        gdb_proof_controls_locked(); \
        gdb_proof_verify_axis_mapping(); \
        gdb_proof_verify_button_mapping(); \
        gdb_proof_verify_trigger_behavior(); \
    } while(0)

#endif /* GDB_PROOF_CONTROLS_H */
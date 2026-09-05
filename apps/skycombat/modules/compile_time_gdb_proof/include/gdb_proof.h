/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef GDB_PROOF_H
#define GDB_PROOF_H

/*
 * Compile-Time GDB Proof System
 * 
 * This system ensures critical functions are called at runtime
 * by using GDB verification during the build process.
 */

// Marker functions that MUST be called for safety
void gdb_proof_init_aircraft_manager(void);
void gdb_proof_bounds_check_enabled(void);
void gdb_proof_null_check_enabled(void);
void gdb_proof_no_coredump_guarantee(void);

// Macro to mark a function as requiring GDB proof
#define GDB_PROOF_REQUIRED __attribute__((used))

// Macro to insert proof markers in code
#define GDB_PROOF_CHECKPOINT(name) \
    do { \
        void gdb_proof_checkpoint_##name(void) GDB_PROOF_REQUIRED; \
        gdb_proof_checkpoint_##name(); \
    } while(0)

#endif /* GDB_PROOF_H */
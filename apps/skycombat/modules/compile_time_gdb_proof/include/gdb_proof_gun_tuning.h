/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef GDB_PROOF_GUN_TUNING_H
#define GDB_PROOF_GUN_TUNING_H

// Macro to verify right stick fine-tunes guns WITHOUT changing trajectory
#define VERIFY_GUN_TUNING() do { \
    extern void gdb_proof_verify_gun_tuning(void); \
    gdb_proof_verify_gun_tuning(); \
} while(0)

#endif /* GDB_PROOF_GUN_TUNING_H */
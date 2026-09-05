/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef GDB_PROOF_PRACTICE_TARGETS_H
#define GDB_PROOF_PRACTICE_TARGETS_H

// Macro to verify practice targets are spawned correctly
#define VERIFY_PRACTICE_TARGETS() do { \
    extern void gdb_proof_verify_practice_targets(void); \
    gdb_proof_verify_practice_targets(); \
} while(0)

#endif /* GDB_PROOF_PRACTICE_TARGETS_H */
/* purpose: Check the PostNu6_3 proof of the Ironwood bundle in a v6 transaction. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_VERIFY_PROOF_H
#define ZCL_IRONWOOD_VERIFY_PROOF_H
#include "base/result.h"
#include <stdint.h>
#include <stddef.h>
struct ironwood_opening_basis;
struct ironwood_postnu63_constraint_programs;
/* Parse the entire canonical v6 frame and verify its nonempty Ironwood bundle's
 * PostNu6_3 Halo2 proof against its actual actions. The program and setup
 * bytes are checked against the pinned circuit and public IPA parameter set.
 * All inputs must remain stable for the call. A successful proof check still
 * requires separate signature, value, anchor, nullifier and contextual checks
 * before a node can admit the transaction. */
struct zcl_result ironwood_postnu63_verify_proof(const uint8_t *wire, size_t length,
    const struct ironwood_postnu63_constraint_programs *programs, const struct ironwood_opening_basis *basis);
/* Same proof check using the resident, digest-checked public parameters. */
struct zcl_result ironwood_postnu63_verify_proof_resident(const uint8_t *wire, size_t length);
#endif

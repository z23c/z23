/* purpose: Compute and verify transparent v6 input signatures. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_TRANSACTION_V6_TRANSPARENT_H
#define Z23_TRANSACTION_V6_TRANSPARENT_H
#include "primitives/transaction_v6_sighash.h"
#include "base/result.h"
/* Inputs are parsed from one full wire frame. Prevouts must be authenticated
 * against chainstate in input order. No contextual validity is implied. All
 * inputs remain stable for the call; output is unchanged on failure. The
 * expected branch is selected by the caller from trusted chain context. */
struct zcl_result v6_transparent_sighash(const uint8_t *wire, size_t length,
    const struct transaction_v6_prevout *prevouts, size_t count, size_t index,
    uint8_t hash_type, uint32_t expected_branch, uint8_t out[32]);
/* Check only an exact P2PKH prevout using the script interpreter. */
struct zcl_result v6_transparent_verify_p2pkh(const uint8_t *wire, size_t length,
    const struct transaction_v6_prevout *prevouts, size_t count, size_t index,
    uint32_t expected_branch, unsigned int script_flags);
#endif

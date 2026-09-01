/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * domain/consensus/verify.h — pure consensus validators.
 *
 * The functions in this module take a block / header / transaction
 * and return a typed zcl_result describing acceptance or the precise
 * reason for rejection. They have NO side effects: no I/O, no
 * mutation of in-memory caches, no allocation beyond the caller's
 * arena. They are the only path by which untrusted bytes become
 * "valid" in the eyes of the rest of the system.
 *
 * Layering rule:
 *   domain/consensus/ may #include from:
 *     - util/   (zcl_result, log macros)
 *     - core/   (uint256, arith_uint256, hash)
 *     - chain/  (struct block_header, consensus_params)
 *     - crypto/ (sha256, equihash)
 *     - sapling/, script/, primitives/  (pure validators)
 *   It must NOT #include from:
 *     - app/, core/modules/net/, engine/modules/storage/, platform/adapters/
 *
 * Some implementations may delegate to the core/modules/chain, core/modules/script, and
 * core/modules/sapling implementations.
 */

#ifndef ZCL_DOMAIN_CONSENSUS_VERIFY_H
#define ZCL_DOMAIN_CONSENSUS_VERIFY_H

#include <stdint.h>

#include "util/result.h"

struct uint256;
struct consensus_params;

/* Verify that block_hash satisfies the Proof-of-Work target encoded
 * in n_bits, under the given consensus parameters. Pure: no I/O.
 *
 * Returns ZCL_OK on valid PoW. Returns a non-ok result with one of
 *   DOMAIN_CONSENSUS_ERR_POW_TARGET_BELOW_MIN   nBits below floor
 *   DOMAIN_CONSENSUS_ERR_POW_HASH_ABOVE_TARGET  hash > target
 *   DOMAIN_CONSENSUS_ERR_POW_TARGET_INVALID     nBits malformed
 * on rejection.
 */
struct zcl_result domain_consensus_verify_pow_solution(
        const struct uint256 *block_hash,
        uint32_t n_bits,
        const struct consensus_params *params);

/* Error codes used by domain/consensus/ validators. The numeric
 * values are stable across builds; new codes are appended at the
 * end. Returned via zcl_result.code. */
enum domain_consensus_err {
    DOMAIN_CONSENSUS_ERR_POW_TARGET_BELOW_MIN  = 1001,
    DOMAIN_CONSENSUS_ERR_POW_HASH_ABOVE_TARGET = 1002,
    DOMAIN_CONSENSUS_ERR_POW_TARGET_INVALID    = 1003,
    DOMAIN_CONSENSUS_ERR_NULL_ARG              = 1004,
};

#endif /* ZCL_DOMAIN_CONSENSUS_VERIFY_H */

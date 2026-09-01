/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * domain/consensus/pow.h — pure Proof-of-Work difficulty arithmetic.
 *
 * Three pieces of consensus-critical math live here:
 *
 *   - domain_consensus_block_proof:
 *       Compute the work a single block contributes to chainwork.
 *       work = 2**256 / (target+1) where target = compact(n_bits).
 *
 *   - domain_consensus_increase_difficulty_by:
 *       Take an nBits target and tighten it by an integer multiplier,
 *       clamped at params->powLimit. Used by the post-DiffAdj / post-
 *       Buttercup catch-up rule that fires when blocks are way late.
 *
 *   - domain_consensus_calculate_next_work_required:
 *       The averaging-window-based retargeting: given the average
 *       target across the window and the actual timespan, produce the
 *       next compact nBits target, clamped at params->powLimit.
 *
 * All three are pure: they read only their arguments + consensus_params,
 * and emit a uint32_t compact target or an arith_uint256. No clock,
 * RNG, allocation, or I/O. They replay deterministically from inputs.
 *
 * Layering: domain/consensus/ may #include from util/, core/, consensus/.
 * The fact this module depends only on arith_uint256 + consensus_params
 * is what makes it eligible to live here. The legacy chain/pow.h API
 * stays unchanged — core/modules/chain/src/pow.c becomes a thin wrapper layer.
 */

#ifndef ZCL_DOMAIN_CONSENSUS_POW_H
#define ZCL_DOMAIN_CONSENSUS_POW_H

#include <stdint.h>

#include "core/arith_uint256.h"
#include "util/result.h"

struct consensus_params;

/* Compute the work value of a single block with target encoded in
 * n_bits. Equivalent to 2**256 / (target+1). On a malformed n_bits
 * (negative / overflow / zero target), out_work is set to zero — this
 * preserves the legacy GetBlockProof contract, which feeds chainwork
 * accumulation and must never crash on bad input.
 *
 * Note: this function intentionally does NOT take consensus_params.
 * The legacy GetBlockProof depends only on the compact-encoded target;
 * it does not consult powLimit. Keeping the signature parameter-free
 * lets chainwork accumulation stay deterministic across reorgs without
 * threading a chainparams pointer through every caller.
 *
 * On success (or benign-malformed input): returns ZCL_OK and writes
 *   either the work value or zero into *out_work.
 *
 * Error codes:
 *   DOMAIN_CONSENSUS_POW_ERR_NULL_OUT     out_work == NULL
 */
struct zcl_result domain_consensus_block_proof(
        uint32_t n_bits,
        struct arith_uint256 *out_work);

/* Divide an nBits target by an integer multiplier, clamping the
 * resulting target at params->powLimit (i.e. don't let difficulty
 * fall below the consensus floor).
 *
 * On success: returns ZCL_OK and writes the new compact target to
 * *out_bits.
 *
 * Error codes:
 *   DOMAIN_CONSENSUS_POW_ERR_NULL_PARAMS  params == NULL
 *   DOMAIN_CONSENSUS_POW_ERR_NULL_OUT     out_bits == NULL
 *   DOMAIN_CONSENSUS_POW_ERR_BAD_DIVISOR  multiplier == 0
 */
struct zcl_result domain_consensus_increase_difficulty_by(
        uint32_t n_bits,
        int64_t multiplier,
        const struct consensus_params *params,
        uint32_t *out_bits);

/* Compute the next-block nBits target given the averaged window
 * target and the actual measured timespan. Replays exactly the
 * retargeting logic from Zcash/ZClassic difficulty adjustment.
 *
 * On success: returns ZCL_OK and writes the new compact target to
 * *out_bits.
 *
 * Error codes:
 *   DOMAIN_CONSENSUS_POW_ERR_NULL_PARAMS  params == NULL
 *   DOMAIN_CONSENSUS_POW_ERR_NULL_OUT     out_bits == NULL
 */
struct zcl_result domain_consensus_calculate_next_work_required(
        struct arith_uint256 bn_avg,
        int64_t last_block_time,
        int64_t first_block_time,
        const struct consensus_params *params,
        int next_height,
        uint32_t *out_bits);

/* Error codes used by domain/consensus/pow.{c,h}. Stable across
 * builds; new codes are appended. Returned via zcl_result.code. */
enum domain_consensus_pow_err {
    DOMAIN_CONSENSUS_POW_ERR_NULL_PARAMS = 1201,
    DOMAIN_CONSENSUS_POW_ERR_NULL_OUT    = 1202,
    DOMAIN_CONSENSUS_POW_ERR_BAD_DIVISOR = 1203,
};

#endif /* ZCL_DOMAIN_CONSENSUS_POW_H */

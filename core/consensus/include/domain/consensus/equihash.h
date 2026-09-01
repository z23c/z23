/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * domain/consensus/equihash.h — pure Equihash solution verification.
 *
 * Given a block header (which carries an Equihash solution byte-array
 * and a nonce in `nNonce`), decide whether the solution is a valid
 * Equihash answer to the challenge defined by the header's other
 * fields. This is the pure proof-checking half of the Equihash PoW —
 * not the solver. (The solver lives in core/modules/crypto/src/equihash_solver.c
 * and is intentionally NOT part of the domain — solving is a search
 * with allocation and parallelism; verification is a tight pure check.)
 *
 * The verification algorithm is, for the (N=200, K=9) ZClassic mainnet
 * parameters (and the supported regtest/testnet variants):
 *
 *   1. Map the solution byte-length to its (N, K) parameter set.
 *   2. Re-build the BLAKE2b "ZcashPoW" personalised state.
 *   3. Feed the header pre-nonce bytes + nonce into the state.
 *   4. Hand the state + solution to equihash_is_valid_solution(), which
 *      expands the minimal solution into indices, re-derives each hash,
 *      and checks that the XOR-chain of K+1 collisions terminates in
 *      zero (the Generalised Birthday witness).
 *
 * The function is pure in the observable sense: same inputs always
 * produce the same answer, no clock, no RNG, no I/O, no global state.
 * The underlying `equihash_is_valid_solution` does allocate a fixed-
 * size scratch buffer proportional to 1<<K from the C heap — this is
 * a deliberate engineering choice in the crypto primitive (the buffer
 * is too large for the stack on parameters > N=200,K=9) and is
 * confined behind the crypto/ port. The domain function itself does
 * NOT allocate.
 *
 * Layering: domain/consensus/ may #include from util/, core/, chain/,
 * consensus/, crypto/, sapling/, script/, primitives/. The fact this
 * module depends only on primitives/block.h + crypto/{blake2b,equihash}.h
 * is what makes it eligible to live here.
 *
 * Background: zclassicd src/crypto/equihash.cpp::IsValidSolution is the
 * historic source-of-truth. core/modules/chain/src/equihash.c is the existing
 * legacy wrapper; it becomes a thin delegator after this extraction.
 */

#ifndef ZCL_DOMAIN_CONSENSUS_EQUIHASH_H
#define ZCL_DOMAIN_CONSENSUS_EQUIHASH_H

#include <stdbool.h>
#include <stdint.h>

#include "util/result.h"

struct block_header;
struct consensus_params;

/* Verify the Equihash solution embedded in `header`. The challenge is
 * derived from the header's other fields (version, prev-block hash,
 * merkle root, final-Sapling root, nTime, nBits) and the nonce in
 * `header->nNonce`. The solution itself lives in `header->nSolution`
 * with length `header->nSolutionSize`.
 *
 * `params` is reserved for future use (e.g. activation-height-gated
 * algorithm changes). It is currently unused by the verifier — the
 * Equihash parameter set is selected purely by solution size — but is
 * required so the signature matches the rest of the consensus surface
 * and so future fork rules can gate without an ABI break. Pass NULL
 * only if you know you do not care; the function tolerates a NULL
 * params today.
 *
 * On success returns ZCL_OK and writes `true` to *out_valid for a
 * valid solution, `false` for an invalid one. *out_valid is ONLY
 * written on success.
 *
 * On failure returns one of:
 *   DOMAIN_CONSENSUS_EQUIHASH_ERR_NULL_HEADER   header == NULL
 *   DOMAIN_CONSENSUS_EQUIHASH_ERR_NULL_OUT      out_valid == NULL
 *   DOMAIN_CONSENSUS_EQUIHASH_ERR_BAD_SOL_SIZE  solution size does not
 *                                               correspond to a known
 *                                               (N,K) parameter set
 *
 * NB: an arithmetically *wrong* solution is NOT a failure of this
 * function — it is a success with *out_valid=false. Only contract
 * violations (null pointer, malformed length) flow through the error
 * path. This matches the regression-seal convention of the other
 * consensus extractions.
 */
struct zcl_result domain_consensus_verify_equihash_solution(
        const struct block_header *header,
        const struct consensus_params *params,
        bool *out_valid);

/* Error codes used by domain/consensus/equihash.{c,h}. Stable across
 * builds; new codes are appended. Returned via zcl_result.code. */
enum domain_consensus_equihash_err {
    DOMAIN_CONSENSUS_EQUIHASH_ERR_NULL_HEADER  = 1301,
    DOMAIN_CONSENSUS_EQUIHASH_ERR_NULL_OUT     = 1302,
    DOMAIN_CONSENSUS_EQUIHASH_ERR_BAD_SOL_SIZE = 1303,
};

#endif /* ZCL_DOMAIN_CONSENSUS_EQUIHASH_H */

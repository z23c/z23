/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Canonical per-row header admission verify (see block_row_verify.h). The
 * single home for the hash-bind + CheckProofOfWork + checkpoint-gated
 * check_equihash_solution sequence, shared by every loader instead of each
 * copying it. This
 * TU changes nothing about what "valid" means — it only calls the frozen
 * consensus verifiers in the frozen order. */

// one-result-type-ok:pure-verify-verdict — this TU exposes ONE pure predicate
// (block_row_verify) whose typed enum verdict IS the failure reason; each
// caller maps that verdict to its own machine token. There is no fallible I/O
// service surface here to carry a struct zcl_result.

#include "services/block_row_verify.h"

#include "chain/chainparams.h"
#include "chain/equihash.h"
#include "chain/pow.h"
#include "primitives/block.h"
#include "core/uint256.h"

#include <string.h>

enum block_row_verify_result
block_row_verify(const uint8_t expected_hash[32], uint32_t n_bits,
                 const struct block_header *header,
                 const struct chain_params *cp, bool check_equihash)
{
    if (!cp)
        return BLOCK_ROW_VERIFY_NO_PARAMS;

    struct uint256 hash;
    memcpy(hash.data, expected_hash, 32);

    /* Hash-bind: recompute the PoW hash from the header and compare to the
     * stored/claimed hash. Skipped when the caller holds no full header (the
     * flat cache), which stores no solution to re-derive it from. */
    if (header) {
        struct uint256 computed;
        block_header_get_hash(header, &computed);
        if (memcmp(computed.data, expected_hash, 32) != 0)
            return BLOCK_ROW_VERIFY_HASH_BIND_MISMATCH;
    }

    if (!CheckProofOfWork(hash, n_bits, &cp->consensus))
        return BLOCK_ROW_VERIFY_HIGH_HASH;

    if (check_equihash && header && !check_equihash_solution(header, cp))
        return BLOCK_ROW_VERIFY_BAD_EQUIHASH;

    return BLOCK_ROW_VERIFY_OK;
}

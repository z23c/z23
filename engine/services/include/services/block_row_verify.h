/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Canonical per-row header admission verify — the ONE primitive every
 * persisted-state loader (--importblockindex, node.db `blocks` hydrate, and
 * the block_index.bin flat cache) calls so all three admit stored block state
 * at the SAME strength. It runs the EXISTING consensus checks in the EXISTING
 * order; it changes WHERE and HOW CONSISTENTLY they run, never what "valid"
 * means. No consensus predicate is defined or altered here — this TU only
 * CALLS CheckProofOfWork + check_equihash_solution (the frozen verifiers). */

#ifndef ZCL_SERVICES_BLOCK_ROW_VERIFY_H
#define ZCL_SERVICES_BLOCK_ROW_VERIFY_H

#include <stdbool.h>
#include <stdint.h>

struct block_header;
struct chain_params;

/* Typed verdict — each loader maps it to its own reason vocabulary so the
 * import, validate-headers, blocks-hydrate, and flat paths keep the exact
 * machine tokens their callers/tests already expect. */
enum block_row_verify_result {
    BLOCK_ROW_VERIFY_OK = 0,
    BLOCK_ROW_VERIFY_NO_PARAMS,          /* cp == NULL */
    BLOCK_ROW_VERIFY_HASH_BIND_MISMATCH, /* header re-hash != expected_hash */
    BLOCK_ROW_VERIFY_HIGH_HASH,          /* CheckProofOfWork target failed */
    BLOCK_ROW_VERIFY_BAD_EQUIHASH,       /* check_equihash_solution failed */
};

/* Verify one persisted block row against the frozen consensus checks.
 *
 *   expected_hash  the stored/claimed 32-byte PoW hash (the LevelDB key, the
 *                  `blocks` hash column, or the flat entry hash).
 *   n_bits         the stored difficulty target bits used for the PoW check
 *                  (when `header` != NULL the caller passes header->nBits).
 *   header         the reconstructed canonical header, or NULL when the caller
 *                  cannot rebuild it (the flat cache stores no merkle root /
 *                  nonce / Equihash solution). NULL => hash-bind AND the
 *                  Equihash check are skipped; only CheckProofOfWork on the
 *                  stored hash runs.
 *   cp             chain params (consensus target + Equihash params).
 *   check_equihash run the full Equihash solution check (callers gate this on
 *                  their stride / above-checkpoint budget). Ignored when
 *                  header == NULL.
 *
 * Sequence (identical to the pre-dedup copies): hash-bind -> CheckProofOfWork
 * -> (gated) check_equihash_solution. Returns the first failing stage, or
 * BLOCK_ROW_VERIFY_OK. Pure: no clock/RNG/IO. */
enum block_row_verify_result
block_row_verify(const uint8_t expected_hash[32], uint32_t n_bits,
                 const struct block_header *header,
                 const struct chain_params *cp, bool check_equihash);

#endif /* ZCL_SERVICES_BLOCK_ROW_VERIFY_H */

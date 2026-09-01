/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * validation/accept_block_header.h — header-only acceptance API and
 * thin lib-side wrappers around the pure DOMAIN header checks.
 *
 * The legacy free function `accept_block_header()` (declared in
 * validation/process_block.h) is the high-level acceptance-into-the-
 * block-index entry point: it walks the block_index map, fixes
 * scrambled heights, and runs contextual header checks. That function
 * intentionally stays in process_block.h to preserve the existing include
 * topology — wt callers of the high-level path already wire it through
 * process_block.h.
 *
 * The wrappers exposed here are the thin lib-side adapters around
 * domain/consensus/header_accept.h: they decode a domain `zcl_result` into
 * the validation_state shape expected by the peer-visible reject path.
 */

#ifndef ZCL_VALIDATION_ACCEPT_BLOCK_HEADER_H
#define ZCL_VALIDATION_ACCEPT_BLOCK_HEADER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "consensus/validation.h"
#include "primitives/block.h"

struct main_state;
struct block_index;

/* Create (or return the already-mapped) in-memory block_index entry for
 * `header`: inserts into ms->map_block_index, links pprev, and computes
 * nHeight + nChainWork. This is the sole runtime block_index producer.
 * Declared here so the staged reducer (app/jobs header_admit stage) can
 * create the index entry
 * from raw header bytes without routing through the legacy
 * accept_block_header(). Returns NULL on allocation failure. Does NOT touch
 * coins.db, the active-chain tip, or disk. */
struct block_index *add_to_block_index(struct main_state *ms,
                                       const struct block_header *header);

/* Run domain_consensus_check_header_version_too_low() and, on
 * rejection, populate `state` exactly as the legacy
 *   REJECT_IF(header->nVersion < MIN_BLOCK_VERSION,
 *             state, 100, "version-too-low");
 * gate does (dos=100, corruption=false, code=REJECT_INVALID,
 * reject_reason="version-too-low"). Returns true on accept,
 * false on reject (state populated).
 */
bool accept_block_header_check_version_too_low(
        const struct block_header *header,
        int32_t min_version,
        struct validation_state *state);

/* Run domain_consensus_check_header_version_obsolete() and, on
 * rejection, populate `state` exactly as the legacy
 *   REJECT_OBSOLETE_IF(header->nVersion < 4, state, "bad-version");
 * gate does (dos=0, corruption=false, code=REJECT_OBSOLETE,
 * reject_reason="bad-version"). Returns true on accept, false on
 * reject.
 */
bool accept_block_header_check_version_obsolete(
        const struct block_header *header,
        int32_t obsolete_below,
        struct validation_state *state);

/* Run domain_consensus_check_header_timestamp_too_new() and, on
 * rejection, populate `state` exactly as the legacy
 *   REJECT_INVALID_IF(block_header_get_time(header) >
 *                     GetAdjustedTime() + 2 * 60 * 60,
 *                     state, "time-too-new");
 * gate does (dos=0, corruption=false, code=REJECT_INVALID,
 * reject_reason="time-too-new"). The caller supplies
 * `now_upper_bound` (typically `GetAdjustedTime() + drift`); the
 * wrapper itself touches no clock.
 */
bool accept_block_header_check_timestamp_too_new(
        const struct block_header *header,
        int64_t now_upper_bound,
        struct validation_state *state);

/* Run domain_consensus_check_header_timestamp_too_old() and, on
 * rejection, populate `state` exactly as the legacy
 *   REJECT_INVALID_IF(header_time <= median_time_past, state,
 *                     "time-too-old");
 * gate does (dos=0, corruption=false, code=REJECT_INVALID,
 * reject_reason="time-too-old"). The caller supplies `prev_mtp`
 * (typically block_index_get_median_time_past(pindex_prev)); the
 * wrapper itself does not walk the block index.
 */
bool accept_block_header_check_timestamp_too_old(
        const struct block_header *header,
        int64_t prev_mtp,
        struct validation_state *state);

/* Run domain_consensus_check_header_equihash_solution_size() and,
 * on rejection, populate `state` exactly as the legacy
 *   REJECT_IF(sol_size != expected, state, 100,
 *             "bad-equihash-solution-size");
 * gate does (dos=100, corruption=false, code=REJECT_INVALID,
 * reject_reason="bad-equihash-solution-size"). The caller supplies
 * `expected_solution_size` (computed from chain_params_equihash_n/k
 * which lives in chain/chainparams.h — kept out of the domain layer).
 * Legacy semantics: a zero-size header silently passes.
 */
bool accept_block_header_check_equihash_solution_size(
        const struct block_header *header,
        size_t expected_solution_size,
        struct validation_state *state);

/* Run domain_consensus_check_header_bits_match() and, on rejection,
 * populate `state` exactly as the legacy
 *   REJECT_IF(header->nBits != expected_bits, state, 100,
 *             "bad-diffbits");
 * gate does (dos=100, corruption=false, code=REJECT_INVALID,
 * reject_reason="bad-diffbits"). The caller supplies `expected_bits`
 * (typically GetNextWorkRequired which walks the averaging window —
 * explicitly NOT pure, so it stays out of the domain layer).
 */
bool accept_block_header_check_bits_match(
        const struct block_header *header,
        uint32_t expected_bits,
        struct validation_state *state);

#endif /* ZCL_VALIDATION_ACCEPT_BLOCK_HEADER_H */

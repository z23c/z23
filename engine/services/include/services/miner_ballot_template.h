/* purpose: Add a ballot to a bounded temporary mining template. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_MINER_BALLOT_TEMPLATE_H
#define ZCL_SERVICES_MINER_BALLOT_TEMPLATE_H
#include "base/result.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
struct block;
struct chain_params;
struct block_template;

/* Append a final zero-value ballot output to an UNSOLVED, caller-owned block.
 * Mining limit is 1..DEFAULT_BLOCK_MAX_SIZE inclusive. The entire block is
 * canonically serialized into a fixed-capacity buffer with the selected
 * height's actual Equihash solution width and a 100-byte coinbase scriptSig.
 * Checked serialization, every txid and Merkle root must succeed; duplicate
 * Merkle pairs are refused. On success the original unsolved header and
 * scriptSig lengths are restored, the new coinbase hash and Merkle root are
 * installed, and reserved_size_out receives the serialized bound.
 *
 * On ANY error, the caller MUST discard the private block/template: an
 * appended output or temporary content may have been written. This is mining
 * policy and is not a block validation or consensus predicate. Pool edits
 * after this call require rechecking size, txid and Merkle root. */
struct zcl_result miner_ballot_template_apply(struct block *block,
    const uint8_t catalog[32], const uint8_t bitmap[32],
    const struct chain_params *params, int height, size_t mining_limit,
    size_t *reserved_size_out);

/* Fit a research template to the supplied limit by dropping a trailing suffix.
 * The caller discards the template on any error. */
struct zcl_result miner_research_template_fit(struct block_template *tmpl,
    const struct chain_params *params, int height, bool reserve_ballot, size_t limit);
#endif

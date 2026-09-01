/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private selected-chain receipt and body-verification seam for the
 * owner-gated nullifier backfill service. */

#ifndef ZCL_NULLIFIER_BACKFILL_CHAIN_H
#define ZCL_NULLIFIER_BACKFILL_CHAIN_H

#include "core/uint256.h"
#include "util/result.h"

#include <stdbool.h>
#include <stdint.h>

struct block;
struct block_index;
struct nullifier_backfill_config;
struct sqlite3;

struct nbf_chain_binding {
    int target_height;
    struct uint256 target_hash;
    int tip_height;
    struct uint256 tip_hash;
    struct block_index *target;
    struct block_index *tip;
};

bool nbf_chain_binding_equal(const struct nbf_chain_binding *a,
                             const struct nbf_chain_binding *b);

struct zcl_result nbf_chain_binding_read(
    struct sqlite3 *db,
    struct nbf_chain_binding *out,
    bool *found_out,
    bool *valid_out);

struct zcl_result nbf_chain_binding_capture(
    const struct nullifier_backfill_config *cfg,
    int64_t activation,
    struct nbf_chain_binding *out);

bool nbf_chain_binding_store_in_tx(
    struct sqlite3 *db,
    const struct nbf_chain_binding *binding);

struct zcl_result nbf_chain_body_verify(
    const struct nbf_chain_binding *binding,
    const struct block *blk,
    int64_t height);

#endif /* ZCL_NULLIFIER_BACKFILL_CHAIN_H */

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * What a snapshot offer may say about the UTXO mirror it would serve.
 *
 * The anchor height is the mirror's own cursor minus one, read with the rows in
 * one read transaction on a connection of its own, so the height, the block it
 * names and the root cannot describe different moments. The mirror is a read
 * model: an anchor says what this node's rows are, never that they are right. */

#ifndef ZCL_SERVICES_SNAPSHOT_OFFER_ANCHOR_H
#define ZCL_SERVICES_SNAPSHOT_OFFER_ANCHOR_H

#include <stdbool.h>
#include <stdint.h>

#include "util/result.h"

struct snapshot_offer;

struct snapshot_offer_anchor {
    int32_t height;
    uint8_t block_hash[32];
    uint8_t chain_work[32];
    uint8_t utxo_root[32];
    uint8_t mmr_root[32];
    uint64_t num_utxos;
};

/* Read the anchor of the node.db at db_path. Refuses, with out zeroed, unless
 * the cursor is a well-formed positive height, a validated block row with a
 * non-zero work stands at cursor-1 and every height below it has a validated
 * row, no utxo row claims a height at or past the cursor, and the set is not
 * empty. */
struct zcl_result snapshot_offer_anchor_read(const char *db_path,
                                             struct snapshot_offer_anchor *out);

/* Do the bytes about to be served hash to what the anchor read? The file is
 * written apart from the anchor's transaction, so the root is what ties them. */
struct zcl_result snapshot_offer_anchor_check_payload(
    const struct snapshot_offer_anchor *anchor,
    const uint8_t payload_sha3[32], uint64_t payload_count);

/* Fill an offer's fields the anchor decides. peer_tip_height is the anchor:
 * the receiver's finality rule takes it as a live snapshot at this node's tip. */
void snapshot_offer_from_anchor(struct snapshot_offer *offer,
                                const struct snapshot_offer_anchor *anchor);

#ifdef ZCL_TESTING
/* Called inside the read transaction, after the cursor is read. */
void snapshot_offer_anchor_test_set_mid_read_hook(void (*hook)(void *ctx),
                                                  void *ctx);
#endif

#endif /* ZCL_SERVICES_SNAPSHOT_OFFER_ANCHOR_H */

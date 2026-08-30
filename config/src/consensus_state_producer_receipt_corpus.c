/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Header-corpus digest for the producer receipt: recompute the genesis..H*
 * header chain digest from the producer's own progress.kv rows. Split from
 * consensus_state_producer_receipt.c along the file-size ceiling seam. */

#include "consensus_state_producer_receipt_internal.h"
#include "consensus_state_proof_prefix.h"

/* See the contract note in consensus_state_producer_receipt_internal.h: this
 * MUST stay byte-identical to prove_header_chain() in
 * consensus_state_snapshot_export_proof.c. */
bool producer_receipt_header_corpus_digest(sqlite3 *db, int32_t height,
                                           const uint8_t expected_hash[32],
                                           uint8_t out[32])
{
    return consensus_state_proof_header_digest(db, height, expected_hash, out,
                                                NULL);
}

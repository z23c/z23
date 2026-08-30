/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: internal contract for the COMMITTED final receipt row — the read,
 * write, and exact-match comparison of the singleton
 * consensus_state_source_receipt row — shared between
 * config/src/consensus_state_producer_receipt_final.c (the row I/O) and
 * config/src/consensus_state_producer_receipt.c (finalize(), its only caller).
 *
 * Split out of config/src/consensus_state_producer_receipt.c when that file
 * passed its shape ceiling.
 */

#ifndef ZCL_CONSENSUS_STATE_PRODUCER_RECEIPT_FINAL_INTERNAL_H
#define ZCL_CONSENSUS_STATE_PRODUCER_RECEIPT_FINAL_INTERNAL_H

#include "storage/consensus_state_bundle_codec.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

enum final_receipt_state {
    FINAL_RECEIPT_READ_ERROR = 0, FINAL_RECEIPT_ABSENT,
    FINAL_RECEIPT_IDENTICAL, FINAL_RECEIPT_MONOTONIC_PREDECESSOR,
    FINAL_RECEIPT_CONFLICT,
};

bool read_existing_receipt_fold_cursor(sqlite3 *db, int64_t *out,
                                       bool *present);

bool write_final_receipt(
    sqlite3 *db, const struct consensus_state_source_receipt *r);

/* Replace one cryptographically valid, same-session predecessor with its
 * strictly higher successor.  Call only after final_receipt_state returned
 * FINAL_RECEIPT_MONOTONIC_PREDECESSOR. */
bool advance_final_receipt(
    sqlite3 *db, const struct consensus_state_source_receipt *r);

enum final_receipt_state final_receipt_state(
    sqlite3 *db, const struct consensus_state_source_receipt *expected);

#endif /* ZCL_CONSENSUS_STATE_PRODUCER_RECEIPT_FINAL_INTERNAL_H */

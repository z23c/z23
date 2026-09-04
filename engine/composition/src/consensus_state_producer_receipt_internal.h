/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Internal contract shared by the producer-receipt TUs
 * (consensus_state_producer_receipt.c + _corpus.c + _session_retire.c). */

#ifndef ZCL_CONSENSUS_STATE_PRODUCER_RECEIPT_INTERNAL_H
#define ZCL_CONSENSUS_STATE_PRODUCER_RECEIPT_INTERNAL_H

#include "config/consensus_state_producer_receipt.h"
#include "storage/consensus_state_bundle_codec.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

#define PRODUCER_RECEIPT_SUBSYS "consensus_producer_receipt"

#define PRODUCER_SESSION_SCHEMA_V1 "zcl.consensus_state_producer_session.v1"
#define PRODUCER_SESSION_SCHEMA_V2 "zcl.consensus_state_producer_session.v2"

#define PRODUCER_SESSION_SCHEMA_SQL \
    "CREATE TABLE IF NOT EXISTS consensus_state_producer_session(" \
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1)," \
    "schema TEXT NOT NULL,running_binary_digest BLOB NOT NULL," \
    "source_tree_root BLOB NOT NULL,toolchain_digest BLOB NOT NULL," \
    "build_inputs_digest BLOB NOT NULL,source_epoch_digest BLOB NOT NULL," \
    "source_clean INTEGER NOT NULL,validation_profile INTEGER NOT NULL," \
    "producer_commit TEXT NOT NULL,datadir TEXT NOT NULL," \
    "start_time_us INTEGER NOT NULL)"

struct producer_session {
    uint8_t running_binary_digest[32];
    uint8_t source_epoch_digest[32];
    struct consensus_state_source_receipt claim; /* claim fields only */
    int64_t started_us; /* session start_time_us (0 when absent) */
    bool present;
};

/* SHA3-256 of the running executable's on-disk image. Used by begin() to
 * bind the session to this build and by retire() to decide whether the
 * stored session already matches the build about to judge it. */
bool producer_running_binary_digest(uint8_t out[32]);

/* The running build's own v2 claim and source epoch — recomputed from the
 * executable, never derived from any stored row (resume/retire authority is
 * always the running build's, not the row's). */
bool producer_current_v2_claim(
    uint8_t validation_profile,
    struct consensus_state_source_receipt *out,
    uint8_t source_epoch[32]);

/* Load the singleton start session from the store. Returns false only on a
 * store error; out->present reports whether a row exists (a missing table
 * is a legitimate "no session"). */
bool producer_session_load(sqlite3 *db, struct producer_session *out);

/* Exact-equality resume test between a stored session and the running
 * build's independently derived claim/epoch/binary digest. */
bool producer_session_matches_current(
    const struct producer_session *stored,
    const struct consensus_state_source_receipt *current,
    const uint8_t current_epoch[32],
    const uint8_t running_binary[32]);

/* Same field order as producer_session_matches_current; writes a short
 * "field=<name> expected=<8-hex> actual=<8-hex>" description of the FIRST
 * field that diverges (or "field=none (session matches)" if it would pass)
 * into `out`. Used to make a mismatch refusal name the exact cause instead
 * of a generic "does not match" sentence. */
void producer_session_mismatch_detail(
    const struct producer_session *stored,
    const struct consensus_state_source_receipt *current,
    const uint8_t current_epoch[32], const uint8_t running_binary[32],
    char *out, size_t out_size);

/* Recompute the genesis..height header corpus digest and confirm the tip hash.
 * MUST stay byte-identical to prove_header_chain() in
 * consensus_state_snapshot_export_proof.c — the exporter compares the receipt's
 * chain_corpus_digest against its own recomputation. The producer-receipt test
 * runs the real exporter, so any drift here fails the test. */
bool producer_receipt_header_corpus_digest(sqlite3 *db, int32_t height,
                                           const uint8_t expected_hash[32],
                                           uint8_t out[32]);

#endif /* ZCL_CONSENSUS_STATE_PRODUCER_RECEIPT_INTERNAL_H */

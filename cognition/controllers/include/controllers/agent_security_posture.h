/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONTROLLERS_AGENT_SECURITY_POSTURE_H
#define ZCL_CONTROLLERS_AGENT_SECURITY_POSTURE_H

#include <stdbool.h>
#include <stdint.h>

struct json_value;
struct node_db;

struct agent_security_posture {
    bool review_required;
    bool node_db_available;
    bool progress_store_available;
    bool snapshot_evidence_present;
    bool trusted_state_present;
    bool full_history_validation_complete;
    bool snapshot_full_validation_complete;
    bool snapshot_utxo_sha3_verified;
    bool snapshot_flyclient_verified;
    bool snapshot_chunk_hash_coverage_verified;
    bool anchor_cursor_known;
    bool anchor_history_complete;
    bool anchor_backfill_gap;
    bool nullifier_cursor_known;
    bool nullifier_history_complete;
    bool nullifier_backfill_gap;
    int snapshot_anchor_height;
    /* Background-validation walk's current height (chain_evidence_authority_
     * service.h's persisted "cec.background_validation_height" counter,
     * copied from the SAME chain_evidence_controller_snapshot() call that
     * fills snapshot_anchor_height above — no new read/lock). -1 when unknown
     * (node_db unavailable, or the walk has not recorded a height yet). See
     * `z23 core sync validation` for the walk this height belongs to. */
    int background_validation_height;
    int64_t sprout_anchor_activation_cursor;
    int64_t sapling_anchor_activation_cursor;
    int64_t nullifier_activation_cursor;
    char status[48];
    char bootstrap_model[64];
    char full_history_validation_origin[32];
    char full_history_validation_state[48];
    char anchor_history_state[64];
    char nullifier_history_state[64];
    char next_action[96];
    /* Non-blocking-serve provenance. When the shared node.db connection is busy
     * with a long maintenance op, collect() skips the DB reads entirely and
     * fills this struct from the last live snapshot instead: served_from_cache
     * is true and cache_age_ms is the snapshot's age (or -1 if no snapshot has
     * ever been published). Live collections leave served_from_cache false. */
    bool served_from_cache;
    int64_t cache_age_ms;
};

void agent_security_posture_collect(struct agent_security_posture *out,
                                    struct node_db *ndb);
bool agent_security_posture_allows_public_serving(
    const struct agent_security_posture *posture);
void agent_push_security_posture_json(struct json_value *out, const char *key,
                                      struct node_db *ndb);
/* Render an already-collected posture without repeating its SQLite reads. */
void agent_push_security_posture_snapshot_json(
    struct json_value *out, const char *key,
    const struct agent_security_posture *posture);

#ifdef ZCL_TESTING
void agent_security_posture_test_override_review_required(int required);
#endif

#endif /* ZCL_CONTROLLERS_AGENT_SECURITY_POSTURE_H */

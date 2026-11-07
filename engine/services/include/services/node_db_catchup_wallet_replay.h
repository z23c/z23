/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: bounded Sapling wallet replay against an authenticated endpoint. */
#ifndef ZCL_NODE_DB_CATCHUP_WALLET_REPLAY_H
#define ZCL_NODE_DB_CATCHUP_WALLET_REPLAY_H

#include <stdint.h>

struct node_db;
struct db_service;
struct main_state;
struct wallet;

enum sapling_replay_phase { SAPLING_REPLAY_DISCOVER, SAPLING_REPLAY_SPENDS };
enum sapling_replay_status {
    SAPLING_REPLAY_COMPLETE, SAPLING_REPLAY_INCOMPLETE, SAPLING_REPLAY_BUSY,
    SAPLING_REPLAY_KEYS_UNAVAILABLE, SAPLING_REPLAY_CHAIN_CHANGED,
    SAPLING_REPLAY_DB_ERROR, SAPLING_REPLAY_EVENT_UNAVAILABLE, SAPLING_REPLAY_INVALID,
    SAPLING_REPLAY_WALLET_CHANGED
};
struct sapling_replay_result {
    enum sapling_replay_status status;
    enum sapling_replay_phase phase;
    int start_height, end_height;
    /* Reference and scan identity are populated only by the fixed-reference API. */
    int reference_height;
    int last_complete;
    int notes_found;
    uint8_t endpoint_hash[32], reference_hash[32], scan_identity[32];
    uint8_t key_digest[32];
};
/* COMPLETE covers only the selected Sapling phase, not witness coverage or
 * wallet readiness. Caller supplies a finite range and its authenticated
 * endpoint, owns no wallet/chain locks during this call, and must retain its
 * separate history/readiness fence. SPENDS requires the DISCOVER key digest
 * after independently rebuilding witnesses/nullifiers for the same range.
 * The caller keeps the projection event sink alive until this call returns;
 * shutdown must drain the coordinator and DB worker before closing it. */
struct sapling_replay_result node_db_catchup_sapling_replay(
    struct db_service *svc, struct node_db *db, struct main_state *state,
    struct wallet *wallet, const char *datadir, int start, int end,
    enum sapling_replay_phase phase, const uint8_t endpoint_hash[32],
    const uint8_t expected_key_digest[32]);

/* Fixed-reference recovery: checks the reference and full wallet identity
 * under their locks through each block transaction. No lock is held by the
 * caller. COMPLETE is phase-local and does not publish wallet readiness. */
struct sapling_replay_result node_db_catchup_sapling_replay_at_reference(
    struct db_service *svc, struct node_db *db, struct main_state *state,
    struct wallet *wallet, const char *datadir, int start, int end,
    int reference_height, const uint8_t reference_hash[32],
    enum sapling_replay_phase phase, const uint8_t endpoint_hash[32],
    const uint8_t expected_scan_identity[32], const uint8_t expected_key_digest[32]);

#endif

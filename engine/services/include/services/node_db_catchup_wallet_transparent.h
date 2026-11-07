/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: bounded transparent wallet replay against an authenticated endpoint. */
#ifndef Z23_NODE_DB_CATCHUP_WALLET_TRANSPARENT_H
#define Z23_NODE_DB_CATCHUP_WALLET_TRANSPARENT_H
#include <stdint.h>
struct main_state;
struct wallet;
enum transparent_replay_status {
    TRANSPARENT_REPLAY_COMPLETE, TRANSPARENT_REPLAY_BUSY,
    TRANSPARENT_REPLAY_INCOMPLETE, TRANSPARENT_REPLAY_KEYS_CHANGED,
    TRANSPARENT_REPLAY_CHAIN_CHANGED, TRANSPARENT_REPLAY_WALLET_ERROR,
    TRANSPARENT_REPLAY_INVALID
};
struct transparent_replay_result {
    enum transparent_replay_status status;
    int start_height, end_height, reference_height, last_complete;
    uint8_t endpoint_hash[32], scan_identity[32];
};
/* Replays at most 256 authenticated blocks into wallet RAM only. Caller holds
 * no chain or wallet locks and retains the pending readiness fence. The reference endpoint
 * and full wallet scan identity must match the separately acquired proofs.
 * Partial progress is retryable; COMPLETE does not publish wallet readiness. */
struct transparent_replay_result node_db_catchup_wallet_transparent(
    struct main_state *state, struct wallet *wallet, const char *datadir,
    int start, int end, int reference_height, const uint8_t endpoint_hash[32],
    const uint8_t scan_identity[32]);
#endif

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Snapshot Sync Contract — high-performance UTXO snapshot sync.
 *
 * Service actions for P2P snapshot protocol:
 *   handle_offer     — validate + accept incoming snapshot offer
 *   handle_fc_proofs — verify FlyClient MMB proofs (PoW chain)
 *   handle_data      — apply UTXO chunk (batch commit every 100K)
 *   handle_end       — finalize + SHA3 verify; runtime activation contained
 *   validate_serve_request — check PoW + rate limit for serving
 *
 * Security: Two-phase verification
 *   Phase 1 (pre-download): FlyClient — 50 random block samples
 *     with MMB inclusion proofs + PoW target checks. Proves the
 *     peer's chain has valid cumulative work (≥150-bit security).
 *   Phase 2 (post-download): SHA3-256 over all UTXOs in canonical
 *     order. Proves data integrity (hash matches offered root).
 *
 * Flow: offer → zfcchallenge → zfcproofs → zsnapreq → data → end
 *
 * Uses shared node_db connection in turbo mode with batch commits.
 * State machine driven, event observable, ActiveRecord validated. */

#ifndef ZCL_NET_SNAPSHOT_SYNC_CONTRACT_H
#define ZCL_NET_SNAPSHOT_SYNC_CONTRACT_H

#include "event/event.h"
#include "net/flyclient.h"
#include "sync/sync_state.h"
#include "util/result.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct byte_stream;
struct node_db;
struct fast_sync_pow;
struct active_chain;
struct mmb_leaf_store;
struct main_state;
struct p2p_node;
struct block_index;

/* Runtime peer-snapshot activation is fail-closed until a single canonical
 * installer can atomically publish every transparent/shielded/reducer state
 * component plus provenance and rollback. Download + verification may run;
 * activation returns this error and raises this one dependency blocker. */
#define SNAPSYNC_ACTIVATION_CONTAINED_ERROR_CODE (-12)
#define SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID \
    "snapshot_sync.activation_unified_installer_required"

enum snapsync_followup_action {
    SNAPSYNC_FOLLOWUP_NONE = 0,
    SNAPSYNC_FOLLOWUP_SEND_FC_CHALLENGE = 1,
    SNAPSYNC_FOLLOWUP_SEND_SNAPSHOT_REQ = 2,
};

enum snapsync_serve_action {
    SNAPSYNC_SERVE_ACTION_NONE = 0,
    SNAPSYNC_SERVE_ACTION_SEND_CHUNK = 1,
    SNAPSYNC_SERVE_ACTION_SEND_END = 2,
};

struct snapsync_serve_step {
    enum snapsync_serve_action action;
    int64_t chunk_offset;
    size_t chunk_len;
    uint32_t entries;
};

struct snapsync_offer_acceptance {
    bool should_begin_receive;
    bool should_store_offer_details;
    bool should_reset_offset;
    bool should_update_peer_state;
    enum peer_state peer_state;
    bool should_set_sync_state;
    enum sync_state sync_state;
};

struct snapsync_end_result {
    bool verified;
    bool should_resume_header_sync;
    bool should_update_peer_state;
    enum peer_state peer_state;
    bool should_activate_tip;
    bool should_set_sync_state;
    enum sync_state sync_state;
};

struct snapsync_serve_start {
    bool should_begin_serving;
    bool should_reset_progress;
    bool should_reset_cursor;
    bool should_update_peer_state;
    enum peer_state peer_state;
    uint64_t total_utxos;
};

struct snapsync_offer_followup {
    enum snapsync_followup_action action;
    bool should_send;
};

struct snapsync_verify_result {
    bool verified;
    enum snapsync_followup_action action;
    bool should_send;
};

struct snapsync_serve_complete {
    bool should_finish_serving;
    bool should_update_peer_state;
    enum peer_state peer_state;
};

struct snapshot_sync_service {
    enum snapshot_sync_state state;

    /* Offer details */
    uint8_t  offered_utxo_root[32];
    uint8_t  offered_mmb_root[32];
    uint8_t  offered_block_hash[32];
    uint8_t  offered_chain_work[32];
    int32_t  offered_height;
    int32_t  offered_peer_tip_height;
    uint64_t offered_count;
    uint32_t offered_protocol_version;
    uint32_t offered_schema_version;

    /* FlyClient challenge (generated on offer accept) */
    struct fc_challenge fc_challenge;
    bool     fc_verified;     /* true after FlyClient proofs pass */

    /* Progress */
    uint64_t received_utxos;
    int64_t  start_time_us;
    uint32_t serving_peer_id;

    /* Stall detection */
    int64_t  last_progress_time_us;  /* timestamp of last progress (chunk or commit) */
    uint64_t last_progress_utxos;    /* received_utxos at last progress check */

    /* Per-peer stall blacklist: peers that stalled are rejected for
     * SNAPSYNC_BLACKLIST_SECS.  Prevents the same slow peer from winning
     * the offer race repeatedly after each stall reset. */
#define SNAPSYNC_MAX_BLACKLIST 16
    struct {
        uint32_t peer_id;
        int64_t  blacklisted_at_us;
    } blacklist[SNAPSYNC_MAX_BLACKLIST];
    int blacklist_count;

    /* Database — shared connection, turbo mode during receive */
    struct node_db *ndb;
    bool     turbo_active;
    uint64_t last_commit_at;  /* received_utxos at last COMMIT */
};

struct snapsync_status {
    enum snapshot_sync_state state;
    uint64_t offered_count;
    uint32_t serving_peer_id;
    int32_t offered_height;
    bool turbo_active;
    int64_t staged_row_count;
};

struct snapsync_stall_status {
    bool receiving;
    bool stalled;
    int64_t elapsed_secs;
    uint64_t received_utxos;
    uint64_t offered_utxos;
    uint32_t serving_peer_id;
};

struct snapsync_negotiation_status {
    bool negotiating;
    bool stalled;
    int64_t elapsed_secs;
    int32_t offered_height;
    uint64_t offered_utxos;
    uint32_t serving_peer_id;
};

struct snapsync_failed_status {
    bool failed;
    int64_t elapsed_secs;
    int32_t offered_height;
    uint64_t offered_utxos;
    uint32_t serving_peer_id;
    bool turbo_active;
    int64_t staged_row_count;
};

/* ── Lifecycle ─────────────────────────────────────────────────── */

/* Initialize (called once at boot) */
void snapsync_init(struct snapshot_sync_service *svc, struct node_db *ndb);

/* Reset service back to IDLE (after complete or failed) */
void snapsync_reset(struct snapshot_sync_service *svc);

/* Global singleton — initialized lazily on first snapshot offer */
struct snapshot_sync_service *snapsync_global(void);
bool snapsync_global_initialized(void);
void snapsync_global_ensure_init(struct node_db *ndb);

/* Resolve the active snapshot sync service for Condition detect/witness
 * paths: prefer the wired runtime service, else the lazily-initialized
 * global, else NULL. Non-test accessor (no g_test_svc override). */
struct snapshot_sync_service *snapsync_condition_service(void);

/* ── Controller Actions (called from message router) ───────────── */

/* Result codes for controller actions */
enum snapsync_offer_result {
    SNAPSYNC_OFFER_ACCEPTED,      /* offer accepted, send zsnapreq */
    SNAPSYNC_OFFER_REJECTED_RANGE,     /* num_utxos or total_bytes out of range */
    SNAPSYNC_OFFER_REJECTED_NO_MMR,    /* no MMR root — can't verify chain */
    SNAPSYNC_OFFER_REJECTED_NOT_AHEAD, /* peer not far enough ahead */
    SNAPSYNC_OFFER_REJECTED_BUSY,      /* already receiving a snapshot */
    SNAPSYNC_OFFER_REJECTED_BLACKLISTED, /* peer stalled before */
    SNAPSYNC_OFFER_REJECTED_PARSE,     /* malformed wire data */
    SNAPSYNC_OFFER_REJECTED_STALE_SCHEMA, /* unsupported protocol/schema */
    SNAPSYNC_OFFER_REJECTED_UNFINAL,   /* anchor inside peer finality window */
    SNAPSYNC_OFFER_REJECTED_WEAK_WORK, /* missing or non-competitive chainwork */
};

/* Parsed snapshot offer params (wire → struct by router) */
struct snapshot_offer_params {
    int32_t  height;
    uint8_t  block_hash[32];
    uint8_t  utxo_root[32];
    uint8_t  mmr_root[32];
    uint8_t  mmb_root[32];
    uint8_t  chain_work[32];
    uint64_t num_utxos;
    uint64_t total_bytes;
    uint32_t protocol_version;
    uint32_t snapshot_schema_version;
    int32_t  peer_tip_height;
    uint32_t peer_id;
    int32_t  our_height;  /* receiver's current chain height */
};

/* Action: handle incoming snapshot offer.
 * Validates offer, transitions IDLE → NEGOTIATING.
 * Generates FlyClient challenge (svc->fc_challenge).
 * Router should send zfcchallenge BEFORE zsnapreq.
 * Returns result code for the router to act on. */
enum snapsync_offer_result snapsync_handle_offer(
    struct snapshot_sync_service *svc,
    const struct snapshot_offer_params *params);
struct zcl_result snapsync_request_recovery(struct snapshot_sync_service *svc,
                               int32_t target_height,
                               const struct snapshot_offer_params *manifest);
struct zcl_result snapsync_build_local_recovery_manifest(struct node_db *ndb,
                                            struct snapshot_offer_params *out,
                                            uint32_t peer_id);
struct zcl_result snapsync_parse_offer_params(struct snapshot_offer_params *params,
                                 struct byte_stream *s);
struct zcl_result snapsync_parse_fc_response(struct fc_response *resp,
                                struct byte_stream *s);
struct zcl_result snapsync_write_fc_challenge(const struct snapshot_sync_service *svc,
                                 struct byte_stream *s);
struct zcl_result snapsync_write_snapshot_request(struct byte_stream *s,
                                     int32_t our_height,
                                     const uint8_t peer_ip[16]);
struct zcl_result snapsync_build_fc_response(struct fc_response *resp,
                                const struct fc_challenge *challenge,
                                const struct active_chain *chain_active,
                                const struct mmb_leaf_store *leaf_store);
struct zcl_result snapsync_write_fc_response(struct byte_stream *s,
                                const struct fc_response *resp);
int snapsync_activate_verified_tip(const struct snapshot_sync_service *svc,
                                   struct main_state *ms);
void snapsync_build_offer_acceptance(struct snapsync_offer_acceptance *result);
void snapsync_build_end_result(struct snapsync_end_result *result,
                               bool verified);
void snapsync_build_serve_start(struct snapsync_serve_start *result,
                                uint64_t total_utxos);
void snapsync_build_offer_followup(struct snapsync_offer_followup *result,
                                   const struct snapshot_sync_service *svc);
void snapsync_build_verify_result(struct snapsync_verify_result *result,
                                  bool verified);
void snapsync_build_serve_complete(struct snapsync_serve_complete *result);
/* Prepare the next snapshot-serve step (chunk / end / backpressure-none).
 * Returns ZCL_OK with step->action set; a non-ok result (carrying the
 * reason) on malformed args or a buffer/scan overflow. */
struct zcl_result snapsync_prepare_serve_step(struct snapsync_serve_step *step,
                                              struct p2p_node *node,
                                              const uint8_t *buf,
                                              int64_t buf_size);

/* Action: verify FlyClient proofs from peer.
 * Checks 20 random block samples with MMB inclusion proofs
 * and PoW target verification. If ALL pass, sets fc_verified=true.
 * Router should only send zsnapreq after this returns ok. */
struct zcl_result snapsync_verify_flyclient(struct snapshot_sync_service *svc,
                               const struct fc_response *resp);

/* Action: apply a chunk of UTXO data from wire.
 * Auto-transitions to RECEIVING on first chunk.
 * Returns count of UTXOs applied, or -1 on error. */
int snapsync_apply_chunk(struct snapshot_sync_service *svc,
                         const uint8_t *chunk_data, size_t chunk_len);

/* Action: handle snapshot end — finalize + SHA3 verify.
 * Only accepts from the serving peer. While runtime activation containment is
 * active, a valid payload remains staged and this returns the explicit
 * SNAPSYNC_ACTIVATION_CONTAINED_ERROR_CODE rather than publishing COMPLETE. */
struct zcl_result snapsync_handle_end(struct snapshot_sync_service *svc,
                         uint32_t peer_id);

/* Result codes for serve request validation */
enum snapsync_serve_result {
    SNAPSYNC_SERVE_OK,            /* serve the snapshot */
    SNAPSYNC_SERVE_BAD_POW,       /* invalid or missing PoW */
    SNAPSYNC_SERVE_RATE_LIMITED,   /* too many requests from this IP */
    SNAPSYNC_SERVE_NOT_READY,     /* snapshot not prebuilt yet */
    SNAPSYNC_SERVE_TRUNCATED,     /* malformed request */
};

/* Action: validate a snapshot serve request.
 * Checks PoW, rate limits. Returns result code. */
enum snapsync_serve_result snapsync_validate_serve_request(
    const uint8_t *pow_data, size_t pow_len,
    const uint8_t peer_ip[16]);

/* Serve-side client-puzzle LOAD CENSUS — observation only.
 *
 * Every accepted zsnapreq is offered to a struct puzzle_gate via
 * puzzle_gate_admit_external() so the shared primitive's load EWMA is fed
 * by real snapshot-serve traffic. The gate's verdict is deliberately NOT
 * load-bearing here: see the block comment above
 * snapsync_validate_serve_request() in engine/services/src/snapshot_sync_service.c
 * for why single-use cannot be enforced on this wire format yet, and what
 * protocol revision would make it enforceable.
 *
 * `duplicates` is the count of accepted requests whose proof was
 * byte-identical to one already seen — i.e. exactly the honest-peer
 * collision that blocks turning the verdict on. A window with
 * duplicates == 0 under real traffic is evidence; a nonzero count is the
 * measured cost of enforcing it today. */
struct snapsync_serve_puzzle_census {
    uint64_t offered;      /* accepted requests fed to the gate       */
    uint64_t first_sight;  /* gate admitted (proof not seen before)   */
    uint64_t duplicates;   /* gate refused: byte-identical proof      */
    int      bits_now;     /* difficulty the gate would demand now    */
    int64_t  rate_ewma_milli; /* accepted-per-second ×1000            */
};
void snapsync_get_serve_puzzle_census(struct snapsync_serve_puzzle_census *out);
void snapsync_reset_serve_puzzle_census(void);

/* ── Low-level (used internally / by handle_offer) ─────────────── */

struct zcl_result snapsync_accept_offer(struct snapshot_sync_service *svc,
                           int32_t height, uint64_t num_utxos,
                           const uint8_t utxo_root[32],
                           const uint8_t mmb_root[32],
                           const uint8_t block_hash[32],
                           uint32_t peer_id);

struct zcl_result snapsync_begin_receive(struct snapshot_sync_service *svc);

struct zcl_result snapsync_finalize(struct snapshot_sync_service *svc);

/* Query progress */
void snapsync_get_progress(const struct snapshot_sync_service *svc,
                           uint64_t *received, uint64_t *total,
                           double *rate_per_sec);
void snapsync_get_status_snapshot(const struct snapshot_sync_service *svc,
                                 struct snapsync_status *out);
enum snapsync_followup_action snapsync_offer_followup_action(
    const struct snapshot_sync_service *svc);
enum snapsync_followup_action snapsync_verify_followup_action(
    bool verified);
struct zcl_result snapsync_build_request_pow(const uint8_t peer_ip[16],
                                struct fast_sync_pow *pow);

/* True if snapshot sync is in any active state (not IDLE/COMPLETE/FAILED).
 * Use this to suppress block/header processing during snapshot sync. */
bool snapsync_is_active(void);

/* True if this node has blocks on disk but no UTXO set and is waiting for a
 * P2P snapshot to arrive. When true, reducer activation MUST NOT run because
 * the UTXO set is empty — connecting blocks from genesis would permanently
 * mark valid blocks as BLOCK_FAILED.
 *
 * Becomes false once a snapshot is received (SNAPSYNC_COMPLETE) or if
 * coins_best_block is set at a meaningful height. */
bool snapsync_awaiting_utxos(void);

/* Query snapshot receive stall state. If progress advanced since the last
 * check, refreshes the receive timer and reports not stalled. */
void snapsync_get_stall_status(struct snapshot_sync_service *svc,
                               struct snapsync_stall_status *out);

/* Query snapshot negotiation stall state. A stalled negotiation means an
 * offer was accepted but FlyClient proofs did not arrive in time. */
void snapsync_get_negotiation_status(struct snapshot_sync_service *svc,
                                     struct snapsync_negotiation_status *out);

/* Query terminal snapshot failure state. A FAILED service rejects new offers
 * as busy until reset, so Conditions use this as a recoverable terminal edge. */
void snapsync_get_failed_status(struct snapshot_sync_service *svc,
                                struct snapsync_failed_status *out);

/* Check if snapshot receive has stalled (no chunk for >60s while RECEIVING).
 * If stalled, resets the service to IDLE so a new offer can be accepted.
 * Returns true if a stall was detected and reset was performed. */
bool snapsync_check_stall(void);

/* Check if accepted snapshot negotiation has stalled before receive begins.
 * If stalled, blacklists the peer and resets to IDLE. */
bool snapsync_check_negotiation_stall(void);

/* Check if snapshot sync is in terminal FAILED. If so, blacklist the failed
 * serving peer when known, reset to IDLE, and reopen the offer path. */
bool snapsync_check_failed_reset(void);

/* Stall timeout: seconds without any new UTXOs received before resetting.
 * Must be long enough for SQLite batch commits (~10-30s) + TCP backpressure
 * during WAL checkpoint.  120s balances fast recovery vs false positives. */
#define SNAPSYNC_STALL_TIMEOUT_SECS 120

#define SNAPSYNC_NEGOTIATION_TIMEOUT_SECS 120

/* Blacklist duration: seconds a peer is rejected after stalling.
 * Long enough to let other peers serve, short enough to retry if
 * the peer was temporarily slow (e.g., disk I/O spike). */
#define SNAPSYNC_BLACKLIST_SECS 600

/* Check if a peer is blacklisted for snapshot serving. */
bool snapsync_is_peer_blacklisted(const struct snapshot_sync_service *svc,
                                  uint32_t peer_id);

/* Add a peer to the stall blacklist. */
void snapsync_blacklist_peer(struct snapshot_sync_service *svc,
                             uint32_t peer_id);

/* Snapshot anchor: non-owning pointer to a placeholder block_index at the
 * snapshot height. The block_index is owned by the block map or caller; this
 * slot is only a locator hint so header sync resumes from snapshot height,
 * not from the lower locally-indexed chain tip. Returns NULL if no snapshot
 * anchor is set. */
struct block_index *snapsync_get_anchor(void);
void snapsync_set_anchor(struct block_index *anchor);

#endif

/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_NET_MSGPROCESSOR_H
#define ZCL_NET_MSGPROCESSOR_H

#include "net/net.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "coins/coins_view.h"
#include "chain/chainparams.h"
#include "net/fast_sync.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* config/ is the composition root and sits ABOVE lib/; msgprocessor only
 * ever holds an opaque pointer to the runtime context, so it forward-declares
 * the struct instead of including config/runtime.h. The .c files that need
 * the fields include that header themselves. */
struct app_runtime_context;

struct block;
struct transaction;
struct zmsg_message;
struct file_offer;
struct file_payment;
struct validation_state;
struct active_chain;
struct block_index;
struct fc_challenge;
struct fc_response;
struct msg_block_intake;
struct zswap_yardsale_ad;

typedef bool (*msg_compact_block_submit_fn)(struct block *block,
                                            struct validation_state *out,
                                            void *ctx);
typedef bool (*msg_block_submit_fn)(struct block *block,
                                    struct validation_state *out,
                                    void *ctx);
typedef int (*msg_catchup_drain_fn)(void *ctx);
typedef void (*msg_catchup_batch_scope_fn)(void *ctx);
typedef void (*msg_peer_save_fn)(const struct p2p_node *node, void *ctx);
typedef bool (*msg_zmsg_save_fn)(const struct zmsg_message *msg, void *ctx);
typedef bool (*msg_file_offer_save_fn)(const struct file_offer *offer,
                                       void *ctx);
typedef int (*msg_file_payment_ingest_fn)(
    const struct file_payment *payment, int64_t peer_id,
    int64_t now_unix, void *ctx);
typedef bool (*msg_zswap_ad_save_fn)(const struct zswap_yardsale_ad *ad,
                                     void *ctx);
/* Port seam for the yardsale ingress policy (verify/dedup/clamp/store):
 * lib/net must not name lib/zswap symbols (module-order ratchet), so the
 * handler calls the yardsale through this injected port; the composition
 * root (config/) wires it to zswap_yardsale_ingest_wire. The int result
 * carries enum zswap_yardsale_ingest values (zswap/zswap_yardsale.h). */
typedef int (*msg_zswap_ad_ingest_fn)(const uint8_t *wire, size_t wire_len,
                                      const uint8_t expected_network_genesis[32],
                                      int64_t peer_id, int64_t now_unix,
                                      struct zswap_yardsale_ad *out_ad,
                                      void *ctx);
/* Port seams for the yardsale swap ceremony wires (zswapaccept /
 * zswappartial), same module-order rationale as the ad ingest port: the
 * handlers call the yardsale controller through these injected ports; the
 * composition root (config/) wires them. The int results carry enum
 * zswap_ceremony_wire_result values (zswap/zswap_ceremony.h). The accept
 * port additionally fills respond_wire when it returns
 * ZSWAP_CEREMONY_WIRE_RESPOND (the seller's zswap_partial.v1 answer). */
typedef int (*msg_zswap_accept_ingest_fn)(const uint8_t *wire,
                                          size_t wire_len,
                                          int64_t peer_id, int64_t now_unix,
                                          uint8_t *respond_wire,
                                          size_t respond_cap,
                                          size_t *respond_len, void *ctx);
typedef int (*msg_zswap_partial_ingest_fn)(const uint8_t *wire,
                                           size_t wire_len,
                                           int64_t peer_id, int64_t now_unix,
                                           void *ctx);
typedef bool (*msg_file_service_save_fn)(const uint8_t ip[16],
                                         uint16_t port,
                                         uint16_t p2p_port,
                                         int64_t last_seen,
                                         bool is_zcl23,
                                         void *ctx);
typedef bool (*msg_snapshot_active_fn)(void *ctx);
typedef struct block_index *(*msg_snapshot_anchor_get_fn)(void *ctx);
typedef void (*msg_snapshot_anchor_set_fn)(struct block_index *anchor,
                                           void *ctx);
enum msg_activation_request_source {
    MSG_ACTIVATE_BLOCK_FILE_SCAN = 0,
    MSG_ACTIVATE_HEADERS_ALL_DATA,
};
typedef void (*msg_activation_request_fn)(
    enum msg_activation_request_source source,
    void *ctx);
typedef void (*msg_activation_anchor_clear_fn)(const char *reason,
                                               void *ctx);
typedef void (*msg_post_activation_repair_fn)(void *ctx);
typedef int (*msg_block_file_scan_fn)(void *ctx);
typedef bool (*msg_block_index_heights_repaired_fn)(void *ctx);
typedef bool (*msg_header_tip_commit_fn)(struct block_index *header_tip,
                                         void *ctx);
typedef bool (*msg_snapshot_anchor_recommit_fn)(struct block_index *anchor,
                                                int from_height,
                                                void *ctx);
typedef void (*msg_wallet_tx_accepted_fn)(const struct transaction *tx,
                                          void *ctx);
typedef void (*msg_block_connected_fn)(int height, void *ctx);
typedef void (*msg_peer_header_vote_fn)(uint32_t peer_id,
                                        int height,
                                        const char hash_hex[65],
                                        void *ctx);
typedef bool (*msg_flyclient_proof_fn)(
    struct fc_response *resp,
    const struct fc_challenge *challenge,
    const struct active_chain *chain_active,
    void *ctx);
typedef int (*msg_block_hashes_range_fn)(int32_t start_height,
                                         int32_t end_height,
                                         uint8_t (*hashes_out)[32],
                                         size_t max,
                                         void *ctx);
typedef bool (*msg_utxo_sha3_compute_fn)(uint8_t out[32],
                                         uint64_t *utxo_count,
                                         void *ctx);

struct msg_block_intake_stats {
    uint64_t enqueued;
    uint64_t dropped;
    uint64_t processed;
    uint64_t accepted;
    uint64_t rejected;
    uint64_t retryable;
    uint64_t clone_failed;
    uint64_t spawn_failed;
    uint64_t max_depth;
    uint64_t current_depth;
    uint64_t capacity;
    int64_t last_enqueue_unix;
    int64_t last_process_unix;
    bool running;
    bool stopping;
};

/* Lifetime ZMSG transport counters. These distinguish wire receipt from
 * application acceptance and expose ACK progress without logging message
 * bodies. All fields are monotone except the two last-event timestamps. */
struct msg_zmsg_stats {
    uint64_t frames_received;
    uint64_t messages_accepted;
    uint64_t duplicates;
    uint64_t acknowledgements_received;
    int64_t last_received_unix;
    int64_t last_ack_unix;
};

/* Slice-12 hook signatures. frame: one received swarm frame's payload
 * bytes (already framing-verified); the implementation penalizes
 * (peer_scoring_record) and replies through the node's send queue.
 * tick: one per-peer message-cycle; the implementation syncs peer
 * membership, drives the scheduler, and drains outbound frames
 * addressed to THIS node. The file-scope forward declarations are
 * required: without them the tags in the typedef parameter lists below
 * get prototype scope and no longer match the definitions. */
struct msg_processor;
struct p2p_node;
typedef bool (*msg_zcode_swarm_frame_fn)(struct msg_processor *mp,
                                         struct p2p_node *node,
                                         const uint8_t *payload,
                                         size_t payload_len, void *ctx);
typedef void (*msg_zcode_swarm_tick_fn)(struct msg_processor *mp,
                                        struct p2p_node *node, void *ctx);

struct msg_processor {
    struct main_state *main_state;
    struct tx_mempool *mempool;
    struct coins_view_cache *coins_tip;
    const struct chain_params *params;
    const char *datadir;
    struct net_manager *net_mgr;
    const struct app_runtime_context *runtime;
    msg_block_submit_fn block_submit;
    void *block_submit_ctx;
    msg_catchup_drain_fn catchup_drain;
    void *catchup_drain_ctx;
    msg_catchup_batch_scope_fn catchup_batch_begin;
    msg_catchup_batch_scope_fn catchup_batch_end;
    void *catchup_batch_scope_ctx;
    msg_compact_block_submit_fn compact_block_submit;
    void *compact_block_submit_ctx;
    msg_peer_save_fn peer_save;
    void *peer_save_ctx;
    msg_zmsg_save_fn zmsg_save;
    void *zmsg_save_ctx;
    _Atomic uint64_t zmsg_frames_received;
    _Atomic uint64_t zmsg_messages_accepted;
    _Atomic uint64_t zmsg_duplicates;
    _Atomic uint64_t zmsg_acknowledgements_received;
    _Atomic int64_t zmsg_last_received_unix;
    _Atomic int64_t zmsg_last_ack_unix;
    msg_file_offer_save_fn file_offer_save;
    void *file_offer_save_ctx;
    msg_file_payment_ingest_fn file_payment_ingest;
    void *file_payment_ingest_ctx;
    msg_zswap_ad_save_fn zswap_ad_save;
    void *zswap_ad_save_ctx;
    msg_zswap_ad_ingest_fn zswap_ad_ingest;
    void *zswap_ad_ingest_ctx;
    msg_zswap_accept_ingest_fn zswap_accept_ingest;
    void *zswap_accept_ingest_ctx;
    msg_zswap_partial_ingest_fn zswap_partial_ingest;
    void *zswap_partial_ingest_ctx;
    msg_file_service_save_fn file_service_save;
    void *file_service_save_ctx;
    msg_snapshot_active_fn snapshot_active;
    void *snapshot_active_ctx;
    msg_snapshot_anchor_get_fn snapshot_anchor_get;
    void *snapshot_anchor_get_ctx;
    msg_snapshot_anchor_set_fn snapshot_anchor_set;
    void *snapshot_anchor_set_ctx;
    msg_activation_request_fn activation_request;
    void *activation_request_ctx;
    msg_activation_anchor_clear_fn activation_anchor_clear;
    void *activation_anchor_clear_ctx;
    msg_post_activation_repair_fn post_activation_repair;
    void *post_activation_repair_ctx;
    msg_block_file_scan_fn block_file_scan;
    void *block_file_scan_ctx;
    msg_block_index_heights_repaired_fn block_index_heights_repaired;
    void *block_index_heights_repaired_ctx;
    msg_header_tip_commit_fn header_tip_commit;
    void *header_tip_commit_ctx;
    msg_snapshot_anchor_recommit_fn snapshot_anchor_recommit;
    void *snapshot_anchor_recommit_ctx;
    msg_wallet_tx_accepted_fn wallet_tx_accepted;
    void *wallet_tx_accepted_ctx;
    msg_block_connected_fn block_connected;
    void *block_connected_ctx;
    msg_peer_header_vote_fn peer_header_vote;
    void *peer_header_vote_ctx;
    msg_flyclient_proof_fn flyclient_proof;
    void *flyclient_proof_ctx;
    msg_block_hashes_range_fn block_hashes_range;
    void *block_hashes_range_ctx;
    msg_utxo_sha3_compute_fn utxo_sha3_compute;
    void *utxo_sha3_compute_ctx;
    struct msg_block_intake *block_intake;
    /* ZCODE package swarm (slice 12): the engine lives ABOVE lib/net in
     * the module order (lib/vcs), so net speaks to it only through these
     * hooks. NULL = the swarm is not wired (handlers drop frames). */
    msg_zcode_swarm_frame_fn zcode_swarm_frame;
    msg_zcode_swarm_tick_fn zcode_swarm_tick;
    void *zcode_swarm_ctx;
};

/* ── P2P message dispatch table ──────────────────────────────────
 * Each entry maps a P2P command string to a handler function.
 * The dispatch table replaces the strcmp chain in msg_process_messages.
 * Handlers return true on success, false on protocol error. */

struct byte_stream;  /* forward decl */

typedef bool (*msg_handler_fn)(struct msg_processor *mp,
                               struct p2p_node *node,
                               struct byte_stream *s);

struct msg_dispatch_entry {
    char command[13];           /* P2P command (max 12 bytes + NUL) */
    msg_handler_fn handler;
    bool requires_handshake;   /* must have completed version/verack? */
    bool zcl23_only;           /* requires NODE_ZCL23 service bit? */
    const char *service_name;  /* for logging: "p2p", "sync", "game", etc. */
};

/* Get the dispatch table (NULL-terminated). For testing. */
const struct msg_dispatch_entry *msg_get_dispatch_table(void);

void msg_processor_init(struct msg_processor *mp,
                         struct main_state *ms,
                         struct tx_mempool *mempool,
                         struct coins_view_cache *coins_tip,
                         const struct chain_params *params,
                         const char *datadir,
                         struct net_manager *net_mgr,
                         const struct app_runtime_context *runtime);
void msg_processor_stop_block_intake(struct msg_processor *mp);
void msg_processor_get_block_intake_stats(
    const struct msg_processor *mp,
    struct msg_block_intake_stats *out);
void msg_processor_get_zmsg_stats(const struct msg_processor *mp,
                                  struct msg_zmsg_stats *out);

void msg_processor_set_compact_block_submit(
    struct msg_processor *mp,
    msg_compact_block_submit_fn submit,
    void *ctx);
void msg_processor_set_block_submit(struct msg_processor *mp,
                                    msg_block_submit_fn submit,
                                    void *ctx);
void msg_processor_set_catchup_drain(struct msg_processor *mp,
                                     msg_catchup_drain_fn drain,
                                     void *ctx);
void msg_processor_set_catchup_batch_scope(
    struct msg_processor *mp,
    msg_catchup_batch_scope_fn begin,
    msg_catchup_batch_scope_fn end,
    void *ctx);
void msg_processor_set_peer_save(struct msg_processor *mp,
                                 msg_peer_save_fn save,
                                 void *ctx);
void msg_processor_set_zmsg_save(struct msg_processor *mp,
                                 msg_zmsg_save_fn save,
                                 void *ctx);
void msg_processor_set_file_offer_save(struct msg_processor *mp,
                                       msg_file_offer_save_fn save,
                                       void *ctx);
void msg_processor_set_file_payment_ingest(
    struct msg_processor *mp, msg_file_payment_ingest_fn ingest, void *ctx);
void msg_processor_set_zswap_ad_save(struct msg_processor *mp,
                                     msg_zswap_ad_save_fn save,
                                     void *ctx);
void msg_processor_set_zswap_ad_ingest(struct msg_processor *mp,
                                       msg_zswap_ad_ingest_fn ingest,
                                       void *ctx);
void msg_processor_set_zswap_accept_ingest(
    struct msg_processor *mp,
    msg_zswap_accept_ingest_fn ingest,
    void *ctx);
void msg_processor_set_zswap_partial_ingest(
    struct msg_processor *mp,
    msg_zswap_partial_ingest_fn ingest,
    void *ctx);

/* Originate one gossip wire to every fast-sync peer (the outbound half of
 * the zswapquote relay idiom — used by the yardsale buyer to publish his
 * zswapaccept). No-op when net_mgr or params are absent. */
void msg_processor_flood_message(struct msg_processor *mp,
                                 const char *command,
                                 const uint8_t *wire, size_t wire_len);
void msg_processor_set_file_service_save(struct msg_processor *mp,
                                         msg_file_service_save_fn save,
                                         void *ctx);
void msg_processor_set_snapshot_active(struct msg_processor *mp,
                                       msg_snapshot_active_fn active,
                                       void *ctx);
void msg_processor_set_snapshot_anchor_accessors(
    struct msg_processor *mp,
    msg_snapshot_anchor_get_fn get_anchor,
    void *get_ctx,
    msg_snapshot_anchor_set_fn set_anchor,
    void *set_ctx);
void msg_processor_set_activation_hooks(
    struct msg_processor *mp,
    msg_activation_request_fn request,
    void *request_ctx,
    msg_activation_anchor_clear_fn clear_anchor,
    void *clear_ctx,
    msg_post_activation_repair_fn repair,
    void *repair_ctx);
void msg_processor_set_header_index_hooks(
    struct msg_processor *mp,
    msg_block_file_scan_fn scan,
    void *scan_ctx,
    msg_block_index_heights_repaired_fn heights_repaired,
    void *heights_repaired_ctx);
void msg_processor_set_header_chainstate_hooks(
    struct msg_processor *mp,
    msg_header_tip_commit_fn commit_header_tip,
    void *commit_header_tip_ctx,
    msg_snapshot_anchor_recommit_fn recommit_anchor,
    void *recommit_anchor_ctx);
void msg_processor_set_wallet_tx_accepted(
    struct msg_processor *mp,
    msg_wallet_tx_accepted_fn accepted,
    void *ctx);
void msg_processor_set_block_connected(
    struct msg_processor *mp,
    msg_block_connected_fn connected,
    void *ctx);
void msg_processor_set_peer_header_vote(
    struct msg_processor *mp,
    msg_peer_header_vote_fn vote,
    void *ctx);
void msg_processor_set_flyclient_proof_builder(
    struct msg_processor *mp,
    msg_flyclient_proof_fn build,
    void *ctx);
void msg_processor_set_block_hashes_range(
    struct msg_processor *mp,
    msg_block_hashes_range_fn load,
    void *ctx);
void msg_processor_set_utxo_sha3_compute(
    struct msg_processor *mp,
    msg_utxo_sha3_compute_fn compute,
    void *ctx);

/* ZCODE package swarm (slice 12): wire the engine hooks. The P2P
 * command is "zpkgswm"; the dispatch row lives in msgprocessor.c. */
void msg_processor_set_zcode_swarm(
    struct msg_processor *mp,
    msg_zcode_swarm_frame_fn frame,
    msg_zcode_swarm_tick_fn tick,
    void *ctx);

/* Fairness contract for the connman message cycle: inbound work for one
 * peer must yield back to the send phase regularly so queued block requests
 * and timeout reassignments cannot be starved by a large receive backlog. */
#define ZCL_MSG_PROCESS_MAX_PER_CYCLE 128

bool msg_process_messages(void *ctx, struct p2p_node *node);
bool msg_send_messages(void *ctx, struct p2p_node *node, bool send_trickle);
int msg_get_height(void *ctx);

/* Update the cached snapshot offer (thread-safe). Called from boot.c. */
struct snapshot_offer;
void msg_processor_update_offer(const struct snapshot_offer *offer);
bool msg_processor_get_offer(struct snapshot_offer *offer);
void msg_processor_invalidate_offer(void);
uint64_t msg_processor_offer_cache_version(void);

/* Publish or invalidate cached fast-sync artifacts.
 * Ownership of heap-backed arrays transfers on successful publish.
 * Caller must provide internally consistent manifests:
 * - sync manifest: num_chunks > 0, chunk_size > 0, non-NULL chunk_hashes
 * - block manifest: start_height <= end_height, num_pieces > 0,
 *   non-NULL piece_hashes */
bool msg_processor_publish_manifest(struct sync_manifest *manifest);
void msg_processor_invalidate_manifest(void);
bool msg_processor_get_manifest_header(struct sync_manifest *out);
uint64_t msg_processor_manifest_cache_version(void);

/* Deep-copy the cached manifest's chunk_hashes array so MSG_MANIFEST can
 * be serialized on the wire without holding g_manifest_mutex through the
 * socket write. On success *out_hashes is heap-allocated (caller frees)
 * and *out_count is the number of 32-byte hashes. Returns false if no
 * manifest is published or allocation fails. */
bool msg_processor_copy_manifest_hashes(uint8_t (**out_hashes)[32],
                                        uint32_t *out_count);

bool msg_processor_publish_block_manifest(struct block_piece_manifest *manifest,
                                         int32_t built_at_height);
void msg_processor_invalidate_block_manifest(void);
bool msg_processor_get_block_manifest_header(struct block_piece_manifest *out,
                                            int32_t *built_at_height);
uint64_t msg_processor_block_manifest_cache_version(void);

#include "core/uint256.h"

/* Clear one block from the recent-block relay dedup ring so recovery refetches
 * can re-enter the reducer after an earlier non-finalized delivery. */
void msg_processor_clear_seen_block(const struct uint256 *hash);

/* per-peer FlyClient challenge rate-limit tuning. See
 * msgprocessor.c for the full rationale — short version: each
 * zfcchallenge is expensive (50 MMB proofs), so we cap per-peer
 * consumption at BURST on first use and refill at RATE_PER_SEC. A
 * legitimate IBD peer needs one token per snapshot offer; a flood
 * burns through the burst, then drops silently. */
#define FC_CHALLENGE_RATE_PER_SEC 10u
#define FC_CHALLENGE_BURST        30u

/* test hooks: drive the FlyClient challenge rate limiter with an
 * explicit clock, read dropped-challenge telemetry, and reset the table
 * between cases. Not intended for production call-sites. */
bool msgprocessor_test_fc_rate_acquire(node_id_t peer_id, int64_t now_ms);
uint32_t msgprocessor_test_fc_rate_dropped(node_id_t peer_id);
bool msgprocessor_test_fc_rate_should_score(node_id_t peer_id);
void msgprocessor_test_fc_rate_reset(void);

/* test hooks: drive the g_swarm_active atomic CAS used by the
 * zmanifest handler. try_claim returns true exactly once until
 * release() is called; concurrent callers see at most one success. */
bool msgprocessor_test_swarm_try_claim(void);
void msgprocessor_test_swarm_release(void);
bool msgprocessor_test_swarm_is_active(void);

/* test hook (D1): drive the swarm's aggregate SHA3 UTXO-snapshot verify
 * + reaction (peer offence + typed blocker on mismatch) directly,
 * without needing a full byte-stream MSG_CHUNK_DATA dispatch. Returns
 * true (PASSED, sync trusted-complete) when local_root == expected_root,
 * false (FAILED, sync NOT complete) otherwise. */
bool msgprocessor_test_swarm_utxo_sha3_verify(struct msg_processor *mp,
                                              struct p2p_node *node,
                                              const uint8_t local_root[32],
                                              const uint8_t expected_root[32],
                                              uint64_t local_count);

/* test hook: swap the allocator process_mempool uses for its
 * scratch hash buffer. Pass NULL to restore the default zcl_malloc
 * path; pass a function that returns NULL to simulate OOM. Only
 * influences process_mempool — no global malloc override. */
void msgprocessor_test_set_mempool_alloc_hook(void *(*hook)(size_t));

/* Test helpers for block relay deduplication. */
bool msgprocessor_test_block_already_seen(const struct uint256 *hash);
void msgprocessor_test_block_mark_seen(const struct uint256 *hash);
bool msgprocessor_test_accept_block_for_processing(const struct uint256 *hash,
                                                   bool snapshot_active);
bool msgprocessor_test_should_ignore_snapshot_offer(
    enum snapshot_sync_state snapsync_state,
    uint32_t serving_peer_id,
    enum peer_state peer_state,
    uint32_t peer_id,
    enum sync_state sync_state);
void msgprocessor_test_reset_recent_blocks(void);
int msgprocessor_test_get_recent_block_count(void);

/* ── Header sync diagnostic counters (msg_headers.c) ─────────── */

struct msg_headers_stats {
    uint64_t batches_received;
    uint64_t total_accepted;
    uint64_t total_rejected;
    uint64_t newly_added;
    uint64_t already_known;
    /* push_getheaders_from() continuation-suppression counters — a
     * non-zero, GROWING value names a silent-halt-turned-loud: either a
     * null-hash anchor (re-anchored) or an active snapshot exchange that
     * is pausing header sync. See msg_headers.c. */
    uint64_t getheaders_suppressed_no_hash;
    uint64_t getheaders_suppressed_snapshot;
    /* Sibling silent-drop sites in the same file, closed for the same
     * reason (a stall must always name a blocker, never go quiet):
     * inbound `headers` dropped receive-side, push_getheaders() and
     * push_getheaders_span() dropped send-side, all while a snapshot
     * exchange owns the wire; the locator-alloc OOM in
     * push_getheaders_span(); and the getheaders-serving defer while a
     * peer snapshot transfer is in progress. See msg_headers.c. */
    uint64_t headers_recv_suppressed_snapshot;
    uint64_t push_getheaders_suppressed_snapshot;
    uint64_t push_getheaders_span_suppressed_snapshot;
    uint64_t push_getheaders_span_alloc_fail;
    uint64_t getheaders_deferred_snapshot_serving;
    /* Serve-side accounting — what OTHER peers cost this node.
     *
     * getheaders_served_requests counts `getheaders` requests this node
     * ANSWERED (a request deferred while a snapshot transfer owns the wire
     * is counted by getheaders_deferred_snapshot_serving instead, not
     * here); headers_served_total counts the headers those replies
     * actually carried.
     *
     * The pair is the amplification ratio, and without it the serve path
     * is unmeasurable: requests is what a stranger spends, headers is what
     * it gets back. requests climbing while headers stands still is a peer
     * grinding empty replies — cheap for it, work for us. Every header in
     * headers_served_total costs one full Equihash verification (383-390 us
     * at 200,9), so headers_served_total is also, to within the refusals,
     * the serve path's PoW bill. */
    uint64_t headers_served_total;
    uint64_t getheaders_served_requests;
};

void msg_headers_get_stats(struct msg_headers_stats *out);

/* ── Client-puzzle PoW guard for zchunkreq / zblkreq ─────────────────
 * See msgprocessor_snapshot.c for the full design note (stateless:
 * challenge = SHA3-256(secret||peer_ip||time_bucket), no per-peer server
 * state, no seed distribution round trip). Difficulty is 0 (mechanism
 * present, gate open) until armed. */
#define SNAP_POW_BUCKET_SECS 60   /* challenge validity window (+1 grace)  */
#define SNAP_POW_MIN_BITS    12   /* idle floor: ~4k hashes, sub-ms        */
#define SNAP_POW_MAX_BITS    22   /* saturated: ~4M hashes per request     */
#define SNAP_POW_WINDOW_SECS 10   /* request-rate measurement window       */
#define SNAP_POW_SOFT_RATE   8    /* accepted reqs/window before ramp      */
#define SNAP_POW_RATE_STEP   4    /* +1 bit per this many reqs over soft   */

void msg_snapshot_pow_set_armed(bool armed);
bool msg_snapshot_pow_is_armed(void);

/* Test hooks: drive/inspect the stateless snapshot PoW guard with an
 * explicit clock. Not intended for production call sites. */
bool msgprocessor_test_snap_pow_solve(const uint8_t peer_ip[16],
                                      int64_t at_time, int difficulty_bits,
                                      uint64_t *nonce_out);
bool msgprocessor_test_snap_pow_admit_at(const uint8_t peer_ip[16],
                                         int64_t at_time,
                                         const uint64_t *nonce);
int msgprocessor_test_snap_pow_bits_at(int64_t at_time);
void msgprocessor_test_snap_pow_reset(void);

#endif

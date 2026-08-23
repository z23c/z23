/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Internal header shared between the msgprocessor split files.
 * NOT part of the public API — only included by msg_*.c files. */

#ifndef ZCL_NET_MSG_INTERNAL_H
#define ZCL_NET_MSG_INTERNAL_H

#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/p2p_message.h"
#include "core/serialize.h"
#include "sync/sync_state.h"

/* ── Forward declarations for split message handlers ──────────── */

struct sync_getheaders_action;

struct msg_block_acceptance {
    bool reached_peer_tip;
    bool should_emit_tip_updated;
    bool should_set_sync_state;
    enum sync_state next_sync_state;
    bool should_set_flush_policy;
    bool should_update_peer_state;
    enum peer_state next_peer_state;
};

/* msg_version.c — version/verack handshake */
void push_version(struct msg_processor *mp, struct p2p_node *node);
void push_verack(struct msg_processor *mp, struct p2p_node *node);
void msg_version_build(struct version_message *ver,
                       const struct msg_processor *mp,
                       const struct p2p_node *node,
                       int start_height);
bool msg_version_learn_advertised_addr(struct net_manager *nm,
                                       const struct p2p_node *node,
                                       const struct version_message *ver);
bool msg_version_should_save_peer(const struct p2p_node *node);
bool process_version(struct msg_processor *mp, struct p2p_node *node,
                     struct byte_stream *s);
bool process_verack(struct msg_processor *mp, struct p2p_node *node);

/* msg_headers.c — header sync messages */
struct block_header;

/* Append one wire `headers` element (serialized header + a 0 tx-count) to
 * `body`, unless doing so would push the framed reply — the count prefix plus
 * `body` — past MAX_PROTOCOL_MESSAGE_LENGTH. On refusal `body` is rolled back
 * to its prior size and false is returned; the serve loop then stops and sends
 * exactly what fit. Bounding by bytes (not just header count) is required
 * because ~2000 Equihash headers (~1.5 KB each) overflow the 2 MiB wire cap and
 * the receiver drops the whole oversized reply. */
bool getheaders_try_append_header(struct byte_stream *body,
                                  const struct block_header *hdr);

/* getheaders serve-path building blocks (msg_headers.c). Non-static so the
 * offline serve-path regression test (test_getheaders_serve_fallback) can
 * drive them without a live network; production callers are
 * process_getheaders' serve loop only.
 *
 * getheaders_index_header_servable builds the servable header for `iter`:
 * in-memory index first, then the flat block file, then the runtime's durable
 * complete-header authorities (node.db, reducer repair table, projection).
 * A true return always hash-binds: the header written to `hdr_out`
 * serializes to `iter->phashBlock`, so it is byte-for-byte the header this
 * node accepted under that hash. A false return names the refusal in the
 * log; it is an availability/serve verdict, never a validity verdict (no
 * status bits are mutated).
 *
 * It resolves WHICH bytes are authoritative before verifying them, so it
 * spends at most ONE full Equihash verification per call no matter how many
 * stores it had to consult. See the resolve/verify note in msg_headers.c.
 *
 * getheaders_next_servable_successor walks FORWARD from `parent` past any
 * unservable entries (guard-bounded) and returns the first servable
 * successor, or NULL when the chain is exhausted or the guard trips. It
 * hands the proved header back through `hdr_out` (nullable) so the serve
 * loop does not have to re-verify what the walk already verified. */
bool getheaders_index_header_servable(struct msg_processor *mp,
                                      struct block_index *iter,
                                      struct block_header *hdr_out);
struct block_index *getheaders_next_servable_successor(
    struct msg_processor *mp,
    struct block_index *parent,
    struct block_header *hdr_out);

/* Bytes of Equihash solution the serve path is currently keeping pinned on
 * in-memory block_index entries. The serve path re-reads a missing solution
 * from the flat block file or the node.db row and memoises it so the next
 * serve is free; because `getheaders` needs only a completed handshake and
 * index entries live for the process lifetime, that memoisation is capped.
 * Past the cap headers are still loaded and served in full — only the
 * caching stops. Exposed for the offline regression test and for operator
 * diagnostics; nothing branches on it. */
size_t getheaders_solution_cache_bytes(void);

/* Full Equihash verifications the getheaders SERVE path has performed since
 * process start. This is the DoS unit for header serving: an unauthenticated
 * post-handshake peer chooses how many of these this node runs, and each one
 * costs 383-390 us of a core at 200,9. The contract it pins is at most ONE
 * per header put on the wire — see test_getheaders_serve_pow_dedup. Exposed
 * for that test and for operator diagnostics; nothing branches on it. */
uint64_t getheaders_serve_pow_checks(void);

/* Header serves refused because NO store on this node holds the header bytes:
 * the in-memory index entry came from block_index.bin (whose on-disk row keeps
 * no hashMerkleRoot, no nNonce and no nSolution), the block body is absent or
 * unreadable, and node.db has no `blocks` row for it. That is DATA
 * AVAILABILITY, never a validity verdict — the entry keeps its status bits and
 * is never marked failed.
 *
 * It is also the fleet's genesis-sync blocker in one number: on a
 * snapshot/bundle-seeded datadir EVERY height below the seed floor is
 * permanently in this state (measured on a seeded node, node.db `blocks`
 * starts at h=3222916 against a 3226485-entry header index), so a peer syncing
 * from genesis gets a 0-header reply and stalls. A non-zero and climbing count
 * means this node cannot serve early history and something upstream — shipping
 * header bytes below the floor, or steering such peers elsewhere — has to give.
 * Exposed for the offline serve regression tests and operator diagnostics;
 * nothing branches on it. */
uint64_t getheaders_serve_refusals_no_header_bytes(void);

/* Serve-path verification receipts — the bound on how often a peer can make
 * this node REDO an Equihash verification it has already done.
 *
 * The dedup behind getheaders_serve_pow_checks holds within one lookup. This
 * holds ACROSS lookups: a header this process already proved, under this
 * build and these consensus parameters, is not proved again. A receipt is
 * minted only where full verification succeeded, is keyed on the header's own
 * hash (re-derived from the verified bytes, so it can never be honoured for
 * different bytes), carries the generation tag it was minted under, and lives
 * in a fixed static table — so every miss, eviction, collision, build change
 * and parameter change falls through to full verification. Failures are never
 * cached: a time-too-new refusal un-fails as the clock advances, and caching
 * it would poison the serve path against a valid chain. See the long note in
 * msg_headers.c and lib/test/src/test_getheaders_serve_receipt.c.
 *
 * Exposed for that test and for operator diagnostics; nothing branches on it.
 *   slots/bytes — the structural cap, constants;
 *   occupied    — slots currently holding a receipt (<= slots, always);
 *   hits        — verifications skipped because proof was already done;
 *   mints       — receipts created, i.e. verifications that SUCCEEDED;
 *   evictions   — mints that displaced a different header from its slot. */
struct getheaders_receipt_stats {
    size_t   slots;
    size_t   bytes;
    size_t   occupied;
    uint64_t hits;
    uint64_t mints;
    uint64_t evictions;
};
void getheaders_verify_receipt_stats(struct getheaders_receipt_stats *out);

bool process_getheaders(struct msg_processor *mp, struct p2p_node *node,
                        struct byte_stream *s);
bool process_headers(struct msg_processor *mp, struct p2p_node *node,
                     struct byte_stream *s);
void push_getheaders(struct msg_processor *mp, struct p2p_node *node);
void push_getheaders_from(struct msg_processor *mp,
                          struct p2p_node *node,
                          struct block_index *from);
void exec_getheaders_action(struct msg_processor *mp,
                            struct p2p_node *node,
                            const struct sync_getheaders_action *action);

/* NET-3 range-parallel header acquisition (msg_headers.c).
 *
 * push_getheaders_span: issue a getheaders whose locator forks at
 * `start_hash` and whose hash_stop is `stop_hash` (NULL = unbounded
 * forward). Used to bound a peer to its assigned span.
 *
 * msg_try_range_parallel_getheaders: when >=2 fast-sync-capable peers are
 * connected and the missing-header gap exceeds one wire batch, partition
 * the range into disjoint checkpoint-anchored spans and drive THIS peer's
 * span. Returns true iff it issued the request (caller then skips the
 * normal single-peer getheaders). Returns false — leaving the existing
 * path untouched — when the conditions don't hold, so single-peer sync
 * behaves exactly as before. Never fires while a header-band hole is open
 * (the band backfill owns the anchor then). */
void push_getheaders_span(struct msg_processor *mp, struct p2p_node *node,
                          const struct uint256 *start_hash,
                          const struct uint256 *stop_hash);
bool msg_try_range_parallel_getheaders(struct msg_processor *mp,
                                       struct p2p_node *node,
                                       int our_height, int64_t now_seconds);

/* msg_blocks.c — block handling */
bool process_block_msg(struct msg_processor *mp, struct p2p_node *node,
                       struct byte_stream *s);
bool process_getdata(struct msg_processor *mp, struct p2p_node *node,
                     struct byte_stream *s);
bool process_getblocks(struct msg_processor *mp, struct p2p_node *node,
                       struct byte_stream *s);

/* msg_tx.c — transaction relay */
bool process_tx_msg(struct msg_processor *mp, struct p2p_node *node,
                    struct byte_stream *s);
bool process_inv(struct msg_processor *mp, struct p2p_node *node,
                 struct byte_stream *s);
bool process_mempool(struct msg_processor *mp, struct p2p_node *node);

/* Mempool sync-on-connect: after a successful handshake, pull the peer's
 * mempool inventory ONCE by sending an outbound "mempool" message (no
 * payload) — the peer answers via its own process_mempool() above. Gated
 * on node->relay_txes (no point asking a peer that told us it won't relay)
 * and on not being deep in IBD (bulk historical sync has no use for
 * mempool inventory). node->mempool_requested makes this idempotent per
 * peer regardless of how many times the caller invokes it (e.g. a
 * misbehaving peer resending verack). Returns true iff the request was
 * actually queued this call. */
bool msg_tx_maybe_request_mempool(struct msg_processor *mp,
                                  struct p2p_node *node);

/* classification outcome for an incoming `tx` message. The
 * handler needs to differentiate malicious rejections (apply peer
 * ban-score) from non-malicious rejections (orphan, duplicate,
 * rate-limit) and success. Exposed to tests so regression cases can
 * exercise the classifier without re-entering Dandelion + wallet
 * side effects that `process_tx_msg` does after acceptance. */
enum tx_accept_result {
    TX_ACCEPT_OK = 0,
    TX_ACCEPT_INVALID,          /* failed check_transaction / coinbase */
    TX_ACCEPT_DUPLICATE,        /* already in mempool */
    TX_ACCEPT_CONFLICT,         /* double-spend vs current mempool */
    TX_ACCEPT_BELOW_FEE,        /* fee < min_relay_fee */
    TX_ACCEPT_MISSING_INPUTS,   /* unknown inputs (orphan) */
    TX_ACCEPT_NONFINAL,         /* nLockTime policy rejection */
    TX_ACCEPT_EXPIRING_SOON,    /* expiry-height policy rejection */
    TX_ACCEPT_INTERNAL_ERROR,   /* mempool full / OOM */
};

/* Classify + add-or-reject a transaction, applying peer scoring for
 * malicious outcomes. Does NOT dedupe against the tx_already_seen
 * cache (the handler does that first). Does NOT relay (Dandelion /
 * wallet sync stays in `process_tx_msg`). */
enum tx_accept_result msg_tx_accept(struct msg_processor *mp,
                                    struct p2p_node *node,
                                    struct transaction *tx);

/* msg_compact.c — compact blocks (BIP152) */
bool process_sendcmpct(struct msg_processor *mp, struct p2p_node *node,
                       struct byte_stream *s);
bool process_cmpctblock(struct msg_processor *mp, struct p2p_node *node,
                        struct byte_stream *s);
bool process_getblocktxn(struct msg_processor *mp, struct p2p_node *node,
                         struct byte_stream *s);
bool process_blocktxn(struct msg_processor *mp, struct p2p_node *node,
                      struct byte_stream *s);

/* ── Shared helpers (remain in msgprocessor.c) ────────────────── */

/* Access the download manager singleton. */
struct download_manager *msg_get_download_mgr(void);
#define get_download_mgr() msg_get_download_mgr()

/* Access the cached snapshot offer/manifest. */
void send_snapshot_offer_msg(struct p2p_node *node,
                             const struct snapshot_offer *offer,
                             const unsigned char *msg_start);
void push_manifest(struct msg_processor *mp, struct p2p_node *node);
void push_block_manifest(struct msg_processor *mp, struct p2p_node *node);

/* Block/tx dedup ring buffers. */
bool block_already_seen(const struct uint256 *hash);
void block_mark_seen(const struct uint256 *hash);
void block_clear_seen(const struct uint256 *hash);
bool tx_already_seen(const struct uint256 *hash);
void tx_mark_seen(const struct uint256 *hash);

/* decide whether a freshly processed block may safely be added to the dedup
 * ring. Historically, every received block was marked seen BEFORE the
 * synchronous block-intake path; if intake SKIP'd (e.g.
 * ACTIVATION_SKIP_ALREADY_RUNNING from controller mutex contention), the block
 * was indexed-but-not-connected AND permanently dedup'd, leaving it stuck in
 * block_index forever.
 *
 * Returns true only when the block is in the active chain —
 * i.e. has actually been activated, not just received and
 * indexed. Any other state (NULL pindex, orphan, skipped) returns
 * false so the dedup ring does NOT short-circuit subsequent
 * arrivals. */
struct active_chain;
struct block_index;
struct validation_state;
bool msg_block_validation_is_retryable(const struct validation_state *state);
bool msg_processor_enqueue_p2p_block(struct msg_processor *mp,
                                     const struct block *blk,
                                     const struct uint256 *hash,
                                     uint32_t peer_id,
                                     struct validation_state *out);
bool msg_blocks_should_mark_seen(const struct active_chain *chain,
                                  const struct block_index *bi);
bool msg_processor_snapshot_active(const struct msg_processor *mp);
struct block_index *msg_processor_snapshot_anchor(const struct msg_processor *mp);
void msg_processor_set_snapshot_anchor(const struct msg_processor *mp,
                                       struct block_index *anchor);
void msg_processor_request_activation(const struct msg_processor *mp,
                                      enum msg_activation_request_source source);
void msg_processor_clear_activation_anchor(const struct msg_processor *mp,
                                           const char *reason);
void msg_processor_repair_post_activation_anchor(const struct msg_processor *mp);
int msg_processor_scan_block_files(const struct msg_processor *mp);
bool msg_processor_block_index_heights_repaired(const struct msg_processor *mp);
bool msg_processor_commit_header_tip(const struct msg_processor *mp,
                                     struct block_index *header_tip);
bool msg_processor_recommit_snapshot_anchor(const struct msg_processor *mp,
                                            struct block_index *anchor,
                                            int from_height);
void msg_processor_note_block_connected(const struct msg_processor *mp,
                                        int height);
void msg_processor_record_peer_header_vote(const struct msg_processor *mp,
                                           uint32_t peer_id,
                                           int height,
                                           const char hash_hex[65]);
void msg_processor_request_invalid_block_headers(struct msg_processor *mp,
                                                 struct p2p_node *node);
void msg_processor_plan_valid_block_acceptance(
    struct msg_block_acceptance *out,
    const struct msg_processor *mp,
    const struct p2p_node *node,
    const struct block_index *new_tip);

/* Shared accessors. */
struct node_db *msg_node_db(const struct msg_processor *mp);
struct snapshot_sync_service *msg_snapshot_sync(const struct msg_processor *mp);
struct snapshot_sync_service *msg_snapshot_sync_ensure(const struct msg_processor *mp);

/* Dandelion state (in msg_tx.c). */
struct dandelion_state;
extern struct dandelion_state g_dandelion;
extern bool g_dandelion_init;

#endif /* ZCL_NET_MSG_INTERNAL_H */

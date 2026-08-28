/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Internal header shared by the msgprocessor_snapshot*.c translation units.
 * NOT part of the public API. Mirrors the connman.c/connman_dialer.c
 * split shape (see connman_internal.h): a small header for the pieces
 * one file needs to call into the other, promoted from `static` only
 * as needed.
 *
 * The split is by responsibility:
 *   msgprocessor_snapshot.c       — lifecycle (mp_snapshot_maybe_offer,
 *                                   mp_snapshot_send_tick's client-side
 *                                   swarm/block-swarm coordinators),
 *                                   the mp_handle_zcl23_sync dispatcher,
 *                                   the requester-side push_chunk_request
 *                                   / push_block_piece_request /
 *                                   parse_block_piece_payload_refs /
 *                                   block_payload_submit_all.
 *   msgprocessor_snapshot_fcrate.c — the fc_rate_* FlyClient-challenge
 *                                   rate limiter (table, mutex, admit +
 *                                   flood-score check) plus its
 *                                   deterministic test surface, split out
 *                                   of msgprocessor_snapshot.c — shares no
 *                                   state with the rest of the dispatcher
 *                                   except the two calls into it from the
 *                                   MSG_FC_CHALLENGE branch.
 *   msgprocessor_snapshot_serve.c — the SERVE side: cached offer/manifest
 *                                   /block-manifest publish+accessor
 *                                   APIs, send_snapshot_offer_msg,
 *                                   push_manifest, push_block_manifest,
 *                                   build_block_piece_payloads, and the
 *                                   per-message-command
 *                                   serve handlers the dispatcher calls
 *                                   into (mp_serve_snapshot_req,
 *                                   mp_serve_chunk_req, mp_serve_block_req)
 *                                   plus the PEER_SNAPSHOT_SERVING chunk
 *                                   send loop (mp_snapshot_send_tick_serve).
 *   msgprocessor_snapshot_pow.c   — the zchunkreq/zblkreq client-puzzle
 *                                   PoW guard: the arming flag, the
 *                                   adaptive-difficulty load window, and
 *                                   the deterministic-clock test surface
 *                                   over both.
 *   msgprocessor_block_swarm_abandon.c — the shared fail-closed transition
 *                                   from block swarm to legacy body fetch.
 *
 * Everything declared here used to be `static` in msgprocessor_snapshot.c;
 * it is promoted to external linkage (single definition, still in
 * whichever file owns it) purely so the other file can call it — no
 * behavior changed by the split. */

#ifndef ZCL_NET_MSGPROCESSOR_SNAPSHOT_INTERNAL_H
#define ZCL_NET_MSGPROCESSOR_SNAPSHOT_INTERNAL_H

#include "net/msgprocessor.h"
#include "net/msg_internal.h"
#include "core/serialize.h"
#include <stdbool.h>
#include <stdatomic.h>

struct msg_processor;
struct p2p_node;
struct byte_stream;
struct block_swarm;

struct block_swarm_abandonment {
    uint32_t complete;
    uint32_t total;
    uint32_t failed;
    int64_t last_complete_unix;
};

/* Shared fail-closed transition for integrity and silent-stall abandonment.
 * Caller owns the block-swarm mutex; finish/report run after it is released
 * so peer pipeline locks never nest inside the swarm lock. */
bool mp_block_swarm_abandon_locked(
    struct block_swarm *swarm, _Atomic bool *active,
    _Atomic int64_t *reaped_unix, int64_t now,
    struct block_swarm_abandonment *out);
void mp_block_swarm_finish_abandon(struct msg_processor *mp);
void mp_block_swarm_report_integrity_abandon(
    struct msg_processor *mp, const struct p2p_node *node,
    uint32_t piece_index, const struct block_swarm_abandonment *abandoned);
void mp_block_swarm_mark_complete_through_height(
    struct block_swarm *swarm, int32_t have_height);

/* Max on-wire bytes for one serialized block inside a zblkdata response —
 * shared because both the server (build_block_piece_payloads, this file's
 * MSG_BLOCK_REQ response) and the client (parse_block_piece_payload_refs,
 * msgprocessor_snapshot.c's MSG_BLOCK_DATA intake) must agree on the same
 * cap. */
#define BLOCK_PIECE_MAX_BLOCK_BYTES 2000000u

/* ── msgprocessor_snapshot_fcrate.c: called from the MSG_FC_CHALLENGE
 * branch of mp_handle_zcl23_sync in msgprocessor_snapshot.c ──────────── */

/* Acquire this peer's FlyClient-challenge token at now_ms. Returns true
 * when the challenge may be answered; false means drop it silently. */
bool fc_rate_acquire(node_id_t peer_id, int64_t now_ms);

/* Returns true the first time this is called after peer_id's bucket empties
 * (letting the caller register one PEER_OFFENCE_FLOOD per episode); false
 * on subsequent calls within the same flood. dropped_out, if non-NULL, gets
 * the peer's current lifetime drop count. */
bool fc_rate_should_score(node_id_t peer_id, uint32_t *dropped_out);

/* ── msgprocessor_snapshot_serve.c: called from the mp_handle_zcl23_sync
 * dispatcher and mp_snapshot_send_tick in msgprocessor_snapshot.c ──── */

/* Serve a zsnapreq (peer asking for our full snapshot). */
void mp_serve_snapshot_req(struct msg_processor *mp, struct p2p_node *node,
                           struct byte_stream *s);

/* Serve a zchunkreq (peer asking for one UTXO chunk by index). */
void mp_serve_chunk_req(struct msg_processor *mp, struct p2p_node *node,
                        struct byte_stream *s);

/* Serve a zblkreq (peer asking for one block piece by index). */
void mp_serve_block_req(struct msg_processor *mp, struct p2p_node *node,
                        struct byte_stream *s);

/* Admit a zchunkreq/zblkreq at the current wall clock. `nonce` is the
 * peer-supplied puzzle solution, NULL when the request carried none.
 * Returns true when the request may be served — always true while the
 * guard is disarmed. The only call that crosses from the serve handlers
 * into msgprocessor_snapshot_pow.c; every other entry point of that file
 * is either its own static detail or the public test surface declared in
 * net/msgprocessor.h. */
bool msg_snapshot_pow_admit(uint8_t request_kind, uint32_t request_index,
                            const uint64_t *nonce);

/* The PEER_SNAPSHOT_SERVING half of mp_snapshot_send_tick: streams
 * snapshot chunks to a peer we're actively serving. Returns true if the
 * caller must return immediately (matches the original inline `return;`
 * on a stale-offer reset — the swarm/block-swarm coordinator sections
 * below it in mp_snapshot_send_tick must NOT run in that case), false to
 * fall through to them normally. */
bool mp_snapshot_send_tick_serve(struct msg_processor *mp,
                                 struct p2p_node *node);

#endif /* ZCL_NET_MSGPROCESSOR_SNAPSHOT_INTERNAL_H */

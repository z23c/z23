/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Internal header shared between the msgprocessor_*.c split files.
 * NOT part of the public API — only included by msgprocessor_*.c files.
 *
 * The split is by message family:
 *   msgprocessor.c             — dispatch table + msg_process_messages
 *                                + msg_send_messages + lifecycle init
 *   msgprocessor_handshake.c   — version, verack, sendheaders
 *   msgprocessor_inv.c         — inv, getdata, notfound, addr, getaddr
 *   msgprocessor_pingpong.c    — ping, pong, feefilter, reject
 *   msgprocessor_snapshot.c    — sync_manifest, chunk_*, block_piece_*,
 *                                swarm state, fast-sync globals
 *   msgprocessor_snapshot_fcrate.c — the fc_rate_* FlyClient-challenge
 *                                rate limiter, split out of
 *                                msgprocessor_snapshot.c
 */

#ifndef ZCL_NET_MSGPROCESSOR_INTERNAL_H
#define ZCL_NET_MSGPROCESSOR_INTERNAL_H

#include "net/msgprocessor.h"
#include "net/msg_internal.h"
#include "net/net.h"
#include "net/p2p_message.h"
#include "net/fast_sync.h"
#include "core/serialize.h"

/* ── Dispatch-table handler wrappers ──────────────────────────────
 * Defined per split file; referenced by g_msg_dispatch in msgprocessor.c.
 * All share the same signature so the dispatcher is uniform. */

/* msgprocessor_handshake.c */
bool mp_handle_version(struct msg_processor *mp, struct p2p_node *node,
                       struct byte_stream *s);
bool mp_handle_verack(struct msg_processor *mp, struct p2p_node *node,
                      struct byte_stream *s);
bool mp_handle_sendheaders(struct msg_processor *mp, struct p2p_node *node,
                           struct byte_stream *s);

/* msgprocessor_pingpong.c */
bool mp_handle_ping(struct msg_processor *mp, struct p2p_node *node,
                    struct byte_stream *s);
bool mp_handle_pong(struct msg_processor *mp, struct p2p_node *node,
                    struct byte_stream *s);
bool mp_handle_feefilter(struct msg_processor *mp, struct p2p_node *node,
                         struct byte_stream *s);
bool mp_handle_reject(struct msg_processor *mp, struct p2p_node *node,
                      struct byte_stream *s);

/* msgprocessor_inv.c */
bool mp_handle_inv(struct msg_processor *mp, struct p2p_node *node,
                   struct byte_stream *s);
bool mp_handle_getdata(struct msg_processor *mp, struct p2p_node *node,
                       struct byte_stream *s);
bool mp_handle_notfound(struct msg_processor *mp, struct p2p_node *node,
                        struct byte_stream *s);
bool mp_handle_addr(struct msg_processor *mp, struct p2p_node *node,
                    struct byte_stream *s);
bool mp_handle_getaddr(struct msg_processor *mp, struct p2p_node *node,
                       struct byte_stream *s);

/* The chain-sync family (getheaders, headers, getblocks, block,
 * sendcmpct, cmpctblock, getblocktxn, blocktxn) is dispatched directly
 * to the process_* handlers declared in net/msg_internal.h — no
 * mp_handle_* wrappers. */

/* msgprocessor_snapshot.c — combined ZCL23 snapshot/chunk/block-piece
 * dispatcher. Called by msg_process_messages for any z-prefixed command
 * not handled by an explicit table entry. */
bool mp_handle_zcl23_sync(struct msg_processor *mp,
                          struct p2p_node *node,
                          struct byte_stream *s,
                          const char *cmd);

/* msgprocessor_zcode_swarm.c — the ZCODE package swarm frame hook seam
 * (slice 12; "zpkgswm"). */
bool mp_handle_zcode_swarm(struct msg_processor *mp,
                           struct p2p_node *node,
                           struct byte_stream *s);

/* msgprocessor_snapshot.c lifecycle hook invoked from msg_send_messages.
 * Encapsulates the heavy snapshot/swarm/fast-sync state machine. */

/* Per-peer trickle tick: snapshot serving stream, swarm coordinator,
 * block-swarm coordinator. Operates only on the supplied node and only
 * fires the work appropriate to its state. */
void mp_snapshot_send_tick(struct msg_processor *mp,
                            struct p2p_node *node);

/* Push a snapshot offer (if we have one) to a peer behind us, gated on
 * the same staleness checks used elsewhere. Called from
 * msg_send_messages once we hit PEER_ACTIVE on a ZCL23 peer. */
void mp_snapshot_maybe_offer(struct msg_processor *mp,
                              struct p2p_node *node);

/* Drive the periodic snapshot-stall reset. Returns true when a stall
 * was detected and the receiver was reset to accept a new offer. */
bool mp_snapshot_check_stall(void);

/* Is the snapshot receive path currently active? Equivalent to
 * snapsync_is_active() and exposed here purely for symmetry. */
bool mp_snapshot_is_active(void);

/* Is the parallel UTXO swarm currently coordinating chunk downloads?
 * Production path equivalent of msgprocessor_test_swarm_is_active —
 * used by the header-stall logic in msg_send_messages to suppress
 * disconnect actions while a swarm is in progress. */
bool mp_swarm_is_active(void);
bool mp_block_swarm_is_active(void);
/* Stall watchdog for the block swarm: reaps an active swarm with no piece
 * completion for BLOCK_SWARM_STALL_SECS so the legacy getdata path (paused
 * while a swarm is active) resumes body fetch. Called from
 * msg_send_messages before the swarm-active gate. */
bool mp_block_swarm_reap_if_stalled(struct msg_processor *mp);
/* One crash-ordered durability scope held across the complete block swarm;
 * per-piece scopes nest inside it. */

#endif /* ZCL_NET_MSGPROCESSOR_INTERNAL_H */

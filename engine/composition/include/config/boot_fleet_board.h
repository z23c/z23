/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fleet board / wiki gossip — inventory, fetch, and post delivery,
 * multiplexed on the existing `zpkgswm` frame.
 *
 * The board adds NO P2P command of its own. It rides the swarm frame the
 * package swarm already carries, exactly as the mesh status and mesh terminal
 * frames do, and it is dispatched BEFORE the swarm engine is created so a node
 * that does not host packages still carries the board. Every full node is an
 * equal citizen here: there is no server, no referee, and no node whose copy
 * of the board is more true than another's.
 *
 * What travels:
 *   INV   ids this node holds, newest first, announced to each peer once per
 *         announce period and after a local post;
 *   GET   ids the receiving node does not hold, asked back to the announcer;
 *   POST  one whole signed post.
 *
 * What the receiver does: verify the signature, re-derive the id from the
 * bytes, check the clock, and store. A post that fails any of those is
 * refused and the peer is scored for an invalid payload, the same way any
 * other malformed message is scored. Nothing on this wire is authority: a
 * verified post says only that a host key made a statement. */

#ifndef ZCL_CONFIG_BOOT_FLEET_BOARD_H
#define ZCL_CONFIG_BOOT_FLEET_BOARD_H

#include "net/msgprocessor.h"
#include "session/fleet_board_proto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;
struct node_db;

/* Per-peer flood ceiling. A peer may deliver at most this many board frames
 * per window; frames over the ceiling are dropped without a score, because a
 * chatty peer is not a lying peer. */
enum {
    FLEET_BOARD_PEER_FRAMES_PER_WINDOW = 64,
    FLEET_BOARD_PEER_WINDOW_SECONDS = 10,
    FLEET_BOARD_ANNOUNCE_PERIOD_SECONDS = 30,
    /* Must cover both the receive window and the announce interval before a
     * disconnected peer's fixed slot is safe to reuse. */
    FLEET_BOARD_SLOT_PROTECT_SECONDS =
        FLEET_BOARD_PEER_WINDOW_SECONDS >= FLEET_BOARD_ANNOUNCE_PERIOD_SECONDS
            ? FLEET_BOARD_PEER_WINDOW_SECONDS
            : FLEET_BOARD_ANNOUNCE_PERIOD_SECONDS,
    FLEET_BOARD_PEER_SLOTS = 64,
    /* Slots protect individual established peers. This second ceiling keeps
     * aggregate receive work bounded even while many identities churn. */
    FLEET_BOARD_RECEIVE_FRAMES_PER_WINDOW =
        FLEET_BOARD_PEER_SLOTS * FLEET_BOARD_PEER_FRAMES_PER_WINDOW,
};

/* Frame multiplexer leg. Returns true when these bytes were a board frame —
 * handled, dropped, or refused — and false when they belong to somebody
 * else's leg of the swarm frame. */
bool boot_fleet_board_frame(struct msg_processor *mp, struct p2p_node *node,
                            const uint8_t *payload, size_t payload_len,
                            void *ctx);

/* Per-peer message-cycle hook: announce this node's inventory to `node` at
 * most once per announce period. Cheap and allocation-free on the common
 * path (the period has not elapsed). */
void boot_fleet_board_tick(struct msg_processor *mp, struct p2p_node *node,
                           void *ctx);

/* Record the composition context. Safe before the store opens. */
void boot_fleet_board_wire(struct boot_svc_ctx *svc);

/* Drop per-peer state. Idempotent. */
void boot_fleet_board_shutdown(void);

/* Load (creating on first use) this node's board signing identity — the same
 * durable Ed25519 online key the DHT uses, so a node has ONE host identity
 * and a reader can tie a post to the node that made it. Returns false, with
 * `why` filled, when no identity material can be established; the caller
 * then fails closed rather than inventing an anonymous key. */
bool boot_fleet_board_identity(uint8_t seed_out[32], uint8_t pubkey_out[32],
                               char *why, size_t why_capacity);

/* Copy the cached public host identity without touching the identity file or
 * exposing the seed. Read-only status uses this so observation never creates
 * a host key. */
bool boot_fleet_board_public_identity(uint8_t pubkey_out[32]);

#ifdef ZCL_TESTING
/* Deterministic rate-limit seams for adversarial churn tests. */
bool boot_fleet_board_admit_for_testing(int64_t peer_id, int64_t now);
bool boot_fleet_board_announce_due_for_testing(int64_t peer_id, int64_t now);
int64_t boot_fleet_board_inventory_cursor_for_testing(int64_t peer_id);
bool boot_fleet_board_inventory_cursor_commit_for_testing(
    int64_t peer_id, int64_t before_seq, int64_t last_seq, bool end_page);
#endif

/* Compose, sign, store, and announce one local post. `now` is Unix seconds.
 * This is the ONLY write path: a post is signed by this host, appended to
 * this node's ledger, and gossiped, in that order, so a post that could not
 * be stored is never announced. */
enum fleet_board_result boot_fleet_board_publish(
    struct fleet_board_post *post, int64_t now);

/* Announce a specific id to every connected peer. Used right after a local
 * post so the fleet sees it without waiting for the announce period. */
void boot_fleet_board_announce(const uint8_t id[32]);

struct rpc_table;
/* Register the `fleet_board` RPC method — the node-side half of every board
 * and wiki command leaf. */
void boot_fleet_board_register_rpc(struct rpc_table *table);

#endif /* ZCL_CONFIG_BOOT_FLEET_BOARD_H */

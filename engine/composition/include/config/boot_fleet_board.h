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

/* Grant the worker role to every key this node is ALREADY storing posts
 * from, through the role seam (util/fleet_role_check.h). Called once at
 * wire, and safe to call again: a key that already holds the role is not
 * granted twice. Returns how many of those keys hold the role afterwards;
 * zero on a node with no checker installed, which keeps refusing. */
size_t boot_fleet_board_grandfather(struct node_db *ndb);

/* Drop per-peer state. Idempotent. */
void boot_fleet_board_shutdown(void);

/* Posts that arrived, verified, and were still refused because the host key
 * that signed them holds no role granting `fleet.board.post` for that kind
 * on this node — or because no role checker is installed at all. Counted
 * since this process started and reported by `fleet board status`. The
 * answer to a climbing number is `z23 fleet roles grant`, with the
 * fingerprint prefix the refusal line printed. */
uint64_t boot_fleet_board_role_refused_count(void);

/* Host scans that stopped at FLEET_BOARD_HOST_LIST_MAX with another
 * distinct posting key still to come. Above zero means a key that has
 * posted here was never looked at and its posts are refused for that
 * reason. Reported as `grandfather_truncated`. */
uint64_t boot_fleet_board_grandfather_truncated_count(void);

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

/* ── FLEET-scope carriage: the "board" mesh stream service ────────────────
 * (engine/composition/src/boot_fleet_board_fleet.c)
 *
 * A FLEET-scope post never rides the public INV/GET flood above. It moves
 * between PAIRED boxes only, over the existing mesh stream primitive, the
 * same way the fleet ledger's rows do: pull only. A box asks each paired
 * peer for the fleet posts that peer has received since the last one it
 * saw, and answers the same question when asked. Nothing is pushed and
 * nothing is volunteered. A stream opens over whichever session the two
 * boxes already share, including one the ANSWERING box dialled, so a box
 * behind NAT that dials out can still be pulled from.
 *
 * Who is answered: a peer whose pairing row grants the status capability,
 * whose delegation is still current, and whose online key holds a role
 * granting FLEET_BOARD_FLEET_READ_LEAF here. Anybody else is refused
 * before the store is read. What is answered: fleet-scoped, verified,
 * unexpired posts only, bounded by FLEET_BOARD_FLEET_ANSWER_POSTS_MAX and
 * FLEET_BOARD_FLEET_ANSWER_MAX per pull. What is kept: every pulled post
 * goes through db_fleet_board_post_ingest, so TTL, signature, the author
 * key's role and the store caps all still decide, and a post this box
 * already holds is a no-op by id. Public-scope behaviour is unchanged.
 *
 * The cursor is in the ANSWERING box's own arrival numbers (schema v84):
 * assigned once at ingest, strictly rising in commit order, and never
 * rewritten by a reclaim, so a page that resumes after number N misses
 * nothing that lands later, whatever second it lands in. Every answer
 * names the answering process by a random epoch; a restart may reuse a
 * number whose row was reclaimed, so a new epoch sends the asking box
 * back to the beginning, which dedupe by id makes free of effect. A post
 * this box refuses for a reason that can clear (a role not granted yet, a
 * clock behind the author's, a quota or a full store) is offered again by
 * a sweep that alternates with forward pulls, so it is neither lost nor
 * able to hold back the rest of the board. */

#define FLEET_BOARD_FLEET_SERVICE_NAME "board"
/* The command leaf whose grant lets a peer read this box's fleet posts:
 * the worker and observer roles already carry it (roles.def). */
#define FLEET_BOARD_FLEET_READ_LEAF "fleet.board.list"
#define FLEET_BOARD_FLEET_PULL_INTERVAL_S 15
#define FLEET_BOARD_FLEET_VERSION 2u
#define FLEET_BOARD_FLEET_MSG_PULL 1u
#define FLEET_BOARD_FLEET_MSG_ANSWER 2u
#define FLEET_BOARD_FLEET_EPOCH_BYTES 16u
/* type, version, u64 after_arrival */
#define FLEET_BOARD_FLEET_PULL_BYTES 10u
/* type, version, epoch, u64 arrival of the last row the page consumed */
#define FLEET_BOARD_FLEET_ANSWER_HEAD (2u + FLEET_BOARD_FLEET_EPOCH_BYTES + 8u)
/* One answer record: u64 arrival, 32-byte id, u32 length, post wire. */
#define FLEET_BOARD_FLEET_RECORD_HEAD 44u
#define FLEET_BOARD_FLEET_ANSWER_MAX (size_t)(48u * 1024u)
#define FLEET_BOARD_FLEET_ANSWER_POSTS_MAX 32u
#define FLEET_BOARD_FLEET_INBOX_MAX 8u
#define FLEET_BOARD_FLEET_PEERS_MAX 64u

void boot_fleet_board_fleet_wire(struct boot_svc_ctx *svc);
void boot_fleet_board_fleet_shutdown(void);
/* Registered once; serves both halves of every board stream. */
bool boot_fleet_board_fleet_register_service(void);

/* Counted since this process started. delegation_refused: a paired peer
 * whose delegation is no longer current, on either half. role_refused: a
 * paired peer whose online key holds no FLEET_BOARD_FLEET_READ_LEAF grant,
 * refused before the store was read. inbox_full: an answer that arrived
 * with no free commit slot (asked for again next pull). stored: fleet posts
 * a pull added to this box's store. deferred: pulled posts refused for a
 * reason that can clear, each offered again by a later sweep.
 * answer_refused: answers dropped whole because they did not add up. */
struct boot_fleet_board_fleet_counts {
    uint64_t delegation_refused;
    uint64_t role_refused;
    uint64_t inbox_full;
    uint64_t stored;
    uint64_t deferred;
    uint64_t answer_refused;
};
void boot_fleet_board_fleet_counts(struct boot_fleet_board_fleet_counts *out);

#ifdef ZCL_TESTING
struct vcs_zcode_dht_delegation;
/* Seams that drive the EXACT production callbacks over a loopback, as the
 * fleet ledger's do. bind names the ANSWERING box's store (both halves
 * share one process) and forgets every per-peer cursor; pull opens the
 * asking half toward a resolved peer with the cursor held for that peer's
 * box id; pull_paired runs the real pull lane over the pairing rows; serve
 * runs the answering tick once; drain_into commits the inbox into the
 * ASKING box's store and returns how many posts it newly stored.
 * bind_authority stands in for the DHT delegation lookup, the genesis and
 * the clock, exactly as boot_fleet_ledger_test_bind_authority does; the
 * pairing authority itself still runs. Pass NULL to unbind. */
void boot_fleet_board_fleet_test_bind(struct node_db *serve_db);
bool boot_fleet_board_fleet_test_pull(const uint8_t peer_noise[32],
                                      const uint8_t peer_box_id[32]);
void boot_fleet_board_fleet_test_pull_paired(int64_t now);
void boot_fleet_board_fleet_test_serve(void);
size_t boot_fleet_board_fleet_test_drain_into(struct node_db *ndb);
void boot_fleet_board_fleet_test_bind_authority(
    const struct vcs_zcode_dht_delegation *peer_delegation,
    const uint8_t network_genesis[32], int64_t now);
void boot_fleet_board_fleet_test_new_epoch(void);
/* Durable resume: remember the pull cursor under `dir`, drop the in-memory
 * copy the way a process restart does, and read the `after` the next pull
 * asked. NULL clears the directory. */
void boot_fleet_board_fleet_test_cursor_dir(const char *dir);
void boot_fleet_board_fleet_test_restart_cursors(void);
int64_t boot_fleet_board_fleet_test_last_after(void);
#endif

#endif /* ZCL_CONFIG_BOOT_FLEET_BOARD_H */

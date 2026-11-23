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
#include "models/fleet_board_post.h"
#include "vcs/zcode_dht_identity.h"

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

/* Grant the worker role to every key this node is ALREADY storing fleet- or
 * legacy-scope posts from (never public-scope ones, which no role gate
 * admitted), through the role seam (util/fleet_role_check.h). Called once at
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
#ifdef ZCL_TESTING
bool boot_fleet_board_identity_test(uint8_t seed_out[32], uint8_t pubkey_out[32],
                                    char *why, size_t why_capacity,
                                    void (*hook)(void *), void *ctx);
#endif

/* Copy the cached public host identity without touching the identity file or
 * exposing the seed. Read-only status uses this so observation never creates
 * a host key. */
bool boot_fleet_board_public_identity(uint8_t pubkey_out[32]);
enum vcs_zcode_dht_key_probe boot_fleet_board_identity_probe(
    const char *expected_datadir, uint8_t pubkey_out[32]);
enum vcs_zcode_dht_key_create boot_fleet_board_identity_create_if_absent(
    const char *expected_datadir, uint8_t pubkey_out[32]);
/* Load an existing online identity without creating one; for resuming a
 * previously authorized local task after restart. */
bool boot_fleet_board_load_existing_identity(uint8_t pubkey_out[32]);
bool boot_fleet_board_datadir_matches(const char *datadir);

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
/* boot_fleet_board_publish_to, below, adds the local caller's delivery
 * hint for the push. */

/* Internal app-host renewal: persist the canonical signed wire before the
 * guarded append. The caller provides its exclusive zero-busy-timeout runtime
 * writer, and announces only after releasing the package-store guard. Obtain
 * local_host from boot_fleet_board_public_identity and validate the immutable
 * post before entering that guard. */
struct node_db;
enum fleet_board_result boot_fleet_board_sign_app_offer(struct fleet_board_post *post);
bool boot_fleet_board_validate_app_offer(const struct fleet_board_post *post,
                                         const uint8_t local_host[32]);
enum fleet_board_result boot_fleet_board_append_app_offer_nowait(
    struct node_db *writer, struct fleet_board_post *post,
    const uint8_t local_host[32], int64_t now, bool *stored);

/* Receiver-local atomic wiki append. Sign with this host's existing identity,
 * store through the canonical board writer, and announce only committed new
 * objects. A retained replay returns the original signed revision. */
enum fleet_board_wiki_write_status boot_fleet_board_wiki_write(
    struct fleet_board_post *post, const uint8_t *expected, int64_t now,
    struct db_fleet_board_post *out, enum fleet_board_result *refusal);

/* Announce a specific id to every connected peer. Used right after a local
 * post so the fleet sees it without waiting for the announce period. A
 * public post a peer delivers is announced the same way, once, when this
 * node first stores it, to every peer but the one it came from; this counts
 * those relayed inventory lines since the process started. */
void boot_fleet_board_announce(const uint8_t id[32]);
uint64_t boot_fleet_board_relayed_count(void);

struct rpc_table;
/* Register the `fleet_board` RPC method — the node-side half of every board
 * and wiki command leaf. */
void boot_fleet_board_register_rpc(struct rpc_table *table);
/* Register the `fleet_board_ingest` RPC method — first-contact discovery's
 * only write into the local board (raw signed frame -> ingest chain). */
void boot_fleet_board_ingest_register_rpc(struct rpc_table *table);
/* Owner app-host operations dispatched by the resident board RPC. */
struct json_value;
bool boot_app_host_rpc_dispatch(struct node_db *db, const char *op,
                                const struct json_value *in,
                                struct json_value *result, int64_t now);

/* ── FLEET-scope carriage: the "board" mesh stream service ────────────────
 * (engine/composition/src/boot_fleet_board_fleet.c)
 *
 * A FLEET-scope post never rides the public INV/GET flood above. It moves
 * between PAIRED boxes only, over the existing mesh stream primitive, the
 * same way the fleet ledger's rows do. A box asks each paired peer for the
 * fleet posts that peer has received since the last one it saw, and answers
 * the same question when asked: the pull is the carrier, and the only one
 * that retries. A stream opens over whichever session the two boxes already
 * share, including one the ANSWERING box dialled, so a box behind NAT that
 * dials out can still be pulled from.
 *
 * PUSH only speeds posts up; it is never the only way a post arrives.
 * After this box durably stores a new fleet post it signed itself (the
 * local post path), the lane tick FANS IT OUT: once, to every paired peer
 * that has a live session now and that the answering half's own disclosure
 * decision would serve on a pull (below), except a peer proving this box's
 * own board key; a peer with no session is left to the pull, and a peer the
 * decision refuses is counted in push_fanout_refused by the check that
 * failed and never pushed to. A fanned-out post is never pushed to a box
 * that could not have pulled it. The addressed push described next runs
 * first for the same post and its addressee is not pushed to twice.
 *
 * The addressed push offers a post to ONE box, once, in a stream whose whole
 * payload rides the OPEN (FLEET_BOARD_FLEET_MSG_PUSH). Which box: the board key the local
 * caller named in the post RPC's `push_to` delivery hint when it gave a
 * usable one, else the author of the post this one answers (`ref`) when
 * this box holds that post and another box wrote it; a post with neither has
 * no addressed push (the fan-out still offers it). Nothing in a signed post names a
 * recipient (a mail row's `to` is text the node does not read), so agent
 * mail is pushed only by the hint its exporter passes. The hint is never
 * signed, stored, put in a frame or echoed to a peer; it decides only whom
 * the node TRIES, and a hint that is malformed, names this box, or rides a
 * post that is not a new FLEET post of this box's own is refused by name
 * (enum fleet_board_push_hint) and the post is treated as if it carried
 * none. When a hint and a `ref` name different boxes the hint is used and
 * the ref is not: one post, one addressee, never two. The hint is honoured
 * only on the call that newly stores the post: a row stored by an earlier
 * call and posted again (an exporter that re-exports after a crash, or
 * after a restart lost the in-memory queue) is refused not_stored and is
 * carried by the pull only. Hinted and ref-derived entries share the one
 * FLEET_BOARD_PUSH_QUEUE_MAX-entry queue, and a full queue drops its oldest
 * entry, so heavy agent mail can evict earlier entries; the pull carries
 * every one of them. The addressee is pushed to only when its board key is
 * the online key of exactly one paired peer and, at the moment the push opens, the answering half's own
 * disclosure decision for a pull from that peer's Noise key serves it: the
 * same function a pull is judged by (board_accept_authorized, asked with
 * nothing recorded), on the same pairing rows, with the same checks (a
 * current delegation on that session, the read role, the roster), and the
 * newest row that serves proves the addressee's board key; then while its send queue
 * is under budget (net_send_over_budget) and no other push to it is open,
 * and only while the post is one a pull would still serve (unexpired, or a
 * wiki page). Where the pull would refuse, the post is skipped ineligible
 * and the pull remains its only carrier. So a push never reaches a peer a
 * pull from that peer would not be served, and no hint can make a post
 * reach a box the pull would not serve: a local process able to call the post RPC can
 * already publish the post to every eligible box by pull, and gains only
 * the choice of which one of those is tried first. Which pairing rows that
 * decision judges: a pairing is one row, keyed by its pairing id, the hash
 * of network genesis, peer master key and peer Noise key; rows are
 * insert-only and a revocation is sticky, so a revoked pairing id is never
 * live again, and one Noise key holds several rows only under different
 * masters (or networks). The decision takes the newest
 * FLEET_BOARD_DISCLOSURE_ROWS_MAX rows for the peer's Noise key that grant
 * the status capability now (mesh_pairing_allows: not revoked, unexpired)
 * and serves the peer when any one of them passes every check on its own:
 * that row's master's delegation resolves and is current and bound to this
 * session under that row, then the read role and the roster. A revoked or
 * expired row is never judged, so no other row carries its authority; an
 * allowing row past those newest is not judged (fail closed), and neither
 * is a row past the first FLEET_BOARD_FLEET_PEERS_MAX of the pairing list,
 * which runs oldest first. When none serves, the newest judged row's
 * refusal is counted and logged once ("no live pairing" when no row
 * allows). Nothing is
 * relayed: a box pushes only posts its own key signed. The receiver copies
 * the payload into a bounded push inbox, separate from the pull inbox, on
 * the frame path, and checks nothing else there; its lane tick re-proves the
 * pusher, decodes every pushed record and requires its id to be its bytes,
 * FLEET scope and the pusher's own board key as author before it asks the
 * store anything about it (so a push can never learn whether this box holds
 * a post another box wrote), stores each through the same checks a pulled
 * post meets without waiting on another board writer, and closes the stream
 * with a receipt (FLEET_BOARD_FLEET_MSG_PUSH_RECEIPT). A record refused or
 * deferred for a node-wide reason (another board writer holding the lock, a
 * full store, a failed append, the node-wide wiki replacement cap) carries
 * no result code in the receipt, so a pusher learns only its own post's
 * fate. Received pushes are committed one
 * a tick, oldest first. Fairness holds among pushes that got an inbox slot:
 * FLEET_BOARD_PUSH_INBOX_MAX distinct paired peers that refill their slots
 * at once can keep the inbox full, and every other push is then refused
 * push_inbox_full and left to the pull. A new pushed record costs two
 * signature checks (its decode, then the one store ingest every post takes),
 * so a commit costs at most 2 * FLEET_BOARD_PUSH_POSTS_MAX. The receiving
 * half accepts a pusher on any pairing row for its Noise key that grants the
 * status capability now, whose delegation is current on that session and
 * whose key the roster admits: the checks this box's asking half makes on
 * any row before it pulls from that peer, so a push is accepted only from a
 * peer this box would pull from, and only records signed by a key those
 * rows prove (the read role is not asked: the pusher is disclosed nothing).
 * A push touches
 * no cursor, sweep or answer check. A push that is refused, lost, or
 * never answered is not sent again: the next pull carries the post, and a
 * post both paths deliver is one row by id. An older node answers the new
 * type stream_malformed, and that session is not pushed to again.
 *
 * Who is answered: a peer with a pairing row (of those judged, above) that
 * grants the status capability, whose delegation under that row is still
 * current, and whose online key holds a role
 * granting FLEET_BOARD_FLEET_READ_LEAF here — and, once a fleet roster is in
 * force (config/boot_fleet_roster.h, ZRC 0012 step 2), that is a member of it;
 * the asking half pulls only from such a peer, and ingest takes a fleet post
 * only from a member author. Anybody else is refused
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
 * able to hold back the rest of the board. The cursor file is synced but
 * the row store may lose its last rows to a power cut, so each start sweeps
 * every peer's rows up to its saved cursor; a full cursor table evicts the
 * peer idle longest for a new one.
 *
 * Carriage with no pairing row: the "board.roster" service. A pairing needs a
 * held ZID delegation, whose anchoring costs coins; the fleet roster is sealed
 * by the owner and costs nothing. A machine on the roster reaches the same
 * pull lane through a service of its own, so "board" and every pairing stay
 * byte for byte what they were, and an older node answers
 * stream_service_unknown. The pull carries the asker's board signing key and
 * that key's signature over the network genesis, this Noise session's
 * transcript and generation, and the cursor; the answer starts with the same
 * from the answering box. It is answered only under a MEMBER verdict
 * (boot_fleet_roster_carries_peer), so no root, no sealed row, a gate switched
 * off, notes past their TTL, a revoked key and an unverifiable roster all
 * admit nothing; a peer with any pairing row stays on the pairing path; the
 * read role still applies. A box holding no armed roster of its own takes only
 * sealed roster and head rows from an answer until those rows arm it. This lane
 * asks only a session whose address a sealed line claims as its onion, or a
 * session that already proved a member key here. It spends nothing.
 *
 * Revocation rides the same lane as a sealed head row (config/boot_fleet_roster.h).
 * Every answer's head rows are offered before anything else in it. A roster
 * answer also leads with the answering box's newest head row whenever the pull
 * has not reached it yet, so a box that arms from its first page has the head
 * first. That record carries FLEET_BOARD_ROSTER_PINNED_ARRIVAL, outside the
 * cursor's numbering, so it moves no cursor; a pull already past that row pays
 * nothing. The lane tick finds that row, so a row newer than the last look
 * travels only by its own number until the next one. A hostile answerer can
 * still leave it out; only the next honest answer, or `fleet import`, then
 * supplies it. */

#define FLEET_BOARD_FLEET_SERVICE_NAME "board"
#define FLEET_BOARD_ROSTER_SERVICE_NAME "board.roster"
/* No real arrival number is 0, so this can only be the pinned head row. */
#define FLEET_BOARD_ROSTER_PINNED_ARRIVAL 0
/* The board signing key, then its signature. */
#define FLEET_BOARD_ROSTER_PROOF_BYTES 96u
/* A plain pull, then the proof. */
#define FLEET_BOARD_ROSTER_PULL_BYTES (FLEET_BOARD_FLEET_PULL_BYTES + 96u)
/* The command leaf whose grant lets a peer read this box's fleet posts:
 * the worker and observer roles already carry it (roles.def). */
#define FLEET_BOARD_FLEET_READ_LEAF "fleet.board.list"
#define FLEET_BOARD_FLEET_PULL_INTERVAL_S 15
#define FLEET_BOARD_FLEET_VERSION 2u
#define FLEET_BOARD_FLEET_MSG_PULL 1u
#define FLEET_BOARD_FLEET_MSG_ANSWER 2u
#define FLEET_BOARD_FLEET_EPOCH_BYTES 16u

#define FLEET_BOARD_OBSERVATION_CAPACITY 64u

/* Bounded, volatile observations; sequence describes observation order only.
 * The peer identifier is the paired peer's master public key. */
enum boot_fleet_board_observation_phase {
    FLEET_BOARD_OBS_OPEN_ATTEMPT, FLEET_BOARD_OBS_OPEN_FAILURE,
    FLEET_BOARD_OBS_CLOSE, FLEET_BOARD_OBS_INGEST, FLEET_BOARD_OBS_GATE,
    FLEET_BOARD_OBS_ANSWER_REFUSED, FLEET_BOARD_OBS_ANSWER_DEFERRED,
    FLEET_BOARD_OBS_CURSOR_RESET
};
enum boot_fleet_board_gate_reason {
    FLEET_BOARD_GATE_PAIRING, FLEET_BOARD_GATE_DELEGATION_UNRESOLVED,
    FLEET_BOARD_GATE_DELEGATION_REFUSED, FLEET_BOARD_GATE_ROSTER
};
enum boot_fleet_board_answer_deferred_reason {
    FLEET_BOARD_ANSWER_INBOX_FULL, FLEET_BOARD_ANSWER_ALLOCATION_FAILED
};
enum boot_fleet_board_cursor_reset_reason {
    FLEET_BOARD_CURSOR_EPOCH_CHANGED, FLEET_BOARD_CURSOR_EPOCH_UNOBSERVED
};
struct boot_fleet_board_observation {
    bool found;
    uint64_t sequence;
    int64_t after;
    int64_t arrival;
    int result;
    enum boot_fleet_board_observation_phase phase;
    bool stored;
    bool retryable;
    bool epoch_set;
    uint8_t epoch[FLEET_BOARD_FLEET_EPOCH_BYTES];
};
void boot_fleet_board_observe_query(const uint8_t peer[32], const uint8_t post[32],
                                    struct boot_fleet_board_observation *attempt,
                                    struct boot_fleet_board_observation *ingest);
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
/* Paired peers and roster targets are planned apart, each up to PEERS_MAX per
 * tick, and share one cursor table. It holds both, or least-recently-used
 * eviction would drop the very cursor each pull is about to use. */
#define FLEET_BOARD_FLEET_CURSOR_SLOTS (2u * FLEET_BOARD_FLEET_PEERS_MAX)
/* The lane tick. A tick with no push work takes the board lane's own lock
 * twice, reads the clock and two counters, and returns; the pull, the answer
 * drain and everything else the lane did once a second still run once a
 * second. While posts wait in the push queue and nothing changed (no post
 * queued and no push ended since the last round) a tick adds one counter
 * read and one push lock pair: the sending round, with its pairing walk,
 * runs at most once a second otherwise. The supervisor already ticks every
 * 100 ms for the stream pump, so this adds no wakeup of its own. */
#define FLEET_BOARD_FLEET_TICK_US 100000

/* PUSH (see above). The OPEN payload: type, version, record count n, then n
 * records of a 32-byte id, a u32 length and the post wire, nothing after. */
#define FLEET_BOARD_FLEET_MSG_PUSH 3u
/* The CLOSE payload: type, version, push code, n, u64 commit time in Unix
 * milliseconds, then n records of a 32-byte id, a verdict and a result. */
#define FLEET_BOARD_FLEET_MSG_PUSH_RECEIPT 4u
#define FLEET_BOARD_PUSH_HEAD 3u
#define FLEET_BOARD_PUSH_RECORD_HEAD 36u
#define FLEET_BOARD_PUSH_POSTS_MAX 8u
/* The whole OPEN payload, under MESH_STREAM_PAYLOAD_MAX. A post too large to
 * ride in it is not pushed. */
#define FLEET_BOARD_PUSH_MAX (size_t)(16u * 1024u)
#define FLEET_BOARD_PUSH_RECEIPT_HEAD 12u
#define FLEET_BOARD_PUSH_RECEIPT_RECORD 34u
#define FLEET_BOARD_PUSH_RECEIPT_MAX                                           \
    (FLEET_BOARD_PUSH_RECEIPT_HEAD +                                           \
     FLEET_BOARD_PUSH_POSTS_MAX * FLEET_BOARD_PUSH_RECEIPT_RECORD)
/* Post ids waiting for the lane tick; a full queue gives up its oldest. */
#define FLEET_BOARD_PUSH_QUEUE_MAX 32u
/* Received pushes waiting for the lane tick, preallocated, at most one per
 * pushing peer; the tick commits one push a tick, in arrival order, so a
 * peer that refills its slot at once waits behind every push that arrived
 * before its refill. */
#define FLEET_BOARD_PUSH_INBOX_MAX 8u
/* A sender closes its own push this long after opening it when no receipt
 * came; a receiver closes an uncommitted push at the same mark. A post kept
 * in the queue because its peer had a push open is dropped at the same
 * mark. */
#define FLEET_BOARD_PUSH_WAIT_S 10
/* The credit a push stream opens with. The payload rides the OPEN, which
 * spends no credit; one byte is the smallest window the primitive accepts. */
#define FLEET_BOARD_PUSH_WINDOW 1u

/* The push's own verdict, first on its receipt. */
enum fleet_board_push_code {
    FLEET_BOARD_PUSH_CODE_COMMITTED = 0, /* every record judged, see below */
    FLEET_BOARD_PUSH_CODE_MALFORMED,     /* framing, id, or scope: voided whole */
    FLEET_BOARD_PUSH_CODE_AUTHOR,        /* a record not signed by the pusher */
    FLEET_BOARD_PUSH_CODE_INBOX_FULL,    /* no free push inbox slot */
    FLEET_BOARD_PUSH_CODE_BUSY,          /* this peer already has one waiting */
    FLEET_BOARD_PUSH_CODE_REVOKED,       /* the pusher lost standing before commit */
    FLEET_BOARD_PUSH_CODE_UNAVAILABLE,   /* no store, no memory, or the wait ran out */
    FLEET_BOARD_PUSH_CODES
};

/* One record's verdict on a committed push. */
enum fleet_board_push_record_verdict {
    FLEET_BOARD_PUSH_RECORD_STORED = 0,
    FLEET_BOARD_PUSH_RECORD_HELD,     /* this box already held it */
    FLEET_BOARD_PUSH_RECORD_DEFERRED, /* a refusal that can clear: pull retries */
    FLEET_BOARD_PUSH_RECORD_REFUSED,
    FLEET_BOARD_PUSH_VERDICTS
};

/* Why the sending half did not push a post it was offered. */
enum fleet_board_push_skip {
    FLEET_BOARD_PUSH_SKIP_NOT_OWN = 0,   /* not FLEET scope, or not signed here */
    FLEET_BOARD_PUSH_SKIP_NO_ADDRESSEE,  /* no `ref`, or it names no other box's post */
    FLEET_BOARD_PUSH_SKIP_QUEUE_FULL,    /* dropped as the oldest of a full queue */
    FLEET_BOARD_PUSH_SKIP_GONE,          /* no longer in this box's store */
    FLEET_BOARD_PUSH_SKIP_UNRESOLVED,    /* no paired peer, or not the pull row's key */
    FLEET_BOARD_PUSH_SKIP_AMBIGUOUS,     /* ... or more than one */
    FLEET_BOARD_PUSH_SKIP_INELIGIBLE,    /* a pull from it would not be served */
    FLEET_BOARD_PUSH_SKIP_NOT_CONNECTED, /* no live session to it */
    FLEET_BOARD_PUSH_SKIP_OVER_BUDGET,   /* its send queue is over budget */
    FLEET_BOARD_PUSH_SKIP_UNSUPPORTED,   /* it refused the type this session */
    FLEET_BOARD_PUSH_SKIP_BUSY,          /* a push to it stayed open too long */
    FLEET_BOARD_PUSH_SKIP_TOO_LARGE,     /* the post cannot ride one OPEN */
    FLEET_BOARD_PUSH_SKIP_OPEN_FAILED,   /* the stream primitive refused the open */
    FLEET_BOARD_PUSH_SKIP_NO_RECEIPT,    /* closed by this box after the wait */
    FLEET_BOARD_PUSH_SKIP_EXPIRED,       /* expired while it waited: no pull serves it */
    FLEET_BOARD_PUSH_SKIPS
};

/* What the node did with the `push_to` delivery hint of one post RPC. Every
 * value but NONE and QUEUED is a refusal: the hint is dropped and the post
 * is pushed (or not) exactly as if it had carried none. */
enum fleet_board_push_hint {
    FLEET_BOARD_PUSH_HINT_NONE = 0,  /* no hint was given */
    FLEET_BOARD_PUSH_HINT_QUEUED,    /* queued for the one box it names */
    FLEET_BOARD_PUSH_HINT_MALFORMED, /* not 64 lowercase hex */
    FLEET_BOARD_PUSH_HINT_NOT_FLEET, /* the post is not FLEET scope */
    FLEET_BOARD_PUSH_HINT_NOT_OWN,   /* the post is not signed by this box */
    FLEET_BOARD_PUSH_HINT_NOT_STORED, /* the publish stored no new plain post */
    FLEET_BOARD_PUSH_HINT_SELF,      /* it names this box's own board key */
    FLEET_BOARD_PUSH_HINTS
};

/* Which check a push judgment of a paired peer failed: the addressee's on
 * the sending half, the pusher's at its commit on the receiving half. */
enum fleet_board_push_refusal {
    FLEET_BOARD_PUSH_REFUSAL_PAIRING = 0, /* no row grants the status capability now */
    FLEET_BOARD_PUSH_REFUSAL_DELEGATION,  /* unresolved, or not current on chain */
    FLEET_BOARD_PUSH_REFUSAL_ROLE,        /* addressee only: no read leaf grant */
    FLEET_BOARD_PUSH_REFUSAL_ROSTER,      /* the fleet roster does not admit its key */
    FLEET_BOARD_PUSH_REFUSALS
};

void boot_fleet_board_fleet_wire(struct boot_svc_ctx *svc);
void boot_fleet_board_fleet_shutdown(void);
/* Registered once; serves both halves of every board stream. */
bool boot_fleet_board_fleet_register_service(void);

/* Counted since this process started. delegation_refused: a paired peer
 * whose delegation is no longer current, on either half of the pull.
 * role_refused: a paired peer whose online key holds no
 * FLEET_BOARD_FLEET_READ_LEAF grant, refused a pull before the store was
 * read. Neither counts a push judgment: push_refused_out counts, by the
 * check that failed, the addressees the sending half did not push to, and
 * push_refused_in the pushers whose standing failed at the commit (each such
 * push is also answered push_revoked). inbox_full: an answer that arrived
 * with no free commit slot (asked for again next pull). stored: fleet posts
 * a pull added to this box's store. deferred: pulled posts refused for a
 * reason that can clear, each offered again by a later sweep.
 * answer_refused: answers dropped whole because they did not add up.
 * roster_refused: carriage with no pairing row refused, on either half.
 * The push, sending half: push_queued posts offered to the queue,
 * push_opened push streams opened, push_skipped each reason a post was not
 * pushed or a push ended without a receipt, push_closed push streams the
 * peer ended without a receipt by the primitive's reason (an older peer's
 * stream_malformed is counted under push_skipped UNSUPPORTED instead),
 * push_receipt the receipts that came back by push code and push_receipt_records
 * their records by verdict. Receiving half: push_in the pushes this box
 * answered by push code (refusals at open included) and push_in_records
 * the records it judged by verdict; push_in_dropped pushes that ended
 * before their commit; push_data_refused DATA on a push stream, which
 * closes it. push_hint: the post RPC's `push_to` hints by what was done
 * with each; a hinted post that never reaches the queue is counted there
 * only, never also under push_skipped. The read-only `fleet_board op=status`
 * reply carries all of these under "carriage". */
struct boot_fleet_board_fleet_counts {
    uint64_t delegation_refused;
    uint64_t role_refused;
    uint64_t inbox_full;
    uint64_t stored;
    uint64_t deferred;
    uint64_t answer_refused;
    uint64_t roster_refused;
    uint64_t push_queued;
    uint64_t push_opened;
    uint64_t push_skipped[FLEET_BOARD_PUSH_SKIPS];
    uint64_t push_closed[16]; /* by enum mesh_stream_refusal */
    uint64_t push_receipt[FLEET_BOARD_PUSH_CODES];
    uint64_t push_receipt_records[FLEET_BOARD_PUSH_VERDICTS];
    uint64_t push_in[FLEET_BOARD_PUSH_CODES];
    uint64_t push_in_records[FLEET_BOARD_PUSH_VERDICTS];
    uint64_t push_in_dropped;
    uint64_t push_data_refused;
    uint64_t push_refused_out[FLEET_BOARD_PUSH_REFUSALS];
    uint64_t push_refused_in[FLEET_BOARD_PUSH_REFUSALS];
    uint64_t push_hint[FLEET_BOARD_PUSH_HINTS];
    /* The fan-out: posts added to a push for one more peer, and connected
     * paired peers it did not push to because a pull from them would not be
     * served, by the check that failed. */
    uint64_t push_fanout;
    uint64_t push_fanout_refused[FLEET_BOARD_PUSH_REFUSALS];
};
void boot_fleet_board_fleet_counts(struct boot_fleet_board_fleet_counts *out);

/* Offer one post this box just stored durably to the push queue: O(1) under
 * the push lock, no store read, no stream call, safe from the RPC thread.
 * Only a FLEET-scope post signed by `own_key` (this box's board key) whose
 * `ref` names a post is queued; anything else is counted and left to the
 * pull. */
void boot_fleet_board_fleet_push_enqueue(const struct fleet_board_post *post,
                                         const uint8_t own_key[32]);
/* The same, with the local caller's `push_to` delivery hint (NULL: none):
 * text naming the board key of the one box to try. A usable hint queues the
 * post for that box whether or not it has a `ref`, and its box is used in
 * place of the ref's. The hint is copied into the queue entry only; the
 * post is untouched. Returns what was done with the hint, counted. */
enum fleet_board_push_hint boot_fleet_board_fleet_push_enqueue_to(
    const struct fleet_board_post *post, const uint8_t own_key[32],
    const char *push_to);
/* The local post path's offer: the same entry, also fanned out to every
 * connected peer a pull would serve the post to (see PUSH above), and queued
 * even when it has neither a usable hint nor a `ref`. */
enum fleet_board_push_hint boot_fleet_board_fleet_push_enqueue_all(
    const struct fleet_board_post *post, const uint8_t own_key[32],
    const char *push_to);
/* A hint whose publish stored nothing new (the same post again, or a typed
 * wiki review): counted and refused; MALFORMED when it is not even a key. */
enum fleet_board_push_hint boot_fleet_board_fleet_push_hint_unused(
    const char *push_to);
/* The token each hint verdict renders as in the post and status replies. */
const char *boot_fleet_board_push_hint_name(enum fleet_board_push_hint h);
/* boot_fleet_board_publish with the local caller's optional `push_to`
 * delivery hint (NULL: none), handed to the push queue only when this call
 * newly stored a FLEET post. The hint is never signed, stored or announced,
 * and changes nothing about whether or how the post is published.
 * `hint_out` (may be NULL) receives what was done with it:
 * FLEET_BOARD_PUSH_HINT_NONE when there was none or the publish failed. */
enum fleet_board_result boot_fleet_board_publish_to(
    struct fleet_board_post *post, int64_t now, const char *push_to,
    enum fleet_board_push_hint *hint_out);

#ifdef ZCL_TESTING
struct vcs_zcode_dht_delegation;
/* Seams that drive the EXACT production callbacks over a loopback, as the
 * fleet ledger's do. bind names the ANSWERING box's store (both halves
 * share one process) and forgets every per-peer cursor; pull opens the
 * asking half toward a resolved peer with the cursor held for that peer's
 * box id; pull_paired runs the real pull lane over the pairing rows; serve
 * runs on_tick once over every live stream, as the pump does; drain_into
 * commits the inbox into the ASKING box's store and returns how many posts
 * it newly stored.
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
/* The roster path. pull_roster opens one roster pull toward a connected peer;
 * pull_roster_lane runs the real lane, target walk included, and returns how
 * many it opened. roster_identity makes one side (1 asks, 2 answers) sign as
 * the box it stands in for; a NULL seed goes back to the node's own key. */
bool boot_fleet_board_fleet_test_pull_roster(struct boot_svc_ctx *svc,
                                             const uint8_t peer_noise[32]);
size_t boot_fleet_board_fleet_test_pull_roster_lane(struct boot_svc_ctx *svc,
                                                    struct node_db *store,
                                                    int64_t now);
void boot_fleet_board_fleet_test_roster_identity(int side, const uint8_t *seed,
                                                 const uint8_t *pub);
/* The state-tag guard. retag swaps the state of every live "board" stream on
 * one side for a fresh one carrying `tag` (any value, known or not), freeing
 * the old one, and returns how many it swapped; states_freed counts every
 * state the lane has freed, whatever its tag. */
size_t boot_fleet_board_fleet_test_retag(bool local_initiator, int tag);
uint64_t boot_fleet_board_fleet_test_states_freed(void);
/* The push. bind_second_peer makes the delegation stand-in answer for a
 * second Noise static as well (NULL clears it), so one process can hold the
 * pusher's and the addressee's pairing at once. push_send runs the sending
 * half of one lane tick with `store` as this box's store; push_commit runs
 * the receiving half of one tick into `store` and returns the records it
 * newly stored. pre_push_dispatch makes the "board" OPEN behave exactly as a
 * node from before the push did. forget_inbox drops every received push, as
 * a restart would. queued and inbox_used read the two bounded tables;
 * live_tagged counts live "board" streams on one side whose state carries
 * `tag`; age_push moves every push stream's open time `seconds` back, so the
 * next pump tick sees its wait run out. */
void boot_fleet_board_fleet_test_bind_second_peer(
    const struct vcs_zcode_dht_delegation *peer_delegation);
/* A third delegation the stand-in answers for (NULL clears it; bind_authority
 * clears it too), so a hint and a `ref` can name two different addressees
 * while the pusher still resolves. */
void boot_fleet_board_fleet_test_bind_third_peer(
    const struct vcs_zcode_dht_delegation *peer_delegation);
size_t boot_fleet_board_fleet_test_push_send(struct boot_svc_ctx *svc,
                                             struct node_db *store);
size_t boot_fleet_board_fleet_test_push_commit(struct node_db *store);
void boot_fleet_board_fleet_test_pre_push_dispatch(bool on);
void boot_fleet_board_fleet_test_push_forget_inbox(void);
size_t boot_fleet_board_fleet_test_push_queued(void);
size_t boot_fleet_board_fleet_test_push_inbox_used(void);
size_t boot_fleet_board_fleet_test_live_tagged(bool local_initiator, int tag);
void boot_fleet_board_fleet_test_age_push(int64_t seconds);
/* push_send_at is push_send at lane time `now` (Unix seconds);
 * push_peer_walks counts the pairing walks the sending half has made. tick
 * runs the lane's own supervisor tick body with `svc` as the wired context
 * and `now` as the wall clock; tick_runs reads how many times its
 * once-a-second work (the answer drain) and its pull-interval work (the
 * pulls) have run. */
size_t boot_fleet_board_fleet_test_push_send_at(struct boot_svc_ctx *svc,
                                                struct node_db *store,
                                                int64_t now);
uint64_t boot_fleet_board_fleet_test_push_peer_walks(void);
void boot_fleet_board_fleet_test_tick(struct boot_svc_ctx *svc, int64_t now);
void boot_fleet_board_fleet_test_tick_runs(uint64_t *seconds, uint64_t *pulls);
#endif

/* The refusal phrase for `r` and, where one exists, the limit hit and the
 * command that clears it. Writes into buf and returns it. */
const char *boot_fleet_board_write_message(enum fleet_board_result r, char *buf,
                                           size_t cap);

/* The stage a replication refusal happened at, and one command an operator
 * can run. Naming only: no acceptance rule depends on any of it. */
enum boot_fleet_board_stage {
    BOARD_STAGE_PAIRING, BOARD_STAGE_DELEGATION, BOARD_STAGE_STREAM,
    BOARD_STAGE_ANSWER_ROLE, BOARD_STAGE_INGEST_ROLE,
    BOARD_STAGE_INGEST_LIMIT, BOARD_STAGE_DECODE, BOARD_STAGE_ROSTER, BOARD_STAGE_CLOCK,
    BOARD_STAGE_INGEST_STORAGE, BOARD_STAGE_ANSWER_INBOX, BOARD_STAGE_ANSWER_ALLOCATION,
    BOARD_STAGES
};
const char *boot_fleet_board_stage_name(enum boot_fleet_board_stage s);
const char *boot_fleet_board_stage_action(enum boot_fleet_board_stage s);
/* "stage=<name>: <detail>; next: <action>" into buf; returns buf. */
const char *boot_fleet_board_stage_line(enum boot_fleet_board_stage s,
                                        const char *detail, char *buf,
                                        size_t cap);
enum boot_fleet_board_stage boot_fleet_board_ingest_stage(
    enum fleet_board_result r);
/* One WARN line "<what>: stage=...; next: ..." for a refusal at a stage. */
void boot_fleet_board_stage_warn(const char *what,
                                 enum boot_fleet_board_stage s,
                                 const char *detail);
void boot_fleet_board_ingest_warn(const char *what, enum fleet_board_result r);
/* The stage line for one refused ingest result. */
const char *boot_fleet_board_ingest_line(enum fleet_board_result r, char *buf,
                                         size_t cap);
/* The stage line for a deferred ingest; a roster-only box says why. */
const char *boot_fleet_board_deferred_line(enum fleet_board_result r,
                                           bool roster_only, char *buf,
                                           size_t cap);
/* The stage a recorded observation was refused at; false when it is not a
 * refusal (stored, held, stale, an open attempt, a finished stream). */
bool boot_fleet_board_observation_stage(
    const struct boot_fleet_board_observation *v,
    enum boot_fleet_board_stage *out);
#endif /* ZCL_CONFIG_BOOT_FLEET_BOARD_H */

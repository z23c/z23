/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_NET_CONNMAN_H
#define ZCL_NET_CONNMAN_H

#include "net/net.h"
#include "net/anchor_peers.h"
#include "net/onion_discovery.h"
#include "chain/chainparams.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#define MAX_ADDNODES 16

/* Reactor fd-array ceiling for thread_socket_handler's poll() set (listen
 * sockets + connected peers). Named so the hand-sized pfds[]/node_fds[]
 * stack arrays and the connman_start() admission check below share one
 * source of truth instead of silently truncating past a hardcoded literal.
 * Ceiling doc: 8 listen sockets + up to ~1000 configured max_connections
 * (net.h DEFAULT_MAX_PEER_CONNECTIONS=125 today; CONNMAN_DEFERRED_FREE_
 * HARD_CAP above already treats 8x default = 1000 as the operator ceiling).
 * 1024 gives headroom over 1008 without wasting much stack (pollfd is 8
 * bytes; { int; size_t } is 16 bytes -> ~24 KB total per poll iteration,
 * fine against the default 8 MB thread stack). */
#define REACTOR_MAX_FDS 1024

/* fds the reactor reserves for listen sockets when clamping the config-derived
 * max_connections at connman_init (config validation time). REACTOR_MAX_FDS -
 * REACTOR_LISTEN_RESERVE = 1000 is exactly the documented operator ceiling (8×
 * DEFAULT_MAX_PEER_CONNECTIONS), and 24 reserved listen fds is well above the
 * practical listen-socket count (~8). Clamping max_connections to that ceiling
 * up front makes the connman_start() near-overflow clamp + the
 * connman_reactor_overflow blocker structurally unreachable for any listen
 * count within the reserve; the start-time blocker survives only as the
 * backstop for the genuinely impossible case (listen sockets ALONE exceeding
 * the reactor). */
#define REACTOR_LISTEN_RESERVE 24

/* Reactor admission + high-water stats, exposed for the net/connman
 * dump-state JSON (see peer_lifecycle_dump_state_json). Populated at
 * connman_start() (configured_*) and updated on the socket-handler thread's
 * hot path (npfds_high_water; single-writer atomic, no lock). */
struct connman_reactor_stats {
    size_t npfds_high_water;
    size_t reactor_max_fds;
    int    configured_max_connections;
    size_t configured_listen_sockets;
};

void connman_get_reactor_stats(struct connman_reactor_stats *out);

/* v2 (Noise) transport ADVERTISEMENT census — observation only.
 *
 * Nothing reads these to make a decision. The v2 transport default stays OFF
 * (`-v2transport`, connman.c) because every peer on the live network today
 * speaks the unencrypted v1 wire: flipping the default before a measured
 * population of peers advertises NODE_V2TRANSPORT would partition this node
 * off the network. This census is the evidence that decision needs — it
 * counts peers whose version message advertised the bit, nothing more.
 *
 * Sampled once per socket-handler poll iteration (~20 Hz) while the node
 * list lock is already held, so `advertising_now` is a live count and
 * `advertising_high_water` / `advertising_observations_total` accumulate
 * across peer churn without needing to remember individual peers. A
 * nonzero high-water over a measured window is the precondition for even
 * discussing the default flip; the flip itself stays an owner decision. */
struct connman_v2transport_stats {
    size_t   advertising_now;      /* peers currently advertising the bit  */
    size_t   handshaked_now;       /* handshake-complete peers, same walk  */
    size_t   advertising_high_water;         /* max advertising_now seen   */
    uint64_t advertising_observations_total; /* Σ advertising_now / sample */
    uint64_t samples_total;                  /* poll iterations sampled    */
};

void connman_get_v2transport_stats(struct connman_v2transport_stats *out);

#ifdef ZCL_TESTING
/* The census recorder the reactor poll loop calls, exposed so the
 * accumulation rule is testable without spinning up real sockets. */
void connman_note_v2transport_sample_for_test(size_t advertising,
                                              size_t handshaked);
#endif

#ifdef ZCL_TESTING
/* Pure reactor-admission clamp math connman_start() uses internally — see
 * connman.c. Exposed so the clamp-vs-refuse boundary is unit-testable
 * without spawning the real reactor threads. */
int connman_reactor_admit_for_test(size_t listen_sockets, int requested_max,
                                    bool *impossible_out);
#endif

/* Initial capacity of the deferred-free list: starts at 256, grows
 * dynamically on overflow up to CONNMAN_DEFERRED_FREE_HARD_CAP. The fixed
 * cap-256 used to overflow under Tor-driven churn while the message
 * handler held snapshot refs, triggering the deliberate-leak fallback in
 * thread_socket_handler. grow the array instead. The hard
 * ceiling is 8× DEFAULT_MAX_PEER_CONNECTIONS = 1000, large enough that
 * hitting it indicates a genuine leak (and tripping the SIGABRT handler
 * is the right outcome). */
#define CONNMAN_DEFERRED_FREE_INIT_CAP 256
#define CONNMAN_DEFERRED_FREE_HARD_CAP 1000
#define CONNMAN_DHT_HINT_MAX 64

enum connman_outbound_target_source {
    CONNMAN_TARGET_NONE = 0,
    CONNMAN_TARGET_ADDNODE,
    CONNMAN_TARGET_ADDRMAN,
    CONNMAN_TARGET_ANCHOR,   /* persisted anchors.dat, dialed first at boot */
    CONNMAN_TARGET_DHT_HINT, /* chain-bound ZENDP hint, one priority attempt */
    CONNMAN_TARGET_ZCL23_DB, /* discovered peer, via the shared scheduler */
};

enum connman_addnode_failure_kind {
    CONNMAN_ADDNODE_FAILURE_TCP = 0,
    CONNMAN_ADDNODE_FAILURE_PROTOCOL,
};

/* ── addnode self-healing (RETIRE + HARVEST) ─────────────────────────────
 *
 * Evidence (live node, 2026-07): an addnode with 5,431 consecutive TCP
 * failures (host dead for weeks, TCP-closed on every attempt) kept
 * consuming a dial slot + backoff cycle forever, while the census store
 * knew of two healthy, un-dialed peers sitting idle in node_census. RETIRE
 * stops paying rent on a permanently-dead host; HARVEST spends the freed
 * capacity on the census's already-proven-reachable candidates.
 *
 * Both knobs below are deliberately conservative: a retirement has a cheap
 * escape hatch (one successful dial, or an operator `addnode add` re-add —
 * see connman_record_addnode_attempt / connman_open_connection), so a
 * false-positive retirement costs nothing but a delayed rediscovery, while
 * never retiring costs a dial slot forever.
 *
 * RETIRE thresholds — a connection with zero successes over this many
 * consecutive TCP failures AND this long since the failure streak began
 * (first failure after the last success, or since the addnode was added)
 * is almost certainly a permanently dead host, not a transient outage.
 * "Zero successes" falls out for free: connman_record_addnode_attempt
 * (success=true) resets addnode_tcp_failures to 0, so the threshold below
 * is only reachable on an unbroken failure streak since the last success. */
#define ZCL_ADDNODE_RETIRE_MIN_TCP_FAILURES 500
#define ZCL_ADDNODE_RETIRE_MIN_WINDOW_SECS  (48 * 3600)  /* 48 hours */

/* HARVEST tuning: how many census rows one pull can add to addrman, how
 * fresh a harvested peer's last successful dial must be to count as a live
 * discovery candidate, the minimum gap between pulls (so a hungry outbound
 * loop doesn't hammer the census DB every iteration), and how small addrman
 * must be (while below the healthy-outbound floor) before a pull fires. */
#define ZCL_ADDNODE_HARVEST_MAX_CANDIDATES         16
#define ZCL_ADDNODE_HARVEST_RECENT_SUCCESS_SECS    (24 * 3600) /* 24 hours */
#define ZCL_ADDNODE_HARVEST_INTERVAL_SECS          60
#define ZCL_ADDNODE_HARVEST_WEAK_ADDRMAN_THRESHOLD 8

struct connman_known_peer {
    uint8_t ip[16];
    uint16_t port;
    uint64_t services;
};

typedef int (*connman_known_zcl23_peers_fn)(
    void *ctx,
    struct connman_known_peer *out,
    size_t max);

struct connman_outbound_health {
    size_t outbound_total;
    size_t inbound_total;
    size_t healthy;
    size_t inbound_healthy;
    size_t connecting;
    size_t handshake_incomplete;
    size_t inbound_handshake_incomplete;
    size_t ipv4_group_count;
    size_t ipv4_max_group_size;
    size_t healthy_ipv4_group_count;
    size_t healthy_ipv4_max_group_size;
    size_t addnode_count;
    size_t addnode_backoff_active;
    int addnode_backoff_max_sec;
    int64_t addnode_tcp_failures;
    int64_t addnode_protocol_failures;
    /* Count of addnodes currently in the retired state (excluded from dial
     * rotation — see connman_retire_dead_addnodes). Revivable, so this is a
     * live snapshot, not the lifetime total (that is
     * addnode_retirements_total on struct connman, surfaced separately by
     * the network dumpstate rollup). */
    size_t addnode_retired_count;
};

struct connman_message_cycle_stats {
    uint64_t cycles;
    uint64_t nodes_snapshotted;
    uint64_t send_calls;
    uint64_t process_calls;
    uint64_t recv_ready;
    uint64_t idle_waits;
    uint64_t wakes;
};

struct connman {
    struct net_manager manager;
    const struct chain_params *params;
    bool started;
    bool dns_seed_thread_started;
    bool socket_thread_started;
    bool open_thread_started;
    bool message_thread_started;
    struct p2p_node **deferred_free;
    size_t num_deferred_free;
    size_t deferred_free_cap;
    /* Persistent addnode list — reconnected automatically on disconnect */
    struct net_address addnodes[MAX_ADDNODES];
    int num_addnodes;
    size_t next_addnode_cursor;
    int64_t addnode_last_attempt[MAX_ADDNODES];
    int addnode_backoff_sec[MAX_ADDNODES];
    int64_t addnode_tcp_failures[MAX_ADDNODES];
    int64_t addnode_protocol_failures[MAX_ADDNODES];
    /* Self-healing ledger (see the RETIRE/HARVEST doc block above).
     * addnode_first_failure_ts[i] is the wall-clock time the current
     * unbroken TCP-failure streak began (0 = no streak in progress; reset
     * to 0 on any success). addnode_retired[i]/addnode_retired_at[i] mark
     * an addnode excluded from dial rotation because the streak crossed
     * both RETIRE thresholds; a retired entry stays in the ledger (never
     * removed) and is revived by one manual dial success or an operator
     * `addnode add` re-add. addnode_retirements_total is a monotonic
     * lifetime counter (never decremented by revival or removal) for
     * operator visibility. */
    int64_t addnode_first_failure_ts[MAX_ADDNODES];
    bool addnode_retired[MAX_ADDNODES];
    int64_t addnode_retired_at[MAX_ADDNODES];
    int64_t addnode_retirements_total;
    /* HARVEST cadence: wall-clock seconds of the last census pull (0 =
     * none yet). Gates connman_harvest_census_candidates() calls from the
     * open-connections loop to ZCL_ADDNODE_HARVEST_INTERVAL_SECS apart. */
    int64_t last_census_harvest_ts;
    /* Anchor peers (net/anchor_peers.h): the healthy outbound set persisted to
     * anchors.dat on shutdown + every addrman flush, reloaded at boot and
     * dialed FIRST (before the addrman random walk). `anchors_tried[i]` gives
     * each loaded anchor exactly one priority attempt; once all are tried the
     * dialer falls into the normal addnode/addrman flow. */
    struct anchor_peer_set anchors;
    bool                   anchors_tried[ANCHOR_PEERS_MAX];
    /* Address-free ZCODE NODES hints resolve through signed ZENDP records,
     * then land here for one priority dial by the existing non-blocking
     * dialer. They are also added to addrman; this queue is merely urgency,
     * never a second address authority or socket stack. */
    zcl_mutex_t             dht_hint_lock;
    struct net_address      dht_hints[CONNMAN_DHT_HINT_MAX];
    size_t                  dht_hint_count;
    /* Feeler cadence: wall-clock seconds of the last feeler dial initiated
     * (0 = none yet). One feeler per ZCL_FEELER_INTERVAL_SECS. */
    int64_t                last_feeler_ts;
    /* Data directory for persisting addrman (peers.dat) */
    const char *datadir;
    const char *onion_peer_datadir;
    onion_peer_discover_fn onion_peer_discover;
    connman_known_zcl23_peers_fn known_zcl23_peers;
    void *known_zcl23_peers_ctx;
    /* One dial owner for every source. The ZCL23 database is preferred on
     * alternating scheduler turns, while its exact endpoints inherit
     * addrman's durable handshake-qualified failure cooldown. These counters
     * make suppression and fairness visible without an unbounded ledger. */
    _Atomic uint64_t zcl23_preference_round;
    _Atomic uint64_t zcl23_candidates_seen;
    _Atomic uint64_t zcl23_dials_scheduled;
    _Atomic uint64_t zcl23_backoff_skips;
    _Atomic uint64_t zcl23_policy_skips;

    /* Message-loop counters for operator/agent diagnostics. The message
     * thread updates these on the hot path; RPC/API readers snapshot them
     * lock-free via connman_get_message_cycle_stats(). */
    _Atomic uint64_t message_cycles;
    _Atomic uint64_t message_nodes_snapshotted;
    _Atomic uint64_t message_send_calls;
    _Atomic uint64_t message_process_calls;
    _Atomic uint64_t message_recv_ready;
    _Atomic uint64_t message_idle_waits;
    _Atomic uint64_t message_wakes;
    _Atomic int64_t  message_last_progress_us;
    _Atomic int64_t  dial_scheduler_last_progress_us;
};

/* Persist a newly learned NODE_V2TRANSPORT capability in the existing
 * addrman/addnode dial sources and mark the outbound plaintext connection for
 * one controlled reconnect.  Returns true only for the first upgrade request
 * (the dial target did not already carry the capability). */
bool connman_request_v2_upgrade(struct connman *cm, struct p2p_node *node);

bool connman_init(struct connman *cm, const struct chain_params *params,
                   struct node_signals *signals);
bool connman_start(struct connman *cm);
void connman_signal_stop(struct connman *cm);
void connman_join(struct connman *cm);
void connman_stop(struct connman *cm);
void connman_free(struct connman *cm);

/* Persist addrman to {datadir}/peers.dat. Call on shutdown. */
void connman_save_addrman(struct connman *cm);

/* Load addrman from {datadir}/peers.dat. Call before connman_start. */
void connman_load_addrman(struct connman *cm);

void connman_add_seed_node(struct connman *cm, const char *host,
                            uint16_t port);
void connman_open_connection(struct connman *cm,
                              const struct net_address *addr);
bool connman_queue_dht_hint(struct connman *cm,
                            const struct net_address *addr);
bool connman_dht_hint_pending(struct connman *cm);
bool connman_take_dht_hint(struct connman *cm, struct net_address *out);
bool connman_remove_addnode(struct connman *cm,
                            const struct net_address *addr);

/* Kick the seed-discovery loop: re-add fixed seeds + retry DNS resolve.
 * Safe to call from any thread; idempotent. In -connect mode this is a no-op:
 * explicit peers are the entire outbound universe. Used by the sync watchdog
 * when it detects a peer-floor breach or single-peer recovery state to widen
 * the addrman selection without waiting for the adaptive timer. */
void connman_kick_seed_discovery(struct connman *cm);

/* Peer-of-last-resort: synchronously fetch /directory.json from every known
 * onion-directory seed (operator file ~/.config/zclassic23/onion-seeds, then
 * the chainparams onionSeeds) plus any known zcl23 .onion peers, harvesting
 * their advertised clearnet IPs into addrman. Used by the peer_floor_violated
 * remedy when outbound count has collapsed to zero: a recovering/partitioned
 * node MUST still find a supplier without a human. Blocking (per-seed 60s);
 * call only from a dedicated discovery/condition thread, never a hot path.
 * No-op in -connect mode or when Tor is not ready. Safe from any thread. */
void connman_kick_onion_seeds(struct connman *cm);

/* Resolve one operator-selected v3 onion through /directory.json, add every
 * advertised numeric endpoint to the persistent addnode set, and schedule an
 * immediate P2P dial. Unlike the background seed pass, this explicit path is
 * allowed in -connect mode so isolated/devfleet nodes can use Tor rendezvous
 * without opening the general seed universe. Returns endpoints scheduled,
 * 0 when the directory carried none, or -1 on validation/fetch failure. */
int connman_add_onion_seed(struct connman *cm, const char *onion);

void connman_set_onion_peer_discovery(struct connman *cm,
                                      const char *datadir,
                                      onion_peer_discover_fn discover);

void connman_set_known_zcl23_peer_source(
    struct connman *cm,
    connman_known_zcl23_peers_fn peers,
    void *ctx);

size_t connman_get_node_count(const struct connman *cm);

/* Count of outbound peers in PEER_HANDSHAKE_COMPLETE or later that also
 * advertise NODE_NETWORK. Used by the sync watchdog to distinguish
 * slot-burning peers from peers actually able to serve us blocks. */
size_t connman_outbound_healthy_count(struct connman *cm);

/* Total peers (inbound + outbound) currently in PEER_HANDSHAKE_COMPLETE or
 * later and not marked for disconnect. Distinct from
 * connman_outbound_healthy_count (outbound + NODE_NETWORK only): this is the
 * whole handshaked-peer population the omniscience surface reports. */
size_t connman_handshaked_peer_count(struct connman *cm);

/* The connection manager's address table (peers.dat), READ-only for the
 * network crawler seed. Returns NULL for a NULL connman. */
struct addr_man *connman_addrman(struct connman *cm);

/* Time-to-first-handshaked-peer telemetry. connman_start() stamps a monotonic
 * epoch; the FIRST fully-handshaked peer (any direction) records now-epoch.
 * connman_time_to_first_peer_us() returns that delta in microseconds, or 0 if
 * no peer has completed a handshake yet.
 * connman_note_first_handshaked_peer() is the single record hook (called from
 * peer_lifecycle_note_handshake_complete): idempotent (only the first
 * post-epoch call records) and a no-op before connman_start() has run. */
int64_t connman_time_to_first_peer_us(void);
void    connman_note_first_handshaked_peer(void);

/* After a completed handshake, drop inbound sockets from the same remote IP
 * when a handshaked outbound already owns that host. Operator-local and
 * feeler sockets are left alone. Mixed inbound+outbound to one host splits
 * getheaders and trips peer-stability attention. */
void connman_evict_same_ip_inbound_when_outbound(struct connman *cm,
                                                 struct p2p_node *node);

/* Return the highest starting_height among handshaked, non-disconnecting
 * NODE_NETWORK peers, or -1 if no usable block-serving peer is present. */
int connman_max_peer_height(struct connman *cm);
void connman_get_outbound_health(struct connman *cm,
                                 struct connman_outbound_health *out);
void connman_get_message_cycle_stats(
    struct connman *cm,
    struct connman_message_cycle_stats *out);

/* Watchdog gate for the two scheduler loops owned by connman. Not-started
 * instances are fresh; a started loop must have progressed within max_age_us. */
bool connman_runtime_progress_fresh(struct connman *cm, int64_t max_age_us);
int connman_force_outbound_rotation(struct connman *cm, const char *reason);

void connman_relay_transaction(struct connman *cm,
                                const struct uint256 *txid);

/* Announce a newly-accepted block to every handshaked peer by pushing a
 * MSG_BLOCK inv (the counterpart to connman_relay_transaction). A node that
 * mints or accepts a new tip out-of-band — a locally-mined block (regtest
 * `generate`) or an externally-submitted one (`submitblock`) — never travels
 * the P2P block-receive relay path in msg_blocks.c, so without this the tip
 * stays invisible to already-connected peers until they independently re-query.
 * Bounded: one inv per peer, filtered by each peer's known-inventory set
 * (p2p_node_push_inventory), so a repeated announce of the same hash is a
 * no-op and there is no announce storm. Peers respond with getheaders/getdata
 * and fetch the block themselves. */
void connman_relay_block(struct connman *cm,
                         const struct uint256 *hash);

/* one pass of the message-handler loop body.
 *
 * Snapshots cm->manager.nodes[] under cs_nodes + bumps ref_count on each
 * non-disconnected entry, releases cs_nodes, calls the process_messages
 * and send_messages signals against the local copy, then re-acquires
 * cs_nodes to decrement refs. Returns true if any peer saw work.
 *
 * Exposed outside the message thread so the stress test can drive
 * the cycle directly without needing to stand up a full connman_start(). */
bool connman_run_message_cycle(struct connman *cm);

/* Wake the message-handler thread so queued outbound work (for example
 * timeout-requeued block downloads) is dispatched immediately instead of
 * waiting for the idle poll interval. Safe to call from service threads. */
void connman_wake_message_handler(struct connman *cm);

/* one pass of the socket-handler deferred-free sweep.
 *
 * Walks cm->deferred_free[], freeing entries whose ref_count has reached
 * zero and re-parking any that are still held by an in-flight snapshot.
 * Caller must hold cm->manager.cs_nodes. Exposed for the stress test. */
void connman_run_deferred_free_sweep(struct connman *cm);

bool connman_pick_next_outbound_target(
    struct connman *cm,
    size_t *addnode_cursor,
    struct addr_info *result,
    enum connman_outbound_target_source *source,
    size_t *addnode_index);

/* One outbound dial target chosen for a parallel batch. */
struct connman_dial_candidate {
    struct net_address                   addr;
    enum connman_outbound_target_source  source;
    size_t                               addnode_index; /* only for ADDNODE */
    bool                                 is_feeler;      /* transient probe */
};

/* Gather up to `max` (clamped to MAX_OUTBOUND_CONNECTIONS) distinct outbound
 * dial candidates for one non-blocking batch, in PRIORITY order:
 *   1. un-tried persisted anchors (each dialed once, marked tried), then
 *   2. a chain-bound DHT endpoint hint, then
 *   3. database-discovered ZCL23 peers on alternating scheduler turns, then
 *   4. addnode / addrman via connman_pick_next_outbound_target.
 * Every candidate passes the same per-candidate gates the serial dialer used
 * (reachable port, not already connected, not is_local, /16+/32+onion
 * diversity), PLUS an in-batch dedupe + diversity tally so a single batch
 * cannot itself breach a diversity cap. Returns the number written to `out`.
 * Exposed so the anchors-before-addrman ordering is unit-testable. */
size_t connman_gather_dial_candidates(struct connman *cm,
                                      struct connman_dial_candidate *out,
                                      size_t max);

#ifdef ZCL_TESTING
/* Regression seam for the owned discovery-thread shutdown wait. A nominally
 * long cadence must observe connman_signal_stop() within one 100ms slice. */
bool connman_wait_for_stop_for_test(int seconds);
void connman_set_stop_for_test(bool stop);
/* Pure form of the -connect idle gate. A pending chain-bound DHT hint must
 * keep the dialer awake even after every explicit addnode has a connection. */
bool connman_connect_only_wait_needed_for_test(bool connect_only,
                                               size_t outbound,
                                               size_t addnode_count,
                                               bool dht_hint_pending);
bool connman_outbound_rate_allowed_for_test(bool below_floor,
                                            bool interval_elapsed,
                                            bool dht_hint_pending);
int connman_addrman_retry_cooldown_for_test(int attempts);
#endif

/* Snapshot the currently healthy (handshaked, NODE_NETWORK, non-disconnecting,
 * non-feeler) outbound peers into `set` (capped at ANCHOR_PEERS_MAX). This is
 * what gets persisted to anchors.dat. Exposed for tests. */
void connman_collect_healthy_anchors(struct connman *cm,
                                     struct anchor_peer_set *set);

/* addnode reconnection backoff trio. All three stamp
 * addnode_last_attempt[i] with wall time so the dialer's cooldown can
 * pace retries.
 *
 * record_addnode_attempt(success=true) clears addnode_backoff_sec[i] and
 * both failure counters to 0 (a live connection forgives past failures);
 * success=false forwards to record_addnode_failure with a TCP kind. */
void connman_record_addnode_attempt(struct connman *cm,
                                    size_t addnode_index,
                                    bool success);
/* Bumps the per-kind failure counter (addnode_tcp_failures[i] or
 * addnode_protocol_failures[i]) and sets addnode_backoff_sec[i] from a
 * gentle early ramp keyed on that count: 20 -> 60 -> 120 -> 300 -> 600 ->
 * 1200 -> 1800s (capped). A PROTOCOL failure starts one ramp step ahead of
 * a TCP failure (so PROTOCOL > TCP for the same count). A single transient
 * failure costs ~20s — not an instant 900s lockout — so a momentarily-flaky
 * but reachable peer is re-dialed in time to fill the outbound floor, while
 * a persistently-dead host still reaches the 1800s ceiling after ~6-7
 * consecutive misses. */
void connman_record_addnode_failure(struct connman *cm,
                                    size_t addnode_index,
                                    enum connman_addnode_failure_kind kind);
/* Charges a PROTOCOL failure (which on the FIRST miss backs off ~60s and
 * ramps to the 1800s ceiling — see record_addnode_failure) when an addnode
 * peer drops before the handshake completes. No-op for inbound,
 * already-handshaked, or non-addnode nodes. */
void connman_note_addnode_prehandshake_disconnect(
    struct connman *cm,
    const struct p2p_node *node,
    const char *reason);

/* RETIRE: scan every addnode and retire (exclude from dial rotation) any
 * whose failure streak has crossed BOTH ZCL_ADDNODE_RETIRE_MIN_TCP_FAILURES
 * and ZCL_ADDNODE_RETIRE_MIN_WINDOW_SECS. `outbound_healthy` is the
 * caller's current healthy-outbound count (connman_outbound_healthy_count());
 * when it is below ZCL_PEER_FLOOR_HEALTHY (net/net.h, the single source of
 * truth) this is a no-op — never burn one of the last few dial-of-last-resort
 * targets while the node is already starved for peers. Idempotent (already-
 * retired entries are skipped) and cheap (O(MAX_ADDNODES), no I/O), so it is
 * safe to call every open-connections loop iteration. Exposed for the
 * retirement/floor-guard/revival unit tests. */
void connman_retire_dead_addnodes(struct connman *cm, size_t outbound_healthy);

/* HARVEST: pull up to ZCL_ADDNODE_HARVEST_MAX_CANDIDATES rows from the
 * durable network census (<datadir>/peers_projection.db node_census, via the
 * read-only lib/storage/src/census_read.c reader) that have a positive
 * dial_success_count AND a last_success within
 * ZCL_ADDNODE_HARVEST_RECENT_SUCCESS_SECS, and feed each one into addrman via
 * addrman_add() — the NEW-table discovery path, NOT the pinned addnode list.
 * addrman's own bucket/group diversity caps apply exactly as they do to any
 * other addrman_add() call. `min_height` is an optional "height near tip"
 * filter (node_census.last_reported_height >= min_height); pass -1 for no
 * height filter (connman itself does not track chain height — a caller that
 * does, e.g. a sync service, may pass its own tip-relative floor). Best-
 * effort and fail-open: an absent/unpopulated census store is a silent no-op,
 * never an error (the crawler may simply not have run yet). Returns the
 * number of rows actually added to addrman. Exposed for the harvest unit
 * test (fixture census DB) and for a caller that wants to force a pull
 * outside the ZCL_ADDNODE_HARVEST_INTERVAL_SECS cadence the open-connections
 * loop applies to its own automatic calls. */
size_t connman_harvest_census_candidates(struct connman *cm,
                                         int64_t min_height);

#endif

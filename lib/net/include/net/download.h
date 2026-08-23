/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block download manager — coordinates parallel block downloads across
 * multiple peers during IBD. Prevents duplicate requests, enforces
 * timeouts, reassigns stalled blocks, and tracks per-peer performance.
 *
 * Architecture:
 *   - Single global instance (g_download_mgr), mutex-protected
 *   - Hash table of in-flight blocks: hash → (peer_id, request_time)
 *   - Sliding window: max N blocks in-flight per peer
 *   - Timeout: blocks not received within T seconds get reassigned
 *   - Stats: per-peer blocks received, latency, failures
 */

#ifndef ZCL_DOWNLOAD_H
#define ZCL_DOWNLOAD_H

#include "core/uint256.h"
#include "util/sync.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Tuning constants — conservative (at-tip) defaults.
 * During IBD, use dl_get_*() functions which return catch-up values.
 * IBD per-peer and timeout used to stay at the at-tip 128 / 15 s pair;
 * a 15 s reassign on a 128-deep WAN window stamped DL_PEER_AVOID_COOLDOWN
 * on the only peer and parked GETDATA. IBD keeps Equihash / scripts /
 * proofs; it only holds the request window open long enough to fill. */
#define DL_MAX_IN_FLIGHT_PER_PEER 128    /* max concurrent block requests per peer (at tip) */
#define DL_MAX_IN_FLIGHT_PER_PEER_IBD 256 /* max concurrent block requests per WAN peer (IBD) */
#define DL_MAX_IN_FLIGHT_PER_LOOPBACK 512 /* loopback bypasses WAN-fairness ceiling */
#define DL_MAX_IN_FLIGHT_TOTAL    1024   /* max total in-flight blocks (at tip) */
#define DL_MAX_IN_FLIGHT_TOTAL_IBD 4096  /* max total in-flight blocks (during IBD) */
#define DL_REQUEST_TIMEOUT_SECS   30     /* reassign after this many seconds (at tip) */
#define DL_REQUEST_TIMEOUT_SECS_IBD 45   /* reassign after this many seconds (during IBD) */
#define DL_STALL_TIMEOUT_SECS     120    /* disconnect peer after this */
#define DL_WINDOW_SIZE            512    /* blocks to request per batch */
#define DL_MAX_TRACKED_PEERS      512    /* above connman's <=200 live peers;
                                          * leaves churn/cache headroom */
#define DL_PEER_AVOID_COOLDOWN_SECS 30   /* temporarily avoid a peer after a
                                          * block request timeout */
#define DL_TIP_BIAS_RESERVE 64           /* S2.3: count of the lowest-height
                                          * (tip-adjacent, most-urgent) queue
                                          * entries preferentially reserved for
                                          * a peer whose bandwidth_score is
                                          * >=2x a slower requester's. A slower
                                          * peer skips past this reserve only
                                          * when something eligible exists
                                          * beyond it; it falls back INTO the
                                          * reserve immediately when the queue
                                          * is shallower or nothing else is
                                          * eligible, so a slow peer is never
                                          * starved (bias, not partition). */
#define DL_MAX_HISTORY_IN_FLIGHT 16       /* background history is subordinate
                                          * to tip-advancing forward work */
#define DL_MAX_HISTORY_PER_PEER 2         /* keep any one peer from becoming a
                                          * history-only bottleneck */

/* Work classes are part of the download manager's scheduling contract.
 * Forward work always wins assignment; history uses its own bounded lane. */
enum dl_work_class {
    DL_WORK_FORWARD = 0,
    DL_WORK_HISTORY = 1,
};

/* Dynamic limits — return catch-up values during IBD, conservative at tip.
 * These check sync_get_state() internally. Thread-safe. */
size_t dl_get_max_in_flight_total(void);
size_t dl_get_max_in_flight_per_peer(void);
int    dl_get_request_timeout_secs(void);

/* Per-block in-flight entry */
struct dl_in_flight {
    struct uint256 hash;
    int32_t        height;          /* -1 if unknown */
    uint32_t       peer_id;
    int64_t        request_time;    /* seconds since epoch */
    enum dl_work_class work_class;
    bool           active;          /* true if slot in use */
};

/* Queued-hash membership entry (open addressing). state: 0 = virgin
 * (probe-chain terminator), 1 = live, 2 = tombstone (deleted; probe
 * continues through it). */
struct dl_queued_key {
    struct uint256 hash;
    uint8_t        state;
};

/* Per-peer download stats */
struct dl_peer_stats {
    uint32_t peer_id;
    uint32_t blocks_requested;
    uint32_t blocks_received;
    uint32_t blocks_timed_out;
    int64_t  last_body_received_time; /* wall-clock epoch seconds of the most
                                       * recent block body credited to this
                                       * peer; 0 until the first body arrives.
                                       * Feeds the delivered-then-dark body-
                                       * stall rule (dl_peer_body_staleness ->
                                       * syncsvc_should_disconnect_body_dark_peer):
                                       * a peer that delivered >=1 body and then
                                       * went silent lets this cursor go stale
                                       * while blocks_received stays > 0, the
                                       * exact case Rule C exempts. */
    int64_t  avg_delivery_us;       /* rolling average delivery time (EWMA) */
    uint32_t bandwidth_score;       /* adaptive score: higher = faster peer */
    bool     active;
    bool     is_loopback;           /* K2: peer at 127.0.0.0/8 or ::1; gets
                                     * DL_MAX_IN_FLIGHT_PER_LOOPBACK window
                                     * and bypasses bandwidth-score scaling */
    uint64_t zero_assign_generation; /* dependency generation of the most
                                      * recent parkable zero-result attempt */
    int64_t  zero_assign_retry_after; /* cooldown deadline; 0 means wait only
                                       * for the relevant generation to move */
    size_t   zero_assign_global_limit;
    int      zero_assign_result;
};

/* Cheap operator/AI diagnostics over the current in-flight set. Sentinel
 * values when no request is in flight:
 *   oldest_in_flight_age_seconds = -1
 *   oldest_in_flight_height      = -1
 *   oldest_in_flight_peer_id     = 0
 */
struct dl_diagnostics {
    int     request_timeout_seconds;
    int64_t oldest_in_flight_age_seconds;
    int32_t oldest_in_flight_height;
    uint32_t oldest_in_flight_peer_id;
    uint64_t overdue_in_flight;
    uint64_t in_flight_peer_count;
    uint64_t queue_peer_avoid_count;
    int64_t  queue_peer_avoid_max_seconds;
    uint64_t queued_forward;
    uint64_t queued_history;
    uint64_t in_flight_forward;
    uint64_t in_flight_history;
    uint64_t assign_attempts;
    uint64_t assign_successes;
    uint64_t assign_zero_results;
    uint32_t last_assign_peer_id;
    uint64_t last_assign_max_requested;
    uint64_t last_assign_available;
    uint64_t last_assign_assigned;
    uint64_t last_assign_queue_len;
    uint64_t last_assign_active;
    uint64_t last_assign_peer_in_flight;
    uint64_t last_assign_peer_limit;
    uint64_t last_assign_global_limit;
    int      last_assign_result;

    /* Reason-specific dependency generations for zero-result parking. */
    uint64_t queue_generation;
    uint64_t capacity_generation;
    uint64_t total_orphaned;    /* requests settled without a body:
                                 * disconnect-requeue + backpressure drain */
    int64_t  accounting_drift;  /* requested - received - timed_out -
                                 * orphaned - in_flight; 0 unless a settle
                                 * path leaked (each leaked request once
                                 * latched download_queue_starved forever) */
};

enum dl_assign_result {
    DL_ASSIGN_NONE = 0,
    DL_ASSIGN_ASSIGNED,
    DL_ASSIGN_NO_QUEUE,
    DL_ASSIGN_MAX_ZERO,
    DL_ASSIGN_PEER_WINDOW_FULL,
    DL_ASSIGN_GLOBAL_WINDOW_FULL,
    DL_ASSIGN_HISTORY_THROTTLED,
    DL_ASSIGN_NO_SLOT,
    DL_ASSIGN_PEER_AVOID_COOLDOWN,
};

const char *dl_assign_result_name(int result);

/* Download manager — global singleton */
struct download_manager {
    zcl_mutex_t cs;

    /* In-flight hash table (open addressing, power-of-2 size) */
    struct dl_in_flight *slots;
    size_t               num_slots;     /* capacity (power of 2) */
    size_t               num_active;    /* current in-flight count */

    /* Per-peer stats */
    struct dl_peer_stats peers[DL_MAX_TRACKED_PEERS];
    size_t               num_peers;

    /* Download window: blocks we need but haven't requested yet */
    struct uint256      *queue;         /* block hashes to download */
    int32_t             *queue_heights; /* corresponding heights */
    uint32_t            *queue_avoid_peers; /* peer to avoid temporarily */
    int64_t             *queue_avoid_until; /* epoch seconds; 0 = inactive */
    enum dl_work_class  *queue_classes; /* logical forward/history lanes */
    size_t               queue_len;
    size_t               queue_cap;

    /* Membership set over `queue` (open addressing, power-of-2 size,
     * load < 50%). Makes the "already queued?" check O(1); the old
     * per-item linear scan was O(queue_len) and, with the queue pinned
     * at its 65536 cap during deep IBD, turned every bulk enqueue into
     * an O(n^2) grind that held `cs` for minutes and starved every
     * other thread touching the manager. */
    struct dl_queued_key *qset;
    size_t                qset_slots;   /* capacity (power of 2) */
    size_t                qset_live;    /* live entries == queue_len */
    size_t                qset_tombs;   /* tombstoned entries */

    /* Global stats. Settle invariant: every total_requested increment is
     * matched by exactly one of total_received / total_timed_out /
     * total_orphaned, or the request is still in a live slot (num_active).
     * A path that deactivates a slot without settling breaks the identity
     * and shows up as nonzero accounting_drift in dl_get_diagnostics(). */
    uint64_t total_requested;
    uint64_t total_received;
    uint64_t total_timed_out;
    uint64_t total_orphaned;        /* settled by disconnect-requeue or
                                     * backpressure drain (no body, no
                                     * timeout) */
    uint64_t total_duplicate;
    uint64_t total_queue_evicted;   /* high-height entries displaced at cap */
    uint64_t total_queue_rejected;  /* pushes refused at cap (not lower
                                     * than the current tail) */

    /* Last assignment attempt telemetry. These fields let the agent
     * distinguish "message pump never tried" from "tried but peer/global
     * windows rejected the work" without tailing logs. */
    uint64_t assign_attempts;
    uint64_t assign_successes;
    uint64_t assign_zero_results;
    uint32_t last_assign_peer_id;
    uint64_t last_assign_max_requested;
    uint64_t last_assign_available;
    uint64_t last_assign_assigned;
    uint64_t last_assign_queue_len;
    uint64_t last_assign_active;
    uint64_t last_assign_peer_in_flight;
    uint64_t last_assign_peer_limit;
    uint64_t last_assign_global_limit;
    int      last_assign_result;
    uint64_t queue_generation;
    uint64_t capacity_generation;

    /* Byte throughput tracking */
    uint64_t total_bytes_received;   /* total block bytes downloaded */
    int64_t  sync_start_time;        /* epoch seconds when first block received */

    /* Epoch seconds of the most recent event that force-cleared an
     * in-flight slot WITHOUT the body ever arriving — either
     * dl_drain_for_backpressure() (tip-stall backpressure) or
     * dl_check_timeouts() reassigning a slow peer's request to someone
     * else. 0 if neither has ever happened. Both leave the exact same
     * trace as "never requested": the slot's `active` flag goes false,
     * so a legitimately-requested block body that arrives late (the
     * original peer was just slow, or we were under backpressure) is
     * indistinguishable from a truly unsolicited push by inspecting the
     * hash alone — dl_mark_received() returns 0 for both. See
     * dl_last_forced_settle_time() / the PEER_OFFENCE_UNREQUESTED
     * call-site in msg_blocks.c, which withholds scoring for
     * DL_STALL_TIMEOUT_SECS after either event rather than risk
     * banning an honest-but-slow peer. */
    int64_t  last_forced_settle_time;
};

/* Initialize the download manager. Call once at startup. */
void dl_init(struct download_manager *dm);

/* Free all resources. */
void dl_free(struct download_manager *dm);

/* Check if a block is already in-flight (requested from any peer). */
bool dl_is_in_flight(struct download_manager *dm, const struct uint256 *hash);

/* Mark a block as requested from a specific peer.
 * Returns false if already in-flight or table full. */
bool dl_mark_requested(struct download_manager *dm,
                       const struct uint256 *hash, int32_t height,
                       uint32_t peer_id);

/* Mark a block as received (remove from in-flight).
 * Returns the peer_id that requested it, or 0 if not found. */
uint32_t dl_mark_received(struct download_manager *dm,
                          const struct uint256 *hash);

/* Check for timed-out requests. Returns number of blocks reassigned.
 * Timed-out blocks are moved back to the download queue.
 * Call periodically from send_messages. */
size_t dl_check_timeouts(struct download_manager *dm, int64_t now);

/* Get number of in-flight blocks for a specific peer. */
size_t dl_peer_in_flight(struct download_manager *dm, uint32_t peer_id);

/* Per-peer body-download progress snapshot (any out-pointer may be NULL).
 * `requested` = block getdata slots assigned to this peer, `received` =
 * bodies it delivered, `timed_out` = its requests that expired unfilled.
 * Zeroes every out-pointer when the peer is untracked. Used by the
 * body-download stall discipline to fail over off a peer that accepts
 * getdata but never returns a block body. Thread-safe. */
void dl_peer_body_progress(struct download_manager *dm, uint32_t peer_id,
                           uint64_t *requested, uint64_t *received,
                           uint64_t *timed_out);

/* Delivered-then-dark staleness snapshot — the complement of
 * dl_peer_body_progress(). Reports `received` (bodies this peer delivered),
 * `timed_out` (its getdata requests that expired unfilled), and
 * `last_body_time` (wall-clock epoch seconds of the most recent block body
 * credited to it; 0 if it never delivered one). The body-download stall
 * discipline feeds these to syncsvc_should_disconnect_body_dark_peer() to
 * fail over off a peer that delivered >=1 body and THEN went silent — the
 * case syncsvc_should_disconnect_body_stalled_peer() (Rule C) deliberately
 * exempts. Any out-pointer may be NULL; all are zeroed when the peer is
 * untracked. Thread-safe. */
void dl_peer_body_staleness(struct download_manager *dm, uint32_t peer_id,
                            uint64_t *received, uint64_t *timed_out,
                            int64_t *last_body_time);

/* Handle peer disconnect — re-queue all in-flight blocks from this peer.
 * Call from connman when a peer is disconnected. Returns count re-queued. */
size_t dl_peer_disconnected(struct download_manager *dm, uint32_t peer_id);

/* Settle ONE named block that a peer answered `notfound`, re-queueing just
 * that hash (with the usual per-peer avoid deadline so the same peer is not
 * immediately re-asked for it). Returns 1 if a matching active slot was
 * settled, 0 if there was none.
 *
 * WHY THIS EXISTS AS A SEPARATE ENTRY POINT. `notfound` used to be handled by
 * calling dl_peer_disconnected() once per missing block, which is a whole-peer
 * action: it requeues and orphans EVERY in-flight request to that peer and
 * marks its dl_peer_stats inactive. One block the peer happens not to have
 * therefore threw away the entire in-flight window — up to
 * dl_get_max_in_flight_total() requests — and did it again for each item in a
 * multi-entry notfound. On a single-peer client (`-connect=HOST:PORT`, which
 * is exactly what the C3 cold-start stopwatch runs) there is no "another peer"
 * to re-ask, so the requeue bought nothing and the collateral damage was total.
 *
 * The stall is worse than the wasted requests, because every re-queued hash is
 * stamped with dl_peer_avoid_deadline() — a DL_PEER_AVOID_COOLDOWN_SECS (30 s)
 * "do not ask this peer" mark. Dumping the window therefore told the client to
 * avoid its ONLY peer for the next 30 s across ~500 blocks at the queue front,
 * so body arrival flatlined until the cooldown expired, then flatlined again on
 * the next notfound.
 *
 * Measured on the C3 stopwatch 2026-07-30, two independent 600 s runs against
 * one serving peer (dumpstate sync_monitor + node.log notfound lines):
 *   run 1: requested=33728 received=4797 timed_out=12032 in_flight=0
 *          -> 16899 ORPHANED (50.1%) over 35 notfound blocks = 483 each
 *   run 2: requested=42816 received=8060 timed_out=12544 in_flight=512
 *          -> 21700 ORPHANED (50.7%) over 57 notfound blocks = 381 each
 * (orphans derived from the requested-vs-settled identity documented on the
 * stats fields above). Orphaning was the single largest loss bucket in both
 * runs, and ~400-500 per notfound is the whole live in-flight window each time.
 * Observed body arrival over loopback in that state: ~1.5 blocks/s with
 * multi-minute flatlines, while the reducer's body_fetch stage sat idle with
 * blocked_count=0 and error_count=0 — nothing downstream of the wire was the
 * constraint. */
size_t dl_mark_notfound(struct download_manager *dm, uint32_t peer_id,
                        const struct uint256 *hash);

/* Block-swarm sibling of dl_peer_disconnected: event-driven requeue of any
 * BitTorrent-style block pieces the disconnecting peer had in flight in the
 * process-global g_block_swarm coordinator (lib/net/src/msgprocessor_snapshot.c).
 * Without this, a dead peer's in-flight pieces stay CHUNK_INFLIGHT — no other
 * peer can claim them — until the 8 s BLOCK_PIECE_TIMEOUT sweep. Called from
 * connman's disconnect cleanup right after dl_peer_disconnected. A no-op
 * (returns 0) when no block swarm is active. Returns pieces re-queued. */
size_t mp_block_swarm_peer_disconnected(uint32_t peer_id);

/* NET-2: current per-peer EWMA bandwidth score (0..255, 0 = none measured).
 * Read at session close to bank the peer's final reputation. */
uint32_t dl_peer_bandwidth_score(struct download_manager *dm, uint32_t peer_id);

/* NET-2: seed a peer's INITIAL bandwidth score from banked reputation (only if
 * unmeasured — never overrides a live score), so a known-fast peer starts at
 * its historical download window instead of the minimum. Bounded to 0..255. */
void dl_peer_seed_bandwidth_score(struct download_manager *dm,
                                  uint32_t peer_id, uint32_t score);

/* Add blocks to the download queue (blocks we need but haven't requested).
 * Deduplicates against already-in-flight and already-queued blocks. */
size_t dl_queue_blocks(struct download_manager *dm,
                       const struct uint256 *hashes,
                       const int32_t *heights,
                       size_t count);

/* Class-aware enqueue. DL_WORK_HISTORY is intrinsically capped during
 * assignment; callers do not need to reproduce scheduler limits. */
size_t dl_queue_blocks_class(struct download_manager *dm,
                             const struct uint256 *hashes,
                             const int32_t *heights,
                             size_t count,
                             enum dl_work_class work_class);

/* Push a block to the FRONT of the queue (highest priority).
 * Used by reducer activation when it needs the next sequential block. */
void dl_queue_priority(struct download_manager *dm,
                       const struct uint256 *hash, int32_t height);

/* Assign queued blocks to a peer. Returns number assigned.
 * Respects dl_get_max_in_flight_per_peer() (or DL_MAX_IN_FLIGHT_PER_LOOPBACK
 * for peers flagged via dl_set_peer_loopback) and dl_get_max_in_flight_total().
 * Fills `out_hashes` with the assigned block hashes. */
size_t dl_assign_to_peer(struct download_manager *dm,
                         uint32_t peer_id,
                         struct uint256 *out_hashes,
                         size_t max_assign);

/* Cheap preflight for callers that would otherwise scan the in-flight table
 * before dl_assign_to_peer(). False means this peer already produced a
 * parkable zero result for the current dependency generation. Different
 * peers remain independently eligible, preserving multi-peer fetch. */
bool dl_assignment_should_attempt(struct download_manager *dm,
                                  uint32_t peer_id);

/* K2: mark a peer as loopback so dl_assign_to_peer uses
 * DL_MAX_IN_FLIGHT_PER_LOOPBACK and bypasses bandwidth-score scaling.
 * Caller-set (the download manager doesn't see net addresses). Idempotent. */
void dl_set_peer_loopback(struct download_manager *dm,
                          uint32_t peer_id, bool is_loopback);

/* Update peer stats when a block is received from them. */
void dl_peer_block_received(struct download_manager *dm,
                            uint32_t peer_id, int64_t delivery_us);

/* Get download stats for RPC/diagnostics. */
void dl_get_stats(struct download_manager *dm,
                  uint64_t *requested, uint64_t *received,
                  uint64_t *timed_out, uint64_t *in_flight,
                  uint64_t *queued);

/* Get in-flight age/overdue diagnostics for RPC/agent telemetry. */
void dl_get_diagnostics(struct download_manager *dm,
                        struct dl_diagnostics *out);

/* Record block bytes received (call from process_block_msg). */
void dl_add_bytes_received(struct download_manager *dm, uint64_t bytes);

/* Get byte throughput stats. */
void dl_get_throughput(struct download_manager *dm,
                       uint64_t *total_bytes, double *mbps_avg);

/* Get the adaptive per-peer window size based on bandwidth score.
 * Fast peers get up to dl_get_max_in_flight_per_peer(); slow peers get fewer.
 * Returns 0 if peer not found. */
size_t dl_peer_adaptive_window(struct download_manager *dm, uint32_t peer_id);

/* Global download manager accessor (initialized by msg_processor_init). */
struct download_manager *msg_get_download_mgr(void);

/* drain the queue + in-flight tracking under tip-stall
 * backpressure. Returns the number of (queued + in-flight) entries
 * dropped. Block bodies that arrive after the drain are no longer
 * tracked — dl_mark_received returns 0 — and are freed by the
 * normal net_message_free / block_already_seen paths. The header
 * chain in main_state is untouched. Safe to call from any thread. */
size_t dl_drain_for_backpressure(struct download_manager *dm);

/* Epoch seconds of the last forced settle-without-body event (backpressure
 * drain OR timeout reassignment), or 0 if neither has ever happened. See
 * the field comment on download_manager::last_forced_settle_time. */
int64_t dl_last_forced_settle_time(struct download_manager *dm);

#endif /* ZCL_DOWNLOAD_H */

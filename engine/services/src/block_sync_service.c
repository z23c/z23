/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

// one-result-type-ok:planner-decision-out-structs
//
// This is a pure sync planner. Every syncsvc_* entry that decides anything
// fills a domain decision OUT-STRUCT (sync_getheaders_action,
// sync_block_assignment, sync_block_batch, sync_block_acceptance,
// sync_progress_snapshot, sync_stall_recovery, sync_next_block_download)
// and the failure/why context travels IN that struct (e.g.
// sync_next_block_download.reason[]). The bool returns are non-fallible
// "should I act" PREDICATES whose richer reasoning already lives in the
// out-struct (build_stall_recovery / queue_next_block_download /
// should_warn_tip_stale); the enum return (syncsvc_recovery_header_anchor)
// is a pure mapping. No bare-bool strips a lost failure reason — the null/
// arg failures in build_stall_recovery log via LOG_FAIL. The coherent result
// type of this file is "a planned decision out-struct". Behavior bit-for-bit.

#include "platform/time_compat.h"
#include "sync/sync_planner.h"
#include "util/pprev_walk.h"
#include "net/download.h"
#include "net/net.h"
#include "services/sync_benchmark_service.h"
#include "validation/main_state.h"
#include "validation/process_block.h"
#include "consensus/params.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"

static int64_t g_last_stall_log = 0;
static int64_t g_last_stall_reset = 0;
static int64_t g_last_stale_warn = 0;

/* zcl.sync_benchmark.v1 one-shot guards. Each flips exactly once per process
 * (matching sync_benchmark_init's per-boot arming in boot.c): the two
 * *_begun flags stamp SYNC_BENCH_TAIL_DOWNLOAD / SYNC_BENCH_TAIL_FOLD on
 * their first real call, and g_sb_sovereign_recorded gates the terminal
 * mark_sovereign + write_receipt(complete=true) pair in
 * syncsvc_collect_progress so a receipt is never written more than once nor
 * before the reducer frontier genuinely reaches the peer-agreed tip. */
static atomic_bool g_sb_tail_download_begun = false;
static atomic_bool g_sb_tail_fold_begun = false;
static atomic_bool g_sb_sovereign_recorded = false;

/* One-shot begin helpers (kept out of their callers to hold the callers'
 * cyclomatic complexity under cap — each of these adds exactly one new
 * branch, and the callers already sit at the ratchet). */
static void sb_begin_tail_download_once(void)
{
    bool expected = false;
    if (atomic_compare_exchange_strong(&g_sb_tail_download_begun, &expected,
                                       true))
        sync_benchmark_phase_begin(SYNC_BENCH_TAIL_DOWNLOAD);
}

static void sb_begin_tail_fold_once(void)
{
    bool expected = false;
    if (atomic_compare_exchange_strong(&g_sb_tail_fold_begun, &expected,
                                       true))
        sync_benchmark_phase_begin(SYNC_BENCH_TAIL_FOLD);
}

/* Fires the terminal zcl.sync_benchmark.v1 milestone exactly once: ends
 * TAIL_DOWNLOAD/TAIL_FOLD, marks sovereignty, and writes the one
 * complete=true receipt. Called only when the caller has already confirmed
 * sync_state == SYNC_AT_TIP — the proven "reached the peer-agreed tip"
 * signal (see syncsvc_note_valid_block). */
static void sb_record_sovereign_once(void)
{
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_sb_sovereign_recorded, &expected,
                                        true))
        return;
    sync_benchmark_phase_end(SYNC_BENCH_TAIL_DOWNLOAD);
    sync_benchmark_phase_end(SYNC_BENCH_TAIL_FOLD);
    sync_benchmark_mark_sovereign();
    (void)sync_benchmark_write_receipt(true, NULL);
}

void syncsvc_plan_invalid_block_getheaders(struct sync_getheaders_action *action,
                                           enum sync_state sync_state)
{
    struct sync_getheaders_action empty = {0};

    if (!action) return;
    *action = empty;

    if (sync_state > SYNC_BLOCKS_DOWNLOAD)
        return;

    action->should_send = true;
    action->anchor = SYNC_HEADER_REQUEST_TIP;
    action->should_log = false;
}

void syncsvc_plan_block_assignment(struct sync_block_assignment *plan,
                                   const struct p2p_node *node,
                                   size_t in_flight,
                                   int our_height)
{
    struct sync_block_assignment empty = {0};
    if (!plan) return;
    *plan = empty;

    /* zcl.sync_benchmark.v1: SYNC_BENCH_TAIL_DOWNLOAD begins on this boot's
     * first block-assignment planning call — the earliest real signal that
     * tail body download has started. Fires at most once per process; ended
     * (alongside TAIL_FOLD) in syncsvc_collect_progress once the frontier
     * reaches the peer-agreed tip. */
    sb_begin_tail_download_once();

    if (!node || node->state < PEER_HANDSHAKE_COMPLETE)
        return;

    /* Don't assign block bodies to a peer we KNOW is behind — it cannot
     * hold queued (ahead-of-us) blocks, so a getdata would only burn an
     * in-flight slot until timeout instead of fetching from a strictly-
     * ahead peer. Exact analog of zclassicd FindNextBlocksToDownload
     * (main.cpp:501). Unknown-height peers (starting_height<0, e.g. the
     * mid-handshake oracle) stay eligible. Net policy only. */
    if (syncsvc_peer_is_behind(node, our_height))
        return;

    /* K2: loopback peers have a wider request window. The WAN-fairness
     * cap exists to spread block-body load across strangers — neither
     * fairness nor RTT scaling applies to a co-located zclassicd. The
     * download manager's matching per-peer cap is
     * DL_MAX_IN_FLIGHT_PER_LOOPBACK; we plan up to half of that per
     * batch so a single call doesn't saturate the window. */
    bool peer_is_loopback = net_addr_is_local(&node->addr.svc.addr);
    plan->should_assign = true;
    if (peer_is_loopback) {
        plan->max_assign = 256;
        if (in_flight > DL_MAX_IN_FLIGHT_PER_LOOPBACK / 2)
            plan->max_assign = 64;
    } else {
        /* WAN: IBD holds a deeper per-peer window (see
         * dl_get_max_in_flight_per_peer). Plan a larger GETDATA batch so
         * one send_messages tick can fill that window; at tip keep the
         * conservative 64/16 pair so relay stays polite. */
        size_t per_peer = dl_get_max_in_flight_per_peer();
        bool ibd = per_peer > DL_MAX_IN_FLIGHT_PER_PEER;
        plan->max_assign = ibd ? 128 : 64;
        if (in_flight > per_peer / 2)
            plan->max_assign = ibd ? 64 : 16;
    }
}

void syncsvc_assign_peer_blocks(struct sync_block_batch *batch,
                                struct download_manager *dm,
                                const struct p2p_node *node,
                                struct uint256 *out_hashes,
                                size_t out_cap,
                                int our_height)
{
    struct sync_block_batch empty = {0};
    struct sync_block_assignment plan;

    if (!batch) return;
    *batch = empty;

    if (!dm || !node || !out_hashes || out_cap == 0)
        return;

    /* Reject handshake/behind peers before touching the manager's in-flight
     * table. The load-sensitive plan is recomputed below after the cheap
     * eligibility-only pass. */
    syncsvc_plan_block_assignment(&plan, node, 0, our_height);
    batch->should_assign = plan.should_assign;
    if (!plan.should_assign)
        return;

    /* Keep network assignment event-driven. A peer that already returned a
     * structural zero for this exact queue/window generation stays parked;
     * another peer is independently eligible, and enqueue/receive/timeout
     * advances the manager generation. This removes the old 100 ms
     * re-scan storm without weakening multi-peer body fetch. */
    dl_set_peer_loopback(dm, (uint32_t)node->id,
                         net_addr_is_local(&node->addr.svc.addr));
    if (!dl_assignment_should_attempt(dm, (uint32_t)node->id))
        return;

    batch->in_flight_before = dl_peer_in_flight(dm, (uint32_t)node->id);
    syncsvc_plan_block_assignment(&plan, node, batch->in_flight_before,
                                  our_height);
    batch->should_assign = plan.should_assign;
    if (!plan.should_assign)
        return;

    if (plan.max_assign > out_cap)
        plan.max_assign = out_cap;
    /* K2: keep the download manager's per-peer state in sync with the
     * peer's network class so dl_assign_to_peer picks the right cap.
     * Idempotent; cheap; no harm in calling on every assignment. */
    batch->assigned = dl_assign_to_peer(dm, (uint32_t)node->id,
                                        out_hashes, plan.max_assign);
}

void syncsvc_note_valid_block(struct sync_block_acceptance *result,
                              const struct p2p_node *node,
                              enum sync_state sync_state,
                              int new_tip_height,
                              int best_header_height,
                              uint32_t new_tip_time,
                              int max_peer_height,
                              enum body_history_status body_history)
{
    struct sync_block_acceptance empty = {0};
    bool headers_caught_up = false;

    if (!result) return;
    *result = empty;
    if (!node) return;

    /* zcl.sync_benchmark.v1: SYNC_BENCH_TAIL_FOLD begins on this boot's first
     * accepted-block reducer note — the earliest real signal that tail
     * fold has started. Fires at most once per process; ended (alongside
     * TAIL_DOWNLOAD) in syncsvc_collect_progress once the frontier reaches
     * the peer-agreed tip. */
    sb_begin_tail_fold_once();

    /* Match ZClassic C++ tip detection: consider "at tip" when EITHER:
     * (a) our height >= peer's starting_height AND headers caught up, OR
     * (b) our tip's block time is within PoWTargetSpacing*2 of now
     *     (tip is recent, we're receiving blocks in real-time).
     *
     * (b) handles the edge case where peer's starting_height from
     * handshake is stale — the peer advanced while we were syncing,
     * so new_tip_height never reaches the old starting_height. */
    bool tip_is_recent = (new_tip_time > 0 &&
        (int64_t)new_tip_time > (int64_t)platform_time_wall_time_t()
            - POST_BUTTERCUP_POW_TARGET_SPACING * 2);
    bool reached_peer = (node->starting_height > 0 &&
                         new_tip_height >= node->starting_height);
    /* Guard against stale starting_height: if peers have advanced
     * 144+ blocks beyond this node's starting_height, don't use it
     * for at-tip detection — it would trigger false AT_TIP. */
    if (reached_peer && max_peer_height > 0 &&
        max_peer_height > node->starting_height + 144)
        reached_peer = false;

    if (!reached_peer && !tip_is_recent)
        return;

    headers_caught_up =
        (best_header_height >= 0 && best_header_height <= new_tip_height + 1);
    result->reached_peer_tip = true;

    /* This is the at-tip edge that actually fires on a live node:
     * msg_blocks.c turns it into sync_set_state(SYNC_AT_TIP, "caught up to
     * peer") on every accepted block, and sync_get_state() is what
     * `z23 status` prints as sync=at_tip. Gating only the timer-driven
     * evaluator in syncsvc_plan_periodic_tip_state would leave the claim
     * exactly as sayable as it was before this whole census existed.
     *
     * Same rule as there, and for the same reason: equality against
     * COMPLETE, so BODY_HISTORY_UNKNOWN — "I could not establish my own
     * coverage" — is refused exactly as hard as a known hole, and a status
     * this code has never heard of is refused too. Reaching the peer's
     * height while missing the bodies below your own tip is not being at
     * tip.
     *
     * Everything that is NOT a completeness claim still happens: peer state
     * still advances to PEER_ACTIVE below, and the node keeps syncing,
     * relaying and serving. What it loses is the right to say it is done. */
    bool history_proven = body_history_status_is_proven(body_history);

    if (history_proven &&
        (headers_caught_up || tip_is_recent) &&
        (sync_state == SYNC_BLOCKS_DOWNLOAD ||
         sync_state == SYNC_CONNECTING_BLOCKS ||
         sync_state == SYNC_REORG)) {
        result->should_set_sync_state = true;
        result->next_sync_state = SYNC_AT_TIP;
        result->should_set_flush_policy = true;
        result->should_emit_tip_updated = (sync_state != SYNC_REORG);
    }

    if (headers_caught_up &&
        (node->state == PEER_SYNCING_BLOCKS ||
         node->state == PEER_SYNCING_HEADERS)) {
        result->should_update_peer_state = true;
        result->next_peer_state = PEER_ACTIVE;
    }
}

void syncsvc_plan_periodic_tip_state(
    struct sync_tip_state_evaluation *result,
    enum sync_state sync_state,
    bool served_tip_published,
    int served_height,
    int local_height,
    int header_height,
    int peer_height,
    size_t peer_count,
    uint64_t queued,
    uint64_t in_flight,
    uint64_t intake_pending,
    enum body_history_status body_history)
{
    struct sync_tip_state_evaluation empty = {
        .target_height = -1,
        .served_gap = -1,
        .local_gap = -1,
    };
    if (!result)
        return;
    *result = empty;

    /* Only catch-up states have legal, meaningful periodic AT_TIP edges.
     * Snapshot/reorg/failure ownership must never be pre-empted by a height
     * sample taken on another thread. */
    if (sync_state != SYNC_HEADERS_DOWNLOAD &&
        sync_state != SYNC_BLOCKS_DOWNLOAD &&
        sync_state != SYNC_CONNECTING_BLOCKS)
        return;

    /* Fail closed until every authority needed by the decision exists.  In
     * particular, do not turn an isolated node AT_TIP merely because its
     * local/header heights agree with each other. */
    if (!served_tip_published || served_height < 0 || local_height < 0 ||
        served_height > local_height || header_height < local_height ||
        peer_count == 0 || peer_height < 0)
        return;

    int target = local_height;
    if (header_height > target)
        target = header_height;
    if (peer_height > target)
        target = peer_height;

    result->target_height = target;
    result->served_gap = target > served_height ? target - served_height : 0;
    result->local_gap = target > local_height ? target - local_height : 0;

    /* Height agreement is necessary and NOT sufficient. A node can match the
     * network's height while missing the bodies for almost every block below
     * its own tip — that is exactly the state this gate was added for. So the
     * body-history census has to have positively established full coverage.
     *
     * BODY_HISTORY_UNKNOWN blocks the transition just as hard as
     * BODY_HISTORY_INCOMPLETE does. A node that has not measured its own
     * coverage is not a proven-complete node, and "I could not look" must
     * never buy the same answer as "I looked and it was fine". Written as an
     * equality against COMPLETE, never as `!= INCOMPLETE`, so a new status
     * value can never leak through. That equality lives in exactly one place
     * now (body_history_status_is_proven); this is a caller, not a copy. */
    bool history_proven = body_history_status_is_proven(body_history);

    result->should_set_at_tip =
        history_proven &&
        result->served_gap <= 1 && result->local_gap <= 1 &&
        queued == 0 && in_flight == 0 && intake_pending == 0;
}

void syncsvc_collect_progress(struct sync_progress_snapshot *snapshot,
                              struct download_manager *dm,
                              enum sync_state sync_state,
                              int chain_height,
                              int header_height,
                              int64_t peer_last_block_time,
                              int64_t now_seconds)
{
    struct sync_progress_snapshot empty;
    if (!snapshot) return;
    memset(&empty, 0, sizeof(empty));
    *snapshot = empty;

    snapshot->sync_state = sync_state;
    snapshot->chain_height = chain_height;
    snapshot->header_height = header_height;

    if (dm) {
        dl_get_stats(dm,
                     &snapshot->requested,
                     &snapshot->received,
                     &snapshot->timed_out,
                     &snapshot->in_flight,
                     &snapshot->queued);
        dl_get_throughput(dm, &snapshot->total_bytes, &snapshot->mbps_avg);
    }

    snapshot->gib_received =
        (double)snapshot->total_bytes / (1024.0 * 1024.0 * 1024.0);
    snapshot->should_log_progress =
        (sync_state != SYNC_IDLE && sync_state != SYNC_AT_TIP);

    if (sync_state == SYNC_AT_TIP && peer_last_block_time > 0 &&
        now_seconds > peer_last_block_time) {
        snapshot->tip_stale_seconds = now_seconds - peer_last_block_time;
        snapshot->tip_stale = snapshot->tip_stale_seconds > 600;
    }

    /* zcl.sync_benchmark.v1: the terminal milestone. SYNC_AT_TIP is this
     * file's own proven-complete "reached the peer-agreed tip" signal (see
     * syncsvc_note_valid_block above: it requires a proven body-history
     * census, not just a height match) — the exact frontier condition the
     * instrument's honesty contract requires before it may claim sovereignty.
     * Never fabricates completion on any other sync_state. */
    if (sync_state == SYNC_AT_TIP)
        sb_record_sovereign_once();
}

/* Test-only: rearm the three one-shot zcl.sync_benchmark.v1 guards above so a
 * test binary that drives multiple independent sync scenarios through this
 * file's functions can observe each one's begin/end pair, not just the
 * first. Declared via an in-test `extern` (this file's public surface is
 * core/modules/sync/include/sync/sync_planner.h, a sealed core/ header this
 * lane does not touch) — the same pattern test_connect_tip_hot_loop_exit.c
 * and others already use for test-only hooks. */
void syncsvc_sync_benchmark_reset_for_testing(void)
{
    atomic_store_explicit(&g_sb_tail_download_begun, false,
                          memory_order_relaxed);
    atomic_store_explicit(&g_sb_tail_fold_begun, false, memory_order_relaxed);
    atomic_store_explicit(&g_sb_sovereign_recorded, false,
                          memory_order_relaxed);
}

bool syncsvc_build_stall_recovery(struct sync_stall_recovery *recovery,
                                  const struct main_state *ms,
                                  const struct p2p_node *node,
                                  uint64_t queued,
                                  uint64_t in_flight,
                                  int64_t now_seconds)
{
    struct sync_stall_recovery empty = {0};
    if (!recovery) LOG_FAIL("block_sync", "build_stall_recovery: null recovery pointer");
    *recovery = empty;

    if (!ms || !node) LOG_FAIL("block_sync", "build_stall_recovery: null ms=%d node=%d", !ms, !node);

    int our_h = active_chain_height(&ms->chain_active);
    if (queued != 0 || in_flight != 0) return false;
    if (node->starting_height <= our_h + 10) return false;
    if (node->state < PEER_HANDSHAKE_COMPLETE) return false;
    if (now_seconds - g_last_stall_log <= 10) return false;

    g_last_stall_log = now_seconds;
    recovery->should_recover = true;
    recovery->should_log = true;
    recovery->chain_height = our_h;
    recovery->next_height = our_h + 1;

    /* ONE pass over block_map gathers everything the planning below
     * needs: per-height data presence for the probe window (our_h+1..
     * our_h+10), the +1 entry counters, and the alt-candidate pool.
     * The map holds millions of entries at depth — a probe loop of up to
     * 10 full scans plus two more full scans pins a core and starves every
     * other map reader when run near a deep tip. */
    #define STALL_PROBE_WINDOW 10
    #define STALL_ALT_CANDIDATES 64
    bool have_data_at[STALL_PROBE_WINDOW] = {false};
    struct stall_candidates {
        struct block_index *descendants[STALL_ALT_CANDIDATES];
        struct block_index *fallback[STALL_PROBE_WINDOW][STALL_ALT_CANDIDATES];
        size_t fallback_count[STALL_PROBE_WINDOW];
    };
    struct stall_candidates *cand = zcl_calloc(1, sizeof(*cand), "stall cand");
    if (!cand) return true;
    struct block_index *tip = active_chain_tip(&ms->chain_active);
    size_t cand_count = 0;
    {
        size_t pi = 0;
        struct block_index *px;
        while (block_map_next(&ms->map_block_index, &pi, NULL, &px)) {
            if (!px) continue;
            int dh = px->nHeight - our_h;
            if (dh < 1) continue;
            if (dh <= STALL_PROBE_WINDOW) {
                if (dh == 1) {
                    recovery->entries_at_next++;
                    if (px->nStatus & BLOCK_FAILED_MASK) recovery->entries_failed++;
                    if (px->nStatus & BLOCK_HAVE_DATA) recovery->entries_with_data++;
                }
                if (px->nStatus & BLOCK_HAVE_DATA)
                    have_data_at[dh - 1] = true;
            }
            if (tip && dh <= 512 &&
                !(px->nStatus & BLOCK_FAILED_MASK) &&
                !(px->nStatus & BLOCK_HAVE_DATA) &&
                px->phashBlock) {
                /* Keep each possible first-gap fallback independently;
                 * data later in the map can move that gap forward. */
                if (dh <= STALL_PROBE_WINDOW &&
                    cand->fallback_count[dh - 1] < STALL_ALT_CANDIDATES)
                    cand->fallback[dh - 1][cand->fallback_count[dh - 1]++] = px;
                if (cand_count == STALL_ALT_CANDIDATES &&
                    px->nHeight >= cand->descendants[cand_count - 1]->nHeight)
                    continue;
                /* Filter BEFORE bounding the pool. Unrelated forks must
                 * not crowd out a descendant, nor deep descendants H+1. */
                struct block_index *walk = pprev_walk_until_height(
                    px, our_h, 100000, "block_sync.alt_descent");
                if (walk != tip &&
                    !(walk && walk->phashBlock && tip->phashBlock &&
                      uint256_eq(walk->phashBlock, tip->phashBlock)))
                    continue;
                size_t pos = cand_count;
                if (pos == STALL_ALT_CANDIDATES) {
                    --pos;
                } else {
                    ++cand_count;
                }
                while (pos > 0 &&
                       cand->descendants[pos - 1]->nHeight > px->nHeight) {
                    cand->descendants[pos] = cand->descendants[pos - 1];
                    --pos;
                }
                cand->descendants[pos] = px;
            }
        }
    }
    for (int probe = 1; probe <= STALL_PROBE_WINDOW; probe++) {
        if (!have_data_at[probe - 1]) {
            recovery->next_height = our_h + probe;
            break;
        }
    }

    if (!tip) {
        free(cand);
        return true;
    }

    struct uint256 *alt_hashes = zcl_calloc(64, sizeof(struct uint256), "stall recovery hashes");
    int32_t *alt_heights = zcl_calloc(64, sizeof(int32_t), "stall recovery heights");
    if (!alt_hashes || !alt_heights) {
        free(alt_hashes);
        free(alt_heights);
        free(cand);
        return true;
    }

    size_t alt_count = 0;
    for (size_t ci = 0; ci < cand_count; ci++) {
        struct block_index *alt = cand->descendants[ci];
        alt_hashes[alt_count] = *alt->phashBlock;
        alt_heights[alt_count++] = alt->nHeight;
    }

    if (alt_count == 0) {
        /* Fallback: entries at the first gap height, descent not
         * required (matches the old iter3 pass). */
        size_t gap = (size_t)(recovery->next_height - our_h - 1);
        for (size_t ci = 0; ci < cand->fallback_count[gap]; ci++) {
            struct block_index *alt = cand->fallback[gap][ci];
            alt_hashes[alt_count] = *alt->phashBlock;
            alt_heights[alt_count] = alt->nHeight;
            alt_count++;
        }
    }
    free(cand);
    #undef STALL_PROBE_WINDOW
    #undef STALL_ALT_CANDIDATES

    recovery->alt_hashes = alt_hashes;
    recovery->alt_heights = alt_heights;
    recovery->alt_count = alt_count;
    recovery->should_request_tip_parent = (tip->pprev != NULL);

    if (alt_count == 0 && now_seconds - g_last_stall_reset > 30) {
        g_last_stall_reset = now_seconds;
        recovery->should_reset_tip_next = true;
    }

    return true;
}

enum sync_header_request_anchor syncsvc_recovery_header_anchor(
    const struct sync_stall_recovery *recovery,
    const struct block_index *tip)
{
    if (!recovery || !recovery->should_recover)
        return SYNC_HEADER_REQUEST_TIP;

    if (recovery->should_request_tip_parent && tip && tip->pprev)
        return SYNC_HEADER_REQUEST_TIP_PARENT;

    return SYNC_HEADER_REQUEST_TIP;
}

void syncsvc_plan_recovery_getheaders(struct sync_getheaders_action *action,
                                      const struct sync_stall_recovery *recovery,
                                      const struct block_index *tip)
{
    struct sync_getheaders_action empty = {0};

    if (!action) return;
    *action = empty;
    if (!recovery || !recovery->should_recover)
        return;

    action->should_send = true;
    action->anchor = syncsvc_recovery_header_anchor(recovery, tip);
    action->should_log = false;
}

/* Per-peer rate limit for the all-rejected (bad-prevblk) recovery probe —
 * see SYNC_REJECT_PROBE_INTERVAL_SECS in sync_planner.h. Pure over
 * (now, last_probe) so the decision is unit-testable; the caller stamps
 * node->last_reject_probe_time when this returns true. */
bool syncsvc_should_probe_after_reject(int64_t now_seconds,
                                       int64_t last_probe_seconds)
{
    if (last_probe_seconds <= 0)
        return true;  // raw-return-ok:never-probed-is-not-an-error
    return (now_seconds - last_probe_seconds) >=
           SYNC_REJECT_PROBE_INTERVAL_SECS;
}

void syncsvc_note_header_batch_outcome(struct p2p_node *node,
                                       size_t accepted,
                                       bool any_bad_prevblk)
{
    if (!node) return;
    if (accepted > 0) {
        atomic_store_explicit(&node->reject_probe_pending, false,
                              memory_order_relaxed);
    } else if (any_bad_prevblk) {
        atomic_store_explicit(&node->reject_probe_pending, true,
                              memory_order_relaxed);
    }
}

bool syncsvc_should_fire_reject_probe(const struct p2p_node *node,
                                      int64_t now_seconds)
{
    if (!node)
        return false;  // raw-return-ok:null-peer-is-not-an-error
    if (!atomic_load_explicit(&node->reject_probe_pending,
                              memory_order_relaxed))
        return false;  // raw-return-ok:not-pending-is-not-an-error
    return syncsvc_should_probe_after_reject(now_seconds,
        atomic_load_explicit(&node->last_reject_probe_time,
                             memory_order_relaxed));
}

void syncsvc_apply_stall_recovery(const struct sync_stall_recovery *recovery,
                                  struct main_state *ms,
                                  struct download_manager *dm,
                                  int *cleared_blocks)
{
    if (cleared_blocks) *cleared_blocks = 0;
    if (!recovery || !ms) return;

    if (recovery->alt_count > 0 && dm) {
        dl_queue_blocks(dm, recovery->alt_hashes,
                        recovery->alt_heights, recovery->alt_count);
        return;
    }

    (void)cleared_blocks;
}

bool syncsvc_should_warn_tip_stale(
    const struct sync_progress_snapshot *snapshot,
    const struct p2p_node *node,
    int64_t now_seconds)
{
    if (!snapshot || !node || node->inbound || !snapshot->tip_stale)
        return false;
    if (now_seconds - g_last_stale_warn <= 300)
        return false;

    g_last_stale_warn = now_seconds;
    return true;
}

void syncsvc_plan_tip_stale_getheaders(struct sync_getheaders_action *action,
                                       const struct sync_progress_snapshot *snapshot,
                                       const struct p2p_node *node,
                                       int64_t now_seconds)
{
    struct sync_getheaders_action empty = {0};

    if (!action) return;
    *action = empty;

    if (!syncsvc_should_warn_tip_stale(snapshot, node, now_seconds))
        return;

    action->should_send = true;
    action->anchor = SYNC_HEADER_REQUEST_TIP;
    action->should_log = true;
}

void syncsvc_free_stall_recovery(struct sync_stall_recovery *recovery)
{
    if (!recovery) return;
    free(recovery->alt_hashes);
    free(recovery->alt_heights);
    recovery->alt_hashes = NULL;
    recovery->alt_heights = NULL;
    recovery->alt_count = 0;
}

/* Rule D — delivered-then-dark body-download stall (the complement of Rule C,
 * syncsvc_should_disconnect_body_stalled_peer in header_sync_service.c). Rule C
 * exempts any peer with body_received > 0, so a peer that serves a few block
 * bodies and then goes silent holds its outbound slot forever while the body
 * cursor never advances again. This lives beside the block-download planners
 * (its concern is block bodies, not headers) rather than growing the
 * header-sync file; the decision itself is pure, mirroring Rule C. See the
 * contract in sync/sync_planner.h. */
bool syncsvc_should_disconnect_body_dark_peer(const struct p2p_node *node,
                                              int our_height,
                                              uint64_t body_received,
                                              uint64_t body_timed_out,
                                              int64_t last_body_time,
                                              int64_t now_seconds)
{
    if (!node)
        return false;
    /* IBD-gated, exactly like Rule C: at/near tip a peer legitimately
     * delivers no body for long stretches (block cadence ~150s), so the
     * discipline only runs while we still NEED bodies. */
    if (!syncsvc_is_initial_block_download(node, our_height))
        return false; // raw-return-ok:IBD-gate — pure keep-peer decision, not an error
    if (node->state < PEER_HANDSHAKE_COMPLETE)
        return false;

    /* Complement of Rule C: this rule owns ONLY the delivered-then-dark
     * case. A peer that never delivered a body is Rule C's job; keying on
     * body_received > 0 here (Rule C keys on == 0) makes the two mutually
     * exclusive, so no peer is ever judged by both — no double-eviction. */
    if (body_received == 0)
        return false;

    /* Defensive: body_received > 0 implies a real body timestamp, but never
     * judge on a zero/unknown cursor. */
    if (last_body_time <= 0)
        return false;

    /* Minimum-demand floor (mirrors Rule C): only judge a peer we have
     * genuinely asked AND waited on. A peer with requests still legitimately
     * in flight has not timed them out, so it is not a deadbeat — we key on
     * timed_out, not the raw request count. */
    if (body_timed_out < SYNC_BODY_STALL_MIN_TIMEOUTS)
        return false;

    /* Genuine staleness: no body for a full stall window. */
    return (now_seconds - last_body_time) >= SYNC_BODY_STALL_TIMEOUT_SECS;
}

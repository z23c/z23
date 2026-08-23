/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

// one-result-type-ok:header-sync-planner-predicates — every remaining exported bool is a pure header-sync decision (should_/is_/peer_is_behind/headers_chain_from_tip/begin_peer_sync-declines), an ANSWER not a fallible op; the sole fallible surface (syncsvc_build_getheaders_locator, malloc/null path) is already struct zcl_result. Cf. seed_integrity_gate.c / chain_tip_watchdog.c.
#include "platform/time_compat.h"
#include "sync/sync_planner.h"
#include "net/snapshot_sync_contract.h"
#include "net/net.h"
#include "net/netaddr.h"
#include "validation/chainstate.h"
#include "validation/sync_evidence_policy.h"
#include "core/arith_uint256.h"
#include "chain/chain.h"
#include <stdlib.h>
#include <time.h>
#include <stdatomic.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"

static int g_getheaders_log_count = 0;
static bool g_block_file_scan_triggered = false;

/* Fold stale-peer backoffs into one 60s summary; atomic state keeps the
 * concurrent hot path lock-free. */
static _Atomic int64_t g_stale_window_start_unix = 0;
static _Atomic int     g_stale_window_count = 0;
static _Atomic int64_t g_stale_window_min = 0;
static _Atomic int64_t g_stale_window_max = 0;
#define STALE_SUMMARY_WINDOW_SECS ((int64_t)60)

static void syncsvc_build_locator_from_tip(struct block_locator *loc,
                                           const struct block_index *tip,
                                           const char *alloc_label,
                                           const char *realloc_label)
{
    const struct block_index *walk = tip;
    size_t alloc = 0;
    size_t idx = 0;
    int step = 1;
    int counter = 0;

    if (!loc || !tip || !tip->phashBlock)
        return;

    alloc = 32;
    loc->vhave = zcl_malloc(alloc * sizeof(struct uint256),
                            alloc_label);
    if (!loc->vhave)
        return;

    while (walk && walk->phashBlock && idx < MAX_LOCATOR_HASHES) {
        if (idx == alloc) {
            if (alloc >= MAX_LOCATOR_HASHES)
                break;
            size_t next_alloc = alloc * 2;
            if (next_alloc > MAX_LOCATOR_HASHES)
                next_alloc = MAX_LOCATOR_HASHES;
            struct uint256 *nv = zcl_realloc(loc->vhave,
                                         next_alloc * sizeof(struct uint256),
                                         realloc_label);
            if (!nv)
                break;
            loc->vhave = nv;
            alloc = next_alloc;
        }
        loc->vhave[idx++] = *walk->phashBlock;

        const struct block_index *prev = walk;
        for (int i = 0; i < step && walk; i++)
            walk = walk->pprev;
        if (walk == prev)
            break;

        /* Keep the first 12 hashes dense (step=1) for better fork
         * detection near the tip, then double every step after. */
        if (++counter > 12 && step < 1048576)
            step *= 2;
    }

    loc->num_hashes = idx;
}

void syncsvc_evaluate_header_batch(struct sync_header_batch *result,
                                   size_t accepted,
                                   uint64_t total_count,
                                   const struct block_index *last_header)
{
    struct sync_header_batch empty = {0};

    if (!result) return;
    *result = empty;

    result->should_warn_all_rejected = result->should_probe_after_reject =
        (accepted == 0 && total_count > 0);
    result->should_emit_received = (accepted > 0);
    /* ZClassic/Zcash MAX_HEADERS_RESULTS is 160, not Bitcoin's 2000.
     * Request more headers if the batch was full (peer likely has more). */
    result->should_request_more_headers =
        (accepted > 0 && total_count >= 160 &&
         last_header && last_header->phashBlock);
}

void syncsvc_plan_header_download(struct sync_header_download_plan *plan,
                                  enum sync_state sync_state,
                                  const struct block_index *candidate,
                                  const struct block_index *tip,
                                  int our_height,
                                  struct uint256 *hashes,
                                  int32_t *heights,
                                  size_t max_collect)
{
    struct sync_header_download_plan empty = {0};

    if (!plan) return;
    *plan = empty;

    if (!candidate || candidate->nHeight <= our_height)
        return;

    plan->has_candidate = true;
    plan->should_begin_blocks_download =
        syncsvc_should_begin_blocks_download(sync_state, candidate, our_height);
    syncsvc_collect_needed_blocks(&plan->needed_blocks, candidate, tip,
                                  our_height, hashes, heights, max_collect);
}

void syncsvc_plan_header_processing(struct sync_header_processing_plan *plan,
                                    size_t accepted,
                                    uint64_t total_count,
                                    const struct block_index *last_header,
                                    enum sync_state sync_state,
                                    const struct block_index *candidate,
                                    const struct block_index *tip,
                                    int our_height,
                                    struct uint256 *hashes,
                                    int32_t *heights,
                                    size_t max_collect)
{
    struct sync_header_processing_plan empty = {0};

    if (!plan) return;
    *plan = empty;

    syncsvc_evaluate_header_batch(&plan->batch, accepted, total_count,
                                  last_header);
    plan->should_scan_block_files =
        syncsvc_should_scan_block_files_after_headers(accepted, last_header);
    syncsvc_plan_header_download(&plan->download, sync_state, candidate, tip,
                                 our_height, hashes, heights, max_collect);
    plan->should_set_sync_state =
        plan->download.should_begin_blocks_download ||
        (sync_state == SYNC_HEADERS_DOWNLOAD && total_count == 0);
    if (plan->should_set_sync_state)
        plan->next_sync_state = SYNC_BLOCKS_DOWNLOAD;
    plan->should_queue_needed_blocks =
        (hashes && heights && plan->download.has_candidate &&
         plan->download.needed_blocks.count > 0);
    plan->queue_count = plan->download.needed_blocks.count;
    plan->should_activate_chain =
        plan->download.needed_blocks.should_activate_chain;
}

bool syncsvc_should_restart_headers_from_tip(size_t accepted,
                                             const struct block_index *last_header,
                                             int our_height,
                                             int peer_height,
                                             bool band_fill_in_progress)
{
    /* A frontier-extending batch below an installed-above-frontier island
     * is the band fill in progress — restarting from tip here is a
     * self-defeating loop that keeps the band hole open forever. */
    if (band_fill_in_progress)
        return false;
    if (accepted == 0 || !last_header)
        return false;
    if (last_header->nHeight >= our_height)
        return false;

    /* A far-ahead peer that answers with headers below our active tip is not
     * making sync progress. Continuing from that low header crawls the node
     * around genesis and starves the real next block after the active tip. */
    return peer_height > our_height + 100;
}

void syncsvc_build_block_file_scan_activation(
    struct sync_chain_activation *result,
    int scanned_blocks)
{
    struct sync_chain_activation empty = {0};

    if (!result) return;
    *result = empty;
    result->should_activate =
        syncsvc_should_activate_after_block_file_scan(scanned_blocks);
}

void syncsvc_build_header_processing_activation(
    struct sync_chain_activation *result,
    const struct sync_header_processing_plan *plan)
{
    struct sync_chain_activation empty = {0};

    if (!result) return;
    *result = empty;
    result->should_activate =
        syncsvc_should_activate_after_header_processing(plan);
}

bool syncsvc_should_log_accepted_headers(const struct p2p_node *node,
                                         const struct block_index *header_tip)
{
    static int headers_log_count = 0;

    if (!header_tip)
        return true;

    if (node && node->starting_height > 0 &&
        header_tip->nHeight < node->starting_height - 2000) {
        return (headers_log_count++ % 10 == 0);
    }

    return true;
}

bool syncsvc_is_initial_block_download(const struct p2p_node *node,
                                       int our_height)
{
    if (!node) return false;
    return (node->starting_height > 0 &&
            our_height < node->starting_height - 144);
}

/* Compute getheaders interval with exponential backoff for stale peers.
 * Base interval depends on sync phase; each consecutive empty header
 * response doubles the interval up to a cap of 600s.
 *
 * Stage K1: loopback peers (127.0.0.0/8, ::1) bypass the stale-backoff
 * entirely. A co-located zclassicd on the same machine is unspoofable
 * by definition — the throttle exists to protect against remote peers
 * that return short header batches as a slow-loris vector. There's no
     * evidence downgrade vs the existing model. With ZClassic's MAX_HEADERS_RESULTS
 * of 160, a 14K-block catch-up via P2P getheaders takes ~88 rounds —
 * keeping the loopback peer at base interval (1-5 s) lets that finish
 * in ~minutes instead of stalling on the 32× cap.
 */
static int64_t syncsvc_getheaders_interval(const struct p2p_node *node,
                                           int our_height)
{
    int64_t base;
    if (syncsvc_is_initial_block_download(node, our_height) || syncsvc_header_band_hole_open())
        base = 10;   /* S8: band hole (island-anchored tip) also forces IBD */
    else if (node->starting_height > 0 && our_height < node->starting_height)
        base = 30;   /* tighter than old 60s for faster catch-up */
    else
        base = 120;

    bool peer_is_loopback = net_addr_is_local(&node->addr.svc.addr);

    /* Exponential backoff based on consecutive stale responses */
    int stale = atomic_load_explicit(&node->getheaders_stale_count,
                                     memory_order_relaxed);
    if (stale > 0 && !peer_is_loopback) {
        int shift = stale > 5 ? 5 : stale;  /* cap at 2^5 = 32x */
        base <<= shift;
    }

    /* Loopback peers get a tighter base interval to close any IBD lag
     * quickly. Remote peers stay at the phase-appropriate base. */
    if (peer_is_loopback && base > 5)
        base = 5;

    /* Hard cap: never wait more than 600s */
    if (base > 600)
        base = 600;

    if (base > 60) {
        /* Fold this backoff into the window (cheap relaxed atomics, no
         * per-peer line), then emit one summary when the window rolls over. */
        const memory_order rx = memory_order_relaxed;
        int64_t now = platform_time_wall_unix();
        int64_t window_start = atomic_load_explicit(&g_stale_window_start_unix, rx);
        if (window_start == 0) {
            atomic_store_explicit(&g_stale_window_start_unix, now, rx);
            window_start = now;
        }
        if (atomic_fetch_add_explicit(&g_stale_window_count, 1, rx) == 0) {
            atomic_store_explicit(&g_stale_window_min, base, rx);
            atomic_store_explicit(&g_stale_window_max, base, rx);
        } else {
            if (base < atomic_load_explicit(&g_stale_window_min, rx))
                atomic_store_explicit(&g_stale_window_min, base, rx);
            if (base > atomic_load_explicit(&g_stale_window_max, rx))
                atomic_store_explicit(&g_stale_window_max, base, rx);
        }
        if (now - window_start >= STALE_SUMMARY_WINDOW_SECS) {
            /* count is per-probe fold events (a backed-off peer is probed
             * repeatedly inside one window) — an over-estimate of distinct
             * peers, so labelled "observations". min/max bound the intervals. */
            printf("[headers] %d stale-interval observations "
                   "(intervals %llds-%llds)\n",
                   atomic_load_explicit(&g_stale_window_count, rx),
                   (long long)atomic_load_explicit(&g_stale_window_min, rx),
                   (long long)atomic_load_explicit(&g_stale_window_max, rx));
            atomic_store_explicit(&g_stale_window_count, 0, rx);
            atomic_store_explicit(&g_stale_window_start_unix, now, rx);
        }
    }

    return base;
}

bool syncsvc_should_request_headers(const struct p2p_node *node,
                                    int our_height,
                                    int64_t now_seconds)
{
    if (!node || node->inbound) return false;
    if (node->state < PEER_SYNCING_HEADERS) return false;

    /* Never spend a getheaders round on a peer we KNOW is at/behind us; it
     * can only re-deliver headers we already have (stale rounds). At tip
     * our_height tracks the peer's starting_height, so this stays false for
     * a healthy at-tip peer and only fires on a truly-behind peer (the live
     * 3056758-vs-3150488 wedge). Net policy only — no validity touched. */
    if (syncsvc_peer_is_behind(node, our_height))
        return false;

    int64_t interval = syncsvc_getheaders_interval(node, our_height);
    return (now_seconds - atomic_load_explicit(&node->last_getheaders_time,
                                                memory_order_relaxed)) > interval;
}

void syncsvc_plan_periodic_getheaders(struct sync_getheaders_action *action,
                                      const struct p2p_node *node,
                                      int our_height,
                                      int64_t now_seconds)
{
    struct sync_getheaders_action empty = {0};

    if (!action) return;
    *action = empty;

    if (!syncsvc_should_request_headers(node, our_height, now_seconds))
        return;

    action->should_send = true;
    action->anchor = SYNC_HEADER_REQUEST_TIP;
    action->should_log = true;

    int64_t interval = syncsvc_getheaders_interval(node, our_height);
    printf("[headers] getheaders planned: peer=%d our_h=%d peer_start_h=%d interval=%llds\n",
           node->id, our_height, node->starting_height, (long long)interval);
}

void syncsvc_note_headers_requested(struct p2p_node *node,
                                    int64_t now_seconds)
{
    if (!node) return;
    atomic_store_explicit(&node->last_getheaders_time, now_seconds,
                          memory_order_relaxed);
}

/* Credit a peer for a delivered headers batch. `newly_added` is the
 * count of headers NOT previously in our block index — callers must
 * pass that, never the raw accepted count, which also includes
 * already-known headers a withholding peer could replay forever to
 * stay "useful" (see the process_headers call site, msg_headers.c). */
void syncsvc_note_headers_received(struct p2p_node *node,
                                   size_t newly_added)
{
    if (!node) return;
    if (newly_added > 0) {
        atomic_store_explicit(&node->getheaders_stale_count, 0,
                              memory_order_relaxed);
        atomic_store_explicit(&node->last_useful_headers_time,
                              (int64_t)platform_time_wall_time_t(),
                              memory_order_relaxed);
        node->total_headers_delivered += (uint64_t)newly_added;
    } else {
        atomic_fetch_add_explicit(&node->getheaders_stale_count, 1,
                                  memory_order_relaxed);
    }
}

bool syncsvc_should_scan_block_files_after_headers(size_t accepted,
                                                   const struct block_index *header_tip)
{
    if (g_block_file_scan_triggered)
        return false;
    if (accepted == 0 || !header_tip)
        return false;
    if (header_tip->nHeight <= 1000)
        return false;

    g_block_file_scan_triggered = true;
    return true;
}

struct zcl_result syncsvc_build_getheaders_locator(struct block_locator *loc,
                                      const struct active_chain *chain,
                                      const struct block_index *from,
                                      const struct block_index *best_header_fallback,
                                      const struct uint256 *genesis_hash)
{
    bool has_genesis = false;
    size_t i;

    if (!loc || !genesis_hash)
        return ZCL_ERR(-1, "null loc=%d genesis_hash=%d", !loc, !genesis_hash);

    block_locator_init(loc);
    if (from) {
        syncsvc_build_locator_from_tip(loc, from,
                                       "header_sync locator index",
                                       "header_sync.locator_index");
    } else if (chain) {
        syncsvc_build_locator_from_tip(loc, active_chain_tip(chain),
                                       "header_sync locator chain",
                                       "header_sync.locator_chain");
    }

    /* Full-index boot: the active_chain window / authority is not yet seated so
     * active_chain_tip() gave nothing. Anchor at the known header frontier
     * rather than collapsing to a genesis-only locator (which pins header sync
     * near genesis). NEVER genesis when a frontier header exists. */
    if (loc->num_hashes == 0 && best_header_fallback &&
        best_header_fallback->phashBlock) {
        syncsvc_build_locator_from_tip(loc, best_header_fallback,
                                       "header_sync locator best_header",
                                       "header_sync.locator_best_header");
    }

    if (loc->num_hashes == 0) {
        loc->vhave = zcl_malloc(sizeof(struct uint256), "header_sync genesis locator");
        if (!loc->vhave)
            return ZCL_ERR(-2, "malloc failed for genesis-only locator");
        loc->vhave[0] = *genesis_hash;
        loc->num_hashes = 1;
        return ZCL_OK;
    }

    for (i = 0; i < loc->num_hashes; i++) {
        if (uint256_eq(&loc->vhave[i], genesis_hash)) {
            has_genesis = true;
            break;
        }
    }

    if (!has_genesis) {
        struct uint256 *new_vhave = zcl_realloc(loc->vhave,
            (loc->num_hashes + 1) * sizeof(struct uint256),
            "header_sync.getheaders_locator");
        if (!new_vhave) {
            block_locator_free(loc);
            return ZCL_ERR(-3, "realloc failed for %zu hashes", loc->num_hashes + 1);
        }
        loc->vhave = new_vhave;
        loc->vhave[loc->num_hashes] = *genesis_hash;
        loc->num_hashes++;
    }

    return ZCL_OK;
}

enum sync_header_log_mode syncsvc_header_log_mode(
    const struct p2p_node *node,
    const struct block_index *tip,
    bool in_ibd)
{
    if (!node || !tip || !tip->phashBlock)
        return SYNC_HEADER_LOG_NONE;

    if (in_ibd) {
        if (g_getheaders_log_count++ % 10 == 0)
            return SYNC_HEADER_LOG_IBD;
        return SYNC_HEADER_LOG_NONE;
    }

    return SYNC_HEADER_LOG_TIP;
}

bool syncsvc_should_activate_after_block_file_scan(int scanned_blocks)
{
    return scanned_blocks > 0;
}

bool syncsvc_should_activate_after_header_processing(
    const struct sync_header_processing_plan *plan)
{
    if (!plan)
        return false;

    return plan->should_activate_chain;
}

bool syncsvc_should_release_snapshot_anchor(
    const struct block_index *anchor,
    const struct block_index *header_tip)
{
    return anchor && header_tip &&
           header_tip->nHeight >= anchor->nHeight + zcl_finality_depth();
}

bool syncsvc_should_begin_blocks_download(enum sync_state sync_state,
                                          const struct block_index *candidate,
                                          int our_height)
{
    return candidate && candidate->nHeight > our_height &&
           (sync_state == SYNC_HEADERS_DOWNLOAD ||
            sync_state == SYNC_BLOCKS_DOWNLOAD);
}

bool syncsvc_headers_chain_from_tip(const struct block_index *candidate,
                                    const struct block_index *tip,
                                    int our_height)
{
    const struct block_index *verify = candidate;
    const struct block_index *last_valid = NULL;

    while (verify && verify->nHeight > our_height) {
        last_valid = verify;
        verify = verify->pprev;
    }

    if (verify == tip)
        return true;
    if (verify && tip && verify->nHeight == tip->nHeight &&
        verify->phashBlock && tip->phashBlock &&
        uint256_eq(verify->phashBlock, tip->phashBlock)) {
        return true;
    }
    if (verify && tip && verify->nHeight == tip->nHeight)
        return true;

    /* After snapshot sync, the chain walks back to the snapshot anchor
     * (pprev=NULL at high height). If the walk stopped at a verified
     * anchor (non-null last_valid with NULL pprev above our_height),
     * accept this as a valid chain root. The anchor has FlyClient + SHA3
     * evidence and represents a verified chain point. */
    struct block_index *anchor = snapsync_get_anchor();
    if (!verify && anchor && last_valid) {
        const struct block_index *check = last_valid;
        while (check && check != anchor)
            check = check->pprev;
        if (check == anchor)
            return true;
    }

    /* Chainwork fallback: if pprev walk failed (broken links from LDB
     * import) but the candidate has strictly more chain work than our
     * tip, accept it. Block download + connect_block will still fully
     * validate everything — this check is just a sanity gate. */
    if (candidate && tip &&
        candidate->nHeight > our_height &&
        arith_uint256_compare(&candidate->nChainWork, &tip->nChainWork) > 0)
        return true;

    return false;
}
void syncsvc_collect_needed_blocks(struct sync_needed_blocks *result,
                                   const struct block_index *candidate,
                                   const struct block_index *tip,
                                   int our_height,
                                   struct uint256 *hashes,
                                   int32_t *heights,
                                   size_t max_collect)
{
    struct sync_needed_blocks empty = {0};
    size_t walk_steps = 0;
    struct block_index *walk;
    size_t i;

    if (!result) return;
    *result = empty;

    if (!candidate || !hashes || !heights || max_collect == 0)
        return;

    result->chains_from_tip =
        syncsvc_headers_chain_from_tip(candidate, tip, our_height);
    if (!result->chains_from_tip) {
        /* After snapshot sync or LDB import, pprev gaps are expected —
         * the chain walk hits NULL before reaching our_height.
         * Allow download in that case since connect_block validates fully.
         * But if the walk reached a real block at/below our_height that
         * isn't the tip, this is a genuine fork — reject it. */
        bool has_pprev_gap = false;
        if (candidate->nHeight > our_height) {
            const struct block_index *w = candidate;
            while (w && w->nHeight > our_height)
                w = w->pprev;
            has_pprev_gap = (w == NULL);
        }
        if (has_pprev_gap) {
            result->chains_from_tip = true; /* override — allow download */
        } else {
            return;
        }
    }

    walk = (struct block_index *)candidate;
    while (walk && walk->nHeight > our_height &&
           result->count < max_collect && walk_steps < 2048) {
        if (!(walk->nStatus & BLOCK_HAVE_DATA) &&
            !(walk->nStatus & BLOCK_FAILED_MASK) &&
            walk->phashBlock) {
            hashes[result->count] = *walk->phashBlock;
            heights[result->count] = walk->nHeight;
            result->count++;
        }
        if (walk->pprev) {
            walk = walk->pprev;
        } else {
            break; /* pprev gap — collected what we could */
        }
        walk_steps++;
    }

    for (i = 0; i < result->count / 2; i++) {
        struct uint256 th = hashes[i];
        int32_t ti = heights[i];

        hashes[i] = hashes[result->count - 1 - i];
        heights[i] = heights[result->count - 1 - i];
        hashes[result->count - 1 - i] = th;
        heights[result->count - 1 - i] = ti;
    }

    result->should_activate_chain = (result->count == 0);
}

/* ── Header sync stall detection ──────────────────────────── */

bool syncsvc_should_disconnect_stale_header_peer(const struct p2p_node *node,
                                                  int our_height,
                                                  int best_header_height,
                                                  int64_t now_seconds)
{
    if (!node) return false;
    if (!syncsvc_is_initial_block_download(node, our_height))
        return false;  // raw-return-ok:only-relevant-during-ibd-not-an-error
    if (node->state < PEER_SYNCING_HEADERS)
        return false;

    /* Frontier-parity gate (P2): when our HEADER frontier has already
     * reached the peer's claimed tip, getheaders cannot be "useful" by
     * construction — new headers only arrive at block cadence (~150s),
     * slower than HEADER_STALL_TIMEOUT_SECS, so disconnecting here is
     * pure churn (the wedged-tip regime: chain tip pinned far below the
     * header frontier keeps IBD true vs our_height while headers track
     * the network tip). A genuinely withholding peer claims a height
     * far above our frontier and is unaffected.
     *
     * node->starting_height is handshake-static, so this parity gate
     * progressively relaxes stale-header discipline for long-lived
     * peers as the chain grows past their connect-time claim — accepted
     * consciously given IBD gating, the loopback lifeline, rule B's
     * per-stall-cycle rotation, and the peer-floor conditions. */
    if (node->starting_height > 0 &&
        best_header_height >= node->starting_height - 144)
        return false;

    /* If peer has never delivered useful headers, use connection time. */
    int64_t ref_time = atomic_load_explicit(&node->last_useful_headers_time,
                                             memory_order_relaxed);
    if (ref_time == 0)
        ref_time = node->time_connected;

    return (now_seconds - ref_time) >= HEADER_STALL_TIMEOUT_SECS;
}

bool syncsvc_should_disconnect_body_stalled_peer(const struct p2p_node *node,
                                                  int our_height,
                                                  uint64_t body_received,
                                                  uint64_t body_timed_out,
                                                  int64_t now_seconds)
{
    if (!node)
        return false;
    /* Only when we still NEED bodies. At/near tip a peer legitimately
     * delivers no body for long stretches (block cadence ~150s), so the
     * discipline is IBD-gated exactly like the stale-header rule. */
    if (!syncsvc_is_initial_block_download(node, our_height))
        return false;  // raw-return-ok:only-relevant-during-ibd-not-an-error
    if (node->state < PEER_HANDSHAKE_COMPLETE)
        return false;

    /* Delivered at least one body ⇒ the peer CAN serve bodies; keep it. */
    if (body_received > 0)
        return false;

    /* Judge only a peer we have genuinely asked AND waited on: at least
     * SYNC_BODY_STALL_MIN_TIMEOUTS block requests were assigned to it and
     * every one expired unfilled. A peer with requests still legitimately
     * in flight (assigned but not yet timed out) is not a deadbeat, so we
     * key on timed_out, not on the raw request count. */
    if (body_timed_out < SYNC_BODY_STALL_MIN_TIMEOUTS)
        return false;

    /* Grace: never judge a peer inside its first stall window. */
    int64_t ref_time = node->time_connected ? node->time_connected
                                            : now_seconds;
    return (now_seconds - ref_time) >= SYNC_BODY_STALL_TIMEOUT_SECS;
}

bool syncsvc_is_header_sync_stalled(enum sync_state state,
                                    int best_header_height,
                                    int64_t last_advance_time,
                                    int64_t now_seconds)
{
    (void)best_header_height; /* used by caller for logging */
    if (state != SYNC_HEADERS_DOWNLOAD)
        return false;
    if (last_advance_time == 0)
        return false;
    return (now_seconds - last_advance_time) >= HEADER_STALL_TIMEOUT_SECS;
}

bool syncsvc_should_request_headers_with_fallback(const struct p2p_node *node,
                                                   int our_height,
                                                   int64_t now_seconds,
                                                   bool header_stall_active)
{
    if (!node) return false;
    /* Even during a stall, a peer we KNOW is at/behind us cannot extend
     * our header frontier — asking it just burns a stale round. Unknown-
     * height peers (starting_height<0) stay eligible. Net policy only. */
    if (syncsvc_peer_is_behind(node, our_height)) return false;
    /* During stall, allow inbound peers as fallback */
    if (node->inbound && !header_stall_active) return false;
    if (node->state < PEER_SYNCING_HEADERS) {
        /* For inbound peers during stall, only require PEER_ACTIVE or better */
        if (node->inbound && header_stall_active && node->state >= PEER_ACTIVE)
            ; /* allow */
        else
            return false;
    }

    int64_t interval;
    if (syncsvc_is_initial_block_download(node, our_height))
        interval = 10;
    else
        interval = 30; /* tighter during stall */
    return (now_seconds - atomic_load_explicit(&node->last_getheaders_time,
                                                memory_order_relaxed)) > interval;
}

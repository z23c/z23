/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tip-publication evidence and commit helpers for process_block.
 *
 * Selection code decides which block can advance; this file validates the
 * evidence attached to that decision and crosses the boot-owned publication
 * hook boundary. Keep CSR/test-fallback mechanics out of chain selection. */

#include <stdio.h>

#include "chain/chain.h"
#include "chain/pow.h"
#include "coins/coins_view.h"
#include "core/uint256.h"
#include "core/utiltime.h"
#include "event/event.h"
#include "util/log_macros.h"
#include "util/result.h"
#include "util/trace.h"
#include "validation/mirror_consensus.h"

#include "process_block_internal.h"

#ifdef ZCL_TESTING
/* Test-harness CSR fallback only. Keep this local so the validation lib does
 * not include the app chain-tip service in production code. */
enum tip_source {
    TIP_FROM_CONNECT = 1,
    TIP_FROM_DISCONNECT = 2,
};
struct zcl_result chain_set_active_tip(struct main_state *ms,
                                       struct block_index *new_tip,
                                       enum tip_source src,
                                       const char *reason);
#endif

/* ── csr-migration helper ────────────────────────────────────
 * process_block.c mutates the chain tip from five different places
 * (forward extend, disconnect rollback, genesis connect without
 * disk, reorg recovery, no-fork reset). All of them route through
 * this helper so the cross-source validation and observability
 * live in one place. */
static bool process_block_header_ancestry_linked(const struct block_index *tip)
{
    if (!tip || !tip->phashBlock)
        return false;
    if (tip->nHeight == 0)
        return true;
    return tip->pprev && tip->pprev->phashBlock &&
           tip->pprev->nHeight == tip->nHeight - 1;
}

static bool process_block_chainwork_recomputed(const struct block_index *tip)
{
    struct arith_uint256 expected;
    struct arith_uint256 proof;

    if (!tip)
        return false;
    proof = GetBlockProof(tip);
    if (arith_uint256_is_zero(&proof))
        return false;
    expected = proof;
    if (tip->pprev)
        arith_uint256_add(&expected, &tip->pprev->nChainWork, &proof);
    return arith_uint256_compare(&expected, &tip->nChainWork) == 0 &&
           !arith_uint256_is_zero(&tip->nChainWork);
}

/* Evidence-side mirror of find_most_work_chain's candidate eligibility.
 *
 * The two functions scan the SAME map_block_index and MUST agree about
 * which entries represent a real competing chain. They diverged: a prior
 * recompute_index_from_genesis stamped nChainWork (and left BLOCK_HAVE_DATA)
 * on thousands of STALE off-chain fork/orphan entries above the header tip,
 * whose pprev pointers are not linked down to the active tip. The original
 * predicate counted ANY such higher-work HAVE_DATA entry whose
 * block_index_get_ancestor(candidate, tip->nHeight) != tip as a competing
 * chain — but for a torn fork that walk returns NULL (chain.c: unlinked
 * pprev), and NULL != tip flipped the result to "not best work" forever,
 * permanently wedging tip promotion.
 *
 * find_most_work_chain(), the authority on selection, requires
 * BLOCK_VALID_TREE, tolerates unlinked pprev, and never reorgs below the tip
 * — so it had already selected our tip's path. The disagreement was purely
 * this predicate's looser filter. Align the filter:
 *   - require BLOCK_VALID_TREE — stale entries that lost tree validity are
 *     not selectable and cannot be "better work";
 *   - a candidate only beats the tip when its ancestry RESOLVES to a real
 *     block at tip->nHeight that is NOT the tip (a genuine connectable
 *     sibling fork -> we SHOULD reorg -> return false). A NULL resolution
 *     means the candidate is not contiguous-data-linked down to tip height
 *     (torn/orphan fork): find_most_work_chain could never select it, so it
 *     must NOT veto promotion.
 *
 * Reorg safety: a genuinely better, fully-downloaded, fully-linked
 * competing chain still resolves block_index_get_ancestor(candidate,
 * tip->nHeight) to a real block != tip, so this still returns false and
 * the reorg path runs. Only the unresolvable (NULL) torn-fork case is
 * reclassified, and that case was never a valid reorg target. */
static bool process_block_tip_is_best_work(const struct main_state *ms,
                                           const struct block_index *tip)
{
    size_t iter = 0;
    struct block_index *candidate = NULL;

    if (!ms || !tip)
        return false;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &candidate)) {
        if (!candidate || block_has_any_failure(candidate))
            continue;
        if (!block_index_is_valid(candidate, BLOCK_VALID_TREE))
            continue;
        if (!(candidate->nStatus & BLOCK_HAVE_DATA))
            continue;
        if (arith_uint256_compare(&candidate->nChainWork,
                                  &tip->nChainWork) <= 0)
            continue;
        struct block_index *anc =
            block_index_get_ancestor(candidate, tip->nHeight);
        /* Only a RESOLVED, non-tip ancestor proves a real connectable
         * competing chain (-> reorg). A NULL resolution is a torn/orphan
         * fork that find_most_work_chain cannot select — it must not veto
         * the tip and wedge promotion. */
        if (anc && anc != tip)
            return false;
    }
    return true;
}

#ifdef ZCL_TESTING
bool process_block_test_tip_is_best_work(const struct main_state *ms,
                                         const struct block_index *tip)
{
    return process_block_tip_is_best_work(ms, tip);
}
#endif

static struct process_block_tip_evidence process_block_verified_tip_evidence(
    const struct main_state *ms,
    const struct block_index *tip,
    bool block_bytes_hash_checked)
{
    struct process_block_tip_evidence evidence = {0};
    evidence.header_ancestry_linked =
        process_block_header_ancestry_linked(tip);
    evidence.chainwork_recomputed =
        process_block_chainwork_recomputed(tip);
    evidence.nakamoto_selected_best_work =
        process_block_tip_is_best_work(ms, tip);
    evidence.block_bytes_hash_checked = block_bytes_hash_checked;
    return evidence;
}

bool process_block_commit_tip(struct main_state *ms,
                              struct coins_view_cache *coins_tip,
                              struct block_index *new_tip,
                              const char *reason,
                              bool update_header_tip,
                              bool persist_coins_best,
                              const struct process_block_tip_evidence *verified)
{
#ifndef ZCL_TESTING
    (void)coins_tip;
#endif
    struct trace_span *tip_span = trace_start("process_block.publish_tip");
    trace_attr_int(tip_span, "height", new_tip ? new_tip->nHeight : -1);
    trace_attr_str(tip_span, "reason", reason ? reason : "");

    if (!new_tip || !new_tip->phashBlock) {
        trace_set_status(tip_span, TRACE_STATUS_ERROR);
        trace_attr_str(tip_span, "error", "null_tip");
        trace_end(tip_span);
        LOG_FAIL("validation", "process_block_commit_tip called with null tip or null phashBlock");
    }

    enum process_block_tip_publish_result pr =
        process_block_publish_tip(ms, coins_tip, new_tip, reason,
                                  update_header_tip, persist_coins_best,
                                  verified);
    if (pr == PROCESS_BLOCK_TIP_PUBLISH_OK) {
        trace_end(tip_span);
        return true;
    }

#ifdef ZCL_TESTING
    if (pr == PROCESS_BLOCK_TIP_PUBLISH_REJECTED_NOT_INITIALIZED) {
        /* Test harness path: no boot publication hook was wired. Use
         * the canonical helper so events still fire. */
        (void)chain_set_active_tip(ms, new_tip, TIP_FROM_CONNECT,
                             reason ? reason : "tip_hook_uninit_fallback");
        if (update_header_tip) ms->pindex_best_header = new_tip;
        if (coins_tip) coins_view_cache_set_best_block(coins_tip,
                                                        new_tip->phashBlock);
        trace_attr_str(tip_span, "fallback", "raw_setters");
        trace_end(tip_span);
        return true;
    }
#endif

    /* Real validation failure. The boot-owned publisher has already
     * emitted structured rejection detail; shout too so this shows up
     * in the node log even when events are disabled. */
    fprintf(stderr, // obs-ok:pre-existing-diagnostic
            "process_block: tip publisher rejected commit (%s) reason=%s h=%d\n",
            process_block_tip_publish_result_name(pr), reason, new_tip->nHeight);
    if (pr == PROCESS_BLOCK_TIP_PUBLISH_REJECTED_DB_BUSY)
        mirror_consensus_record_blocker("db-writer-busy");
    else if (pr == PROCESS_BLOCK_TIP_PUBLISH_REJECTED_PERSIST)
        mirror_consensus_record_blocker("csr-persist-failed");
    trace_set_status(tip_span, TRACE_STATUS_ERROR);
    trace_attr_str(tip_span, "error",
                   process_block_tip_publish_result_name(pr));
    trace_end(tip_span);
    return false;
}

/* Propagate tip-publisher rejection to the caller. If
 * process_block_commit_tip returns false (CSR refused the commit for
 * coins_mismatch / tip_not_in_index / stale_index / etc.) the caller
 * must not treat the block as accepted: otherwise the in-memory chain
 * tip stays at the old height while every inbound block re-emits
 * EV_BLOCK_CONNECTED for that same height forever, ballooning the
 * download queue and RSS until SIGABRT. Returning false here lets the
 * reducer surface the failure and stop the re-emit loop. */
bool update_tip(struct main_state *ms, struct block_index *pindex_new)
{
    if (pindex_new) {
        struct process_block_tip_evidence evidence =
            process_block_verified_tip_evidence(ms, pindex_new, true);
        /* coins_tip is NULL here on purpose: the pre-migration
         * update_tip never set coins_best_block (connect_block had
         * already done it while building the new tip), and the
         * fallback path should preserve that behaviour. */
        if (!process_block_commit_tip(ms, NULL, pindex_new,
                                      "process_block.update_tip", true,
                                      false,
                                      &evidence))
            return false;
    } else {
        /* Disconnect past genesis — empty the chain. No commit to
         * make, but still route the concrete publication through CSR
         * so active-tip clears use the same promotion boundary. */
        enum process_block_tip_publish_result pr =
            process_block_clear_tip(ms, "disconnect_past_genesis");
#ifdef ZCL_TESTING
        if (pr == PROCESS_BLOCK_TIP_PUBLISH_REJECTED_NOT_INITIALIZED) {
            (void)chain_set_active_tip(ms, NULL, TIP_FROM_DISCONNECT,
                                 "disconnect_past_genesis");
        } else
#endif
        if (pr != PROCESS_BLOCK_TIP_PUBLISH_OK) {
            fprintf(stderr,
                    "validation: tip publisher rejected active-tip clear (%s)\n",
                    process_block_tip_publish_result_name(pr));
            return false;
        }
    }

    char hex[65];
    if (pindex_new && pindex_new->phashBlock)
        uint256_get_hex(pindex_new->phashBlock, hex);
    else
        snprintf(hex, sizeof(hex), "(null)");

    event_emitf(EV_TIP_UPDATED, 0, "h=%d %s",
                pindex_new ? pindex_new->nHeight : -1, hex);

    /* Progress log every 10000 blocks with speed metric */
    if (pindex_new && pindex_new->nHeight % 10000 == 0 && pindex_new->nHeight > 0) {
        static int64_t last_log_time = 0;
        static int last_log_height = 0;
        int64_t now_log = GetTime();
        int64_t elapsed = now_log - last_log_time;
        int blocks_done = pindex_new->nHeight - last_log_height;
        double bps = elapsed > 0 ? (double)blocks_done / (double)elapsed : 0;
        printf("Chain: height=%d  %.0f blk/s\n",
               pindex_new->nHeight, bps);
        last_log_time = now_log;
        last_log_height = pindex_new->nHeight;
    }

    return true;
}

/* External wrapper for the chain-advance protocol. */
bool process_block_commit_tip_ext(struct main_state *ms,
                                  struct coins_view_cache *coins_tip,
                                  struct block_index *new_tip,
                                  const char *reason,
                                  bool update_header_tip)
{
    return process_block_commit_tip(ms, coins_tip, new_tip, reason,
                                    update_header_tip, false, NULL);
}

/* Regression surface: exposes the post-refactor update_tip so a
 * unit test can drive a real csr_instance through a rejecting input
 * and assert the caller observes false. Production callers go through the
 * reducer/tip-finalize path; this wrapper must not grow any new behaviour. */
bool process_block_test_update_tip(struct main_state *ms,
                                    struct block_index *pindex_new)
{
    return update_tip(ms, pindex_new);
}

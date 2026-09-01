/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * tip_finalize_stage — implementation. See jobs/tip_finalize_stage.h. */

#include "platform/time_compat.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/tip_finalize_stage_hooks.h"
#include "jobs/stage_helpers.h"
#include "jobs/refold_progress.h"
#include "jobs/reducer_frontier.h"
#include "jobs/block_header_emit.h"
#include "tip_finalize_anchor_internal.h"
#include "tip_finalize_evidence.h"
#include "tip_finalize_stage_durable.h"
#include "tip_finalize_post_step.h"
#include "tip_finalize_log_store.h"
#include "tip_finalize_stage_observe.h"
#include "tip_finalize_batch_drain.h"
#include "tip_finalize_provable_tip.h"
#include "tip_finalize_visible_body.h"

#include "chain/chain.h"
#include "core/arith_uint256.h"
#include "event/event.h"
#include "services/chain_evidence_authority_service.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/reducer_stage_profile.h"
#include "util/stage.h"
#include "validation/main_state.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define STAGE_NAME "tip_finalize"

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct main_state *g_ms = NULL;
static stage_t *g_stage = NULL;

/* The provable-tip (H*) cache helpers — tf_refresh_provable_tip,
 * tf_warm_provable_tip_once, tf_advance_provable_tip — own their own TU
 * tip_finalize_provable_tip.c (a separable concern from the finalize step). */

/* Cross-TU seam for tip_finalize_anchor.c (tip_finalize_anchor_internal.h):
 * the anchor/seed TU reads the live stage handle at call time and publishes
 * the served tip through the same single update path as the step body. */
stage_t *tip_finalize_stage_handle(void) { return g_stage; }

void tip_finalize_publish_last_advance(int height, const uint8_t hash[32])
{ tip_finalize_observe_update_last_advance(height, hash); }

bool tip_finalize_stage_authority_snapshot(int64_t *height, uint8_t hash[32])
{ return tip_finalize_observe_get_last_advance(height, hash); }

static int reorg_depth_from(struct block_index *old_tip,
                            struct block_index *new_tip)
{
    int depth = 0;
    struct block_index *p = new_tip;
    while (p && p->nHeight > old_tip->nHeight) {
        p = p->pprev;
        depth++;
    }
    while (p && old_tip && p != old_tip) {
        p = p->pprev;
        old_tip = old_tip->pprev;
        depth++;
    }
    return depth > 0 ? depth : 1;
}

/* HEADER-ONLY canonical-successor witness (deadlock cure `a35ca0c8f`).
 *
 * Returns true iff new_tip (N+1) is sufficient HEADER-level evidence that
 * old_tip (N) is on the canonical most-work chain — WITHOUT requiring N+1's
 * body / scripts / utxo verdict. N is finalizable on its OWN proven verdict
 * (utxo_apply_log_at(N).ok==1, already checked at the upstream.ok gate); N+1 is
 * consulted only as the most-work successor that pins N to the canonical chain.
 *
 * All five checks are HEADER-only and reorg-safe:
 *   - new_tip is not a failed block (block_has_any_failure clear) — never
 *     finalize past a consensus-invalid successor;
 *   - new_tip carries >= BLOCK_VALID_HEADER (Equihash PoW verified);
 *   - new_tip->pprev == old_tip BY BLOCK HASH (canonical parent; a duplicate
 *     same-hash object must not defeat it — the bde617a7e lesson — so this is
 *     hash identity, never pointer identity);
 *   - new_tip->nChainWork strictly greater than old_tip's;
 *   - new_tip is best_header's own ancestor at its height, compared BY HASH
 *     (on the most-work header chain).
 * N+1 is NEVER finalized or served on this evidence: tip_finalize still requires
 * N+1's own ok=1 before advancing past it, and H* is capped by the contiguous
 * ok=1 prefix (reducer_frontier), so it climbs only to N. */
static bool is_canonical_header_successor(struct block_index *old_tip,
                                          struct block_index *new_tip,
                                          struct block_index *best_header)
{
    if (!old_tip || !new_tip || !best_header)
        return false;
    if (!old_tip->phashBlock || !new_tip->phashBlock)
        return false;
    if (block_has_any_failure(new_tip))
        return false;
    if ((new_tip->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_HEADER)
        return false;
    if (!new_tip->pprev || !new_tip->pprev->phashBlock ||
        !uint256_eq(new_tip->pprev->phashBlock, old_tip->phashBlock))
        return false;
    if (arith_uint256_compare(&new_tip->nChainWork, &old_tip->nChainWork) <= 0)
        return false;
    if (new_tip->nHeight > best_header->nHeight)
        return false;
    struct block_index *anc =
        block_index_get_ancestor(best_header, new_tip->nHeight);
    if (!anc || !anc->phashBlock ||
        !uint256_eq(anc->phashBlock, new_tip->phashBlock))
        return false;
    return true;
}

/* HEADER-LOOKAHEAD RESOLUTION GUARD. best_header ancestry is a useful fallback
 * when the have-data window is a block behind the header frontier, but only for
 * the direct child of the already-resolved finalized tip. If the header
 * candidate's parent hash differs from old_tip, it is a competing fork/reorg
 * candidate. Leave new_tip unresolved so tip_finalize HOLDS and the reorg/window
 * owner handles the branch; writing a height-keyed reorg_detected row here
 * poisons H* with stale residue once the canonical window catches up. */
static bool header_lookahead_extends_tip(const struct block_index *old_tip,
                                         const struct block_index *candidate)
{
    if (!old_tip)
        return true; /* old_tip may be resolved from the same best_header path. */
    if (!candidate || !candidate->pprev || !candidate->pprev->phashBlock ||
        !old_tip->phashBlock)
        return false;
    return uint256_eq(candidate->pprev->phashBlock, old_tip->phashBlock);
}

static bool finalized_row_active_match(sqlite3 *db, int row_height,
                                       bool *out_known, bool *out_matches)
{
    *out_known = false;
    *out_matches = false;
    struct finalized_tip_row row;
    if (!finalized_tip_row_at(db, row_height, &row))
        return false;
    if (!row.found || !row.ok || !row.has_tip_hash)
        return true;
    /* Skip tip SEED rows. An anchor row stores the block's OWN hash (row H ->
     * hash H), not the finalized lookahead convention (row H -> hash H+1) that
     * this match assumes. Comparing an anchor's hash(H) to active_chain_at(H+1)
     * ALWAYS mismatches, which false-detects a reorg and rewinds the cursor
     * back onto the seed forever (a finalize-frontier oscillation). A genuine
     * reorg at/around the seed is still caught by the real finalized rows. */
    if (row.is_anchor)
        return true;  /* out_known stays false → no-op for the rewind scan */

    struct main_state *ms = g_ms;
    struct block_index *active = ms ? active_chain_at(&ms->chain_active, row_height + 1) : NULL;
    if (!active || !active->phashBlock) {
        /* Missing/short windows occur during legitimate boot/resume and stay
         * unknown.  invalidateblock first marks this row's exact successor
         * hash FAILED, which is the explicit evidence that absence means a
         * disconnect rather than window lag. */
        struct block_index *recorded_owner = ms
            ? block_map_find(&ms->map_block_index, &row.tip_hash) : NULL;
        if (recorded_owner && block_has_any_failure(recorded_owner)) *out_known = true;
        return true;
    }
    *out_known = true;
    *out_matches = uint256_eq(&row.tip_hash, active->phashBlock);
    return true;
}

static bool rewind_cursor_if_active_chain_reorged(sqlite3 *db)
{
    if (!g_stage || !g_ms)
        return true;

    uint64_t cursor = 0;
    if (!stage_cursor_read_or_zero(db, STAGE_NAME, STAGE_NAME, &cursor))
        return false;
    if (cursor == 0)
        return true;
    if (cursor > (uint64_t)INT32_MAX) {
        LOG_WARN("tip_finalize", "[tip_finalize] reorg rewind cursor too large: %llu", (unsigned long long)cursor);
        return false;
    }

    bool known = false;
    bool matches = false;
    if (!finalized_row_active_match(db, (int)cursor - 1, &known, &matches))
        return false;
    if (!known || matches)
        return true;

    uint64_t rewind_to = 0;
    for (int h = (int)cursor - 2; h >= 0; h--) {
        known = false;
        matches = false;
        if (!finalized_row_active_match(db, h, &known, &matches))
            return false;
        if (known && matches) {
            rewind_to = (uint64_t)h + 1u;
            break;
        }
    }
    if (rewind_to == cursor)
        return true;

    if (!stage_set_cursor(g_stage, db, rewind_to)) {
        LOG_WARN("tip_finalize", "[tip_finalize] reorg rewind failed from=%llu to=%llu", (unsigned long long)cursor, (unsigned long long)rewind_to);
        return false;
    }

    /* OS-S2: clamp boot-derived cursors to the fork height so a restart in the
     * reorg window re-derives navigation indices above it. fork = rewind_to-1. */
    tip_finalize_hooks_reorg_clamp((int)rewind_to - 1);

    /* LOWER the external provable-tip cache (H*) on the reorg rewind. This is
     * the #1 site: stage_set_cursor just dropped the tip_finalize cursor, but
     * g_last_advance_height (and thus active_chain_height) is raise-only and
     * stays stale-high until a new finalize republishes. Without this refresh
     * the external readers (getblockcount / P2P start_height) would serve an
     * unproven height across the reorg window. We hold progress_store_tx_lock
     * here (tip_finalize_stage_step_once), and this is the SAME chokepoint every
     * other unwind path (process_block_invalidate, utxo_apply_delta_reorg,
     * process_block_self_heal) flows through via reducer_kick -> tip_finalize
     * drain, so refreshing here lowers the cache for ALL of them. */
    tf_refresh_provable_tip(db);

    tip_finalize_observe_note_reorg_rewind();
    event_emitf(EV_BLOCK_REJECTED, 0,
                "tip_finalize reorg_cursor_rewind from=%llu to=%llu",
                (unsigned long long)cursor, (unsigned long long)rewind_to);
    return true;
}

static bool live_utxo_count_after(int height_after, int64_t *out_count)
{
    return tip_finalize_hooks_count_utxos(height_after, out_count);
}

static job_result_t step_finalize(struct stage_step_ctx *c)
{
    tip_finalize_observe_mark_step();

    struct main_state *ms = g_ms;
    if (!ms) return JOB_IDLE;
    sqlite3 *db = progress_store_db();
    if (!db) return JOB_IDLE;

    int next_h = (int)c->cursor_in;
    if (next_h < 0) return JOB_FATAL;

    uint64_t uv_cursor = 0;
    if (!stage_upstream_frontier_or_zero(db, "utxo_apply", STAGE_NAME,
                                   &uv_cursor))
        return JOB_FATAL;
    if ((uint64_t)next_h > uv_cursor) {  /* ANOMALY: names a typed blocker — see tip_finalize_observe_note_cursor_gap */
        tip_finalize_observe_note_cursor_gap(next_h, uv_cursor);
        return JOB_IDLE;
    }
    tip_finalize_observe_clear_cursor_gap();
    if ((uint64_t)next_h >= uv_cursor) {
        tip_finalize_observe_mark_blocked(TIP_FINALIZE_BLOCKED_AT_UV_FRONTIER);
        return JOB_IDLE;
    }

    struct utxo_apply_row upstream;
    int found = utxo_apply_log_at(db, next_h, &upstream);
    if (found < 0) return JOB_FATAL;
    if (found == 0) {  /* durable upstream-log hole, not "not yet" — see stage_upstream_log_hole_note */
        stage_upstream_log_hole_note(STAGE_NAME, "utxo_apply_log", next_h, uv_cursor, NULL);
        tip_finalize_observe_mark_blocked(TIP_FINALIZE_BLOCKED_UV_ROW_MISSING);
        return JOB_IDLE;
    }
    stage_upstream_log_hole_clear(STAGE_NAME);

    if (upstream.ok == 0) {
        tip_finalize_evidence_clear();
        struct arith_uint256 zero;
        arith_uint256_set_zero(&zero);
        if (!log_insert(db, next_h, "upstream_failed", false, &zero, -1, 0, NULL))
            return JOB_FATAL;
        tip_finalize_observe_inc_upstream_failed();
        c->cursor_out = c->cursor_in + 1;
        return JOB_ADVANCED;
    }

    struct block_index *old_tip = active_chain_at(&ms->chain_active, next_h);
    struct block_index *new_tip = active_chain_at(&ms->chain_active, next_h + 1);
    /* WINDOW-SLOT SELF-HEAL. The active-chain window's lower slot at next_h can
     * read NULL while next_h is genuinely on the finalized chain: a blocks-less
     * snapshot boot retracts the window to the seed, and as the body-dependent
     * stages extend it UP the seed-region slot is left empty even though the
     * authority still names next_h finalized. active_chain_at then returns NULL
     * → tip_finalize idles on current_tip_missing forever and H* pins at the
     * seed even though utxo_apply is folding ok=1 rows past it (observed:
     * ua_cursor climbing, ua_ok=1, tf_blocked=current_tip_missing). Re-resolve
     * the slot from the durable finalized-hash table + the block map (the SAME
     * authority active_chain_tip() uses), so finalize can proceed; a real
     * absence (no finalized row / not in map) still falls through to the
     * blocked-IDLE below. Read-only on the window. */
    if (!old_tip) {
        struct uint256 oh;
        if (tip_finalize_stage_block_hash_at(db, next_h, oh.data))
            old_tip = block_map_find(&ms->map_block_index, &oh);
    }
    if (!new_tip) {
        struct uint256 nh;
        if (tip_finalize_stage_block_hash_at(db, next_h + 1, nh.data))
            new_tip = block_map_find(&ms->map_block_index, &nh);
    }
    /* HEADER-CHAIN SELF-HEAL (deadlock-cure step 3). The lookahead successor
     * N+1 (and, on a deeply-retracted window, even N) can be genuinely on the
     * canonical most-work chain yet ABSENT from BOTH the active-chain window
     * (the have-data extender stalled at the body frontier a block below it —
     * the live 3162166 wedge: new_tip=active_chain_at(N+1)=NULL) AND the
     * finalized-hash table (N+1 is not finalized — enabling that is the whole
     * point). Resolve it from the best-header ancestry, the same slot-
     * independent authority validate_headers_stage's vh_resolve_bi uses. This is
     * the missing link: without it, a body-level lookahead miss returns JOB_IDLE
     * here (TF_BLOCKED_LOOKAHEAD_MISSING) BEFORE the canonical-successor gate
     * below can ever run. Read-only on the window; the gate re-proves PoW +
     * most-work + ancestry before any finalize, and a genuine absence still
     * falls through to the blocked-IDLE returns. */
    if (ms->pindex_best_header) {
        if (!old_tip && next_h <= ms->pindex_best_header->nHeight)
            old_tip = block_index_get_ancestor(ms->pindex_best_header, next_h);
        if (!new_tip && next_h + 1 <= ms->pindex_best_header->nHeight) {
            struct block_index *header_tip =
                block_index_get_ancestor(ms->pindex_best_header, next_h + 1);
            if (header_lookahead_extends_tip(old_tip, header_tip))
                new_tip = header_tip;
        }
    }
    if (!new_tip) {
        tip_finalize_observe_mark_blocked(TIP_FINALIZE_BLOCKED_LOOKAHEAD_MISSING);
        return JOB_IDLE;
    }
    if (!old_tip || !old_tip->phashBlock) {  /* ANOMALY: names a typed blocker — see tip_finalize_observe_note_tip_missing */
        tip_finalize_observe_note_tip_missing(next_h);
        return JOB_IDLE;
    }
    /* old_tip (and new_tip above) resolved — clear any stale tip-missing claim. */
    tip_finalize_observe_clear_tip_missing();

    bool anchor_row_compatible = upstream.is_anchor ||
        upstream.evidence == MINT_VALIDATION_EVIDENCE_VERIFIED;
    int anchor_ready = anchor_row_compatible
        ? tip_finalize_trusted_anchor_at(db, next_h, old_tip->phashBlock) : 0;
    if (anchor_ready < 0)
        return JOB_FATAL;
    if (upstream.ok != 1)
        return tip_finalize_evidence_refuse(c, next_h, upstream.evidence);
    if (anchor_ready != 1) {
        int evidence_ready = tip_finalize_full_evidence_at(
            db, next_h, old_tip->phashBlock);
        if (evidence_ready < 0)
            return JOB_FATAL;
        if (upstream.evidence != MINT_VALIDATION_EVIDENCE_VERIFIED ||
            evidence_ready != 1)
            return tip_finalize_evidence_refuse(c, next_h, upstream.evidence);
    }
    tip_finalize_evidence_clear();

    struct arith_uint256 work_delta;
    arith_uint256_set_zero(&work_delta);

    /* Canonical-parent check BY BLOCK HASH, not pointer identity. old_tip and
     * new_tip can now be resolved from DIFFERENT authorities (active-chain
     * window vs best-header ancestry vs block map via the self-heals above), so
     * a duplicate same-hash block_index object would make a pointer compare
     * false-detect a reorg and write an ok=0 row that caps H* a block below the
     * truth — the exact class bde617a7e fixed in the window extender. Contiguity
     * is the consensus property child.hashPrevBlock == parent.GetBlockHash();
     * test THAT. A genuine fork (different parent hash, or a NULL/severed pprev)
     * still takes the reorg_detected ok=0 advance below — invariant 4 intact. */
    if (!new_tip->pprev || !new_tip->pprev->phashBlock || !old_tip->phashBlock ||
        !uint256_eq(new_tip->pprev->phashBlock, old_tip->phashBlock)) {
        int depth = reorg_depth_from(old_tip, new_tip);
        if (!log_insert(db, next_h, "reorg_detected", false, &work_delta, -1, depth, NULL))
            return JOB_FATAL;
        tip_finalize_observe_inc_reorg_detected();
        event_emitf(EV_BLOCK_REJECTED, 0,
                    "tip_finalize reorg_detected height=%d depth=%d", next_h, depth);
        c->cursor_out = c->cursor_in + 1;
        return JOB_ADVANCED;
    }

    /* Reaching here we KNOW new_tip->pprev == old_tip (the structural-reorg
     * branch above returned first) — a LINEAR one-block lookahead extension.
     * Two outcomes are NOT the same and must be handled differently:
     *
     *  (a) HOLD (block_missing / block_failed / have_data_missing /
     *      not_script_valid / not_header_valid): the successor H+1 is not an
     *      eligible canonical witness yet.  A failed successor is especially
     *      important here: invalidateblock may retract chain[] while the
     *      durable finalized-hash row still resolves that exact map owner.
     *      Re-finalizing through it would republish the failed block, run its
     *      post-finalize mempool removal, and oscillate back to the rewind.
     *      H is genuinely finalizable only once an eligible successor exists.
     *      We must NOT advance the cursor — advancing strands H forever
     *      because anchor_cursor_to_authority is MONOTONIC (never pulls back),
     *      producing a finalize-frontier oscillation. Return JOB_IDLE:
     *      cursor unchanged, framework rolls back the txn (no junk row), and
     *      the frontier retries on the next tick once the successor lands.
     *
     *  (b) chainwork_not_greater: a LINEAR successor that adds no work. On a
     *      valid PoW chain GetBlockProof() is strictly >= 1 per block, so this
     *      is unreachable for a real header; it appears only from a
     *      corrupt/zero-work synthetic candidate that must NEVER finalize.
     *      Persist the precondition_failed ok=0 row, count it, emit the
     *      reject, and ADVANCE past it so the pipeline cannot deadlock on an
     *      unfinalizable lighter candidate. */
    const char *transient_reason = tip_finalize_precondition_block_reason(new_tip);
    /* not_script_valid from the block_index mirror is NOT authoritative: the bit
     * can drift CLEAR on a restored datadir while the reducer's hash-bound
     * script_validate_log still proves THIS block's scripts were verified. When
     * (and only when) the reason is the script-validity level, the candidate is
     * not a failed block, and the log carries a hash-matched ok=1 row, treat the
     * scripts as valid and heal the in-RAM bit so other nStatus readers + the
     * persisted projection converge. The have_data_missing / not_header_valid /
     * block_missing reasons are unchanged — only the script-validity source is
     * rerouted to the authority. */
    if (transient_reason != NULL &&
        strcmp(transient_reason, "not_script_valid") == 0 &&
        !(new_tip->nStatus & BLOCK_FAILED_MASK) &&
        tip_finalize_script_evidence_at(
            db, new_tip->nHeight, new_tip->phashBlock) == 1) {
        new_tip->nStatus = (new_tip->nStatus & ~(unsigned)BLOCK_VALID_MASK)
                           | BLOCK_VALID_SCRIPTS;
        block_index_emit_header_event(new_tip, "tip_finalize_selfheal",
                                      NULL, NULL);
        transient_reason = NULL;
    }
    if (transient_reason != NULL) {
        /* HEADER-ONLY FINALIZE (deadlock-cure step 3). N's own upstream verdict
         * is ok=1 (the upstream.ok gate above). If N+1 is a CANONICAL header
         * successor — PoW-verified, strictly-greater-work, best-header ancestor,
         * canonical parent — then N is provably on the most-work chain and is
         * finalizable NOW using N+1 as a HEADER witness, even though N+1's body /
         * scripts / utxo verdict are not yet pipelined. Requiring them here is
         * the body-level lookahead that deadlocks the frontier (live 3162166):
         * the downstream stages cannot fold N+1 until the window exposes it, and
         * the window will not pass a frozen finalize tip. Clear transient_reason
         * and FALL THROUGH to the normal finalize tail — it consumes only N+1's
         * HEADER fields (nChainWork, phashBlock, nHeight), so the durable row
         * (lookahead convention, hash(N+1), status "finalized"), the reorg-rewind
         * scan, and the H* refresh are exactly the normal-finalize semantics
         * (no anchor row, so no reorg-rewind blind spot). H* still climbs
         * only to N (utxo_apply caps the contiguous ok=1 prefix), so N+1 is never
         * served. The window move + served-tip publish in the tail are
         * HAVE_DATA-gated, so a still-bodiless N+1 finalizes N (H* += 1) WITHOUT
         * pinning a bodiless slot or advertising an unbodied active-chain tip. */
        if (is_canonical_header_successor(old_tip, new_tip,
                                          ms->pindex_best_header)) {
            tip_finalize_observe_inc_header_witness();
            transient_reason = NULL;  /* proceed to the normal finalize tail */
        } else {
            tip_finalize_observe_inc_successor_pending();
            tip_finalize_observe_record_precondition_block(next_h,
                                                           transient_reason);
            tip_finalize_observe_mark_blocked(
                TIP_FINALIZE_BLOCKED_SUCCESSOR_PENDING);
            /* Genuinely not a canonical successor (no/!PoW header, off
             * best_header, or not greater work): hold H until its successor is
             * ready. No DB row, no cursor move. */
            return JOB_IDLE;
        }
    }
    if (arith_uint256_compare(&new_tip->nChainWork, &old_tip->nChainWork) <= 0) {
        if (!log_insert(db, next_h, "precondition_failed", false, &work_delta, -1, 0, NULL))
            return JOB_FATAL;
        tip_finalize_observe_inc_precondition_failed();
        tip_finalize_observe_record_precondition_block(
            next_h, "chainwork_not_greater");
        event_emitf(EV_BLOCK_REJECTED, 0,
                    "tip_finalize precondition_failed height=%d reason=%s",
                    next_h, "chainwork_not_greater");
        c->cursor_out = c->cursor_in + 1;
        return JOB_ADVANCED;
    }

    arith_uint256_sub(&work_delta, &new_tip->nChainWork, &old_tip->nChainWork);

    int64_t utxo_size_after = -1;
    if (!live_utxo_count_after(next_h + 1, &utxo_size_after))
        return JOB_FATAL;
    if (utxo_size_after >= 0) {
        int64_t spent = 0, added = 0;
        /* O(1) running total instead of an O(height) SUM(...) WHERE height<=?
         * per finalize (which made this stage O(height^2) over a fold). upstream
         * is THIS height's own ok=1 utxo_apply row (loaded above), so the cache
         * folds in exactly the row the full SUM would; it falls back to the full
         * SUM on any non-adjacency (reorg rewind / ok=0 gap) or the self-check
         * stride. Identical values to utxo_apply_sums_through in all cases. */
        int64_t tf_sum_t0 = platform_time_monotonic_us();
        if (!utxo_apply_sum_through_incremental(db, next_h,
                                                upstream.spent_count,
                                                upstream.added_count,
                                                &spent, &added))
            return JOB_FATAL;
        reducer_stage_profile_observe_us(
            REDUCER_PROFILE_TIP_FINALIZE, RPF_TF_INCREMENTAL_SUM_US,
            (uint64_t)(platform_time_monotonic_us() - tf_sum_t0));
        int64_t expected = added - spent;
        if (utxo_size_after != expected) {
            if (!log_insert(db, next_h, "utxo_count_diverged", false,
                            &work_delta, utxo_size_after, 0, NULL))
                return JOB_FATAL;
            tip_finalize_observe_inc_utxo_count_diverged();
            event_emitf(EV_BLOCK_REJECTED, 0,
                        "tip_finalize utxo_count_diverged height=%d live=%lld expected=%lld",
                        next_h, (long long)utxo_size_after, (long long)expected);
            c->cursor_out = c->cursor_in + 1;
            return JOB_ADVANCED;
        }
    }

    int64_t tf_log_t0 = platform_time_monotonic_us();
    if (!log_insert(db, next_h, "finalized", true, &work_delta,
                    utxo_size_after, 0, new_tip->phashBlock))
        return JOB_FATAL;
    reducer_stage_profile_observe_us(
        REDUCER_PROFILE_TIP_FINALIZE, RPF_TF_LOG_INSERT_US,
        (uint64_t)(platform_time_monotonic_us() - tf_log_t0));

    int64_t published_before = tip_finalize_observe_last_height();
    /* Advertise the served-tip authority (g_last_advance_height ->
     * active_chain_height / active_chain_tip) ONLY when new_tip has its body: a
     * header-only finalize of N on a still-bodiless N+1 must not move the
     * active-chain tip onto N+1. H* (getblockcount / P2P start_height) is
     * published separately by tf_refresh_provable_tip below and still climbs to
     * N. For a normal finalize new_tip always has BLOCK_HAVE_DATA (precondition
     * passed), so this is a no-op there. */
    bool publish = (new_tip->nStatus & BLOCK_HAVE_DATA) &&
                   (published_before < 0 || new_tip->nHeight >= (int)published_before);

    /* Durable row first; then move the local chain[] cache/window — EXCEPT
     * during a from-genesis refold. There the stage extend already widened the
     * window to best_header, so retracting it to next_h+1 here forces the next
     * stage step to re-walk ~3.1M pprev nodes (active_chain_fill_window) — the
     * dominant cold-refold cost (~3 blk/s, CPU cache-bound). The served-tip
     * AUTHORITY is g_last_advance_height (published by update_last_advance
     * below), NOT c->height, so leaving the window wide keeps active_chain_height
     * / getblockcount correct; only active_chain_at visibility stays wide, which
     * is safe during a refold — the stages read at/below the fold frontier and
     * the watchdog/reconcile are suspended (refold_in_progress()). Normal sync
     * keeps the retraction (the window must track the finalized frontier). See
     * docs/work/refold-fold-rate-bottlenecks.md (#1). */
    bool tf_do_window =
        !refold_in_progress() && (new_tip->nStatus & BLOCK_HAVE_DATA);
    int64_t tf_win_t0 = platform_time_monotonic_us();
    if (tf_do_window &&
        !tip_finalize_batch_window_move(ms, new_tip)) { // one-write-path-ok:reducer-tip-authority
        /* HAVE_DATA gate (deadlock-cure step 3): never move the window onto a
         * body-missing N+1 — that is the bodiless-slot pin the have-data extender
         * is built to refuse (false-reorg cascade). When N+1's body is present
         * (the live 3162167 case, and ALWAYS for a normal finalize) the window
         * advances so the downstream body stages can fold N+1 and the frontier
         * cascades; when it is absent we still finalize N (H* += 1) and the body
         * is fetched by gap_fill / stall recovery before the window catches up. */
        LOG_WARN("tip_finalize", "[tip_finalize] chain_active set_tip failed height=%d", next_h);
        return JOB_FATAL;
    }
    if (tf_do_window)
        reducer_stage_profile_observe_us(
            REDUCER_PROFILE_TIP_FINALIZE, RPF_TF_WINDOW_MOVE_US,
            (uint64_t)(platform_time_monotonic_us() - tf_win_t0));

    tip_finalize_observe_inc_finalized();
    tip_finalize_observe_add_work(&work_delta);
    if (publish) {
        int64_t tf_post_t0 = platform_time_monotonic_us();
        tip_finalize_run_post_finalize(new_tip);
        reducer_stage_profile_observe_us(
            REDUCER_PROFILE_TIP_FINALIZE, RPF_TF_POST_FINALIZE_US,
            (uint64_t)(platform_time_monotonic_us() - tf_post_t0));
        /* Publish the SELF-CONSISTENT authority pair: the served tip block's
         * OWN height with its OWN hash — derive the label from the block,
         * never the cursor. Publishing (next_h, hash(next_h+1)) makes
         * active_chain_height() == active_chain_tip()->nHeight - 1 at the
         * finalize frontier, and accept_block_header's label-trust install
         * turns that inconsistent pair into a -1 height splice across the
         * whole header graph when a peer re-delivers the tip header. */
        tip_finalize_observe_update_last_advance(new_tip->nHeight,
                                                 new_tip->phashBlock->data);
    } else if (new_tip->nStatus & BLOCK_HAVE_DATA) {
        /* An at-tip authority path may have published this exact block before
         * the reducer writes its finalized row. The wallet/MMR/MMB effects are
         * one-shot and remain gated by publish, but cache invalidation and
         * confirmed-tx removal are idempotent and mandatory. Skipping them
         * leaves an already-confirmed transaction live in the mempool. */
        int64_t tf_post_t0 = platform_time_monotonic_us();
        tip_finalize_run_mempool_reconcile(new_tip);
        reducer_stage_profile_observe_us(
            REDUCER_PROFILE_TIP_FINALIZE, RPF_TF_POST_FINALIZE_US,
            (uint64_t)(platform_time_monotonic_us() - tf_post_t0));
    }
    /* O(1) watermark advance (or full-fold fallback on any doubt) — see
     * tf_advance_provable_tip. reorg rewind always takes the full path above. */
    int64_t tf_pt_t0 = platform_time_monotonic_us();
    tf_advance_provable_tip(db, next_h);
    reducer_stage_profile_observe_us(
        REDUCER_PROFILE_TIP_FINALIZE, RPF_TF_PROVABLE_TIP_US,
        (uint64_t)(platform_time_monotonic_us() - tf_pt_t0));
    c->cursor_out = c->cursor_in + 1;
    return JOB_ADVANCED;
}

static bool is_authoritative(void)
{
    return true;
}

static int64_t get_height(void)
{
    return tip_finalize_stage_last_height();
}

static bool get_hash(uint8_t hash[32])
{
    int64_t h;
    return tip_finalize_observe_get_last_advance(&h, hash);
}

bool tip_finalize_stage_init(struct main_state *ms)
{
    if (!ms) LOG_FAIL("tip_finalize", "init: NULL main_state");

    sqlite3 *db = progress_store_db();
    if (!db) LOG_FAIL("tip_finalize", "init: progress_store not open");

    pthread_mutex_lock(&g_lock);
    tip_finalize_observe_init();
    tip_finalize_visible_body_reset();
    /* Drop any volatile utxo_apply SUM cache from a prior lifecycle: the next
     * finalize re-seeds it from the full SUM (this datadir's own durable rows). */
    utxo_apply_sum_through_reset();
    g_ms = ms;

    struct block_index *existing_tip = active_chain_cached_tip(&ms->chain_active);

    struct active_chain_authority auth = { .get_height = get_height,
        .get_hash = get_hash, .is_authoritative = is_authoritative };
    active_chain_register_authority(&auth);
    active_chain_register_block_map(&ms->map_block_index);

    if (g_stage != NULL) {
        if (existing_tip && existing_tip->phashBlock &&
            !tip_finalize_anchor_cursor_to_authority(db, existing_tip->nHeight,
                existing_tip->phashBlock->data, false, false, "init_existing_tip_reanchor")) {
            pthread_mutex_unlock(&g_lock);
            return false;
        }
        if (!tip_finalize_stage_hydrate_cursor_from_store(
                db, g_stage, "init_existing_tip_reanchor")) {
            pthread_mutex_unlock(&g_lock);
            return false;
        }
        tip_finalize_stage_publish_resolved_or_fresh_tip(
            db, existing_tip, "init_existing_tip_reanchor");
        tf_warm_provable_tip_once(db, "init_existing_tip_reanchor");
        chain_evidence_note_finalized_tip(existing_tip);
        pthread_mutex_unlock(&g_lock);
        return true;
    }

    if (!ensure_log_schema(db)) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    stage_t *s = stage_create(STAGE_NAME, step_finalize, NULL);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        LOG_FAIL("tip_finalize", "init: stage_create failed");
    }

    g_ms = ms;
    g_stage = s;
    /* The active-chain cache is a served-tip authority, not reducer progress.
     * On recovered datadirs it may sit above H-star/coins while upstream stage
     * cursors are deliberately clamped for repair. Publish the tip_finalize
     * authority cursor, but only explicit seed anchors may align upstream
     * reducer cursors. */
    if (existing_tip && existing_tip->phashBlock &&
        !tip_finalize_anchor_cursor_to_authority(db, existing_tip->nHeight,
                existing_tip->phashBlock->data, false, true, "init_existing_tip")) {
        stage_destroy(s);
        g_stage = NULL;
        pthread_mutex_unlock(&g_lock);
        return false;
    }
    if (!tip_finalize_stage_hydrate_cursor_from_store(
            db, s, "init_existing_tip")) {
        stage_destroy(s);
        g_stage = NULL;
        pthread_mutex_unlock(&g_lock);
        return false;
    }
    tip_finalize_stage_publish_resolved_or_fresh_tip(
        db, existing_tip, "init_existing_tip");
    tf_warm_provable_tip_once(db, "init_existing_tip");
    chain_evidence_note_finalized_tip(existing_tip);
    pthread_mutex_unlock(&g_lock);

    LOG_INFO("tip_finalize", "[tip_finalize] stage initialised (authoritative)");
    return true;
}

job_result_t tip_finalize_stage_step_once(void)
{
    if (!g_stage) return JOB_IDLE;
    sqlite3 *db = progress_store_db();
    if (!db) return JOB_IDLE;
    progress_store_tx_lock();
    /* Re-widen chain[] INSIDE the lock so the extend, reorg-check, read
     * (active_chain_at), and write (active_chain_move_window_tip) are
     * atomic from this thread's perspective — closing the race where a
     * concurrent active_chain write changed chain[next_h+1] between the
     * extend and step_finalize's decision. stage_helpers.h
     * Lock-order: progress_store_tx_lock -> active_chain.write_lock;
     * reverse does not exist (active_chain_fill_window is array-only). */
    reducer_extend_window_to_candidate(g_ms, true);
    bool rewind_ok = rewind_cursor_if_active_chain_reorged(db);
    if (!rewind_ok) {
        progress_store_tx_unlock();
        return JOB_FATAL;
    }
    /* One-time provable-tip cache warm. H* (the getblockcount / explorer /
     * health / P2P start_height authority) is published ONLY on a finalize
     * advance (step_finalize) or a reorg rewind (above). A node that boots
     * already AT tip — the -load-snapshot-at-own-height resume path, or any
     * normal at-tip restart between blocks — hits neither, so the cache would
     * sit at the -1 sentinel (served as 0) until the next network block
     * finalizes (up to a full block interval). Publish the durable H* once here:
     * we hold progress_store_tx_lock and the reorg check already ran, so
     * compute_hstar reads a consistent committed prefix. Gated on the published
     * sentinel so the O(tip-anchor) fold runs exactly once; the advance/rewind
     * chokepoints keep it fresh thereafter. On a fresh/IBD node this publishes
     * the honest 0 (unchanged served value) and the advance path takes over. */
    if (!reducer_frontier_provable_tip_is_published())
        tf_refresh_provable_tip(db);
    tip_finalize_reconcile_visible_cursor_body(db, g_stage, g_ms);
    job_result_t r = stage_run_once(g_stage, db);
    progress_store_tx_unlock();
    return r;
}

void tip_finalize_stage_shutdown(void)
{
    tip_finalize_evidence_clear();
    pthread_mutex_lock(&g_lock);
    tip_finalize_visible_body_reset();
    if (g_stage) {
        stage_destroy(g_stage);
        g_stage = NULL;
    }
    g_ms = NULL;
    tip_finalize_hooks_reset();
    tip_finalize_observe_shutdown();
    utxo_apply_sum_through_reset();
    /* Mirror the served-tip reset into the external provable-tip cache so a
     * stale-high H* from this run cannot leak into the next boot. */
    reducer_frontier_provable_tip_reset();
    pthread_mutex_unlock(&g_lock);
}

/* tip_finalize_stage_set_authoritative_tip, tip_finalize_stage_seed_anchor,
 * and the durable tip readers live in sibling TUs. The DI-hook setters
 * (tip_finalize_stage_set_utxo_counter / _set_reorg_clamp) and their accessors
 * live in tip_finalize_stage_hooks.c. */

uint64_t tip_finalize_stage_cursor(void) { return g_stage ? stage_cursor(g_stage) : 0; }
int64_t tip_finalize_stage_step_us_ewma(void)
{
    return g_stage ? stage_step_us_ewma(g_stage) : 0;
}
int64_t tip_finalize_stage_last_height(void) { return tip_finalize_observe_last_height(); }

/* Test-only: reset the published served-tip height to -1 (a stale high value
 * from a prior group without shutdown() poisons later active_chain_tip reads). */
void tip_finalize_stage_test_reset(void) { tip_finalize_observe_reset_last_height(); reducer_frontier_provable_tip_reset(); utxo_apply_sum_through_reset(); }
uint64_t tip_finalize_stage_finalized_total(void) { return tip_finalize_observe_finalized_total(); }
uint64_t tip_finalize_stage_upstream_failed_total(void) { return tip_finalize_observe_upstream_failed_total(); }
uint64_t tip_finalize_stage_reorg_detected_total(void) { return tip_finalize_observe_reorg_detected_total(); }
uint64_t tip_finalize_stage_utxo_count_diverged_total(void) { return tip_finalize_observe_utxo_count_diverged_total(); }
uint64_t tip_finalize_stage_precondition_failed_total(void) { return tip_finalize_observe_precondition_failed_total(); }
uint64_t tip_finalize_stage_successor_pending_total(void) { return tip_finalize_observe_successor_pending_total(); }
uint64_t tip_finalize_stage_header_witness_total(void) { return tip_finalize_observe_header_witness_total(); }
uint64_t tip_finalize_stage_total_work_added_low(void) { return tip_finalize_observe_total_work_added_low(); }

/* Lock-free blocked-class snapshot for the supervisor stall log. Returns a
 * process-lifetime string literal (safe for LOG_WARN); "" when none yet. */
const char *tip_finalize_stage_last_blocked_reason(void)
{
    return tip_finalize_observe_last_blocked_reason();
}

bool tip_finalize_dump_state_json(struct json_value *out, const char *key)
{
    sqlite3 *db = progress_store_db();
    return tip_finalize_observe_dump_state_json(out, key, db, g_stage);
}

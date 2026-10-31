/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Reconcile L1 reducer flags and cursors without mutating coins. */

#include "jobs/stage_repair.h"
#include "jobs/stage_repair_internal.h"
#include "stage_repair_reducer_frontier_evidence.h"
#include "stage_repair_reducer_frontier_internal.h"

#include "jobs/block_header_emit.h"
#include "jobs/reducer_frontier.h"
#include "platform/time_compat.h"
#include "storage/coins_kv.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "util/stage.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

static bool maybe_emit_header(struct block_index *bi, bool apply,
                              const char *why,
                              struct stage_reducer_frontier_reconcile_result *out)
{
    if (!apply)
        return true;
    block_index_emit_header_event(bi, why, NULL, NULL);
    out->header_events_emitted++;
    return true;
}

/* Flag-reconcile steps for one block_index entry that raise or set state from
 * log evidence. Returns true when the entry needed a change. */
static bool reconcile_block_flags_set(
    struct block_index *bi,
    const struct rf_log_evidence *ev,
    bool readable,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    bool changed = false;
    if (ev->script_ok_hash &&
        (bi->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS) {
        if (apply) {
            bi->nStatus = (bi->nStatus & ~(unsigned)BLOCK_VALID_MASK)
                          | BLOCK_VALID_SCRIPTS;
        }
        out->scripts_set++;
        changed = true;
    }

    if (ev->validate_ok_hash && ev->body_ok && readable &&
        (bi->nStatus & BLOCK_HAVE_DATA) == 0) {
        if (apply)
            bi->nStatus |= BLOCK_HAVE_DATA;
        out->have_data_set++;
        changed = true;
    }
    return changed;
}

/* Flag-reconcile steps for one block_index entry that clear state the evidence
 * disproves. Returns true when the entry needed a change. */
static bool reconcile_block_flags_clear(
    struct block_index *bi,
    const struct rf_log_evidence *ev,
    bool readable,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    bool changed = false;
    if ((bi->nStatus & BLOCK_HAVE_DATA) && !readable) {
        if (apply) {
            bi->nStatus &= ~(unsigned)BLOCK_HAVE_DATA;
            bi->nFile = -1;
            bi->nDataPos = 0;
        }
        out->have_data_cleared++;
        if (out->lowest_have_data_cleared < 0 ||
            bi->nHeight < out->lowest_have_data_cleared)
            out->lowest_have_data_cleared = bi->nHeight;
        changed = true;
    }

    if ((bi->nStatus & BLOCK_FAILED_MASK) &&
        ev->script_ok_hash && ev->proof_ok_hash && ev->utxo_ok_hash) {
        if (apply)
            bi->nStatus &= ~(unsigned)BLOCK_FAILED_MASK;
        out->failed_mask_cleared++;
        changed = true;
    }
    return changed;
}

static bool reconcile_block_index_flags(
    sqlite3 *db,
    struct main_state *ms,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    char datadir[2048];
    GetDataDir(true, datadir, sizeof(datadir));

    /* LOCK ORDER: cs_main OUTER, progress store INNER — but the inner one
     * is a TRYLOCK, and that is the whole point.
     *
     * The tree holds BOTH nesting orders and cannot be made to hold only
     * one:
     *   - Before tip_finalize_stage_init registers the height authority,
     *     active_chain_height() reads the progress store internally
     *     (core/modules/validation/src/chainstate.c), so every cs_main holder is
     *     cs_main -> progress. That boot window is where a startup
     *     wedge can occur.
     *   - After it, is_authoritative() returns true unconditionally
     *     (engine/jobs/src/tip_finalize_stage.c) so that edge disappears —
     *     while the reducer drive runs the opposite way for the whole
     *     process lifetime: STAGE_DRAIN_IMPL (engine/jobs/include/jobs/job.h)
     *     holds progress across every step, and body_fetch's step takes
     *     cs_main inside it (engine/jobs/src/body_fetch_stage.c).
     * A repair that BLOCKS on the second lock therefore closes a cycle
     * against one phase or the other no matter which order it picks.
     *
     * So it blocks on neither. This is a self-heal observer on the
     * condition-engine thread, not a correctness-critical path, and the
     * codebase already names this shape: progress_store_tx_trylock() is
     * the "non-blocking counterpart for observational surfaces", used the
     * same way by engine/conditions/src/reducer_drive_watchdog.c. Losing the
     * race costs one tick — the condition re-runs — and it can never
     * wait-for a lock while holding cs_main, so it cannot be half of a
     * deadlock. Skipped, not blocked. The stale-script replay holds both in
     * the opposite order under the same rule: reducer_frontier_replay_lock
     * takes progress, tries cs_main, and releases progress before retrying. */
    zcl_mutex_lock(&ms->cs_main);
    if (!progress_store_tx_trylock()) {
        zcl_mutex_unlock(&ms->cs_main);
        return false;
    }

    struct rf_evidence_stmts es;
    if (!rf_evidence_stmts_prepare(db, &es)) {
        progress_store_tx_unlock();
        zcl_mutex_unlock(&ms->cs_main);
        return false;
    }

    bool ok = true;
    size_t iter = 0;
    struct block_index *bi = NULL;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &bi)) {
        if (!bi || bi->nHeight <= out->hstar || bi->nHeight > out->sweep_top)
            continue;

        struct rf_log_evidence ev;
        if (!rf_evidence_for_block_unlocked(&es, bi, &ev)) {
            ok = false;
            break;
        }

        /* Full-block read + rehash ONLY when the verdict can depend on it:
         * the HAVE_DATA-set check needs it only with validate+body evidence
         * present, the HAVE_DATA-clear check only when the flag is set. The
         * set-then-clear interleave cannot misread the gate: the set fires
         * only when `readable` just proved true, making the clear's
         * !readable false. Everything else below never reads `readable`. */
        bool readable = false;
        if ((bi->nStatus & BLOCK_HAVE_DATA) ||
            (ev.validate_ok_hash && ev.body_ok))
            readable = stage_reducer_frontier_block_pos_readable_hash(bi, datadir);

        bool changed =
            reconcile_block_flags_set(bi, &ev, readable, apply, out);
        if (reconcile_block_flags_clear(bi, &ev, readable, apply, out))
            changed = true;

        if (changed)
            maybe_emit_header(bi, apply,
                              "reducer_frontier_reconcile_light", out);
    }

    rf_evidence_stmts_finalize(&es);
    progress_store_tx_unlock();
    zcl_mutex_unlock(&ms->cs_main);
    return ok;
}

/* ── tip_finalize rewind-churn refusal (defence-in-depth under the
 * coins-frontier clamp above) ────────────────────────────────────────────
 * A repeated rewind-to-the-same-height pass can read as progress every
 * tick (the write lands, apply reports repaired=true) while H* never moves
 * and something upstream keeps re-advancing the cursor back to the same
 * height between passes. That shape is a
 * livelock: the reconcile keeps re-clamping the SAME height forever
 * instead of a named blocker ever surfacing.
 *
 * This memo tracks consecutive rewinds to the identical target height
 * while H* (out->hstar, freshly computed by reducer_frontier_compute_hstar
 * every pass) stays pinned at the value it had on the FIRST rewind of the
 * streak. Once the streak reaches TIP_FINALIZE_REWIND_CHURN_LIMIT
 * consecutive asks, the rewind is refused and a typed TRANSIENT blocker
 * names the loop so the meta-detector/ladder escalates instead of the
 * reconcile quietly re-succeeding forever. A forward advance (catching
 * tip_finalize UP toward hstar+1) is never gated here — only a target
 * strictly BELOW the current cursor is a rewind. The memo (and any fired
 * blocker) resets the moment the target height or hstar_at_first_rewind
 * differs from the pinned streak, i.e. whenever H* advances or a different
 * height is being asked for.
 *
 * Plain statics: the reconcile apply runs on the serial reducer-drive
 * thread (LOCK-ORDER LAW — this file never takes csr->lock); test callers
 * are serial too. */
#define TIP_FINALIZE_REWIND_CHURN_LIMIT 3
static struct {
    bool valid;
    int  target_height;
    int  hstar_at_first_rewind;
    int  consecutive_count;
} g_tip_finalize_rewind_churn_memo;

#ifdef ZCL_TESTING
void stage_reducer_frontier_reset_rewind_churn_memo_for_testing(void)
{
    memset(&g_tip_finalize_rewind_churn_memo, 0,
           sizeof(g_tip_finalize_rewind_churn_memo));
}
#endif

/* Returns true when the rewind to `target` must be REFUSED because the
 * streak already hit the limit — a typed blocker is registered and *out is
 * set to reflect the refusal (cursor left untouched). Returns false when
 * the rewind may proceed, having recorded this attempt in the memo
 * (starting a fresh streak — and clearing any prior blocker — when the
 * target height or the pinned hstar differs from the running streak). */
static bool tip_finalize_rewind_churn_gate(
    int cur, int target, int hstar,
    struct stage_reducer_frontier_reconcile_result *out)
{
    bool same_streak =
        g_tip_finalize_rewind_churn_memo.valid &&
        g_tip_finalize_rewind_churn_memo.target_height == target &&
        g_tip_finalize_rewind_churn_memo.hstar_at_first_rewind == hstar;

    if (same_streak && g_tip_finalize_rewind_churn_memo.consecutive_count >=
                            TIP_FINALIZE_REWIND_CHURN_LIMIT) {
        char reason[BLOCKER_REASON_MAX];
        snprintf(reason, sizeof(reason),
                 "tip_finalize rewind %d->%d refused: hstar=%d remained "
                 "pinned for %d requests; projection reconcile is cycling, "
                 "so the recovery ladder must escalate",
                 cur, target, hstar,
                 g_tip_finalize_rewind_churn_memo.consecutive_count);
        struct blocker_record rec;
        if (blocker_init(&rec, "tip_finalize.rewind_churn", "stage_repair",
                         BLOCKER_TRANSIENT, reason)) {
            rec.escape_deadline_secs = 60;
            blocker_set(&rec);
        }
        LOG_WARN("stage_repair",
                 "[stage_repair] reducer_frontier tip_finalize rewind churn "
                 "refused: cur=%d target=%d hstar=%d count=%d",
                 cur, target, hstar,
                 g_tip_finalize_rewind_churn_memo.consecutive_count);
        out->tip_finalize_cursor_after = cur;
        out->clamped_tip_finalize = false;
        return true;
    }

    if (same_streak) {
        g_tip_finalize_rewind_churn_memo.consecutive_count++;
    } else {
        blocker_clear("tip_finalize.rewind_churn");
        g_tip_finalize_rewind_churn_memo.valid = true;
        g_tip_finalize_rewind_churn_memo.target_height = target;
        g_tip_finalize_rewind_churn_memo.hstar_at_first_rewind = hstar;
        g_tip_finalize_rewind_churn_memo.consecutive_count = 1;
    }
    return false;
}

static void tip_finalize_preserve_trusted_base(
    sqlite3 *db, int cur, int *lo, int *hi,
    struct stage_reducer_frontier_reconcile_result *out)
{
    if (stage_repair_preserve_trusted_base_transition(
            db, out->hstar, cur, out)) {
        *hi = cur;
        if (*lo > *hi)
            *lo = *hi;
    }
}

static int tip_finalize_cursor_target(int cur, int lo, int hi)
{
    return cur < lo ? lo : (cur > hi ? hi : cur);
}

static bool reconcile_tip_finalize_cursor(
    sqlite3 *db,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    /* OWN-frame: accept [hstar, hstar+1] capped at coins_applied's next
     * height. Capping one lower clamped the catch-up resting state every
     * pass and livelocked the rewind-churn gate; refuse deeper caps. */
    int cur = out->tip_finalize_cursor_before;
    int lo = out->hstar;
    int hi = out->hstar + 1;
    if (out->coins_applied_found && out->coins_applied_height >= 0) {
        int applied_through = out->coins_applied_height - 1;
        if (applied_through < 0)
            applied_through = 0;
        int min_allowed = out->hstar > 0 ? out->hstar - 1 : 0;
        if (applied_through < min_allowed) {
            out->tip_finalize_cursor_after = cur;
            LOG_WARN("stage_repair",
                     "[stage_repair] tip_finalize clamp refused: "
                     "coins_applied=%d applied_through=%d is below "
                     "hstar=%d min_allowed=%d cursor=%d",
                     out->coins_applied_height, applied_through,
                     out->hstar, min_allowed, cur);
            return true;
        }
        if (hi > applied_through + 1)
            hi = applied_through + 1;
        if (lo > hi)
            lo = hi;
    }

    tip_finalize_preserve_trusted_base(db, cur, &lo, &hi, out);

    int target = tip_finalize_cursor_target(cur, lo, hi);
    if (cur == target) {
        out->tip_finalize_cursor_after = cur;
        return true;
    }

    if (apply && target < cur &&
        tip_finalize_rewind_churn_gate(cur, target, out->hstar, out))
        return true;   /* rewind-churn refused: gate already set *out */

    out->clamped_tip_finalize = true;
    out->tip_finalize_cursor_after = target;
    if (!apply)
        return true;

    return stage_reducer_frontier_force_stage_cursor_in_tx(
        db, "tip_finalize", "L1", target);
}

#ifdef ZCL_TESTING
/* Test-only: drives the tip_finalize cursor clamp/rewind directly (bypasses
 * the full frontier snapshot + block_index sweep). The caller populates
 * `out->hstar`, `out->tip_finalize_cursor_before`, and optionally
 * `out->coins_applied_found` / `out->coins_applied_height`, then reads back
 * `out->clamped_tip_finalize` / `out->tip_finalize_cursor_after`. Used to
 * pin the rewind-churn refusal (see tip_finalize_rewind_churn_gate above)
 * without standing up a main_state/active-chain fixture. */
bool stage_reducer_frontier_reconcile_tip_finalize_cursor_for_testing(
    struct sqlite3 *db,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    return reconcile_tip_finalize_cursor(db, apply, out);
}
#endif

/* ── detect-path memo ───────────────────────────────────────────────────
 * The reconcile-light Condition polls the dry-run every 5 s; on a stalled
 * node each poll paid the full pipeline sweep (compute_hstar log walks,
 * per-height evidence reads, hash-verified block reads) under the global
 * locks. A dry-run against an unchanged store is deterministic, so the last
 * CLEAN full-pipeline dry-run is cached keyed on sqlite3_total_changes64
 * (any row write through the handle invalidates) and re-swept at least
 * every RF_DETECT_MEMO_TTL_SECS to bound staleness from the two inputs the
 * change counter cannot see: in-memory block_index flags mutated with no
 * progress.kv write, and block-file bytes on disk. Engages ONLY on the
 * progress_store_db() singleton, whose handle and change counter are stable
 * for the process lifetime (a closed-and-reopened private db could replay
 * both the pointer and the counter). Actionable, refused, or early-returned
 * results are never cached; every apply run invalidates. Plain statics:
 * detect and remedy both run on the serial condition-engine tick thread
 * (the g_cursor_gap_warn convention); test callers are serial. */
#define RF_DETECT_MEMO_TTL_SECS 60
static struct {
    bool valid;
    int64_t swept_unix;
    int64_t total_changes;
    struct stage_reducer_frontier_reconcile_result result;
} g_detect_memo;

#ifdef ZCL_TESTING
/* Test-only: drop the dry-run detect memo. The memo keys on (live db pointer,
 * total_changes, 60 s TTL) — sound in production where the progress.kv
 * connection is long-lived and total_changes is monotonic. But a test process
 * that closes and reopens progress.kv per fixture can reuse the freed db
 * pointer AND reset total_changes to a value that coincidentally matches a
 * prior fixture's cached entry, so a stale "clean" result wrongly hits. Tests
 * call this between fixtures to guarantee an uncontaminated sweep. */
void stage_reducer_frontier_reset_detect_memo_for_testing(void)
{
    g_detect_memo.valid = false;
    /* The rewind-churn memo is per-episode process state on the same serial
     * drive thread; a test process running many reconcile fixtures back to
     * back must clear it between fixtures too, or a prior fixture's streak
     * refuses a fresh fixture's legitimate rewind. */
    memset(&g_tip_finalize_rewind_churn_memo, 0,
           sizeof(g_tip_finalize_rewind_churn_memo));
}

bool stage_reducer_frontier_reconcile_flags_for_testing(
    sqlite3 *db,
    struct main_state *ms,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    return reconcile_block_index_flags(db, ms, apply, out);
}
#endif

/* Outcome of one early-exit step of the reconcile: run the next step, publish
 * the (final) result and return true, or return false. */
enum rf_step {
    RF_STEP_NEXT,
    RF_STEP_DONE,
    RF_STEP_FAIL,
};

/* Which throttled WARN the impl must emit for a finished step. */
enum rf_warn {
    RF_WARN_NONE,
    RF_WARN_COIN_UNKNOWN,
    RF_WARN_STALE_VALIDATE,
    RF_WARN_L1_REFUSED,
};

static void rf_publish_result(
    struct stage_reducer_frontier_reconcile_result *out,
    const struct stage_reducer_frontier_reconcile_result *local)
{
    if (out)
        *out = *local;
}

/* Serve a clean dry-run from the detect memo (true), or record the change
 * counter sampled before the sweep (false). */
static bool rf_detect_memo_lookup(
    sqlite3 *db, bool apply, bool memo_eligible,
    struct stage_reducer_frontier_reconcile_result *out,
    int64_t *changes_at_entry)
{
    *changes_at_entry = 0;
    if (apply) {
        /* The repair may mutate flags/cursors/logs; never serve a result
         * captured before it (failed applies invalidate too — safe side). */
        g_detect_memo.valid = false;
    } else if (memo_eligible && g_detect_memo.valid &&
               sqlite3_total_changes64(db) == g_detect_memo.total_changes &&
               platform_time_wall_unix() - g_detect_memo.swept_unix <
                   RF_DETECT_MEMO_TTL_SECS) {
        if (out)
            *out = g_detect_memo.result;
        return true;
    }
    /* Sampled BEFORE the sweep: a write racing the sweep moves the counter
     * past this sample, so the next dry-run misses the memo and re-sweeps. */
    *changes_at_entry =
        memo_eligible ? sqlite3_total_changes64(db) : 0;
    g_detect_memo.valid = false;
    return false;
}

static void rf_init_local(
    struct stage_reducer_frontier_reconcile_result *local)
{
    memset(local, 0, sizeof(*local));
    local->tip_finalize_cursor_before = -1;
    local->tip_finalize_cursor_after = -1;
    local->validate_headers_cursor_before = -1;
    local->validate_headers_cursor_after = -1;
    local->body_fetch_cursor_before = -1;
    local->body_fetch_cursor_after = -1;
    local->body_persist_cursor_before = -1;
    local->body_persist_cursor_after = -1;
    local->lowest_have_data_cleared = -1;
    local->lowest_validate_headers_refill_hole = -1;
    local->lowest_validate_headers_hash_split = -1;
    local->lowest_body_fetch_refill_hole = -1;
    local->lowest_body_persist_refill_hole = -1;
    local->lowest_script_validate_refill_hole = -1;
    local->lowest_proof_validate_refill_hole = -1;
    local->script_validate_cursor_before = -1;
    local->script_validate_cursor_after = -1;
    local->proof_validate_cursor_before = -1;
    local->proof_validate_cursor_after = -1;
    local->tipfin_backfill_height = -1;
    local->tipfin_backfill_refused_height = -1;
    local->tipfin_backfill_refused_log = STAGE_REPAIR_TIPFIN_LOG_UNKNOWN;
    local->coins_applied_height = -1;
    local->lowest_noncanonical = -1;
    local->lowest_reorg_residue_tipfin = -1;
    local->lowest_script_validate_hash_split = -1;
}

/* Snapshot, then the label-splice re-bind, the non-canonical purge and the
 * stale reorg-residue tip_finalize replacement, each re-reading the snapshot
 * when it changed the store. */
static bool rf_snapshot_and_purges(
    sqlite3 *db,
    struct main_state *ms,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *local)
{
    if (!stage_table_ensure(db))
        return false;
    if (!stage_reducer_frontier_read_snapshot(db, local))
        return false;  // raw-return-ok:callee LOG_WARNs every failure path

    /* Label-splice re-bind runs BEFORE every coin arm: a NULL-block_hash
     * proof/script suffix at the utxo_apply frontier pins H* on
     * utxo_apply.label_splice — a coins-untouching repair that must never be
     * masked by an unrelated coin refusal. It deliberately FALLS THROUGH (does
     * not early-return) so a fired re-bind and a later coin refusal coexist in
     * one result for the remedy to disambiguate. H* is unchanged (the deleted
     * rows sit above the frontier). See stage_repair_reducer_frontier_rebind.c. */
    bool label_splice_mutated = false;
    if (!stage_reducer_frontier_try_label_splice_rebind(db, apply, local,
                                                        &label_splice_mutated))
        return false;
    if (label_splice_mutated)
        local->repaired = true;

    /* Non-canonical residue purge runs FIRST: rows describing the wrong
     * block at their height (relabel/reorg residue) become ordinary
     * rowless holes, so every repair below sees a consistent world. The
     * purge itself clamps the script_validate / proof_validate cursors to
     * the lowest height it made rowless, in the same transaction as the
     * deletes: deletes without the clamp
     * strand the hole — the refill scan keys on the body_persist_log
     * anchor row the purge also deletes, so it reads no hole. */
    if (!stage_reducer_frontier_purge_noncanonical(db, ms, apply, local))
        return false;
    if (local->noncanonical_purged > 0) {
        local->repaired = true;
        /* Rows were deleted and cursors may have moved; re-read the
         * snapshot so every gate below sees the post-purge frontier and
         * cursors, not the pre-purge world. Counters / clamp flags are
         * preserved (stage_reducer_frontier_read_snapshot rewrites only
         * the frontier / cursor fields). The refusal flags are LATCHED
         * (the snapshot only ever SETS them true), so clear them first —
         * the re-read re-derives them from the post-purge store. */
        local->refused_coin_tear = false;
        local->refused_coin_unknown = false;
        if (!stage_reducer_frontier_read_snapshot(db, local))
            return false;  // raw-return-ok:callee LOG_WARNs every failure path
    }

    /* FIX-A — stale reorg-residue tip_finalize verdict replacement. A depth-N
     * reorg can leave an ok=0 'reorg_detected' tip_finalize row at a height
     * already covered by coins (h <= coins_applied-1) while the column above
     * it is a contiguous rowless gap that header_admit still evidences. That
     * ok=0 row caps H* one below h (the success-checked contiguity walk
     * terminates on it), which makes coins_applied > H*+1 read as a FALSE
     * coin tear, and the existing header_admit-keyed refill that WOULD heal
     * the column lives after the coin-tear refusal early-return (unreachable).
     * Replacing the residue verdict with a fresh ok=1 row (gated on coins
     * coverage + upstream re-evidence; never deletes, never touches coins)
     * lifts the H* cap so the snapshot re-reads with no tear and the existing
     * refill + tip_finalize clamp re-derive the column. Runs in the SAME
     * dry-run/apply spirit as the noncanonical purge above. */
    if (!stage_reducer_frontier_purge_stale_reorg_tipfin(db, apply, local))
        return false;
    if (local->reorg_residue_tipfin_replaced > 0) {
        local->repaired = true;
        /* The replacement moved H* (and may have cleared the tear); re-read
         * the snapshot so every gate below sees the lifted frontier. The
         * accumulated *_found / *_purged / *_replaced counters and `repaired`
         * are preserved (stage_reducer_frontier_read_snapshot rewrites only
         * the frontier / cursor fields, never these). The refusal flags
         * are LATCHED (the snapshot only ever SETS them true), so clear
         * them first — the re-read re-derives them from the lifted H*. */
        local->refused_coin_tear = false;
        local->refused_coin_unknown = false;
        if (!stage_reducer_frontier_read_snapshot(db, local))
            return false;  // raw-return-ok:callee LOG_WARNs every failure path
    }
    return true;
}

/* Step: an absent coin frontier is final. Sets *warn when the de-storm
 * throttle admits the WARN (the impl emits it). */
static enum rf_step rf_step_coin_unknown(
    const struct stage_reducer_frontier_reconcile_result *local,
    enum rf_warn *warn, uint64_t *reps)
{
    if (!local->refused_coin_unknown)
        return RF_STEP_NEXT;
    /* De-storm: fires every apply pass while coins_applied_height stays
     * absent. Key is constant (there is no varying identity here — the
     * condition is either present or not) so this collapses to
     * first-fire + 60 s keepalive, mirroring l1_refuse_throttle below. */
    static struct log_throttle coin_unknown_throttle = LOG_THROTTLE_INIT;
    if (log_throttle_should_emit(&coin_unknown_throttle, 1,
                                 platform_time_wall_unix(), 60, reps))
        *warn = RF_WARN_COIN_UNKNOWN;
    return RF_STEP_DONE;
}

static enum rf_step rf_step_replay(
    sqlite3 *db,
    struct main_state *ms,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *local)
{
    bool handled_replay = false;
    if (!stage_reducer_frontier_try_replay_repairs(
            db, ms, apply, local, &handled_replay))
        return RF_STEP_FAIL;
    if (handled_replay)
        return RF_STEP_DONE;
    return RF_STEP_NEXT;
}

static enum rf_step rf_step_pre_refusal(
    sqlite3 *db,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *local)
{
    /* Pre-refusal repairs, ordered: FIX-2a (clamp script/proof cursors back
     * to the lowest unapplied rowless hole) then FIX-1 (tip_finalize_log
     * backfill). Both exist for the coin-tear pin ONLY (see the decls in
     * stage_repair_reducer_frontier_internal.h) and run BEFORE the
     * coin-tear refusal so a healed frontier passes it arithmetically;
     * diagnostics live inside the callees. The tear gate lives HERE, not
     * just in the callees: the reconcile-light Condition polls _needed()
     * every 5s on any stalled node (tear or not), so the owner gate keeps
     * the healthy/no-tear path out of the pre-refusal adapter entirely. */
    /* Also fires for a tip_finalize-ONLY rowless hole with NO coin tear (the
     * live H*-pin class): served_floor > H* while coins are applied THROUGH the
     * span (applied-through >= served_floor), so the hash-bound insert-only
     * backfill fills it coins-backed. The unapplied-hole clamp stays tear-only. */
    bool tipfin_only_hole = !local->refused_coin_tear && local->hstar > 0 &&
        local->served_floor > local->hstar && local->coins_applied_found &&
        local->coins_applied_height - 1 >= local->served_floor;
    if (local->refused_coin_tear || tipfin_only_hole) {
        bool handled_pre_refusal = false;
        if (local->refused_coin_tear &&
            !stage_reducer_frontier_try_unapplied_hole_clamp(
                db, apply, local, &handled_pre_refusal))
            return RF_STEP_FAIL;
        if (!handled_pre_refusal &&
            !stage_reducer_frontier_try_tipfin_backfill(
                db, apply, local, &handled_pre_refusal))
            return RF_STEP_FAIL;
        if (handled_pre_refusal)
            return RF_STEP_DONE;
    }
    return RF_STEP_NEXT;
}

/* Step: the coin-tear refusal. A stale validate hash repaired before the
 * refusal, or the refusal itself, is final; *warn names the throttled WARN
 * the impl emits. */
static enum rf_step rf_step_coin_tear(
    sqlite3 *db,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *local,
    enum rf_warn *warn, uint64_t *reps)
{
    if (local->refused_coin_tear) {
        if (!stage_reducer_frontier_reconcile_validate_hash_split_cursor(
                db, apply, local))
            return RF_STEP_FAIL;
        if (local->clamped_validate_headers) {
            local->refused_coin_tear = false;
            local->repaired = true;
            if (apply) {
                /* De-storm: a wedged node re-hits this identical repair every
                 * reducer pass until the split genuinely clears. Key on the
                 * repair fingerprint (hstar, validate_headers target height)
                 * so a genuinely-advancing repair re-emits but a stuck repeat
                 * collapses to first-fire + 60 s keepalive. Mirrors
                 * l1_repaired_throttle below. */
                static struct log_throttle stale_validate_throttle =
                    LOG_THROTTLE_INIT;
                uint64_t key =
                    ((uint64_t)(uint32_t)local->hstar << 32) |
                    (uint32_t)local->validate_headers_cursor_after;
                if (log_throttle_should_emit(&stale_validate_throttle, key,
                                             platform_time_wall_unix(), 60,
                                             reps))
                    *warn = RF_WARN_STALE_VALIDATE;
            }
            return RF_STEP_DONE;
        }
    }

    if (local->refused_coin_tear) {
        /* De-storm: a wedged node reruns this reconcile every reducer pass.
         * Key on (coins_applied_height, hstar+1) so a moving frontier re-emits
         * but a stuck one collapses to first-fire + 60 s keepalive (reps). */
        static struct log_throttle l1_refuse_throttle = LOG_THROTTLE_INIT;
        uint64_t key = ((uint64_t)(uint32_t)local->coins_applied_height << 32)
                       | (uint32_t)(local->hstar + 1);
        if (log_throttle_should_emit(&l1_refuse_throttle, key,
                                     platform_time_wall_unix(), 60, reps))
            *warn = RF_WARN_L1_REFUSED;
        return RF_STEP_DONE;
    }
    return RF_STEP_NEXT;
}

/* The early-exit steps in order; the first non-NEXT outcome wins. */
static enum rf_step rf_run_steps(
    sqlite3 *db,
    struct main_state *ms,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *local,
    enum rf_warn *warn, uint64_t *reps)
{
    *warn = RF_WARN_NONE;
    enum rf_step step = rf_step_coin_unknown(local, warn, reps);
    if (step == RF_STEP_NEXT)
        step = rf_step_replay(db, ms, apply, local);
    if (step == RF_STEP_NEXT)
        step = rf_step_pre_refusal(db, apply, local);
    if (step == RF_STEP_NEXT)
        step = rf_step_coin_tear(db, apply, local, warn, reps);
    return step;
}

static bool rf_reconcile_sweeps(
    sqlite3 *db,
    struct main_state *ms,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *local)
{
    if (local->sweep_top > local->hstar &&
        !reconcile_block_index_flags(db, ms, apply, local))
        return false;

    if (!stage_reducer_frontier_reconcile_refill_cursors(db, ms, apply, local))
        return false;

    if (!reconcile_tip_finalize_cursor(db, apply, local))
        return false;
    return true;
}

/* Whether a cursor clamp this pass counts as a repair. */
static bool rf_clamp_repaired(
    const struct stage_reducer_frontier_reconcile_result *local)
{
    /* An UNRESOLVED script-side hash_split this pass (the dual replay did not
     * re-derive it — e.g. the canonical body is not yet on disk) must NOT
     * self-report `repaired` via a validate_headers / tip_finalize cursor clamp:
     * those clamps re-derive the SAME canonical header / clamp the served tip
     * but cannot move H* past the split (apply_hash_agreement still caps it), so
     * counting them as success would self-clear the condition and starve the
     * sticky_escalator. Leave it honestly unresolved so the witness stays false,
     * attempts accrue to max_attempts, and the escalator arms its terminating
     * ladder. With the discriminator + replay routing fixed the replay normally
     * fires (handled_replay returns before this point), so this guard only bites
     * the residual non-advancing case (canonical body genuinely absent). A
     * genuine VALIDATE-side split still counts its clamp (it does advance H*). */
    bool unresolved_script_side_split =
        local->lowest_script_validate_hash_split >= 0 &&
        !local->stale_script_repaired;
    bool clamp_repaired =
        (!unresolved_script_side_split) &&
        (local->clamped_tip_finalize || local->clamped_validate_headers);
    return clamp_repaired;
}

static void rf_update_repaired(
    struct stage_reducer_frontier_reconcile_result *local)
{
    bool clamp_repaired = rf_clamp_repaired(local);

    local->repaired = local->repaired ||
                     clamp_repaired ||
                     local->clamped_body_fetch ||
                     local->clamped_body_persist ||
                     local->clamped_script_validate ||
                     local->clamped_proof_validate ||
                     local->pre_refusal_unapplied_clamp ||
                     local->tipfin_backfill_count > 0 ||
                     local->scripts_set > 0 ||
                     local->have_data_set > 0 ||
                     local->have_data_cleared > 0 ||
                     local->failed_mask_cleared > 0;
}

/* Whether the throttled "L1 repaired" WARN is admitted this pass. */
static bool rf_l1_repaired_should_emit(
    bool apply,
    const struct stage_reducer_frontier_reconcile_result *local,
    uint64_t *l1_repaired_reps)
{
    /* De-storm: on a wedged node this reconcile "repairs" the same frontier
     * every reducer pass (~5s) — an unthrottled WARN is a co-mechanism of the
     * live 18k-line log storm. Key on the repair fingerprint (hstar,
     * coins_applied_height, and the set/cleared counts) so a genuinely-advancing
     * repair re-emits but a stuck repeat collapses to first-fire + 60 s
     * keepalive. Mirrors l1_refuse_throttle ~60 lines above. */
    static struct log_throttle l1_repaired_throttle = LOG_THROTTLE_INIT;
    uint64_t l1_repaired_key =
        ((uint64_t)(uint32_t)local->hstar << 32) |
        (uint32_t)(((uint32_t)local->coins_applied_height << 12) ^
                   (uint32_t)(local->have_data_cleared + local->failed_mask_cleared +
                              local->have_data_set + local->scripts_set));
    return apply && local->repaired &&
        log_throttle_should_emit(&l1_repaired_throttle, l1_repaired_key,
                                 platform_time_wall_unix(), 60,
                                 l1_repaired_reps);
}

static void rf_detect_memo_store(
    bool apply, bool memo_eligible, int64_t changes_at_entry,
    const struct stage_reducer_frontier_reconcile_result *local)
{
    /* Only this terminal exit caches: every early return above is an
     * actionable/abnormal state the next tick must re-derive fresh. */
    if (!apply && memo_eligible &&
        stage_reducer_frontier_result_is_memo_clean(local)) {
        g_detect_memo.valid = true;
        g_detect_memo.swept_unix = platform_time_wall_unix();
        g_detect_memo.total_changes = changes_at_entry;
        g_detect_memo.result = *local;
    }
}

static bool reducer_frontier_reconcile_light_impl(
    sqlite3 *db,
    struct main_state *ms,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (!db)
        LOG_FAIL("stage_repair", "reducer_frontier_reconcile: NULL db");
    if (!ms)
        LOG_FAIL("stage_repair", "reducer_frontier_reconcile: NULL main_state");

    bool memo_eligible = db == progress_store_db();
    int64_t changes_at_entry = 0;
    if (rf_detect_memo_lookup(db, apply, memo_eligible, out, &changes_at_entry))
        return true;

    struct stage_reducer_frontier_reconcile_result local;
    rf_init_local(&local);

    if (!rf_snapshot_and_purges(db, ms, apply, &local))
        return false;

    enum rf_warn warn = RF_WARN_NONE;
    uint64_t reps = 0;
    enum rf_step step = rf_run_steps(db, ms, apply, &local, &warn, &reps);
    if (step == RF_STEP_FAIL)
        return false;
    if (warn == RF_WARN_COIN_UNKNOWN)
        LOG_WARN("stage_repair",
                 "[stage_repair] reducer_frontier L1 refused: "
                 "coins_applied_height absent (coin frontier unknown) "
                 "repeats=%llu", (unsigned long long)reps);
    else if (warn == RF_WARN_STALE_VALIDATE)
        LOG_WARN("stage_repair",
                 "[stage_repair] reducer_frontier repaired stale "
                 "validate hash before coin-tear refusal "
                 "hstar=%d coins_applied=%d validate_headers=%d->%d "
                 "validate_hash_split=%d repeats=%llu",
                 local.hstar, local.coins_applied_height,
                 local.validate_headers_cursor_before,
                 local.validate_headers_cursor_after,
                 local.lowest_validate_headers_hash_split,
                 (unsigned long long)reps);
    else if (warn == RF_WARN_L1_REFUSED)
        LOG_WARN("stage_repair",
                 "[stage_repair] reducer_frontier L1 refused: "
                 "coins_applied_height=%d > hstar_cursor=%d (L2 required) "
                 "repeats=%llu",
                 local.coins_applied_height, local.hstar + 1,
                 (unsigned long long)reps);
    if (step == RF_STEP_DONE) {
        rf_publish_result(out, &local);
        return true;
    }

    if (!rf_reconcile_sweeps(db, ms, apply, &local))
        return false;

    rf_update_repaired(&local);

    uint64_t l1_repaired_reps = 0;
    if (rf_l1_repaired_should_emit(apply, &local, &l1_repaired_reps)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] reducer_frontier L1 repaired hstar=%d "
                 "served_floor=%d coins_applied=%d sweep_top=%d "
                 "validate_headers=%d->%d body_fetch=%d->%d "
                 "body_persist=%d->%d tip_finalize=%d->%d scripts_set=%d "
                 "have_data_set=%d have_data_cleared=%d "
                 "validate_refill_hole=%d body_refill_hole=%d "
                 "validate_hash_split=%d body_persist_refill_hole=%d "
                 "failed_mask_cleared=%d "
                 "script_validate=%d->%d proof_validate=%d->%d "
                 "script_refill_hole=%d proof_refill_hole=%d "
                 "unapplied_clamp=%d tipfin_backfill_h=%d "
                 "tipfin_backfill_n=%d repeats=%llu",
                 local.hstar, local.served_floor, local.coins_applied_height,
                 local.sweep_top, local.validate_headers_cursor_before,
                 local.validate_headers_cursor_after,
                 local.body_fetch_cursor_before,
                 local.body_fetch_cursor_after,
                 local.body_persist_cursor_before,
                 local.body_persist_cursor_after,
                 local.tip_finalize_cursor_before,
                 local.tip_finalize_cursor_after,
                 local.scripts_set, local.have_data_set,
                 local.have_data_cleared,
                 local.lowest_validate_headers_refill_hole,
                 local.lowest_body_fetch_refill_hole,
                 local.lowest_validate_headers_hash_split,
                 local.lowest_body_persist_refill_hole,
                 local.failed_mask_cleared,
                 local.script_validate_cursor_before,
                 local.script_validate_cursor_after,
                 local.proof_validate_cursor_before,
                 local.proof_validate_cursor_after,
                 local.lowest_script_validate_refill_hole,
                 local.lowest_proof_validate_refill_hole,
                 (int)local.pre_refusal_unapplied_clamp,
                 local.tipfin_backfill_height,
                 local.tipfin_backfill_count,
                 (unsigned long long)l1_repaired_reps);
    }

    rf_detect_memo_store(apply, memo_eligible, changes_at_entry, &local);

    rf_publish_result(out, &local);
    return true;
}

bool stage_reducer_frontier_reconcile_light_needed(
    sqlite3 *db,
    struct main_state *ms,
    struct stage_reducer_frontier_reconcile_result *out)
{
    return reducer_frontier_reconcile_light_impl(db, ms, false, out);
}

bool stage_reducer_frontier_reconcile_light(
    sqlite3 *db,
    struct main_state *ms,
    struct stage_reducer_frontier_reconcile_result *out)
{
    return reducer_frontier_reconcile_light_impl(db, ms, true, out);
}

/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "conditions/have_data_unreadable.h"
#include "conditions/block_height_census.h"
#include "framework/condition.h"
#include "util/log_macros.h"

#include "chain/chain.h"
#include "event/event.h"
#include "jobs/reducer_frontier.h"
#include "jobs/utxo_apply_stage.h"
#include "services/sync_monitor.h"
#include "storage/disk_block_io.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdio.h>

static _Atomic int g_target_at_detect = -1;
static _Atomic int g_file_at_detect = -1;
static _Atomic unsigned g_pos_at_detect = 0;
static _Atomic int g_remedy_calls = 0;
static _Atomic bool g_target_from_note;
static struct uint256 g_target_hash;
static struct reducer_frontier_body_read_note g_note_at_detect;

/* Test seam: the mid-chain candidate reads utxo_apply's own select-idle
 * record (see jobs/utxo_apply_stage.h) — real side effects a unit test
 * cannot manufacture without driving the whole reducer pipeline, so route
 * through overridable function pointers exactly like
 * tip_stall_oracle_rebuild.c's oracle/rebuild seams. */
typedef int64_t (*hdu_select_idle_height_fn)(void);
typedef bool (*hdu_select_idle_is_read_failure_fn)(void);

static hdu_select_idle_height_fn g_select_idle_height_fn =
    utxo_apply_stage_select_idle_height;
static hdu_select_idle_is_read_failure_fn g_select_idle_is_read_failure_fn =
    utxo_apply_stage_select_idle_is_read_failure;

static bool pred_readable_candidate(const struct block_index *p, void *ctx)
{
    (void)ctx;
    return (p->nStatus & BLOCK_HAVE_DATA) && !(p->nStatus & BLOCK_FAILED_MASK);
}

static struct block_index *target_index(struct main_state *ms, int target)
{
    if (!ms || target < 0)
        return NULL;
    return block_height_find(ms, target, pred_readable_candidate, NULL);
}

static struct block_index *exact_target_index(
    struct main_state *ms, int target, const struct uint256 *hash,
    bool require_active)
{
    if (!ms || target < 0 || !hash)
        return NULL;
    struct block_index *p = require_active
        ? active_chain_at(&ms->chain_active, target)
        : block_map_find(&ms->map_block_index, hash);
    if (!p || p->nHeight != target || !p->phashBlock ||
        !uint256_eq(p->phashBlock, hash) ||
        !(block_index_status_load(p) & BLOCK_HAVE_DATA) ||
        block_has_any_failure(p))
        return NULL;
    return p;
}

/* `h` as a candidate iff a block there is HAVE_DATA-flagged but not actually
 * readable from disk (the provably-bogus flag this Condition heals). */
static struct block_index *unreadable_at(struct main_state *ms, int h,
                                         const char *datadir)
{
    struct block_index *p = target_index(ms, h);
    if (!p)
        return NULL;
    if (block_index_have_data_readable(p, datadir))
        return NULL;
    return p;
}

/* Candidate 2 pre-check: the utxo_apply select-idle record only qualifies
 * while the stage reports a genuine read failure and its recorded height is
 * a strictly earlier blocker than any candidate already in hand. Returns
 * that height, or -1 when there is no qualifying candidate. */
static int hdu_select_idle_candidate_height(
    bool tip_recent, struct block_index *candidate, int cur_target)
{
    if (tip_recent || !g_select_idle_is_read_failure_fn())
        return -1;  // raw-return-ok:no qualifying candidate, not an error; original skipped silently
    int64_t ua_h = g_select_idle_height_fn();
    if (ua_h >= 0 && (candidate == NULL || ua_h < cur_target))
        return (int)ua_h;
    return -1;  // raw-return-ok:no qualifying candidate, not an error; original skipped silently
}

/* Candidate 3 pre-check: snapshot the stage_repair body-read note and
 * re-verify it against the live index. Returns the unreadable exact-match
 * block when the note names a strictly earlier blocker than any candidate
 * already in hand, NULL otherwise; *note receives the snapshot whenever one
 * exists. */
static struct block_index *hdu_frontier_note_candidate_index(
    struct main_state *ms, const char *datadir, struct block_index *candidate,
    int cur_target, struct reducer_frontier_body_read_note *note)
{
    if (!reducer_frontier_body_read_note_snapshot(note))
        return NULL;
    int rf_h = note->height;
    if (rf_h >= 0 && (candidate == NULL || rf_h < cur_target)) {
        struct block_index *rf_p = exact_target_index(
            ms, rf_h, &note->block_hash, true);
        if (rf_p && !block_index_have_data_readable(rf_p, datadir))
            return rf_p;
    }
    return NULL;
}

static bool detect_have_data_unreadable(void)
{
    int64_t tip_age = sync_monitor_tip_advance_age();
    bool tip_recent = tip_age >= 0 && tip_age < 60;

    struct main_state *ms = condition_engine_main_state();
    if (!ms)
        return false;
    int tip = active_chain_height(&ms->chain_active);
    if (tip < 0)
        return false;

    char datadir[2048];
    GetDataDir(true, datadir, sizeof(datadir));

    /* Candidate 1: the live tip's immediate next block — the class this
     * Condition originally healed (a torn HAVE_DATA flag wedging the tip). */
    int target = tip + 1;
    struct block_index *p = tip_recent
        ? NULL : unreadable_at(ms, target, datadir);

    /* Candidate 2: the LOWEST read-failed height across the reducer stages,
     * NOT necessarily tip+1 — utxo_apply's own select-idle record of the
     * height it is currently stuck trying to read a body for (e.g. mid-chain,
     * during a stale-script/coin-backfill replay that rewinds the stage
     * cursor to re-derive an OLDER height). Only a genuine local read failure
     * (INDEXED_BODY_READ_FAILED / STAGE_READ_FAILED) qualifies — a missing or
     * hash-mismatched body is a different repair's domain. Prefer the lower
     * of the two candidates so the earliest blocker heals first; re-verified
     * against the live block_index (the atomic is a sticky "last observed"
     * value, not necessarily still pending). */
    int ua_h = hdu_select_idle_candidate_height(tip_recent, p, target);
    if (ua_h >= 0) {
        struct block_index *ua_p = unreadable_at(ms, ua_h, datadir);
        if (ua_p) {
            target = ua_h;
            p = ua_p;
        }
    }

    /* Candidate 3: the stage_repair body torn-read repair note
     * (jobs/reducer_frontier.h). stage_repair_read_active_block_checked recorded
     * a canonical body it could not read (torn bytes / wrong block) during a
     * reducer_frontier replay — a height utxo_apply's own step may never reach
     * because the replay defers first. Re-verify against
     * the live index and prefer the lowest candidate, same as candidate 2. */
    struct reducer_frontier_body_read_note note;
    bool from_note = false;
    struct block_index *rf_p = hdu_frontier_note_candidate_index(
        ms, datadir, p, target, &note);
    if (rf_p) {
        target = note.height;
        p = rf_p;
        from_note = true;
    }

    if (!p)
        return false;

    atomic_store(&g_target_at_detect, target);
    atomic_store(&g_file_at_detect, p->nFile);
    atomic_store(&g_pos_at_detect, p->nDataPos);
    g_target_hash = *p->phashBlock;
    atomic_store(&g_target_from_note, from_note);
    if (from_note)
        g_note_at_detect = note;
    return true;
}

static enum condition_remedy_result remedy_have_data_unreadable(void)
{
    struct main_state *ms = condition_engine_main_state();
    int target = atomic_load(&g_target_at_detect);
    if (!ms)
        return COND_REMEDY_FAILED;
    bool from_note = atomic_load(&g_target_from_note);
    zcl_mutex_lock(&ms->cs_main);
    struct block_index *p = exact_target_index(
        ms, target, &g_target_hash, from_note);
    zcl_mutex_unlock(&ms->cs_main);
    if (!p)
        return COND_REMEDY_SKIP;

    atomic_fetch_add(&g_remedy_calls, 1);

    /* Local self-heal first: a torn position
     * can be stale rather than bodiless — the block still exists elsewhere
     * in the blk files (a duplicate copy, or the indexed record was
     * overwritten by a foreign writer on a hardlinked blk file). Repair the
     * position through the verified store instead of clearing real data.
     * Gated on a plausible current position and bounded to a same-file scan:
     * the torn-synthetic-flag class this Condition owns (nFile=-1/nPos=0,
     * body never on disk) would only buy an expensive full-blk-set walk per
     * attempt; only a genuine stale position with a surviving same-file
     * copy is repaired here. Anything else falls through to the clear. */
    if (block_index_file_load(p) >= 0 && block_index_data_pos_load(p) != 0) {
        char repair_dir[2048];
        GetDataDir(true, repair_dir, sizeof(repair_dir));
        if (block_index_repair_pos_from_disk(p, repair_dir, false)) {
            LOG_WARN("condition",
                     "[condition:have_data_unreadable] repaired h=%d position "
                     "from a local blk-file copy (was file=%d pos=%u)",
                     target, atomic_load(&g_file_at_detect),
                     atomic_load(&g_pos_at_detect));
            return COND_REMEDY_OK;
        }
    }

    zcl_mutex_lock(&ms->cs_main);
    struct block_index *current = exact_target_index(
        ms, target, &g_target_hash, from_note);
    if (current != p) {
        zcl_mutex_unlock(&ms->cs_main);
        return COND_REMEDY_SKIP;
    }
    int file = block_index_file_load(p);
    unsigned pos = block_index_data_pos_load(p);
    (void)block_index_status_clear_bits(p, (unsigned)BLOCK_HAVE_DATA);
    block_index_disk_pos_store(p, -1, 0);
    zcl_mutex_unlock(&ms->cs_main);
    LOG_WARN("condition", "[condition:have_data_unreadable] clearing h=%d file=%d pos=%u", target, file, pos);
    event_emitf(EV_BLOCK_REJECTED, 0,
                "HAVE_DATA_UNREADABLE h=%d file=%d pos=%u",
                target, file, pos);
    return COND_REMEDY_OK;
}

/* The detect-time target has healed without a body read when the
 * stage_repair note has moved on or the block has left the index (or changed
 * hash). */
static bool hdu_target_gone(struct block_index *p, bool note_target,
                            bool same_note)
{
    if (note_target && !same_note)
        return true;
    return !p || (note_target && (!p->phashBlock ||
                                  !uint256_eq(p->phashBlock, &g_target_hash)));
}

static bool witness_have_data_unreadable(int64_t target_at_detect)
{
    (void)target_at_detect;
    struct main_state *ms = condition_engine_main_state();
    int target = atomic_load(&g_target_at_detect);
    if (!ms || target < 0)
        return false;

    bool note_target = atomic_load(&g_target_from_note);
    struct reducer_frontier_body_read_note current_note;
    bool same_note = note_target &&
        reducer_frontier_body_read_note_snapshot(&current_note) &&
        current_note.generation == g_note_at_detect.generation &&
        uint256_eq(&current_note.block_hash, &g_note_at_detect.block_hash);
    struct block_index *p = note_target
        ? active_chain_at(&ms->chain_active, target)
        : target_index(ms, target);
    bool healed = hdu_target_gone(p, note_target, same_note);
    if (!healed) {
        char datadir[2048];
        GetDataDir(true, datadir, sizeof(datadir));
        /* The reducer stage's own cursor advancing past target is the
         * authoritative "re-derived through the repaired height" signal for the
         * mid-chain (backfill/replay) case: there the active/finalized tip can
         * already sit above an arbitrary rewound target even though nothing has
         * actually been repaired yet, so tip-height alone is not a safe witness.
         * Covers the tip+1 case too — once the block is re-fetched and applied,
         * the cursor advances to target+1. */
        healed = block_index_have_data_readable(p, datadir) ||
                 (!note_target &&
                  (int64_t)utxo_apply_stage_cursor() > (int64_t)target);
    }

    /* When the torn body at `target` is readable/advanced again, retire the
     * stage_repair body-read note + its typed blocker so the
     * refetch+revalidate chain terminates even if the replay path itself does
     * not re-read the height. No-op unless the note currently names target. */
    if (healed && same_note)
        (void)reducer_frontier_body_read_note_clear_if(&current_note);
    return healed;
}

static struct condition c_have_data_unreadable = {
    .name = "have_data_unreadable",
    .severity = COND_WARN,
    .poll_secs = 5,
    .backoff_secs = 30,
    .max_attempts = 3,
    /* Continue-with-cooldown: the remedy depends on an external resource (a
     * P2P re-fetch of the cleared body, driven by the sibling
     * body_fetch_missing_have_data Condition). After 3 fast attempts (one
     * operator page per episode) re-arm every 10 minutes; unbounded re-arms
     * (0) since this is a purely external dependency. */
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
    .detect = detect_have_data_unreadable,
    .remedy = remedy_have_data_unreadable,
    .witness = witness_have_data_unreadable,
    .witness_window_secs = 30,
};

void register_have_data_unreadable(void)
{
    (void)condition_register(&c_have_data_unreadable);
}

#ifdef ZCL_TESTING
static int64_t hdu_test_no_select_idle_height(void) { return -1; } // raw-return-ok:test-stub-no-signal-sentinel
static bool hdu_test_no_select_idle_read_failure(void) { return false; }

void have_data_unreadable_test_reset(void)
{
    atomic_store(&g_target_at_detect, -1);
    atomic_store(&g_file_at_detect, -1);
    atomic_store(&g_pos_at_detect, 0);
    atomic_store(&g_remedy_calls, 0);
    atomic_store(&g_target_from_note, false);
    g_select_idle_height_fn = hdu_test_no_select_idle_height;
    g_select_idle_is_read_failure_fn = hdu_test_no_select_idle_read_failure;
    condition_reset_state(&c_have_data_unreadable);
}

int have_data_unreadable_test_remedy_calls(void)
{
    return atomic_load(&g_remedy_calls);
}

void have_data_unreadable_test_set_select_idle_stubs(
    int64_t (*height_fn)(void), bool (*is_read_failure_fn)(void))
{
    g_select_idle_height_fn =
        height_fn ? height_fn : hdu_test_no_select_idle_height;
    g_select_idle_is_read_failure_fn =
        is_read_failure_fn ? is_read_failure_fn
                           : hdu_test_no_select_idle_read_failure;
}
#endif

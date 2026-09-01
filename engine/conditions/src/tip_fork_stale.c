/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Condition: tip_fork_stale
 *
 * The capstone self-healer for stale data-bearing forks at the active
 * frontier. The active tip stops advancing because a STALE block is either
 * the active tip itself (same-height sibling of the best-header chain) or
 * sits at tip+1 as an active-tip child (it carries BLOCK_HAVE_DATA). The
 * evidence controller correctly refuses to advance through the stale branch,
 * while the REAL higher-work chain is visible in the header tree
 * (pindex_best_header has strictly more chainwork than the active tip).
 *
 * detect() fires TRUE only when ALL three hold:
 *   (a) the active tip has not advanced for a sustained window — normally
 *       TIP_STALL_SECS, the same tip-age signal block_failed_mask_at_tip
 *       uses, but collapsed to TIP_STALL_CORROBORATED_SECS when the fold has
 *       ALREADY named a live apply-candidate anomaly at tip+1 (see
 *       stall_window_secs below);
 *   (b) a higher-work HEADER chain exists — pindex_best_header has
 *       strictly more nChainWork than the active tip (best_header is
 *       chainwork-ranked);
 *   (c) one of the two frontier stale-shapes is present:
 *       - the active tip is a data-bearing same-height sibling of
 *         get_ancestor(best_header, tip), sharing the same parent but a
 *         different hash; or
 *       - the block the node keeps trying to connect at tip+1 is a CHILD of
 *         the active tip carrying BLOCK_HAVE_DATA, AND it is NOT on the
 *         best-header chain:
 *           block_index_get_ancestor(best_header, tip+1) != that_child.
 *
 * SAFETY: detect is deliberately conservative. We NEVER fire on normal
 * IBD / catch-up where the tip+1 child we are missing data for IS on the
 * best-header chain (just missing its body): in that case
 * get_ancestor(best_header, tip+1) == that_child, so condition (c) is
 * false and we stay quiet. We only ever invalidate a block that is
 * provably NOT on the most-work header chain.
 *
 * remedy():
 *   1. process_block_invalidate(stale target) — marks it BLOCK_FAILED_VALID
 *      + disconnects/reorgs via the validated path so find_most_work_chain
 *      stops selecting it.
 *   2. rebuild_recent(from ~tip-2) — fetch+connect the canonical chain's
 *      recent bodies from zclassicd through the normal validated accept
 *      path.
 *   3. If zclassicd is unavailable, degrade to native P2P by queueing the
 *      best-header ancestor body at the proven stale height. This names the
 *      same-height missing-parent shape directly without adding a new repair
 *      condition.
 *   Both are bounded and idempotent. No new consensus writer.
 *
 * witness(): the active tip advanced beyond its detect-time height.
 */

#include "conditions/tip_fork_stale.h"
#include "framework/condition.h"
#include "util/log_macros.h"

#include "controllers/repair_controller.h"
#include "chain/chain.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "jobs/utxo_apply_stage.h"
#include "platform/time_compat.h"
#include "services/sync_monitor.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/process_block_invalidate.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

/* Sustained no-advance window before we even consider a stale-fork stall.
 * Matches block_failed_mask_at_tip's 300 s — a normal block is ~75 s, so
 * 300 s with no advance and a higher-work header chain is clearly stuck. */
#define TIP_STALL_SECS 300

/* Corroborated window. TIP_STALL_SECS is pure PATIENCE: "the tip has not moved"
 * cannot by itself tell a stale fork apart from slow blocks or a body still in
 * flight, so the condition waits 300 s hoping the tip moves on its own. But when
 * the fold has already NAMED the wedge — utxo_apply is held at tip+1 by a live
 * apply-candidate anomaly, meaning the block map / durable parent / on-disk body
 * actively DISAGREE with the ok-bound verdict — waiting adds nothing. That hold
 * is published from the first selection attempt (utxo_apply_stage_fallback.c),
 * so the information exists seconds into the wedge; patience only spends the
 * external monitor's gap budget, which has real headroom of 2 blocks.
 *
 * This shortens PATIENCE only. Gates (b) and (c) below — a strictly higher-work
 * header chain, and a target provably NOT on that chain — are untouched, so the
 * set of blocks this condition is ever willing to invalidate does not grow by
 * one block. A corroborated fire invalidates exactly what a 300 s fire would
 * have invalidated, just sooner. */
#define TIP_STALL_CORROBORATED_SECS 10

static _Atomic int64_t g_tip_height_at_check = -1;
static _Atomic int64_t g_tip_unchanged_since = 0;
static _Atomic int64_t g_tip_at_detect = -1;
static _Atomic int64_t g_stale_target_height = -1;
/* Hash of the confirmed-stale frontier target captured at detect time, so
 * the remedy invalidates EXACTLY the block detect proved is off the
 * best-header chain (never re-resolves a different block between detect and
 * remedy). */
static struct uint256 g_stale_target_hash;
static _Atomic bool g_stale_target_valid = false;

enum stale_target_kind {
    STALE_TARGET_NONE = 0,
    STALE_TARGET_ACTIVE_TIP = 1,
    STALE_TARGET_TIP_CHILD = 2,
};
static _Atomic int g_stale_target_kind = STALE_TARGET_NONE;

/* Test seams: the remedy's two real side effects are an invalidate (reaches
 * the activation controller) and a rebuild_recent (reaches zclassicd). Both
 * are unavailable in a unit test, so route them through overridable function
 * pointers that default to the production calls. */
typedef enum invalidate_result (*tfs_invalidate_fn)(
    struct main_state *ms, const struct uint256 *hash,
    struct uint256 *out_hash);
typedef bool (*tfs_rebuild_fn)(int from_height);
typedef struct zcl_result (*tfs_queue_body_fn)(int height,
                                               const char *reason);
/* The live apply-candidate-anomaly hold height. A unit test cannot run the real
 * utxo_apply selection path, so this is a seam like the three above; the
 * production reader is the stage's own accessor. */
typedef int64_t (*tfs_anomaly_hold_fn)(void);

static enum invalidate_result tfs_default_invalidate(
    struct main_state *ms, const struct uint256 *hash,
    struct uint256 *out_hash)
{
    return process_block_invalidate(ms, hash, out_hash);
}

static bool tfs_default_rebuild(int from_height)
{
    return rebuild_recent_repair(from_height);
}

static struct zcl_result tfs_default_queue_body(int height,
                                                const char *reason)
{
    return sync_monitor_queue_best_header_body(height, NULL, reason);
}

static int64_t tfs_default_anomaly_hold(void)
{
    return utxo_apply_stage_candidate_anomaly_hold_height();
}

static tfs_invalidate_fn g_invalidate_fn = tfs_default_invalidate;
static tfs_rebuild_fn g_rebuild_fn = tfs_default_rebuild;
static tfs_queue_body_fn g_queue_body_fn = tfs_default_queue_body;
static tfs_anomaly_hold_fn g_anomaly_hold_fn = tfs_default_anomaly_hold;

/* Last window detect() actually applied, for the remedy log line: an operator
 * reading "fired after 12 s" must be able to see it was the corroborated path
 * and not a shortened global timer. */
static _Atomic int64_t g_stall_window_at_detect = TIP_STALL_SECS;

#ifdef ZCL_TESTING
static _Atomic int g_test_invalidate_calls;
static _Atomic int g_test_rebuild_calls;
static _Atomic int g_test_queue_body_calls;
static _Atomic int64_t g_test_last_invalidate_height = -1;
static _Atomic int g_test_last_rebuild_from = -1;
static _Atomic int g_test_last_queue_body_height = -1;
#endif

static struct main_state *ms_or_null(void)
{
    return condition_engine_main_state();
}

static int64_t current_tip_height(struct main_state *ms)
{
    return ms ? (int64_t)active_chain_height(&ms->chain_active) : -1;
}

static bool same_index_hash(const struct block_index *a,
                            const struct block_index *b)
{
    return a && b && a->phashBlock && b->phashBlock &&
           uint256_eq(a->phashBlock, b->phashBlock);
}

static bool same_parent_hash(const struct block_index *a,
                             const struct block_index *b)
{
    return a && b && a->pprev && b->pprev &&
           same_index_hash(a->pprev, b->pprev);
}

static void remember_stale_target(struct block_index *target,
                                  enum stale_target_kind kind)
{
    if (!target || !target->phashBlock) {
        atomic_store(&g_stale_target_valid, false);
        atomic_store(&g_stale_target_kind, STALE_TARGET_NONE);
        return;
    }

    atomic_store(&g_stale_target_height, target->nHeight);
    g_stale_target_hash = *target->phashBlock;
    atomic_store(&g_stale_target_kind, kind);
    atomic_store(&g_stale_target_valid, true);
}

/* Among the children at `target` height, return the one that is a CHILD of
 * the active tip carrying BLOCK_HAVE_DATA but NOT itself failed — i.e. the
 * data-bearing block the node keeps retrying at tip+1. NULL if none. */
static struct block_index *find_active_tip_child_with_data(
    struct main_state *ms, struct block_index *tip, int target_height)
{
    if (!ms || !tip)
        return NULL;
    size_t iter = 0;
    struct block_index *p = NULL;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &p)) {
        if (!p || p->nHeight != target_height)
            continue;
        if (!same_index_hash(p->pprev, tip))
            continue; /* must be a direct child of the active tip */
        if (!(p->nStatus & BLOCK_HAVE_DATA))
            continue;
        if (block_has_any_failure(p))
            continue; /* already invalidated — nothing to heal */
        return p;
    }
    return NULL;
}

/* How long the tip must have held still before gates (b)/(c) are consulted.
 * TIP_STALL_CORROBORATED_SECS when the fold is held at tip+1 RIGHT NOW by an
 * apply-candidate anomaly, TIP_STALL_SECS otherwise. tip+1 is the only height
 * that matters: both stale shapes this condition repairs — a stale active tip
 * whose canonical sibling's child cannot attach, and a stale data-bearing child
 * at tip+1 — surface as selection failing at exactly tip+1. An anomaly hold
 * anywhere else (a stale-script or coin-backfill replay rewinds the stage cursor
 * to arbitrary earlier heights) is a different wedge with its own healer and
 * must not shorten this one's patience. */
static int64_t stall_window_secs(int64_t tip_h)
{
    int64_t hold_h = g_anomaly_hold_fn ? g_anomaly_hold_fn() : -1;
    if (hold_h >= 0 && hold_h == tip_h + 1)
        return TIP_STALL_CORROBORATED_SECS;
    return TIP_STALL_SECS;
}

static bool detect_tip_fork_stale(void)
{
    struct main_state *ms = ms_or_null();
    if (!ms)
        return false;

    struct block_index *tip = active_chain_tip(&ms->chain_active);
    int64_t tip_h = current_tip_height(ms);
    if (!tip || tip_h <= 0)
        return false; /* tip not established — stay quiet */

    /* (a) sustained no-advance window. Reset the timer whenever the tip
     * moves; only a tip that has held still for TIP_STALL_SECS qualifies. */
    int64_t now = platform_time_wall_unix();
    int64_t prev_tip = atomic_load(&g_tip_height_at_check);
    if (prev_tip != tip_h) {
        atomic_store(&g_tip_height_at_check, tip_h);
        atomic_store(&g_tip_unchanged_since, now);
        return false;
    }
    int64_t since = atomic_load(&g_tip_unchanged_since);
    if (since == 0) {
        atomic_store(&g_tip_unchanged_since, now);
        return false;
    }
    int64_t window = stall_window_secs(tip_h);
    if (now - since < window)
        return false;
    atomic_store(&g_stall_window_at_detect, window);

    /* (b) a strictly higher-work HEADER chain exists. */
    struct block_index *bh = ms->pindex_best_header;
    if (!bh)
        return false;
    if (arith_uint256_compare(&bh->nChainWork, &tip->nChainWork) <= 0)
        return false; /* no more-work header chain — normal at-tip */
    if (bh->nHeight <= tip_h)
        return false; /* best header not actually ahead — not a fork stall */

    /* (c1) The active tip itself is a same-height data-bearing stale
     * sibling of the best-header chain. Limit this first repair to the
     * simple sibling shape (same parent, different hash); deeper divergence
     * will be named by follow-up repair once the frontier rewinds. */
    struct block_index *bh_at_tip = block_index_get_ancestor(bh, (int)tip_h);
    if ((tip->nStatus & BLOCK_HAVE_DATA) && !block_has_any_failure(tip) &&
        bh_at_tip && !same_index_hash(bh_at_tip, tip) &&
        !block_has_any_failure(bh_at_tip) &&
        same_parent_hash(bh_at_tip, tip)) {
        atomic_store(&g_tip_at_detect, tip_h);
        remember_stale_target(tip, STALE_TARGET_ACTIVE_TIP);
        return true;
    }

    /* (c2) The data-bearing tip+1 child the node keeps retrying is NOT on
     * the best-header chain. */
    int target = (int)tip_h + 1;
    struct block_index *child =
        find_active_tip_child_with_data(ms, tip, target);
    if (!child)
        return false; /* nothing stuck at tip+1 — normal missing-body IBD */

    struct block_index *bh_at_target =
        block_index_get_ancestor(bh, target);
    if (same_index_hash(bh_at_target, child))
        return false; /* child IS on the best-header chain — LEGIT, never
                       * invalidate. Just a missing body; let IBD fetch it. */

    /* Confirmed stale fork: tip stalled, a higher-work header chain exists,
     * and the data-bearing child at tip+1 is off that chain. */
    atomic_store(&g_tip_at_detect, tip_h);
    remember_stale_target(child, STALE_TARGET_TIP_CHILD);
    return true;
}

static enum condition_remedy_result remedy_tip_fork_stale(void)
{
    struct main_state *ms = ms_or_null();
    if (!ms || !atomic_load(&g_stale_target_valid))
        return COND_REMEDY_SKIP;

    int64_t tip_at_detect = atomic_load(&g_tip_at_detect);
    int64_t target_h = atomic_load(&g_stale_target_height);
    int kind = atomic_load(&g_stale_target_kind);
    const char *kind_name = kind == STALE_TARGET_ACTIVE_TIP ? "active_tip" :
        (kind == STALE_TARGET_TIP_CHILD ? "tip_child" : "unknown");
    struct uint256 stale = g_stale_target_hash;

    /* (1) Invalidate the confirmed-stale frontier target so
     * find_most_work_chain stops selecting it. Reuses the validated
     * disconnect/reorg path. */
    struct uint256 out_hash;
    enum invalidate_result ir = g_invalidate_fn(ms, &stale, &out_hash);
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_invalidate_calls, 1);
    atomic_store(&g_test_last_invalidate_height, target_h);
#endif
    if (ir != INVALIDATE_OK) {
        LOG_WARN("condition",
            "[condition:tip_fork_stale] invalidate kind=%s h=%lld "
            "result=%s - remedy aborted before rebuild",
            kind_name, (long long)target_h, invalidate_result_name(ir));
        return COND_REMEDY_FAILED;
    }

    /* (2) Pull the canonical recent bodies from zclassicd and connect them
     * through the normal validated accept path. Start a small margin below
     * the detect-time tip so a 1-block stale fork is always inside window. */
    int from_h = (int)(tip_at_detect - 2);
    if (from_h < 0)
        from_h = 0;
    bool rebuilt = g_rebuild_fn(from_h);
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_rebuild_calls, 1);
    atomic_store(&g_test_last_rebuild_from, from_h);
#endif

    int64_t tip_now = current_tip_height(ms);
    LOG_WARN("condition",
        "[condition:tip_fork_stale] invalidated stale %s h=%lld, "
        "rebuild_recent from=%d ok=%s tip %lld -> %lld stall_window=%llds",
        kind_name, (long long)target_h, from_h, rebuilt ? "yes" : "no",
        (long long)tip_at_detect, (long long)tip_now,
        (long long)atomic_load(&g_stall_window_at_detect));

    if (!rebuilt) {
        if (target_h < 0 || target_h > INT32_MAX)
            return COND_REMEDY_FAILED;

        struct zcl_result qr = g_queue_body_fn((int)target_h,
            "condition:tip_fork_stale best-header body fallback");
#ifdef ZCL_TESTING
        atomic_fetch_add(&g_test_queue_body_calls, 1);
        atomic_store(&g_test_last_queue_body_height, (int)target_h);
#endif
        if (!qr.ok) {
            LOG_WARN("condition",
                "[condition:tip_fork_stale] native body fallback failed "
                "kind=%s h=%lld code=%d msg=%s",
                kind_name, (long long)target_h, qr.code, qr.message);
            return COND_REMEDY_FAILED;
        }

        LOG_WARN("condition",
            "[condition:tip_fork_stale] queued best-header body fallback "
            "kind=%s h=%lld after rebuild_recent failed",
            kind_name, (long long)target_h);
        return COND_REMEDY_OK;
    }

    /* The engine downgrades to UNWITNESSED if the tip did not actually
     * advance, so returning OK here only sticks when witness() confirms. */
    return COND_REMEDY_OK;
}

static bool witness_tip_fork_stale(int64_t target_at_detect)
{
    (void)target_at_detect;
    struct main_state *ms = ms_or_null();
    if (!ms)
        return false;
    return current_tip_height(ms) > atomic_load(&g_tip_at_detect);
}

static struct condition c_tip_fork_stale = {
    .name = "tip_fork_stale",
    .severity = COND_CRITICAL,
    .poll_secs = 10,
    .backoff_secs = 60,
    .max_attempts = 3,
    .detect = detect_tip_fork_stale,
    .remedy = remedy_tip_fork_stale,
    .witness = witness_tip_fork_stale,
    .witness_window_secs = 120,
};

void register_tip_fork_stale(void)
{
    (void)condition_register(&c_tip_fork_stale);
}

#ifdef ZCL_TESTING
void tip_fork_stale_test_reset(void)
{
    atomic_store(&g_tip_height_at_check, -1);
    atomic_store(&g_tip_unchanged_since, 0);
    atomic_store(&g_tip_at_detect, -1);
    atomic_store(&g_stale_target_height, -1);
    atomic_store(&g_stale_target_valid, false);
    atomic_store(&g_stale_target_kind, STALE_TARGET_NONE);
    g_invalidate_fn = tfs_default_invalidate;
    g_rebuild_fn = tfs_default_rebuild;
    g_queue_body_fn = tfs_default_queue_body;
    g_anomaly_hold_fn = tfs_default_anomaly_hold;
    atomic_store(&g_stall_window_at_detect, (int64_t)TIP_STALL_SECS);
    atomic_store(&g_test_invalidate_calls, 0);
    atomic_store(&g_test_rebuild_calls, 0);
    atomic_store(&g_test_queue_body_calls, 0);
    atomic_store(&g_test_last_invalidate_height, -1);
    atomic_store(&g_test_last_rebuild_from, -1);
    atomic_store(&g_test_last_queue_body_height, -1);
    condition_reset_state(&c_tip_fork_stale);
}

/* Force the no-advance stall timer to satisfy the TIP_STALL_SECS window
 * without waiting in real time. Pins the tip-height/unchanged-since state
 * to (tip_h, now - age_secs). */
void tip_fork_stale_test_force_stall(int64_t tip_h, int64_t age_secs)
{
    atomic_store(&g_tip_height_at_check, tip_h);
    atomic_store(&g_tip_unchanged_since,
                 platform_time_wall_unix() - age_secs);
}

void tip_fork_stale_test_set_remedy_stubs(
    enum invalidate_result (*inv)(struct main_state *,
                                  const struct uint256 *,
                                  struct uint256 *),
    bool (*reb)(int))
{
    if (inv) g_invalidate_fn = inv;
    if (reb) g_rebuild_fn = reb;
}

void tip_fork_stale_test_set_queue_body_stub(
    struct zcl_result (*queue_body)(int height, const char *reason))
{
    if (queue_body) g_queue_body_fn = queue_body;
}

void tip_fork_stale_test_set_anomaly_hold_stub(int64_t (*hold)(void))
{
    if (hold) g_anomaly_hold_fn = hold;
}

int64_t tip_fork_stale_test_stall_window_at_detect(void)
{
    return atomic_load(&g_stall_window_at_detect);
}

int tip_fork_stale_test_invalidate_calls(void)
{
    return atomic_load(&g_test_invalidate_calls);
}

int tip_fork_stale_test_rebuild_calls(void)
{
    return atomic_load(&g_test_rebuild_calls);
}

int tip_fork_stale_test_queue_body_calls(void)
{
    return atomic_load(&g_test_queue_body_calls);
}

int64_t tip_fork_stale_test_last_invalidate_height(void)
{
    return atomic_load(&g_test_last_invalidate_height);
}

int tip_fork_stale_test_last_rebuild_from(void)
{
    return atomic_load(&g_test_last_rebuild_from);
}

int tip_fork_stale_test_last_queue_body_height(void)
{
    return atomic_load(&g_test_last_queue_body_height);
}
#endif

/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Condition: tip_stall_oracle_rebuild
 *
 * The NON-fork twin of tip_fork_stale. It heals the wedge class where the
 * active tip stops advancing not because of a stale fork, but because the
 * CANONICAL next bodies never arrive over P2P — yet a trusted local
 * zclassicd oracle is reachable and strictly ahead and HAS those bodies.
 *
 * The wedge: the node holds at height H with its full header chain synced
 * far ahead (best_header >> H). We send well-formed getdata(MSG_BLOCK) for
 * the missing canonical bodies, but the zcashd/MagicBean peers return
 * neither `block` nor `notfound`, so no body ever lands, tip_finalize never
 * gets the H+1/H+2 lookahead bodies it needs, and the tip is stuck.
 * body_fetch_missing_have_data re-queues the doomed P2P fetch and escalates
 * to operator_needed; tip_fork_stale deliberately stays quiet because the
 * missing block IS on the best-header chain (not a fork). Nothing falls
 * back to the reachable oracle that demonstrably holds every missing body.
 *
 * detect() fires TRUE only when ALL hold:
 *   (a) the active tip has not advanced for a sustained window
 *       (TIP_STALL_SECS) — same no-advance signal tip_fork_stale uses;
 *   (b) a strictly higher-work HEADER chain exists, ahead by a real margin
 *       (best_header has more chainwork AND nHeight >= tip + MIN_GAP) — so a
 *       single-block header lead during normal at-tip operation never fires;
 *   (c) it is NOT a stale fork: there is no data-bearing child of the active
 *       tip at tip+1 that is OFF the best-header chain (that case belongs to
 *       tip_fork_stale, which also invalidates);
 *   (d) the local oracle (zclassicd) is reachable AND strictly ahead by the
 *       same margin — i.e. there is a trusted source that has the bodies.
 *
 * SAFETY: when no oracle is reachable, detect stays quiet and the native
 * P2P/sync path owns recovery — this is a FALLBACK for a node co-located
 * with a trusted full node, never a replacement for sovereign sync. It only
 * ever ingests blocks through the same validated reducer_ingest_block accept
 * path rebuild_recent uses; it introduces no new consensus writer and never
 * lowers the tip (rebuild connects forward through the validated path).
 *
 * remedy(): rebuild_recent_repair(from ~tip-2) — fetch+connect the canonical
 * recent bodies from zclassicd through the normal validated accept path.
 *
 * witness(): the active tip advanced beyond its detect-time height.
 */

#include "conditions/tip_stall_oracle_rebuild.h"
#include "framework/condition.h"
#include "util/log_macros.h"

#include "controllers/repair_controller.h"
#include "chain/chain.h"
#include "core/arith_uint256.h"
#include "platform/time_compat.h"
#include "rpc/legacy_chain_oracle.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stddef.h>

/* Sustained no-advance window before we consider an oracle-backed rebuild.
 * Long enough that the native P2P/body_fetch path gets first crack, short
 * enough that a node with a reachable oracle does not sit wedged. */
#define TIP_STALL_SECS 120

/* Minimum height gap (best_header above tip, and oracle above tip) before we
 * fire. A lead of 1 is normal between a header arriving and its body landing
 * at the tip; require >= 2 so healthy at-tip operation never triggers. */
#define MIN_GAP 2

static _Atomic int64_t g_tip_height_at_check = -1;
static _Atomic int64_t g_tip_unchanged_since = 0;
static _Atomic int64_t g_tip_at_detect = -1;
static _Atomic int64_t g_best_header_at_detect = -1;
static _Atomic int g_oracle_height_at_detect = -1;
static _Atomic int g_last_rebuild_from = -1;
static _Atomic int g_last_rebuild_ok = 0;
static _Atomic int64_t g_last_witness_tip_height = -1;

/* Test seams: the remedy's real side effects (read zclassicd height, run
 * rebuild_recent_repair) reach external services unavailable to a unit test,
 * so route them through overridable function pointers. */
typedef bool (*tsor_oracle_height_fn)(int *out_height);
typedef bool (*tsor_rebuild_fn)(int from_height);

static tsor_oracle_height_fn g_oracle_height_fn = legacy_chain_rpc_get_block_count;
static tsor_rebuild_fn g_rebuild_fn = rebuild_recent_repair;

#ifdef ZCL_TESTING
static _Atomic int g_test_rebuild_calls;
static _Atomic int g_test_last_rebuild_from = -1;
#endif

static struct main_state *ms_or_null(void)
{
    return condition_engine_main_state();
}

static int64_t current_tip_height(struct main_state *ms)
{
    return ms ? (int64_t)active_chain_height(&ms->chain_active) : -1;
}

/* True iff a data-bearing child of the active tip sits at tip+1 but is NOT
 * the best-header chain's block at tip+1 — the stale-fork signature that
 * tip_fork_stale owns. We must defer to it (it also invalidates). */
static bool has_stale_fork_child(struct main_state *ms, struct block_index *tip,
                                 struct block_index *bh, int target)
{
    if (!ms || !tip || !bh)
        return false;
    size_t iter = 0;
    struct block_index *p = NULL;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &p)) {
        if (!p || p->nHeight != target)
            continue;
        if (p->pprev != tip)
            continue; /* must be a direct child of the active tip */
        if (!(p->nStatus & BLOCK_HAVE_DATA))
            continue;
        if (block_has_any_failure(p))
            continue;
        /* data-bearing tip+1 child. If it is NOT on the best-header chain,
         * it is a confirmed stale fork -> tip_fork_stale's job. */
        if (block_index_get_ancestor(bh, target) != p)
            return true;
    }
    return false;
}

static bool detect_tip_stall_oracle_rebuild(void)
{
    struct main_state *ms = ms_or_null();
    if (!ms)
        return false;

    struct block_index *tip = active_chain_tip(&ms->chain_active);
    int64_t tip_h = current_tip_height(ms);
    if (!tip || tip_h <= 0)
        return false;

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
    if (now - since < TIP_STALL_SECS)
        return false;

    /* (b) a strictly higher-work HEADER chain exists, ahead by a real
     * margin (so a 1-block header lead at the tip never fires). */
    struct block_index *bh = ms->pindex_best_header;
    if (!bh)
        return false;
    if (arith_uint256_compare(&bh->nChainWork, &tip->nChainWork) <= 0)
        return false;
    if (bh->nHeight < tip_h + MIN_GAP)
        return false;

    /* (c) NOT a stale fork — defer those to tip_fork_stale. */
    if (has_stale_fork_child(ms, tip, bh, (int)tip_h + 1))
        return false;

    /* (d) the local oracle is reachable AND strictly ahead by the margin. */
    int remote = 0;
    if (!g_oracle_height_fn(&remote)) {
        LOG_WARN("condition",
                 "[condition:tip_stall_oracle_rebuild] tip_h=%lld stalled but "
                 "oracle unreachable; native sync owns recovery",
                 (long long)tip_h);
        return false; /* no trusted oracle -> native sync owns recovery */
    }
    if ((int64_t)remote < tip_h + MIN_GAP)
        return false;

    atomic_store(&g_tip_at_detect, tip_h);
    atomic_store(&g_best_header_at_detect, bh->nHeight);
    atomic_store(&g_oracle_height_at_detect, remote);
    return true;
}

static enum condition_remedy_result remedy_tip_stall_oracle_rebuild(void)
{
    struct main_state *ms = ms_or_null();
    if (!ms)
        return COND_REMEDY_SKIP;

    int64_t tip_at_detect = atomic_load(&g_tip_at_detect);
    if (tip_at_detect < 0)
        return COND_REMEDY_SKIP;

    /* Start a small margin below the detect-time tip so the immediate
     * lookahead bodies (tip+1, tip+2) are always inside the fetch window.
     * Re-ingesting blocks already present is idempotent. */
    int from_h = (int)(tip_at_detect - 2);
    if (from_h < 0)
        from_h = 0;

    bool rebuilt = g_rebuild_fn(from_h);
    atomic_store(&g_last_rebuild_from, from_h);
    atomic_store(&g_last_rebuild_ok, rebuilt ? 1 : 0);
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_rebuild_calls, 1);
    atomic_store(&g_test_last_rebuild_from, from_h);
#endif

    int64_t tip_now = current_tip_height(ms);
    LOG_WARN("condition",
        "[condition:tip_stall_oracle_rebuild] rebuild_recent from=%d ok=%s "
        "tip %lld -> %lld",
        from_h, rebuilt ? "yes" : "no",
        (long long)tip_at_detect, (long long)tip_now);

    if (!rebuilt)
        return COND_REMEDY_FAILED;
    /* The engine downgrades to UNWITNESSED if the tip did not actually
     * advance, so OK here only sticks when witness() confirms. */
    return COND_REMEDY_OK;
}

static bool witness_tip_stall_oracle_rebuild(int64_t target_at_detect)
{
    (void)target_at_detect;
    struct main_state *ms = ms_or_null();
    if (!ms)
        return false;
    int64_t tip = current_tip_height(ms);
    atomic_store(&g_last_witness_tip_height, tip);
    return tip > atomic_load(&g_tip_at_detect);
}

static bool detail_tip_stall_oracle_rebuild(struct json_value *out)
{
    struct main_state *ms = ms_or_null();
    int64_t current_tip = current_tip_height(ms);
    int64_t current_best_header =
        ms && ms->pindex_best_header ? ms->pindex_best_header->nHeight : -1;
    int64_t unchanged_since = atomic_load(&g_tip_unchanged_since);
    int64_t now = platform_time_wall_unix();
    int64_t unchanged_age =
        unchanged_since > 0 && now >= unchanged_since ? now - unchanged_since
                                                      : -1;

    bool ok = true;
    ok = ok && json_push_kv_int(out, "tip_height_at_check",
                                atomic_load(&g_tip_height_at_check));
    ok = ok && json_push_kv_int(out, "tip_unchanged_since_unix",
                                unchanged_since);
    ok = ok && json_push_kv_int(out, "tip_unchanged_age_s",
                                unchanged_age);
    ok = ok && json_push_kv_int(out, "tip_height_at_detect",
                                atomic_load(&g_tip_at_detect));
    ok = ok && json_push_kv_int(out, "best_header_at_detect",
                                atomic_load(&g_best_header_at_detect));
    ok = ok && json_push_kv_int(out, "oracle_height_at_detect",
                                atomic_load(&g_oracle_height_at_detect));
    ok = ok && json_push_kv_int(out, "current_tip_height", current_tip);
    ok = ok && json_push_kv_int(out, "current_best_header_height",
                                current_best_header);
    ok = ok && json_push_kv_int(out, "last_rebuild_from",
                                atomic_load(&g_last_rebuild_from));
    ok = ok && json_push_kv_bool(out, "last_rebuild_ok",
                                 atomic_load(&g_last_rebuild_ok) != 0);
    ok = ok && json_push_kv_int(out, "last_witness_tip_height",
                                atomic_load(&g_last_witness_tip_height));
    ok = ok && json_push_kv_bool(
        out, "last_witness_tip_advanced",
        atomic_load(&g_last_witness_tip_height) >
            atomic_load(&g_tip_at_detect));
    ok = ok && json_push_kv_int(out, "stall_secs", TIP_STALL_SECS);
    ok = ok && json_push_kv_int(out, "min_gap_blocks", MIN_GAP);
    ok = ok && json_push_kv_str(
        out, "remedy_contract",
        "oracle rebuild is witnessed only when active tip advances beyond tip_height_at_detect");
    return ok;
}

static struct condition c_tip_stall_oracle_rebuild = {
    .name = "tip_stall_oracle_rebuild",
    .severity = COND_CRITICAL,
    .poll_secs = 15,
    .backoff_secs = 60,
    .max_attempts = 5,
    /* Continue-with-cooldown (sticky-node plan #7): this remedy depends on an
     * external rebuild source. After 5 fast attempts (one operator page per
     * episode) re-arm every 15 minutes so the rebuild is retried when the
     * source becomes reachable again. Bounded to 8 re-arms per fault episode
     * (~2h of retries on one unchanged stall target) so a genuinely stuck
     * height still eventually defers to the higher-tier escalator instead of
     * spinning a heavy rebuild forever; a NEW stall target (the wedge moved)
     * resets the budget. This is the right tier for a CRITICAL condition whose
     * dependency is external but whose remedy is expensive. */
    .cooldown_secs = 900,
    .cooldown_max_rearms = 8,
    .detect = detect_tip_stall_oracle_rebuild,
    .remedy = remedy_tip_stall_oracle_rebuild,
    .witness = witness_tip_stall_oracle_rebuild,
    .detail = detail_tip_stall_oracle_rebuild,
    .witness_window_secs = 180,
};

void register_tip_stall_oracle_rebuild(void)
{
    (void)condition_register(&c_tip_stall_oracle_rebuild);
}

#ifdef ZCL_TESTING
void tip_stall_oracle_rebuild_test_reset(void)
{
    atomic_store(&g_tip_height_at_check, -1);
    atomic_store(&g_tip_unchanged_since, 0);
    atomic_store(&g_tip_at_detect, -1);
    atomic_store(&g_best_header_at_detect, -1);
    atomic_store(&g_oracle_height_at_detect, -1);
    atomic_store(&g_last_rebuild_from, -1);
    atomic_store(&g_last_rebuild_ok, 0);
    atomic_store(&g_last_witness_tip_height, -1);
    g_oracle_height_fn = legacy_chain_rpc_get_block_count;
    g_rebuild_fn = rebuild_recent_repair;
    atomic_store(&g_test_rebuild_calls, 0);
    atomic_store(&g_test_last_rebuild_from, -1);
    condition_reset_state(&c_tip_stall_oracle_rebuild);
}

void tip_stall_oracle_rebuild_test_force_stall(int64_t tip_h, int64_t age_secs)
{
    atomic_store(&g_tip_height_at_check, tip_h);
    atomic_store(&g_tip_unchanged_since,
                 platform_time_wall_unix() - age_secs);
}

void tip_stall_oracle_rebuild_test_set_stubs(bool (*oracle_height)(int *),
                                             bool (*rebuild)(int))
{
    if (oracle_height) g_oracle_height_fn = oracle_height;
    if (rebuild) g_rebuild_fn = rebuild;
}

int tip_stall_oracle_rebuild_test_rebuild_calls(void)
{
    return atomic_load(&g_test_rebuild_calls);
}

int tip_stall_oracle_rebuild_test_last_rebuild_from(void)
{
    return atomic_load(&g_test_last_rebuild_from);
}
#endif

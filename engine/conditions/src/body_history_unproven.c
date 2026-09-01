/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Condition body_history_unproven: fire whenever the node cannot PROVE it
 * holds the block bodies for its own history — on a known hole and on
 * unmeasured coverage alike. See conditions/body_history_unproven.h. */

#include "conditions/body_history_unproven.h"

#include "framework/condition.h"
#include "services/gap_fill_service.h"
#include "services/sync_monitor.h"
#include "storage/body_coverage.h"
#include "storage/body_history.h"
#include "json/json.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

/* Progress baseline: how much the census had established at the last
 * progressing() call. A backfill of millions of bodies cannot finish inside
 * a witness window, so the condition proves it is CONVERGING rather than
 * being declared unrecoverable. */
static _Atomic int64_t g_last_examined = -1;
static _Atomic int64_t g_last_held = -1;
static _Atomic int     g_remedy_calls = 0;

/* Snapshot both the published verdict and the census counters. Returns false
 * when nothing has been published — which is itself the UNKNOWN state, not a
 * reason to stay quiet. */
static bool bhu_snapshot(struct body_history_verdict *v, int64_t *examined)
{
    bool published = body_history_get_verdict(v);
    if (examined) {
        body_history_global_lock();
        *examined = (int64_t)body_history_global_census()->heights_examined;
        body_history_global_unlock();
    }
    return published;
}

static bool detect_body_history_unproven(void)
{
    struct body_history_verdict v;
    (void)bhu_snapshot(&v, NULL);

    /* Fires on INCOMPLETE and on UNKNOWN alike. The two are different facts
     * and the detail string says which, but neither one is "fine". Written
     * as "not COMPLETE" on purpose: a status this code has never heard of
     * must fire, not pass. */
    return v.status != BODY_HISTORY_COMPLETE;
}

static enum condition_remedy_result remedy_body_history_unproven(void)
{
    atomic_fetch_add(&g_remedy_calls, 1);

    /* The cure is the gap-fill worker's bounded below-tip census + backfill.
     * It is deliberately rate-limited so it cannot starve live sync, so the
     * remedy is "run the next pass now", not "fetch everything". */
    gap_fill_kick();
    return COND_REMEDY_OK;
}

/* Re-derive the answer from what the node actually HOLDS, against the
 * current active-chain height — never from the cached published flag. A
 * witness that read the flag would be witnessing the census's own opinion
 * of itself; this reads the coverage maps and the live tip. */
static bool witness_body_history_unproven(int64_t target_at_detect)
{
    (void)target_at_detect;

    struct main_state *ms = sync_monitor_main_state();
    if (!ms)
        return false;
    int tip = active_chain_height(&ms->chain_active);
    if (tip < 0)
        return false;

    struct body_history_verdict v;
    body_history_global_lock();
    bool ok = body_history_evaluate(body_coverage_global_map(),
                                    body_history_global_measured(),
                                    0, (int64_t)tip, &v);
    body_history_global_unlock();
    return ok && body_history_verdict_is_proven(&v);
}

static bool progressing_body_history_unproven(int64_t target_at_detect)
{
    (void)target_at_detect;

    struct body_history_verdict v;
    int64_t examined = 0;
    (void)bhu_snapshot(&v, &examined);

    int64_t prev_examined = atomic_load(&g_last_examined);
    int64_t prev_held = atomic_load(&g_last_held);

    /* Two independent advances count as progress: more heights definitively
     * probed (the census is converging on an answer) or more bodies held
     * (the backfill is landing). Re-snapshot on a true return so the next
     * round measures fresh movement, per the condition_progressing_fn
     * contract — pure churn must exhaust the budget and page the operator. */
    bool advanced = (prev_examined >= 0 && examined > prev_examined) ||
                    (prev_held >= 0 && v.held_count > prev_held);

    atomic_store(&g_last_examined, examined);
    atomic_store(&g_last_held, v.held_count);

    /* First observation establishes the baseline; it is not yet evidence of
     * movement, so it does not count as progress. */
    return advanced;
}

/* The named blocker's payload. Both counts are always emitted: an operator
 * reading `missing_count: 0` must be able to see `unmeasured_count` in the
 * same breath and tell a clean node from an unmeasured one. */
static bool detail_body_history_unproven(struct json_value *out)
{
    if (!out)
        return false;
    json_set_object(out);

    struct body_history_verdict v;
    bool published = bhu_snapshot(&v, NULL);

    json_push_kv_str(out, "blocker_id", BODY_HISTORY_UNPROVEN_BLOCKER);
    json_push_kv_str(out, "status", body_history_status_name(v.status));
    json_push_kv_bool(out, "verdict_published", published);
    json_push_kv_int(out, "window_lo", v.window_lo);
    json_push_kv_int(out, "window_hi", v.window_hi);
    json_push_kv_int(out, "held_count", v.held_count);
    json_push_kv_int(out, "missing_count", v.missing_count);
    json_push_kv_int(out, "lowest_missing", v.lowest_missing);
    json_push_kv_int(out, "unmeasured_count", v.unmeasured_count);
    json_push_kv_int(out, "lowest_unmeasured", v.lowest_unmeasured);
    json_push_kv_int(out, "remedy_calls", atomic_load(&g_remedy_calls));
    return true;
}

static struct condition c_body_history_unproven = {
    .name = "body_history_unproven",
    /* WARN, not CRITICAL: the node keeps serving and keeps syncing. What it
     * loses is the right to call itself at tip. Escalation to an operator
     * page happens through the attempt budget if the census stops
     * converging. */
    .severity = COND_WARN,
    .poll_secs = 30,
    .backoff_secs = 60,
    .max_attempts = 10,
    .detect = detect_body_history_unproven,
    .remedy = remedy_body_history_unproven,
    .witness = witness_body_history_unproven,
    .progressing = progressing_body_history_unproven,
    .detail = detail_body_history_unproven,
    .witness_window_secs = 120,
    /* A multi-million-block backfill outlives any attempt budget, so re-arm
     * forever rather than latching operator_needed on a node that is
     * demonstrably making progress. */
    .cooldown_secs = 900,
    .cooldown_max_rearms = 0,
};

void register_body_history_unproven(void)
{
    (void)condition_register(&c_body_history_unproven);
}

#ifdef ZCL_TESTING
void body_history_unproven_test_reset(void)
{
    atomic_store(&g_last_examined, -1);
    atomic_store(&g_last_held, -1);
    atomic_store(&g_remedy_calls, 0);
    condition_reset_state(&c_body_history_unproven);
}

bool body_history_unproven_test_detect(void)
{
    return detect_body_history_unproven();
}
#endif

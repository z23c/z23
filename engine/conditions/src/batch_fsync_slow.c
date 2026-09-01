/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Condition: batch_fsync_slow
 *
 * SYMPTOM: the reducer drive's batched pre-commit durability flush
 *   (reducer_batched_durability_precommit, engine/reducer/services/src/reducer_body_fsync.c
 *   — fdatasyncs deferred block bodies + flushes the event_log ONCE per stage
 *   batch COMMIT, and can VETO the commit on failure) is timed at
 *   the call site so a genuine IO stall inside it (ext4 jbd2 journal-commit
 *   wait, a slow/contended disk) is never invisible behind "the fold is
 *   slow" with no attributable cause. This Condition watches the EWMA of
 *   that flush's own wall-clock duration (alpha = 1/16, the same integer-EWMA
 *   shape as platform/modules/util/src/stage.c's step_us_ewma) against a GENEROUS
 *   env-tunable budget, so a real IO regression becomes a named fact instead
 *   of a mystery slow drain.
 * REMEDY: OBSERVATIONAL ONLY. There is no safe automated action against slow
 *   disk IO, and the veto-on-failed-flush durability contract is FROZEN —
 *   this Condition only times it, never changes it. The remedy names a
 *   TRANSIENT blocker ("batch_fsync_slow") carrying the EWMA, the last single
 *   flush duration, and the configured budget, then logs it. COND_REMEDY_OK:
 *   an honest "nothing to fix here but the disk", so the continue-with-
 *   cooldown tier re-arms unbounded rather than ever latching operator_needed
 *   on a transient IO regression (mirrors disk_full_pause.c).
 * WITNESSED: clears the instant a fresh read of the EWMA drops back at/under
 *   the budget. The EWMA only advances when the drive actually commits a
 *   batch, so a fully idle drive leaves the last-known reading standing until
 *   the next commit — the same shape as every other EWMA-driven signal in
 *   this codebase (there is nothing to force-repoll; unlike disk_monitor
 *   there is no independent live probe of "is IO slow right now" other than
 *   the EWMA itself).
 * COND_WARN; poll_secs=20. Budget default is GENEROUS (env
 *   ZCL_BATCH_FSYNC_SLOW_EWMA_US, default 4,000,000us = 4s) so a healthy
 *   node — even one with an occasionally-slow journal commit — never
 *   false-fires; it exists to catch a SUSTAINED regression, not a single
 *   blip (the EWMA itself already smooths single-sample noise). A one-time
 *   informational page fires after a few fast attempts, then the engine
 *   re-arms the (no-op) remedy every 5 minutes, UNBOUNDED, while the flush
 *   stays slow — sticky-node plan #7. */

#include "conditions/batch_fsync_slow.h"
#include "framework/condition.h"
#include "services/reducer_ingest_service.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

#define BATCH_FSYNC_SLOW_EWMA_US_DEFAULT (4LL * 1000 * 1000)  /* 4s */
#define BATCH_FSYNC_SLOW_POLL_SECS       20
#define BATCH_FSYNC_SLOW_BACKOFF_SECS    120
#define BATCH_FSYNC_SLOW_MAX_ATTEMPTS    3
#define BATCH_FSYNC_SLOW_COOLDOWN_SECS   300

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
static _Atomic int64_t g_test_budget_override = -1; /* -1 = use env/default */
#endif

static int64_t batch_fsync_slow_budget_us(void)
{
#ifdef ZCL_TESTING
    int64_t ov = atomic_load(&g_test_budget_override);
    if (ov >= 0)
        return ov;
#endif
    const char *env = getenv("ZCL_BATCH_FSYNC_SLOW_EWMA_US");
    if (env && env[0]) {
        char *end = NULL;
        long long v = strtoll(env, &end, 10);
        if (end != env && v > 0)
            return (int64_t)v;
    }
    return BATCH_FSYNC_SLOW_EWMA_US_DEFAULT;
}

static bool detect_batch_fsync_slow(void)
{
    int64_t last_us = 0, ewma_us = 0;
    reducer_body_fsync_timing_snapshot(&last_us, &ewma_us);
    if (ewma_us <= 0)
        return false; /* never sampled yet (no batch commit observed) */
    return ewma_us > batch_fsync_slow_budget_us();
}

static enum condition_remedy_result remedy_batch_fsync_slow(void)
{
    int64_t last_us = 0, ewma_us = 0;
    reducer_body_fsync_timing_snapshot(&last_us, &ewma_us);
    int64_t budget_us = batch_fsync_slow_budget_us();

    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "batch pre-commit fsync (bodies+event_log) flush_us_ewma=%lld "
             "last_flush_us=%lld exceeds budget_us=%lld — observational, no "
             "veto/durability change; clears when the EWMA drops back under "
             "budget",
             (long long)ewma_us, (long long)last_us, (long long)budget_us);

    struct blocker_record r;
    if (blocker_init(&r, "batch_fsync_slow", "reducer_body_fsync",
                     BLOCKER_TRANSIENT, reason)) {
        (void)blocker_set(&r);
    }

    LOG_WARN("condition",
             "[condition:batch_fsync_slow] flush_us_ewma=%lld last_flush_us=%lld "
             "budget_us=%lld action=name_blocker",
             (long long)ewma_us, (long long)last_us, (long long)budget_us);

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif

    /* Honest "nothing to fix but the disk": no automated action can speed up
     * IO. OK (not FAILED) so the continue-with-cooldown tier never latches
     * operator_needed on a transient IO regression — see disk_full_pause.c
     * for the identical rationale. */
    return COND_REMEDY_OK;
}

static bool witness_batch_fsync_slow(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: clears iff a FRESH read of the live EWMA is back at
    // or under budget. There is no independent force-repoll (unlike
    // disk_monitor_poll_now()) — the EWMA only advances on the drive's own
    // next batch commit, matching every other EWMA-driven signal in this
    // codebase (e.g. stage.c's step_us_ewma).
    int64_t last_us = 0, ewma_us = 0;
    reducer_body_fsync_timing_snapshot(&last_us, &ewma_us);
    bool resolved = ewma_us <= batch_fsync_slow_budget_us();
    if (resolved)
        blocker_clear("batch_fsync_slow");
    return resolved;
}

static bool detail_batch_fsync_slow(struct json_value *out)
{
    if (!out)
        return false;
    int64_t last_us = 0, ewma_us = 0;
    reducer_body_fsync_timing_snapshot(&last_us, &ewma_us);
    bool ok = true;
    ok = ok && json_push_kv_int(out, "flush_us_ewma", ewma_us);
    ok = ok && json_push_kv_int(out, "last_flush_us", last_us);
    ok = ok && json_push_kv_int(out, "budget_us", batch_fsync_slow_budget_us());
    return ok;
}

static struct condition c_batch_fsync_slow = {
    .name = "batch_fsync_slow",
    .severity = COND_WARN,
    .poll_secs = BATCH_FSYNC_SLOW_POLL_SECS,
    .backoff_secs = BATCH_FSYNC_SLOW_BACKOFF_SECS,
    .max_attempts = BATCH_FSYNC_SLOW_MAX_ATTEMPTS,
    /* Continue-with-cooldown (sticky-node plan #7): a slow disk is a
     * recoverable external-resource condition, never a local deterministic
     * fault — see disk_full_pause.c for the identical rationale. */
    .cooldown_secs = BATCH_FSYNC_SLOW_COOLDOWN_SECS,
    .cooldown_max_rearms = 0,
    .detect = detect_batch_fsync_slow,
    .remedy = remedy_batch_fsync_slow,
    .witness = witness_batch_fsync_slow,
    .detail = detail_batch_fsync_slow,
    .witness_window_secs = BATCH_FSYNC_SLOW_BACKOFF_SECS,
};

void register_batch_fsync_slow(void)
{
    (void)condition_register(&c_batch_fsync_slow);
}

#ifdef ZCL_TESTING
void batch_fsync_slow_test_reset(void)
{
    atomic_store(&g_test_remedy_calls, 0);
    atomic_store(&g_test_budget_override, -1);
    blocker_clear("batch_fsync_slow");
}

int batch_fsync_slow_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}

void batch_fsync_slow_test_set_budget_us(int64_t budget_us)
{
    atomic_store(&g_test_budget_override, budget_us);
}
#endif

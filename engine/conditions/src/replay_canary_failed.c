/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "conditions/replay_canary_failed.h"
#include "util/log_macros.h"
#include "framework/condition.h"

#include "services/canary_sentinel_watch.h"

#include <stdatomic.h>

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

static bool detect_replay_canary_failed(void)
{
    return canary_sentinel_watch_fail_active();
}

static enum condition_remedy_result remedy_replay_canary_failed(void)
{
    char detail[512];
    int fails = canary_sentinel_watch_fail_detail(detail, sizeof(detail));

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif

    LOG_WARN("condition", "[condition:replay_canary_failed] %d FAIL "
             "sentinel(s): %s action=operator_escalation",
             fails, detail[0] ? detail : "-");

    /* A replay-canary FAIL means the binary could not honestly re-derive the
     * chain (or diverged from the reference node). There is no safe automatic
     * fix — keep the condition unresolved so the engine pages the operator
     * instead of pretending. Only a later PASS run clears the latch. */
    return COND_REMEDY_FAILED;
}

static bool witness_replay_canary_failed(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: remedy_replay_canary_failed returns
    // COND_REMEDY_FAILED and NEVER mutates the watch latch — the latch is
    // derived solely from on-disk sentinel files an external canary run
    // writes (atomic rename), and a FAIL kind only clears when a SUBSEQUENT
    // run writes a PASS sentinel for that same kind (absence never clears).
    // So this read cannot be self-certified by the remedy; it exists for the
    // engine's !detected deactivation path once the canary genuinely passes
    // again, which needs a truthful latch read, never a constant.
    return !canary_sentinel_watch_fail_active();
}

static struct condition c_replay_canary_failed = {
    .name = "replay_canary_failed",
    .severity = COND_CRITICAL,
    .poll_secs = 60,
    .backoff_secs = 300,
    .max_attempts = 1,
    .detect = detect_replay_canary_failed,
    .remedy = remedy_replay_canary_failed,
    .witness = witness_replay_canary_failed,
    .witness_window_secs = 60,
};

void register_replay_canary_failed(void)
{
    (void)condition_register(&c_replay_canary_failed);
}

#ifdef ZCL_TESTING
void replay_canary_failed_test_reset(void)
{
    atomic_store(&g_test_remedy_calls, 0);
    condition_reset_state(&c_replay_canary_failed);
}

int replay_canary_failed_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif

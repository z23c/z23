/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tor_start_failed condition — see conditions/tor_start_failed.h. */

#include "conditions/tor_start_failed.h"

#include "config/boot_tor_watch.h"
#include "framework/condition.h"
#include "net/tor_integration.h"
#include "platform/time_compat.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdio.h>

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

static bool detect_tor_start_failed(void)
{
    return boot_tor_watch_failed(boot_tor_watch_current());
}

/* The retry schedule is the WATCH's, not the engine's: boot_tor_watch_due()
 * is what makes the first retries land at 5s/15s/45s instead of waiting the
 * condition's own backoff. The engine still owns the outer bound (backoff +
 * cooldown re-arm), so this can never spin. */
static bool urgent_tor_start_failed(void)
{
    return boot_tor_watch_due(boot_tor_watch_current(),
                              platform_time_monotonic_us());
}

static void tor_raise_blocker(const char *reason)
{
    struct blocker_record r;
    /* blocker-id: tor.start_failed */
    if (blocker_init(&r, BOOT_TOR_START_FAILED_BLOCKER,
                     BOOT_TOR_START_FAILED_OWNER, BLOCKER_DEPENDENCY, reason))
        (void)blocker_set(&r);
    else
        LOG_WARN("onion_tor",
                 "could not name the Tor start failure as a blocker "
                 "(reason too long?); retrying anyway: %s", reason);
}

static enum condition_remedy_result remedy_tor_start_failed(void)
{
    struct boot_tor_watch *w = boot_tor_watch_current();
    if (!w)
        return COND_REMEDY_SKIP;

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif

    char reason[BOOT_TOR_REASON_MAX];
    boot_tor_watch_capture_fault(w, reason, sizeof(reason));
    tor_raise_blocker(reason);
    LOG_WARN("condition",
             "[condition:tor_start_failed] embedded Tor is not running while "
             "an onion was requested: %s", reason);

    int64_t now_us = platform_time_monotonic_us();
    if (!boot_tor_watch_due(w, now_us))
        return COND_REMEDY_SKIP;
    /* The wrapper's return says only "the start call was made". Whether Tor
     * actually came up is the witness's job, below. */
    (void)boot_tor_watch_retry(w, now_us);
    return COND_REMEDY_OK;
}

static bool witness_tor_start_failed(int64_t target_at_detect)
{
    // honest-witness-ok: the observable is core's own live-thread predicate
    // tor_integration_is_enabled(), still true after the settling time. The
    // remedy's start sets that flag at once, before Tor has parsed anything, so
    // the flag alone proves nothing right after a retry. Tor's own thread clears
    // it when Tor ends, and the remedy cannot keep it set, so a Tor that is still
    // running after the settling time is independent evidence the symptom moved.
    (void)target_at_detect;
    if (!boot_tor_watch_confirm_up(boot_tor_watch_current(),
                                   tor_integration_is_enabled(),
                                   platform_time_monotonic_us()))
        return false; // raw-return-ok:witness-observation-not-an-error

    blocker_clear(BOOT_TOR_START_FAILED_BLOCKER);
    return true;
}

static struct condition c_tor_start_failed = {
    .name = "tor_start_failed",
    .severity = COND_WARN,
    .poll_secs = 5,
    /* The cap of the watch's own schedule. urgent_tor_start_failed() is what
     * releases the earlier, shorter retries. */
    .backoff_secs = 300,
    /* Four attempts (5s, 15s, 45s, 135s) before the operator is paged, then
     * the cooldown re-arm keeps retrying every 5 minutes with no bound of its
     * own — an external-resource fault (a port a departing process still holds,
     * a torrc a human is editing) must not become a give-up. The one bound is
     * the watch's: past TOR_MAX_STARTS_IN_PROCESS it is never due again, and
     * this remedy only keeps the blocker up saying a restart is needed. */
    .max_attempts = 4,
    .cooldown_secs = 300,
    .cooldown_max_rearms = 0,
    .detect = detect_tor_start_failed,
    .remedy = remedy_tor_start_failed,
    .witness = witness_tor_start_failed,
    .urgent = urgent_tor_start_failed,
    .witness_window_secs = 120,
};

void register_tor_start_failed(void)
{
    (void)condition_register(&c_tor_start_failed);
}

#ifdef ZCL_TESTING
void tor_start_failed_test_reset(void)
{
    atomic_store(&g_test_remedy_calls, 0);
    condition_reset_state(&c_tor_start_failed);
}

int tor_start_failed_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif

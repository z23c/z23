/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the shared log_throttle de-storm primitive (util/log_throttle).
 * These pin the EXACT cadence the three reducer sites (tip_finalize cursor-gap +
 * precondition, reducer_frontier coin-tear, reconcile_light gate-suppress) rely
 * on: emit on first key / key change / keepalive-elapsed, with the suppressed
 * repeat count reported as the prior key's count on a change and the running
 * count on a keep-alive. The clock is caller-supplied, so these are pure and
 * deterministic — no real time. */

#include "test/test_core.h"

#include "support/log_throttle.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define LT_CHECK(name, expr) do {                                  \
    printf("log_throttle: %s... ", (name));                        \
    if (expr) { printf("OK\n"); }                                  \
    else { printf("FAIL\n"); failures++; }                         \
} while (0)

/* First call on a fresh throttle always emits with reps=0 (the prior key's
 * count, and there was no prior key). */
static int case_first_emit(void)
{
    int failures = 0;
    struct log_throttle t = LOG_THROTTLE_INIT;
    uint64_t reps = 999;
    bool emit = log_throttle_should_emit(&t, 100, 1000, 300, &reps);
    LT_CHECK("first call emits", emit);
    LT_CHECK("first call reports reps=0", reps == 0);
    LT_CHECK("reps accessor reads 0 after change", log_throttle_reps(&t) == 0);
    return failures;
}

/* Same key inside the keepalive window is suppressed; the running repeat count
 * climbs on every suppressed call even though nothing is emitted. */
static int case_suppression(void)
{
    int failures = 0;
    struct log_throttle t = LOG_THROTTLE_INIT;
    uint64_t reps = 0;

    (void)log_throttle_should_emit(&t, 100, 1000, 300, &reps);   /* emit, reps=0 */

    bool e1 = log_throttle_should_emit(&t, 100, 1001, 300, &reps);
    LT_CHECK("same key within window suppressed (#1)", !e1);
    LT_CHECK("running reps == 1 after first suppress", reps == 1);

    bool e2 = log_throttle_should_emit(&t, 100, 1100, 300, &reps);
    LT_CHECK("same key within window suppressed (#2)", !e2);
    LT_CHECK("running reps == 2 after second suppress", reps == 2);
    LT_CHECK("reps accessor matches running count", log_throttle_reps(&t) == 2);
    return failures;
}

/* A key change emits immediately (ignoring the keepalive window) and reports
 * the PRIOR key's accumulated suppressed count, then resets the counter. */
static int case_change_triggers_emit(void)
{
    int failures = 0;
    struct log_throttle t = LOG_THROTTLE_INIT;
    uint64_t reps = 0;

    (void)log_throttle_should_emit(&t, 100, 1000, 300, &reps);   /* emit */
    (void)log_throttle_should_emit(&t, 100, 1001, 300, &reps);   /* suppress, reps=1 */
    (void)log_throttle_should_emit(&t, 100, 1002, 300, &reps);   /* suppress, reps=2 */

    /* Change to key 200 still well inside the 300 s window — must emit. */
    bool emit = log_throttle_should_emit(&t, 200, 1003, 300, &reps);
    LT_CHECK("key change emits inside window", emit);
    LT_CHECK("change reports PRIOR key's count (2)", reps == 2);
    LT_CHECK("counter reset for new key", log_throttle_reps(&t) == 0);
    return failures;
}

/* When the same key persists past the keepalive interval, a keep-alive emit
 * fires carrying the running suppressed count (NOT reset). */
static int case_keepalive_triggers_emit(void)
{
    int failures = 0;
    struct log_throttle t = LOG_THROTTLE_INIT;
    uint64_t reps = 0;

    (void)log_throttle_should_emit(&t, 100, 1000, 300, &reps);   /* emit, last=1000 */
    (void)log_throttle_should_emit(&t, 100, 1200, 300, &reps);   /* suppress, reps=1 */

    /* 1000 + 300 == 1300: keepalive boundary is inclusive (>=). */
    bool e_boundary = log_throttle_should_emit(&t, 100, 1300, 300, &reps);
    LT_CHECK("keepalive emits at >= boundary", e_boundary);
    LT_CHECK("keepalive reports running count (2)", reps == 2);
    /* keep-alive does NOT reset the counter. */
    LT_CHECK("counter not reset on keepalive", log_throttle_reps(&t) == 2);

    /* Next call resets the keepalive window relative to 1300. */
    bool e_after = log_throttle_should_emit(&t, 100, 1301, 300, &reps);
    LT_CHECK("suppressed again right after keepalive", !e_after);
    LT_CHECK("running count keeps climbing (3)", reps == 3);
    return failures;
}

/* The boolean-change entry point (for callers whose key is a string tuple)
 * applies the identical first/change/keepalive cadence. */
static int case_changed_variant(void)
{
    int failures = 0;
    struct log_throttle t = LOG_THROTTLE_INIT;
    uint64_t reps = 0;

    bool e0 = log_throttle_should_emit_changed(&t, true, 1000, 300, &reps);
    LT_CHECK("changed=true first emits", e0);
    LT_CHECK("changed first reps=0", reps == 0);

    bool e1 = log_throttle_should_emit_changed(&t, false, 1001, 300, &reps);
    LT_CHECK("changed=false within window suppressed", !e1);
    LT_CHECK("changed=false running reps=1", reps == 1);

    bool e2 = log_throttle_should_emit_changed(&t, true, 1002, 300, &reps);
    LT_CHECK("changed=true re-emits inside window", e2);
    LT_CHECK("changed=true reports prior count (1)", reps == 1);

    bool e3 = log_throttle_should_emit_changed(&t, false, 1303, 300, &reps);
    LT_CHECK("changed=false keepalive emits at boundary", e3);
    LT_CHECK("changed=false keepalive running count (1)", reps == 1);
    return failures;
}

/* reset() re-arms the throttle: the next call behaves like a first emit
 * (reps=0), modeling the gate-suppress site re-arming when evidence clears. */
static int case_reset(void)
{
    int failures = 0;
    struct log_throttle t = LOG_THROTTLE_INIT;
    uint64_t reps = 0;

    (void)log_throttle_should_emit(&t, 100, 1000, 300, &reps);
    (void)log_throttle_should_emit(&t, 100, 1001, 300, &reps);   /* reps -> 1 */
    LT_CHECK("reps accumulated before reset", log_throttle_reps(&t) == 1);

    log_throttle_reset(&t);
    LT_CHECK("reps cleared by reset", log_throttle_reps(&t) == 0);

    /* Re-arm: the SAME key now counts as a fresh first emit (reps=0), even
     * though only 1 s has passed since the pre-reset emit. */
    bool emit = log_throttle_should_emit(&t, 100, 1002, 300, &reps);
    LT_CHECK("emit after reset (re-armed)", emit);
    LT_CHECK("reps=0 after reset re-arm", reps == 0);
    return failures;
}

/* NULL throttle is a safe no-op (never emits, reps zeroed). */
static int case_null_safe(void)
{
    int failures = 0;
    uint64_t reps = 7;
    bool emit = log_throttle_should_emit(NULL, 1, 1000, 300, &reps);
    LT_CHECK("NULL throttle does not emit", !emit);
    LT_CHECK("NULL throttle zeroes out_reps", reps == 0);
    LT_CHECK("NULL reps accessor returns 0", log_throttle_reps(NULL) == 0);
    log_throttle_reset(NULL);  /* must not crash */
    return failures;
}

int test_log_throttle(void)
{
    int failures = 0;
    printf("\n--- log_throttle (shared de-storm primitive) ---\n");
    failures += case_first_emit();
    failures += case_suppression();
    failures += case_change_triggers_emit();
    failures += case_keepalive_triggers_emit();
    failures += case_changed_variant();
    failures += case_reset();
    failures += case_null_safe();
    if (failures == 0)
        printf("log_throttle: all cases passed\n");
    else
        printf("log_throttle: %d failure(s)\n", failures);
    return failures;
}

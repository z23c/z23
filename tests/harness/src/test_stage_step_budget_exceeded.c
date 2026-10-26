/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the stage_step_budget_exceeded condition — the
 * OBSERVATIONAL per-stage EWMA-vs-budget performance regression naming
 * (perf-named-conditions workflow). Covers: (a) an injected over-budget EWMA
 * raises the typed blocker naming the stage, (b) the blocker clears once
 * that stage's EWMA recovers, (c) a healthy fold (no forced ewma, or ewma
 * comfortably inside a forced budget) never false-fires, and (d) the
 * warm-up rolling baseline does not enforce a budget until it has locked,
 * and — once locked at a steady-state value — a genuine multi-x regression
 * on top of it trips the condition.
 *
 * condition_tick_one() gates a NOT-YET-active condition's detect() calls by
 * real wall-clock poll_secs (15s for this condition), so this test installs
 * the same fake clock_iface_t the sync_watchdog / reducer_drive_watchdog
 * condition tests use to advance wall time without sleeping. */

#include "test/test_core.h"

#include "conditions/stage_step_budget_exceeded.h"
#include "framework/condition.h"
#include "json/json.h"
#include "platform/clock.h"
#include "util/blocker.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SSBE_CHECK(name, expr) do { \
    printf("stage_step_budget_exceeded: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Pipeline indices, matching conditions/stage_step_budget_exceeded.h. */
#define IDX_HEADER_ADMIT     0
#define IDX_VALIDATE_HEADERS 1
#define IDX_BODY_FETCH       2
#define IDX_BODY_PERSIST     3
#define IDX_SCRIPT_VALIDATE  4
#define IDX_PROOF_VALIDATE   5
#define IDX_UTXO_APPLY       6
#define IDX_TIP_FINALIZE     7

struct ssbe_fake_clock {
    _Atomic int64_t wall_ms;
};

static int64_t ssbe_fake_now_mono(void *self)
{
    (void)self;
    return 1;
}

static int64_t ssbe_fake_now_wall(void *self)
{
    struct ssbe_fake_clock *c = (struct ssbe_fake_clock *)self;
    return atomic_load(&c->wall_ms);
}

static void ssbe_fake_clock_install(struct ssbe_fake_clock *c, int64_t unix_s)
{
    atomic_store(&c->wall_ms, unix_s * 1000);
    static clock_iface_t iface;
    iface.now_monotonic_ns = ssbe_fake_now_mono;
    iface.now_wall_ms = ssbe_fake_now_wall;
    iface.self = c;
    clock_set_default(&iface);
}

static void ssbe_fake_clock_set(struct ssbe_fake_clock *c, int64_t unix_s)
{
    atomic_store(&c->wall_ms, unix_s * 1000);
}

static void ssbe_reset(void)
{
    condition_engine_reset_for_testing();
    blocker_reset_for_testing();
    stage_step_budget_exceeded_test_reset();
    register_stage_step_budget_exceeded();
}

static void ssbe_cleanup(void)
{
    condition_engine_reset_for_testing();
    blocker_reset_for_testing();
    stage_step_budget_exceeded_test_reset();
    clock_reset_default();
}

/* State after condition_engine_tick() saw an injected breach: the condition
 * is active, its blocker is raised, and the remedy fired exactly once. */
static bool ssbe_breach_fires_remedy_once(void)
{
    bool ok = true;
    ok = ok && stage_step_budget_exceeded_test_remedy_calls() == 1;
    ok = ok && condition_engine_get_active_count() == 1;
    ok = ok && blocker_exists("stage_step_budget_exceeded");
    return ok;
}

/* True when this condition's blocker snapshot reason names the given
 * pipeline stage. */
static bool ssbe_blocker_reason_names_stage(const char *stage_name)
{
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    bool found_reason = false;
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].id, "stage_step_budget_exceeded") == 0 &&
            strstr(snaps[i].reason, stage_name) != NULL) {
            found_reason = true;
            break;
        }
    }
    return found_reason;
}

/* Finds this condition's object inside a dumped "conditions" array. */
static const struct json_value *ssbe_find_condition_in_dump(
    const struct json_value *conditions)
{
    const struct json_value *found = NULL;
    for (size_t i = 0; conditions && i < json_size(conditions); i++) {
        const struct json_value *c = json_at(conditions, i);
        const struct json_value *nm = c ? json_get(c, "name") : NULL;
        if (nm && strcmp(json_get_str(nm), "stage_step_budget_exceeded") == 0) {
            found = c;
            break;
        }
    }
    return found;
}

/* Dumps engine state as JSON and checks the condition's detail names the
 * stage, the observed EWMA and the forced budget. */
static bool ssbe_dump_detail_matches_breach(void)
{
    struct json_value dump;
    json_init(&dump);
    json_set_object(&dump);
    bool dumped = condition_engine_dump_state_json(&dump, NULL);
    bool okd = dumped;
    const struct json_value *conditions = json_get(&dump, "conditions");
    okd = okd && conditions != NULL;
    const struct json_value *found = ssbe_find_condition_in_dump(conditions);
    okd = okd && found != NULL;
    const struct json_value *detail = found ? json_get(found, "detail") : NULL;
    okd = okd && detail != NULL;
    okd = okd && json_get(detail, "stage") != NULL;
    okd = okd &&
          strcmp(json_get_str(json_get(detail, "stage")), "utxo_apply") == 0;
    okd = okd && json_get_int(json_get(detail, "observed_ewma_us")) == 100000;
    okd = okd && json_get_int(json_get(detail, "budget_us")) == 1000;
    json_free(&dump);
    return okd;
}

/* State after the offending stage's EWMA falls back under budget: the
 * blocker is gone and the engine is idle. */
static bool ssbe_recovery_cleared_blocker(void)
{
    bool ok = true;
    ok = ok && !blocker_exists("stage_step_budget_exceeded");
    ok = ok && condition_engine_get_active_count() == 0;
    return ok;
}

/* Runs `ticks` engine ticks, each advancing the fake wall clock 20s past
 * the previous one; the engine must stay idle after every tick. */
static bool ssbe_poll_ticks_stay_idle(struct ssbe_fake_clock *fc, int64_t t0,
                                      int ticks)
{
    bool ok = true;
    for (int i = 0; i < ticks; i++) {
        ssbe_fake_clock_set(fc, t0 + 20 * (i + 1));
        condition_engine_tick();
        ok = ok && condition_engine_get_active_count() == 0;
    }
    return ok;
}

/* Forces every stage's EWMA comfortably inside a forced budget, then ticks
 * on from t0 + 200: nothing may trip and the remedy must never fire. */
static bool ssbe_ewma_inside_budget_never_trips(struct ssbe_fake_clock *fc,
                                                int64_t t0)
{
    for (int i = 0; i < 8; i++) {
        stage_step_budget_exceeded_test_set_ewma_us(i, 1000);
        stage_step_budget_exceeded_test_set_budget_us(i, 50000);
    }
    bool ok = ssbe_poll_ticks_stay_idle(fc, t0 + 200, 6);
    ok = ok && stage_step_budget_exceeded_test_remedy_calls() == 0;
    return ok;
}

/* State after a genuine multi-x regression on the locked baseline: the
 * condition is active and its blocker reason names the regressed stage. */
static bool ssbe_regression_on_locked_baseline_trips(void)
{
    bool ok = true;
    ok = ok && condition_engine_get_active_count() == 1;
    ok = ok && blocker_exists("stage_step_budget_exceeded");
    bool found_reason = ssbe_blocker_reason_names_stage("proof_validate");
    ok = ok && found_reason;
    return ok;
}

/* An overflowing operator override must be rejected rather than becoming an
 * effectively unreachable budget. The test deliberately uses the real
 * env-or-baseline path: a steady EWMA locks the baseline, then a genuine
 * slowdown must be named. Preserve any caller-provided override exactly. */
static bool ssbe_overflowing_env_falls_back(struct ssbe_fake_clock *fc,
                                             int64_t t0)
{
    const char *var = "ZCL_STAGE_BUDGET_US_PROOF_VALIDATE";
    const char *old = getenv(var);
    char *saved = old ? strdup(old) : NULL;
    if (old && !saved)
        return false;

    bool ok = setenv(var, "9223372036854775808", 1) == 0;
    if (ok) {
        ssbe_reset();
        ssbe_fake_clock_install(fc, t0);
        stage_step_budget_exceeded_test_set_ewma_us(IDX_PROOF_VALIDATE, 1000);
        for (int i = 0; i < 10; i++) {
            ssbe_fake_clock_set(fc, t0 + 20 * (i + 1));
            condition_engine_tick();
            ok = ok && condition_engine_get_active_count() == 0;
        }
        stage_step_budget_exceeded_test_set_ewma_us(IDX_PROOF_VALIDATE, 50000);
        ssbe_fake_clock_set(fc, t0 + 240);
        condition_engine_tick();
        ok = ok && condition_engine_get_active_count() == 1 &&
             blocker_exists("stage_step_budget_exceeded");
    }

    if (saved)
        ok = setenv(var, saved, 1) == 0 && ok;
    else
        ok = unsetenv(var) == 0 && ok;
    free(saved);
    return ok;
}

int test_stage_step_budget_exceeded(void);
int test_stage_step_budget_exceeded(void)
{
    printf("\n=== stage_step_budget_exceeded condition tests ===\n");
    int failures = 0;
    struct ssbe_fake_clock fc;
    int64_t t0 = 3000000000;

    /* ---- (a) injected breach: EWMA over a forced budget names the stage ---- */
    {
        ssbe_reset();
        ssbe_fake_clock_install(&fc, t0);
        stage_step_budget_exceeded_test_set_ewma_us(IDX_UTXO_APPLY, 100000);
        stage_step_budget_exceeded_test_set_budget_us(IDX_UTXO_APPLY, 1000);

        condition_engine_tick();
        bool ok = ssbe_breach_fires_remedy_once();
        SSBE_CHECK("EWMA over forced budget trips + fires remedy once", ok);

        bool found_reason = ssbe_blocker_reason_names_stage("utxo_apply");
        SSBE_CHECK("blocker reason names the offending stage", found_reason);

        bool okd = ssbe_dump_detail_matches_breach();
        SSBE_CHECK("detail names stage + observed_ewma_us + budget_us", okd);

        /* ---- (b) recovery clears the blocker ---- */
        stage_step_budget_exceeded_test_set_ewma_us(IDX_UTXO_APPLY, 500);
        ssbe_fake_clock_set(&fc, t0 + 20);
        condition_engine_tick();

        bool ok2 = ssbe_recovery_cleared_blocker();
        SSBE_CHECK("EWMA falling back under budget clears the blocker", ok2);
    }

    /* ---- (c) a healthy fold never false-fires ---- */
    {
        ssbe_reset();
        ssbe_fake_clock_install(&fc, t0);

        /* (c1) no forced ewma at all -- every real *_stage_step_us_ewma()
         * accessor reads 0 (no stage has run in this test process), so the
         * "never stepped" skip must hold for every one of the 8 stages. */
        bool ok = ssbe_poll_ticks_stay_idle(&fc, t0, 8);
        SSBE_CHECK("no forced EWMA anywhere never trips", ok);

        /* (c2) forced ewma comfortably inside a forced budget on every
         * stage -- must never trip regardless of how many ticks run. */
        bool ok2 = ssbe_ewma_inside_budget_never_trips(&fc, t0);
        SSBE_CHECK("EWMA well inside budget on every stage never trips", ok2);
    }

    /* ---- (d) warm-up baseline: no enforcement until locked, then a real
     * multi-x regression on top of the learned baseline trips it ---- */
    {
        ssbe_reset();
        ssbe_fake_clock_install(&fc, t0);

        /* Steady-state EWMA for proof_validate only; no forced budget, so the
         * real warm-up/baseline path is exercised. Give it generous extra
         * ticks past the (private) warm-up tick count so this test does not
         * depend on that exact constant. */
        const int64_t steady_us = 20000;
        stage_step_budget_exceeded_test_set_ewma_us(IDX_PROOF_VALIDATE, steady_us);
        bool ok = ssbe_poll_ticks_stay_idle(&fc, t0, 10);
        SSBE_CHECK("steady-state EWMA through warm-up never trips "
                  "(baseline == the value itself, not over budget)", ok);

        /* Now a genuine multi-x regression on the same stage: comfortably
         * above ANY reasonable multiplier of the learned baseline. */
        stage_step_budget_exceeded_test_set_ewma_us(IDX_PROOF_VALIDATE,
                                                    steady_us * 50);
        ssbe_fake_clock_set(&fc, t0 + 20 * 12);
        condition_engine_tick();

        bool ok2 = ssbe_regression_on_locked_baseline_trips();
        SSBE_CHECK("a real multi-x regression on the learned baseline trips it",
                  ok2);
    }

    /* ---- (e) malformed/overflowing override falls back to baseline ---- */
    SSBE_CHECK("overflowing stage budget env falls back and names slowdown",
               ssbe_overflowing_env_falls_back(&fc, t0 + 1000));

    ssbe_cleanup();

    printf("=== test_stage_step_budget_exceeded complete: %d failure(s) ===\n",
           failures);
    return failures;
}

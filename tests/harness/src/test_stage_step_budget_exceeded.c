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
#include <stdint.h>
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

/* ---- measured-gap cases: warm-up lock, worst-stage pick, witness edges,
 * env overrides, active-branch warm-up, reset and registration posture ---- */

/* Like `ok = ok && expr`, but names the first failing line. */
#define SSBE_AND(ok, expr) do { \
    if ((ok) && !(expr)) { \
        printf("[ssbe line %d failed] ", __LINE__); \
        (ok) = false; \
    } \
} while (0)

#define SSBE_NSTAGES 8
#define SSBE_COND "stage_step_budget_exceeded"

static const char *const ssbe_stage_names[SSBE_NSTAGES] = {
    "header_admit", "validate_headers", "body_fetch", "body_persist",
    "script_validate", "proof_validate", "utxo_apply", "tip_finalize",
};

struct ssbe_ctx {
    struct ssbe_fake_clock *fc;
    int64_t now;
};

/* Plain copy of the detail JSON: the episode snapshot plus every roster row. */
struct ssbe_view {
    bool ok;
    char stage[32];
    int64_t observed;
    int64_t budget;
    int64_t last_fire;
    char name[SSBE_NSTAGES][32];
    int64_t ewma[SSBE_NSTAGES];
    int64_t bud[SSBE_NSTAGES];
    int64_t base[SSBE_NSTAGES];
};

static int64_t ssbe_geti(const struct json_value *o, const char *k)
{
    const struct json_value *v = o ? json_get(o, k) : NULL;
    return v ? json_get_int(v) : INT64_MIN;
}

static void ssbe_copy_str(char *dst, size_t cap, const struct json_value *o,
                          const char *k)
{
    const struct json_value *v = o ? json_get(o, k) : NULL;
    const char *s = v ? json_get_str(v) : NULL;
    snprintf(dst, cap, "%s", s ? s : "<missing>");
}

static bool ssbe_view_roster(struct ssbe_view *v, const struct json_value *detail)
{
    const struct json_value *stages = json_get(detail, "stages");
    if (!stages || json_size(stages) != SSBE_NSTAGES)
        return false;
    for (size_t i = 0; i < SSBE_NSTAGES; i++) {
        const struct json_value *row = json_at(stages, i);
        ssbe_copy_str(v->name[i], sizeof(v->name[i]), row, "stage");
        v->ewma[i] = ssbe_geti(row, "step_us_ewma");
        v->bud[i] = ssbe_geti(row, "budget_us");
        v->base[i] = ssbe_geti(row, "baseline_us");
    }
    return true;
}

static struct ssbe_view ssbe_snap(void)
{
    struct ssbe_view v;
    memset(&v, 0, sizeof(v));
    struct json_value dump;
    json_init(&dump);
    json_set_object(&dump);
    bool dumped = condition_engine_dump_state_json(&dump, NULL);
    const struct json_value *found =
        dumped ? ssbe_find_condition_in_dump(json_get(&dump, "conditions"))
               : NULL;
    const struct json_value *detail = found ? json_get(found, "detail") : NULL;
    if (detail) {
        ssbe_copy_str(v.stage, sizeof(v.stage), detail, "stage");
        v.observed = ssbe_geti(detail, "observed_ewma_us");
        v.budget = ssbe_geti(detail, "budget_us");
        v.last_fire = ssbe_geti(detail, "last_fire_unix");
        v.ok = ssbe_view_roster(&v, detail);
    }
    json_free(&dump);
    return v;
}

/* cleared_count is cumulative across resets, so each case counts from here. */
static int ssbe_cleared_base;

static void ssbe_begin(struct ssbe_ctx *c)
{
    ssbe_reset();
    ssbe_fake_clock_install(c->fc, c->now);
    struct condition_runtime_snapshot s;
    ssbe_cleared_base = condition_engine_get_registered_snapshot(SSBE_COND, &s)
                            ? s.cleared_count : -1;
}

/* Each tick moves the fake wall clock 20s, past the 15s poll gate. */
static void ssbe_ticks(struct ssbe_ctx *c, int n)
{
    for (int i = 0; i < n; i++) {
        c->now += 20;
        ssbe_fake_clock_set(c->fc, c->now);
        condition_engine_tick();
    }
}

static void ssbe_force(int idx, int64_t ewma, int64_t budget)
{
    stage_step_budget_exceeded_test_set_ewma_us(idx, ewma);
    stage_step_budget_exceeded_test_set_budget_us(idx, budget);
}

/* No episode ever began: nothing cleared, no remedy, no stage frozen. A
 * detect() that fires spuriously is cleared by witness() inside the same
 * tick, so active_count alone cannot see it; cleared_count and the frozen
 * stage snapshot can. */
static bool ssbe_no_episode(void)
{
    struct ssbe_view v = ssbe_snap();
    struct condition_runtime_snapshot s;
    bool ok = v.ok && condition_engine_get_registered_snapshot(SSBE_COND, &s);
    SSBE_AND(ok, s.cleared_count == ssbe_cleared_base && !s.currently_active);
    SSBE_AND(ok, v.stage[0] == '\0' && v.last_fire == 0);
    SSBE_AND(ok, stage_step_budget_exceeded_test_remedy_calls() == 0);
    SSBE_AND(ok, condition_engine_get_active_count() == 0);
    return ok;
}

/* Engine state right after the first tick of a breach episode. */
static bool ssbe_trip_engine_state(void)
{
    struct condition_runtime_snapshot s;
    bool ok = condition_engine_get_registered_snapshot(SSBE_COND, &s);
    SSBE_AND(ok, s.currently_active && s.cleared_count == ssbe_cleared_base);
    SSBE_AND(ok, s.last_outcome == COND_REMEDY_FAILED);
    SSBE_AND(ok, s.operator_needed_emitted && s.attempts == 1);
    SSBE_AND(ok, stage_step_budget_exceeded_test_remedy_calls() == 1);
    SSBE_AND(ok, condition_engine_get_active_count() == 1);
    SSBE_AND(ok, blocker_exists(SSBE_COND));
    return ok;
}

static bool ssbe_trip_view(const struct ssbe_ctx *c, const char *stage,
                           int64_t ewma, int64_t budget)
{
    struct ssbe_view v = ssbe_snap();
    bool ok = v.ok && strcmp(v.stage, stage) == 0;
    SSBE_AND(ok, v.observed == ewma && v.budget == budget);
    SSBE_AND(ok, v.last_fire == c->now);
    SSBE_AND(ok, ssbe_blocker_reason_names_stage(stage));
    return ok;
}

/* The 5th nonzero-EWMA tick locks the baseline at the EWMA; the budget is
 * 6x the baseline with a 5000us floor; a zero EWMA never counts. */
static bool ssbe_warmup_locks_on_fifth_nonzero_tick(struct ssbe_ctx *c)
{
    ssbe_begin(c);
    stage_step_budget_exceeded_test_set_ewma_us(IDX_HEADER_ADMIT, 2000);
    stage_step_budget_exceeded_test_set_ewma_us(IDX_BODY_FETCH, 1);
    ssbe_ticks(c, 4);
    struct ssbe_view v = ssbe_snap();
    bool ok = v.ok;
    SSBE_AND(ok, v.base[IDX_HEADER_ADMIT] == 0 && v.bud[IDX_HEADER_ADMIT] == -1);
    SSBE_AND(ok, v.base[IDX_BODY_FETCH] == 0 && v.bud[IDX_BODY_FETCH] == -1);
    ssbe_ticks(c, 1);
    v = ssbe_snap();
    SSBE_AND(ok, v.ok);
    SSBE_AND(ok, v.base[IDX_HEADER_ADMIT] == 2000);
    SSBE_AND(ok, v.bud[IDX_HEADER_ADMIT] == 12000);
    SSBE_AND(ok, v.base[IDX_BODY_FETCH] == 1 && v.bud[IDX_BODY_FETCH] == 5000);
    SSBE_AND(ok, v.ewma[IDX_BODY_PERSIST] == 0 && v.bud[IDX_BODY_PERSIST] == -1);
    for (int i = 0; ok && i < SSBE_NSTAGES; i++)
        ok = strcmp(v.name[i], ssbe_stage_names[i]) == 0;
    /* Five ticks at a zero EWMA, then four nonzero ticks: not yet locked. */
    stage_step_budget_exceeded_test_set_ewma_us(IDX_VALIDATE_HEADERS, 100);
    ssbe_ticks(c, 4);
    v = ssbe_snap();
    SSBE_AND(ok, v.ok && v.base[IDX_VALIDATE_HEADERS] == 0);
    ssbe_ticks(c, 1);
    v = ssbe_snap();
    SSBE_AND(ok, v.ok && v.base[IDX_VALIDATE_HEADERS] == 100);
    SSBE_AND(ok, ssbe_no_episode());
    return ok;
}

/* Worst over-budget stage wins; a tie keeps the earlier stage; an EWMA equal
 * to its budget, or a zero budget, is not a breach. */
static bool ssbe_worst_stage_pick(struct ssbe_ctx *c)
{
    ssbe_begin(c);
    ssbe_force(IDX_HEADER_ADMIT, 9000, 1000);
    ssbe_force(IDX_VALIDATE_HEADERS, 3000, 1000);
    ssbe_force(IDX_BODY_FETCH, 9000, 1000);
    ssbe_force(IDX_BODY_PERSIST, 1000, 1000);
    ssbe_ticks(c, 1);
    bool ok = ssbe_trip_engine_state();
    SSBE_AND(ok, ssbe_trip_view(c, "header_admit", 9000, 1000));

    ssbe_begin(c);
    ssbe_force(IDX_HEADER_ADMIT, 3000, 1000);
    ssbe_force(IDX_VALIDATE_HEADERS, 9000, 1000);
    ssbe_force(IDX_BODY_FETCH, 5000, 1000);
    ssbe_ticks(c, 1);
    SSBE_AND(ok, ssbe_trip_engine_state());
    SSBE_AND(ok, ssbe_trip_view(c, "validate_headers", 9000, 1000));

    ssbe_begin(c);
    ssbe_force(IDX_PROOF_VALIDATE, 1000, 1000);
    ssbe_force(IDX_UTXO_APPLY, 3000, 0);
    ssbe_ticks(c, 3);
    SSBE_AND(ok, ssbe_no_episode());
    return ok;
}

/* witness() resolves on budget <= 0 or ewma <= budget, never on budget 1
 * while the EWMA is far above it. */
static bool ssbe_witness_boundaries(struct ssbe_ctx *c)
{
    ssbe_begin(c);
    ssbe_force(IDX_UTXO_APPLY, 100000, 1000);
    ssbe_ticks(c, 1);
    bool ok = condition_engine_get_active_count() == 1;
    stage_step_budget_exceeded_test_set_budget_us(IDX_UTXO_APPLY, 1);
    ssbe_ticks(c, 1);
    SSBE_AND(ok, condition_engine_get_active_count() == 1);
    SSBE_AND(ok, blocker_exists(SSBE_COND));
    stage_step_budget_exceeded_test_set_budget_us(IDX_UTXO_APPLY, 0);
    ssbe_ticks(c, 1);
    SSBE_AND(ok, ssbe_recovery_cleared_blocker());

    ssbe_force(IDX_UTXO_APPLY, 100000, 1000);
    ssbe_ticks(c, 1);
    SSBE_AND(ok, condition_engine_get_active_count() == 1);
    stage_step_budget_exceeded_test_set_ewma_us(IDX_UTXO_APPLY, 1000);
    ssbe_ticks(c, 1);
    SSBE_AND(ok, ssbe_recovery_cleared_blocker());
    return ok;
}

struct ssbe_env_save {
    char *old;
    bool had;
    bool armed;
};

static bool ssbe_env_put(const char *var, const char *val,
                         struct ssbe_env_save *s)
{
    const char *o = getenv(var);
    s->old = o ? strdup(o) : NULL;
    if (o && !s->old)
        return false;
    s->had = o != NULL;
    s->armed = true;
    return setenv(var, val, 1) == 0;
}

static bool ssbe_env_restore(const char *var, struct ssbe_env_save *s)
{
    if (!s->armed)
        return true;
    int rc = s->had ? setenv(var, s->old, 1) : unsetenv(var);
    free(s->old);
    s->old = NULL;
    s->armed = false;
    return rc == 0;
}

/* Operator budgets "9" and "1" (one digit each, so a read of the second
 * character is caught) beat the learned baseline and enforce at once. */
static bool ssbe_env_budgets_enforced(struct ssbe_ctx *c)
{
    const char *va = "ZCL_STAGE_BUDGET_US_SCRIPT_VALIDATE";
    const char *vb = "ZCL_STAGE_BUDGET_US_PROOF_VALIDATE";
    struct ssbe_env_save a = {0};
    struct ssbe_env_save b = {0};
    bool ok = ssbe_env_put(va, "9", &a) && ssbe_env_put(vb, "1", &b);
    if (ok) {
        ssbe_begin(c);
        stage_step_budget_exceeded_test_set_ewma_us(IDX_SCRIPT_VALIDATE, 50);
        stage_step_budget_exceeded_test_set_ewma_us(IDX_PROOF_VALIDATE, 5);
        ssbe_ticks(c, 1);
        struct ssbe_view v = ssbe_snap();
        ok = ssbe_trip_engine_state();
        SSBE_AND(ok, ssbe_trip_view(c, "script_validate", 50, 9));
        SSBE_AND(ok, v.ok && v.bud[IDX_SCRIPT_VALIDATE] == 9);
        SSBE_AND(ok, v.bud[IDX_PROOF_VALIDATE] == 1);
        SSBE_AND(ok, v.base[IDX_SCRIPT_VALIDATE] == 0);
        SSBE_AND(ok, v.base[IDX_PROOF_VALIDATE] == 0);
    }
    ok = ssbe_env_restore(vb, &b) && ok;
    ok = ssbe_env_restore(va, &a) && ok;
    return ok;
}

/* Only a budget of "1" is set: an EWMA of 5 is a breach of budget 1. */
static bool ssbe_env_budget_one_enforced(struct ssbe_ctx *c)
{
    const char *vb = "ZCL_STAGE_BUDGET_US_PROOF_VALIDATE";
    struct ssbe_env_save b = {0};
    bool ok = ssbe_env_put(vb, "1", &b);
    if (ok) {
        ssbe_begin(c);
        stage_step_budget_exceeded_test_set_ewma_us(IDX_PROOF_VALIDATE, 5);
        ssbe_ticks(c, 1);
        ok = ssbe_trip_engine_state();
        SSBE_AND(ok, ssbe_trip_view(c, "proof_validate", 5, 1));
    }
    return ssbe_env_restore(vb, &b) && ok;
}

/* While one stage is frozen in an episode, the other stages keep warming. */
static bool ssbe_active_branch_warms_other_stages(struct ssbe_ctx *c)
{
    ssbe_begin(c);
    ssbe_force(IDX_SCRIPT_VALIDATE, 100000, 1000);
    stage_step_budget_exceeded_test_set_ewma_us(IDX_VALIDATE_HEADERS, 2000);
    ssbe_ticks(c, 4);
    struct ssbe_view v = ssbe_snap();
    bool ok = v.ok && condition_engine_get_active_count() == 1;
    SSBE_AND(ok, v.base[IDX_VALIDATE_HEADERS] == 0);
    ssbe_ticks(c, 1);
    v = ssbe_snap();
    SSBE_AND(ok, v.ok && v.base[IDX_VALIDATE_HEADERS] == 2000);
    SSBE_AND(ok, v.bud[IDX_VALIDATE_HEADERS] == 12000);
    SSBE_AND(ok, strcmp(v.stage, "script_validate") == 0);
    SSBE_AND(ok, condition_engine_get_active_count() == 1);
    return ok;
}

static bool ssbe_view_is_pristine(void)
{
    struct ssbe_view v = ssbe_snap();
    bool ok = v.ok && v.stage[0] == '\0';
    SSBE_AND(ok, v.observed == 0 && v.budget == 0 && v.last_fire == 0);
    for (int i = 0; ok && i < SSBE_NSTAGES; i++)
        ok = v.ewma[i] == 0 && v.bud[i] == -1 && v.base[i] == 0;
    return ok;
}

/* test_reset() must clear every piece of state a dirty run leaves behind,
 * and the setters must ignore an out-of-range stage index. */
static bool ssbe_reset_clears_everything(struct ssbe_ctx *c)
{
    ssbe_begin(c);
    for (int i = 0; i < SSBE_NSTAGES; i++)
        stage_step_budget_exceeded_test_set_ewma_us(i, 3000);
    ssbe_ticks(c, 5);
    for (int i = 0; i < SSBE_NSTAGES - 1; i++)
        ssbe_force(i, 777, 888);
    ssbe_force(IDX_TIP_FINALIZE, 100000, 1000);
    ssbe_ticks(c, 1);
    bool ok = ssbe_trip_engine_state();

    stage_step_budget_exceeded_test_reset();
    stage_step_budget_exceeded_test_set_ewma_us(-1, 5);
    stage_step_budget_exceeded_test_set_ewma_us(SSBE_NSTAGES, 5);
    stage_step_budget_exceeded_test_set_budget_us(-1, 5);
    stage_step_budget_exceeded_test_set_budget_us(SSBE_NSTAGES, 5);
    struct condition_runtime_snapshot s;
    SSBE_AND(ok, condition_engine_get_registered_snapshot(SSBE_COND, &s));
    SSBE_AND(ok, !s.currently_active && s.attempts == 0);
    SSBE_AND(ok, !blocker_exists(SSBE_COND));
    SSBE_AND(ok, stage_step_budget_exceeded_test_remedy_calls() == 0);
    SSBE_AND(ok, ssbe_view_is_pristine());

    /* The warm-up counters restarted from zero as well. */
    for (int i = 0; i < SSBE_NSTAGES; i++)
        stage_step_budget_exceeded_test_set_ewma_us(i, 3000);
    ssbe_ticks(c, 4);
    struct ssbe_view v = ssbe_snap();
    SSBE_AND(ok, v.ok);
    for (int i = 0; ok && i < SSBE_NSTAGES; i++)
        ok = v.base[i] == 0;
    ssbe_ticks(c, 1);
    v = ssbe_snap();
    SSBE_AND(ok, v.ok);
    for (int i = 0; ok && i < SSBE_NSTAGES; i++)
        ok = v.base[i] == 3000;
    return ok;
}

static bool ssbe_registration_posture(void)
{
    ssbe_reset();
    struct condition_runtime_snapshot s;
    bool ok = condition_engine_get_registered_snapshot(SSBE_COND, &s);
    SSBE_AND(ok, s.registered && s.severity == COND_WARN);
    SSBE_AND(ok, s.poll_secs == 15 && s.backoff_secs == 60);
    SSBE_AND(ok, s.max_attempts == 1 && s.witness_window_secs == 60);
    SSBE_AND(ok, s.cooldown_secs == 600 && s.cooldown_max_rearms == 0);
    return ok;
}

static int ssbe_check_measured_gaps(struct ssbe_fake_clock *fc, int64_t t0)
{
    int failures = 0;
    struct ssbe_ctx c = { .fc = fc, .now = t0 };
    SSBE_CHECK("warm-up locks on the 5th nonzero tick; budget is 6x, floor 5ms",
               ssbe_warmup_locks_on_fifth_nonzero_tick(&c));
    SSBE_CHECK("worst stage wins, ties keep the first, equal or zero is quiet",
               ssbe_worst_stage_pick(&c));
    SSBE_CHECK("witness resolves on budget<=0 or ewma<=budget only",
               ssbe_witness_boundaries(&c));
    SSBE_CHECK("operator env budgets 9 and 1 beat the learned baseline",
               ssbe_env_budgets_enforced(&c));
    SSBE_CHECK("operator env budget 1 alone is enforced",
               ssbe_env_budget_one_enforced(&c));
    SSBE_CHECK("an active episode keeps warming the other stages",
               ssbe_active_branch_warms_other_stages(&c));
    SSBE_CHECK("test_reset clears state; setters ignore bad indices",
               ssbe_reset_clears_everything(&c));
    SSBE_CHECK("registration posture matches the contract",
               ssbe_registration_posture());
    return failures;
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

    failures += ssbe_check_measured_gaps(&fc, t0 + 5000);

    ssbe_cleanup();

    printf("=== test_stage_step_budget_exceeded complete: %d failure(s) ===\n",
           failures);
    return failures;
}

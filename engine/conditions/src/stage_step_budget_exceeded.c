/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_step_budget_exceeded — see the header for the SYMPTOM/REMEDY/
 * WITNESSED contract. Purely observational: every input here is one of the
 * already-existing lock-free per-stage EWMA accessors
 * (each jobs/<stage>_stage.h's own <stage>_stage_step_us_ewma, wrapping
 * stage_step_us_ewma() in platform/modules/util/src/stage.c, a plain atomic_load — see
 * "Threading" there), so
 * this file never touches progress_store, coins_kv, or any lock the reducer
 * drive holds (LOCK-ORDER LAW). Nothing here can gate or slow the fold. */

#include "conditions/stage_step_budget_exceeded.h"
#include "conditions/condition_registry.h"

#include "framework/condition.h"
#include "jobs/body_fetch_stage.h"
#include "jobs/body_persist_stage.h"
#include "jobs/header_admit_stage.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/script_validate_stage.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/validate_headers_stage.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

#define STAGE_BUDGET_BLOCKER_ID "stage_step_budget_exceeded"
#define STAGE_BUDGET_OWNER      "stage_step_budget"

/* Warm-up rolling baseline (see header doc). WARMUP_TICKS is counted in
 * detect() calls with a nonzero EWMA for that stage, not wall time — a
 * rarely-stepping stage (e.g. tip_finalize under IBD backpressure) still
 * converges, just more slowly. MULTIPLIER=6 catches the "a stage can slow
 * 10x and stay silent" class this condition exists for, with real margin
 * left over for normal EWMA jitter (already alpha=1/16 smoothed).
 * FLOOR_US guards a stage whose baseline itself lands near the timer's
 * 1us floor (stage_record_step_timing floors a measured-0 step to 1us) from
 * getting an unrealistically tight budget that a single scheduling hiccup
 * could cross. */
#define STAGE_BUDGET_WARMUP_TICKS 5
#define STAGE_BUDGET_MULTIPLIER   6
#define STAGE_BUDGET_FLOOR_US     5000 /* 5ms */

typedef int64_t (*stage_ewma_fn)(void);

struct stage_budget_slot {
    const char    *name;       /* matches STAGE_NAME in the owning jobs .c file + dumpstate */
    const char    *env_suffix; /* ZCL_STAGE_BUDGET_US_<env_suffix> */
    stage_ewma_fn  ewma_fn;
    _Atomic int64_t baseline_us;  /* 0 = not yet locked */
    _Atomic int     warmup_ticks; /* consecutive nonzero-EWMA ticks seen */
};

static struct stage_budget_slot g_slots[STAGE_BUDGET_NUM_STAGES] = {
    { "header_admit",     "HEADER_ADMIT",     header_admit_stage_step_us_ewma,     0, 0 },
    { "validate_headers", "VALIDATE_HEADERS", validate_headers_stage_step_us_ewma, 0, 0 },
    { "body_fetch",       "BODY_FETCH",       body_fetch_stage_step_us_ewma,       0, 0 },
    { "body_persist",     "BODY_PERSIST",     body_persist_stage_step_us_ewma,     0, 0 },
    { "script_validate",  "SCRIPT_VALIDATE",  script_validate_stage_step_us_ewma,  0, 0 },
    { "proof_validate",   "PROOF_VALIDATE",   proof_validate_stage_step_us_ewma,   0, 0 },
    { "utxo_apply",       "UTXO_APPLY",       utxo_apply_stage_step_us_ewma,       0, 0 },
    { "tip_finalize",     "TIP_FINALIZE",     tip_finalize_stage_step_us_ewma,     0, 0 },
};

/* Snapshot of the worst-over-budget stage at the rising edge of the episode
 * (single-writer: the condition-engine tick thread — see condition.c). */
static _Atomic int     g_stage_idx_at_detect = -1;
static _Atomic int64_t g_ewma_at_detect;
static _Atomic int64_t g_budget_at_detect;
static _Atomic int64_t g_last_fire_unix;

#ifdef ZCL_TESTING
static _Atomic int     g_test_remedy_calls;
/* -1 = unset (use the real reader/lookup) in every slot — must NOT default
 * to 0 (BSS zero-init), or an override of "0" would silently suppress every
 * real EWMA read before the first *_test_reset() call in this process. */
static _Atomic int64_t g_test_ewma_override[STAGE_BUDGET_NUM_STAGES] = {
    -1, -1, -1, -1, -1, -1, -1, -1 };
static _Atomic int64_t g_test_budget_override[STAGE_BUDGET_NUM_STAGES] = {
    -1, -1, -1, -1, -1, -1, -1, -1 };
#endif

static int64_t stage_budget_read_ewma(int idx)
{
#ifdef ZCL_TESTING
    int64_t forced = atomic_load(&g_test_ewma_override[idx]);
    if (forced >= 0)
        return forced;
#endif
    return g_slots[idx].ewma_fn();
}

static int64_t stage_budget_env_override(int idx)
{
    char var[48];
    snprintf(var, sizeof(var), "ZCL_STAGE_BUDGET_US_%s", g_slots[idx].env_suffix);
    const char *v = getenv(var);
    if (!v || !v[0])
        return -1; // raw-return-ok:sentinel-no-env-override, not an error
    char *end = NULL;
    long long n = strtoll(v, &end, 10);
    if (!end || *end != '\0' || n <= 0)
        return -1; // raw-return-ok:sentinel-malformed-env-falls-back, not an error
    return (int64_t)n;
}

static int64_t stage_budget_from_baseline(int64_t baseline_us)
{
    if (baseline_us <= 0)
        return -1; // raw-return-ok:sentinel-still-warming-up, not an error
    int64_t budget = baseline_us * STAGE_BUDGET_MULTIPLIER;
    if (budget < STAGE_BUDGET_FLOOR_US)
        budget = STAGE_BUDGET_FLOOR_US;
    return budget;
}

/* Pure read: the current effective budget for stage `idx`, WITHOUT mutating
 * warm-up state. Safe from any thread/any call frequency (witness(), detail(),
 * a native dump-state query) — only detect() below is allowed to advance the
 * warm-up counters, so how often an operator reads state never perturbs
 * learning. -1 = not yet enforceable (still warming up, no env override). */
static int64_t stage_budget_peek(int idx)
{
#ifdef ZCL_TESTING
    int64_t forced = atomic_load(&g_test_budget_override[idx]);
    if (forced >= 0)
        return forced;
#endif
    int64_t env = stage_budget_env_override(idx);
    if (env > 0)
        return env;
    return stage_budget_from_baseline(atomic_load(&g_slots[idx].baseline_us));
}

/* Advancing variant: the ONLY function allowed to progress the per-stage
 * warm-up counter / lock the baseline. Called once per stage per detect()
 * tick (single-writer: the condition-engine tick thread). */
static int64_t stage_budget_effective_advance(int idx, int64_t ewma_now_us)
{
#ifdef ZCL_TESTING
    int64_t forced = atomic_load(&g_test_budget_override[idx]);
    if (forced >= 0)
        return forced;
#endif
    int64_t env = stage_budget_env_override(idx);
    if (env > 0)
        return env;

    struct stage_budget_slot *slot = &g_slots[idx];
    int64_t baseline = atomic_load(&slot->baseline_us);
    if (baseline == 0 && ewma_now_us > 0) {
        int seen = atomic_fetch_add(&slot->warmup_ticks, 1) + 1;
        if (seen >= STAGE_BUDGET_WARMUP_TICKS) {
            atomic_store(&slot->baseline_us, ewma_now_us);
            baseline = ewma_now_us;
        }
    }
    return stage_budget_from_baseline(baseline);
}

static struct condition c_stage_step_budget_exceeded;

static bool detect_stage_step_budget_exceeded(void)
{
    bool active = atomic_load(&c_stage_step_budget_exceeded.state.currently_active);

    if (active) {
        /* Doctrine (framework/condition.c condition_tick_one): detect() gates
         * episode START, never CONTINUATION — the frozen stage stays put;
         * witness() is the sole clear-edge. Still advance every OTHER
         * stage's warm-up so the roster keeps converging while one stage is
         * breaching, and report the frozen stage's live state honestly. */
        for (int i = 0; i < STAGE_BUDGET_NUM_STAGES; i++) {
            if (i == atomic_load(&g_stage_idx_at_detect))
                continue;
            (void)stage_budget_effective_advance(i, stage_budget_read_ewma(i));
        }
        int idx = atomic_load(&g_stage_idx_at_detect);
        if (idx < 0)
            return false;
        int64_t ewma = stage_budget_read_ewma(idx);
        int64_t budget = stage_budget_effective_advance(idx, ewma);
        return budget > 0 && ewma > budget;
    }

    int worst = -1;
    int64_t worst_over = 0, worst_ewma = 0, worst_budget = 0;
    for (int i = 0; i < STAGE_BUDGET_NUM_STAGES; i++) {
        int64_t ewma = stage_budget_read_ewma(i);
        int64_t budget = stage_budget_effective_advance(i, ewma);
        if (ewma <= 0 || budget <= 0)
            continue; /* never stepped, or still warming up — no enforcement */
        if (ewma > budget) {
            int64_t over = ewma - budget;
            if (worst < 0 || over > worst_over) {
                worst = i;
                worst_over = over;
                worst_ewma = ewma;
                worst_budget = budget;
            }
        }
    }
    if (worst < 0)
        return false;

    atomic_store(&g_stage_idx_at_detect, worst);
    atomic_store(&g_ewma_at_detect, worst_ewma);
    atomic_store(&g_budget_at_detect, worst_budget);
    return true;
}

static enum condition_remedy_result remedy_stage_step_budget_exceeded(void)
{
    int idx = atomic_load(&g_stage_idx_at_detect);
    const char *name = (idx >= 0 && idx < STAGE_BUDGET_NUM_STAGES)
                           ? g_slots[idx].name : "(unknown)";
    int64_t ewma = atomic_load(&g_ewma_at_detect);
    int64_t budget = atomic_load(&g_budget_at_detect);

    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "stage '%s' step_us_ewma=%lld exceeds budget_us=%lld "
             "(observational only — never gates or slows the fold; clears "
             "the instant this stage's EWMA falls back under budget)",
             name, (long long)ewma, (long long)budget);

    struct blocker_record r;
    if (blocker_init(&r, STAGE_BUDGET_BLOCKER_ID, STAGE_BUDGET_OWNER,
                     BLOCKER_TRANSIENT, reason)) {
        (void)blocker_set(&r);
        atomic_store(&g_last_fire_unix, platform_time_wall_unix());
    }

    LOG_WARN("condition",
             "[condition:stage_step_budget_exceeded] stage=%s "
             "observed_ewma_us=%lld budget_us=%lld action=name_blocker",
             name, (long long)ewma, (long long)budget);

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    /* Honest "cannot/will-not self-heal": this condition exists ONLY to name
     * a slowdown, never to act on the fold. COND_REMEDY_FAILED pages the
     * operator on the normal ladder; the cooldown re-arm keeps re-notifying
     * without ever latching a persistent-but-not-broken slow patch forever. */
    return COND_REMEDY_FAILED;
}

static bool witness_stage_step_budget_exceeded(int64_t target_at_detect)
{
    (void)target_at_detect;
    int idx = atomic_load(&g_stage_idx_at_detect);
    if (idx < 0)
        return true; // honest-witness-ok: nothing frozen, defensively resolved
    // honest-witness-ok: re-reads the SAME stage's live EWMA and effective
    // budget fresh (peek — no warm-up side effect) rather than trusting the
    // detect-time snapshot; true only once that stage's real cost has
    // actually fallen back into budget.
    int64_t ewma = stage_budget_read_ewma(idx);
    int64_t budget = stage_budget_peek(idx);
    bool resolved = budget <= 0 || ewma <= budget;
    if (resolved)
        blocker_clear(STAGE_BUDGET_BLOCKER_ID);
    return resolved;
}

static bool detail_stage_step_budget_exceeded(struct json_value *out)
{
    if (!out)
        return false;
    int idx = atomic_load(&g_stage_idx_at_detect);
    bool ok = true;
    ok = ok && json_push_kv_str(out, "stage",
                                idx >= 0 ? g_slots[idx].name : "");
    ok = ok && json_push_kv_int(out, "observed_ewma_us",
                                atomic_load(&g_ewma_at_detect));
    ok = ok && json_push_kv_int(out, "budget_us",
                                atomic_load(&g_budget_at_detect));
    ok = ok && json_push_kv_int(out, "last_fire_unix",
                                atomic_load(&g_last_fire_unix));

    struct json_value roster;
    json_init(&roster);
    json_set_array(&roster);
    for (int i = 0; i < STAGE_BUDGET_NUM_STAGES; i++) {
        struct json_value one;
        json_init(&one);
        json_set_object(&one);
        json_push_kv_str(&one, "stage", g_slots[i].name);
        json_push_kv_int(&one, "step_us_ewma", stage_budget_read_ewma(i));
        json_push_kv_int(&one, "budget_us", stage_budget_peek(i));
        json_push_kv_int(&one, "baseline_us",
                         atomic_load(&g_slots[i].baseline_us));
        json_push_back(&roster, &one);
        json_free(&one);
    }
    ok = ok && json_push_kv(out, "stages", &roster);
    json_free(&roster);
    return ok;
}

static struct condition c_stage_step_budget_exceeded = {
    .name = "stage_step_budget_exceeded",
    .severity = COND_WARN,
    .poll_secs = 15,
    .backoff_secs = 60,
    .max_attempts = 1,
    .detect = detect_stage_step_budget_exceeded,
    .remedy = remedy_stage_step_budget_exceeded,
    .witness = witness_stage_step_budget_exceeded,
    .detail = detail_stage_step_budget_exceeded,
    .witness_window_secs = 60,
    /* Continue-with-cooldown (sticky-node plan #7): a slow stage is not a
     * deterministic-unrecoverable local fault — it may be legitimate load
     * (heavy proof validation) that eases on its own. Re-arm every 10
     * minutes, unbounded, while it stays over budget; the episode itself
     * clears instantly (via witness) the moment the EWMA recovers. */
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
};

void register_stage_step_budget_exceeded(void)
{
    (void)condition_register(&c_stage_step_budget_exceeded);
}

#ifdef ZCL_TESTING
void stage_step_budget_exceeded_test_reset(void)
{
    atomic_store(&g_stage_idx_at_detect, -1);
    atomic_store(&g_ewma_at_detect, 0);
    atomic_store(&g_budget_at_detect, 0);
    atomic_store(&g_last_fire_unix, 0);
    atomic_store(&g_test_remedy_calls, 0);
    for (int i = 0; i < STAGE_BUDGET_NUM_STAGES; i++) {
        atomic_store(&g_slots[i].baseline_us, 0);
        atomic_store(&g_slots[i].warmup_ticks, 0);
        atomic_store(&g_test_ewma_override[i], -1);
        atomic_store(&g_test_budget_override[i], -1);
    }
    blocker_clear(STAGE_BUDGET_BLOCKER_ID);
    condition_reset_state(&c_stage_step_budget_exceeded);
}

int stage_step_budget_exceeded_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}

void stage_step_budget_exceeded_test_set_ewma_us(int idx, int64_t us)
{
    if (idx < 0 || idx >= STAGE_BUDGET_NUM_STAGES)
        return;
    atomic_store(&g_test_ewma_override[idx], us);
}

void stage_step_budget_exceeded_test_set_budget_us(int idx, int64_t us)
{
    if (idx < 0 || idx >= STAGE_BUDGET_NUM_STAGES)
        return;
    atomic_store(&g_test_budget_override[idx], us);
}
#endif

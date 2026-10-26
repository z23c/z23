/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "conditions/condition_registry.h"
#include "event/event.h"
#include "framework/condition.h"
#include "json/json.h"

#include <stdatomic.h>
#include <string.h>

#define CE_CHECK(name, expr) do { \
    printf("condition_engine: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static _Atomic bool g_detect;
static _Atomic bool g_witness;
static _Atomic bool g_urgent;
static _Atomic int g_detect_calls;
static _Atomic int g_remedy_calls;
static _Atomic int g_detail_calls;
static _Atomic int g_operator_events;

static bool ce_detect(void)
{
    atomic_fetch_add(&g_detect_calls, 1);
    return atomic_load(&g_detect);
}

static enum condition_remedy_result ce_remedy(void)
{
    atomic_fetch_add(&g_remedy_calls, 1);
    return COND_REMEDY_OK;
}

static bool ce_witness(int64_t target_at_detect)
{
    (void)target_at_detect;
    return atomic_load(&g_witness);
}

static bool ce_urgent(void)
{
    return atomic_load(&g_urgent);
}

static bool ce_detail(struct json_value *out)
{
    atomic_fetch_add(&g_detail_calls, 1);
    return out && json_push_kv_int(out, "fixture_detail", 42);
}

static void operator_observer(enum event_type type, uint32_t peer_id,
                              const void *payload, uint32_t payload_len,
                              void *ctx)
{
    (void)type;
    (void)peer_id;
    (void)payload;
    (void)payload_len;
    (void)ctx;
    atomic_fetch_add(&g_operator_events, 1);
}

static void reset_fixture(void)
{
    condition_engine_reset_for_testing();
    event_log_init();
    atomic_store(&g_detect, false);
    atomic_store(&g_witness, false);
    atomic_store(&g_urgent, false);
    atomic_store(&g_detect_calls, 0);
    atomic_store(&g_remedy_calls, 0);
    atomic_store(&g_detail_calls, 0);
    atomic_store(&g_operator_events, 0);
}

static const struct json_value *ce_json_condition(
    const struct json_value *conditions,
    const char *name)
{
    if (!conditions || !name)
        return NULL;
    for (size_t i = 0; i < json_size(conditions); i++) {
        const struct json_value *cond = json_at(conditions, i);
        const struct json_value *n = cond ? json_get(cond, "name") : NULL;
        if (n && strcmp(json_get_str(n), name) == 0)
            return cond;
    }
    return NULL;
}

static bool ce_first_remedy_runs(struct condition *cond)
{
    reset_fixture();
    bool ok = condition_register(cond);
    atomic_store(&g_detect, true);
    condition_engine_tick();
    ok = ok && atomic_load(&g_remedy_calls) == 1;
    ok = ok && condition_engine_get_active_count() == 1;
    struct condition_engine_summary summary;
    condition_engine_get_summary(&summary);
    ok = ok && summary.registered_count == 1;
    ok = ok && summary.active_count == 1;
    ok = ok && summary.unresolved_count == 0;
    ok = ok && summary.unresolved_critical_count == 0;
    return ok;
}

static bool ce_backoff_suppresses_retry(struct condition *cond)
{
    reset_fixture();
    bool ok = condition_register(cond);
    atomic_store(&g_detect, true);
    condition_engine_tick();
    condition_engine_tick();
    ok = ok && atomic_load(&g_remedy_calls) == 1;
    return ok;
}

static bool ce_urgent_bypasses_backoff(struct condition *cond)
{
    reset_fixture();
    bool ok = condition_register(cond);
    atomic_store(&g_detect, true);
    atomic_store(&g_urgent, true);
    condition_engine_tick();
    condition_engine_tick();
    /* Both ticks run the remedy despite the 30s backoff (urgent bypass). */
    ok = ok && atomic_load(&g_remedy_calls) == 2;
    return ok;
}

static bool ce_urgent_false_keeps_backoff(struct condition *cond)
{
    reset_fixture();
    bool ok = condition_register(cond);
    atomic_store(&g_detect, true);
    atomic_store(&g_urgent, false);   /* not urgent → backoff still holds */
    condition_engine_tick();
    condition_engine_tick();
    ok = ok && atomic_load(&g_remedy_calls) == 1;
    return ok;
}

static bool ce_poll_suppresses_recheck(struct condition *cond)
{
    reset_fixture();
    bool ok = condition_register(cond);
    atomic_store(&g_detect, false);
    condition_engine_tick();
    condition_engine_tick();
    ok = ok && atomic_load(&g_detect_calls) == 1;
    ok = ok && atomic_load(&g_remedy_calls) == 0;
    return ok;
}

static bool ce_witness_clears_active(struct condition *cond)
{
    reset_fixture();
    bool ok = condition_register(cond);
    atomic_store(&g_detect, true);
    condition_engine_tick();
    atomic_store(&g_witness, true);
    condition_engine_tick();
    ok = ok && condition_engine_get_active_count() == 0;
    ok = ok && atomic_load(&cond->state.cleared_count) == 1;
    return ok;
}

static bool ce_max_attempts_pages_operator(struct condition *cond)
{
    reset_fixture();
    event_observe(EV_OPERATOR_NEEDED, operator_observer, NULL);
    bool ok = condition_register(cond);
    atomic_store(&g_detect, true);
    condition_engine_tick();
    condition_engine_tick();
    ok = ok && atomic_load(&g_remedy_calls) == 2;
    ok = ok && condition_engine_get_unresolved_count() == 1;
    ok = ok && atomic_load(&cond->state.operator_needed_emitted);
    ok = ok && atomic_load(&cond->state.last_operator_needed_unix) > 0;
    return ok;
}

static bool ce_unresolved_critical_is_scoped(struct condition *cond)
{
    /* An unresolved CRITICAL condition must count toward BOTH the plain
     * and the severity-scoped accessor (sticky_escalator's belt +
     * suspenders auto-arm gates on the scoped one). */
    reset_fixture();
    bool ok = condition_register(cond);
    atomic_store(&g_detect, true);
    condition_engine_tick();
    condition_engine_tick();
    ok = ok && condition_engine_get_unresolved_count() == 1;
    ok = ok && condition_engine_get_unresolved_critical_count() == 1;
    return ok;
}

static bool ce_unresolved_warn_not_critical(struct condition *cond)
{
    /* download_queue_starved (COND_WARN) can sit
     * "unresolved" (operator_needed_emitted latched) for hours on a
     * healthy, tip-synced node. It must count toward the plain unresolved
     * total (unchanged behavior for health_controller / event_agent_summary
     * reporting) but NOT toward the CRITICAL-scoped count sticky_escalator
     * uses to decide whether to auto-arm its chain-recovery ladder. */
    reset_fixture();
    bool ok = condition_register(cond);
    atomic_store(&g_detect, true);
    condition_engine_tick();
    condition_engine_tick();
    ok = ok && atomic_load(&g_remedy_calls) == 2;
    ok = ok && condition_engine_get_unresolved_count() == 1;
    ok = ok && condition_engine_get_unresolved_critical_count() == 0;
    return ok;
}

static bool ce_duplicate_register_rejected(struct condition *cond)
{
    reset_fixture();
    bool ok = condition_register(cond);
    ok = ok && !condition_register(cond);
    return ok;
}

static bool ce_unwitnessed_remedy_escalates(struct condition *cond)
{
    reset_fixture();
    event_observe(EV_OPERATOR_NEEDED, operator_observer, NULL);
    bool ok = condition_register(cond);
    atomic_store(&g_detect, true);
    atomic_store(&g_witness, false); /* symptom NEVER clears */

    /* Run enough ticks to exhaust max_attempts. */
    condition_engine_tick();
    condition_engine_tick();
    condition_engine_tick();
    condition_engine_tick();

    /* Remedy returned OK every time, but because the witness never
     * confirmed the symptom cleared, the reported outcome must be
     * UNWITNESSED — never OK. A frozen tip cannot self-report success. */
    ok = ok && atomic_load(&cond->state.last_outcome) ==
                   COND_REMEDY_UNWITNESSED;
    /* The condition must still be active and never marked cleared. */
    ok = ok && atomic_load(&cond->state.currently_active);
    ok = ok && atomic_load(&cond->state.cleared_count) == 0;
    /* After max_attempts un-witnessed remedies it must escalate. */
    ok = ok && condition_engine_get_unresolved_count() == 1;
    ok = ok &&
         atomic_load(&cond->state.operator_needed_emitted);
    ok = ok &&
         atomic_load(&cond->state.last_operator_needed_unix) > 0;
    return ok;
}

static bool ce_witnessed_clear_after_unwitnessed(struct condition *cond)
{
    /* Counter-case: once the symptom DOES clear, a witnessed remedy clears
     * the condition and never escalates — even after prior failed attempts. */
    reset_fixture();
    event_observe(EV_OPERATOR_NEEDED, operator_observer, NULL);
    bool ok = condition_register(cond);
    atomic_store(&g_detect, true);
    atomic_store(&g_witness, false);
    condition_engine_tick();            /* attempt 1: unwitnessed */
    ok = ok && atomic_load(&cond->state.last_outcome) ==
                   COND_REMEDY_UNWITNESSED;
    atomic_store(&g_witness, true);     /* symptom now resolved */
    condition_engine_tick();            /* early-witness clears it */
    ok = ok && atomic_load(&cond->state.cleared_count) == 1;
    ok = ok && condition_engine_get_active_count() == 0;
    return ok;
}

static bool ce_limbo_keeps_remedy_cadence(struct condition *cond)
{
    reset_fixture();
    bool ok = condition_register(cond);
    atomic_store(&g_detect, true);
    condition_engine_tick();            /* activates, attempt 1 */
    ok = ok && atomic_load(&g_remedy_calls) == 1;
    atomic_store(&g_detect, false);     /* detect flaps false */
    atomic_store(&g_witness, false);    /* symptom NOT cleared */
    condition_engine_tick();            /* must retry, not freeze */
    ok = ok && atomic_load(&g_remedy_calls) == 2;
    ok = ok && atomic_load(&cond->state.attempts) == 2;
    ok = ok && atomic_load(&cond->state.currently_active);
    return ok;
}

static bool ce_limbo_escalates_to_operator(struct condition *cond)
{
    reset_fixture();
    event_observe(EV_OPERATOR_NEEDED, operator_observer, NULL);
    bool ok = condition_register(cond);
    atomic_store(&g_detect, true);
    condition_engine_tick();            /* attempt 1 */
    atomic_store(&g_detect, false);
    condition_engine_tick();            /* attempt 2 */
    condition_engine_tick();            /* attempt 3 = max_attempts */
    ok = ok && atomic_load(&g_remedy_calls) == 3;
    ok = ok && atomic_load(&cond->state.operator_needed_emitted);
    ok = ok && atomic_load(&g_operator_events) >= 1;
    ok = ok && condition_engine_get_unresolved_count() == 1;
    return ok;
}

static bool ce_aged_episode_pages_operator(struct condition *cond)
{
    reset_fixture();
    event_observe(EV_OPERATOR_NEEDED, operator_observer, NULL);
    bool ok = condition_register(cond);
    atomic_store(&g_detect, true);
    condition_engine_tick();            /* activates, attempt 1 */
    ok = ok && atomic_load(&cond->state.attempts) == 1;
    ok = ok && !atomic_load(&cond->state.operator_needed_emitted);
    /* Age the episode past the budget (1 + 1000*5*2 = 10001s): rewind
     * first_detect_unix by 20000s. */
    atomic_store(&cond->state.first_detect_unix,
                 atomic_load(&cond->state.first_detect_unix) - 20000);
    condition_engine_tick();            /* backoff holds attempt 2 */
    ok = ok && atomic_load(&cond->state.attempts) == 1;
    ok = ok && atomic_load(&cond->state.operator_needed_emitted);
    ok = ok && atomic_load(&g_operator_events) >= 1;
    return ok;
}

static bool ce_witness_resets_limbo_episode(struct condition *cond)
{
    /* Witness-clear still ends a limbo episode and resets its state. */
    reset_fixture();
    bool ok = condition_register(cond);
    int cleared_before = atomic_load(&cond->state.cleared_count);
    atomic_store(&g_detect, true);
    condition_engine_tick();            /* attempt 1 */
    atomic_store(&g_detect, false);
    condition_engine_tick();            /* limbo retry, attempt 2 */
    ok = ok && atomic_load(&cond->state.currently_active);
    atomic_store(&g_witness, true);     /* symptom resolved */
    condition_engine_tick();            /* witness-clear */
    ok = ok && !atomic_load(&cond->state.currently_active);
    ok = ok && atomic_load(&cond->state.cleared_count) ==
                   cleared_before + 1;
    ok = ok && atomic_load(&cond->state.attempts) == 0;
    ok = ok && condition_engine_get_active_count() == 0;
    return ok;
}

static bool ce_snapshot_exposes_guardable_state(struct condition *cond)
{
    reset_fixture();
    bool ok = condition_register(cond);
    struct condition_runtime_snapshot snap;
    memset(&snap, 0, sizeof(snap));
    ok = ok &&
         condition_engine_get_registered_snapshot("ce_basic", &snap);
    ok = ok && snap.registered;
    ok = ok && snap.severity == COND_CRITICAL;
    ok = ok && snap.poll_secs == 1;
    ok = ok && snap.backoff_secs == 30;
    ok = ok && snap.max_attempts == 3;
    ok = ok && snap.witness_window_secs == 60;
    ok = ok && !snap.currently_active;
    ok = ok && snap.attempts == 0;
    ok = ok &&
         !condition_engine_get_registered_snapshot("not_a_condition",
                                                   &snap);
    return ok;
}

static bool ce_dump_json_includes_details(struct condition *cond)
{
    reset_fixture();
    bool ok = condition_register(cond);
    struct json_value out;
    json_init(&out);
    json_set_object(&out);
    ok = ok && condition_engine_dump_state_json(&out, NULL);
    ok = ok && json_get(&out, "registered_count") != NULL;
    ok = ok && json_get(&out, "conditions") != NULL;
    const struct json_value *conditions = json_get(&out, "conditions");
    const struct json_value *basic =
        ce_json_condition(conditions, "ce_basic");
    ok = ok && basic != NULL;
    ok = ok && json_get(basic, "last_remedy_unix") != NULL;
    ok = ok && json_get(basic, "last_operator_needed_unix") != NULL;
    ok = ok && json_get(basic, "target_at_detect") != NULL;
    ok = ok && json_get(basic, "operator_needed_emitted") != NULL;
    const struct json_value *detail = json_get(basic, "detail");
    ok = ok && detail != NULL;
    ok = ok && json_get_int(json_get(detail, "fixture_detail")) == 42;
    ok = ok && atomic_load(&g_detail_calls) == 1;
    json_free(&out);
    return ok;
}

static bool ce_registry_expected_names_match(
    const struct json_value *conditions,
    const char *const *expected,
    int expected_count,
    bool ok)
{
    for (size_t i = 0; i < (size_t)expected_count; i++) {
        const struct json_value *condition = json_at(conditions, i);
        const struct json_value *name = condition
                                            ? json_get(condition, "name")
                                            : NULL;
        ok = ok && name && strcmp(json_get_str(name), expected[i]) == 0;
        for (size_t j = i + 1; j < (size_t)expected_count; j++)
            ok = ok && strcmp(expected[i], expected[j]) != 0;
    }
    return ok;
}

static bool ce_registry_has_self_heal_names(bool ok)
{
    ok = ok &&
         condition_engine_has_registered("body_fetch_missing_have_data");
    ok = ok &&
         condition_engine_has_registered("have_data_unreadable");
    ok = ok &&
         condition_engine_has_registered("stale_validate_headers_repair");
    ok = ok &&
         condition_engine_has_registered(
             "reducer_frontier_reconcile_light");
    ok = ok && !condition_engine_has_registered("not_a_condition");
    return ok;
}

static bool ce_cooldown_rearms_past_max_attempts(struct condition *cond)
{
    reset_fixture();
    event_observe(EV_OPERATOR_NEEDED, operator_observer, NULL);
    bool ok = condition_register(cond);
    atomic_store(&g_detect, true);
    atomic_store(&g_witness, false);   /* symptom never clears */

    /* Tick 1: breach detected, remedy attempt 1/1 exhausts max_attempts
     * immediately (unwitnessed) -> operator paged, but NOT latched. */
    condition_engine_tick();
    ok = ok && atomic_load(&g_remedy_calls) == 1;
    ok = ok && atomic_load(&cond->state.operator_needed_emitted);
    ok = ok && atomic_load(&cond->state.currently_active);

    /* Tick 2: attempts(1) >= max_attempts(1) so condition_due_for_remedy
     * consults cooldown_rearm(); last_cooldown_unix is still 0 (never
     * armed before), so the FIRST re-arm is immediate — proving the
     * engine tries again in the very next tick rather than requiring a
     * human. A legacy (cooldown_secs==0) condition would stay at
     * g_remedy_calls==1 forever from here on (condition_cooldown_rearm
     * returns false unconditionally when cooldown_secs<=0). */
    condition_engine_tick();
    ok = ok && atomic_load(&g_remedy_calls) == 2;
    ok = ok && atomic_load(&cond->state.cooldown_rearms) == 1;

    /* Tick 3: right after a re-arm the cooldown gap has not elapsed
     * (last_cooldown_unix == now), so the engine rate-limits and the count
     * holds; the next step distinguishes this from latched-forever. */
    condition_engine_tick();
    ok = ok && atomic_load(&g_remedy_calls) == 2;

    /* Simulate the cooldown window elapsing (mirrors the existing
     * first_detect_unix-rewind aging trick used by c_aged above) and
     * tick again: a SECOND re-arm must fire, proving the engine keeps
     * retrying indefinitely rather than latching after one re-arm. */
    atomic_store(&cond->state.last_cooldown_unix,
                 atomic_load(&cond->state.last_cooldown_unix) - 10);
    condition_engine_tick();
    ok = ok && atomic_load(&g_remedy_calls) == 3;
    ok = ok && atomic_load(&cond->state.cooldown_rearms) == 2;
    ok = ok && atomic_load(&cond->state.currently_active);
    ok = ok && atomic_load(&cond->state.cleared_count) == 0;
    return ok;
}

static bool ce_cooldown_witness_clear_resets(struct condition *cond, bool ok)
{
    /* Finally the symptom clears: witness-clear must still end the
     * episode and fully reset the cooldown bookkeeping, ready for a
     * fresh episode with a clean budget next time. */
    atomic_store(&g_witness, true);
    condition_engine_tick();
    ok = ok && atomic_load(&cond->state.cleared_count) == 1;
    ok = ok && !atomic_load(&cond->state.currently_active);
    ok = ok && atomic_load(&cond->state.cooldown_rearms) == 0;
    ok = ok && atomic_load(&cond->state.last_cooldown_unix) == 0;
    ok = ok && condition_engine_get_active_count() == 0;
    return ok;
}

static bool ce_cooldown_rearms_then_resets(struct condition *cond)
{
    bool ok = ce_cooldown_rearms_past_max_attempts(cond);
    return ce_cooldown_witness_clear_resets(cond, ok);
}

int test_condition_engine(void)
{
    printf("\n=== condition engine tests ===\n");
    int failures = 0;
    bool ok = false;

    static struct condition c_basic = {
        .name = "ce_basic",
        .severity = COND_CRITICAL,
        .poll_secs = 1,
        .backoff_secs = 30,
        .max_attempts = 3,
        .detect = ce_detect,
        .remedy = ce_remedy,
        .witness = ce_witness,
        .detail = ce_detail,
        .witness_window_secs = 60,
    };

    ok = ce_first_remedy_runs(&c_basic);
    CE_CHECK("register + first remedy", ok);

    ok = ce_backoff_suppresses_retry(&c_basic);
    CE_CHECK("backoff suppresses immediate retry", ok);

    /* An urgent() hook returning true makes the remedy immediately due,
     * bypassing the 30s backoff — the second tick runs the remedy even though
     * backoff_secs has not elapsed. With urgent() false it stays suppressed
     * (the case above). This is the checkpoint-header-capture fast path. */
    static struct condition c_urgent = {
        .name = "ce_urgent",
        .severity = COND_CRITICAL,
        .poll_secs = 1,
        .backoff_secs = 30,
        .max_attempts = 5,
        .detect = ce_detect,
        .remedy = ce_remedy,
        .witness = ce_witness,
        .urgent = ce_urgent,
        .witness_window_secs = 60,
    };

    ok = ce_urgent_bypasses_backoff(&c_urgent);
    CE_CHECK("urgent hook bypasses backoff (remedy runs immediately)", ok);

    ok = ce_urgent_false_keeps_backoff(&c_urgent);
    CE_CHECK("urgent hook false leaves backoff intact", ok);

    static struct condition c_slow_poll = {
        .name = "ce_slow_poll",
        .severity = COND_WARN,
        .poll_secs = 60,
        .backoff_secs = 0,
        .max_attempts = 1,
        .detect = ce_detect,
        .remedy = ce_remedy,
        .witness = ce_witness,
        .witness_window_secs = 60,
    };

    ok = ce_poll_suppresses_recheck(&c_slow_poll);
    CE_CHECK("poll interval suppresses immediate recheck", ok);

    ok = ce_witness_clears_active(&c_basic);
    CE_CHECK("witness clears active state", ok);

    static struct condition c_max = {
        .name = "ce_max",
        .severity = COND_CRITICAL,
        .poll_secs = 1,
        .backoff_secs = 0,
        .max_attempts = 2,
        .detect = ce_detect,
        .remedy = ce_remedy,
        .witness = ce_witness,
        .witness_window_secs = 60,
    };

    ok = ce_max_attempts_pages_operator(&c_max);
    CE_CHECK("max attempts emits operator event", ok);

    ok = ce_unresolved_critical_is_scoped(&c_max);
    CE_CHECK("unresolved CRITICAL condition counts in the scoped total",
             ok);

    static struct condition c_max_warn = {
        .name = "ce_max_warn",
        .severity = COND_WARN,
        .poll_secs = 1,
        .backoff_secs = 0,
        .max_attempts = 2,
        .detect = ce_detect,
        .remedy = ce_remedy,
        .witness = ce_witness,
        .witness_window_secs = 60,
    };

    ok = ce_unresolved_warn_not_critical(&c_max_warn);
    CE_CHECK("unresolved WARN condition excluded from the CRITICAL-scoped "
             "count", ok);

    ok = ce_duplicate_register_rejected(&c_basic);
    CE_CHECK("duplicate registration rejected", ok);

    /* P0 RESILIENCE REGRESSION: a remedy that returns COND_REMEDY_OK but whose
     * symptom never clears (witness stays false) must NOT be reported as `ok`,
     * must accrue attempts, and must escalate to operator_needed after
     * max_attempts. This is the "self-heal LIES" wedge: peer_floor_violated
     * fired 46x result=ok while the tip stayed frozen. */
    static struct condition c_unwitnessed = {
        .name = "ce_unwitnessed",
        .severity = COND_CRITICAL,
        .poll_secs = 1,
        .backoff_secs = 0,
        .max_attempts = 3,
        .detect = ce_detect,
        .remedy = ce_remedy,       /* always returns COND_REMEDY_OK */
        .witness = ce_witness,     /* stays false → symptom never clears */
        .witness_window_secs = 60,
    };

    ok = ce_unwitnessed_remedy_escalates(&c_unwitnessed);
    CE_CHECK("unwitnessed remedy is not ok and escalates", ok);

    ok = ce_witnessed_clear_after_unwitnessed(&c_unwitnessed);
    CE_CHECK("witnessed clear after unwitnessed attempt resolves", ok);

    /* P0 LIMBO REGRESSION: an ACTIVE episode
     * whose detect() flaps false while witness() stays false must not freeze
     * with no remedy retry, no attempts accrual, no operator page
     * (e.g. reducer_frontier_reconcile_light attempts stuck 1/5 while a
     * script_validate_log hole persists). detect() gates episode
     * START only; while active the remedy cadence must continue and the
     * episode may end ONLY via witness-clear. */
    static struct condition c_limbo = {
        .name = "ce_limbo",
        .severity = COND_CRITICAL,
        .poll_secs = 1,
        .backoff_secs = 0,
        .max_attempts = 3,
        .detect = ce_detect,
        .remedy = ce_remedy,
        .witness = ce_witness,
        .witness_window_secs = 60,
    };

    ok = ce_limbo_keeps_remedy_cadence(&c_limbo);
    CE_CHECK("active undetected unwitnessed episode keeps remedy cadence",
             ok);

    ok = ce_limbo_escalates_to_operator(&c_limbo);
    CE_CHECK("undetected active episode still escalates to operator", ok);

    /* Age-based page: an episode older than its schedule budget
     * (max(600, poll + backoff*max_attempts*2)) pages even at attempts=1. */
    static struct condition c_aged = {
        .name = "ce_aged",
        .severity = COND_CRITICAL,
        .poll_secs = 1,
        .backoff_secs = 1000,   /* second attempt never due in this test */
        .max_attempts = 5,
        .detect = ce_detect,
        .remedy = ce_remedy,
        .witness = ce_witness,
        .witness_window_secs = 60,
    };

    ok = ce_aged_episode_pages_operator(&c_aged);
    CE_CHECK("age budget pages operator at attempts below max", ok);

    ok = ce_witness_resets_limbo_episode(&c_limbo);
    CE_CHECK("witness clear resets active undetected episode", ok);

    ok = ce_snapshot_exposes_guardable_state(&c_basic);
    CE_CHECK("registered snapshot exposes guardable state", ok);

    ok = ce_dump_json_includes_details(&c_basic);
    CE_CHECK("dump json includes registry, liveness, and details", ok);

    {
        reset_fixture();
        condition_registry_register_all();
        struct json_value out;
        json_init(&out);
        json_set_object(&out);
        bool ok = condition_engine_dump_state_json(&out, NULL);
        const struct json_value *conditions = json_get(&out, "conditions");
        const struct json_value *registered = json_get(&out,
                                                       "registered_count");
        static const char *const expected[] = {
#define ZCL_CONDITION(name) #name,
#include "conditions/condition_registry.def"
#undef ZCL_CONDITION
        };
        _Static_assert(CONDITION_REGISTRY_COUNT == 56,
                       "condition registry must contain exactly 56 entries");
        _Static_assert(sizeof(expected) / sizeof(expected[0]) ==
                           CONDITION_REGISTRY_COUNT,
                       "condition registry name/count drift");
        const int expected_count = CONDITION_REGISTRY_COUNT;
        ok = ok && registered && json_get_int(registered) == expected_count;
        ok = ok && conditions && json_size(conditions) == (size_t)expected_count;
        ok = ce_registry_expected_names_match(conditions, expected,
                                              expected_count, ok);
        ok = ce_registry_has_self_heal_names(ok);
        json_free(&out);
        CE_CHECK("register_all exposes current self-heal set", ok);
    }

    /* A COND_CRITICAL condition with cooldown_secs > 0 re-arms the remedy
     * after max_attempts instead of latching (as sync_violation_lag and
     * tip_wedged_resnapshot use). With max_attempts=1 a single unwitnessed
     * remedy pages immediately, then cooldown_secs keeps retrying until the
     * symptom clears. */
    static struct condition c_cooldown = {
        .name = "ce_cooldown",
        .severity = COND_CRITICAL,
        .poll_secs = 1,
        .backoff_secs = 0,
        .max_attempts = 1,
        .cooldown_secs = 5,
        .cooldown_max_rearms = 0,
        .detect = ce_detect,
        .remedy = ce_remedy,
        .witness = ce_witness,
        .witness_window_secs = 60,
    };

    ok = ce_cooldown_rearms_then_resets(&c_cooldown);
    CE_CHECK("cooldown-bearing CRITICAL re-arms past max_attempts "
             "instead of latching, then witness-clear resets it", ok);

    reset_fixture();
    return failures;
}

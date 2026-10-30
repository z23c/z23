/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * recovery_coordinator — implementation. See services/recovery_coordinator.h.
 *
 * // one-result-type-ok:recovery-coordinator-orchestrator
 * //
 * // This is a supervisor-child ORCHESTRATOR, not a fallible executor of its
 * // own. Its public surfaces are the void register/setter and a single
 * // dump_state_json out-struct. Its one job is the naming fallback: on an
 * // unresolved CRITICAL that no cheap self-healing condition owns, name a
 * // typed, escalatable blocker so a silent halt is unrepresentable.
 *
 * The cheap rungs (cursor warm-restart, bounded range re-derive, segment
 * refetch-by-hash) are NOT dispatched here — the reducer_frontier_reconcile_
 * light and segment_corruption conditions own them at equal/higher cadence.
 * When either is the active healer the coordinator stays quiet; that is the
 * "an applicable cheap rung is already firing" case. */

#include "services/recovery_coordinator.h"

#include "platform/time_compat.h"
#include "framework/condition.h"
#include "services/sync_monitor.h"
#include "supervisors/domains.h"
#include "support/log_throttle.h"
#include "validation/main_state.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "event/event.h"
#include "json/json.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Module state ──────────────────────────────────────────────────── */

static struct main_state       *g_ms      = NULL;
static const char              *g_datadir = NULL;
static struct liveness_contract g_contract;
static _Atomic supervisor_child_id g_id = SUPERVISOR_INVALID_ID;

/* Lifetime counters (atomic: dumped off-thread while the supervisor tick
 * drives). */
static _Atomic int64_t  g_last_run_unix = 0;
static _Atomic uint64_t g_runs          = 0;
static _Atomic uint64_t g_blocker_fires = 0;

/* The unresolved-critical set is logged when it changes, and once per
 * RC_KEEPALIVE_SECS while it persists. Naming happens on every pass. */
#define RC_NAMED_MAX      8
#define RC_KEEPALIVE_SECS 600

struct rc_names {
    const char *name[CONDITION_MAX_REGISTRY];
    size_t n;
};

/* Invariant: g_logged_set, g_set_log and g_clock are written only by the
 * thread running recovery_coordinator_drive(), and by the test hooks only
 * while it is not running. */
static struct rc_names     g_logged_set; /* last logged set, sorted */
static struct log_throttle g_set_log = LOG_THROTTLE_INIT;
static _Atomic uint64_t    g_log_emits = 0;
/* Keepalive cadence reads the monotonic clock, so a wall-clock step can neither
 * suppress nor storm the keepalive. Seconds are enough for a 600 s cadence. The
 * monotonic clock stops while a phone is suspended, so the keepalive counts
 * awake time. */
static int64_t rc_mono_secs(void)
{
    return platform_time_monotonic_ms() / 1000;
}
static int64_t (*g_clock)(void) = rc_mono_secs;

/* The conditions that own the cheap recovery rungs. When either is the active
 * healer the coordinator's naming fallback stays quiet — the applicable rung
 * is already firing on that condition's own tick (5s / 30s). Kept as a small
 * table so the coverage relationship is explicit and testable. */
static const char *const g_owning_conditions[] = {
    "reducer_frontier_reconcile_light", /* rungs 1-2: cursor clamp + re-derive */
    "segment_corruption",               /* rung 3: segment refetch-by-hash     */
};

static bool owning_condition_active(void)
{
    for (size_t i = 0; i < sizeof(g_owning_conditions) /
                           sizeof(g_owning_conditions[0]); i++) {
        struct condition_runtime_snapshot snap;
        if (condition_engine_get_registered_snapshot(g_owning_conditions[i],
                                                      &snap) &&
            snap.currently_active)
            return true;
    }
    return false;
}

static int rc_name_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static void rc_collect(const char *name, void *ctx)
{
    struct rc_names *set = ctx;
    set->name[set->n++] = name;
}

static bool rc_same_set(const struct rc_names *a, const struct rc_names *b)
{
    if (a->n != b->n)
        return false;
    for (size_t i = 0; i < a->n; i++) {
        if (strcmp(a->name[i], b->name[i]) != 0)
            return false;
    }
    return true;
}

/* Writes the first RC_NAMED_MAX names, comma-separated, then "+N more". When
 * the text would not fit cap, the output ends in "..." within cap; the marker
 * may overwrite up to three trailing characters of the last name that fit. */
static void rc_mark_truncated(char *out, size_t cap, size_t off)
{
    size_t at = off < cap - 4 ? off : cap - 4;
    memcpy(out + at, "...", 3);
    out[at + 3] = '\0';
}

static void rc_format_names(char *out, size_t cap, const struct rc_names *set)
{
    size_t off = 0;
    size_t shown = set->n < RC_NAMED_MAX ? set->n : RC_NAMED_MAX;
    if (cap < 5) {
        if (cap)
            out[0] = '\0';
        return;
    }
    out[0] = '\0';
    for (size_t i = 0; i < shown; i++) {
        int w = snprintf(out + off, cap - off, "%s%s",
                         i ? ", " : "", set->name[i]);
        if (w < 0 || (size_t)w >= cap - off) {
            rc_mark_truncated(out, cap, off);
            return;
        }
        off += (size_t)w;
    }
    if (set->n > shown) {
        int w = snprintf(out + off, cap - off, ", +%zu more", set->n - shown);
        if (w < 0 || (size_t)w >= cap - off)
            rc_mark_truncated(out, cap, off);
    }
}

static void rc_log_state_clear(void)
{
    g_logged_set.n = 0;
    log_throttle_reset(&g_set_log);
}

static void rc_log_unresolved(void)
{
    struct rc_names now_set = {.n = 0};
    condition_engine_for_each_unresolved_critical(rc_collect, &now_set);
    qsort(now_set.name, now_set.n, sizeof(now_set.name[0]), rc_name_cmp);

    bool changed = !rc_same_set(&now_set, &g_logged_set);
    if (!log_throttle_should_emit_changed(&g_set_log, changed, g_clock(),
                                          RC_KEEPALIVE_SECS, NULL))
        return;
    g_logged_set = now_set;

    char shown[512];
    rc_format_names(shown, sizeof(shown), &now_set);
    LOG_WARN("recovery_coordinator",
             "[recovery_coordinator] no cheap self-heal owns the unresolved "
             "critical(s): %s — named typed blocker "
             "recovery_coordinator.no_applicable_rung", shown);
    atomic_fetch_add(&g_log_emits, 1u);
}

/* Name a typed blocker: a critical inconsistency reached the coordinator with
 * no cheap self-healing condition owning it — make it a named, escalatable
 * dependency rather than a silent cycle. retry_budget = -1 keeps it a
 * retry-forever dependency (never auto-expired), matching the pre-fold rung-4
 * semantics. */
static void name_blocker(void)
{
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "recovery_coordinator: critical inconsistency unresolved but no "
             "cheap self-healing condition owns it (cursor clamp / range "
             "re-derive / segment refetch all covered elsewhere and inactive) "
             "— deeper recovery or operator attention required");
    blocker_name_dependency("recovery_coordinator.no_applicable_rung",
                            "recovery_coordinator", reason);
    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=recovery-no-applicable-rung blocker=named");
    rc_log_unresolved();
    atomic_fetch_add(&g_blocker_fires, 1u);
}

/* ── Self-driven supervised tick ──────────────────────────────────── */

static void recovery_coordinator_drive(void)
{
    /* Only act on a genuinely detected inconsistency: an unresolved CRITICAL
     * condition. A healthy node never names anything here. */
    if (condition_engine_get_unresolved_critical_count() <= 0) {
        rc_log_state_clear();
        return;
    }

    /* A cheap self-healing condition owns rungs 1-3; if either is the active
     * healer, the applicable rung is already firing at its own cadence — stay
     * quiet, exactly as the old inline dispatch short-circuited when rung 1-3
     * was actionable. */
    if (owning_condition_active())
        return;

    name_blocker();
    atomic_store(&g_last_run_unix, platform_time_wall_unix());
    atomic_fetch_add(&g_runs, 1u);
}

static void recovery_coordinator_tick(struct liveness_contract *c)
{
    (void)c;
    recovery_coordinator_drive();
    supervisor_progress(atomic_load(&g_id),
                        (int64_t)atomic_load(&g_runs));
}

void recovery_coordinator_set_datadir(const char *datadir)
{
    g_datadir = datadir; /* process-lifetime string from boot ctx */
}

void recovery_coordinator_register(struct main_state *ms)
{
    if (!ms) return;
    if (atomic_load(&g_id) != SUPERVISOR_INVALID_ID) return; /* idempotent */
    g_ms = ms;
    liveness_contract_init(&g_contract, "chain.recovery_coordinator");
    atomic_store(&g_contract.period_secs, (int64_t)30);
    atomic_store(&g_contract.deadline_secs, (int64_t)0);
    atomic_store(&g_contract.progress_max_quiet_us, (int64_t)0);
    g_contract.on_tick  = recovery_coordinator_tick;
    g_contract.on_stall = NULL;
    supervisor_domains_init();
    atomic_store(&g_id, supervisor_register_in_domain(g_chain_sup, &g_contract));
    if (atomic_load(&g_id) == SUPERVISOR_INVALID_ID)
        LOG_WARN("recovery_coordinator",
                 "[recovery_coordinator] WARN register failed");
}

bool recovery_coordinator_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_push_kv_bool(out, "registered",
                      atomic_load(&g_id) != SUPERVISOR_INVALID_ID);
    json_push_kv_str(out, "role", "no-applicable-rung naming fallback");
    json_push_kv_int(out, "last_run_unix", atomic_load(&g_last_run_unix));
    json_push_kv_int(out, "runs", (int64_t)atomic_load(&g_runs));
    json_push_kv_int(out, "blocker_fires", (int64_t)atomic_load(&g_blocker_fires));

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < sizeof(g_owning_conditions) /
                           sizeof(g_owning_conditions[0]); i++) {
        struct json_value s;
        json_init(&s);
        json_set_str(&s, g_owning_conditions[i]);
        json_push_back(&arr, &s);
        json_free(&s);
    }
    json_push_kv(out, "owning_conditions", &arr);
    json_free(&arr);
    return true;
}

#ifdef ZCL_TESTING
void recovery_coordinator_test_reset(void)
{
    atomic_store(&g_last_run_unix, 0);
    atomic_store(&g_runs, 0u);
    atomic_store(&g_blocker_fires, 0u);
    atomic_store(&g_log_emits, 0u);
    g_clock = rc_mono_secs;
    rc_log_state_clear();
}

void recovery_coordinator_test_set_clock(int64_t (*now)(void))
{
    g_clock = now ? now : rc_mono_secs;
}

long long recovery_coordinator_test_log_emits(void)
{
    return (long long)atomic_load(&g_log_emits);
}

void recovery_coordinator_test_format_logged(char *out, size_t cap)
{
    rc_format_names(out, cap, &g_logged_set);
}

void recovery_coordinator_test_drive(void)
{
    recovery_coordinator_drive();
}

void recovery_coordinator_test_name_blocker(void)
{
    name_blocker();
    atomic_store(&g_last_run_unix, platform_time_wall_unix());
    atomic_fetch_add(&g_runs, 1u);
}

long long recovery_coordinator_test_blocker_fires(void)
{
    return (long long)atomic_load(&g_blocker_fires);
}

long long recovery_coordinator_test_runs(void)
{
    return (long long)atomic_load(&g_runs);
}
#endif

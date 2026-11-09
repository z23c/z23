/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Supervisor introspection — bounded snapshots and diagnostic JSON. */
#include "platform/time_compat.h"
#include "util/supervisor.h"
#include "supervisor_internal.h"
#include "json/json.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* Live count excludes retired slots; the registry count is a high-water mark. */
int supervisor_live_count_locked(void)
{
    int n = 0;
    for (int i = 0; i < g_contract_count; i++)
        if (g_contracts[i] != NULL) n++;
    return n;
}

int supervisor_child_headroom(void)
{
    pthread_mutex_lock(&g_lock);
    int used = supervisor_live_count_locked();
    pthread_mutex_unlock(&g_lock);
    int left = SUPERVISOR_CAP - used;
    return left > 0 ? left : 0;
}

/* ── Introspection ─────────────────────────────────────────────────── */

const char *supervisor_stall_reason_name(enum supervisor_stall_reason r)
{
    switch (r) {
    case SUPERVISOR_STALL_NONE:             return "none";
    case SUPERVISOR_STALL_TIME_DEADLINE:    return "time_deadline";
    case SUPERVISOR_STALL_NO_PROGRESS:      return "no_progress";
    case SUPERVISOR_STALL_CHILD_REPORTED:   return "child_reported";
    case SUPERVISOR_STALL_REPEATED_RESTART: return "repeated_restart";
    }
    return "(invalid)";
}

const char *supervisor_progress_policy_name(enum supervisor_progress_policy p)
{
    switch (p) {
    case SUPERVISOR_PROGRESS_UNDECLARED: return "undeclared";
    case SUPERVISOR_PROGRESS_ARMED:      return "armed";
    case SUPERVISOR_PROGRESS_EXEMPT:     return "exempt";
    }
    return "(invalid)";
}

const char *supervisor_restart_policy_name(enum supervisor_restart_policy p)
{
    switch (p) {
    case SUPERVISOR_RESTART_TEMPORARY: return "temporary";
    case SUPERVISOR_RESTART_TRANSIENT: return "transient";
    case SUPERVISOR_RESTART_PERMANENT: return "permanent";
    }
    return "(invalid)";
}

int supervisor_child_count_total(void)
{
    pthread_mutex_lock(&g_lock);
    int n = supervisor_live_count_locked();
    pthread_mutex_unlock(&g_lock);
    return n;
}

uint64_t supervisor_sweep_heartbeat(void)
{
    return atomic_load(&g_sweep_heartbeat);
}

int64_t supervisor_sweep_last_us(void)
{
    return atomic_load(&g_sweep_last_us);
}

int64_t supervisor_tick_runner_last_hb_age_us(void)
{
    return platform_time_monotonic_us() -
           atomic_load(&g_runner_contract.last_tick_us);
}

uint32_t supervisor_tick_runner_stall_fires(void)
{
    return atomic_load(&g_runner_contract.stall_fires);
}

bool supervisor_tick_runner_running(void)
{
    return atomic_load(&g_runner_running);
}

int supervisor_snapshot_all(struct supervisor_snapshot *out, int max)
{
    if (!out || max <= 0) return 0;
    int64_t now = platform_time_monotonic_us();
    pthread_mutex_lock(&g_lock);
    /* Dense live-only snapshot: retired (NULL) slots are skipped, so a
     * recently restarted subsystem never appears twice and never faults
     * the dereference below. */
    int n = 0;
    for (int i = 0; i < g_contract_count && n < max; i++) {
        const struct liveness_contract *c = g_contracts[i];
        if (!c)
            continue;
        memset(&out[n], 0, sizeof(out[n]));
        memcpy(out[n].name, c->name, sizeof(out[n].name));
        out[n].parent           = c->parent;
        int64_t lt              = atomic_load(&c->last_tick_us);
        out[n].last_tick_age_us = now - lt;
        out[n].progress_marker  = atomic_load(&c->progress_marker);
        out[n].period_secs      = atomic_load(&c->period_secs);
        out[n].period_us        = atomic_load(&c->period_us);
        out[n].deadline_secs    = atomic_load(&c->deadline_secs);
        out[n].completed        = atomic_load(&c->completed);
        out[n].stall_reason     = atomic_load(&c->stall_reason);
        out[n].progress_policy  = (int)effective_progress_policy(c);
        out[n].progress_max_quiet_us =
                                  atomic_load(&c->progress_max_quiet_us);
        memcpy(out[n].progress_exempt_reason, c->progress_exempt_reason,
               sizeof(out[n].progress_exempt_reason));
        out[n].ticks_run        = atomic_load(&c->ticks_run);
        out[n].idle_ticks       = atomic_load(&c->idle_ticks);
        out[n].stall_fires      = atomic_load(&c->stall_fires);
        out[n].stall_delivery_pending =
            supervisor_stall_token_reason(
                atomic_load(&c->stall_delivery_pending)) !=
                    SUPERVISOR_STALL_NONE;
        out[n].stall_delivery_coalesced =
            atomic_load(&c->stall_delivery_coalesced);
        out[n].stall_delivery_discarded =
            atomic_load(&c->stall_delivery_discarded);
        out[n].restart_count    = atomic_load(&c->restart_count);
        out[n].restart_policy   = atomic_load(&c->restart_policy);
        out[n].worker_state     = atomic_load(&c->worker_state);
        out[n].restarts_in_window = atomic_load(&c->restarts_in_window);
        n++;
    }
    pthread_mutex_unlock(&g_lock);
    return n;
}

static bool push_contract_json(struct json_value *arr,
                               const struct liveness_contract *c, int64_t now);

#define SUPERVISOR_STALLED_PAGE_KEY "supervisor.stalled.children.live.discovery.v1:"
#define SUPERVISOR_STALLED_PAGE_SIZE 8
/* Offsets are registry slots, not a stable snapshot; each call is a live view. */
static bool supervisor_stalled_offset(const char *key, unsigned *out)
{
    const char *p = key + strlen(SUPERVISOR_STALLED_PAGE_KEY);
    if (!*p || (p[0] == '0' && p[1])) return false;
    unsigned start = 0;
    for (; *p; p++) {
        if (*p < '0' || *p > '9' || start > SUPERVISOR_CAP) return false;
        start = start * 10u + (unsigned)(*p - '0');
        if (start > SUPERVISOR_CAP) return false;
    }
    *out = start; return true;
}
static bool supervisor_stalled_rows(unsigned start, struct json_value *rows, unsigned *count, int *next)
{
    bool ok = true; unsigned included = 0;
    pthread_mutex_lock(&g_lock);
    for (int i = (int)start; ok && i < g_contract_count; i++) {
        const struct liveness_contract *c = g_contracts[i];
        if (!c) continue;
        enum supervisor_stall_reason reason = atomic_load(&c->stall_reason);
        if (reason == SUPERVISOR_STALL_NONE) continue;
        if (included == SUPERVISOR_STALLED_PAGE_SIZE) { *next = i; break; }
        struct json_value row; json_init(&row); json_set_object(&row);
        ok = json_push_kv_str(&row, "name", c->name) &&
             json_push_kv_str(&row, "reason", supervisor_stall_reason_name(reason)) && json_push_back(rows, &row);
        json_free(&row); included++;
    }
    pthread_mutex_unlock(&g_lock);
    *count = included; return ok;
}
static bool supervisor_stalled_page(struct json_value *out, const char *key)
{
    unsigned start, included = 0; int next = -1;
    if (!supervisor_stalled_offset(key, &start)) return false;
    struct json_value rows; json_init(&rows); json_set_array(&rows);
    bool ok = supervisor_stalled_rows(start, &rows, &included, &next);
    json_free(out); json_set_object(out);
    ok = ok && json_push_kv_bool(out, "live", true) && json_push_kv_int(out, "returned", included) &&
        json_push_kv(out, "children", &rows);
    if (ok && next >= 0) {
        char cursor[96]; int n = snprintf(cursor, sizeof(cursor), "%s%d", SUPERVISOR_STALLED_PAGE_KEY, next);
        ok = n > 0 && (size_t)n < sizeof(cursor) && json_push_kv_str(out, "next_key", cursor);
    }
    json_free(&rows); return ok;
}

static bool supervisor_dump_key(struct json_value *out, const char *key)
{
    supervisor_domain_t *domain = NULL;
    bool child_found = false, ok = false;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_domain_count; i++)
        if (strcmp(g_domains[i].label, key) == 0) { domain = &g_domains[i]; break; }
    if (!domain) {
        for (int i = 0; i < g_contract_count; i++) {
            const struct liveness_contract *c = g_contracts[i];
            if (!c || strcmp(c->name, key)) continue;
            struct json_value children;
            json_init(&children); json_set_array(&children);
            child_found = true;
            ok = push_contract_json(&children, c, platform_time_monotonic_us()) &&
                 json_size(&children) == 1;
            if (ok) {
                json_free(out);
                ok = json_copy_checked(out, json_at(&children, 0));
            }
            json_free(&children);
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);
    if (domain) return supervisor_domain_dump_state_json(domain, out);
    if (child_found) return ok;
    if (!strncmp(key, SUPERVISOR_STALLED_PAGE_KEY, strlen(SUPERVISOR_STALLED_PAGE_KEY)))
        return supervisor_stalled_page(out, key);
    return strcmp(key, "summary") == 0;
}

static bool supervisor_root_fields(struct json_value *out)
{
    bool ok = true;
    json_set_object(out);
    ok &= json_push_kv_bool(out, "running",      atomic_load(&g_running));
    ok &= json_push_kv_bool(out, "thread_alive", atomic_load(&g_thread_alive));
    ok &= json_push_kv_int (out, "tick_ms",      atomic_load(&g_tick_ms));
    /* Pillar 7: is the root sweep thread itself alive. */
    ok &= json_push_kv_int (out, "sweep_heartbeat",
                      (int64_t)atomic_load(&g_sweep_heartbeat));
    ok &= json_push_kv_int (out, "sweep_last_age_us",
                      platform_time_monotonic_us() - atomic_load(&g_sweep_last_us));
    /* Tick-runner: the thread that actually executes child on_tick callbacks.
     * A last_hb_age_us past the runner deadline means one child's tick is
     * wedged (named via the supervisor.tick_runner_wedged blocker); the sweep
     * above is unaffected, so the node stays alive. */
    ok &= json_push_kv_bool(out, "tick_runner_running",
                      atomic_load(&g_runner_running));
    ok &= json_push_kv_int (out, "tick_runner_last_hb_age_us",
                      supervisor_tick_runner_last_hb_age_us());
    ok &= json_push_kv_int (out, "tick_runner_stall_fires",
                      (int64_t)atomic_load(&g_runner_contract.stall_fires));
    ok &= json_push_kv_bool(out, "stall_delivery_running",
                      atomic_load(&g_stall_runner_running));
    int64_t stall_hb = atomic_load(&g_stall_runner_last_us);
    ok &= json_push_kv_int(out, "stall_delivery_last_hb_age_us",
                     stall_hb > 0
                         ? platform_time_monotonic_us() - stall_hb : 0);
    ok &= json_push_kv_str(out, "stall_delivery_active_callback",
                     supervisor_stall_active_callback_name_internal());
    ok &= json_push_kv_bool(out, "runner_blocker_delivery_pending",
                      atomic_load(&g_runner_blocker_action) !=
                          0);
    ok &= json_push_kv_int(out, "runner_blocker_delivery_coalesced",
                     atomic_load(&g_runner_blocker_coalesced));
    ok &= json_push_kv_int(out, "runner_blocker_delivery_discarded",
                     atomic_load(&g_runner_blocker_discarded));
    ok &= json_push_kv_str(out, "active_callback",
                     supervisor_active_callback_name());
    /* Progress-policy debt, at the root where an operator reads it first:
     * how many supervised children have no answer to "how would anyone know
     * if this stopped achieving anything?". Floored (shrink-only) by
     * tools/lint/lintc/gate_supervisor_progress_declared.c. */
    ok &= json_push_kv_int (out, "progress_undeclared_count",
                      (int64_t)supervisor_progress_undeclared_count());
    /* Registry margin. 0 means the next subsystem to register runs
     * UNSUPERVISED — see SUPERVISOR_CAP in util/supervisor.h. */
    ok &= json_push_kv_int (out, "child_headroom",
                      (int64_t)supervisor_child_headroom());

    return ok;
}

bool supervisor_dump_state_json(struct json_value *out, const char *key)
{
    if (!out || !supervisor_root_fields(out)) return false;
    if (key && key[0]) return supervisor_dump_key(out, key);

    json_push_kv_int(out, "child_count", supervisor_child_count_total());

    struct json_value domains;
    json_init(&domains);
    json_set_array(&domains);

    pthread_mutex_lock(&g_lock);
    supervisor_domain_t *domain_snap[SUPERVISOR_DOMAIN_CAP];
    int dn = g_domain_count;
    for (int i = 0; i < dn; i++) domain_snap[i] = &g_domains[i];
    pthread_mutex_unlock(&g_lock);

    for (int i = 0; i < dn; i++) {
        struct json_value domain_json;
        json_init(&domain_json);
        if (supervisor_domain_dump_state_json(domain_snap[i], &domain_json)) {
            json_push_back(&domains, &domain_json);
        }
        json_free(&domain_json);
    }
    json_push_kv(out, "domains", &domains);
    json_free(&domains);

    struct json_value orphans;
    json_init(&orphans);
    json_set_array(&orphans);
    struct supervisor_domain root_domain;
    memset(&root_domain, 0, sizeof(root_domain));
    if (supervisor_domain_dump_state_json(&root_domain, &orphans)) {
        const struct json_value *kids = json_get(&orphans, "children");
        if (kids) json_push_kv(out, "root_orphans", kids);
    } else {
        json_push_kv(out, "root_orphans", &orphans);
    }
    json_free(&orphans);
    return true;
}

static bool push_contract_json(struct json_value *arr,
                               const struct liveness_contract *c,
                               int64_t now)
{
    struct json_value child;
    bool ok = true;
    json_init(&child);
    json_set_object(&child);
    ok &= json_push_kv_str (&child, "name",   c->name);
    ok &= json_push_kv_int (&child, "parent", c->parent);
    int64_t lt = atomic_load(&c->last_tick_us);
    ok &= json_push_kv_int (&child, "last_tick_age_us", now - lt);
    ok &= json_push_kv_int (&child, "progress_marker",
                      atomic_load(&c->progress_marker));
    ok &= json_push_kv_int (&child, "period_secs",
                      atomic_load(&c->period_secs));
    ok &= json_push_kv_int (&child, "period_us",
                      atomic_load(&c->period_us));
    ok &= json_push_kv_int (&child, "deadline_secs",
                      atomic_load(&c->deadline_secs));
    ok &= json_push_kv_bool(&child, "completed",
                      atomic_load(&c->completed));
    ok &= json_push_kv_str (&child, "stall_reason",
                      supervisor_stall_reason_name(
                          (enum supervisor_stall_reason)
                          atomic_load(&c->stall_reason)));
    ok &= json_push_kv_int (&child, "ticks_run",
                      atomic_load(&c->ticks_run));
    /* Results, not activity. `ticks_run` says it ran; these say whether it
     * achieved anything, was legitimately idle, or is being watched at all.
     * ticks_run - idle_ticks is the count of runs that were supposed to
     * produce something. */
    ok &= json_push_kv_int (&child, "idle_ticks",
                      atomic_load(&c->idle_ticks));
    ok &= json_push_kv_str (&child, "progress_policy",
                      supervisor_progress_policy_name(
                          effective_progress_policy(c)));
    ok &= json_push_kv_int (&child, "progress_max_quiet_us",
                      atomic_load(&c->progress_max_quiet_us));
    ok &= json_push_kv_str (&child, "progress_exempt_reason",
                      c->progress_exempt_reason);
    ok &= json_push_kv_int (&child, "stall_fires",
                      atomic_load(&c->stall_fires));
    ok &= json_push_kv_bool(&child, "stall_delivery_pending",
                      supervisor_stall_token_reason(
                          atomic_load(&c->stall_delivery_pending)) !=
                              SUPERVISOR_STALL_NONE);
    ok &= json_push_kv_int (&child, "stall_delivery_coalesced",
                      atomic_load(&c->stall_delivery_coalesced));
    ok &= json_push_kv_int (&child, "stall_delivery_discarded",
                      atomic_load(&c->stall_delivery_discarded));
    ok &= json_push_kv_int (&child, "restart_count",
                      atomic_load(&c->restart_count));
    ok &= json_push_kv_str (&child, "restart_policy",
                      supervisor_restart_policy_name(
                          (enum supervisor_restart_policy)
                          atomic_load(&c->restart_policy)));
    ok &= json_push_kv_int (&child, "restarts_in_window",
                      atomic_load(&c->restarts_in_window));
    ok &= json_push_back(arr, &child);
    json_free(&child);
    return ok;
}

bool supervisor_domain_dump_state_json(supervisor_domain_t *domain,
                                       struct json_value *out)
{
    if (!domain || !out) return false;
    bool root = (domain->label[0] == '\0');
    json_set_object(out);
    json_push_kv_str(out, "name", root ? "root" : domain->label);

    struct liveness_contract *snap[SUPERVISOR_CAP];
    int n = 0;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_contract_count && n < SUPERVISOR_CAP; i++) {
        if (g_contracts[i] == NULL)
            continue; /* retired slot: never counted, never dumped */
        bool match = root ? (g_contract_domains[i] == NULL)
                          : (g_contract_domains[i] == domain);
        if (match) snap[n++] = g_contracts[i];
    }
    pthread_mutex_unlock(&g_lock);

    json_push_kv_int(out, "child_count", n);
    struct json_value children;
    json_init(&children);
    json_set_array(&children);
    int64_t now = platform_time_monotonic_us();
    for (int i = 0; i < n; i++) {
        if (snap[i]) push_contract_json(&children, snap[i], now);
    }
    json_push_kv(out, "children", &children);
    json_free(&children);
    return true;
}

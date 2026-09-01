/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * See services/service_state_driver.h. Drives the canonical service_state
 * from real sync/condition progress and persists it to progress.kv.
 *
 * Reset/consensus safety: this file NEVER touches the chain, a stage cursor,
 * the public tip, or a consensus gate. It reads existing signals
 * (active_chain_height, connman_max_peer_height, condition snapshots) and
 * writes only two opaque kv rows ("service_state", "service_state_reason")
 * to progress.kv. Every failure is logged and swallowed. */

#include "services/service_state_driver.h"

#include "util/service_state.h"
#include "util/result.h"
#include "util/log_macros.h"
#include "storage/progress_store.h"
#include "framework/condition.h"
#include "services/sync_monitor.h"
#include "net/connman.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* A node is "on tip" when within this many blocks of the best-known peer. */
#define SS_ON_TIP_GAP 1

/* The named repair Conditions whose active remedy puts the node in REPAIRING.
 * Centralized so adding a third is a one-line change. A cleaner long-term
 * design is an `is_repair` flag on struct condition + a framework predicate;
 * that touches engine/modules/framework and is deferred (see the driver design notes). */
static const char *const k_repair_conditions[] = {
    "body_fetch_missing_have_data",
    "stale_validate_headers_repair",
};

/* REPAIRING is transient; remember the operational mode to restore when the
 * repair clears. Seeded to SYNCING — the post-boot default. */
static _Atomic int g_prior_state = SERVICE_STATE_SYNCING;

#ifdef ZCL_TESTING
static _Atomic int  g_ovr_enabled;
static _Atomic int  g_ovr_local_h;
static _Atomic int  g_ovr_peer_max;
static _Atomic int  g_ovr_tip_age;
#endif

static bool repair_condition_active(void)
{
    size_t n = sizeof(k_repair_conditions) / sizeof(k_repair_conditions[0]);
    for (size_t i = 0; i < n; i++) {
        struct condition_runtime_snapshot snap;
        memset(&snap, 0, sizeof(snap));
        if (condition_engine_get_registered_snapshot(k_repair_conditions[i],
                                                      &snap) &&
            snap.registered && snap.currently_active)
            return true;
    }
    return false;
}

struct zcl_result service_state_persist_to_progress_store(void)
{
    sqlite3 *db = progress_store_db();
    if (!db) {
        LOG_WARN("service_state",
                 "[service_state] persist: progress.kv unavailable");
        return ZCL_ERR(-5, "persist: progress.kv unavailable");
    }

    int32_t id = (int32_t)service_state_current();
    char reason[160] = {0};
    service_state_reason_copy(reason, sizeof(reason));

    /* (state, reason) MUST persist atomically: a torn write (state set, reason
     * stale) on the very state machine that drives restart recovery is exactly
     * what blocker review flagged. One BEGIN IMMEDIATE wraps both meta writes
     * (the tx lock is recursive, so progress_meta_set_in_tx nests safely). */
    progress_store_tx_lock();
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("service_state", "[service_state] persist BEGIN failed: %s",
                 err ? err : "(no message)");
        struct zcl_result r =
            ZCL_ERR(-6, "persist BEGIN failed: %s", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        return r;
    }
    bool ok = progress_meta_set_in_tx(db, "service_state", &id, sizeof(id)) &&
              progress_meta_set_in_tx(db, "service_state_reason",
                                      reason, strlen(reason));
    const char *fini = ok ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(db, fini, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("service_state", "[service_state] persist %s failed: %s",
                 fini, err ? err : "(no message)");
        struct zcl_result r =
            ZCL_ERR(-6, "persist %s failed: %s", fini,
                    err ? err : "(no message)");
        if (err) sqlite3_free(err);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        return r;
    }
    progress_store_tx_unlock();

    if (!ok) {
        LOG_WARN("service_state",
                 "[service_state] persist failed (id=%d) — rolled back",
                 (int)id);
        return ZCL_ERR(-6, "persist meta write failed (id=%d) — rolled back",
                       (int)id);
    }
    return ZCL_OK;
}

void service_state_transition_and_persist(enum service_state next,
                                          const char *reason)
{
    /* The atomic pairing: advance the in-RAM mode, then immediately persist it.
     * Collapsing the two hand-paired calls into one means a transition that must
     * survive a restart can never be left un-persisted by a forgotten second
     * call. The persist's own result is intentionally swallowed (already logged
     * inside), matching every prior `(void)`-ignored call site. */
    service_state_advance(next, reason);
    (void)service_state_persist_to_progress_store();
}

struct zcl_result service_state_restore_from_progress_store(void)
{
    sqlite3 *db = progress_store_db();
    if (!db) {
        LOG_WARN("service_state",
                 "[service_state] restore: progress.kv unavailable");
        return ZCL_ERR(-5, "restore: progress.kv unavailable");
    }

    int32_t id = SERVICE_STATE_BOOT;
    size_t n = 0;
    bool found = false;
    progress_store_tx_lock();
    bool got = progress_meta_get(db, "service_state", &id, sizeof(id),
                                 &n, &found);
    progress_store_tx_unlock();
    if (!got || !found || n != sizeof(id)) {
        /* Expected on first boot / fresh datadir — not a hard error, but no
         * record was applied, so this is a non-ok (informational) result. */
        return ZCL_ERR(-7, "restore: no persisted service_state record "
                           "(fresh datadir / first boot)");
    }
    if ((int)id < 0 || (int)id >= SERVICE_STATE__COUNT) {
        LOG_WARN("service_state",
                 "[service_state] restore: invalid state id=%d", (int)id);
        return ZCL_ERR(-5, "restore: invalid persisted state id=%d", (int)id);
    }

    char reason[256] = {0};
    size_t rn = 0;
    bool rfound = false;
    progress_store_tx_lock();
    (void)progress_meta_get(db, "service_state_reason", reason,
                            sizeof(reason) - 1, &rn, &rfound);
    progress_store_tx_unlock();
    if (!rfound || rn == 0)
        snprintf(reason, sizeof(reason), "restored");

    service_state_advance((enum service_state)id, reason);
    if ((enum service_state)id >= SERVICE_STATE_DEGRADED_SERVING &&
        (enum service_state)id != SERVICE_STATE_REPAIRING)
        atomic_store(&g_prior_state, (int)id);
    return ZCL_OK;
}

void service_state_driver_tick(void)
{
    /* The same five-second supervised tick also closes the raw sync FSM's
     * asynchronous-intake edge.  This must run even while the higher-level
     * service_state is still in a pre-serving state. */
    (void)sync_monitor_evaluate_tip_state();

    enum service_state cur = service_state_current();

    /* Step 1 — REPAIRING edge. A named repair Condition that is actively
     * remediating takes precedence over the sync-gap machine. */
    bool repairing_now = repair_condition_active();
    if (repairing_now && cur != SERVICE_STATE_REPAIRING) {
        atomic_store(&g_prior_state, (int)cur);
        service_state_advance(SERVICE_STATE_REPAIRING,
                              "repair condition active");
        /* Deliberately NOT persisted: REPAIRING is transient; the persisted
         * record keeps the underlying operational mode for restart. */
        return;
    }
    if (!repairing_now && cur == SERVICE_STATE_REPAIRING) {
        enum service_state prior =
            (enum service_state)atomic_load(&g_prior_state);
        service_state_transition_and_persist(prior, "repair condition cleared");
        return;
    }
    if (repairing_now)
        return; /* stay in REPAIRING */

    /* Step 2 — sync-gap machine. Boot owns BOOT/RESTORE/RECONCILE; the driver
     * only moves the node once it has reached a serving mode. The enum is
     * ordered, so the ordinal guard is equivalent to {BOOT,RESTORE,RECONCILE}
     * and stays correct if a new pre-serving state is inserted. */
    if (cur < SERVICE_STATE_DEGRADED_SERVING)
        return;

    int local_h, peer_max;
    int64_t age;
#ifdef ZCL_TESTING
    if (atomic_load(&g_ovr_enabled)) {
        local_h  = atomic_load(&g_ovr_local_h);
        peer_max = atomic_load(&g_ovr_peer_max);
        age      = (int64_t)atomic_load(&g_ovr_tip_age);
    } else
#endif
    {
        struct main_state *ms = sync_monitor_main_state();
        if (!ms)
            return;
        local_h = active_chain_height(&ms->chain_active);
        struct connman *cm = sync_monitor_connman();
        peer_max = cm ? connman_max_peer_height(cm) : -1;
        age = sync_monitor_tip_advance_age();
    }

    /* No peers / unknown best tip: cannot conclude HEALTHY — hold. */
    if (peer_max < 0)
        return;

    int gap = peer_max - local_h;
    if (gap < 0)
        gap = 0; /* stale peer starting_height can read below us; treat on-tip */

    int active = condition_engine_get_active_count();

    enum service_state next;
    if (active > 0)
        next = SERVICE_STATE_DEGRADED_SERVING;
    else if (gap <= SS_ON_TIP_GAP)
        next = SERVICE_STATE_HEALTHY;
    else
        next = SERVICE_STATE_SYNCING;

    if (next != cur) {
        char reason[128];
        snprintf(reason, sizeof(reason),
                 "local=%d peer=%d gap=%d active=%d age=%llds",
                 local_h, peer_max, gap, active, (long long)age);
        /* Record the new mode as the prior-state to restore after a REPAIRING
         * detour BEFORE the atomic advance+persist; the stored value is `next`
         * (independent of the transition), so the order is semantically inert
         * but keeps the advance+persist a single atomic call. */
        atomic_store(&g_prior_state, (int)next);
        service_state_transition_and_persist(next, reason);
    }
}

#ifdef ZCL_TESTING
void service_state_driver_test_set_overrides(int local_h, int peer_max,
                                             int tip_age_secs)
{
    atomic_store(&g_ovr_local_h, local_h);
    atomic_store(&g_ovr_peer_max, peer_max);
    atomic_store(&g_ovr_tip_age, tip_age_secs);
    atomic_store(&g_ovr_enabled, 1);
}

void service_state_driver_test_clear_overrides(void)
{
    atomic_store(&g_ovr_enabled, 0);
}
#endif

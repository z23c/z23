/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Supervision tests: the REST
 * /api cache-refresh thread and the block/tx/address lookup-worker thread
 * are registered with the util/supervisor.h liveness tree (op domain) and
 * name a typed blocker when their on_stall fires. Exercises the
 * registration + stall wiring hermetically via ZCL_TESTING seams, without
 * spawning the real detached worker threads (which sleep and drive
 * compute_* against whatever main_state is/isn't set). */

#include "test/test_core.h"

#include "controllers/api_controller.h"
#include "controllers/operator_needed_policy.h"
#include "models/hodl_wave.h"
#include "supervisors/domains.h"
#include "util/blocker.h"
#include "util/supervisor.h"
#include "../../../engine/controllers/src/api_controller_internal.h"

#include <stdio.h>
#include <stdatomic.h>
#include <string.h>

#define ACS_CHECK(name, expr) do { \
    printf("api_controller_supervision: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static bool find_snapshot(const char *name, struct supervisor_snapshot *out)
{
    struct supervisor_snapshot snaps[SUPERVISOR_CAP];
    int n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].name, name) == 0) {
            *out = snaps[i];
            return true;
        }
    }
    return false;
}

static bool cache_stop_interrupts_utxo_scan(void)
{
    /* A cache stop must interrupt a long read without allowing the rows read
     * before SQLITE_INTERRUPT to become a seemingly valid partial snapshot. */
    bool ok = true;
    sqlite3 *db = NULL;
    ok = ok && sqlite3_open(":memory:", &db) == SQLITE_OK;
    ok = ok && sqlite3_exec(db,
        "CREATE TABLE utxos(height INTEGER, value INTEGER);"
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL "
        "SELECT x+1 FROM n WHERE x<5000) "
        "INSERT INTO utxos SELECT x, x FROM n;",
        NULL, NULL, NULL) == SQLITE_OK;

    _Atomic int running = 1;
    ok = ok && api_cache_test_sqlite_progress(&running) == 0;
    atomic_store(&running, 0);
    ok = ok && api_cache_test_sqlite_progress(&running) == 1;
    sqlite3_progress_handler(db, 1000, api_cache_test_sqlite_progress,
                             &running);
    struct hodl_wave_snapshot hodl;
    bool scanned = hodl_wave_scan_current_utxos(db, 5000, &hodl);
    sqlite3_progress_handler(db, 0, NULL, NULL);
    ok = ok && !scanned &&
         strcmp(hodl.status, "UTXO index scan interrupted") == 0;
    if (db)
        sqlite3_close(db);
    return ok;
}

static bool cache_refresh_thread_supervision_ok(void)
{
    /* ── Cache-refresh thread ─────────────────────────────────────── */
    bool ok = true;
    blocker_clear("api_cache_refresh_stalled");

    api_cache_test_register_supervisor();
    ok = ok && api_cache_test_supervisor_id() != SUPERVISOR_INVALID_ID;

    struct supervisor_snapshot snap;
    bool found = find_snapshot("op.api_cache_refresh", &snap);
    ok = ok && found;
    ok = ok && found && snap.deadline_secs == 120;
    ok = ok && found && snap.period_secs == 0;

    ok = ok && !blocker_exists("api_cache_refresh_stalled");
    api_cache_test_force_stall();
    ok = ok && blocker_exists("api_cache_refresh_stalled");
    ok = ok && blocker_class_for("api_cache_refresh_stalled") ==
             BLOCKER_TRANSIENT;

    blocker_clear("api_cache_refresh_stalled");
    return ok;
}

static bool supervisor_children_distinct_ok(void)
{
    /* ── Both children distinct, both in the op domain (dumpstate
     * supervisor visibility). ─────────────── */
    bool ok = true;
    ok = ok && api_cache_test_supervisor_id() !=
             api_lookup_test_supervisor_id();

    struct supervisor_snapshot cache_snap, lookup_snap;
    ok = ok && find_snapshot("op.api_cache_refresh", &cache_snap);
    ok = ok && find_snapshot("op.api_lookup", &lookup_snap);
    return ok;
}

static bool stop_restart_rearms_supervision_ok(void)
{
    /* Stop/restart reuses the registered children. Prove that quiesce's
     * deadline=0 is temporary and each next generation re-arms supervision. */
    bool ok = true;
    api_cache_supervisor_quiesce();
    api_lookup_supervisor_quiesce();
    struct supervisor_snapshot cache_snap, lookup_snap;
    ok = ok && find_snapshot("op.api_cache_refresh", &cache_snap) &&
         cache_snap.deadline_secs == 0;
    ok = ok && find_snapshot("op.api_lookup", &lookup_snap) &&
         lookup_snap.deadline_secs == 0;

    api_cache_test_register_supervisor();
    api_lookup_test_register_supervisor();
    ok = ok && find_snapshot("op.api_cache_refresh", &cache_snap) &&
         cache_snap.deadline_secs == 120;
    ok = ok && find_snapshot("op.api_lookup", &lookup_snap) &&
         lookup_snap.deadline_secs == 60;
    return ok;
}

/* Copy the active blockers named in `ids` out of the process-wide registry, so
 * the checks below see only what they raised. */
static int pick_blockers(const char *const *ids, int n_ids,
                         struct blocker_snapshot *out)
{
    struct blocker_snapshot all[BLOCKER_CAP];
    int n = blocker_snapshot_all(all, BLOCKER_CAP);
    int picked = 0;
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n_ids; j++)
            if (strcmp(all[i].id, ids[j]) == 0)
                out[picked++] = all[i];
    return picked;
}

static void raise_blocker(const char *id, bool capability_only)
{
    struct blocker_record rec;
    if (!blocker_init(&rec, id, "test.status", BLOCKER_PERMANENT, "test"))
        return;
    rec.capability_only = capability_only;
    (void)blocker_set(&rec);
}

/* The public status reason and operator_needed that a healthy, peered node
 * reports while `snaps` are the only active blockers. */
static struct api_node_summary_reason summary_reason_for(
    const struct blocker_snapshot *snaps, int n, bool *operator_needed)
{
    struct node_health_snapshot health = {0};
    struct agent_security_posture posture = {0};
    struct download_stats_snapshot download = {0};
    health.serving = true;
    health.healthy = true;
    health.has_peers = true;
    const struct blocker_snapshot *authority = api_authority_blocker(snaps, n);
    struct api_node_summary_reason sel = api_node_summary_select_reason(
        &health, &posture, authority, false, &download);
    *operator_needed = node_status_reason_operator_needed(sel.reason, 0);
    return sel;
}

/* A lost optional capability stays listed but must not gate public serving. */
static bool capability_blocker_does_not_gate_serving(void)
{
    static const char *const ids[] = { "shielded_spend_unavailable" };
    blocker_clear(ids[0]);
    raise_blocker(ids[0], true);
    struct blocker_snapshot snaps[1];
    int n = pick_blockers(ids, 1, snaps);
    bool needed = true;
    bool ok = n == 1 && snaps[0].capability_only;
    ok = ok && !api_blocker_hard_gates_public_serving(
                    blocker_select_dominant(snaps, n));
    struct api_node_summary_reason sel = summary_reason_for(snaps, n, &needed);
    ok = ok && sel.reason != ZCL_STATUS_REASON_TYPED_BLOCKER && !needed;
    blocker_clear(ids[0]);
    return ok;
}

/* A real PERMANENT integrity blocker still gates, and a capability blocker
 * raised beside it cannot take its place as the dominant one. */
static bool integrity_blocker_still_gates_serving(void)
{
    static const char *const ids[] = { "shielded_spend_unavailable",
                                       "test.integrity_fault" };
    blocker_clear(ids[0]);
    blocker_clear(ids[1]);
    raise_blocker(ids[0], true);
    raise_blocker(ids[1], false);
    struct blocker_snapshot snaps[2];
    int n = pick_blockers(ids, 2, snaps);
    bool needed = false;
    const struct blocker_snapshot *dominant = blocker_select_dominant(snaps, n);
    bool ok = n == 2 && dominant &&
              strcmp(dominant->id, "test.integrity_fault") == 0 &&
              api_blocker_hard_gates_public_serving(dominant);
    struct api_node_summary_reason sel = summary_reason_for(snaps, n, &needed);
    ok = ok && sel.reason == ZCL_STATUS_REASON_TYPED_BLOCKER && needed;
    blocker_clear(ids[0]);
    blocker_clear(ids[1]);
    return ok;
}

int api_controller_supervision_focused_tests(void)
{
    printf("\n=== api_controller supervision-coverage tests (#13) ===\n");
    int failures = 0;

    bool scan_ok = cache_stop_interrupts_utxo_scan();
    ACS_CHECK("cache stop interrupts UTXO scan without partial success",
              scan_ok);

    bool cache_thread_ok = cache_refresh_thread_supervision_ok();
    ACS_CHECK("api cache-refresh thread registered + names blocker on stall",
              cache_thread_ok);

    /* ── Lookup-worker thread ─────────────────────────────────────── */
    {
        bool ok = true;
        blocker_clear("api_lookup_stalled");

        api_lookup_test_register_supervisor();
        ok = ok && api_lookup_test_supervisor_id() != SUPERVISOR_INVALID_ID;

        struct supervisor_snapshot snap;
        bool found = find_snapshot("op.api_lookup", &snap);
        ok = ok && found;
        ok = ok && found && snap.deadline_secs == 60;
        ok = ok && found && snap.period_secs == 0;

        ok = ok && !blocker_exists("api_lookup_stalled");
        api_lookup_test_force_stall();
        ok = ok && blocker_exists("api_lookup_stalled");
        ok = ok && blocker_class_for("api_lookup_stalled") ==
                 BLOCKER_TRANSIENT;

        blocker_clear("api_lookup_stalled");
        ACS_CHECK("api lookup-worker thread registered + names blocker on stall",
                  ok);
    }

    bool children_ok = supervisor_children_distinct_ok();
    ACS_CHECK("cache + lookup are distinct, both-visible supervisor children",
              children_ok);

    ACS_CHECK("a capability-only blocker is listed but does not gate public serving",
              capability_blocker_does_not_gate_serving());
    ACS_CHECK("a PERMANENT integrity blocker still gates public serving",
              integrity_blocker_still_gates_serving());

    bool rearm_ok = stop_restart_rearms_supervision_ok();
    ACS_CHECK("stop/restart re-arms both existing supervisor children", rearm_ok);

    return failures;
}

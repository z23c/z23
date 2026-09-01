/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_agent_posture_trylock — the node.db-connection-level non-blocking
 * guard for agent_security_posture_collect()'s bootstrap read.
 *
 * On a wedged node with a write-retry storm: the brief
 * typed status front door (`z23 status` -> rpc_agent_summary) calls
 * agent_security_posture_collect() -> posture_collect_bootstrap() ->
 * chain_evidence_controller_snapshot(), which issues ~a dozen synchronous
 * reads on the SHARED node.db connection. node_db_long_op_active() only
 * routes around the rarer NAMED long ops (PRAGMA quick_check, the staging-
 * cleanup DELETE) that opt in via db_long_op_start/finish — ordinary write
 * contention (a writer thread retrying SQLITE_BUSY inside one
 * sqlite3_step() call) never names itself, yet it holds SQLite's own
 * per-connection mutex (every public API call on a connection opened with
 * SQLITE_OPEN_FULLMUTEX serializes behind it) for up to the connection's
 * ZCL_NODE_DB_BUSY_TIMEOUT_MS (10s) while it retries. Any other thread
 * calling into that SAME connection — including this collect's reads —
 * then queued behind it for the same duration (measured ~10s via the
 * chain_evidence dumpers before this fix).
 *
 * The fix (agent_security_posture.c): try the connection's own mutex
 * (sqlite3_db_mutex) non-blockingly before the bootstrap read. On a miss,
 * serve the last-known-good snapshot immediately — labeled
 * "posture_unavailable_busy" the first time nothing has ever been cached,
 * upgrading to the last REAL collected snapshot once one exists — instead
 * of queuing. This mirrors progress_store_tx_trylock()'s non-blocking
 * pattern (test_stage_dump_trylock.c) at the node.db-connection level
 * (node.db has no equivalent app-level write-serialization mutex to
 * trylock).
 *
 * This test grabs that SAME primitive (sqlite3_mutex_enter/leave on
 * sqlite3_db_mutex) from a helper thread to deterministically simulate a
 * writer's in-flight sqlite3_step() call — the exact mechanism the fix
 * targets — without depending on a genuinely slow query's timing.
 *
 * Ordering note: agent_security_posture.c's last-known-good cache is a
 * single process-wide static, not scoped to any one struct node_db. This
 * file's single test case is therefore written as ONE ordered scenario
 * (no cache exists yet -> busy shows the labeled partial -> a real collect
 * populates the cache -> a later busy period upgrades to that real
 * snapshot instead) rather than independent cases, so it never depends on
 * — or is broken by — whatever order test_parallel/test_zcl happen to run
 * cases in. */

#include "test/test_core.h"

#include "controllers/agent_security_posture.h"
#include "models/database.h"
#include "platform/time_compat.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define AP_CHECK(name, expr) do {                                 \
    printf("agent_posture_trylock: %s... ", (name));              \
    if (expr) { printf("OK\n"); }                                 \
    else { printf("FAIL\n"); failures++; }                        \
} while (0)

/* ---- lock-holder thread: grabs the connection's own mutex and parks ---- */
struct ap_locker {
    sqlite3 *db;
    _Atomic int locked;   /* set once the mutex is held */
    _Atomic int release;  /* main thread sets this to let the holder go */
};

static void *ap_locker_thread(void *arg)
{
    struct ap_locker *lk = (struct ap_locker *)arg;
    sqlite3_mutex *m = sqlite3_db_mutex(lk->db);
    sqlite3_mutex_enter(m);
    atomic_store(&lk->locked, 1);
    /* Hold until told to release (bounded spin so a stuck test can never
     * wedge the suite forever). */
    for (int i = 0; i < 500000 && !atomic_load(&lk->release); i++) {
        struct timespec ts = { 0, 200000 }; /* 0.2ms */
        nanosleep(&ts, NULL);
    }
    sqlite3_mutex_leave(m);
    return NULL;
}

static bool ap_lock_connection(struct ap_locker *lk, sqlite3 *db,
                               pthread_t *th_out)
{
    lk->db = db;
    atomic_store(&lk->locked, 0);
    atomic_store(&lk->release, 0);
    if (pthread_create(th_out, NULL, ap_locker_thread, lk) != 0)
        return false;
    for (int i = 0; i < 500000 && !atomic_load(&lk->locked); i++) {
        struct timespec ts = { 0, 200000 };
        nanosleep(&ts, NULL);
    }
    return atomic_load(&lk->locked) != 0;
}

static void ap_unlock_connection(struct ap_locker *lk, pthread_t th)
{
    atomic_store(&lk->release, 1);
    pthread_join(th, NULL);
}

static int case_collect_nonblocking_scenario(void)
{
    int failures = 0;
    struct node_db ndb;
    struct ap_locker lk;
    pthread_t th;

    bool opened = node_db_open(&ndb, ":memory:");
    AP_CHECK("node.db (:memory:) opens", opened);
    if (!opened)
        return failures;

    /* 1. Contend BEFORE any collect has ever run — proves the very first
     *    call, with no last-known-good snapshot to fall back on, still
     *    answers promptly with the labeled busy partial rather than
     *    blocking. A blocking implementation would stall here until step 3
     *    releases the lock. */
    bool locked = ap_lock_connection(&lk, ndb.db, &th);
    AP_CHECK("locker holds the connection mutex (cold)", locked);

    struct agent_security_posture cold_busy;
    int64_t t0 = platform_time_monotonic_ms();
    agent_security_posture_collect(&cold_busy, &ndb);
    int64_t elapsed_ms = platform_time_monotonic_ms() - t0;
    AP_CHECK("cold busy: returns within budget (<500ms)", elapsed_ms < 500);
    AP_CHECK("cold busy: status is posture_unavailable_busy",
             strcmp(cold_busy.status, "posture_unavailable_busy") == 0);
    AP_CHECK("cold busy: next_action is retry_status_query",
             strcmp(cold_busy.next_action, "retry_status_query") == 0);
    AP_CHECK("cold busy: served_from_cache", cold_busy.served_from_cache);
    AP_CHECK("cold busy: node_db_available is false",
             !cold_busy.node_db_available);
    AP_CHECK("cold busy: no prior snapshot -> cache_age_ms is the sentinel",
             cold_busy.cache_age_ms == -1);

    /* 2. Still contended: the labeled partial from step 1 is now cached, so
     *    this call answers from THAT cache with a real (non-sentinel) age
     *    instead of recomputing the same placeholder statelessly. */
    struct timespec pause = { 0, 5 * 1000 * 1000 }; /* 5ms */
    nanosleep(&pause, NULL);

    struct agent_security_posture still_busy;
    agent_security_posture_collect(&still_busy, &ndb);
    AP_CHECK("still busy: status stays posture_unavailable_busy",
             strcmp(still_busy.status, "posture_unavailable_busy") == 0);
    AP_CHECK("still busy: cache_age_ms is now a real, non-sentinel age",
             still_busy.cache_age_ms >= 0);

    /* 3. Release; the SAME connection now serves a fresh, full collect. */
    ap_unlock_connection(&lk, th);

    struct agent_security_posture live;
    agent_security_posture_collect(&live, &ndb);
    AP_CHECK("free: node_db_available", live.node_db_available);
    AP_CHECK("free: not served from cache", !live.served_from_cache);
    AP_CHECK("free: status is not the busy marker",
             strcmp(live.status, "posture_unavailable_busy") != 0);

    /* 4. Contend again, now that a REAL collect has succeeded: the front
     *    upgrades to serving that last-known-GOOD snapshot (matching the
     *    live collect's own diagnostic status) rather than regressing to
     *    the "we know nothing" placeholder — never destroy real data with a
     *    worse-informed busy label once real data exists. */
    locked = ap_lock_connection(&lk, ndb.db, &th);
    AP_CHECK("locker holds the connection mutex (warm)", locked);

    struct agent_security_posture warm_busy;
    agent_security_posture_collect(&warm_busy, &ndb);
    AP_CHECK("warm busy: served_from_cache", warm_busy.served_from_cache);
    AP_CHECK("warm busy: node_db_available carried from the real snapshot",
             warm_busy.node_db_available == live.node_db_available);
    AP_CHECK("warm busy: upgrades to the real status, not the busy marker",
             strcmp(warm_busy.status, live.status) == 0);

    ap_unlock_connection(&lk, th);

    struct agent_security_posture live_again;
    agent_security_posture_collect(&live_again, &ndb);
    AP_CHECK("free again: not served from cache", !live_again.served_from_cache);

    node_db_close(&ndb);
    return failures;
}

/* background_validation_height (agent_security_posture.h) is copied from the
 * SAME chain_evidence_controller_snapshot() call posture_collect_bootstrap()
 * already makes for snapshot_anchor_height — no new read, no new lock. Prove
 * it defaults to -1 alongside snapshot_anchor_height on a fresh datadir with
 * no recorded evidence, and that it reflects a persisted value once one
 * exists (mirroring how chain_evidence_snapshot.c reads either field:
 * state_get_i32(ndb, key, -1)). */
static int case_background_validation_height_populates(void)
{
    int failures = 0;
    struct node_db ndb;

    bool opened = node_db_open(&ndb, ":memory:");
    AP_CHECK("bvh: node.db (:memory:) opens", opened);
    if (!opened)
        return failures;

    struct agent_security_posture fresh;
    agent_security_posture_collect(&fresh, &ndb);
    AP_CHECK("bvh: fresh node_db_available", fresh.node_db_available);
    AP_CHECK("bvh: fresh snapshot_anchor_height defaults -1",
             fresh.snapshot_anchor_height == -1);
    AP_CHECK("bvh: fresh background_validation_height defaults -1 alongside it",
             fresh.background_validation_height == -1);

    AP_CHECK("bvh: seed cec.background_validation_height=777",
             node_db_state_set_int(&ndb, "cec.background_validation_height",
                                   777));

    struct agent_security_posture seeded;
    agent_security_posture_collect(&seeded, &ndb);
    AP_CHECK("bvh: seeded background_validation_height == 777",
             seeded.background_validation_height == 777);
    /* Unrelated field stays at its own default — the two are independent
     * columns of the same view, not aliases of one another. */
    AP_CHECK("bvh: snapshot_anchor_height still -1 (untouched)",
             seeded.snapshot_anchor_height == -1);

    node_db_close(&ndb);
    return failures;
}

/* Status collection holds sqlite3_db_mutex to stay non-blocking. A stale
 * freeze is intentionally useful here because the mutating CEC loader would
 * auto-clear it and persist three repairs. On the live node those writes are
 * routed through db_service, whose worker waits for the mutex held by this
 * caller: a permanent self-deadlock. Prove the observation path leaves the
 * persisted state byte-for-byte alone; boot init remains the repair owner. */
static int case_collect_never_repairs_cec_state(void)
{
    int failures = 0;
    struct node_db ndb;
    char state[64] = {0};
    char reason[128] = {0};
    size_t state_len = 0, reason_len = 0;

    bool opened = node_db_open(&ndb, ":memory:");
    AP_CHECK("readonly: node.db (:memory:) opens", opened);
    if (!opened)
        return failures;
    AP_CHECK("readonly: seed frozen state",
             node_db_state_set(&ndb, "cec.sync_state",
                               "contradiction_frozen",
                               strlen("contradiction_frozen") + 1));
    AP_CHECK("readonly: seed formerly-demoted reason",
             node_db_state_set(&ndb, "cec.contradiction_reason",
                               "active_tip_hash_mismatch",
                               strlen("active_tip_hash_mismatch") + 1));

    struct agent_security_posture observed;
    agent_security_posture_collect(&observed, &ndb);
    AP_CHECK("readonly: collect completed with node.db available",
             observed.node_db_available);
    AP_CHECK("readonly: persisted state remains readable",
             node_db_state_get(&ndb, "cec.sync_state", state,
                               sizeof(state), &state_len));
    AP_CHECK("readonly: status did not auto-clear frozen state",
             strcmp(state, "contradiction_frozen") == 0);
    AP_CHECK("readonly: persisted reason remains readable",
             node_db_state_get(&ndb, "cec.contradiction_reason", reason,
                               sizeof(reason), &reason_len));
    AP_CHECK("readonly: status did not rewrite the reason",
             strcmp(reason, "active_tip_hash_mismatch") == 0);

    node_db_close(&ndb);
    return failures;
}

int test_agent_posture_trylock(void)
{
    int failures = 0;
    failures += case_collect_nonblocking_scenario();
    failures += case_background_validation_height_populates();
    failures += case_collect_never_repairs_cec_state();
    if (failures == 0)
        printf("test_agent_posture_trylock: ALL PASSED\n");
    else
        printf("test_agent_posture_trylock: %d FAILURE(S)\n", failures);
    return failures;
}

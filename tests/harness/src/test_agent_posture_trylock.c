/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_agent_posture_trylock — the node.db-connection-level non-blocking
 * guard for agent_security_posture_collect()'s bootstrap read.
 *
 * agent_security_posture_collect() -> posture_collect_bootstrap() issues ~a
 * dozen synchronous reads on the shared node.db connection. A writer retrying
 * SQLITE_BUSY inside one sqlite3_step() holds SQLite's per-connection mutex
 * for up to ZCL_NODE_DB_BUSY_TIMEOUT_MS (10s), and any other thread on that
 * connection queues behind it.
 *
 * agent_security_posture.c therefore try-locks the connection's mutex
 * (sqlite3_db_mutex) before the bootstrap read. On a miss it serves the
 * last-known-good snapshot immediately: "posture_unavailable_busy" while
 * nothing is cached, the last real collected snapshot afterwards. This
 * mirrors progress_store_tx_trylock() (test_stage_dump_trylock.c).
 *
 * The test takes that same mutex from a helper thread to simulate a writer's
 * in-flight sqlite3_step().
 *
 * The last-known-good cache is one process-wide static, so the single test
 * case is ONE ordered scenario (no cache -> busy shows the labeled partial ->
 * a real collect populates the cache -> a later busy period serves that
 * snapshot). */

#include "test/test_core.h"

#include "controllers/agent_security_posture.h"
#include "models/database.h"
#include "platform/clock.h"
#include "storage/progress_store.h"
#include "storage/anchor_kv.h"
#include "storage/nullifier_kv.h"
#include "services/chain_evidence_authority_service.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define AP_CHECK(name, expr) do {                                 \
    printf("agent_posture_trylock: %s... ", (name));              \
    if (expr) { printf("OK\n"); }                                 \
    else { printf("FAIL\n"); failures++; }                        \
} while (0)

/* SQLite's public seams observe attempted waits on the collector thread. */
static sqlite3_mutex_methods ap_mutex_methods;
static sqlite3_vfs *ap_vfs;
static int (*ap_vfs_sleep)(sqlite3_vfs *, int);
static bool ap_probes_configured;
static _Thread_local bool ap_collecting;
static pthread_mutex_t ap_control = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ap_changed = PTHREAD_COND_INITIALIZER;
static bool ap_done;
static int ap_blocking_calls;

static void ap_note_blocking_call(void)
{
    pthread_mutex_lock(&ap_control);
    ap_blocking_calls++;
    pthread_cond_broadcast(&ap_changed);
    pthread_mutex_unlock(&ap_control);
}

static void ap_mutex_enter(sqlite3_mutex *mutex)
{
    if (ap_collecting)
        ap_note_blocking_call();
    ap_mutex_methods.xMutexEnter(mutex);
}

static int ap_sleep(sqlite3_vfs *vfs, int microseconds)
{
    if (ap_collecting) {
        ap_note_blocking_call();
        return microseconds;
    }
    return ap_vfs_sleep(vfs, microseconds);
}

static bool ap_install_probes(void)
{
    if (sqlite3_initialize() != SQLITE_OK)
        return false;
    if (sqlite3_shutdown() != SQLITE_OK)
        return false;
    if (sqlite3_config(SQLITE_CONFIG_GETMUTEX, &ap_mutex_methods) != SQLITE_OK)
        return false;
    if (!ap_mutex_methods.xMutexEnter)
        return false;
    sqlite3_mutex_methods methods = ap_mutex_methods;
    methods.xMutexEnter = ap_mutex_enter;
    if (sqlite3_config(SQLITE_CONFIG_MUTEX, &methods) != SQLITE_OK)
        return false;
    ap_probes_configured = true;
    ap_vfs = sqlite3_vfs_find(NULL);
    if (!ap_vfs || !ap_vfs->xSleep)
        return false;
    ap_vfs_sleep = ap_vfs->xSleep;
    ap_vfs->xSleep = ap_sleep;
    return true;
}

static bool ap_restore_probes(void)
{
    if (!ap_probes_configured)
        return true;
    if (ap_vfs_sleep)
        ap_vfs->xSleep = ap_vfs_sleep;
    if (sqlite3_shutdown() != SQLITE_OK)
        return false;
    if (sqlite3_config(SQLITE_CONFIG_MUTEX, &ap_mutex_methods) != SQLITE_OK)
        return false;
    ap_probes_configured = false;
    return true;
}

struct ap_locker {
    sqlite3 *db;
    bool locked;
    bool release;
};

static void *ap_locker_thread(void *arg)
{
    struct ap_locker *lk = arg;
    sqlite3_mutex *m = sqlite3_db_mutex(lk->db);
    sqlite3_mutex_enter(m);
    pthread_mutex_lock(&ap_control);
    lk->locked = true;
    pthread_cond_broadcast(&ap_changed);
    while (!lk->release)
        pthread_cond_wait(&ap_changed, &ap_control);
    pthread_mutex_unlock(&ap_control);
    sqlite3_mutex_leave(m);
    return NULL;
}

static bool ap_lock_connection(struct ap_locker *lk, sqlite3 *db,
                               pthread_t *th_out)
{
    *th_out = (pthread_t){0};
    *lk = (struct ap_locker){ .db = db };
    if (pthread_create(th_out, NULL, ap_locker_thread, lk) != 0)
        return false;
    pthread_mutex_lock(&ap_control);
    while (!lk->locked)
        pthread_cond_wait(&ap_changed, &ap_control);
    pthread_mutex_unlock(&ap_control);
    return true;
}

static void ap_unlock_connection(struct ap_locker *lk, pthread_t th)
{
    pthread_mutex_lock(&ap_control);
    lk->release = true;
    pthread_cond_broadcast(&ap_changed);
    pthread_mutex_unlock(&ap_control);
    pthread_join(th, NULL);
}

struct ap_collector {
    struct node_db *ndb;
    struct agent_security_posture posture;
};

static void *ap_collect(void *arg)
{
    struct ap_collector *c = arg;
    ap_collecting = true;
    agent_security_posture_collect(&c->posture, c->ndb);
    ap_collecting = false;
    pthread_mutex_lock(&ap_control);
    ap_done = true;
    pthread_cond_broadcast(&ap_changed);
    pthread_mutex_unlock(&ap_control);
    return NULL;
}

static int ap_check_cold_busy(struct node_db *ndb, struct ap_locker *lk)
{
    int failures = 0;
    struct ap_collector c = { .ndb = ndb };
    pthread_t collector;
    ap_done = false;
    ap_blocking_calls = 0;
    bool started = pthread_create(&collector, NULL, ap_collect, &c) == 0;
    AP_CHECK("cold busy: collector starts", started);
    if (!started)
        return failures;
    pthread_mutex_lock(&ap_control);
    while (!ap_done && ap_blocking_calls == 0)
        pthread_cond_wait(&ap_changed, &ap_control);
    AP_CHECK("cold busy: completes before holder release", ap_done && !lk->release);
    AP_CHECK("cold busy: no blocking lock or sleep call", ap_blocking_calls == 0);
    /* Release only after both observations; a defective collector can finish. */
    if (!ap_done) {
        lk->release = true;
        pthread_cond_broadcast(&ap_changed);
    }
    pthread_mutex_unlock(&ap_control);
    pthread_join(collector, NULL);
    AP_CHECK("cold busy: status is posture_unavailable_busy",
             strcmp(c.posture.status, "posture_unavailable_busy") == 0);
    AP_CHECK("cold busy: next_action is retry_status_query",
             strcmp(c.posture.next_action, "retry_status_query") == 0);
    AP_CHECK("cold busy: served_from_cache", c.posture.served_from_cache);
    AP_CHECK("cold busy: node_db_available is false", !c.posture.node_db_available);
    AP_CHECK("cold busy: no prior snapshot -> cache_age_ms is the sentinel",
             c.posture.cache_age_ms == -1);
    return failures;
}

static int case_collect_nonblocking_scenario(void)
{
    int failures = 0;
    struct node_db ndb;
    struct ap_locker lk;
    pthread_t th;

    bool opened = node_db_open(&ndb, ":memory:");
    if (!opened) {
        printf("agent_posture_trylock: node.db (:memory:) opens... FAIL\n");
        return 1;
    }

    /* 1. Hold the connection mutex before the first collect. Completion and
     *    blocking-call observations precede release; the cold result must
     *    be the labeled busy partial. */
    bool locked = ap_lock_connection(&lk, ndb.db, &th);
    AP_CHECK("locker holds the connection mutex (cold)", locked);
    if (!locked) {
        node_db_close(&ndb);
        return failures;
    }

    failures += ap_check_cold_busy(&ndb, &lk);
    if (failures) {
        ap_unlock_connection(&lk, th);
        node_db_close(&ndb);
        return failures;
    }

    /* 2. Still contended: the labeled partial from step 1 is now cached, so
     *    this call answers from THAT cache with a real (non-sentinel) age
     *    instead of recomputing the same placeholder statelessly. */

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

    /* 4. Contend again after a REAL collect succeeded: the front serves the
     *    last-known-good snapshot rather than the "we know nothing"
     *    placeholder. */
    locked = ap_lock_connection(&lk, ndb.db, &th);
    AP_CHECK("locker holds the connection mutex (warm)", locked);
    if (!locked) {
        node_db_close(&ndb);
        return failures;
    }

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

/* Status collection holds sqlite3_db_mutex to stay non-blocking. It must not
 * run the mutating CEC loader (which would auto-clear a stale freeze and
 * persist repairs through db_service, whose worker waits on that mutex: a
 * self-deadlock). Prove the observation path leaves persisted state
 * byte-for-byte alone; boot init remains the repair owner. */
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

/* libc's transaction mutex cannot be driven by the injectable clock. The
 * condition deadline only bounds cleanup of a defective blocking collector;
 * the observation is completion while the real transaction lock is held.
 * The injectable clock below also avoids real cache-age timing inputs. */
static bool ap_collect_under_progress_lock(struct ap_collector *c)
{
    struct timespec deadline;
    bool completed = false;
    pthread_t collector;
    ap_done = false;
    if (timespec_get(&deadline, TIME_UTC) != TIME_UTC) {
        progress_store_tx_unlock();
        return false;
    }
    deadline.tv_sec += 30;
    if (pthread_create(&collector, NULL, ap_collect, c) != 0) {
        progress_store_tx_unlock();
        return false;
    }
    pthread_mutex_lock(&ap_control);
    int rc = 0;
    while (!ap_done && rc == 0)
        rc = pthread_cond_timedwait(&ap_changed, &ap_control, &deadline);
    completed = ap_done;
    pthread_mutex_unlock(&ap_control);
    /* Always release before joining: the baseline's blocked read recovers. */
    progress_store_tx_unlock();
    pthread_join(collector, NULL);
    return completed;
}

static int64_t ap_virtual_mono(void *self)
{
    return *(int64_t *)self;
}

static int64_t ap_virtual_wall(void *self)
{
    return *(int64_t *)self / 1000000;
}

static int ap_check_progress_partial(const struct agent_security_posture *posture)
{
    int failures = 0;
    const struct ap_collector c = { .posture = *posture };
    AP_CHECK("progress busy: fresh partial is not labeled as cached",
             !c.posture.served_from_cache && c.posture.cache_age_ms == 0);
    AP_CHECK("progress busy: fresh bootstrap evidence survives old cached evidence",
             c.posture.background_validation_height == 888 &&
             !c.posture.full_history_validation_complete);
    AP_CHECK("progress busy: unknown progress requires review and refuses public serving",
             c.posture.review_required &&
             !agent_security_posture_allows_public_serving(&c.posture));
    AP_CHECK("progress busy: progress availability and cursor knowledge are unknown",
             !c.posture.progress_store_available &&
             !c.posture.anchor_cursor_known && !c.posture.nullifier_cursor_known);
    AP_CHECK("progress busy: unknown cursor sentinels survive",
             c.posture.sprout_anchor_activation_cursor == -1 &&
             c.posture.sapling_anchor_activation_cursor == -1 &&
             c.posture.nullifier_activation_cursor == -1);
    AP_CHECK("progress busy: explicit progress contention status",
             strcmp(c.posture.status, "review_required_progress_store_busy") == 0 &&
             strcmp(c.posture.next_action, "retry_status_query") == 0);
    AP_CHECK("progress busy: explicit unknown progress labels",
             strcmp(c.posture.anchor_history_state, "unknown_progress_busy") == 0 &&
             strcmp(c.posture.nullifier_history_state, "unknown_progress_busy") == 0);

    return failures;
}

static bool ap_seed_complete_history(struct node_db *ndb)
{
    sqlite3 *db = progress_store_db();
    return anchor_kv_ensure_schema(db) &&
           anchor_kv_initialize_history(db, 0) &&
           nullifier_kv_ensure_schema(db) &&
           nullifier_kv_initialize_history(db, 0) &&
           node_db_state_set(ndb, "cec.sync_state", "fully_validated",
                             sizeof "fully_validated") &&
           node_db_state_set_int(ndb, "cec.full_validation_origin",
                                 CEC_FULL_VALIDATION_GENESIS_HISTORY);
}

static int case_progress_contention_preserves_bootstrap(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof dir, "agent_posture_trylock", "progress");
    progress_store_close();
    bool opened = progress_store_open(dir);
    AP_CHECK("progress busy: isolated progress store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }
    struct node_db ndb;
    opened = node_db_open(&ndb, ":memory:");
    AP_CHECK("progress busy: isolated node database opens", opened);
    if (!opened) {
        progress_store_close();
        test_cleanup_tmpdir(dir);
        return failures;
    }
    int64_t now = 1000000000;
    const clock_iface_t *previous_clock = clock_default();
    const clock_iface_t clock = {
        .now_monotonic_ns = ap_virtual_mono,
        .now_wall_ms = ap_virtual_wall, .self = &now,
    };
    clock_set_default(&clock);
    AP_CHECK("progress busy: seed persisted complete genesis history",
             ap_seed_complete_history(&ndb));
    AP_CHECK("progress busy: seed cached evidence height",
             node_db_state_set_int(&ndb, "cec.background_validation_height", 777));
    struct agent_security_posture live;
    agent_security_posture_collect(&live, &ndb);
    AP_CHECK("progress busy: real progress reader was available",
             live.progress_store_available && !live.served_from_cache);
    AP_CHECK("progress busy: cached real history is complete and permits serving",
             live.full_history_validation_complete && live.anchor_history_complete &&
             live.nullifier_history_complete && !live.review_required &&
             agent_security_posture_allows_public_serving(&live));
    AP_CHECK("progress busy: persisted bootstrap now requires review",
             node_db_state_set(&ndb, "cec.sync_state", "empty", sizeof "empty"));
    AP_CHECK("progress busy: change only live bootstrap evidence",
             node_db_state_set_int(&ndb, "cec.background_validation_height", 888));
    now = 2000000000;
    progress_store_tx_lock();
    struct ap_collector c = { .ndb = &ndb };
    bool completed = ap_collect_under_progress_lock(&c);
    AP_CHECK("progress busy: collection completes before transaction lock release",
             completed);
    failures += ap_check_progress_partial(&c.posture);
    struct agent_security_posture recovered;
    agent_security_posture_collect(&recovered, &ndb);
    AP_CHECK("progress free: fresh collection resumes with changed evidence",
             !recovered.served_from_cache &&
             recovered.background_validation_height == 888);
    AP_CHECK("progress free: progress and zero cursor histories are restored",
             recovered.progress_store_available && recovered.anchor_cursor_known &&
             recovered.nullifier_cursor_known && recovered.anchor_history_complete &&
             recovered.nullifier_history_complete);
    AP_CHECK("progress free: status is no longer progress busy",
             strcmp(recovered.status, "review_required_progress_store_busy") != 0);
    clock_set_default(previous_clock);
    node_db_close(&ndb);
    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_agent_posture_trylock(void)
{
    int failures = 0;
    bool installed = ap_install_probes();
    AP_CHECK("SQLite contention probes installed", installed);
    if (!installed) {
        AP_CHECK("SQLite partial probe setup restored", ap_restore_probes());
        return failures;
    }
    failures += case_collect_nonblocking_scenario();
    failures += case_background_validation_height_populates();
    failures += case_collect_never_repairs_cec_state();
    failures += case_progress_contention_preserves_bootstrap();
    AP_CHECK("SQLite contention probes restored", ap_restore_probes());
    if (failures == 0)
        printf("test_agent_posture_trylock: ALL PASSED\n");
    else
        printf("test_agent_posture_trylock: %d FAILURE(S)\n", failures);
    return failures;
}

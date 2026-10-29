/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_catchup_cadence — the PARITY-SAFETY guard for the live-sync catch-up
 * drain-batch override (engine/jobs/src/catchup_cadence.c).
 *
 * The override changes how many blocks each reducer stage folds per drain
 * when a node has fallen behind. On a NORMAL boot (no peers, or peers but no
 * material gap) it is INERT: catchup_cadence_drain_batch returns its argument
 * UNCHANGED (as in test_refold_cadence.c).
 *
 * It FIRES (honoring clamped env knobs) once BOTH gates are open (peers
 * connected AND gap (network_tip - log_head) >= ZCL_CATCHUP_GAP_THRESHOLD),
 * and closing either gate restores the inert identity.
 *
 * Peers come from a test-populated struct connman via
 * sync_monitor_set_context() (as in test_sync_rate_below_floor.c); log_head
 * via catchup_cadence_test_set_log_head_override(). */

#include "test/test_core.h"

#include "jobs/catchup_cadence.h"
#include "jobs/job.h"
#include "platform/clock.h"
#include "storage/progress_store.h"
#include "util/stage.h"
#include <sqlite3.h>
#include "jobs/validate_headers_stage.h"   /* VH_BATCH_SIZE, VH_BATCH_PER_TICK */
#include "net/connman.h"
#include "net/protocol.h"
#include "services/sync_monitor.h"
#include "supervisors/staged_sync_supervisor.h" /* test_effective_batch (A12) */
#include "util/sync.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CC_CHECK(name, expr) do {                                 \
    printf("catchup_cadence: %s... ", (name));                    \
    if (expr) { printf("OK\n"); }                                 \
    else { printf("FAIL\n"); failures++; }                        \
} while (0)

static void cc_clear_env(void)
{
    unsetenv("ZCL_CATCHUP_DRAIN_BATCH");
    unsetenv("ZCL_CATCHUP_DRAIN_BUDGET_MS");
    unsetenv("ZCL_CATCHUP_GAP_THRESHOLD");
    unsetenv("ZCL_CATCHUP_TICK_MS");
    unsetenv("ZCL_CATCHUP_DEFER_GAP_THRESHOLD");
    unsetenv("ZCL_VH_CATCHUP_POOL_SIZE");
}

static void cc_reset(struct connman *cm)
{
    cc_clear_env();
    catchup_cadence_test_reset();
    memset(cm, 0, sizeof(*cm));
    zcl_mutex_init(&cm->manager.cs_nodes);
    sync_monitor_set_context(cm, NULL, NULL);
}

static void cc_cleanup(void)
{
    cc_clear_env();
    catchup_cadence_test_reset();
    sync_monitor_set_context(NULL, NULL, NULL);
}

static void cc_add_peer(struct connman *cm, struct p2p_node *peer, int height)
{
    memset(peer, 0, sizeof(*peer));
    peer->id = 1;
    peer->starting_height = height;
    peer->state = PEER_ACTIVE;
    peer->services = NODE_NETWORK;
    static struct p2p_node *peers[1];
    peers[0] = peer;
    cm->manager.nodes = peers;
    cm->manager.num_nodes = 1;
}

/* (1a) NORMAL boot, no peers at all: inert regardless of log_head. */
static int case_no_peers_inert(void)
{
    int failures = 0;
    struct connman cm;
    cc_reset(&cm);

    catchup_cadence_test_set_log_head_override(0); /* huge implied gap */
    CC_CHECK("no peers: not active", !catchup_cadence_active());
    CC_CHECK("no peers: batch 100 unchanged", catchup_cadence_drain_batch(100) == 100);
    CC_CHECK("no peers: batch 64 unchanged", catchup_cadence_drain_batch(64) == 64);
    /* The critical pin: inactive -> tick period 0 (caller keeps its
     * unmodified 2s period_secs, byte-identical at tip). */
    CC_CHECK("no peers: tick period 0", catchup_cadence_tick_period_us() == 0);

    cc_cleanup();
    return failures;
}

/* (1b) NORMAL boot, peers connected but at/near tip (gap below threshold):
 * inert. ZCL_CATCHUP_DRAIN_BATCH is ignored while inactive. (The gap
 * threshold is part of the activation predicate; it is tuned in
 * case_active_when_gap_exceeds_threshold.) */
static int case_small_gap_inert(void)
{
    int failures = 0;
    struct connman cm;
    struct p2p_node peer;
    cc_reset(&cm);
    cc_add_peer(&cm, &peer, 1000);
    catchup_cadence_test_set_log_head_override(999); /* gap = 1, far under default 500 */

    CC_CHECK("small gap: not active", !catchup_cadence_active());
    CC_CHECK("small gap: batch 100 unchanged", catchup_cadence_drain_batch(100) == 100);
    CC_CHECK("small gap: batch 500 unchanged", catchup_cadence_drain_batch(500) == 500);
    CC_CHECK("small gap: tick period 0", catchup_cadence_tick_period_us() == 0);

    setenv("ZCL_CATCHUP_DRAIN_BATCH", "9999", 1);
    CC_CHECK("small gap: drain-batch env ignored while inactive",
             catchup_cadence_drain_batch(100) == 100);
    cc_clear_env();

    setenv("ZCL_CATCHUP_TICK_MS", "1500", 1);
    CC_CHECK("small gap: tick-ms env ignored while inactive",
             catchup_cadence_tick_period_us() == 0);
    cc_clear_env();

    cc_cleanup();
    return failures;
}

/* (1c) Exactly AT the gap threshold minus one: still inert (>= is the
 * activation predicate, not >). */
static int case_gap_just_under_threshold_inert(void)
{
    int failures = 0;
    struct connman cm;
    struct p2p_node peer;
    cc_reset(&cm);
    cc_add_peer(&cm, &peer, 1000);
    /* default threshold 500; gap = 1000 - 501 = 499 */
    catchup_cadence_test_set_log_head_override(501);

    CC_CHECK("gap 499 < threshold 500: not active", !catchup_cadence_active());
    CC_CHECK("gap 499 < threshold 500: batch unchanged",
             catchup_cadence_drain_batch(100) == 100);
    CC_CHECK("gap 499 < threshold 500: tick period 0",
             catchup_cadence_tick_period_us() == 0);

    cc_cleanup();
    return failures;
}

/* (2) Peers connected AND gap >= threshold: active, defaults apply, env
 * knobs tune it (clamped). */
static int case_active_when_gap_exceeds_threshold(void)
{
    int failures = 0;
    struct connman cm;
    struct p2p_node peer;
    cc_reset(&cm);
    cc_add_peer(&cm, &peer, 1000);
    /* default threshold 500; gap = 1000 - 400 = 600 */
    catchup_cadence_test_set_log_head_override(400);

    CC_CHECK("gap 600 >= threshold 500: active", catchup_cadence_active());
    CC_CHECK("active: measured default batch 2000",
             catchup_cadence_drain_batch(100) == CATCHUP_CADENCE_DEFAULT_DRAIN_BATCH);
    CC_CHECK("active: default batch applies regardless of caller's arg",
             catchup_cadence_drain_batch(64) == CATCHUP_CADENCE_DEFAULT_DRAIN_BATCH);
    CC_CHECK("active: default tick period 1,000,000us (1s)",
             catchup_cadence_tick_period_us() ==
                 (int64_t)CATCHUP_CADENCE_DEFAULT_TICK_MS * 1000);

    /* Env override + clamp [1000,2000] ms. */
    setenv("ZCL_CATCHUP_TICK_MS", "1500", 1);
    CC_CHECK("active: env tick period 1500ms",
             catchup_cadence_tick_period_us() == (int64_t)1500 * 1000);
    setenv("ZCL_CATCHUP_TICK_MS", "1", 1); /* below floor -> clamp to 1000 */
    CC_CHECK("active: tick period clamp low (1000ms floor)",
             catchup_cadence_tick_period_us() == (int64_t)1000 * 1000);
    setenv("ZCL_CATCHUP_TICK_MS", "999999", 1); /* above ceiling -> 2000 */
    CC_CHECK("active: tick period clamp high (2000ms ceiling)",
             catchup_cadence_tick_period_us() == (int64_t)2000 * 1000);
    cc_clear_env();

    /* Exactly AT the threshold (gap == 500) also activates (>=, not >). */
    catchup_cadence_test_set_log_head_override(500); /* gap = 500 */
    CC_CHECK("gap == threshold: active", catchup_cadence_active());

    /* Env override. */
    setenv("ZCL_CATCHUP_DRAIN_BATCH", "777", 1);
    CC_CHECK("active: env batch 777", catchup_cadence_drain_batch(100) == 777);
    cc_clear_env();

    /* Clamp: absurd values are bounded, never returned raw. */
    setenv("ZCL_CATCHUP_DRAIN_BATCH", "0", 1); /* below floor -> clamp to 1 */
    CC_CHECK("active: batch clamp low", catchup_cadence_drain_batch(100) == 1);
    setenv("ZCL_CATCHUP_DRAIN_BATCH", "5000000", 1); /* above ceiling -> 1000000 */
    CC_CHECK("active: batch clamp high", catchup_cadence_drain_batch(100) == 1000000);
    cc_clear_env();

    /* ZCL_CATCHUP_GAP_THRESHOLD env override + clamp. */
    catchup_cadence_test_set_log_head_override(700); /* gap = 300 */
    CC_CHECK("gap 300 < default threshold: not active", !catchup_cadence_active());
    setenv("ZCL_CATCHUP_GAP_THRESHOLD", "200", 1); /* now gap(300) >= threshold(200) */
    CC_CHECK("lowered threshold via env: active", catchup_cadence_active());
    setenv("ZCL_CATCHUP_GAP_THRESHOLD", "0", 1); /* below floor -> clamp to 1 */
    CC_CHECK("threshold clamp low: still active (gap 300 >= 1)",
             catchup_cadence_active());
    cc_clear_env();

    cc_cleanup();
    return failures;
}

/* (3) Active, then the gap closes (backlog drains) -> RESTORES the inert
 * identity. No leak into the live path once caught up. */
static int case_active_then_restore(void)
{
    int failures = 0;
    struct connman cm;
    struct p2p_node peer;
    cc_reset(&cm);
    cc_add_peer(&cm, &peer, 1000);
    catchup_cadence_test_set_log_head_override(400); /* gap = 600, active */

    CC_CHECK("restore: active before catch-up", catchup_cadence_active());
    CC_CHECK("restore: measured batch while active",
             catchup_cadence_drain_batch(100) == CATCHUP_CADENCE_DEFAULT_DRAIN_BATCH);
    CC_CHECK("restore: tick period 1s while active",
             catchup_cadence_tick_period_us() ==
                 (int64_t)CATCHUP_CADENCE_DEFAULT_TICK_MS * 1000);

    /* Backlog drains: log_head catches up to network_tip. */
    catchup_cadence_test_set_log_head_override(1000); /* gap = 0 */
    CC_CHECK("restore: not active once caught up", !catchup_cadence_active());
    CC_CHECK("restore: batch 100 unchanged once caught up",
             catchup_cadence_drain_batch(100) == 100);
    CC_CHECK("restore: tick period resets to 0 once caught up",
             catchup_cadence_tick_period_us() == 0);

    /* Peers then disconnect entirely: still inert. */
    catchup_cadence_test_set_log_head_override(0);
    cm.manager.num_nodes = 0;
    CC_CHECK("restore: not active with no peers even with huge gap",
             !catchup_cadence_active());
    CC_CHECK("restore: batch unchanged with no peers",
             catchup_cadence_drain_batch(100) == 100);
    CC_CHECK("restore: tick period 0 with no peers",
             catchup_cadence_tick_period_us() == 0);

    cc_cleanup();
    return failures;
}

/* (A12) The supervisor's per-tick effective batch must be FAN-OUT aware: a
 * stage whose step_once verifies many units of consensus work
 * (validate_headers: VH_BATCH_SIZE Equihash solutions per step) must not have
 * its catch-up batch multiplied beyond what its worker pool can absorb.
 * stage_effective_batch scales the fanning stage's catch-up step cap by the
 * pool widening in force (validate_headers_stage_catchup_step_cap:
 * vh_runtime_pool_size() / VH_POOL_SIZE, clamped [1, VH_CATCHUP_STEP_MULT]),
 * leaves non-fanning stages fully accelerated, and is byte-identical when the
 * override is inactive. ZCL_VH_CATCHUP_POOL_SIZE is set explicitly wherever a
 * scale is asserted so checks are host-nproc-independent. */
static int case_fanout_capped_under_catchup(void)
{
    int failures = 0;
    struct connman cm;
    struct p2p_node peer;
    cc_reset(&cm);

    /* --- inactive (no peers): byte-identical, fan-out or not. --- */
    CC_CHECK("A12 inactive: fanout stage batch unchanged",
             staged_sync_supervisor_test_effective_batch(
                 VH_BATCH_PER_TICK, VH_BATCH_SIZE) == VH_BATCH_PER_TICK);
    CC_CHECK("A12 inactive: non-fanout stage batch unchanged",
             staged_sync_supervisor_test_effective_batch(100, 1) == 100);

    /* --- catch-up ACTIVE (peers + gap >= threshold). --- */
    cc_add_peer(&cm, &peer, 100000);
    catchup_cadence_test_set_log_head_override(0); /* gap = 100000, active */
    CC_CHECK("A12 active precondition", catchup_cadence_active());

    /* A non-fanning stage is accelerated to the measured catch-up batch. */
    int nonfan = staged_sync_supervisor_test_effective_batch(100, 1);
    CC_CHECK("A12 active: non-fanout stage accelerated to measured default",
             nonfan == CATCHUP_CADENCE_DEFAULT_DRAIN_BATCH);

    /* A fanning stage (validate_headers) is raised by EXACTLY the pool scale
     * in force, capped at VH_CATCHUP_STEP_MULT — never to the raw catch-up
     * default. Pin the pool at 16 (4x VH_POOL_SIZE): 4x steps. */
    setenv("ZCL_VH_CATCHUP_POOL_SIZE", "16", 1);
    int fan = staged_sync_supervisor_test_effective_batch(
        VH_BATCH_PER_TICK, VH_BATCH_SIZE);
    CC_CHECK("A12 active: fanout stage not raised to catch-up default",
             fan < CATCHUP_CADENCE_DEFAULT_DRAIN_BATCH);
    CC_CHECK("A12 active: fanout stage at pool-scaled cap (pool 16 -> 4x)",
             fan == VH_BATCH_PER_TICK * VH_CATCHUP_STEP_MULT);
    /* The load-bearing property: per-tick Equihash volume grows no faster
     * than the workers to run it — wall time per tick is baseline-shaped. */
    CC_CHECK("A12 active: per-tick fanned work scales with the pool",
             (long)fan * VH_BATCH_SIZE / 16
                 == (long)VH_BATCH_PER_TICK * VH_BATCH_SIZE / VH_POOL_SIZE);

    /* A partial widening (8 = 2x) yields a partial step raise. */
    setenv("ZCL_VH_CATCHUP_POOL_SIZE", "8", 1);
    CC_CHECK("A12 active: pool 8 -> 2x steps",
             staged_sync_supervisor_test_effective_batch(
                 VH_BATCH_PER_TICK, VH_BATCH_SIZE)
                 == VH_BATCH_PER_TICK * 2);

    /* No widening (pool pinned at or below VH_POOL_SIZE) -> NO step raise:
     * the old hard containment is the floor of the new one. */
    setenv("ZCL_VH_CATCHUP_POOL_SIZE", "4", 1);
    CC_CHECK("A12 active: pool 4 -> normal batch (no raise)",
             staged_sync_supervisor_test_effective_batch(
                 VH_BATCH_PER_TICK, VH_BATCH_SIZE) == VH_BATCH_PER_TICK);
    setenv("ZCL_VH_CATCHUP_POOL_SIZE", "2", 1);
    CC_CHECK("A12 active: pool 2 -> normal batch (clamped, never below)",
             staged_sync_supervisor_test_effective_batch(
                 VH_BATCH_PER_TICK, VH_BATCH_SIZE) == VH_BATCH_PER_TICK);

    /* Env unset: the default pool min(nproc,16) decides the scale; assert
     * against the same host computation, so any host passes. */
    unsetenv("ZCL_VH_CATCHUP_POOL_SIZE");
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    if (nproc < 1) nproc = 1;
    if (nproc > VH_CATCHUP_POOL_CAP) nproc = VH_CATCHUP_POOL_CAP;
    int scale = (int)(nproc / VH_POOL_SIZE);
    if (scale < 1) scale = 1;
    if (scale > VH_CATCHUP_STEP_MULT) scale = VH_CATCHUP_STEP_MULT;
    CC_CHECK("A12 active: default pool -> min(nproc,16)-scaled steps",
             staged_sync_supervisor_test_effective_batch(
                 VH_BATCH_PER_TICK, VH_BATCH_SIZE)
                 == VH_BATCH_PER_TICK * scale);

    cc_cleanup();
    return failures;
}

/* (D) Small-backlog durability gate (catchup_cadence_deferred_sync_active):
 * a fresh latecomer on a SHORT chain — gap far under the 500-block cadence
 * threshold — still needs its staged drains inside the reducer's
 * batched-durability scope, because event_log_append's per-append double
 * fsync on the shared tick runner dominates a short sync on a slow disk
 * (commons journey run1: 227 barrier appends, 69.1 s of barrier wait for a
 * 124-block chain). The gate opens past one block of backlog, keeps the
 * accelerated batch/tick knobs inert, and never leaks into a caught-up
 * node. */
static int case_small_backlog_defer_sync_gate(void)
{
    int failures = 0;
    struct connman cm;
    struct p2p_node peer;
    cc_reset(&cm);

    /* No peers: closed regardless of the implied gap. */
    catchup_cadence_test_set_log_head_override(0);
    CC_CHECK("defer gate: closed with no peers",
             !catchup_cadence_deferred_sync_active());

    /* The journey shape: one peer 124 blocks ahead of an empty log head. */
    cc_add_peer(&cm, &peer, 124);
    catchup_cadence_test_set_log_head_override(0); /* gap = 124 */
    CC_CHECK("gap 124: accelerated cadence still inert",
             !catchup_cadence_active());
    CC_CHECK("gap 124: deferred-sync gate open",
             catchup_cadence_deferred_sync_active());
    CC_CHECK("gap 124: batch unchanged",
             catchup_cadence_drain_batch(100) == 100);
    CC_CHECK("gap 124: tick period unchanged",
             catchup_cadence_tick_period_us() == 0);

    /* One block behind — a live node receiving each new tip block: closed,
     * so at-tip per-op durability is byte-for-byte unchanged. */
    catchup_cadence_test_set_log_head_override(123); /* gap = 1 */
    CC_CHECK("gap 1: deferred-sync gate closed",
             !catchup_cadence_deferred_sync_active());

    /* Exactly at the threshold opens (>=, not >). */
    catchup_cadence_test_set_log_head_override(122); /* gap = 2 */
    CC_CHECK("gap 2 (at threshold): deferred-sync gate open",
             catchup_cadence_deferred_sync_active());

    /* Backlog fully drains: closed again. */
    catchup_cadence_test_set_log_head_override(124); /* gap = 0 */
    CC_CHECK("gap 0: deferred-sync gate closed",
             !catchup_cadence_deferred_sync_active());

    /* Env override + clamp, same shape as the cadence knobs. */
    catchup_cadence_test_set_log_head_override(123); /* gap = 1 */
    setenv("ZCL_CATCHUP_DEFER_GAP_THRESHOLD", "1", 1);
    CC_CHECK("defer threshold env 1: gap 1 opens",
             catchup_cadence_deferred_sync_active());
    setenv("ZCL_CATCHUP_DEFER_GAP_THRESHOLD", "0", 1); /* clamp to 1 */
    CC_CHECK("defer threshold clamp low: gap 1 still opens",
             catchup_cadence_deferred_sync_active());
    cc_clear_env();

    /* Peers disconnect mid-backlog: closed. */
    catchup_cadence_test_set_log_head_override(0); /* gap = 124 */
    cm.manager.num_nodes = 0;
    CC_CHECK("defer gate: closed when peers disconnect",
             !catchup_cadence_deferred_sync_active());

    cc_cleanup();
    return failures;
}

static int64_t cc_fake_time = 1000;
static int cc_fake_steps;
static int64_t cc_now(void *unused) { (void)unused; return cc_fake_time; }
static int64_t cc_wall(void *unused) { (void)unused; return 1; }
static job_result_t cc_fake_stage_step_once(void)
{
    cc_fake_steps++;
    sqlite3 *db = progress_store_db();
    if (db && sqlite3_exec(db, "INSERT INTO cc_budget_rows VALUES(1)", NULL, NULL, NULL) != SQLITE_OK)
        return JOB_FATAL;
    if (cc_fake_time > 0) cc_fake_time += 40000;
    return JOB_ADVANCED;
}
STAGE_DRAIN_IMPL(cc_fake)

static void *cc_probe_progress_lock(void *arg)
{
    bool *unlocked = arg;
    *unlocked = progress_store_tx_trylock();
    if (*unlocked) progress_store_tx_unlock();
    return NULL;
}

static int case_elapsed_budget(void)
{
    int failures = 0;
    struct connman cm;
    struct p2p_node peer;
    cc_reset(&cm);
    cc_add_peer(&cm, &peer, 1000);
    catchup_cadence_test_set_log_head_override(0);
    CC_CHECK("budget: catch-up active", catchup_cadence_active());
    struct platform_clock_source source = {cc_now, cc_wall, NULL};
    platform_clock_set_source(&source);
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "catchup_cadence", "budget");
    bool opened = progress_store_open(dir);
    CC_CHECK("budget: store opens", opened);
    if (!opened) { platform_clock_clear_source(); cc_cleanup(); return failures; }
    sqlite3 *db = progress_store_db();
    CC_CHECK("budget: row table created", sqlite3_exec(db, "CREATE TABLE cc_budget_rows(v INTEGER)", NULL, NULL, NULL) == SQLITE_OK);
    cc_fake_time = 1000; cc_fake_steps = 0;
    CC_CHECK("budget: unset keeps full drain", cc_fake_stage_drain(5) == 5 && cc_fake_steps == 5);
    setenv("ZCL_CATCHUP_DRAIN_BUDGET_MS", "100", 1);
    cc_fake_time = 1000; cc_fake_steps = 0;
    CC_CHECK("budget: yields after complete step", cc_fake_stage_drain(8) == 3 && cc_fake_steps == 3);
    CC_CHECK("budget: next drain progresses", cc_fake_stage_drain(8) == 3 && cc_fake_steps == 6);
    sqlite3_stmt *rows = NULL;
    bool committed = sqlite3_get_autocommit(db) == 1 &&
                     sqlite3_prepare_v2(db, "SELECT count(*) FROM cc_budget_rows", -1, &rows, NULL) == SQLITE_OK &&
                     sqlite3_step(rows) == SQLITE_ROW && sqlite3_column_int(rows, 0) == 11;
    sqlite3_finalize(rows);
    CC_CHECK("budget: yielded batches commit all rows", committed);
    bool unlocked = false;
    pthread_t probe;
    bool probe_started = pthread_create(&probe, NULL, cc_probe_progress_lock, &unlocked) == 0;
    if (probe_started) pthread_join(probe, NULL);
    CC_CHECK("budget: yielded batch releases progress lock", probe_started && unlocked);
    cc_fake_time = 0; cc_fake_steps = 0;
    CC_CHECK("budget: failed clock yields after step", cc_fake_stage_drain(8) == 1 && cc_fake_steps == 1);
    cm.manager.num_nodes = 0;
    CC_CHECK("budget: catch-up inactive", !catchup_cadence_active());
    cc_fake_time = 1000; cc_fake_steps = 0;
    CC_CHECK("budget: inactive keeps full drain", cc_fake_stage_drain(5) == 5 && cc_fake_steps == 5);
    platform_clock_clear_source();
    progress_store_close();
    test_cleanup_tmpdir(dir);
    cc_cleanup();
    return failures;
}

int test_catchup_cadence(void)
{
    int failures = 0;
    failures += case_elapsed_budget();
    failures += case_no_peers_inert();
    failures += case_small_gap_inert();
    failures += case_gap_just_under_threshold_inert();
    failures += case_active_when_gap_exceeds_threshold();
    failures += case_active_then_restore();
    failures += case_fanout_capped_under_catchup();
    failures += case_small_backlog_defer_sync_gate();
    if (failures == 0)
        printf("test_catchup_cadence: ALL PASSED\n");
    else
        printf("test_catchup_cadence: %d FAILURE(S)\n", failures);
    return failures;
}

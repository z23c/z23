/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_refold_premature_clear: a from-anchor refold must not clear early.
 *
 * A from-anchor refold captures its resume target once at boot
 * (refold_progress_mark_started_from_anchor, durable
 * REFOLD_FROM_ANCHOR_TARGET_KEY). The reconcile tick clears the refold when
 * utxo_apply reaches that target. If the chain advances after boot, the
 * frozen target is below the live tip, so clearing at the frozen target drops
 * refold_from_anchor / refold_in_progress while the fold is still climbing.
 *
 * The fixture arms a refold at boot height R, then advances the live tip to
 * R+N. A tick whose utxo_apply cursor reached only R must KEEP the refold
 * armed. The tick is given the live tip each call
 * (refold_tick_clear_against_live_tip) and raises the durable target to
 * MAX(stored, live_tip) before clearing.
 *
 * Hermetic: a throwaway :memory: progress.kv image. */

#include "test/test_core.h"

#include "jobs/refold_progress.h"
#include "jobs/reducer_frontier.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define RP_CHECK(name, expr) do {                                  \
    printf("refold_premature_clear: %s... ", (name));              \
    if (expr) { printf("OK\n"); }                                  \
    else { printf("FAIL\n"); failures++; }                         \
} while (0)

/* Model the reconcile tick's clear contract for a given LIVE tip, mirroring
 * detect_reducer_frontier_reconcile_light:
 *   1. bump the durable target up to the live tip (never lowers);
 *   2. clear iff utxo_apply has reached the (now-current) target. */
static bool refold_tick_clear_against_live_tip(sqlite3 *db, int32_t ua,
                                               int32_t live_tip)
{
#ifdef REPRO_UNFIXED_TICK
    (void)live_tip;  /* UNFIXED tick: no bump — clears against the frozen target */
#else
    (void)refold_progress_bump_target(db, live_tip);
#endif
    return refold_progress_clear_if_reached(db, ua, -1);
}

/* Decode the durable from-anchor target (LE int32) for assertions. Returns -1
 * when absent. */
static int32_t read_durable_target(sqlite3 *db)
{
    uint8_t tbuf[4] = {0};
    size_t tn = 0;
    bool tfound = false;
    progress_store_tx_lock();
    bool ok = progress_meta_get(db, REFOLD_FROM_ANCHOR_TARGET_KEY,
                                tbuf, sizeof(tbuf), &tn, &tfound);
    progress_store_tx_unlock();
    if (!ok || !tfound || tn != 4)
        return -1;
    return (int32_t)((uint32_t)tbuf[0] | ((uint32_t)tbuf[1] << 8) |
                     ((uint32_t)tbuf[2] << 16) | ((uint32_t)tbuf[3] << 24));
}

/* Arm a from-anchor refold with resume_target=R, then the chain advances to
 * R+N during the fold. utxo_apply has only reached R; the reconcile tick must
 * NOT clear the refold yet. */
static int case_advance_during_fold(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK)
        return 1;
    RP_CHECK("meta table ensure", progress_meta_table_ensure(db));

    refold_progress_test_set_cached(false);

    const int32_t R = 3151901;   /* the boot resume target (frozen at boot) */
    const int32_t N = 720;       /* blocks mined during the multi-hour fold */
    const int32_t live_tip = R + N;

    /* Arm the from-anchor refold at the boot height R. */
    RP_CHECK("mark from-anchor ok",
             refold_progress_mark_started_from_anchor(db, R));
    RP_CHECK("armed: from_anchor active", refold_from_anchor_active());
    RP_CHECK("armed: in_progress", refold_in_progress());
    RP_CHECK("armed: durable target == R", read_durable_target(db) == R);

    /* The chain has advanced to live_tip; the fold has only reached R. The
     * clear must NOT fire. */
    RP_CHECK("tick at ua=R is no-op ok",
             refold_tick_clear_against_live_tip(db, /*ua=*/R, live_tip));
    RP_CHECK("STILL from_anchor active (not prematurely cleared)",
             refold_from_anchor_active());
    RP_CHECK("STILL in_progress (not prematurely cleared)",
             refold_in_progress());
    RP_CHECK("durable target now tracks live_tip",
             read_durable_target(db) == live_tip);

    /* Intermediate progress below the live tip: still no clear. */
    RP_CHECK("tick at ua=live_tip-1 is no-op ok",
             refold_tick_clear_against_live_tip(db, live_tip - 1, live_tip));
    RP_CHECK("STILL from_anchor active at live_tip-1",
             refold_from_anchor_active());

    /* The fold genuinely REACHES the live tip — NOW it must clear (do not
     * over-correct into never-clearing). */
    RP_CHECK("tick at ua=live_tip fires the clear ok",
             refold_tick_clear_against_live_tip(db, live_tip, live_tip));
    RP_CHECK("cleared: from_anchor inactive", !refold_from_anchor_active());
    RP_CHECK("cleared: not in_progress", !refold_in_progress());

    refold_progress_test_set_cached(false);
    sqlite3_close(db);
    return failures;
}

/* The bump must never LOWER the durable target (the live tip can briefly read
 * stale/lower during a reorg-rollback window; the fold ceiling must not drop),
 * and must be inert when no from-anchor refold is armed. */
static int case_bump_invariants(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK)
        return 1;
    RP_CHECK("meta table ensure", progress_meta_table_ensure(db));
    refold_progress_test_set_cached(false);

    const int32_t R = 1000;
    RP_CHECK("mark from-anchor ok",
             refold_progress_mark_started_from_anchor(db, R));
    RP_CHECK("bump up to 2000 ok", refold_progress_bump_target(db, 2000));
    RP_CHECK("target == 2000", read_durable_target(db) == 2000);
    /* A lower live tip must NOT lower the target. */
    RP_CHECK("bump down to 1500 ok (inert)",
             refold_progress_bump_target(db, 1500));
    RP_CHECK("target stays 2000", read_durable_target(db) == 2000);

    /* Disarm, then bump must be inert (never resurrects the signal). */
    RP_CHECK("clear at 2000 disarms ok",
             refold_progress_clear_if_reached(db, 2000, -1));
    RP_CHECK("disarmed", !refold_from_anchor_active());
    RP_CHECK("bump while disarmed ok (inert)",
             refold_progress_bump_target(db, 9999));
    RP_CHECK("target absent while disarmed", read_durable_target(db) == -1);
    RP_CHECK("still disarmed after bump", !refold_from_anchor_active());

    refold_progress_test_set_cached(false);
    sqlite3_close(db);
    return failures;
}

/* A from-anchor refold to a resume target above the tip the boot seeded
 * (the finalize log ends above the coins-restored tip) is local work all the
 * way up: no height up to the target counts as chain progress. */
static int case_seeds_high_water(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK)
        return 1;
    RP_CHECK("meta table ensure", progress_meta_table_ensure(db));
    refold_progress_test_set_cached(false);
    reducer_frontier_test_reset_high_water();
    reducer_frontier_provable_tip_reset();
    reducer_frontier_provable_tip_seed_high_water(100);
    RP_CHECK("mark from-anchor ok",
             refold_progress_mark_started_from_anchor(db, 120));
    for (int32_t h = 1; h <= 120; h++)
        reducer_frontier_provable_tip_set(h);
    RP_CHECK("climb to the resume target stamps nothing",
             reducer_frontier_provable_tip_advance_age_ms() == -1);
    reducer_frontier_provable_tip_set(121);
    RP_CHECK("a height above the resume target does",
             reducer_frontier_provable_tip_advance_age_ms() >= 0);
    reducer_frontier_provable_tip_reset();
    reducer_frontier_test_reset_high_water();
    refold_progress_test_set_cached(false);
    sqlite3_close(db);
    return failures;
}

int test_refold_premature_clear(void)
{
    int failures = 0;
    failures += case_seeds_high_water();
    failures += case_advance_during_fold();
    failures += case_bump_invariants();
    if (failures == 0)
        printf("test_refold_premature_clear: ALL PASSED\n");
    else
        printf("test_refold_premature_clear: %d FAILURE(S)\n", failures);
    return failures;
}

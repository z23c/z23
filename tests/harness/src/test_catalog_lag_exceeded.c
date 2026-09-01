/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the catalog_lag_exceeded self-heal condition
 * (engine/conditions/src/catalog_lag_exceeded.c). Exercised via the ZCL_TESTING
 * hooks (synthetic completeness snapshots injected into the sustain evaluator)
 * so no live node / progress store is required:
 *
 *   - the two-consecutive-pass sustain (a single over-threshold blip never
 *     fires; the offending index is latched on the confirming pass);
 *   - a NOT-over pass re-arms (resets the sustain);
 *   - a disabled index over threshold never fires;
 *   - the remedy raises the typed named blocker "catalog.<index>.lag_exceeded"
 *     (non-destructive) and is countable;
 *   - registration + the rearm-forever cooldown posture.
 */

#include "test/test_core.h"

#include "conditions/catalog_lag_exceeded.h"
#include "framework/condition.h"
#include "storage/catalog_completeness.h"
#include "util/blocker.h"

#include <stdio.h>
#include <string.h>

#define CL_CHECK(name, expr) do { \
    printf("  catalog_lag_exceeded: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static struct catalog_index_status cl_row(const char *name, int64_t cursor,
                                          int64_t target, int64_t lag,
                                          bool enabled)
{
    struct catalog_index_status r;
    memset(&r, 0, sizeof(r));
    r.name = name;
    r.cursor = cursor;
    r.target = target;
    r.lag = lag;
    r.enabled = enabled;
    return r;
}

int test_catalog_lag_exceeded(void)
{
    printf("\n=== catalog_lag_exceeded tests ===\n");
    int failures = 0;

    blocker_module_init();
    blocker_reset_for_testing();
    catalog_lag_exceeded_test_reset();

    /* One enabled index far over the 1000-block threshold, one enabled but
     * under it (must be ignored). */
    struct catalog_index_status rows[2];
    rows[0] = cl_row("txindex", 1000, 5000, 4000, true);
    rows[1] = cl_row("zslp_ledger", 4999, 5000, 1, true);   /* under threshold */

    /* Sustain: the first over-pass ARMS but does not fire. */
    CL_CHECK("first over-pass arms (no fire)",
             !catalog_lag_exceeded_test_feed(rows, 2));
    /* The second consecutive over-pass fires and latches the offending index. */
    CL_CHECK("second consecutive over-pass fires",
             catalog_lag_exceeded_test_feed(rows, 2));
    {
        const char *nm = catalog_lag_exceeded_test_lagging_name();
        CL_CHECK("latched lagging index == txindex (the worst over-threshold)",
                 nm && strcmp(nm, "txindex") == 0);
    }

    /* Remedy: non-destructive; raises the typed named blocker + is countable. */
    CL_CHECK("remedy returns COND_REMEDY_OK",
             catalog_lag_exceeded_test_remedy() == (int)COND_REMEDY_OK);
    CL_CHECK("remedy raised blocker catalog.txindex.lag_exceeded",
             blocker_exists("catalog.txindex.lag_exceeded"));
    CL_CHECK("remedy blocker class is DEPENDENCY",
             blocker_class_for("catalog.txindex.lag_exceeded") ==
                 BLOCKER_DEPENDENCY);
    CL_CHECK("remedy call counted once",
             catalog_lag_exceeded_test_remedy_calls() == 1);

    /* A NOT-over pass re-arms (resets the sustain). */
    {
        struct catalog_index_status ok_rows[1];
        ok_rows[0] = cl_row("txindex", 4999, 5000, 1, true);
        CL_CHECK("under-threshold pass does not fire",
                 !catalog_lag_exceeded_test_feed(ok_rows, 1));
        /* After the reset a single over-pass must ARM again (no immediate fire). */
        CL_CHECK("after re-arm, a single over-pass does not fire",
                 !catalog_lag_exceeded_test_feed(rows, 2));
    }

    /* An index far over threshold whose cursor ADVANCES every pass is healthy
     * from-genesis catch-up, not a stall: it must NOT fire no matter how many
     * passes (the live serve-node defect — a backfill folding one bounded batch
     * per tick sat 2.9M blocks behind H* for hours and tripped a stall-reading
     * dependency blocker while it was steadily advancing). */
    catalog_lag_exceeded_test_reset();
    {
        struct catalog_index_status adv[1];
        adv[0] = cl_row("address_index", 100000, 3000000, 2900000, true);
        CL_CHECK("advancing backfill: pass 1 arms (no fire)",
                 !catalog_lag_exceeded_test_feed(adv, 1));
        adv[0] = cl_row("address_index", 100128, 3000000, 2899872, true);
        CL_CHECK("advancing backfill: pass 2 advanced -> no fire",
                 !catalog_lag_exceeded_test_feed(adv, 1));
        adv[0] = cl_row("address_index", 100256, 3000000, 2899744, true);
        CL_CHECK("advancing backfill: pass 3 advanced -> still no fire",
                 !catalog_lag_exceeded_test_feed(adv, 1));
        /* Cursor now FREEZES (genuine wedge): the next pass sees no advance and
         * fires, naming the stalled index. */
        adv[0] = cl_row("address_index", 100256, 3000000, 2899744, true);
        CL_CHECK("frozen backfill: pass after freeze fires (real stall)",
                 catalog_lag_exceeded_test_feed(adv, 1));
        const char *fnm = catalog_lag_exceeded_test_lagging_name();
        CL_CHECK("latched frozen index == address_index",
                 fnm && strcmp(fnm, "address_index") == 0);
    }

    /* A frozen index whose fold guard has already named the STRUCTURAL
     * snapshot-seed floor must NOT also collect the misleading "stalled and
     * must resume" lag blocker (the 2026-07-27 live op_return_index case:
     * frozen at -1 on a seeded datadir — it can never resume, and the
     * below_snapshot_seed blocker is the truthful naming). */
    catalog_lag_exceeded_test_reset();
    blocker_reset_for_testing();
    {
        struct blocker_record sr;
        CL_CHECK("seed-floor blocker raised for op_return_index",
                 blocker_init(&sr, "op_return_index.below_snapshot_seed",
                              "op_return_index", BLOCKER_DEPENDENCY,
                              "test: structural seed floor") &&
                     blocker_set(&sr) == 0);
        struct catalog_index_status frz[1];
        frz[0] = cl_row("op_return_index", -1, 3195000, 3195001, true);
        CL_CHECK("frozen + seed-floor: pass 1 arms (no fire)",
                 !catalog_lag_exceeded_test_feed(frz, 1));
        CL_CHECK("frozen + seed-floor: pass 2 suppressed (structural named)",
                 !catalog_lag_exceeded_test_feed(frz, 1));
        CL_CHECK("frozen + seed-floor: pass 3 still suppressed",
                 !catalog_lag_exceeded_test_feed(frz, 1));
        CL_CHECK("no lag blocker raised alongside the structural one",
                 !blocker_exists("catalog.op_return_index.lag_exceeded"));
        /* Same freeze WITHOUT the seed blocker still fires (suppression is
         * specific, not a blanket freeze amnesty). Reset the arm state too:
         * the suppression path above deliberately leaves the index armed,
         * so without a reset the first feed here would fire immediately. */
        blocker_reset_for_testing();
        catalog_lag_exceeded_test_reset();
        CL_CHECK("frozen w/o seed-floor: pass re-arms",
                 !catalog_lag_exceeded_test_feed(frz, 1));
        CL_CHECK("frozen w/o seed-floor: fires (genuine stall)",
                 catalog_lag_exceeded_test_feed(frz, 1));
    }

    /* A DISABLED index over threshold never fires, no matter how many passes. */
    catalog_lag_exceeded_test_reset();
    {
        struct catalog_index_status dis[1];
        dis[0] = cl_row("txindex", 0, 5000, 5000, false);
        CL_CHECK("disabled over-threshold: pass 1 no fire",
                 !catalog_lag_exceeded_test_feed(dis, 1));
        CL_CHECK("disabled over-threshold: pass 2 no fire (never)",
                 !catalog_lag_exceeded_test_feed(dis, 1));
    }

    /* Registration + rearm-forever cooldown posture (peer_floor's shape). */
    condition_engine_reset_for_testing();
    register_catalog_lag_exceeded();
    CL_CHECK("registered in condition engine",
             condition_engine_has_registered("catalog_lag_exceeded"));
    {
        struct condition_runtime_snapshot snap;
        if (condition_engine_get_registered_snapshot("catalog_lag_exceeded",
                                                     &snap)) {
            CL_CHECK("severity == COND_WARN", snap.severity == COND_WARN);
            CL_CHECK("cooldown rearm-forever (600s, unbounded rearms)",
                     snap.cooldown_secs == 600 && snap.cooldown_max_rearms == 0);
            CL_CHECK("finite max_attempts before paging", snap.max_attempts == 5);
        } else {
            CL_CHECK("registered snapshot retrievable", false);
        }
    }

    blocker_reset_for_testing();
    catalog_lag_exceeded_test_reset();
    printf("catalog_lag_exceeded: %d failures\n", failures);
    return failures;
}

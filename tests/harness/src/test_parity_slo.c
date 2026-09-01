/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the standing consensus-parity SLO:
 *
 *   1. parity_slo_breach condition detector, fed synthetic mirror stats via
 *      legacy_mirror_sync_test_set_stats + a controllable clock
 *      (parity_slo_breach_test_set_now):
 *        - a clean agreeing sample never arms either signal;
 *        - a transient same-height hash disagreement (window not yet
 *          elapsed) does not fire;
 *        - a SUSTAINED hash disagreement (window elapsed) fires signal A;
 *        - a SUSTAINED oracle-unreachable window fires signal B;
 *        - the mirror not being configured (enabled=false) never fires and
 *          resets tracking;
 *        - a later clean sample re-arms (resets) the tracking so a fresh
 *          episode starts clean.
 *   2. remedy raises the typed named blocker "consensus.parity_slo_breach"
 *      (non-destructive) and witness clears it on one clean agreeing sample.
 *   3. registration + the rearm-forever cooldown posture (peer_floor's
 *      shape).
 *   4. the parity_samples model: insert + bounded-retention prune (the
 *      ring buffer the mirror's comparator writes one row to per tick).
 */

#include "test/test_core.h"

#include "conditions/parity_slo_breach.h"
#include "framework/condition.h"
#include "services/legacy_mirror_sync_service.h"
#include "models/parity_sample.h"
#include "models/database.h"
#include "util/blocker.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PS_CHECK(name, expr) do { \
    printf("  parity_slo: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static struct legacy_mirror_sync_stats ps_stats(bool enabled, bool reachable,
                                                bool comparison_known,
                                                bool comparison_hashes_agree,
                                                int comparison_height,
                                                int local_height,
                                                int legacy_height)
{
    struct legacy_mirror_sync_stats s;
    memset(&s, 0, sizeof(s));
    s.enabled = enabled;
    s.reachable = reachable;
    s.comparison_known = comparison_known;
    s.comparison_hashes_agree = comparison_hashes_agree;
    s.comparison_height = comparison_height;
    s.local_height = local_height;
    s.legacy_height = legacy_height;
    return s;
}

static int test_detector(void)
{
    int failures = 0;
    printf("parity_slo_breach: detector on synthetic sample sequences...\n");

    legacy_mirror_sync_reset_for_test();
    parity_slo_breach_test_reset();

    /* ── agree: never arms ──────────────────────────────────────────── */
    parity_slo_breach_test_set_now(1000);
    for (int i = 0; i < 5; i++) {
        struct legacy_mirror_sync_stats s =
            ps_stats(true, true, true, true, 100 + i, 100 + i, 100 + i);
        legacy_mirror_sync_test_set_stats(&s, NULL);
        parity_slo_breach_test_set_now(1000 + i * 400);
        PS_CHECK("agree: never fires", !parity_slo_breach_test_detect());
    }

    /* ── disagree-transient: window not yet elapsed ───────────────────── */
    parity_slo_breach_test_reset();
    parity_slo_breach_test_set_now(5000);
    {
        struct legacy_mirror_sync_stats s =
            ps_stats(true, true, true, false, 200, 200, 205);
        legacy_mirror_sync_test_set_stats(&s, NULL);
        PS_CHECK("disagree: arms but does not fire immediately",
                 !parity_slo_breach_test_detect());
        parity_slo_breach_test_set_now(5000 + 1799);
        PS_CHECK("disagree: 1 second short of window still does not fire",
                 !parity_slo_breach_test_detect());
    }

    /* ── disagree-sustained: window elapsed -> fires signal A ─────────── */
    parity_slo_breach_test_set_now(5000 + 1800);
    {
        struct legacy_mirror_sync_stats s =
            ps_stats(true, true, true, false, 200, 200, 205);
        legacy_mirror_sync_test_set_stats(&s, NULL);
        PS_CHECK("disagree: sustained 30min fires", parity_slo_breach_test_detect());
    }

    /* ── unreachable-sustained: fires signal B ─────────────────────────── */
    parity_slo_breach_test_reset();
    parity_slo_breach_test_set_now(9000);
    {
        struct legacy_mirror_sync_stats s =
            ps_stats(true, false, false, false, -1, 300, -1);
        legacy_mirror_sync_test_set_stats(&s, NULL);
        PS_CHECK("unreachable: arms but does not fire immediately",
                 !parity_slo_breach_test_detect());
        parity_slo_breach_test_set_now(9000 + 1800);
        PS_CHECK("unreachable: sustained 30min fires",
                 parity_slo_breach_test_detect());
    }

    /* ── not configured: never fires, resets tracking ──────────────────── */
    parity_slo_breach_test_reset();
    parity_slo_breach_test_set_now(20000);
    {
        struct legacy_mirror_sync_stats s =
            ps_stats(false, false, false, false, -1, 400, -1);
        legacy_mirror_sync_test_set_stats(&s, NULL);
        PS_CHECK("disabled: pass 1 no fire", !parity_slo_breach_test_detect());
        parity_slo_breach_test_set_now(20000 + 5000);
        PS_CHECK("disabled: pass 2 (well past any window) still no fire",
                 !parity_slo_breach_test_detect());
    }

    /* ── a later clean sample re-arms tracking for a fresh episode ─────── */
    parity_slo_breach_test_reset();
    parity_slo_breach_test_set_now(30000);
    {
        struct legacy_mirror_sync_stats bad =
            ps_stats(true, true, true, false, 500, 500, 505);
        legacy_mirror_sync_test_set_stats(&bad, NULL);
        (void)parity_slo_breach_test_detect(); /* arm */
        parity_slo_breach_test_set_now(30000 + 500);
        struct legacy_mirror_sync_stats clean =
            ps_stats(true, true, true, true, 510, 510, 510);
        legacy_mirror_sync_test_set_stats(&clean, NULL);
        PS_CHECK("clean sample resets tracking (no fire)",
                 !parity_slo_breach_test_detect());
        /* Even after the ORIGINAL window would have elapsed, no fire —
         * the disagreement episode was reset, not just paused. */
        parity_slo_breach_test_set_now(30000 + 1900);
        struct legacy_mirror_sync_stats still_bad =
            ps_stats(true, true, true, false, 600, 600, 605);
        legacy_mirror_sync_test_set_stats(&still_bad, NULL);
        PS_CHECK("fresh disagreement must accumulate its own window",
                 !parity_slo_breach_test_detect());
    }

    parity_slo_breach_test_reset();
    legacy_mirror_sync_reset_for_test();
    printf("parity_slo_breach detector: %d failures\n", failures);
    return failures;
}

static int test_remedy_witness_registration(void)
{
    int failures = 0;
    printf("parity_slo_breach: remedy + witness + registration...\n");

    blocker_module_init();
    blocker_reset_for_testing();
    legacy_mirror_sync_reset_for_test();
    parity_slo_breach_test_reset();

    /* Force a sustained hash disagreement, then detect + remedy. */
    parity_slo_breach_test_set_now(1000);
    struct legacy_mirror_sync_stats bad =
        ps_stats(true, true, true, false, 700, 700, 705);
    legacy_mirror_sync_test_set_stats(&bad, NULL);
    (void)parity_slo_breach_test_detect();
    parity_slo_breach_test_set_now(1000 + 1800);
    legacy_mirror_sync_test_set_stats(&bad, NULL);
    PS_CHECK("sustained disagreement fires", parity_slo_breach_test_detect());

    condition_engine_reset_for_testing();
    register_parity_slo_breach();
    PS_CHECK("registered in condition engine",
             condition_engine_has_registered("parity_slo_breach"));
    {
        struct condition_runtime_snapshot snap;
        if (condition_engine_get_registered_snapshot("parity_slo_breach",
                                                      &snap)) {
            PS_CHECK("severity == COND_WARN", snap.severity == COND_WARN);
            PS_CHECK("cooldown rearm-forever (600s, unbounded rearms)",
                     snap.cooldown_secs == 600 && snap.cooldown_max_rearms == 0);
            PS_CHECK("finite max_attempts before paging", snap.max_attempts == 1);
        } else {
            PS_CHECK("registered snapshot retrievable", false);
        }
    }

    /* Drive detect/remedy/witness directly via the engine tick, since the
     * condition's remedy/witness are file-static (not test-exported —
     * matching net_partition_suspected's shape: only detect is exported). */
    condition_engine_tick();
    PS_CHECK("engine remedy raised the named blocker",
             blocker_exists("consensus.parity_slo_breach"));

    /* Clean sample resolves it: witness clears the blocker on next tick. */
    struct legacy_mirror_sync_stats clean =
        ps_stats(true, true, true, true, 710, 710, 710);
    legacy_mirror_sync_test_set_stats(&clean, NULL);
    condition_engine_tick();
    PS_CHECK("clean sample clears the blocker",
             !blocker_exists("consensus.parity_slo_breach"));

    blocker_reset_for_testing();
    condition_engine_reset_for_testing();
    parity_slo_breach_test_reset();
    legacy_mirror_sync_reset_for_test();
    printf("parity_slo_breach remedy/witness/registration: %d failures\n",
           failures);
    return failures;
}

static struct db_parity_sample ps_sample(int64_t ts, int64_t our_h,
                                         int64_t oracle_h, int64_t eq_at,
                                         int hash_eq, int reachable)
{
    struct db_parity_sample s;
    memset(&s, 0, sizeof(s));
    s.ts = ts;
    s.our_height = our_h;
    s.oracle_height = oracle_h;
    s.heights_equal_at = eq_at;
    s.hash_equal = hash_eq;
    s.oracle_reachable = reachable;
    return s;
}

static int test_ring_buffer_cap(void)
{
    int failures = 0;
    printf("parity_sample: ring-buffer bounded retention...\n");

    char dbdir[256];
    char dbpath[320];
    struct node_db ndb;
    test_make_tmpdir(dbdir, sizeof(dbdir), "paritysample", "ring");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
    memset(&ndb, 0, sizeof(ndb));

    if (node_db_open(&ndb, dbpath)) {
        for (int i = 0; i < 30; i++) {
            struct db_parity_sample s =
                ps_sample(1000 + i, 100 + i, 100 + i, 100 + i, 1, 1);
            PS_CHECK("save", db_parity_sample_save(&ndb, &s));
        }
        PS_CHECK("count == 30 before prune",
                 db_parity_sample_count(&ndb) == 30);

        PS_CHECK("prune to newest 10", db_parity_sample_prune(&ndb, 10));
        PS_CHECK("count == 10 after prune",
                 db_parity_sample_count(&ndb) == 10);

        struct db_parity_sample out[10];
        int n = db_parity_sample_recent(&ndb, out, 10);
        PS_CHECK("recent returns 10 rows", n == 10);
        PS_CHECK("newest-first: ts == 1029 (row 29)", out[0].ts == 1029);
        PS_CHECK("newest-first: our_height == 129", out[0].our_height == 129);

        /* pruning to a larger N than present is a no-op success */
        PS_CHECK("prune above count is a no-op success",
                 db_parity_sample_prune(&ndb, 1000));
        PS_CHECK("count unchanged at 10",
                 db_parity_sample_count(&ndb) == 10);

        node_db_close(&ndb);
    } else {
        printf("  FAIL: node_db_open\n");
        failures++;
    }

    test_cleanup_tmpdir(dbdir);
    printf("parity_sample ring buffer: %d failures\n", failures);
    return failures;
}

int test_parity_slo(void)
{
    printf("\n=== parity_slo tests ===\n");
    int failures = 0;
    failures += test_detector();
    failures += test_remedy_witness_registration();
    failures += test_ring_buffer_cap();
    printf("parity_slo: %d total failures\n", failures);
    return failures;
}

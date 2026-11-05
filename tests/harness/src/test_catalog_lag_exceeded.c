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
#include "controllers/diagnostics_internal.h"
#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "storage/catalog_completeness.h"
#include "storage/progress_store.h"
#include "json/json.h"
#include <pthread.h>
#include <errno.h>
#include <time.h>
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

struct cl_lock_holder {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int state;
};

static void *cl_hold_progress_lock(void *arg)
{
    struct cl_lock_holder *h = arg;
    progress_store_tx_lock();
    pthread_mutex_lock(&h->mutex);
    h->state = 1;
    pthread_cond_signal(&h->cond);
    struct timespec deadline;
    timespec_get(&deadline, TIME_UTC);
    deadline.tv_sec += 2;
    while (h->state == 1) {
        if (pthread_cond_timedwait(&h->cond, &h->mutex, &deadline) == ETIMEDOUT) {
            h->state = 3; /* regression escape: release, then fail the assertion */
            break;
        }
    }
    pthread_mutex_unlock(&h->mutex);
    progress_store_tx_unlock();
    return NULL;
}

static int cl_test_progress_contention(const struct catalog_index_status *rows,
                                        size_t row_count)
{
    int failures = 0;
    /* Another thread retains the recursive progress mutex until every busy
     * observation returns. This proves yielding rather than eventual release. */
    {
        struct cl_lock_holder h = {
            PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0
        };
        pthread_t thread;
        int rc = pthread_create(&thread, NULL, cl_hold_progress_lock, &h);
        CL_CHECK("contention helper starts", rc == 0);
        if (rc == 0) {
            pthread_mutex_lock(&h.mutex);
            while (h.state == 0)
                pthread_cond_wait(&h.cond, &h.mutex);
            pthread_mutex_unlock(&h.mutex);
            struct catalog_index_status busy_rows[CATALOG_COMPLETENESS_MAX_INDEXES];
            size_t n = 99;
            CL_CHECK("snapshot explicitly unavailable under contention",
                     !catalog_completeness_snapshot_try(busy_rows,
                         CATALOG_COMPLETENESS_MAX_INDEXES, 5000, &n) && n == 0);
            CL_CHECK("live detect yields", !catalog_lag_exceeded_test_detect_live());
            CL_CHECK("busy detect preserves armed sustain",
                     catalog_lag_exceeded_test_feed(rows, row_count));
            CL_CHECK("live witness yields", !catalog_lag_exceeded_test_witness_live());
            CL_CHECK("busy witness preserves pending blocker",
                     blocker_exists("catalog.txindex.lag_exceeded"));
            struct json_value out;
            json_init(&out);
            CL_CHECK("coverage diagnostic returns while lock remains held",
                     catalog_coverage_dump_state_json(&out, NULL));
            const struct json_value *status = json_get(&out, "snapshot_status");
            CL_CHECK("coverage diagnostic names busy observation",
                     status && json_get_str(status) && strcmp(json_get_str(status), "progress_store_busy") == 0);
            CL_CHECK("busy observation never claims complete coverage",
                     json_get(&out, "complete_coverage_count") == NULL);
            json_free(&out);
            json_init(&out);
            CL_CHECK("omniscience returns while progress lock remains held",
                     omniscience_dump_state_json(&out, NULL));
            status = json_get(&out, "snapshot_status");
            CL_CHECK("omniscience reports explicit busy snapshot",
                     status && json_get_str(status) &&
                     strcmp(json_get_str(status), "progress_store_busy") == 0);
            const struct json_value *verdict = json_get(&out, "verdict");
            CL_CHECK("omniscience busy verdict is unknown",
                     verdict && json_get_str(verdict) &&
                     strcmp(json_get_str(verdict), "unknown: progress store busy") == 0);
            CL_CHECK("omniscience omits completeness claims when busy",
                     json_get(&out, "indexes") == NULL &&
                     json_get(&out, "worst_lag") == NULL);
            json_free(&out);

            pthread_mutex_lock(&h.mutex);
            CL_CHECK("all observations returned before holder released", h.state == 1);
            h.state = 2;
            pthread_cond_signal(&h.cond);
            pthread_mutex_unlock(&h.mutex);
            pthread_join(thread, NULL);
            CL_CHECK("snapshot recovers after release",
                     catalog_completeness_snapshot_try(busy_rows,
                         CATALOG_COMPLETENESS_MAX_INDEXES, 5000, &n) && n > 0);
        }
        pthread_cond_destroy(&h.cond);
        pthread_mutex_destroy(&h.mutex);
    }

    return failures;
}

/* ── Seeding-mutant tests: threshold, latch, witness and dump contracts ──
 * "no_such_idx" is a name the live catalog never reports, so the live
 * witness reads cursor_now == -1 for it: the advance test is then decided
 * purely by the cursor recorded at detect. */

static bool cl_fire(const char *name, int64_t cursor)
{
    struct catalog_index_status r[1];
    r[0] = cl_row(name, cursor, cursor + 5000, 5000, true);
    return !catalog_lag_exceeded_test_feed(r, 1) &&
           catalog_lag_exceeded_test_feed(r, 1);
}

/* Fresh latch, fire for no_such_idx at `cursor`, raise its blocker. */
static bool cl_fire_and_raise(int64_t cursor)
{
    blocker_reset_for_testing();
    catalog_lag_exceeded_test_reset();
    return cl_fire("no_such_idx", cursor) &&
           catalog_lag_exceeded_test_remedy() == (int)COND_REMEDY_OK;
}

static int cl_registered_budget_case(void)
{
    int failures = 0;
    condition_engine_reset_for_testing();
    register_catalog_lag_exceeded();
    struct condition_runtime_snapshot s;
    memset(&s, 0, sizeof(s));
    bool got = condition_engine_get_registered_snapshot("catalog_lag_exceeded",
                                                        &s);
    CL_CHECK("registered snapshot retrievable", got);
    CL_CHECK("poll interval is 5s", s.poll_secs == 5);
    CL_CHECK("remedy backoff is 60s", s.backoff_secs == 60);
    CL_CHECK("witness window is 60s", s.witness_window_secs == 60);
    return failures;
}

static int cl_threshold_boundary_case(void)
{
    int failures = 0;
    catalog_lag_exceeded_test_reset();
    struct catalog_index_status at[1];
    at[0] = cl_row("thr_idx", 10, 1010, 1000, true);
    bool a1 = catalog_lag_exceeded_test_feed(at, 1);
    bool a2 = catalog_lag_exceeded_test_feed(at, 1);
    bool a3 = catalog_lag_exceeded_test_feed(at, 1);
    CL_CHECK("lag exactly 1000 never fires", !a1 && !a2 && !a3);
    struct catalog_index_status over[1];
    over[0] = cl_row("thr_idx", 10, 1011, 1001, true);
    CL_CHECK("lag 1001 arms on the first pass",
             !catalog_lag_exceeded_test_feed(over, 1));
    CL_CHECK("lag 1001 fires on the second frozen pass",
             catalog_lag_exceeded_test_feed(over, 1));
    return failures;
}

static int cl_reset_clears_latch_case(void)
{
    int failures = 0;
    catalog_lag_exceeded_test_reset();
    blocker_reset_for_testing();
    bool fired = cl_fire("no_such_idx", 7);
    int r1 = catalog_lag_exceeded_test_remedy();
    int r2 = catalog_lag_exceeded_test_remedy();
    CL_CHECK("fired and remedied twice",
             fired && r1 == (int)COND_REMEDY_OK && r2 == (int)COND_REMEDY_OK);
    CL_CHECK("remedy calls are counted exactly",
             catalog_lag_exceeded_test_remedy_calls() == 2);
    catalog_lag_exceeded_test_reset();
    CL_CHECK("reset forgets the latched index",
             catalog_lag_exceeded_test_lagging_name() == NULL);
    CL_CHECK("reset zeroes the remedy count",
             catalog_lag_exceeded_test_remedy_calls() == 0);
    CL_CHECK("remedy with nothing latched skips",
             catalog_lag_exceeded_test_remedy() == (int)COND_REMEDY_SKIP);
    CL_CHECK("a skipped remedy is not counted",
             catalog_lag_exceeded_test_remedy_calls() == 0);
    CL_CHECK("witness with nothing latched is satisfied",
             catalog_lag_exceeded_test_witness_live());
    return failures;
}

static int cl_remedy_blocker_text_case(void)
{
    int failures = 0;
    bool raised = cl_fire_and_raise(-2);
    struct blocker_snapshot b;
    memset(&b, 0, sizeof(b));
    bool found = blocker_find_by_id_prefix("catalog.no_such_idx.lag_exceeded",
                                           &b);
    CL_CHECK("remedy raised the named blocker", raised && found);
    CL_CHECK("reason names the index and the 1000-block threshold",
             strstr(b.reason, "index no_such_idx is > 1000 blocks behind H*")
                 != NULL);
    CL_CHECK("reason names the frozen cursor",
             strstr(b.reason, "frozen at -2 across the poll interval") != NULL);
    CL_CHECK("the blocker never auto-escapes", b.escape_deadline_us == 0);
    return failures;
}

static int cl_witness_cursor_boundary_case(void)
{
    int failures = 0;
    /* cursor_now is -1 for an unknown name. Detected at -1: no advance. */
    bool eq = cl_fire_and_raise(-1);
    bool w_eq = catalog_lag_exceeded_test_witness_live();
    CL_CHECK("cursor equal to the detect cursor is not an advance",
             eq && !w_eq && blocker_exists("catalog.no_such_idx.lag_exceeded"));
    /* Detected at -2: cursor_now -1 advanced by one and clears the blocker. */
    bool lo = cl_fire_and_raise(-2);
    bool w_lo = catalog_lag_exceeded_test_witness_live();
    CL_CHECK("a one-step advance witnesses and clears the blocker",
             lo && w_lo && !blocker_exists("catalog.no_such_idx.lag_exceeded"));
    /* Detected far ahead of anything live: stays unwitnessed, blocker kept. */
    bool hi = cl_fire_and_raise(5000000000LL);
    bool w_hi = catalog_lag_exceeded_test_witness_live();
    CL_CHECK("a cursor behind the detect cursor is unwitnessed and keeps the blocker",
             hi && !w_hi && blocker_exists("catalog.no_such_idx.lag_exceeded"));
    return failures;
}

static int cl_witness_seed_floor_case(void)
{
    int failures = 0;
    bool raised = cl_fire_and_raise(5000000000LL);
    struct blocker_record sr;
    bool seeded = blocker_init(&sr, "no_such_idx.below_snapshot_seed",
                               "no_such_idx", BLOCKER_DEPENDENCY,
                               "test: structural seed floor") &&
                  blocker_set(&sr) == 0;
    CL_CHECK("lag blocker and seed-floor blocker both raised",
             raised && seeded &&
                 blocker_exists("catalog.no_such_idx.lag_exceeded"));
    CL_CHECK("a named seed floor satisfies the witness",
             catalog_lag_exceeded_test_witness_live());
    CL_CHECK("and supersedes the lag blocker",
             !blocker_exists("catalog.no_such_idx.lag_exceeded"));
    return failures;
}

static int cl_suppression_rearms_case(void)
{
    int failures = 0;
    blocker_reset_for_testing();
    catalog_lag_exceeded_test_reset();
    struct blocker_record sr;
    bool seeded = blocker_init(&sr, "sup_idx.below_snapshot_seed", "sup_idx",
                               BLOCKER_DEPENDENCY, "test: structural seed floor") &&
                  blocker_set(&sr) == 0;
    struct catalog_index_status frz[1];
    frz[0] = cl_row("sup_idx", -1, 5000, 5001, true);
    bool p1 = catalog_lag_exceeded_test_feed(frz, 1);
    bool p2 = catalog_lag_exceeded_test_feed(frz, 1);
    CL_CHECK("seed floor suppresses a frozen index", seeded && !p1 && !p2);
    blocker_clear("sup_idx.below_snapshot_seed");
    CL_CHECK("after the floor clears, the first pass re-arms only",
             !catalog_lag_exceeded_test_feed(frz, 1));
    CL_CHECK("and the next frozen pass fires",
             catalog_lag_exceeded_test_feed(frz, 1));
    return failures;
}

static int cl_busy_observation_case(void)
{
    int failures = 0;
    bool raised = cl_fire_and_raise(-5);
    struct cl_lock_holder h = {
        PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0
    };
    pthread_t thread;
    int rc = pthread_create(&thread, NULL, cl_hold_progress_lock, &h);
    CL_CHECK("contention helper starts", raised && rc == 0);
    if (rc != 0)
        return failures;
    pthread_mutex_lock(&h.mutex);
    while (h.state == 0)
        pthread_cond_wait(&h.cond, &h.mutex);
    pthread_mutex_unlock(&h.mutex);
    bool w = catalog_lag_exceeded_test_witness_live();
    bool kept = blocker_exists("catalog.no_such_idx.lag_exceeded");
    struct json_value out;
    json_init(&out);
    bool dumped = catalog_coverage_dump_state_json(&out, NULL);
    const struct json_value *sc = json_get(&out, "snapshot_complete");
    const struct json_value *rt = json_get(&out, "retryable");
    bool incomplete = sc && !json_get_bool(sc);
    bool retry = rt && json_get_bool(rt);
    json_free(&out);
    pthread_mutex_lock(&h.mutex);
    h.state = 2;
    pthread_cond_signal(&h.cond);
    pthread_mutex_unlock(&h.mutex);
    pthread_join(thread, NULL);
    pthread_cond_destroy(&h.cond);
    pthread_mutex_destroy(&h.mutex);
    CL_CHECK("a busy witness never clears on a would-be advance", !w && kept);
    CL_CHECK("busy dump says incomplete and retryable",
             dumped && incomplete && retry);
    return failures;
}

static bool cl_dump_row_matches(const struct json_value *row,
                                const struct catalog_index_status *s)
{
    const char *name = json_get_str(json_get(row, "name"));
    const char *cov = json_get_str(json_get(row, "coverage"));
    bool ok = name && s->name && strcmp(name, s->name) == 0;
    ok = ok && json_get_bool(json_get(row, "enabled")) == s->enabled;
    ok = ok && json_get_bool(json_get(row, "always_on")) == s->always_on;
    ok = ok && json_get_int(json_get(row, "cursor")) == s->cursor;
    ok = ok && json_get_int(json_get(row, "floor")) == s->floor;
    ok = ok && json_get_int(json_get(row, "target")) == s->target;
    ok = ok && json_get_int(json_get(row, "lag")) == s->lag;
    ok = ok && cov && strcmp(cov, catalog_coverage_name(
                         (enum catalog_coverage)s->coverage)) == 0;
    ok = ok && json_get_bool(json_get(row, "emptiness_is_meaningful")) ==
               catalog_index_emptiness_is_meaningful(s);
    return ok;
}

static int cl_dump_rows_mismatched(const struct json_value *arr,
                                   const struct catalog_index_status *rows,
                                   size_t n)
{
    int bad = 0;
    for (size_t i = 0; i < n; i++)
        if (!cl_dump_row_matches(json_at(arr, i), &rows[i]))
            bad++;
    return bad;
}

static int cl_dump_matches_snapshot_case(void)
{
    int failures = 0;
    struct json_value none;
    json_init(&none);
    CL_CHECK("dump without an output object refuses",
             !catalog_coverage_dump_state_json(NULL, NULL));
    json_free(&none);

    int64_t hstar = (int64_t)reducer_frontier_provable_tip_cached();
    struct catalog_index_status rows[CATALOG_COMPLETENESS_MAX_INDEXES];
    size_t n = catalog_completeness_snapshot(
        rows, CATALOG_COMPLETENESS_MAX_INDEXES, hstar);
    struct json_value out;
    json_init(&out);
    bool dumped = catalog_coverage_dump_state_json(&out, NULL);
    const struct json_value *st = json_get(&out, "snapshot_status");
    const struct json_value *sc = json_get(&out, "snapshot_complete");
    CL_CHECK("a live dump reports a complete available snapshot",
             dumped && n > 0 && sc && json_get_bool(sc) && st &&
                 strcmp(json_get_str(st), "available") == 0);
    CL_CHECK("target height and index count come from the snapshot",
             json_get_int(json_get(&out, "target_height")) == hstar &&
                 json_get_int(json_get(&out, "index_count")) == (int64_t)n);
    int64_t enabled = 0, meaningful = 0;
    for (size_t i = 0; i < n; i++) {
        if (!rows[i].enabled)
            continue;
        enabled++;
        if (catalog_index_emptiness_is_meaningful(&rows[i]))
            meaningful++;
    }
    CL_CHECK("enabled and complete-coverage headlines are exact",
             json_get_int(json_get(&out, "enabled_count")) == enabled &&
                 json_get_int(json_get(&out, "complete_coverage_count")) ==
                     meaningful);
    const struct json_value *arr = json_get(&out, "indexes");
    CL_CHECK("one array row per index",
             arr && json_size(arr) == n);
    CL_CHECK("every row carries the snapshot's exact fields",
             arr && json_size(arr) == n &&
                 cl_dump_rows_mismatched(arr, rows, n) == 0);
    json_free(&out);
    return failures;
}

static int cl_live_detect_quiet_case(void)
{
    int failures = 0;
    catalog_lag_exceeded_test_reset();
    CL_CHECK("a quiet live catalog does not fire on its first pass",
             !catalog_lag_exceeded_test_detect_live());
    return failures;
}

static int cl_mutant_tests(void)
{
    int failures = 0;
    failures += cl_registered_budget_case();
    failures += cl_threshold_boundary_case();
    failures += cl_reset_clears_latch_case();
    failures += cl_remedy_blocker_text_case();
    failures += cl_witness_cursor_boundary_case();
    failures += cl_witness_seed_floor_case();
    failures += cl_suppression_rearms_case();
    failures += cl_busy_observation_case();
    failures += cl_dump_matches_snapshot_case();
    failures += cl_live_detect_quiet_case();
    return failures;
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

    failures += cl_test_progress_contention(rows, 2);

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
     * catch-up, not a stall: it must NOT fire however many passes. */
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
     * must resume" lag blocker (it can never resume). */
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
        /* The same freeze WITHOUT the seed blocker still fires (suppression
         * is specific). Reset the arm state too: the suppression path leaves
         * the index armed. */
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
    failures += cl_mutant_tests();

    blocker_reset_for_testing();
    catalog_lag_exceeded_test_reset();
    printf("catalog_lag_exceeded: %d failures\n", failures);
    return failures;
}

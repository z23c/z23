/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for body_coverage: the pure range algebra (insert/remove/contains/
 * find-first-hole/total), the bounded scan, progress_meta persistence, the
 * gap-fill scheduler (plan / no-source blocker), and a fixture that drives a
 * synthetic coverage hole through the real download manager (enqueue →
 * assign → receive → note_stored → hole closes). */

#include "test/test_core.h"

#include "storage/body_coverage.h"
#include "storage/progress_store.h"
#include "net/download.h"
#include "core/uint256.h"

#include <sqlite3.h>
#include <string.h>
#include <stdio.h>

/* ── Pure range algebra ─────────────────────────────────────────── */

static int test_bc_insert_disjoint_and_merge(void)
{
    int failures = 0;
    TEST("insert: disjoint, overlap, and adjacency all normalize") {
        struct body_coverage_map m;
        body_coverage_init(&m);

        /* Two disjoint ranges. */
        ASSERT(body_coverage_insert(&m, 10, 20));
        ASSERT(body_coverage_insert(&m, 40, 50));
        ASSERT(body_coverage_range_count(&m) == 2);

        /* Adjacent on the right of the first (21 touches 20 -> merge). */
        ASSERT(body_coverage_insert(&m, 21, 30));
        ASSERT(body_coverage_range_count(&m) == 2);
        ASSERT(body_coverage_contains(&m, 25));

        /* A range that bridges the two remaining ranges -> single range. */
        ASSERT(body_coverage_insert(&m, 31, 39));
        ASSERT(body_coverage_range_count(&m) == 1);
        ASSERT(body_coverage_total_covered(&m) == 41); /* 10..50 inclusive */
        ASSERT(body_coverage_max_covered(&m) == 50);

        /* Re-inserting a fully-covered sub-range is a no-op. */
        ASSERT(body_coverage_insert(&m, 15, 45));
        ASSERT(body_coverage_range_count(&m) == 1);
        ASSERT(body_coverage_total_covered(&m) == 41);

        /* Invalid / empty inserts are benign no-ops. */
        ASSERT(body_coverage_insert(&m, 100, 50));  /* lo > hi */
        ASSERT(body_coverage_insert(&m, -5, -1));   /* negative */
        ASSERT(body_coverage_range_count(&m) == 1);

        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_insert_left_adjacency(void)
{
    int failures = 0;
    TEST("insert: adjacency on the left edge merges") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        ASSERT(body_coverage_insert(&m, 100, 200));
        /* [90,99] touches [100,..] on the left. */
        ASSERT(body_coverage_insert(&m, 90, 99));
        ASSERT(body_coverage_range_count(&m) == 1);
        ASSERT(body_coverage_contains(&m, 90));
        ASSERT(body_coverage_contains(&m, 200));
        ASSERT(body_coverage_total_covered(&m) == 111);
        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_remove_split_and_edges(void)
{
    int failures = 0;
    TEST("remove: split, left-clip, right-clip, full delete, no-op") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        ASSERT(body_coverage_insert(&m, 0, 100));

        /* Split down the middle -> [0,39] and [60,100]. */
        ASSERT(body_coverage_remove(&m, 40, 59));
        ASSERT(body_coverage_range_count(&m) == 2);
        ASSERT(!body_coverage_contains(&m, 50));
        ASSERT(body_coverage_contains(&m, 39));
        ASSERT(body_coverage_contains(&m, 60));
        ASSERT(body_coverage_total_covered(&m) == 40 + 41);

        /* Left-clip [0,39] -> [10,39]. */
        ASSERT(body_coverage_remove(&m, 0, 9));
        ASSERT(!body_coverage_contains(&m, 5));
        ASSERT(body_coverage_contains(&m, 10));

        /* Right-clip [60,100] -> [60,90]. */
        ASSERT(body_coverage_remove(&m, 91, 100));
        ASSERT(!body_coverage_contains(&m, 95));
        ASSERT(body_coverage_contains(&m, 90));

        /* Full delete of a whole range. */
        ASSERT(body_coverage_remove(&m, 10, 39));
        ASSERT(body_coverage_range_count(&m) == 1);
        ASSERT(!body_coverage_contains(&m, 20));

        /* No-op removes. */
        ASSERT(body_coverage_remove(&m, 1000, 2000));
        ASSERT(body_coverage_remove(&m, 50, 10)); /* lo > hi */
        ASSERT(body_coverage_range_count(&m) == 1);

        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_note_stored_pruned(void)
{
    int failures = 0;
    TEST("note_stored/note_pruned track single heights and coalesce") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        /* Store a contiguous run one height at a time -> one range. */
        for (int h = 5; h <= 9; h++)
            ASSERT(body_coverage_note_stored(&m, h));
        ASSERT(body_coverage_range_count(&m) == 1);
        ASSERT(body_coverage_total_covered(&m) == 5);

        /* Punch a hole. */
        ASSERT(body_coverage_note_pruned(&m, 7));
        ASSERT(body_coverage_range_count(&m) == 2);
        ASSERT(!body_coverage_contains(&m, 7));

        /* Re-store closes it back to one range. */
        ASSERT(body_coverage_note_stored(&m, 7));
        ASSERT(body_coverage_range_count(&m) == 1);
        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_find_first_hole(void)
{
    int failures = 0;
    TEST("find_first_hole across boundaries and clamping") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        struct bc_range hole;

        /* Empty map: the whole window is a hole. */
        ASSERT(body_coverage_find_first_hole(&m, 0, 10, &hole));
        ASSERT(hole.lo == 0 && hole.hi == 10);

        /* Coverage [0,99] and [200,299]; query [0,299] -> hole [100,199]. */
        ASSERT(body_coverage_insert(&m, 0, 99));
        ASSERT(body_coverage_insert(&m, 200, 299));
        ASSERT(body_coverage_find_first_hole(&m, 0, 299, &hole));
        ASSERT(hole.lo == 100 && hole.hi == 199);

        /* Query entirely inside covered range -> no hole. */
        ASSERT(!body_coverage_find_first_hole(&m, 10, 90, &hole));

        /* Query straddling the tail of coverage -> hole clamps to window. */
        ASSERT(body_coverage_find_first_hole(&m, 50, 150, &hole));
        ASSERT(hole.lo == 100 && hole.hi == 150);

        /* Hole at the start of the window. */
        ASSERT(body_coverage_find_first_hole(&m, 150, 250, &hole));
        ASSERT(hole.lo == 150 && hole.hi == 199);

        /* Hole past all coverage. */
        ASSERT(body_coverage_find_first_hole(&m, 300, 400, &hole));
        ASSERT(hole.lo == 300 && hole.hi == 400);

        /* Fully covered window -> false. */
        ASSERT(body_coverage_insert(&m, 100, 199));
        ASSERT(!body_coverage_find_first_hole(&m, 0, 299, &hole));

        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

static bool tbc_have_odd_tens(int64_t h, void *ctx)
{
    (void)ctx;
    /* have-data for [10,19] and [30,39] only. */
    return (h >= 10 && h <= 19) || (h >= 30 && h <= 39);
}

static int test_bc_scan_window(void)
{
    int failures = 0;
    TEST("scan_window coalesces contiguous have-data runs") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        size_t n = body_coverage_scan_window(&m, 0, 50, tbc_have_odd_tens, NULL);
        ASSERT(n == 20);
        ASSERT(body_coverage_range_count(&m) == 2);
        ASSERT(body_coverage_contains(&m, 15));
        ASSERT(body_coverage_contains(&m, 35));
        ASSERT(!body_coverage_contains(&m, 25));
        ASSERT(body_coverage_total_covered(&m) == 20);
        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Persistence ────────────────────────────────────────────────── */

static int test_bc_persistence_roundtrip(void)
{
    int failures = 0;
    TEST("save/load round-trips the coverage map through progress_meta") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "body_coverage", "main");
        bool opened = progress_store_open(dir);
        ASSERT(opened);
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        ASSERT(progress_meta_table_ensure(db));

        struct body_coverage_map m;
        body_coverage_init(&m);
        ASSERT(body_coverage_insert(&m, 0, 99));
        ASSERT(body_coverage_insert(&m, 200, 299));
        ASSERT(body_coverage_insert(&m, 3056759, 3155842));
        ASSERT(body_coverage_save(&m, db));

        struct body_coverage_map loaded;
        body_coverage_init(&loaded);
        /* Preload some stale ranges to prove load REPLACES, not merges. */
        ASSERT(body_coverage_insert(&loaded, 9000, 9999));
        ASSERT(body_coverage_load(&loaded, db));
        ASSERT(body_coverage_range_count(&loaded) == 3);
        ASSERT(body_coverage_total_covered(&loaded) ==
               body_coverage_total_covered(&m));
        ASSERT(body_coverage_contains(&loaded, 3100000));
        ASSERT(!body_coverage_contains(&loaded, 9500));

        /* A fresh key (delete) -> load clears to empty and succeeds. */
        ASSERT(progress_meta_delete(db, BODY_COVERAGE_META_KEY));
        ASSERT(body_coverage_load(&loaded, db));
        ASSERT(body_coverage_range_count(&loaded) == 0);

        body_coverage_free(&m);
        body_coverage_free(&loaded);
        progress_store_close();
        PASS();
    } _test_next:;
    return failures;
}

/* ── Scheduler ──────────────────────────────────────────────────── */

static int test_bc_scheduler_plan_and_blocker(void)
{
    int failures = 0;
    TEST("scheduler plans the first hole and latches the no-source blocker") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        ASSERT(body_coverage_insert(&m, 0, 99));
        ASSERT(body_coverage_insert(&m, 200, 299));

        struct body_coverage_scheduler s;
        body_coverage_scheduler_init(&s);

        struct bc_range hole;
        ASSERT(body_coverage_scheduler_plan(&s, &m, 0, 299, 1000, &hole));
        ASSERT(hole.lo == 100 && hole.hi == 199);
        ASSERT(s.has_active_hole);
        ASSERT(s.needed_lo == 0 && s.needed_hi == 299);

        /* No source can serve it -> latch fires once and stays. */
        body_coverage_scheduler_mark_no_source(&s, 1000);
        ASSERT(s.blocked_no_source);
        ASSERT(s.no_source_fires == 1);
        body_coverage_scheduler_mark_no_source(&s, 1005); /* idempotent */
        ASSERT(s.no_source_fires == 1);
        ASSERT(s.blocked_since_unix == 1000);

        /* Work gets enqueued -> latch clears. */
        body_coverage_scheduler_mark_enqueued(&s);
        ASSERT(!s.blocked_no_source);

        /* Fill the hole, replan -> no hole, latch stays clear. */
        ASSERT(body_coverage_insert(&m, 100, 199));
        body_coverage_scheduler_mark_no_source(&s, 1010);
        ASSERT(s.blocked_no_source);
        ASSERT(!body_coverage_scheduler_plan(&s, &m, 0, 299, 1010, &hole));
        ASSERT(!s.has_active_hole);
        ASSERT(!s.blocked_no_source); /* plan-fully-covered clears it */

        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_scheduler_fill_rate(void)
{
    int failures = 0;
    TEST("scheduler computes a per-second fill rate across plans") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        ASSERT(body_coverage_insert(&m, 0, 9)); /* 10 covered */

        struct body_coverage_scheduler s;
        body_coverage_scheduler_init(&s);
        struct bc_range hole;

        /* First plan seeds the baseline (no rate yet). */
        ASSERT(body_coverage_scheduler_plan(&s, &m, 0, 99, 1000, &hole));
        ASSERT(s.fill_rate_per_sec == 0.0);

        /* Add 20 covered heights over 10 seconds -> rate 2.0/s. */
        ASSERT(body_coverage_insert(&m, 10, 29));
        ASSERT(body_coverage_scheduler_plan(&s, &m, 0, 99, 1010, &hole));
        ASSERT(s.fill_rate_per_sec > 1.9 && s.fill_rate_per_sec < 2.1);

        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Fixture: drive a synthetic hole through the download manager ── */

/* Deterministic block hash for a height (distinct, non-null). */
static struct uint256 tbc_hash_for_height(int32_t h)
{
    struct uint256 out;
    memset(out.data, 0, 32);
    out.data[0] = (uint8_t)(h & 0xFF);
    out.data[1] = (uint8_t)((h >> 8) & 0xFF);
    out.data[2] = (uint8_t)((h >> 16) & 0xFF);
    out.data[31] = 0xC0; /* non-zero tail for probe-chain robustness */
    return out;
}

static int test_bc_gap_enqueue_drain_fixture(void)
{
    int failures = 0;
    TEST("a coverage hole is enqueued, drained via download mgr, and closes") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        ASSERT(body_coverage_insert(&m, 0, 99));
        ASSERT(body_coverage_insert(&m, 200, 299));

        struct body_coverage_scheduler s;
        body_coverage_scheduler_init(&s);

        /* Plan the hole the fold needs: [100,199] within needed [0,299]. */
        struct bc_range hole;
        ASSERT(body_coverage_scheduler_plan(&s, &m, 0, 299, 1, &hole));
        ASSERT(hole.lo == 100 && hole.hi == 199);

        /* Enqueue the hole as ranged work into the real download manager
         * (composing with its existing height-sorted queue; peer selection
         * untouched). */
        struct download_manager dm;
        dl_init(&dm);

        const int N = (int)(hole.hi - hole.lo + 1); /* 100 heights */
        struct uint256 hashes[100];
        int32_t heights[100];
        for (int i = 0; i < N; i++) {
            heights[i] = (int32_t)hole.lo + i;
            hashes[i] = tbc_hash_for_height(heights[i]);
        }
        size_t added = dl_queue_blocks(&dm, hashes, heights, (size_t)N);
        ASSERT(added == (size_t)N);
        body_coverage_scheduler_mark_enqueued(&s);
        ASSERT(!s.blocked_no_source);

        /* Assign to a peer (N <= DL_MAX_IN_FLIGHT_PER_PEER) and drain: the
         * queue is height-sorted ascending, so out[i] is height lo+i. As
         * each body "arrives", note it into coverage. */
        struct uint256 out[100];
        size_t assigned = dl_assign_to_peer(&dm, 1, out, (size_t)N);
        ASSERT(assigned == (size_t)N);
        for (size_t i = 0; i < assigned; i++) {
            uint32_t peer = dl_mark_received(&dm, &out[i]);
            ASSERT(peer == 1);
            ASSERT(uint256_eq(&out[i], &hashes[i])); /* ascending height */
            ASSERT(body_coverage_note_stored(&m, heights[i]));
        }

        /* Hole is closed: coverage is now contiguous [0,299]. */
        ASSERT(body_coverage_range_count(&m) == 1);
        ASSERT(!body_coverage_find_first_hole(&m, 0, 299, &hole));
        ASSERT(!body_coverage_scheduler_plan(&s, &m, 0, 299, 2, &hole));

        dl_free(&dm);
        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

int test_body_coverage(void)
{
    int failures = 0;
    failures += test_bc_insert_disjoint_and_merge();
    failures += test_bc_insert_left_adjacency();
    failures += test_bc_remove_split_and_edges();
    failures += test_bc_note_stored_pruned();
    failures += test_bc_find_first_hole();
    failures += test_bc_scan_window();
    failures += test_bc_persistence_roundtrip();
    failures += test_bc_scheduler_plan_and_blocker();
    failures += test_bc_scheduler_fill_rate();
    failures += test_bc_gap_enqueue_drain_fixture();
    return failures;
}

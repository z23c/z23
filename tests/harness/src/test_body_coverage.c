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
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdint.h>
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

static int test_bc_maximum_height_range_boundaries(void)
{
    int failures = 0;
    TEST("maximum-height ranges merge and count without overflow") {
        struct body_coverage_map m;
        struct bc_range hole;
        body_coverage_init(&m);

        ASSERT(body_coverage_insert(&m, 4, 7));
        ASSERT(body_coverage_insert(&m, 8, 9));
        ASSERT(body_coverage_range_count(&m) == 1);
        ASSERT(m.ranges[0].lo == 4 && m.ranges[0].hi == 9);

        body_coverage_reset(&m);
        ASSERT(body_coverage_insert(&m, 0, INT64_MAX - 1));
        ASSERT(body_coverage_insert(&m, INT64_MAX, INT64_MAX));
        ASSERT(body_coverage_range_count(&m) == 1);
        ASSERT(m.ranges[0].lo == 0 && m.ranges[0].hi == INT64_MAX);
        ASSERT(body_coverage_total_covered(&m) == INT64_MAX);
        ASSERT(!body_coverage_find_first_hole(&m, INT64_MAX - 1,
                                              INT64_MAX, &hole));

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

static int test_bc_persistence_rejects_over_cap_range_count(void)
{
    int failures = 0;
    TEST("load rejects an over-cap persisted range count") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "body_coverage", "over_cap");
        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        ASSERT(progress_meta_table_ensure(db));

        const uint32_t count = BODY_COVERAGE_PERSIST_MAX_RANGES + 1u;
        const size_t bytes = 3 * sizeof(uint32_t) +
            (size_t)count * 2 * sizeof(int64_t);
        uint8_t *blob = zcl_malloc(bytes, "test_body_coverage_over_cap");
        ASSERT(blob != NULL);
        memset(blob, 0, bytes);
        uint32_t header[] = { 0x42434f56u, 1u, count };
        memcpy(blob, header, sizeof(header));
        ASSERT(progress_meta_set(db, "body_coverage.over_cap", blob, bytes));
        free(blob);

        struct body_coverage_map m;
        body_coverage_init(&m);
        ASSERT(!body_coverage_load_key(&m, db, "body_coverage.over_cap"));
        ASSERT(body_coverage_range_count(&m) == 0);
        body_coverage_free(&m);
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

/* ── Mutation-gap coverage: exact boundaries of the range algebra ── */

static bool tbc_ranges_are(const struct body_coverage_map *m, size_t n,
                           const int64_t (*e)[2])
{
    if (body_coverage_range_count(m) != n)
        return false;
    for (size_t i = 0; i < n; i++)
        if (m->ranges[i].lo != e[i][0] || m->ranges[i].hi != e[i][1])
            return false;
    return true;
}

static int test_bc_insert_gap_and_adjacency_edges(void)
{
    int failures = 0;
    TEST("insert: a one-height gap stays two ranges, adjacency merges") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        ASSERT(body_coverage_insert(&m, 10, 20));
        ASSERT(body_coverage_insert(&m, 5, 8)); /* 9 missing */
        static const int64_t e1[][2] = { {5, 8}, {10, 20} };
        ASSERT(tbc_ranges_are(&m, 2, e1));
        ASSERT(body_coverage_insert(&m, 22, 25)); /* 21 missing */
        static const int64_t e2[][2] = { {5, 8}, {10, 20}, {22, 25} };
        ASSERT(tbc_ranges_are(&m, 3, e2));
        ASSERT(body_coverage_insert(&m, 9, 9)); /* bridges 8|10 */
        ASSERT(body_coverage_insert(&m, 21, 21)); /* bridges 20|22 */
        static const int64_t e3[][2] = { {5, 25} };
        ASSERT(tbc_ranges_are(&m, 1, e3));
        /* Height 0 is a valid single-height range and joins at 1. */
        ASSERT(body_coverage_insert(&m, 0, 0));
        static const int64_t e4[][2] = { {0, 0}, {5, 25} };
        ASSERT(tbc_ranges_are(&m, 2, e4));
        ASSERT(body_coverage_insert(&m, 1, 4));
        static const int64_t e5[][2] = { {0, 25} };
        ASSERT(tbc_ranges_are(&m, 1, e5));
        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_insert_extend_and_invalid(void)
{
    int failures = 0;
    TEST("insert: one-range extension both ways; invalid input is a no-op") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        ASSERT(!body_coverage_insert(NULL, 1, 2));
        ASSERT(!body_coverage_remove(NULL, 1, 2));
        ASSERT(body_coverage_insert(&m, 10, 20));
        ASSERT(body_coverage_insert(&m, 5, 12)); /* extends low side only */
        static const int64_t e1[][2] = { {5, 20} };
        ASSERT(tbc_ranges_are(&m, 1, e1));
        ASSERT(body_coverage_insert(&m, 18, 30)); /* extends high side only */
        static const int64_t e2[][2] = { {5, 30} };
        ASSERT(tbc_ranges_are(&m, 1, e2));
        ASSERT(body_coverage_insert(&m, 7, 7)); /* lo == hi is valid */
        ASSERT(body_coverage_insert(&m, 40, 40));
        static const int64_t e3[][2] = { {5, 30}, {40, 40} };
        ASSERT(tbc_ranges_are(&m, 2, e3));
        ASSERT(body_coverage_insert(&m, -1, 3)); /* negative lo: ignored */
        ASSERT(body_coverage_insert(&m, 9, 8));  /* lo > hi: ignored */
        ASSERT(tbc_ranges_are(&m, 2, e3));
        ASSERT(body_coverage_total_covered(&m) == 27);
        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_insert_collapse_with_tail(void)
{
    int failures = 0;
    TEST("insert: bridging several ranges keeps the head and tail intact") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        for (int64_t i = 0; i < 5; i++)
            ASSERT(body_coverage_insert(&m, i * 10, i * 10 + 1));
        ASSERT(body_coverage_insert(&m, 9, 22)); /* absorbs [10,11],[20,21] */
        static const int64_t e1[][2] = { {0, 1}, {9, 22}, {30, 31}, {40, 41} };
        ASSERT(tbc_ranges_are(&m, 4, e1));
        ASSERT(body_coverage_insert(&m, 31, 40)); /* absorbs the last two */
        static const int64_t e2[][2] = { {0, 1}, {9, 22}, {30, 41} };
        ASSERT(tbc_ranges_are(&m, 3, e2));
        ASSERT(body_coverage_insert(&m, 2, 8)); /* absorbs the first two */
        static const int64_t e3[][2] = { {0, 22}, {30, 41} };
        ASSERT(tbc_ranges_are(&m, 2, e3));
        /* Disjoint insert at the front, middle and back shifts the tail. */
        ASSERT(body_coverage_insert(&m, 50, 51));
        ASSERT(body_coverage_insert(&m, 25, 26));
        static const int64_t e4[][2] = { {0, 22}, {25, 26}, {30, 41}, {50, 51} };
        ASSERT(tbc_ranges_are(&m, 4, e4));
        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_insert_front_and_max_height(void)
{
    int failures = 0;
    TEST("insert: front insert shifts every range; INT64_MAX absorbs the rest") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        ASSERT(body_coverage_insert(&m, 30, 31));
        ASSERT(body_coverage_insert(&m, 20, 21));
        ASSERT(body_coverage_insert(&m, 10, 11));
        static const int64_t e1[][2] = { {10, 11}, {20, 21}, {30, 31} };
        ASSERT(tbc_ranges_are(&m, 3, e1));
        ASSERT(body_coverage_insert(&m, 14, INT64_MAX)); /* joins 20.. and 30.. */
        static const int64_t e2[][2] = { {10, 11}, {14, INT64_MAX} };
        ASSERT(tbc_ranges_are(&m, 2, e2));
        ASSERT(body_coverage_insert(&m, 3, 4));
        ASSERT(body_coverage_insert(&m, 5, 9)); /* bridges 4|10 */
        static const int64_t e3[][2] = { {3, 11}, {14, INT64_MAX} };
        ASSERT(tbc_ranges_are(&m, 2, e3));
        ASSERT(body_coverage_insert(&m, 0, INT64_MAX));
        static const int64_t e4[][2] = { {0, INT64_MAX} };
        ASSERT(tbc_ranges_are(&m, 1, e4));
        ASSERT(body_coverage_max_covered(&m) == INT64_MAX);
        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_capacity_growth(void)
{
    int failures = 0;
    TEST("insert/remove: capacity doubles from 8 and reset keeps it") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        for (int64_t i = 0; i < 8; i++)
            ASSERT(body_coverage_insert(&m, i * 10, i * 10));
        ASSERT(m.cap == 8 && m.count == 8);
        ASSERT(body_coverage_insert(&m, 80, 80));
        ASSERT(m.cap == 16 && m.count == 9);
        for (int64_t i = 9; i < 17; i++)
            ASSERT(body_coverage_insert(&m, i * 10, i * 10));
        ASSERT(m.cap == 32 && m.count == 17);
        for (int64_t i = 0; i < 17; i++)
            ASSERT(body_coverage_contains(&m, i * 10) &&
                   !body_coverage_contains(&m, i * 10 + 1));
        /* A split at full capacity grows the array and loses nothing. */
        for (int64_t i = 17; i < 32; i++)
            ASSERT(body_coverage_insert(&m, i * 10, i * 10 + 2));
        ASSERT(m.count == 32 && m.cap == 32);
        ASSERT(body_coverage_remove(&m, 301, 301));
        ASSERT(m.count == 33 && m.cap == 64);
        ASSERT(body_coverage_contains(&m, 300) && !body_coverage_contains(&m, 301)
               && body_coverage_contains(&m, 302));
        body_coverage_reset(&m);
        ASSERT(m.count == 0 && m.cap == 64);
        body_coverage_free(&m);
        ASSERT(m.ranges == NULL && m.cap == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_remove_exact_edges(void)
{
    int failures = 0;
    TEST("remove: touching, equal and straddling edges keep exact remnants") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        ASSERT(body_coverage_remove(&m, 0, 5)); /* empty map */
        ASSERT(body_coverage_insert(&m, 10, 20));
        ASSERT(body_coverage_insert(&m, 30, 40));
        ASSERT(body_coverage_remove(&m, 21, 29)); /* touches none */
        ASSERT(body_coverage_remove(&m, 0, 9));   /* touches none */
        ASSERT(body_coverage_remove(&m, 41, 50)); /* touches none */
        static const int64_t e0[][2] = { {10, 20}, {30, 40} };
        ASSERT(tbc_ranges_are(&m, 2, e0));
        ASSERT(body_coverage_remove(&m, 20, 29)); /* hits r.hi exactly */
        ASSERT(body_coverage_remove(&m, 0, 10));  /* hits r.lo exactly */
        static const int64_t e1[][2] = { {11, 19}, {30, 40} };
        ASSERT(tbc_ranges_are(&m, 2, e1));
        ASSERT(body_coverage_remove(&m, 11, 12)); /* from r.lo: no left part */
        ASSERT(body_coverage_remove(&m, 38, 40)); /* to r.hi: no right part */
        static const int64_t e2[][2] = { {13, 19}, {30, 37} };
        ASSERT(tbc_ranges_are(&m, 2, e2));
        ASSERT(body_coverage_remove(&m, 19, 30)); /* spans both edges */
        static const int64_t e3[][2] = { {13, 18}, {31, 37} };
        ASSERT(tbc_ranges_are(&m, 2, e3));
        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_remove_single_heights_and_all(void)
{
    int failures = 0;
    TEST("remove: single heights, negative lo, and a window over everything") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        ASSERT(body_coverage_insert(&m, 0, 4));
        ASSERT(body_coverage_remove(&m, -3, 2)); /* negative lo: ignored */
        ASSERT(body_coverage_total_covered(&m) == 5);
        ASSERT(body_coverage_remove(&m, 0, 0));
        ASSERT(body_coverage_remove(&m, 4, 4));
        static const int64_t e1[][2] = { {1, 3} };
        ASSERT(tbc_ranges_are(&m, 1, e1));
        ASSERT(body_coverage_remove(&m, 2, 2)); /* lo == hi splits */
        static const int64_t e2[][2] = { {1, 1}, {3, 3} };
        ASSERT(tbc_ranges_are(&m, 2, e2));
        ASSERT(body_coverage_insert(&m, 7, 8));
        ASSERT(body_coverage_remove(&m, 0, INT64_MAX));
        ASSERT(body_coverage_range_count(&m) == 0);
        ASSERT(body_coverage_max_covered(&m) == -1);
        ASSERT(body_coverage_total_covered(&m) == 0);
        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_contains_many_ranges(void)
{
    int failures = 0;
    TEST("contains: binary search is exact over twenty ranges") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        ASSERT(!body_coverage_contains(&m, 0));
        for (int64_t i = 0; i < 20; i++)
            ASSERT(body_coverage_insert(&m, i * 10, i * 10 + 4));
        for (int64_t h = 0; h < 210; h++) {
            bool want = h < 200 && (h % 10) <= 4;
            ASSERT(body_coverage_contains(&m, h) == want);
        }
        ASSERT(!body_coverage_contains(&m, -1));
        ASSERT(!body_coverage_contains(NULL, 3));
        ASSERT(body_coverage_contains(&m, 194) && !body_coverage_contains(&m, 195));
        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_hole_window_edges(void)
{
    int failures = 0;
    TEST("find_first_hole: window edges against a single range") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        struct bc_range hole = { -7, -7 };
        ASSERT(body_coverage_insert(&m, 10, 20));
        ASSERT(!body_coverage_find_first_hole(&m, 11, 10, &hole));
        ASSERT(!body_coverage_find_first_hole(&m, -1, 10, &hole));
        ASSERT(!body_coverage_find_first_hole(&m, 0, 10, NULL));
        ASSERT(!body_coverage_find_first_hole(NULL, 0, 10, &hole));
        ASSERT(hole.lo == -7 && hole.hi == -7); /* untouched on refusal */
        ASSERT(body_coverage_find_first_hole(&m, 0, 10, &hole));
        ASSERT(hole.lo == 0 && hole.hi == 9);   /* range starts at `to` */
        ASSERT(body_coverage_find_first_hole(&m, 0, 9, &hole));
        ASSERT(hole.lo == 0 && hole.hi == 9);   /* range starts above `to` */
        ASSERT(body_coverage_find_first_hole(&m, 9, 9, &hole));
        ASSERT(hole.lo == 9 && hole.hi == 9);
        ASSERT(!body_coverage_find_first_hole(&m, 10, 10, &hole));
        ASSERT(!body_coverage_find_first_hole(&m, 20, 20, &hole));
        ASSERT(body_coverage_find_first_hole(&m, 21, 21, &hole));
        ASSERT(hole.lo == 21 && hole.hi == 21);
        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_hole_walk_across_ranges(void)
{
    int failures = 0;
    TEST("find_first_hole: walking a cursor across several ranges") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        struct bc_range hole;
        ASSERT(body_coverage_insert(&m, 0, 9));
        ASSERT(body_coverage_insert(&m, 11, 19));
        ASSERT(body_coverage_insert(&m, 21, 29));
        ASSERT(body_coverage_find_first_hole(&m, 0, 29, &hole));
        ASSERT(hole.lo == 10 && hole.hi == 10);
        ASSERT(body_coverage_find_first_hole(&m, 11, 29, &hole));
        ASSERT(hole.lo == 20 && hole.hi == 20);
        ASSERT(!body_coverage_find_first_hole(&m, 21, 29, &hole));
        ASSERT(!body_coverage_find_first_hole(&m, 22, 28, &hole));
        ASSERT(body_coverage_find_first_hole(&m, 21, 30, &hole));
        ASSERT(hole.lo == 30 && hole.hi == 30);
        ASSERT(body_coverage_find_first_hole(&m, 12, 40, &hole));
        ASSERT(hole.lo == 20 && hole.hi == 20);
        /* A range ending just below `to` leaves exactly `to` open. */
        ASSERT(body_coverage_find_first_hole(&m, 0, 10, &hole));
        ASSERT(hole.lo == 10 && hole.hi == 10);
        ASSERT(body_coverage_find_first_hole(&m, 5, 10, &hole));
        ASSERT(hole.lo == 10 && hole.hi == 10);
        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_total_and_max_covered(void)
{
    int failures = 0;
    TEST("total_covered/max_covered: widths, saturation and emptiness") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        ASSERT(body_coverage_total_covered(NULL) == 0);
        ASSERT(body_coverage_max_covered(NULL) == -1);
        ASSERT(body_coverage_range_count(NULL) == 0);
        ASSERT(body_coverage_max_covered(&m) == -1);
        ASSERT(body_coverage_insert(&m, 7, 7));
        ASSERT(body_coverage_total_covered(&m) == 1);
        ASSERT(body_coverage_max_covered(&m) == 7);
        ASSERT(body_coverage_insert(&m, 100, 102));
        ASSERT(body_coverage_total_covered(&m) == 4);
        ASSERT(body_coverage_max_covered(&m) == 102);
        body_coverage_reset(&m);
        ASSERT(body_coverage_insert(&m, 0, INT64_MAX));
        ASSERT(body_coverage_total_covered(&m) == INT64_MAX);
        body_coverage_reset(&m);
        ASSERT(body_coverage_insert(&m, 1, INT64_MAX));
        ASSERT(body_coverage_total_covered(&m) == INT64_MAX);
        ASSERT(body_coverage_remove(&m, 2, INT64_MAX));
        ASSERT(body_coverage_total_covered(&m) == 1);
        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

struct tbc_scan_probe {
    size_t calls;
    int64_t first;
    int64_t last;
};

static bool tbc_have_probe(int64_t h, void *ctx)
{
    struct tbc_scan_probe *p = ctx;
    if (p->calls++ == 0)
        p->first = h;
    p->last = h;
    return h <= 2 || h == 5 || h >= 9;
}

static bool tbc_have_none(int64_t h, void *ctx)
{
    (void)h;
    (void)ctx;
    return false;
}

static int test_bc_scan_window_edges(void)
{
    int failures = 0;
    TEST("scan_window: runs at height 0 and at the window end are kept") {
        struct body_coverage_map m;
        body_coverage_init(&m);
        struct tbc_scan_probe p = { 0, -1, -1 };
        ASSERT(body_coverage_scan_window(&m, 0, 10, tbc_have_probe, &p) == 6);
        ASSERT(p.calls == 11 && p.first == 0 && p.last == 10);
        static const int64_t e1[][2] = { {0, 2}, {5, 5}, {9, 10} };
        ASSERT(tbc_ranges_are(&m, 3, e1));
        ASSERT(body_coverage_scan_window(&m, 3, 4, tbc_have_none, NULL) == 0);
        ASSERT(body_coverage_scan_window(&m, 5, 5, tbc_have_probe, &p) == 1);
        ASSERT(body_coverage_scan_window(&m, 7, 3, tbc_have_probe, &p) == 0);
        ASSERT(body_coverage_scan_window(&m, -1, 3, tbc_have_probe, &p) == 0);
        ASSERT(body_coverage_scan_window(&m, 0, 3, NULL, &p) == 0);
        ASSERT(body_coverage_scan_window(NULL, 0, 3, tbc_have_probe, &p) == 0);
        body_coverage_reset(&m);
        struct tbc_scan_probe q = { 0, -1, -1 };
        ASSERT(body_coverage_scan_window(&m, 0, 0, tbc_have_probe, &q) == 1);
        ASSERT(q.calls == 1 && body_coverage_contains(&m, 0));
        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Persistence: blob layout and every load refusal ────────────── */

static bool tbc_put_blob(sqlite3 *db, const char *key, uint32_t magic,
                         uint32_t ver, uint32_t count, const int64_t *pairs,
                         size_t npairs)
{
    size_t len = 12 + npairs * 16;
    uint8_t *buf = zcl_malloc(len, "test_bc_blob");
    if (!buf)
        return false;
    memcpy(buf, &magic, 4);
    memcpy(buf + 4, &ver, 4);
    memcpy(buf + 8, &count, 4);
    if (npairs)
        memcpy(buf + 12, pairs, npairs * 16);
    bool ok = progress_meta_set(db, key, buf, len);
    free(buf);
    return ok;
}

static bool tbc_load_rejected(sqlite3 *db, const char *key)
{
    struct body_coverage_map m;
    body_coverage_init(&m);
    bool ok = body_coverage_insert(&m, 1, 2);
    ok = ok && !body_coverage_load_key(&m, db, key);
    ok = ok && body_coverage_range_count(&m) == 0;
    body_coverage_free(&m);
    return ok;
}

static bool tbc_blob_layout_ok(sqlite3 *db)
{
    struct body_coverage_map m;
    body_coverage_init(&m);
    bool ok = body_coverage_insert(&m, 3, 9) && body_coverage_insert(&m, 20, 21);
    ok = ok && body_coverage_save_key(&m, db, "bc.layout");
    uint8_t raw[64];
    size_t len = 0;
    bool found = false;
    ok = ok && progress_meta_get(db, "bc.layout", raw, sizeof(raw), &len, &found);
    uint32_t hdr[3] = { 0x42434f56u, 1u, 2u };
    int64_t body[4] = { 3, 9, 20, 21 };
    ok = ok && found && len == 12 + 32;
    ok = ok && memcmp(raw, hdr, 12) == 0 && memcmp(raw + 12, body, 32) == 0;
    body_coverage_free(&m);
    return ok;
}

static bool tbc_save_truncates_to_cap(sqlite3 *db)
{
    struct body_coverage_map m;
    body_coverage_init(&m);
    const size_t n = BODY_COVERAGE_PERSIST_MAX_RANGES + 1u;
    m.ranges = zcl_malloc(n * sizeof(*m.ranges), "test_bc_big_map");
    if (!m.ranges)
        return false;
    for (size_t i = 0; i < n; i++) {
        m.ranges[i].lo = (int64_t)i * 2;
        m.ranges[i].hi = (int64_t)i * 2;
    }
    m.count = m.cap = n;
    bool ok = body_coverage_save_key(&m, db, "bc.big");
    struct body_coverage_map loaded;
    body_coverage_init(&loaded);
    ok = ok && body_coverage_load_key(&loaded, db, "bc.big");
    ok = ok && body_coverage_range_count(&loaded) ==
                   BODY_COVERAGE_PERSIST_MAX_RANGES;
    ok = ok && body_coverage_max_covered(&loaded) ==
                   (int64_t)(BODY_COVERAGE_PERSIST_MAX_RANGES - 1u) * 2;
    ok = ok && body_coverage_contains(&loaded, 0);
    body_coverage_free(&loaded);
    body_coverage_free(&m);
    return ok;
}

static bool tbc_load_at_exact_cap(sqlite3 *db)
{
    const size_t n = BODY_COVERAGE_PERSIST_MAX_RANGES;
    int64_t *zeros = zcl_malloc(n * 16, "test_bc_zero_pairs");
    if (!zeros)
        return false;
    memset(zeros, 0, n * 16);
    bool ok = tbc_put_blob(db, "bc.exact", 0x42434f56u, 1u, (uint32_t)n,
                           zeros, n);
    free(zeros);
    struct body_coverage_map m;
    body_coverage_init(&m);
    ok = ok && body_coverage_load_key(&m, db, "bc.exact");
    ok = ok && body_coverage_range_count(&m) == 1 &&
         body_coverage_contains(&m, 0);
    body_coverage_free(&m);
    return ok;
}

static int test_bc_persistence_format_and_cap(void)
{
    int failures = 0;
    TEST("save writes the documented blob; the range cap is exact") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "body_coverage", "format");
        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        bool ok = db != NULL && progress_meta_table_ensure(db);
        ok = ok && tbc_blob_layout_ok(db);
        ok = ok && tbc_save_truncates_to_cap(db);
        ok = ok && tbc_load_at_exact_cap(db);
        progress_store_close();
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

static bool tbc_header_refusals_ok(sqlite3 *db)
{
    static const int64_t one[2] = { 5, 6 };
    bool ok = tbc_put_blob(db, "bc.magic", 0x42434f57u, 1u, 0, NULL, 0);
    ok = ok && tbc_load_rejected(db, "bc.magic");
    ok = ok && tbc_put_blob(db, "bc.ver0", 0x42434f56u, 0u, 0, NULL, 0);
    ok = ok && tbc_load_rejected(db, "bc.ver0");
    ok = ok && tbc_put_blob(db, "bc.ver2", 0x42434f56u, 2u, 0, NULL, 0);
    ok = ok && tbc_load_rejected(db, "bc.ver2");
    ok = ok && tbc_put_blob(db, "bc.short", 0x42434f56u, 1u, 2, one, 1);
    ok = ok && tbc_load_rejected(db, "bc.short"); /* count > data */
    ok = ok && tbc_put_blob(db, "bc.long", 0x42434f56u, 1u, 0, one, 1);
    ok = ok && tbc_load_rejected(db, "bc.long");  /* data > count */
    uint8_t tiny[11] = { 0 };
    ok = ok && progress_meta_set(db, "bc.tiny", tiny, sizeof(tiny));
    ok = ok && tbc_load_rejected(db, "bc.tiny");
    return ok;
}

static bool tbc_load_normalizes_ok(sqlite3 *db)
{
    struct body_coverage_map m;
    body_coverage_init(&m);
    bool ok = tbc_put_blob(db, "bc.empty", 0x42434f56u, 1u, 0, NULL, 0);
    ok = ok && body_coverage_insert(&m, 1, 2);
    ok = ok && body_coverage_load_key(&m, db, "bc.empty");
    ok = ok && body_coverage_range_count(&m) == 0; /* a header-only blob */
    static const int64_t messy[] = { 20, 30, 0, 25, 40, 35, 50, 60 };
    ok = ok && tbc_put_blob(db, "bc.messy", 0x42434f56u, 1u, 4, messy, 4);
    ok = ok && body_coverage_load_key(&m, db, "bc.messy");
    static const int64_t e[][2] = { {0, 30}, {50, 60} };
    ok = ok && tbc_ranges_are(&m, 2, e); /* the lo > hi pair was dropped */
    ok = ok && !body_coverage_load_key(NULL, db, "bc.messy");
    ok = ok && !body_coverage_load_key(&m, NULL, "bc.messy");
    ok = ok && !body_coverage_load_key(&m, db, NULL);
    ok = ok && !body_coverage_save_key(&m, db, NULL);
    ok = ok && !body_coverage_save_key(&m, NULL, "bc.messy");
    ok = ok && !body_coverage_save_key(NULL, db, "bc.messy");
    body_coverage_free(&m);
    return ok;
}

static int test_bc_persistence_load_refusals(void)
{
    int failures = 0;
    TEST("load refuses a bad header or length and normalizes what it keeps") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "body_coverage", "refuse");
        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        bool ok = db != NULL && progress_meta_table_ensure(db);
        ok = ok && tbc_header_refusals_ok(db);
        ok = ok && tbc_load_normalizes_ok(db);
        progress_store_close();
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Scheduler: plan bookkeeping ────────────────────────────────── */

static int test_bc_scheduler_initial_and_blocker(void)
{
    int failures = 0;
    TEST("scheduler: initial state and the no-source latch bookkeeping") {
        struct body_coverage_scheduler s;
        body_coverage_scheduler_init(&s);
        ASSERT(s.needed_lo == -1 && s.needed_hi == -1);
        ASSERT(s.last_total_covered == -1 && s.last_plan_unix == 0);
        ASSERT(!s.blocked_no_source && s.no_source_fires == 0);
        body_coverage_scheduler_init(NULL);
        body_coverage_scheduler_mark_no_source(NULL, 5);
        body_coverage_scheduler_mark_enqueued(NULL);
        body_coverage_scheduler_clear_no_source(NULL);
        body_coverage_scheduler_mark_no_source(&s, 77);
        ASSERT(s.blocked_no_source && s.blocked_since_unix == 77);
        body_coverage_scheduler_mark_no_source(&s, 99);
        ASSERT(s.blocked_since_unix == 77 && s.no_source_fires == 1);
        body_coverage_scheduler_mark_enqueued(&s);
        ASSERT(!s.blocked_no_source && s.blocked_since_unix == 0);
        body_coverage_scheduler_mark_no_source(&s, 120);
        ASSERT(s.blocked_since_unix == 120 && s.no_source_fires == 2);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_scheduler_plan_bounds(void)
{
    int failures = 0;
    TEST("scheduler plan: needed-range bounds and counters") {
        struct body_coverage_map m;
        struct body_coverage_scheduler s;
        struct bc_range hole = { -1, -1 };
        body_coverage_init(&m);
        body_coverage_scheduler_init(&s);
        ASSERT(!body_coverage_scheduler_plan(NULL, &m, 0, 5, 10, &hole));
        ASSERT(!body_coverage_scheduler_plan(&s, NULL, 0, 5, 10, &hole));
        ASSERT(s.plans == 0);
        ASSERT(body_coverage_scheduler_plan(&s, &m, 0, 0, 10, &hole));
        ASSERT(hole.lo == 0 && hole.hi == 0 && s.has_active_hole);
        ASSERT(s.plans == 1 && s.holes_seen == 1);
        ASSERT(s.active_hole.lo == 0 && s.active_hole.hi == 0);
        ASSERT(body_coverage_scheduler_plan(&s, &m, 5, 5, 11, NULL));
        ASSERT(s.active_hole.lo == 5 && s.active_hole.hi == 5);
        ASSERT(s.plans == 2 && s.holes_seen == 2);
        body_coverage_scheduler_mark_no_source(&s, 11);
        ASSERT(body_coverage_scheduler_plan(&s, &m, 6, 7, 12, &hole));
        ASSERT(s.blocked_no_source); /* an open hole keeps the latch */
        ASSERT(!body_coverage_scheduler_plan(&s, &m, -1, 5, 13, &hole));
        ASSERT(!s.has_active_hole && !s.blocked_no_source);
        ASSERT(s.needed_lo == -1 && s.needed_hi == 5);
        ASSERT(!body_coverage_scheduler_plan(&s, &m, 9, 8, 14, &hole));
        ASSERT(s.needed_lo == 9 && s.needed_hi == 8 && s.holes_seen == 3);
        ASSERT(s.plans == 5);
        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_scheduler_rate_edges(void)
{
    int failures = 0;
    TEST("scheduler fill rate: first plan, same second, and prune") {
        struct body_coverage_map m;
        struct body_coverage_scheduler s;
        struct bc_range hole;
        body_coverage_init(&m);
        body_coverage_scheduler_init(&s);
        /* An empty first map still seeds the baseline (total 0, not -1). */
        ASSERT(body_coverage_scheduler_plan(&s, &m, 0, 99, 1000, &hole));
        ASSERT(s.last_total_covered == 0 && s.last_plan_unix == 1000);
        ASSERT(body_coverage_insert(&m, 0, 19));
        ASSERT(body_coverage_scheduler_plan(&s, &m, 0, 99, 1010, &hole));
        ASSERT(s.fill_rate_per_sec == 2.0);
        ASSERT(s.last_total_covered == 20 && s.last_plan_unix == 1010);
        /* Same second: the prior rate stands. */
        ASSERT(body_coverage_insert(&m, 20, 59));
        ASSERT(body_coverage_scheduler_plan(&s, &m, 0, 99, 1010, &hole));
        ASSERT(s.fill_rate_per_sec == 2.0 && s.last_total_covered == 60);
        /* A clock step backwards does not recompute it either. */
        ASSERT(body_coverage_scheduler_plan(&s, &m, 0, 99, 1005, &hole));
        ASSERT(s.fill_rate_per_sec == 2.0 && s.last_plan_unix == 1005);
        /* Pruned coverage reports a zero rate, never a negative one. */
        ASSERT(body_coverage_remove(&m, 0, 29));
        ASSERT(body_coverage_scheduler_plan(&s, &m, 0, 99, 1015, &hole));
        ASSERT(s.fill_rate_per_sec == 0.0);
        ASSERT(body_coverage_insert(&m, 0, 29));
        ASSERT(body_coverage_scheduler_plan(&s, &m, 0, 99, 1018, &hole));
        ASSERT(s.fill_rate_per_sec == 10.0);
        body_coverage_free(&m);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bc_scheduler_first_plan_no_rate(void)
{
    int failures = 0;
    TEST("scheduler fill rate: no rate until a prior plan has a clock") {
        struct body_coverage_map m;
        struct body_coverage_scheduler s;
        struct bc_range hole;
        body_coverage_init(&m);
        body_coverage_scheduler_init(&s);
        ASSERT(body_coverage_insert(&m, 0, 49));
        ASSERT(body_coverage_scheduler_plan(&s, &m, 0, 99, 500, &hole));
        ASSERT(s.fill_rate_per_sec == 0.0); /* total was unseeded (-1) */
        ASSERT(s.last_total_covered == 50);
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
    failures += test_bc_maximum_height_range_boundaries();
    failures += test_bc_scan_window();
    failures += test_bc_persistence_roundtrip();
    failures += test_bc_persistence_rejects_over_cap_range_count();
    failures += test_bc_scheduler_plan_and_blocker();
    failures += test_bc_scheduler_fill_rate();
    failures += test_bc_gap_enqueue_drain_fixture();
    failures += test_bc_insert_gap_and_adjacency_edges();
    failures += test_bc_insert_extend_and_invalid();
    failures += test_bc_insert_collapse_with_tail();
    failures += test_bc_insert_front_and_max_height();
    failures += test_bc_capacity_growth();
    failures += test_bc_remove_exact_edges();
    failures += test_bc_remove_single_heights_and_all();
    failures += test_bc_contains_many_ranges();
    failures += test_bc_hole_window_edges();
    failures += test_bc_hole_walk_across_ranges();
    failures += test_bc_total_and_max_covered();
    failures += test_bc_scan_window_edges();
    failures += test_bc_persistence_format_and_cap();
    failures += test_bc_persistence_load_refusals();
    failures += test_bc_scheduler_initial_and_blocker();
    failures += test_bc_scheduler_plan_bounds();
    failures += test_bc_scheduler_rate_edges();
    failures += test_bc_scheduler_first_plan_no_rate();
    return failures;
}

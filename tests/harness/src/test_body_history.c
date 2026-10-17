/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for body_history — "which block bodies BELOW my tip am I missing?"
 *
 * The census has three outcomes (COMPLETE / INCOMPLETE / UNKNOWN); an unreadable
 * block index must publish as UNKNOWN, never as "no hole". The tests hunt for a
 * collapse back to two:
 *
 *   test_bh_unreadable_index_is_not_no_hole  — every height indeterminate
 *      must NOT report COMPLETE or proven. Fresh-node shape (empty coverage map).
 *   test_bh_restored_coverage_is_a_claim_not_a_look — the same window on a
 *      RESTARTED node, where progress.kv hands back a coverage map claiming
 *      everything. The claim is a file, not a look, and certifies nothing.
 *   test_bh_persistence_never_restores_a_verdict — the durable half of the
 *      same rule: a restart resumes the census cursor and nothing else.
 *   test_bh_partial_read_does_not_certify    — half the window readable and
 *      fully held still is not COMPLETE.
 *   test_bh_at_tip_requires_proven_history   — the AT_TIP planner refuses
 *      the transition on UNKNOWN exactly as hard as on INCOMPLETE.
 *
 * The positive direction is covered too: a deliberate hole below the tip is
 * found, counted, located, and handed to the real download manager.
 */

#include "test/test_core.h"

#include "storage/body_history.h"
#include "storage/body_coverage.h"
#include "storage/progress_store.h"
#include "sync/sync_planner.h"
#include "net/download.h"
#include "net/net.h"
#include "services/body_backfill_service.h"
#include "validation/main_state.h"
#include "platform/time_compat.h"
#include "json/json.h"
#include "core/uint256.h"

#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ── A synthetic chain the probe can read ───────────────────────── */

/* Models the two things a real probe distinguishes: whether the height is
 * indexed at all (an unreadable/absent block-index entry) and, if it is,
 * whether the body is on disk. */
struct bh_fake_chain {
    int64_t  height_count;
    uint8_t *indexed;    /* 0 = index entry unreadable (INDETERMINATE) */
    uint8_t *have_data;  /* 1 = BLOCK_HAVE_DATA set */
    uint64_t probe_calls;
};

static void bh_fake_hash(struct uint256 *out, int64_t h)
{
    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < 8; i++)
        out->data[i] = (uint8_t)((uint64_t)h >> (8 * i));
    out->data[31] = 0xAB;
}

static bool bh_fake_chain_init(struct bh_fake_chain *c, int64_t n)
{
    memset(c, 0, sizeof(*c));
    c->height_count = n;
    c->indexed = calloc((size_t)n, 1);
    c->have_data = calloc((size_t)n, 1);
    if (!c->indexed || !c->have_data) {
        free(c->indexed);
        free(c->have_data);
        memset(c, 0, sizeof(*c));
        return false;
    }
    for (int64_t h = 0; h < n; h++) {
        c->indexed[h] = 1;
        c->have_data[h] = 1;
    }
    return true;
}

static void bh_fake_chain_free(struct bh_fake_chain *c)
{
    free(c->indexed);
    free(c->have_data);
    memset(c, 0, sizeof(*c));
}

/* Mirrors gf_history_probe in engine/services/src/gap_fill_service.c: an
 * unreadable index entry yields INDETERMINATE, never MISSING and never
 * HAVE. */
static enum body_history_probe bh_fake_probe(int64_t height,
                                             struct uint256 *out_hash,
                                             void *ctx)
{
    struct bh_fake_chain *c = (struct bh_fake_chain *)ctx;
    if (!c)
        return BODY_HISTORY_PROBE_INDETERMINATE;
    c->probe_calls++;
    if (height < 0 || height >= c->height_count)
        return BODY_HISTORY_PROBE_INDETERMINATE;
    if (!c->indexed[height])
        return BODY_HISTORY_PROBE_INDETERMINATE;
    if (c->have_data[height])
        return BODY_HISTORY_PROBE_HAVE;
    if (out_hash)
        bh_fake_hash(out_hash, height);
    return BODY_HISTORY_PROBE_MISSING;
}

/* Drive the census over [0, tip] to completion (bounded passes), folding
 * into the caller's maps. Returns total heights handed back as MISSING. */
static int64_t bh_run_full_census(struct body_history_census *census,
                                  struct body_coverage_map *held,
                                  struct body_coverage_map *measured,
                                  struct bh_fake_chain *chain,
                                  int64_t tip,
                                  int64_t budget,
                                  struct uint256 *collect_h,
                                  int32_t *collect_n,
                                  size_t collect_cap,
                                  size_t *collected_out)
{
    int64_t total_missing = 0;
    size_t collected = 0;
    uint8_t *classes = malloc((size_t)budget);
    struct uint256 *hashes = malloc((size_t)budget * sizeof(*hashes));
    if (!classes || !hashes) {
        free(classes);
        free(hashes);
        if (collected_out) *collected_out = 0;
        return -1;
    }

    /* Bounded by construction: one pass per budget-sized window, plus slack.
     * A runaway cursor fails the loop cap rather than hanging the suite. */
    int64_t max_passes = (tip / budget) + 8;
    for (int64_t p = 0; p < max_passes; p++) {
        int64_t lo = 0, hi = 0;
        if (!body_history_census_plan(census, 0, tip, budget, &lo, &hi))
            break;
        size_t n = body_history_census_probe_window(lo, hi, bh_fake_probe,
                                                    chain, classes, hashes,
                                                    (size_t)budget);
        struct body_history_pass_result res;
        if (!body_history_census_fold(census, held, measured, lo, classes, n,
                                      &res))
            break;
        body_history_census_advance(census, lo, hi);
        total_missing += res.missing;
        if (collect_h && collect_n && collected < collect_cap) {
            collected += body_history_census_collect_missing(
                lo, classes, hashes, n,
                collect_h + collected, collect_n + collected,
                collect_cap - collected);
        }
        if (census->sweeps_completed > 0)
            break;
    }

    free(classes);
    free(hashes);
    if (collected_out) *collected_out = collected;
    return total_missing;
}

/* ── 1. The rejected defect: unreadable index != no hole ────────── */

/* Fresh-node shape: `held` starts empty. The restarted-node half is
 * test_bh_restored_coverage_is_a_claim_not_a_look. */
static int test_bh_unreadable_index_is_not_no_hole(void)
{
    int failures = 0;
    TEST("unreadable index on a fresh node reports could-not-determine") {
        struct bh_fake_chain chain;
        ASSERT(bh_fake_chain_init(&chain, 500));
        /* The WHOLE window is unreadable — the exact case that must not
         * publish as a clean bill of health. */
        for (int64_t h = 0; h < 500; h++)
            chain.indexed[h] = 0;

        struct body_coverage_map held, measured;
        body_coverage_init(&held);
        body_coverage_init(&measured);
        struct body_history_census census;
        body_history_census_init(&census);

        int64_t missing = bh_run_full_census(&census, &held, &measured,
                                             &chain, 499, 64,
                                             NULL, NULL, 0, NULL);
        ASSERT(missing == 0);              /* nothing was found missing ... */
        ASSERT(census.heights_indeterminate == 500); /* ... because nothing
                                                      * could be read */
        ASSERT(census.heights_examined == 0);

        /* Neither map may have absorbed an unreadable height. */
        ASSERT(body_coverage_total_covered(&measured) == 0);
        ASSERT(body_coverage_total_covered(&held) == 0);

        struct body_history_verdict v;
        ASSERT(body_history_evaluate(&held, &measured, 0, 499, &v));

        /* THE assertion. missing_count is 0 — and that must NOT read as
         * "no hole". */
        ASSERT(v.missing_count == 0);
        ASSERT(v.status == BODY_HISTORY_UNKNOWN);
        ASSERT(v.status != BODY_HISTORY_COMPLETE);
        ASSERT(!body_history_verdict_is_proven(&v));
        ASSERT(v.unmeasured_count == 500);
        ASSERT(v.lowest_unmeasured == 0);
        ASSERT(v.lowest_missing == -1);
        ASSERT(strcmp(body_history_status_name(v.status), "unknown") == 0);

        /* And it must be DISTINGUISHABLE from a genuinely complete node,
         * not merely "also zero missing". */
        struct body_coverage_map full_held, full_measured;
        body_coverage_init(&full_held);
        body_coverage_init(&full_measured);
        ASSERT(body_coverage_insert(&full_held, 0, 499));
        ASSERT(body_coverage_insert(&full_measured, 0, 499));
        struct body_history_verdict good;
        ASSERT(body_history_evaluate(&full_held, &full_measured, 0, 499,
                                     &good));
        ASSERT(good.status == BODY_HISTORY_COMPLETE);
        ASSERT(body_history_verdict_is_proven(&good));
        ASSERT(good.missing_count == v.missing_count); /* same zero ... */
        ASSERT(good.status != v.status);               /* ... different state */
        ASSERT(good.unmeasured_count != v.unmeasured_count);
        body_coverage_free(&full_held);
        body_coverage_free(&full_measured);

        body_coverage_free(&held);
        body_coverage_free(&measured);
        bh_fake_chain_free(&chain);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 1b. Restored coverage is a claim, not a look ────────────────── */

/* body_coverage_load() restores `held` from progress.kv at boot, so `held`
 * claims coverage nothing in this process has verified. With progress.kv
 * claiming 0..999, no successful probe this boot, and an unreadable block
 * index, the verdict must not be complete or proven. */
static int test_bh_restored_coverage_is_a_claim_not_a_look(void)
{
    int failures = 0;
    TEST("a coverage map restored from disk is a claim, never a probe") {
        struct bh_fake_chain chain;
        ASSERT(bh_fake_chain_init(&chain, 1000));
        /* The block index is unreadable end to end. */
        for (int64_t h = 0; h < 1000; h++)
            chain.indexed[h] = 0;

        struct body_coverage_map held, measured;
        body_coverage_init(&held);
        body_coverage_init(&measured);
        /* What body_coverage_load() hands back at boot: a full claim. */
        ASSERT(body_coverage_insert(&held, 0, 999));
        /* What this boot has actually established: nothing. */
        ASSERT(body_coverage_total_covered(&measured) == 0);

        struct body_history_census census;
        body_history_census_init(&census);
        int64_t missing = bh_run_full_census(&census, &held, &measured,
                                             &chain, 999, 64,
                                             NULL, NULL, 0, NULL);
        ASSERT(missing == 0);
        ASSERT(census.heights_examined == 0);          /* zero successful */
        ASSERT(census.heights_indeterminate == 1000);  /* probes */
        ASSERT(body_coverage_total_covered(&measured) == 0);
        /* An indeterminate probe must not evict the claim either — "I could
         * not look" is not "it is gone". */
        ASSERT(body_coverage_total_covered(&held) == 1000);

        struct body_history_verdict v;
        ASSERT(body_history_evaluate(&held, &measured, 0, 999, &v));

        /* THE assertions. Zero successful probes cannot certify anything. */
        ASSERT(v.status != BODY_HISTORY_COMPLETE);
        ASSERT(!body_history_verdict_is_proven(&v));
        ASSERT(v.status == BODY_HISTORY_UNKNOWN);
        ASSERT(v.unmeasured_count == 1000);
        ASSERT(v.lowest_unmeasured == 0);
        ASSERT(v.missing_count == 0);
        ASSERT(v.lowest_missing == -1);
        /* held_count is what this boot PROVED it holds, not what the file
         * says. The restored claim buys exactly zero. */
        ASSERT(v.held_count == 0);

        /* And both at-tip edges refuse it, which is the consequence that
         * actually matters to an operator. */
        struct sync_tip_state_evaluation eval;
        syncsvc_plan_periodic_tip_state(&eval, SYNC_BLOCKS_DOWNLOAD, true,
                                        1000, 1000, 1000, 1000, 3, 0, 0, 0,
                                        v.status);
        ASSERT(!eval.should_set_at_tip);
        struct sync_block_acceptance acc;
        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        node.starting_height = 100;
        node.state = PEER_SYNCING_BLOCKS;
        syncsvc_note_valid_block(&acc, &node, SYNC_BLOCKS_DOWNLOAD,
                                 100, 100, 0, 0, v.status);
        ASSERT(!acc.should_set_sync_state);

        /* One readable height changes the answer for that height ONLY — the
         * evidence map is per-height, so a partial recovery cannot certify
         * the window either. */
        chain.indexed[999] = 1;
        body_history_census_init(&census);
        (void)bh_run_full_census(&census, &held, &measured, &chain, 999, 64,
                                 NULL, NULL, 0, NULL);
        struct body_history_verdict v2;
        ASSERT(body_history_evaluate(&held, &measured, 0, 999, &v2));
        ASSERT(v2.status == BODY_HISTORY_UNKNOWN);
        ASSERT(!body_history_verdict_is_proven(&v2));
        ASSERT(v2.held_count == 1);          /* the one height we looked at */
        ASSERT(v2.unmeasured_count == 999);

        body_coverage_free(&held);
        body_coverage_free(&measured);
        bh_fake_chain_free(&chain);
        PASS();
    } _test_next:;
    return failures;
}

/* A probe that cannot run at all must be indistinguishable in outcome from
 * the unreadable case and never leave a slot looking answered. */
static int test_bh_null_probe_leaves_everything_unmeasured(void)
{
    int failures = 0;
    TEST("a probe that cannot run leaves every height unmeasured") {
        uint8_t classes[128];
        struct uint256 hashes[128];
        /* Poison the buffers with the HAVE value first: if probe_window
         * ever skipped its pre-fill, this would sail through as coverage. */
        memset(classes, BODY_HISTORY_PROBE_HAVE, sizeof(classes));
        memset(hashes, 0xFF, sizeof(hashes));

        size_t n = body_history_census_probe_window(0, 127, NULL, NULL,
                                                    classes, hashes, 128);
        ASSERT(n == 0);
        for (size_t i = 0; i < 128; i++)
            ASSERT(classes[i] == BODY_HISTORY_PROBE_INDETERMINATE);

        struct body_coverage_map held, measured;
        body_coverage_init(&held);
        body_coverage_init(&measured);
        struct body_history_census census;
        body_history_census_init(&census);

        struct body_history_pass_result res;
        /* Fold the full poisoned window even though probe_window reported
         * 0: a caller that trusts its own cap must still measure nothing. */
        ASSERT(body_history_census_fold(&census, &held, &measured, 0,
                                        classes, 128, &res));
        ASSERT(res.indeterminate == 128);
        ASSERT(res.examined == 0);
        ASSERT(body_coverage_total_covered(&measured) == 0);

        struct body_history_verdict v;
        ASSERT(body_history_evaluate(&held, &measured, 0, 127, &v));
        ASSERT(v.status == BODY_HISTORY_UNKNOWN);
        ASSERT(v.unmeasured_count == 128);
        ASSERT(!body_history_verdict_is_proven(&v));

        body_coverage_free(&held);
        body_coverage_free(&measured);
        PASS();
    } _test_next:;
    return failures;
}

/* Half readable and every readable height held: still not COMPLETE. */
static int test_bh_partial_read_does_not_certify(void)
{
    int failures = 0;
    TEST("a partially readable window never certifies complete") {
        struct body_coverage_map held, measured;
        body_coverage_init(&held);
        body_coverage_init(&measured);
        /* Probed and held: [500, 999]. Never probed: [0, 499]. */
        ASSERT(body_coverage_insert(&held, 500, 999));
        ASSERT(body_coverage_insert(&measured, 500, 999));

        struct body_history_verdict v;
        ASSERT(body_history_evaluate(&held, &measured, 0, 999, &v));
        ASSERT(v.missing_count == 0);
        ASSERT(v.status == BODY_HISTORY_UNKNOWN);
        ASSERT(!body_history_verdict_is_proven(&v));
        ASSERT(v.unmeasured_count == 500);
        ASSERT(v.lowest_unmeasured == 0);
        ASSERT(v.held_count == 500);

        /* Narrowed to what was measured it is complete: UNKNOWN is about scope. */
        struct body_history_verdict narrow;
        ASSERT(body_history_evaluate(&held, &measured, 500, 999, &narrow));
        ASSERT(narrow.status == BODY_HISTORY_COMPLETE);
        ASSERT(body_history_verdict_is_proven(&narrow));

        body_coverage_free(&held);
        body_coverage_free(&measured);
        PASS();
    } _test_next:;
    return failures;
}

/* Bad arguments and allocation-free failure paths all land on UNKNOWN. */
static int test_bh_evaluate_failure_paths_are_unknown(void)
{
    int failures = 0;
    TEST("every evaluate failure path publishes unknown, not clean") {
        struct body_coverage_map held, measured;
        body_coverage_init(&held);
        body_coverage_init(&measured);
        ASSERT(body_coverage_insert(&held, 0, 99));
        ASSERT(body_coverage_insert(&measured, 0, 99));

        struct body_history_verdict v;

        /* Poison first so a function that returns early without resetting
         * would be caught. */
        memset(&v, 0xEE, sizeof(v));
        ASSERT(!body_history_evaluate(NULL, &measured, 0, 99, &v));
        ASSERT(v.status == BODY_HISTORY_UNKNOWN);
        ASSERT(!body_history_verdict_is_proven(&v));

        memset(&v, 0xEE, sizeof(v));
        ASSERT(!body_history_evaluate(&held, NULL, 0, 99, &v));
        ASSERT(v.status == BODY_HISTORY_UNKNOWN);

        memset(&v, 0xEE, sizeof(v));
        ASSERT(!body_history_evaluate(&held, &measured, -1, 99, &v));
        ASSERT(v.status == BODY_HISTORY_UNKNOWN);

        memset(&v, 0xEE, sizeof(v));
        ASSERT(!body_history_evaluate(&held, &measured, 100, 50, &v));
        ASSERT(v.status == BODY_HISTORY_UNKNOWN);
        ASSERT(v.missing_count == 0);
        ASSERT(v.lowest_missing == -1);

        /* A zero-initialized verdict — the shape every uninitialized caller
         * gets — is UNKNOWN, not COMPLETE. */
        struct body_history_verdict zero;
        memset(&zero, 0, sizeof(zero));
        ASSERT(zero.status == BODY_HISTORY_UNKNOWN);
        ASSERT(!body_history_verdict_is_proven(&zero));

        body_coverage_free(&held);
        body_coverage_free(&measured);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2. The positive direction: a real hole below the tip ───────── */

static int test_bh_below_tip_hole_found_and_enqueued(void)
{
    int failures = 0;
    TEST("a deliberate hole below the tip is found, located and enqueued") {
        /* 3,000 heights; bodies missing for [40, 60], below the tip and outside
         * gap_fill_compute_window ([tip+1, best_header]). */
        struct bh_fake_chain chain;
        ASSERT(bh_fake_chain_init(&chain, 3000));
        for (int64_t h = 40; h <= 60; h++)
            chain.have_data[h] = 0;

        struct body_coverage_map held, measured;
        body_coverage_init(&held);
        body_coverage_init(&measured);
        struct body_history_census census;
        body_history_census_init(&census);

        struct uint256 collected_h[64];
        int32_t collected_n[64];
        size_t collected = 0;
        int64_t missing = bh_run_full_census(&census, &held, &measured,
                                             &chain, 2999, 256,
                                             collected_h, collected_n, 64,
                                             &collected);
        ASSERT(missing == 21);
        ASSERT(census.heights_examined == 3000);
        ASSERT(census.heights_indeterminate == 0);
        ASSERT(census.sweeps_completed == 1);

        struct body_history_verdict v;
        ASSERT(body_history_evaluate(&held, &measured, 0, 2999, &v));
        ASSERT(v.status == BODY_HISTORY_INCOMPLETE);
        ASSERT(!body_history_verdict_is_proven(&v));
        ASSERT(v.missing_count == 21);
        ASSERT(v.lowest_missing == 40);
        ASSERT(v.unmeasured_count == 0);
        ASSERT(v.held_count == 2979);

        /* Every missing height was collected for the download manager. */
        ASSERT(collected == 21);

        /* And it goes through the EXISTING download primitives, not a new
         * path: dl_queue_blocks accepts all 21 and hands them to a peer in
         * ascending height order. */
        struct download_manager dm;
        dl_init(&dm);
        size_t added = dl_queue_blocks(&dm, collected_h, collected_n,
                                       collected);
        ASSERT(added == 21);
        uint64_t in_flight = 0, queued = 0;
        dl_get_stats(&dm, NULL, NULL, NULL, &in_flight, &queued);
        ASSERT(queued == 21);

        struct uint256 out[32];
        size_t assigned = dl_assign_to_peer(&dm, 1, out, 21);
        ASSERT(assigned == 21);
        struct uint256 want40;
        bh_fake_hash(&want40, 40);
        ASSERT(uint256_eq(&out[0], &want40)); /* lowest missing goes first */
        dl_free(&dm);

        /* Bodies land: re-running the census now certifies the window. */
        for (int64_t h = 40; h <= 60; h++)
            chain.have_data[h] = 1;
        body_history_census_init(&census);
        (void)bh_run_full_census(&census, &held, &measured, &chain, 2999,
                                 256, NULL, NULL, 0, NULL);
        struct body_history_verdict after;
        ASSERT(body_history_evaluate(&held, &measured, 0, 2999, &after));
        ASSERT(after.status == BODY_HISTORY_COMPLETE);
        ASSERT(body_history_verdict_is_proven(&after));
        ASSERT(after.missing_count == 0);
        ASSERT(after.unmeasured_count == 0);

        body_coverage_free(&held);
        body_coverage_free(&measured);
        bh_fake_chain_free(&chain);
        PASS();
    } _test_next:;
    return failures;
}

/* The owner's node in miniature: genesis held, one contiguous hole covering
 * almost everything, and the top few thousand heights held. */
static int test_bh_one_contiguous_hole_from_height_one(void)
{
    int failures = 0;
    TEST("genesis plus a tail, hole from height 1 — the live-node shape") {
        struct bh_fake_chain chain;
        ASSERT(bh_fake_chain_init(&chain, 4000));
        for (int64_t h = 1; h <= 3800; h++)
            chain.have_data[h] = 0;

        struct body_coverage_map held, measured;
        body_coverage_init(&held);
        body_coverage_init(&measured);
        struct body_history_census census;
        body_history_census_init(&census);

        int64_t missing = bh_run_full_census(&census, &held, &measured,
                                             &chain, 3999, 512,
                                             NULL, NULL, 0, NULL);
        ASSERT(missing == 3800);

        struct body_history_verdict v;
        ASSERT(body_history_evaluate(&held, &measured, 0, 3999, &v));
        ASSERT(v.status == BODY_HISTORY_INCOMPLETE);
        ASSERT(v.missing_count == 3800);
        ASSERT(v.lowest_missing == 1);
        ASSERT(v.held_count == 200);   /* genesis + [3801, 3999] */
        ASSERT(v.unmeasured_count == 0);

        body_coverage_free(&held);
        body_coverage_free(&measured);
        bh_fake_chain_free(&chain);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. The census is bounded and resumable ─────────────────────── */

static int test_bh_census_is_bounded_and_resumable(void)
{
    int failures = 0;
    TEST("census walks a bounded window per pass and resumes downward") {
        struct body_history_census c;
        body_history_census_init(&c);

        int64_t lo = 0, hi = 0;
        ASSERT(body_history_census_plan(&c, 0, 9999, 1000, &lo, &hi));
        ASSERT(hi == 9999 && lo == 9000);   /* walks DOWN from the tip */
        body_history_census_advance(&c, lo, hi);
        ASSERT(c.passes == 1);

        ASSERT(body_history_census_plan(&c, 0, 9999, 1000, &lo, &hi));
        ASSERT(hi == 8999 && lo == 8000);
        body_history_census_advance(&c, lo, hi);

        /* Walk it out; the last window clamps to window_lo and the sweep
         * wraps exactly once. */
        for (int i = 0; i < 8; i++) {
            ASSERT(body_history_census_plan(&c, 0, 9999, 1000, &lo, &hi));
            body_history_census_advance(&c, lo, hi);
        }
        ASSERT(lo == 0);
        ASSERT(c.sweeps_completed == 1);
        ASSERT(c.passes == 10);

        /* A pass never exceeds its budget, even on a huge window. */
        struct body_history_census big;
        body_history_census_init(&big);
        ASSERT(body_history_census_plan(&big, 0, 3196956,
                                        BODY_HISTORY_CENSUS_BUDGET,
                                        &lo, &hi));
        ASSERT(hi - lo + 1 == BODY_HISTORY_CENSUS_BUDGET);

        /* Unusable windows are refused rather than silently "done". */
        ASSERT(!body_history_census_plan(&big, 0, -1, 4096, &lo, &hi));
        ASSERT(!body_history_census_plan(&big, 5, 1, 4096, &lo, &hi));
        ASSERT(!body_history_census_plan(&big, 0, 100, 0, &lo, &hi));
        ASSERT(!body_history_census_plan(NULL, 0, 100, 10, &lo, &hi));
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4. "At tip" is unsayable while history is unproven ─────────── */

static int test_bh_at_tip_requires_proven_history(void)
{
    int failures = 0;
    TEST("at-tip is refused on both incomplete AND unknown history") {
        struct sync_tip_state_evaluation eval;

        /* A textbook at-tip situation: every height agrees, peers present,
         * nothing queued, nothing in flight, nothing pending. The ONLY
         * variable below is the body-history verdict. */
        #define BH_PLAN(status_) \
            syncsvc_plan_periodic_tip_state(&eval, SYNC_BLOCKS_DOWNLOAD, \
                                            true, 1000, 1000, 1000, 1000, \
                                            3, 0, 0, 0, (status_))

        BH_PLAN(BODY_HISTORY_COMPLETE);
        ASSERT(eval.should_set_at_tip);      /* the only value that passes */

        BH_PLAN(BODY_HISTORY_INCOMPLETE);
        ASSERT(!eval.should_set_at_tip);     /* known hole */

        BH_PLAN(BODY_HISTORY_UNKNOWN);
        ASSERT(!eval.should_set_at_tip);     /* could not determine —
                                              * refused just as hard */

        /* The zero value is the fail-closed default: a caller that forgot to
         * set the argument gets a refusal, not a free pass. */
        enum body_history_status defaulted = 0;
        BH_PLAN(defaulted);
        ASSERT(!eval.should_set_at_tip);

        #undef BH_PLAN
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5. Singleton, persistence, dumper ──────────────────────────── */

static int test_bh_singleton_defaults_to_unknown(void)
{
    int failures = 0;
    TEST("the global verdict starts unknown and is never restored as proven") {
        body_history_reset();

        struct body_history_verdict v;
        memset(&v, 0xEE, sizeof(v));
        ASSERT(!body_history_get_verdict(&v));   /* nothing published */
        ASSERT(v.status == BODY_HISTORY_UNKNOWN);
        ASSERT(!body_history_is_proven());

        /* Publishing a complete verdict is the only way to become proven. */
        struct body_history_verdict good;
        memset(&good, 0, sizeof(good));
        good.status = BODY_HISTORY_COMPLETE;
        body_history_publish(&good);
        ASSERT(body_history_is_proven());

        /* Publishing NULL publishes ignorance — it does not leave the last
         * good news standing. */
        body_history_publish(NULL);
        ASSERT(!body_history_is_proven());
        ASSERT(body_history_get_verdict(&v));    /* published, but unknown */
        ASSERT(v.status == BODY_HISTORY_UNKNOWN);

        body_history_reset();
        ASSERT(!body_history_is_proven());
        PASS();
    } _test_next:;
    return failures;
}

/* body_history_load() restores the census cursor only; the `measured` evidence
 * map must not come back off disk, or the first pass after a restart could
 * republish COMPLETE after probing a fraction of the chain. */
static int test_bh_persistence_never_restores_a_verdict(void)
{
    int failures = 0;
    TEST("a restart resumes the cursor but must re-earn every probe") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "body_history", "main");
        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        ASSERT(progress_meta_table_ensure(db));

        body_history_reset();
        body_history_global_lock();
        ASSERT(body_coverage_insert(body_history_global_measured(), 100, 999));
        body_history_global_census()->cursor = 555;
        body_history_global_census()->cursor_valid = true;
        body_history_global_unlock();

        struct body_history_verdict good;
        memset(&good, 0, sizeof(good));
        good.status = BODY_HISTORY_COMPLETE;
        body_history_publish(&good);
        ASSERT(body_history_is_proven());
        ASSERT(body_history_save(db));

        /* Simulate the restart. */
        body_history_reset();
        ASSERT(!body_history_is_proven());
        ASSERT(body_history_load(db));

        body_history_global_lock();
        int64_t measured = body_coverage_total_covered(
            body_history_global_measured());
        int64_t cursor = body_history_global_census()->cursor;
        body_history_global_unlock();
        ASSERT(cursor == 555);     /* the work pointer came back ... */
        ASSERT(measured == 0);     /* ... the evidence did NOT ... */
        ASSERT(!body_history_is_proven()); /* ... and neither did the verdict */

        /* Load must clear stale in-memory evidence too, not merely decline to
         * add to it: a restart that skipped body_history_reset() must not
         * inherit the previous run's probes. */
        body_history_global_lock();
        ASSERT(body_coverage_insert(body_history_global_measured(), 0, 4095));
        body_history_global_unlock();
        ASSERT(body_history_load(db));
        body_history_global_lock();
        measured = body_coverage_total_covered(
            body_history_global_measured());
        body_history_global_unlock();
        ASSERT(measured == 0);

        /* gap_fill_start() can reload this singleton after an in-process
         * stop/start. A missing or malformed durable cursor must not retain
         * the prior run's in-memory work pointer. (Qualification of the
         * Hetzner handoff candidate, gist 52a8508e.) */
        ASSERT(progress_meta_delete(db, BODY_HISTORY_CURSOR_META_KEY));
        body_history_global_lock();
        body_history_global_census()->cursor = 777;
        body_history_global_census()->cursor_valid = true;
        body_history_global_unlock();
        ASSERT(body_history_load(db));
        body_history_global_lock();
        ASSERT(!body_history_global_census()->cursor_valid);
        ASSERT(body_history_global_census()->cursor == -1);
        body_history_global_unlock();

        const uint8_t malformed_cursor = 0;
        ASSERT(progress_meta_set(db, BODY_HISTORY_CURSOR_META_KEY,
                                 &malformed_cursor,
                                 sizeof(malformed_cursor)));
        body_history_global_lock();
        body_history_global_census()->cursor = 888;
        body_history_global_census()->cursor_valid = true;
        body_history_global_unlock();
        ASSERT(body_history_load(db));
        body_history_global_lock();
        ASSERT(!body_history_global_census()->cursor_valid);
        ASSERT(body_history_global_census()->cursor == -1);
        body_history_global_unlock();

        body_history_reset();
        progress_store_close();
        PASS();
    } _test_next:;
    return failures;
}

/* The boot catch-up burst runs census slices until this returns true. It
 * answers "has this boot looked at every height", weaker than "are the bodies
 * there": an INCOMPLETE window is fully measured and ends the burst. */
static int test_bh_fully_measured_is_looked_not_proven(void)
{
    int failures = 0;
    TEST("fully-measured means every height was looked at, not that it is ok") {
        body_history_reset();
        /* Nothing published: a node that has run no census has looked at
         * nothing, so the burst must keep going. */
        ASSERT(!body_history_window_fully_measured());
        ASSERT(!body_history_is_proven());

        /* Published, but part of the window is still unprobed. */
        struct body_history_verdict partial;
        memset(&partial, 0, sizeof(partial));
        partial.status = BODY_HISTORY_UNKNOWN;
        partial.window_lo = 0;
        partial.window_hi = 3196956;
        partial.window_heights = 3196957;
        partial.unmeasured_count = 3155842;
        body_history_publish(&partial);
        ASSERT(!body_history_window_fully_measured());

        /* Every height looked at, and holes found. The burst is DONE — the
         * measurement succeeded; its answer was just bad news. */
        struct body_history_verdict inc = partial;
        inc.status = BODY_HISTORY_INCOMPLETE;
        inc.unmeasured_count = 0;
        inc.missing_count = 3155842;
        body_history_publish(&inc);
        ASSERT(body_history_window_fully_measured());
        ASSERT(!body_history_is_proven());   /* looked != proven */

        /* Every height looked at and every body present. */
        struct body_history_verdict comp = inc;
        comp.status = BODY_HISTORY_COMPLETE;
        comp.missing_count = 0;
        comp.held_count = 3196957;
        body_history_publish(&comp);
        ASSERT(body_history_window_fully_measured());
        ASSERT(body_history_is_proven());

        /* A zero-height window has not been measured, it has been skipped —
         * otherwise a node with no chain would end its burst claiming a
         * completed measurement. */
        struct body_history_verdict empty;
        memset(&empty, 0, sizeof(empty));
        empty.window_lo = -1;
        empty.window_hi = -1;
        body_history_publish(&empty);
        ASSERT(!body_history_window_fully_measured());

        /* Publishing ignorance retracts it too. */
        body_history_publish(&comp);
        ASSERT(body_history_window_fully_measured());
        body_history_publish(NULL);
        ASSERT(!body_history_window_fully_measured());

        body_history_reset();
        PASS();
    } _test_next:;
    return failures;
}

static int test_bh_dump_state_json_separates_the_three(void)
{
    int failures = 0;
    TEST("dumpstate body_history publishes unknown as a status, not a gap") {
        body_history_reset();

        /* Unknown: the dump must carry status=unknown, proven=false, and a
         * blocker id — not an absent field an operator could read as fine. */
        struct json_value v = {0};
        json_set_object(&v);
        ASSERT(body_history_dump_state_json(&v, NULL));
        const struct json_value *status = json_get(&v, "status");
        const struct json_value *proven = json_get(&v, "proven");
        const struct json_value *missing = json_get(&v, "missing_count");
        const struct json_value *unmeasured = json_get(&v, "unmeasured_count");
        const struct json_value *blocker = json_get(&v, "blocker_id");
        ASSERT(status && strcmp(json_get_str(status), "unknown") == 0);
        ASSERT(proven && json_get_bool(proven) == false);
        ASSERT(missing != NULL);      /* present, and zero */
        ASSERT(unmeasured != NULL);   /* the field that tells them apart */
        ASSERT(blocker &&
               strcmp(json_get_str(blocker),
                      BODY_HISTORY_UNPROVEN_BLOCKER) == 0);
        json_free(&v);

        /* Incomplete: counts and the lowest missing height are carried. */
        struct body_history_verdict inc;
        memset(&inc, 0, sizeof(inc));
        inc.status = BODY_HISTORY_INCOMPLETE;
        inc.window_lo = 0;
        inc.window_hi = 3196956;
        inc.missing_count = 3155842;
        inc.lowest_missing = 1;
        inc.unmeasured_count = 0;
        inc.lowest_unmeasured = -1;
        body_history_publish(&inc);

        struct json_value v2 = {0};
        json_set_object(&v2);
        ASSERT(body_history_dump_state_json(&v2, NULL));
        const struct json_value *s2 = json_get(&v2, "status");
        const struct json_value *m2 = json_get(&v2, "missing_count");
        const struct json_value *l2 = json_get(&v2, "lowest_missing");
        ASSERT(s2 && strcmp(json_get_str(s2), "incomplete") == 0);
        ASSERT(m2 && json_get_int(m2) == 3155842);
        ASSERT(l2 && json_get_int(l2) == 1);
        json_free(&v2);

        /* Complete: proven, and no blocker id. */
        struct body_history_verdict comp;
        memset(&comp, 0, sizeof(comp));
        comp.status = BODY_HISTORY_COMPLETE;
        comp.lowest_missing = -1;
        comp.lowest_unmeasured = -1;
        body_history_publish(&comp);

        struct json_value v3 = {0};
        json_set_object(&v3);
        ASSERT(body_history_dump_state_json(&v3, NULL));
        const struct json_value *s3 = json_get(&v3, "status");
        const struct json_value *p3 = json_get(&v3, "proven");
        const struct json_value *b3 = json_get(&v3, "blocker_id");
        ASSERT(s3 && strcmp(json_get_str(s3), "complete") == 0);
        ASSERT(p3 && json_get_bool(p3) == true);
        ASSERT(b3 && json_get_str(b3)[0] == '\0');
        json_free(&v3);

        body_history_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6. Adversarial: a MOVING tip must not restart the sweep ────── */

/* On a live chain the tip advances during the sweep; re-anchoring the cursor
 * on every advance would pin the walk to the top band forever. */
static int test_bh_census_descends_under_a_moving_tip(void)
{
    int failures = 0;
    TEST("a tip that advances mid-sweep must not restart the census") {
        struct body_history_census c;
        body_history_census_init(&c);

        /* The owner's chain and the real cadence: one census pass per
         * gap-fill tick (5 s), one new block roughly every 75 s, so the tip
         * advances about once every 15 passes. */
        int64_t tip = 3196956;
        int64_t lo = 0, hi = 0;
        int64_t lowest = tip;
        for (int pass = 0; pass < 4000; pass++) {
            if (pass > 0 && pass % 15 == 0)
                tip++;
            ASSERT(body_history_census_plan(&c, 0, tip,
                                            BODY_HISTORY_CENSUS_BUDGET,
                                            &lo, &hi));
            body_history_census_advance(&c, lo, hi);
            if (lo < lowest)
                lowest = lo;
        }

        /* 4000 passes x 4096 heights is about five sweeps of budget; failing to
         * finish one sweep in that means the walk is stopped. */

        ASSERT(lowest == 0);
        ASSERT(c.sweeps_completed >= 1);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 7. Adversarial: the OTHER at-tip edge ──────────────────────── */

/* syncsvc_plan_periodic_tip_state is the timer-driven at-tip edge;
 * syncsvc_note_valid_block fires on every accepted block. Both are gated. */
static int test_bh_block_acceptance_refuses_unproven_history(void)
{
    int failures = 0;
    TEST("the block-acceptance at-tip edge also refuses unproven history") {
        struct sync_block_acceptance result;
        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        node.starting_height = 100;
        node.state = PEER_SYNCING_BLOCKS;

        /* Proven coverage: the edge is allowed. */
        syncsvc_note_valid_block(&result, &node, SYNC_BLOCKS_DOWNLOAD,
                                 100, 100, 0, 0, BODY_HISTORY_COMPLETE);
        ASSERT(result.reached_peer_tip);
        ASSERT(result.should_set_sync_state);
        ASSERT(result.next_sync_state == SYNC_AT_TIP);

        /* A known hole below the tip: refused. */
        syncsvc_note_valid_block(&result, &node, SYNC_BLOCKS_DOWNLOAD,
                                 100, 100, 0, 0, BODY_HISTORY_INCOMPLETE);
        ASSERT(result.reached_peer_tip);
        ASSERT(!result.should_set_sync_state);

        /* Could not determine: refused exactly as hard. */
        syncsvc_note_valid_block(&result, &node, SYNC_BLOCKS_DOWNLOAD,
                                 100, 100, 0, 0, BODY_HISTORY_UNKNOWN);
        ASSERT(result.reached_peer_tip);
        ASSERT(!result.should_set_sync_state);

        /* The zero value is the fail-closed default: a caller that forgot
         * to pass the argument gets a refusal, not a free pass. */
        enum body_history_status defaulted = 0;
        syncsvc_note_valid_block(&result, &node, SYNC_BLOCKS_DOWNLOAD,
                                 100, 100, 0, 0, defaulted);
        ASSERT(!result.should_set_sync_state);

        /* Peer bookkeeping is NOT a completeness claim and must still
         * happen, so an unproven node keeps syncing and serving normally.
         * It loses the right to say it is done, nothing else. */
        ASSERT(result.should_update_peer_state);
        ASSERT(result.next_peer_state == PEER_ACTIVE);

        /* The recent-tip bypass (b) is a HEIGHT heuristic — it must not
         * become a second way around the coverage gate. */
        uint32_t recent = (uint32_t)(platform_time_wall_time_t() - 60);
        syncsvc_note_valid_block(&result, &node, SYNC_BLOCKS_DOWNLOAD,
                                 100, 100000, recent, 0,
                                 BODY_HISTORY_UNKNOWN);
        ASSERT(!result.should_set_sync_state);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 8. Adversarial: the restored cursor must SURVIVE the next pass ── */

/* window_lo / window_hi are not persisted, so plan() must not discard the
 * restored cursor on a window-bounds mismatch; the resume must survive being
 * used. */
static int test_bh_restored_cursor_survives_the_first_pass(void)
{
    int failures = 0;
    TEST("a restored cursor still points where it did after one pass") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "body_history_resume", "main");
        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        ASSERT(progress_meta_table_ensure(db));

        body_history_reset();
        body_history_global_lock();
        body_history_global_census()->cursor = 1000000;
        body_history_global_census()->cursor_valid = true;
        body_history_global_unlock();
        ASSERT(body_history_save(db));

        /* Restart: fresh singleton, then load. */
        body_history_reset();
        ASSERT(body_history_load(db));

        /* The first census pass after boot. The window bounds are whatever
         * the live tip is — they were never persisted. */
        int64_t lo = 0, hi = 0;
        body_history_global_lock();
        bool planned = body_history_census_plan(body_history_global_census(),
                                                0, 3196956,
                                                BODY_HISTORY_CENSUS_BUDGET,
                                                &lo, &hi);
        body_history_global_unlock();
        ASSERT(planned);

        /* It must carry on from 1,000,000 — not leap back to the tip. */
        ASSERT(hi == 1000000);
        ASSERT(lo == 1000000 - BODY_HISTORY_CENSUS_BUDGET + 1);

        /* A cursor that no longer lies inside the window is still refused
         * and re-anchored: fail-closed on a reorg that shortened the chain. */
        body_history_global_lock();
        body_history_global_census()->cursor = 9000000;
        planned = body_history_census_plan(body_history_global_census(),
                                           0, 3196956,
                                           BODY_HISTORY_CENSUS_BUDGET,
                                           &lo, &hi);
        body_history_global_unlock();
        ASSERT(planned);
        ASSERT(hi == 3196956);

        body_history_reset();
        progress_store_close();
        PASS();
    } _test_next:;
    return failures;
}

/* A verdict must expire: if the index goes bad after a clean sweep, the
 * earlier evidence is demoted (body_history_census_fold INDETERMINATE branch)
 * and the verdict stops reading complete-and-proven. */
static int test_bh_a_verdict_expires_when_the_index_goes_bad(void)
{
    int failures = 0;
    TEST("a proven verdict expires once the index stops being readable") {
        struct bh_fake_chain chain;
        ASSERT(bh_fake_chain_init(&chain, 500));
        /* Sweep one: a healthy node. Every height indexed and held. */
        for (int64_t h = 0; h < 500; h++) {
            chain.indexed[h] = 1;
            chain.have_data[h] = 1;
        }

        struct body_coverage_map held, measured;
        body_coverage_init(&held);
        body_coverage_init(&measured);
        struct body_history_census census;
        body_history_census_init(&census);

        ASSERT(bh_run_full_census(&census, &held, &measured, &chain, 499, 64,
                                  NULL, NULL, 0, NULL) == 0);

        struct body_history_verdict v;
        ASSERT(body_history_evaluate(&held, &measured, 0, 499, &v));
        ASSERT(v.status == BODY_HISTORY_COMPLETE);
        ASSERT(body_history_verdict_is_proven(&v));
        ASSERT(body_coverage_total_covered(&measured) == 500);

        /* The block index becomes unreadable under a running node; `held` is
         * unchanged and must not be what certifies. */
        for (int64_t h = 0; h < 500; h++)
            chain.indexed[h] = 0;

        struct body_history_census resweep;
        body_history_census_init(&resweep);
        ASSERT(bh_run_full_census(&resweep, &held, &measured, &chain, 499, 64,
                                  NULL, NULL, 0, NULL) == 0);
        ASSERT(resweep.heights_indeterminate == 500);
        ASSERT(resweep.heights_examined == 0);

        /* THE assertion: the earlier sweep's evidence is gone. */
        ASSERT(body_coverage_total_covered(&measured) == 0);

        /* `held` is untouched: an unreadable entry is not evidence the body was
         * deleted. */
        ASSERT(body_coverage_total_covered(&held) == 500);

        struct body_history_verdict after;
        ASSERT(body_history_evaluate(&held, &measured, 0, 499, &after));
        ASSERT(after.status == BODY_HISTORY_UNKNOWN);
        ASSERT(!body_history_verdict_is_proven(&after));
        ASSERT(after.unmeasured_count == 500);
        ASSERT(after.missing_count == 0);   /* still no INVENTED hole */

        bh_fake_chain_free(&chain);
        body_coverage_free(&held);
        body_coverage_free(&measured);
        PASS();
    } _test_next:;
    return failures;
}

/* The per-pass cap must be able to drain a window already measured: the census
 * advances past whatever a pass declines to request. */
static int test_bh_normal_backfill_drains_the_window_it_measured(void)
{
    int failures = 0;
    TEST("one NORMAL pass requests every hole the same pass measured") {
        /* One window's worth of chain, holed far past the throttled cap. */
        const int64_t budget = BODY_HISTORY_CENSUS_BUDGET;
        const int64_t n_holes = BODY_HISTORY_ENQUEUE_MAX * 4 + 7;
        struct bh_fake_chain chain;
        ASSERT(bh_fake_chain_init(&chain, budget));
        for (int64_t h = 0; h < n_holes; h++)
            chain.have_data[h] = 0;

        struct body_coverage_map held, measured;
        body_coverage_init(&held);
        body_coverage_init(&measured);
        struct body_history_census census;
        body_history_census_init(&census);

        uint8_t *classes = malloc((size_t)budget);
        struct uint256 *hashes = malloc((size_t)budget * sizeof(*hashes));
        ASSERT(classes && hashes);

        /* Exactly ONE pass, the way body_backfill_pass runs one per tick. */
        int64_t lo = 0, hi = 0;
        ASSERT(body_history_census_plan(&census, 0, budget - 1, budget,
                                        &lo, &hi));
        ASSERT(lo == 0 && hi == budget - 1);
        size_t n = body_history_census_probe_window(lo, hi, bh_fake_probe,
                                                    &chain, classes, hashes,
                                                    (size_t)budget);
        struct body_history_pass_result res;
        ASSERT(body_history_census_fold(&census, &held, &measured, lo,
                                        classes, n, &res));
        ASSERT(res.missing == n_holes);

        struct uint256 *out_h =
            malloc((size_t)budget * sizeof(*out_h));
        int32_t *out_n = malloc((size_t)budget * sizeof(*out_n));
        ASSERT(out_h && out_n);

        /* The throttled default takes its 64 and leaves the rest unrequested. */
        size_t drip = body_history_census_collect_missing(
            lo, classes, hashes, n, out_h, out_n,
            BODY_HISTORY_ENQUEUE_MAX);
        ASSERT(drip == BODY_HISTORY_ENQUEUE_MAX);
        ASSERT((int64_t)drip < n_holes);

        /* The operator-selected cap drains the same window in that one
         * pass, so a single descent of the chain is enough. */
        size_t drain = body_history_census_collect_missing(
            lo, classes, hashes, n, out_h, out_n,
            BODY_HISTORY_ENQUEUE_MAX_NORMAL);
        ASSERT(drain == (size_t)n_holes);
        ASSERT((int64_t)drain == res.missing);

        /* Structural, not incidental: the cap must cover a whole window,
         * or the cursor once again advances past holes it just counted. */
        ASSERT(BODY_HISTORY_ENQUEUE_MAX_NORMAL >= BODY_HISTORY_CENSUS_BUDGET);

        /* What it collected is the real work: the lowest hole first, and
         * every entry a height the pass actually marked missing. */
        struct uint256 want0_drain;
        bh_fake_hash(&want0_drain, 0);
        ASSERT(uint256_eq(&out_h[0], &want0_drain));
        ASSERT(out_n[0] == 0);
        ASSERT(out_n[drain - 1] == (int32_t)(n_holes - 1));

        free(out_h);
        free(out_n);
        free(classes);
        free(hashes);
        body_coverage_free(&held);
        body_coverage_free(&measured);
        bh_fake_chain_free(&chain);
        PASS();
    } _test_next:;
    return failures;
}

/* The descending census cursor (and the census-only burst) can sit in a
 * held tip band while a known hole below the tip pauses background
 * validation. The backfill pass must collect that named lowest hole even
 * when the current census window has nothing to request. */
static int test_bh_lowest_missing_fill_when_cursor_is_at_tip(void)
{
    int failures = 0;
    TEST("lowest known hole is collected while the census cursor sits at the tip") {
        const int64_t budget = 256;
        const int64_t tip = budget * 3 - 1;
        struct bh_fake_chain chain;
        ASSERT(bh_fake_chain_init(&chain, tip + 1));
        for (int64_t h = 10; h <= 40; h++)
            chain.have_data[h] = 0;

        struct body_coverage_map held, measured;
        body_coverage_init(&held);
        body_coverage_init(&measured);
        struct body_history_census census;
        body_history_census_init(&census);

        ASSERT(bh_run_full_census(&census, &held, &measured, &chain, tip,
                                  budget, NULL, NULL, 0, NULL) == 31);
        struct body_history_verdict v;
        ASSERT(body_history_evaluate(&held, &measured, 0, tip, &v));
        ASSERT(v.status == BODY_HISTORY_INCOMPLETE);
        ASSERT(v.lowest_missing == 10);
        ASSERT(v.missing_count == 31);

        /* Wrap: a new sweep starts at the tip, matching the live cursor
         * after sweeps_completed increments. That window is fully held. */
        body_history_census_init(&census);
        int64_t lo = 0, hi = 0;
        ASSERT(body_history_census_plan(&census, 0, tip, budget, &lo, &hi));
        ASSERT(hi == tip);
        ASSERT(lo > v.lowest_missing);

        uint8_t *classes = malloc((size_t)budget);
        struct uint256 *hashes = malloc((size_t)budget * sizeof(*hashes));
        ASSERT(classes && hashes);
        size_t n = body_history_census_probe_window(lo, hi, bh_fake_probe,
                                                    &chain, classes, hashes,
                                                    (size_t)budget);
        struct uint256 out_h[64];
        int32_t out_n[64];
        ASSERT(body_history_census_collect_missing(
                   lo, classes, hashes, n, out_h, out_n, 64) == 0);

        int64_t fill_lo = v.lowest_missing;
        int64_t fill_hi = fill_lo + budget - 1;
        if (fill_hi > tip)
            fill_hi = tip;
        n = body_history_census_probe_window(fill_lo, fill_hi, bh_fake_probe,
                                             &chain, classes, hashes,
                                             (size_t)budget);
        size_t fill_got = body_history_census_collect_missing(
            fill_lo, classes, hashes, n, out_h, out_n, 64);
        ASSERT(fill_got == 31);
        ASSERT(out_n[0] == 10);

        struct download_manager dm;
        dl_init(&dm);
        ASSERT(dl_queue_blocks_class(&dm, out_h, out_n, fill_got,
                                     DL_WORK_HISTORY) == fill_got);
        uint64_t queued = 0;
        dl_get_stats(&dm, NULL, NULL, NULL, NULL, &queued);
        ASSERT(queued == 31);
        dl_free(&dm);

        free(classes);
        free(hashes);
        body_coverage_free(&held);
        body_coverage_free(&measured);
        bh_fake_chain_free(&chain);
        PASS();
    } _test_next:;
    return failures;
}

/* Exact terminal inputs from an independent C3 run. H* reaching a
 * checkpoint-bootstrapped peer tip does not supply the absent historical
 * bodies. This is a refusal witness, not a full-node C3 PASS. */
static int test_bh_c3_checkpoint_terminal_witness(void)
{
    int failures = 0;
    TEST("C3 equal durable tip with missing checkpoint prefix stays nonterminal") {
        const int tip = 3248094;
        const int checkpoint = 3056758;
        struct body_coverage_map held, measured;
        struct body_history_verdict verdict;
        struct sync_tip_state_evaluation eval;
        body_coverage_init(&held);
        body_coverage_init(&measured);
        ASSERT(body_coverage_insert(&held, 0, 0));
        ASSERT(body_coverage_insert(&held, checkpoint + 1, tip));
        ASSERT(body_coverage_insert(&measured, 0, tip));
        ASSERT(body_history_evaluate(&held, &measured, 0, tip, &verdict));
        ASSERT(verdict.status == BODY_HISTORY_INCOMPLETE);
        ASSERT(verdict.held_count == 191337);
        ASSERT(verdict.missing_count == checkpoint);
        ASSERT(verdict.lowest_missing == 1);
        ASSERT(verdict.unmeasured_count == 0);
        syncsvc_plan_periodic_tip_state(&eval, SYNC_BLOCKS_DOWNLOAD, true,
                                       tip, tip, tip, tip, 1, 0, 0, 0,
                                       verdict.status);
        ASSERT(eval.target_height == tip);
        ASSERT(eval.served_gap == 0 && eval.local_gap == 0);
        ASSERT(!eval.should_set_at_tip);

        /* Only the controlled unit fixture gains its missing coverage here;
         * no running node state or production completeness predicate changes. */
        ASSERT(body_coverage_insert(&held, 1, checkpoint));
        ASSERT(body_history_evaluate(&held, &measured, 0, tip, &verdict));
        ASSERT(verdict.status == BODY_HISTORY_COMPLETE);
        ASSERT(verdict.missing_count == 0);
        syncsvc_plan_periodic_tip_state(&eval, SYNC_BLOCKS_DOWNLOAD, true,
                                       tip, tip, tip, tip, 1, 0, 0, 0,
                                       verdict.status);
        ASSERT(eval.should_set_at_tip);
        body_coverage_free(&held);
        body_coverage_free(&measured);
        PASS();
    } _test_next:;
    return failures;
}

static bool bh_service_chain(struct main_state *ms, int tip, int missing_hi)
{
    struct block_index *previous = NULL;
    for (int h = 0; h <= tip; h++) {
        struct uint256 hash;
        bh_fake_hash(&hash, h);
        struct block_index *bi = chainstate_insert_block_index(
            (struct chainstate *)ms, &hash);
        if (!bi)
            return false;
        bi->nHeight = h;
        bi->pprev = previous;
        bi->nStatus = BLOCK_VALID_SCRIPTS;
        if (h == 0 || h > missing_hi)
            bi->nStatus |= BLOCK_HAVE_DATA;
        previous = bi;
    }
    return active_chain_move_window_tip(&ms->chain_active, previous);
}

static int test_bh_service_separates_receipt_from_accounting(void)
{
    int failures = 0;
    TEST("backfill distinguishes scheduled received and body-accounted work") {
        struct main_state *ms = calloc(1, sizeof(*ms));
        ASSERT(ms);
        main_state_init(ms);
        ASSERT(bh_service_chain(ms, 100, 1));
        struct download_manager dm;
        dl_init(&dm);
        body_history_reset();
        ASSERT(body_backfill_pass(ms, &dm, false, false, NULL, NULL) == 1);
        uint64_t requested = 0, received = 0, queued = 0;
        dl_get_stats(&dm, &requested, &received, NULL, NULL, &queued);
        ASSERT(queued == 1 && requested == 0 && received == 0);
        struct uint256 hash;
        bh_fake_hash(&hash, 1);
        struct uint256 assigned;
        ASSERT(dl_assign_to_peer(&dm, 7, &assigned, 1) == 1);
        ASSERT(uint256_eq(&assigned, &hash));
        ASSERT(dl_mark_received(&dm, &hash) == 7);
        ASSERT(body_backfill_pass(ms, &dm, false, true, NULL, NULL) == 0);
        struct body_history_verdict v;
        ASSERT(body_history_get_verdict(&v));
        ASSERT(v.status == BODY_HISTORY_INCOMPLETE && v.lowest_missing == 1);
        dl_get_stats(&dm, &requested, &received, NULL, NULL, &queued);
        ASSERT(requested == 1 && received == 1);
        printf("[C3 history control] requested=1 received=1 missing=1 until body accounting\n");

        /* Unit input standing for the existing verified persistence boundary;
         * this test does not claim a receipt validates or writes a body. */
        active_chain_at(&ms->chain_active, 1)->nStatus |= BLOCK_HAVE_DATA;
        ASSERT(body_backfill_pass(ms, &dm, false, true, NULL, NULL) == 0);
        ASSERT(body_history_get_verdict(&v));
        ASSERT(v.status == BODY_HISTORY_COMPLETE && v.missing_count == 0);
        dl_free(&dm);
        main_state_free(ms);
        free(ms);
        body_history_reset();
        PASS();
    } _test_next:;
    return failures;
}

static int test_bh_service_advances_after_lowest_window_fills(void)
{
    int failures = 0;
    TEST("real backfill service advances beyond a durably accounted lowest window") {
        const int window = BODY_HISTORY_CENSUS_BUDGET;
        const int tip = window * 8;
        struct main_state *ms = calloc(1, sizeof(*ms));
        ASSERT(ms);
        main_state_init(ms);
        ASSERT(bh_service_chain(ms, tip, window + 64));
        struct download_manager dm;
        dl_init(&dm);
        body_history_reset();
        for (int pass = 0; pass < 10 && !body_history_window_fully_measured(); pass++)
            ASSERT(body_backfill_pass(ms, &dm, false, true, NULL, NULL) == 0);
        struct body_history_verdict v;
        ASSERT(body_history_get_verdict(&v));
        ASSERT(v.lowest_missing == 1 && v.unmeasured_count == 0);

        /* Recorded HAVE_DATA is the post-persistence input, not a receipt.
         * The old published coverage deliberately remains stale. */
        for (int h = 1; h <= window; h++)
            active_chain_at(&ms->chain_active, h)->nStatus |= BLOCK_HAVE_DATA;
        body_history_global_lock();
        body_history_global_census()->cursor = tip;
        body_history_global_census()->cursor_valid = true;
        body_history_global_unlock();
        int64_t started_us = platform_time_monotonic_us();
        clock_t cpu_start = clock();
        int first = body_backfill_pass(ms, &dm, false, false, NULL, NULL);
        int second = body_backfill_pass(ms, &dm, false, false, NULL, NULL);
        int64_t first_work_us = platform_time_monotonic_us() - started_us;
        clock_t cpu_end = clock();
        body_history_global_lock();
        int64_t cursor_after = body_history_global_census()->cursor;
        body_history_global_unlock();
        printf("[C3 window mechanics] cursor-before=%d cursor-after=%lld two-pass-wall-us=%lld cpu-us=%.0f\n",
               tip, (long long)cursor_after, (long long)first_work_us,
               cpu_start == (clock_t)-1 || cpu_end == (clock_t)-1 ? -1.0 :
               1000000.0 * (double)(cpu_end - cpu_start) / CLOCKS_PER_SEC);
        uint64_t queued = 0;
        dl_get_stats(&dm, NULL, NULL, NULL, NULL, &queued);
        bool next_window_queued = false;
        for (size_t i = 0; i < dm.queue_len; i++)
            if (dm.queue_heights[i] == window + 1)
                next_window_queued = true;
        printf("[C3 history witness] first=%d second=%d queued=%llu next4097=%d\n",
               first, second, (unsigned long long)queued, next_window_queued);
        printf("[C3 history latency] next-window-observed-us=%lld\n",
               (long long)(next_window_queued ? first_work_us : -1));
        ASSERT(queued <= BODY_HISTORY_ENQUEUE_MAX * 2);
        ASSERT(next_window_queued);
        ASSERT(body_history_get_verdict(&v));
        ASSERT(v.lowest_missing == window + 1);
        ASSERT(!body_history_verdict_is_proven(&v));
        int duplicate = body_backfill_pass(ms, &dm, false, false, NULL, NULL);
        ASSERT(duplicate == 0);
        size_t received = 0;
        const int batches = (64 + DL_MAX_HISTORY_PER_PEER - 1) /
                            DL_MAX_HISTORY_PER_PEER;
        for (int batch = 0; batch < batches && received < 64; batch++) {
            struct uint256 assigned[DL_MAX_HISTORY_IN_FLIGHT];
            size_t n = dl_assign_to_peer(&dm, 7, assigned, DL_MAX_HISTORY_IN_FLIGHT);
            ASSERT(n > 0 && n <= DL_MAX_HISTORY_PER_PEER);
            for (size_t i = 0; i < n; i++) {
                ASSERT(dl_mark_received(&dm, &assigned[i]) == 7);
                struct block_index *bi = block_map_find(&ms->map_block_index,
                                                        &assigned[i]);
                ASSERT(bi && bi->nHeight > window);
                bi->nStatus |= BLOCK_HAVE_DATA;
                received++;
            }
        }
        ASSERT(received == 64);
        ASSERT(body_backfill_pass(ms, &dm, false, false, NULL, NULL) == 0);
        ASSERT(body_history_get_verdict(&v));
        ASSERT(body_history_verdict_is_proven(&v));
        printf("[C3 history latency] controlled-accounting-complete-us=%lld\n",
               (long long)(platform_time_monotonic_us() - started_us));
        dl_free(&dm);
        main_state_free(ms);
        free(ms);
        body_history_reset();
        PASS();
    } _test_next:;
    return failures;
}

static int bh_elapsed_compare(const void *a, const void *b)
{
    int64_t left = *(const int64_t *)a;
    int64_t right = *(const int64_t *)b;
    return (left > right) - (left < right);
}

static int test_bh_service_full_queue_is_bounded(void)
{
    int failures = 0;
    TEST("full queue backpressure keeps census live without growing downloads") {
        struct main_state *ms = calloc(1, sizeof(*ms));
        ASSERT(ms);
        main_state_init(ms);
        ASSERT(bh_service_chain(ms, 1000, 500));
        struct download_manager dm;
        dl_init(&dm);
        body_history_reset();
        for (int h = 1; h <= 300; h++) {
            struct uint256 hash;
            int32_t height = h;
            bh_fake_hash(&hash, h);
            ASSERT(dl_queue_blocks_class(&dm, &hash, &height, 1,
                                         DL_WORK_HISTORY) == 1);
        }
        size_t initial_cap = dm.queue_cap;
        int64_t elapsed[20];
        for (int sample = 0; sample < 20; sample++) {
            int64_t begin = platform_time_monotonic_us();
            ASSERT(body_backfill_pass(ms, &dm, false, false, NULL, NULL) == 0);
            elapsed[sample] = platform_time_monotonic_us() - begin;
            ASSERT(dm.queue_len == 300 && dm.queue_cap == initial_cap);
            struct body_history_verdict v;
            ASSERT(body_history_get_verdict(&v));
            ASSERT(v.status == BODY_HISTORY_INCOMPLETE && v.missing_count == 500);
        }
        qsort(elapsed, 20, sizeof(elapsed[0]), bh_elapsed_compare);
        printf("[C3 backpressure latency] n=20 service-completion-us p50=%lld p95=%lld queue=300 capacity=%zu\n",
               (long long)elapsed[9], (long long)elapsed[18], initial_cap);
        dl_free(&dm);
        main_state_free(ms);
        free(ms);
        body_history_reset();
        PASS();
    } _test_next:;
    return failures;
}

static int test_bh_service_boundary(int accounted, int remaining)
{
    int failures = 0;
    TEST("hole-directed refresh crosses arbitrary windows without duplicate receipts") {
        const int tip = BODY_HISTORY_CENSUS_BUDGET * 8 + 17;
        struct main_state *ms = calloc(1, sizeof(*ms));
        ASSERT(ms);
        main_state_init(ms);
        ASSERT(bh_service_chain(ms, tip, accounted + remaining));
        struct download_manager dm;
        dl_init(&dm);
        body_history_reset();
        (void)body_backfill_catch_up(ms, &dm, false, NULL, NULL, NULL, NULL);
        ASSERT(body_history_window_fully_measured());
        for (int h = 1; h <= accounted; h++)
            active_chain_at(&ms->chain_active, h)->nStatus |= BLOCK_HAVE_DATA;
        body_history_global_lock();
        body_history_global_census()->cursor = tip;
        body_history_global_unlock();
        /* Each hole probe consumes at most the existing census budget.
         * Allow one probe per accounted window, then one opportunity to
         * enqueue the newly exposed hole; never increase the service cap. */
        const int passes = (accounted + BODY_HISTORY_CENSUS_BUDGET - 1) /
                           BODY_HISTORY_CENSUS_BUDGET + 1;
        for (int pass = 0; pass < passes; pass++)
            (void)body_backfill_pass(ms, &dm, false, false, NULL, NULL);
        struct body_history_verdict v;
        ASSERT(body_history_get_verdict(&v));
        printf("[C3 boundary] accounted=%d remaining=%d lowest=%lld queued=%zu\n",
               accounted, remaining, (long long)v.lowest_missing, dm.queue_len);
        ASSERT(v.lowest_missing == accounted + 1);
        ASSERT(dm.queue_len == (size_t)remaining);
        ASSERT(body_backfill_pass(ms, &dm, false, false, NULL, NULL) == 0);
        size_t received = 0;
        const int batches = (remaining + DL_MAX_HISTORY_PER_PEER - 1) /
                            DL_MAX_HISTORY_PER_PEER;
        for (int batch = 0; batch < batches && received < (size_t)remaining; batch++) {
            struct uint256 hashes[DL_MAX_HISTORY_IN_FLIGHT];
            size_t n = dl_assign_to_peer(&dm, 7, hashes, DL_MAX_HISTORY_IN_FLIGHT);
            ASSERT(n > 0 && n <= DL_MAX_HISTORY_PER_PEER);
            for (size_t i = 0; i < n; i++) {
                ASSERT(dl_mark_received(&dm, &hashes[i]) == 7);
                ASSERT(dl_mark_received(&dm, &hashes[i]) == UINT32_MAX);
                struct block_index *bi = block_map_find(&ms->map_block_index, &hashes[i]);
                ASSERT(bi && bi->nHeight > accounted);
                bi->nStatus |= BLOCK_HAVE_DATA;
                received++;
            }
        }
        ASSERT(received == (size_t)remaining);
        ASSERT(body_backfill_pass(ms, &dm, false, false, NULL, NULL) == 0);
        ASSERT(body_history_get_verdict(&v));
        ASSERT(body_history_verdict_is_proven(&v));
        uint64_t total_received = 0;
        dl_get_stats(&dm, NULL, &total_received, NULL, NULL, NULL);
        ASSERT(total_received == (uint64_t)remaining);
        dl_free(&dm);
        main_state_free(ms);
        free(ms);
        body_history_reset();
        PASS();
    } _test_next:;
    return failures;
}

struct bh_abort_fixture { int heartbeats; };
static bool bh_abort_after_slice(void *ctx)
{
    return ((struct bh_abort_fixture *)ctx)->heartbeats > 0;
}
static void bh_abort_heartbeat(void *ctx)
{
    ((struct bh_abort_fixture *)ctx)->heartbeats++;
}

static int test_bh_service_abort_resume_rewind(void)
{
    int failures = 0;
    TEST("real census abort resumes without queues or false completion and handles rewind") {
        struct main_state *ms = calloc(1, sizeof(*ms));
        ASSERT(ms);
        main_state_init(ms);
        ASSERT(bh_service_chain(ms, 16384, 1));
        struct download_manager dm;
        dl_init(&dm);
        body_history_reset();
        struct bh_abort_fixture abort = {0};
        ASSERT(body_backfill_catch_up(ms, &dm, false, bh_abort_after_slice,
                                      &abort, bh_abort_heartbeat, &abort) == 1);
        ASSERT(abort.heartbeats == 1 && dm.queue_len == 0);
        struct body_history_verdict v;
        ASSERT(body_history_get_verdict(&v));
        ASSERT(v.status == BODY_HISTORY_UNKNOWN && !body_history_verdict_is_proven(&v));
        ASSERT(body_backfill_catch_up(ms, &dm, false, bh_abort_after_slice,
                                      &abort, bh_abort_heartbeat, &abort) == 0);
        ASSERT(dm.queue_len == 0);
        /* Resume is a real burst invocation; no forced completion flag. */
        ASSERT(body_backfill_catch_up(ms, &dm, false, NULL, NULL, NULL, NULL) > 0);
        ASSERT(body_history_get_verdict(&v));
        ASSERT(v.status == BODY_HISTORY_INCOMPLETE && v.missing_count == 1);
        /* Rewind changes the unit chain input. A fresh service pass must
         * evaluate the shortened scope and retain its actual hole. */
        ASSERT(active_chain_move_window_tip(&ms->chain_active,
                                            active_chain_at(&ms->chain_active, 17)));
        ASSERT(body_backfill_pass(ms, &dm, true, false, NULL, NULL) == 0);
        ASSERT(body_history_get_verdict(&v));
        ASSERT(v.window_hi == 17 && v.missing_count == 1);
        ASSERT(!body_history_verdict_is_proven(&v) && dm.queue_len == 0);
        /* Restarted measurement never imports a cached complete verdict. */
        body_history_reset();
        ASSERT(!body_history_get_verdict(&v) || !body_history_verdict_is_proven(&v));
        ASSERT(body_backfill_pass(ms, &dm, false, false, NULL, NULL) == 1);
        ASSERT(body_backfill_pass(ms, &dm, false, false, NULL, NULL) == 0);
        ASSERT(dm.queue_len == 1);
        dl_free(&dm);
        main_state_free(ms);
        free(ms);
        body_history_reset();
        PASS();
    } _test_next:;
    return failures;
}

int test_body_history(void)
{
    int failures = 0;
    failures += test_bh_service_abort_resume_rewind();
    failures += test_bh_service_boundary(4095, 2);
    failures += test_bh_service_boundary(4096, 2);
    failures += test_bh_service_boundary(8192, 17);
    failures += test_bh_service_full_queue_is_bounded();
    failures += test_bh_service_separates_receipt_from_accounting();
    failures += test_bh_service_advances_after_lowest_window_fills();
    failures += test_bh_c3_checkpoint_terminal_witness();
    failures += test_bh_a_verdict_expires_when_the_index_goes_bad();
    failures += test_bh_census_descends_under_a_moving_tip();
    failures += test_bh_restored_cursor_survives_the_first_pass();
    failures += test_bh_block_acceptance_refuses_unproven_history();
    failures += test_bh_unreadable_index_is_not_no_hole();
    failures += test_bh_restored_coverage_is_a_claim_not_a_look();
    failures += test_bh_null_probe_leaves_everything_unmeasured();
    failures += test_bh_partial_read_does_not_certify();
    failures += test_bh_evaluate_failure_paths_are_unknown();
    failures += test_bh_below_tip_hole_found_and_enqueued();
    failures += test_bh_normal_backfill_drains_the_window_it_measured();
    failures += test_bh_lowest_missing_fill_when_cursor_is_at_tip();
    failures += test_bh_one_contiguous_hole_from_height_one();
    failures += test_bh_census_is_bounded_and_resumable();
    failures += test_bh_at_tip_requires_proven_history();
    failures += test_bh_singleton_defaults_to_unknown();
    failures += test_bh_persistence_never_restores_a_verdict();
    failures += test_bh_fully_measured_is_looked_not_proven();
    failures += test_bh_dump_state_json_separates_the_three();
    return failures;
}

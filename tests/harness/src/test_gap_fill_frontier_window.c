/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pins gap-fill's anti-wedge window math. The service must refill from the
 * reducer/body-fetch frontier, skip bodies already present, and choose the
 * connectable bottom of a large header gap.
 */

#include "test/test_core.h"
#include "json/json.h"

#include "chain/chain.h"
#include "services/gap_fill_service.h"
#include "util/safe_alloc.h"

#include <stdlib.h>

#define GF_CHECK(name, expr) do {                                      \
    printf("gap_fill_frontier_window: %s... ", (name));               \
    if (expr) printf("OK\n");                                         \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

static void gf_hash_for_height(struct uint256 *out, int height)
{
    for (size_t i = 0; i < sizeof(out->data); i++)
        out->data[i] = (uint8_t)(height + (int)i * 17);
}

static bool gf_build_chain(int count, struct block_index **blocks_out,
                           struct uint256 **hashes_out)
{
    struct block_index *blocks =
        zcl_calloc((size_t)count, sizeof(*blocks), "gf_blocks");
    struct uint256 *hashes =
        zcl_calloc((size_t)count, sizeof(*hashes), "gf_hashes");
    if (!blocks || !hashes) {
        free(blocks);
        free(hashes);
        return false;
    }

    for (int h = 0; h < count; h++) {
        block_index_init(&blocks[h]);
        gf_hash_for_height(&hashes[h], h);
        blocks[h].hashBlock = hashes[h];
        blocks[h].phashBlock = &blocks[h].hashBlock;
        blocks[h].nHeight = h;
        blocks[h].pprev = h > 0 ? &blocks[h - 1] : NULL;
    }

    *blocks_out = blocks;
    *hashes_out = hashes;
    return true;
}

int test_gap_fill_frontier_window(void)
{
    printf("\n=== gap_fill_frontier_window ===\n");
    int failures = 0;

    struct gap_fill_window w;

    bool has = gap_fill_compute_window(7253, 7600, 6764, &w);
    GF_CHECK("body-fetch cursor anchors below active tip",
             has && w.effective_tip_h == 6763 && w.lo == 6764 &&
                 w.hi == 7600 && w.count == 837);

    /* S2.4: gap_fill_compute_window's floor cursor is generic. Feeding it
     * the (structurally faster, body-independent) validate_headers cursor
     * instead of a stalled body_fetch cursor must let the window advance up
     * to active_tip_h again — not stay pinned at the stalled low value —
     * while GAPFILL_WINDOW still bounds it. */
    {
        struct gap_fill_window w_stalled, w_decoupled;
        int active_tip_h = 3176325;      /* reducer-connected tip */
        int best_header_h = 3176325 + GAPFILL_WINDOW + 500; /* headers ahead */
        uint64_t stalled_body_fetch_cursor = 3176200; /* stuck behind tip */
        uint64_t advancing_validate_headers_cursor =
            (uint64_t)best_header_h; /* headers keep pace with announces */

        bool has_stalled = gap_fill_compute_window(
            active_tip_h, best_header_h, stalled_body_fetch_cursor,
            &w_stalled);
        GF_CHECK("stalled body_fetch cursor still floors the window",
                 has_stalled &&
                     w_stalled.effective_tip_h ==
                         (int)stalled_body_fetch_cursor - 1);

        bool has_decoupled = gap_fill_compute_window(
            active_tip_h, best_header_h, advancing_validate_headers_cursor,
            &w_decoupled);
        GF_CHECK("validate_headers cursor lets the window advance to active tip",
                 has_decoupled &&
                     w_decoupled.effective_tip_h == active_tip_h &&
                     w_decoupled.lo == active_tip_h + 1);
        GF_CHECK("decoupled window still bounded by GAPFILL_WINDOW",
                 w_decoupled.count == GAPFILL_WINDOW &&
                     w_decoupled.hi == active_tip_h + GAPFILL_WINDOW);
    }

    struct block_index body_missing;
    struct block_index body_present;
    struct uint256 hash;
    gf_hash_for_height(&hash, 42);
    block_index_init(&body_missing);
    body_missing.nHeight = 42;
    body_missing.hashBlock = hash;
    body_missing.phashBlock = &body_missing.hashBlock;
    block_index_init(&body_present);
    body_present.nHeight = 43;
    body_present.hashBlock = hash;
    body_present.phashBlock = &body_present.hashBlock;
    body_present.nStatus = BLOCK_HAVE_DATA;
    GF_CHECK("missing block with hash is queueable",
             gap_fill_block_needs_queue(&body_missing));
    GF_CHECK("BLOCK_HAVE_DATA block is not queueable",
             !gap_fill_block_needs_queue(&body_present));
    GF_CHECK("NULL hash block is not queueable",
             !gap_fill_block_needs_queue(&(struct block_index){0}));

    int best_h = GAPFILL_WINDOW + 80;
    struct block_index *blocks = NULL;
    struct uint256 *hashes = NULL;
    bool built = gf_build_chain(best_h + 1, &blocks, &hashes);
    GF_CHECK("synthetic pprev chain built", built);
    if (built) {
        has = gap_fill_compute_window(10, best_h, 0, &w);
        struct block_index *start =
            gap_fill_window_walk_start(&blocks[best_h], &w);
        GF_CHECK("large gap caps at GAPFILL_WINDOW",
                 has && w.count == GAPFILL_WINDOW && w.lo == 11 &&
                     w.hi == 10 + GAPFILL_WINDOW);
        GF_CHECK("large gap starts at connectable bottom window",
                 start == &blocks[10 + GAPFILL_WINDOW]);
    }
    free(blocks);
    free(hashes);

    /* Regression: during initial sync the validated-header lead exceeds the
     * old 131072-step pprev cap.  The production index has skip pointers, so
     * positioning must use them instead of falling back to the far-ahead
     * best header.  These two sparse nodes model one valid skip hop spanning
     * twice the old cap without allocating a giant fixture chain. */
    {
        struct block_index far_best;
        struct block_index bottom;
        block_index_init(&far_best);
        block_index_init(&bottom);
        far_best.nHeight = 786432;
        bottom.nHeight = 524288;
        far_best.pskip = &bottom;

        struct gap_fill_window far_window = {
            .hi = bottom.nHeight,
            .has_work = true,
        };
        struct block_index *start =
            gap_fill_window_walk_start(&far_best, &far_window);
        GF_CHECK("large header lead uses skip ancestor for bottom window",
                 start == &bottom);

        far_best.pskip = NULL;
        start = gap_fill_window_walk_start(&far_best, &far_window);
        GF_CHECK("broken ancestry refuses instead of using far-ahead best",
                 start == NULL);
    }

    /* Smoke-test the diagnostics dumper (`z23 dumpstate gap_fill`):
     * the service was never started in this test, so it must still report
     * a well-formed, not-running snapshot instead of crashing. */
    {
        struct json_value v = {0};
        json_set_object(&v);
        bool ok = gap_fill_dump_state_json(&v, NULL);
        const struct json_value *running = json_get(&v, "running");
        const struct json_value *passes = json_get(&v, "passes");
        GF_CHECK("dump_state_json returns true and reports running+passes",
                 ok && running && json_get_bool(running) == false &&
                     passes && json_get_int(passes) == 0);
        json_free(&v);
    }

    printf("gap_fill_frontier_window: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}

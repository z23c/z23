/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * block_height_find(): the per-height block census the self-heal conditions
 * use instead of scanning the whole block map on every poll. The census must
 * return exactly what a full scan returns, observe status flags set after it
 * was built, and rebuild when the map, the tip or the best header changes.
 */

#include "test/test_core.h"

#include "conditions/block_height_census.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdio.h>
#include <string.h>

#define BHC_CHECK(name, expr) do {                       \
    printf("block_height_census: %s... ", (name));       \
    if (expr) printf("OK\n");                            \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

static struct block_index *bhc_insert(struct main_state *ms, int h, int salt,
                                      struct block_index *prev,
                                      unsigned status)
{
    struct uint256 hash;
    memset(&hash, 0, sizeof(hash));
    hash.data[0] = (uint8_t)(h & 0xFF);
    hash.data[1] = (uint8_t)((h >> 8) & 0xFF);
    hash.data[2] = (uint8_t)(salt & 0xFF);
    hash.data[3] = (uint8_t)((salt >> 8) & 0xFF);
    hash.data[4] = 0x5C;
    struct block_index *pi =
        chainstate_insert_block_index((struct chainstate *)ms, &hash);
    if (!pi)
        return NULL;
    pi->nHeight = h;
    pi->nStatus = status;
    pi->pprev = prev;
    arith_uint256_set_u64(&pi->nChainWork, (uint64_t)(h + 1));
    return pi;
}

static bool pred_failed(const struct block_index *p, void *ctx)
{
    (void)ctx;
    return (p->nStatus & BLOCK_FAILED_MASK) != 0;
}

static bool pred_any(const struct block_index *p, void *ctx)
{
    (void)p;
    (void)ctx;
    return true;
}

/* Reference: the full-map scan the census replaces. */
static struct block_index *bhc_scan(struct main_state *ms, int h,
                                    block_height_pred_fn pred)
{
    size_t iter = 0;
    struct block_index *p = NULL;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &p))
        if (p && p->nHeight == h && pred(p, NULL))
            return p;
    return NULL;
}

static int bhc_case_matches_scan_and_caches(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);
    block_height_census_test_reset();

    struct block_index *g = bhc_insert(&ms, 0, 0, NULL, BLOCK_VALID_TREE);
    struct block_index *a = bhc_insert(&ms, 1, 1, g, BLOCK_VALID_TREE);
    struct block_index *b = bhc_insert(&ms, 1, 2, g, BLOCK_VALID_TREE);
    bhc_insert(&ms, 2, 3, a, BLOCK_VALID_TREE);

    BHC_CHECK("no failed block at h=1",
              block_height_find(&ms, 1, pred_failed, NULL) == NULL);
    unsigned long scans = block_height_census_test_scans();
    BHC_CHECK("first query scans once", scans == 1);

    BHC_CHECK("repeat query reuses the census",
              block_height_find(&ms, 1, pred_failed, NULL) == NULL &&
              block_height_census_test_scans() == scans);

    b->nStatus |= BLOCK_FAILED_VALID;
    BHC_CHECK("status set after the census is observed without a rescan",
              block_height_find(&ms, 1, pred_failed, NULL) == b &&
              block_height_census_test_scans() == scans);
    BHC_CHECK("agrees with the full scan",
              block_height_find(&ms, 1, pred_failed, NULL) ==
              bhc_scan(&ms, 1, pred_failed));
    BHC_CHECK("first match in bucket order",
              block_height_find(&ms, 1, pred_any, NULL) ==
              bhc_scan(&ms, 1, pred_any));
    BHC_CHECK("empty height yields NULL",
              block_height_find(&ms, 9, pred_any, NULL) == NULL);
    return failures;
}

static int bhc_case_rebuilds_on_change(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);
    block_height_census_test_reset();

    struct block_index *g = bhc_insert(&ms, 0, 0, NULL, BLOCK_VALID_TREE);
    struct block_index *a = bhc_insert(&ms, 1, 1, g, BLOCK_VALID_TREE);
    BHC_CHECK("nothing failed yet",
              block_height_find(&ms, 1, pred_failed, NULL) == NULL);
    unsigned long scans = block_height_census_test_scans();

    struct block_index *late =
        bhc_insert(&ms, 1, 7, g, BLOCK_VALID_TREE | BLOCK_FAILED_VALID);
    BHC_CHECK("a block inserted after the census is found",
              block_height_find(&ms, 1, pred_failed, NULL) == late &&
              block_height_census_test_scans() == scans + 1);

    scans = block_height_census_test_scans();
    active_chain_move_window_tip(&ms.chain_active, a);
    (void)block_height_find(&ms, 1, pred_failed, NULL);
    BHC_CHECK("a moved tip rebuilds the census",
              block_height_census_test_scans() == scans + 1);

    scans = block_height_census_test_scans();
    ms.pindex_best_header = late;
    (void)block_height_find(&ms, 1, pred_failed, NULL);
    BHC_CHECK("a changed best header rebuilds the census",
              block_height_census_test_scans() == scans + 1);
    return failures;
}

static int bhc_case_overflow_falls_back_to_scan(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);
    block_height_census_test_reset();

    struct block_index *g = bhc_insert(&ms, 0, 0, NULL, BLOCK_VALID_TREE);
    struct block_index *last = NULL;
    for (int i = 0; i < 100; i++)
        last = bhc_insert(&ms, 1, 100 + i, g,
                          i == 99 ? BLOCK_FAILED_VALID : BLOCK_VALID_TREE);
    BHC_CHECK("height with more blocks than the census holds",
              block_height_find(&ms, 1, pred_failed, NULL) == last);
    BHC_CHECK("overflow result matches the full scan",
              block_height_find(&ms, 1, pred_any, NULL) ==
              bhc_scan(&ms, 1, pred_any));
    return failures;
}

int test_block_height_census(void)
{
    printf("\n=== block_height_census tests ===\n");
    int failures = 0;
    failures += bhc_case_matches_scan_and_caches();
    failures += bhc_case_rebuilds_on_change();
    failures += bhc_case_overflow_falls_back_to_scan();
    return failures;
}

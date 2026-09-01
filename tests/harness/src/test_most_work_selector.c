/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the shared most-work eligibility selector used by both
 * active_chain_most_work_candidate() and find_most_work_chain().
 */

#include "test/test_core.h"

#include "chain/chain.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MW_CHECK(name, expr) do { \
    printf("most_work_selector: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

struct block_index *find_most_work_chain(struct main_state *ms);

static struct block_index *mw_mk_idx(struct main_state *ms, int height,
                                     uint64_t work, uint8_t seed,
                                     struct block_index *prev)
{
    struct block_index *bi = zcl_calloc(1, sizeof(*bi), "test_mw_block_index");
    struct uint256 *hp = zcl_malloc(sizeof(*hp), "test_mw_hash");
    if (!bi || !hp) {
        free(bi);
        free(hp);
        return NULL;
    }

    memset(hp, seed, sizeof(*hp));
    hp->data[0] = (uint8_t)height;
    hp->data[1] = seed;

    bi->nHeight = height;
    bi->phashBlock = hp;
    bi->pprev = prev;
    bi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    bi->nTx = 1;
    bi->nChainTx = prev ? prev->nChainTx + 1 : 1;
    arith_uint256_set_u64(&bi->nChainWork, work);

    if (!block_map_insert(&ms->map_block_index, hp, bi)) {
        free((void *)(uintptr_t)bi->phashBlock);
        free(bi);
        return NULL;
    }
    return bi;
}

static void mw_free_idx(struct block_index *bi)
{
    if (!bi)
        return;
    free((void *)(uintptr_t)bi->phashBlock);
    free(bi);
}

static void mw_set_active_tip(struct main_state *ms,
                              struct block_index **chain,
                              size_t count)
{
    for (size_t i = 0; i < count; i++)
        active_chain_move_window_tip(&ms->chain_active, chain[i]);
}

static void mw_free_state(struct main_state *ms,
                          struct block_index **idx,
                          size_t count)
{
    for (size_t i = 0; i < count; i++)
        mw_free_idx(idx[i]);
    main_state_free(ms);
}

static int test_failed_candidate_skipped(void)
{
    int failures = 0;
    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    main_state_init(&ms);

    struct block_index *g  = mw_mk_idx(&ms, 0, 1, 0x00, NULL);
    struct block_index *a1 = mw_mk_idx(&ms, 1, 10, 0x0A, g);
    struct block_index *a2 = mw_mk_idx(&ms, 2, 20, 0x0B, a1);
    struct block_index *b1 = mw_mk_idx(&ms, 1, 11, 0x1A, g);
    struct block_index *b2 = mw_mk_idx(&ms, 2, 30, 0x1B, b1);
    struct block_index *owned[] = {g, a1, a2, b1, b2};
    struct block_index *active[] = {g, a1, a2};
    if (!g || !a1 || !a2 || !b1 || !b2)
        failures++;
    else {
        mw_set_active_tip(&ms, active, 3);
        ms.pindex_best_header = b2;
        b2->nStatus |= BLOCK_FAILED_VALID;

        struct most_work_selection_stats stats;
        struct block_index *direct = select_most_work_eligible(
                &ms.chain_active, &ms.map_block_index, &stats);
        MW_CHECK("failed candidate: shared selector returns active tip",
                 direct == a2);
        MW_CHECK("failed candidate: production selector matches",
                 find_most_work_chain(&ms) == direct);
        MW_CHECK("failed candidate: failure counter increments",
                 stats.skipped_failed >= 1);
    }

    mw_free_state(&ms, owned, sizeof(owned) / sizeof(owned[0]));
    return failures;
}

static int test_no_data_candidate_skipped(void)
{
    int failures = 0;
    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    main_state_init(&ms);

    struct block_index *g  = mw_mk_idx(&ms, 0, 1, 0x00, NULL);
    struct block_index *a1 = mw_mk_idx(&ms, 1, 10, 0x0A, g);
    struct block_index *a2 = mw_mk_idx(&ms, 2, 20, 0x0B, a1);
    struct block_index *b1 = mw_mk_idx(&ms, 1, 11, 0x1A, g);
    struct block_index *b2 = mw_mk_idx(&ms, 2, 30, 0x1B, b1);
    struct block_index *owned[] = {g, a1, a2, b1, b2};
    struct block_index *active[] = {g, a1, a2};
    if (!g || !a1 || !a2 || !b1 || !b2)
        failures++;
    else {
        mw_set_active_tip(&ms, active, 3);
        ms.pindex_best_header = b2;
        b2->nStatus &= ~BLOCK_HAVE_DATA;
        b2->nChainTx = 0;

        struct most_work_selection_stats stats;
        struct block_index *direct = select_most_work_eligible(
                &ms.chain_active, &ms.map_block_index, &stats);
        MW_CHECK("no-data candidate: shared selector returns active tip",
                 direct == a2);
        MW_CHECK("no-data candidate: production selector matches",
                 find_most_work_chain(&ms) == direct);
        MW_CHECK("no-data candidate: no-data counter increments",
                 stats.skipped_no_chaintx >= 1);
    }

    mw_free_state(&ms, owned, sizeof(owned) / sizeof(owned[0]));
    return failures;
}

static int test_below_tip_candidate_refused(void)
{
    int failures = 0;
    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    main_state_init(&ms);

    struct block_index *g  = mw_mk_idx(&ms, 0, 1, 0x00, NULL);
    struct block_index *a1 = mw_mk_idx(&ms, 1, 10, 0x0A, g);
    struct block_index *a2 = mw_mk_idx(&ms, 2, 20, 0x0B, a1);
    struct block_index *a3 = mw_mk_idx(&ms, 3, 30, 0x0C, a2);
    struct block_index *a4 = mw_mk_idx(&ms, 4, 40, 0x0D, a3);
    struct block_index *s1 = mw_mk_idx(&ms, 1, 99, 0x5A, g);
    struct block_index *owned[] = {g, a1, a2, a3, a4, s1};
    struct block_index *active[] = {g, a1, a2, a3, a4};
    if (!g || !a1 || !a2 || !a3 || !a4 || !s1)
        failures++;
    else {
        mw_set_active_tip(&ms, active, 5);
        ms.pindex_best_header = s1;

        struct most_work_selection_stats stats;
        struct block_index *direct = select_most_work_eligible(
                &ms.chain_active, &ms.map_block_index, &stats);
        MW_CHECK("below-tip fork: shared selector returns active tip",
                 direct == a4);
        MW_CHECK("below-tip fork: production selector matches",
                 find_most_work_chain(&ms) == direct);
        MW_CHECK("below-tip fork: refusal flag set",
                 stats.refused_below_tip);
        MW_CHECK("below-tip fork: refusal heights recorded",
                 stats.refused_below_tip_height == 1 &&
                 stats.refused_below_tip_tip_height == 4);
    }

    mw_free_state(&ms, owned, sizeof(owned) / sizeof(owned[0]));
    return failures;
}

static int test_equal_work_failed_incumbent_adopted(void)
{
    int failures = 0;
    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    main_state_init(&ms);

    struct block_index *g  = mw_mk_idx(&ms, 0, 1, 0x00, NULL);
    struct block_index *a1 = mw_mk_idx(&ms, 1, 10, 0x0A, g);
    struct block_index *a2 = mw_mk_idx(&ms, 2, 20, 0x0B, a1);
    struct block_index *b1 = mw_mk_idx(&ms, 1, 10, 0x1A, g);
    struct block_index *b2 = mw_mk_idx(&ms, 2, 20, 0x1B, b1);
    struct block_index *owned[] = {g, a1, a2, b1, b2};
    struct block_index *active[] = {g, a1, a2};
    if (!g || !a1 || !a2 || !b1 || !b2)
        failures++;
    else {
        mw_set_active_tip(&ms, active, 3);
        ms.pindex_best_header = b2;
        a2->nStatus |= BLOCK_FAILED_VALID;

        struct most_work_selection_stats stats;
        struct block_index *direct = select_most_work_eligible(
                &ms.chain_active, &ms.map_block_index, &stats);
        MW_CHECK("equal-work failed incumbent: shared selector adopts sibling",
                 direct == b2);
        MW_CHECK("equal-work failed incumbent: production selector matches",
                 find_most_work_chain(&ms) == direct);
        MW_CHECK("equal-work failed incumbent: failed incumbent counted",
                 stats.skipped_failed >= 1);
    }

    mw_free_state(&ms, owned, sizeof(owned) / sizeof(owned[0]));
    return failures;
}

static int test_forward_higher_work_selected(void)
{
    int failures = 0;
    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    main_state_init(&ms);

    struct block_index *g  = mw_mk_idx(&ms, 0, 1, 0x00, NULL);
    struct block_index *a1 = mw_mk_idx(&ms, 1, 10, 0x0A, g);
    struct block_index *a2 = mw_mk_idx(&ms, 2, 20, 0x0B, a1);
    struct block_index *d1 = mw_mk_idx(&ms, 1, 11, 0x2A, g);
    struct block_index *d2 = mw_mk_idx(&ms, 2, 21, 0x2B, d1);
    struct block_index *d3 = mw_mk_idx(&ms, 3, 31, 0x2C, d2);
    struct block_index *owned[] = {g, a1, a2, d1, d2, d3};
    struct block_index *active[] = {g, a1, a2};
    if (!g || !a1 || !a2 || !d1 || !d2 || !d3)
        failures++;
    else {
        mw_set_active_tip(&ms, active, 3);
        ms.pindex_best_header = d3;

        struct most_work_selection_stats stats;
        struct block_index *direct = select_most_work_eligible(
                &ms.chain_active, &ms.map_block_index, &stats);
        MW_CHECK("forward fork: shared selector picks higher-work candidate",
                 direct == d3);
        MW_CHECK("forward fork: active-chain wrapper matches",
                 active_chain_most_work_candidate(&ms.chain_active,
                                                  &ms.map_block_index) ==
                 direct);
        MW_CHECK("forward fork: production selector matches",
                 find_most_work_chain(&ms) == direct);
        MW_CHECK("forward fork: no stale refusal",
                 !stats.refused_below_tip);
    }

    mw_free_state(&ms, owned, sizeof(owned) / sizeof(owned[0]));
    return failures;
}

int test_most_work_selector(void)
{
    printf("\n=== most-work selector parity tests ===\n");
    int failures = 0;
    failures += test_failed_candidate_skipped();
    failures += test_no_data_candidate_skipped();
    failures += test_below_tip_candidate_refused();
    failures += test_equal_work_failed_incumbent_adopted();
    failures += test_forward_higher_work_selected();
    printf("most_work_selector: %d failures\n", failures);
    return failures;
}

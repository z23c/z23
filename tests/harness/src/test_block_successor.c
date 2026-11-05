/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for main_state_best_known_successor — the shared "next block to
 * serve" used by getheaders/getblocks serving and tip-successor probes.
 *
 * The function replaced two private full-map scans (msg_headers.c /
 * msg_blocks.c) that let one hostile getheaders locator near genesis force
 * ~2 scans per served block. The contract under test:
 *
 *   - active-chain parents resolve via the O(1) window slot;
 *   - the active tip resolves into the header-only zone along the
 *     best-header path (serving headers above the validated tip);
 *   - off-path (stale-branch) parents still resolve via the fallback
 *     scan, and FAILED children are never returned;
 *   - serving follows the ACTIVE chain even when a heavier stale
 *     sibling exists (canonical serving order);
 *   - same-hash/different-pointer parents resolve through block identity,
 *     matching snapshot/header hydration where map and window own twins.
 *
 * Fixture mirrors test_active_chain_extend.c: minimal in-RAM main_state
 * with map-resident blocks and pointer-linked pprev.
 */

#include "test/test_core.h"

#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdio.h>
#include <string.h>

#define BKS_CHECK(name, expr) do {                    \
    printf("block_successor: %s... ", (name));        \
    if (expr) printf("OK\n");                         \
    else { printf("FAIL\n"); failures++; }            \
} while (0)

static struct block_index *bks_insert(struct main_state *ms,
                                      struct uint256 *hash, int h,
                                      struct block_index *prev,
                                      unsigned status, uint64_t work,
                                      uint8_t salt)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)(h & 0xFF);
    hash->data[1] = (uint8_t)((h >> 8) & 0xFF);
    hash->data[2] = salt;

    struct block_index *pi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!pi) return NULL;
    pi->nHeight = h;
    pi->nBits = 0x1f07ffff;
    pi->nTime = 1000000 + (uint32_t)h * 150;
    pi->nVersion = 4;
    pi->nStatus = status;
    pi->nTx = 1;
    pi->nChainTx = (uint32_t)(h + 1);
    arith_uint256_set_u64(&pi->nChainWork, work);
    pi->pprev = prev;
    return pi;
}

/* ---- successor edges the mutation sweep left unkilled ------------------ */

/* Blocks 0..5 (have-data) in the map, window tip at 5, no best header. */
static bool bks_base_chain(struct main_state *ms, struct uint256 *hashes,
                           struct block_index **b)
{
    struct block_index *prev = NULL;
    for (int h = 0; h <= 5; h++) {
        b[h] = bks_insert(ms, &hashes[h], h, prev,
                          BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS,
                          (uint64_t)(h + 1), 0xB5);
        if (!b[h])
            return false;
        prev = b[h];
    }
    ms->pindex_best_header = NULL;
    return active_chain_move_window_tip(&ms->chain_active, b[5]);
}

/* The window's next slot is not a map entry: only the O(1) path can serve
 * it, and a map twin of its hash fails it only at the same height. */
static bool bks_window_slot_outside_map(void)
{
    struct main_state ms; main_state_init(&ms);
    struct uint256 hashes[6];
    struct block_index *b[6];
    bool ok = bks_base_chain(&ms, hashes, b);

    struct uint256 hx;
    memset(&hx, 0, sizeof(hx));
    hx.data[0] = 0x77;
    hx.data[31] = 0x11;
    struct block_index x;
    block_index_init(&x);
    x.phashBlock = &hx;
    x.nHeight = 6;
    x.pprev = b[5];
    x.nStatus = BLOCK_HAVE_DATA;
    ok = ok && active_chain_move_window_tip(&ms.chain_active, &x);
    ok = ok && main_state_best_known_successor(&ms, b[5]) == &x;

    struct block_index *twin =
        chainstate_insert_block_index((struct chainstate *)&ms, &hx);
    ok = ok && twin != NULL;
    if (twin) {
        twin->nHeight = 99;
        twin->nStatus = BLOCK_FAILED_VALID;
        ok = ok && main_state_best_known_successor(&ms, b[5]) == &x;
        twin->nHeight = 6;
        ok = ok && main_state_best_known_successor(&ms, b[5]) == NULL;
    }
    main_state_free(&ms);
    return ok;
}

/* The best-header path runs through objects that are not map entries, so
 * the scan cannot stand in for it. */
static bool bks_header_path_outside_map(void)
{
    struct main_state ms; main_state_init(&ms);
    struct uint256 hashes[6];
    struct block_index *b[6];
    bool ok = bks_base_chain(&ms, hashes, b);

    struct block_index y6, y7;
    block_index_init(&y6);
    block_index_init(&y7);
    y6.nHeight = 6;
    y6.pprev = b[5];
    y7.nHeight = 7;
    y7.pprev = &y6;
    ms.pindex_best_header = &y7;
    ok = ok && main_state_best_known_successor(&ms, b[5]) == &y6;
    y6.nStatus = BLOCK_FAILED_VALID;
    ok = ok && main_state_best_known_successor(&ms, b[5]) == NULL;
    main_state_free(&ms);
    return ok;
}

struct bks_scenario {
    uint64_t w0, w1;
    unsigned s0, s1;
    int expect;
};

/* Two children of an off-path parent, picked in map-iteration order. */
static bool bks_scan_pick(struct main_state *ms, struct block_index *parent,
                          struct block_index **kids)
{
    struct block_index *want[2] = { kids[0], kids[1] };
    struct block_index *cand = NULL;
    size_t iter = 0, n = 0;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &cand)) {
        if (cand == want[0] || cand == want[1]) {
            if (n < 2)
                kids[n] = cand;
            n++;
        }
    }
    (void)parent;
    return n == 2;
}

static bool bks_scan_scenarios(struct main_state *ms, struct block_index *p,
                               struct block_index **k)
{
    static const struct bks_scenario sc[] = {
        { 5, 5, BLOCK_HAVE_DATA, BLOCK_HAVE_DATA, 0 }, /* tie keeps first */
        { 5, 9, BLOCK_HAVE_DATA, BLOCK_HAVE_DATA, 1 }, /* more work wins */
        { 9, 5, BLOCK_HAVE_DATA, BLOCK_HAVE_DATA, 0 },
        { 5, 5, 0, BLOCK_HAVE_DATA, 1 },        /* tie: data beats no data */
        { 5, 5, BLOCK_HAVE_DATA, 0, 0 },
        { 9, 5, 0, BLOCK_HAVE_DATA, 0 },        /* work outranks data */
    };
    for (size_t i = 0; i < sizeof(sc) / sizeof(sc[0]); i++) {
        arith_uint256_set_u64(&k[0]->nChainWork, sc[i].w0);
        arith_uint256_set_u64(&k[1]->nChainWork, sc[i].w1);
        k[0]->nStatus = sc[i].s0;
        k[1]->nStatus = sc[i].s1;
        if (main_state_best_known_successor(ms, p) != k[sc[i].expect])
            return false;
    }
    return true;
}

/* Off-path parent that is not a map entry: the scan must start at the
 * first map position, and its picks follow work then data. */
static bool bks_scan_from_first_entry(void)
{
    struct main_state ms; main_state_init(&ms);
    struct uint256 hp, h1, h2;
    memset(&hp, 0, sizeof(hp)); hp.data[0] = 0x31;
    struct block_index p;
    block_index_init(&p);
    p.phashBlock = &hp;
    p.nHeight = 3;

    struct block_index *k[2];
    k[0] = bks_insert(&ms, &h1, 4, &p, BLOCK_HAVE_DATA, 5, 0xC1);
    bool ok = k[0] != NULL && ms.pindex_best_header == NULL;
    ok = ok && main_state_best_known_successor(&ms, &p) == k[0];
    k[1] = bks_insert(&ms, &h2, 4, &p, BLOCK_HAVE_DATA, 5, 0xC2);
    ok = ok && k[1] != NULL && bks_scan_pick(&ms, &p, k);
    ok = ok && bks_scan_scenarios(&ms, &p, k);
    main_state_free(&ms);
    return ok;
}

static int bks_mutant_gap_cases(void)
{
    int failures = 0;
    BKS_CHECK("window slot outside the map is served, failed only at same height",
              bks_window_slot_outside_map());
    BKS_CHECK("best-header path outside the map is served unless failed",
              bks_header_path_outside_map());
    BKS_CHECK("scan covers the first map entry and ranks by work then data",
              bks_scan_from_first_entry());
    return failures;
}

int test_block_successor(void)
{
    printf("\n=== main_state_best_known_successor tests ===\n");
    int failures = 0;

    struct main_state ms; main_state_init(&ms);
    static struct uint256 hashes[16];
    struct block_index *b[8];

    /* Active chain 0..5 (have-data), header-only extension 6..7. */
    struct block_index *prev = NULL;
    for (int h = 0; h <= 7; h++) {
        unsigned status = (h <= 5) ? (BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS)
                                   : 0; /* header-only above the tip */
        b[h] = bks_insert(&ms, &hashes[h], h, prev, status,
                          (uint64_t)(h + 1), 0xB5);
        if (!b[h]) { BKS_CHECK("fixture insert", false); return failures; }
        prev = b[h];
    }
    bool ok = active_chain_move_window_tip(&ms.chain_active, b[5]);
    ms.pindex_best_header = b[7];
    BKS_CHECK("fixture: window tip at 5, best header at 7", ok);

    /* 1. O(1) active-chain hop. */
    BKS_CHECK("on-chain parent -> next window slot",
              main_state_best_known_successor(&ms, b[2]) == b[3]);

    /* 2. Active tip -> header-only zone along the best-header path. */
    BKS_CHECK("active tip -> first header-only successor",
              main_state_best_known_successor(&ms, b[5]) == b[6]);
    BKS_CHECK("header-only parent -> next on best-header path",
              main_state_best_known_successor(&ms, b[6]) == b[7]);

    /* The request-side locator resolves through the block map while the
     * active window or best-header ancestry may retain a different object for
     * the same consensus hash.  Both fast paths are hash identity, never
     * pointer identity. */
    struct block_index twin2;
    block_index_init(&twin2);
    twin2.phashBlock = b[2]->phashBlock;
    twin2.nHeight = b[2]->nHeight;
    twin2.pprev = b[1];
    BKS_CHECK("same-hash active parent twin -> next window slot",
              main_state_best_known_successor(&ms, &twin2) == b[3]);
    struct block_index twin6;
    block_index_init(&twin6);
    twin6.phashBlock = b[6]->phashBlock;
    twin6.nHeight = b[6]->nHeight;
    twin6.pprev = b[5];
    BKS_CHECK("same-hash header parent twin -> next header slot",
              main_state_best_known_successor(&ms, &twin6) == b[7]);

    /* 3. Best header itself has no successor. */
    BKS_CHECK("best header -> NULL",
              main_state_best_known_successor(&ms, b[7]) == NULL);

    /* 4. Stale branch: fork off b[3] at heights 4'/5' — resolved by the
     * fallback scan (off active chain, off best-header path). Heavier
     * work than the active siblings to prove serving still follows the
     * ACTIVE chain from on-chain parents (canonical order). */
    struct block_index *fork4 = bks_insert(&ms, &hashes[10], 4, b[3],
                                           BLOCK_HAVE_DATA, 1000, 0xF0);
    struct block_index *fork5 = bks_insert(&ms, &hashes[11], 5, fork4,
                                           BLOCK_HAVE_DATA, 1001, 0xF0);
    BKS_CHECK("fixture: stale branch inserted", fork4 && fork5);
    BKS_CHECK("stale-branch parent -> its child via fallback scan",
              main_state_best_known_successor(&ms, fork4) == fork5);
    struct block_index fork4_twin;
    block_index_init(&fork4_twin);
    fork4_twin.phashBlock = fork4->phashBlock;
    fork4_twin.nHeight = fork4->nHeight;
    fork4_twin.pprev = fork4->pprev;
    BKS_CHECK("same-hash stale parent twin -> child via fallback scan",
              main_state_best_known_successor(&ms, &fork4_twin) == fork5);
    BKS_CHECK("on-chain parent ignores heavier stale sibling",
              main_state_best_known_successor(&ms, b[3]) == b[4]);

    /* 5. FAILED children are never served. */
    fork5->nStatus |= BLOCK_FAILED_VALID;
    BKS_CHECK("failed child -> NULL",
              main_state_best_known_successor(&ms, fork4) == NULL);

    /* 6. NULL safety. */
    BKS_CHECK("NULL ms/parent -> NULL",
              main_state_best_known_successor(NULL, b[2]) == NULL &&
              main_state_best_known_successor(&ms, NULL) == NULL);

    failures += bks_mutant_gap_cases();

    main_state_free(&ms);
    return failures;
}

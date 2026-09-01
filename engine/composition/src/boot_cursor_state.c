/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * OS-S2 boot cursors — see config/boot_cursor_state.h. Owns the node_state
 * cursor keys, the reorg clamp, the block-index fingerprint, and the
 * cursor-gated wrappers for the height-repair (#1) and nChainTx-propagation
 * (#2) boot passes. Keeping this logic here (not inline in boot.c) holds
 * boot.c under its line ceiling.
 */

#include "config/boot_cursor_state.h"

#include "services/block_index_integrity.h"
#include "models/database.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "core/arith_uint256.h"
#include "controllers/wallet_scan.h"
#include "jobs/tip_finalize_stage.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Comparator for sorting block_index pointers by height (ascending). */
static int bcs_cmp_height(const void *a, const void *b)
{
    const struct block_index *pa = *(const struct block_index *const *)a;
    const struct block_index *pb = *(const struct block_index *const *)b;
    return (pa->nHeight > pb->nHeight) - (pa->nHeight < pb->nHeight);
}

uint64_t boot_block_index_fingerprint(const struct main_state *ms)
{
    if (!ms)
        return 0;
    uint64_t fp = 0;
    size_t it = 0;
    struct block_index *bi = NULL;
    while (block_map_next(&ms->map_block_index, &it, NULL, &bi)) {
        if (!bi)
            continue;
        uint64_t h = 0;
        if (bi->phashBlock)
            memcpy(&h, bi->phashBlock->data, sizeof(h)); /* first 8 hash bytes */
        h ^= (uint64_t)bi->nStatus;
        h ^= arith_uint256_get_low64(&bi->nChainWork);
        h ^= (uint64_t)(uint32_t)bi->nHeight << 1;
        h ^= (uint64_t)bi->nChainTx << 17;
        /* Order-independent accumulate (map iteration order is not stable). */
        fp += h;
        fp ^= (h << 7) | (h >> 57);
    }
    return fp;
}

void boot_cursor_clamp_on_reorg(struct node_db *ndb, int fork_height)
{
    if (!ndb || !ndb->open || fork_height < 0)
        return;
    int64_t floor = (int64_t)fork_height - 1;
    static const char *const int_keys[] = {
        BOOT_CUR_HEIGHTS, BOOT_CUR_NCHAINTX, BOOT_CUR_WALLET,
    };
    for (size_t i = 0; i < sizeof(int_keys) / sizeof(int_keys[0]); i++) {
        int64_t cur = -1;
        if (node_db_state_get_int(ndb, int_keys[i], &cur) && cur > floor)
            node_db_state_set_int(ndb, int_keys[i], floor);
    }
    /* The heights-count guard must not fast-skip a clamped index next boot;
     * zero it so #1 re-derives above the clamped high-water. */
    node_db_state_set_int(ndb, BOOT_CUR_HEIGHTS_CNT, 0);
}

/* ── Runtime reorg-clamp injection into tip_finalize ─────────────────── */

static struct node_db *g_reorg_clamp_ndb = NULL;

static void bcs_reorg_clamp_cb(int fork_height, void *user)
{
    (void)user;
    boot_cursor_clamp_on_reorg(g_reorg_clamp_ndb, fork_height);
}

void boot_cursor_install_reorg_clamp(struct node_db *ndb)
{
    g_reorg_clamp_ndb = ndb;
    tip_finalize_stage_set_reorg_clamp(ndb ? bcs_reorg_clamp_cb : NULL, NULL);
}

/* ── #1 — cursor-gated height repair ─────────────────────────────────── */

int boot_cursor_repair_heights(struct main_state *ms, struct node_db *ndb)
{
    if (!ms)
        return 0;

    int64_t heights_done = -1, heights_cnt = -1;
    if (ndb && ndb->open) {
        node_db_state_get_int(ndb, BOOT_CUR_HEIGHTS, &heights_done);
        node_db_state_get_int(ndb, BOOT_CUR_HEIGHTS_CNT, &heights_cnt);
    }

    /* Fast-skip only when the persisted count matches the live map size (no
     * entries added/removed since) AND a high-water is recorded. Any change
     * (import, reorg-clamp zeroing the count) falls through to a range walk. */
    int repaired = 0;
    int hmax = -1;
    bool covered = (heights_cnt == (int64_t)ms->map_block_index.size &&
                    heights_done >= 0);
    if (!covered)
        repaired = block_index_repair_heights_range(ms, (int)heights_done,
                                                    &hmax);
    else
        printf("[height-repair] cursor covers all %zu entries "
               "(upto=%lld) — skipping\n",
               ms->map_block_index.size, (long long)heights_done);

    if (ndb && ndb->open && hmax > (int)heights_done) {
        node_db_state_set_int(ndb, BOOT_CUR_HEIGHTS, hmax);
        node_db_state_set_int(ndb, BOOT_CUR_HEIGHTS_CNT,
                              (int64_t)ms->map_block_index.size);
    }
    return repaired;
}

/* ── #2 — cursor-gated nChainTx propagation ──────────────────────────── */

/* Restricted "already computed" pre-scan: a parent at/below the cursor already
 * carries a verified contiguous nChainTx, so only entries above the cursor are
 * checked. Returns true iff every txn-bearing entry above the cursor already
 * has a consistent nonzero nChainTx. */
static bool bcs_nchaintx_computed_above(struct main_state *ms,
                                        int64_t cursor)
{
    size_t it = 0;
    struct block_index *bi = NULL;
    while (block_map_next(&ms->map_block_index, &it, NULL, &bi)) {
        if (!bi || bi->nHeight <= (int)cursor)
            continue;
        if (bi->nTx > 0 && bi->nChainTx == 0)
            return false;
        if (bi->nHeight > 0 && bi->pprev && bi->pprev->nChainTx > 0 &&
            bi->nTx > 0 &&
            bi->nChainTx != bi->pprev->nChainTx + bi->nTx)
            return false;
    }
    return true;
}

void boot_cursor_propagate_nchaintx(struct main_state *ms, struct node_db *ndb)
{
    if (!ms || ms->map_block_index.size <= 100)
        return;

    int64_t nct_upto = -1;
    if (ndb && ndb->open)
        node_db_state_get_int(ndb, BOOT_CUR_NCHAINTX, &nct_upto);

    bool complete = true;
    if (bcs_nchaintx_computed_above(ms, nct_upto)) {
        printf("nChainTx already computed above cursor h=%lld, skipping "
               "propagation\n", (long long)nct_upto);
    } else {
        size_t n = ms->map_block_index.size;
        struct block_index **sorted =
            zcl_malloc(n * sizeof(*sorted), "boot_cursor.nchaintx_sorted");
        /* On alloc failure the index is NOT re-derived; leave the cursor
         * unstamped so the next boot retries rather than trusting a hole. */
        complete = (sorted != NULL);
        if (sorted) {
            size_t si = 0, idx = 0;
            struct block_index *sp;
            while (block_map_next(&ms->map_block_index, &si, NULL, &sp))
                if (sp && idx < n)
                    sorted[idx++] = sp;
            n = idx;
            qsort(sorted, n, sizeof(*sorted), bcs_cmp_height);
            int total = 0;
            for (int pass = 0; pass < 5; pass++) {
                int propagated = 0;
                for (size_t i = 0; i < n; i++) {
                    struct block_index *b = sorted[i];
                    if (b->nHeight == 0) {
                        if (b->nChainTx == 0 && b->nTx > 0) {
                            b->nChainTx = b->nTx;
                            propagated++;
                        }
                    } else if (b->pprev && b->pprev->nChainTx > 0 &&
                               b->nTx > 0) {
                        unsigned int expected = b->pprev->nChainTx + b->nTx;
                        if (b->nChainTx != expected) {
                            b->nChainTx = expected;
                            propagated++;
                        }
                    }
                }
                total += propagated;
                if (propagated == 0)
                    break;
            }
            free(sorted);
            if (total > 0)
                printf("nChainTx propagated for %d blocks\n", total);
        }
    }

    /* Stamp the cursor to the active tip height once the index is proven
     * contiguous-complete above the old cursor. */
    int tip_h = active_chain_height(&ms->chain_active);
    if (complete && ndb && ndb->open && tip_h > (int)nct_upto)
        node_db_state_set_int(ndb, BOOT_CUR_NCHAINTX, tip_h);
}

/* ── #4 — cursor-gated wallet block scan ─────────────────────────────── */

int boot_cursor_wallet_scan_start(bool have_cursor, int64_t cursor,
                                  bool have_ks, uint64_t stored_fp,
                                  uint64_t cur_fp, int tip_h)
{
    /* No durable cursor (an old wallet datadir predating this cursor) or a
     * changed keyset (a key import/removal makes prior partial scans incomplete
     * for the new keys): one full scan from genesis. Otherwise re-scan only the
     * delta above the cursor. */
    if (!have_cursor || cursor < 0 || !have_ks || stored_fp != cur_fp)
        return 0;
    if (cursor >= (int64_t)tip_h)
        return tip_h + 1;                 /* already scanned to tip → skip */
    return (int)cursor + 1;
}

int boot_cursor_scan_wallet(struct node_db *ndb,
                            const struct active_chain *chain,
                            const struct wallet *w,
                            const char *datadir, int tip_h)
{
    if (!ndb || !ndb->open || !chain || !w || !datadir || tip_h <= 0)
        return 0;

    uint64_t cur_fp = wallet_scan_keyset_fp(w);
    int64_t cursor = -1, stored_fp_i = 0;
    bool have_cursor = node_db_state_get_int(ndb, BOOT_CUR_WALLET, &cursor);
    bool have_ks = node_db_state_get_int(ndb, BOOT_CUR_WALLET_KS, &stored_fp_i);

    int start = boot_cursor_wallet_scan_start(have_cursor, cursor, have_ks,
                                              (uint64_t)stored_fp_i, cur_fp,
                                              tip_h);
    if (start > tip_h)
        return 0;                         /* delta already covered — nothing to do */

    int found = wallet_scan_blocks(ndb, chain, w, datadir, start, tip_h);
    if (found < 0)
        return found;   /* scan error: leave the cursor unstamped, retry next boot */

    /* Persist the O(delta) cursor + keyset fp so the next boot scans only the
     * new tip delta (mirrors boot_cursor_repair_heights' high-water stamp). */
    node_db_state_set_int(ndb, BOOT_CUR_WALLET, tip_h);
    node_db_state_set_int(ndb, BOOT_CUR_WALLET_KS, (int64_t)cur_fp);
    return found;
}

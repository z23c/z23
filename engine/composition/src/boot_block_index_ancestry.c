/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Block-index ancestry repair: genesis-rooted height/work/tx recompute
 * and post-scan orphan pprev resolution from disk.
 *
 * Part of the boot composition root (engine/composition/src/), peeled out of
 * boot_block_file_scan.c to keep both translation units under the LOC
 * ceiling. Owns the two ancestry-repair passes the block-file scan runs
 * after every block is in the map: recompute_index_from_genesis (rebuild
 * height + cumulative chain_work/chain_tx from the genesis pprev chain,
 * ignoring stale labels) and resolve_orphan_pprev_from_disk (relink
 * orphan pprev pointers by reading hashPrevBlock off disk, then fix
 * heights). Both are called only by boot_block_file_scan.c.
 *
 * Consensus-adjacent: touches the block-index load surface. Moved
 * byte-identically from boot_block_file_scan.c — no logic change. */

#include "config/boot_internal.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "validation/chainstate.h"
#include "storage/disk_block_io.h"
#include "util/safe_alloc.h"
#include <stdio.h>
#include <stdlib.h>

/* ── Genesis-rooted height/work/tx recompute ─────────────────── */

struct boot_index_recompute_entry {
    struct block_index *bi;
    unsigned char state; /* 0 unknown, 1 visiting, 2 fixed, 3 unreachable */
};

static int boot_index_cmp_entry_ptr(const void *a, const void *b)
{
    const struct boot_index_recompute_entry *ea = a;
    const struct boot_index_recompute_entry *eb = b;
    if (ea->bi < eb->bi) return -1;
    if (ea->bi > eb->bi) return 1;
    return 0;
}

static struct boot_index_recompute_entry *boot_index_find_entry(
    struct boot_index_recompute_entry *entries, size_t n,
    const struct block_index *bi)
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (entries[mid].bi < bi)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo < n && entries[lo].bi == bi)
        return &entries[lo];
    return NULL;
}

/* Recompute every reachable block's height and cumulative metadata from the
 * genesis pprev chain.  This deliberately ignores existing height labels:
 * after stale flat-cache or SQLite recovery a block can have a locally
 * consistent but globally wrong height, which keeps header sync stuck. */
int recompute_index_from_genesis(struct main_state *ms,
                                 const struct chain_params *params)
{
    if (!ms || !params || ms->map_block_index.size == 0)
        return 0;

    size_t cap = ms->map_block_index.size;
    struct boot_index_recompute_entry *entries =
        zcl_calloc(cap, sizeof(*entries), "boot.index.recompute_entries");
    if (!entries)
        return 0;

    size_t n = 0, iter = 0;
    struct block_index *bi;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &bi)) {
        if (bi && bi->phashBlock && n < cap)
            entries[n++].bi = bi;
    }
    qsort(entries, n, sizeof(*entries), boot_index_cmp_entry_ptr);

    struct boot_index_recompute_entry *genesis = NULL;
    for (size_t i = 0; i < n; i++) {
        if (uint256_eq(entries[i].bi->phashBlock,
                       &params->consensus.hashGenesisBlock)) {
            genesis = &entries[i];
            break;
        }
    }
    if (!genesis) {
        free(entries);
        return 0;
    }

    genesis->state = 2;
    genesis->bi->nHeight = 0;
    genesis->bi->nChainWork = GetBlockProof(genesis->bi);
    if (genesis->bi->nChainTx == 0)
        genesis->bi->nChainTx = genesis->bi->nTx > 0 ? genesis->bi->nTx : 1;
    block_index_build_skip(genesis->bi);

    size_t stack_cap = 4096;
    struct boot_index_recompute_entry **stack =
        zcl_malloc(stack_cap * sizeof(*stack), "boot.index.recompute_stack");
    if (!stack) {
        free(entries);
        return 0;
    }

    int heights_fixed = 0, work_fixed = 0, tx_fixed = 0;
    int reachable = 1, unresolved = 0, cycles = 0;

    for (size_t i = 0; i < n; i++) {
        struct boot_index_recompute_entry *cur = &entries[i];
        if (cur->state == 2)
            continue;

        size_t depth = 0;
        bool ok = false;
        while (cur) {
            if (cur->state == 2) {
                ok = true;
                break;
            }
            if (cur->state == 3)
                break;
            if (cur->state == 1) {
                cycles++;
                break;
            }
            cur->state = 1;
            if (depth >= stack_cap) {
                size_t new_cap = stack_cap * 2;
                struct boot_index_recompute_entry **tmp =
                    zcl_realloc(stack, new_cap * sizeof(*stack), "boot.index.recompute_stack");
                if (!tmp)
                    break;
                stack = tmp;
                stack_cap = new_cap;
            }
            stack[depth++] = cur;
            if (!cur->bi->pprev)
                break;
            cur = boot_index_find_entry(entries, n, cur->bi->pprev);
        }

        if (ok) {
            for (size_t ri = depth; ri > 0; ri--) {
                struct block_index *fix = stack[ri - 1]->bi;
                struct block_index *prev = fix->pprev;
                int expected_h = prev ? prev->nHeight + 1 : 0;
                if (fix->nHeight != expected_h) {
                    fix->nHeight = expected_h;
                    heights_fixed++;
                }
                block_index_build_skip(fix);

                struct arith_uint256 proof = GetBlockProof(fix);
                struct arith_uint256 expected_work;
                if (prev)
                    arith_uint256_add(&expected_work,
                                      &prev->nChainWork, &proof);
                else
                    expected_work = proof;
                if (arith_uint256_compare(&fix->nChainWork,
                                          &expected_work) != 0) {
                    fix->nChainWork = expected_work;
                    work_fixed++;
                }

                unsigned int ntx = fix->nTx > 0 ? fix->nTx : 1;
                unsigned int expected_tx =
                    prev ? prev->nChainTx + ntx : ntx;
                if (fix->nChainTx != expected_tx) {
                    fix->nChainTx = expected_tx;
                    tx_fixed++;
                }
                stack[ri - 1]->state = 2;
                reachable++;
            }
        } else {
            unresolved += (int)depth;
            for (size_t ri = 0; ri < depth; ri++)
                stack[ri]->state = 3;
        }
    }

    printf("  ancestry recompute: reachable=%d heights=%d chain_work=%d "
           "chain_tx=%d unresolved=%d cycles=%d\n",
           reachable, heights_fixed, work_fixed, tx_fixed,
           unresolved, cycles);

    free(stack);
    free(entries);
    return heights_fixed + work_fixed + tx_fixed;
}

/* ── Post-scan pprev resolution from disk ────────────────────── */
/* After all block files are scanned and every block is in the map,
 * resolve orphan pprev links by reading hashPrevBlock from disk.
 * Then propagate heights from genesis outward.
 *
 * Why this is needed: create_block_index_fast links pprev at insert
 * time, but if the parent hasn't been inserted yet (out-of-order in
 * block files, or across file boundaries), pprev stays NULL. The
 * retry passes only fix one level deep per pass. This function
 * resolves ALL orphans in one shot since every block is now in the map. */
int resolve_orphan_pprev_from_disk(struct main_state *ms,
                                   const char *datadir,
                                   const struct chain_params *params)
{
    if (!ms || !datadir) return 0;

    const struct uint256 *genesis = &params->consensus.hashGenesisBlock;
    int resolved = 0, read_errors = 0;

    /* Read hashPrevBlock from disk for orphans, then link pprev. */
    /* Group reads by file to avoid open/close churn */
    for (int file_idx = 0; file_idx < 256; file_idx++) {
        char path[576];
        snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
                 datadir, file_idx);
        FILE *f = NULL;

        disk_block_io_lock();
        size_t iter = 0;
        struct block_index *bi;
        while (block_map_next(&ms->map_block_index, &iter, NULL, &bi)) {
            if (!bi || bi->pprev) continue;
            if (bi->nFile != file_idx) continue;
            if (bi->nDataPos == 0) continue;
            /* Skip genesis */
            if (bi->phashBlock && uint256_eq(bi->phashBlock, genesis))
                continue;

            if (!f) {
                f = fopen(path, "rb");
                if (!f) break;
            }

            /* hashPrevBlock is at offset 4 in serialized header
             * (after int32_t nVersion). nDataPos points to start
             * of block data (past the 8-byte frame header). */
            if (fseek(f, (long)bi->nDataPos + 4, SEEK_SET) != 0) {
                read_errors++;
                continue;
            }
            struct uint256 prev_hash;
            if (fread(prev_hash.data, 1, 32, f) != 32) { // disk-io-lock: held
                read_errors++;
                continue;
            }

            struct block_index *pprev = block_map_find(
                &ms->map_block_index, &prev_hash);
            if (pprev) {
                bi->pprev = pprev;
                resolved++;
            }
        }
        if (f) fclose(f);
        disk_block_io_unlock();
    }

    if (read_errors > 0)
        fprintf(stderr, "resolve_orphan_pprev: %d disk read errors\n",
                read_errors);

    /* Propagate heights from pprev chains.
     *
     * Old approach used 40 fixed passes in hash order — only 40 levels
     * deep from any correct ancestor.  After an LDB UTXO import the flat
     * file covers ~500K entries but the block-file scan adds ~2.5M more
     * whose pprev chains extend far past the flat-file entries.  40
     * passes can't reach them.
     *
     * New approach: for each block whose height != pprev->height+1, walk
     * UP the pprev chain collecting ancestors that also need fixing, then
     * propagate back DOWN.  Each block is visited at most twice (once up,
     * once down) so total work is O(n).  After a block is fixed the
     * height check short-circuits, so shared chain prefixes aren't
     * re-walked. */
    int total_height_fixed = 0;
    {
        /* Preallocate a stack for the deepest chain we might encounter.
         * 3M entries × 8 bytes = 24 MB — fine on any machine running a
         * full node (9+ GB RSS typical). */
        size_t stack_cap = 4096;
        struct block_index **stack = zcl_malloc(stack_cap * sizeof(*stack), "boot.index.orphan_stack");
        if (!stack) {
            fprintf(stderr, "resolve_orphan_pprev: stack alloc failed\n");
            goto skip_height;
        }

        size_t iter = 0;
        struct block_index *bi;
        while (block_map_next(&ms->map_block_index, &iter, NULL, &bi)) {
            if (!bi || !bi->pprev) continue;
            if (bi->nHeight == bi->pprev->nHeight + 1) continue;

            /* Walk UP pprev chain to first correct ancestor.
             * Monotonicity guard prevents the realloc loop from
             * running forever on a corrupt pprev cycle. */
            int depth = 0;
            struct block_index *cur = bi;
            while (cur->pprev &&
                   cur->pprev->nHeight < cur->nHeight &&
                   cur->nHeight != cur->pprev->nHeight + 1) {
                if ((size_t)depth >= stack_cap) {
                    stack_cap *= 2;
                    struct block_index **tmp = zcl_realloc(
                        stack, stack_cap * sizeof(*stack), "boot.index.orphan_stack");
                    if (!tmp) break;
                    stack = tmp;
                }
                stack[depth++] = cur;
                cur = cur->pprev;
            }

            /* cur is now correct (or genesis with pprev==NULL).
             * Fix cur itself first if needed, then propagate down. */
            if (cur->pprev && cur->nHeight != cur->pprev->nHeight + 1) {
                cur->nHeight = cur->pprev->nHeight + 1;
                block_index_build_skip(cur);
                struct arith_uint256 proof = GetBlockProof(cur);
                arith_uint256_add(&cur->nChainWork,
                                  &cur->pprev->nChainWork, &proof);
                total_height_fixed++;
            }

            /* Propagate DOWN the stack (deepest ancestor first) */
            for (int i = depth - 1; i >= 0; i--) {
                struct block_index *fix = stack[i];
                fix->nHeight = fix->pprev->nHeight + 1;
                block_index_build_skip(fix);
                struct arith_uint256 proof = GetBlockProof(fix);
                arith_uint256_add(&fix->nChainWork,
                                  &fix->pprev->nChainWork, &proof);
                total_height_fixed++;
            }
        }

        free(stack);
    }
skip_height:

    if (total_height_fixed > 0)
        printf("  heights resolved for %d blocks\n", total_height_fixed);

    return resolved;
}

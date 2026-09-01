/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the segment sealer's pure range selector — the logic that decides
 * WHICH 10k-aligned, fully-finalized, not-yet-sealed segment to seal next. The
 * threaded service + supervision are exercised at the chain_segment /
 * block_parse_cache level; here we prove the selection invariants directly.
 */

#include "test/test_core.h"

#include "chain/chain.h"
#include "services/block_pruning_service.h"
#include "services/segment_sealer_service.h"
#include "storage/chain_segment.h"
#include "storage/disk_block_io.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SS_CHECK(name, expr) do {                                         \
    if (expr) { printf("  segment_sealer: %s... OK\n", (name)); }          \
    else { printf("  segment_sealer: %s... FAIL\n", (name)); failures++; } \
} while (0)

static bool tiny_body(void *user, uint32_t h, uint8_t **bytes, size_t *len)
{
    (void)user;
    size_t n = 8;
    uint8_t *b = malloc(n); // raw-alloc-ok:test
    if (!b) return false;
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(h + i);
    *bytes = b; *len = n;
    return true;
}

/* ── Prune-after-seal gate ──────────────────────────────────────────────
 * The sealer's internal per-segment sequence (seal_verify_and_prune in
 * segment_sealer_service.c) is: seal a range -> independently re-verify it
 * off disk -> only then may block_pruning_prune_sealed_range() touch the
 * now-redundant blk*.dat bytes. Proven directly against the same primitives
 * the service calls (chain_segment_seal_range / chain_segment_open /
 * block_pruning_prune_sealed_range) rather than through the service's
 * active-chain / 10k-alignment layer, which requires a real
 * 10000+finality_depth-block fixture to exercise (segment_sealer_next_range
 * only ever selects a 10k-aligned, fully-finalized range) — keeping this
 * test fast while still proving the exact gate: pruning never fires for a
 * range that has not itself been sealed AND independently re-verified. */
static int test_prune_after_seal_gate(void)
{
    printf("\n=== segment_sealer (prune-after-seal gate) ===\n");
    int failures = 0;
    char err[256];
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "segment_sealer", "prune_gate");
    char segd[400];
    snprintf(segd, sizeof(segd), "%s/segments", dir);
    mkdir(segd, 0755);
    char blocksd[400];
    snprintf(blocksd, sizeof(blocksd), "%s/blocks", dir);
    mkdir(blocksd, 0755);

    /* Two blk*.dat "files": file 1 holds heights [0,49], file 2 holds
     * [50,199]. Only file 1 will ever be sealed+verified in this test. */
    const int NBLK = 200;
    struct block_index *blocks =
        zcl_malloc((size_t)NBLK * sizeof(*blocks), "test_prune_after_seal");
    struct uint256 *hashes =
        zcl_malloc((size_t)NBLK * sizeof(*hashes), "test_prune_after_seal");
    for (int i = 0; i < NBLK; i++) {
        block_index_init(&blocks[i]);
        memset(&hashes[i], 0, sizeof(hashes[i]));
        hashes[i].data[0] = (unsigned char)(i & 0xFF);
        blocks[i].phashBlock = &hashes[i];
        blocks[i].nHeight = i;
        blocks[i].nStatus = BLOCK_HAVE_DATA;
        blocks[i].nFile = (i < 50) ? 1 : 2;
        if (i > 0) blocks[i].pprev = &blocks[i - 1];
    }
    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    active_chain_init(&ms.chain_active);
    active_chain_move_window_tip(&ms.chain_active, &blocks[NBLK - 1]);

    struct block_pruning_service psvc;
    block_pruning_init(&psvc, &ms, dir);
    psvc.keep_blocks = 0;  /* isolate the seal-gate floor from keep_blocks */

    char blk1[512], blk2[512];
    struct disk_block_pos pos1 = { .nFile = 1, .nPos = 0 };
    struct disk_block_pos pos2 = { .nFile = 2, .nPos = 0 };
    get_block_pos_filename(blk1, sizeof(blk1), dir, &pos1, "blk");
    get_block_pos_filename(blk2, sizeof(blk2), dir, &pos2, "blk");
    FILE *f1 = fopen(blk1, "wb"); if (f1) { fputc('a', f1); fclose(f1); }
    FILE *f2 = fopen(blk2, "wb"); if (f2) { fputc('b', f2); fclose(f2); }
    SS_CHECK("prune-gate: fixture blk files created",
             access(blk1, F_OK) == 0 && access(blk2, F_OK) == 0);

    /* Nothing sealed yet -> the seal-triggered prune must not fire. */
    int p0 = block_pruning_prune_sealed_range(&psvc, 0);
    SS_CHECK("prune-gate: no seal yet -> nothing pruned",
             p0 == 0 && access(blk1, F_OK) == 0 && access(blk2, F_OK) == 0);

    /* Seal [0,50) — the exact writer call the sealer makes. */
    enum cseg_status st = chain_segment_seal_range(segd, tiny_body, NULL,
                                                   0, 50, err, sizeof(err));
    SS_CHECK("prune-gate: seal [0,50) ok", st == CSEG_OK);

    /* Independent post-seal re-verify off disk — the exact check
     * seal_verify_and_prune performs before it will ever prune. */
    char segpath[512];
    snprintf(segpath, sizeof(segpath), "%s/seg-0-50.dat", segd);
    struct chain_segment *seg = NULL;
    enum cseg_status vst = chain_segment_open(segpath, &seg, err, sizeof(err));
    SS_CHECK("prune-gate: post-seal verify ok", vst == CSEG_OK && seg != NULL);
    chain_segment_close(seg);

    /* Only NOW may the prune fire, bounded to exactly the verified range's
     * top: file 1 (max_h=49) is covered by [0,50); file 2 (max_h=199) was
     * never sealed or verified and must survive, even with keep_blocks=0
     * offering it no other protection. */
    int p1 = block_pruning_prune_sealed_range(&psvc, 50);
    SS_CHECK("prune-gate: seal+verify -> exactly the sealed file is pruned",
             p1 == 1);
    SS_CHECK("prune-gate: blk00001.dat deleted (sealed+verified)",
             access(blk1, F_OK) != 0);
    SS_CHECK("prune-gate: blk00002.dat SURVIVES (never sealed/verified)",
             access(blk2, F_OK) == 0);

    active_chain_free(&ms.chain_active);
    free(blocks);
    free(hashes);
    test_rm_rf_recursive(dir);

    printf("segment_sealer (prune-after-seal gate): %d failures\n", failures);
    return failures;
}

int test_segment_sealer(void);
int test_segment_sealer(void)
{
    printf("\n=== segment_sealer (range selector) ===\n");
    int failures = 0;
    const uint32_t SEG = CHAIN_SEGMENT_BLOCKS_PER_SEG; /* 10000 */
    uint32_t first = 999, count = 999;

    /* Empty store: the first aligned segment fully below the frontier. */
    SS_CHECK("empty store, frontier deep -> segment 0",
             segment_sealer_next_range(SEG * 2 + 5, NULL, &first, &count) &&
             first == 0 && count == SEG);

    /* Frontier exactly at the top of segment 0 -> segment 0 is eligible. */
    first = count = 999;
    SS_CHECK("frontier == top of seg0 -> segment 0",
             segment_sealer_next_range(SEG - 1, NULL, &first, &count) &&
             first == 0 && count == SEG);

    /* Frontier one short of the top of segment 0 -> nothing to seal. */
    SS_CHECK("frontier below seg0 top -> none",
             !segment_sealer_next_range(SEG - 2, NULL, &first, &count));

    /* A store that already covers segment 0 -> next is segment 1. */
    {
        char err[256];
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "segment_sealer", "store");
        /* Seal a real, full 10k-aligned segment [0, SEG). */
        enum cseg_status st = chain_segment_seal_range(dir, tiny_body, NULL,
                                                       0, SEG, err, sizeof(err));
        SS_CHECK("seal segment 0 ok", st == CSEG_OK);

        struct chain_segment_store *store = NULL;
        st = chain_segment_store_open(dir, &store, err, sizeof(err));
        SS_CHECK("store open ok", st == CSEG_OK && store != NULL);

        first = count = 999;
        SS_CHECK("seg0 sealed -> next is segment 1",
                 segment_sealer_next_range(SEG * 3, store, &first, &count) &&
                 first == SEG && count == SEG);

        /* Frontier only reaches into segment 1 but not its top -> still none
         * beyond the already-sealed segment 0. */
        SS_CHECK("seg0 sealed, seg1 not finalized -> none",
                 !segment_sealer_next_range(SEG + 3, store, &first, &count));

        chain_segment_store_close(store);
        test_rm_rf_recursive(dir);
    }

    /* ── Bounded backfill catch-up + never-seal-above-frontier ─────────────
     * segment_sealer_seal_next is the primitive the background catch-up loops
     * (run_catchup calls it up to catchup_batch times per tick). Prove it seals
     * exactly ONE segment per call, oldest-first (so looping walks the backlog
     * forward), and NEVER writes a segment whose top exceeds the finalized
     * frontier. Driven with a synthetic body source — no node fixture needed. */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "segment_sealer", "sealnext");
        char err[256] = {0};
        /* Heights 0 .. 3*SEG-1 are finalized; the top of segment 2 == frontier. */
        const uint32_t frontier = SEG * 3 - 1;

        /* Call 1: seals the oldest unsealed segment (segment 0). */
        uint32_t f0 = 999;
        int r0 = segment_sealer_seal_next(dir, frontier, tiny_body, NULL,
                                          &f0, err, sizeof(err));
        SS_CHECK("seal_next #1 seals segment 0", r0 == 1 && f0 == 0);

        /* After call 1 exactly ONE segment is sealed (bounded: not two). */
        {
            struct chain_segment_store *st1 = NULL;
            enum cseg_status o1 = chain_segment_store_open(dir, &st1, err, sizeof(err));
            SS_CHECK("one segment sealed per call",
                     o1 == CSEG_OK && st1 &&
                     chain_segment_store_segment_count(st1) == 1 &&
                     !chain_segment_store_covers(st1, SEG));
            if (st1) chain_segment_store_close(st1);
        }

        /* Call 2: segment 0 sealed -> seals segment 1 (oldest-first advance). */
        uint32_t f1 = 999;
        int r1 = segment_sealer_seal_next(dir, frontier, tiny_body, NULL,
                                          &f1, err, sizeof(err));
        SS_CHECK("seal_next #2 seals segment 1", r1 == 1 && f1 == SEG);

        /* Call 3: seals segment 2 whose top == frontier (inclusive, eligible). */
        uint32_t f2 = 999;
        int r2 = segment_sealer_seal_next(dir, frontier, tiny_body, NULL,
                                          &f2, err, sizeof(err));
        SS_CHECK("seal_next #3 seals segment 2 (top == frontier)",
                 r2 == 1 && f2 == SEG * 2);

        /* Call 4: segment 3 is entirely ABOVE the frontier -> nothing sealed. */
        int r3 = segment_sealer_seal_next(dir, frontier, tiny_body, NULL,
                                          NULL, err, sizeof(err));
        SS_CHECK("seal_next #4 refuses to seal above frontier", r3 == 0);

        /* The store covers exactly [0, frontier]; nothing above was written. */
        struct chain_segment_store *store = NULL;
        enum cseg_status ost = chain_segment_store_open(dir, &store, err, sizeof(err));
        SS_CHECK("sealed_max == frontier, nothing above",
                 ost == CSEG_OK && store &&
                 chain_segment_store_covers(store, frontier) &&
                 !chain_segment_store_covers(store, frontier + 1) &&
                 chain_segment_store_sealed_max(store) == frontier);
        if (store) chain_segment_store_close(store);

        /* And no seg file for the above-frontier segment exists on disk. */
        char above[512];
        snprintf(above, sizeof(above), "%s/seg-%u-%u.dat", dir, SEG * 3, SEG);
        struct stat sb;
        SS_CHECK("no segment file above frontier on disk", stat(above, &sb) != 0);

        test_rm_rf_recursive(dir);
    }

    failures += test_prune_after_seal_gate();

    printf("segment_sealer: %d failures\n", failures);
    return failures;
}

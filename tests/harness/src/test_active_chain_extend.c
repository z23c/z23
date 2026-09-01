/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for active_chain_extend_window_have_data — the anchored, contiguity-
 * proven window extender that lets tip_finalize see its lookahead successor
 * WITHOUT the false-reorg cascade a generic best_header/most-work candidate
 * caused on the live node.
 *
 * The extender must:
 *   - extend the window along the CONTIGUOUS have-data frontier above the
 *     finalized tip, up to max_height (gate is BLOCK_HAVE_DATA, NOT
 *     BLOCK_VALID_SCRIPTS — the body stages must see a have-data block before
 *     it is script-validated; per-stage validity is enforced by each stage);
 *   - REFUSE to cross a gap, a fork (pprev not pointer-equal to the parent),
 *     or a missing-body / header-only block — never exposing a divergent or
 *     bodiless block that would overwrite a finalized slot;
 *   - be a no-op when there is no gap (max_height <= window height).
 *
 * Chain build mirrors test_tip_fork_stale.c: a minimal in-RAM main_state with
 * blocks inserted into map_block_index and pprev linked to the map-resident
 * entries (so the extender's by-pprev contiguity walk is exercised on real
 * pointers).
 */

#include "test/test_core.h"

#include "chain/chain.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "validation/chain_linkage_check.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdio.h>
#include <string.h>

#define ACE_CHECK(name, expr) do {                  \
    printf("active_chain_extend: %s... ", (name));  \
    if (expr) printf("OK\n");                         \
    else { printf("FAIL\n"); failures++; }            \
} while (0)

/* Insert a block at height h building on prev, with the given status. */
static struct block_index *ace_insert(struct main_state *ms,
                                      struct uint256 *hash, int h,
                                      struct block_index *prev, unsigned status)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)(h & 0xFF);
    hash->data[1] = (uint8_t)((h >> 8) & 0xFF);
    hash->data[2] = 0xAC; /* distinct salt */

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
    arith_uint256_set_u64(&pi->nChainWork, (uint64_t)(h + 1));
    pi->pprev = prev;
    return pi;
}

/* Build a contiguous valid have-data chain [0..n-1] in the map; window tip is
 * left at `tip_h`. Returns block pointers in out[]. */
static bool ace_build(struct main_state *ms, struct block_index **out, int n,
                      int tip_h)
{
    static struct uint256 hashes[64];
    struct block_index *prev = NULL;
    for (int h = 0; h < n; h++) {
        out[h] = ace_insert(ms, &hashes[h], h, prev,
                            BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS);
        if (!out[h]) return false;
        prev = out[h];
    }
    return active_chain_move_window_tip(&ms->chain_active, out[tip_h]);
}

/* ── Large-index / reorg equivalence helpers (cases 11-13) ───────────────────
 *
 * The perf lever these lock in: active_chain_extend_window_have_data's FAST
 * path discovers the fill candidate via block_index_get_ancestor (O(log n)
 * along pskip) instead of the per-block full pprev/map walk. These helpers
 * build a real skiplist (block_index_build_skip) so the fast path genuinely
 * hops pskip, and compare the assembled window slot-for-slot against an
 * independent reference pprev walk — the exact ground truth the optimized
 * fill must reproduce byte-for-byte. */

/* Unique, non-null hash for (height, branch). Layout is distinct from
 * ace_insert's (salt in a different byte) so the two families never alias. */
static void ace_hash2(struct uint256 *hash, int h, int branch)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)(h & 0xFF);
    hash->data[1] = (uint8_t)((h >> 8) & 0xFF);
    hash->data[2] = (uint8_t)((h >> 16) & 0xFF);
    hash->data[4] = (uint8_t)branch;
    hash->data[5] = 0xCE; /* salt — keeps the hash non-null at h=0,branch=0 */
}

/* Insert one block at height h on `prev` in `branch`, and build its skiplist
 * (the pskip the fast-path ancestor hop follows). The map COPIES the hash, so
 * the transient stack buffer here is safe. */
static struct block_index *ace_insert_skip(struct main_state *ms, int h,
                                           struct block_index *prev, int branch,
                                           unsigned status)
{
    struct uint256 hash;
    ace_hash2(&hash, h, branch);
    struct block_index *pi =
        chainstate_insert_block_index((struct chainstate *)ms, &hash);
    if (!pi) return NULL;
    pi->nHeight = h;
    pi->nBits = 0x1f07ffff;
    pi->nTime = 1000000 + (uint32_t)h * 150;
    pi->nVersion = 4;
    pi->nStatus = status;
    pi->nTx = 1;
    pi->nChainTx = (uint32_t)(h + 1);
    arith_uint256_set_u64(&pi->nChainWork, (uint64_t)(h + 1) + (uint64_t)branch);
    pi->pprev = prev;
    block_index_build_skip(pi); /* the O(log n) fast path hops this */
    return pi;
}

/* Build the REFERENCE window independently: walk pprev from `tip` to genesis,
 * recording ref[h] = the block on tip's path at height h. This is the exact
 * output the optimized fill must reproduce. */
static void ace_reference_window(struct block_index *tip,
                                 struct block_index **ref, int cap)
{
    for (int i = 0; i < cap; i++) ref[i] = NULL;
    for (struct block_index *w = tip; w; w = w->pprev)
        if (w->nHeight >= 0 && w->nHeight < cap)
            ref[w->nHeight] = w;
}

/* Every visible window slot [0..tip_h] equals the reference by BLOCK HASH
 * (byte identity of the 32-byte hash), is non-NULL, and nothing is visible
 * above tip_h. */
static bool ace_window_matches_ref(struct active_chain *c,
                                   struct block_index **ref, int tip_h)
{
    for (int h = 0; h <= tip_h; h++) {
        struct block_index *got = active_chain_at(c, h);
        if (!got || !ref[h]) return false;
        if (memcmp(got->hashBlock.data, ref[h]->hashBlock.data, 32) != 0)
            return false;
    }
    return active_chain_at(c, tip_h + 1) == NULL;
}

int test_active_chain_extend(void)
{
    printf("\n=== active_chain_extend_window_have_data tests ===\n");
    int failures = 0;
    const int N = 8;

    /* 1. Contiguous frontier: window at 3, bodies through 7 -> extend to 7. */
    {
        struct main_state ms; main_state_init(&ms);
        struct block_index *b[8];
        bool ok = ace_build(&ms, b, N, 3);
        ok = ok && active_chain_at(&ms.chain_active, 4) == NULL; /* gap pre */
        active_chain_extend_window_have_data(&ms.chain_active,
                                             &ms.map_block_index, ms.pindex_best_header, 7);
        ok = ok && active_chain_at(&ms.chain_active, 4) == b[4];
        ok = ok && active_chain_at(&ms.chain_active, 7) == b[7];
        ok = ok && active_chain_at(&ms.chain_active, 3) == b[3]; /* tip intact */
        ACE_CHECK("contiguous have-data frontier -> window extends to max", ok);
        main_state_free(&ms);
    }

    /* 2. Capped by max_height: extend only to 5 even though 6,7 are present. */
    {
        struct main_state ms; main_state_init(&ms);
        struct block_index *b[8];
        bool ok = ace_build(&ms, b, N, 3);
        active_chain_extend_window_have_data(&ms.chain_active,
                                             &ms.map_block_index, ms.pindex_best_header, 5);
        ok = ok && active_chain_at(&ms.chain_active, 5) == b[5];
        ok = ok && active_chain_at(&ms.chain_active, 6) == NULL; /* capped */
        ACE_CHECK("max_height caps the extension", ok);
        main_state_free(&ms);
    }

    /* 3. Fork at 5 (pprev points to 3, not 4) -> stop at 4, never expose 5. */
    {
        struct main_state ms; main_state_init(&ms);
        struct block_index *b[8];
        bool ok = ace_build(&ms, b, N, 3);
        b[5]->pprev = b[3]; /* divergent: not a child of b[4] */
        active_chain_extend_window_have_data(&ms.chain_active,
                                             &ms.map_block_index, ms.pindex_best_header, 7);
        ok = ok && active_chain_at(&ms.chain_active, 4) == b[4];
        ok = ok && active_chain_at(&ms.chain_active, 5) == NULL; /* refused */
        ACE_CHECK("fork/divergent successor refused (stops at contiguous edge)",
                  ok);
        main_state_free(&ms);
    }

    /* 4. Missing body at 5 -> stop at 4. */
    {
        struct main_state ms; main_state_init(&ms);
        struct block_index *b[8];
        bool ok = ace_build(&ms, b, N, 3);
        b[5]->nStatus = BLOCK_VALID_SCRIPTS; /* no BLOCK_HAVE_DATA */
        active_chain_extend_window_have_data(&ms.chain_active,
                                             &ms.map_block_index, ms.pindex_best_header, 7);
        ok = ok && active_chain_at(&ms.chain_active, 4) == b[4];
        ok = ok && active_chain_at(&ms.chain_active, 5) == NULL;
        ACE_CHECK("missing-body successor refused", ok);
        main_state_free(&ms);
    }

    /* 5. Have-data but NOT yet script-validated at 5 -> still EXPOSED. The gate
     * is BLOCK_HAVE_DATA, not BLOCK_VALID_SCRIPTS: the body-dependent stages
     * (body_fetch / body_persist / script_validate) read active_chain_at(their
     * cursor + 1) and MUST see a have-data block before it is script-validated
     * (script validation is exactly what that stage is about to do). Requiring
     * VALID_SCRIPTS here was a chicken-and-egg that wedged the body pipeline.
     * The remaining heights (6,7) retain BLOCK_VALID_SCRIPTS, so with a
     * contiguous have-data frontier the window extends all the way to 7. */
    {
        struct main_state ms; main_state_init(&ms);
        struct block_index *b[8];
        bool ok = ace_build(&ms, b, N, 3);
        b[5]->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_TREE; /* body, no scripts */
        active_chain_extend_window_have_data(&ms.chain_active,
                                             &ms.map_block_index, ms.pindex_best_header, 7);
        ok = ok && active_chain_at(&ms.chain_active, 4) == b[4];
        ok = ok && active_chain_at(&ms.chain_active, 5) == b[5]; /* exposed */
        ok = ok && active_chain_at(&ms.chain_active, 7) == b[7];
        ACE_CHECK("have-data not-yet-script-validated successor IS exposed", ok);
        main_state_free(&ms);
    }

    /* 6. No gap (max_height <= window height) -> no-op, window unchanged. */
    {
        struct main_state ms; main_state_init(&ms);
        struct block_index *b[8];
        bool ok = ace_build(&ms, b, N, 7); /* window already at 7 */
        active_chain_extend_window_have_data(&ms.chain_active,
                                             &ms.map_block_index, ms.pindex_best_header, 7);
        ok = ok && active_chain_at(&ms.chain_active, 7) == b[7];
        ok = ok && active_chain_height(&ms.chain_active) == 7;
        ACE_CHECK("no gap -> no-op", ok);
        main_state_free(&ms);
    }

    /* 7. Window grow RETIRES (never frees) the superseded chain[] array —
     * regression for the cross-thread grow/realloc UAF: a lock-free reader
     * that loaded the pre-grow array pointer must still be able to index it
     * after the grow. Also pins geometric growth (capacity at least doubles),
     * which bounds the retired set, and that active_chain_free reclaims the
     * retired arrays (leak/double-free caught under sanitizers). */
    {
        static struct uint256 far_hashes[2];
        struct main_state ms; main_state_init(&ms);
        struct block_index *b[8];
        bool ok = ace_build(&ms, b, N, 3); /* capacity = 3 + 1024 */
        struct block_index **pre = ms.chain_active.chain;
        int pre_cap = ms.chain_active.capacity;
        ok = ok && pre != NULL && pre_cap > 0;

        /* pprev = NULL: this synthetic far-jump block exists only to force
         * an array grow; a non-NULL pprev with a non-adjacent height label
         * would (correctly) trip the validation-pack label-splice check in
         * active_chain_move_window_tip. NULL pprev is scoped out and the
         * fill loop preserves the lower window identically. */
        struct block_index *far_blk = ace_insert(&ms, &far_hashes[0], pre_cap + 100,
                                             NULL,
                                             BLOCK_HAVE_DATA |
                                             BLOCK_VALID_SCRIPTS);
        ok = ok && far_blk &&
             active_chain_move_window_tip(&ms.chain_active, far_blk);
        ok = ok && ms.chain_active.chain != pre;          /* grew */
        ok = ok && ms.chain_active.capacity >= 2 * pre_cap; /* geometric */
        ok = ok && ms.chain_active.retired != NULL &&
             ms.chain_active.retired->arr == pre;         /* retired, not freed */
        ok = ok && pre[3] == b[3];      /* old array still live + intact */
        ok = ok && active_chain_at(&ms.chain_active, far_blk->nHeight) == far_blk;
        ok = ok && active_chain_at(&ms.chain_active, 3) == b[3];

        /* Second grow chains a second retired array; the first stays live. */
        struct block_index **mid = ms.chain_active.chain;
        int mid_cap = ms.chain_active.capacity;
        struct block_index *far2_blk = ace_insert(&ms, &far_hashes[1],
                                              mid_cap + 100, NULL /* see above */,
                                              BLOCK_HAVE_DATA |
                                              BLOCK_VALID_SCRIPTS);
        ok = ok && far2_blk &&
             active_chain_move_window_tip(&ms.chain_active, far2_blk);
        ok = ok && ms.chain_active.retired != NULL &&
             ms.chain_active.retired->arr == mid &&
             ms.chain_active.retired->next != NULL &&
             ms.chain_active.retired->next->arr == pre;
        ok = ok && pre[3] == b[3] && mid[far_blk->nHeight] == far_blk;
        ACE_CHECK("grow retires superseded chain[] (value-stable for readers)",
                  ok);
        main_state_free(&ms); /* frees both retired arrays */
    }

    /* 8. The wrong-fork wedge regression: pindex_best_header points at a
     * BODILESS orphan above the have-data frontier. The fix scans the range UP
     * TO the header tip (a generous upper bound, NOT a per-stage cap), but the
     * have-data extender refuses to fill to a header-only candidate (no
     * BLOCK_HAVE_DATA), so the window must extend ONLY to the contiguous
     * have-data tip and must NOT pin the header-only orphan — even though the
     * scan bound now sits ABOVE the body floor.
     *
     * Bodies/scripts through 5; 6 and 7 are header-only (no BLOCK_HAVE_DATA);
     * max_height = the HEADER tip (7), proving the orphan-exclusion comes from
     * the internal have-data gate, not from an artificially low scan bound. */
    {
        struct main_state ms; main_state_init(&ms);
        struct block_index *b[8];
        bool ok = ace_build(&ms, b, N, 3);
        /* Bodies + scripts only through 5; 6,7 are header-only (no body). */
        b[6]->nStatus = BLOCK_VALID_TREE; /* header-only orphan, no HAVE_DATA */
        b[7]->nStatus = BLOCK_VALID_TREE;
        ms.pindex_best_header = b[7]; /* best HEADER sits above the body floor */

        /* Scan all the way to the header tip (7), exactly as the fixed
         * reducer_extend_window_to_candidate now passes pindex_best_header. */
        active_chain_extend_window_have_data(&ms.chain_active,
                                             &ms.map_block_index, ms.pindex_best_header, 7);
        ok = ok && active_chain_at(&ms.chain_active, 5) == b[5]; /* reached body */
        ok = ok && active_chain_at(&ms.chain_active, 6) == NULL; /* NOT pinned */
        ok = ok && active_chain_at(&ms.chain_active, 7) == NULL;
        ok = ok && active_chain_height(&ms.chain_active) == 5;
        ACE_CHECK("bodiless best-header orphan NOT pinned even with header-tip "
                  "scan bound", ok);
        main_state_free(&ms);
    }

    /* 9. Upstream-lookahead preservation (the bug this rework fixes): the
     * previous bound was utxo_apply's cursor (the LOWEST stage cursor). An
     * upstream stage (body_persist/script_validate/proof_validate) reads
     * active_chain_at(its_cursor + 1); if the window stopped at utxo_apply's
     * cursor, every height above it returned NULL -> JOB_IDLE -> bodies could
     * never lead utxo_apply -> wedge.
     *
     * Model: utxo_apply finalized at the window tip (3); bodies+scripts present
     * and contiguous through 7. With the header-tip scan bound, the window MUST
     * expose heights 4..7 so an upstream stage at cursor=4,5,6 can read its
     * next block. Concretely: active_chain_at(utxo_apply_cursor + k) for k>=1
     * (i.e. the heights the leading stages consume) is non-NULL up to the
     * have-data frontier — the starvation the cursor-bound caused is gone. */
    {
        struct main_state ms; main_state_init(&ms);
        struct block_index *b[8];
        int utxo_apply_cursor = 3;            /* lowest stage; == window tip */
        bool ok = ace_build(&ms, b, N, utxo_apply_cursor);
        ms.pindex_best_header = b[7];         /* header tip = body frontier here */

        active_chain_extend_window_have_data(&ms.chain_active,
                                             &ms.map_block_index,
                                             ms.pindex_best_header,
                                             ms.pindex_best_header->nHeight);

        /* Every height a leading upstream stage would consume (cursor+1 ..
         * have-data tip) is now exposed — NOT NULL as it was under the
         * utxo_apply-cursor cap. */
        for (int h = utxo_apply_cursor + 1; h <= 7; h++)
            ok = ok && active_chain_at(&ms.chain_active, h) == b[h];
        ok = ok && active_chain_height(&ms.chain_active) == 7;
        ACE_CHECK("upstream lookahead preserved (successors above utxo_apply "
                  "cursor exposed)", ok);
        main_state_free(&ms);
    }

    /* 10. POINTER-IDENTITY WEDGE regression (the live 3162167 stall). The
     * canonical successor exists with a body, but its pprev points to a
     * DUPLICATE block_index object that carries the SAME block hash as the
     * window tip yet a DIFFERENT pointer — exactly what happens when a
     * snapshot-seeded tip slot and a header-ingest pprev resolve the same block
     * to two objects. The old by-pointer contiguity walk (ch->pprev == cand)
     * rejected it and froze the forward fold one block below the header tip;
     * the fix walks by BLOCK HASH (consensus linkage), so it admits the
     * successor and the window advances. Exercises the slow path (best_header
     * NULL) where the by-pprev hash compare lives. */
    {
        struct main_state ms; main_state_init(&ms);
        struct block_index *b[8];
        bool ok = ace_build(&ms, b, N, 3); /* window tip at b[3] */

        /* A duplicate of height-3 (the tip): same hash, different pointer, not
         * in the map; parent is the real b[2] so ancestry stays linked. */
        struct block_index dup3;
        memset(&dup3, 0, sizeof(dup3));
        dup3.hashBlock  = b[3]->hashBlock;   /* SAME block hash as the tip */
        dup3.phashBlock = &dup3.hashBlock;
        dup3.nHeight    = 3;
        dup3.nStatus    = b[3]->nStatus;
        dup3.nChainWork = b[3]->nChainWork;
        dup3.pprev      = b[2];

        b[4]->pprev = &dup3; /* successor links to the duplicate parent */

        active_chain_extend_window_have_data(&ms.chain_active,
                                             &ms.map_block_index,
                                             NULL /* slow path: by-pprev hash */, 7);
        ok = ok && active_chain_at(&ms.chain_active, 4) == b[4]; /* admitted */
        ok = ok && active_chain_at(&ms.chain_active, 7) == b[7]; /* extends on */
        ACE_CHECK("duplicate same-hash parent admitted by HASH not pointer "
                  "(live 3162167 wedge)", ok);
        main_state_free(&ms);
    }

    /* 11. LARGE-INDEX BYTE-IDENTITY (the perf-lever guard). The O(log n)
     * best-header/skiplist FAST path and the O(map) pprev-walk SLOW path each
     * assemble a window slot-for-slot identical to an independent reference
     * pprev walk, across a multi-thousand-block index. This is what makes
     * routing the from-genesis refold through block_index_get_ancestor (instead
     * of the per-block full pprev/map walk — docs/work/refold-fold-rate-
     * bottlenecks.md #1) verdict-preserving: the window it produces is provably
     * the same one the reference walk produces. */
    {
        enum { BIG = 4000 };
        static struct block_index *refbuf[BIG + 8];

        /* FAST path: skiplist built + best_header set. */
        struct main_state msf; main_state_init(&msf);
        chain_linkage_reset_for_testing();
        struct block_index *ftip = NULL, *prev = NULL;
        bool ok = true;
        for (int h = 0; h < BIG && ok; h++) {
            struct block_index *pi = ace_insert_skip(
                &msf, h, prev, 0, BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS);
            ok = ok && pi != NULL; prev = pi; ftip = pi;
        }
        ok = ok && ftip &&
             active_chain_move_window_tip(&msf.chain_active,
                                          block_index_get_ancestor(ftip, 1));
        msf.pindex_best_header = ftip;
        uint64_t f0 = active_chain_extend_window_have_data_fast_count();
        active_chain_extend_window_have_data(&msf.chain_active,
                                             &msf.map_block_index, ftip,
                                             ftip->nHeight);
        ok = ok && active_chain_extend_window_have_data_fast_count() > f0;
        ace_reference_window(ftip, refbuf, BIG + 8);
        ok = ok && ace_window_matches_ref(&msf.chain_active, refbuf, BIG - 1);

        /* SLOW path: best_header NULL -> map scan + pprev-hash contiguity walk.
         * Hashes are height-derived, so the SAME reference applies. */
        struct main_state mss; main_state_init(&mss);
        struct block_index *stip = NULL; prev = NULL;
        for (int h = 0; h < BIG && ok; h++) {
            struct block_index *pi = ace_insert_skip(
                &mss, h, prev, 0, BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS);
            ok = ok && pi != NULL; prev = pi; stip = pi;
        }
        ok = ok && stip &&
             active_chain_move_window_tip(&mss.chain_active,
                                          block_index_get_ancestor(stip, 1));
        uint64_t s0 = active_chain_extend_window_have_data_slow_count();
        active_chain_extend_window_have_data(&mss.chain_active,
                                             &mss.map_block_index, NULL,
                                             stip->nHeight);
        ok = ok && active_chain_extend_window_have_data_slow_count() > s0;
        ok = ok && ace_window_matches_ref(&mss.chain_active, refbuf, BIG - 1);

        ACE_CHECK("large index: skiplist-fast == pprev-slow == reference window "
                  "(byte-identical)", ok);
        main_state_free(&msf);  /* refbuf pointers live until after mss compare */
        main_state_free(&mss);
    }

    /* 12. INCREMENTAL GALLOP across the MAX_GAP (8192) bound. A chain longer
     * than one extend's reach must assemble — over several bounded extends,
     * each covering at most MAX_GAP heights (NOT the whole chain) — a window
     * byte-identical to the single reference pprev walk. This proves the
     * bounded, incrementally-galloping fill is exact, not merely the
     * single-shot case, and that per-extend cost stays O(chain/gap) bounded. */
    {
        enum { BIG2 = 9000 }; /* > ACTIVE_CHAIN_EXTEND_HAVE_DATA_MAX_GAP (8192) */
        static struct block_index *refbuf2[BIG2 + 8];
        struct main_state ms; main_state_init(&ms);
        chain_linkage_reset_for_testing();
        struct block_index *tip = NULL, *prev = NULL;
        bool ok = true;
        for (int h = 0; h < BIG2 && ok; h++) {
            struct block_index *pi = ace_insert_skip(
                &ms, h, prev, 0, BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS);
            ok = ok && pi != NULL; prev = pi; tip = pi;
        }
        ok = ok && tip &&
             active_chain_move_window_tip(&ms.chain_active,
                                          block_index_get_ancestor(tip, 1));
        ms.pindex_best_header = tip;
        int iters = 0;
        while (ok && active_chain_height(&ms.chain_active) < tip->nHeight &&
               iters < 16) {
            active_chain_extend_window_have_data(&ms.chain_active,
                                                 &ms.map_block_index, tip,
                                                 tip->nHeight);
            iters++;
        }
        ok = ok && active_chain_height(&ms.chain_active) == tip->nHeight;
        ok = ok && iters >= 2;                  /* took >1 bounded extend */
        ok = ok && iters <= (BIG2 / 8192) + 2;  /* stayed O(chain/gap) bounded */
        ace_reference_window(tip, refbuf2, BIG2 + 8);
        ok = ok && ace_window_matches_ref(&ms.chain_active, refbuf2, BIG2 - 1);
        ACE_CHECK("incremental gallop across MAX_GAP assembles reference window "
                  "(bounded per-extend, exact)", ok);
        main_state_free(&ms);
    }

    /* 13. REORG / WINDOW-SHRINK then re-extend. After the window is retracted to
     * a fork point (the shrink half of a reorg) and re-extended along a
     * DIVERGENT branch that shares the lower chain, the assembled window is
     * byte-identical to the reference pprev walk of the NEW tip: lower slots
     * preserved, upper slots replaced by the fork. The overlapping heights hold
     * two competing block_index objects, which the fill must resolve to the
     * best-header branch — never leaving a stale main-chain slot visible. */
    {
        enum { MAIN_N = 2000, FORK_FROM = 1000, FORK_TIP = 2499 };
        static struct block_index *refbuf3[FORK_TIP + 8];
        struct main_state ms; main_state_init(&ms);
        chain_linkage_reset_for_testing();
        struct block_index *mtip = NULL, *prev = NULL;
        bool ok = true;
        for (int h = 0; h < MAIN_N && ok; h++) {
            struct block_index *pi = ace_insert_skip(
                &ms, h, prev, 0, BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS);
            ok = ok && pi != NULL; prev = pi; mtip = pi;
        }
        ok = ok && mtip &&
             active_chain_move_window_tip(&ms.chain_active,
                                          block_index_get_ancestor(mtip, 1));
        ms.pindex_best_header = mtip;
        active_chain_extend_window_have_data(&ms.chain_active,
                                             &ms.map_block_index, mtip,
                                             mtip->nHeight);
        struct block_index *main1500 = active_chain_at(&ms.chain_active, 1500);
        ok = ok && main1500 != NULL;

        /* Fork branching off the shared block@FORK_FROM (distinct branch=1
         * hashes -> two objects live at the overlapping heights 1001..1999). */
        struct block_index *fprev = block_index_get_ancestor(mtip, FORK_FROM);
        struct block_index *ftip = NULL;
        for (int h = FORK_FROM + 1; h <= FORK_TIP && ok; h++) {
            struct block_index *pi = ace_insert_skip(
                &ms, h, fprev, 1, BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS);
            ok = ok && pi != NULL; fprev = pi; ftip = pi;
        }

        /* SHRINK: retract the window to the fork point (reorg unwind). */
        ok = ok &&
             active_chain_move_window_tip(&ms.chain_active,
                                          block_index_get_ancestor(mtip, FORK_FROM));
        ok = ok && active_chain_height(&ms.chain_active) == FORK_FROM;

        /* Re-extend along the fork. */
        ms.pindex_best_header = ftip;
        active_chain_extend_window_have_data(&ms.chain_active,
                                             &ms.map_block_index, ftip,
                                             ftip->nHeight);
        ace_reference_window(ftip, refbuf3, FORK_TIP + 8);
        ok = ok && ace_window_matches_ref(&ms.chain_active, refbuf3, FORK_TIP);

        /* The overlapping height now resolves to the FORK object, not main. */
        struct block_index *fork1500 = active_chain_at(&ms.chain_active, 1500);
        ok = ok && fork1500 != NULL && fork1500 != main1500 &&
             memcmp(fork1500->hashBlock.data, refbuf3[1500]->hashBlock.data,
                    32) == 0;
        ACE_CHECK("reorg/window-shrink then re-extend == reference (fork "
                  "resolved, lower window preserved)", ok);
        main_state_free(&ms);
    }

    /* 14. FAST-PATH DUPLICATE-HAVE_DATA rescue (the live H+1 window wedge). The
     * body-dependent pipeline stalls when best_header's ancestry object at H+1
     * is a DUPLICATE that stayed bodiless (BLOCK_HAVE_DATA never set on it)
     * while body_persist set the bit on the block_map's canonical SAME-HASH
     * object. The old fast-path gate read the bit off the ancestry twin, saw no
     * data, and stopped one block short — utxo_apply then logs "step no-advance
     * result=idle select_total=0" forever. have_data_by_hash merges the
     * have-data truth across same-hash twins and fills the window with the
     * body-bearing object, so active_chain_at(H+1) carries the body. It admits
     * NOTHING unverified: both objects are the same hash-linked block. Exercises
     * the FAST path (best_header set, its ancestry hash-matches the tip). */
    {
        struct main_state ms; main_state_init(&ms);
        struct block_index *b[8];
        bool ok = ace_build(&ms, b, N, 3);          /* window tip at b[3] */

        /* hdr4: best_header's ancestry object at height 4 — the SAME block hash
         * as the canonical b[4] (already body-present in the map) but a
         * DIFFERENT object that stayed bodiless. Its parent is the real b[3], so
         * the fast-path liveness guard (ancestry@tip == tip by hash) passes. */
        struct block_index hdr4;
        memset(&hdr4, 0, sizeof(hdr4));
        hdr4.hashBlock  = b[4]->hashBlock;   /* same hash as the canonical body */
        hdr4.phashBlock = &hdr4.hashBlock;
        hdr4.nHeight    = 4;
        hdr4.nStatus    = BLOCK_VALID_TREE;  /* header-only: NO BLOCK_HAVE_DATA */
        hdr4.nChainWork = b[4]->nChainWork;
        hdr4.pprev      = b[3];

        uint64_t fast0 = active_chain_extend_window_have_data_fast_count();
        uint64_t dup0  = active_chain_extend_window_dup_data_rescued_count();
        active_chain_extend_window_have_data(&ms.chain_active,
                                             &ms.map_block_index, &hdr4, 4);
        ok = ok && active_chain_at(&ms.chain_active, 4) == b[4];  /* body twin */
        ok = ok && active_chain_at(&ms.chain_active, 4) != &hdr4; /* not bodiless */
        ok = ok && active_chain_height(&ms.chain_active) == 4;    /* extended */
        ok = ok && active_chain_extend_window_have_data_fast_count() > fast0;
        ok = ok && active_chain_extend_window_dup_data_rescued_count() == dup0 + 1;
        ACE_CHECK("fast-path bodiless-ancestry duplicate rescued via same-hash "
                  "body twin (live H+1 wedge; counter fires)", ok);
        main_state_free(&ms);
    }

    /* 15. NEGATIVE / SAFETY: a genuinely pprev-less body at tip+1 (an
     * unverifiable parent — the exact shape the rejected chain-extender rung
     * admitted) is NEVER pulled into the window, by EITHER path. Admitting it
     * would put a NULL-pprev lookahead at active_chain_at(tip+1), which
     * tip_finalize (tip_finalize_stage.c:429) reads as a genuine fork and would
     * false-mark the good tip below it ok=0 reorg_detected. The have-data merge
     * only relaxes the BLOCK_HAVE_DATA gate; it never touches the pprev/hash
     * contiguity requirement, so the refusal is preserved. Uses a 4-block chain
     * (heights 0..3) so height 4 is free for the orphan. */
    {
        struct main_state ms; main_state_init(&ms);
        struct block_index *bb[4];
        bool ok = ace_build(&ms, bb, 4, 3);       /* window tip at bb[3] */

        /* A body-present successor at height 4 whose parent link is SEVERED
         * (pprev == NULL): in the map (eligible by have-data) but with no
         * verifiable parent, so no path may admit it. */
        struct uint256 orphan_hash;
        struct block_index *orphan =
            ace_insert(&ms, &orphan_hash, 4, NULL,
                       BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS);
        ok = ok && orphan != NULL;

        /* SLOW path (best_header NULL): the pprev-walk refuses a NULL-pprev
         * child. */
        active_chain_extend_window_have_data(&ms.chain_active,
                                             &ms.map_block_index, NULL, 4);
        ok = ok && active_chain_at(&ms.chain_active, 4) == NULL;
        ok = ok && active_chain_height(&ms.chain_active) == 3;

        /* FAST-guard path (best_header == the severed orphan): its ancestry
         * cannot reach the finalized tip (pprev severed), so the guard fails and
         * the slow pprev-walk again refuses it — never admitted. */
        active_chain_extend_window_have_data(&ms.chain_active,
                                             &ms.map_block_index, orphan, 4);
        ok = ok && active_chain_at(&ms.chain_active, 4) == NULL;
        ok = ok && active_chain_height(&ms.chain_active) == 3;

        ACE_CHECK("pprev-less body at tip+1 refused by all paths (no "
                  "false-reorg fuel)", ok);
        main_state_free(&ms);
    }

    chain_linkage_reset_for_testing(); /* no HOLD/counter leak to sibling groups */
    return failures;
}

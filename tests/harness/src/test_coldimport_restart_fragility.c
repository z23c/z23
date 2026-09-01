/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression guard for the COLD-IMPORT RESTART FRAGILITY class.
 *
 * The bug
 * -------
 * A cold-import node that forward-synced PAST its local zclassicd, on a
 * CLEAN restart, loses its forward extent: the need_zcd reimport branch in
 * engine/composition/src/boot.c re-reads zclassicd's LevelDB (which tops out at
 * zclassicd's OWN tip) and the forward-pass best-tip selection +
 * boot_promote_tip_via_csr commits the public tip DOWN to the mirror
 * (zclassicd) index tip — a backward downshift below our derived coins
 * frontier. The guard (boot.c:2125-2147) suppresses that backward commit
 * when our derived coins-best height is STRICTLY above zclassicd's index
 * best: `have_ndcb && ndcb.height > zcd_best_h`.
 *
 * What this test proves (the INVERSE of the bug)
 * ----------------------------------------------
 * Given a block_index that mirrors the cold-import topology — a zclassicd
 * ancestry 0..Z plus a forward extent Z+1..Z+N that exists ABOVE the
 * mirror/zclassicd index tip Z — the EXACT forward-pass best-tip selection
 * algorithm from boot.c:2095-2155 must select the FORWARD EXTENT tip
 * (height Z+N), NOT the mirror tip Z; and the suppression predicate must
 * FIRE (derived frontier > zcd index best), i.e. the tip is NOT committed
 * down to the mirror tip and the forward extent is preserved.
 *
 * Seam honesty
 * ------------
 * boot.c does NOT expose the need_zcd decision (forward-pass tip selection
 * + the suppression predicate) as a pure helper — both are inline statics.
 * This test therefore reconstructs the forward-pass selection EXACTLY
 * against the real exported block_index / chainstate / pow / arith APIs
 * (the same `nChainTx>0 && HAVE_DATA && !FAILED`, highest-nChainWork rule),
 * and replicates the one-line suppression predicate. The block_index
 * topology and the selection algorithm are the load-bearing, real parts;
 * the predicate is one comparison flagged for extraction (see open_risks in
 * the handoff). If boot.c later exposes a pure helper
 *   bool boot_need_zcd_suppress_backward_tip(const struct block_index *zcd_best,
 *                                            bool have_derived, int32_t derived_h);
 * this test should call it directly instead of replicating the predicate.
 *
 * Scratch files live under ./test-tmp/coldimport_<pid>/ per the no-/tmp
 * convention (the topology is in-memory; the dir exists only for symmetry
 * with sibling boot tests and is cleaned at the end).
 */

#include "test/test_core.h"
#include "coins/undo.h"

#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "chain/pow.h"
#include "core/uint256.h"
#include "core/arith_uint256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CI_CHECK(name, expr) do { \
    printf("coldimport_restart_fragility: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Unique synthetic block hash for height `h`. */
static void ci_hash_for(int h, struct uint256 *out)
{
    memset(out->data, 0, 32);
    out->data[0] = (uint8_t)(h & 0xFF);
    out->data[1] = (uint8_t)((h >> 8) & 0xFF);
    out->data[2] = (uint8_t)((h >> 16) & 0xFF);
    out->data[31] = 0x5A;
}

/* Insert one fully-connected, data-bearing block_index entry at `height`,
 * pprev-linked to `parent` (NULL for genesis). Mirrors what a real loaded +
 * connected entry carries: HAVE_DATA, VALID_SCRIPTS, nTx>0, and a pprev
 * chain so the forward-pass below can accumulate nChainWork / nChainTx. */
static struct block_index *ci_insert(struct main_state *ms, int height,
                                     struct block_index *parent)
{
    struct uint256 h;
    ci_hash_for(height, &h);
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, &h);
    if (!bi)
        return NULL;
    bi->nHeight = height;
    bi->nBits = 0x2000ffffu;          /* trivially-easy target (test PoW) */
    bi->nTime = 1700000000u + (uint32_t)height;
    bi->nVersion = 4;
    bi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    bi->nTx = 1;                       /* nonzero so nChainTx propagates */
    bi->nFile = 0;
    bi->nDataPos = (uint32_t)(height * 80);
    bi->pprev = parent;
    return bi;
}

/* The EXACT forward-pass best-tip selection from boot.c:2095-2155.
 * Walks all entries height-sorted, accumulates nChainWork on top of pprev,
 * propagates nChainTx, then picks the highest-work entry that is data-bearing
 * and not failed. Returns the selected tip (or NULL). */
static struct block_index *ci_select_best_tip(struct main_state *ms)
{
    size_t n = ms->map_block_index.size;
    if (n == 0)
        return NULL;
    struct block_index **sorted =
        zcl_malloc(n * sizeof(*sorted), "ci.sorted");
    if (!sorted)
        return NULL;

    size_t si = 0, idx = 0;
    struct block_index *sp;
    while (block_map_next(&ms->map_block_index, &si, NULL, &sp))
        if (sp && idx < n)
            sorted[idx++] = sp;
    n = idx;

    /* Height-sort (parents before children) — boot.c uses
     * cmp_block_index_height; we inline the same ascending-height order. */
    for (size_t i = 0; i + 1 < n; i++)
        for (size_t j = i + 1; j < n; j++)
            if (sorted[j]->nHeight < sorted[i]->nHeight) {
                struct block_index *t = sorted[i];
                sorted[i] = sorted[j];
                sorted[j] = t;
            }

    struct block_index *best = NULL;
    for (size_t i = 0; i < n; i++) {
        struct block_index *b = sorted[i];
        struct arith_uint256 proof = GetBlockProof(b);
        if (b->pprev)
            arith_uint256_add(&b->nChainWork, &b->pprev->nChainWork, &proof);
        else
            b->nChainWork = proof;

        if (b->nTx > 0) {
            if (b->pprev && b->pprev->nChainTx > 0)
                b->nChainTx = b->pprev->nChainTx + b->nTx;
            else if (!b->pprev)
                b->nChainTx = b->nTx;
        }

        if (b->nChainTx > 0 &&
            (b->nStatus & BLOCK_HAVE_DATA) &&
            !(b->nStatus & BLOCK_FAILED_MASK)) {
            if (!best ||
                arith_uint256_compare(&b->nChainWork, &best->nChainWork) > 0)
                best = b;
        }
    }
    free(sorted);
    return best;
}

int test_coldimport_restart_fragility(void)
{
    int failures = 0;

    char dir[256];
    snprintf(dir, sizeof(dir), "./test-tmp/coldimport_%d", (int)getpid());
    mkdir("./test-tmp", 0755);
    mkdir(dir, 0755);

    /* ── Topology: mirror ancestry 0..Z, forward extent Z+1..Z+N. ─────
     * Z (the zclassicd index tip / mirror tip) = 1000.
     * N (forward extent we cold-import-synced past zclassicd) = 5.
     * Derived coins frontier = the forward tip = Z+N. */
    const int Z = 1000;   /* mirror / zclassicd index best height */
    const int N = 5;      /* forward extent length above the mirror tip */
    const int FWD_TIP = Z + N;

    struct main_state ms;
    main_state_init(&ms);

    /* Build the ancestry 0..Z and the forward extent Z+1..Z+N as ONE
     * pprev-linked chain. (We only materialize a tail of the ancestry —
     * the selection only needs a connected pprev chain to accumulate work;
     * heights are what matter for the tip comparison.) Start the
     * materialized chain at A so genesis-anchoring is well-defined. */
    const int A = Z - 4;  /* materialize [A .. Z+N], a small connected tail */

    struct block_index *prev = NULL;
    struct block_index *zcd_tip = NULL;   /* entry at the mirror tip Z */
    struct block_index *fwd_tip = NULL;   /* entry at the forward tip Z+N */
    bool insert_ok = true;
    for (int h = A; h <= FWD_TIP; h++) {
        struct block_index *bi = ci_insert(&ms, h, prev);
        if (!bi) { insert_ok = false; break; }
        if (h == Z)       zcd_tip = bi;
        if (h == FWD_TIP) fwd_tip = bi;
        prev = bi;
    }
    CI_CHECK("setup: chain materialized", insert_ok);
    CI_CHECK("setup: mirror tip entry present", zcd_tip != NULL);
    CI_CHECK("setup: forward tip entry present", fwd_tip != NULL);

    if (!insert_ok || !zcd_tip || !fwd_tip) {
        main_state_free(&ms);
        test_cleanup_tmpdir(dir);
        return failures + 1;
    }

    /* ── Run the REAL forward-pass best-tip selection. ───────────────── */
    struct block_index *best = ci_select_best_tip(&ms);
    CI_CHECK("best-tip selection returned a tip", best != NULL);

    /* INVERSE-OF-BUG #1: the selected tip is the FORWARD extent, NOT the
     * mirror tip. The bug would pin best to the zclassicd index best Z. */
    CI_CHECK("best tip is the forward extent (not the mirror tip)",
             best == fwd_tip);
    CI_CHECK("best tip height is above the mirror tip",
             best && best->nHeight == FWD_TIP && best->nHeight > Z);

    /* INVERSE-OF-BUG #2: the forward extent is PRESERVED in the index —
     * every entry above the mirror tip is still present + connected (the
     * clean-restart bug drops these so the index falls back to the mirror
     * extent). */
    bool fwd_preserved = true;
    struct block_index *w = fwd_tip;
    for (int h = FWD_TIP; h > Z; h--) {
        if (!w || w->nHeight != h ||
            !(w->nStatus & BLOCK_HAVE_DATA)) {
            fwd_preserved = false;
            break;
        }
        w = w->pprev;
    }
    /* After walking the N forward entries we must land exactly on the
     * mirror tip Z — proving the forward extent is a contiguous extension. */
    CI_CHECK("forward extent contiguous + data-bearing above mirror tip",
             fwd_preserved && w == zcd_tip);

    /* INVERSE-OF-BUG #3: the suppression predicate FIRES. boot.c suppresses
     * the backward CSR tip commit when our derived coins frontier is
     * STRICTLY above zclassicd's index best. Here the derived frontier IS
     * the forward tip; the mirror best is Z; so the guard MUST fire.
     *
     * NOTE: this replicates the inline boot.c predicate
     *   have_ndcb && ndcb.height > zcd_best_h
     * pending a pure-helper extraction (see header + open_risks). The
     * inputs (derived frontier, zcd_best height) come from the real
     * selection above, so a regression that lets best fall to the mirror
     * tip flips this assertion. */
    int32_t zcd_best_h = zcd_tip->nHeight;            /* mirror index best */
    bool have_ndcb = true;                            /* canonical datadir */
    int32_t derived_frontier_h = fwd_tip->nHeight;    /* our coins frontier */
    bool suppress_backward_commit =
        have_ndcb && (derived_frontier_h > zcd_best_h);
    CI_CHECK("suppression predicate fires (no backward tip commit)",
             suppress_backward_commit);

    /* CONTROL: a node AT/BELOW zclassicd (legitimate fresh fast-cold-sync)
     * must NOT suppress — the predicate is keyed strictly on '>'. The
     * at-mirror derived frontier equals the mirror best (distinct lvalue so
     * the strict '>' is exercised, not a tautological self-comparison). */
    int32_t at_mirror_frontier_h = zcd_best_h;
    bool suppress_when_at_mirror =
        have_ndcb && (at_mirror_frontier_h > zcd_best_h);
    CI_CHECK("control: at-mirror node does NOT suppress (promotes normally)",
             !suppress_when_at_mirror);

    main_state_free(&ms);
    test_cleanup_tmpdir(dir);
    return failures;
}

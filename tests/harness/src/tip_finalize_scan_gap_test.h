/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A live tip must not set the wallet height over a block the wallet step
 * skipped. Included once by test_tip_finalize_post_step.c after TP_CHECK; the
 * readable body is the fixture's height-1 block, replayed at heights 1..3 on
 * index copies (the wallet step reads the body, never the height it is
 * filed under), and an unreadable index points at no block file.
 *
 * The balance reply trusts RAM when wallet_scanned_through_height() reaches
 * the chain height, so that height is the freshness check here. */

#ifndef TIP_FINALIZE_SCAN_GAP_TEST_H
#define TIP_FINALIZE_SCAN_GAP_TEST_H

#include "storage/block_parse_cache.h"

static struct app_runtime_context *g_gap_rt;

static struct wallet *tp_gap_wallet_new(const struct wallet *like, bool pending)
{
    struct wallet *w = zcl_calloc(1, sizeof(*w), "tp_gap_wallet");
    if (!w) return NULL;
    wallet_init(w);
    w->sapling_notes = zcl_calloc(1, sizeof(*w->sapling_notes), "tp_gap_note");
    if (!w->sapling_notes) { wallet_free(w); free(w); return NULL; }
    w->sapling_notes_cap = w->num_sapling_notes = 1;
    w->sapling_notes[0].used = true;
    memcpy(w->sapling_notes[0].nf, like->sapling_notes[0].nf, 32);
    if (!(pending ? wallet_readiness_initialize(w, WALLET_READINESS_PENDING, true, 1)
                  : wallet_readiness_initialize(w, WALLET_READINESS_READY, false, 0))) {
        wallet_free(w); free(w); return NULL;
    }
    return w;
}

static struct block_index tp_gap_index(const struct block_index *src,
                                       int height, bool readable)
{
    struct block_index at = *src;
    at.phashBlock = src->phashBlock;
    at.nHeight = height;
    if (!readable) {
        at.nFile = 9999; /* no such blk file */
        at.nDataPos = 0;
    }
    return at;
}

static void tp_gap_evict_unreadable(const struct block_index *bi, bool unreadable)
{
    if (unreadable)
        block_parse_cache_evict(bi->nHeight, bi->phashBlock->data);
}

static bool tp_gap_unmarked(const struct wallet *w)
{
    return !w->scan_retry.pending &&
           wallet_scanned_through_height(w) == w->best_block_height;
}

/* The wallet applied block 3 but read through height 1 only, and says so: a
 * retry from 2 is pending under the gap blocker, so the memory-trust height
 * (wallet_scanned_through_height) stays at 1 while best_block_height, the
 * depth reference, follows the tip. */
static bool tp_gap_recorded(const struct wallet *w)
{
    return w->best_block_height == 3 && w->scan_retry.pending &&
           w->scan_retry.from == 2 &&
           strcmp(w->scan_retry.blocker, WALLET_TIP_GAP) == 0 &&
           wallet_scanned_through_height(w) == 1;
}

/* Block 2 is skipped (unreadable, or the wallet not READY), block 3 follows. */
static int tp_gap_skip_case(const struct block_index *src, const char *name,
                            bool unreadable)
{
    int failures = 0;
    struct block_index b1 = tp_gap_index(src, 1, true);
    struct block_index b2 = tp_gap_index(src, 2, !unreadable);
    struct block_index b3 = tp_gap_index(src, 3, true);
    struct wallet *w = tp_gap_wallet_new(app_runtime_wallet(), !unreadable);
    TP_CHECK(name, w != NULL);
    if (!w) return failures;
    struct wallet *original = app_runtime_wallet();
    struct app_runtime_context *rt = g_gap_rt;
    rt->wallet = w;
    /* A PENDING wallet cannot take block 1 through the step, so it starts
     * having read through height 1 (as after a completed boot catch-up). */
    if (!unreadable) w->best_block_height = 1;
    TP_CHECK("scan gap: block 1 advances the wallet",
             (unreadable ? tip_finalize_run_wallet_reconcile(&b1) : true) &&
             w->best_block_height == 1 && tp_gap_unmarked(w));
    tp_gap_evict_unreadable(&b2, unreadable);
    TP_CHECK("scan gap: the skipped block 2 reports not reconciled",
             !tip_finalize_run_wallet_reconcile(&b2));
    TP_CHECK("scan gap: the skip is recorded from block 2",
             w->best_block_height == 1 && w->scan_retry.pending &&
             w->scan_retry.from == 2);
    if (!unreadable &&
        !wallet_readiness_complete(w, true, 1))
        TP_CHECK("scan gap: wallet made READY again", false);
    (void)tip_finalize_run_wallet_reconcile(&b3);
    TP_CHECK("scan gap: block 3 is applied under a recorded gap from block 2",
             tp_gap_recorded(w));
    TP_CHECK("scan gap: balance replies do not trust memory at tip 3",
             wallet_scanned_through_height(w) < 3);
    /* Block 3 was applied over the hole, so a body of block 2 arriving after it
     * leaves a marker (no proof the range between was read in order); the
     * height is never lowered. */
    struct block_index b2late = tp_gap_index(src, 2, true);
    TP_CHECK("scan gap: the late body of block 2 reconciles",
             tip_finalize_run_wallet_reconcile(&b2late) &&
             w->best_block_height == 3 && wallet_scanned_through_height(w) == 1);
    TP_CHECK("scan gap: replaying block 3 keeps the wallet at 3",
             tip_finalize_run_wallet_reconcile(&b3) && w->best_block_height == 3);
    TP_CHECK("scan gap: the marker stays until a rescan reads the range",
             w->scan_retry.pending && wallet_scanned_through_height(w) == 1);
    rt->wallet = original;
    wallet_free(w);
    free(w);
    return failures;
}

/* The ordinary late body: block 2 is published before its body can be read
 * (or while the wallet is not READY), no later block has been applied, and
 * the next pass reads block 2 in order. The wallet has then read every
 * height with no hole, so the marker this mechanism set is gone and the
 * memory-trust height equals the tip. A marker of another owner stays. */
static int tp_gap_late_case(const struct block_index *src, const char *name,
                            bool unreadable, const char *foreign)
{
    int failures = 0;
    struct block_index b2 = tp_gap_index(src, 2, !unreadable);
    struct wallet *w = tp_gap_wallet_new(app_runtime_wallet(), !unreadable);
    TP_CHECK(name, w != NULL);
    if (!w) return failures;
    struct wallet *original = app_runtime_wallet();
    g_gap_rt->wallet = w;
    w->best_block_height = 1;
    if (foreign) {
        w->scan_retry.pending = true;
        w->scan_retry.from = 2;
        snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "%s",
                 foreign);
    }
    tp_gap_evict_unreadable(&b2, unreadable);
    TP_CHECK("late body: the skip leaves block 2 unread",
             !tip_finalize_run_wallet_reconcile(&b2) &&
             w->best_block_height == 1 && w->scan_retry.pending &&
             w->scan_retry.from == 2);
    if (!unreadable && !wallet_readiness_complete(w, true, 1))
        TP_CHECK("late body: wallet made READY again", false);
    struct block_index b2late = tp_gap_index(src, 2, true);
    TP_CHECK("late body: block 2 reconciles in order",
             tip_finalize_run_wallet_reconcile(&b2late) &&
             w->best_block_height == 2);
    if (foreign)
        TP_CHECK("late body: a marker of another owner is not cleared",
                 w->scan_retry.pending &&
                 strcmp(w->scan_retry.blocker, foreign) == 0 &&
                 wallet_scanned_through_height(w) == 1);
    else
        TP_CHECK("late body: no marker remains, scanned through the tip",
                 !w->scan_retry.pending && w->scan_retry.blocker[0] == 0 &&
                 wallet_scanned_through_height(w) == 2 &&
                 wallet_read_scanned_through_height(w) == w->best_block_height);
    g_gap_rt->wallet = original;
    wallet_free(w);
    free(w);
    return failures;
}

/* A replay never lowers the height; consecutive blocks advance unmarked. */
static int tp_gap_normal_case(const struct block_index *src)
{
    int failures = 0;
    struct wallet *w = tp_gap_wallet_new(app_runtime_wallet(), false);
    if (!w) { TP_CHECK("scan gap: normal-case wallet", false); return failures; }
    struct wallet *original = app_runtime_wallet();
    struct app_runtime_context *rt = g_gap_rt;
    rt->wallet = w;
    for (int h = 1; h <= 3; ++h) {
        struct block_index b = tp_gap_index(src, h, true);
        TP_CHECK("scan gap: consecutive block reconciles",
                 tip_finalize_run_wallet_reconcile(&b) &&
                 w->best_block_height == h && tp_gap_unmarked(w));
    }
    struct block_index again = tp_gap_index(src, 2, true);
    TP_CHECK("scan gap: replaying an older block keeps the height",
             tip_finalize_run_wallet_reconcile(&again) &&
             w->best_block_height == 3 && tp_gap_unmarked(w));
    struct block_index same = tp_gap_index(src, 3, true);
    TP_CHECK("scan gap: replaying the same block changes nothing",
             tip_finalize_run_wallet_reconcile(&same) &&
             w->best_block_height == 3 && tp_gap_unmarked(w));
    rt->wallet = original;
    wallet_free(w);
    free(w);
    return failures;
}

static int tp_scan_gap_probe(struct app_runtime_context *rt,
                            const struct block_index *src)
{
    int failures = 0;
    g_gap_rt = rt;
    failures += tp_gap_skip_case(src, "scan gap: unreadable-body wallet", true);
    failures += tp_gap_skip_case(src, "scan gap: PENDING-wallet wallet", false);
    failures += tp_gap_late_case(src, "late body: unreadable-body wallet", true, NULL);
    failures += tp_gap_late_case(src, "late body: PENDING-wallet wallet", false, NULL);
    failures += tp_gap_late_case(src, "late body: foreign marker wallet", true,
                                 "WALLET_CATCH_UP_DEFERRED");
    failures += tp_gap_normal_case(src);
    return failures;
}

#endif /* TIP_FINALIZE_SCAN_GAP_TEST_H */

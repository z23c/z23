/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_refold_body_span_contiguous — the from-anchor fold body-span gate
 * (engine/composition/src/boot_refold_staged.c: boot_refold_body_span_contiguous).
 *
 * The from-anchor cure replays on-disk block BODIES over
 * (anchor_height, resume_target]. A pruned/missing body in that span would
 * stall utxo_apply with no named blocker, so the gate verifies every body is
 * present (BLOCK_HAVE_DATA in the active-chain block_index) and, on a hole,
 * refuses and raises the named blocker refold.body_gap with the first missing
 * height.
 *
 *   (C1) a CONTIGUOUS span [anchor+1 .. tip] passes, no blocker raised;
 *   (C2) an empty span (resume_target <= anchor_height) passes trivially;
 *   (C3) a HOLE (one height missing BLOCK_HAVE_DATA) refuses, reports
 *        first_missing == the hole height, and raises refold.body_gap;
 *   (C4) a MISSING block_index slot (header gap) also refuses and names the
 *        first missing height;
 *   (C5) ms == NULL refuses;
 *   (C6) raise_blocker=false reports the gap without touching the blocker
 *        registry.
 *
 * Synthetic block_index: heights are inserted via chainstate_insert_block_index
 * and installed ascending with active_chain_install_tip_slot; a skipped
 * height is the hole. No datadir, no disk block bodies. */

#include "test/test_core.h"

#include "config/boot.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"
#include "core/uint256.h"
#include "util/blocker.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define BSC_CHECK(name, expr) do {                        \
    printf("  refold_body_span: %s... ", (name));          \
    if (expr) printf("OK\n");                              \
    else { printf("FAIL\n"); failures++; }                 \
} while (0)

#define BSC_ANCHOR 1000

static void bsc_hash_for(int h, struct uint256 *out)
{
    memset(out->data, 0, 32);
    out->data[0] = (uint8_t)(h & 0xFF);
    out->data[1] = (uint8_t)((h >> 8) & 0xFF);
    out->data[2] = (uint8_t)((h >> 16) & 0xFF);
    out->data[31] = 0xb5;
}

/* Insert a block_index slot at `height` into ms and install it as the active
 * tip (ascending installs accumulate lower slots). When have_data is true the
 * BLOCK_HAVE_DATA bit is set (a present body); when false the slot exists but
 * the body is absent (a cleared/pruned body). */
static bool bsc_install(struct main_state *ms, int height, bool have_data)
{
    struct uint256 h;
    bsc_hash_for(height, &h);
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, &h);
    if (!bi)
        return false;
    bi->nHeight = height;
    bi->nStatus = BLOCK_VALID_TREE | (have_data ? BLOCK_HAVE_DATA : 0);
    bi->nFile = have_data ? 0 : -1;
    bi->nDataPos = 0;
    return active_chain_install_tip_slot(&ms->chain_active, bi);
}

/* Install ascending block_index slots for every height in
 * [from_height .. to_height]. Every height gets a present body except
 * `hole_height`, whose body is marked absent; pass a height outside the
 * span (e.g. -1) for a fully present span. Returns true only when every
 * install succeeded (same short-circuit as the inline loops it replaces). */
static bool bsc_install_span_with_hole(struct main_state *ms, int from_height,
                                       int to_height, int hole_height)
{
    bool seeded = true;
    for (int h = from_height; h <= to_height; h++)
        seeded = seeded &&
                 bsc_install(ms, h, /*have_data=*/(h != hole_height));
    return seeded;
}

int test_refold_body_span_contiguous(void);
int test_refold_body_span_contiguous(void)
{
    test_reset_shared_globals();
    printf("\n=== refold_body_span_contiguous tests ===\n");
    int failures = 0;

    /* ── C1: a fully contiguous span [anchor+1 .. tip] passes. ───────────── */
    {
        struct main_state ms;
        main_state_init(&ms);
        bool seeded = bsc_install_span_with_hole(&ms, BSC_ANCHOR,
                                                 BSC_ANCHOR + 10, -1);
        BSC_CHECK("C1: synthetic contiguous chain installed", seeded);
        BSC_CHECK("C1: tip at anchor+10",
                  active_chain_height(&ms.chain_active) == BSC_ANCHOR + 10);

        int32_t first_missing = 99;
        bool ok = boot_refold_body_span_contiguous(
            &ms, BSC_ANCHOR, BSC_ANCHOR + 10, &first_missing, true);
        BSC_CHECK("C1: contiguous span PASSES", ok);
        BSC_CHECK("C1: first_missing reset to -1 on pass", first_missing == -1);
        BSC_CHECK("C1: no refold.body_gap blocker raised",
                  !blocker_exists("refold.body_gap"));

        main_state_free(&ms);
    }

    /* ── C2: an empty span (resume_target <= anchor) passes trivially. ───── */
    {
        struct main_state ms;
        main_state_init(&ms);
        (void)bsc_install(&ms, BSC_ANCHOR, true);
        int32_t fm = 99;
        bool ok = boot_refold_body_span_contiguous(
            &ms, BSC_ANCHOR, BSC_ANCHOR, &fm, true);
        BSC_CHECK("C2: empty span (target==anchor) PASSES", ok);
        bool ok2 = boot_refold_body_span_contiguous(
            &ms, BSC_ANCHOR, BSC_ANCHOR - 5, &fm, true);
        BSC_CHECK("C2: empty span (target<anchor) PASSES", ok2);
        main_state_free(&ms);
    }

    /* ── C3: a HOLE (cleared BLOCK_HAVE_DATA) REFUSES + raises the blocker. ─ */
    {
        blocker_reset_for_testing();
        struct main_state ms;
        main_state_init(&ms);
        const int hole = BSC_ANCHOR + 5;
        bool seeded = bsc_install_span_with_hole(&ms, BSC_ANCHOR,
                                                 BSC_ANCHOR + 10, hole);
        BSC_CHECK("C3: chain with one body hole installed", seeded);

        int32_t first_missing = -1;
        bool ok = boot_refold_body_span_contiguous(
            &ms, BSC_ANCHOR, BSC_ANCHOR + 10, &first_missing, true);
        BSC_CHECK("C3: span with a hole REFUSES (returns false)", !ok);
        BSC_CHECK("C3: first_missing == the hole height",
                  first_missing == hole);
        BSC_CHECK("C3: NAMED blocker refold.body_gap raised",
                  blocker_exists("refold.body_gap"));
        BSC_CHECK("C3: blocker class is DEPENDENCY",
                  blocker_class_for("refold.body_gap") == BLOCKER_DEPENDENCY);

        main_state_free(&ms);
        blocker_reset_for_testing();
    }

    /* ── C4: a MISSING slot (header gap) also REFUSES + names the height. ── */
    {
        blocker_reset_for_testing();
        struct main_state ms;
        main_state_init(&ms);
        /* Install anchor..anchor+3 contiguous, then JUMP to anchor+6 as the tip
         * — leaving anchor+4 / anchor+5 as NULL slots (no block_index). */
        bool seeded = bsc_install_span_with_hole(&ms, BSC_ANCHOR,
                                                 BSC_ANCHOR + 3, -1);
        seeded = seeded && bsc_install(&ms, BSC_ANCHOR + 6, true);
        BSC_CHECK("C4: chain with a header-slot gap installed", seeded);

        int32_t first_missing = -1;
        bool ok = boot_refold_body_span_contiguous(
            &ms, BSC_ANCHOR, BSC_ANCHOR + 6, &first_missing, true);
        BSC_CHECK("C4: span with a NULL slot REFUSES", !ok);
        BSC_CHECK("C4: first_missing == first NULL slot (anchor+4)",
                  first_missing == BSC_ANCHOR + 4);
        BSC_CHECK("C4: named blocker raised on a slot gap too",
                  blocker_exists("refold.body_gap"));
        main_state_free(&ms);
        blocker_reset_for_testing();
    }

    /* ── C5: ms == NULL refuses (no chain → cannot prove contiguity). ────── */
    {
        int32_t fm = -1;
        bool ok = boot_refold_body_span_contiguous(
            NULL, BSC_ANCHOR, BSC_ANCHOR + 5, &fm, false);
        BSC_CHECK("C5: ms==NULL REFUSES", !ok);
    }

    /* ── C6: raise_blocker=false reports the gap WITHOUT a blocker. ──────── */
    {
        blocker_reset_for_testing();
        struct main_state ms;
        main_state_init(&ms);
        const int hole = BSC_ANCHOR + 2;
        bool seeded = bsc_install_span_with_hole(&ms, BSC_ANCHOR,
                                                 BSC_ANCHOR + 4, hole);
        BSC_CHECK("C6: chain seeded", seeded);

        int32_t first_missing = -1;
        bool ok = boot_refold_body_span_contiguous(
            &ms, BSC_ANCHOR, BSC_ANCHOR + 4, &first_missing, false);
        BSC_CHECK("C6: gap detected (returns false)", !ok);
        BSC_CHECK("C6: first_missing reported", first_missing == hole);
        BSC_CHECK("C6: NO blocker raised when raise_blocker=false",
                  !blocker_exists("refold.body_gap"));
        main_state_free(&ms);
        blocker_reset_for_testing();
    }

    /* ── C7: LOCAL body rebind on a gap. ──────────────────────────────────
     * A gap triggers scan_block_files_mark_data ONCE, only when the rebind
     * datadir is set AND local blk*.dat exist. The scan over a dummy file
     * marks nothing, so the gap persists and the blocker is still raised;
     * this checks the gating, not the end-to-end rebind. */

    /* C7a: datadir set + a local blk00000.dat present → the rebind scan fires
     * exactly ONCE (once-per-process guard), even across two calls. */
    {
        boot_refold_body_rebind_reset_for_test();
        blocker_reset_for_testing();
        chain_params_select(CHAIN_REGTEST);   /* scan reads chain_params_get() */

        char root[256], blocksdir[400], blkpath[512];
        test_make_tmpdir(root, sizeof(root), "refold_rebind", "havefiles");
        snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", root);
        (void)mkdir(blocksdir, 0700);
        snprintf(blkpath, sizeof(blkpath), "%s/blk00000.dat", blocksdir);
        FILE *bf = fopen(blkpath, "wb");
        bool wrote = bf && fwrite("nomagic-dummy-body", 1, 18, bf) == 18;
        if (bf) fclose(bf);
        BSC_CHECK("C7a: dummy blk00000.dat staged", wrote);

        boot_refold_body_rebind_set_datadir(root);

        struct main_state ms;
        main_state_init(&ms);
        const int hole = BSC_ANCHOR + 3;
        bool seeded = bsc_install_span_with_hole(&ms, BSC_ANCHOR,
                                                 BSC_ANCHOR + 6, hole);
        BSC_CHECK("C7a: chain with a body hole installed", seeded);

        int32_t fm = -1;
        bool ok = boot_refold_body_span_contiguous(
            &ms, BSC_ANCHOR, BSC_ANCHOR + 6, &fm, true);
        BSC_CHECK("C7a: gap persists (dummy file has no real bodies)", !ok);
        BSC_CHECK("C7a: rebind scan FIRED once", // NOLINT
                  boot_refold_body_rebind_scan_attempts_for_test() == 1);
        BSC_CHECK("C7a: named blocker still raised (bodies genuinely absent)",
                  blocker_exists("refold.body_gap"));

        /* Second call: the once-per-process guard means NO second scan. */
        (void)boot_refold_body_span_contiguous(
            &ms, BSC_ANCHOR, BSC_ANCHOR + 6, &fm, true);
        BSC_CHECK("C7a: rebind scan NOT repeated (once-per-process guard)",
                  boot_refold_body_rebind_scan_attempts_for_test() == 1);

        main_state_free(&ms);
        test_rm_rf_recursive(root);
        boot_refold_body_rebind_reset_for_test();
        blocker_reset_for_testing();
    }

    /* C7b: datadir set but NO local block files → the files-exist gate blocks
     * the scan (attempts stays 0); the gap is still named. */
    {
        boot_refold_body_rebind_reset_for_test();
        blocker_reset_for_testing();
        char root[256];
        test_make_tmpdir(root, sizeof(root), "refold_rebind", "nofiles");
        boot_refold_body_rebind_set_datadir(root);   /* no blocks/ dir */

        struct main_state ms;
        main_state_init(&ms);
        bool seeded = bsc_install_span_with_hole(&ms, BSC_ANCHOR,
                                                 BSC_ANCHOR + 4,
                                                 BSC_ANCHOR + 2);
        BSC_CHECK("C7b: chain with a hole installed", seeded);

        int32_t fm = -1;
        bool ok = boot_refold_body_span_contiguous(
            &ms, BSC_ANCHOR, BSC_ANCHOR + 4, &fm, true);
        BSC_CHECK("C7b: gap named (returns false)", !ok);
        BSC_CHECK("C7b: rebind scan NOT attempted (no local block files)",
                  boot_refold_body_rebind_scan_attempts_for_test() == 0);
        BSC_CHECK("C7b: named blocker raised", blocker_exists("refold.body_gap"));

        main_state_free(&ms);
        test_rm_rf_recursive(root);
        boot_refold_body_rebind_reset_for_test();
        blocker_reset_for_testing();
    }

    /* C7c: default (rebind datadir UNSET) → the pre-existing behavior is
     * unchanged: a gap is named, the scan never runs. */
    {
        boot_refold_body_rebind_reset_for_test();   /* datadir unset */
        blocker_reset_for_testing();

        struct main_state ms;
        main_state_init(&ms);
        bool seeded = bsc_install_span_with_hole(&ms, BSC_ANCHOR,
                                                 BSC_ANCHOR + 4,
                                                 BSC_ANCHOR + 1);
        BSC_CHECK("C7c: chain with a hole installed", seeded);

        int32_t fm = -1;
        bool ok = boot_refold_body_span_contiguous(
            &ms, BSC_ANCHOR, BSC_ANCHOR + 4, &fm, true);
        BSC_CHECK("C7c: gap named (returns false)", !ok);
        BSC_CHECK("C7c: rebind scan NOT attempted (datadir unset — default)",
                  boot_refold_body_rebind_scan_attempts_for_test() == 0);
        BSC_CHECK("C7c: named blocker raised", blocker_exists("refold.body_gap"));

        main_state_free(&ms);
        boot_refold_body_rebind_reset_for_test();
        blocker_reset_for_testing();
    }

    return failures;
}

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the fail-loud validation pack check 1 + the HOLD latch
 * (core/modules/validation/src/chain_linkage_check.c):
 *
 *   - healthy +1 advance passes, no blocker (non-fire);
 *   - label splice (pprev height != h-1) REFUSES the move, registers
 *     chain.linkage_violation, latches the HOLD — process alive (the
 *     crash-only contract);
 *   - HOLD refuses moves at/past the divergence, allows rewinds below;
 *   - clear releases the hold + blocker, moves pass again;
 *   - depth-10 reorg (rewind + reconnect) never fires (non-fire);
 *   - genesis install and >+1 jumps are scoped out of pointer identity
 *     but the label check still applies (non-fire on healthy labels). */

#include "test/test_core.h"

#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "util/blocker.h"
#include "validation/chain_linkage_check.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdio.h>
#include <string.h>

#define CLC_CHECK(name, expr) do {                  \
    printf("chain_linkage_check: %s... ", (name));  \
    if (expr) printf("OK\n");                         \
    else { printf("FAIL\n"); failures++; }            \
} while (0)

static struct block_index *clc_insert(struct main_state *ms,
                                      struct uint256 *hash, int h,
                                      struct block_index *prev, uint8_t salt)
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
    pi->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
    pi->nTx = 1;
    arith_uint256_set_u64(&pi->nChainWork, (uint64_t)(h + 1));
    pi->pprev = prev;
    return pi;
}

int test_chain_linkage_check(void)
{
    test_reset_shared_globals();   /* monolith isolation: see test_helpers.c */
    printf("\n=== chain_linkage_check tests ===\n");
    int failures = 0;

    blocker_module_init();
    blocker_reset_for_testing();
    chain_linkage_reset_for_testing();

    /* 1. Healthy chain: genesis install + sequential +1 advances pass,
     * no blocker, no hold. */
    {
        struct main_state ms; main_state_init(&ms);
        static struct uint256 h[16];
        struct block_index *b[16];
        struct block_index *prev = NULL;
        bool ok = true;
        for (int i = 0; i < 12; i++) {
            b[i] = clc_insert(&ms, &h[i], i, prev, 0x11);
            ok = ok && b[i] != NULL;
            prev = b[i];
        }
        for (int i = 0; i < 12 && ok; i++)
            ok = active_chain_move_window_tip(&ms.chain_active, b[i]);
        ok = ok && !chain_linkage_hold_active();
        ok = ok && !blocker_exists("chain.linkage_violation");
        ok = ok && chain_linkage_violations_total() == 0;
        CLC_CHECK("healthy genesis + 11 sequential advances pass", ok);
        main_state_free(&ms);
    }

    /* 2. Label splice fires at block 1: a block whose pprev height label
     * is 7 below (the +6/+7 splice boundary shape) is REFUSED. */
    {
        chain_linkage_reset_for_testing();
        blocker_reset_for_testing();
        struct main_state ms; main_state_init(&ms);
        static struct uint256 h[16];
        struct block_index *b[16];
        struct block_index *prev = NULL;
        bool ok = true;
        for (int i = 0; i < 5; i++) {
            b[i] = clc_insert(&ms, &h[i], i, prev, 0x22);
            ok = ok && b[i] != NULL;
            prev = b[i];
        }
        for (int i = 0; i < 5 && ok; i++)
            ok = active_chain_move_window_tip(&ms.chain_active, b[i]);
        /* The spliced block: built on b[4] (h=4) but LABELED h=11. */
        b[5] = clc_insert(&ms, &h[5], 11, b[4], 0x22);
        ok = ok && b[5] != NULL;
        bool refused = !active_chain_move_window_tip(&ms.chain_active, b[5]);
        ok = ok && refused;
        ok = ok && chain_linkage_hold_active();
        ok = ok && chain_linkage_hold_refuse_from() == 11;
        ok = ok && blocker_exists("chain.linkage_violation");
        ok = ok && blocker_class_for("chain.linkage_violation") ==
                       BLOCKER_PERMANENT;
        ok = ok && chain_linkage_violations_total() == 1;
        /* Crash-only: window tip unchanged, process obviously alive. */
        ok = ok && active_chain_tip(&ms.chain_active) == b[4];
        CLC_CHECK("label splice refused at block 1 + HOLD + blocker", ok);

        /* 3. HOLD semantics on the same state: a rewind BELOW the
         * divergence passes; a healthy-looking move AT/PAST it refuses. */
        bool rewind_ok = active_chain_move_window_tip(&ms.chain_active, b[2]);
        uint64_t refusals_before = chain_linkage_hold_refusals_total();
        /* healthy-labeled block at 11 building correctly would still be
         * refused by the hold (refuse_from=11): build labels 3..11. */
        struct block_index *p = b[2];
        static struct uint256 h2[16];
        struct block_index *c = NULL;
        for (int i = 3; i <= 11; i++) {
            c = clc_insert(&ms, &h2[i], i, p, 0x33);
            p = c;
        }
        bool held = !active_chain_move_window_tip(&ms.chain_active, c);
        bool ok2 = rewind_ok && held &&
                   chain_linkage_hold_refusals_total() > refusals_before;
        CLC_CHECK("HOLD: rewind below passes, move at/past refuses", ok2);

        /* 4. Clear releases hold + blocker; the held move now passes. */
        chain_linkage_hold_clear("linkage");
        bool ok3 = !chain_linkage_hold_active() &&
                   !blocker_exists("chain.linkage_violation") &&
                   active_chain_move_window_tip(&ms.chain_active, c);
        CLC_CHECK("clear releases hold + blocker; move passes", ok3);
        main_state_free(&ms);
    }

    /* 5. Depth-10 reorg: rewind to the fork then reconnect a heavier
     * branch block-by-block — never fires (non-fire proof). */
    {
        chain_linkage_reset_for_testing();
        blocker_reset_for_testing();
        struct main_state ms; main_state_init(&ms);
        static struct uint256 h[40];
        struct block_index *a[20], *bb[20];
        struct block_index *prev = NULL;
        bool ok = true;
        for (int i = 0; i < 15; i++) {           /* branch A: 0..14 */
            a[i] = clc_insert(&ms, &h[i], i, prev, 0x44);
            ok = ok && a[i] != NULL;
            prev = a[i];
        }
        for (int i = 0; i < 15 && ok; i++)
            ok = active_chain_move_window_tip(&ms.chain_active, a[i]);
        /* branch B forks at height 4 (depth-10 reorg), extends to 16 */
        prev = a[4];
        for (int i = 5; i <= 16; i++) {
            bb[i] = clc_insert(&ms, &h[20 + i], i, prev, 0x55);
            ok = ok && bb[i] != NULL;
            prev = bb[i];
        }
        /* rewind to the fork point, then reconnect B one by one */
        ok = ok && active_chain_move_window_tip(&ms.chain_active, a[4]);
        for (int i = 5; i <= 16 && ok; i++)
            ok = active_chain_move_window_tip(&ms.chain_active, bb[i]);
        ok = ok && !chain_linkage_hold_active();
        ok = ok && !blocker_exists("chain.linkage_violation");
        ok = ok && active_chain_tip(&ms.chain_active) == bb[16];
        CLC_CHECK("depth-10 reorg rewind+reconnect never fires", ok);
        main_state_free(&ms);
    }

    /* 6. Cold-import shape: a jump far past the window (> +1) with
     * healthy labels passes (scoped out of pointer identity). */
    {
        chain_linkage_reset_for_testing();
        blocker_reset_for_testing();
        struct main_state ms; main_state_init(&ms);
        static struct uint256 h[40];
        struct block_index *prev = NULL, *bi = NULL;
        bool ok = true;
        for (int i = 0; i < 30; i++) {
            bi = clc_insert(&ms, &h[i], i, prev, 0x66);
            ok = ok && bi != NULL;
            prev = bi;
        }
        /* window empty (height -1): seed-jump straight to 29 */
        ok = ok && active_chain_move_window_tip(&ms.chain_active, bi);
        ok = ok && !chain_linkage_hold_active();
        ok = ok && !blocker_exists("chain.linkage_violation");
        CLC_CHECK("seed jump (> +1, healthy labels) passes", ok);
        main_state_free(&ms);
    }

    /* 7. +1 advance whose pprev is NOT the window tip object (a
     * single-move 1-block fork switch) is ALLOWED — fill_window rewrites
     * the window from the pprev walk — but COUNTED as a diagnostic.
     * Refusing it would false-HOLD routine network reorgs. */
    {
        chain_linkage_reset_for_testing();
        blocker_reset_for_testing();
        struct main_state ms; main_state_init(&ms);
        static struct uint256 h[8];
        struct block_index *b0, *b1, *b1x, *b2;
        b0 = clc_insert(&ms, &h[0], 0, NULL, 0x77);
        b1 = clc_insert(&ms, &h[1], 1, b0, 0x77);
        b1x = clc_insert(&ms, &h[2], 1, b0, 0x78); /* sibling at h=1 */
        bool ok = b0 && b1 && b1x;
        ok = ok && active_chain_move_window_tip(&ms.chain_active, b0);
        ok = ok && active_chain_move_window_tip(&ms.chain_active, b1);
        /* b2 builds on the SIBLING b1x, not the window tip b1 */
        b2 = clc_insert(&ms, &h[3], 2, b1x, 0x78);
        ok = ok && b2 != NULL;
        uint64_t before = chain_linkage_offtip_switches_total();
        ok = ok && active_chain_move_window_tip(&ms.chain_active, b2);
        ok = ok && chain_linkage_offtip_switches_total() == before + 1;
        ok = ok && !blocker_exists("chain.linkage_violation");
        ok = ok && !chain_linkage_hold_active();
        /* The window was rewritten onto the new branch. */
        ok = ok && active_chain_at(&ms.chain_active, 1) == b1x;
        ok = ok && active_chain_tip(&ms.chain_active) == b2;
        CLC_CHECK("+1 fork switch allowed + counted (no false HOLD)", ok);
        chain_linkage_reset_for_testing();
        blocker_reset_for_testing();
        main_state_free(&ms);
    }

    return failures;
}

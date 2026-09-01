/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * L2 LOCK-IN — ContextualCheckBlockHeader skipped >1000 below tip.
 *
 * Parity-audit round 2 (docs/work/parity-audit-round2-findings.md, L2):
 * process_block_should_skip_contextual_header() returns TRUE — i.e. the
 * incoming header SKIPS contextual_check_block_header() on the synchronous
 * path — whenever the active tip is past height 100000 AND the header's
 * parent sits more than 1000 blocks below that tip
 * (process_block_contextual_header.c:74-76, case (a)). zclassicd runs
 * ContextualCheckBlockHeader unconditionally in AcceptBlockHeader and again
 * in ConnectTip (main.cpp:4472, :3373-3388), so a contextually-invalid
 * header below tip-1000 (bad-diffbits / bad-equihash-solution-size /
 * time-too-old / bad-version / bad-fork-at-checkpoint) is consensus-gated
 * there but only background-rechecked here.
 *
 * THESE PINS ASSERT THE CURRENT (LOOSENED) BEHAVIOR so that a future
 * tightening (removing the skip, which the doc says is replay-gated) flips
 * them deliberately:
 *   - tip > 100001, parent < tip-1000              -> skip == true
 *   - tip > 100001, parent within 1000 of tip      -> skip == false
 *   - tip <= 100000 (the case (a) guard), far below -> skip == false
 *
 * Case (b) (the post-FlyClient sparse-window tail) is deliberately
 * NEUTRALIZED here by passing nPowAveragingWindow == 0, so the verdict is
 * driven only by case (a) — the loosening this pin freezes. The active-chain
 * height is supplied via a registered active_chain_authority so the result is
 * deterministic and independent of any open progress-store DB.
 */

#include "test/test_core.h"

#include "validation/process_block.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "consensus/params.h"
#include "chain/chain.h"

#include <stdio.h>
#include <string.h>

#define L2_CHECK(name, expr) do {                                  \
    printf("parity_lockin_contextual_header: %s... ", (name));     \
    if ((expr)) printf("OK\n");                                    \
    else { printf("FAIL\n"); failures++; }                         \
} while (0)

/* Deterministic active-chain height source: bypasses the progress-store DB
 * and c->height so the test verdict is reproducible regardless of test
 * ordering / open datadirs. */
static int64_t g_l2_auth_height = 0;
static int64_t l2_auth_get_height(void) { return g_l2_auth_height; }
static bool    l2_auth_is_authoritative(void) { return true; }

int test_parity_lockin_contextual_header(void)
{
    int failures = 0;

    test_reset_shared_globals();

    struct main_state ms;
    main_state_init(&ms);

    /* Case (b) neutralized: pow_window == 0 makes the predicate skip the
     * sparse-window walk entirely, so only case (a) decides the verdict. */
    struct consensus_params consensus;
    memset(&consensus, 0, sizeof(consensus));
    consensus.nPowAveragingWindow = 0;

    /* Register a height authority so active_chain_height() returns exactly
     * what we set, independent of any DB. */
    struct active_chain_authority auth = {
        .get_height = l2_auth_get_height,
        .get_hash = NULL,
        .is_authoritative = l2_auth_is_authoritative,
    };
    active_chain_register_authority(&auth);

    /* ---- PIN 1: tip > 100001, parent > 1000 below tip -> skip == true ---- */
    {
        g_l2_auth_height = 200000;  /* > 100000 */
        L2_CHECK("authority reports tip=200000",
                 active_chain_height(&ms.chain_active) == 200000);

        struct block_index prev;
        block_index_init(&prev);
        prev.nHeight = 150000;  /* 200000 - 150000 = 50000 > 1000 below tip */

        bool skip = process_block_should_skip_contextual_header(
                        &ms, &prev, &consensus);
        L2_CHECK("L2 PIN: tip=200000, parent=150000 (>1000 below) "
                 "-> contextual header SKIPPED today (true)",
                 skip == true);
    }

    /* ---- PIN 2: tip > 100001, parent within 1000 of tip -> skip == false -- */
    {
        g_l2_auth_height = 200000;

        struct block_index prev;
        block_index_init(&prev);
        prev.nHeight = 199500;  /* 200000 - 199500 = 500 <= 1000: within window */

        bool skip = process_block_should_skip_contextual_header(
                        &ms, &prev, &consensus);
        L2_CHECK("L2 PIN: tip=200000, parent=199500 (within 1000) "
                 "-> contextual header NOT skipped (false)",
                 skip == false);

        /* Exact boundary: parent == tip - 1000 is NOT strictly < tip-1000,
         * so it is within the window -> not skipped. */
        struct block_index edge;
        block_index_init(&edge);
        edge.nHeight = 200000 - 1000;  /* == tip-1000, boundary */
        bool skip_edge = process_block_should_skip_contextual_header(
                             &ms, &edge, &consensus);
        L2_CHECK("L2 PIN: parent == tip-1000 (boundary) -> NOT skipped (false)",
                 skip_edge == false);

        /* One below the boundary: parent == tip-1001 is strictly < tip-1000
         * -> skipped. */
        struct block_index below;
        block_index_init(&below);
        below.nHeight = 200000 - 1001;
        bool skip_below = process_block_should_skip_contextual_header(
                              &ms, &below, &consensus);
        L2_CHECK("L2 PIN: parent == tip-1001 (just past boundary) -> SKIPPED (true)",
                 skip_below == true);
    }

    /* ---- PIN 3: tip <= 100000 disables case (a) entirely -> skip == false -- */
    {
        g_l2_auth_height = 100000;  /* NOT > 100000 */
        L2_CHECK("authority reports tip=100000",
                 active_chain_height(&ms.chain_active) == 100000);

        struct block_index prev;
        block_index_init(&prev);
        prev.nHeight = 10;  /* far below, but tip-guard not crossed */

        bool skip = process_block_should_skip_contextual_header(
                        &ms, &prev, &consensus);
        L2_CHECK("L2 PIN: tip=100000 (<=100000 guard), parent far below "
                 "-> NOT skipped (false)",
                 skip == false);
    }

    /* ---- contract: NULL pindex_prev -> false ---- */
    {
        g_l2_auth_height = 200000;
        bool skip = process_block_should_skip_contextual_header(
                        &ms, NULL, &consensus);
        L2_CHECK("contract: NULL pindex_prev -> false", skip == false);
    }

    /* Restore globals for the sequential in-process runner. */
    active_chain_register_authority(&(struct active_chain_authority){0});
    main_state_free(&ms);
    test_reset_shared_globals();

    return failures;
}

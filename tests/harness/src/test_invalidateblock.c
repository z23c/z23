/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for process_block_invalidate / process_block_reconsider —
 * the operator recovery lever (Bitcoin Core invalidateblock /
 * reconsiderblock semantics).
 *
 * What is unit-testable here (pure, in-memory, no LevelDB / no live
 * activation controller):
 *
 *   (a) invalidate a tip block → it is marked BLOCK_FAILED_VALID and
 *       chain selection (find_most_work_chain) now picks the sibling
 *       fork instead. The "tip changes" outcome is observed through the
 *       canonical selector the production reorg path uses.
 *   (b) reconsiderblock → the failure marks are cleared and the original
 *       chain is selectable again.
 *   (c) invalidate a DEEPER block → the block AND its descendant subtree
 *       are marked failed (FAILED_VALID on the target, FAILED_CHILD on
 *       descendants), so the whole branch drops out of selection.
 *
 * The full disconnect-and-reorg of the *active* chain (which calls the
 * real disconnect_tip against coins/undo + LevelDB via the activation
 * controller) is an integration concern — exercised by test_reorg_safety
 * for the disconnect machinery and by `make deploy` + `z23 status` for the
 * end-to-end lever. Here we prove the mark/clear core + that the
 * canonical selector honors it, which is the consensus-relevant contract.
 *
 * Fixture style mirrors test_reorg_safety.c (synthetic block_index forks)
 * and test_process_block_revalidate.c (main_state + block_map_insert).
 */

#include "test/test_core.h"

#include "chain/chain.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/process_block.h"
#include "validation/process_block_invalidate.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IB_CHECK(name, expr) do { \
    printf("invalidateblock: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* find_most_work_chain is the canonical selector the reorg path uses; it
 * skips BLOCK_FAILED entries. Declared in process_block_core.c. */
struct block_index *find_most_work_chain(struct main_state *ms);

static int g_restore_hook_calls;
static bool g_restore_hook_context_ok;
static struct block_index *g_restore_hook_first;
static struct block_index *g_restore_hook_old_tip;
static enum process_block_mempool_segment_action g_restore_hook_action;

static bool fake_mempool_restore(
    void *ctx,
    struct block_index *first_disconnected,
    struct block_index *old_active_tip,
    enum process_block_mempool_segment_action action,
    struct process_block_mempool_restore_result *out)
{
    g_restore_hook_context_ok = ctx == &g_restore_hook_calls;
    g_restore_hook_calls++;
    g_restore_hook_first = first_disconnected;
    g_restore_hook_old_tip = old_active_tip;
    g_restore_hook_action = action;
    if (out) {
        out->blocks_read = 1;
        out->txs_attempted = 1;
        if (action == PROCESS_BLOCK_MEMPOOL_RESTORE_DISCONNECTED) {
            out->txs_accepted = 1;
            out->txs_relayed = 1;
        } else {
            out->txs_removed = 1;
        }
    }
    return true;
}

/* Build a heap block_index at `height` with `work`, owned hash from
 * `seed`, prev link `prev`, and clean (valid+have-data) status. Inserts
 * into the block_map. Returns the pindex. */
static struct block_index *mk_idx(struct main_state *ms, int height,
                                  uint64_t work, uint8_t seed,
                                  struct block_index *prev)
{
    struct block_index *bi = calloc(1, sizeof(*bi));
    struct uint256 *hp = malloc(sizeof(*hp));
    memset(hp, seed, sizeof(*hp));
    /* Make the height part of the hash so siblings at the same height
     * (different seeds) get distinct hashes. */
    hp->data[0] = (uint8_t)height;
    bi->nHeight = height;
    bi->phashBlock = hp;
    bi->pprev = prev;
    bi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    bi->nTx = 1;
    bi->nChainTx = prev ? prev->nChainTx + 1 : 1;
    arith_uint256_set_u64(&bi->nChainWork, work);
    block_map_insert(&ms->map_block_index, hp, bi);
    return bi;
}

static void free_idx(struct block_index *bi)
{
    if (!bi) return;
    free((void *)(uintptr_t)bi->phashBlock);
    free(bi);
}

int test_invalidateblock(void)
{
    printf("\n=== invalidateblock / reconsiderblock tests ===\n");
    int failures = 0;

    /* ── 1. Result-name mappings (stable strings for RPC/native/logs) ── */
    IB_CHECK("name(INVALIDATE_OK)",
             strcmp(invalidate_result_name(INVALIDATE_OK), "ok") == 0);
    IB_CHECK("name(INVALIDATE_BLOCK_NOT_FOUND)",
             strcmp(invalidate_result_name(INVALIDATE_BLOCK_NOT_FOUND),
                    "block_not_found") == 0);
    IB_CHECK("name(INVALIDATE_IS_GENESIS)",
             strcmp(invalidate_result_name(INVALIDATE_IS_GENESIS),
                    "is_genesis") == 0);
    IB_CHECK("name(INVALIDATE_DISCONNECT_FAIL)",
             strcmp(invalidate_result_name(INVALIDATE_DISCONNECT_FAIL),
                    "disconnect_failed") == 0);
    IB_CHECK("name(INVALIDATE_PERSIST_FAILED)",
             strcmp(invalidate_result_name(INVALIDATE_PERSIST_FAILED),
                    "persist_failed") == 0);
    IB_CHECK("name(RECONSIDER_OK)",
             strcmp(reconsider_result_name(RECONSIDER_OK), "ok") == 0);
    IB_CHECK("name(RECONSIDER_NO_FAILURE)",
             strcmp(reconsider_result_name(RECONSIDER_NO_FAILURE),
                    "no_failure") == 0);
    IB_CHECK("name(RECONSIDER_BLOCK_NOT_FOUND)",
             strcmp(reconsider_result_name(RECONSIDER_BLOCK_NOT_FOUND),
                    "block_not_found") == 0);

    /* ── 2. Bad-args + not-found paths ─────────────────────────────── */
    {
        struct uint256 h;
        memset(&h, 0xAB, sizeof(h));
        IB_CHECK("invalidate NULL ms → NOT_ATTEMPTED",
                 process_block_invalidate(NULL, &h, NULL) ==
                     INVALIDATE_NOT_ATTEMPTED);
        IB_CHECK("reconsider NULL ms → NOT_ATTEMPTED",
                 process_block_reconsider(NULL, &h, NULL) ==
                     RECONSIDER_NOT_ATTEMPTED);

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        IB_CHECK("invalidate unknown hash → BLOCK_NOT_FOUND",
                 process_block_invalidate(&ms, &h, NULL) ==
                     INVALIDATE_BLOCK_NOT_FOUND);
        IB_CHECK("reconsider unknown hash → BLOCK_NOT_FOUND",
                 process_block_reconsider(&ms, &h, NULL) ==
                     RECONSIDER_BLOCK_NOT_FOUND);
        main_state_free(&ms);
    }

    /* ── 3. Invalidate a tip block → selection picks the sibling ───── */
    /*
     *   genesis(0) → A1(1,w=10) → A2(2,w=20)        [chain A, the tip]
     *             ↘ B1(1,w=11) → B2(2,w=21)         [chain B, more work]
     *
     * With everything clean, find_most_work_chain picks B2. After we
     * invalidate B2 (the most-work tip), B2 + descendants drop out and
     * the selector falls back to A2.
     */
    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);

        struct block_index *g  = mk_idx(&ms, 0, 1,  0x00, NULL);
        struct block_index *a1 = mk_idx(&ms, 1, 10, 0x0A, g);
        struct block_index *a2 = mk_idx(&ms, 2, 20, 0x0B, a1);
        struct block_index *b1 = mk_idx(&ms, 1, 11, 0x1A, g);
        struct block_index *b2 = mk_idx(&ms, 2, 21, 0x1B, b1);

        /* Active tip = A2 (chain A). pindex_best_header = the
         * most-work header so selection is honest. */
        active_chain_move_window_tip(&ms.chain_active, g);
        active_chain_move_window_tip(&ms.chain_active, a1);
        active_chain_move_window_tip(&ms.chain_active, a2);
        ms.pindex_best_header = b2;

        IB_CHECK("pre-invalidate: selector picks B2 (most work)",
                 find_most_work_chain(&ms) == b2);

        /* Invalidate B2 (pure mark — no activation/coins needed). */
        size_t marked_children = 0;
        process_block_mark_invalid(&ms, b2, &marked_children);

        IB_CHECK("invalidate tip: B2 carries BLOCK_FAILED_VALID",
                 (b2->nStatus & BLOCK_FAILED_VALID) != 0);
        /* Core semantics: validity level is preserved (not lowered) so
         * reconsider restores selectability by clearing only FAILED. */
        IB_CHECK("invalidate tip: B2 keeps its validity level",
                 (b2->nStatus & BLOCK_VALID_MASK) != 0);
        /* B2 has no descendants → zero FAILED_CHILD marks. */
        IB_CHECK("invalidate tip: no descendants marked",
                 marked_children == 0);
        IB_CHECK("invalidate tip: selector now picks A2 (reorg target)",
                 find_most_work_chain(&ms) == a2);

        /* ── 4. reconsiderblock → B2 cleared, B2 selectable again ── */
        size_t cleared = 0;
        process_block_clear_invalid(&ms, b2, &cleared);
        IB_CHECK("reconsider: cleared count == 1 (just B2)",
                 cleared == 1);
        IB_CHECK("reconsider: B2 failure bits cleared",
                 (b2->nStatus & BLOCK_FAILED_ANY_MASK) == 0);
        IB_CHECK("reconsider: selector picks B2 again",
                 find_most_work_chain(&ms) == b2);

        free_idx(g); free_idx(a1); free_idx(a2);
        free_idx(b1); free_idx(b2);
        main_state_free(&ms);
    }

    /* ── 5. Invalidate a DEEPER block → whole subtree drops out ────── */
    /*
     *   genesis(0) → A1(1,w=10) → A2(2,w=20)              [chain A, tip]
     *             ↘ B1(1,w=11) → B2(2,w=21) → B3(3,w=31)  [chain B]
     *
     * Invalidate B1 (the fork root, deeper than the B tip). B1 gets
     * FAILED_VALID; B2 and B3 inherit FAILED_CHILD. Selection falls back
     * to A2 even though the B branch had more raw work.
     */
    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);

        struct block_index *g  = mk_idx(&ms, 0, 1,  0x00, NULL);
        struct block_index *a1 = mk_idx(&ms, 1, 10, 0x0A, g);
        struct block_index *a2 = mk_idx(&ms, 2, 20, 0x0B, a1);
        struct block_index *b1 = mk_idx(&ms, 1, 11, 0x1A, g);
        struct block_index *b2 = mk_idx(&ms, 2, 21, 0x1B, b1);
        struct block_index *b3 = mk_idx(&ms, 3, 31, 0x1C, b2);

        active_chain_move_window_tip(&ms.chain_active, g);
        active_chain_move_window_tip(&ms.chain_active, a1);
        active_chain_move_window_tip(&ms.chain_active, a2);
        ms.pindex_best_header = b3;

        IB_CHECK("deeper: pre-invalidate selector picks B3",
                 find_most_work_chain(&ms) == b3);

        size_t marked_children = 0;
        process_block_mark_invalid(&ms, b1, &marked_children);

        IB_CHECK("deeper: B1 carries FAILED_VALID",
                 (b1->nStatus & BLOCK_FAILED_VALID) != 0);
        IB_CHECK("deeper: B2 inherited FAILED_CHILD",
                 (b2->nStatus & BLOCK_FAILED_CHILD) != 0);
        IB_CHECK("deeper: B3 inherited FAILED_CHILD",
                 (b3->nStatus & BLOCK_FAILED_CHILD) != 0);
        IB_CHECK("deeper: 2 descendants marked",
                 marked_children == 2);
        IB_CHECK("deeper: A-chain untouched (A2 clean)",
                 (a2->nStatus & BLOCK_FAILED_ANY_MASK) == 0);
        IB_CHECK("deeper: selector falls back to A2",
                 find_most_work_chain(&ms) == a2);

        /* reconsider B1 clears the whole subtree (B1 + B2 + B3 = 3). */
        size_t cleared = 0;
        process_block_clear_invalid(&ms, b1, &cleared);
        IB_CHECK("deeper: reconsider clears B1+B2+B3 (3)",
                 cleared == 3);
        IB_CHECK("deeper: B3 failure bits cleared",
                 (b3->nStatus & BLOCK_FAILED_ANY_MASK) == 0);
        IB_CHECK("deeper: selector picks B3 again after reconsider",
                 find_most_work_chain(&ms) == b3);

        free_idx(g); free_idx(a1); free_idx(a2);
        free_idx(b1); free_idx(b2); free_idx(b3);
        main_state_free(&ms);
    }

    /* ── 6. reconsider on a clean block → NO_FAILURE no-op ─────────── */
    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        struct block_index *g  = mk_idx(&ms, 0, 1,  0x00, NULL);
        struct block_index *a1 = mk_idx(&ms, 1, 10, 0x0A, g);

        size_t cleared = 0;
        process_block_clear_invalid(&ms, a1, &cleared);
        IB_CHECK("reconsider clean block: nothing cleared", cleared == 0);

        free_idx(g); free_idx(a1);
        main_state_free(&ms);
    }

    /* ── 7. Hash identity: duplicate active object still disconnects ──
     *
     * Snapshot seeding and header ingestion may retain distinct block_index
     * objects for the same block hash. The block map resolves `target`, while
     * the active-chain slot contains `active_twin`. invalidateblock is
     * hash-addressed and must retreat through the active object's parent;
     * pointer-only containment leaves a FAILED active tip published while
     * reporting success (physical matrix regression, 2026-08-14). */
    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);

        struct block_index *g = mk_idx(&ms, 0, 1, 0x00, NULL);
        struct block_index *target = mk_idx(&ms, 1, 10, 0x0A, g);
        struct block_index active_twin = *target;
        active_twin.hashBlock = *target->phashBlock;
        active_twin.phashBlock = &active_twin.hashBlock;
        active_twin.pprev = g;
        ms.pindex_best_header = &active_twin;

        active_chain_move_window_tip(&ms.chain_active, g);
        active_chain_move_window_tip(&ms.chain_active, &active_twin);
        IB_CHECK("same-hash fixture: pointer containment differs",
                 !active_chain_contains(&ms.chain_active, target));
        IB_CHECK("same-hash fixture: active and target hashes agree",
                 uint256_eq(active_twin.phashBlock, target->phashBlock));

        size_t marked_children = 0;
        process_block_mark_invalid(&ms, target, &marked_children);
        IB_CHECK("same-hash active object: live twin is marked failed",
                 (active_twin.nStatus & BLOCK_FAILED_VALID) != 0);
        bool disconnected = process_block_disconnect_to_parent(
            NULL, &ms, NULL, NULL, target, NULL);
        IB_CHECK("same-hash active object: disconnect succeeds",
                 disconnected);
        IB_CHECK("same-hash active object: tip retreats to parent",
                 active_chain_height(&ms.chain_active) == 0 &&
                 active_chain_tip(&ms.chain_active) == g);
        size_t cleared = 0;
        process_block_clear_invalid(&ms, target, &cleared);
        IB_CHECK("same-hash active object: reconsider clears live twin",
                 (active_twin.nStatus & BLOCK_FAILED_ANY_MASK) == 0);

        free_idx(g); free_idx(target);
        main_state_free(&ms);
    }

    /* ── 8. Full operator path dispatches post-unwind mempool restore ── */
    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        struct block_index *g = mk_idx(&ms, 0, 1, 0x00, NULL);
        struct block_index *tip = mk_idx(&ms, 1, 10, 0x0A, g);
        active_chain_move_window_tip(&ms.chain_active, tip);
        ms.pindex_best_header = tip;

        g_restore_hook_calls = 0;
        g_restore_hook_context_ok = false;
        g_restore_hook_first = NULL;
        g_restore_hook_old_tip = NULL;
        process_block_set_mempool_restore_hook(fake_mempool_restore,
                                                &g_restore_hook_calls);
        IB_CHECK("mempool hook: full invalidate succeeds",
                 process_block_invalidate(&ms, tip->phashBlock, NULL) ==
                     INVALIDATE_OK);
        IB_CHECK("mempool hook: called exactly once after active disconnect",
                 g_restore_hook_calls == 1);
        IB_CHECK("mempool hook: context survives dispatch",
                 g_restore_hook_context_ok);
        IB_CHECK("mempool hook: exact disconnected segment named",
                 g_restore_hook_first == tip && g_restore_hook_old_tip == tip);
        IB_CHECK("mempool hook: invalidate requests restore action",
                 g_restore_hook_action ==
                     PROCESS_BLOCK_MEMPOOL_RESTORE_DISCONNECTED);
        IB_CHECK("mempool hook: failed ancestry retracts best header",
                 ms.pindex_best_header == g);
        /* Production's reducer reconnect repopulates the raw window before the
         * reconsider-side exact-block mempool reconciliation. Mirror that
         * post-reducer observation in this controller-free unit fixture. */
        IB_CHECK("mempool hook: model reducer reconnect window",
                 active_chain_move_window_tip(&ms.chain_active, tip));
        IB_CHECK("mempool hook: reconsider succeeds",
                 process_block_reconsider(&ms, tip->phashBlock, NULL) ==
                     RECONSIDER_OK);
        IB_CHECK("mempool hook: reconsider dispatches second action",
                 g_restore_hook_calls == 2 &&
                     g_restore_hook_action ==
                         PROCESS_BLOCK_MEMPOOL_REMOVE_RECONNECTED);
        IB_CHECK("mempool hook: reconnected segment named exactly",
                 g_restore_hook_first == tip && g_restore_hook_old_tip == tip);
        IB_CHECK("mempool hook: reconsider rebuilds best header",
                 ms.pindex_best_header == tip);
        process_block_set_mempool_restore_hook(NULL, NULL);

        free_idx(g); free_idx(tip);
        main_state_free(&ms);
    }

    /* ── 9. Canonical tip FLOOR: refuse a below-tip higher-work fork ──
     *
     * The exact never-stuck wound (process_block_core.c:106-120): a
     * stale-import fork tip at a LOWER height but HIGHER nChainWork (bad
     * work accounting from old LDB data) must NOT trigger a backwards
     * reorg. find_most_work_chain returns the active TIP instead — else
     * the chain reorgs backward, the staged activation finality guard
     * logs below_finality_depth forever, and the node wedges. The floor
     * is DIRECTIONAL: a higher-work fork ABOVE the tip is still selected
     * (a legitimate forward reorg). Both directions are asserted so a
     * regression to either a blanket refusal or no floor at all fails.
     */
    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);

        /* Active chain to tip A4 (height 4, work 40). */
        struct block_index *g  = mk_idx(&ms, 0, 1,  0x00, NULL);
        struct block_index *a1 = mk_idx(&ms, 1, 10, 0x0A, g);
        struct block_index *a2 = mk_idx(&ms, 2, 20, 0x0B, a1);
        struct block_index *a3 = mk_idx(&ms, 3, 30, 0x0C, a2);
        struct block_index *a4 = mk_idx(&ms, 4, 40, 0x0D, a3);
        /* Stale-import fork tip: height 1 (BELOW tip h=4) but work 99
         * (ABOVE tip work 40) — the pathological backwards candidate. */
        struct block_index *s1 = mk_idx(&ms, 1, 99, 0x5A, g);

        active_chain_move_window_tip(&ms.chain_active, g);
        active_chain_move_window_tip(&ms.chain_active, a1);
        active_chain_move_window_tip(&ms.chain_active, a2);
        active_chain_move_window_tip(&ms.chain_active, a3);
        active_chain_move_window_tip(&ms.chain_active, a4);
        ms.pindex_best_header = s1; /* the import thinks s1 is "best" */

        /* s1 has the max nChainWork, so without the floor the selector
         * would pick it and reorg backward 3 blocks. The floor must
         * return the tip a4 instead. */
        IB_CHECK("floor: below-tip higher-work fork → selector returns TIP",
                 find_most_work_chain(&ms) == a4);
        IB_CHECK("floor: below-tip fork s1 is NOT selected",
                 find_most_work_chain(&ms) != s1);

        free_idx(g); free_idx(a1); free_idx(a2);
        free_idx(a3); free_idx(a4); free_idx(s1);
        main_state_free(&ms);
    }
    {
        /* Directional check: a higher-work fork ABOVE the tip IS selected
         * (the floor only blocks BACKWARD reorgs, not forward ones).
         *   genesis → A1 → A2                 [active tip A2, h=2]
         *          ↘ D1 → D2 → D3             [fork, h=3, more work]
         */
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);

        struct block_index *g  = mk_idx(&ms, 0, 1,  0x00, NULL);
        struct block_index *a1 = mk_idx(&ms, 1, 10, 0x0A, g);
        struct block_index *a2 = mk_idx(&ms, 2, 20, 0x0B, a1);
        struct block_index *d1 = mk_idx(&ms, 1, 11, 0x2A, g);
        struct block_index *d2 = mk_idx(&ms, 2, 21, 0x2B, d1);
        struct block_index *d3 = mk_idx(&ms, 3, 31, 0x2C, d2);

        active_chain_move_window_tip(&ms.chain_active, g);
        active_chain_move_window_tip(&ms.chain_active, a1);
        active_chain_move_window_tip(&ms.chain_active, a2);
        ms.pindex_best_header = d3;

        IB_CHECK("floor: above-tip higher-work fork IS selected (forward reorg)",
                 find_most_work_chain(&ms) == d3);

        free_idx(g); free_idx(a1); free_idx(a2);
        free_idx(d1); free_idx(d2); free_idx(d3);
        main_state_free(&ms);
    }

    printf("invalidateblock: %d failures\n", failures);
    return failures;
}

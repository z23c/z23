/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test: "torn block-index wedges tip promotion".
 *
 * PINS the live failure class observed on build e2a4d75e3:
 *
 *   - The coins/UTXO tip is at height N (consistent:
 *     coins_best_block_hash == active_tip_hash).
 *   - The block_index sqlite projection / chain_evidence is BEHIND at
 *     N-k: a small gap of blocks above the projection cursor have NOT
 *     had nChainTx / nChainWork propagated, so find_most_work_chain
 *     does NOT select N+1 as best-work.
 *   - process_block therefore cannot stamp nakamoto_selected_best_work
 *     on the N+1 evidence record. chain_evidence_controller_promote_tip
 *     rejects with CEC_REJECTED_INCOMPLETE_INDEX_EVIDENCE
 *     ("nakamoto=0") and stays in state=tip_following, retrying forever.
 *     The block body for N+1 is on disk and connect_block would succeed,
 *     but the tip never advances.
 *
 * REAL GATE asserted (not a guess):
 *   - chain_evidence_record_has_block_index_required()
 *       engine/services/src/chain_evidence_controller.c:71-80
 *     (requires nakamoto_selected_best_work, among others)
 *   - chain_evidence_controller_promote_tip() returning
 *     CEC_REJECTED_INCOMPLETE_INDEX_EVIDENCE at
 *       engine/services/src/chain_evidence_controller.c:492
 *     while leaving authority->state == CEC_TIP_FOLLOWING.
 *
 * Mirrors the fixture style of test_chain_evidence_controller.c
 * (auth_fixture: in-memory node_db + block_map + active_chain +
 * coins_view_cache + csr + authority over 3 blocks at heights 0,1,2).
 */

#include "test/test_core.h"

#include "services/chain_evidence_authority_service.h"
#include "validation/process_block.h"
#include "validation/main_state.h"
#include "chain/chain.h"
#include "coins/coins_view.h"
#include "models/database.h"

#include <stdio.h>
#include <string.h>

struct torn_fixture {
    struct node_db ndb;
    struct block_map bm;
    struct active_chain chain;
    struct block_index *header_tip;
    struct coins_view_cache coins_tip;
    struct chain_state_repository csr;
    struct chain_evidence_controller authority;
    struct uint256 hashes[3];
    struct block_index blocks[3];
};

static bool torn_fixture_init(struct torn_fixture *f)
{
    memset(f, 0, sizeof(*f));
    if (!node_db_open(&f->ndb, ":memory:"))
        return false;
    block_map_init(&f->bm);
    active_chain_init(&f->chain);

    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    coins_view_cache_init(&f->coins_tip, &null_view);

    for (int i = 0; i < 3; i++) {
        memset(f->hashes[i].data, i + 1, 32);
        block_index_init(&f->blocks[i]);
        f->blocks[i].phashBlock = &f->hashes[i];
        f->blocks[i].nHeight = i;
        f->blocks[i].pprev = i ? &f->blocks[i - 1] : NULL;
        f->blocks[i].nStatus = BLOCK_VALID_TREE;
        arith_uint256_set_u64(&f->blocks[i].nChainWork, (uint64_t)i + 1);
        block_map_insert(&f->bm, &f->hashes[i], &f->blocks[i]);
        const struct block_index *canon =
            block_map_find(&f->bm, &f->hashes[i]);
        if (canon)
            f->blocks[i].phashBlock = canon->phashBlock;
    }

    csr_init(&f->csr, &f->bm, &f->chain, &f->header_tip,
             &f->coins_tip, &f->ndb, NULL);
    chain_evidence_controller_init(&f->authority, &f->ndb, &f->csr);
    return true;
}

static void torn_fixture_free(struct torn_fixture *f)
{
    csr_free(&f->csr);
    coins_view_cache_free(&f->coins_tip);
    active_chain_free(&f->chain);
    block_map_free(&f->bm);
    node_db_close(&f->ndb);
}

/* Drive the fixture into the live symptom and PIN it:
 *
 * 1. Active tip + coins cursor at height 1 (N), fully consistent.
 * 2. Block 2 (N+1) is the would-be next tip: body is on disk
 *    (BLOCK_HAVE_DATA set, connect_block would succeed) but the
 *    block_index work-link is TORN above the projection cursor —
 *    nChainTx==0 and work not propagated — so find_most_work_chain
 *    would NOT select it as best-work.
 * 3. The N+1 tip request therefore carries a verified record with
 *    nakamoto_selected_best_work == false (the caller could not stamp
 *    it). Assert:
 *      (a) chain_evidence_record_has_block_index_required() is NOT-READY
 *          for that record (the REAL completeness predicate), and
 *      (b) promote_tip rejects with CEC_REJECTED_INCOMPLETE_INDEX_EVIDENCE
 *          and STAYS in CEC_TIP_FOLLOWING (retry-forever symptom),
 *          and the active tip does NOT advance past N.
 */
static int test_torn_index_wedges_tip_promotion(void)
{
    int failures = 0;
    struct torn_fixture f;
    if (!torn_fixture_init(&f))
        return 1;

    /* --- Step 1: establish a consistent, fully-evidenced tip at height 1
     * (N) via a normal promotion. This is what puts the controller into
     * state=tip_following — the state the live node was wedged in. --- */
    struct chain_evidence_record n_evidence = {
        .source_class = CEC_SOURCE_CLASS_NATIVE_P2P,
        .publish_state = CEC_PUBLISH_LOCAL_EVIDENCE,
        .header_ancestry_linked = true,
        .chainwork_recomputed = true,
        .nakamoto_selected_best_work = true,
        .block_bytes_hash_checked = true,
    };
    struct chain_evidence_controller_tip_request seed_req = {
        .new_tip = &f.blocks[1],
        .utxo_max_height = 1,
        .update_header_tip = true,
        .reason = "unit.torn_index_seed",
        .verified = n_evidence,
    };
    if (chain_evidence_controller_promote_tip(&f.authority, &seed_req)
        != CEC_OK)
        failures++;
    if (f.authority.state != CEC_TIP_FOLLOWING)
        failures++;
    if (active_chain_height(&f.chain) != 1)
        failures++;

    /* --- Step 2: torn N+1 (block 2): body on disk, work-link torn. --- */
    f.blocks[2].nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
    f.blocks[2].nChainTx = 0;                       /* not work-propagated */
    arith_uint256_set_zero(&f.blocks[2].nChainWork);/* above proj. cursor  */

    /* --- Step 3a: the REAL completeness predicate is NOT-READY. ---
     * This is the gate chain_evidence_controller_promote_tip consults at
     * chain_evidence_controller.c:475. With nakamoto_selected_best_work
     * unset (find_most_work_chain did not select the torn N+1), the
     * record is incomplete. */
    struct chain_evidence_record torn = {
        .source_class = CEC_SOURCE_CLASS_NATIVE_P2P,
        .publish_state = CEC_PUBLISH_LOCAL_EVIDENCE,
        .header_ancestry_linked = true,    /* ancestry=1 (live: =1) */
        .chainwork_recomputed = true,      /* work=1     (live: =1) */
        .block_bytes_hash_checked = true,  /* bytes=1    (live: =1) */
        .nakamoto_selected_best_work = false, /* nakamoto=0 — the wedge */
    };
    if (chain_evidence_record_has_block_index_required(&torn))
        failures++; /* predicate must report NOT-READY for the torn record */

    /* --- Step 3b: promote_tip rejects + stays tip_following + no advance. */
    struct chain_evidence_controller_tip_request req = {
        .new_tip = &f.blocks[2],
        .utxo_max_height = 1,   /* coins still at N; never ahead of index */
        .update_header_tip = true,
        .reason = "unit.torn_index_promote",
        .verified = torn,
    };
    enum chain_evidence_controller_result r =
        chain_evidence_controller_promote_tip(&f.authority, &req);
    if (r != CEC_REJECTED_INCOMPLETE_INDEX_EVIDENCE)
        failures++;
    /* The retry-forever symptom: NOT frozen, stays tip_following. */
    if (f.authority.state != CEC_TIP_FOLLOWING)
        failures++;
    /* The tip MUST NOT have advanced past N (height 1). */
    if (active_chain_height(&f.chain) != 1)
        failures++;
    if (f.header_tip != &f.blocks[1])
        failures++;

    /* =====================================================================
     * PENDING REPAIR (separate slice). When a future fix relinks the torn
     * block-index so find_most_work_chain selects N+1, the SAME predicate
     * and promotion path must FLIP to READY and the tip must advance to
     * N+1. We assert that flip HERE so the repair is provable and the
     * class cannot silently regress.
     *
     * The repair's observable effect at this seam is exactly one flag:
     * once the work-link is propagated, the caller can stamp
     * nakamoto_selected_best_work. We model the post-relink record and
     * assert the gate opens. (The repair that produces this stamping in
     * production — work/nChainTx propagation above the projection cursor —
     * is a separate slice; this pins the gate it must satisfy.)
     * ===================================================================== */
    struct chain_evidence_record relinked = torn;
    relinked.nakamoto_selected_best_work = true; /* find_most_work_chain N+1 */
    if (!chain_evidence_record_has_block_index_required(&relinked))
        failures++; /* after relink, the completeness predicate is READY */

    /* And the promotion now succeeds, advancing the tip to N+1. */
    /* Reflect the relinked work into the block_index so csr accepts it. */
    f.blocks[2].nChainTx = 1;
    arith_uint256_set_u64(&f.blocks[2].nChainWork, 3);
    struct chain_evidence_controller_tip_request relink_req = {
        .new_tip = &f.blocks[2],
        .utxo_max_height = 1,
        .update_header_tip = true,
        .reason = "unit.torn_index_relinked",
        .verified = relinked,
    };
    enum chain_evidence_controller_result r2 =
        chain_evidence_controller_promote_tip(&f.authority, &relink_req);
    if (r2 != CEC_OK)
        failures++;
    if (active_chain_height(&f.chain) != 2)
        failures++;
    if (f.header_tip != &f.blocks[2])
        failures++;
    if (f.authority.state != CEC_TIP_FOLLOWING)
        failures++;

    torn_fixture_free(&f);
    return failures;
}

/* =========================================================================
 * Predicate-level proof of the FIX (consensus path).
 *
 * Exercises the REAL process_block_tip_is_best_work predicate (via the
 * ZCL_TESTING hook process_block_test_tip_is_best_work) — the exact
 * function that computes nakamoto_selected_best_work and whose false
 * negative wedged the live tip at 3125314.
 *
 * Two cases, both over the SAME map_block_index, against tip at height 2:
 *
 *   CASE A — torn/stale non-ancestor fork above tip (the wedge):
 *     a fork entry at height 4 with HAVE_DATA + higher nChainWork than the
 *     tip but UNLINKED pprev (block_index_get_ancestor → NULL). Before the
 *     fix this returned NOT-best-work forever; after the fix the predicate
 *     is READY (true) because a torn fork is not a connectable competitor.
 *
 *   CASE B — guard: a GENUINE higher-work, fully-downloaded, fully-LINKED
 *     competing fork that branches at height 2 (sibling of the tip). Its
 *     ancestry resolves to a real block != tip at tip->nHeight, so the
 *     predicate MUST still return NOT-best-work (false) — the reorg is
 *     correctly detected and promotion is correctly withheld.
 *
 * Together these prove the fix removes the false negative WITHOUT masking a
 * real reorg.
 * ========================================================================= */
static int test_tip_is_best_work_predicate(void)
{
    int failures = 0;

    /* Linked main chain: 0 <- 1 <- 2 (tip at height 2). */
    struct uint256 h[3];
    struct block_index main_blk[3];
    struct main_state ms;
    main_state_init(&ms);

    for (int i = 0; i < 3; i++) {
        memset(h[i].data, i + 1, 32);
        block_index_init(&main_blk[i]);
        main_blk[i].phashBlock = &h[i];
        main_blk[i].nHeight = i;
        main_blk[i].pprev = i ? &main_blk[i - 1] : NULL;
        main_blk[i].nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
        arith_uint256_set_u64(&main_blk[i].nChainWork, (uint64_t)(i + 1));
        block_map_insert(&ms.map_block_index, &h[i], &main_blk[i]);
    }
    struct block_index *tip = &main_blk[2];

    /* Baseline: with only the linked main chain, the tip is best work. */
    if (!process_block_test_tip_is_best_work(&ms, tip))
        failures++;

    /* --- CASE A: torn/stale non-ancestor fork above tip. ---
     * height 4, HAVE_DATA, higher work, but pprev UNLINKED (orphan/torn),
     * exactly the ~4,600 stale entries recompute_index stamped work onto.
     * block_index_get_ancestor(torn, 2) walks pprev, hits NULL → returns
     * NULL. The fixed predicate must NOT treat this as a competing chain. */
    struct uint256 torn_hash;
    struct block_index torn_fork;
    memset(torn_hash.data, 0x90, 32);
    block_index_init(&torn_fork);
    torn_fork.phashBlock = &torn_hash;
    torn_fork.nHeight = 4;
    torn_fork.pprev = NULL;                 /* TORN: ancestry unresolvable */
    torn_fork.nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
    arith_uint256_set_u64(&torn_fork.nChainWork, 99); /* > tip work (3) */
    block_map_insert(&ms.map_block_index, &torn_hash, &torn_fork);

    /* Sanity: the ancestry really is unresolvable to tip height. */
    if (block_index_get_ancestor(&torn_fork, tip->nHeight) != NULL)
        failures++;
    /* THE FIX: torn fork above tip does NOT veto promotion. */
    if (!process_block_test_tip_is_best_work(&ms, tip))
        failures++;

    /* --- CASE B: genuine higher-work, fully-linked competing fork. ---
     * Branch a sibling at height 2 off the same parent (main_blk[1]) and a
     * child at height 3 with higher work than the tip. fork3's ancestry at
     * height 2 resolves to fork2 (a real block != tip) → MUST still report
     * NOT-best-work so the reorg is detected. */
    struct uint256 fh[2];          /* fork heights 2 and 3 */
    struct block_index fork_blk[2];
    memset(fh[0].data, 0xA2, 32);
    memset(fh[1].data, 0xA3, 32);
    block_index_init(&fork_blk[0]);
    block_index_init(&fork_blk[1]);
    fork_blk[0].phashBlock = &fh[0];
    fork_blk[0].nHeight = 2;
    fork_blk[0].pprev = &main_blk[1];        /* sibling of the tip */
    fork_blk[0].nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
    arith_uint256_set_u64(&fork_blk[0].nChainWork, 3);
    fork_blk[1].phashBlock = &fh[1];
    fork_blk[1].nHeight = 3;
    fork_blk[1].pprev = &fork_blk[0];
    fork_blk[1].nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
    arith_uint256_set_u64(&fork_blk[1].nChainWork, 50); /* > tip work (3) */
    block_map_insert(&ms.map_block_index, &fh[0], &fork_blk[0]);
    block_map_insert(&ms.map_block_index, &fh[1], &fork_blk[1]);

    /* Sanity: the genuine fork's ancestry resolves to a real, non-tip
     * block at tip height. */
    struct block_index *fanc = block_index_get_ancestor(&fork_blk[1],
                                                        tip->nHeight);
    if (fanc != &fork_blk[0] || fanc == tip)
        failures++;
    /* REORG STILL DETECTED: a genuine connectable higher-work fork makes
     * the tip NOT best-work, so promotion is correctly withheld. */
    if (process_block_test_tip_is_best_work(&ms, tip))
        failures++;

    main_state_free(&ms);
    return failures;
}

int test_torn_index_blocks_tip(void)
{
    int failures = 0;
    failures += test_torn_index_wedges_tip_promotion();
    failures += test_tip_is_best_work_predicate();
    return failures;
}

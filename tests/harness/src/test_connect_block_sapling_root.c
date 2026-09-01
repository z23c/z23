/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pins the DEFAULT-OFF Sapling-root parity enforcement in
 * core/modules/validation/src/connect_block.c (project_sapling_root_parity_hole).
 *
 * Background. zclassic23 historically rejected ONLY an all-zeros
 * hashFinalSaplingRoot post-Sapling-activation ("bad-sapling-root-zeroed").
 * zclassicd rejects ANY mismatch between the block's hashFinalSaplingRoot
 * and the recomputed Sapling commitment-tree root — so zclassic23 was too
 * LENIENT (a latent fork hole: it would accept a wrong NON-ZERO root).
 *
 * The fix adds a PURE recompute predicate (sapling_root_matches) and an
 * additional reject ("bad-sapling-root-mismatch"), gated behind the
 * DEFAULT-OFF runtime flag g_enforce_sapling_root (-enforce-sapling-root).
 *
 * This test pins all three behaviors at a Sapling-ACTIVE,
 * checkpoint-covered height (expensive_checks=false → PoW + parallel script
 * verification skipped, so the Sapling-root branch is reached directly):
 *
 *   1. Flag OFF (DEFAULT) + a deliberately-WRONG non-zero root → ACCEPTS.
 *      This is the byte-identical-to-today guarantee: default behavior is
 *      unchanged; only the all-zeros reject fires by default.
 *   2. Flag ON  + the CORRECT recomputed root                  → ACCEPTS.
 *   3. Flag ON  + a deliberately-WRONG non-zero root           → REJECTS
 *      with reason "bad-sapling-root-mismatch".
 *
 * Plus a direct unit test of the pure predicate's NULL-frontier contract
 * (cannot-decide → do-not-reject), which is why enabling the flag without a
 * wired frontier can never false-reject.
 *
 * To keep the recompute tractable the test wires a depth-4 Sapling testing
 * tree via connect_block_set_sapling_tree(); the block carries zero shielded
 * outputs, so the post-block root equals the pre-block tree's root, which we
 * compute and use as the "correct" header root.
 */

#include "test/test_core.h"

#include "validation/connect_block.h"
#include "validation/contextual_check_tx.h"
#include "coins/coins_view.h"
#include "coins/coins.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sapling/incremental_merkle_tree.h"
#include "bloom/merkle.h"
#include "core/uint256.h"
#include "core/arith_uint256.h"
#include "script/script.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <string.h>
#include <stdatomic.h>

#define SR_CHECK(name, expr) do {          \
    printf("%s... ", (name));              \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Mainnet Sapling activates at height 476969 (chainparams.c). Use a height
 * above it so consensus_network_upgrade_active(UPGRADE_SAPLING) is true. */
#define SR_HEIGHT 480000

/* A coinbase with one tiny output (well under any subsidy + fees). */
static struct transaction sr_make_coinbase(int height)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 4;            /* Sapling-era tx version */
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "sr_cb_vin");
    uint8_t sig[6] = { 4,
                       (uint8_t)(height & 0xFF),
                       (uint8_t)((height >> 8) & 0xFF),
                       (uint8_t)((height >> 16) & 0xFF),
                       (uint8_t)((height >> 24) & 0xFF),
                       0x11 };
    script_set(&tx.vin[0].script_sig, sig, 6);
    uint256_set_null(&tx.vin[0].prevout.hash);
    tx.vin[0].prevout.n = 0xFFFFFFFF;
    tx.vin[0].sequence = 0xFFFFFFFF;
    tx.num_vout = 1;
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "sr_cb_vout");
    tx.vout[0].value = 1000;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx.vout[0].script_pub_key, pk, 3);
    transaction_compute_hash(&tx);
    return tx;
}

static void sr_free_tx(struct transaction *tx)
{
    free(tx->vin);
    free(tx->vout);
}

/* Mainnet params with a checkpoint COVERING SR_HEIGHT so connect_block runs
 * with expensive_checks=false. */
static struct chain_params sr_params(struct checkpoint_entry *out_entry)
{
    struct chain_params p = *chain_params_get();
    memset(out_entry, 0, sizeof(*out_entry));
    out_entry->height = SR_HEIGHT;
    memset(out_entry->hash.data, 0x01, 32);
    p.checkpointData.entries = out_entry;
    p.checkpointData.nEntries = 1;
    return p;
}

/* Build a small, non-empty depth-4 Sapling testing tree (a stable, known
 * frontier) and return it plus its root. Static storage so the pointer
 * handed to connect_block_set_sapling_tree() outlives the call. */
static struct incremental_merkle_tree *sr_pre_block_tree(struct uint256 *root_out)
{
    static struct incremental_merkle_tree tree;
    sapling_testing_tree_init(&tree);
    for (int i = 0; i < 3; i++) {
        struct uint256 leaf;
        memset(leaf.data, (uint8_t)(0xA0 + i), 32);
        incremental_tree_append(&tree, &leaf);
    }
    incremental_tree_root(&tree, root_out);
    return &tree;
}

/* Run connect_block (non-just_check) over a coinbase-only Sapling-active
 * block whose header carries `header_root`. Returns the result and copies
 * the reject reason out. The global g_sapling_tree is set to a known
 * pre-block frontier so the pure predicate has something to fold. */
static bool sr_run(const struct uint256 *header_root, char reject_out[256])
{
    /* Keep the deferred-proof skip OFF so we don't perturb other branches. */
    atomic_store(&g_deferred_proof_validation_below_height, -1);

    struct uint256 dummy_root;
    connect_block_set_sapling_tree(sr_pre_block_tree(&dummy_root));

    struct checkpoint_entry cpentry;
    struct chain_params params = sr_params(&cpentry);

    struct transaction cb = sr_make_coinbase(SR_HEIGHT);

    struct block blk;
    memset(&blk, 0, sizeof(blk));
    blk.num_vtx = 1;
    blk.vtx = zcl_calloc(1, sizeof(struct transaction), "sr_blk_vtx");
    blk.vtx[0] = cb;
    blk.header.nVersion = 4;
    blk.header.hashFinalSaplingRoot = *header_root;

    struct uint256 txids[1] = { cb.hash };
    blk.header.hashMerkleRoot = compute_merkle_root(txids, 1);

    struct uint256 prev_hash;
    memset(prev_hash.data, 0x33, 32);
    blk.header.hashPrevBlock = prev_hash;

    struct uint256 block_hash;
    block_header_get_hash(&blk.header, &block_hash);

    struct block_index pprev_idx;
    block_index_init(&pprev_idx);
    pprev_idx.nHeight = SR_HEIGHT - 1;
    pprev_idx.phashBlock = &prev_hash;
    arith_uint256_set_u64(&pprev_idx.nChainWork, (uint64_t)SR_HEIGHT);
    pprev_idx.has_chain_sprout_value = false;
    pprev_idx.has_chain_sapling_value = false;

    struct block_index pindex;
    block_index_init(&pindex);
    pindex.nHeight = SR_HEIGHT;
    pindex.phashBlock = &block_hash;
    pindex.pprev = &pprev_idx;

    struct coins_view_cache view;
    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    coins_view_cache_init(&view, &null_view);
    coins_view_cache_set_best_block(&view, &prev_hash);

    struct validation_state vs;
    validation_state_init(&vs);

    bool ok = connect_block(&blk, &vs, &pindex, &view, &params,
                            false /* just_check=false */);
    if (reject_out) {
        strncpy(reject_out, vs.reject_reason, 255);
        reject_out[255] = '\0';
    }

    coins_view_cache_free(&view);
    free(blk.vtx);
    sr_free_tx(&cb);
    connect_block_set_sapling_tree(NULL);
    return ok;
}

int test_connect_block_sapling_root(void)
{
    printf("\n=== connect_block Sapling-root parity (default-off) ===\n");
    int failures = 0;

    /* The correct post-block root: with zero shielded outputs, it equals the
     * pre-block tree's root. A wrong-but-nonzero root for the reject cases. */
    struct uint256 correct_root;
    (void)sr_pre_block_tree(&correct_root);
    struct uint256 wrong_root;
    memset(wrong_root.data, 0x7E, 32); /* non-zero ⇒ skips the zeros reject */

    /* Sanity: the wrong root is genuinely different from the correct one,
     * else cases 1 and 3 would be vacuous. */
    SR_CHECK("fixture: wrong_root differs from correct_root",
             memcmp(wrong_root.data, correct_root.data, 32) != 0);

    /* Pure-predicate contract: NULL frontier cannot decide → never rejects. */
    {
        struct block b;
        memset(&b, 0, sizeof(b));
        memset(b.header.hashFinalSaplingRoot.data, 0x7E, 32);
        SR_CHECK("predicate: NULL frontier returns true (cannot-decide)",
                 sapling_root_matches(&b, NULL));
    }

    /* 1. DEFAULT (flag OFF) + WRONG non-zero root → ACCEPTS (unchanged). */
    {
        atomic_store(&g_enforce_sapling_root, false);
        char reject[256] = "";
        bool ok = sr_run(&wrong_root, reject);
        SR_CHECK("flag OFF: wrong non-zero root still ACCEPTS (byte-identical)",
                 ok);
        SR_CHECK("flag OFF: no bad-sapling-root-mismatch reject",
                 strstr(reject, "bad-sapling-root-mismatch") == NULL);
    }

    /* 2. Flag ON + CORRECT recomputed root → ACCEPTS. */
    {
        atomic_store(&g_enforce_sapling_root, true);
        char reject[256] = "";
        bool ok = sr_run(&correct_root, reject);
        SR_CHECK("flag ON: correct recomputed root ACCEPTS", ok);
        atomic_store(&g_enforce_sapling_root, false);
    }

    /* 3. Flag ON + WRONG non-zero root → REJECTS (bad-sapling-root-mismatch). */
    {
        atomic_store(&g_enforce_sapling_root, true);
        char reject[256] = "";
        bool ok = sr_run(&wrong_root, reject);
        SR_CHECK("flag ON: wrong non-zero root REJECTS", !ok);
        SR_CHECK("flag ON: reject reason is bad-sapling-root-mismatch",
                 strstr(reject, "bad-sapling-root-mismatch") != NULL);
        atomic_store(&g_enforce_sapling_root, false);
    }

    /* Leave the global in its default (off) state for any later group. */
    atomic_store(&g_enforce_sapling_root, false);
    return failures;
}

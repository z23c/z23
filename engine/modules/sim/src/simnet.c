/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet — deterministic, RAM-only single-node chain harness.
 * See engine/modules/sim/include/sim/simnet.h for the design contract.
 *
 * This file ASSEMBLES inputs and ASSERTS outputs against the real
 * consensus code (connect_block). It never modifies a consensus predicate:
 * a rejected block means the harness built the wrong block, not that the
 * validator is wrong.
 */

#include "sim/simnet.h"

#include "sim/seed_tape.h"
#include "validation/connect_block.h"
#include "validation/contextual_check_tx.h" /* contextual_check_transaction (Lane C) */
#include "consensus/validation.h"
#include "consensus/consensus.h"          /* COINBASE_MATURITY */
#include "consensus/params.h"             /* PRE_BUTTERCUP_POW_TARGET_SPACING */
#include "consensus/upgrades.h"           /* UPGRADE_OVERWINTER / UPGRADE_SAPLING */
#include "sapling/incremental_merkle_tree.h" /* Sapling note-commitment tree */
#include "coins/coins.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "bloom/merkle.h"
#include "core/uint256.h"
#include "core/arith_uint256.h"
#include "script/script.h"
#include "util/timedata.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* First mintable height. Low enough that Sapling is inactive (so the
 * all-zero hashFinalSaplingRoot check is skipped) and the subsidy dwarfs
 * our tiny coinbase outputs. */
#define SIM_BASE_HEIGHT 100

/* A single checkpoint at this height "covers" every height we mint, so
 * connect_block runs with expensive_checks=false (PoW + parallel scripts
 * skipped) — the same mechanism as test_connect_block_self_write.c. */
#define SIM_CHECKPOINT_HEIGHT 1000000

/* Value carried by every synthetic coinbase output. Well under any subsidy
 * so the "bad-cb-amount" reward check always passes. */
#define SIM_COINBASE_VALUE 1000000

/* Fixed simulator clock epoch. It is intentionally above the CLTV
 * time-lock threshold (500,000,000) so time-based lock tests can advance by
 * a few 150-second virtual blocks instead of millions of pre-threshold ones. */
#define SIM_START_BLOCK_TIME 1700000000u

/* ── Transaction builders (adapted from
 *    tests/harness/src/test_connect_block_self_write.c) ─────────────────── */

/* Coinbase whose scriptSig encodes `height`, giving each coinbase a unique
 * txid (so BIP30 never trips). One output of SIM_COINBASE_VALUE. */
static struct transaction sim_make_coinbase_to(int height,
                                               const struct script *script,
                                               int64_t value)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "simnet_cb_vin");
    uint8_t sig[6] = { 4,
                       (uint8_t)(height & 0xFF),
                       (uint8_t)((height >> 8) & 0xFF),
                       (uint8_t)((height >> 16) & 0xFF),
                       (uint8_t)((height >> 24) & 0xFF),
                       0x11 };
    script_set(&tx.vin[0].script_sig, sig, sizeof(sig));
    uint256_set_null(&tx.vin[0].prevout.hash);
    tx.vin[0].prevout.n = 0xFFFFFFFF;
    tx.vin[0].sequence = 0xFFFFFFFF;
    tx.num_vout = 1;
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "simnet_cb_vout");
    tx.vout[0].value = value;
    if (script) {
        tx.vout[0].script_pub_key = *script;
    } else {
        uint8_t pk[] = {0x76, 0xa9, 0x14};
        script_set(&tx.vout[0].script_pub_key, pk, sizeof(pk));
    }
    transaction_compute_hash(&tx);
    return tx;
}

static struct transaction sim_make_coinbase(int height)
{
    return sim_make_coinbase_to(height, NULL, SIM_COINBASE_VALUE);
}

/* Transparent spend of `in_txid`:`in_n` producing one output of
 * `out_value`. expensive_checks=false skips script verification, so a
 * placeholder scriptSig suffices. */
static struct transaction sim_make_spend(const struct uint256 *in_txid,
                                         uint32_t in_n, int64_t out_value)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "simnet_spend_vin");
    tx.vin[0].prevout.hash = *in_txid;
    tx.vin[0].prevout.n = in_n;
    uint8_t sig[] = {0x00, 0x00};
    script_set(&tx.vin[0].script_sig, sig, sizeof(sig));
    tx.vin[0].sequence = 0xFFFFFFFF;
    tx.num_vout = 1;
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "simnet_spend_vout");
    tx.vout[0].value = out_value;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx.vout[0].script_pub_key, pk, sizeof(pk));
    transaction_compute_hash(&tx);
    return tx;
}

static void sim_free_tx(struct transaction *tx)
{
    /* Per the harness contract (simnet.h simnet_mint_txs): ONLY the tx's
     * vin/vout arrays are owned by simnet and freed here. The Sapling
     * spend/output/JoinSplit description arrays are NOT owned by the harness —
     * a caller may hand a stack-allocated description (e.g.
     * test_simnet_input_value_range's zeroed value_balance output), and
     * free()ing a stack pointer aborts. Callers that heap-allocate shielded
     * arrays (e.g. test_simnet_sapling_shielded_send) free their own after the
     * mint returns; the pointers survive this call untouched. */
    free(tx->vin);
    free(tx->vout);
    tx->vin = NULL;
    tx->vout = NULL;
}

/* get_anchor vtable hook for s->null_view (see simnet.h's
 * sapling_anchor_history doc comment). Linear scan is fine — sim runs mint a
 * handful of blocks, never a real chain's worth. Sprout is never queried by
 * any sim caller today; report it as HISTORY_INCOMPLETE rather than silently
 * accepting an un-registered Sprout anchor. */
static enum coins_anchor_lookup_result sim_anchor_lookup(
    void *self, enum coins_anchor_pool pool, const struct uint256 *root,
    struct incremental_merkle_tree *tree_out)
{
    (void)tree_out;
    struct simnet *s = self;
    if (!s || pool != COINS_ANCHOR_SAPLING)
        return COINS_ANCHOR_HISTORY_INCOMPLETE;
    for (size_t i = 0; i < s->sapling_anchor_count; i++)
        if (uint256_eq(&s->sapling_anchor_history[i], root))
            return COINS_ANCHOR_FOUND;
    return COINS_ANCHOR_MISSING;
}

static struct coins_view_vtable g_sim_anchor_vtable = {
    .get_anchor = sim_anchor_lookup,
};

/* Assemble `txs[0..ntx)` into a block at `height`, drive it through the
 * REAL connect_block, and on success advance the in-RAM tip. Frees each
 * tx's vin/vout (and the block's vtx copy array) on every path — the caller
 * hands ownership of the built txs to this helper. */
static bool sim_mint_block(struct simnet *s, struct transaction *txs,
                           size_t ntx, int height)
{
    if (!s || !s->initialized || ntx == 0)
        LOG_FAIL("simnet", "invalid mint request (ntx=%zu)", ntx);

    struct uint256 *txids = zcl_malloc(ntx * sizeof(*txids), "simnet_txids");
    if (!txids) {
        for (size_t i = 0; i < ntx; i++) sim_free_tx(&txs[i]);
        LOG_FAIL("simnet", "OOM allocating %zu txids", ntx);
    }

    struct block blk;
    memset(&blk, 0, sizeof(blk));
    blk.num_vtx = ntx;
    blk.vtx = zcl_calloc(ntx, sizeof(struct transaction), "simnet_blk_vtx");
    if (!blk.vtx) {
        free(txids);
        for (size_t i = 0; i < ntx; i++) sim_free_tx(&txs[i]);
        LOG_FAIL("simnet", "OOM allocating %zu vtx", ntx);
    }
    for (size_t i = 0; i < ntx; i++) {
        blk.vtx[i] = txs[i];
        txids[i] = txs[i].hash;
    }

    blk.header.nVersion = 4;
    blk.header.hashPrevBlock = s->tip.hashBlock;
    blk.header.hashMerkleRoot = compute_merkle_root(txids, ntx);
    blk.header.nTime = s->next_block_time;
    free(txids);

    /* Post-Sapling activation, connect_block (connect_block.c:704-736)
     * rejects an all-zero hashFinalSaplingRoot.
     *
     * Lane A (transparent-only sims, s->sapling_tree == NULL): the tree is
     * never appended to and stays empty, so its root is exactly the empty-tree
     * root — stamp that.
     *
     * Lane C (s->sapling_tree enabled): append THIS block's shielded-output
     * note commitments (in tx, then output order) to a value-copy of the live
     * tree and stamp the REAL resulting root. The copy `tree_after` is
     * committed to s->sapling_tree only after connect_block accepts the block,
     * so a rejected block leaves the tree unchanged (rollback-safe). */
    struct incremental_merkle_tree tree_after;
    bool have_tree_after = false;
    if (consensus_network_upgrade_active(&s->params.consensus, height,
                                         UPGRADE_SAPLING)) {
        if (s->sapling_tree) {
            tree_after = *s->sapling_tree;
            for (size_t i = 0; i < ntx; i++)
                for (size_t j = 0; j < txs[i].num_shielded_output; j++)
                    incremental_tree_append(&tree_after,
                                            &txs[i].v_shielded_output[j].cm);
            incremental_tree_root(&tree_after,
                                  &blk.header.hashFinalSaplingRoot);
            have_tree_after = true;
        } else {
            struct incremental_merkle_tree stree;
            sapling_tree_init(&stree);
            incremental_tree_empty_root(&stree, &blk.header.hashFinalSaplingRoot);
        }
    }

    struct uint256 block_hash;
    block_header_get_hash(&blk.header, &block_hash);

    struct block_index pindex;
    block_index_init(&pindex);
    pindex.nHeight = height;
    pindex.phashBlock = &block_hash;
    pindex.pprev = &s->tip;

    struct validation_state vs;
    validation_state_init(&vs);

    /* Lane C: drive the REAL shielded consensus verifier on each shielded tx.
     * contextual_check_transaction (validation/contextual_check_tx.c) is the
     * exact function contextual_check_block invokes per tx (and that the live
     * node reaches via engine/jobs/src/script_validate_contextual.c). It runs
     * check_spend/check_output/final_check on the Sapling descriptions plus the
     * JoinSplit Ed25519 sig — the full Groth16 verification path — with the
     * deferral gate off (g_deferred_proof_validation_below_height == -1, set in
     * simnet_init) so no proof is skipped. We invoke it per shielded tx (not
     * the whole block) so the harness's plain v1 coinbase does not have to
     * satisfy the block-level BIP34 / Overwinter-version rules, which are
     * orthogonal to the shielded-proof verification this lane exercises.
     * The transparent value balance is still enforced by connect_block below. */
    if (s->run_contextual_check) {
        for (size_t i = 0; i < ntx; i++) {
            if (txs[i].num_shielded_spend == 0 &&
                txs[i].num_shielded_output == 0 &&
                txs[i].num_joinsplit == 0)
                continue;
            struct validation_state cvs;
            validation_state_init(&cvs);
            if (!contextual_check_transaction(&txs[i], &cvs,
                                              &s->params.consensus,
                                              height, 100 /* dosLevel */)) {
                free(blk.vtx);
                for (size_t k = 0; k < ntx; k++)
                    sim_free_tx(&txs[k]);
                LOG_FAIL("simnet",
                         "contextual_check_transaction rejected tx %zu "
                         "at height %d: %s", i, height, cvs.reject_reason);
            }
        }
    }

    bool ok = connect_block(&blk, &vs, &pindex, &s->view, &s->params,
                            false /* just_check */);

    free(blk.vtx);
    for (size_t i = 0; i < ntx; i++)
        sim_free_tx(&txs[i]);

    if (!ok)
        LOG_FAIL("simnet", "connect_block rejected height %d: %s",
                 height, vs.reject_reason);

    /* Block accepted — commit the appended Sapling tree (Lane C). */
    if (have_tree_after && s->sapling_tree) {
        *s->sapling_tree = tree_after;

        /* Register this block's resulting root as a recognized anchor for
         * LATER blocks' spends (sim_anchor_lookup above). Without this, any
         * cross-block Sapling spend (mint the note in block N, spend it in
         * block N+1+) fails connect_block's
         * coins_view_cache_have_joinsplit_requirements check — the sim's
         * null_view has no other source of historical anchors. */
        if (s->sapling_anchor_count == s->sapling_anchor_cap) {
            size_t new_cap = s->sapling_anchor_cap ? s->sapling_anchor_cap * 2 : 4;
            struct uint256 *grown = zcl_realloc(s->sapling_anchor_history,
                                                new_cap * sizeof(*grown),
                                                "simnet_sapling_anchor_history");
            if (!grown)
                LOG_FAIL("simnet",
                         "OOM growing sapling anchor history to %zu entries",
                         new_cap);
            s->sapling_anchor_history = grown;
            s->sapling_anchor_cap = new_cap;
        }
        incremental_tree_root(s->sapling_tree,
                              &s->sapling_anchor_history[s->sapling_anchor_count++]);
    }

    /* Advance the tip in RAM. tip.phashBlock keeps pointing at
     * tip.hashBlock (a fixed address), so links stay valid across mints. */
    s->tip.hashBlock = block_hash;
    s->tip.phashBlock = &s->tip.hashBlock;
    s->tip.nHeight = height;
    s->tip.pprev = NULL;
    s->tip.has_chain_sprout_value = false;
    s->tip.has_chain_sapling_value = false;
    arith_uint256_set_u64(&s->tip.nChainWork, (uint64_t)height + 1);
    s->tip_height = height;
    s->last_block_time = blk.header.nTime;
    s->next_block_time += PRE_BUTTERCUP_POW_TARGET_SPACING;
    if (s->clock_tape) {
        int rc = seed_tape_advance(
                s->clock_tape,
                (int64_t)PRE_BUTTERCUP_POW_TARGET_SPACING * 1000000LL);
        if (rc < 0)
            LOG_WARN("simnet", "seed_tape advance failed rc=%d", rc);
    }
    return true;
}

bool simnet_init(struct simnet *s)
{
    if (!s)
        LOG_FAIL("simnet", "NULL simnet");

    memset(s, 0, sizeof(*s));

    /* Keep the BIP30 self-write branch live and deterministic (no deferred
     * proof window) — mirrors the connect_block test harness. */
    atomic_store(&g_deferred_proof_validation_below_height, -1);

    /* Value-copy the chain params, then install a single checkpoint that
     * covers every height we mint (expensive_checks=false). */
    s->params = *chain_params_get();
    memset(&s->cpentry, 0, sizeof(s->cpentry));
    s->cpentry.height = SIM_CHECKPOINT_HEIGHT;
    memset(s->cpentry.hash.data, 0x01, 32);
    s->params.checkpointData.entries = &s->cpentry;
    s->params.checkpointData.nEntries = 1;

    /* Synthetic base tip, one below the first mintable height. */
    block_index_init(&s->tip);
    s->tip.nHeight = SIM_BASE_HEIGHT - 1;
    memset(s->tip.hashBlock.data, 0x33, 32);
    s->tip.phashBlock = &s->tip.hashBlock;
    s->tip.pprev = NULL;
    s->tip.has_chain_sprout_value = false;
    s->tip.has_chain_sapling_value = false;
    arith_uint256_set_u64(&s->tip.nChainWork, (uint64_t)SIM_BASE_HEIGHT);
    s->tip_height = SIM_BASE_HEIGHT - 1;
    s->last_block_time = 0;
    s->next_block_time = SIM_START_BLOCK_TIME;
    s->mempool_txs = NULL;
    s->mempool_count = 0;
    s->mempool_cap = 0;
    s->mempool_last_reject = 0;
    s->mempool_last_detail[0] = '\0';
    s->clock_tape = NULL;

    /* The live UTXO set: an empty coins cache over a zeroed backing view.
     * Its best block is the synthetic base tip (view/prevblock invariant). */
    memset(&s->null_view, 0, sizeof(s->null_view));
    s->null_view.vtable = &g_sim_anchor_vtable;
    s->null_view.impl = s;
    coins_view_cache_init(&s->view, &s->null_view);
    coins_view_cache_set_best_block(&s->view, &s->tip.hashBlock);

    s->initialized = true;
    return true;
}

void simnet_free(struct simnet *s)
{
    if (!s || !s->initialized)
        return;
    for (size_t i = 0; i < s->mempool_count; i++)
        transaction_free(&s->mempool_txs[i]);
    free(s->mempool_txs);
    s->mempool_txs = NULL;
    s->mempool_count = 0;
    s->mempool_cap = 0;
    free(s->sapling_tree);            /* Lane C: owned note-commitment tree */
    s->sapling_tree = NULL;
    free(s->sapling_anchor_history);  /* Lane C: owned anchor registry */
    s->sapling_anchor_history = NULL;
    s->sapling_anchor_count = 0;
    s->sapling_anchor_cap = 0;
    coins_view_cache_free(&s->view);
    s->initialized = false;
}

void simnet_use_seed_tape(struct simnet *s, seed_tape_t *tape)
{
    if (!s || !s->initialized) {
        LOG_WARN("simnet", "cannot bind seed tape to uninitialized simnet");
        return;
    }
    s->clock_tape = tape;
    if (tape) {
        int64_t now = GetAdjustedTime();
        if (now > 0 && now <= UINT32_MAX)
            s->next_block_time = (uint32_t)now;
    }
}

void simnet_activate_sapling_at(struct simnet *s, int height)
{
    if (!s || !s->initialized) {
        LOG_WARN("simnet",
                 "cannot set Sapling activation on uninitialized simnet");
        return;
    }
    if (height < 0) {
        LOG_WARN("simnet", "ignoring negative Sapling activation height %d",
                 height);
        return;
    }
    /* Mutate ONLY the sim's value-copy of params — never chain_params_get()
     * or the mainnet definition in core/modules/chain/src/chainparams.c. Overwinter
     * must be active wherever Sapling is (Sapling is an Overwinter-family
     * upgrade); mainnet already ships both at the same height (476969), so
     * co-lowering them to `height` is the faithful sim-local profile. */
    s->params.consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight = height;
    s->params.consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight = height;
}

bool simnet_mint_coinbase(struct simnet *s, struct uint256 *out_cb_txid)
{
    if (!s || !s->initialized)
        LOG_FAIL("simnet", "uninitialized simnet");

    int height = s->tip_height + 1;
    struct transaction cb = sim_make_coinbase(height);
    struct uint256 cb_txid = cb.hash;

    if (!sim_mint_block(s, &cb, 1, height))
        return false;   /* sim_mint_block already logged + freed */

    if (out_cb_txid)
        *out_cb_txid = cb_txid;
    return true;
}

bool simnet_mint_coinbase_to(struct simnet *s, const struct script *script,
                             int64_t value, struct uint256 *out_cb_txid)
{
    if (!s || !s->initialized || !script)
        LOG_FAIL("simnet", "invalid coinbase-to-script mint request");
    if (!MoneyRange(value))
        LOG_FAIL("simnet", "coinbase value out of range: %lld",
                 (long long)value);

    int height = s->tip_height + 1;
    struct transaction cb = sim_make_coinbase_to(height, script, value);
    struct uint256 cb_txid = cb.hash;

    if (!sim_mint_block(s, &cb, 1, height))
        return false;

    if (out_cb_txid)
        *out_cb_txid = cb_txid;
    return true;
}

bool simnet_mint_txs(struct simnet *s, struct transaction *txs, size_t ntx)
{
    if (!s || !s->initialized)
        LOG_FAIL("simnet", "uninitialized simnet");
    if (ntx > 0 && !txs)
        LOG_FAIL("simnet", "NULL tx array for %zu txs", ntx);
    if (ntx > SIZE_MAX - 1)
        LOG_FAIL("simnet", "too many txs: %zu", ntx);

    int height = s->tip_height + 1;
    struct transaction cb = sim_make_coinbase(height);
    struct transaction *block_txs =
        zcl_calloc(ntx + 1, sizeof(*block_txs), "simnet_public_txs");
    if (!block_txs) {
        sim_free_tx(&cb);
        for (size_t i = 0; i < ntx; i++)
            sim_free_tx(&txs[i]);
        LOG_FAIL("simnet", "OOM allocating %zu public tx slots", ntx + 1);
    }

    block_txs[0] = cb;
    for (size_t i = 0; i < ntx; i++) {
        block_txs[i + 1] = txs[i];
        transaction_init(&txs[i]);
    }

    bool ok = sim_mint_block(s, block_txs, ntx + 1, height);
    free(block_txs);
    return ok;
}

bool simnet_mint_to_height(struct simnet *s, int target_height)
{
    if (!s || !s->initialized)
        LOG_FAIL("simnet", "uninitialized simnet");
    while (s->tip_height < target_height) {
        if (!simnet_mint_coinbase(s, NULL))
            return false;
    }
    return true;
}

bool simnet_spend(struct simnet *s, const struct uint256 *in_txid,
                  uint32_t in_n, int64_t out_value, struct uint256 *out_txid)
{
    if (!s || !s->initialized || !in_txid)
        LOG_FAIL("simnet", "invalid spend request");

    /* Resolve the input coin so we can (a) honor coinbase maturity and
     * (b) fail early with a clear message if it is absent. */
    struct coins in_coin;
    coins_init(&in_coin);
    if (!coins_view_cache_get_coins(&s->view, in_txid, &in_coin)) {
        coins_free(&in_coin);
        LOG_FAIL("simnet", "input coin absent");
    }
    if (!coins_is_available(&in_coin, in_n)) {
        coins_free(&in_coin);
        LOG_FAIL("simnet", "input output %u unavailable/spent", in_n);
    }
    if (out_value > in_coin.vout[in_n].value) {
        int64_t have = in_coin.vout[in_n].value;
        coins_free(&in_coin);
        LOG_FAIL("simnet", "out_value %lld exceeds input value %lld",
                 (long long)out_value, (long long)have);
    }

    /* Mint at a height that satisfies the real coinbase-maturity predicate
     * (pindex->nHeight - coin.height >= COINBASE_MATURITY). Non-coinbase
     * inputs are spendable at the next height. */
    int next = s->tip_height + 1;
    if (in_coin.is_coinbase) {
        int mature_at = in_coin.height + COINBASE_MATURITY;
        if (mature_at > next)
            next = mature_at;
    }
    coins_free(&in_coin);

    struct transaction cb = sim_make_coinbase(next);
    struct transaction spend = sim_make_spend(in_txid, in_n, out_value);
    struct uint256 spend_txid = spend.hash;

    struct transaction txs[2] = { cb, spend };
    if (!sim_mint_block(s, txs, 2, next))
        return false;   /* sim_mint_block already logged + freed */

    if (out_txid)
        *out_txid = spend_txid;
    return true;
}

int simnet_tip_height(const struct simnet *s)
{
    return (s && s->initialized) ? s->tip_height : -1;
}

uint32_t simnet_next_block_time(const struct simnet *s)
{
    return (s && s->initialized) ? s->next_block_time : 0;
}

bool simnet_tip_hash(const struct simnet *s, struct uint256 *out)
{
    if (!s || !s->initialized || !out)
        LOG_FAIL("simnet", "invalid tip hash request");
    *out = s->tip.hashBlock;
    return true;
}

bool simnet_coin_exists(struct simnet *s, const struct uint256 *txid)
{
    if (!s || !s->initialized || !txid)
        return false;
    return coins_view_cache_have_coins(&s->view, txid);
}

bool simnet_coin_value(struct simnet *s, const struct uint256 *txid,
                       uint32_t n, int64_t *out_value)
{
    if (!s || !s->initialized || !txid)
        return false;
    struct coins c;
    coins_init(&c);
    if (!coins_view_cache_get_coins(&s->view, txid, &c)) {
        coins_free(&c);
        return false;
    }
    bool ok = coins_is_available(&c, n);
    if (ok && out_value)
        *out_value = c.vout[n].value;
    coins_free(&c);
    return ok;
}

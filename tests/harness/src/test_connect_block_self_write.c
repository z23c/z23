/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pins the BIP30 same-height self-write tolerance in
 * core/modules/validation/src/connect_block.c.
 *
 * Background (see BOOT_INVARIANTS.md "at-tip kill-9 ordering" and the
 * MEMORY note "THE WEDGE: BIP30 self-write"): a kill-9 mid-connect can
 * leave the UTXO set one block ahead of the tip cursor, so when
 * connect_block re-applies the SAME block its own outputs are already
 * present and unspent. That is NOT a BIP30 violation — a genuine BIP30
 * collision is a DIFFERENT block overwriting another block's still-unspent
 * coinbase, which post-BIP34 can only carry a coin from a DIFFERENT
 * (earlier) height. The fix tolerates `existing.height == pindex->nHeight`
 * (overwrite, continue) and rejects everything else as bad-txns-BIP30.
 *
 * The original tolerance covered only vtx[0] (coinbase). This session
 * extended it to EVERY vtx, because a partial apply leaves the block's
 * NON-coinbase outputs in the set too. These tests pin BOTH:
 *   1. a NON-coinbase output already unspent at the block's own height
 *      connects (overwrites) rather than failing BIP30;
 *   2. a coin present at a DIFFERENT (earlier) height still fails BIP30.
 *
 * To exercise the BIP30 loop in isolation we use a checkpoint-covered
 * height: that sets expensive_checks=false (skips PoW + parallel script
 * verification) WITHOUT setting skip_bip30 (which is gated only on the
 * deferred-proof global). So the self-write branch is genuinely reached
 * — not short-circuited.
 */

#include "test/test_core.h"

#include "validation/connect_block.h"
#include "validation/check_block.h"
#include "validation/contextual_check_tx.h"
#include "validation/update_coins.h"
#include "coins/coins_view.h"
#include "coins/coins.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "bloom/merkle.h"
#include "core/uint256.h"
#include "core/arith_uint256.h"
#include "script/script.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <string.h>
#include <stdatomic.h>

#define SW_CHECK(name, expr) do {          \
    printf("%s... ", (name));              \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Test height: low enough that Sapling is inactive (so the all-zero
 * hashFinalSaplingRoot check is skipped) and the subsidy is large enough
 * to cover our tiny coinbase output. */
#define SW_HEIGHT 100

/* A funding txid that the non-coinbase tx spends. Seeded into the view as
 * a plain (non-coinbase) coin so coinbase-maturity never trips. */
static struct uint256 sw_funding_txid(void)
{
    struct uint256 h;
    memset(h.data, 0x5A, 32);
    return h;
}

static struct transaction sw_make_coinbase(int height)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "sw_cb_vin");
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
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "sw_cb_vout");
    tx.vout[0].value = 1000;     /* well under any subsidy + fees */
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx.vout[0].script_pub_key, pk, 3);
    transaction_compute_hash(&tx);
    return tx;
}

/* Non-coinbase tx: spends sw_funding_txid:0 (value 50000), produces one
 * output of value 40000 (10000 fee). */
static struct transaction sw_make_spend(void)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "sw_spend_vin");
    tx.vin[0].prevout.hash = sw_funding_txid();
    tx.vin[0].prevout.n = 0;
    uint8_t sig[] = {0x00, 0x00};
    script_set(&tx.vin[0].script_sig, sig, 2);
    tx.vin[0].sequence = 0xFFFFFFFF;
    tx.num_vout = 1;
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "sw_spend_vout");
    tx.vout[0].value = 40000;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx.vout[0].script_pub_key, pk, 3);
    transaction_compute_hash(&tx);
    return tx;
}

static void sw_free_tx(struct transaction *tx)
{
    free(tx->vin);
    free(tx->vout);
}

/* Seed `view` with one unspent output for `txid` at `height`. */
static void sw_seed_coin(struct coins_view_cache *view,
                         const struct uint256 *txid,
                         int height, int64_t value, bool is_coinbase)
{
    struct coins_cache_entry *e = coins_view_cache_modify_new(view, txid);
    coins_alloc(&e->coins, 1);
    e->coins.height = height;
    e->coins.version = 1;
    e->coins.is_coinbase = is_coinbase;
    e->coins.vout[0].value = value;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&e->coins.vout[0].script_pub_key, pk, 3);
    e->flags = COINS_CACHE_DIRTY;
}

/* Build mainnet params with a checkpoint that COVERS SW_HEIGHT so
 * connect_block runs with expensive_checks=false (PoW + scripts skipped)
 * while the BIP30 loop still runs (skip_bip30 stays false). Returns a
 * static checkpoint entry array via *out_entry. */
static struct chain_params sw_params(struct checkpoint_entry *out_entry)
{
    struct chain_params p = *chain_params_get();
    memset(out_entry, 0, sizeof(*out_entry));
    out_entry->height = SW_HEIGHT;        /* >= SW_HEIGHT → covered */
    memset(out_entry->hash.data, 0x01, 32);
    p.checkpointData.entries = out_entry;
    p.checkpointData.nEntries = 1;
    return p;
}

/* Run connect_block (non-just_check) over a 2-tx block whose spend tx's
 * own output is pre-seeded in the view at `existing_height`. Returns the
 * connect_block result and copies reject_reason out. */
static bool sw_run(int existing_height, char reject_out[256])
{
    /* Force the BIP30 self-write branch to be live: deferred-proof
     * disabled so skip_bip30 == false. */
    atomic_store(&g_deferred_proof_validation_below_height, -1);

    struct checkpoint_entry cpentry;
    struct chain_params params = sw_params(&cpentry);

    struct transaction cb = sw_make_coinbase(SW_HEIGHT);
    struct transaction spend = sw_make_spend();

    struct block blk;
    memset(&blk, 0, sizeof(blk));
    blk.num_vtx = 2;
    blk.vtx = zcl_calloc(2, sizeof(struct transaction), "sw_blk_vtx");
    blk.vtx[0] = cb;
    blk.vtx[1] = spend;
    blk.header.nVersion = 4;

    struct uint256 txids[2] = { cb.hash, spend.hash };
    blk.header.hashMerkleRoot = compute_merkle_root(txids, 2);

    /* prev block: a distinct non-genesis hash; the view's best block is
     * set to it so the view/prevblock invariant passes. */
    struct uint256 prev_hash;
    memset(prev_hash.data, 0x33, 32);
    blk.header.hashPrevBlock = prev_hash;

    struct uint256 block_hash;
    block_header_get_hash(&blk.header, &block_hash);

    struct block_index pprev_idx;
    block_index_init(&pprev_idx);
    pprev_idx.nHeight = SW_HEIGHT - 1;
    pprev_idx.phashBlock = &prev_hash;
    arith_uint256_set_u64(&pprev_idx.nChainWork, (uint64_t)SW_HEIGHT);
    pprev_idx.has_chain_sprout_value = false;
    pprev_idx.has_chain_sapling_value = false;

    struct block_index pindex;
    block_index_init(&pindex);
    pindex.nHeight = SW_HEIGHT;
    pindex.phashBlock = &block_hash;
    pindex.pprev = &pprev_idx;

    struct coins_view_cache view;
    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    coins_view_cache_init(&view, &null_view);
    coins_view_cache_set_best_block(&view, &prev_hash);

    /* Funding coin the spend consumes (plain, mature). */
    struct uint256 funding = sw_funding_txid();
    sw_seed_coin(&view, &funding, 1 /* mature */, 50000, false);

    /* THE RESIDUE: the spend tx's OWN output already unspent in the set,
     * at `existing_height`. existing_height == SW_HEIGHT models a prior
     * partial apply of THIS block (must be tolerated); a different height
     * models a genuine BIP30 collision (must be rejected). */
    sw_seed_coin(&view, &spend.hash, existing_height, 40000, false);

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
    sw_free_tx(&cb);
    sw_free_tx(&spend);
    return ok;
}

int test_connect_block_self_write(void)
{
    printf("\n=== connect_block BIP30 self-write tolerance ===\n");
    int failures = 0;

    /* 1. Same-height self-write of a NON-coinbase output → tolerated.
     *    Pre-fix (coinbase-only tolerance) this returned false with
     *    bad-txns-BIP30 because vtx[1] is not vtx[0]. */
    {
        char reject[256] = "";
        bool ok = sw_run(SW_HEIGHT, reject);
        SW_CHECK("self-write: non-coinbase output at own height connects",
                 ok);
        SW_CHECK("self-write: own-height connect is not a BIP30 reject",
                 strstr(reject, "BIP30") == NULL);
    }

    /* 2. Genuine duplicate (coin present at a DIFFERENT/earlier height)
     *    → still rejected as bad-txns-BIP30. This is the guard that the
     *    tolerance did not become a blanket "always overwrite". */
    {
        char reject[256] = "";
        bool ok = sw_run(SW_HEIGHT - 5, reject);
        SW_CHECK("self-write: different-height duplicate is rejected",
                 !ok);
        SW_CHECK("self-write: different-height reject names bad-txns-BIP30",
                 strstr(reject, "BIP30") != NULL);
    }

    return failures;
}

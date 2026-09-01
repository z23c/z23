/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * 01_mint_and_spend — the simulator "hello world".
 *
 * WHAT THIS DEMONSTRATES
 * -----------------------
 * z23's deterministic simulator (`engine/modules/sim`) drives the REAL consensus
 * validator (`connect_block()`) over an in-RAM UTXO set — no disk, no real
 * proof-of-work, no live funds, no wall clock. Everything you see below
 * exercises the exact same code path a live node uses to accept a block; the
 * only things skipped are PoW itself and expensive script/proof checks
 * (turned off via a synthetic checkpoint the sim installs, the identical
 * mechanism `tests/harness/src/test_connect_block_self_write.c` uses). If a step
 * below returns false, the real validator rejected the block — the fix
 * belongs in how the example builds the block, never in consensus code.
 *
 * THE MENTAL MODEL
 * -----------------
 * A `struct simnet` is one single-node chain: a `coins_view_cache` (the live
 * UTXO set) plus a `block_index` tip. You mint blocks onto it one at a time;
 * each successful mint advances the tip and folds that block's effect into
 * the UTXO view — the same fold the real node's `utxo_apply` reducer stage
 * performs, just synchronously and in memory.
 *
 * A freshly mined coinbase output is NOT spendable immediately: the real
 * consensus rule (`COINBASE_MATURITY` = 100, see
 * lib/consensus/include/consensus/consensus.h) requires 100 confirmations
 * before a coinbase output can be spent. This example mines past that
 * maturity window explicitly with `simnet_mint_to_height` so a learner can
 * see the concept, even though the wallet-level helpers (see
 * docs/SIMULATOR_TXNS.md) can skip straight to a mature spend under the hood.
 *
 * Determinism: everything randomness-dependent (the wallet's P2PKH keypair)
 * is drawn from a `seed_tape` installed BEFORE `simnet_wallet_create`, so
 * this program produces the identical address/txids on every run — that is
 * the whole point of "every bug is a 64-bit seed" (engine/modules/sim/include/sim/seed_tape.h).
 *
 * Build (via the integrator's docs/examples/Makefile):
 *   cc -std=c2x -DZCL_TESTING <lib -I flags> docs/examples/01_mint_and_spend.c -o ...
 *
 * NOTE: this file only uses PUBLIC (non-test-only) sim headers — no
 * `#ifdef ZCL_TESTING` gated declaration is required to compile or link it.
 */

#include "sim/simnet.h"
#include "sim/simnet_wallet.h"
#include "sim/seed_tape.h"
#include "consensus/consensus.h"
#include "core/uint256.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    printf("=== 01_mint_and_spend: the simnet hello world ===\n");

    /* Fixed seed + fixed virtual start time => byte-identical run every
     * time. Change ZCL_EXAMPLE_SEED and the whole run (address, txids,
     * timestamps) changes right along with it — that's the debugging
     * superpower: any failure reproduces from one number. */
    const uint64_t ZCL_EXAMPLE_SEED = 0xC0FFEE1234ULL;
    const int64_t  ZCL_EXAMPLE_START_WALL = 1700000000; /* arbitrary fixed unix time */

    seed_tape_t *tape = seed_tape_open(ZCL_EXAMPLE_SEED, ZCL_EXAMPLE_START_WALL);
    if (!tape) {
        fprintf(stderr, "FAIL: seed_tape_open returned NULL (OOM?)\n");
        return 1;
    }
    seed_tape_install(tape);

    /* Every chain/consensus/script code path (connect_block, coinbase
     * subsidy, address prefixes, ...) reads its parameters through
     * chain_params_get(), which asserts a network was selected first. A
     * real node does this once at boot (engine/composition/src/boot.c); a standalone
     * program driving the simulator must do it before the first simnet_*
     * call. */
    chain_params_select(CHAIN_MAIN);

    printf("[1/4] initializing simnet (in-RAM chain, no disk, no real PoW)...\n");
    struct simnet sim;
    if (!simnet_init(&sim)) {
        fprintf(stderr, "FAIL: simnet_init failed\n");
        seed_tape_uninstall();
        seed_tape_close(tape);
        return 1;
    }
    /* simnet_init places a synthetic base tip just below the first mintable
     * height; bind the tape so nTime/GetAdjustedTime() advance deterministically
     * with every mint (150s target spacing per block, ZClassic's real spacing). */
    simnet_use_seed_tape(&sim, tape);
    printf("      base tip height = %d\n", simnet_tip_height(&sim));

    /* A deterministic P2PKH wallet drawn from the installed seed tape's RNG.
     * Same seed => same keypair => same address on every run. */
    struct simnet_wallet *wallet = simnet_wallet_create(&sim);
    if (!wallet) {
        fprintf(stderr, "FAIL: simnet_wallet_create failed\n");
        simnet_free(&sim);
        seed_tape_uninstall();
        seed_tape_close(tape);
        return 1;
    }
    printf("      deterministic wallet address: %s\n", simnet_wallet_address(wallet));

    printf("[2/4] minting a coinbase that pays the wallet's script...\n");
    struct uint256 cb_txid;
    uint256_set_null(&cb_txid);
    const int64_t CB_VALUE = 1000000; /* zats; the sim's coinbase subsidy stub */
    if (!simnet_mint_coinbase_to(&sim, simnet_wallet_script(wallet), CB_VALUE, &cb_txid)) {
        fprintf(stderr, "FAIL: simnet_mint_coinbase_to was rejected by connect_block\n");
        simnet_wallet_free(wallet);
        simnet_free(&sim);
        seed_tape_uninstall();
        seed_tape_close(tape);
        return 1;
    }
    int height_after_mint = simnet_tip_height(&sim);
    printf("      tip advanced to height %d; coinbase txid recorded\n", height_after_mint);
    assert(simnet_coin_exists(&sim, &cb_txid) && "freshly minted coinbase must be a live UTXO");

    printf("[3/4] mining %d filler blocks to clear COINBASE_MATURITY (=%d)...\n",
           COINBASE_MATURITY, COINBASE_MATURITY);
    /* This is the real consensus predicate from connect_block():
     *   pindex->nHeight - coin.height >= COINBASE_MATURITY
     * We satisfy it the honest way -- by actually mining that many blocks on
     * top, exactly like a live node accruing confirmations -- rather than
     * special-casing the check. */
    int mature_height = height_after_mint + COINBASE_MATURITY;
    if (!simnet_mint_to_height(&sim, mature_height)) {
        fprintf(stderr, "FAIL: simnet_mint_to_height(%d) rejected by connect_block\n",
                mature_height);
        simnet_wallet_free(wallet);
        simnet_free(&sim);
        seed_tape_uninstall();
        seed_tape_close(tape);
        return 1;
    }
    printf("      tip is now height %d (coinbase matured at %d confirmations)\n",
           simnet_tip_height(&sim), simnet_tip_height(&sim) - height_after_mint);
    assert(simnet_tip_height(&sim) - height_after_mint >= COINBASE_MATURITY);

    printf("[4/4] spending the matured coinbase to a new output...\n");
    struct uint256 spend_txid;
    uint256_set_null(&spend_txid);
    const int64_t SPEND_VALUE = 900000; /* < CB_VALUE; the remainder is the fee */
    if (!simnet_spend(&sim, &cb_txid, 0, SPEND_VALUE, &spend_txid)) {
        fprintf(stderr, "FAIL: simnet_spend rejected the coinbase spend\n");
        simnet_wallet_free(wallet);
        simnet_free(&sim);
        seed_tape_uninstall();
        seed_tape_close(tape);
        return 1;
    }

    /* This is the assertion the whole example exists to demonstrate: after
     * connect_block() folds the spend, the OLD coin is gone from the live
     * UTXO view and the NEW coin is present -- the same fold the real node's
     * utxo_apply stage performs against coins_kv on disk. */
    bool old_coin_gone = !simnet_coin_exists(&sim, &cb_txid);
    bool new_coin_present = simnet_coin_exists(&sim, &spend_txid);
    int64_t new_coin_value = 0;
    bool value_readable = simnet_coin_value(&sim, &spend_txid, 0, &new_coin_value);

    printf("      spent coinbase consumed:  %s\n", old_coin_gone ? "yes" : "NO (BUG)");
    printf("      new UTXO present in view:  %s\n", new_coin_present ? "yes" : "NO (BUG)");
    if (value_readable)
        printf("      new UTXO value:            %" PRId64 " zats\n", new_coin_value);

    if (!old_coin_gone || !new_coin_present || !value_readable || new_coin_value != SPEND_VALUE) {
        fprintf(stderr,
                "FAIL: post-spend UTXO view assertions failed "
                "(old_gone=%d new_present=%d value_readable=%d value=%" PRId64 ")\n",
                old_coin_gone, new_coin_present, value_readable, new_coin_value);
        simnet_wallet_free(wallet);
        simnet_free(&sim);
        seed_tape_uninstall();
        seed_tape_close(tape);
        return 1;
    }

    printf("\n=== SUCCESS: minted a coinbase, matured it past COINBASE_MATURITY, "
           "spent it, and verified the UTXO-set fold — all through the real "
           "validator ===\n");

    simnet_wallet_free(wallet);
    simnet_free(&sim);
    seed_tape_uninstall();
    seed_tape_close(tape);
    return 0;
}

/* Production counterpart:
 * ------------------------
 * This example's steps map onto real node code as follows:
 *
 *   simnet_mint_coinbase_to()  -> the miner assembling a coinbase in the
 *       real block-template path (engine/jobs/ mining assembly) followed by
 *       connect_block() in lib/consensus, driven by the utxo_apply reducer
 *       stage (engine/jobs/src/utxo_apply_stage.c) on a live node.
 *
 *   COINBASE_MATURITY check    -> lib/consensus/include/consensus/consensus.h
 *       (COINBASE_MATURITY = 100), enforced inside connect_block() for every
 *       real block, not just this example.
 *
 *   simnet_spend()             -> wallet_create_transaction() /
 *       wallet_create_transaction_multi() in contexts/wallet/modules/wallet/include/wallet/wallet.h,
 *       followed by wallet_commit_transaction() (validate -> admit to
 *       mempool -> record in wallet), and ultimately the RPC surface
 *       native wallet-send commands or
 *       `sendtoaddress` for a live node.
 *
 *   simnet_coin_exists() /
 *   simnet_coin_value()        -> core/modules/coins/include/coins/coins_view.h
 *       (coins_view_cache_have_coins() etc.) over the real on-disk coins_kv
 *       table, or `z23 core wallet utxo list` / `getrawtransaction`
 *       at the RPC layer.
 */

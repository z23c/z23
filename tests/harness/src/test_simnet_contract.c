/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_simnet_contract — HTLC / escrow contract overlay over the deterministic
 * simnet (sim-phase2 Item 4).
 *
 * Exercises the full fund -> redeem / refund lifecycle of a P2SH Hash
 * Time-Locked Contract driven through the REAL consensus code in the RAM-only
 * simnet. Every draw comes from the installed seed tape, so the whole run
 * replays from one 64-bit seed; on a failure we print the seed to repro.
 *
 * WHICH PREDICATES ARE REAL HERE (be precise — a test that "passes" because a
 * check was skipped is worse than no test):
 *
 *   - Refund-before-locktime is rejected by a REAL transaction-admission rule:
 *     domain_consensus_tx_is_final() at mempool add time (the refund tx sets
 *     nLockTime=locktime + a non-final sequence, so it is non-final until the
 *     tip height exceeds the locktime). This is SIMNET_MEMPOOL_REJECT_NONFINAL.
 *     It is NOT the script-level OP_CHECKLOCKTIMEVERIFY — that op is a script
 *     check, and scripts are not executed in-sim (expensive_checks=false).
 *
 *   - The preimage guard (OP_SHA256 <hash> OP_EQUALVERIFY) is a SCRIPT op, so
 *     it is SKIPPED during an in-sim mint. We prove this explicitly (a
 *     wrong-preimage redeem is ACCEPTED by an in-sim mint) and then verify the
 *     guard for real by running the PRODUCTION script interpreter directly via
 *     simnet_contract_check_redeem_script() — a wrong preimage yields
 *     SCRIPT_ERR_EQUALVERIFY. No faked in-sim rejection.
 */

#include "test/test_core.h"

#include "coins/coins.h"
#include "coins/coins_view.h"
#include "core/random.h"
#include "primitives/transaction.h"
#include "script/htlc.h"
#include "script/script.h"
#include "script/script_error.h"
#include "sim/seed_tape.h"
#include "sim/simnet.h"
#include "sim/simnet_contract.h"
#include "sim/simnet_mempool.h"
#include "sim/simnet_wallet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SC_CHECK(name, expr) do {          \
    printf("  %s... ", (name));            \
    if ((expr)) { printf("OK\n"); }        \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* True iff the UTXO at `txid`:`n` exists and its scriptPubKey equals `want` —
 * the sim's notion of "this party owns the coin". */
static bool sc_coin_script_is(struct simnet *s, const struct uint256 *txid,
                              uint32_t n, const struct script *want)
{
    struct coins coin;
    coins_init(&coin);
    bool ok = coins_view_cache_get_coins(&s->view, txid, &coin) &&
              coins_is_available(&coin, n);
    bool match = ok &&
                 coin.vout[n].script_pub_key.size == want->size &&
                 memcmp(coin.vout[n].script_pub_key.data, want->data,
                        want->size) == 0;
    coins_free(&coin);
    return match;
}

/* Build a deterministic HTLC from the installed seed tape's RNG. */
static bool sc_make_htlc(struct simnet_contract_htlc *c, uint32_t locktime)
{
    uint8_t secret[32], rpk[33], fpk[33];
    GetRandBytes(secret, sizeof(secret));
    GetRandBytes(rpk, sizeof(rpk));
    GetRandBytes(fpk, sizeof(fpk));
    /* Shape them like compressed pubkeys (cosmetic; the interpreter at
     * flags=P2SH does not validate pubkey format, and check_sig is stubbed). */
    rpk[0] = 0x02;
    fpk[0] = 0x03;
    return simnet_contract_htlc_init(c, secret, rpk, fpk, locktime);
}

static int run_contract_scenario(uint64_t seed)
{
    int failures = 0;

    seed_tape_t *tape = seed_tape_open(seed, 1700000000);
    if (!tape) {
        printf("  seed tape open... FAIL\n");
        return 1;
    }
    seed_tape_install(tape);

    struct simnet sim;
    SC_CHECK("simnet init", simnet_init(&sim));
    simnet_use_seed_tape(&sim, tape);

    struct simnet_wallet *funder = simnet_wallet_create(&sim);
    struct simnet_wallet *participant = simnet_wallet_create(&sim);
    struct simnet_wallet *redeemer = simnet_wallet_create(&sim);
    struct simnet_wallet *refunder = simnet_wallet_create(&sim);
    SC_CHECK("wallets create", funder && participant && redeemer && refunder);
    if (!funder || !participant || !redeemer || !refunder) {
        simnet_wallet_free(funder);
        simnet_wallet_free(participant);
        simnet_wallet_free(redeemer);
        simnet_wallet_free(refunder);
        simnet_free(&sim);
        seed_tape_uninstall();
        seed_tape_close(tape);
        return failures + 1;
    }

    /* ─── HAPPY PATH: fund -> redeem with correct preimage ─── */
    struct simnet_tx_result f0;
    SC_CHECK("fund funder wallet (happy)",
             simnet_wallet_fund(funder, 500000, &f0));

    struct simnet_contract_htlc happy;
    uint32_t happy_lock = (uint32_t)(simnet_tip_height(&sim) + 50);
    SC_CHECK("build happy HTLC", sc_make_htlc(&happy, happy_lock));

    struct simnet_tx_result happy_fund;
    SC_CHECK("fund HTLC P2SH output",
             simnet_contract_fund(&sim, funder, &happy, 200000, &happy_fund));
    SC_CHECK("funded coin present at fund_txid:0",
             sc_coin_script_is(&sim, &happy_fund.txid, 0, &happy.p2sh));
    int64_t happy_fund_value = 0;
    SC_CHECK("initiator HTLC carries the exact contract value",
             simnet_coin_value(&sim, &happy_fund.txid, 0,
                               &happy_fund_value) &&
             happy_fund_value == 200000);

    /* The counterparty role creates the same consensus P2SH shape from a
     * different wallet and independently funds it. Keeping this as a
     * separate coin prevents an initiator-only fixture from masquerading as
     * evidence for swap_participate's counter-funding leg. */
    struct simnet_tx_result participant_wallet_fund;
    SC_CHECK("fund participant wallet",
             simnet_wallet_fund(participant, 500000,
                                &participant_wallet_fund));
    struct simnet_contract_htlc participant_htlc;
    uint32_t participant_lock =
        (uint32_t)(simnet_tip_height(&sim) + 40);
    SC_CHECK("build participant HTLC",
             sc_make_htlc(&participant_htlc, participant_lock));
    struct simnet_tx_result participant_fund;
    SC_CHECK("participant independently funds counter HTLC",
             simnet_contract_fund(&sim, participant, &participant_htlc,
                                  180000, &participant_fund));
    int64_t participant_value = 0;
    SC_CHECK("participant HTLC is mined with exact script and value",
             sc_coin_script_is(&sim, &participant_fund.txid, 0,
                               &participant_htlc.p2sh) &&
             simnet_coin_value(&sim, &participant_fund.txid, 0,
                               &participant_value) &&
             participant_value == 180000);

    struct transaction redeem_tx;
    struct simnet_tx_result redeem_res;
    SC_CHECK("build redeem (correct preimage)",
             simnet_contract_build_redeem(&redeem_tx, &happy_fund.txid,
                                          200000, &happy, happy.secret,
                                          simnet_wallet_script(redeemer),
                                          &redeem_res));
    SC_CHECK("redeem enqueues", simnet_mempool_add(&sim, &redeem_tx, NULL));
    SC_CHECK("redeem mints", simnet_mempool_mint(&sim));
    SC_CHECK("redeemer owns redeemed coin",
             sc_coin_script_is(&sim, &redeem_res.txid, 0,
                               simnet_wallet_script(redeemer)));
    SC_CHECK("funded HTLC coin is now spent",
             !simnet_coin_value(&sim, &happy_fund.txid, 0, NULL));
    transaction_free(&redeem_tx);

    /* ─── REFUND PATH: early refund rejected (real finality rule),
     *     then succeeds after mint_to_height past the CLTV window ─── */
    struct simnet_tx_result f1;
    SC_CHECK("fund funder wallet (refund)",
             simnet_wallet_fund(funder, 500000, &f1));

    struct simnet_contract_htlc refc;
    uint32_t refund_lock = (uint32_t)(simnet_tip_height(&sim) + 6);
    SC_CHECK("build refund HTLC", sc_make_htlc(&refc, refund_lock));

    struct simnet_tx_result refund_fund;
    SC_CHECK("fund refund HTLC P2SH output",
             simnet_contract_fund(&sim, funder, &refc, 160000, &refund_fund));

    struct transaction refund_tx;
    struct simnet_tx_result refund_res;
    SC_CHECK("build refund spend",
             simnet_contract_build_refund(&refund_tx, &refund_fund.txid,
                                          160000, &refc,
                                          simnet_wallet_script(refunder),
                                          &refund_res));

    /* Before the window: rejected by domain_consensus_tx_is_final() at mempool
     * admission (NONFINAL) — a real transaction-level rule, not a fake. */
    struct simnet_mempool_result early;
    bool early_ok = simnet_mempool_add(&sim, &refund_tx, &early);
    SC_CHECK("early refund rejected NONFINAL (tx_is_final)",
             !early_ok && early.reason == SIMNET_MEMPOOL_REJECT_NONFINAL &&
             simnet_tip_height(&sim) < (int)refund_lock);

    /* Open the window: absolute CLTV height reached via empty mint blocks. */
    SC_CHECK("mint_to_height past CLTV window",
             simnet_mint_to_height(&sim, (int)refund_lock) &&
             simnet_tip_height(&sim) == (int)refund_lock);
    SC_CHECK("refund enqueues after window",
             simnet_mempool_add(&sim, &refund_tx, NULL));
    SC_CHECK("refund mints", simnet_mempool_mint(&sim));
    SC_CHECK("refunder owns refunded coin",
             sc_coin_script_is(&sim, &refund_res.txid, 0,
                               simnet_wallet_script(refunder)));
    SC_CHECK("refund-funded HTLC coin is now spent",
             !simnet_coin_value(&sim, &refund_fund.txid, 0, NULL));
    transaction_free(&refund_tx);

    /* ─── WRONG-PREIMAGE: skipped in-sim (proven), rejected by the real
     *     script interpreter with SCRIPT_ERR_EQUALVERIFY ─── */
    int err_ok = -1, err_bad = -1;
    SC_CHECK("real interpreter accepts correct preimage",
             simnet_contract_check_redeem_script(&happy, happy.secret,
                                                 &err_ok) &&
             err_ok == (int)SCRIPT_ERR_OK);

    uint8_t wrong[32];
    memcpy(wrong, happy.secret, 32);
    wrong[0] ^= 0xFF; /* still 32 bytes: passes OP_SIZE, fails OP_EQUALVERIFY */
    SC_CHECK("real interpreter rejects wrong preimage (EQUALVERIFY)",
             !simnet_contract_check_redeem_script(&happy, wrong, &err_bad) &&
             err_bad == (int)SCRIPT_ERR_EQUALVERIFY);

    /* Prove the guard is genuinely SKIPPED at mint time (expensive_checks=
     * false): a wrong-preimage redeem of a fresh HTLC is ACCEPTED in-sim. This
     * is EXPECTED and is exactly why the guard must be checked via the real
     * interpreter above — never assert an in-sim rejection here. */
    struct simnet_tx_result f2;
    SC_CHECK("fund funder wallet (skip-proof)",
             simnet_wallet_fund(funder, 500000, &f2));
    struct simnet_contract_htlc skipc;
    uint32_t skip_lock = (uint32_t)(simnet_tip_height(&sim) + 50);
    SC_CHECK("build skip-proof HTLC", sc_make_htlc(&skipc, skip_lock));
    struct simnet_tx_result skip_fund;
    SC_CHECK("fund skip-proof HTLC",
             simnet_contract_fund(&sim, funder, &skipc, 140000, &skip_fund));
    struct transaction skip_tx;
    struct simnet_tx_result skip_res;
    SC_CHECK("build wrong-preimage redeem",
             simnet_contract_build_redeem(&skip_tx, &skip_fund.txid, 140000,
                                          &skipc, wrong,
                                          simnet_wallet_script(redeemer),
                                          &skip_res));
    SC_CHECK("wrong-preimage redeem ACCEPTED in-sim (script skipped)",
             simnet_mempool_add(&sim, &skip_tx, NULL) &&
             simnet_mempool_mint(&sim) &&
             simnet_coin_value(&sim, &skip_res.txid, 0, NULL));
    transaction_free(&skip_tx);

    simnet_wallet_free(funder);
    simnet_wallet_free(participant);
    simnet_wallet_free(redeemer);
    simnet_wallet_free(refunder);
    simnet_free(&sim);
    seed_tape_uninstall();
    seed_tape_close(tape);

    if (failures)
        printf("\n  SIMNET_CONTRACT REPRO SEED: 0x%016llx\n",
               (unsigned long long)seed);
    return failures;
}

int test_simnet_contract(void)
{
    printf("\n=== simnet contract overlay (HTLC escrow) ===\n");

    uint64_t base_seed = 0x484C54435F455343ULL; /* "HLTC_ESC" */
    const char *env = getenv("ZCL_SIMNET_CONTRACT_SEED");
    if (env && env[0])
        base_seed = (uint64_t)strtoull(env, NULL, 0);

    int failures = run_contract_scenario(base_seed);

    /* A second, differently-seeded run to shake out any seed-specific luck
     * while staying fast + hermetic (Item 5: each group <~2s). */
    failures += run_contract_scenario(base_seed ^ 0x9E3779B97F4A7C15ULL);

    printf("=== simnet contract overlay: %d failure(s) ===\n", failures);
    return failures;
}

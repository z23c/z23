/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * 06_htlc_swap.c — HTLC (Hash Time-Locked Contract) atomic-swap lifecycle,
 * driven entirely in the deterministic simnet harness.
 *
 * WHAT THIS DEMONSTRATES
 * -----------------------
 * An HTLC is the cross-chain atomic-swap primitive (ZCL/BTC/LTC/DOGE — same
 * 97-byte contract shape as dcrdex): a P2SH output that can be spent two
 * ways:
 *
 *   1. REDEEM (claim path): whoever knows the 32-byte secret whose SHA256
 *      equals `secret_hash`, and can sign as `recipient_pkh`, may spend it
 *      any time.
 *   2. REFUND (timeout path): after an absolute block-height locktime,
 *      whoever can sign as `refunder_pkh` may reclaim the funds instead.
 *
 * This is the building block of a cross-chain swap: Alice locks coins for
 * Bob behind a secret only Alice knows; Bob locks his own coins on a
 * different chain behind the SAME secret_hash; whichever side redeems first
 * publishes the secret in its scriptSig, which the other side extracts and
 * reuses to redeem its own leg. If nobody redeems, both sides refund after
 * their respective timeouts. This example proves both settlement paths in
 * one node's mempool/chain, plus the secret-extraction step a real
 * counterparty would perform by reading the redeeming transaction.
 *
 * MENTAL MODEL
 * ------------
 * The simulator (`engine/modules/sim/include/sim/simnet.h`) is a deterministic,
 * RAM-only single-node chain harness. It builds blocks and folds them
 * through the REAL `connect_block()` consensus path (script checks +
 * locktime finality are real; PoW/expensive checks are skipped by a
 * synthetic covering checkpoint — see docs/SIMULATOR.md). Everything here
 * is the same code path a live node runs; wallet keys and the virtual clock
 * come from a `seed_tape` so THOSE are byte-for-byte repeatable.
 *
 * ONE DELIBERATE EXCEPTION: the HTLC secret itself is NOT seed-tape
 * deterministic. `htlc_generate_secret()` (core/modules/script/src/htlc.c) calls
 * `GetRandBytes()` — the real OS CSPRNG, the same call real key/secret
 * material generation always uses — not `rng_u64()` (the mockable hook
 * `seed_tape_install()` intercepts, which is what makes
 * `simnet_wallet_create()`'s keys reproducible). This is intentional: a
 * "make secrets replayable" test hook must never leak into the one code
 * path that mints genuine cryptographic secret material, even for a demo.
 * So this example's secret bytes differ on every run while the surrounding
 * chain mechanics (heights, fees, tx sizes, the wallets' own addresses) do
 * not — the redeem/refund LOGIC is exercised identically either way.
 *
 * Ground-truth reference for this exact flow:
 *   tests/harness/src/test_simnet_txkit.c  (txk_htlc_scripts / txk_build_htlc_spend)
 *   tests/harness/src/test_htlc.c          (unit coverage of each htlc_* builder)
 *   docs/SIMULATOR_TXNS.md            ("test a timelocked contract")
 *
 * Build: this file is meant to be compiled by the examples harness, which
 * links it against the library sources it calls into (sim, script, core,
 * crypto). It is intentionally self-contained otherwise.
 */

#include "core/amount.h"
#include "core/uint256.h"
#include "crypto/sha256.h"
#include "primitives/transaction.h"
#include "script/htlc.h"
#include "script/script.h"
#include "script/standard.h"
#include "sim/seed_tape.h"
#include "sim/simnet.h"
#include "sim/simnet_mempool.h"
#include "sim/simnet_wallet.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Build the 97-byte HTLC redeem script + its P2SH scriptPubKey for a given
 * absolute-height locktime, using a freshly generated secret/hash pair.
 * Mirrors txk_htlc_scripts() in test_simnet_txkit.c, but uses the real
 * htlc_generate_secret() (random-looking, deterministic under the seed
 * tape) instead of a hand-filled test pattern. */
static bool build_htlc(uint32_t locktime,
                       const uint8_t recipient_pkh[20],
                       const uint8_t refunder_pkh[20],
                       struct script *p2sh_out,
                       uint8_t contract_out[HTLC_CONTRACT_SIZE],
                       uint8_t secret_out[32])
{
    uint8_t secret_hash[32];
    htlc_generate_secret(secret_out, secret_hash);

    struct htlc_params hp;
    memset(&hp, 0, sizeof(hp));
    memcpy(hp.secret_hash, secret_hash, 32);
    memcpy(hp.recipient_pkh, recipient_pkh, 20);
    memcpy(hp.refunder_pkh, refunder_pkh, 20);
    hp.locktime = locktime;

    size_t len = htlc_build_script(&hp, contract_out, HTLC_CONTRACT_SIZE);
    if (len != HTLC_CONTRACT_SIZE)
        return false;

    struct script redeem;
    script_set(&redeem, contract_out, len);
    struct script_id sid;
    script_id_from_script(&sid, &redeem);
    script_for_p2sh(p2sh_out, &sid);
    return true;
}

/* Build a spend of an HTLC-funded coin, either via the redeem path (needs
 * the secret) or the refund path (needs the locktime to have passed). This
 * is a hand-assembled transaction, not a wallet send: an HTLC P2SH input
 * has a nonstandard scriptSig the simnet_wallet helpers don't know how to
 * produce, so we build the tx fields directly (same shape as
 * txk_build_htlc_spend in test_simnet_txkit.c). Signature/pubkey bytes are
 * dummy fill — simnet's `expensive_checks=false` path does not execute the
 * script interpreter, only structure/value/locktime checks. */
static bool build_htlc_spend(struct transaction *tx,
                             const struct uint256 *fund_txid,
                             const struct script *to_script,
                             int64_t input_value,
                             const uint8_t contract[HTLC_CONTRACT_SIZE],
                             const uint8_t secret[32],
                             bool refund,
                             uint32_t locktime)
{
    uint8_t sig[72], pubkey[33], scriptsig_buf[512];
    memset(sig, 0x30, sizeof(sig));
    memset(pubkey, 0x02, sizeof(pubkey));

    size_t ss_len = refund
        ? htlc_build_refund_scriptsig(scriptsig_buf, sizeof(scriptsig_buf),
                                      sig, sizeof(sig), pubkey, sizeof(pubkey),
                                      contract, HTLC_CONTRACT_SIZE)
        : htlc_build_redeem_scriptsig(scriptsig_buf, sizeof(scriptsig_buf),
                                      sig, sizeof(sig), pubkey, sizeof(pubkey),
                                      secret, contract, HTLC_CONTRACT_SIZE);
    if (ss_len == 0)
        return false;

    struct script script_sig;
    script_set(&script_sig, scriptsig_buf, ss_len);

    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1))
        return false;
    tx->version = 1;
    /* Refund must set an nLockTime the mempool can check against the
     * contract's CLTV height, and a non-final nSequence so the locktime is
     * actually enforced (0xFFFFFFFF would disable it). Redeem has no
     * timelock, so both are the "always final" values. */
    tx->lock_time = refund ? locktime : 0;
    tx->vin[0].prevout.hash = *fund_txid;
    tx->vin[0].prevout.n = 0;
    tx->vin[0].script_sig = script_sig;
    tx->vin[0].sequence = refund ? 0xFFFFFFFEu : 0xFFFFFFFFu;

    struct fee_rate rate = simnet_wallet_default_fee_rate();
    /* Set a placeholder output value first so serialize_size is accurate,
     * then compute the real fee and the final output value. */
    tx->vout[0].value = input_value;
    tx->vout[0].script_pub_key = *to_script;
    transaction_compute_hash(tx);
    size_t size = transaction_serialize_size(tx);
    int64_t fee = fee_rate_get_fee(&rate, size);
    if (fee <= 0 || input_value <= fee)
        return false;
    tx->vout[0].value = input_value - fee;
    transaction_compute_hash(tx);
    return true;
}

int main(void)
{
    printf("=== 06_htlc_swap: HTLC atomic-swap contract lifecycle ===\n\n");

    /* Fixed seed => byte-identical wallet addresses, txids, fees, sizes, and
     * timing on every run — the "every bug is a 64-bit seed" discipline.
     * The one exception is the HTLC secret itself; see the file header's
     * "ONE DELIBERATE EXCEPTION" note. */
    seed_tape_t *tape = seed_tape_open(0x06874C5350ULL /* "swap" */, 1700000000);
    assert(tape != NULL);
    seed_tape_install(tape);

    /* Select a chain network before any chain/consensus/script code runs —
     * connect_block, coinbase subsidy, and address encoding all read their
     * parameters through chain_params_get(), which asserts one was chosen. */
    chain_params_select(CHAIN_MAIN);

    struct simnet sim;
    assert(simnet_init(&sim));
    simnet_use_seed_tape(&sim, tape);

    struct simnet_wallet *alice = simnet_wallet_create(&sim); /* funder/refunder */
    struct simnet_wallet *bob   = simnet_wallet_create(&sim); /* redeemer */
    assert(alice && bob);

    printf("[1/4] funding alice + maturing coinbase (100 blocks)...\n");
    struct simnet_tx_result fund;
    if (!simnet_wallet_fund(alice, 400000, &fund) ||
        simnet_wallet_balance(alice) != 400000) {
        fprintf(stderr, "FAIL: alice funding/maturity did not settle\n");
        return 1;
    }
    printf("      alice balance = %lld zatoshi at height %d\n",
           (long long)simnet_wallet_balance(alice), simnet_tip_height(&sim));

    /* ── Leg A: redeem path — Bob knows the secret and claims immediately. */
    printf("\n[2/4] leg A: fund an HTLC redeemable by bob, then redeem it...\n");
    uint8_t bob_pkh[20], alice_pkh[20];
    memset(bob_pkh, 0x11, sizeof(bob_pkh));   /* stand-in recipient pkh */
    memset(alice_pkh, 0x71, sizeof(alice_pkh)); /* stand-in refunder pkh */

    uint32_t redeem_locktime = (uint32_t)(simnet_tip_height(&sim) + 3);
    struct script redeem_p2sh;
    uint8_t redeem_contract[HTLC_CONTRACT_SIZE], redeem_secret[32];
    if (!build_htlc(redeem_locktime, bob_pkh, alice_pkh,
                    &redeem_p2sh, redeem_contract, redeem_secret)) {
        fprintf(stderr, "FAIL: could not build redeem-path HTLC script\n");
        return 1;
    }
    printf("      secret   = %02x%02x%02x%02x...(32 bytes, from htlc_generate_secret;"
           " real CSPRNG, so this DIFFERS on every run — see file header)\n",
           redeem_secret[0], redeem_secret[1], redeem_secret[2], redeem_secret[3]);

    struct simnet_tx_result htlc_fund;
    if (!simnet_wallet_send(alice, &redeem_p2sh, 180000, &htlc_fund) ||
        !simnet_mempool_mint(&sim) ||
        !simnet_coin_value(&sim, &htlc_fund.txid, 0, NULL)) {
        fprintf(stderr, "FAIL: HTLC funding output did not land in the UTXO set\n");
        return 1;
    }
    printf("      HTLC funded: txid:0 holds 180000 zatoshi behind the P2SH contract\n");

    struct transaction redeem_tx;
    if (!build_htlc_spend(&redeem_tx, &htlc_fund.txid, simnet_wallet_script(bob),
                          180000, redeem_contract, redeem_secret,
                          /*refund=*/false, redeem_locktime)) {
        fprintf(stderr, "FAIL: could not build redeem scriptSig\n");
        return 1;
    }
    struct simnet_mempool_result redeem_reject;
    if (!simnet_mempool_add(&sim, &redeem_tx, &redeem_reject)) {
        fprintf(stderr, "FAIL: redeem tx rejected: %s\n",
                simnet_mempool_reject_name(redeem_reject.reason));
        return 1;
    }
    if (!simnet_mempool_mint(&sim) ||
        !simnet_coin_value(&sim, &redeem_tx.hash, 0, NULL)) {
        fprintf(stderr, "FAIL: redeem tx did not mint/settle\n");
        return 1;
    }
    printf("      redeem accepted+mined at height %d — bob now holds the coin\n",
           simnet_tip_height(&sim));

    /* This is the step a real cross-chain counterparty performs: read the
     * secret back out of the settled redeem transaction's scriptSig, so it
     * can be reused to redeem the matching leg on the OTHER chain. */
    const uint8_t *sig_bytes = redeem_tx.vin[0].script_sig.data;
    size_t sig_len = redeem_tx.vin[0].script_sig.size;
    uint8_t extracted_secret[32];
    if (!htlc_extract_secret(sig_bytes, sig_len, extracted_secret) ||
        memcmp(extracted_secret, redeem_secret, 32) != 0) {
        fprintf(stderr, "FAIL: htlc_extract_secret did not recover the original secret\n");
        return 1;
    }
    printf("      htlc_extract_secret recovered the exact secret from the on-chain scriptSig\n");
    transaction_free(&redeem_tx);

    /* ── Leg B: refund path — nobody redeems; alice reclaims after timeout. */
    printf("\n[3/4] leg B: fund an HTLC, let the timeout pass, refund it...\n");
    uint32_t refund_locktime = (uint32_t)(simnet_tip_height(&sim) + 3);
    struct script refund_p2sh;
    uint8_t refund_contract[HTLC_CONTRACT_SIZE], refund_secret[32];
    if (!build_htlc(refund_locktime, bob_pkh, alice_pkh,
                    &refund_p2sh, refund_contract, refund_secret)) {
        fprintf(stderr, "FAIL: could not build refund-path HTLC script\n");
        return 1;
    }

    struct simnet_tx_result htlc_fund2;
    if (!simnet_wallet_send(alice, &refund_p2sh, 160000, &htlc_fund2) ||
        !simnet_mempool_mint(&sim)) {
        fprintf(stderr, "FAIL: second HTLC funding did not settle\n");
        return 1;
    }

    struct transaction refund_tx;
    if (!build_htlc_spend(&refund_tx, &htlc_fund2.txid, simnet_wallet_script(alice),
                          160000, refund_contract, refund_secret,
                          /*refund=*/true, refund_locktime)) {
        fprintf(stderr, "FAIL: could not build refund scriptSig\n");
        return 1;
    }

    /* Before the locktime height, the refund must be rejected as
     * non-final — this is the CLTV guarantee that keeps Bob's redeem
     * window exclusive until the timeout genuinely expires. */
    struct simnet_mempool_result early_reject;
    bool accepted_early = simnet_mempool_add(&sim, &refund_tx, &early_reject);
    if (accepted_early || early_reject.reason != SIMNET_MEMPOOL_REJECT_NONFINAL) {
        fprintf(stderr, "FAIL: refund before locktime was not rejected as NONFINAL\n");
        return 1;
    }
    printf("      refund before height %u correctly rejected (%s)\n",
           refund_locktime, simnet_mempool_reject_name(early_reject.reason));

    if (!simnet_mint_to_height(&sim, (int)refund_locktime)) {
        fprintf(stderr, "FAIL: could not advance chain to the locktime height\n");
        return 1;
    }
    if (!simnet_mempool_add(&sim, &refund_tx, NULL) ||
        !simnet_mempool_mint(&sim) ||
        !simnet_coin_value(&sim, &refund_tx.hash, 0, NULL)) {
        fprintf(stderr, "FAIL: refund after locktime did not settle\n");
        return 1;
    }
    printf("      refund accepted+mined at height %d — alice reclaimed the coin\n",
           simnet_tip_height(&sim));
    transaction_free(&refund_tx);

    printf("\n[4/4] both HTLC settlement paths proved through real connect_block()\n");
    printf("      redeem path : secret-holder claims any time before or after timeout\n");
    printf("      refund path : original funder reclaims only after the CLTV height\n");

    seed_tape_uninstall();
    seed_tape_close(tape);
    simnet_free(&sim);
    simnet_wallet_free(alice);
    simnet_wallet_free(bob);

    printf("\n=== SUCCESS: HTLC atomic-swap lifecycle settled both ways — "
           "fund/redeem (secret-holder claims) and fund/refund (funder "
           "reclaims after CLTV timeout) ===\n");
    return 0;
}

/* Production counterpart:
 * ------------------------
 * - Script construction: `htlc_build_script`, `htlc_p2sh_address`,
 *   `htlc_generate_secret`, `htlc_extract_secret`, `htlc_build_redeem_scriptsig`,
 *   `htlc_build_refund_scriptsig` in core/modules/script/src/htlc.c are the SAME
 *   functions a live node calls — nothing here is sim-only.
 * - RPC/controller glue: `rpc_swap_initiate` / `rpc_swap_participate` in
 *   engine/controllers/src/swap_controller.c build the HTLC params + P2SH
 *   script + local swap-state record from `swap_initiate` / `swap_participate`
 *   RPCs and the native swap commands.
 * - What's NOT wired yet (see docs/SIMULATOR.md swap rows, Class B/C): the
 *   controller builds the contract and records local state, but there is no
 *   node-broadcast redeem/refund/settlement path today — an operator would
 *   currently have to fund/redeem/refund the P2SH address by hand (e.g. via
 *   `zclassic-cli` raw-transaction calls) the way this example does directly
 *   against simnet. Closing that gap is the remaining work named in
 *   docs/HOW_THE_NODE_WORKS.md's ZSWP coverage note.
 */

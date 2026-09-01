/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * 02_multi_io_p2sh — transaction shapes through the deterministic simulator.
 *
 * WHAT THIS DEMONSTRATES
 * -----------------------
 * z23's `simnet` harness (engine/modules/sim/) builds real transactions, feeds
 * them through the REAL consensus function `connect_block()`, and inspects
 * the resulting in-RAM UTXO set — no disk, no real PoW, no real funds, but
 * genuine consensus validation. This example builds two transaction SHAPES
 * that a wallet or any higher-level service must be able to construct:
 *
 *   1. A multi-input, multi-output transparent transaction: two separate
 *      matured coinbases are consolidated as inputs and split across two
 *      recipient outputs in a single transaction (proves the wallet's
 *      coin-selection and fee math handle >1 input and >1 output at once).
 *
 *   2. A P2SH (Pay-to-Script-Hash) spend: fund a hash-time-locked contract
 *      (HTLC) script, then redeem it with the real "reveal the secret and
 *      sign" scriptSig path (script/htlc.c) — the same 97-byte contract
 *      shape used by ZSWP cross-chain atomic swaps.
 *
 * MENTAL MODEL
 * ------------
 * A simnet block is minted at a height covered by a synthetic checkpoint,
 * so `connect_block()` runs with expensive_checks=false (skips PoW/script
 * execution) but still enforces every STRUCTURAL and VALUE consensus rule:
 * input/output balance, coinbase maturity, duplicate inputs, locktime
 * finality, etc. If a block here gets rejected, the bug is in how THIS
 * program built the block — not in the consensus code being bypassed.
 *
 * Everything is deterministic: one seed tape drives both the wallet keys
 * (via the RNG hook) and the virtual block clock (via the clock hook), so
 * this program produces byte-identical txids/fees/sizes on every run.
 *
 * BUILD / RUN
 * -----------
 *   make -C examples && ./examples/bin/02_multi_io_p2sh
 *
 * See docs/cookbook/02_multi_io_p2sh.md for expected output and API notes.
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

/* Print one result row in the same shape the test suite's cost table uses
 * (docs/SIMULATOR_TXNS.md), so learners can cross-reference. */
static void print_result(const char *label, const struct simnet_tx_result *r)
{
    char hex[65];
    uint256_get_hex(&r->txid, hex);
    printf("    %-28s txid=%s fee=%lld zats size=%zu bytes\n", label, hex,
           (long long)r->fee, r->tx_size);
}

/* Build the 97-byte HTLC contract + its P2SH wrapper. Fixed, non-secret
 * bytes are used for the recipient/refunder pubkey hashes and the secret —
 * this is a teaching example, not a real swap, so there is no randomness
 * to seed here (the secret is baked in and revealed on redeem, exactly as
 * a real HTLC redeem does). See core/modules/script/include/script/htlc.h. */
static bool build_htlc(uint32_t lock_height, struct script *p2sh_out,
                        uint8_t contract_out[HTLC_CONTRACT_SIZE],
                        uint8_t secret_out[32])
{
    for (size_t i = 0; i < 32; i++)
        secret_out[i] = (uint8_t)(0xC0 + i);

    struct htlc_params hp;
    memset(&hp, 0, sizeof(hp));
    struct sha256_ctx sctx;
    sha256_init(&sctx);
    sha256_write(&sctx, secret_out, 32);
    sha256_finalize(&sctx, hp.secret_hash);
    for (size_t i = 0; i < 20; i++) {
        hp.recipient_pkh[i] = (uint8_t)(0x21 + i);
        hp.refunder_pkh[i] = (uint8_t)(0x81 + i);
    }
    hp.locktime = lock_height;

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

/* Manually assemble a one-in/one-out spend of the P2SH output using the
 * REAL redeem scriptSig builder (reveal secret + signature-shaped bytes;
 * simnet skips signature verification, but the scriptSig SHAPE and the
 * secret preimage are exactly what a live redeem transmits). This is the
 * one piece of the toolkit that has no `simnet_wallet_*` convenience
 * wrapper (P2SH redemption is protocol-specific, not a generic wallet op),
 * so it is built by hand the same way tests/harness/src/test_simnet_txkit.c
 * does it. */
static bool build_htlc_redeem(struct transaction *tx,
                               const struct uint256 *fund_txid,
                               int64_t input_value,
                               const struct script *to_script,
                               const uint8_t contract[HTLC_CONTRACT_SIZE],
                               const uint8_t secret[32],
                               struct simnet_tx_result *out)
{
    uint8_t sig[72], pubkey[33], script_sig_bytes[512];
    memset(sig, 0x30, sizeof(sig));   /* placeholder DER-shaped signature */
    memset(pubkey, 0x02, sizeof(pubkey));

    size_t ss_len = htlc_build_redeem_scriptsig(
        script_sig_bytes, sizeof(script_sig_bytes), sig, sizeof(sig), pubkey,
        sizeof(pubkey), secret, contract, HTLC_CONTRACT_SIZE);
    if (ss_len == 0)
        return false;
    struct script script_sig;
    script_set(&script_sig, script_sig_bytes, ss_len);

    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1))
        return false;
    tx->version = 1;
    tx->lock_time = 0;
    tx->vin[0].prevout.hash = *fund_txid;
    tx->vin[0].prevout.n = 0;
    tx->vin[0].script_sig = script_sig;
    tx->vin[0].sequence = 0;
    tx->vout[0].script_pub_key = *to_script;

    /* Fee at the node wallet's default rate (see policy/fees.h), computed
     * against the tx's real serialized size, mirroring how the wallet
     * helpers in simnet_wallet.c size fees for you automatically. */
    struct fee_rate rate = simnet_wallet_default_fee_rate();
    size_t size = transaction_serialize_size(tx);
    int64_t fee = fee_rate_get_fee(&rate, size);
    if (fee <= 0 || input_value <= fee)
        return false;
    tx->vout[0].value = input_value - fee;
    transaction_compute_hash(tx);

    if (out) {
        out->txid = tx->hash;
        out->fee = fee;
        out->tx_size = transaction_serialize_size(tx);
        out->input_value = input_value;
        out->output_value = input_value - fee;
        out->change_value = 0;
        out->change_vout = UINT32_MAX;
    }
    return true;
}

int main(void)
{
    /* Fixed seed => byte-identical wallet keys, addresses, txids, fees, and
     * sizes on every run (docs/SIMULATOR.md "the simulator is deterministic"). */
    seed_tape_t *tape = seed_tape_open(0x02017054584B4954ULL, 1700000000);
    assert(tape != NULL);
    seed_tape_install(tape);

    /* Select a chain network before any chain/consensus/script code runs —
     * connect_block, coinbase subsidy, and address encoding all read their
     * parameters through chain_params_get(), which asserts one was chosen. */
    chain_params_select(CHAIN_MAIN);

    struct simnet sim;
    assert(simnet_init(&sim));
    simnet_use_seed_tape(&sim, tape);

    struct simnet_wallet *alice = simnet_wallet_create(&sim);
    struct simnet_wallet *bob = simnet_wallet_create(&sim);
    struct simnet_wallet *carol = simnet_wallet_create(&sim);
    assert(alice && bob && carol);

    printf("=== 02_multi_io_p2sh: multi-input/multi-output send + a P2SH "
           "HTLC fund/redeem ===\n");

    /* [1/4] Fund alice with TWO separate matured coinbases. simnet_wallet_fund
     * mints the coinbase then mines COINBASE_MATURITY (100) empty blocks so
     * the coin is real spendable value under the same predicate connect_block
     * enforces on the live chain — no shortcut. */
    printf("[1/4] minting two coinbases to alice (200 maturity blocks total)...\n");
    struct simnet_tx_result fund1, fund2;
    assert(simnet_wallet_fund(alice, 70000, &fund1));
    assert(simnet_wallet_fund(alice, 70000, &fund2));
    assert(simnet_wallet_balance(alice) == 140000);

    /* [2/4] Multi-input, multi-output transparent tx: request 60000 to bob
     * and 30000 to carol (90000 total) — more than either single 70000 UTXO
     * covers, so the wallet's coin selection must pull BOTH inputs into one
     * transaction, and the two named recipients force two distinct outputs
     * (plus a change output back to alice). */
    printf("[2/4] building multi-input/multi-output transparent tx"
           " (2 inputs -> 2 recipients + change)...\n");
    struct simnet_wallet_recipient recips[2] = {
        { .wallet = bob, .amount = 60000 },
        { .wallet = carol, .amount = 30000 },
    };
    struct simnet_tx_result multi;
    assert(simnet_wallet_send_many(alice, recips, 2, &multi));
    assert(multi.input_value == 140000); /* both funded coinbases consumed */
    assert(simnet_mempool_size(&sim) == 1);
    assert(simnet_mempool_mint(&sim));
    assert(simnet_wallet_balance(bob) == 60000);
    assert(simnet_wallet_balance(carol) == 30000);
    print_result("multi-input/multi-output", &multi);

    /* [3/4] Fund a P2SH HTLC output. The redeem lock height is 3 blocks
     * ahead purely so the contract is well-formed (this example only
     * exercises the redeem path, not the refund timeout path — see
     * test_simnet_txkit.c for the refund-before-timeout negative case). */
    printf("[3/4] funding a P2SH HTLC output (real 97-byte contract)...\n");
    struct simnet_tx_result fund3;
    assert(simnet_wallet_fund(alice, 200000, &fund3));

    uint32_t lock_height = (uint32_t)(simnet_tip_height(&sim) + 3);
    struct script p2sh_script;
    uint8_t contract[HTLC_CONTRACT_SIZE], secret[32];
    assert(build_htlc(lock_height, &p2sh_script, contract, secret));

    struct simnet_tx_result htlc_fund;
    assert(simnet_wallet_send(alice, &p2sh_script, 150000, &htlc_fund));
    assert(simnet_mempool_mint(&sim));
    int64_t p2sh_value = 0;
    assert(simnet_coin_value(&sim, &htlc_fund.txid, 0, &p2sh_value));
    assert(p2sh_value == 150000);
    print_result("P2SH HTLC fund", &htlc_fund);

    /* [4/4] Redeem the P2SH output by revealing the secret. This is the
     * "spend a script, not a plain pubkey hash" shape — connect_block's
     * structural/value checks apply exactly as they do for a P2PKH spend;
     * only the scriptSig contents differ. */
    printf("[4/4] redeeming the P2SH HTLC (reveal secret)...\n");
    struct transaction redeem_tx;
    struct simnet_tx_result redeem;
    assert(build_htlc_redeem(&redeem_tx, &htlc_fund.txid, 150000,
                             simnet_wallet_script(bob), contract, secret,
                             &redeem));
    assert(simnet_mempool_add(&sim, &redeem_tx, NULL));
    assert(simnet_mempool_mint(&sim));
    assert(simnet_coin_value(&sim, &redeem.txid, 0, NULL));
    print_result("P2SH HTLC redeem", &redeem);
    transaction_free(&redeem_tx);

    printf("\ntip height = %d\n", simnet_tip_height(&sim));

    simnet_wallet_free(alice);
    simnet_wallet_free(bob);
    simnet_wallet_free(carol);
    simnet_free(&sim);
    seed_tape_uninstall();
    seed_tape_close(tape);

    printf("=== SUCCESS: built, minted, and verified a multi-input/"
           "multi-output transparent send and a P2SH HTLC fund+redeem, "
           "all through connect_block() ===\n");
    return 0;
}

/* Production counterpart:
 * ------------------------
 * The simnet wallet helpers here are teaching stand-ins for the real node
 * wallet, which does the same coin-selection + fee math + P2SH bookkeeping
 * against the live chain and sqlite-backed UTXO projection instead of an
 * in-RAM view:
 *
 *   - Multi-input/multi-output send:
 *       wallet_create_transaction()   in contexts/wallet/modules/wallet/include/wallet/wallet.h
 *       (invoked by `z23 core wallet transaction send` or the
 *        `sendtoaddress` RPC path via
 *        contexts/wallet/controllers/src/wallet_controller.c and
 *        engine/controllers/src/transaction_controller.c)
 *   - P2SH HTLC fund + redeem (real cross-chain atomic swaps):
 *       script/htlc.h build/redeem/refund builders (already production code
 *       — this example calls the SAME functions the node calls), wired to
 *       swap state in engine/controllers/src/swap_controller.c
 *       (`swap_initiate`, `swap_participate`; on-chain broadcast/settlement
 *       of the redeem/refund path is still in flight — see
 *       docs/SIMULATOR.md's ZSWP action-coverage rows).
 */

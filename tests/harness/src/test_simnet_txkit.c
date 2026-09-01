/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet transaction toolkit coverage.
 */

#include "test/test_core.h"

#include "crypto/sha256.h"
#include "keys/key.h"
#include "script/interpreter.h"
#include "script/htlc.h"
#include "script/script_error.h"
#include "script/script_flags.h"
#include "script/standard.h"
#include "sim/seed_tape.h"
#include "sim/simnet.h"
#include "sim/simnet_mempool.h"
#include "sim/simnet_wallet.h"
#include "validation/sighash.h"
#include "validation/tx_verifier.h"

#include <stdio.h>
#include <string.h>

#define TXK_CHECK(name, expr) do {        \
    printf("%s... ", (name));             \
    if ((expr)) printf("OK\n");           \
    else { printf("FAIL\n"); failures++; } \
} while (0)

#define TXK_SAPLING_BRANCH_ID 0x76b809bbU

struct txk_cost_row {
    const char *kind;
    size_t size;
    int64_t fee;
    int blocks;
    int seconds;
};

static void txk_test_key(struct privkey *key, uint8_t tag)
{
    memset(key->vch, tag, sizeof(key->vch));
    key->fValid = true;
    key->fCompressed = true;
}

static void txk_add_cost(struct txk_cost_row *rows, size_t *nrows,
                         const char *kind,
                         const struct simnet_tx_result *r,
                         int blocks)
{
    rows[*nrows].kind = kind;
    rows[*nrows].size = r->tx_size;
    rows[*nrows].fee = r->fee;
    rows[*nrows].blocks = blocks;
    rows[*nrows].seconds = blocks * 150;
    (*nrows)++;
}

static void txk_print_cost_table(const struct txk_cost_row *rows, size_t nrows)
{
    printf("\nSIMNET_TXKIT_COST_TABLE_BEGIN\n");
    printf("| tx kind | size_bytes | fee_zcl | usable_blocks | virtual_minutes |\n");
    printf("|---|---:|---:|---:|---:|\n");
    for (size_t i = 0; i < nrows; i++) {
        printf("| %s | %zu | %.8f | %d | %.1f |\n",
               rows[i].kind, rows[i].size,
               (double)rows[i].fee / (double)COIN,
               rows[i].blocks, (double)rows[i].seconds / 60.0);
    }
    printf("SIMNET_TXKIT_COST_TABLE_END\n");
}

static bool txk_cost_table_matches(const struct txk_cost_row *rows,
                                   size_t nrows)
{
    static const struct txk_cost_row expected[] = {
        { "P2PKH single-in/single-out", 121, 1210, 1, 150 },
        { "multi-input consolidation", 164, 1640, 1, 150 },
        { "multi-output fan-out", 189, 1890, 1, 150 },
        { "2-of-2 P2SH multisig spend", 322, 5000, 1, 150 },
        { "OP_RETURN data carrier", 103, 1030, 1, 150 },
        { "OP_RETURN plus value output", 137, 1370, 1, 150 },
        { "P2SH HTLC fund", 162, 1620, 1, 150 },
        { "HTLC redeem path", 325, 3250, 1, 150 },
        { "HTLC refund path", 292, 2920, 3, 450 },
        { "chained spend after mint", 87, 870, 2, 300 },
    };
    if (nrows != sizeof(expected) / sizeof(expected[0]))
        return false;
    for (size_t i = 0; i < nrows; i++) {
        if (strcmp(rows[i].kind, expected[i].kind) != 0 ||
            rows[i].size != expected[i].size ||
            rows[i].fee != expected[i].fee ||
            rows[i].blocks != expected[i].blocks ||
            rows[i].seconds != expected[i].seconds)
            return false;
    }
    return true;
}

static bool txk_make_manual_spend(struct transaction *tx,
                                  const struct uint256 *prev_txid,
                                  uint32_t prev_vout,
                                  const struct script *script_sig,
                                  const struct script *to_script,
                                  int64_t out_value,
                                  uint32_t lock_time,
                                  uint32_t sequence)
{
    transaction_init(tx);
    if (!prev_txid || !to_script)
        return false;
    if (!transaction_alloc(tx, 1, 1))
        return false;
    tx->version = 1;
    tx->lock_time = lock_time;
    tx->vin[0].prevout.hash = *prev_txid;
    tx->vin[0].prevout.n = prev_vout;
    if (script_sig) {
        tx->vin[0].script_sig = *script_sig;
    } else {
        uint8_t sig[] = {0x00, 0x00};
        script_set(&tx->vin[0].script_sig, sig, sizeof(sig));
    }
    tx->vin[0].sequence = sequence;
    tx->vout[0].value = out_value;
    tx->vout[0].script_pub_key = *to_script;
    transaction_compute_hash(tx);
    return true;
}

static bool txk_finalize_manual_fee(struct transaction *tx,
                                    int64_t input_value,
                                    struct simnet_tx_result *out)
{
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

static void txk_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_write(&ctx, data, len);
    sha256_finalize(&ctx, out);
}

static bool txk_htlc_scripts(uint32_t lock_height,
                             struct script *p2sh_script,
                             uint8_t contract[HTLC_CONTRACT_SIZE],
                             uint8_t secret[32])
{
    for (size_t i = 0; i < 32; i++)
        secret[i] = (uint8_t)(0xA0 + i);

    struct htlc_params hp;
    memset(&hp, 0, sizeof(hp));
    txk_sha256(secret, 32, hp.secret_hash);
    for (size_t i = 0; i < 20; i++) {
        hp.recipient_pkh[i] = (uint8_t)(0x11 + i);
        hp.refunder_pkh[i] = (uint8_t)(0x71 + i);
    }
    hp.locktime = lock_height;

    size_t len = htlc_build_script(&hp, contract, HTLC_CONTRACT_SIZE);
    if (len != HTLC_CONTRACT_SIZE)
        return false;
    struct script redeem;
    script_set(&redeem, contract, len);
    struct script_id sid;
    script_id_from_script(&sid, &redeem);
    script_for_p2sh(p2sh_script, &sid);
    return true;
}

static bool txk_build_htlc_spend(struct transaction *tx,
                                 const struct uint256 *fund_txid,
                                 const struct script *to_script,
                                 int64_t input_value,
                                 const uint8_t contract[HTLC_CONTRACT_SIZE],
                                 const uint8_t secret[32],
                                 bool refund,
                                 uint32_t lock_height,
                                 struct simnet_tx_result *out)
{
    uint8_t sig[72], pubkey[33], ss[512];
    memset(sig, 0x30, sizeof(sig));
    memset(pubkey, 0x02, sizeof(pubkey));

    size_t ss_len = refund
        ? htlc_build_refund_scriptsig(ss, sizeof(ss), sig, sizeof(sig),
                                      pubkey, sizeof(pubkey), contract,
                                      HTLC_CONTRACT_SIZE)
        : htlc_build_redeem_scriptsig(ss, sizeof(ss), sig, sizeof(sig),
                                      pubkey, sizeof(pubkey), secret,
                                      contract, HTLC_CONTRACT_SIZE);
    if (ss_len == 0)
        return false;
    struct script script_sig;
    script_set(&script_sig, ss, ss_len);
    if (!txk_make_manual_spend(tx, fund_txid, 0, &script_sig, to_script,
                               input_value - 1,
                               refund ? lock_height : 0,
                               refund ? 0xFFFFFFFEu : 0u))
        return false;
    return txk_finalize_manual_fee(tx, input_value, out);
}

static bool txk_build_multisig_spend(
    struct transaction *tx, const struct uint256 *fund_txid,
    int64_t input_value, const struct script *to_script,
    const struct script *redeem, const struct privkey keys[2],
    struct simnet_tx_result *out, bool *tamper_rejected)
{
    if (!tx || !fund_txid || input_value <= 5000 || !to_script || !redeem ||
        !keys || !out || !tamper_rejected)
        return false;
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1))
        return false;
    tx->overwintered = true;
    tx->version = SAPLING_TX_VERSION;
    tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    tx->vin[0].prevout.hash = *fund_txid;
    tx->vin[0].prevout.n = 0;
    tx->vin[0].sequence = UINT32_MAX;
    tx->vout[0].value = input_value - 5000;
    tx->vout[0].script_pub_key = *to_script;

    struct precomputed_tx_data txdata;
    precompute_tx_data(tx, &txdata);
    struct sighash_type hash_type = { .raw = SIGHASH_ALL };
    struct uint256 sighash;
    if (!signature_hash(redeem, tx, 0, hash_type, input_value,
                        TXK_SAPLING_BRANCH_ID, &txdata, &sighash)) {
        transaction_free(tx);
        return false;
    }

    struct script *script_sig = &tx->vin[0].script_sig;
    script_init(script_sig);
    script_sig->data[script_sig->size++] = OP_0;
    for (size_t i = 0; i < 2; i++) {
        unsigned char signature[SIGNATURE_SIZE + 1];
        size_t signature_len = 0;
        if (!privkey_sign(&keys[i], &sighash, signature, &signature_len)) {
            transaction_free(tx);
            return false;
        }
        signature[signature_len++] = SIGHASH_ALL;
        if (!script_push_data(script_sig, signature, signature_len)) {
            transaction_free(tx);
            return false;
        }
    }
    if (!script_push_data(script_sig, redeem->data, redeem->size)) {
        transaction_free(tx);
        return false;
    }
    transaction_compute_hash(tx);

    struct script p2sh;
    struct script_id sid;
    script_id_from_script(&sid, redeem);
    script_for_p2sh(&p2sh, &sid);
    struct tx_sig_checker checker_ctx;
    tx_sig_checker_init(&checker_ctx, tx, 0, input_value,
                        TXK_SAPLING_BRANCH_ID, &txdata);
    struct sig_checker checker = tx_make_sig_checker(&checker_ctx);
    ScriptError script_error = SCRIPT_ERR_OK;
    bool valid = verify_script(script_sig, &p2sh,
                               SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC,
                               &checker, TXK_SAPLING_BRANCH_ID,
                               &script_error);
    struct script tampered = *script_sig;
    if (tampered.size > 10)
        tampered.data[10] ^= 0x01;
    script_error = SCRIPT_ERR_OK;
    *tamper_rejected = !verify_script(
        &tampered, &p2sh, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC,
        &checker, TXK_SAPLING_BRANCH_ID, &script_error);
    if (!valid || !*tamper_rejected) {
        transaction_free(tx);
        return false;
    }

    out->txid = tx->hash;
    out->fee = 5000;
    out->tx_size = transaction_serialize_size(tx);
    out->input_value = input_value;
    out->output_value = input_value - 5000;
    out->change_value = 0;
    out->change_vout = UINT32_MAX;
    return out->tx_size > 0;
}

int test_simnet_txkit(void)
{
    printf("\n=== simnet transaction toolkit ===\n");
    int failures = 0;
    struct txk_cost_row rows[16];
    size_t nrows = 0;

    seed_tape_t *tape = seed_tape_open(0x54584B4954ULL, 1700000000);
    TXK_CHECK("seed tape opens", tape != NULL);
    if (!tape)
        return failures + 1;
    seed_tape_install(tape);

    struct simnet sim;
    TXK_CHECK("simnet init", simnet_init(&sim));
    simnet_use_seed_tape(&sim, tape);
    TXK_CHECK("initial next block time is deterministic",
              simnet_next_block_time(&sim) == 1700000000u);

    struct simnet_wallet *alice = simnet_wallet_create(&sim);
    struct simnet_wallet *bob = simnet_wallet_create(&sim);
    struct simnet_wallet *carol = simnet_wallet_create(&sim);
    struct simnet_wallet *dave = simnet_wallet_create(&sim);
    struct simnet_wallet *erin = simnet_wallet_create(&sim);
    TXK_CHECK("wallets create deterministic addresses",
              alice && bob && carol && dave && erin &&
              strcmp(simnet_wallet_address(alice),
                     simnet_wallet_address(bob)) != 0);

    struct simnet_tx_result fund_a1;
    TXK_CHECK("fund alice and mature coinbase",
              simnet_wallet_fund(alice, 500000, &fund_a1) &&
              simnet_wallet_balance(alice) == 500000);

    struct simnet_tx_result single;
    TXK_CHECK("P2PKH single-in/single-out send enqueues",
              simnet_wallet_send_to_wallet(alice, bob, 50000, &single) &&
              simnet_mempool_size(&sim) == 1);
    txk_add_cost(rows, &nrows, "P2PKH single-in/single-out", &single, 1);
    TXK_CHECK("P2PKH single-in/single-out mints",
              simnet_mempool_mint(&sim) &&
              simnet_wallet_balance(bob) == 50000);

    struct simnet_tx_result fund_b1, fund_b2;
    TXK_CHECK("fund erin twice for multi-input",
              simnet_wallet_fund(erin, 70000, &fund_b1) &&
              simnet_wallet_fund(erin, 70000, &fund_b2));
    struct simnet_tx_result multi_in;
    TXK_CHECK("multi-input consolidation uses two inputs",
              simnet_wallet_send_to_wallet(erin, carol, 120000,
                                           &multi_in) &&
              multi_in.input_value == 140000);
    txk_add_cost(rows, &nrows, "multi-input consolidation", &multi_in, 1);
    TXK_CHECK("multi-input consolidation mints",
              simnet_mempool_mint(&sim) &&
              simnet_wallet_balance(carol) == 120000);

    struct simnet_tx_result fund_c1;
    TXK_CHECK("fund alice for fan-out",
              simnet_wallet_fund(alice, 300000, &fund_c1));
    struct simnet_wallet_recipient fanout[3] = {
        { .wallet = bob, .amount = 20000 },
        { .wallet = carol, .amount = 30000 },
        { .wallet = dave, .amount = 40000 },
    };
    struct simnet_tx_result fan;
    TXK_CHECK("multi-output fan-out enqueues",
              simnet_wallet_send_many(alice, fanout, 3, &fan));
    txk_add_cost(rows, &nrows, "multi-output fan-out", &fan, 1);
    TXK_CHECK("multi-output fan-out mints",
              simnet_mempool_mint(&sim) &&
              simnet_wallet_balance(dave) == 40000);

    struct privkey multisig_keys[2];
    struct pubkey multisig_pubkeys[2];
    txk_test_key(&multisig_keys[0], 0x21);
    txk_test_key(&multisig_keys[1], 0x42);
    bool multisig_keys_ready =
        privkey_get_pubkey(&multisig_keys[0], &multisig_pubkeys[0]) &&
        privkey_get_pubkey(&multisig_keys[1], &multisig_pubkeys[1]);
    struct script multisig_redeem, multisig_p2sh;
    struct script_id multisig_sid;
    script_for_multisig(&multisig_redeem, 2, multisig_pubkeys, 2);
    script_id_from_script(&multisig_sid, &multisig_redeem);
    script_for_p2sh(&multisig_p2sh, &multisig_sid);

    struct simnet_tx_result multisig_fund;
    TXK_CHECK("fund 2-of-2 P2SH multisig and mint",
              multisig_keys_ready &&
              simnet_wallet_fund(alice, 250000, NULL) &&
              simnet_wallet_send(alice, &multisig_p2sh, 150000,
                                 &multisig_fund) &&
              simnet_mempool_mint(&sim) &&
              simnet_coin_value(&sim, &multisig_fund.txid, 0, NULL));
    struct transaction multisig_spend;
    struct simnet_tx_result multisig_spend_result;
    bool multisig_tamper_rejected = false;
    bool multisig_spend_ready = txk_build_multisig_spend(
        &multisig_spend, &multisig_fund.txid, 150000,
        simnet_wallet_script(bob), &multisig_redeem,
        multisig_keys, &multisig_spend_result,
        &multisig_tamper_rejected);
    TXK_CHECK("2-of-2 spend passes consensus interpreter",
              multisig_spend_ready &&
              multisig_tamper_rejected);
    if (multisig_spend_ready)
        txk_add_cost(rows, &nrows, "2-of-2 P2SH multisig spend",
                     &multisig_spend_result, 1);
    TXK_CHECK("2-of-2 signed spend enqueues and mints",
              multisig_spend_ready &&
              simnet_mempool_add(&sim, &multisig_spend, NULL) &&
              simnet_mempool_mint(&sim) &&
              simnet_coin_value(&sim, &multisig_spend_result.txid, 0,
                                NULL));
    if (multisig_spend_ready)
        transaction_free(&multisig_spend);

    struct simnet_tx_result fund_d1;
    TXK_CHECK("fund alice for OP_RETURN",
              simnet_wallet_fund(alice, 120000, &fund_d1));
    const uint8_t opret_payload[] = { 't', 'x', 'k', 'i', 't' };
    struct simnet_tx_result opret_only;
    TXK_CHECK("OP_RETURN without user value output enqueues",
              simnet_wallet_op_return(alice, opret_payload,
                                      sizeof(opret_payload), NULL,
                                      &opret_only));
    txk_add_cost(rows, &nrows, "OP_RETURN data carrier", &opret_only, 1);
    TXK_CHECK("OP_RETURN without user value output mints",
              simnet_mempool_mint(&sim) &&
              simnet_coin_value(&sim, &opret_only.txid,
                                opret_only.change_vout, NULL));

    struct simnet_tx_result fund_d2;
    TXK_CHECK("fund alice for OP_RETURN plus value",
              simnet_wallet_fund(alice, 140000, &fund_d2));
    struct simnet_wallet_recipient opret_value = {
        .wallet = bob,
        .amount = 25000,
    };
    struct simnet_tx_result opret_with_value;
    TXK_CHECK("OP_RETURN with value output enqueues",
              simnet_wallet_op_return(alice, opret_payload,
                                      sizeof(opret_payload), &opret_value,
                                      &opret_with_value));
    txk_add_cost(rows, &nrows, "OP_RETURN plus value output",
                 &opret_with_value, 1);
    TXK_CHECK("OP_RETURN with value output mints",
              simnet_mempool_mint(&sim) &&
              simnet_wallet_balance(bob) >= 75000);

    struct simnet_tx_result fund_e1;
    TXK_CHECK("fund alice for HTLC", simnet_wallet_fund(alice, 400000, &fund_e1));
    uint8_t contract[HTLC_CONTRACT_SIZE], secret[32];
    struct script htlc_p2sh;
    uint32_t lock_height = (uint32_t)(simnet_tip_height(&sim) + 3);
    TXK_CHECK("build real HTLC P2SH script",
              txk_htlc_scripts(lock_height, &htlc_p2sh, contract, secret));

    struct simnet_tx_result htlc_fund;
    TXK_CHECK("fund P2SH HTLC through wallet/mempool",
              simnet_wallet_send(alice, &htlc_p2sh, 180000, &htlc_fund));
    txk_add_cost(rows, &nrows, "P2SH HTLC fund", &htlc_fund, 1);
    TXK_CHECK("P2SH HTLC fund mints",
              simnet_mempool_mint(&sim) &&
              simnet_coin_value(&sim, &htlc_fund.txid, 0, NULL));

    struct transaction redeem_tx;
    struct simnet_tx_result htlc_redeem;
    TXK_CHECK("build HTLC redeem-path spend",
              txk_build_htlc_spend(&redeem_tx, &htlc_fund.txid,
                                   simnet_wallet_script(bob), 180000,
                                   contract, secret, false, 0,
                                   &htlc_redeem));
    TXK_CHECK("HTLC redeem-path spend enqueues",
              simnet_mempool_add(&sim, &redeem_tx, NULL));
    txk_add_cost(rows, &nrows, "HTLC redeem path", &htlc_redeem, 1);
    TXK_CHECK("HTLC redeem-path spend mints",
              simnet_mempool_mint(&sim) &&
              simnet_coin_value(&sim, &htlc_redeem.txid, 0, NULL));
    transaction_free(&redeem_tx);

    uint8_t refund_contract[HTLC_CONTRACT_SIZE], refund_secret[32];
    struct script refund_p2sh;
    uint32_t refund_lock_height = (uint32_t)(simnet_tip_height(&sim) + 3);
    TXK_CHECK("build refund HTLC P2SH script",
              txk_htlc_scripts(refund_lock_height, &refund_p2sh,
                               refund_contract, refund_secret));

    struct simnet_tx_result htlc_fund_refund;
    TXK_CHECK("fund second P2SH HTLC for refund",
              simnet_wallet_send(alice, &refund_p2sh, 160000,
                                 &htlc_fund_refund) &&
              simnet_mempool_mint(&sim));

    struct transaction refund_tx;
    struct simnet_tx_result htlc_refund;
    TXK_CHECK("build HTLC refund-path spend",
              txk_build_htlc_spend(&refund_tx, &htlc_fund_refund.txid,
                                   simnet_wallet_script(alice), 160000,
                                   refund_contract, refund_secret, true,
                                   refund_lock_height,
                                   &htlc_refund));
    struct simnet_mempool_result reject_refund;
    bool refund_before = simnet_mempool_add(&sim, &refund_tx, &reject_refund);
    TXK_CHECK("HTLC refund before lock height is rejected",
              !refund_before &&
              reject_refund.reason == SIMNET_MEMPOOL_REJECT_NONFINAL);
    TXK_CHECK("advance to lock height",
              simnet_mint_to_height(&sim, (int)refund_lock_height));
    TXK_CHECK("HTLC refund after lock height enqueues",
              simnet_mempool_add(&sim, &refund_tx, NULL));
    txk_add_cost(rows, &nrows, "HTLC refund path", &htlc_refund, 3);
    TXK_CHECK("HTLC refund after lock height mints",
              simnet_mempool_mint(&sim) &&
              simnet_coin_value(&sim, &htlc_refund.txid, 0, NULL));
    transaction_free(&refund_tx);

    struct simnet_tx_result fund_f1;
    TXK_CHECK("fund alice for chained-spend policy",
              simnet_wallet_fund(alice, 110000, &fund_f1));
    struct simnet_tx_result chain_first;
    TXK_CHECK("first chained spend enqueues",
              simnet_wallet_send_to_wallet(alice, bob, 45000,
                                           &chain_first));

    struct transaction chain_second;
    struct simnet_tx_result chain_second_res;
    TXK_CHECK("build spend of same-batch output",
              txk_make_manual_spend(&chain_second, &chain_first.txid, 0,
                                    NULL, simnet_wallet_script(carol),
                                    44000, 0, 0xFFFFFFFFu) &&
              txk_finalize_manual_fee(&chain_second, 45000,
                                      &chain_second_res));
    struct simnet_mempool_result chain_reject;
    bool chain_same_batch = simnet_mempool_add(&sim, &chain_second,
                                               &chain_reject);
    TXK_CHECK("same-batch chained spend is rejected as missing input",
              !chain_same_batch &&
              chain_reject.reason == SIMNET_MEMPOOL_REJECT_MISSING_INPUT &&
              simnet_mempool_size(&sim) == 1);
    TXK_CHECK("mint first chained spend",
              simnet_mempool_mint(&sim));
    TXK_CHECK("chained spend enqueues after first mint",
              simnet_mempool_add(&sim, &chain_second, NULL));
    txk_add_cost(rows, &nrows, "chained spend after mint",
                 &chain_second_res, 2);
    TXK_CHECK("chained spend after mint mints",
              simnet_mempool_mint(&sim) &&
              simnet_coin_value(&sim, &chain_second_res.txid, 0, NULL));
    transaction_free(&chain_second);

    struct transaction missing_tx;
    struct uint256 bogus;
    memset(bogus.data, 0xAB, sizeof(bogus.data));
    TXK_CHECK("build missing-input negative tx",
              txk_make_manual_spend(&missing_tx, &bogus, 0, NULL,
                                    simnet_wallet_script(alice), 1, 0,
                                    0xFFFFFFFFu));
    struct simnet_mempool_result missing_reject;
    bool missing_ok = simnet_mempool_add(&sim, &missing_tx,
                                         &missing_reject);
    TXK_CHECK("mempool rejects missing input with typed reason",
              !missing_ok &&
              missing_reject.reason == SIMNET_MEMPOOL_REJECT_MISSING_INPUT);
    transaction_free(&missing_tx);

    struct simnet_tx_result poor_send;
    TXK_CHECK("send exceeding balance fails",
              !simnet_wallet_send_to_wallet(dave, alice, 999999999,
                                            &poor_send));

    struct simnet_tx_result fund_overflow;
    TXK_CHECK("fund dave for value-overflow negative",
              simnet_wallet_fund(dave, 30000, &fund_overflow));
    struct transaction overflow_tx;
    TXK_CHECK("build value-overflow negative tx",
              txk_make_manual_spend(&overflow_tx, &fund_overflow.txid, 0,
                                    NULL, simnet_wallet_script(alice),
                                    30001, 0, 0xFFFFFFFFu));
    struct simnet_mempool_result overflow_reject;
    bool overflow_ok = simnet_mempool_add(&sim, &overflow_tx,
                                          &overflow_reject);
    TXK_CHECK("mempool rejects value overflow with typed reason",
              !overflow_ok &&
              overflow_reject.reason == SIMNET_MEMPOOL_REJECT_VALUE_OVERFLOW);
    transaction_free(&overflow_tx);

    TXK_CHECK("cost table row count", nrows == 10);
    TXK_CHECK("cost table values are deterministic",
              txk_cost_table_matches(rows, nrows));
    txk_print_cost_table(rows, nrows);

    simnet_wallet_free(alice);
    simnet_wallet_free(bob);
    simnet_wallet_free(carol);
    simnet_wallet_free(dave);
    simnet_wallet_free(erin);
    simnet_free(&sim);
    seed_tape_uninstall();
    seed_tape_close(tape);

    return failures;
}

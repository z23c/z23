/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves the "input value out of range" consensus reject through simnet's
 * REAL connect_block() — a transaction whose summed input value exceeds
 * MAX_MONEY must be rejected with "bad-txns-inputvalues-outofrange", while
 * the exact-boundary and ordinary in-range variants are accepted.
 *
 * The predicate under test is the CONTEXTUAL input-value range check in
 * connect_block.c: for every non-coinbase tx it computes
 * value_in = coins_view_cache_get_value_in(view, tx) and rejects with
 * "bad-txns-inputvalues-outofrange" when value_in < 0 or !MoneyRange(value_in)
 * (connect_block.c:504-524). get_value_in (core/modules/coins/src/coins_view.c:429)
 * sums the transparent prevout values (looked up from the UTXO set — the
 * CONTEXT a standalone tx does not have) PLUS the tx's positive Sapling
 * value_balance, and returns -1 the moment that cumulative total leaves
 * [0, MAX_MONEY] (coins_view.c:444-457).
 *
 * Why value_balance is the vehicle: a single UTXO can never carry an
 * out-of-range value on its own — every coin in the view was minted through
 * connect_block, which caps each coinbase output at the block subsidy
 * (bad-cb-amount, connect_block.c:748). Reaching value_in > MAX_MONEY with
 * transparent coins alone would need ~1.7M summed inputs. A Sapling
 * value_balance that unshields value from the pool is the real,
 * consensus-legitimate way a tx's total input value can exceed a single coin.
 *
 * The key distinction this test pins is CONTEXTUAL vs CONTEXT-FREE. Before
 * the value_in check, connect_block runs check_block -> check_transaction
 * (connect_block.c:191), whose context-free structural pass
 * (domain/consensus/src/tx_structural.c) already bounds value_balance itself
 * to <= MAX_MONEY (bad-txns-valuebalance-toolarge, tx_structural.c:170) and
 * bounds the SHIELDED-only input total vpub_new + value_balance to MAX_MONEY
 * (bad-txns-txintotal-toolarge, tx_structural.c:244-252) — but it CANNOT see
 * the transparent prevout values. So a tx with value_balance <= MAX_MONEY
 * plus a real transparent input passes the structural gate and is caught only
 * later by connect_block's contextual get_value_in, which is exactly the
 * bad-txns-inputvalues-outofrange path. The tx therefore carries value_balance
 * != 0, which requires a shielded component to exist (bad-txns-valuebalance-
 * nonzero, tx_structural.c:162); a single zeroed Sapling output description
 * satisfies that. connect_block runs expensive_checks=false under the sim's
 * synthetic checkpoint (no Groth16/binding-sig verification), and the default
 * hashFinalSaplingRoot enforcement is off, so the zeroed output is inert here.
 * We lower the Sapling activation height so this is a Sapling-active tx.
 *
 * Three cases, each in its own freshly-initialized simnet (connect_block
 * mutates the shared coins_view tx-by-tx, so a fresh sim keeps each case
 * independent — same reasoning as test_simnet_doublespend.c):
 *   1. Positive control (ordinary): a transparent spend, value_balance == 0,
 *      value_in well inside range -> ACCEPTED, tip advances.
 *   2. Boundary positive control: value_balance chosen so value_in == exactly
 *      MAX_MONEY -> ACCEPTED (MoneyRange upper bound is inclusive). This makes
 *      the negative a true off-by-one, not a vacuous pass.
 *   3. Negative: value_balance chosen so value_in == MAX_MONEY + 1 -> REJECTED
 *      with "bad-txns-inputvalues-outofrange", and the tip does NOT advance.
 *
 * Per the harness contract (simnet.h): if a mint is rejected, the fix is
 * always in this file's block construction, never in connect_block.
 */

#include "test/test_core.h"
#include "validation/main_constants.h"

#include "sim/simnet.h"
#include "core/amount.h"
/* SAPLING_TX_VERSION / SAPLING_VERSION_GROUP_ID come from
 * primitives/transaction.h (included directly by this file). */
/* COINBASE_MATURITY comes from validation/main_constants.h, already pulled in
 * included directly by this file. */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define IVR_CHECK(name, expr) do {        \
    printf("%s... ", (name));             \
    if ((expr)) printf("OK\n");           \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Transparent spend of `in_txid`:`in_n` paying `out_value` to a placeholder
 * P2PKH-shaped script, carrying an explicit Sapling `value_balance`. Same tx
 * shape as ds_make_spend() in test_simnet_doublespend.c; the only addition is
 * setting value_balance (positive = value unshielded from the Sapling pool,
 * which get_value_in folds into the tx's total input value). simnet mints at
 * a checkpoint-covered height so connect_block runs expensive_checks=false —
 * scriptSig content and Sapling proofs are never verified, so a bare
 * value_balance with no shielded spends/outputs still exercises exactly the
 * value_in MoneyRange arithmetic we are targeting. `marker` varies the
 * scriptSig so distinct spends get distinct txids.
 *
 * When `value_balance` != 0 the tx must carry a shielded component or the
 * structural gate rejects it (bad-txns-valuebalance-nonzero); the caller
 * passes a zeroed `shielded_out` (which it OWNS — this function only borrows
 * the pointer; simnet's sim_free_tx frees vin/vout only, never the shielded
 * array, so a caller-owned stack object is correct and leak-free). A Sapling
 * value_balance also implies a Sapling-shaped tx, so we set the overwintered
 * Sapling version + group id. */
static bool ivr_make_spend(struct transaction *tx, const struct uint256 *in_txid,
                           uint32_t in_n, int64_t out_value,
                           int64_t value_balance,
                           struct output_description *shielded_out,
                           uint8_t marker)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1))
        return false;
    if (value_balance != 0) {
        tx->overwintered = true;
        tx->version = SAPLING_TX_VERSION;          /* 4 */
        tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    } else {
        tx->version = SAPLING_TX_VERSION;
    }
    tx->value_balance = value_balance;
    if (shielded_out) {
        memset(shielded_out, 0, sizeof(*shielded_out));
        tx->v_shielded_output = shielded_out;
        tx->num_shielded_output = 1;
    }
    tx->vin[0].prevout.hash = *in_txid;
    tx->vin[0].prevout.n = in_n;
    uint8_t sig[] = {0x00, marker};
    script_set(&tx->vin[0].script_sig, sig, sizeof(sig));
    tx->vin[0].sequence = 0xFFFFFFFF;
    tx->vout[0].value = out_value;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx->vout[0].script_pub_key, pk, sizeof(pk));
    transaction_compute_hash(tx);
    return true;
}

/* Mint `txs` while redirecting stderr to a scratch file, so the reject
 * reason connect_block logs via LOG_FAIL ("connect_block rejected height
 * %d: %s", sim_mint_block in engine/modules/sim/src/simnet.c) can be inspected without
 * touching simnet.c — its public API does not surface validation_state.
 * Identical plumbing to ds_mint_capture() in test_simnet_doublespend.c. */
static bool ivr_mint_capture(struct simnet *sim, struct transaction *txs,
                             size_t ntx, char *out_reason,
                             size_t out_reason_len)
{
    if (out_reason && out_reason_len > 0)
        out_reason[0] = '\0';

    mkdir("./test-tmp", 0755);
    char path[256];
    snprintf(path, sizeof(path),
             "./test-tmp/simnet_input_value_range_stderr_%d.log", (int)getpid());

    fflush(stderr);
    int saved_fd = dup(STDERR_FILENO);
    FILE *capf = (saved_fd >= 0) ? fopen(path, "w+") : NULL;
    if (!capf) {
        if (saved_fd >= 0)
            close(saved_fd);
        return simnet_mint_txs(sim, txs, ntx);
    }
    dup2(fileno(capf), STDERR_FILENO);

    bool ok = simnet_mint_txs(sim, txs, ntx);

    fflush(stderr);
    dup2(saved_fd, STDERR_FILENO);
    close(saved_fd);

    if (out_reason && out_reason_len > 0) {
        long sz = ftell(capf);
        if (sz > 0) {
            rewind(capf);
            size_t want = (size_t)sz < out_reason_len - 1
                            ? (size_t)sz : out_reason_len - 1;
            size_t rd = fread(out_reason, 1, want, capf);
            out_reason[rd] = '\0';
        }
    }
    fclose(capf);
    unlink(path);
    return ok;
}

/* Mint a coinbase, then advance the honest chain so the NEXT mint is exactly
 * at coinbase maturity for that coinbase — the spend must be judged on its
 * input value, not rejected as a premature-coinbase spend. Returns the
 * coinbase txid and its output value via out params. */
static bool ivr_fund_matured_coinbase(struct simnet *sim, struct uint256 *out_cb,
                                      int64_t *out_value)
{
    if (!simnet_mint_coinbase(sim, out_cb))
        return false;
    int cb_height = simnet_tip_height(sim);
    if (!simnet_mint_to_height(sim, cb_height + COINBASE_MATURITY - 1))
        return false;
    return simnet_coin_value(sim, out_cb, 0, out_value);
}

int test_simnet_input_value_range(void)
{
    printf("\n=== simnet input value out of range rejection "
           "(connect_block) ===\n");
    int failures = 0;

    /* ── Positive control (ordinary): a transparent spend with
     * value_balance == 0 and value_in well inside range is accepted. ──── */
    {
        struct simnet sim;
        IVR_CHECK("ordinary: simnet init", simnet_init(&sim));
        simnet_activate_sapling_at(&sim, simnet_tip_height(&sim) + 1);

        struct uint256 cb;
        int64_t cb_value = 0;
        IVR_CHECK("ordinary: fund matured coinbase",
                  ivr_fund_matured_coinbase(&sim, &cb, &cb_value) &&
                  cb_value > 0);
        int pre_height = simnet_tip_height(&sim);

        struct transaction spend;
        IVR_CHECK("ordinary: build in-range spend",
                  ivr_make_spend(&spend, &cb, 0, cb_value / 2, 0, NULL, 0xA0));
        struct transaction txs[1] = { spend };
        char reason[256];
        bool ok = ivr_mint_capture(&sim, txs, 1, reason, sizeof(reason));
        IVR_CHECK("ordinary: in-range spend is accepted", ok);
        IVR_CHECK("ordinary: tip advances", simnet_tip_height(&sim) == pre_height + 1);
        IVR_CHECK("ordinary: spent coinbase output is consumed",
                  !simnet_coin_exists(&sim, &cb));

        simnet_free(&sim);
    }

    /* ── Boundary positive control: value_balance pushes value_in to
     * EXACTLY MAX_MONEY. MoneyRange is inclusive, so this is accepted —
     * proving the negative below is a true off-by-one, not vacuous. ────── */
    {
        struct simnet sim;
        IVR_CHECK("boundary: simnet init", simnet_init(&sim));
        simnet_activate_sapling_at(&sim, simnet_tip_height(&sim) + 1);

        struct uint256 cb;
        int64_t cb_value = 0;
        IVR_CHECK("boundary: fund matured coinbase",
                  ivr_fund_matured_coinbase(&sim, &cb, &cb_value) &&
                  cb_value > 0 && cb_value < MAX_MONEY);
        int pre_height = simnet_tip_height(&sim);

        /* value_in = cb_value + value_balance == MAX_MONEY */
        int64_t vb_boundary = MAX_MONEY - cb_value;
        IVR_CHECK("boundary: value_balance is a valid positive amount",
                  vb_boundary > 0);
        struct transaction spend;
        struct output_description sout;
        IVR_CHECK("boundary: build value_in == MAX_MONEY spend",
                  ivr_make_spend(&spend, &cb, 0, 1000, vb_boundary, &sout, 0xB0));
        struct transaction txs[1] = { spend };
        char reason[256];
        bool ok = ivr_mint_capture(&sim, txs, 1, reason, sizeof(reason));
        IVR_CHECK("boundary: value_in == MAX_MONEY is accepted", ok);
        IVR_CHECK("boundary: tip advances",
                  simnet_tip_height(&sim) == pre_height + 1);

        simnet_free(&sim);
    }

    /* ── Negative: value_balance pushes value_in to MAX_MONEY + 1, one
     * atoshi past the range. connect_block must reject the whole block
     * with "bad-txns-inputvalues-outofrange" and the tip must not move. ── */
    {
        struct simnet sim;
        IVR_CHECK("negative: simnet init", simnet_init(&sim));
        simnet_activate_sapling_at(&sim, simnet_tip_height(&sim) + 1);

        struct uint256 cb;
        int64_t cb_value = 0;
        IVR_CHECK("negative: fund matured coinbase",
                  ivr_fund_matured_coinbase(&sim, &cb, &cb_value) &&
                  cb_value > 0 && cb_value < MAX_MONEY);
        int pre_height = simnet_tip_height(&sim);

        /* value_in = cb_value + value_balance == MAX_MONEY + 1 (out of range).
         * Each summand is individually in range, so the rejection comes from
         * the cumulative MoneyRange guard in get_value_in, not a per-input
         * value check. */
        int64_t vb_over = MAX_MONEY - cb_value + 1;
        IVR_CHECK("negative: value_balance is individually in range",
                  MoneyRange(vb_over));
        struct transaction spend;
        struct output_description sout;
        IVR_CHECK("negative: build value_in == MAX_MONEY + 1 spend",
                  ivr_make_spend(&spend, &cb, 0, 1000, vb_over, &sout, 0xC0));
        struct transaction txs[1] = { spend };
        char reason[256];
        bool ok = ivr_mint_capture(&sim, txs, 1, reason, sizeof(reason));
        IVR_CHECK("negative: out-of-range input value is rejected", !ok);
        IVR_CHECK("negative: reject reason is bad-txns-inputvalues-outofrange",
                  strstr(reason, "bad-txns-inputvalues-outofrange") != NULL);
        IVR_CHECK("negative: tip does not advance to the bad block",
                  simnet_tip_height(&sim) == pre_height);
        IVR_CHECK("negative: coinbase output remains unspent after rejection",
                  simnet_coin_exists(&sim, &cb));

        /* Not vacuous: an honest block still mints after the rejection. */
        struct uint256 honest_cb;
        IVR_CHECK("negative: honest block still mints after rejection",
                  simnet_mint_coinbase(&sim, &honest_cb) &&
                  simnet_tip_height(&sim) == pre_height + 1);

        simnet_free(&sim);
    }

    printf("=== simnet_input_value_range: %d failures ===\n", failures);
    return failures;
}

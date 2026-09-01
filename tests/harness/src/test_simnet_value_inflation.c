/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves OUTPUT VALUE INFLATION rejection through simnet's real
 * connect_block() — the "no money creation" consensus invariant that must
 * be exercised deterministically before live ZCL.
 *
 * A non-coinbase transaction whose total output value EXCEEDS its total
 * input value would mint money from nothing. connect_block computes
 *   value_in  = coins_view_cache_get_value_in(view, tx)
 *   value_out = transaction_get_value_out(tx)
 * and rejects with "bad-txns-in-belowout" when value_in < value_out
 * (core/modules/validation/src/connect_block.c:527-531). The whole block is rejected
 * (validation_state_dos returns false), so the tip never advances to it.
 *
 * This is distinct from the classes already covered elsewhere:
 *   - bad-cb-amount            : the COINBASE over-claims the subsidy+fees
 *                                (byzantine harness), a block-level check.
 *   - bad-txns-vout-negative / -toolarge : a single output is out of the
 *                                MoneyRange [0, MAX_MONEY] (value-range).
 * Here every individual output IS in range and the coinbase is honest; the
 * defect is purely that the SUM of a spend's outputs is larger than the SUM
 * of what it consumes.
 *
 * Two cases, both against the REAL validator:
 *   1. Negative: a matured coinbase worth 1_000_000 zatoshi is spent to a
 *      single output of 2_000_000 (1_000_000 conjured). connect_block
 *      rejects with bad-txns-in-belowout; the tip does not advance.
 *   2. Positive control: the SAME matured coinbase, same shape, spent to an
 *      output of 900_000 (a 100_000 fee, inputs > outputs) is ACCEPTED and
 *      the tip advances — so the negative is not vacuously passing.
 *
 * The two cases each run in their OWN freshly-initialized simnet: case 1
 * leaves connect_block's mutable `view` cache in a partially-walked state
 * on the rejected block (it reuses one cache across mints — see the note in
 * test_simnet_doublespend.c), so a clean sim is the faithful way to assert
 * the positive control accepts the identical outpoint.
 *
 * The equal-value boundary (value_in == value_out, a zero-fee tx) is the
 * first ACCEPTED point — connect_block rejects only strict value_in <
 * value_out — and is asserted as a third case so the exact threshold is
 * pinned.
 *
 * Per the harness contract (simnet.h): if a mint is rejected, the fix is
 * always in this file's block construction, never in connect_block.
 */

#include "test/test_core.h"
#include "validation/main_constants.h"

#include "sim/simnet.h"
/* COINBASE_MATURITY comes from consensus/consensus.h, already pulled in
 * included directly by this file. */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The value simnet mints into every synthetic coinbase output
 * (SIM_COINBASE_VALUE in engine/modules/sim/src/simnet.c). Kept in sync as a local
 * constant so the inflation math below reads plainly; if the harness value
 * changes, the positive control (< this) and negative (> this) still
 * bracket it as long as this mirror is updated. */
#define VI_COINBASE_VALUE 1000000

#define VI_CHECK(name, expr) do {         \
    printf("%s... ", (name));             \
    if ((expr)) printf("OK\n");           \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Transparent spend of `in_txid`:`in_n` paying `out_value` to a placeholder
 * P2PKH-shaped script. Identical shape to ds_make_spend() in
 * test_simnet_doublespend.c and sim_make_spend() in engine/modules/sim/src/simnet.c.
 * simnet mints at heights covered by a synthetic checkpoint (simnet.h), so
 * connect_block runs with expensive_checks=false and scriptSig content is
 * never verified — only the outpoint linkage, coin availability, and the
 * value arithmetic matter here. This helper is needed (rather than the
 * public simnet_spend) precisely because simnet_spend REFUSES out_value >
 * input value at the harness layer (engine/modules/sim/src/simnet.c), so the inflating
 * tx must be assembled directly and driven through simnet_mint_txs. */
static bool vi_make_spend(struct transaction *tx, const struct uint256 *in_txid,
                          uint32_t in_n, int64_t out_value)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1))
        return false;
    tx->version = 1;
    tx->vin[0].prevout.hash = *in_txid;
    tx->vin[0].prevout.n = in_n;
    uint8_t sig[] = {0x00, 0x01};
    script_set(&tx->vin[0].script_sig, sig, sizeof(sig));
    tx->vin[0].sequence = 0xFFFFFFFF;
    tx->vout[0].value = out_value;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx->vout[0].script_pub_key, pk, sizeof(pk));
    transaction_compute_hash(tx);
    return true;
}

/* Call simnet_mint_txs() while redirecting stderr to a scratch file, so this
 * test can inspect connect_block's reject reason without any change to
 * simnet.c (whose public API in simnet.h does not surface validation_state).
 * sim_mint_block() logs "connect_block rejected height %d: %s" via LOG_FAIL()
 * on a rejected block; that log line is the only place the reason text leaves
 * the harness. Best-effort: if the capture plumbing itself fails, this runs
 * the mint uncaptured and leaves `out_reason` empty (the boolean return — the
 * thing every assertion relies on — is unaffected either way). Mirrors
 * ds_mint_capture() in test_simnet_doublespend.c. */
static bool vi_mint_capture(struct simnet *sim, struct transaction *txs,
                            size_t ntx, char *out_reason,
                            size_t out_reason_len)
{
    if (out_reason && out_reason_len > 0)
        out_reason[0] = '\0';

    mkdir("./test-tmp", 0755);
    char path[256];
    snprintf(path, sizeof(path),
             "./test-tmp/simnet_value_inflation_stderr_%d.log", (int)getpid());

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

/* Mint a coinbase, advance the honest chain to exactly one block below its
 * maturity, and return the coinbase txid + the tip height right before the
 * spend attempt. The NEXT mint (height = cb_height + COINBASE_MATURITY) is
 * the first height at which connect_block's maturity predicate
 * (pindex->nHeight - coin.height >= COINBASE_MATURITY) allows spending the
 * coinbase — so any rejection there is for the value arithmetic, not for a
 * premature spend. Returns false on any harness failure. */
static bool vi_fund_matured_coinbase(struct simnet *sim, struct uint256 *out_cb,
                                     int *out_pre_height)
{
    if (!simnet_mint_coinbase(sim, out_cb))
        return false;
    int cb_height = simnet_tip_height(sim);
    if (!simnet_mint_to_height(sim, cb_height + COINBASE_MATURITY - 1))
        return false;
    *out_pre_height = simnet_tip_height(sim);
    return true;
}

int test_simnet_value_inflation(void)
{
    printf("\n=== simnet output value inflation rejection "
           "(connect_block) ===\n");
    int failures = 0;

    /* ── Negative: outputs (2_000_000) exceed inputs (1_000_000). ─────── */
    {
        struct simnet sim;
        VI_CHECK("negative: simnet init", simnet_init(&sim));

        struct uint256 cb;
        int pre_height = 0;
        VI_CHECK("negative: fund matured coinbase",
                 vi_fund_matured_coinbase(&sim, &cb, &pre_height));

        int64_t cb_value = 0;
        VI_CHECK("negative: coinbase value readable",
                 simnet_coin_value(&sim, &cb, 0, &cb_value));
        VI_CHECK("negative: coinbase value is the funding amount",
                 cb_value == VI_COINBASE_VALUE);

        /* Output = 2x the input: 1_000_000 zatoshi conjured from nothing.
         * Every individual output is in MoneyRange, so this can ONLY be
         * caught by the value_in < value_out check. */
        struct transaction inflate;
        VI_CHECK("negative: build inflating spend (out > in)",
                 vi_make_spend(&inflate, &cb, 0, cb_value * 2));

        struct transaction txs[1] = { inflate };
        char reason[256];
        bool ok = vi_mint_capture(&sim, txs, 1, reason, sizeof(reason));
        VI_CHECK("negative: inflating spend is rejected by connect_block",
                 !ok);
        VI_CHECK("negative: reject reason is bad-txns-in-belowout",
                 strstr(reason, "bad-txns-in-belowout") != NULL);
        VI_CHECK("negative: tip does not advance to the bad block",
                 simnet_tip_height(&sim) == pre_height);
        VI_CHECK("negative: coinbase outpoint is still unspent after reject",
                 simnet_coin_exists(&sim, &cb));

        simnet_free(&sim);
    }

    /* ── Positive control: outputs (900_000) = inputs (1_000_000) - fee. ─ */
    {
        struct simnet sim;
        VI_CHECK("positive: simnet init", simnet_init(&sim));

        struct uint256 cb;
        int pre_height = 0;
        VI_CHECK("positive: fund matured coinbase",
                 vi_fund_matured_coinbase(&sim, &cb, &pre_height));

        struct transaction spend;
        VI_CHECK("positive: build valid spend (out < in, 100k fee)",
                 vi_make_spend(&spend, &cb, 0, VI_COINBASE_VALUE - 100000));

        struct transaction txs[1] = { spend };
        struct uint256 spend_txid = txs[0].hash;
        char reason[256];
        bool ok = vi_mint_capture(&sim, txs, 1, reason, sizeof(reason));
        VI_CHECK("positive: valid spend is accepted by connect_block", ok);
        VI_CHECK("positive: tip advances by one",
                 simnet_tip_height(&sim) == pre_height + 1);
        VI_CHECK("positive: spent coinbase output is consumed",
                 !simnet_coin_exists(&sim, &cb));
        VI_CHECK("positive: new output exists",
                 simnet_coin_exists(&sim, &spend_txid));

        simnet_free(&sim);
    }

    /* ── Boundary: outputs == inputs (zero fee) is the first ACCEPTED
     * point — connect_block rejects only STRICT value_in < value_out, so
     * value_in == value_out must pass. Pins the exact threshold. ──────── */
    {
        struct simnet sim;
        VI_CHECK("boundary: simnet init", simnet_init(&sim));

        struct uint256 cb;
        int pre_height = 0;
        VI_CHECK("boundary: fund matured coinbase",
                 vi_fund_matured_coinbase(&sim, &cb, &pre_height));

        struct transaction spend;
        VI_CHECK("boundary: build zero-fee spend (out == in)",
                 vi_make_spend(&spend, &cb, 0, VI_COINBASE_VALUE));

        struct transaction txs[1] = { spend };
        char reason[256];
        bool ok = vi_mint_capture(&sim, txs, 1, reason, sizeof(reason));
        VI_CHECK("boundary: zero-fee spend (out == in) is accepted", ok);
        VI_CHECK("boundary: tip advances by one",
                 simnet_tip_height(&sim) == pre_height + 1);

        simnet_free(&sim);
    }

    printf("=== simnet_value_inflation: %d failures ===\n", failures);
    return failures;
}

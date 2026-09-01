/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves TRANSPARENT negative-fee rejection through simnet's real
 * connect_block() — a tx whose outputs exceed its inputs (an implied
 * negative fee / money creation) must be REJECTED, deterministically,
 * before live ZCL.
 *
 * WHICH reason string fires, and why NOT the two the operation is named
 * after ("bad-txns-fee-negative" / "bad-txns-fee-outofrange"):
 *
 *   connect_block's fee block (core/modules/validation/src/connect_block.c:502-548)
 *   runs these checks IN ORDER on each non-coinbase tx:
 *     1. value_in  = coins_view_cache_get_value_in(view, tx)   (>=0, MoneyRange)
 *     2. value_out = transaction_get_value_out(tx)
 *     3. if (value_in <  value_out) -> "bad-txns-in-belowout"      (:527-531)
 *     4. tx_fee = value_in - value_out
 *     5. if (tx_fee < 0)            -> "bad-txns-fee-negative"      (:537-541)
 *     6. if (!MoneyRange(fees+tx_fee)) -> "bad-txns-fee-outofrange" (:543-547)
 *
 *   A tx implying a negative fee is exactly value_out > value_in, which
 *   check 3 catches FIRST — so "bad-txns-in-belowout" is the string the
 *   validator actually emits for the negative-fee operation. Check 5
 *   ("bad-txns-fee-negative") is defensive/unreachable: reaching it needs
 *   value_in >= value_out (else check 3 returned), and then
 *   tx_fee = value_in - value_out is >= 0 by construction, so tx_fee < 0
 *   never holds. It mirrors zclassicd's CheckTxInputs structure and is
 *   kept for parity, not because any transparent input can trip it.
 *
 *   Check 6 ("bad-txns-fee-outofrange") needs the running per-block fee
 *   SUM (fees + tx_fee) to exceed MAX_MONEY (21,000,000 * COIN =
 *   2.1e15 zatoshi). A single tx's fee is bounded by its value_in, which
 *   is MoneyRange-capped; and simnet funding is coinbase-only, bounded by
 *   the block subsidy (bad-cb-amount, connect_block.c:748) — so
 *   accumulating > MAX_MONEY of fees in one block is not deterministically
 *   constructible through the public simnet API. This file therefore
 *   proves the reachable manifestation of the operation and documents the
 *   two shadowed/out-of-reach strings above rather than guessing at them.
 *
 * Two cases:
 *   1. Negative case: spend a matured coinbase (value SIM_COINBASE_VALUE =
 *      1,000,000 zatoshi) to a single output of 2,000,000 zatoshi. Outputs
 *      exceed inputs -> implied negative fee -> connect_block rejects with
 *      "bad-txns-in-belowout" and the tip does NOT advance to the bad block.
 *   2. Positive control: spend the same-sized matured coinbase to a single
 *      output of 900,000 zatoshi (a +100,000-zatoshi in-range fee). The
 *      block is ACCEPTED, the tip advances by one, the coinbase output is
 *      consumed, and the new output exists — so the negative case is not
 *      vacuously passing.
 *
 * Per the harness contract (simnet.h): if a mint is rejected, the fix is
 * always in this file's block construction, never in connect_block.
 */

#include "test/test_core.h"
#include "validation/main_constants.h"

#include "sim/simnet.h"
/* COINBASE_MATURITY comes from validation/main_constants.h, already
 * included directly by this file. */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Value every synthetic simnet coinbase output carries (must match
 * SIM_COINBASE_VALUE in engine/modules/sim/src/simnet.c). The negative case pays MORE
 * than this; the positive control pays LESS. */
#define FR_COINBASE_VALUE 1000000

#define FR_CHECK(name, expr) do {         \
    printf("%s... ", (name));             \
    if ((expr)) printf("OK\n");           \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Transparent spend of `in_txid`:`in_n` paying `out_value` to a
 * placeholder P2PKH-shaped script. Same shape as ds_make_spend() in
 * test_simnet_doublespend.c and sim_make_spend() in engine/modules/sim/src/simnet.c.
 * simnet mints at heights covered by a synthetic checkpoint (simnet.h), so
 * connect_block runs with expensive_checks=false and scriptSig content is
 * never verified — only the outpoint linkage and the input/output VALUE
 * relationship (the thing this file exercises) matter here. */
static bool fr_make_spend(struct transaction *tx, const struct uint256 *in_txid,
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

/* Call simnet_mint_txs() while redirecting stderr to a scratch file, so
 * this test can inspect connect_block's reject reason without any change to
 * simnet.c (whose public API in simnet.h does not surface validation_state
 * to the caller). sim_mint_block() in engine/modules/sim/src/simnet.c logs
 * "connect_block rejected height %d: %s" via LOG_FAIL() on a rejected
 * block; that log line is the only place the reason text leaves the
 * harness. Best-effort: if the capture plumbing itself fails, this just
 * runs the mint uncaptured and leaves `out_reason` empty (the boolean
 * return value — the thing the assertions rely on — is unaffected either
 * way). Same pattern as ds_mint_capture() in test_simnet_doublespend.c. */
static bool fr_mint_capture(struct simnet *sim, struct transaction *txs,
                            size_t ntx, char *out_reason,
                            size_t out_reason_len)
{
    if (out_reason && out_reason_len > 0)
        out_reason[0] = '\0';

    mkdir("./test-tmp", 0755);
    char path[256];
    snprintf(path, sizeof(path),
             "./test-tmp/simnet_fee_range_stderr_%d.log", (int)getpid());

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

/* Mint a coinbase, advance to one block short of its maturity, and return
 * the coinbase txid — so the NEXT minted block (height = cb_height +
 * COINBASE_MATURITY) is exactly where connect_block's maturity predicate
 * (pindex->nHeight - coin.height >= COINBASE_MATURITY) first allows
 * spending it. This guarantees any rejection is about the input/output
 * value relationship, not premature-coinbase spending. */
static bool fr_fund_matured_coinbase(struct simnet *sim, struct uint256 *out_cb)
{
    if (!simnet_mint_coinbase(sim, out_cb))
        return false;
    int cb_height = simnet_tip_height(sim);
    return simnet_mint_to_height(sim, cb_height + COINBASE_MATURITY - 1);
}

int test_simnet_fee_range(void)
{
    printf("\n=== simnet transaction fee negative/out-of-range rejection "
           "(connect_block) ===\n");
    int failures = 0;

    /* ── Positive control: a matured-coinbase spend paying LESS than the
     * input (a +100,000-zatoshi in-range fee) is accepted; the tip
     * advances and the new output exists. This anchors the negative case
     * below as non-vacuous. ─────────────────────────────────────────── */
    {
        struct simnet sim;
        FR_CHECK("positive control: simnet init", simnet_init(&sim));

        struct uint256 cb;
        FR_CHECK("positive control: fund matured coinbase",
                 fr_fund_matured_coinbase(&sim, &cb));
        int pre_height = simnet_tip_height(&sim);

        /* out_value (900,000) < input (1,000,000) -> fee = +100,000. */
        struct transaction spend;
        FR_CHECK("positive control: build in-range positive-fee spend",
                 fr_make_spend(&spend, &cb, 0, 900000));

        struct transaction txs[1] = { spend };
        struct uint256 spend_txid = spend.hash; /* keep before ownership moves */
        char reason[256];
        bool ok = fr_mint_capture(&sim, txs, 1, reason, sizeof(reason));
        FR_CHECK("positive control: positive-fee spend is accepted", ok);
        FR_CHECK("positive control: tip advances by one",
                 simnet_tip_height(&sim) == pre_height + 1);
        FR_CHECK("positive control: spent coinbase output is consumed",
                 !simnet_coin_exists(&sim, &cb));
        FR_CHECK("positive control: new output exists",
                 simnet_coin_exists(&sim, &spend_txid));

        simnet_free(&sim);
    }

    /* ── Negative case: a matured-coinbase spend paying MORE than the
     * input (outputs 2,000,000 > input 1,000,000 -> implied negative fee /
     * money creation) is rejected by connect_block with
     * "bad-txns-in-belowout", and the tip does NOT advance. ──────────── */
    {
        struct simnet sim;
        FR_CHECK("negative case: simnet init", simnet_init(&sim));

        struct uint256 cb;
        FR_CHECK("negative case: fund matured coinbase",
                 fr_fund_matured_coinbase(&sim, &cb));
        int pre_attempt_height = simnet_tip_height(&sim);

        /* out_value (2,000,000) > input (1,000,000) -> value_in < value_out
         * -> connect_block.c:527 fires before the (shadowed) fee-negative
         * check at :537. */
        struct transaction spend;
        FR_CHECK("negative case: build outputs>inputs (negative-fee) spend",
                 fr_make_spend(&spend, &cb, 0, 2 * FR_COINBASE_VALUE));

        struct transaction txs[1] = { spend };
        char reason[256];
        bool ok = fr_mint_capture(&sim, txs, 1, reason, sizeof(reason));
        FR_CHECK("negative case: negative-fee spend is rejected by connect_block",
                 !ok);
        FR_CHECK("negative case: reject reason is bad-txns-in-belowout",
                 strstr(reason, "bad-txns-in-belowout") != NULL);
        FR_CHECK("negative case: tip does not advance to the bad block",
                 simnet_tip_height(&sim) == pre_attempt_height);

        /* Not vacuous: the chain still accepts an honest block after
         * rejecting the negative-fee attempt. */
        struct uint256 honest_cb;
        FR_CHECK("negative case: honest block still mints after rejection",
                 simnet_mint_coinbase(&sim, &honest_cb) &&
                 simnet_tip_height(&sim) == pre_attempt_height + 1);

        simnet_free(&sim);
    }

    printf("=== simnet_fee_range: %d failures ===\n", failures);
    return failures;
}

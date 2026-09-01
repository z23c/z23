/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves TRANSPARENT double-spend rejection through simnet's real
 * connect_block() — a core consensus safety property that must be
 * exercised deterministically before live ZCL.
 *
 * Two negative cases plus a positive control:
 *   1. Same-block double-spend: two distinct transactions in ONE block
 *      both spend the same matured-coinbase outpoint. connect_block
 *      processes vtx[] in order (core/modules/validation/src/connect_block.c),
 *      applying update_coins_with_undo() as each tx passes its checks, so
 *      the second spender sees the outpoint already consumed by the first
 *      and coins_view_cache_have_inputs() fails ->
 *      "bad-txns-inputs-missingorspent" (connect_block.c:460-473). The
 *      whole block is rejected (validation_state_dos returns false), so
 *      the tip never advances to it.
 *   2. Cross-block double-spend: the outpoint is spent (and the spend
 *      COMMITS — the tip advances) in block N, then a second, different
 *      transaction tries to spend the SAME outpoint in block N+1. Same
 *      have_inputs check, same rejection, and the chain keeps working
 *      afterward (an honest block still mints on top of N).
 *   3. Positive control: a single valid spend of a matured coinbase
 *      succeeds, so the negatives above are not vacuously passing.
 *
 * Case 1 and case 2 each run in their OWN freshly-initialized simnet.
 * Reason: connect_block() mutates its `view` argument (a
 * coins_view_cache) tx-by-tx as it walks the block — it is the SAME
 * cache the sim reuses across mints (simnet.h: "view ... IS the chain
 * state"), not a disposable per-block overlay the caller discards on
 * failure (as a full node's ConnectTip/ActivateBestChainStep does with a
 * temporary cache). So in the same-block case, the FIRST spender's write
 * lands in `view` before the SECOND spender is even evaluated, even
 * though the overall block — and therefore the tip advance — is
 * rejected. This file asserts the two things simnet's public API
 * actually promises across that partial-apply: connect_block returns
 * false with the missingorspent reason, and the tip height (the
 * authoritative "did this block happen" signal) does not move. It
 * deliberately does not re-assert the spent coin's view-level existence
 * after the rejected same-block attempt, since that is an artifact of
 * the harness reusing one mutable cache across mints, not a claim about
 * consensus behavior.
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

#define DS_CHECK(name, expr) do {         \
    printf("%s... ", (name));             \
    if ((expr)) printf("OK\n");           \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Transparent spend of `in_txid`:`in_n` paying `out_value` to a
 * placeholder P2PKH-shaped script. Same shape as sim_make_spend() in
 * engine/modules/sim/src/simnet.c and txk_make_manual_spend() in
 * test_simnet_txkit.c. simnet mints at heights covered by a synthetic
 * checkpoint (simnet.h), so connect_block runs with
 * expensive_checks=false and scriptSig content is never verified — only
 * the outpoint linkage and coin availability matter here. `marker`
 * varies the scriptSig so two spends of the same input get distinct
 * txids: without that, BIP30/duplicate-txid detection (not the
 * missingorspent path this file is proving) would fire first. */
static bool ds_make_spend(struct transaction *tx, const struct uint256 *in_txid,
                          uint32_t in_n, int64_t out_value, uint8_t marker)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1))
        return false;
    tx->version = 1;
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

/* Call simnet_mint_txs() while redirecting stderr to a scratch file, so
 * this test can inspect connect_block's reject reason without any
 * change to simnet.c (whose public API in simnet.h does not surface
 * validation_state to the caller). sim_mint_block() in
 * engine/modules/sim/src/simnet.c logs "connect_block rejected height %d: %s" via
 * LOG_FAIL() on a rejected block; that log line is the only place the
 * reason text leaves the harness. Best-effort: if the capture plumbing
 * itself fails, this just runs the mint uncaptured and leaves
 * `out_reason` empty (the boolean return value — the thing every other
 * assertion in this file relies on — is unaffected either way). */
static bool ds_mint_capture(struct simnet *sim, struct transaction *txs,
                            size_t ntx, char *out_reason,
                            size_t out_reason_len)
{
    if (out_reason && out_reason_len > 0)
        out_reason[0] = '\0';

    mkdir("./test-tmp", 0755);
    char path[256];
    snprintf(path, sizeof(path),
             "./test-tmp/simnet_doublespend_stderr_%d.log", (int)getpid());

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

int test_simnet_doublespend(void)
{
    printf("\n=== simnet transparent double-spend rejection "
           "(connect_block) ===\n");
    int failures = 0;

    /* ── Positive control: a single valid spend of a matured coinbase
     * succeeds, so the negatives below are not vacuously passing. ──── */
    {
        struct simnet sim;
        DS_CHECK("positive control: simnet init", simnet_init(&sim));

        struct uint256 cb;
        DS_CHECK("positive control: mint coinbase",
                 simnet_mint_coinbase(&sim, &cb));

        struct uint256 spend_txid;
        bool spent = simnet_spend(&sim, &cb, 0, 900000, &spend_txid);
        DS_CHECK("positive control: single valid spend succeeds", spent);
        DS_CHECK("positive control: spent coinbase output is consumed",
                 !simnet_coin_exists(&sim, &cb));
        DS_CHECK("positive control: new output exists",
                 simnet_coin_exists(&sim, &spend_txid));

        simnet_free(&sim);
    }

    /* ── Same-block double-spend: two distinct txs spend the SAME
     * matured-coinbase outpoint inside one block. ───────────────────── */
    {
        struct simnet sim;
        DS_CHECK("same-block: simnet init", simnet_init(&sim));

        struct uint256 cb;
        DS_CHECK("same-block: mint coinbase", simnet_mint_coinbase(&sim, &cb));
        int cb_height = simnet_tip_height(&sim);

        /* Advance the honest chain to one block short of maturity so the
         * NEXT mint (height = cb_height + COINBASE_MATURITY) is exactly
         * where connect_block's maturity predicate
         * (pindex->nHeight - coin.height >= COINBASE_MATURITY) first
         * allows spending `cb` — the double-spend must be rejected for
         * being a double-spend, not for being premature. */
        DS_CHECK("same-block: advance to one below maturity",
                 simnet_mint_to_height(&sim,
                     cb_height + COINBASE_MATURITY - 1));
        int pre_attempt_height = simnet_tip_height(&sim);

        struct transaction spend_a = {0}, spend_b = {0};
        bool built = ds_make_spend(&spend_a, &cb, 0, 900000, 0xAA) &&
                     ds_make_spend(&spend_b, &cb, 0, 800000, 0xBB);
        DS_CHECK("same-block: build two distinct spends of one outpoint",
                 built);

        struct transaction txs[2] = { spend_a, spend_b };
        char reason[256];
        bool ok = ds_mint_capture(&sim, txs, 2, reason, sizeof(reason));
        DS_CHECK("same-block double-spend is rejected by connect_block",
                 !ok);
        DS_CHECK("same-block: reject reason is bad-txns-inputs-missingorspent",
                 strstr(reason, "bad-txns-inputs-missingorspent") != NULL);
        DS_CHECK("same-block: tip does not advance to the bad block",
                 simnet_tip_height(&sim) == pre_attempt_height);

        simnet_free(&sim);
    }

    /* ── Cross-block double-spend: the outpoint is spent (and commits)
     * in block N; a different tx tries to spend it again in block N+1;
     * the chain keeps working (honest mint) after the rejection. ────── */
    {
        struct simnet sim;
        DS_CHECK("cross-block: simnet init", simnet_init(&sim));

        struct uint256 cb;
        DS_CHECK("cross-block: mint coinbase", simnet_mint_coinbase(&sim, &cb));

        struct uint256 first_spend_txid;
        bool first_ok = simnet_spend(&sim, &cb, 0, 900000, &first_spend_txid);
        DS_CHECK("cross-block: first spend (block N) succeeds", first_ok);
        DS_CHECK("cross-block: outpoint is consumed after block N",
                 !simnet_coin_exists(&sim, &cb));
        int height_after_first_spend = simnet_tip_height(&sim);

        struct transaction spend_again;
        DS_CHECK("cross-block: build second spend of the same outpoint",
                 ds_make_spend(&spend_again, &cb, 0, 700000, 0xCC));

        struct transaction txs[1] = { spend_again };
        char reason[256];
        bool ok = ds_mint_capture(&sim, txs, 1, reason, sizeof(reason));
        DS_CHECK("cross-block double-spend (block N+1) is rejected", !ok);
        DS_CHECK("cross-block: reject reason is bad-txns-inputs-missingorspent",
                 strstr(reason, "bad-txns-inputs-missingorspent") != NULL);
        DS_CHECK("cross-block: tip does not advance past block N",
                 simnet_tip_height(&sim) == height_after_first_spend);

        /* Not vacuous: the chain still accepts an honest block after
         * rejecting the double-spend attempt. */
        struct uint256 honest_cb;
        DS_CHECK("cross-block: honest block still mints after rejection",
                 simnet_mint_coinbase(&sim, &honest_cb) &&
                 simnet_tip_height(&sim) == height_after_first_spend + 1);

        simnet_free(&sim);
    }

    printf("=== simnet_doublespend: %d failures ===\n", failures);
    return failures;
}

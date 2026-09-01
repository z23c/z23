/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves DUPLICATE-INPUT rejection through simnet's real connect_block() —
 * a single transaction that lists the SAME outpoint twice as two separate
 * inputs must be rejected with "bad-txns-inputs-duplicate", while a
 * structurally identical transaction whose two inputs reference DISTINCT
 * outpoints is accepted and advances the tip.
 *
 * This is a DIFFERENT consensus rule than the double-spend covered by
 * test_simnet_doublespend.c:
 *   - Double-spend  = two inputs (in the same block, or across blocks) that
 *     spend the same coin; caught by the UTXO availability check in
 *     connect_block ("bad-txns-inputs-missingorspent").
 *   - Duplicate input = ONE transaction whose vin list contains the same
 *     COutPoint twice; caught structurally (context-free) by
 *     CheckTransaction before any UTXO lookup. The pure rule lives in
 *     domain/consensus/src/tx_structural.c:256-263 (the O(n^2) pairwise
 *     outpoint_cmp loop that emits "bad-txns-inputs-duplicate", DoS 100),
 *     reached from connect_block -> check_block ->
 *     check_transaction_in_block (core/modules/validation/src/check_block.c:248-250).
 *
 * Existing coverage of this rule is unit-level only — it calls the domain /
 * CheckTransaction surface directly (test_domain_consensus_tx_structural.c,
 * test_check_tx_edge.c, test_transaction.c). This file closes the gap by
 * driving the SAME rule through the full simnet connect_block path, the way
 * a mined block actually reaches it.
 *
 * Determinism: simnet mints at heights covered by a synthetic checkpoint,
 * so connect_block runs with expensive_checks=false (PoW + scriptSig
 * content never verified). Only tx structure, outpoint linkage and coin
 * availability matter. No disk, no real funds, no wall clock.
 *
 * Per the harness contract (simnet.h): if a mint is rejected, the fix is
 * always in THIS file's block construction, never in connect_block.
 */

#include "test/test_core.h"
#include "validation/main_constants.h"

#include "sim/simnet.h"
/* COINBASE_MATURITY comes from validation/main_constants.h, pulled in
 * included directly by this file. */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DI_CHECK(name, expr) do {          \
    printf("%s... ", (name));              \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Build a two-input, one-output transparent transaction. vin[0] spends
 * `a_txid`:`a_n`; vin[1] spends `b_txid`:`b_n`. Passing the SAME (txid,n)
 * for both makes a duplicate-input tx; passing two distinct coins makes a
 * valid two-input spend. scriptSig content is irrelevant under
 * expensive_checks=false but is set to keep the tx well-formed. Same shape
 * as ds_make_spend() in test_simnet_doublespend.c, widened to two inputs. */
static bool di_make_two_input_spend(struct transaction *tx,
                                    const struct uint256 *a_txid, uint32_t a_n,
                                    const struct uint256 *b_txid, uint32_t b_n,
                                    int64_t out_value)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 2, 1))
        return false;
    tx->version = 1;

    tx->vin[0].prevout.hash = *a_txid;
    tx->vin[0].prevout.n = a_n;
    uint8_t sig0[] = {0x00, 0xA0};
    script_set(&tx->vin[0].script_sig, sig0, sizeof(sig0));
    tx->vin[0].sequence = 0xFFFFFFFF;

    tx->vin[1].prevout.hash = *b_txid;
    tx->vin[1].prevout.n = b_n;
    uint8_t sig1[] = {0x00, 0xB1};
    script_set(&tx->vin[1].script_sig, sig1, sizeof(sig1));
    tx->vin[1].sequence = 0xFFFFFFFF;

    tx->vout[0].value = out_value;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx->vout[0].script_pub_key, pk, sizeof(pk));

    transaction_compute_hash(tx);
    return true;
}

/* Mint through simnet_mint_txs() while capturing stderr, so the test can
 * read connect_block's reject reason (surfaced only via sim_mint_block()'s
 * LOG_FAIL "connect_block rejected height %d: %s"). Byte-for-byte the same
 * capture approach as ds_mint_capture() in test_simnet_doublespend.c; no
 * change to simnet.c. On capture-plumbing failure it runs the mint
 * uncaptured (the boolean return — the load-bearing assertion — is
 * unaffected) and leaves out_reason empty. */
static bool di_mint_capture(struct simnet *sim, struct transaction *txs,
                            size_t ntx, char *out_reason,
                            size_t out_reason_len)
{
    if (out_reason && out_reason_len > 0)
        out_reason[0] = '\0';

    mkdir("./test-tmp", 0755);
    char path[256];
    snprintf(path, sizeof(path),
             "./test-tmp/simnet_dupinput_stderr_%d.log", (int)getpid());

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

int test_simnet_duplicate_input(void)
{
    printf("\n=== simnet duplicate-input rejection (connect_block) ===\n");
    int failures = 0;

    /* ── Negative: one tx lists the SAME matured-coinbase outpoint twice.
     * Must be rejected structurally as bad-txns-inputs-duplicate, and the
     * tip must not advance to the bad block. ─────────────────────────── */
    {
        struct simnet sim;
        DI_CHECK("negative: simnet init", simnet_init(&sim));

        struct uint256 cb;
        DI_CHECK("negative: mint coinbase", simnet_mint_coinbase(&sim, &cb));
        int cb_height = simnet_tip_height(&sim);

        /* Advance to one below maturity so the dup-input tx is minted at
         * exactly the first height where `cb` is spendable — the rejection
         * must be for the duplicate input, not for premature coinbase
         * spend (same maturity setup as test_simnet_doublespend.c). */
        DI_CHECK("negative: advance to one below maturity",
                 simnet_mint_to_height(&sim,
                     cb_height + COINBASE_MATURITY - 1));
        int pre_attempt_height = simnet_tip_height(&sim);

        struct transaction dup;
        DI_CHECK("negative: build tx with the same outpoint twice",
                 di_make_two_input_spend(&dup, &cb, 0, &cb, 0, 900000));

        struct transaction txs[1] = { dup };
        char reason[1024];
        bool ok = di_mint_capture(&sim, txs, 1, reason, sizeof(reason));
        DI_CHECK("negative: duplicate-input tx rejected by connect_block",
                 !ok);
        DI_CHECK("negative: reject reason is bad-txns-inputs-duplicate",
                 strstr(reason, "bad-txns-inputs-duplicate") != NULL);
        DI_CHECK("negative: tip does not advance to the bad block",
                 simnet_tip_height(&sim) == pre_attempt_height);

        simnet_free(&sim);
    }

    /* ── Positive control: a structurally identical two-input tx whose
     * inputs reference two DISTINCT matured coinbase outpoints is accepted,
     * the coins are consumed, the new output exists and the tip advances.
     * Proves the negative above is not vacuously rejecting any two-input
     * tx. ────────────────────────────────────────────────────────────── */
    {
        struct simnet sim;
        DI_CHECK("positive: simnet init", simnet_init(&sim));

        struct uint256 cb1, cb2;
        DI_CHECK("positive: mint first coinbase",
                 simnet_mint_coinbase(&sim, &cb1));
        int cb1_height = simnet_tip_height(&sim);
        DI_CHECK("positive: mint second coinbase",
                 simnet_mint_coinbase(&sim, &cb2));
        int cb2_height = simnet_tip_height(&sim);
        DI_CHECK("positive: the two coinbases have distinct txids",
                 memcmp(&cb1, &cb2, sizeof cb1) != 0);

        /* Mature the YOUNGER coinbase (cb2). Minting at
         * cb2_height + COINBASE_MATURITY satisfies the maturity predicate
         * for both coins (cb1 is one block older). */
        DI_CHECK("positive: advance to one below maturity of younger cb",
                 simnet_mint_to_height(&sim,
                     cb2_height + COINBASE_MATURITY - 1));
        int pre_height = simnet_tip_height(&sim);
        (void)cb1_height;

        /* Two inputs of SIM_COINBASE_VALUE (1,000,000) each = 2,000,000 in;
         * pay 1,900,000 out, leaving a positive fee. */
        struct transaction good;
        DI_CHECK("positive: build two-input tx over distinct outpoints",
                 di_make_two_input_spend(&good, &cb1, 0, &cb2, 0, 1900000));
        struct uint256 good_txid = good.hash;

        struct transaction txs[1] = { good };
        char reason[1024];
        bool ok = di_mint_capture(&sim, txs, 1, reason, sizeof(reason));
        DI_CHECK("positive: two-distinct-input tx accepted by connect_block",
                 ok);
        DI_CHECK("positive: tip advances by one",
                 simnet_tip_height(&sim) == pre_height + 1);
        DI_CHECK("positive: first input coin is consumed",
                 !simnet_coin_exists(&sim, &cb1));
        DI_CHECK("positive: second input coin is consumed",
                 !simnet_coin_exists(&sim, &cb2));
        DI_CHECK("positive: new output exists",
                 simnet_coin_exists(&sim, &good_txid));

        simnet_free(&sim);
    }

    printf("=== simnet_duplicate_input: %d failures ===\n", failures);
    return failures;
}

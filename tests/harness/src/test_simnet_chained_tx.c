/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves INTRA-BLOCK dependent-transaction (chained-spend) handling
 * through simnet's real connect_block() — a core consensus safety
 * property that must be exercised deterministically before live ZCL.
 *
 * A real block can contain a chain of transactions: tx B spends an
 * output created by tx A in the SAME block. Consensus requires
 * topological order — a tx may spend an EARLIER same-block tx's
 * output, but not a LATER one, because connect_block() processes
 * vtx[] strictly in order (core/modules/validation/src/connect_block.c),
 * applying update_coins_with_undo() as each tx passes its checks. If
 * A appears before B, B's coins_view_cache_have_inputs() check sees
 * A's output already applied and succeeds. If B appears before A,
 * the same check fails ("bad-txns-inputs-missingorspent",
 * connect_block.c:460-473) because A's output does not exist in the
 * view yet — the whole block is rejected and the tip never advances.
 *
 * Two cases plus a same-content control:
 *   1. In-order chained spend (A before B) is ACCEPTED: the tip
 *      advances and B's output is present in the live UTXO view.
 *   2. Out-of-order chained spend (B before A) — built from tx
 *      content IDENTICAL to case 1 (same txids, proven by
 *      uint256_eq) — is REJECTED with the missingorspent reason, and
 *      the tip does not advance. Because the tx content is identical
 *      to the accepted case, the rejection is attributable to
 *      ORDER alone, not to some other defect in the block.
 *
 * Modeled on test_simnet_doublespend.c (the sibling proof for
 * same-outpoint double-spend rejection) and the manual-spend builder
 * in test_simnet_txkit.c's txk_make_manual_spend().
 *
 * Per the harness contract (simnet.h): if a mint is rejected, the fix
 * is always in this file's block construction, never in
 * connect_block.
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

#define CT_CHECK(name, expr) do {         \
    printf("%s... ", (name));             \
    if ((expr)) printf("OK\n");           \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Transparent spend of `in_txid`:`in_n` paying `out_value` to a
 * placeholder P2PKH-shaped script. Same shape as ds_make_spend() in
 * test_simnet_doublespend.c: simnet mints at heights covered by a
 * synthetic checkpoint, so connect_block runs with
 * expensive_checks=false and scriptSig content is never verified —
 * only the outpoint linkage and coin availability matter here.
 * `marker` varies the scriptSig so distinct logical spends get
 * distinct txids without affecting determinism (two calls with the
 * same arguments always produce the same txid). */
static bool ct_make_spend(struct transaction *tx, const struct uint256 *in_txid,
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
 * validation_state to the caller). Identical technique to
 * ds_mint_capture() in test_simnet_doublespend.c. Best-effort: if the
 * capture plumbing itself fails, this just runs the mint uncaptured and
 * leaves `out_reason` empty (the boolean return value — the thing
 * every other assertion in this file relies on — is unaffected
 * either way). */
static bool ct_mint_capture(struct simnet *sim, struct transaction *txs,
                            size_t ntx, char *out_reason,
                            size_t out_reason_len)
{
    if (out_reason && out_reason_len > 0)
        out_reason[0] = '\0';

    mkdir("./test-tmp", 0755);
    char path[256];
    snprintf(path, sizeof(path),
             "./test-tmp/simnet_chained_tx_stderr_%d.log", (int)getpid());

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

int test_simnet_chained_tx(void)
{
    printf("\n=== simnet intra-block chained-tx ordering "
           "(connect_block) ===\n");
    int failures = 0;

    struct uint256 a_txid_case1, b_txid_case1;
    memset(&a_txid_case1, 0, sizeof(a_txid_case1));
    memset(&b_txid_case1, 0, sizeof(b_txid_case1));

    /* ── Case 1: in-order chained spend (A before B) is accepted. ──── */
    {
        struct simnet sim;
        CT_CHECK("in-order: simnet init", simnet_init(&sim));

        struct uint256 cb;
        CT_CHECK("in-order: mint coinbase", simnet_mint_coinbase(&sim, &cb));
        int cb_height = simnet_tip_height(&sim);

        /* Advance to one below maturity so the NEXT mint (the block
         * containing A and B) is exactly where connect_block's
         * maturity predicate first allows spending `cb`. */
        CT_CHECK("in-order: advance to one below maturity",
                 simnet_mint_to_height(&sim, cb_height + COINBASE_MATURITY - 1));
        int pre_height = simnet_tip_height(&sim);

        struct transaction tx_a, tx_b;
        CT_CHECK("in-order: build tx A (spends matured coinbase)",
                 ct_make_spend(&tx_a, &cb, 0, 900000, 0xA1));
        struct uint256 a_txid = tx_a.hash;
        CT_CHECK("in-order: build tx B (spends A's not-yet-committed output)",
                 ct_make_spend(&tx_b, &a_txid, 0, 800000, 0xB1));
        struct uint256 b_txid = tx_b.hash;

        struct transaction txs[2] = { tx_a, tx_b };   /* A BEFORE B */
        bool ok = simnet_mint_txs(&sim, txs, 2);
        CT_CHECK("in-order: chained spend (A then B) is ACCEPTED", ok);
        CT_CHECK("in-order: tip advances to the new block",
                 simnet_tip_height(&sim) == pre_height + 1);
        CT_CHECK("in-order: A's output is consumed by B",
                 !simnet_coin_exists(&sim, &a_txid));
        CT_CHECK("in-order: B's output exists in the live view",
                 simnet_coin_exists(&sim, &b_txid));

        a_txid_case1 = a_txid;
        b_txid_case1 = b_txid;

        simnet_free(&sim);
    }

    /* ── Case 2: out-of-order chained spend (B before A), built from
     * tx content IDENTICAL to case 1, is rejected. Same maturity
     * setup on a fresh simnet reproduces the exact same coinbase (no
     * randomness anywhere in the harness), so A and B end up with
     * the same txids as case 1 — proving the two blocks differ ONLY
     * in transaction order, not in content. ──────────────────────── */
    {
        struct simnet sim;
        CT_CHECK("out-of-order: simnet init", simnet_init(&sim));

        struct uint256 cb;
        CT_CHECK("out-of-order: mint coinbase", simnet_mint_coinbase(&sim, &cb));
        int cb_height = simnet_tip_height(&sim);

        CT_CHECK("out-of-order: advance to one below maturity",
                 simnet_mint_to_height(&sim, cb_height + COINBASE_MATURITY - 1));
        int pre_height = simnet_tip_height(&sim);

        struct transaction tx_a, tx_b;
        CT_CHECK("out-of-order: build tx A (identical content to case 1)",
                 ct_make_spend(&tx_a, &cb, 0, 900000, 0xA1));
        struct uint256 a_txid = tx_a.hash;
        CT_CHECK("out-of-order: build tx B (identical content to case 1)",
                 ct_make_spend(&tx_b, &a_txid, 0, 800000, 0xB1));
        struct uint256 b_txid = tx_b.hash;

        CT_CHECK("out-of-order: A's txid matches the accepted case 1 block "
                 "(same tx content)",
                 uint256_eq(&a_txid, &a_txid_case1));
        CT_CHECK("out-of-order: B's txid matches the accepted case 1 block "
                 "(same tx content)",
                 uint256_eq(&b_txid, &b_txid_case1));

        struct transaction txs[2] = { tx_b, tx_a };   /* B BEFORE A */
        char reason[256];
        bool ok = ct_mint_capture(&sim, txs, 2, reason, sizeof(reason));
        CT_CHECK("out-of-order: chained spend (B before A) is REJECTED", !ok);
        CT_CHECK("out-of-order: reject reason is bad-txns-inputs-missingorspent",
                 strstr(reason, "bad-txns-inputs-missingorspent") != NULL);
        CT_CHECK("out-of-order: tip does not advance to the bad block",
                 simnet_tip_height(&sim) == pre_height);

        /* Not vacuous: the chain still accepts an honest block after
         * rejecting the out-of-order attempt. */
        struct uint256 honest_cb;
        CT_CHECK("out-of-order: honest block still mints after rejection",
                 simnet_mint_coinbase(&sim, &honest_cb) &&
                 simnet_tip_height(&sim) == pre_height + 1);

        simnet_free(&sim);
    }

    /* ── Positive control: a longer in-order chain (A -> B -> C, all
     * in one block) is accepted, showing the mechanism generalizes
     * past a single hop. ─────────────────────────────────────────── */
    {
        struct simnet sim;
        CT_CHECK("3-chain: simnet init", simnet_init(&sim));

        struct uint256 cb;
        CT_CHECK("3-chain: mint coinbase", simnet_mint_coinbase(&sim, &cb));
        int cb_height = simnet_tip_height(&sim);

        CT_CHECK("3-chain: advance to one below maturity",
                 simnet_mint_to_height(&sim, cb_height + COINBASE_MATURITY - 1));
        int pre_height = simnet_tip_height(&sim);

        struct transaction tx_a, tx_b, tx_c;
        CT_CHECK("3-chain: build tx A (spends matured coinbase)",
                 ct_make_spend(&tx_a, &cb, 0, 900000, 0xC1));
        struct uint256 a_txid = tx_a.hash;
        CT_CHECK("3-chain: build tx B (spends A's output)",
                 ct_make_spend(&tx_b, &a_txid, 0, 800000, 0xC2));
        struct uint256 b_txid = tx_b.hash;
        CT_CHECK("3-chain: build tx C (spends B's output)",
                 ct_make_spend(&tx_c, &b_txid, 0, 700000, 0xC3));
        struct uint256 c_txid = tx_c.hash;

        struct transaction txs[3] = { tx_a, tx_b, tx_c };
        bool ok = simnet_mint_txs(&sim, txs, 3);
        CT_CHECK("3-chain: chained spend (A, B, C in order) is ACCEPTED", ok);
        CT_CHECK("3-chain: tip advances to the new block",
                 simnet_tip_height(&sim) == pre_height + 1);
        CT_CHECK("3-chain: A's output is consumed",
                 !simnet_coin_exists(&sim, &a_txid));
        CT_CHECK("3-chain: B's output is consumed",
                 !simnet_coin_exists(&sim, &b_txid));
        CT_CHECK("3-chain: C's output exists in the live view",
                 simnet_coin_exists(&sim, &c_txid));

        simnet_free(&sim);
    }

    printf("=== simnet_chained_tx: %d failures ===\n", failures);
    return failures;
}

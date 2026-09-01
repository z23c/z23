/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves the empty-input / empty-output structural rejection through
 * simnet's REAL connect_block() — a context-free consensus safety
 * property that every full node MUST enforce before any coin moves.
 *
 * The two structural predicates live in
 * domain/consensus/src/tx_structural.c:92-105
 * (domain_consensus_check_transaction_structural):
 *
 *   - a non-coinbase tx with no transparent vin AND no joinsplit AND no
 *     shielded spend  -> "bad-txns-vin-empty"  (dos 10)
 *   - a tx with no transparent vout AND no joinsplit AND no shielded
 *     output          -> "bad-txns-vout-empty" (dos 10)
 *
 * connect_block reaches them via the full block-validation path:
 *   connect_block()               (core/modules/validation/src/connect_block.c:191)
 *     -> check_block()            (core/modules/validation/src/check_block.c:249)
 *       -> check_transaction_in_block()
 *         -> domain_consensus_check_transaction_structural()
 * so this file exercises the SAME reject surface a live block would hit,
 * driven deterministically with no disk, no PoW, and no real funds.
 *
 * These structural checks fire in check_block BEFORE connect_block's
 * per-input coin-availability check (connect_block.c:~460), so an
 * empty-vout tx carrying a fabricated (never-existing) input is still
 * rejected for vout-empty — not for a missing coin. That ordering is
 * what makes the empty-vout negative meaningful.
 *
 * A positive control (a valid >=1-in / >=1-out spend that commits and
 * advances the tip) guards against the negatives passing vacuously.
 *
 * Distinct from test_validation.c (which calls check_transaction() in
 * isolation) and test_domain_consensus_tx_structural.c (which calls the
 * domain function directly): this is the only place the empty-vin /
 * empty-vout rejects are proven through the assembled-block ->
 * connect_block harness that the token/name/spend simulators build on.
 *
 * Per the harness contract (simnet.h): if a mint is rejected, the fix is
 * always in this file's block construction, never in connect_block.
 */

#include "test/test_core.h"

#include "sim/simnet.h"
/* COINBASE_MATURITY comes from validation/main_constants.h, already
 * included directly by this file. */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define EV_CHECK(name, expr) do {         \
    printf("%s... ", (name));             \
    if ((expr)) printf("OK\n");           \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Build a non-coinbase tx with ZERO inputs and one transparent output.
 * transaction_alloc(tx, 0, 1) leaves tx->vin NULL / num_vin == 0 (see
 * core/modules/primitives/src/transaction.c:73 — a zero count allocates no array),
 * which is exactly the shape the vin-empty predicate rejects. */
static bool ev_make_empty_vin(struct transaction *tx, int64_t out_value)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 0, 1))
        return false;
    tx->version = 1;
    tx->vout[0].value = out_value;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx->vout[0].script_pub_key, pk, sizeof(pk));
    transaction_compute_hash(tx);
    return true;
}

/* Build a tx with one input and ZERO outputs. transaction_alloc(tx, 1, 0)
 * leaves tx->vout NULL / num_vout == 0. The input references a fabricated
 * (never-minted) outpoint: since the vout-empty structural check in
 * check_block runs before connect_block's coin-availability check, the tx
 * is rejected for having no outputs, not for a missing coin. The 0xAA
 * prevout hash is non-null so transaction_is_coinbase() is false and the
 * tx is treated as an ordinary spend. */
static bool ev_make_empty_vout(struct transaction *tx)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 0))
        return false;
    tx->version = 1;
    memset(tx->vin[0].prevout.hash.data, 0xAA, 32);
    tx->vin[0].prevout.n = 0;
    uint8_t sig[] = {0x00, 0x00};
    script_set(&tx->vin[0].script_sig, sig, sizeof(sig));
    tx->vin[0].sequence = 0xFFFFFFFF;
    transaction_compute_hash(tx);
    return true;
}

/* Mint `txs[0..ntx)` while capturing stderr, so this test can read
 * connect_block's reject reason without touching simnet.c (whose public
 * API in simnet.h does not surface validation_state). sim_mint_block()
 * logs "connect_block rejected height %d: %s" via LOG_FAIL() on a rejected
 * block; that is the only place the reason text leaves the harness. Same
 * dup2 pattern as ds_mint_capture() in test_simnet_doublespend.c. If the
 * capture plumbing itself fails, the mint still runs uncaptured (the
 * boolean return — what every assertion relies on — is unaffected). */
static bool ev_mint_capture(struct simnet *sim, struct transaction *txs,
                            size_t ntx, char *out_reason,
                            size_t out_reason_len)
{
    if (out_reason && out_reason_len > 0)
        out_reason[0] = '\0';

    mkdir("./test-tmp", 0755);
    char path[256];
    snprintf(path, sizeof(path),
             "./test-tmp/simnet_empty_vin_vout_stderr_%d.log", (int)getpid());

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
            /* connect_block emits several log lines before sim_mint_block's
             * final "connect_block rejected ...: <reason>" line, so read the
             * TAIL of the capture (the last out_reason_len-1 bytes) rather
             * than the head — otherwise a long preamble truncates the reason
             * string off the end. */
            size_t want = (size_t)sz < out_reason_len - 1
                            ? (size_t)sz : out_reason_len - 1;
            long off = sz - (long)want;
            if (off < 0)
                off = 0;
            fseek(capf, off, SEEK_SET);
            size_t rd = fread(out_reason, 1, want, capf);
            out_reason[rd] = '\0';
        }
    }
    fclose(capf);
    unlink(path);
    return ok;
}

int test_simnet_empty_vin_vout(void)
{
    printf("\n=== simnet empty-vin / empty-vout rejection "
           "(connect_block) ===\n");
    int failures = 0;

    /* ── Positive control: a valid >=1-in / >=1-out spend of a matured
     * coinbase commits and advances the tip, so the negatives below are
     * not vacuously passing. ───────────────────────────────────────── */
    {
        struct simnet sim;
        EV_CHECK("positive control: simnet init", simnet_init(&sim));

        struct uint256 cb;
        EV_CHECK("positive control: mint coinbase",
                 simnet_mint_coinbase(&sim, &cb));

        struct uint256 spend_txid;
        bool spent = simnet_spend(&sim, &cb, 0, 900000, &spend_txid);
        EV_CHECK("positive control: single valid spend succeeds", spent);
        EV_CHECK("positive control: spent coinbase output is consumed",
                 !simnet_coin_exists(&sim, &cb));
        EV_CHECK("positive control: new output exists",
                 simnet_coin_exists(&sim, &spend_txid));

        simnet_free(&sim);
    }

    /* ── Negative 1: a non-coinbase tx with ZERO inputs is rejected for
     * bad-txns-vin-empty, and the tip does not advance. ─────────────── */
    {
        struct simnet sim;
        EV_CHECK("empty-vin: simnet init", simnet_init(&sim));

        /* An honest coinbase first, so the chain is non-trivial and the
         * pre-attempt tip height is meaningful. */
        struct uint256 cb;
        EV_CHECK("empty-vin: mint coinbase", simnet_mint_coinbase(&sim, &cb));
        int pre_attempt_height = simnet_tip_height(&sim);

        struct transaction bad;
        EV_CHECK("empty-vin: build tx with zero inputs",
                 ev_make_empty_vin(&bad, 500000));

        struct transaction txs[1] = { bad };
        char reason[256];
        bool ok = ev_mint_capture(&sim, txs, 1, reason, sizeof(reason));
        EV_CHECK("empty-vin tx is rejected by connect_block", !ok);
        EV_CHECK("empty-vin: reject reason is bad-txns-vin-empty",
                 strstr(reason, "bad-txns-vin-empty") != NULL);
        EV_CHECK("empty-vin: tip does not advance to the bad block",
                 simnet_tip_height(&sim) == pre_attempt_height);

        /* Not vacuous: an honest block still mints after the rejection. */
        struct uint256 honest_cb;
        EV_CHECK("empty-vin: honest block still mints after rejection",
                 simnet_mint_coinbase(&sim, &honest_cb) &&
                 simnet_tip_height(&sim) == pre_attempt_height + 1);

        simnet_free(&sim);
    }

    /* ── Negative 2: a tx with ZERO outputs is rejected for
     * bad-txns-vout-empty (before the coin-availability check, so the
     * fabricated input never matters), and the tip does not advance. ── */
    {
        struct simnet sim;
        EV_CHECK("empty-vout: simnet init", simnet_init(&sim));

        struct uint256 cb;
        EV_CHECK("empty-vout: mint coinbase", simnet_mint_coinbase(&sim, &cb));
        int pre_attempt_height = simnet_tip_height(&sim);

        struct transaction bad;
        EV_CHECK("empty-vout: build tx with zero outputs",
                 ev_make_empty_vout(&bad));

        struct transaction txs[1] = { bad };
        char reason[256];
        bool ok = ev_mint_capture(&sim, txs, 1, reason, sizeof(reason));
        EV_CHECK("empty-vout tx is rejected by connect_block", !ok);
        EV_CHECK("empty-vout: reject reason is bad-txns-vout-empty",
                 strstr(reason, "bad-txns-vout-empty") != NULL);
        EV_CHECK("empty-vout: tip does not advance to the bad block",
                 simnet_tip_height(&sim) == pre_attempt_height);

        struct uint256 honest_cb;
        EV_CHECK("empty-vout: honest block still mints after rejection",
                 simnet_mint_coinbase(&sim, &honest_cb) &&
                 simnet_tip_height(&sim) == pre_attempt_height + 1);

        simnet_free(&sim);
    }

    printf("=== simnet_empty_vin_vout: %d failures ===\n", failures);
    return failures;
}

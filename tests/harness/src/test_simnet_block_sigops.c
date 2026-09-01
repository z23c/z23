/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves the MAX_BLOCK_SIGOPS consensus limit through simnet's REAL
 * connect_block() — a block whose aggregate signature-operation count
 * exceeds the ceiling must be REJECTED with "bad-blk-sigops", and a block
 * exactly AT the ceiling must be ACCEPTED (the tip advances).
 *
 * Consensus source of truth. MAX_BLOCK_SIGOPS = 20000
 * (core/modules/validation/include/validation/main_constants.h:38). connect_block()
 * runs check_block() first (core/modules/validation/src/connect_block.c:191); its
 * aggregate sigop tally lives in
 * domain/consensus/src/check_block.c::domain_consensus_check_block_sigops,
 * which sums get_legacy_sig_op_count() over every vtx and rejects with the
 * reason string "bad-blk-sigops" (check_block.c:185) when the total is
 * strictly greater than 20000. connect_block re-checks the same ceiling on
 * its own incremental tally (connect_block.c:431), so both the legacy and
 * the P2SH-augmented paths share the exact boundary this file straddles.
 *
 * Sigop accounting used here. script_get_sig_op_count (core/modules/script/src/
 * script.c:90, accurate=false) counts one sigop per OP_CHECKSIG (0xac)
 * byte in a scriptPubKey. A single struct script is capped at
 * MAX_SCRIPT_SIZE = 10000 bytes, so each output scriptPubKey contributes at
 * most 10000 sigops; two full 10000-byte OP_CHECKSIG outputs sum to exactly
 * 20000 (== the ceiling, accepted), and adding a third one-byte OP_CHECKSIG
 * output makes 20001 (> the ceiling, rejected). The harness coinbase
 * (sim_make_coinbase: scriptSig has no CHECKSIG opcode, scriptPubKey is the
 * 3-byte {OP_DUP,OP_HASH160,push20} prefix whose trailing push truncates the
 * walk) contributes ZERO sigops, so the spend tx's outputs alone set the
 * block total. This is a deterministic, off-by-one boundary test.
 *
 * Structure mirrors test_simnet_doublespend.c: a positive control (a block
 * exactly at the limit is accepted so the negative is not vacuous), then the
 * negative (one sigop over the limit is rejected with the correct reason and
 * the tip does not advance). Each case runs in its own freshly-initialized
 * simnet. Per the harness contract (sim/simnet.h): if a mint is rejected,
 * the fix is always in this file's block construction, never in
 * connect_block.
 */

#include "test/test_core.h"
#include "validation/main_constants.h"

#include "sim/simnet.h"
/* COINBASE_MATURITY / MAX_BLOCK_SIGOPS come from
 * validation/main_constants.h, already pulled in transitively by
 * included directly by this file. */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SO_CHECK(name, expr) do {         \
    printf("%s... ", (name));             \
    if ((expr)) printf("OK\n");           \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Build a transparent spend of `in_txid`:`in_n` with `nout` outputs, where
 * output i carries `checksig_bytes[i]` OP_CHECKSIG (0xac) bytes in its
 * scriptPubKey — i.e. contributes exactly that many legacy sigops. Each
 * output value is a tiny fixed amount; the (large) remainder of the spent
 * coin is the fee. The scriptSig is a 2-byte placeholder (no sigop opcodes)
 * — expensive_checks=false at simnet mint heights means scriptSig content is
 * never executed, only the outpoint linkage matters. Returns false on an
 * out-of-range request. */
static bool so_make_sigop_spend(struct transaction *tx,
                                const struct uint256 *in_txid,
                                uint32_t in_n,
                                const size_t *checksig_bytes,
                                size_t nout)
{
    transaction_init(tx);
    if (!in_txid || nout == 0)
        return false;
    for (size_t i = 0; i < nout; i++) {
        if (checksig_bytes[i] > MAX_SCRIPT_SIZE)
            return false; /* one script cannot exceed MAX_SCRIPT_SIZE bytes */
    }
    if (!transaction_alloc(tx, 1, nout))
        return false;
    tx->version = 1;
    tx->vin[0].prevout.hash = *in_txid;
    tx->vin[0].prevout.n = in_n;
    uint8_t sig[] = { 0x00, 0x00 };
    script_set(&tx->vin[0].script_sig, sig, sizeof(sig));
    tx->vin[0].sequence = 0xFFFFFFFF;

    static uint8_t checksig_buf[MAX_SCRIPT_SIZE];
    memset(checksig_buf, 0xac /* OP_CHECKSIG */, sizeof(checksig_buf));
    for (size_t i = 0; i < nout; i++) {
        tx->vout[i].value = 1000; /* tiny; remainder of coin is fee */
        if (checksig_bytes[i] == 0) {
            /* A degenerate-but-legal empty scriptPubKey (0 sigops). */
            tx->vout[i].script_pub_key.size = 0;
        } else {
            script_set(&tx->vout[i].script_pub_key, checksig_buf,
                       checksig_bytes[i]);
        }
    }
    transaction_compute_hash(tx);
    return true;
}

/* Mint `txs`/`ntx` through simnet_mint_txs() while capturing stderr so the
 * reject reason logged by sim_mint_block ("connect_block rejected height
 * %d: %s", engine/modules/sim/src/simnet.c:202) can be inspected without any change to
 * simnet.c (whose public API does not surface validation_state). Identical
 * plumbing to ds_mint_capture() in test_simnet_doublespend.c. Best-effort:
 * if the capture plumbing fails the mint still runs and the boolean return
 * value — the thing every assertion here relies on — is unaffected. */
static bool so_mint_capture(struct simnet *sim, struct transaction *txs,
                            size_t ntx, char *out_reason,
                            size_t out_reason_len)
{
    if (out_reason && out_reason_len > 0)
        out_reason[0] = '\0';

    mkdir("./test-tmp", 0755);
    char path[256];
    snprintf(path, sizeof(path),
             "./test-tmp/simnet_block_sigops_stderr_%d.log", (int)getpid());

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

/* Mint a coinbase, mature it, and return its txid in *out_cb. Advances the
 * tip so the NEXT simnet_mint_txs() (at cb_height + COINBASE_MATURITY) can
 * spend `cb` through the real maturity predicate
 * (pindex->nHeight - coin.height >= COINBASE_MATURITY). */
static bool so_fund_mature_coinbase(struct simnet *sim, struct uint256 *out_cb)
{
    if (!simnet_mint_coinbase(sim, out_cb))
        return false;
    int cb_height = simnet_tip_height(sim);
    /* One block short of maturity; the spend block mints at exactly
     * cb_height + COINBASE_MATURITY. */
    return simnet_mint_to_height(sim, cb_height + COINBASE_MATURITY - 1);
}

int test_simnet_block_sigops(void)
{
    printf("\n=== simnet block sigop limit (connect_block) ===\n");
    int failures = 0;

    /* The consensus ceiling this test straddles. */
    SO_CHECK("MAX_BLOCK_SIGOPS is the expected 20000",
             MAX_BLOCK_SIGOPS == 20000);

    /* ── Positive control: a block whose aggregate legacy sigop count is
     * EXACTLY at the ceiling (two 10000-byte OP_CHECKSIG outputs = 20000,
     * plus a zero-sigop coinbase) is ACCEPTED and the tip advances. This
     * proves the negative below is a true off-by-one, not a block rejected
     * for some unrelated reason. ─────────────────────────────────────── */
    {
        struct simnet sim;
        SO_CHECK("at-limit: simnet init", simnet_init(&sim));

        struct uint256 cb;
        SO_CHECK("at-limit: fund + mature coinbase",
                 so_fund_mature_coinbase(&sim, &cb));
        int pre_height = simnet_tip_height(&sim);

        /* 10000 + 10000 = 20000 sigops == MAX_BLOCK_SIGOPS (accepted:
         * the check is strictly `> MAX_BLOCK_SIGOPS`). */
        size_t at_limit[2] = { MAX_SCRIPT_SIZE, MAX_SCRIPT_SIZE };
        struct transaction spend_at;
        SO_CHECK("at-limit: build 20000-sigop spend",
                 so_make_sigop_spend(&spend_at, &cb, 0, at_limit, 2));

        struct transaction txs[1] = { spend_at };
        struct uint256 spend_txid = txs[0].hash;
        char reason[2048];
        bool ok = so_mint_capture(&sim, txs, 1, reason, sizeof(reason));
        SO_CHECK("at-limit block (20000 sigops) is accepted", ok);
        SO_CHECK("at-limit: tip advances by one",
                 simnet_tip_height(&sim) == pre_height + 1);
        SO_CHECK("at-limit: spend output exists in the UTXO set",
                 simnet_coin_exists(&sim, &spend_txid));

        simnet_free(&sim);
    }

    /* ── Negative: a block ONE sigop over the ceiling (two 10000-byte
     * OP_CHECKSIG outputs + one 1-byte OP_CHECKSIG output = 20001) is
     * REJECTED with "bad-blk-sigops", and the tip does not advance. ──── */
    {
        struct simnet sim;
        SO_CHECK("over-limit: simnet init", simnet_init(&sim));

        struct uint256 cb;
        SO_CHECK("over-limit: fund + mature coinbase",
                 so_fund_mature_coinbase(&sim, &cb));
        int pre_height = simnet_tip_height(&sim);

        /* 10000 + 10000 + 1 = 20001 sigops > MAX_BLOCK_SIGOPS. */
        size_t over_limit[3] = { MAX_SCRIPT_SIZE, MAX_SCRIPT_SIZE, 1 };
        struct transaction spend_over;
        SO_CHECK("over-limit: build 20001-sigop spend",
                 so_make_sigop_spend(&spend_over, &cb, 0, over_limit, 3));

        struct transaction txs[1] = { spend_over };
        struct uint256 spend_txid = txs[0].hash;
        char reason[2048];
        bool ok = so_mint_capture(&sim, txs, 1, reason, sizeof(reason));
        SO_CHECK("over-limit block (20001 sigops) is rejected by connect_block",
                 !ok);
        SO_CHECK("over-limit: reject reason is bad-blk-sigops",
                 strstr(reason, "bad-blk-sigops") != NULL);
        SO_CHECK("over-limit: tip does not advance to the bad block",
                 simnet_tip_height(&sim) == pre_height);
        SO_CHECK("over-limit: spend output is absent from the UTXO set",
                 !simnet_coin_exists(&sim, &spend_txid));

        /* Not vacuous: the chain still accepts an honest block after
         * rejecting the over-limit block. */
        struct uint256 honest_cb;
        SO_CHECK("over-limit: honest block still mints after rejection",
                 simnet_mint_coinbase(&sim, &honest_cb) &&
                 simnet_tip_height(&sim) == pre_height + 1);

        simnet_free(&sim);
    }

    printf("=== simnet_block_sigops: %d failures ===\n", failures);
    return failures;
}

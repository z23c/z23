/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_utxo_apply_coinbase_maturity - pins the DEFAULT-OFF coinbase-maturity
 * parity reject on the LIVE fold path (utxo_apply_compute_block_delta).
 *
 * Background. zclassicd's Consensus::CheckTxInputs (zclassic-cpp/src/main.cpp
 * :2056-2060) rejects "bad-txns-premature-spend-of-coinbase" when a tx spends
 * a coinbase output whose creation height is within COINBASE_MATURITY (100) of
 * the spending block's height (nSpendHeight - coins->nHeight <
 * COINBASE_MATURITY, where nSpendHeight = pindexPrev->nHeight + 1 = the height
 * of the block being connected). zclassic23 enforced this only in the
 * boot-reindex connect_block.c path and the repair ladder; the LIVE reducer
 * fold (utxo_apply_delta.c) did not. The fix adds the reject behind the
 * DEFAULT-OFF runtime flag g_enforce_coinbase_maturity
 * (-enforce-coinbase-maturity).
 *
 * This test pins both behaviors with hand-built blocks and a trivial in-test
 * lookup that returns a COINBASE coin at a controllable creation height:
 *
 *   (a) Flag OFF (DEFAULT) + a premature coinbase spend (depth < 100)
 *       -> ACCEPTS. The byte-identical-to-today guarantee: default behavior
 *       does NOT reject on this path.
 *   (b) Flag ON + the SAME premature spend (depth < 100) -> REJECTS with
 *       failure_kind "bad-txns-premature-spend-of-coinbase".
 *   (c) Flag ON + a MATURE coinbase spend (depth == 100) -> ACCEPTS.
 *   (d) Flag ON + spending a NON-coinbase coin at depth 0 -> ACCEPTS
 *       (the rule is coinbase-only; a normal coin is never premature).
 *
 * compute_block_delta is called DIRECTLY; no datadir or coins_kv is needed
 * for the predicate cases. Case (b2) additionally proves the reject is durable
 * through an isolated coins_kv apply attempt (the delta is never applied when
 * ok==false). The global flag is restored to its default (off) at the end.
 */

#include "test/test_core.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"  /* enum chain_network */
#include "core/uint256.h"
#include "jobs/utxo_apply_delta.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/replay_count_only.h"   /* D2 replay-gate count-and-continue */
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "util/safe_alloc.h"
#include "validation/main_constants.h"  /* COINBASE_MATURITY */

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>   /* setenv / unsetenv */
#include <string.h>

#define UCM_CHECK(name, expr) do {                          \
    printf("utxo_apply_coinbase_maturity: %s... ", (name)); \
    if ((expr)) printf("OK\n");                             \
    else { printf("FAIL\n"); failures++; }                  \
} while (0)

/* The single external input coin the spend consumes, with the creation
 * height + coinbase flag the lookup reports back to the reducer. */
struct ucm_coin {
    struct uint256 txid;
    uint32_t vout;
    int64_t value;
    uint32_t height;
    bool is_coinbase;
};

static bool ucm_lookup(const struct uint256 *txid, uint32_t vout,
                       struct utxo_apply_lookup *out, void *user)
{
    const struct ucm_coin *c = user;
    memset(out, 0, sizeof(*out));
    if (c && c->vout == vout && uint256_eq(&c->txid, txid)) {
        out->found = true;
        out->value = c->value;
        out->height = c->height;
        out->is_coinbase = c->is_coinbase;
        out->script_len = 0;
    }
    return true;
}

/* Coinbase vtx[0]: value irrelevant to the rule under test, distinct hash. */
static void ucm_make_coinbase(struct transaction *tx, uint8_t tag)
{
    transaction_init(tx);
    (void)transaction_alloc(tx, 1, 1);
    outpoint_set_null(&tx->vin[0].prevout);
    tx->vout[0].value = 1000000000LL;
    uint8_t pk[3] = { 0x76, 0xa9, tag };
    script_set(&tx->vout[0].script_pub_key, pk, 3);
    uint256_set_null(&tx->hash);
    tx->hash.data[0] = 0xC0;
    tx->hash.data[1] = tag;
}

/* Set vout[i] to a distinct P2PKH-shaped (spendable) script. Using a SHIELDED
 * (zero-vout) spend would dodge the coinbase-transparent-output protection
 * rule; a transparent output is fine here because that protection rule is
 * itself gated on chain_params fCoinbaseMustBeProtected, and on regtest (the
 * test chain) that flag is false, so only the maturity rule under test fires. */
static void ucm_set_normal_out(struct transaction *tx, size_t i, int64_t value,
                               uint8_t marker)
{
    tx->vout[i].value = value;
    uint8_t pk[4] = { 0x76, 0xa9, 0xBB, marker };
    script_set(&tx->vout[i].script_pub_key, pk, 4);
}

/* Build a {coinbase, spend} block. The spend consumes `coin` and has one
 * output the caller fills after this returns. */
static bool ucm_build_block(struct block *b, uint8_t tag,
                            const struct ucm_coin *coin)
{
    block_init(b);
    b->num_vtx = 2;
    b->vtx = zcl_calloc(b->num_vtx, sizeof(struct transaction), "ucm_vtx");
    if (!b->vtx) return false;
    ucm_make_coinbase(&b->vtx[0], tag);
    transaction_init(&b->vtx[1]);
    if (!transaction_alloc(&b->vtx[1], 1, 1)) return false;
    b->vtx[1].vin[0].prevout.hash = coin->txid;
    b->vtx[1].vin[0].prevout.n = coin->vout;
    uint256_set_null(&b->vtx[1].hash);
    b->vtx[1].hash.data[0] = 0x5E;
    b->vtx[1].hash.data[1] = tag;
    return true;
}

int test_utxo_apply_coinbase_maturity(void);
int test_utxo_apply_coinbase_maturity(void)
{
    printf("\n=== utxo_apply coinbase-maturity parity (default-off) ===\n");
    int failures = 0;

    /* Run on regtest, where fCoinbaseMustBeProtected is false
     * (chainparams.c:575). That keeps the separate
     * coinbase-spend-has-transparent-outputs protection rule
     * (utxo_apply_delta.c) from rejecting the transparent-output coinbase
     * spends in the ACCEPT cases below, isolating the maturity rule under
     * test. Restore the prior network at the end. */
    enum chain_network saved_net = CHAIN_MAIN;
    {
        const char *id = chain_params_get()->strNetworkID;
        if (strcmp(id, "test") == 0)        saved_net = CHAIN_TESTNET;
        else if (strcmp(id, "regtest") == 0) saved_net = CHAIN_REGTEST;
        else                                 saved_net = CHAIN_MAIN;
    }
    chain_params_select(CHAIN_REGTEST);

    /* A coinbase coin created at height 10. The spending block height controls
     * the depth: spend at height (10 + COINBASE_MATURITY - 1) is premature
     * (depth 99 < 100); spend at height (10 + COINBASE_MATURITY) is mature
     * (depth 100). */
    struct ucm_coin cb;
    memset(&cb, 0, sizeof(cb));
    cb.txid.data[0] = 0xE7;
    cb.txid.data[1] = 0x0C;
    cb.vout = 0;
    cb.value = 1250000000LL;
    cb.height = 10;
    cb.is_coinbase = true;

    const uint32_t premature_h = cb.height + COINBASE_MATURITY - 1; /* depth 99 */
    const uint32_t mature_h    = cb.height + COINBASE_MATURITY;     /* depth 100 */

    /* (a) DEFAULT (flag OFF) + premature coinbase spend -> ACCEPTS (unchanged).
     * This is the byte-identical-to-today guarantee. */
    {
        atomic_store(&g_enforce_coinbase_maturity, false);
        struct block b;
        bool built = ucm_build_block(&b, 0xA1, &cb);
        UCM_CHECK("(a) premature block builds", built);
        if (built) {
            ucm_set_normal_out(&b.vtx[1], 0, cb.value, 0x11);
            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, premature_h, ucm_lookup, &cb,
                                           &out);
            UCM_CHECK("(a) flag OFF: premature spend ACCEPTS (byte-identical)",
                      out.ok == true);
            UCM_CHECK("(a) flag OFF: the coinbase input was spent",
                      out.spent_count == 1);
            free_delta(&out);
        }
        block_free(&b);
    }

    /* (a2) D2 AUTHORITY INTEGRATION PIN (parity-audit round 3).
     * The earlier (a) check pins the accept/reject decision; this case pins
     * that the LIVE-FOLD AUTHORITY (utxo_apply_compute_block_delta, the
     * function utxo_apply_stage.c drives to author coins_kv) actually FOLDS a
     * block that spends a coinbase at depth 99 with the flag OFF — it does NOT
     * block. We assert the full delta the authority produces, not merely that
     * it didn't error: the coinbase coin is recorded as spent with its
     * is_coinbase flag and creation height preserved, the new output is added,
     * and total_value_delta nets the spend against the new output. zclassicd
     * would REJECT this block (bad-txns-premature-spend-of-coinbase); zcl23
     * accepts it on the live author path today. Pinning the WHOLE delta makes
     * a future default-on flip (the tightening) flip this case loudly. */
    {
        atomic_store(&g_enforce_coinbase_maturity, false);
        struct block b;
        bool built = ucm_build_block(&b, 0xA2, &cb);
        UCM_CHECK("(a2) authority: depth-99 block builds", built);
        if (built) {
            const int64_t out_value = cb.value - 1000; /* leave a small fee */
            ucm_set_normal_out(&b.vtx[1], 0, out_value, 0x21);
            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, premature_h, ucm_lookup, &cb,
                                           &out);
            UCM_CHECK("(a2) authority flag OFF: depth-99 coinbase spend "
                      "does NOT block (ok)", out.ok == true);
            UCM_CHECK("(a2) authority: exactly one input spent",
                      out.spent_count == 1);
            UCM_CHECK("(a2) authority: spent coin is the coinbase coin",
                      out.spent_count == 1 && out.spent != NULL &&
                      out.spent[0].is_coinbase == true &&
                      out.spent[0].height == cb.height &&
                      out.spent[0].value == cb.value);
            /* added: vtx[1].vout[0]; the coinbase vtx[0] output is also added.
             * The authority records every spendable output, so added_count is
             * the 2 outputs (coinbase out + the spend's out). */
            UCM_CHECK("(a2) authority: outputs were added",
                      out.added_count == 2);
            /* total_value_delta = (added outputs) - (spent coinbase). The
             * coinbase vtx[0] adds 1,000,000,000 (ucm_make_coinbase), the
             * spend adds out_value, and the spent coinbase removes cb.value. */
            UCM_CHECK("(a2) authority: value delta nets spend vs new outputs",
                      out.total_value_delta ==
                          (1000000000LL + out_value) - cb.value);
            free_delta(&out);
        }
        block_free(&b);
    }

    /* (b) Flag ON + premature coinbase spend -> REJECTS. */
    {
        atomic_store(&g_enforce_coinbase_maturity, true);
        struct block b;
        bool built = ucm_build_block(&b, 0xB2, &cb);
        UCM_CHECK("(b) premature block builds", built);
        if (built) {
            ucm_set_normal_out(&b.vtx[1], 0, cb.value, 0x12);
            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, premature_h, ucm_lookup, &cb,
                                           &out);
            UCM_CHECK("(b) flag ON: premature spend REJECTS", out.ok == false);
            UCM_CHECK("(b) flag ON: reject is bad-txns-premature-spend-of-coinbase",
                      out.failure_kind != NULL &&
                      strcmp(out.failure_kind,
                             "bad-txns-premature-spend-of-coinbase") == 0);
            free_delta(&out);
        }
        block_free(&b);
        atomic_store(&g_enforce_coinbase_maturity, false);
    }

    /* (c) Flag ON + MATURE coinbase spend (depth == 100) -> ACCEPTS. */
    {
        atomic_store(&g_enforce_coinbase_maturity, true);
        struct block b;
        bool built = ucm_build_block(&b, 0xC3, &cb);
        UCM_CHECK("(c) mature block builds", built);
        if (built) {
            ucm_set_normal_out(&b.vtx[1], 0, cb.value, 0x13);
            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, mature_h, ucm_lookup, &cb, &out);
            UCM_CHECK("(c) flag ON: mature spend (depth 100) ACCEPTS",
                      out.ok == true);
            UCM_CHECK("(c) flag ON: the coinbase input was spent",
                      out.spent_count == 1);
            free_delta(&out);
        }
        block_free(&b);
        atomic_store(&g_enforce_coinbase_maturity, false);
    }

    /* (d) Flag ON + spending a NON-coinbase coin at depth 0 -> ACCEPTS.
     * The maturity rule is coinbase-only; a normal coin is never premature. */
    {
        atomic_store(&g_enforce_coinbase_maturity, true);
        struct ucm_coin normal = cb;
        normal.txid.data[0] = 0xE8;       /* distinct coin */
        normal.is_coinbase = false;
        normal.height = 12;
        struct block b;
        bool built = ucm_build_block(&b, 0xD4, &normal);
        UCM_CHECK("(d) non-coinbase block builds", built);
        if (built) {
            ucm_set_normal_out(&b.vtx[1], 0, normal.value, 0x14);
            struct delta_summary out;
            /* Spend at height 12 (depth 0) — would be premature IF coinbase. */
            utxo_apply_compute_block_delta(&b, 12, ucm_lookup, &normal, &out);
            UCM_CHECK("(d) flag ON: non-coinbase coin at depth 0 ACCEPTS",
                      out.ok == true);
            UCM_CHECK("(d) flag ON: the non-coinbase input was spent",
                      out.spent_count == 1);
            free_delta(&out);
        }
        block_free(&b);
        atomic_store(&g_enforce_coinbase_maturity, false);
    }

    /* (e) D2 REPLAY-GATE COUNT-AND-CONTINUE (env-gated ZCL_REPLAY_COUNT_ONLY).
     * The MOST IMPORTANT mechanism check: when the env gate is active AND the
     * tightening flag is ON, a premature coinbase spend must be LOGGED+COUNTED
     * and the delta must come back as a NON-halting SKIP that authors NO coins
     * — proving the count-only fold reads/logs/continues and never authors
     * coins past a fire (so it can reach tip and count EVERY offender, never
     * corrupting the copy's coins_kv). */
    {
        replay_count_only_reset_for_test();   /* clears cached env + counters */
        setenv("ZCL_REPLAY_COUNT_ONLY", "1", 1);
        atomic_store(&g_enforce_coinbase_maturity, true);

        UCM_CHECK("(e) count-only env latches active",
                  replay_count_only_active() == true);

        struct block b;
        bool built = ucm_build_block(&b, 0xE5, &cb);
        UCM_CHECK("(e) count-only block builds", built);
        if (built) {
            ucm_set_normal_out(&b.vtx[1], 0, cb.value, 0x15);
            struct delta_summary out;
            /* Same premature (depth 99) spend as (b), which REJECTS+HALTS when
             * the env is unset. In count-only mode it must NOT halt. */
            utxo_apply_compute_block_delta(&b, premature_h, ucm_lookup, &cb,
                                           &out);
            /* (1) does NOT flip ok / halt the frontier */
            UCM_CHECK("(e) count-only: fire does NOT halt (ok stays true)",
                      out.ok == true);
            /* (2) marked as a count-only skip so the stage skips authoring */
            UCM_CHECK("(e) count-only: block marked count_only_d2_skip",
                      out.count_only_d2_skip == true);
            /* (3) authors NO coins past the fire — the load-bearing safety */
            UCM_CHECK("(e) count-only: NO coins authored (0 spent, 0 added)",
                      out.spent_count == 0 && out.added_count == 0 &&
                      out.spent == NULL && out.added == NULL &&
                      out.total_value_delta == 0);
            /* (4) the fire was COUNTED + first offending height recorded */
            UCM_CHECK("(e) count-only: the fire was counted (total == 1)",
                      replay_count_only_total_rejected() == 1);
            UCM_CHECK("(e) count-only: first offending height recorded",
                      replay_count_only_first_offending_height() ==
                          (int64_t)premature_h);
            free_delta(&out);
        }
        block_free(&b);

        /* (e2) CONTROL — with the env UNSET, the SAME premature spend rejects
         * exactly as case (b) did. This is the live-path-unchanged proof: the
         * count-only branch is unreachable when the env is unset, so the fold
         * makes the identical reject decision it makes today. */
        unsetenv("ZCL_REPLAY_COUNT_ONLY");
        replay_count_only_reset_for_test();   /* re-latch from the unset env */
        UCM_CHECK("(e2) env unset latches INACTIVE",
                  replay_count_only_active() == false);
        struct block b2;
        bool built2 = ucm_build_block(&b2, 0xE6, &cb);
        UCM_CHECK("(e2) control block builds", built2);
        if (built2) {
            ucm_set_normal_out(&b2.vtx[1], 0, cb.value, 0x16);
            struct delta_summary out2;
            utxo_apply_compute_block_delta(&b2, premature_h, ucm_lookup, &cb,
                                           &out2);
            UCM_CHECK("(e2) env unset: premature spend REJECTS (live unchanged)",
                      out2.ok == false &&
                      out2.count_only_d2_skip == false &&
                      out2.failure_kind != NULL &&
                      strcmp(out2.failure_kind,
                             "bad-txns-premature-spend-of-coinbase") == 0);
            free_delta(&out2);
        }
        block_free(&b2);
        atomic_store(&g_enforce_coinbase_maturity, false);
        replay_count_only_reset_for_test();
    }

    /* Leave the global in its default (off) state for any later group. */
    atomic_store(&g_enforce_coinbase_maturity, false);
    /* Restore the network selection the caller (or a prior group) had. */
    chain_params_select(saved_net);

    printf("=== utxo_apply coinbase-maturity parity: %d failures ===\n",
           failures);
    return failures;
}

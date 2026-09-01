/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Coin selection audit tests: adversarial UTXO distributions.
 *
 * Exercises wallet_select_coins with dust, many small, few large,
 * exact match, and edge-case UTXO sets.  Pins deterministic minimal-input
 * selection so wallet insertion order cannot inflate fees or signing work. */

#include "test/test_core.h"
#include "wallet/wallet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"

#define ZCL_COIN   100000000LL  /* 1 ZCL = 1e8 zatoshi */
#define ZCL_DUST   546LL        /* dust threshold */
#define MAX_SEL 256

/* ── Synthetic UTXO helpers ──────────────────────────────── */

/* Build a minimal wallet_tx with a single output of the given value.
 * Allocated on heap — caller must free each wtx. */
static struct wallet_tx *make_wtx(int64_t value, int confirms)
{
    struct wallet_tx *wtx = zcl_calloc(1, sizeof(*wtx), "test_wtx");
    if (!wtx) return NULL;
    wtx->used = true;
    wtx->confirms = confirms;
    wtx->tx.num_vout = 1;
    wtx->tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_vout");
    if (!wtx->tx.vout) { free(wtx); return NULL; }
    wtx->tx.vout[0].value = value;
    return wtx;
}

static void free_wtx(struct wallet_tx *wtx)
{
    if (!wtx) return;
    free(wtx->tx.vout);
    free(wtx);
}

/* Build a coin_entry array from value/count pairs.
 * Returns heap-allocated arrays in *coins_out and *wtxs_out.
 * Caller must free both (and each wtx via free_wtx). */
static size_t make_utxo_set(const int64_t *values, size_t n,
                              struct coin_entry **coins_out,
                              struct wallet_tx ***wtxs_out)
{
    struct coin_entry *coins = zcl_calloc(n, sizeof(struct coin_entry), "test_coins");
    struct wallet_tx **wtxs = zcl_calloc(n, sizeof(struct wallet_tx *), "test_wtxs");
    for (size_t i = 0; i < n; i++) {
        wtxs[i] = make_wtx(values[i], 6);
        coins[i].wtx = wtxs[i];
        coins[i].i = 0;
        coins[i].depth = 6;
        coins[i].spendable = true;
        coins[i].solvable = true;
    }
    *coins_out = coins;
    *wtxs_out = wtxs;
    return n;
}

static void free_utxo_set(struct coin_entry *coins, struct wallet_tx **wtxs,
                            size_t n)
{
    for (size_t i = 0; i < n; i++)
        free_wtx(wtxs[i]);
    free(wtxs);
    free(coins);
}

/* ── Tests ───────────────────────────────────────────────── */

static int test_exact_single_coin(void)
{
    int failures = 0;
    TEST("coin-sel: exact single coin match") {
        int64_t vals[] = { 1 * ZCL_COIN, 2 * ZCL_COIN, 5 * ZCL_COIN };
        struct coin_entry *coins; struct wallet_tx **wtxs;
        size_t n = make_utxo_set(vals, 3, &coins, &wtxs);

        struct coin_entry sel[MAX_SEL];
        size_t nsel = 0; int64_t total = 0;

        bool ok = wallet_select_coins(NULL, coins, n, 1 * ZCL_COIN,
                                        sel, &nsel, MAX_SEL, &total);
        ASSERT(ok);
        ASSERT(total >= 1 * ZCL_COIN);
        /* Smallest sufficient single coin is the exact match. */
        ASSERT_EQ(nsel, (size_t)1);
        ASSERT_EQ(total, 1 * ZCL_COIN);

        free_utxo_set(coins, wtxs, n);
        PASS();
    } _test_next:;
    return failures;
}

static int test_many_dust_utxos(void)
{
    int failures = 0;
    TEST("coin-sel: 100 dust UTXOs cannot reach 1 ZCL target") {
        int64_t vals[100];
        for (int i = 0; i < 100; i++) vals[i] = ZCL_DUST;
        struct coin_entry *coins; struct wallet_tx **wtxs;
        size_t n = make_utxo_set(vals, 100, &coins, &wtxs);

        struct coin_entry sel[MAX_SEL];
        size_t nsel = 0; int64_t total = 0;

        bool ok = wallet_select_coins(NULL, coins, n, 1 * ZCL_COIN,
                                        sel, &nsel, MAX_SEL, &total);
        /* 100 * 546 = 54,600 < 100,000,000 = 1 ZCL */
        ASSERT(!ok);
        ASSERT(total < 1 * ZCL_COIN);
        ASSERT_EQ(nsel, (size_t)100);

        free_utxo_set(coins, wtxs, n);
        PASS();
    } _test_next:;
    return failures;
}

static int test_many_dust_plus_one_large(void)
{
    int failures = 0;
    TEST("coin-sel: dust+large — selects the one sufficient coin") {
        int64_t vals[51];
        for (int i = 0; i < 50; i++) vals[i] = ZCL_DUST;  /* 50 dust coins */
        vals[50] = 10 * ZCL_COIN;                           /* one large coin */
        struct coin_entry *coins; struct wallet_tx **wtxs;
        size_t n = make_utxo_set(vals, 51, &coins, &wtxs);

        struct coin_entry sel[MAX_SEL];
        size_t nsel = 0; int64_t total = 0;

        bool ok = wallet_select_coins(NULL, coins, n, 1 * ZCL_COIN,
                                        sel, &nsel, MAX_SEL, &total);
        ASSERT(ok);
        ASSERT_EQ(nsel, (size_t)1);
        ASSERT_EQ(total, 10 * ZCL_COIN);

        free_utxo_set(coins, wtxs, n);
        PASS();
    } _test_next:;
    return failures;
}

static int test_large_then_dust(void)
{
    int failures = 0;
    TEST("coin-sel: large before dust — selects single large") {
        int64_t vals[51];
        vals[0] = 10 * ZCL_COIN;                            /* large coin first */
        for (int i = 1; i <= 50; i++) vals[i] = ZCL_DUST;   /* then dust */
        struct coin_entry *coins; struct wallet_tx **wtxs;
        size_t n = make_utxo_set(vals, 51, &coins, &wtxs);

        struct coin_entry sel[MAX_SEL];
        size_t nsel = 0; int64_t total = 0;

        bool ok = wallet_select_coins(NULL, coins, n, 1 * ZCL_COIN,
                                        sel, &nsel, MAX_SEL, &total);
        ASSERT(ok);
        ASSERT_EQ(nsel, (size_t)1);
        ASSERT_EQ(total, 10 * ZCL_COIN);

        free_utxo_set(coins, wtxs, n);
        PASS();
    } _test_next:;
    return failures;
}

static int test_few_large_coins(void)
{
    int failures = 0;
    TEST("coin-sel: 3 large coins — selects minimum to cover target") {
        int64_t vals[] = { 100 * ZCL_COIN, 200 * ZCL_COIN, 500 * ZCL_COIN };
        struct coin_entry *coins; struct wallet_tx **wtxs;
        size_t n = make_utxo_set(vals, 3, &coins, &wtxs);

        struct coin_entry sel[MAX_SEL];
        size_t nsel = 0; int64_t total = 0;

        bool ok = wallet_select_coins(NULL, coins, n, 150 * ZCL_COIN,
                                        sel, &nsel, MAX_SEL, &total);
        ASSERT(ok);
        /* The smallest sufficient single coin wins. */
        ASSERT_EQ(nsel, (size_t)1);
        ASSERT_EQ(total, 200 * ZCL_COIN);

        free_utxo_set(coins, wtxs, n);
        PASS();
    } _test_next:;
    return failures;
}

static int test_empty_utxo_set(void)
{
    int failures = 0;
    TEST("coin-sel: empty UTXO set fails") {
        struct coin_entry sel[1];
        size_t nsel = 0; int64_t total = 0;

        bool ok = wallet_select_coins(NULL, NULL, 0, 1 * ZCL_COIN,
                                        sel, &nsel, 1, &total);
        ASSERT(!ok);
        ASSERT_EQ(nsel, (size_t)0);
        ASSERT_EQ(total, (int64_t)0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_all_unspendable(void)
{
    int failures = 0;
    TEST("coin-sel: all unspendable UTXOs fails") {
        int64_t vals[] = { 1 * ZCL_COIN, 2 * ZCL_COIN };
        struct coin_entry *coins; struct wallet_tx **wtxs;
        size_t n = make_utxo_set(vals, 2, &coins, &wtxs);

        /* Mark all as unspendable. */
        for (size_t i = 0; i < n; i++)
            coins[i].spendable = false;

        struct coin_entry sel[MAX_SEL];
        size_t nsel = 0; int64_t total = 0;

        bool ok = wallet_select_coins(NULL, coins, n, 1 * ZCL_COIN,
                                        sel, &nsel, MAX_SEL, &total);
        ASSERT(!ok);
        ASSERT_EQ(nsel, (size_t)0);

        free_utxo_set(coins, wtxs, n);
        PASS();
    } _test_next:;
    return failures;
}

static int test_target_zero(void)
{
    int failures = 0;
    TEST("coin-sel: target=0 succeeds without consuming a coin") {
        int64_t vals[] = { 1 * ZCL_COIN };
        struct coin_entry *coins; struct wallet_tx **wtxs;
        size_t n = make_utxo_set(vals, 1, &coins, &wtxs);

        struct coin_entry sel[MAX_SEL];
        size_t nsel = 0; int64_t total = 0;

        bool ok = wallet_select_coins(NULL, coins, n, 0,
                                        sel, &nsel, MAX_SEL, &total);
        ASSERT(ok);
        ASSERT_EQ(nsel, (size_t)0);
        ASSERT_EQ(total, (int64_t)0);

        free_utxo_set(coins, wtxs, n);
        PASS();
    } _test_next:;
    return failures;
}

static int test_prefers_single_over_exact_pair(void)
{
    int failures = 0;
    TEST("coin-sel: one sufficient input beats an exact two-input pair") {
        int64_t vals[] = { 3 * ZCL_COIN, 7 * ZCL_COIN, 20 * ZCL_COIN };
        struct coin_entry *coins; struct wallet_tx **wtxs;
        size_t n = make_utxo_set(vals, 3, &coins, &wtxs);

        struct coin_entry sel[MAX_SEL];
        size_t nsel = 0; int64_t total = 0;

        bool ok = wallet_select_coins(NULL, coins, n, 10 * ZCL_COIN,
                                        sel, &nsel, MAX_SEL, &total);
        ASSERT(ok);
        /* One 20 ZCL input costs less to process than two smaller inputs. */
        ASSERT_EQ(nsel, (size_t)1);
        ASSERT_EQ(total, 20 * ZCL_COIN);

        free_utxo_set(coins, wtxs, n);
        PASS();
    } _test_next:;
    return failures;
}

static int test_many_small_coins(void)
{
    int failures = 0;
    TEST("coin-sel: 200 small coins (0.01 ZCL each)") {
        int64_t vals[200];
        for (int i = 0; i < 200; i++) vals[i] = ZCL_COIN / 100;  /* 0.01 ZCL */
        struct coin_entry *coins; struct wallet_tx **wtxs;
        size_t n = make_utxo_set(vals, 200, &coins, &wtxs);

        struct coin_entry sel[MAX_SEL];
        size_t nsel = 0; int64_t total = 0;

        /* Target: 1 ZCL = 100 * 0.01 ZCL */
        bool ok = wallet_select_coins(NULL, coins, n, 1 * ZCL_COIN,
                                        sel, &nsel, MAX_SEL, &total);
        ASSERT(ok);
        ASSERT_EQ(nsel, (size_t)100);
        ASSERT_EQ(total, 1 * ZCL_COIN);

        free_utxo_set(coins, wtxs, n);
        PASS();
    } _test_next:;
    return failures;
}

static int test_max_selected_limit(void)
{
    int failures = 0;
    TEST("coin-sel: max_selected limit honored") {
        int64_t vals[] = { ZCL_COIN / 10, ZCL_COIN / 10, ZCL_COIN / 10, ZCL_COIN / 10, ZCL_COIN / 10 };
        struct coin_entry *coins; struct wallet_tx **wtxs;
        size_t n = make_utxo_set(vals, 5, &coins, &wtxs);

        struct coin_entry sel[2];
        size_t nsel = 0; int64_t total = 0;

        /* Target 1 ZCL needs all 5, but max_selected=2 */
        bool ok = wallet_select_coins(NULL, coins, n, 1 * ZCL_COIN,
                                        sel, &nsel, 2, &total);
        ASSERT(!ok);
        ASSERT_EQ(nsel, (size_t)2);
        ASSERT_EQ(total, ZCL_COIN / 5);  /* 0.2 ZCL */

        free_utxo_set(coins, wtxs, n);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mixed_spendable_unspendable(void)
{
    int failures = 0;
    TEST("coin-sel: mixed spendable/unspendable skips correctly") {
        int64_t vals[] = { 5 * ZCL_COIN, 3 * ZCL_COIN, 2 * ZCL_COIN, 1 * ZCL_COIN };
        struct coin_entry *coins; struct wallet_tx **wtxs;
        size_t n = make_utxo_set(vals, 4, &coins, &wtxs);

        /* Make first and third unspendable. */
        coins[0].spendable = false;  /* 5 ZCL — skip */
        coins[2].spendable = false;  /* 2 ZCL — skip */

        struct coin_entry sel[MAX_SEL];
        size_t nsel = 0; int64_t total = 0;

        bool ok = wallet_select_coins(NULL, coins, n, 4 * ZCL_COIN,
                                        sel, &nsel, MAX_SEL, &total);
        /* Only 3 + 1 = 4 ZCL available spendable */
        ASSERT(ok);
        ASSERT_EQ(nsel, (size_t)2);
        ASSERT_EQ(total, 4 * ZCL_COIN);

        free_utxo_set(coins, wtxs, n);
        PASS();
    } _test_next:;
    return failures;
}

static int test_single_satoshi(void)
{
    int failures = 0;
    TEST("coin-sel: target 1 satoshi with 1 satoshi coin") {
        int64_t vals[] = { 1 };
        struct coin_entry *coins; struct wallet_tx **wtxs;
        size_t n = make_utxo_set(vals, 1, &coins, &wtxs);

        struct coin_entry sel[1];
        size_t nsel = 0; int64_t total = 0;

        bool ok = wallet_select_coins(NULL, coins, n, 1,
                                        sel, &nsel, 1, &total);
        ASSERT(ok);
        ASSERT_EQ(nsel, (size_t)1);
        ASSERT_EQ(total, (int64_t)1);

        free_utxo_set(coins, wtxs, n);
        PASS();
    } _test_next:;
    return failures;
}

static int test_change_overshoot(void)
{
    int failures = 0;
    TEST("coin-sel: documents change overshoot with large coins") {
        /* Only have 10 ZCL coins, target 1.5 ZCL — change = 8.5 ZCL */
        int64_t vals[] = { 10 * ZCL_COIN };
        struct coin_entry *coins; struct wallet_tx **wtxs;
        size_t n = make_utxo_set(vals, 1, &coins, &wtxs);

        struct coin_entry sel[MAX_SEL];
        size_t nsel = 0; int64_t total = 0;

        bool ok = wallet_select_coins(NULL, coins, n, ZCL_COIN + ZCL_COIN / 2,
                                        sel, &nsel, MAX_SEL, &total);
        ASSERT(ok);
        int64_t change = total - (ZCL_COIN + ZCL_COIN / 2);
        /* Change = 10 - 1.5 = 8.5 ZCL — large overshoot */
        ASSERT(change == (int64_t)(ZCL_COIN * 85 / 10));
        ASSERT_EQ(nsel, (size_t)1);

        free_utxo_set(coins, wtxs, n);
        PASS();
    } _test_next:;
    return failures;
}

static int test_order_independence(void)
{
    int failures = 0;
    TEST("coin-sel: wallet insertion order does not change selection") {
        int64_t vals_a[] = { 1 * ZCL_COIN, 2 * ZCL_COIN, 3 * ZCL_COIN };
        struct coin_entry *ca; struct wallet_tx **wa;
        make_utxo_set(vals_a, 3, &ca, &wa);

        struct coin_entry sel[MAX_SEL];
        size_t nsel = 0; int64_t total = 0;

        wallet_select_coins(NULL, ca, 3, 3 * ZCL_COIN,
                             sel, &nsel, MAX_SEL, &total);
        size_t nsel_a = nsel;

        int64_t total_a = total;

        int64_t vals_b[] = { 3 * ZCL_COIN, 2 * ZCL_COIN, 1 * ZCL_COIN };
        struct coin_entry *cb; struct wallet_tx **wb;
        make_utxo_set(vals_b, 3, &cb, &wb);

        nsel = 0; total = 0;
        wallet_select_coins(NULL, cb, 3, 3 * ZCL_COIN,
                             sel, &nsel, MAX_SEL, &total);
        size_t nsel_b = nsel;

        ASSERT_EQ(nsel_a, (size_t)1);
        ASSERT_EQ(nsel_b, (size_t)1);
        ASSERT_EQ(total_a, 3 * ZCL_COIN);
        ASSERT_EQ(total, 3 * ZCL_COIN);

        free_utxo_set(ca, wa, 3);
        free_utxo_set(cb, wb, 3);
        PASS();
    } _test_next:;
    return failures;
}

static int test_candidate_allocation_failure(void)
{
    int failures = 0;
    TEST("coin-sel: candidate allocation failure is fail-closed") {
        int64_t vals[] = { 1 * ZCL_COIN, 2 * ZCL_COIN };
        struct coin_entry *coins; struct wallet_tx **wtxs;
        size_t n = make_utxo_set(vals, 2, &coins, &wtxs);
        struct coin_entry sel[MAX_SEL];
        size_t nsel = 9;
        int64_t total = 99;

        zcl_alloc_fault_fail_next("wallet_coin_candidates");
        bool ok = wallet_select_coins(NULL, coins, n, 4 * ZCL_COIN,
                                      sel, &nsel, MAX_SEL, &total);
        zcl_alloc_fault_clear();
        ASSERT(!ok);
        ASSERT_EQ(nsel, (size_t)0);
        ASSERT_EQ(total, (int64_t)0);

        free_utxo_set(coins, wtxs, n);
        PASS();
    } _test_next:;
    return failures;
}

static int test_liquidity_planner(void)
{
    int failures = 0;
    TEST("coin-sel: liquidity planner separates ready, fanout, and funding states") {
        struct wallet_liquidity_plan plan;
        struct coin_entry *coins; struct wallet_tx **wtxs;

        int64_t ready_vals[] = { 2000, 2000, 2000, 2000 };
        size_t n = make_utxo_set(ready_vals, 4, &coins, &wtxs);
        ASSERT(wallet_liquidity_plan_compute(
            coins, n, 5000, 1000, 100, 100, 3, &plan));
        ASSERT(strcmp(plan.status, "READY_NOW") == 0);
        ASSERT(plan.ready_now);
        ASSERT_EQ(plan.current_independent_slots, 3);
        ASSERT_EQ(plan.current_inputs_used, 3);
        ASSERT(!plan.fanout_recommended);
        free_utxo_set(coins, wtxs, n);

        int64_t one_coin[] = { 5000 };
        n = make_utxo_set(one_coin, 1, &coins, &wtxs);
        ASSERT(wallet_liquidity_plan_compute(
            coins, n, 5000, 1000, 100, 100, 3, &plan));
        ASSERT(strcmp(plan.status, "NEEDS_FANOUT") == 0);
        ASSERT(!plan.ready_now);
        ASSERT(plan.fanout_possible);
        ASSERT(plan.fanout_recommended);
        ASSERT_EQ(plan.current_independent_slots, 1);
        ASSERT_EQ(plan.recommended_fanout_outputs, 3);
        ASSERT_EQ(plan.fanout_output_value_zat, (int64_t)1100);
        ASSERT_EQ(plan.fanout_outputs_total_zat, (int64_t)3300);

        ASSERT(wallet_liquidity_plan_compute(
            coins, n, 3000, 1000, 100, 100, 3, &plan));
        ASSERT(strcmp(plan.status, "INSUFFICIENT_POLICY_BUDGET") == 0);
        ASSERT(!plan.fanout_possible);

        ASSERT(wallet_liquidity_plan_compute(
            coins, n, 3300, 1000, 100, 100, 3, &plan));
        ASSERT(strcmp(plan.status, "FANOUT_FEE_EXCEEDS_BUDGET") == 0);
        ASSERT_EQ(plan.maximum_fanout_slots, 2);
        free_utxo_set(coins, wtxs, n);

        int64_t transparent_short[] = { 2000 };
        n = make_utxo_set(transparent_short, 1, &coins, &wtxs);
        ASSERT(wallet_liquidity_plan_compute(
            coins, n, 5000, 1000, 100, 100, 3, &plan));
        ASSERT(strcmp(plan.status, "NEEDS_TRANSPARENT_LIQUIDITY") == 0);
        ASSERT(!plan.fanout_possible);
        free_utxo_set(coins, wtxs, n);

        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ─────────────────────────────────────────── */

int test_coin_selection(void);

int test_coin_selection(void)
{
    int failures = 0;
    printf("\n=== coin selection audit tests ===\n");

    failures += test_exact_single_coin();
    failures += test_many_dust_utxos();
    failures += test_many_dust_plus_one_large();
    failures += test_large_then_dust();
    failures += test_few_large_coins();
    failures += test_empty_utxo_set();
    failures += test_all_unspendable();
    failures += test_target_zero();
    failures += test_prefers_single_over_exact_pair();
    failures += test_many_small_coins();
    failures += test_max_selected_limit();
    failures += test_mixed_spendable_unspendable();
    failures += test_single_satoshi();
    failures += test_change_overshoot();
    failures += test_order_independence();
    failures += test_candidate_allocation_failure();
    failures += test_liquidity_planner();

    printf("%d passed, %d failed\n",
           17 - failures, failures);
    return failures;
}

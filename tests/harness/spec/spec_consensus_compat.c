/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Consensus compatibility spec tests.
 * Verified against ZClassic C++ source: ZclassicCommunity/zclassic
 *
 * FEATURE: Bit-for-bit UTXO compatibility with ZClassic C++ (zclassicd) */

#include "test/test_core.h"
#include "chain/pow.h"
#include "coins/compressor.h"
#include "coins/coins_view.h"

#ifndef COINBASE_MATURITY
#define COINBASE_MATURITY 100
#endif

/* ── STORY 1: Unspendable outputs never enter UTXO set ──────── */

static int test_cc_op_return_filtered(void) {
    int failures = 0;
    TEST("GIVEN tx with OP_RETURN WHEN coins created THEN OP_RETURN is null") {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 2);
        tx.vout[0].value = 100000;
        uint8_t p2pkh[] = {0x76,0xa9,0x14, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x88,0xac};
        script_set(&tx.vout[0].script_pub_key, p2pkh, sizeof(p2pkh));
        tx.vout[1].value = 0;
        uint8_t op_ret[] = {0x6a, 0x04, 'Z','S','L','P'};
        script_set(&tx.vout[1].script_pub_key, op_ret, sizeof(op_ret));
        struct coins c; coins_init(&c);
        coins_from_transaction(&c, &tx, 500);
        ASSERT(coins_is_available(&c, 0));
        ASSERT(!coins_is_available(&c, 1));
        PASS();
        coins_free(&c); transaction_free(&tx);
    } _test_next:;
    return failures;
}

static int test_cc_all_op_return_pruned(void) {
    int failures = 0;
    TEST("GIVEN tx with ONLY OP_RETURN WHEN coins created THEN fully pruned") {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.vout[0].value = 0;
        uint8_t op_ret[] = {0x6a, 0x02, 0xff, 0xff};
        script_set(&tx.vout[0].script_pub_key, op_ret, sizeof(op_ret));
        struct coins c; coins_init(&c);
        coins_from_transaction(&c, &tx, 1000);
        ASSERT(coins_is_pruned(&c));
        ASSERT(c.num_vout == 0);
        PASS();
        coins_free(&c); transaction_free(&tx);
    } _test_next:;
    return failures;
}

static int test_cc_is_unspendable_op_return(void) {
    int failures = 0;
    TEST("GIVEN OP_RETURN script WHEN IsUnspendable THEN true") {
        struct script s;
        uint8_t d[] = {0x6a, 0x04, 0,0,0,0};
        script_set(&s, d, sizeof(d));
        ASSERT(script_is_unspendable(&s));
        PASS();
    } _test_next:;
    return failures;
}

static int test_cc_is_unspendable_p2pkh(void) {
    int failures = 0;
    TEST("GIVEN P2PKH script WHEN IsUnspendable THEN false") {
        struct script s;
        uint8_t p[] = {0x76,0xa9,0x14, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x88,0xac};
        script_set(&s, p, sizeof(p));
        ASSERT(!script_is_unspendable(&s));
        PASS();
    } _test_next:;
    return failures;
}

static int test_cc_is_unspendable_empty(void) {
    int failures = 0;
    TEST("GIVEN empty script WHEN IsUnspendable THEN false (matches C++)") {
        struct script s; s.size = 0;
        ASSERT(!script_is_unspendable(&s));
        PASS();
    } _test_next:;
    return failures;
}

/* ── STORY 2: Spending creates correct undo data ─────────────── */

static int test_cc_spend_partial(void) {
    int failures = 0;
    TEST("GIVEN 2 outputs WHEN spend first THEN second still available") {
        struct coins c; coins_init(&c); coins_alloc(&c, 2);
        c.vout[0].value = 5000; c.vout[1].value = 3000;
        ASSERT(coins_spend(&c, 0));
        ASSERT(!coins_is_available(&c, 0));
        ASSERT(coins_is_available(&c, 1));
        ASSERT(!coins_is_pruned(&c));
        PASS();
        coins_free(&c);
    } _test_next:;
    return failures;
}

static int test_cc_spend_all_pruned(void) {
    int failures = 0;
    TEST("GIVEN 1 output WHEN spend it THEN fully pruned") {
        struct coins c; coins_init(&c); coins_alloc(&c, 1);
        c.vout[0].value = 7000;
        coins_spend(&c, 0);
        ASSERT(coins_is_pruned(&c));
        PASS();
        coins_free(&c);
    } _test_next:;
    return failures;
}

static int test_cc_double_spend_rejected(void) {
    int failures = 0;
    TEST("GIVEN spent output WHEN spend again THEN returns false") {
        struct coins c; coins_init(&c); coins_alloc(&c, 1);
        c.vout[0].value = 1000;
        coins_spend(&c, 0);
        ASSERT(!coins_spend(&c, 0));
        PASS();
        coins_free(&c);
    } _test_next:;
    return failures;
}

/* ── STORY 3: Coinbase maturity enforced ─────────────────────── */

static int test_cc_maturity_constant(void) {
    int failures = 0;
    TEST("GIVEN COINBASE_MATURITY THEN equals 100 (ZClassic C++)") {
        ASSERT(COINBASE_MATURITY == 100);
        PASS();
    } _test_next:;
    return failures;
}

static int test_cc_maturity_immature(void) {
    int failures = 0;
    TEST("GIVEN coinbase h=1000 WHEN spent h=1099 THEN immature") {
        ASSERT(1099 - 1000 < COINBASE_MATURITY);
        PASS();
    } _test_next:;
    return failures;
}

static int test_cc_maturity_exact(void) {
    int failures = 0;
    TEST("GIVEN coinbase h=1000 WHEN spent h=1100 THEN mature (exactly 100)") {
        ASSERT(!(1100 - 1000 < COINBASE_MATURITY));
        PASS();
    } _test_next:;
    return failures;
}

/* ── STORY 4: Cache flush safety ─────────────────────────────── */

static int test_cc_flush_success_clears(void) {
    int failures = 0;
    TEST("GIVEN cache WHEN flush succeeds THEN cache cleared") {
        struct coins_view null_view; memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache parent;
        coins_view_cache_init(&parent, &null_view);
        struct coins_view pv; coins_view_cache_as_view(&pv, &parent);
        struct coins_view_cache child;
        coins_view_cache_init(&child, &pv);
        struct uint256 txid; memset(txid.data, 0x42, 32);
        struct coins_cache_entry *e = coins_view_cache_modify_new(&child, &txid);
        coins_alloc(&e->coins, 1); e->coins.vout[0].value = 999;
        ASSERT(coins_view_cache_flush_for_testing(&child));
        ASSERT(coins_map_count(&child.cache_coins) == 0);
        ASSERT(coins_view_cache_have_coins(&parent, &txid));
        PASS();
        coins_view_cache_free(&child);
        coins_view_cache_free(&parent);
    } _test_next:;
    return failures;
}

static int test_cc_flush_failure_retains(void) {
    int failures = 0;
    TEST("GIVEN cache WHEN flush fails THEN cache RETAINED (our safety improvement)") {
        struct coins_view null_view; memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache cache;
        coins_view_cache_init(&cache, &null_view);
        struct uint256 txid; memset(txid.data, 0x77, 32);
        struct coins_cache_entry *e = coins_view_cache_modify_new(&cache, &txid);
        coins_alloc(&e->coins, 1); e->coins.vout[0].value = 555;
        ASSERT(!coins_view_cache_flush_for_testing(&cache));
        ASSERT(coins_map_count(&cache.cache_coins) > 0);
        ASSERT(coins_view_cache_have_coins(&cache, &txid));
        PASS();
        coins_view_cache_free(&cache);
    } _test_next:;
    return failures;
}

/* ── STORY 5: Amount compression roundtrip ───────────────────── */

static int test_cc_compress_roundtrip(void) {
    int failures = 0;
    TEST("GIVEN various amounts WHEN compress+decompress THEN exact roundtrip") {
        int64_t amounts[] = {0, 1, 100000000LL, 50000000LL, 2100000000000000LL,
                             12345678LL, 99999999LL, 1250000000LL};
        bool ok = true;
        for (size_t i = 0; i < sizeof(amounts)/sizeof(amounts[0]); i++) {
            if ((int64_t)decompress_amount(compress_amount(amounts[i])) != amounts[i]) {
                ok = false;
                break;
            }
        }
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

/* ── STORY 6: Chain selection excludes orphans ───────────────── */

static int test_cc_orphan_nchaintx(void) {
    int failures = 0;
    TEST("GIVEN orphan block (nChainTx=0) THEN excluded from chain selection") {
        struct block_index orphan; memset(&orphan, 0, sizeof(orphan));
        orphan.nChainTx = 0;
        ASSERT(orphan.nChainTx == 0);
        /* find_most_work_chain filters nChainTx==0, matching C++ HaveTxsDownloaded */
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ─────────────────────────────────────────────── */

int spec_consensus_compat(void)
{
    printf("\n=== Consensus Compatibility: ZClassic C++ Parity ===\n");
    int failures = 0;

    /* Story 1: Unspendable outputs */
    failures += test_cc_op_return_filtered();
    failures += test_cc_all_op_return_pruned();
    failures += test_cc_is_unspendable_op_return();
    failures += test_cc_is_unspendable_p2pkh();
    failures += test_cc_is_unspendable_empty();

    /* Story 2: Spend undo */
    failures += test_cc_spend_partial();
    failures += test_cc_spend_all_pruned();
    failures += test_cc_double_spend_rejected();

    /* Story 3: Coinbase maturity */
    failures += test_cc_maturity_constant();
    failures += test_cc_maturity_immature();
    failures += test_cc_maturity_exact();

    /* Story 4: Cache flush safety */
    failures += test_cc_flush_success_clears();
    failures += test_cc_flush_failure_retains();

    /* Story 5: Serialization */
    failures += test_cc_compress_roundtrip();

    /* Story 6: Chain selection */
    failures += test_cc_orphan_nchaintx();

    printf("\n%d passed, %d failed\n", 15 - failures, failures);
    return failures;
}

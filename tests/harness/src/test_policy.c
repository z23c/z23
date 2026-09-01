/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for policy fee estimation: tx_confirm_stats and block_policy_estimator. */

#include "test/test_core.h"
#include "policy/fees.h"
#include <math.h>

int test_policy(void)
{
    int failures = 0;

    /* ── tx_confirm_stats_init ─────────────────────────────── */

    printf("tx_confirm_stats_init: zeroed state... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        bool ok = (s.buckets == NULL);
        ok = ok && (s.num_buckets == 0);
        ok = ok && (s.max_confirms == 0);
        ok = ok && (s.decay == DEFAULT_DECAY);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── tx_confirm_stats_setup ────────────────────────────── */

    printf("tx_confirm_stats_setup: bucket allocation... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double buckets[] = { 10.0, 100.0, 1000.0 };
        tx_confirm_stats_setup(&s, buckets, 3, 5, 0.99);
        bool ok = (s.num_buckets == 4); /* 3 defaults + 1 INFINITY */
        ok = ok && (s.max_confirms == 5);
        ok = ok && (s.decay == 0.99);
        ok = ok && (s.buckets[0] == 10.0);
        ok = ok && (s.buckets[1] == 100.0);
        ok = ok && (s.buckets[2] == 1000.0);
        ok = ok && (isinf(s.buckets[3]));
        ok = ok && (s.tx_ct_avg != NULL);
        ok = ok && (s.conf_avg != NULL);
        ok = ok && (s.unconf_txs != NULL);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        tx_confirm_stats_free(&s);
    }

    /* ── tx_confirm_stats_find_bucket ──────────────────────── */

    printf("tx_confirm_stats_find_bucket: exact match... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double buckets[] = { 10.0, 100.0, 1000.0 };
        tx_confirm_stats_setup(&s, buckets, 3, 5, DEFAULT_DECAY);
        unsigned int idx = tx_confirm_stats_find_bucket(&s, 100.0);
        bool ok = (idx == 1);
        if (ok) printf("OK\n"); else { printf("FAIL (idx=%u)\n", idx); failures++; }
        tx_confirm_stats_free(&s);
    }

    printf("tx_confirm_stats_find_bucket: below first bucket... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double buckets[] = { 10.0, 100.0, 1000.0 };
        tx_confirm_stats_setup(&s, buckets, 3, 5, DEFAULT_DECAY);
        unsigned int idx = tx_confirm_stats_find_bucket(&s, 5.0);
        bool ok = (idx == 0); /* 10.0 >= 5.0, so bucket 0 */
        if (ok) printf("OK\n"); else { printf("FAIL (idx=%u)\n", idx); failures++; }
        tx_confirm_stats_free(&s);
    }

    printf("tx_confirm_stats_find_bucket: between buckets... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double buckets[] = { 10.0, 100.0, 1000.0 };
        tx_confirm_stats_setup(&s, buckets, 3, 5, DEFAULT_DECAY);
        unsigned int idx = tx_confirm_stats_find_bucket(&s, 50.0);
        bool ok = (idx == 1); /* 100.0 >= 50.0 */
        if (ok) printf("OK\n"); else { printf("FAIL (idx=%u)\n", idx); failures++; }
        tx_confirm_stats_free(&s);
    }

    printf("tx_confirm_stats_find_bucket: above all finite buckets... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double buckets[] = { 10.0, 100.0, 1000.0 };
        tx_confirm_stats_setup(&s, buckets, 3, 5, DEFAULT_DECAY);
        unsigned int idx = tx_confirm_stats_find_bucket(&s, 5000.0);
        bool ok = (idx == 3); /* INFINITY >= 5000.0 */
        if (ok) printf("OK\n"); else { printf("FAIL (idx=%u)\n", idx); failures++; }
        tx_confirm_stats_free(&s);
    }

    /* ── tx_confirm_stats_max_confirms ─────────────────────── */

    printf("tx_confirm_stats_max_confirms... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double buckets[] = { 10.0, 100.0 };
        tx_confirm_stats_setup(&s, buckets, 2, 10, DEFAULT_DECAY);
        unsigned int mc = tx_confirm_stats_max_confirms(&s);
        bool ok = (mc == 10);
        if (ok) printf("OK\n"); else { printf("FAIL (max_confirms=%u)\n", mc); failures++; }
        tx_confirm_stats_free(&s);
    }

    /* ── tx_confirm_stats_new_tx ───────────────────────────── */

    printf("tx_confirm_stats_new_tx: returns bucket index... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double buckets[] = { 10.0, 100.0, 1000.0 };
        tx_confirm_stats_setup(&s, buckets, 3, 5, DEFAULT_DECAY);
        unsigned int bi = tx_confirm_stats_new_tx(&s, 100, 50.0);
        bool ok = (bi == 1); /* bucket for 50.0 is index 1 (100.0 >= 50.0) */
        /* Also verify unconf_txs was incremented */
        ok = ok && (s.unconf_txs[100 % 5][1] == 1);
        if (ok) printf("OK\n"); else { printf("FAIL (bi=%u)\n", bi); failures++; }
        tx_confirm_stats_free(&s);
    }

    /* ── tx_confirm_stats_record ───────────────────────────── */

    printf("tx_confirm_stats_record: basic recording... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double buckets[] = { 10.0, 100.0, 1000.0 };
        tx_confirm_stats_setup(&s, buckets, 3, 5, DEFAULT_DECAY);
        tx_confirm_stats_record(&s, 2, 50.0);
        /* blocks_to_confirm=2, val=50.0 -> bucket 1
         * cur_block_conf[1][1] and above should be incremented
         * cur_block_tx_ct[1] = 1, cur_block_val[1] = 50.0 */
        bool ok = (s.cur_block_tx_ct[1] == 1);
        ok = ok && (s.cur_block_val[1] == 50.0);
        ok = ok && (s.cur_block_conf[1][1] == 1); /* conf_avg[blocks_to_confirm-1=1][bucket=1] */
        ok = ok && (s.cur_block_conf[2][1] == 1); /* also incremented for i=3 */
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        tx_confirm_stats_free(&s);
    }

    printf("tx_confirm_stats_record: blocks_to_confirm < 1 ignored... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double buckets[] = { 10.0, 100.0 };
        tx_confirm_stats_setup(&s, buckets, 2, 5, DEFAULT_DECAY);
        tx_confirm_stats_record(&s, 0, 50.0);
        /* Should be a no-op */
        bool ok = (s.cur_block_tx_ct[0] == 0 && s.cur_block_tx_ct[1] == 0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        tx_confirm_stats_free(&s);
    }

    /* ── tx_confirm_stats_update_averages ──────────────────── */

    printf("tx_confirm_stats_update_averages: decay applied... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double buckets[] = { 10.0, 100.0 };
        tx_confirm_stats_setup(&s, buckets, 2, 3, 0.5);
        /* Record a transaction in bucket 1, then update averages */
        tx_confirm_stats_record(&s, 1, 50.0);
        tx_confirm_stats_update_averages(&s);
        /* avg[1] = 0 * 0.5 + 50.0 = 50.0 */
        bool ok = (s.avg[1] == 50.0);
        /* tx_ct_avg[1] = 0 * 0.5 + 1 = 1.0 */
        ok = ok && (s.tx_ct_avg[1] == 1.0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        tx_confirm_stats_free(&s);
    }

    /* ── tx_confirm_stats_clear_current ────────────────────── */

    printf("tx_confirm_stats_clear_current: resets current block data... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double buckets[] = { 10.0, 100.0 };
        tx_confirm_stats_setup(&s, buckets, 2, 3, DEFAULT_DECAY);
        tx_confirm_stats_record(&s, 1, 50.0);
        tx_confirm_stats_clear_current(&s, 1);
        bool ok = (s.cur_block_tx_ct[0] == 0 && s.cur_block_tx_ct[1] == 0);
        ok = ok && (s.cur_block_val[0] == 0 && s.cur_block_val[1] == 0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        tx_confirm_stats_free(&s);
    }

    /* ── tx_confirm_stats_remove_tx ────────────────────────── */

    printf("tx_confirm_stats_remove_tx: decrements unconf... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double buckets[] = { 10.0, 100.0 };
        tx_confirm_stats_setup(&s, buckets, 2, 5, DEFAULT_DECAY);
        /* Add a tx at height 100 in bucket 1 */
        unsigned int bi = tx_confirm_stats_new_tx(&s, 100, 50.0);
        /* unconf_txs[100 % 5][1] should be 1 */
        bool ok = (s.unconf_txs[100 % 5][bi] == 1);
        /* Remove it */
        tx_confirm_stats_remove_tx(&s, 100, 101, bi);
        ok = ok && (s.unconf_txs[100 % 5][bi] == 0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        tx_confirm_stats_free(&s);
    }

    /* ── tx_confirm_stats_estimate_median: empty stats ─────── */

    printf("tx_confirm_stats_estimate_median: empty returns -1... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double buckets[] = { 10.0, 100.0, 1000.0 };
        tx_confirm_stats_setup(&s, buckets, 3, 5, DEFAULT_DECAY);
        double med = tx_confirm_stats_estimate_median(&s, 1, 1.0, 0.85, true, 10);
        bool ok = (med == -1.0);
        if (ok) printf("OK\n"); else { printf("FAIL (median=%f)\n", med); failures++; }
        tx_confirm_stats_free(&s);
    }

    /* ── tx_confirm_stats lifecycle: init, setup, free ─────── */

    printf("tx_confirm_stats: init/setup/free lifecycle... ");
    {
        struct tx_confirm_stats s;
        tx_confirm_stats_init(&s);
        double buckets[] = { 1.0, 2.0, 4.0, 8.0, 16.0 };
        tx_confirm_stats_setup(&s, buckets, 5, MAX_BLOCK_CONFIRMS, DEFAULT_DECAY);
        bool ok = (s.num_buckets == 6);
        ok = ok && (s.max_confirms == MAX_BLOCK_CONFIRMS);
        tx_confirm_stats_free(&s);
        /* If we got here without crash, lifecycle works */
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── fee_rate helpers ──────────────────────────────────── */

    printf("fee_rate_init: zero... ");
    {
        struct fee_rate fr;
        fee_rate_init(&fr);
        bool ok = (fr.satoshis_per_k == 0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("fee_rate_init_from_fee: basic... ");
    {
        struct fee_rate fr;
        fee_rate_init_from_fee(&fr, 10000, 250);
        /* 10000 * 1000 / 250 = 40000 */
        bool ok = (fr.satoshis_per_k == 40000);
        if (ok) printf("OK (%" PRId64 ")\n", fr.satoshis_per_k);
        else { printf("FAIL (%" PRId64 ")\n", fr.satoshis_per_k); failures++; }
    }

    printf("fee_rate_init_from_fee: zero size... ");
    {
        struct fee_rate fr;
        fee_rate_init_from_fee(&fr, 10000, 0);
        bool ok = (fr.satoshis_per_k == 0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("fee_rate_get_fee_per_k... ");
    {
        struct fee_rate fr;
        fr.satoshis_per_k = 5000;
        CAmount fee_per_k = fee_rate_get_fee_per_k(&fr);
        bool ok = (fee_per_k == 5000);
        if (ok) printf("OK\n"); else { printf("FAIL (%" PRId64 ")\n", fee_per_k); failures++; }
    }

    printf("fee_rate_get_fee: proportional... ");
    {
        struct fee_rate fr;
        fr.satoshis_per_k = 10000; /* 10000 sat per 1000 bytes */
        CAmount fee = fee_rate_get_fee(&fr, 500);
        /* 10000 * 500 / 1000 = 5000 */
        bool ok = (fee == 5000);
        if (ok) printf("OK (%" PRId64 ")\n", fee);
        else { printf("FAIL (%" PRId64 ")\n", fee); failures++; }
    }

    printf("fee_rate_get_fee: minimum fee... ");
    {
        struct fee_rate fr;
        fr.satoshis_per_k = 1; /* very low rate */
        CAmount fee = fee_rate_get_fee(&fr, 1);
        /* 1 * 1 / 1000 = 0, but if > 0 rate, min fee = satoshis_per_k */
        bool ok = (fee == 1);
        if (ok) printf("OK\n"); else { printf("FAIL (%" PRId64 ")\n", fee); failures++; }
    }

    /* ── Constants sanity ──────────────────────────────────── */

    printf("policy constants... ");
    {
        bool ok = (MAX_BLOCK_CONFIRMS == 25);
        ok = ok && (DEFAULT_DECAY == 0.998);
        ok = ok && (MIN_SUCCESS_PCT == 0.85);
        ok = ok && (FEE_SPACING == 1.1);
        ok = ok && (PRI_SPACING == 2.0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

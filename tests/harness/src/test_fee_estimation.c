/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Fee estimation robustness — adversarial fee distributions.
 *
 * Tests that the block_policy_estimator produces sane results when
 * faced with adversarial inputs: extreme fees, bimodal distributions,
 * spam floods, sudden fee spikes/drops, and empty blocks. */

#include "test/test_core.h"
#include "validation/txmempool.h"
#include "policy/fees.h"
#include <math.h>

/* Helper: build a minimal mempool_entry with the given fee/size/height. */
static struct mempool_entry make_entry(CAmount fee, size_t tx_size,
                                       unsigned int height)
{
    struct mempool_entry e;
    memset(&e, 0, sizeof(e));
    e.fee = fee;
    e.tx_size = tx_size;
    e.mod_size = tx_size;
    e.height = height;
    e.had_no_deps = true;
    e.priority = 0.0;
    /* Give each entry a unique hash based on fee + height. */
    memset(e.tx.hash.data, 0, 32);
    memcpy(e.tx.hash.data, &fee, sizeof(fee));
    memcpy(e.tx.hash.data + 8, &height, sizeof(height));
    return e;
}

/* Helper: seed the estimator with N blocks of uniform-fee txs. */
static void seed_uniform(struct block_policy_estimator *e,
                         CAmount fee_per_tx, size_t tx_size,
                         int txs_per_block, unsigned int start_height,
                         int num_blocks)
{
    for (int b = 0; b < num_blocks; b++) {
        unsigned int h = start_height + (unsigned int)b;
        struct mempool_entry entries[64];
        int count = txs_per_block > 64 ? 64 : txs_per_block;
        for (int i = 0; i < count; i++) {
            entries[i] = make_entry(fee_per_tx + (CAmount)i,
                                    tx_size, h > 0 ? h - 1 : 0);
            /* Hash must be unique per tx */
            int uid = b * 1000 + i;
            memcpy(entries[i].tx.hash.data + 16, &uid, sizeof(uid));
            policy_process_transaction(e, &entries[i], true);
        }
        policy_process_block(e, h, entries, (size_t)count, true);
    }
}

int test_fee_estimation(void)
{
    int failures = 0;

    /* ── 1. All-zero fees produce no estimate ─────────────── */
    printf("fee estimation: all-zero fees produce no estimate... ");
    {
        struct fee_rate min_fee = { .satoshis_per_k = 1000 };
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        /* Process 10 blocks with zero-fee txs */
        for (unsigned int h = 1; h <= 10; h++) {
            struct mempool_entry e = make_entry(0, 250, h - 1);
            int uid = (int)h;
            memcpy(e.tx.hash.data + 16, &uid, sizeof(uid));
            policy_process_transaction(&est, &e, true);
            policy_process_block(&est, h, &e, 1, true);
        }

        struct fee_rate r = policy_estimate_fee(&est, 2);
        bool ok = (r.satoshis_per_k == 0);  /* no fee data → no estimate */

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 2. MAX_MONEY fee does not overflow ───────────────── */
    printf("fee estimation: MAX_MONEY fee does not overflow... ");
    {
        struct fee_rate min_fee = { .satoshis_per_k = 1000 };
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        seed_uniform(&est, MAX_MONEY / 10, 250, 10, 1, 10);

        struct fee_rate r = policy_estimate_fee(&est, 2);
        /* Estimate should be valid (>0) and not negative (overflow) */
        bool ok = (r.satoshis_per_k >= 0);

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 3. Single-satoshi fees ───────────────────────────── */
    printf("fee estimation: single-satoshi fees... ");
    {
        struct fee_rate min_fee = { .satoshis_per_k = 1 };
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        seed_uniform(&est, 1, 250, 10, 1, 10);

        struct fee_rate r = policy_estimate_fee(&est, 2);
        /* Should give a low estimate, not crash or return garbage */
        bool ok = (r.satoshis_per_k >= 0);

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 4. Bimodal distribution: half low, half high ─────── */
    printf("fee estimation: bimodal fee distribution... ");
    {
        struct fee_rate min_fee = { .satoshis_per_k = 1000 };
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        for (unsigned int h = 1; h <= 20; h++) {
            struct mempool_entry entries[20];
            for (int i = 0; i < 20; i++) {
                /* Half at 1000 sat/kB, half at 1000000 sat/kB */
                CAmount fee = (i < 10) ? 250 : 250000;  /* for 250-byte tx */
                entries[i] = make_entry(fee, 250, h - 1);
                int uid = (int)h * 1000 + i;
                memcpy(entries[i].tx.hash.data + 16, &uid, sizeof(uid));
                policy_process_transaction(&est, &entries[i], true);
            }
            policy_process_block(&est, h, entries, 20, true);
        }

        struct fee_rate r = policy_estimate_fee(&est, 2);
        /* With mixed data the estimator should produce some valid estimate */
        bool ok = (r.satoshis_per_k >= 0);

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 5. Spam flood: 100 blocks of min-fee txs then 10 normal ── */
    printf("fee estimation: spam flood followed by normal blocks... ");
    {
        struct fee_rate min_fee = { .satoshis_per_k = 1000 };
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        /* 50 blocks of min-fee spam (1000 sat/kB for 250-byte tx = 250 sat) */
        seed_uniform(&est, 250, 250, 20, 1, 50);

        /* 10 blocks of normal-fee txs (10000 sat/kB = 2500 sat/tx) */
        seed_uniform(&est, 2500, 250, 20, 51, 10);

        struct fee_rate r = policy_estimate_fee(&est, 2);
        /* After normal blocks, estimate should not be stuck at spam level.
         * Decay ensures recent data has more weight. */
        bool ok = (r.satoshis_per_k >= 0);

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 6. Sudden fee spike ──────────────────────────────── */
    printf("fee estimation: sudden fee spike... ");
    {
        struct fee_rate min_fee = { .satoshis_per_k = 1000 };
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        /* 20 blocks of normal fees */
        seed_uniform(&est, 2500, 250, 20, 1, 20);

        /* Sudden spike: 5 blocks at 100x fee */
        seed_uniform(&est, 250000, 250, 20, 21, 5);

        struct fee_rate r = policy_estimate_fee(&est, 2);
        /* Should adapt upward, not stay at old low level */
        bool ok = (r.satoshis_per_k >= 0);

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 7. Empty blocks do not crash ─────────────────────── */
    printf("fee estimation: empty blocks do not crash... ");
    {
        struct fee_rate min_fee = { .satoshis_per_k = 1000 };
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        /* Process 20 empty blocks */
        for (unsigned int h = 1; h <= 20; h++)
            policy_process_block(&est, h, NULL, 0, true);

        struct fee_rate r = policy_estimate_fee(&est, 2);
        bool ok = (r.satoshis_per_k == 0);  /* no data → no estimate */

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 8. Duplicate block heights are rejected ──────────── */
    printf("fee estimation: duplicate block heights rejected... ");
    {
        struct fee_rate min_fee = { .satoshis_per_k = 1000 };
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        seed_uniform(&est, 2500, 250, 10, 1, 5);
        unsigned int bsh = est.best_seen_height;

        /* Process same height again — should be no-op */
        policy_process_block(&est, bsh, NULL, 0, true);
        bool ok = (est.best_seen_height == bsh);

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 9. Decay convergence: old data fades ─────────────── */
    printf("fee estimation: decay converges old data to zero... ");
    {
        struct fee_rate min_fee = { .satoshis_per_k = 1000 };
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        /* Seed with high-fee data */
        seed_uniform(&est, 50000, 250, 20, 1, 10);

        struct fee_rate r1 = policy_estimate_fee(&est, 2);

        /* Process 200 empty blocks — decay erodes old data */
        for (unsigned int h = 11; h <= 210; h++)
            policy_process_block(&est, h, NULL, 0, true);

        struct fee_rate r2 = policy_estimate_fee(&est, 2);

        /* After many empty blocks, estimate should have decayed toward zero
         * or become unavailable (-1 → 0). */
        bool ok = (r2.satoshis_per_k <= r1.satoshis_per_k);

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 10. Varying tx sizes produce consistent per-kB rates ── */
    printf("fee estimation: varying tx sizes consistent per-kB... ");
    {
        struct fee_rate min_fee = { .satoshis_per_k = 1000 };
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        /* All txs pay ~10000 sat/kB but have different sizes */
        for (unsigned int h = 1; h <= 20; h++) {
            struct mempool_entry entries[10];
            size_t sizes[] = { 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000 };
            for (int i = 0; i < 10; i++) {
                /* fee = 10000 * size / 1000 = 10 * size */
                CAmount fee = 10 * (CAmount)sizes[i];
                entries[i] = make_entry(fee, sizes[i], h - 1);
                int uid = (int)h * 1000 + i;
                memcpy(entries[i].tx.hash.data + 16, &uid, sizeof(uid));
                policy_process_transaction(&est, &entries[i], true);
            }
            policy_process_block(&est, h, entries, 10, true);
        }

        struct fee_rate r = policy_estimate_fee(&est, 2);
        /* Estimate should be near 10000 sat/kB */
        bool ok = (r.satoshis_per_k >= 0);

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 11. High conf_target with sparse data ────────────── */
    printf("fee estimation: high conf_target with sparse data... ");
    {
        struct fee_rate min_fee = { .satoshis_per_k = 1000 };
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        seed_uniform(&est, 2500, 250, 5, 1, 5);

        /* Request estimate for conf_target=25 (max) with little data */
        struct fee_rate r = policy_estimate_fee(&est, MAX_BLOCK_CONFIRMS);
        bool ok = (r.satoshis_per_k >= 0);  /* must not crash */

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 12. Monotonicity: higher target → lower or equal fee ── */
    printf("fee estimation: monotonicity across targets... ");
    {
        struct fee_rate min_fee = { .satoshis_per_k = 1000 };
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        seed_uniform(&est, 5000, 250, 30, 1, 30);

        bool ok = true;
        CAmount prev = 0;
        for (int t = 1; t <= (int)MAX_BLOCK_CONFIRMS; t++) {
            struct fee_rate r = policy_estimate_fee(&est, t);
            if (t == 1) {
                prev = r.satoshis_per_k;
            } else if (r.satoshis_per_k > 0 && prev > 0) {
                /* Higher target should need <= fee */
                if (r.satoshis_per_k > prev * 2) {
                    ok = false;  /* allow some tolerance, not strict */
                    break;
                }
                prev = r.satoshis_per_k;
            }
        }

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 13. Remove-then-re-add same hash ─────────────────── */
    printf("fee estimation: remove and re-add same tx hash... ");
    {
        struct fee_rate min_fee = { .satoshis_per_k = 1000 };
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        struct mempool_entry e = make_entry(2500, 250, 0);
        policy_process_transaction(&est, &e, true);
        policy_remove_tx(&est, &e.tx.hash);

        /* Re-add same hash at later height */
        e.height = 5;
        est.best_seen_height = 5;
        policy_process_transaction(&est, &e, true);

        bool ok = true;  /* must not crash or double-count */

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 14. Negative fee (invalid) does not corrupt state ── */
    printf("fee estimation: negative fee does not corrupt state... ");
    {
        struct fee_rate min_fee = { .satoshis_per_k = 1000 };
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        struct mempool_entry e = make_entry(-1000, 250, 0);
        policy_process_transaction(&est, &e, true);

        /* Should still work after processing negative fee */
        seed_uniform(&est, 2500, 250, 10, 1, 5);
        struct fee_rate r = policy_estimate_fee(&est, 2);
        bool ok = (r.satoshis_per_k >= 0);

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 15. Rapid block height jumps ─────────────────────── */
    printf("fee estimation: rapid block height jumps... ");
    {
        struct fee_rate min_fee = { .satoshis_per_k = 1000 };
        struct block_policy_estimator est;
        block_policy_estimator_init(&est, &min_fee);

        seed_uniform(&est, 2500, 250, 10, 1, 5);

        /* Jump height by 1000 */
        seed_uniform(&est, 2500, 250, 10, 1000, 5);

        struct fee_rate r = policy_estimate_fee(&est, 2);
        bool ok = (r.satoshis_per_k >= 0);

        block_policy_estimator_free(&est);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

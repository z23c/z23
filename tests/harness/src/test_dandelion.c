/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "net/dandelion.h"
#include "core/uint256.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

/* test hooks — defined under ZCL_TESTING in core/modules/net/src/dandelion.c.
 * Exercise the RNG-driven shuffle and coin-flip without needing a full
 * net_manager fixture. */
bool dandelion_test_shuffle(node_id_t *inout, int n);
bool dandelion_test_should_stem_coin(bool *out_stem);

static struct uint256 make_test_hash(uint8_t seed)
{
    struct uint256 h;
    memset(h.data, seed, 32);
    return h;
}

static int check_dandelion_init_and_stem_decision(void)
{
    int failures = 0;

    /* ── init / free ───────────────────────────────────────────── */
    printf("dandelion_init / dandelion_free... ");
    {
        struct dandelion_state ds;
        dandelion_init(&ds);
        if (ds.enabled && ds.num_stem_peers == 0 && ds.stempool_count == 0)
            printf("OK\n");
        else {
            printf("FAIL\n"); failures++;
        }
        dandelion_free(&ds);
    }

    /* ── should_stem returns false when disabled ───────────────── */
    printf("dandelion_should_stem disabled... ");
    {
        struct dandelion_state ds;
        dandelion_init(&ds);
        ds.enabled = false;
        bool stem = dandelion_should_stem(&ds, DANDELION_NODE_ID_NONE);
        if (!stem)
            printf("OK\n");
        else {
            printf("FAIL (expected false when disabled)\n"); failures++;
        }
        dandelion_free(&ds);
    }

    /* ── should_stem returns false when no stem peers ──────────── */
    printf("dandelion_should_stem no peers... ");
    {
        struct dandelion_state ds;
        dandelion_init(&ds);
        ds.enabled = true;
        ds.num_stem_peers = 0;
        bool stem = dandelion_should_stem(&ds, DANDELION_NODE_ID_NONE);
        if (!stem)
            printf("OK\n");
        else {
            printf("FAIL (expected false with no stem peers)\n"); failures++;
        }
        dandelion_free(&ds);
    }

    /* ── should_stem returns true ~90% when stem peers exist ───── */
    printf("dandelion_should_stem probability... ");
    {
        struct dandelion_state ds;
        dandelion_init(&ds);
        ds.enabled = true;
        ds.num_stem_peers = 2;
        ds.stem_peers[0] = 100;
        ds.stem_peers[1] = 200;

        int stem_count = 0;
        int trials = 1000;
        for (int i = 0; i < trials; i++) {
            if (dandelion_should_stem(&ds, DANDELION_NODE_ID_NONE))
                stem_count++;
        }
        /* Should be ~90% stem (DANDELION_FLUFF_PROB = 10%) */
        double pct = (double)stem_count / trials * 100.0;
        if (pct >= 80.0 && pct <= 97.0)
            printf("OK (%.1f%% stem)\n", pct);
        else {
            printf("FAIL (%.1f%% stem, expected ~90%%)\n", pct); failures++;
        }
        dandelion_free(&ds);
    }

    return failures;
}

static int check_dandelion_stem_peer_selection(void)
{
    int failures = 0;

    /* ── get_stem_peer round-robin ─────────────────────────────── */
    printf("dandelion_get_stem_peer round-robin... ");
    {
        struct dandelion_state ds;
        dandelion_init(&ds);
        ds.num_stem_peers = 2;
        ds.stem_peers[0] = 10;
        ds.stem_peers[1] = 20;
        ds.stem_rr_index = 0;

        node_id_t p1 = dandelion_get_stem_peer(&ds, DANDELION_NODE_ID_NONE);
        node_id_t p2 = dandelion_get_stem_peer(&ds, DANDELION_NODE_ID_NONE);
        /* Round-robin should alternate */
        if (p1 == 10 && p2 == 20)
            printf("OK\n");
        else {
            printf("FAIL (got %d, %d expected 10, 20)\n", p1, p2); failures++;
        }
        dandelion_free(&ds);
    }

    /* ── get_stem_peer skips from_peer ─────────────────────────── */
    printf("dandelion_get_stem_peer skips sender... ");
    {
        struct dandelion_state ds;
        dandelion_init(&ds);
        ds.num_stem_peers = 2;
        ds.stem_peers[0] = 10;
        ds.stem_peers[1] = 20;
        ds.stem_rr_index = 0;

        /* from_peer=10, should skip to 20 */
        node_id_t p = dandelion_get_stem_peer(&ds, 10);
        if (p == 20)
            printf("OK\n");
        else {
            printf("FAIL (got %d, expected 20)\n", p); failures++;
        }
        dandelion_free(&ds);
    }

    /* ── get_stem_peer returns NONE when only peer is sender ───── */
    printf("dandelion_get_stem_peer all excluded... ");
    {
        struct dandelion_state ds;
        dandelion_init(&ds);
        ds.num_stem_peers = 1;
        ds.stem_peers[0] = 10;

        node_id_t p = dandelion_get_stem_peer(&ds, 10);
        if (p == DANDELION_NODE_ID_NONE)
            printf("OK\n");
        else {
            printf("FAIL (got %d, expected NONE)\n", p); failures++;
        }
        dandelion_free(&ds);
    }

    return failures;
}

static int check_dandelion_stempool_membership(void)
{
    int failures = 0;

    /* ── stempool add / contains / remove ──────────────────────── */
    printf("dandelion_stempool basic ops... ");
    {
        struct dandelion_state ds;
        dandelion_init(&ds);

        struct uint256 h1 = make_test_hash(0xAA);
        struct uint256 h2 = make_test_hash(0xBB);

        dandelion_stempool_add(&ds, &h1, 1);
        dandelion_stempool_add(&ds, &h2, 2);

        bool c1 = dandelion_stempool_contains(&ds, &h1);
        bool c2 = dandelion_stempool_contains(&ds, &h2);
        struct uint256 h3 = make_test_hash(0xCC);
        bool c3 = dandelion_stempool_contains(&ds, &h3);

        if (c1 && c2 && !c3 && ds.stempool_count == 2)
            printf("OK\n");
        else {
            printf("FAIL (c1=%d c2=%d c3=%d count=%d)\n",
                   c1, c2, c3, ds.stempool_count);
            failures++;
        }

        /* Remove h1 */
        bool removed = dandelion_stempool_remove(&ds, &h1);
        bool still = dandelion_stempool_contains(&ds, &h1);
        if (removed && !still && ds.stempool_count == 1)
            printf("  remove OK\n");
        else {
            printf("  remove FAIL\n"); failures++;
        }

        dandelion_free(&ds);
    }

    /* ── stempool duplicate rejection ──────────────────────────── */
    printf("dandelion_stempool dedup... ");
    {
        struct dandelion_state ds;
        dandelion_init(&ds);

        struct uint256 h = make_test_hash(0xDD);
        dandelion_stempool_add(&ds, &h, 1);
        dandelion_stempool_add(&ds, &h, 2); /* duplicate */

        if (ds.stempool_count == 1)
            printf("OK\n");
        else {
            printf("FAIL (count=%d, expected 1)\n", ds.stempool_count);
            failures++;
        }
        dandelion_free(&ds);
    }

    return failures;
}

static int check_dandelion_stempool_lifetime(void)
{
    int failures = 0;

    /* ── stempool embargo expiry ───────────────────────────────── */
    printf("dandelion_stempool embargo check... ");
    {
        struct dandelion_state ds;
        dandelion_init(&ds);

        struct uint256 h = make_test_hash(0xEE);
        dandelion_stempool_add(&ds, &h, 1);

        /* Force the embargo time to be in the past */
        for (int i = 0; i < DANDELION_MAX_STEMPOOL; i++) {
            if (ds.stempool[i].active) {
                ds.stempool[i].embargo_time = (int64_t)platform_time_wall_time_t() - 1;
                break;
            }
        }

        struct uint256 expired[8];
        int nexp = dandelion_stempool_check_embargo(&ds, expired, 8);
        if (nexp == 1 && uint256_eq(&expired[0], &h) &&
            ds.stempool_count == 0)
            printf("OK\n");
        else {
            printf("FAIL (nexp=%d count=%d)\n", nexp, ds.stempool_count);
            failures++;
        }
        dandelion_free(&ds);
    }

    /* ── stempool eviction when full ───────────────────────────── */
    printf("dandelion_stempool eviction... ");
    {
        struct dandelion_state ds;
        dandelion_init(&ds);

        /* Fill the stempool — use unique hashes via 4-byte encoding */
        for (int i = 0; i < DANDELION_MAX_STEMPOOL; i++) {
            struct uint256 h;
            memset(h.data, 0, 32);
            memcpy(h.data, &i, sizeof(i)); /* unique via int bytes */
            dandelion_stempool_add(&ds, &h, 1);
        }

        if (ds.stempool_count != DANDELION_MAX_STEMPOOL) {
            printf("FAIL (initial count=%d)\n", ds.stempool_count);
            failures++;
        } else {
            /* Add one more — should evict oldest */
            struct uint256 extra = make_test_hash(0xFF);
            dandelion_stempool_add(&ds, &extra, 1);

            bool has_extra = dandelion_stempool_contains(&ds, &extra);
            if (has_extra && ds.stempool_count == DANDELION_MAX_STEMPOOL)
                printf("OK\n");
            else {
                printf("FAIL (has_extra=%d count=%d)\n",
                       has_extra, ds.stempool_count);
                failures++;
            }
        }
        dandelion_free(&ds);
    }

    return failures;
}

static int check_dandelion_null_and_stats(void)
{
    int failures = 0;

    /* ── NULL safety ───────────────────────────────────────────── */
    printf("dandelion NULL safety... ");
    {
        /* These should not crash */
        dandelion_should_stem(NULL, 0);
        dandelion_get_stem_peer(NULL, 0);
        dandelion_stempool_add(NULL, NULL, 0);
        dandelion_stempool_remove(NULL, NULL);
        dandelion_stempool_contains(NULL, NULL);
        dandelion_stempool_check_embargo(NULL, NULL, 0);
        dandelion_maybe_rotate_epoch(NULL, NULL);
        printf("OK\n");
    }

    /* ── stats tracking ────────────────────────────────────────── */
    printf("dandelion stats... ");
    {
        struct dandelion_state ds;
        dandelion_init(&ds);
        ds.num_stem_peers = 1;
        ds.stem_peers[0] = 42;
        ds.enabled = true;

        /* Run some decisions */
        for (int i = 0; i < 100; i++)
            dandelion_should_stem(&ds, DANDELION_NODE_ID_NONE);

        /* Stats are tracked by the caller (process_tx_msg), not by
         * should_stem directly, so just verify fields exist and are
         * zero-initialized. */
        if (ds.stat_stem_sent == 0 && ds.stat_fluffed == 0 &&
            ds.stat_embargo_fluff == 0)
            printf("OK\n");
        else {
            printf("FAIL (stats not zero-initialized)\n"); failures++;
        }
        dandelion_free(&ds);
    }

    return failures;
}

static int check_dandelion_shuffle_entropy(void)
{
    int failures = 0;

    /* ── stem shuffle is non-deterministic across calls ─────
     *
     * Each call draws fresh entropy, so back-to-back shuffles differ with
     * probability 1 - 1/8!; retried a few times to make a false FAIL
     * negligible. */
    printf("dandelion stem shuffle non-deterministic... ");
    {
        bool any_diff = false;
        bool rng_ok = true;
        for (int trial = 0; trial < 5 && !any_diff && rng_ok; trial++) {
            node_id_t a[8] = {1, 2, 3, 4, 5, 6, 7, 8};
            node_id_t b[8] = {1, 2, 3, 4, 5, 6, 7, 8};
            rng_ok = dandelion_test_shuffle(a, 8) &&
                     dandelion_test_shuffle(b, 8);
            if (rng_ok && memcmp(a, b, sizeof a) != 0)
                any_diff = true;
        }
        if (rng_ok && any_diff)
            printf("OK\n");
        else if (!rng_ok) {
            printf("FAIL (cryptographic RNG returned error)\n"); failures++;
        } else {
            printf("FAIL (5/5 shuffles identical — RNG appears deterministic)\n");
            failures++;
        }
    }

    return failures;
}

/* One 10k batch of the per-tx stem coin. Returns the stem count, or -1
 * when the cryptographic RNG fails. The caller prints that failure. */
static int count_dandelion_stem_coin_trials(int trials)
{
    int stem_count = 0;

    for (int i = 0; i < trials; i++) {
        bool stem;
        if (!dandelion_test_should_stem_coin(&stem))
            return -1;
        if (stem) stem_count++;
    }
    return stem_count;
}

static int check_dandelion_fluff_coin_band(void)
{
    int failures = 0;

    /* ── per-tx fluff coin-flip is statistically uniform ────
     *
     * p_stem = 0.9, n = 10000: mean 9000, sigma 30, band [8910, 9090]
     * inclusive (+-3 sigma). Up to 3 independent batches; pass if any is
     * in-band (a biased RNG fails all of them). */
    printf("dandelion fluff coin-flip ±3σ uniformity (10k)... ");
    {
        const int trials = 10000;
        const int attempts = 3;
        int last_count = -1;
        bool rng_ok = true;
        bool in_band = false;
        for (int a = 0; a < attempts && !in_band; a++) {
            int stem_count;
            rng_ok = true;
            stem_count = count_dandelion_stem_coin_trials(trials);
            if (stem_count < 0) {
                rng_ok = false;
                break;
            }
            last_count = stem_count;
            if (stem_count >= 8910 && stem_count <= 9090)
                in_band = true;
        }
        if (rng_ok && in_band)
            printf("OK (%d/%d stem)\n", last_count, trials);
        else if (!rng_ok) {
            printf("FAIL (cryptographic RNG returned error)\n"); failures++;
        } else {
            printf("FAIL (%d/%d stem — %d batches all outside ±3σ of 9000)\n",
                   last_count, trials, attempts);
            failures++;
        }
    }

    return failures;
}

int test_dandelion(void)
{
    int failures = 0;

    failures += check_dandelion_init_and_stem_decision();
    failures += check_dandelion_stem_peer_selection();
    failures += check_dandelion_stempool_membership();
    failures += check_dandelion_stempool_lifetime();
    failures += check_dandelion_null_and_stats();
    failures += check_dandelion_shuffle_entropy();
    failures += check_dandelion_fluff_coin_band();
    return failures;
}

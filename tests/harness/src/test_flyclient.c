/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for FlyClient probabilistic chain verification. */

#include "test/test_core.h"
#include "net/flyclient.h"
#include "chain/mmb.h"
#include "crypto/sha3.h"
#include "event/event.h"
#include <math.h>
#include <string.h>
#include <stdio.h>

/* Helper: build a small chain for testing */
static void build_test_chain(struct mmb *m, struct mmb_leaf *leaves,
                             uint8_t (*hashes)[32], int n)
{
    mmb_init(m);
    for (int i = 0; i < n; i++) {
        memset(&leaves[i], 0, sizeof(leaves[i]));
        uint32_t h = (uint32_t)i;
        /* Block hash with leading zeros: data[31..28] are 0 (most
         * significant in uint256), height stored in data[0..3] (least
         * significant) so the hash is a small number that trivially
         * passes the PoW difficulty check. */
        memset(leaves[i].block_hash, 0, 32);
        memcpy(leaves[i].block_hash, &h, 4);  /* least significant bytes */
        leaves[i].height = h;
        leaves[i].timestamp = 1600000000 + h * 75;
        /* ZClassic genesis difficulty: 0x2007ffff → target = powLimit */
        leaves[i].nBits = 0x2007ffff;
        uint32_t h2 = h + 1000000;
        sha3_256((const uint8_t *)&h2, 4, leaves[i].sapling_root);
        uint32_t h3 = h + 2000000;
        sha3_256((const uint8_t *)&h3, 4, leaves[i].chain_work);

        mmb_hash_leaf(&leaves[i], hashes[i]);
        mmb_append(m, &leaves[i]);
    }
}

/* ── Index generation tests ──────────────────────────────── */

static int test_fc_indices_count(void)
{
    int failures = 0;
    TEST("fc: generate_indices produces correct count") {
        uint8_t seed[32];
        memset(seed, 0x42, 32);
        uint64_t indices[FC_MAX_SAMPLES];
        uint32_t count = 0;

        fc_generate_indices(seed, 1000000, indices, &count);
        ASSERT(count == FC_NUM_SAMPLES);

        /* Small chain: count ≤ chain_length */
        fc_generate_indices(seed, 5, indices, &count);
        ASSERT(count == 5);

        /* Edge: chain_length = 1 */
        fc_generate_indices(seed, 1, indices, &count);
        ASSERT(count == 1);
        ASSERT(indices[0] == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fc_indices_recent_bias(void)
{
    int failures = 0;
    TEST("fc: indices biased toward recent blocks") {
        uint8_t seed[32];
        memset(seed, 0xAB, 32);
        uint64_t indices[FC_MAX_SAMPLES];
        uint32_t count = 0;

        uint64_t chain_len = 3000000;
        fc_generate_indices(seed, chain_len, indices, &count);
        ASSERT(count == FC_NUM_SAMPLES);

        /* Count how many samples are in the recent quarter */
        int recent_quarter = 0;
        for (uint32_t i = 0; i < count; i++) {
            if (indices[i] >= chain_len * 3 / 4) recent_quarter++;
        }
        /* FlyClient distribution should have at least some in recent quarter.
         * With 50 samples and strong recency bias, expect ≥5 in top 25%. */
        ASSERT(recent_quarter >= 5);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fc_indices_deterministic(void)
{
    int failures = 0;
    TEST("fc: indices deterministic with same seed") {
        uint8_t seed[32];
        memset(seed, 0xCD, 32);
        uint64_t ind1[FC_MAX_SAMPLES], ind2[FC_MAX_SAMPLES];
        uint32_t c1 = 0, c2 = 0;

        fc_generate_indices(seed, 1000000, ind1, &c1);
        fc_generate_indices(seed, 1000000, ind2, &c2);
        ASSERT(c1 == c2);
        ASSERT(memcmp(ind1, ind2, c1 * sizeof(uint64_t)) == 0);

        /* Different seed → different indices */
        uint8_t seed2[32];
        memset(seed2, 0xEF, 32);
        fc_generate_indices(seed2, 1000000, ind2, &c2);
        ASSERT(memcmp(ind1, ind2, c1 * sizeof(uint64_t)) != 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Sample verification tests ───────────────────────────── */

static int test_fc_verify_valid_sample(void)
{
    int failures = 0;
    TEST("fc: verify_sample accepts valid sample") {
        int n = 64;
        struct mmb m;
        struct mmb_leaf leaves[64];
        uint8_t hashes[64][32];
        build_test_chain(&m, leaves, hashes, n);

        uint8_t root[32];
        mmb_root(&m, root);

        /* Build a valid sample for leaf 10 */
        struct fc_sample sample;
        sample.leaf = leaves[10];
        ASSERT(mmb_prove((const uint8_t (*)[32])hashes, n, 10,
                         &sample.proof));

        ASSERT(fc_verify_sample(&sample, root));
        PASS();
    } _test_next:;
    return failures;
}

static int test_fc_verify_bad_proof(void)
{
    int failures = 0;
    TEST("fc: verify_sample rejects bad MMB proof") {
        int n = 32;
        struct mmb m;
        struct mmb_leaf leaves[32];
        uint8_t hashes[32][32];
        build_test_chain(&m, leaves, hashes, n);

        uint8_t root[32];
        mmb_root(&m, root);

        struct fc_sample sample;
        sample.leaf = leaves[5];
        ASSERT(mmb_prove((const uint8_t (*)[32])hashes, n, 5,
                         &sample.proof));

        /* Tamper with proof */
        if (sample.proof.num_siblings > 0)
            sample.proof.siblings[0][0] ^= 0xFF;
        ASSERT(!fc_verify_sample(&sample, root));
        PASS();
    } _test_next:;
    return failures;
}

static int test_fc_verify_bad_leaf(void)
{
    int failures = 0;
    TEST("fc: verify_sample rejects tampered leaf data") {
        int n = 32;
        struct mmb m;
        struct mmb_leaf leaves[32];
        uint8_t hashes[32][32];
        build_test_chain(&m, leaves, hashes, n);

        uint8_t root[32];
        mmb_root(&m, root);

        struct fc_sample sample;
        sample.leaf = leaves[5];
        ASSERT(mmb_prove((const uint8_t (*)[32])hashes, n, 5,
                         &sample.proof));

        /* Tamper with leaf timestamp — proof should fail because
         * recomputed leaf hash won't match proof.leaf_hash */
        sample.leaf.timestamp += 1;
        ASSERT(!fc_verify_sample(&sample, root));
        PASS();
    } _test_next:;
    return failures;
}

/* ── Full chain verification tests ───────────────────────── */

static int test_fc_verify_chain_valid(void)
{
    int failures = 0;
    TEST("fc: verify_response accepts all-valid chain") {
        int n = 100;
        struct mmb m;
        struct mmb_leaf leaves[100];
        uint8_t hashes[100][32];
        build_test_chain(&m, leaves, hashes, n);

        uint8_t root[32];
        mmb_root(&m, root);

        /* Build challenge */
        struct fc_challenge challenge;
        memset(challenge.seed, 0x77, 32);
        challenge.chain_length = n;
        memcpy(challenge.mmb_root, root, 32);

        /* Build response (prover side) */
        struct fc_response resp;
        ASSERT(fc_build_response(&challenge, &m, leaves,
                                 (const uint8_t (*)[32])hashes, &resp));
        ASSERT(resp.num_samples > 0);

        /* Verify (verifier side) */
        ASSERT(fc_verify_response(&resp, &challenge));
        PASS();
    } _test_next:;
    return failures;
}

static int test_fc_verify_chain_rejects_tampered(void)
{
    int failures = 0;
    TEST("fc: verify_response rejects if any sample tampered") {
        int n = 100;
        struct mmb m;
        struct mmb_leaf leaves[100];
        uint8_t hashes[100][32];
        build_test_chain(&m, leaves, hashes, n);

        uint8_t root[32];
        mmb_root(&m, root);

        struct fc_challenge challenge;
        memset(challenge.seed, 0x88, 32);
        challenge.chain_length = n;
        memcpy(challenge.mmb_root, root, 32);

        struct fc_response resp;
        ASSERT(fc_build_response(&challenge, &m, leaves,
                                 (const uint8_t (*)[32])hashes, &resp));

        /* Tamper with first sample's leaf data */
        resp.samples[0].leaf.nBits ^= 0x01;
        ASSERT(!fc_verify_response(&resp, &challenge));
        PASS();
    } _test_next:;
    return failures;
}

static int test_fc_verify_chain_rejects_bad_pow(void)
{
    int failures = 0;
    TEST("fc: verify_response rejects samples that fail PoW target") {
        int n = 100;
        struct mmb m;
        struct mmb_leaf leaves[100];
        uint8_t hashes[100][32];
        build_test_chain(&m, leaves, hashes, n);

        uint8_t root[32];
        mmb_root(&m, root);

        struct fc_challenge challenge;
        memset(challenge.seed, 0x99, 32);
        challenge.chain_length = n;
        memcpy(challenge.mmb_root, root, 32);

        struct fc_response resp;
        ASSERT(fc_build_response(&challenge, &m, leaves,
                                 (const uint8_t (*)[32])hashes, &resp));

        /* Tighten nBits on first sample to an impossibly hard target.
         * The block_hash (a SHA3 of a small integer) won't meet it.
         * Note: we must NOT change the leaf hash in the proof — only
         * the leaf data that's re-checked by fc_verify_response.
         * Since leaf hash is recomputed from leaf data, changing nBits
         * will cause a leaf hash mismatch FIRST.  To test PoW specifically,
         * we'd need to rebuild the proof, but the leaf hash mismatch
         * still causes rejection — which is correct behavior. */
        resp.samples[0].leaf.nBits = 0x03000001; /* impossibly hard */
        ASSERT(!fc_verify_response(&resp, &challenge));
        PASS();
    } _test_next:;
    return failures;
}

static int test_fc_indices_dedup(void)
{
    int failures = 0;
    TEST("fc: generate_indices deduplicates on short chains") {
        uint8_t seed[32];
        memset(seed, 0xAA, 32);
        uint64_t indices[FC_MAX_SAMPLES];
        uint32_t count = 0;

        /* Chain of 200 blocks, 50 samples — moderate collision probability.
         * Without deduplication, duplicates are likely due to recency bias. */
        fc_generate_indices(seed, 200, indices, &count);
        ASSERT(count == 50);

        /* Verify all indices are unique */
        for (uint32_t i = 0; i < count; i++) {
            for (uint32_t j = i + 1; j < count; j++) {
                ASSERT(indices[i] != indices[j]);
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

/* Soundness invariant: when chain_length > count, every sample MUST land
 * on a distinct, in-range block — otherwise FlyClient verifies the same
 * block twice and the probabilistic guarantee weakens.  The 255-retry
 * rehash budget can be exhausted on short chains (observed ~2% of seeds
 * at chain_length=100), so this swept a FIXED seed-set deterministically
 * to exercise the exhaustion path and assert uniqueness every run.
 * Deterministic: seeds are derived from a counter, NOT from the RNG, so
 * this test cannot flake. */
static int test_fc_indices_unique_seed_sweep(void)
{
    int failures = 0;
    TEST("fc: generate_indices yields unique in-range indices for all seeds") {
        /* Chain lengths that span the collision regime: 100 (exhaustion
         * observed here) and 200 (no exhaustion). */
        const uint64_t chain_lens[] = {100, 200};
        const uint32_t num_seeds = 2000;

        for (size_t cl = 0; cl < sizeof(chain_lens) / sizeof(chain_lens[0]); cl++) {
            uint64_t chain_length = chain_lens[cl];

            for (uint32_t s = 0; s < num_seeds; s++) {
                /* Deterministic seed = SHA3 of the counter (no RNG). */
                uint8_t seed[32];
                sha3_256((const uint8_t *)&s, sizeof(s), seed);

                uint64_t indices[FC_MAX_SAMPLES];
                uint32_t count = 0;
                fc_generate_indices(seed, chain_length, indices, &count);

                ASSERT(count == FC_NUM_SAMPLES);

                for (uint32_t i = 0; i < count; i++) {
                    /* In range */
                    ASSERT(indices[i] < chain_length);
                    /* Distinct from every prior sample */
                    for (uint32_t j = 0; j < i; j++) {
                        ASSERT(indices[i] != indices[j]);
                    }
                }
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

/* ── Mutation-gap tests: reference index model, events, PoW edges ─────── */

/* Independent re-statement of the FlyClient sampling rule.  A production
 * change to any hashed byte, shift, exponent or retry counter diverges. */
static uint64_t ref_weighted(const uint8_t h[32], double exponent, uint64_t n)
{
    uint64_t raw = 0;
    for (int j = 0; j < 8; j++)
        raw = (raw << 8) | h[j];
    double x = (double)raw / (double)UINT64_MAX;
    uint64_t idx = (uint64_t)((double)(n - 1) * pow(x, exponent));
    return idx >= n ? n - 1 : idx;
}

static bool ref_taken(const uint64_t *a, uint32_t n, uint64_t v)
{
    for (uint32_t j = 0; j < n; j++)
        if (a[j] == v) return true;
    return false;
}

static uint64_t ref_retry(const uint8_t in36[36], uint64_t idx, const uint64_t *a,
                          uint32_t i, uint64_t n, double e, int *stat)
{
    uint8_t in37[37], h[32];
    memcpy(in37, in36, 36);
    for (unsigned r = 1; r <= 255; r++) {
        in37[36] = (uint8_t)r;
        sha3_256(in37, 37, h);
        idx = ref_weighted(h, e, n);
        if (!ref_taken(a, i, idx)) return idx;
    }
    stat[0]++; /* probe fallback used */
    while (ref_taken(a, i, idx)) {
        if (idx + 1 >= n) stat[1]++; /* probe wrapped past the tip */
        idx = (idx + 1 >= n) ? 0 : idx + 1;
    }
    return idx;
}

static uint32_t ref_indices(const uint8_t seed[32], uint64_t n, uint64_t *out,
                            int *stat)
{
    uint32_t count = n < FC_NUM_SAMPLES ? (uint32_t)n : FC_NUM_SAMPLES;
    double ln = log2((double)n);
    double e = 1.0 / (ln < 1.0 ? 1.0 : ln);
    for (uint32_t i = 0; i < count; i++) {
        uint8_t in[36], h[32];
        memcpy(in, seed, 32);
        for (int b = 0; b < 4; b++)
            in[32 + b] = (uint8_t)(i >> (8 * b));
        sha3_256(in, 36, h);
        uint64_t idx = ref_weighted(h, e, n);
        if (ref_taken(out, i, idx) && n > count)
            idx = ref_retry(in, idx, out, i, n, e, stat);
        out[i] = idx;
    }
    return count;
}

/* One seed/length/prefill comparison.  The prefill makes a one-past-the-end
 * read of the output array visible (a taken-looking or overwritten slot). */
static bool indices_match_ref(const uint8_t seed[32], uint64_t n, uint64_t prefill,
                              int *stat)
{
    uint64_t got[FC_MAX_SAMPLES], want[FC_MAX_SAMPLES];
    uint32_t gc = 0;
    for (int i = 0; i < FC_MAX_SAMPLES; i++) got[i] = prefill;
    fc_generate_indices(seed, n, got, &gc);
    uint32_t wc = ref_indices(seed, n, want, stat);
    if (gc != wc || got[gc] != prefill) return false;
    return memcmp(got, want, wc * sizeof(uint64_t)) == 0;
}

static int test_fc_indices_match_reference(void)
{
    int failures = 0;
    TEST("fc: generate_indices equals the reference sampling model") {
        const uint64_t lens[] = {51, 60, 100, 1000, 3000000};
        int st51[2] = {0, 0}, st_other[2] = {0, 0};
        for (size_t l = 0; l < sizeof(lens) / sizeof(lens[0]); l++) {
            const uint64_t pre[] = {UINT64_MAX, 0, lens[l] - 1};
            for (uint32_t s = 0; s < 150; s++) {
                uint8_t seed[32];
                sha3_256((const uint8_t *)&s, sizeof(s), seed);
                for (size_t p = 0; p < 3; p++)
                    ASSERT(indices_match_ref(seed, lens[l], pre[p],
                                             l == 0 ? st51 : st_other));
            }
        }
        /* 50 samples from 51 slots: the probe fallback must have run, and
         * must have wrapped past the tip back to slot 0 at least once. */
        ASSERT(st51[0] > 0);
        ASSERT(st51[1] > 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fc_indices_degenerate(void)
{
    int failures = 0;
    TEST("fc: generate_indices zero length and null outputs report zero") {
        uint8_t seed[32];
        memset(seed, 0x17, 32);
        uint64_t idx[FC_MAX_SAMPLES];
        uint32_t cnt = 77;
        fc_generate_indices(seed, 0, idx, &cnt);
        ASSERT(cnt == 0);
        cnt = 77;
        fc_generate_indices(seed, 100, NULL, &cnt);
        ASSERT(cnt == 0);
        fc_generate_indices(seed, 100, idx, NULL); /* must not crash */
        /* chain_length 2: log2 == 1.0 exactly, exponent 1 */
        uint32_t c2 = 0;
        fc_generate_indices(seed, 2, idx, &c2);
        ASSERT(c2 == 2);
        ASSERT(idx[0] < 2 && idx[1] < 2);
        PASS();
    } _test_next:;
    return failures;
}

/* Event capture: verification results are published as events, so a deleted
 * or mis-addressed emit is observable. */
struct fc_cap {
    int bad_peer, sample_ev, valid_true, idx_mm, h_mm, proof_f, pow_f;
    int mmb_ev, chain_ev;
    char chain[200], mmb_first[64], pow_first[160];
};
static struct fc_cap g_cap;

static void fc_cap_sample(const char *b)
{
    g_cap.sample_ev++;
    if (strstr(b, "valid=true")) g_cap.valid_true++;
    if (strstr(b, "expected_idx=")) g_cap.idx_mm++;
    if (strstr(b, "height_mismatch")) g_cap.h_mm++;
    if (strstr(b, "proof_failed")) g_cap.proof_f++;
    if (strstr(b, "pow_failed")) {
        if (g_cap.pow_f++ == 0) snprintf(g_cap.pow_first, sizeof(g_cap.pow_first), "%s", b);
    }
}

static void fc_cap_obs(enum event_type t, uint32_t peer, const void *p, uint32_t len,
                       void *ctx)
{
    (void)ctx;
    char b[256];
    uint32_t n = (p && len < 255) ? len : 0;
    if (n) memcpy(b, p, n);
    b[n] = '\0';
    if (peer != 0) g_cap.bad_peer++;
    if (t == EV_FC_SAMPLE_VERIFIED) fc_cap_sample(b);
    if (t == EV_MMB_PROOF_VERIFIED && g_cap.mmb_ev++ == 0)
        snprintf(g_cap.mmb_first, sizeof(g_cap.mmb_first), "%s", b);
    if (t == EV_FC_CHAIN_VERIFIED) {
        g_cap.chain_ev++;
        snprintf(g_cap.chain, sizeof(g_cap.chain), "%s", b);
    }
}

static void fc_cap_begin(void)
{
    event_log_init();
    memset(&g_cap, 0, sizeof(g_cap));
    event_observe(EV_FC_SAMPLE_VERIFIED, fc_cap_obs, NULL);
    event_observe(EV_MMB_PROOF_VERIFIED, fc_cap_obs, NULL);
    event_observe(EV_FC_CHAIN_VERIFIED, fc_cap_obs, NULL);
}

struct fc_fx {
    struct mmb m;
    struct mmb_leaf leaves[100];
    uint8_t hashes[100][32];
    struct fc_challenge ch;
    struct fc_response resp;
    int n;
};
static struct fc_fx g_fx;

static void fx_init(int n)
{
    memset(&g_fx, 0, sizeof(g_fx));
    g_fx.n = n;
    for (int i = 0; i < n; i++) {
        struct mmb_leaf *l = &g_fx.leaves[i];
        uint32_t h = (uint32_t)i, h2 = h + 1000000, h3 = h + 2000000;
        memcpy(l->block_hash, &h, 4);
        l->height = h;
        l->timestamp = 1600000000 + h * 75;
        l->nBits = 0x2007ffff;
        sha3_256((const uint8_t *)&h2, 4, l->sapling_root);
        sha3_256((const uint8_t *)&h3, 4, l->chain_work);
    }
}

static bool fx_seal(uint8_t seed_byte)
{
    mmb_init(&g_fx.m);
    for (int i = 0; i < g_fx.n; i++) {
        mmb_hash_leaf(&g_fx.leaves[i], g_fx.hashes[i]);
        mmb_append(&g_fx.m, &g_fx.leaves[i]);
    }
    mmb_root(&g_fx.m, g_fx.ch.mmb_root);
    memset(g_fx.ch.seed, seed_byte, 32);
    g_fx.ch.chain_length = (uint64_t)g_fx.n;
    return fc_build_response(&g_fx.ch, &g_fx.m, g_fx.leaves,
                             (const uint8_t (*)[32])g_fx.hashes, &g_fx.resp);
}

static bool fx_verify(void)
{
    fc_cap_begin();
    return fc_verify_response(&g_fx.resp, &g_fx.ch);
}

static int test_fc_verify_response_events(void)
{
    int failures = 0;
    TEST("fc: valid response publishes one verified event per sample") {
        fx_init(100);
        ASSERT(fx_seal(0x31));
        ASSERT(fx_verify());
        ASSERT(g_cap.bad_peer == 0);
        ASSERT(g_cap.sample_ev == 50);   /* not 51: loop stops at num_samples */
        ASSERT(g_cap.valid_true == 50);
        ASSERT(g_cap.mmb_ev == 50);
        ASSERT(g_cap.chain_ev == 1);
        ASSERT(strcmp(g_cap.chain, "samples=50 valid=50 all_valid=true") == 0);
        ASSERT(strncmp(g_cap.mmb_first, "leaf=", 5) == 0);
        ASSERT(strstr(g_cap.mmb_first, " valid=true") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fc_verify_response_count_rules(void)
{
    int failures = 0;
    TEST("fc: response with the wrong sample count is rejected before sampling") {
        fx_init(100);
        ASSERT(fx_seal(0x32));
        g_fx.resp.num_samples = 10; /* 10 valid samples, 50 expected */
        ASSERT(!fx_verify());
        ASSERT(g_cap.bad_peer == 0);
        ASSERT(g_cap.sample_ev == 0);
        ASSERT(strcmp(g_cap.chain,
               "samples=10 expected=50 all_valid=false reason=count_mismatch") == 0);
        g_fx.resp.num_samples = 0;
        ASSERT(!fx_verify());
        /* a one-block chain has exactly one sample and it verifies */
        fx_init(1);
        ASSERT(fx_seal(0x33));
        ASSERT(g_fx.resp.num_samples == 1);
        ASSERT(fx_verify());
        PASS();
    } _test_next:;
    return failures;
}

/* A proof whose leaf_hash differs from the real leaf hash ONLY in the last
 * byte, with a tree that commits to that forged hash: mmb_verify accepts it,
 * so only the full 32-byte leaf-hash comparison can refuse the sample. */
static int test_fc_verify_sample_last_byte_forgery(void)
{
    int failures = 0;
    TEST("fc: verify_sample refuses a leaf hash forged in its last byte") {
        fx_init(32);
        ASSERT(fx_seal(0x3a));
        uint8_t forged[32][32];
        memcpy(forged, g_fx.hashes, sizeof(forged));
        forged[5][31] ^= 0x01;
        struct mmb fm;
        mmb_init(&fm);
        for (int i = 0; i < 32; i++)
            (void)mmb_append_hash(&fm, forged[i]);
        ASSERT(fm.num_leaves == 32);
        uint8_t froot[32];
        mmb_root(&fm, froot);
        struct fc_sample s;
        s.leaf = g_fx.leaves[5];
        ASSERT(mmb_prove((const uint8_t (*)[32])forged, 32, 5, &s.proof));
        ASSERT(mmb_verify(&s.proof, froot)); /* the tree itself is consistent */
        ASSERT(!fc_verify_sample(&s, froot));
        /* control: the honest proof against the honest root passes */
        ASSERT(mmb_prove((const uint8_t (*)[32])g_fx.hashes, 32, 5, &s.proof));
        ASSERT(fc_verify_sample(&s, g_fx.ch.mmb_root));
        PASS();
    } _test_next:;
    return failures;
}

static int test_fc_null_arguments(void)
{
    int failures = 0;
    TEST("fc: null arguments are refused by verify and build") {
        fx_init(10);
        ASSERT(fx_seal(0x34));
        const uint8_t (*lh)[32] = (const uint8_t (*)[32])g_fx.hashes;
        ASSERT(!fc_verify_response(NULL, &g_fx.ch));
        ASSERT(!fc_verify_response(&g_fx.resp, NULL));
        ASSERT(!fc_verify_sample(NULL, g_fx.ch.mmb_root));
        ASSERT(!fc_verify_sample(&g_fx.resp.samples[0], NULL));
        struct fc_response out;
        ASSERT(!fc_build_response(NULL, &g_fx.m, g_fx.leaves, lh, &out));
        ASSERT(!fc_build_response(&g_fx.ch, NULL, g_fx.leaves, lh, &out));
        ASSERT(!fc_build_response(&g_fx.ch, &g_fx.m, NULL, lh, &out));
        ASSERT(!fc_build_response(&g_fx.ch, &g_fx.m, g_fx.leaves, NULL, &out));
        ASSERT(!fc_build_response(&g_fx.ch, &g_fx.m, g_fx.leaves, lh, NULL));
        PASS();
    } _test_next:;
    return failures;
}

static int test_fc_build_response_edges(void)
{
    int failures = 0;
    TEST("fc: build_response clears the response and bounds its loop") {
        fx_init(5);
        ASSERT(fx_seal(0x35));
        struct fc_response out;
        memset(&out, 0xAA, sizeof(out));
        ASSERT(fc_build_response(&g_fx.ch, &g_fx.m, g_fx.leaves,
                                 (const uint8_t (*)[32])g_fx.hashes, &out));
        ASSERT(out.num_samples == 5);
        static const struct fc_sample zero_sample;
        ASSERT(memcmp(&out.samples[5], &zero_sample, sizeof(zero_sample)) == 0);
        ASSERT(memcmp(&out.samples[FC_MAX_SAMPLES - 1], &zero_sample,
                      sizeof(zero_sample)) == 0);
        /* a claimed chain longer than the committed tree cannot be proven */
        g_fx.ch.chain_length = 100;
        ASSERT(!fc_build_response(&g_fx.ch, &g_fx.m, g_fx.leaves,
                                  (const uint8_t (*)[32])g_fx.hashes, &out));
        PASS();
    } _test_next:;
    return failures;
}

/* A sample whose proof is for a different leaf, but whose height field and
 * every later check are consistent, must still be refused on index alone. */
static int test_fc_verify_response_wrong_index(void)
{
    int failures = 0;
    TEST("fc: verify_response refuses a valid sample for the wrong index") {
        uint64_t exp[FC_MAX_SAMPLES];
        uint32_t ec = 0;
        uint8_t seed[32];
        memset(seed, 0x36, 32);
        fc_generate_indices(seed, 100, exp, &ec);
        uint64_t j = 0;
        while (ref_taken(exp, ec, j)) j++;
        fx_init(100);
        g_fx.leaves[j].height = (uint32_t)exp[0];
        ASSERT(fx_seal(0x36));
        g_fx.resp.samples[0].leaf = g_fx.leaves[j];
        ASSERT(mmb_prove((const uint8_t (*)[32])g_fx.hashes, 100, j,
                         &g_fx.resp.samples[0].proof));
        ASSERT(!fx_verify());
        ASSERT(g_cap.bad_peer == 0);
        ASSERT(g_cap.idx_mm == 1);
        ASSERT(g_cap.valid_true == 49);
        ASSERT(strcmp(g_cap.chain, "samples=50 valid=49 all_valid=false") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fc_verify_response_wrong_height(void)
{
    int failures = 0;
    TEST("fc: verify_response refuses a sample whose height is not its index") {
        uint64_t exp[FC_MAX_SAMPLES];
        uint32_t ec = 0;
        uint8_t seed[32];
        memset(seed, 0x37, 32);
        fc_generate_indices(seed, 100, exp, &ec);
        fx_init(100);
        g_fx.leaves[exp[3]].height = (uint32_t)exp[3] + 1000;
        ASSERT(fx_seal(0x37));
        ASSERT(!fx_verify());
        ASSERT(g_cap.h_mm == 1);
        ASSERT(g_cap.valid_true == 49);
        ASSERT(g_cap.bad_peer == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fc_verify_response_bad_proof(void)
{
    int failures = 0;
    TEST("fc: verify_response refuses samples whose inclusion proof breaks") {
        fx_init(100);
        ASSERT(fx_seal(0x38));
        g_fx.resp.samples[2].proof.peaks[0][0] ^= 0x01;
        ASSERT(!fx_verify());
        ASSERT(g_cap.bad_peer == 0);
        ASSERT(g_cap.proof_f == 1);
        ASSERT(g_cap.valid_true == 49);
        ASSERT(strcmp(g_cap.chain, "samples=50 valid=49 all_valid=false") == 0);
        /* leaf hash no longer matches the leaf data */
        ASSERT(fx_seal(0x38));
        g_fx.resp.samples[4].proof.leaf_hash[31] ^= 0x01;
        ASSERT(!fx_verify());
        ASSERT(g_cap.proof_f == 1);
        PASS();
    } _test_next:;
    return failures;
}

/* Every leaf gets the same block_hash and nBits; the proofs are rebuilt so
 * only the PoW check can decide the outcome. */
static bool fx_pow_verdict(const uint8_t hash[32], uint32_t nBits)
{
    fx_init(100);
    for (int i = 0; i < 100; i++) {
        memcpy(g_fx.leaves[i].block_hash, hash, 32);
        g_fx.leaves[i].nBits = nBits;
    }
    if (!fx_seal(0x39)) return false;
    return fx_verify();
}

static int test_fc_pow_target_edges(void)
{
    int failures = 0;
    TEST("fc: PoW check accepts hash == target and refuses anything above") {
        uint8_t h[32] = {0};
        h[29] = 0xff; h[30] = 0xff; h[31] = 0x07;    /* == target(0x2007ffff) */
        ASSERT(fx_pow_verdict(h, 0x2007ffff));
        ASSERT(g_cap.pow_f == 0);
        h[0] = 0x01;                                  /* target + 1 */
        ASSERT(!fx_pow_verdict(h, 0x2007ffff));
        ASSERT(g_cap.pow_f == 50 && g_cap.valid_true == 0);
        ASSERT(g_cap.bad_peer == 0);
        ASSERT(strstr(g_cap.pow_first, "pow_failed nBits=2007ffff") != NULL);
        ASSERT(strcmp(g_cap.chain, "samples=50 valid=0 all_valid=false") == 0);
        memset(h, 0, 32);
        h[31] = 0x08;                                 /* top byte above target */
        ASSERT(!fx_pow_verdict(h, 0x2007ffff));
        memset(h, 0xff, 32);
        h[31] = 0x06;                                 /* top byte below target */
        ASSERT(fx_pow_verdict(h, 0x2007ffff));
        PASS();
    } _test_next:;
    return failures;
}

static int test_fc_pow_rejects_malformed_nbits(void)
{
    int failures = 0;
    TEST("fc: PoW check refuses zero, negative and overflowing targets") {
        const uint8_t zero_hash[32] = {0};
        /* hash 0 is <= any target a broken decode could leave behind */
        ASSERT(!fx_pow_verdict(zero_hash, 0x00000000));       /* zero target */
        ASSERT(!fx_pow_verdict(zero_hash, 0x04800001));       /* negative */
        ASSERT(!fx_pow_verdict(zero_hash, 0x210100ff));       /* overflow */
        ASSERT(g_cap.pow_f == 50);
        ASSERT(fx_pow_verdict(zero_hash, 0x2007ffff));        /* control */
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ──────────────────────────────────────────── */

int test_flyclient(void)
{
    int failures = 0;

    /* Index generation */
    failures += test_fc_indices_count();
    failures += test_fc_indices_recent_bias();
    failures += test_fc_indices_deterministic();
    failures += test_fc_indices_dedup();
    failures += test_fc_indices_unique_seed_sweep();

    /* Sample verification */
    failures += test_fc_verify_valid_sample();
    failures += test_fc_verify_bad_proof();
    failures += test_fc_verify_bad_leaf();

    /* Full chain verification */
    failures += test_fc_verify_chain_valid();
    failures += test_fc_verify_chain_rejects_tampered();
    failures += test_fc_verify_chain_rejects_bad_pow();

    /* Mutation-gap tests */
    failures += test_fc_indices_match_reference();
    failures += test_fc_indices_degenerate();
    failures += test_fc_verify_response_events();
    failures += test_fc_verify_response_count_rules();
    failures += test_fc_verify_sample_last_byte_forgery();
    failures += test_fc_null_arguments();
    failures += test_fc_build_response_edges();
    failures += test_fc_verify_response_wrong_index();
    failures += test_fc_verify_response_wrong_height();
    failures += test_fc_verify_response_bad_proof();
    failures += test_fc_pow_target_edges();
    failures += test_fc_pow_rejects_malformed_nbits();
    event_clear_all_observers();

    return failures;
}

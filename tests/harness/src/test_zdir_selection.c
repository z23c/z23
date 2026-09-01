/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the ZDIR per-client selection derivation (core/modules/net/zdir_selection.c).
 *
 * The two properties this file exists to defend:
 *
 *   NO GLOBAL ANSWER — the preferred set must be reproducible for one node
 *   and different for every node. A single deterministic guard set that all
 *   clients compute identically would be an anonymity monoculture, strictly
 *   worse than Tor's committee. Tests 4-6 and 13 hold that line.
 *
 *   ADVISORY, NEVER EXCLUSIVE — the module's only influence on peer choice
 *   is a [1.0, 4.0] dial multiplier that can never dip below 1.0. Nothing it
 *   emits can narrow the peer set or exclude a host. Tests 7-9 hold that.
 *
 * Golden vectors (test 1) are FROZEN and were cross-checked against an
 * out-of-tree FIPS-202 SHA3-256 implementation (openssl dgst -sha3-256) on
 * the exact preimages documented beside each one. If a change here makes
 * them move, the derivation changed and every node's preference set with it.
 *
 * Pure unit test: no files, no sockets, no SQLite, no clock.
 */

#include "test/test_core.h"
#include "net/zdir_selection.h"
#include "crypto/sha3.h"

#include <string.h>

/* ── helpers ─────────────────────────────────────────────────────────── */

static bool zdir_t_hex_eq(const uint8_t *bytes, size_t n, const char *hex)
{
    if (strlen(hex) != n * 2)
        return false;
    for (size_t i = 0; i < n; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", bytes[i]);
        if (buf[0] != hex[i * 2] || buf[1] != hex[i * 2 + 1])
            return false;
    }
    return true;
}

static void zdir_t_print_hex(const uint8_t *bytes, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("%02x", bytes[i]);
}

/* Deterministic 16-relay fixture: four owners × four relays, ascending
 * seniority and bandwidth. Identical layout to the vector generator that
 * produced the frozen selection in test 13. */
static void zdir_t_build_fixture(struct zdir_candidate *c, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        memset(&c[i], 0, sizeof(c[i]));
        struct net_addr na;
        memset(&na, 0, sizeof(na));
        na.ip[0] = 'R'; na.ip[1] = 'L'; na.ip[2] = 'Y'; na.ip[3] = (uint8_t)i;
        (void)zdir_endpoint_id(c[i].id, &na, (uint16_t)(9000 + i));
        memset(c[i].owner_id, (uint8_t)(0x40 + (i % 4)), 32);
        c[i].registration_height = (uint32_t)(1000u * (uint32_t)i);
        c[i].bandwidth_score = (uint8_t)(i * 16);
    }
}

static void zdir_t_base_params(struct zdir_params *p, const uint8_t ck[32])
{
    memset(p, 0, sizeof(*p));
    for (int i = 0; i < 32; i++)
        p->block_hash[i] = (uint8_t)(0xa0 + i);
    memcpy(p->client_key, ck, 32);
    p->chain_height = 20000;
    p->seniority_full_blocks = 10000;
    p->per_owner_cap = 2;
    p->want = 8;
}

int test_zdir_selection(void)
{
    int failures = 0;

    /* The canonical node secret for every vector below: addrman nKey bytes
     * 0x00..0x1f. */
    uint8_t secret[32];
    for (int i = 0; i < 32; i++)
        secret[i] = (uint8_t)i;

    uint8_t client_key[32];
    if (!zdir_client_key(client_key, secret)) {
        printf("zdir_selection: client key derivation... FAIL (returned false)\n");
        return 1;   /* everything downstream depends on this */
    }

    /* ── 1. FROZEN GOLDEN VECTORS ─────────────────────────────────────
     * Preimages, byte for byte:
     *   client_key  = SHA3-256(00 ‖ "ZDIR" ‖ 00 01 .. 1f)
     *   seed        = SHA3-256(01 ‖ "ZDIR" ‖ a0 a1 .. bf ‖ client_key)
     *   score       = SHA3-256(02 ‖ "ZDIR" ‖ seed ‖ 11×32)
     *   endpoint_id = SHA3-256(03 ‖ "ZDIR" ‖ ::ffff:10.0.0.7 ‖ 00×32 ‖ 00
     *                          ‖ 61 1f)         (port 8033, little-endian)
     * All four confirmed against openssl dgst -sha3-256. */
    printf("zdir_selection: frozen golden vectors... ");
    {
        static const char *kGoldClientKey =
            "fecb38e7bd249a40a36c9e317aa04ffbc9b2d1bde0fbc55b3eccb9afecd54b90";
        static const char *kGoldSeed =
            "341b4a0529286bec19b674c14f07c2c116ad293307d9a0b5f3e59f9d93174a91";
        static const char *kGoldScore =
            "3ff8cba79c890e137decd30b9f81c3d59b537074ea7c2308abe17ffc91dd5e3c";
        static const char *kGoldEndpoint =
            "2fa9d201dfdfb1b06c14502d49120d5d4020e4bad1b4ce62005715d754119b86";

        uint8_t block_hash[32];
        for (int i = 0; i < 32; i++)
            block_hash[i] = (uint8_t)(0xa0 + i);

        uint8_t seed[32], score[32], endpoint[32], cid[32];
        memset(cid, 0x11, sizeof(cid));

        bool ok = zdir_epoch_seed(seed, block_hash, client_key);
        ok = ok && zdir_candidate_score(score, seed, cid);

        struct net_addr addr;
        memset(&addr, 0, sizeof(addr));
        static const uint8_t kMapped[16] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 7
        };
        memcpy(addr.ip, kMapped, 16);
        ok = ok && zdir_endpoint_id(endpoint, &addr, 8033);

        ok = ok && zdir_t_hex_eq(client_key, 32, kGoldClientKey);
        ok = ok && zdir_t_hex_eq(seed, 32, kGoldSeed);
        ok = ok && zdir_t_hex_eq(score, 32, kGoldScore);
        ok = ok && zdir_t_hex_eq(endpoint, 32, kGoldEndpoint);

        if (ok) {
            printf("OK\n");
        } else {
            printf("FAIL\n  client_key "); zdir_t_print_hex(client_key, 32);
            printf("\n  want       %s\n  seed       ", kGoldClientKey);
            zdir_t_print_hex(seed, 32);
            printf("\n  want       %s\n  score      ", kGoldSeed);
            zdir_t_print_hex(score, 32);
            printf("\n  want       %s\n  endpoint   ", kGoldScore);
            zdir_t_print_hex(endpoint, 32);
            printf("\n  want       %s\n", kGoldEndpoint);
            failures++;
        }
    }

    /* ── 2. domain separation ─────────────────────────────────────────
     * The same 64-byte payload pushed through the seed and candidate
     * sub-domains must not collide, and neither may equal the untagged
     * SHA3-256(a ‖ b) that a naive implementation would produce. A digest
     * minted here can never be replayed as another protocol's digest. */
    printf("zdir_selection: domain separation across sub-domains... ");
    {
        uint8_t a[32], b[32];
        memset(a, 0x5a, sizeof(a));
        memset(b, 0xa5, sizeof(b));

        uint8_t as_seed[32], as_score[32], untagged[32];
        bool ok = zdir_epoch_seed(as_seed, a, b);
        ok = ok && zdir_candidate_score(as_score, a, b);

        uint8_t concat[64];
        memcpy(concat, a, 32);
        memcpy(concat + 32, b, 32);
        sha3_256(concat, sizeof(concat), untagged);

        ok = ok && memcmp(as_seed, as_score, 32) != 0;
        ok = ok && memcmp(as_seed, untagged, 32) != 0;
        ok = ok && memcmp(as_score, untagged, 32) != 0;

        /* The 32-byte-input domains must likewise stay apart. */
        uint8_t ck_a[32];
        ok = ok && zdir_client_key(ck_a, a);
        ok = ok && memcmp(ck_a, as_seed, 32) != 0;
        ok = ok && memcmp(ck_a, untagged, 32) != 0;

        if (ok) printf("OK\n");
        else { printf("FAIL (sub-domain digests collided)\n"); failures++; }
    }

    /* ── 3. purity: repeated calls are byte-identical ─────────────────── */
    printf("zdir_selection: derivation is pure and repeatable... ");
    {
        struct zdir_candidate c[16];
        zdir_t_build_fixture(c, 16);
        struct zdir_params p;
        zdir_t_base_params(&p, client_key);

        struct zdir_selection s1, s2;
        uint16_t w1[16], w2[16];
        bool ok = zdir_select(&p, c, 16, w1, &s1);
        ok = ok && zdir_select(&p, c, 16, w2, &s2);
        ok = ok && s1.preferred_count == s2.preferred_count;
        ok = ok && memcmp(&s1, &s2, sizeof(s1)) == 0;
        ok = ok && memcmp(w1, w2, sizeof(w1)) == 0;
        ok = ok && s1.preferred_count == 8;

        if (ok) printf("OK\n");
        else { printf("FAIL (count=%u)\n", s1.preferred_count); failures++; }
    }

    /* ── 4. NO GLOBAL ANSWER: one bit of client_key reorders everything ─ */
    printf("zdir_selection: one-bit client-key change reorders selection... ");
    {
        uint8_t secret2[32], ck2[32];
        memcpy(secret2, secret, 32);
        secret2[0] ^= 0x01;

        struct zdir_candidate c[16];
        zdir_t_build_fixture(c, 16);

        struct zdir_params p1, p2;
        zdir_t_base_params(&p1, client_key);
        bool ok = zdir_client_key(ck2, secret2);
        zdir_t_base_params(&p2, ck2);

        struct zdir_selection s1, s2;
        ok = ok && zdir_select(&p1, c, 16, NULL, &s1);
        ok = ok && zdir_select(&p2, c, 16, NULL, &s2);
        ok = ok && memcmp(s1.seed, s2.seed, 32) != 0;
        ok = ok && memcmp(s1.preferred, s2.preferred,
                          sizeof(s1.preferred)) != 0;

        if (ok) printf("OK\n");
        else { printf("FAIL (two clients agreed — monoculture)\n"); failures++; }
    }

    /* ── 5. global diversification across many clients ────────────────
     * 64 distinct clients over 16 relays: every relay must be chosen by
     * someone (no relay is structurally unreachable) and no relay may be
     * chosen by every client (no single target serves the whole network). */
    printf("zdir_selection: 64 clients diversify across the candidate set... ");
    {
        struct zdir_candidate c[16];
        zdir_t_build_fixture(c, 16);

        unsigned chosen_by[16] = { 0 };
        bool ok = true;
        for (unsigned k = 0; ok && k < 64; k++) {
            uint8_t sk[32], ck[32];
            memset(sk, 0, sizeof(sk));
            sk[0] = (uint8_t)k;
            sk[1] = (uint8_t)(k * 7u + 3u);
            ok = zdir_client_key(ck, sk);

            struct zdir_params p;
            zdir_t_base_params(&p, ck);
            p.per_owner_cap = 8;   /* let the derivation, not the cap, spread */
            p.want = 4;

            struct zdir_selection s;
            ok = ok && zdir_select(&p, c, 16, NULL, &s);
            for (uint32_t i = 0; ok && i < s.preferred_count; i++)
                chosen_by[s.preferred[i]]++;
        }

        unsigned never = 0, always = 0;
        for (int i = 0; i < 16; i++) {
            if (chosen_by[i] == 0) never++;
            if (chosen_by[i] == 64) always++;
        }
        ok = ok && never == 0 && always == 0;

        if (ok) printf("OK\n");
        else {
            printf("FAIL (never_chosen=%u always_chosen=%u)\n", never, always);
            failures++;
        }
    }

    /* ── 6. advancing the block hash rotates the ordering ─────────────── */
    printf("zdir_selection: new block hash rotates the preference set... ");
    {
        struct zdir_candidate c[16];
        zdir_t_build_fixture(c, 16);

        struct zdir_params p1, p2;
        zdir_t_base_params(&p1, client_key);
        zdir_t_base_params(&p2, client_key);
        p2.block_hash[31] ^= 0x01;

        struct zdir_selection s1, s2;
        bool ok = zdir_select(&p1, c, 16, NULL, &s1);
        ok = ok && zdir_select(&p2, c, 16, NULL, &s2);
        ok = ok && memcmp(s1.seed, s2.seed, 32) != 0;
        ok = ok && memcmp(s1.preferred, s2.preferred,
                          sizeof(s1.preferred)) != 0;

        if (ok) printf("OK\n");
        else { printf("FAIL (block hash did not rotate selection)\n"); failures++; }
    }

    /* ── 7. ADVISORY: weights are bounded in [1.0, 4.0], always ──────── */
    printf("zdir_selection: weight range is bounded and never below neutral... ");
    {
        bool ok = true;
        static const uint32_t kFull[] = { 0u, 1u, 10u, 10000u, 4000000u };
        static const uint32_t kAges[] = { 0u, 1u, 5000u, 10000u, 999999999u };

        for (unsigned f = 0; ok && f < sizeof(kFull) / sizeof(kFull[0]); f++) {
            for (unsigned a = 0; ok && a < sizeof(kAges) / sizeof(kAges[0]); a++) {
                for (unsigned bw = 0; ok && bw <= 255u; bw++) {
                    uint16_t w = zdir_weight_milli((uint8_t)bw, kAges[a],
                                                   kFull[f]);
                    double m = zdir_weight_multiplier(w);
                    ok = w >= ZDIR_WEIGHT_NEUTRAL_MILLI &&
                         w <= ZDIR_WEIGHT_MAX_MILLI &&
                         m >= 1.0 && m <= 4.0;
                }
            }
        }
        /* Anchor values: no bandwidth or no seniority ⇒ exactly neutral;
         * full bandwidth + full seniority ⇒ the ceiling, never past it. */
        ok = ok && zdir_weight_milli(0, 10000, 10000) ==
                       ZDIR_WEIGHT_NEUTRAL_MILLI;
        ok = ok && zdir_weight_milli(255, 0, 10000) ==
                       ZDIR_WEIGHT_NEUTRAL_MILLI;
        ok = ok && zdir_weight_milli(255, 10000, 10000) ==
                       ZDIR_WEIGHT_MAX_MILLI;
        ok = ok && zdir_weight_milli(255, 5000, 10000) == 2494;
        ok = ok && zdir_weight_milli(255, 7, 0) == ZDIR_WEIGHT_MAX_MILLI;
        /* Out-of-range input still clamps into the advisory band. */
        ok = ok && zdir_weight_multiplier(0) == 1.0;
        ok = ok && zdir_weight_multiplier(65535) == 4.0;
        /* Seniority is monotone: aging never lowers the earned weight. */
        uint16_t prev = 0;
        for (uint32_t age = 0; ok && age <= 10000u; age += 250u) {
            uint16_t w = zdir_weight_milli(200, age, 10000);
            ok = w >= prev;
            prev = w;
        }

        if (ok) printf("OK\n");
        else { printf("FAIL (weight escaped the advisory band)\n"); failures++; }
    }

    /* ── 8. ADVISORY: non-preferred candidates land on exact neutral ──── */
    printf("zdir_selection: unpreferred candidates keep neutral weight... ");
    {
        struct zdir_candidate c[16];
        zdir_t_build_fixture(c, 16);
        struct zdir_params p;
        zdir_t_base_params(&p, client_key);
        p.want = 3;

        uint16_t w[16];
        struct zdir_selection s;
        bool ok = zdir_select(&p, c, 16, w, &s);
        ok = ok && s.preferred_count == 3;

        bool preferred[16] = { false };
        for (uint32_t i = 0; ok && i < s.preferred_count; i++)
            preferred[s.preferred[i]] = true;

        for (int i = 0; ok && i < 16; i++) {
            /* Never below neutral: the type cannot express "avoid this peer". */
            ok = w[i] >= ZDIR_WEIGHT_NEUTRAL_MILLI &&
                 w[i] <= ZDIR_WEIGHT_MAX_MILLI;
            if (ok && !preferred[i])
                ok = w[i] == ZDIR_WEIGHT_NEUTRAL_MILLI;
        }

        if (ok) printf("OK\n");
        else { printf("FAIL (a non-preferred candidate was steered)\n"); failures++; }
    }

    /* ── 9. per-owner influence cap ───────────────────────────────────
     * A Sybil owner that registers many relays cannot take the whole
     * preferred set — and the relays it loses are merely un-boosted (test 8
     * proves they stay dialable at neutral), never excluded. */
    printf("zdir_selection: per-owner cap bounds one owner's slots... ");
    {
        struct zdir_candidate c[16];
        zdir_t_build_fixture(c, 16);   /* owners 0x40..0x43, 4 relays each */

        struct zdir_params p;
        zdir_t_base_params(&p, client_key);
        p.per_owner_cap = 1;
        p.want = 8;

        struct zdir_selection s;
        bool ok = zdir_select(&p, c, 16, NULL, &s);
        /* 4 owners × cap 1 = at most 4 preferred, even though want is 8. */
        ok = ok && s.preferred_count == 4;

        unsigned per_owner[4] = { 0 };
        for (uint32_t i = 0; ok && i < s.preferred_count; i++)
            per_owner[c[s.preferred[i]].owner_id[0] - 0x40u]++;
        for (int i = 0; ok && i < 4; i++)
            ok = per_owner[i] == 1;

        /* cap 0 is defensive shorthand for 1, not "unlimited". */
        struct zdir_params p0 = p;
        p0.per_owner_cap = 0;
        struct zdir_selection s0;
        ok = ok && zdir_select(&p0, c, 16, NULL, &s0);
        ok = ok && s0.preferred_count == 4;

        if (ok) printf("OK\n");
        else { printf("FAIL (count=%u)\n", s.preferred_count); failures++; }
    }

    /* ── 10. total order ⇒ invariant under input permutation ─────────── */
    printf("zdir_selection: result invariant under candidate permutation... ");
    {
        struct zdir_candidate c[16], r[16];
        zdir_t_build_fixture(c, 16);
        for (int i = 0; i < 16; i++)
            r[i] = c[15 - i];

        struct zdir_params p;
        zdir_t_base_params(&p, client_key);
        p.per_owner_cap = 8;

        struct zdir_selection s1, s2;
        bool ok = zdir_select(&p, c, 16, NULL, &s1);
        ok = ok && zdir_select(&p, r, 16, NULL, &s2);
        ok = ok && s1.preferred_count == s2.preferred_count;

        /* Same relays, same rank — only the indices differ. */
        for (uint32_t i = 0; ok && i < s1.preferred_count; i++) {
            ok = memcmp(c[s1.preferred[i]].id, r[s2.preferred[i]].id, 32) == 0;
            ok = ok && memcmp(s1.score[i], s2.score[i], 32) == 0;
        }

        if (ok) printf("OK\n");
        else { printf("FAIL (ordering depended on array order)\n"); failures++; }
    }

    /* ── 11. degenerate inputs are total, not fatal ───────────────────── */
    printf("zdir_selection: empty / short / oversized candidate sets... ");
    {
        struct zdir_params p;
        zdir_t_base_params(&p, client_key);

        struct zdir_selection s;
        bool ok = zdir_select(&p, NULL, 0, NULL, &s);
        ok = ok && s.preferred_count == 0;
        /* The seed is still derived when there is nothing to rank. */
        uint8_t seed[32];
        ok = ok && zdir_epoch_seed(seed, p.block_hash, p.client_key);
        ok = ok && memcmp(seed, s.seed, 32) == 0;

        /* want > available ⇒ everything eligible, no error. */
        struct zdir_candidate c[3];
        zdir_t_build_fixture(c, 3);
        p.per_owner_cap = 8;
        ok = ok && zdir_select(&p, c, 3, NULL, &s);
        ok = ok && s.preferred_count == 3;

        /* want is clamped to the slot cap, never overruns the output. */
        struct zdir_candidate c16[16];
        zdir_t_build_fixture(c16, 16);
        p.want = 9999;
        ok = ok && zdir_select(&p, c16, 16, NULL, &s);
        ok = ok && s.preferred_count == (uint32_t)ZDIR_PREFERRED_MAX;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── 12. null / overflow arguments are rejected and logged ────────── */
    printf("zdir_selection: invalid arguments rejected... ");
    {
        uint8_t out[32], a[32];
        memset(a, 1, sizeof(a));
        struct zdir_selection s;
        struct zdir_params p;
        zdir_t_base_params(&p, client_key);
        struct zdir_candidate c[1];
        zdir_t_build_fixture(c, 1);

        bool ok = !zdir_client_key(NULL, a);
        ok = ok && !zdir_client_key(out, NULL);
        ok = ok && !zdir_epoch_seed(NULL, a, a);
        ok = ok && !zdir_epoch_seed(out, NULL, a);
        ok = ok && !zdir_epoch_seed(out, a, NULL);
        ok = ok && !zdir_candidate_score(out, NULL, a);
        ok = ok && !zdir_endpoint_id(out, NULL, 1);
        ok = ok && !zdir_select(NULL, c, 1, NULL, &s);
        ok = ok && !zdir_select(&p, c, 1, NULL, NULL);
        ok = ok && !zdir_select(&p, NULL, 1, NULL, &s);
        ok = ok && !zdir_select(&p, c, (size_t)ZDIR_CANDIDATES_MAX + 1, NULL, &s);
        ok = ok && !zdir_candidates_from_anchors(NULL, NULL, 0, NULL);

        if (ok) printf("OK\n");
        else { printf("FAIL (an invalid argument was accepted)\n"); failures++; }
    }

    /* ── 13. FROZEN GOLDEN SELECTION ──────────────────────────────────
     * The whole pipeline, end to end, over the 16-relay fixture:
     * client_key from secret 00..1f, block hash a0..bf, chain_height 20000,
     * seniority_full 10000, per_owner_cap 2, want 8. If this list moves,
     * every node's preference ordering moved with it. */
    printf("zdir_selection: frozen end-to-end selection vector... ");
    {
        static const uint32_t kGoldPreferred[8] = { 10, 6, 7, 13, 15, 9, 8, 4 };
        static const uint16_t kGoldWeights[16] = {
            1000, 1000, 1000, 1000, 1752, 1000, 2129, 2317,
            2505, 2694, 2882, 1000, 1000, 2705, 1000, 2400
        };

        struct zdir_candidate c[16];
        zdir_t_build_fixture(c, 16);
        struct zdir_params p;
        zdir_t_base_params(&p, client_key);

        uint16_t w[16];
        struct zdir_selection s;
        bool ok = zdir_select(&p, c, 16, w, &s);
        ok = ok && s.preferred_count == 8;
        for (uint32_t i = 0; ok && i < 8; i++)
            ok = s.preferred[i] == kGoldPreferred[i];
        for (int i = 0; ok && i < 16; i++)
            ok = w[i] == kGoldWeights[i];
        ok = ok && zdir_t_hex_eq(
                       s.seed, 32,
                       "341b4a0529286bec19b674c14f07c2c116ad293307d9a0b5f3e"
                       "59f9d93174a91");

        if (ok) {
            printf("OK\n");
        } else {
            printf("FAIL\n  preferred");
            for (uint32_t i = 0; i < s.preferred_count; i++)
                printf(" %u", s.preferred[i]);
            printf("\n  weights  ");
            for (int i = 0; i < 16; i++)
                printf(" %u", w[i]);
            printf("\n");
            failures++;
        }
    }

    /* ── 14. anchors.dat adapter (reuse, not a parallel peer store) ───── */
    printf("zdir_selection: anchor set adapts into candidates... ");
    {
        struct anchor_peer_set set;
        memset(&set, 0, sizeof(set));
        set.count = ANCHOR_PEERS_MAX;
        for (size_t i = 0; i < set.count; i++) {
            set.peers[i].addr.ip[15] = (uint8_t)(i + 1);
            set.peers[i].port = (uint16_t)(8033 + i);
            set.peers[i].last_height = (int32_t)(3000000 + (int)i);
            set.peers[i].last_success = 1700000000 + (int64_t)i;
        }

        struct zdir_candidate c[ANCHOR_PEERS_MAX];
        size_t n = 0;
        bool ok = zdir_candidates_from_anchors(&set, c, ANCHOR_PEERS_MAX, &n);
        ok = ok && n == (size_t)ANCHOR_PEERS_MAX;

        /* Distinct endpoints ⇒ distinct ids; each anchor owns itself. */
        for (size_t i = 0; ok && i < n; i++) {
            ok = memcmp(c[i].id, c[i].owner_id, 32) == 0;
            ok = ok && c[i].bandwidth_score == 0;
            for (size_t j = 0; ok && j < i; j++)
                ok = memcmp(c[i].id, c[j].id, 32) != 0;
        }

        /* Unmeasured anchors carry no weight opinion at all. */
        struct zdir_params p;
        zdir_t_base_params(&p, client_key);
        p.chain_height = 3100000;
        p.want = ANCHOR_PEERS_MAX;
        uint16_t w[ANCHOR_PEERS_MAX];
        struct zdir_selection s;
        ok = ok && zdir_select(&p, c, n, w, &s);
        ok = ok && s.preferred_count == (uint32_t)ANCHOR_PEERS_MAX;
        for (size_t i = 0; ok && i < n; i++)
            ok = w[i] == ZDIR_WEIGHT_NEUTRAL_MILLI;

        /* A truncating out_cap is honoured, not overrun. */
        struct zdir_candidate small[3];
        size_t n2 = 0;
        ok = ok && zdir_candidates_from_anchors(&set, small, 3, &n2);
        ok = ok && n2 == 3;

        if (ok) printf("OK\n");
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    return failures;
}

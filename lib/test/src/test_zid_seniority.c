/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for ZID seniority weighting (zid/zid_seniority.h) — the properties
 * that make it safe, not merely the arithmetic that makes it run.
 *
 * Each case below is a DOCTRINE assertion with a number attached:
 *   - a Sybil burst buys exactly zero, not "a little each";
 *   - one owner's N relays count approximately once, however large N is;
 *   - two clients with identical inputs get DIFFERENT favourites, because a
 *     single shared ranking would be an anonymity monoculture;
 *   - the same client rederives its own table byte-for-byte;
 *   - nothing this module can return excludes a peer or drops it below the
 *     unweighted baseline, for ANY input including hostile ones.
 *
 * The static assertions pin the advisory ceiling: lib/zid sits below lib/net
 * in config/lib_module_order.def and keeps a local copy of the bound, and
 * lib/test is above both, so this is where widening one without the other
 * fails to COMPILE. */

#include "test/test_core.h"
#include "zid/zid_seniority.h"
#include "net/addrman.h"
#include "net/zdir_selection.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

/* Cross-team pin: T5.1's selection weighting and T5.2's seniority weighting
 * feed the SAME addrman call, so all three must agree on the ceiling.
 * Widening any one alone fails to compile.
 *
 * The ceilings are floating constants, and C23 §6.6p6 admits one in an
 * integer constant expression ONLY as the immediate operand of a cast — so
 * these compare the cast constants, never a cast of an expression.
 * `(uint32_t)(X * 1000.0)` is a cast of an expression and is rejected;
 * `(uint32_t)X * 1000u` is the legal form. The decay factor is fractional
 * and has no legal integer form at all, so it is checked at runtime below. */
_Static_assert((uint32_t)ZID_SENIORITY_MAX_MULT ==
                   (uint32_t)ADDRMAN_REPUTATION_MAX_MULT,
               "the seniority ceiling must track ADDRMAN_REPUTATION_MAX_MULT "
               "— seniority may never out-dial the bound addrman enforces");
_Static_assert(ZDIR_WEIGHT_MAX_MILLI ==
                   (uint32_t)ZID_SENIORITY_MAX_MULT * 1000u,
               "seniority and zdir selection must share one advisory ceiling");
_Static_assert(ZID_SENIORITY_MAX_RELAYS_PER_OWNER > 0,
               "a zero per-owner quota would silence every relay");

/* ── deterministic per-client draw stand-ins ───────────────────────
 *
 * Two independent 64-bit streams keyed off (client_seed, relay_id) via
 * splitmix64. These stand in for T5.1's derivation; the only property the
 * module under test relies on is "uniform, pure, and different per client",
 * which is exactly what the seam contract promises. */
struct fake_client {
    uint64_t seed;
    int      calls;
    bool     refuse;   /* exercise the "no draw available" path */
};

static uint64_t splitmix64(uint64_t x)
{
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

static bool fake_draw(void *vctx, const uint8_t relay_id[32],
                      uint64_t *draw_out)
{
    struct fake_client *c = vctx;
    c->calls++;
    if (c->refuse)
        return false;
    uint64_t h = c->seed;
    for (int i = 0; i < 32; i++)
        h = splitmix64(h ^ (uint64_t)relay_id[i] ^ ((uint64_t)i << 56));
    *draw_out = h;
    return true;
}

/* A draw that always returns the maximum — the best case a relay can
 * possibly get from its own client, used to bound the CEILING. */
static bool max_draw(void *vctx, const uint8_t relay_id[32],
                     uint64_t *draw_out)
{
    (void)vctx;
    (void)relay_id;
    *draw_out = UINT64_MAX;
    return true;
}

/* THE PRODUCTION DRAW — a byte-for-byte mirror of the boot adapter
 * (config/src/boot_seniority.c, bsen_client_draw): the low 8
 * bytes of T5.1's per-candidate score, keyed on an epoch seed that is already
 * bound to this client's key. Kept here so the doctrine cases below can be
 * re-run against what actually ships, not only against a test double. */
struct zdir_ctx {
    uint8_t seed[32];
};

static bool zdir_draw(void *vctx, const uint8_t relay_id[32],
                      uint64_t *draw_out)
{
    const struct zdir_ctx *c = vctx;
    uint8_t score[32];
    if (!c || !zdir_candidate_score(score, c->seed, relay_id))
        return false;
    uint64_t d = 0;
    for (int i = 0; i < 8; i++)
        d |= (uint64_t)score[i] << (8 * i);
    *draw_out = d;
    return true;
}

static void mk_relay(struct zid_relay_registration *r, uint8_t id_byte,
                     uint8_t owner_byte, int32_t height)
{
    memset(r, 0, sizeof(*r));
    memset(r->relay_id, id_byte, 32);
    if (owner_byte)
        memset(r->owner_id, owner_byte, 32);
    r->registration_height = height;
}

/* Sum of every multiplier's EXCESS over the 1.0 baseline — the honest
 * measure of "how much selection weight did this set actually buy". */
static double excess_sum(const struct zid_seniority_weight *w, size_t n)
{
    double s = 0.0;
    for (size_t i = 0; i < n; i++)
        s += w[i].multiplier - 1.0;
    return s;
}

int test_zid_seniority(void)
{
    int failures = 0;
    const int32_t TIP = 3200000;

    printf("zid seniority: the advisory ceilings agree exactly... ");
    {
        /* The static asserts above pin the INTEGER parts of these ceilings;
         * a fractional widening (4.0 -> 4.5) truncates to the same integer
         * and would slip past them. Checked exactly here instead. Also the
         * decay factor, which is fractional by construction and therefore
         * has no legal integer-constant-expression form. */
        bool ok = ZID_SENIORITY_MAX_MULT == ADDRMAN_REPUTATION_MAX_MULT &&
                  ZID_SENIORITY_OWNER_DECAY > 0.0 &&
                  ZID_SENIORITY_OWNER_DECAY < 1.0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("zid seniority: score is exactly 0 below the age floor... ");
    {
        /* Not "small" — EXACTLY zero. This is the whole anti-Sybil claim:
         * N registrations sum to N*0, not to N*epsilon. */
        bool ok = zid_seniority_score(TIP, TIP) == 0.0 &&
                  zid_seniority_score(TIP - 1, TIP) == 0.0 &&
                  zid_seniority_score(TIP - ZID_SENIORITY_MIN_AGE_BLOCKS,
                                      TIP) == 0.0 &&
                  zid_seniority_score(TIP - ZID_SENIORITY_MIN_AGE_BLOCKS + 1,
                                      TIP) == 0.0 &&
                  zid_seniority_score(TIP - ZID_SENIORITY_MIN_AGE_BLOCKS - 1,
                                      TIP) > 0.0;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid seniority: score refuses absent/future/negative heights... ");
    {
        bool ok = zid_seniority_score(-1, TIP) == 0.0 &&
                  zid_seniority_score(TIP + 1, TIP) == 0.0 &&
                  zid_seniority_score(TIP, -1) == 0.0 &&
                  /* A registration claiming to predate genesis is still just
                   * an age, not a licence: bounded by the curve, never >1. */
                  zid_seniority_score(0, INT32_MAX) < 1.0;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid seniority: 100k-block-old relay outweighs a day-old one... ");
    {
        double day = zid_seniority_score(TIP - 576, TIP);       /* ~1 day */
        double old = zid_seniority_score(TIP - 100000, TIP);
        double ancient = zid_seniority_score(TIP - 1000000, TIP);
        bool ok = day == 0.0 &&            /* a day is under the 3.5d floor */
                  old > 0.4 && old < 0.6 &&/* half-life lands near 0.5 */
                  ancient > old && ancient < 1.0 &&
                  /* strictly monotone in age, everywhere above the floor */
                  zid_seniority_score(TIP - 5000, TIP) <
                      zid_seniority_score(TIP - 5001, TIP);
        if (ok) printf("OK\n");
        else { printf("FAIL (day=%f old=%f anc=%f)\n", day, old, ancient);
               failures++; }
    }

    printf("zid seniority: 10,000 fresh relays buy exactly zero weight... ");
    {
        /* THE Sybil case. 200 distinct owners x 50 relays each, every one
         * registered this block. Sum of every boost must be 0.0 exactly. */
        enum { N = 10000 };
        static struct zid_relay_registration regs[N];
        static struct zid_seniority_weight out[N];
        for (int i = 0; i < N; i++) {
            memset(&regs[i], 0, sizeof(regs[i]));
            for (int b = 0; b < 32; b++)
                regs[i].relay_id[b] = (uint8_t)(i * 31 + b);
            memset(regs[i].owner_id, (uint8_t)(i % 200 + 1), 32);
            regs[i].registration_height = TIP;   /* minted right now */
        }
        struct fake_client c = { .seed = 0xA1A1A1A1ULL };
        /* Over the projection quota, so it is REFUSED rather than silently
         * truncated into a partial answer. */
        int over = zid_seniority_rank(regs, N, TIP, fake_draw, &c,
                                      out, N);

        /* Now the same burst inside the quota. */
        int n = ZID_SENIORITY_MAX_RELAYS;
        int got = zid_seniority_rank(regs, (size_t)n, TIP, fake_draw, &c,
                                     out, (size_t)n);
        bool ok = over == -1 && got == n && excess_sum(out, (size_t)n) == 0.0;
        for (int i = 0; i < n && ok; i++)
            ok = out[i].multiplier == 1.0 && out[i].mass == 0.0;
        if (ok) printf("OK\n");
        else { printf("FAIL (over=%d got=%d excess=%f)\n", over, got,
                      excess_sum(out, (size_t)n)); failures++; }
    }

    printf("zid seniority: one owner's 100 senior relays count ~once... ");
    {
        /* Every relay maximally aged and identical in every way except its
         * id — so the ONLY thing limiting this owner is the per-owner cap. */
        enum { N = 100 };
        struct zid_relay_registration regs[N];
        struct zid_seniority_weight out[N];
        for (int i = 0; i < N; i++) {
            mk_relay(&regs[i], (uint8_t)(i + 1), 0x77, TIP - 1000000);
        }
        struct fake_client c = { .seed = 0xBEEFULL };
        int got = zid_seniority_rank(regs, N, TIP, fake_draw, &c, out, N);

        double mass_sum = 0.0;
        int with_mass = 0, quota_capped = 0;
        for (int i = 0; i < N; i++) {
            mass_sum += out[i].mass;
            if (out[i].mass > 0.0) with_mass++;
            if (out[i].over_owner_quota) quota_capped++;
        }
        double single = zid_seniority_score(TIP - 1000000, TIP);
        /* 1 + 1/4 + 1/16 + 1/64 = 1.328125 of a single relay's score. */
        double bound = single * 1.328125;

        bool ok = got == N &&
                  with_mass == ZID_SENIORITY_MAX_RELAYS_PER_OWNER &&
                  quota_capped == N - ZID_SENIORITY_MAX_RELAYS_PER_OWNER &&
                  mass_sum <= bound + 1e-9 &&
                  mass_sum > single;   /* still worth more than one, barely */
        if (ok) printf("OK\n");
        else { printf("FAIL (got=%d mass=%f bound=%f with_mass=%d)\n",
                      got, mass_sum, bound, with_mass); failures++; }
    }

    printf("zid seniority: withheld owner is never pooled with other "
           "unknowns... ");
    {
        /* The cheapest bypass of a per-owner cap is to omit the owner field.
         * Each unknown must be its own owner, so nobody is capped by
         * somebody else's anonymity — and nobody escapes their own cap by
         * hiding, because hiding gets them rank 0 individually but does not
         * remove the cap on the owner they actually declared elsewhere. */
        enum { N = 8 };
        struct zid_relay_registration regs[N];
        struct zid_seniority_weight out[N];
        for (int i = 0; i < N; i++)
            mk_relay(&regs[i], (uint8_t)(i + 1), 0 /* unknown */,
                     TIP - 1000000);
        struct fake_client c = { .seed = 0xC0FFEEULL };
        int got = zid_seniority_rank(regs, N, TIP, fake_draw, &c, out, N);
        bool ok = got == N;
        for (int i = 0; i < N && ok; i++)
            ok = out[i].owner_rank == 0 && !out[i].over_owner_quota &&
                 out[i].mass > 0.0;
        if (ok) printf("OK\n");
        else { printf("FAIL (got=%d)\n", got); failures++; }
    }

    printf("zid seniority: duplicate relay ids decay instead of "
           "double-counting... ");
    {
        /* Submitting the same identity four times is a Sybil attempt with
         * one identity; it must land in successive owner ranks. */
        enum { N = 4 };
        struct zid_relay_registration regs[N];
        struct zid_seniority_weight out[N];
        for (int i = 0; i < N; i++)
            mk_relay(&regs[i], 0x5a, 0x11, TIP - 1000000);
        struct fake_client c = { .seed = 7 };
        int got = zid_seniority_rank(regs, N, TIP, fake_draw, &c, out, N);
        int ranks[N];
        for (int i = 0; i < N; i++) ranks[i] = out[i].owner_rank;
        bool ok = got == N;
        /* ranks are a permutation of 0..N-1, i.e. no two took rank 0. */
        for (int r = 0; r < N && ok; r++) {
            int seen = 0;
            for (int i = 0; i < N; i++) if (ranks[i] == r) seen++;
            ok = seen == 1;
        }
        if (ok) printf("OK\n");
        else { printf("FAIL (got=%d ranks=%d,%d,%d,%d)\n", got,
                      ranks[0], ranks[1], ranks[2], ranks[3]); failures++; }
    }

    printf("zid seniority: NO GLOBAL ANSWER — two clients disagree on the "
           "favourite... ");
    {
        /* Identical chain state, identical relay set, identical code. If the
         * two clients still agreed on a single top relay, this module would
         * have built an anonymity monoculture: one ranking, one target that
         * serves everybody. They must not agree. */
        enum { N = 64 };
        struct zid_relay_registration regs[N];
        struct zid_seniority_weight a[N], b[N];
        for (int i = 0; i < N; i++)
            mk_relay(&regs[i], (uint8_t)(i + 1), (uint8_t)(i + 1),
                     TIP - 1000000);   /* all equally senior, distinct owners */

        struct fake_client ca = { .seed = 0x1111ULL };
        struct fake_client cb = { .seed = 0x2222ULL };
        int ga = zid_seniority_rank(regs, N, TIP, fake_draw, &ca, a, N);
        int gb = zid_seniority_rank(regs, N, TIP, fake_draw, &cb, b, N);

        int top_a = 0, top_b = 0, differing = 0;
        for (int i = 0; i < N; i++) {
            if (a[i].multiplier > a[top_a].multiplier) top_a = i;
            if (b[i].multiplier > b[top_b].multiplier) top_b = i;
            if (a[i].multiplier != b[i].multiplier) differing++;
        }
        bool ok = ga == N && gb == N &&
                  top_a != top_b &&        /* different favourite */
                  differing == N;          /* and NOTHING in common */
        if (ok) printf("OK\n");
        else { printf("FAIL (top_a=%d top_b=%d differing=%d)\n",
                      top_a, top_b, differing); failures++; }
    }

    printf("zid seniority: the same client rederives its table exactly... ");
    {
        enum { N = 32 };
        struct zid_relay_registration regs[N];
        struct zid_seniority_weight a[N], b[N];
        for (int i = 0; i < N; i++)
            mk_relay(&regs[i], (uint8_t)(200 - i), (uint8_t)(i % 5 + 1),
                     TIP - 20000 * (i + 1));
        struct fake_client c1 = { .seed = 0x5EED };
        struct fake_client c2 = { .seed = 0x5EED };
        int g1 = zid_seniority_rank(regs, N, TIP, fake_draw, &c1, a, N);
        int g2 = zid_seniority_rank(regs, N, TIP, fake_draw, &c2, b, N);
        bool ok = g1 == N && g2 == N && memcmp(a, b, sizeof(a)) == 0;

        /* Input order must not matter either — the output is canonical. */
        struct zid_relay_registration rev[N];
        struct zid_seniority_weight c[N];
        for (int i = 0; i < N; i++) rev[i] = regs[N - 1 - i];
        struct fake_client c3 = { .seed = 0x5EED };
        int g3 = zid_seniority_rank(rev, N, TIP, fake_draw, &c3, c, N);
        ok = ok && g3 == N && memcmp(a, c, sizeof(a)) == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid seniority: senior relays win more often across many "
           "clients... ");
    {
        /* Per-client diversity must not have destroyed the point: averaged
         * over the population, seniority still has to buy influence. */
        enum { N = 3 };
        struct zid_relay_registration regs[N];
        struct zid_seniority_weight out[N];
        mk_relay(&regs[0], 0x01, 0x01, TIP - 1000000);  /* ancient */
        mk_relay(&regs[1], 0x02, 0x02, TIP - 20000);    /* middling */
        mk_relay(&regs[2], 0x03, 0x03, TIP - 100);      /* fresh */

        double sum[N] = {0};
        int wins[N] = {0};
        const int CLIENTS = 4000;
        for (int k = 0; k < CLIENTS; k++) {
            struct fake_client c = { .seed = 0xD00D0000ULL + (uint64_t)k };
            if (zid_seniority_rank(regs, N, TIP, fake_draw, &c, out, N) != N)
                continue;
            int top = 0;
            for (int i = 0; i < N; i++) {
                sum[i] += out[i].multiplier;
                if (out[i].multiplier > out[top].multiplier) top = i;
            }
            /* out is sorted by relay_id, which for these ids is 1,2,3. */
            wins[top]++;
        }
        double avg0 = sum[0] / CLIENTS, avg1 = sum[1] / CLIENTS,
               avg2 = sum[2] / CLIENTS;
        bool ok = avg0 > avg1 && avg1 > avg2 &&
                  avg2 == 1.0 &&              /* fresh gets nothing, ever */
                  wins[0] > wins[1] && wins[1] > 0 && wins[2] == 0 &&
                  /* and the ancient relay does NOT own the network: it is
                   * the favourite often, not always. */
                  wins[0] < CLIENTS;
        if (ok) printf("OK\n");
        else { printf("FAIL (avg=%.3f/%.3f/%.3f wins=%d/%d/%d)\n",
                      avg0, avg1, avg2, wins[0], wins[1], wins[2]);
               failures++; }
    }

    printf("zid seniority: ADVISORY — every multiplier stays in [1, 4] and "
           "nothing is dropped... ");
    {
        /* Hostile sweep: extreme heights, unknown owners, max draws, refused
         * draws. No input may produce a multiplier below 1.0 (which would be
         * a penalty) or above the addrman bound, and the output must always
         * carry EVERY input relay. */
        enum { N = 40 };
        struct zid_relay_registration regs[N];
        struct zid_seniority_weight out[N];
        int32_t heights[] = { 0, -1, 1, TIP, TIP + 1, INT32_MAX, INT32_MIN,
                              TIP - 1, TIP - ZID_SENIORITY_MIN_AGE_BLOCKS,
                              TIP - 1000000 };
        for (int i = 0; i < N; i++)
            mk_relay(&regs[i], (uint8_t)(i + 1), (uint8_t)(i % 3),
                     heights[i % 10]);

        bool ok = true;
        struct fake_client c = { .seed = 0xFACEULL };
        int got = zid_seniority_rank(regs, N, TIP, fake_draw, &c, out, N);
        ok = ok && got == N;

        int gmax = zid_seniority_rank(regs, N, TIP, max_draw, NULL, out, N);
        ok = ok && gmax == N;
        for (int i = 0; i < N && ok; i++)
            ok = out[i].multiplier >= 1.0 &&
                 out[i].multiplier <= ZID_SENIORITY_MAX_MULT &&
                 !isnan(out[i].multiplier);

        /* A refused draw is a legitimate negative, not an exclusion. */
        struct fake_client refuser = { .seed = 1, .refuse = true };
        int gref = zid_seniority_rank(regs, N, TIP, fake_draw, &refuser,
                                      out, N);
        ok = ok && gref == N && refuser.calls > 0;
        for (int i = 0; i < N && ok; i++)
            ok = out[i].multiplier == 1.0;

        /* Every input relay is still present in the output. */
        for (int i = 0; i < N && ok; i++)
            ok = zid_seniority_find(out, N, regs[i].relay_id) != NULL;
        if (ok) printf("OK\n");
        else { printf("FAIL (got=%d gmax=%d gref=%d)\n", got, gmax, gref);
               failures++; }
    }

    printf("zid seniority: combine is monotone, bounded, and never "
           "subtracts... ");
    {
        bool ok = zid_seniority_combine(1.0, 1.0) == 1.0 &&
                  zid_seniority_combine(ZID_SENIORITY_MAX_MULT, 1.0) ==
                      ZID_SENIORITY_MAX_MULT &&
                  zid_seniority_combine(1.0, ZID_SENIORITY_MAX_MULT) ==
                      ZID_SENIORITY_MAX_MULT &&
                  zid_seniority_combine(ZID_SENIORITY_MAX_MULT,
                                        ZID_SENIORITY_MAX_MULT) ==
                      ZID_SENIORITY_MAX_MULT &&
                  /* out-of-range degrades to "no opinion", never to a
                   * penalty or an unbounded boost */
                  zid_seniority_combine(-5.0, 1.0) == 1.0 &&
                  zid_seniority_combine(1e9, 1.0) == ZID_SENIORITY_MAX_MULT &&
                  zid_seniority_combine(nan(""), 1.0) == 1.0 &&
                  zid_seniority_combine(1.0, nan("")) == 1.0;

        /* Monotone non-decreasing in BOTH arguments, and never below either
         * one — so neither signal can be used to pull a peer down. */
        for (int i = 0; i <= 20 && ok; i++) {
            for (int j = 0; j <= 20 && ok; j++) {
                double a = 1.0 + 3.0 * i / 20.0;
                double b = 1.0 + 3.0 * j / 20.0;
                double v = zid_seniority_combine(a, b);
                ok = v >= a - 1e-12 && v >= b - 1e-12 &&
                     v <= ZID_SENIORITY_MAX_MULT + 1e-12 &&
                     v == zid_seniority_combine(b, a);   /* symmetric */
                if (ok && j > 0) {
                    double prev = zid_seniority_combine(a,
                                        1.0 + 3.0 * (j - 1) / 20.0);
                    ok = v >= prev - 1e-12;
                }
            }
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid seniority: ranking epoch rate-limits the reshuffle... ");
    {
        int32_t e = ZID_SENIORITY_EPOCH_BLOCKS;
        bool ok = zid_seniority_epoch_height(0) == 0 &&
                  zid_seniority_epoch_height(-5) == 0 &&
                  zid_seniority_epoch_height(e - 1) == 0 &&
                  zid_seniority_epoch_height(e) == e &&
                  zid_seniority_epoch_height(e + 1) == e &&
                  zid_seniority_epoch_height(2 * e - 1) == e &&
                  zid_seniority_epoch_height(2 * e) == 2 * e;
        /* Constant across a whole window: every height in [e, 2e) maps to e,
         * so the favourite set cannot churn per block nor be reground every
         * 150 seconds. */
        for (int32_t h = e; h < 2 * e && ok; h++)
            ok = zid_seniority_epoch_height(h) == e;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid seniority: rank refuses bad input instead of guessing... ");
    {
        struct zid_relay_registration regs[2];
        struct zid_seniority_weight out[2];
        mk_relay(&regs[0], 1, 1, TIP - 1000000);
        mk_relay(&regs[1], 2, 1, TIP - 1000000);
        struct fake_client c = { .seed = 1 };
        bool ok = zid_seniority_rank(NULL, 2, TIP, fake_draw, &c, out, 2) == -1 &&
                  zid_seniority_rank(regs, 2, TIP, fake_draw, &c, NULL, 2) == -1 &&
                  /* NULL draw is refused outright: falling back to a shared
                   * deterministic ranking is the monoculture this module
                   * exists to prevent, so it is not an available default. */
                  zid_seniority_rank(regs, 2, TIP, NULL, &c, out, 2) == -1 &&
                  zid_seniority_rank(regs, 2, TIP, fake_draw, &c, out, 1) == -1 &&
                  zid_seniority_rank(regs, 0, TIP, fake_draw, &c, out, 2) == 0 &&
                  zid_seniority_find(NULL, 0, regs[0].relay_id) == NULL;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zid seniority: the PRODUCTION draw (zdir) keeps the no-global-"
           "answer property... ");
    {
        /* The cases above use a stand-in draw. This one runs the real
         * derivation the boot path wires in — zdir_client_key ->
         * zdir_epoch_seed -> zdir_candidate_score — so the property is proven
         * against what actually ships, not only against the test double. */
        enum { N = 64 };
        struct zid_relay_registration regs[N];
        struct zid_seniority_weight a[N], b[N], a2[N];
        for (int i = 0; i < N; i++)
            mk_relay(&regs[i], (uint8_t)(i + 1), (uint8_t)(i + 1),
                     TIP - 1000000);

        uint8_t secret_a[32], secret_b[32], block_hash[32];
        memset(secret_a, 0x11, sizeof(secret_a));
        memset(secret_b, 0x22, sizeof(secret_b));
        memset(block_hash, 0x33, sizeof(block_hash));

        uint8_t key_a[32], key_b[32];
        struct zdir_ctx ca, cb;
        bool ok = zdir_client_key(key_a, secret_a) &&
                  zdir_client_key(key_b, secret_b) &&
                  zdir_epoch_seed(ca.seed, block_hash, key_a) &&
                  zdir_epoch_seed(cb.seed, block_hash, key_b) &&
                  memcmp(ca.seed, cb.seed, 32) != 0;

        int ga = 0, gb = 0, ga2 = 0;
        if (ok) {
            ga  = zid_seniority_rank(regs, N, TIP, zdir_draw, &ca, a, N);
            gb  = zid_seniority_rank(regs, N, TIP, zdir_draw, &cb, b, N);
            ga2 = zid_seniority_rank(regs, N, TIP, zdir_draw, &ca, a2, N);
            ok = ga == N && gb == N && ga2 == N;
        }

        int differing = 0, top_a = 0, top_b = 0;
        for (int i = 0; i < N && ok; i++) {
            if (a[i].multiplier != b[i].multiplier) differing++;
            if (a[i].multiplier > a[top_a].multiplier) top_a = i;
            if (b[i].multiplier > b[top_b].multiplier) top_b = i;
        }
        ok = ok && differing == N && top_a != top_b &&
             /* same client key + same epoch => same table, exactly */
             memcmp(a, a2, sizeof(a)) == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL (differing=%d top_a=%d top_b=%d)\n",
                      differing, top_a, top_b); failures++; }
    }

    printf("=== ZID seniority: %d failure(s) ===\n", failures);
    return failures;
}

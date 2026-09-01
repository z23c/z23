/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Adaptive client-puzzle admission gate (core/modules/net/puzzle.{c,h}).
 *
 * Proves the reusable anti-abuse primitive that fronts expensive server-side
 * work (store z-address mint, snapshot serve, file stream):
 *   1. pure verify/solve round-trip + negative binding (wrong seed/token/ts);
 *   2. a server-issued challenge is solved and admitted;
 *   3. a solution is SINGLE-USE — an exact replay is refused;
 *   4. difficulty RISES under sustained load and FALLS back to the floor when
 *      idle — with NO reset edge (the property the EWMA exists to give over a
 *      tumbling window);
 *   5. puzzle_gate_admit_external's single-use ring (used by the snapshot
 *      serve path, which verifies its own legacy PoW) rejects replays, and
 *      feeds the same load EWMA a verified admission does;
 *   6. the nonce-start contract: a search from zero is a pure function of
 *      (seed, token, ts), so two independent honest solvers collide and the
 *      single-use ring refuses the second — puzzle_solve_random() is what a
 *      real client must use.
 *
 * None of this touches a consensus predicate — it only decides whether to
 * spend server resources on an unauthenticated request. */

#include "test/test_core.h"
#include "net/puzzle.h"
#include "platform/time_compat.h"
#include <string.h>
#include <stdint.h>

/* ── 1. Pure primitive: verify/solve round-trip + negative binding ─────── */
static int test_puzzle_verify_solve_roundtrip(void)
{
    int failures = 0;
    TEST("puzzle: verify/solve round-trip + wrong seed/token/ts refused") {
        uint8_t seed[32], token[32], other[32];
        memset(seed, 0x11, 32);
        memset(token, 0x22, 32);
        memset(other, 0x33, 32);
        int64_t ts = 1000000;
        /* 16 bits so a wrong-tuple digest hitting the leading-zero target by
         * chance is ~2^-16 per check — negligible flake, still a fast solve. */
        int bits = 16;

        uint64_t nonce = 0;
        ASSERT(puzzle_solve(seed, token, ts, bits, &nonce));
        ASSERT(puzzle_verify(seed, token, ts, nonce, bits));

        /* A KAT-style frozen expectation: the SAME inputs always produce a
         * hash with >= bits leading zeros; a lower difficulty is trivially
         * still satisfied, a much higher one is not by this nonce. */
        ASSERT(puzzle_verify(seed, token, ts, nonce, 8));

        /* Binding: change any input and the leading-zero property is lost
         * (the digest is effectively random for the wrong tuple). */
        ASSERT(!puzzle_verify(other, token, ts, nonce, bits)); /* wrong seed  */
        ASSERT(!puzzle_verify(seed, other, ts, nonce, bits));  /* wrong token */
        ASSERT(!puzzle_verify(seed, token, ts + 1, nonce, bits)); /* wrong ts */
        ASSERT(!puzzle_verify(seed, token, ts, nonce + 1, bits)); /* wrong nonce */
        PASS();
    } _test_next:;
    return failures;
}

/* Client helper: fetch the live challenge and solve it bound to `token`. */
static bool solve_gate(struct puzzle_gate *g, const uint8_t token[32],
                       int64_t *ts_out, uint64_t *nonce_out)
{
    uint8_t seed[32];
    int bits = 0;
    int64_t st = 0;
    puzzle_gate_challenge(g, seed, &bits, &st);
    int64_t ts = (int64_t)platform_time_wall_time_t();
    if (!puzzle_solve(seed, token, ts, bits, nonce_out))
        return false;
    *ts_out = ts;
    return true;
}

/* ── 2 + 3. Challenge → admit, then single-use replay refused ──────────── */
static int test_gate_challenge_admit_and_replay(void)
{
    int failures = 0;
    TEST("puzzle: challenge issued, solved, admitted once; replay refused") {
        struct puzzle_gate g;
        memset(&g, 0, sizeof(g));
        puzzle_gate_init(&g, NULL);

        uint8_t token[32];
        memset(token, 0x9F, 32);

        /* No challenge issued yet → verify refuses. */
        ASSERT(!puzzle_gate_verify(&g, token, (int64_t)platform_time_wall_time_t(), 0));

        int64_t ts = 0;
        uint64_t nonce = 0;
        ASSERT(solve_gate(&g, token, &ts, &nonce));

        /* First presentation admits. */
        ASSERT(puzzle_gate_verify(&g, token, ts, nonce));
        /* Exact replay of the same solution is refused (single-use ring). */
        ASSERT(!puzzle_gate_verify(&g, token, ts, nonce));

        /* A garbage nonce is refused. */
        ASSERT(!puzzle_gate_verify(&g, token, ts, nonce ^ 0xdeadbeefULL));

        /* A stale timestamp (outside skew) is refused before any hashing. */
        ASSERT(!puzzle_gate_verify(&g, token, ts - (PUZZLE_TS_SKEW_SECS + 10), nonce));
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4. EWMA: difficulty rises under load, falls when idle, no reset edge ─ */
static int test_gate_difficulty_rises_and_falls(void)
{
    int failures = 0;
    TEST("puzzle: difficulty rises under load and decays back to floor") {
        /* Tight band so the ramp is quick to drive: min 12, soft 4/sec,
         * +1 bit per 1/sec over soft. Half-life 10s. */
        struct puzzle_policy pol = {
            .min_bits = 12, .max_bits = 26,
            .soft_rate_per_sec = 4, .rate_step_per_sec = 1,
            .ewma_halflife_secs = 10,
        };
        struct puzzle_gate g;
        memset(&g, 0, sizeof(g));
        puzzle_gate_init(&g, &pol);

        uint8_t token[32];
        memset(token, 0x5A, 32);

        /* Idle: difficulty sits at the floor. */
        ASSERT_EQ(puzzle_gate_current_bits(&g), 12);

        /* Issue a challenge at a fixed clock so we control the seed epoch. */
        int64_t wall = 2000000;
        int64_t us = 5000000;   /* monotonic base */
        uint8_t seed[32];
        int bits = 0;
        puzzle_gate_challenge_at(&g, wall, us, seed, &bits, NULL);
        ASSERT_EQ(bits, 12);

        /* Drive ~40 accepted solves spread across ~1 second of monotonic
         * time (well inside the half-life). Each needs a distinct digest so
         * the single-use ring does not reject it: vary the timestamp by 1s
         * per solve (still inside skew), solving against the SAME seed/bits. */
        int64_t prev_rate = -1;
        int64_t last_us = us;
        for (int i = 0; i < 40; i++) {
            int64_t ts = wall + i;              /* distinct → distinct digest */
            uint64_t nonce = 0;
            ASSERT(puzzle_solve(seed, token, ts, bits, &nonce));
            /* advance the monotonic clock ~25ms per solve → ~1s total */
            last_us = us + (int64_t)(i + 1) * 25000;
            ASSERT(puzzle_gate_verify_at(&g, token, ts, nonce, wall, last_us));
            int64_t r = puzzle_gate_rate_ewma_milli(&g);
            (void)prev_rate;
            prev_rate = r;
        }

        /* Under this sustained load the measured rate is well above the soft
         * threshold, so the adaptive difficulty has risen off the floor. */
        int loaded_bits = puzzle_gate_current_bits(&g);
        ASSERT(loaded_bits > 12);
        ASSERT(puzzle_gate_rate_ewma_milli(&g) > (int64_t)pol.soft_rate_per_sec * 1000);

        /* No reset edge: sampling right after a tick never reads exactly 0
         * while loaded (this is the property the window→EWMA swap fixes). */
        ASSERT(puzzle_gate_rate_ewma_milli(&g) > 0);

        /* Idle → the rate decays back under soft and difficulty returns to the
         * floor. The tick caps a single elapsed step at 5s (so one stale
         * sample can never produce a decay cliff), so age the estimate over
         * many small steps — exactly how a live gate ticks as challenges keep
         * arriving. 60 five-second steps ≈ 300s ≫ half-life. */
        int64_t t = last_us;
        for (int i = 0; i < 60; i++) {
            t += 5000000;   /* 5s, at/under the tick's dt cap */
            puzzle_gate_challenge_at(&g, wall, t, seed, &bits, NULL);
        }
        ASSERT(puzzle_gate_rate_ewma_milli(&g) < (int64_t)pol.soft_rate_per_sec * 1000);
        ASSERT_EQ(puzzle_gate_current_bits(&g), 12);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4b. Concurrency term: in-flight large serves raise difficulty ─────── */
static int test_gate_inflight_difficulty(void)
{
    int failures = 0;
    TEST("puzzle: concurrent large serves raise difficulty, drain restores it") {
        struct puzzle_gate g;
        memset(&g, 0, sizeof(g));
        puzzle_gate_init(&g, NULL);

        uint8_t seed[32];
        int idle_bits = 0, load_bits = 0, back_bits = 0;
        int64_t st = 0;

        puzzle_gate_challenge(&g, seed, &idle_bits, &st);
        ASSERT_EQ(idle_bits, PUZZLE_MIN_BITS);

        /* Three concurrent large serves in progress → difficulty ramps. */
        puzzle_gate_serve_begin(&g);
        puzzle_gate_serve_begin(&g);
        puzzle_gate_serve_begin(&g);
        puzzle_gate_challenge(&g, seed, &load_bits, &st);
        ASSERT(load_bits > idle_bits);
        ASSERT_EQ(load_bits, PUZZLE_MIN_BITS + 3 * PUZZLE_INFLIGHT_BITS);

        /* Drains → difficulty falls back to the idle floor. */
        puzzle_gate_serve_end(&g);
        puzzle_gate_serve_end(&g);
        puzzle_gate_serve_end(&g);
        puzzle_gate_challenge(&g, seed, &back_bits, &st);
        ASSERT_EQ(back_bits, PUZZLE_MIN_BITS);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5. External single-use ring (snapshot serve path) ─────────────────── */
static int test_gate_admit_external_replay(void)
{
    int failures = 0;
    TEST("puzzle: admit_external is single-use per digest") {
        struct puzzle_gate g;
        memset(&g, 0, sizeof(g));
        puzzle_gate_init(&g, NULL);

        uint8_t d1[32], d2[32];
        memset(d1, 0xA1, 32);
        memset(d2, 0xB2, 32);

        ASSERT(puzzle_gate_admit_external(&g, d1));   /* first sight admits   */
        ASSERT(!puzzle_gate_admit_external(&g, d1));  /* exact replay refused */
        ASSERT(puzzle_gate_admit_external(&g, d2));   /* a distinct one admits */
        ASSERT(!puzzle_gate_admit_external(&g, d2));  /* its replay refused    */
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5b. admit_external feeds the load EWMA ────────────────────────────────
 *
 * This is the whole point of giving admit_external a caller: a surface that
 * verifies its own proof still makes the shared gate's difficulty respond to
 * real traffic. An idle gate reads zero; a run of distinct admissions must
 * push the measured rate up and the difficulty off the floor. */
static int test_gate_admit_external_feeds_load(void)
{
    int failures = 0;
    TEST("puzzle: admit_external drives the load EWMA off the idle floor") {
        struct puzzle_policy pol = {
            .min_bits = 12, .max_bits = 26,
            .soft_rate_per_sec = 2, .rate_step_per_sec = 1,
            .ewma_halflife_secs = 10,
        };
        struct puzzle_gate g;
        memset(&g, 0, sizeof(g));
        puzzle_gate_init(&g, &pol);

        ASSERT_EQ(puzzle_gate_rate_ewma_milli(&g), 0);
        ASSERT_EQ(puzzle_gate_current_bits(&g), 12);

        /* 40 distinct digests — no replays, so every one is admitted and
         * every one counts as load. */
        for (int i = 0; i < 40; i++) {
            uint8_t d[32];
            memset(d, 0, 32);
            d[0] = (uint8_t)i;
            d[1] = (uint8_t)(i >> 8);
            ASSERT(puzzle_gate_admit_external(&g, d));
        }

        ASSERT(puzzle_gate_rate_ewma_milli(&g) >
               (int64_t)pol.soft_rate_per_sec * 1000);
        ASSERT(puzzle_gate_current_bits(&g) > 12);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6. Nonce-start contract: from-zero collides, random does not ──────────
 *
 * The defect this pins is why the snapshot-serve surface cannot turn its
 * single-use ring on: its solver walks nonces from zero over inputs that two
 * honest peers can share, so both produce the same proof and the second is
 * refused as a replay. Proven here on the primitive rather than inherited
 * from a comment. */
static int test_puzzle_solve_nonce_start(void)
{
    int failures = 0;
    TEST("puzzle: solve-from-zero collides across solvers, random does not") {
        uint8_t seed[32], token[32];
        memset(seed, 0x77, 32);
        memset(token, 0x88, 32);
        int64_t ts = 1700000000;
        int bits = 14;

        /* Two independent solvers with the SAME (seed, token, ts) and the
         * default from-zero search return the IDENTICAL nonce. */
        uint64_t a = 1, b = 2;
        ASSERT(puzzle_solve(seed, token, ts, bits, &a));
        ASSERT(puzzle_solve(seed, token, ts, bits, &b));
        ASSERT(a == b);

        /* So a gate with a single-use ring admits the first and refuses the
         * second — two honest clients, one served. */
        struct puzzle_gate g;
        memset(&g, 0, sizeof(g));
        puzzle_gate_init(&g, NULL);
        uint8_t seed_live[32];
        int live_bits = 0;
        int64_t st = 0;
        puzzle_gate_challenge(&g, seed_live, &live_bits, &st);
        int64_t now = (int64_t)platform_time_wall_time_t();
        uint64_t n1 = 0, n2 = 0;
        ASSERT(puzzle_solve(seed_live, token, now, live_bits, &n1));
        ASSERT(puzzle_solve(seed_live, token, now, live_bits, &n2));
        ASSERT(n1 == n2);
        ASSERT(puzzle_gate_verify(&g, token, now, n1));
        ASSERT(!puzzle_gate_verify(&g, token, now, n2));  /* honest, refused */

        /* puzzle_solve_random searches from an independent random offset, so
         * repeated solves over the same inputs land on different nonces and
         * each is admitted in turn. Two draws matching is ~2^-64 per pair;
         * assert only that BOTH still verify and that a run of them is
         * admitted, so the case can never flake. */
        for (int i = 0; i < 8; i++) {
            uint64_t nr = 0;
            ASSERT(puzzle_solve_random(seed_live, token, now, live_bits, &nr));
            ASSERT(puzzle_verify(seed_live, token, now, nr, live_bits));
            /* nr == n1 only if the random start happened to land exactly on
             * the from-zero answer's basin; skip that astronomically rare
             * case rather than assert against it. */
            if (nr != n1)
                ASSERT(puzzle_gate_verify(&g, token, now, nr));
        }

        /* An explicit start is honoured: starting past the from-zero answer
         * must not return it. */
        uint64_t nf = 0;
        ASSERT(puzzle_solve_from(seed_live, token, now, live_bits, n1 + 1, &nf));
        ASSERT(nf != n1);
        ASSERT(puzzle_verify(seed_live, token, now, nf, live_bits));
        PASS();
    } _test_next:;
    return failures;
}

int test_puzzle(void)
{
    int failures = 0;
    failures += test_puzzle_verify_solve_roundtrip();
    failures += test_gate_challenge_admit_and_replay();
    failures += test_gate_difficulty_rises_and_falls();
    failures += test_gate_inflight_difficulty();
    failures += test_gate_admit_external_replay();
    failures += test_gate_admit_external_feeds_load();
    failures += test_puzzle_solve_nonce_start();
    return failures;
}

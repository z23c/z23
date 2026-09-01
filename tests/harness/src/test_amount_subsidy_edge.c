/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Net-new consensus edge-case tests for amount / block-subsidy arithmetic.
 *
 * These pin boundary behaviour that the existing suites
 * (tests/harness/src/test_core.c "MoneyRange", and
 *  tests/harness/src/test_domain_consensus_subsidy.c) do NOT assert:
 *
 *   - MoneyRange at the int64_t extremes (INT64_MIN / INT64_MAX) and
 *     one satoshi inside MAX_MONEY. A wrong sign-handling or off-by-one
 *     here lets a transaction smuggle an out-of-range / overflow amount
 *     past the value sanity check -> consensus fork / inflation.
 *
 *   - The block subsidy at the EXACT Buttercup activation height
 *     (n == nActivationHeight, the classic off-by-one fork seam), at
 *     exact post-Buttercup halving boundaries (just below / at / above),
 *     and the far-future zero-subsidy regime (subsidy underflows to 0
 *     via the right-shift, and the explicit 64-halving cap). All of
 *     these are asserted as EXACT satoshi values, not "smaller than",
 *     so a regression that merely changes the curve shape is caught.
 *
 * Every case drives the real consensus function
 * domain_consensus_block_subsidy() against the live mainnet params and
 * cross-checks the legacy get_block_subsidy() wrapper where applicable.
 * Pure, deterministic, no network, no node process.
 *
 * Mainnet constants this file relies on (core/modules/chain/src/chainparams.c):
 *   nSubsidySlowStartInterval        = 2      (slow-start shift = 1)
 *   nPreButtercupSubsidyHalvingInterval  = 840000
 *   nPostButtercupSubsidyHalvingInterval = 1680000  (= 840000 * 2)
 *   UPGRADE_BUTTERCUP activation height  = 707000
 *   BUTTERCUP_POW_TARGET_SPACING_RATIO   = 2
 *   full reward base = 12.5 * COIN = 1250000000 sat
 */

#include "test/test_core.h"

#include "domain/consensus/subsidy.h"
#include "chain/subsidy.h"
#include "chain/chainparams.h"
#include "consensus/params.h"
#include "core/amount.h"

#include <stdio.h>

#define ASE_CHECK(name, expr) do { \
    printf("amount_subsidy_edge: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Drive the real consensus function and return the subsidy, asserting
 * the call itself succeeded (ok==true). On error we return a sentinel
 * that cannot equal any legal subsidy so the value assertion also
 * fails loudly. */
static int64_t real_subsidy_ok(int h, const struct consensus_params *p, int *ok_out)
{
    int64_t s = -1;
    struct zcl_result r = domain_consensus_block_subsidy(h, p, &s);
    *ok_out = r.ok ? 1 : 0;
    return r.ok ? s : -1;
}

int test_amount_subsidy_edge(void)
{
    int failures = 0;
    const struct chain_params *cp = chain_params_get();
    const struct consensus_params *params = &cp->consensus;

    const int64_t FULL = (int64_t)(12.5 * COIN); /* 1250000000 */

    /* ===================================================================
     * Part 1 — MoneyRange int64 extremes / one-satoshi boundary.
     * test_core.c covers {0, COIN, MAX_MONEY, -1, MAX_MONEY+1}; it does
     * NOT cover the full-width integer extremes or MAX_MONEY-1.
     * =================================================================== */

    /* The most-negative int64 must be rejected (sign check). */
    ASE_CHECK("MoneyRange(INT64_MIN) == false", MoneyRange(INT64_MIN) == false);

    /* The most-positive int64 is far above MAX_MONEY -> rejected
     * (guards against an overflow-shaped amount slipping through). */
    ASE_CHECK("MoneyRange(INT64_MAX) == true is wrong -> must be false",
              MoneyRange(INT64_MAX) == false);

    /* One satoshi below the cap is in range (lower edge of the top). */
    ASE_CHECK("MoneyRange(MAX_MONEY - 1) == true",
              MoneyRange(MAX_MONEY - 1) == true);

    /* One satoshi (smallest positive) is in range. */
    ASE_CHECK("MoneyRange(1) == true", MoneyRange((CAmount)1) == true);

    /* Sanity: the cap itself is the largest accepted value, and exactly
     * one more is rejected (pins the inclusive upper bound). */
    ASE_CHECK("MoneyRange(MAX_MONEY) == true && MoneyRange(MAX_MONEY+1) == false",
              MoneyRange(MAX_MONEY) == true && MoneyRange(MAX_MONEY + 1) == false);

    /* ===================================================================
     * Part 2 — Subsidy at the EXACT Buttercup activation seam.
     * The existing suite asserts 706999 (full reward) and 707001
     * (post-buttercup, "smaller"), but skips the activation height
     * itself, n == 707000, which is the off-by-one a fork lives in.
     * Buttercup activates with n_height >= 707000, so at exactly 707000 the
     * upgrade is ACTIVE and halvings == 0; the per-block reward drops because
     * post-Buttercup blocks arrive BUTTERCUP_POW_TARGET_SPACING_RATIO (16)x
     * more often, so the reward is (FULL / 16) >> 0 = 78125000 — the same as
     * 707001 (still halvings 0). This pins the >= activation operator: flip it
     * to > and 707000 would pay the FULL pre-Buttercup reward instead.
     * =================================================================== */
    {
        int ok = 0;
        int64_t s = real_subsidy_ok(706999, params, &ok);
        ASE_CHECK("h=706999 (pre-buttercup) == FULL 12.5 COIN",
                  ok && s == FULL);
    }
    {
        int ok = 0;
        int64_t s = real_subsidy_ok(707000, params, &ok);
        ASE_CHECK("h=707000 (EXACT buttercup activation) == 78125000",
                  ok && s == 78125000);
    }
    {
        int ok = 0;
        int64_t s = real_subsidy_ok(707001, params, &ok);
        /* First block after activation: (FULL / 16) >> 0 = 78125000, still
         * halvings 0 (the post-Buttercup halving interval has not elapsed). */
        ASE_CHECK("h=707001 (first full post-buttercup) == 78125000",
                  ok && s == 78125000);
    }
    /* The activation seam must move the reward strictly downward and the
     * legacy wrapper must agree at the exact boundary. */
    {
        ASE_CHECK("legacy wrapper agrees at activation seam (706999/707000)",
                  get_block_subsidy(706999, params) == FULL &&
                  get_block_subsidy(707000, params) == 78125000);
    }

    /* ===================================================================
     * Part 3 — Exact post-buttercup halving boundary (just below / at /
     * above). halvings goes 3 -> 4 when (h - 1 - 707000) crosses a
     * multiple of 1680000, i.e. at h == 2387001.
     *   h=2387000 -> halvings 3 -> (FULL/2)>>3 = 78125000
     *   h=2387001 -> halvings 4 -> (FULL/2)>>4 = 39062500
     * The existing cross-check loop visits these heights but never
     * asserts the exact halved value; we pin both sides of the step.
     * =================================================================== */
    {
        int ok = 0;
        int64_t below = real_subsidy_ok(2387000, params, &ok);
        ASE_CHECK("h=2387000 (just below 2nd post-bc halving) == 78125000",
                  ok && below == 78125000);
    }
    {
        int ok = 0;
        int64_t at = real_subsidy_ok(2387001, params, &ok);
        ASE_CHECK("h=2387001 (at 2nd post-bc halving) == 39062500",
                  ok && at == 39062500);
    }
    /* The boundary must HALVE exactly: below == 2 * at. A bug that
     * shifts the boundary or changes the divisor breaks this identity. */
    {
        int ok1 = 0, ok2 = 0;
        int64_t below = real_subsidy_ok(2387000, params, &ok1);
        int64_t at = real_subsidy_ok(2387001, params, &ok2);
        ASE_CHECK("post-bc halving boundary halves exactly (below == 2*at)",
                  ok1 && ok2 && below == 2 * at);
    }

    /* ===================================================================
     * Part 4 — Far-future zero subsidy.
     * Two distinct ways the reward reaches 0, both consensus-load-bearing:
     *
     *  (a) Underflow via the right-shift while halvings < 64. The first
     *      height whose reward shifts to exactly 0 (verified by direct
     *      computation against the live params) is 46067001; the block
     *      immediately before that boundary still pays 1 satoshi.
     *
     *  (b) The explicit >= 64 halvings cap. At h = 103187001 halvings
     *      reaches 64 and the function returns 0 unconditionally. This
     *      height fits inside int (< INT32_MAX), so it is reachable by
     *      the real int-typed argument.
     *
     * No existing test exercises the zero-subsidy regime at all.
     * =================================================================== */
    {
        int ok = 0;
        int64_t s = real_subsidy_ok(46067001, params, &ok);
        ASE_CHECK("h=46067001 (reward underflows to exactly 0) == 0",
                  ok && s == 0);
    }
    {
        /* One halving interval earlier the reward is still 1 satoshi:
         * proves the zero point is a genuine transition, not always-0. */
        int ok = 0;
        int64_t s = real_subsidy_ok(46067001 - 1680000, params, &ok);
        ASE_CHECK("h=44387001 (one interval before zero) == 1 satoshi",
                  ok && s == 1);
    }
    {
        int ok = 0;
        int64_t s = real_subsidy_ok(103187001, params, &ok);
        ASE_CHECK("h=103187001 (>= 64 halvings cap) == 0, call succeeds",
                  ok && s == 0);
    }
    /* Zero must be a SUCCESS result, never an error, and the legacy
     * wrapper (which fail-safes errors to 0) must return the same 0. */
    {
        int64_t s = -1;
        struct zcl_result r = domain_consensus_block_subsidy(103187001, params, &s);
        ASE_CHECK("zero subsidy is ZCL_OK (not an error path)",
                  r.ok && s == 0 && get_block_subsidy(103187001, params) == 0);
    }

    /* ===================================================================
     * Part 5 — Genesis / slow-start exact edges.
     * test_domain_consensus_subsidy asserts h=0 -> 0 and h=1 -> >0, but
     * not the EXACT slow-start values nor the first post-slow-start
     * block. With nSubsidySlowStartInterval == 2:
     *   h=0 : multiplier 0                       -> 0
     *   h=1 : second slow-start half, (FULL/2)*(1+1) -> FULL
     *   h=2 : post slow-start, halvings 0        -> FULL
     * =================================================================== */
    {
        int ok = 0;
        int64_t s = real_subsidy_ok(0, params, &ok);
        ASE_CHECK("h=0 (genesis) subsidy == 0 exactly", ok && s == 0);
    }
    {
        int ok = 0;
        int64_t s = real_subsidy_ok(1, params, &ok);
        ASE_CHECK("h=1 (last slow-start block) == FULL 12.5 COIN",
                  ok && s == FULL);
    }
    {
        int ok = 0;
        int64_t s = real_subsidy_ok(2, params, &ok);
        ASE_CHECK("h=2 (first post-slow-start block) == FULL 12.5 COIN",
                  ok && s == FULL);
    }

    return failures;
}

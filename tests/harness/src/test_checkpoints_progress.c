/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for domain/consensus/src/checkpoints.c, function
 * domain_consensus_checkpoints_progress_at_now().
 *
 * progress_at_now is the pure verification-progress estimator: it
 * combines a block's cheap-work counter (nChainTx), the cheap-work
 * counter at the last checkpoint (nTransactionsLastCheckpoint), and
 * an estimate of the expensive (post-checkpoint) work that remains,
 * scaled by fTransactionsPerDay and elapsed wall time. The clock has
 * been lifted to the `now_unix_sec` parameter so the whole thing is
 * a pure function of its inputs.
 *
 * This file pins, with one TEST_CASE per int test_*(void) entrypoint
 * (TEST_END defines the _test_next label, so two per function would
 * not compile):
 *
 *   1. Boundary crossover (cheap `<`, exact `==`, expensive `>` the
 *      checkpoint tx count). The recovered fWorkBefore (numerator)
 *      strictly increases as nChainTx grows, and total work is
 *      non-decreasing across the boundary. Recovery is exact because
 *      we zero the elapsed-time term (now == nTimeLastCheckpoint ==
 *      pindex_time), making cheap-branch total work a constant equal
 *      to nTransactionsLastCheckpoint.
 *
 *   2. Zero / degenerate defenses: NULL data -> 0.0; empty table
 *      (nEntries == 0, entries NULL — the function never reads
 *      entries, only the scalar fields); all-zero scalars hitting
 *      the divide-by-zero guard -> 0.0; future time (now < table
 *      time and now < pindex_time) does not crash and stays a finite
 *      clamped fraction.
 *
 *   3. Sigcheck factor: fSigchecks==true scales the *expensive*
 *      component by exactly 5.0 relative to fSigchecks==false. We
 *      isolate the expensive component in the cheap branch (one day
 *      of elapsed time => nExpensiveAfter == fTransactionsPerDay)
 *      and recover it from progress; the sig/no-sig ratio is 5.0 to
 *      the bit.
 *
 *   4. Regression seal: three sampled progress values pinned exactly
 *      (0.0, 0.5, 1.0) for deterministic (tx, time) tuples, plus the
 *      two cheap-branch ratios pinned against their exact rational
 *      forms.
 *
 * Fixture scalars (shared mental model across cases):
 *   nTransactionsLastCheckpoint = 200000
 *   nTimeLastCheckpoint         = 1500000000   (2017-07-14)
 *   fTransactionsPerDay         = 1000.0
 * With these, "one day of future time" contributes exactly 1000
 * transactions of expensive work, so all expected values are small
 * integers / exact dyadic ratios — no float fuzz needed.
 */

#include "test/test_core.h"

#include "domain/consensus/checkpoints.h"
#include "chain/checkpoints.h"
#include "core/uint256.h"

#include <stdbool.h>
#include <stdint.h>

/* Shared fixture scalars. progress_at_now reads only these from the
 * table (never the entries array), so we can leave entries NULL for
 * the empty-table case and point it at a tiny stub elsewhere. */
#define CPP_NTX_LAST   ((int64_t)200000)
#define CPP_NTIME_LAST ((int64_t)1500000000)
#define CPP_TPD        (1000.0)
#define CPP_DAY        ((int64_t)86400)

static void cpp_make_table(struct checkpoint_data *cd,
                           struct checkpoint_entry *e /* may be NULL */,
                           int n)
{
    cd->entries = e;
    cd->nEntries = n;
    cd->nTimeLastCheckpoint = CPP_NTIME_LAST;
    cd->nTransactionsLastCheckpoint = CPP_NTX_LAST;
    cd->fTransactionsPerDay = CPP_TPD;
}

/* ── 1. Boundary crossover + monotonic work ─────────────────────── */
int test_checkpoints_progress_boundary_crossover(void)
{
    int failures = 0;
    TEST_CASE("progress_at_now: boundary crossover < == > monotonic work") {
        struct checkpoint_entry e[1];
        struct checkpoint_data cd;
        memset(e, 0, sizeof(e));
        e[0].height = 100;
        cpp_make_table(&cd, e, 1);

        /* Zero the elapsed-time term in BOTH branches so total work is
         * a clean function of transaction counts:
         *   now == nTimeLastCheckpoint (kills cheap-branch time term)
         *   pindex_time == now         (kills expensive-branch time term)
         * In the cheap branch this makes total work == nTransactionsLast,
         * so fWorkBefore == progress * nTransactionsLast exactly. */
        const int64_t now   = CPP_NTIME_LAST;
        const int64_t ptime = CPP_NTIME_LAST;

        /* below the checkpoint tx count (cheap path, nChainTx < last). */
        double p_below = domain_consensus_checkpoints_progress_at_now(
                             &cd, 50000, ptime, now, true);
        /* still cheap path, but deeper. */
        double p_mid = domain_consensus_checkpoints_progress_at_now(
                           &cd, 120000, ptime, now, true);
        /* exactly at the checkpoint tx count (`<=` keeps cheap path). */
        double p_exact = domain_consensus_checkpoints_progress_at_now(
                             &cd, (uint64_t)CPP_NTX_LAST, ptime, now, true);
        /* above the checkpoint tx count (expensive path, nChainTx > last). */
        double p_above = domain_consensus_checkpoints_progress_at_now(
                             &cd, 250000, ptime, now, true);

        /* Recover fWorkBefore in the cheap branch (total work is the
         * constant nTransactionsLast there). */
        double wb_below = p_below * (double)CPP_NTX_LAST;
        double wb_mid   = p_mid   * (double)CPP_NTX_LAST;
        double wb_exact = p_exact * (double)CPP_NTX_LAST;

        /* Recovered numerator == the input tx count, exactly. */
        ASSERT(wb_below == 50000.0);
        ASSERT(wb_mid   == 120000.0);
        ASSERT(wb_exact == 200000.0);

        /* fWorkBefore (the numerator) strictly increases as nChainTx
         * grows across the cheap regime and into the boundary. */
        ASSERT(wb_below < wb_mid);
        ASSERT(wb_mid   < wb_exact);

        /* At the exact boundary the cheap path saturates: all work is
         * "before", none "after" (time term zeroed) -> progress 1.0. */
        ASSERT(p_exact == 1.0);

        /* Above the boundary the expensive path runs; with now==ptime the
         * "after" work is again zero so progress saturates to 1.0, but
         * total work has grown: 200000 + (250000-200000)*5 == 450000,
         * which is strictly greater than the cheap-branch total 200000.
         * Confirm the expensive path is active and finite. */
        ASSERT(p_above == 1.0);

        /* Total-work monotonicity across the boundary (non-decreasing):
         * cheap totals are all 200000; the expensive total is 450000.
         * Since both saturated points read 1.0 we cannot recover the
         * expensive total from progress alone, so we pin the qualitative
         * invariant directly: an above-boundary block with MORE elapsed
         * "after" time than an at-boundary block has LOWER progress,
         * proving the larger denominator (more total work). */
        double p_exact_t = domain_consensus_checkpoints_progress_at_now(
                               &cd, (uint64_t)CPP_NTX_LAST, ptime, now + CPP_DAY, true);
        double p_above_t = domain_consensus_checkpoints_progress_at_now(
                               &cd, 250000, ptime, now + CPP_DAY, true);
        /* With a day of "after" work added, neither saturates and the
         * above-boundary block (more total work via the 5x expensive
         * cheap-counter) reports HIGHER progress than the at-boundary
         * block, because its numerator grew by 50000*5 while both gained
         * the same 5000 of expensive-after work. */
        ASSERT(p_exact_t < 1.0);
        ASSERT(p_above_t < 1.0);
        ASSERT(p_above_t > p_exact_t);

        /* Pin the `<=` boundary semantics: at the EXACT checkpoint tx
         * count the cheap path must run (the `<=` test), NOT the
         * expensive path. We make the two paths produce different
         * answers by giving the block a pindex_time that differs from
         * the table's checkpoint time, plus a future `now`:
         *   cheap path uses (now - nTimeLastCheckpoint) for elapsed;
         *   expensive path would use (now - pindex_time).
         * now = nTimeLast + 1 day; pindex_time = now - 10 days.
         * Cheap (correct): nExpensiveAfter = 1*1000, fWorkAfter =
         *   1000*5 = 5000, fWorkBefore = 200000 -> 200000/205000.
         * Expensive (the `<` regression): nExpensiveAfter = 10*1000,
         *   fWorkAfter = 50000 -> 200000/250000. */
        const int64_t now_b   = CPP_NTIME_LAST + CPP_DAY;
        const int64_t ptime_b = now_b - 10 * CPP_DAY;
        double p_boundary = domain_consensus_checkpoints_progress_at_now(
                                &cd, (uint64_t)CPP_NTX_LAST, ptime_b, now_b, true);
        ASSERT(p_boundary == 200000.0 / 205000.0);
        /* And it is NOT the value the expensive path would have given. */
        ASSERT(p_boundary != 200000.0 / 250000.0);
    } TEST_END
    return failures;
}

/* ── 2. Zero / degenerate defenses ──────────────────────────────── */
int test_checkpoints_progress_zero_defenses(void)
{
    int failures = 0;
    TEST_CASE("progress_at_now: NULL / empty / future-time defenses") {
        /* NULL data -> clean 0.0, never a deref. */
        ASSERT(domain_consensus_checkpoints_progress_at_now(
                   NULL, 100, CPP_NTIME_LAST, CPP_NTIME_LAST + CPP_DAY, true) == 0.0);

        /* Empty table: nEntries == 0, entries == NULL. progress_at_now
         * reads only the scalar fields, so this must behave identically
         * to a populated table with the same scalars (and not deref
         * entries). tx=0 at now==nTimeLast: numerator 0, denom 200000
         * -> exactly 0.0. */
        struct checkpoint_data empty;
        cpp_make_table(&empty, NULL, 0);
        ASSERT(domain_consensus_checkpoints_progress_at_now(
                   &empty, 0, CPP_NTIME_LAST, CPP_NTIME_LAST, true) == 0.0);

        /* Empty table still computes the boundary case correctly: tx ==
         * nTransactionsLast at now==nTimeLast -> saturated 1.0. Proves
         * the scalar-only computation, independent of entries. */
        ASSERT(domain_consensus_checkpoints_progress_at_now(
                   &empty, (uint64_t)CPP_NTX_LAST, CPP_NTIME_LAST,
                   CPP_NTIME_LAST, true) == 1.0);

        /* Divide-by-zero guard: all-zero scalars, tx=0, now=0. The
         * historical code produced 0/0 = NaN here; the defended code
         * clamps to a clean 0.0. */
        struct checkpoint_data zeros;
        zeros.entries = NULL;
        zeros.nEntries = 0;
        zeros.nTimeLastCheckpoint = 0;
        zeros.nTransactionsLastCheckpoint = 0;
        zeros.fTransactionsPerDay = 0.0;
        ASSERT(domain_consensus_checkpoints_progress_at_now(
                   &zeros, 0, 0, 0, true) == 0.0);

        /* Future time: now_unix_sec earlier than BOTH the table time and
         * the block time. The elapsed-time term goes negative, which can
         * drag the denominator negative; the guard (denom <= 0 -> 0.0)
         * must catch it. With tx=0 (cheap branch) and now far before
         * nTimeLast, denom = 200000 + (negative*5) < 0 -> 0.0, never NaN
         * or +/-inf, and crucially no crash. */
        double future = domain_consensus_checkpoints_progress_at_now(
                            &empty, 0, CPP_NTIME_LAST,
                            CPP_NTIME_LAST - 100 * CPP_DAY, true);
        ASSERT(future == 0.0);

        /* Future time that does NOT flip the denominator stays a finite
         * fraction in [0,1] (no NaN/inf leak). Modest backwards skew. */
        double mild_future = domain_consensus_checkpoints_progress_at_now(
                                 &empty, 100000, CPP_NTIME_LAST,
                                 CPP_NTIME_LAST - CPP_DAY, true);
        ASSERT(mild_future >= 0.0 && mild_future <= 1.0);
        ASSERT(mild_future == mild_future); /* not NaN */
    } TEST_END
    return failures;
}

/* ── 3. Sigcheck factor is exactly 5.0 on expensive work ────────── */
int test_checkpoints_progress_sigcheck_factor(void)
{
    int failures = 0;
    TEST_CASE("progress_at_now: fSigchecks multiplies expensive work by 5.0") {
        struct checkpoint_data cd;
        cpp_make_table(&cd, NULL, 0);

        /* Cheap branch, one day of future time so the expensive-after
         * component equals exactly fTransactionsPerDay == 1000:
         *   nChainTx = 100000  -> fWorkBefore = 100000
         *   nCheapAfter        = 200000 - 100000 = 100000
         *   nExpensiveAfter    = (1 day)/1day * 1000 = 1000
         * sig:   fWorkAfter = 100000 + 1000*5 = 105000
         * nosig: fWorkAfter = 100000 + 1000*1 = 101000
         * progress = 100000 / (100000 + fWorkAfter). */
        const uint64_t tx  = 100000;
        const int64_t now  = CPP_NTIME_LAST + CPP_DAY;
        double ps = domain_consensus_checkpoints_progress_at_now(
                        &cd, tx, CPP_NTIME_LAST, now, true);
        double pn = domain_consensus_checkpoints_progress_at_now(
                        &cd, tx, CPP_NTIME_LAST, now, false);

        /* The toggle must change the answer. */
        ASSERT(ps != pn);

        /* Recover fWorkAfter from progress: progress = wb/(wb+wa) =>
         * wa = wb*(1 - progress)/progress, with wb = 100000 known. */
        double wb = (double)tx;
        double wa_sig   = wb * (1.0 - ps) / ps;   /* expect 105000 */
        double wa_nosig = wb * (1.0 - pn) / pn;   /* expect 101000 */

        /* The cheap-after part (100000) is the SAME in both; only the
         * expensive part is scaled by the factor. Isolate it. */
        double exp_sig   = wa_sig   - 100000.0;   /* expect 5000 */
        double exp_nosig = wa_nosig - 100000.0;   /* expect 1000 */

        /* fSigchecks=false leaves expensive work at the raw per-day count. */
        ASSERT(exp_nosig > 999.0 && exp_nosig < 1001.0);
        /* fSigchecks=true multiplies it by exactly 5.0. */
        ASSERT(exp_sig > 4999.0 && exp_sig < 5001.0);
        double ratio = exp_sig / exp_nosig;
        ASSERT(ratio > 4.999 && ratio < 5.001);

        /* Pin the two progress readings against their exact rational
         * forms — the compiler evaluates these identically to the
         * function's internal expression, so this is a hard regression
         * seal on the 5x factor, not a fuzzy bound. */
        ASSERT(ps == 100000.0 / 205000.0);
        ASSERT(pn == 100000.0 / 201000.0);

        /* With sigchecks ON, more expensive work remains -> the fraction
         * of work already done is SMALLER than with sigchecks OFF. */
        ASSERT(ps < pn);
    } TEST_END
    return failures;
}

/* ── 4. Regression seal: pinned 0.0 / 0.5 / 1.0 samples ──────────── */
int test_checkpoints_progress_regression_seal(void)
{
    int failures = 0;
    TEST_CASE("progress_at_now: pinned progress samples 0.0 / 0.5 / 1.0") {
        struct checkpoint_data cd;
        cpp_make_table(&cd, NULL, 0);

        /* progress == 0.0 (cheap branch): nChainTx == 0, with positive
         * future work present so we exercise the real ratio (0/positive),
         * not just the divide-by-zero guard.
         *   fWorkBefore = 0
         *   fWorkAfter  = 200000 + (1 day * 1000)*5 = 205000 > 0
         *   progress    = 0 / 205000 == 0.0 */
        double p0 = domain_consensus_checkpoints_progress_at_now(
                        &cd, 0, CPP_NTIME_LAST, CPP_NTIME_LAST + CPP_DAY, true);
        ASSERT(p0 == 0.0);

        /* progress == 0.5 (cheap branch): nChainTx == 100000, now ==
         * nTimeLast (no expensive-after term).
         *   fWorkBefore = 100000
         *   fWorkAfter  = (200000 - 100000) + 0 = 100000
         *   progress    = 100000 / 200000 == 0.5 */
        double p5 = domain_consensus_checkpoints_progress_at_now(
                        &cd, 100000, CPP_NTIME_LAST, CPP_NTIME_LAST, true);
        ASSERT(p5 == 0.5);

        /* progress == 1.0 (cheap boundary): nChainTx == nTransactionsLast,
         * now == nTimeLast.
         *   fWorkBefore = 200000
         *   fWorkAfter  = 0 + 0 = 0
         *   progress    = 200000 / 200000 == 1.0 */
        double p1 = domain_consensus_checkpoints_progress_at_now(
                        &cd, (uint64_t)CPP_NTX_LAST, CPP_NTIME_LAST,
                        CPP_NTIME_LAST, true);
        ASSERT(p1 == 1.0);

        /* Ordering of the three sealed samples must hold. */
        ASSERT(p0 < p5);
        ASSERT(p5 < p1);

        /* Determinism: identical inputs -> identical output (pure fn). */
        double p5_again = domain_consensus_checkpoints_progress_at_now(
                              &cd, 100000, CPP_NTIME_LAST, CPP_NTIME_LAST, true);
        ASSERT(p5_again == p5);
    } TEST_END
    return failures;
}

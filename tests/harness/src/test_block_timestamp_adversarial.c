/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Adversarial coverage for the BLOCK-VALIDITY use of block timestamps:
 * a block's own nTime, not the nLockTime/BIP113 use (that is
 * test_bip113_bip65.c's territory, and this file does not repeat it).
 *
 * Two independent rules gate a header's nTime:
 *
 *   1. MEDIAN-TIME-PAST monotonicity (contextual_check_block_header,
 *      check_block.c ~line 358): nTime must be STRICTLY greater than
 *      block_index_get_median_time_past(pindex_prev) — the median of up
 *      to the last MEDIAN_TIME_SPAN(11) ancestor timestamps. Time source:
 *      the ANCESTOR MTP, never wall-clock.
 *
 *   2. FUTURE-TIME bound (check_block_header, check_block.c ~line 165):
 *      nTime must not exceed GetAdjustedTime() + 2h. Time source: the
 *      node's own adjusted-now, never MTP/ancestors.
 *
 * test_bip113_bip65.c pins MTP arithmetic, rejection of nTime <= MTP, and a
 * weak not-"time-too-old" check at nTime==MTP+1. test_domain_consensus_header_accept.c
 * pins the pure domain boundary math with injected MTP/now values.
 * This file drives the REAL production entry points end-to-end with nBits
 * pinned to the genuine GetNextWorkRequired() output so the diffbits gate
 * never masks a timestamp-gate result:
 *   - MTP monotonicity boundary with a TRUE accept/reject flip through
 *     contextual_check_block_header (not just "not this reject reason").
 *   - FUTURE-TIME boundary through the actual check_block_header() legacy
 *     entry point (only the domain function's boundary was pinned before).
 *   - MTP window correctness: an ancestor OUTSIDE the last-11 window must
 *     NOT influence the median (chain longer than MEDIAN_TIME_SPAN).
 *   - MTP hand-reference: an independent (qsort-based) median computed
 *     in the test must match block_index_get_median_time_past() exactly,
 *     including on an out-of-order sequence within the windowed chain.
 *   - Equal-timestamp run: several ancestors sharing one nTime value,
 *     verifying the median and the next block's minimum-nTime rule.
 */

#include "test/test_core.h"
#include "validation/check_block.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "core/uint256.h"
#include "util/timedata.h"
#include "util/safe_alloc.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/* ── helpers ─────────────────────────────────────────────── */

/* Build a linear ancestor chain of `count` block_index entries, times[i]
 * assigned to height i (the returned pointer is the tip). nBits is pinned on
 * every entry so the diffbits gate never fires for these short chains. */
static struct block_index *make_pinned_chain(struct block_index *chain,
                                              int count,
                                              const uint32_t *times,
                                              uint32_t nbits_pin)
{
    for (int i = 0; i < count; i++) {
        block_index_init(&chain[i]);
        chain[i].nHeight = i;
        chain[i].nTime = times[i];
        chain[i].nBits = nbits_pin;
        chain[i].pprev = i > 0 ? &chain[i - 1] : NULL;
    }
    return &chain[count - 1];
}

/* Independent reference median (copy + qsort, index n/2) matching the
 * production index convention, as a genuine second implementation. */
static int cmp_u32(const void *a, const void *b)
{
    uint32_t va = *(const uint32_t *)a, vb = *(const uint32_t *)b;
    return (va > vb) - (va < vb);
}

static int64_t reference_median(const uint32_t *times, int n)
{
    uint32_t *copy = zcl_malloc((size_t)n * sizeof(uint32_t), "test_ref_median");
    memcpy(copy, times, (size_t)n * sizeof(uint32_t));
    qsort(copy, (size_t)n, sizeof(uint32_t), cmp_u32);
    int64_t mid = copy[n / 2];
    free(copy);
    return mid;
}

/* Minimal synthetic header that passes every contextual_check_block_header
 * gate except the timestamp gate under test. */
static void make_pinned_header(struct block_header *hdr, uint32_t nTime,
                                uint32_t nbits_pin)
{
    block_header_init(hdr);
    hdr->nVersion = 4;
    hdr->nTime = nTime;
    hdr->nBits = nbits_pin;
    hdr->nSolutionSize = 0; /* silent pass on equihash-solution-size */
}

/* ── scenarios (each prints its own prompt and verdict) ────────────── */

/* 1a. nTime==MTP must be rejected as "time-too-old" with dos=0. */
static int check_mtp_rejects_time_equal_to_mtp(const struct chain_params *params,
                                               uint32_t nbits_pin)
{
    int failures = 0;
    printf("contextual_check_block_header: nTime==MTP is REJECTED (time-too-old, dos=0)... ");
    struct block_index chain[11];
    uint32_t times[] = {100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100};
    struct block_index *tip = make_pinned_chain(chain, 11, times, nbits_pin);
    int64_t mtp = block_index_get_median_time_past(tip);

    struct block_header hdr;
    make_pinned_header(&hdr, (uint32_t)mtp, nbits_pin);

    struct validation_state state;
    validation_state_init(&state);
    bool ok = contextual_check_block_header(&hdr, &state, params, tip, false);
    if (ok || strcmp(state.reject_reason, "time-too-old") != 0 ||
        state.dos != 0) {
        printf("FAIL (ok=%d reason=%s dos=%d)\n", ok, state.reject_reason, state.dos);
        failures++;
    } else printf("OK\n");
    return failures;
}

/* 1b. nTime==MTP+1 must be truly accepted (the boundary flip). */
static int check_mtp_accepts_time_one_above_mtp(const struct chain_params *params,
                                                uint32_t nbits_pin)
{
    int failures = 0;
    printf("contextual_check_block_header: nTime==MTP+1 is TRULY ACCEPTED (boundary)... ");
    struct block_index chain[11];
    uint32_t times[] = {100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100};
    struct block_index *tip = make_pinned_chain(chain, 11, times, nbits_pin);
    int64_t mtp = block_index_get_median_time_past(tip);

    struct block_header hdr;
    make_pinned_header(&hdr, (uint32_t)(mtp + 1), nbits_pin);

    struct validation_state state;
    validation_state_init(&state);
    bool ok = contextual_check_block_header(&hdr, &state, params, tip, false);
    if (!ok) {
        printf("FAIL (should ACCEPT, got reject_reason=%s)\n", state.reject_reason);
        failures++;
    } else printf("OK\n");
    return failures;
}

/* 1c. nTime==MTP-1 stays rejected (below the boundary too). */
static int check_mtp_rejects_time_one_below_mtp(const struct chain_params *params,
                                                uint32_t nbits_pin)
{
    int failures = 0;
    printf("contextual_check_block_header: nTime==MTP-1 stays rejected (below boundary too)... ");
    struct block_index chain[11];
    uint32_t times[] = {100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100};
    struct block_index *tip = make_pinned_chain(chain, 11, times, nbits_pin);
    int64_t mtp = block_index_get_median_time_past(tip);

    struct block_header hdr;
    make_pinned_header(&hdr, (uint32_t)(mtp - 1), nbits_pin);

    struct validation_state state;
    validation_state_init(&state);
    bool ok = contextual_check_block_header(&hdr, &state, params, tip, false);
    if (ok || strcmp(state.reject_reason, "time-too-old") != 0) {
        printf("FAIL (ok=%d reason=%s)\n", ok, state.reject_reason);
        failures++;
    } else printf("OK\n");
    return failures;
}

/* 2a. nTime==now+2h must be truly accepted (the bound is a strict >). */
static int check_future_time_accepts_two_hours_ahead(const struct chain_params *params)
{
    int failures = 0;
    printf("check_block_header: nTime==now+2h is TRULY ACCEPTED (boundary, strict >)... ");
    int64_t now = GetAdjustedTime();
    struct block_header hdr;
    block_header_init(&hdr);
    hdr.nVersion = 4;
    hdr.nTime = (uint32_t)(now + 2 * 60 * 60);

    struct validation_state state;
    validation_state_init(&state);
    bool ok = check_block_header(&hdr, &state, params, /*check_pow=*/false);
    if (!ok) {
        printf("FAIL (should ACCEPT, got reject_reason=%s)\n", state.reject_reason);
        failures++;
    } else printf("OK\n");
    return failures;
}

/* 2b. nTime==now+2h+1 must be rejected as "time-too-new" with dos=0. */
static int check_future_time_rejects_beyond_two_hours(const struct chain_params *params)
{
    int failures = 0;
    printf("check_block_header: nTime==now+2h+1 is REJECTED (time-too-new, dos=0)... ");
    int64_t now = GetAdjustedTime();
    struct block_header hdr;
    block_header_init(&hdr);
    hdr.nVersion = 4;
    hdr.nTime = (uint32_t)(now + 2 * 60 * 60 + 1);

    struct validation_state state;
    validation_state_init(&state);
    bool ok = check_block_header(&hdr, &state, params, /*check_pow=*/false);
    if (ok || strcmp(state.reject_reason, "time-too-new") != 0 ||
        state.dos != 0) {
        printf("FAIL (ok=%d reason=%s dos=%d)\n", ok, state.reject_reason, state.dos);
        failures++;
    } else printf("OK\n");
    return failures;
}

/* 2c. nTime==now is well inside the bound (accepted). */
static int check_future_time_accepts_adjusted_now(const struct chain_params *params)
{
    int failures = 0;
    printf("check_block_header: nTime==now is well inside the bound (accepted)... ");
    int64_t now = GetAdjustedTime();
    struct block_header hdr;
    block_header_init(&hdr);
    hdr.nVersion = 4;
    hdr.nTime = (uint32_t)now;

    struct validation_state state;
    validation_state_init(&state);
    bool ok = check_block_header(&hdr, &state, params, /*check_pow=*/false);
    if (!ok) { printf("FAIL (%s)\n", state.reject_reason); failures++; }
    else printf("OK\n");
    return failures;
}

/* 3a. The MTP window must exclude ancestors beyond the last 11. */
static int check_mtp_window_excludes_ancestors_beyond_last_eleven(uint32_t nbits_pin)
{
    int failures = 0;
    printf("MTP window excludes ancestors beyond the last 11 (13-block chain)... ");
    /* 13 ascending timestamps: the oldest two (10, 20) must be excluded
     * from the median of the newest 11. */
    struct block_index chain[13];
    uint32_t times[] = {10, 20, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100};
    struct block_index *tip = make_pinned_chain(chain, 13, times, nbits_pin);
    int64_t mtp = block_index_get_median_time_past(tip);
    int64_t ref = reference_median(times + 2, 11); /* last 11 only */
    int64_t ref_all13 = reference_median(times, 13);

    if (mtp != ref) {
        printf("FAIL (mtp=%"PRId64" expected(last-11)=%"PRId64")\n", mtp, ref);
        failures++;
    } else if (mtp == ref_all13 && ref != ref_all13) {
        /* defensive: only meaningful if the two references actually
         * differ; guards against a vacuous pass */
        printf("FAIL (window not applied — matched all-13 median instead)\n");
        failures++;
    } else {
        printf("OK (mtp=%"PRId64", last-11-window enforced, all-13 would be %"PRId64")\n",
               mtp, ref_all13);
    }
    return failures;
}

/* 3b. A single stale outlier beyond the window must not move the median. */
static int check_mtp_window_ignores_stale_outlier(uint32_t nbits_pin)
{
    int failures = 0;
    printf("MTP window: single stale outlier beyond the window doesn't move the median... ");
    /* 12-block chain: exactly one ancestor (the oldest, a huge-backdate
     * outlier) is excluded, proving the window cut protects the median;
     * the newest ancestor is a high outlier and stays included without
     * skewing it. */
    struct block_index chain[12];
    uint32_t times[] = {1, /* huge low outlier, oldest, EXCLUDED */
                        100, 200, 300, 400, 500, 600, 700, 800, 900, 1000,
                        5000000 /* huge high outlier, newest, INCLUDED */};
    /* times[0] falls outside the last-11 window. */
    struct block_index *tip = make_pinned_chain(chain, 12, times, nbits_pin);
    int64_t mtp = block_index_get_median_time_past(tip);
    int64_t ref = reference_median(times + 1, 11); /* drop times[0] only */
    if (mtp != ref) {
        printf("FAIL (mtp=%"PRId64" expected=%"PRId64")\n", mtp, ref);
        failures++;
    } else printf("OK\n");
    return failures;
}

/* 3c. An out-of-order sequence within an 11-window must match the
 * independent (qsort-based) reference median exactly. */
static int check_mtp_matches_hand_reference_for_out_of_order_window(uint32_t nbits_pin)
{
    int failures = 0;
    printf("MTP hand-reference: out-of-order sequence within an 11-window matches an independent median... ");
    struct block_index chain[11];
    uint32_t times[] = {950, 50, 850, 150, 750, 250, 650, 350, 550, 450, 1050};
    struct block_index *tip = make_pinned_chain(chain, 11, times, nbits_pin);
    int64_t mtp = block_index_get_median_time_past(tip);
    int64_t ref = reference_median(times, 11);
    if (mtp != ref) {
        printf("FAIL (mtp=%"PRId64" ref=%"PRId64")\n", mtp, ref);
        failures++;
    } else printf("OK\n");
    return failures;
}

/* 4. Equal-timestamp run: the median must land inside the run and the
 * next block's minimum-nTime rule must hold through the real entry point. */
static int check_equal_timestamp_run_median_and_minimum_time(const struct chain_params *params,
                                                             uint32_t nbits_pin)
{
    int failures = 0;
    printf("MTP with a run of identical ancestor timestamps computes correctly, "
           "next block's minimum-nTime rule enforced... ");
    /* 8 ancestors share nTime=T, 3 are distinct and lower. Sorted:
     * {T-30,T-20,T-10, T,T,T,T,T,T,T,T} (11 total) -> index 5 (0-based)
     * lands inside the run of T's -> median == T. */
    const uint32_t T = 500000000u;
    struct block_index chain[11];
    uint32_t times[] = {T - 30, T - 20, T - 10, T, T, T, T, T, T, T, T};
    struct block_index *tip = make_pinned_chain(chain, 11, times, nbits_pin);
    int64_t mtp = block_index_get_median_time_past(tip);
    int64_t ref = reference_median(times, 11);

    bool fail = false;
    if (mtp != (int64_t)T || mtp != ref) fail = true;

    /* Next block's minimum-nTime rule: nTime==T (==MTP) rejected;
     * nTime==T+1 truly accepted, driven through the real function. */
    struct block_header hdr_at;
    make_pinned_header(&hdr_at, T, nbits_pin);
    struct validation_state st_at;
    validation_state_init(&st_at);
    bool ok_at = contextual_check_block_header(&hdr_at, &st_at, params, tip, false);
    if (ok_at || strcmp(st_at.reject_reason, "time-too-old") != 0) fail = true;

    struct block_header hdr_above;
    make_pinned_header(&hdr_above, T + 1, nbits_pin);
    struct validation_state st_above;
    validation_state_init(&st_above);
    bool ok_above = contextual_check_block_header(&hdr_above, &st_above, params, tip, false);
    if (!ok_above) fail = true;

    if (fail) {
        printf("FAIL (mtp=%"PRId64" ref=%"PRId64" ok_at=%d reason_at=%s ok_above=%d reason_above=%s)\n",
               mtp, ref, ok_at, st_at.reject_reason, ok_above, st_above.reject_reason);
        failures++;
    } else printf("OK\n");
    return failures;
}

int test_block_timestamp_adversarial(void)
{
    int failures = 0;
    printf("\n=== Block-timestamp adversarial (MTP + future-time) ===\n");

    const struct chain_params *params = chain_params_get();
    /* pindexLast==NULL short-circuits GetNextWorkRequired to
     * nProofOfWorkLimit; every chain here is shorter than
     * nPowAveragingWindow(17), so pinning headers to it isolates the
     * timestamp gates from the diffbits gate. */
    uint32_t nbits_pin = GetNextWorkRequired(NULL, NULL, &params->consensus);

    /* ── 1. MTP monotonicity: TRUE accept/reject flip end-to-end ──── */
    failures += check_mtp_rejects_time_equal_to_mtp(params, nbits_pin);
    failures += check_mtp_accepts_time_one_above_mtp(params, nbits_pin);
    failures += check_mtp_rejects_time_one_below_mtp(params, nbits_pin);

    /* ── 2. FUTURE-TIME bound: real check_block_header() legacy entry ── */
    failures += check_future_time_accepts_two_hours_ahead(params);
    failures += check_future_time_rejects_beyond_two_hours(params);
    failures += check_future_time_accepts_adjusted_now(params);

    /* ── 3. MTP window correctness: only the last 11 count ────────── */
    failures += check_mtp_window_excludes_ancestors_beyond_last_eleven(nbits_pin);
    failures += check_mtp_window_ignores_stale_outlier(nbits_pin);
    failures += check_mtp_matches_hand_reference_for_out_of_order_window(nbits_pin);

    /* ── 4. Equal-timestamp run ────────────────────────────────────── */
    failures += check_equal_timestamp_run_median_and_minimum_time(params, nbits_pin);

    printf("=== Block-timestamp adversarial: %d failures ===\n\n", failures);
    return failures;
}

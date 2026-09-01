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
 * test_bip113_bip65.c already pins:
 *   - MTP arithmetic (ascending/out-of-order/short-chain/single-block)
 *   - contextual_check_block_header rejects nTime <= MTP
 *   - a *weak* boundary check that nTime==MTP+1 is not rejected
 *     *specifically* for "time-too-old" (it does NOT assert the header
 *     is actually ACCEPTED — with an unmatched nBits the same call can
 *     still return false via "bad-diffbits", and the existing assertion
 *     doesn't rule that out)
 * test_domain_consensus_header_accept.c already pins the pure domain
 *   functions' boundary math (both rules) with directly-injected
 *   MTP/now_upper_bound values, and cross-checks check_block_header()
 *   for version-too-low, but NOT for time-too-new despite the file's own
 *   header comment claiming it does (see the finding logged in the
 *   accompanying report).
 *
 * GAPS this file closes, all driving the REAL production entry points
 * end-to-end (not just the domain layer) with nBits pinned to the
 * genuine GetNextWorkRequired() output so the diffbits gate can never
 * mask a timestamp-gate result:
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
 * assigned to height i (chain[0] is the oldest / genesis-adjacent, the
 * returned pointer is the newest / tip). nBits is pinned on every entry
 * to `nbits_pin` so contextual_check_block_header's diffbits gate can
 * never fire for these synthetic short (<17-ancestor) chains — see the
 * file header comment for why GetNextWorkRequired always degenerates to
 * nProofOfWorkLimit here regardless of nBits/nTime content. */
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

/* Independent reference median: copy + qsort + take the middle element
 * at index (n/2), matching the PRODUCTION index convention exactly (see
 * block_index_get_median_time_past) but via a totally separate sort
 * (qsort, not the production insertion sort) so this is a genuine
 * second implementation, not a call-through. */
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

/* Build a minimal synthetic header that will pass every OTHER
 * contextual_check_block_header gate (version, equihash-size-silent-
 * pass, diffbits) so only the timestamp gate under test can flip the
 * verdict. */
static void make_pinned_header(struct block_header *hdr, uint32_t nTime,
                                uint32_t nbits_pin)
{
    block_header_init(hdr);
    hdr->nVersion = 4;
    hdr->nTime = nTime;
    hdr->nBits = nbits_pin;
    hdr->nSolutionSize = 0; /* silent pass on equihash-solution-size */
}

int test_block_timestamp_adversarial(void)
{
    int failures = 0;
    printf("\n=== Block-timestamp adversarial (MTP + future-time) ===\n");

    const struct chain_params *params = chain_params_get();
    /* pindexLast==NULL is GetNextWorkRequired's own documented short-
     * circuit for "no ancestor at all" -> nProofOfWorkLimit. Every chain
     * built below is far shorter than nPowAveragingWindow(17), so the
     * real contextual call degenerates to this exact same value
     * regardless of the ancestors' nBits/nTime — pinning headers/chains
     * to it isolates the timestamp gates from the diffbits gate. */
    uint32_t nbits_pin = GetNextWorkRequired(NULL, NULL, &params->consensus);

    /* ── 1. MTP monotonicity: TRUE accept/reject flip end-to-end ──── */
    printf("contextual_check_block_header: nTime==MTP is REJECTED (time-too-old, dos=0)... ");
    {
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
    }

    printf("contextual_check_block_header: nTime==MTP+1 is TRULY ACCEPTED (boundary)... ");
    {
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
    }

    printf("contextual_check_block_header: nTime==MTP-1 stays rejected (below boundary too)... ");
    {
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
    }

    /* ── 2. FUTURE-TIME bound: real check_block_header() legacy entry ── */
    printf("check_block_header: nTime==now+2h is TRULY ACCEPTED (boundary, strict >)... ");
    {
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
    }

    printf("check_block_header: nTime==now+2h+1 is REJECTED (time-too-new, dos=0)... ");
    {
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
    }

    printf("check_block_header: nTime==now is well inside the bound (accepted)... ");
    {
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
    }

    /* ── 3. MTP window correctness: only the last 11 count ────────── */
    printf("MTP window excludes ancestors beyond the last 11 (13-block chain)... ");
    {
        /* 13 ascending timestamps: the OLDEST two (10, 20) must be
         * excluded from the median of the newest 11. If the window were
         * (incorrectly) the whole 13-block history the median would
         * shift down; assert it does NOT. */
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
    }

    printf("MTP window: single stale outlier beyond the window doesn't move the median... ");
    {
        /* 12-block chain: window = last 11, so exactly ONE ancestor
         * (the oldest, a huge-backdate outlier) is excluded — proves the
         * window CUT, not just sort order, is what protects the median.
         * The newest ancestor is ALSO a huge (high) outlier and stays
         * INCLUDED, showing a single included outlier doesn't skew the
         * median either (median resists one extreme value). */
        struct block_index chain[12];
        uint32_t times[] = {1, /* huge low outlier, oldest, EXCLUDED */
                            100, 200, 300, 400, 500, 600, 700, 800, 900, 1000,
                            5000000 /* huge high outlier, newest, INCLUDED */};
        /* times[] has 12 entries: the oldest (times[0]) falls outside
         * the last-11 window; the last entry replaces what would have
         * been times[11]=1100 in the sibling test above. */
        struct block_index *tip = make_pinned_chain(chain, 12, times, nbits_pin);
        int64_t mtp = block_index_get_median_time_past(tip);
        int64_t ref = reference_median(times + 1, 11); /* drop times[0] only */
        if (mtp != ref) {
            printf("FAIL (mtp=%"PRId64" expected=%"PRId64")\n", mtp, ref);
            failures++;
        } else printf("OK\n");
    }

    printf("MTP hand-reference: out-of-order sequence within an 11-window matches an independent median... ");
    {
        struct block_index chain[11];
        uint32_t times[] = {950, 50, 850, 150, 750, 250, 650, 350, 550, 450, 1050};
        struct block_index *tip = make_pinned_chain(chain, 11, times, nbits_pin);
        int64_t mtp = block_index_get_median_time_past(tip);
        int64_t ref = reference_median(times, 11);
        if (mtp != ref) {
            printf("FAIL (mtp=%"PRId64" ref=%"PRId64")\n", mtp, ref);
            failures++;
        } else printf("OK\n");
    }

    /* ── 4. Equal-timestamp run ────────────────────────────────────── */
    printf("MTP with a run of identical ancestor timestamps computes correctly, "
           "next block's minimum-nTime rule enforced... ");
    {
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
    }

    printf("=== Block-timestamp adversarial: %d failures ===\n\n", failures);
    return failures;
}

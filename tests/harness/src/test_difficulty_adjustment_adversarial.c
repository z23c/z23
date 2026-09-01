/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * test_difficulty_adjustment_adversarial — adversarial / security coverage of
 * the ZClassic Digishield-style difficulty-adjustment algorithm (DAA) and the
 * nBits<->target compact encoding. A wrong DAA is a consensus fork AND a
 * timestamp-manipulation attack surface, so these tests attack the retarget
 * from the angles a hostile miner would use:
 *
 *   1. RETARGET CLAMPS. A suspiciously-fast run of blocks (timestamps packed
 *      together) must NOT raise difficulty beyond the per-adjustment max-up
 *      clamp; a suspiciously-slow run must NOT drop below the max-down clamp.
 *      We drive the full GetNextWorkRequired() over a synthetic linked
 *      block_index chain and assert the result equals an INDEPENDENT scalar
 *      reference (64-bit div-then-mul, hand-computed clamped timespan) — NOT
 *      by calling CalculateNextWorkRequired(). Each case also computes the
 *      UNCLAMPED value and asserts it differs, proving the clamp is
 *      load-bearing (a boundary flip changes the outcome).
 *
 *   2. powLimit FLOOR. Difficulty can never ease below powLimit: a computation
 *      that would exceed powLimit is clamped to powLimit, and an attacker-
 *      supplied too-easy nBits handed to IncreaseDifficultyBy() is clamped to
 *      powLimit. The companion "fast" case (result below powLimit) is left
 *      un-clamped, proving the floor bites only when exceeded.
 *
 *   3. nBits COMPACT ENCODING. SetCompact/GetCompact round-trips on canonical
 *      targets; a non-canonical nBits normalizes to a hand-computed canonical
 *      form; a negative-flagged nBits and an overflow nBits (both manipulated-
 *      difficulty inputs) are rejected by the public CheckProofOfWork().
 *
 *   4. TIMESTAMP-MANIPULATION RESISTANCE. The retarget consumes median-time-past
 *      of the window endpoints, not raw tip time, so a single manipulated tip
 *      timestamp (future or past) cannot move the target to an attacker-chosen
 *      value. We assert GetNextWorkRequired is byte-identical before/after the
 *      tip timestamp is shoved to +/- extremes.
 *
 *   5. MIN-DIFFICULTY RULE NOT ON MAINNET. The testnet min-difficulty escape
 *      (nPowAllowMinDifficultyEnabled) is OFF on mainnet params, and functionally
 *      a wildly-late block at a normal mainnet height (outside every upgrade
 *      window) does NOT return powLimit — it takes the averaging path.
 *
 * Pure + deterministic: synthetic block_index chains, fixed times, no clock /
 * RNG / IO. Selects mainnet params and restores the prior network on exit.
 *
 * This EXTENDS (does not duplicate) test_domain_consensus_pow (regression seal
 * vs the wrappers), test_domain_consensus_pow_seal (CheckProofOfWork boundary
 * matrix), and test_pow_diffadj_precedence (the testnet fork-window precedence
 * pin). Here the reference is computed independently in scalar space so a drift
 * in the clamp direction, the /4 damping, or the div-then-mul order diverges.
 */

#include "test/test_core.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"  /* enum chain_network */
#include "chain/pow.h"
#include "consensus/params.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "primitives/block.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DAA_CHECK(name, expr) do {                              \
    printf("difficulty_adjustment_adversarial: %s... ", (name)); \
    if ((expr)) printf("OK\n");                                  \
    else { printf("FAIL\n"); failures++; }                       \
} while (0)

/* Long enough that BOTH the tip and the window-start (pindexLast walked back
 * nPowAveragingWindow==17 hops) have a full 11-deep median-time-past window:
 * pindexFirst sits at index LEN-18, which must be >= 10 -> LEN >= 28. Extra
 * margin keeps the arithmetic identities below exact. */
#define DAA_CHAIN_LEN 40

/* Small target so the retarget math (target/avgTimespan*actualTimespan) fits
 * in 64 bits and can be reproduced with a scalar reference. 0x0700ffff decodes
 * to 0xffff << 32 (~2^48), FAR tighter than any network powLimit (~2^243), so
 * the powLimit clamp never fires in the clamp-boundary cases — isolating the
 * timespan clamp under test. (Verified canonical: get_compact(0xffff<<32) ==
 * 0x0700ffff.) */
#define DAA_SMALL_NBITS 0x0700ffffu

static enum chain_network daa_current_net(void)
{
    const char *id = chain_params_get()->strNetworkID;
    if (strcmp(id, "test") == 0)    return CHAIN_TESTNET;
    if (strcmp(id, "regtest") == 0) return CHAIN_REGTEST;
    return CHAIN_MAIN;
}

/* Build DAA_CHAIN_LEN linked block_index nodes ending at height `tip_height`,
 * uniformly spaced `spacing` seconds apart, all with nBits == DAA_SMALL_NBITS.
 * chain[LEN-1] is the tip (pindexLast). With uniform spacing the endpoints'
 * median-time-past differ by exactly nPowAveragingWindow*spacing (see the
 * derivation in the clamp cases). */
static void daa_build_chain(struct block_index chain[DAA_CHAIN_LEN],
                            int tip_height, int64_t spacing, int64_t base_time)
{
    for (int i = 0; i < DAA_CHAIN_LEN; i++) {
        block_index_init(&chain[i]);
        int back = (DAA_CHAIN_LEN - 1) - i;   /* 0 at the tip */
        chain[i].nHeight = tip_height - back;
        chain[i].nBits = DAA_SMALL_NBITS;
        chain[i].nTime = (uint32_t)(base_time + (int64_t)i * spacing);
        chain[i].pprev = (i == 0) ? NULL : &chain[i - 1];
    }
}

/* Independent scalar reference: reproduce the retarget for a 64-bit-fits target.
 * Mirrors the algorithm's arithmetic (damp toward avg by /4, clamp the actual
 * timespan to [min,max], then bnNew = target/avgTs*actTs) WITHOUT calling the
 * production DAA. `raw_timespan` is last-first BEFORE damping. If `clamp` is
 * false the timespan is used un-clamped (for the boundary-flip contrast). The
 * resulting integer is encoded with arith_uint256_get_compact (a primitive, not
 * the DAA). Returns the expected compact nBits and, via out_actts, the actual
 * timespan actually used. */
static uint32_t daa_ref_retarget(uint64_t target, int64_t raw_timespan,
                                 int64_t avgTs, int64_t minTs, int64_t maxTs,
                                 bool clamp, int64_t *out_actts)
{
    int64_t act = avgTs + (raw_timespan - avgTs) / 4;   /* same /4 damping */
    if (clamp) {
        if (act < minTs) act = minTs;
        if (act > maxTs) act = maxTs;
    }
    if (out_actts) *out_actts = act;
    uint64_t bnNew = (target / (uint64_t)avgTs) * (uint64_t)act;  /* div THEN mul */
    struct arith_uint256 a;
    arith_uint256_set_u64(&a, bnNew);
    return arith_uint256_get_compact(&a, false);
}

int test_difficulty_adjustment_adversarial(void);
int test_difficulty_adjustment_adversarial(void)
{
    printf("\n=== difficulty-adjustment adversarial (clamps / floor / "
           "timestamp / encoding) ===\n");
    int failures = 0;

    enum chain_network saved_net = daa_current_net();
    chain_params_select(CHAIN_MAIN);
    const struct chain_params *cp = chain_params_get();
    const struct consensus_params *params = &cp->consensus;

    /* Pin the premise so a chainparams edit that changes these fails HERE. */
    DAA_CHECK("mainnet: nPowAveragingWindow==17",
              params->nPowAveragingWindow == 17);
    DAA_CHECK("mainnet: nPowMaxAdjustUp==16",  params->nPowMaxAdjustUp == 16);
    DAA_CHECK("mainnet: nPowMaxAdjustDown==32", params->nPowMaxAdjustDown == 32);

    struct arith_uint256 pow_limit_arith;
    uint256_to_arith(&pow_limit_arith, &params->powLimit);
    const uint32_t powlimit_bits = arith_uint256_get_compact(&pow_limit_arith, false);

    /* Decode DAA_SMALL_NBITS to its 64-bit target for the scalar reference. */
    struct arith_uint256 small_target_a;
    arith_uint256_set_compact(&small_target_a, DAA_SMALL_NBITS, NULL, NULL);
    const uint64_t small_target = arith_uint256_get_low64(&small_target_a);
    DAA_CHECK("small nBits is canonical (round-trips)",
              arith_uint256_get_compact(&small_target_a, false) == DAA_SMALL_NBITS);
    DAA_CHECK("small target far below powLimit (isolates timespan clamp)",
              arith_uint256_compare(&small_target_a, &pow_limit_arith) < 0);

    /* Height 100000: pre-Buttercup (150s spacing) -> avgTs=2550, min=2142,
     * max=3366. Outside every upgrade window and min-diff disabled, so
     * GetNextWorkRequired takes the pure averaging path. */
    const int tip_height = 100000;
    const int next_height = tip_height + 1;
    const int64_t spacing = consensus_pow_target_spacing(params, next_height);
    const int64_t avgTs = consensus_averaging_window_timespan(params, next_height);
    const int64_t minTs = consensus_min_actual_timespan(params, next_height);
    const int64_t maxTs = consensus_max_actual_timespan(params, next_height);
    DAA_CHECK("mainnet@100001: spacing==150", spacing == 150);
    DAA_CHECK("mainnet@100001: avgTs==2550", avgTs == 2550);
    DAA_CHECK("mainnet@100001: minTs==2142 (avg*84/100)", minTs == 2142);
    DAA_CHECK("mainnet@100001: maxTs==3366 (avg*132/100)", maxTs == 3366);

    /* ─── 1a. FAST run: max-UP clamp. Blocks 1s apart -> raw window timespan
     * 17*1=17s. Damped 2550+(17-2550)/4 = 1917 < minTs -> clamped to 2142.
     * Difficulty must NOT rise past the max-up clamp. ─────────────────────── */
    {
        struct block_index chain[DAA_CHAIN_LEN];
        daa_build_chain(chain, tip_height, /*spacing=*/1, 1500000000LL);
        struct block_index *pindexLast = &chain[DAA_CHAIN_LEN - 1];

        /* pblock time irrelevant here (no fork-window / min-diff branch at this
         * height); give it a benign value. */
        struct block_header hdr;
        block_header_init(&hdr);
        hdr.nBits = DAA_SMALL_NBITS;
        hdr.nTime = (uint32_t)(block_index_get_time(pindexLast) + spacing);

        unsigned int got = GetNextWorkRequired(pindexLast, &hdr, params);

        int64_t raw = 17 * 1;              /* MTP(last)-MTP(first) under uniform spacing */
        int64_t used = 0;
        uint32_t ref_clamped   = daa_ref_retarget(small_target, raw, avgTs, minTs, maxTs, true,  &used);
        uint32_t ref_unclamped = daa_ref_retarget(small_target, raw, avgTs, minTs, maxTs, false, NULL);

        DAA_CHECK("FAST: damped timespan clamps UP to minTs (2142)", used == minTs);
        DAA_CHECK("FAST: GetNextWorkRequired == clamped scalar reference",
                  got == ref_clamped);
        DAA_CHECK("FAST: clamp is load-bearing (clamped != unclamped)",
                  ref_clamped != ref_unclamped);
    }

    /* ─── 1b. SLOW run: max-DOWN clamp. Blocks 400s apart -> raw 17*400=6800s.
     * Damped 2550+(6800-2550)/4 = 3612 > maxTs -> clamped to 3366. Difficulty
     * must NOT drop below the max-down clamp. ─────────────────────────────── */
    {
        struct block_index chain[DAA_CHAIN_LEN];
        daa_build_chain(chain, tip_height, /*spacing=*/400, 1500000000LL);
        struct block_index *pindexLast = &chain[DAA_CHAIN_LEN - 1];

        struct block_header hdr;
        block_header_init(&hdr);
        hdr.nBits = DAA_SMALL_NBITS;
        hdr.nTime = (uint32_t)(block_index_get_time(pindexLast) + spacing);

        unsigned int got = GetNextWorkRequired(pindexLast, &hdr, params);

        int64_t raw = 17 * 400;
        int64_t used = 0;
        uint32_t ref_clamped   = daa_ref_retarget(small_target, raw, avgTs, minTs, maxTs, true,  &used);
        uint32_t ref_unclamped = daa_ref_retarget(small_target, raw, avgTs, minTs, maxTs, false, NULL);

        DAA_CHECK("SLOW: damped timespan clamps DOWN to maxTs (3366)", used == maxTs);
        DAA_CHECK("SLOW: GetNextWorkRequired == clamped scalar reference",
                  got == ref_clamped);
        DAA_CHECK("SLOW: clamp is load-bearing (clamped != unclamped)",
                  ref_clamped != ref_unclamped);
    }

    /* ─── 2. powLimit FLOOR. bnAvg == powLimit. A slow window (clamps to maxTs)
     * would push bnNew = powLimit*maxTs/avgTs > powLimit -> must clamp to
     * powLimit. A fast window (clamps to minTs) yields powLimit*minTs/avgTs <
     * powLimit -> left un-clamped (harder), proving the floor bites only when
     * exceeded. Reference = get_compact(powLimit), computed independently. ─── */
    {
        int64_t slow_last = 1000000 + 100 * avgTs;   /* wildly slow -> clamps to maxTs */
        uint32_t got_slow = CalculateNextWorkRequired(
            pow_limit_arith, slow_last, 1000000, params, next_height);
        DAA_CHECK("FLOOR: over-limit retarget clamps to powLimit",
                  got_slow == powlimit_bits);

        int64_t fast_last = 1000000 + 1;             /* wildly fast -> clamps to minTs */
        uint32_t got_fast = CalculateNextWorkRequired(
            pow_limit_arith, fast_last, 1000000, params, next_height);
        DAA_CHECK("FLOOR: under-limit retarget NOT clamped (harder than powLimit)",
                  got_fast != powlimit_bits);

        /* IncreaseDifficultyBy: an attacker-supplied too-EASY nBits (target far
         * above powLimit) divided by 1 stays above powLimit -> clamped to the
         * floor. 0x2000ffff decodes to ~2^248 > powLimit(~2^243). */
        struct arith_uint256 easy_a;
        arith_uint256_set_compact(&easy_a, 0x2000ffffu, NULL, NULL);
        DAA_CHECK("FLOOR: crafted easy nBits really exceeds powLimit",
                  arith_uint256_compare(&easy_a, &pow_limit_arith) > 0);
        unsigned int clamped = IncreaseDifficultyBy(0x2000ffffu, 1, params);
        DAA_CHECK("FLOOR: IncreaseDifficultyBy clamps too-easy nBits to powLimit",
                  clamped == powlimit_bits);
    }

    /* ─── 3. nBits COMPACT ENCODING. ─────────────────────────────────────── */
    {
        /* 3a. Canonical round-trips. */
        uint32_t canon[] = {
            0x1d00ffffu, 0x1b0404cbu, 0x1e00ffffu, 0x0700ffffu, 0x03123456u,
        };
        bool rt_ok = true;
        for (size_t i = 0; i < sizeof(canon)/sizeof(canon[0]); i++) {
            struct arith_uint256 t;
            arith_uint256_set_compact(&t, canon[i], NULL, NULL);
            if (arith_uint256_get_compact(&t, false) != canon[i]) {
                printf("\n  round-trip MISMATCH 0x%08x -> 0x%08x\n",
                       canon[i], arith_uint256_get_compact(&t, false));
                rt_ok = false;
            }
        }
        DAA_CHECK("ENC: canonical nBits round-trip through set/get compact", rt_ok);

        /* 3b. Non-canonical normalizes. 0x05001234 decodes to 0x1234<<16 ==
         * 0x12340000, which re-encodes canonically as 0x04123400. */
        {
            struct arith_uint256 t;
            bool neg = true, ovf = true;
            arith_uint256_set_compact(&t, 0x05001234u, &neg, &ovf);
            uint32_t re = arith_uint256_get_compact(&t, false);
            DAA_CHECK("ENC: non-canonical 0x05001234 normalizes to 0x04123400",
                      re == 0x04123400u && re != 0x05001234u && !neg && !ovf);
        }

        /* 3c. Negative-flagged nBits: sign bit set with non-zero word and a
         * non-zero decoded target. set_compact flags it; CheckProofOfWork
         * rejects it regardless of the hash (a manipulated-difficulty input). */
        {
            struct arith_uint256 t;
            bool neg = false, ovf = false;
            arith_uint256_set_compact(&t, 0x05800001u, &neg, &ovf);
            DAA_CHECK("ENC: 0x05800001 flagged negative (non-zero target)",
                      neg && !ovf && !arith_uint256_is_zero(&t));
            struct uint256 h;
            memset(&h, 0, sizeof(h));   /* hash 0: as easy as possible */
            DAA_CHECK("ENC: negative nBits rejected by CheckProofOfWork",
                      CheckProofOfWork(h, 0x05800001u, params) == false);
        }

        /* 3d. Overflow nBits: size 0x23==35 (>34) with non-zero word overflows;
         * rejected by CheckProofOfWork. */
        {
            struct arith_uint256 t;
            bool neg = false, ovf = false;
            arith_uint256_set_compact(&t, 0x23000001u, &neg, &ovf);
            DAA_CHECK("ENC: 0x23000001 flagged overflow", ovf);
            struct uint256 h;
            memset(&h, 0, sizeof(h));
            DAA_CHECK("ENC: overflow nBits rejected by CheckProofOfWork",
                      CheckProofOfWork(h, 0x23000001u, params) == false);
        }
    }

    /* ─── 4. TIMESTAMP-MANIPULATION RESISTANCE. GetNextWorkRequired consumes
     * median-time-past of the window endpoints, so a single manipulated tip
     * timestamp — shoved far into the future OR into the past — cannot move the
     * retarget to an attacker-chosen value. Result must be byte-identical to the
     * honest baseline. ───────────────────────────────────────────────────── */
    {
        struct block_index chain[DAA_CHAIN_LEN];
        daa_build_chain(chain, tip_height, /*spacing=*/spacing, 1500000000LL);
        struct block_index *pindexLast = &chain[DAA_CHAIN_LEN - 1];

        struct block_header hdr;
        block_header_init(&hdr);
        hdr.nBits = DAA_SMALL_NBITS;
        hdr.nTime = (uint32_t)(block_index_get_time(pindexLast) + spacing);

        unsigned int baseline = GetNextWorkRequired(pindexLast, &hdr, params);

        /* Attacker inflates the tip block's own timestamp to the far future.
         * In the 11-value median window the outlier only becomes the max, so the
         * median (6th value) is unchanged -> MTP(last) unchanged -> no effect. */
        uint32_t honest_tip = chain[DAA_CHAIN_LEN - 1].nTime;
        chain[DAA_CHAIN_LEN - 1].nTime = 0xfffffff0u;   /* year ~2106, extreme */
        unsigned int got_future = GetNextWorkRequired(pindexLast, &hdr, params);
        DAA_CHECK("TS: far-future tip timestamp does not change the retarget",
                  got_future == baseline);

        /* Attacker back-dates the tip below its neighbours (out-of-order). The
         * median still ignores a single low outlier. */
        chain[DAA_CHAIN_LEN - 1].nTime = honest_tip - 5;
        unsigned int got_past = GetNextWorkRequired(pindexLast, &hdr, params);
        DAA_CHECK("TS: back-dated tip timestamp does not change the retarget",
                  got_past == baseline);

        chain[DAA_CHAIN_LEN - 1].nTime = honest_tip;    /* restore */

        /* And the baseline itself is the honest averaging result, not powLimit. */
        DAA_CHECK("TS: baseline retarget is a real target, not powLimit",
                  baseline != powlimit_bits);
    }

    /* ─── 5. MIN-DIFFICULTY RULE IS NOT ACTIVE ON MAINNET. The testnet escape
     * hatch is disabled on mainnet, and functionally a wildly-late block at a
     * normal mainnet height (outside every upgrade window) takes the averaging
     * path — it does NOT return powLimit. ─────────────────────────────────── */
    {
        DAA_CHECK("MINDIFF: mainnet nPowAllowMinDifficultyEnabled == false",
                  params->nPowAllowMinDifficultyEnabled == false);
        DAA_CHECK("MINDIFF: mainnet nPowAllowMinDifficultyBlocksAfterHeight == -1",
                  params->nPowAllowMinDifficultyBlocksAfterHeight == -1);

        /* Height 1,000,000: past DIFFADJ [585322,585339) and BUTTERCUP
         * [707000,707017) windows, so scaleDifficultyAtUpgradeFork guards fail
         * and the fork-window min-diff ramp is skipped. */
        const int md_tip = 1000000;
        const int md_next = md_tip + 1;
        const int64_t md_spacing = consensus_pow_target_spacing(params, md_next);

        struct block_index chain[DAA_CHAIN_LEN];
        daa_build_chain(chain, md_tip, md_spacing, 1500000000LL);
        struct block_index *pindexLast = &chain[DAA_CHAIN_LEN - 1];

        /* A block absurdly late (> spacing*12 after the tip): on testnet this
         * would trip the min-diff escape to powLimit; on mainnet it must NOT. */
        struct block_header late;
        block_header_init(&late);
        late.nBits = DAA_SMALL_NBITS;
        late.nTime = (uint32_t)(block_index_get_time(pindexLast) + md_spacing * 100);

        unsigned int got = GetNextWorkRequired(pindexLast, &late, params);
        DAA_CHECK("MINDIFF: wildly-late mainnet block does NOT ease to powLimit",
                  got != powlimit_bits);

        /* It equals the averaging result (uniform-nBits window, actual==avgTs
         * -> no timespan clamp). Independent scalar reference. */
        int64_t md_avgTs = consensus_averaging_window_timespan(params, md_next);
        int64_t md_minTs = consensus_min_actual_timespan(params, md_next);
        int64_t md_maxTs = consensus_max_actual_timespan(params, md_next);
        uint32_t ref = daa_ref_retarget(small_target, 17 * md_spacing,
                                        md_avgTs, md_minTs, md_maxTs, true, NULL);
        DAA_CHECK("MINDIFF: mainnet late block returns the averaging result",
                  got == ref);
    }

    /* Contrast (read-only): the escape hatch IS enabled on testnet params, so
     * the mainnet-off assertion above is meaningful, not vacuous. */
    {
        chain_params_select(CHAIN_TESTNET);
        const struct consensus_params *tp = &chain_params_get()->consensus;
        DAA_CHECK("MINDIFF: testnet nPowAllowMinDifficultyEnabled == true (contrast)",
                  tp->nPowAllowMinDifficultyEnabled == true);
        chain_params_select(CHAIN_MAIN);
    }

    chain_params_select(saved_net);
    printf("=== difficulty-adjustment adversarial: %d failures ===\n", failures);
    return failures;
}

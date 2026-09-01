/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_pow_diffadj_precedence — D1 lock-in pin for the difficulty-retarget
 * operator-precedence DIFFERENCE between zcl23 and zclassicd. See
 * docs/CONSENSUS_PARITY_DOCTRINE.md.
 *
 * THE GAP. The BUTTERCUP/DIFFADJ "fork-window min-difficulty" guard in
 * GetNextWorkRequired (core/modules/chain/src/pow.c:52-56) is gated by:
 *
 *     scaleDifficultyAtUpgradeFork && ( (DIFFADJ window) || (BUTTERCUP window) )
 *
 * zclassicd's expression is  (scale && DIFFADJ) || BUTTERCUP  (`&&` binds
 * tighter than `||`), so on zclassicd the BUTTERCUP branch fires REGARDLESS
 * of `scale`. zcl23's extra paren ANDs `scale` across BOTH window tests, so
 * when scale==false the whole min-diff branch is suppressed.
 *
 *   - On MAINNET this is byte-identical: scale==true collapses both forms to
 *     `B||C`, so the BUTTERCUP min-diff branch fires the same way. (companion
 *     case below.)
 *   - On TESTNET/REGTEST scale==false, so zcl23 does NOT take the BUTTERCUP
 *     min-diff branch in the BUTTERCUP window — it falls through to the
 *     averaging retarget. zclassicd WOULD take it. (primary case below.)
 *
 * This is a PIN of CURRENT behavior, not a fix. A future parity-restore (drop
 * the extra paren) flips the testnet case from "averaging result" to
 * "nProofOfWorkLimit" and this test fails loudly, forcing a deliberate
 * decision (replay-gated against testnet/regtest history — see the doc).
 *
 * Synthetic, pure: builds a linked block_index chain (>= nPowAveragingWindow
 * entries) so the averaging path has data, and one late block_header whose
 * time exceeds prev by spacing*12 (the min-diff trigger). Selects the target
 * network's params, runs GetNextWorkRequired, restores the prior network.
 */

#include "test/test_core.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"  /* enum chain_network */
#include "chain/pow.h"
#include "consensus/params.h"
#include "core/arith_uint256.h"
#include "primitives/block.h"

#include <stdio.h>
#include <string.h>

#define PDP_CHECK(name, expr) do {                      \
    printf("pow_diffadj_precedence: %s... ", (name));   \
    if ((expr)) printf("OK\n");                         \
    else { printf("FAIL\n"); failures++; }              \
} while (0)

/* Number of linked block_index nodes to build. The averaging loop in
 * GetNextWorkRequired walks pprev nPowAveragingWindow (17) times starting at
 * pindexLast; pindexFirst must still be non-NULL after the walk or the
 * function bails out to powLimit. 17 hops need 18 nodes; build a few extra so
 * the median-time-past walk (11 deep) also has data at every node. */
#define PDP_CHAIN_LEN 24

/* nBits for every block in the synthetic chain: clearly TIGHTER (harder) than
 * any network powLimit, so the averaging retarget result is unmistakably NOT
 * nProofOfWorkLimit. 0x1c0fffff is a typical mid-history ZClassic target. */
#define PDP_CHAIN_NBITS 0x1c0fffffu

static const char *pdp_net_id(enum chain_network net)
{
    switch (net) {
    case CHAIN_TESTNET: return "test";
    case CHAIN_REGTEST: return "regtest";
    default:            return "main";
    }
}

static enum chain_network pdp_current_net(void)
{
    const char *id = chain_params_get()->strNetworkID;
    if (strcmp(id, "test") == 0)    return CHAIN_TESTNET;
    if (strcmp(id, "regtest") == 0) return CHAIN_REGTEST;
    return CHAIN_MAIN;
}

/* Build a chain of PDP_CHAIN_LEN block_index nodes ending at height
 * `tip_height`, each spaced `spacing` seconds apart, all with nBits =
 * PDP_CHAIN_NBITS. chain[PDP_CHAIN_LEN-1] is pindexLast (the tip). Times are
 * monotonically increasing so median-time-past is well-defined. */
static void pdp_build_chain(struct block_index chain[PDP_CHAIN_LEN],
                            int tip_height, int64_t spacing, int64_t base_time)
{
    for (int i = 0; i < PDP_CHAIN_LEN; i++) {
        block_index_init(&chain[i]);
        int back = (PDP_CHAIN_LEN - 1) - i;   /* 0 at the tip */
        chain[i].nHeight = tip_height - back;
        chain[i].nBits = PDP_CHAIN_NBITS;
        chain[i].nTime = (uint32_t)(base_time + (int64_t)i * spacing);
        chain[i].pprev = (i == 0) ? NULL : &chain[i - 1];
    }
}

int test_pow_diffadj_precedence(void);
int test_pow_diffadj_precedence(void)
{
    printf("\n=== D1 pow difficulty-precedence parity (lock-in) ===\n");
    int failures = 0;

    enum chain_network saved_net = pdp_current_net();

    /* ───────────────────────────────────────────────────────────────────
     * PRIMARY (TESTNET, scale=false): at a BUTTERCUP-window height, a late
     * block (time > prev + spacing*12) must NOT take the min-diff branch —
     * zcl23 falls through to the AVERAGING retarget. Pin: GetNextWorkRequired
     * returns the averaging result, NOT nProofOfWorkLimit.
     * ─────────────────────────────────────────────────────────────────── */
    {
        chain_params_select(CHAIN_TESTNET);
        const struct chain_params *cp = chain_params_get();
        const struct consensus_params *params = &cp->consensus;

        /* Sanity-pin the params this case relies on (so a chainparams edit
         * that changes the premise fails here, not silently). */
        PDP_CHECK("testnet: scale==false",
                  params->scaleDifficultyAtUpgradeFork == false);
        PDP_CHECK("testnet: nPowAveragingWindow==17",
                  params->nPowAveragingWindow == 17);
        const int buttercup_act =
            params->vUpgrades[UPGRADE_BUTTERCUP].nActivationHeight;
        PDP_CHECK("testnet: BUTTERCUP activates at 78856",
                  buttercup_act == 78856);

        /* pindexLast at height (buttercup_act - 1) ⇒ nHeight = buttercup_act,
         * the FIRST height of the BUTTERCUP averaging window
         * [buttercup_act, buttercup_act + window). Also confirm the second,
         * unconditional min-diff branch (nPowAllowMinDifficultyEnabled) does
         * NOT fire here: it needs pindexLast->nHeight >= 299187, and our tip
         * height (78855) is far below that. */
        const int tip_height = buttercup_act - 1;     /* 78855 */
        const int next_height = tip_height + 1;        /* 78856 */
        PDP_CHECK("testnet: tip below min-diff-after height (second branch "
                  "stays off)",
                  tip_height < params->nPowAllowMinDifficultyBlocksAfterHeight);
        const int64_t spacing = consensus_pow_target_spacing(params, next_height);

        struct block_index chain[PDP_CHAIN_LEN];
        pdp_build_chain(chain, tip_height, spacing, 1500000000LL);
        struct block_index *pindexLast = &chain[PDP_CHAIN_LEN - 1];

        struct arith_uint256 pow_limit;
        uint256_to_arith(&pow_limit, &params->powLimit);
        const unsigned int powlimit_bits =
            arith_uint256_get_compact(&pow_limit, false);

        /* A late block: time exceeds prev by MORE than spacing*12 — the exact
         * input that triggers the min-diff return in the BUTTERCUP branch. */
        struct block_header late;
        block_header_init(&late);
        late.nTime = (uint32_t)(block_index_get_time(pindexLast) + spacing * 12 + 1);
        late.nBits = PDP_CHAIN_NBITS;

        unsigned int got = GetNextWorkRequired(pindexLast, &late, params);

        /* Independently compute what the AVERAGING path yields (the branch we
         * claim zcl23 takes): every block has identical nBits, so bnAvg ==
         * that target, fed into CalculateNextWorkRequired with the chain's
         * median times. This is the EXACT value GetNextWorkRequired must
         * return when the min-diff branch is (correctly, today) skipped. */
        struct arith_uint256 bnAvg;
        arith_uint256_set_compact(&bnAvg, PDP_CHAIN_NBITS, NULL, NULL);
        const struct block_index *pindexFirst = pindexLast;
        for (int i = 0; i < params->nPowAveragingWindow && pindexFirst; i++)
            pindexFirst = pindexFirst->pprev;
        unsigned int avg_expected = powlimit_bits;
        bool have_first = (pindexFirst != NULL);
        if (have_first) {
            avg_expected = CalculateNextWorkRequired(
                bnAvg,
                block_index_get_median_time_past(pindexLast),
                block_index_get_median_time_past(pindexFirst),
                params, next_height);
        }

        PDP_CHECK("testnet: averaging window has enough linked blocks",
                  have_first);
        PDP_CHECK("testnet late block does NOT take min-diff branch "
                  "(got != powLimit)",
                  got != powlimit_bits);
        PDP_CHECK("testnet late block returns the AVERAGING result",
                  got == avg_expected);
        /* Belt-and-suspenders: the averaging result itself is the tighter
         * chain target region, not the loose powLimit. */
        PDP_CHECK("testnet averaging result is tighter than powLimit",
                  avg_expected != powlimit_bits);
    }

    /* ───────────────────────────────────────────────────────────────────
     * COMPANION (MAINNET, scale=true): the SAME shape at a mainnet
     * BUTTERCUP-window height DOES take the min-diff branch — mainnet is
     * unaffected by the precedence bug. Pin: GetNextWorkRequired returns
     * nProofOfWorkLimit.
     * ─────────────────────────────────────────────────────────────────── */
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *cp = chain_params_get();
        const struct consensus_params *params = &cp->consensus;

        PDP_CHECK("mainnet: scale==true",
                  params->scaleDifficultyAtUpgradeFork == true);
        const int buttercup_act =
            params->vUpgrades[UPGRADE_BUTTERCUP].nActivationHeight;
        PDP_CHECK("mainnet: BUTTERCUP activates at 707000",
                  buttercup_act == 707000);
        PDP_CHECK("mainnet: min-difficulty NOT enabled",
                  params->nPowAllowMinDifficultyEnabled == false);

        const int tip_height = buttercup_act - 1;     /* 706999 */
        const int next_height = tip_height + 1;        /* 707000 */
        const int64_t spacing = consensus_pow_target_spacing(params, next_height);

        struct block_index chain[PDP_CHAIN_LEN];
        pdp_build_chain(chain, tip_height, spacing, 1500000000LL);
        struct block_index *pindexLast = &chain[PDP_CHAIN_LEN - 1];

        struct arith_uint256 pow_limit;
        uint256_to_arith(&pow_limit, &params->powLimit);
        const unsigned int powlimit_bits =
            arith_uint256_get_compact(&pow_limit, false);

        struct block_header late;
        block_header_init(&late);
        late.nTime = (uint32_t)(block_index_get_time(pindexLast) + spacing * 12 + 1);
        late.nBits = PDP_CHAIN_NBITS;

        unsigned int got = GetNextWorkRequired(pindexLast, &late, params);

        PDP_CHECK("mainnet late block DOES take min-diff branch "
                  "(got == powLimit)",
                  got == powlimit_bits);
    }

    chain_params_select(saved_net);
    printf("=== D1 pow difficulty-precedence parity: %d failures "
           "(restored net=%s) ===\n", failures, pdp_net_id(saved_net));
    return failures;
}

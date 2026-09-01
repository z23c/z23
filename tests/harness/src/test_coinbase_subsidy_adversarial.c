/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Adversarial coverage of the block-subsidy / coinbase-value / halving
 * consensus rules, closing gaps NOT exercised by existing suites:
 *
 *   - tests/harness/src/test_amount_subsidy_edge.c pins the Buttercup activation
 *     seam (h=707000), one post-Buttercup halving boundary (h=2387001), the
 *     zero-subsidy tail and genesis/slow-start edges — all pure arithmetic
 *     on domain_consensus_block_subsidy(), all against MAINNET params.
 *   - tests/harness/src/test_utxo_apply_value_balance.c ((i)/(j)/(k)) and
 *     tests/harness/src/test_simnet_byzantine.c (SIMNET_BYZ_BAD_CB_AMOUNT) drive
 *     connect_block's "bad-cb-amount" check for coinbase == subsidy+fees
 *     (accept), subsidy+fees+1 (reject) and bare subsidy+1 (reject) — but
 *     always at a small, fixed simnet height (~100-101) that never crosses
 *     a halving boundary, and always via SIM_COINBASE_VALUE (1,000,000),
 *     never the real schedule value.
 *   - tests/harness/src/test_domain_consensus_check_block.c already covers the
 *     structural "first tx must be coinbase" (bad-cb-missing) and "no other
 *     tx may be a coinbase" (bad-cb-multiple) rules, including cross-check
 *     against the legacy C++ reference. Not duplicated here.
 *
 * What is genuinely UNCOVERED, and what this file adds:
 *
 *   1. HALVING BOUNDARY, exact satoshi values, via a REAL reachable chain
 *      configuration. Mainnet's own nPreButtercupSubsidyHalvingInterval
 *      (840,000 blocks) never actually produces a halving in practice:
 *      UPGRADE_BUTTERCUP activates at mainnet height 707,000, strictly
 *      before the first pre-Buttercup halving would land (840,001), so
 *      consensus_halving() always takes the Buttercup branch by the time
 *      the interval could fire on mainnet. REGTEST is configured with
 *      UPGRADE_BUTTERCUP permanently DISABLED
 *      (NETWORK_UPGRADE_NO_ACTIVATION, core/modules/chain/src/chainparams.c) and a
 *      150-block interval (PRE_BUTTERCUP_REGTEST_HALVING_INTERVAL), so it
 *      is the one real, live chain_params configuration in which the
 *      pre-Buttercup halving interval actually produces a halving. Part A
 *      pins the exact reward just below / at / above that boundary.
 *
 *   2. connect_block's "bad-cb-amount" check binds the REWARD TO THE
 *      BLOCK'S OWN HEIGHT, not to a stale/previous height's (higher)
 *      pre-halving reward. Part B drives simnet's real connect_block()
 *      across the same regtest halving boundary and proves:
 *        - the exact post-halving reward is ACCEPTED at the boundary
 *          height (not the old, larger pre-halving reward — a stale-value
 *          replay would silently look "smaller than the old reward" but is
 *          still an over-claim against the NEW reward and must reject),
 *        - one satoshi over either side's reward is REJECTED with
 *          "bad-cb-amount",
 *        - the exact pre-halving reward, if resubmitted UNCHANGED one
 *          block later (at the post-halving height), is REJECTED — this
 *          is the concrete "attacker replays the stale reward across a
 *          halving" attack a height-independent constant would let through.
 *
 *   3. FOUNDERS/DEV-FEE SPLIT: mainnet chainparams populate
 *      vFoundersRewardAddress[]/nFoundersRewardAddresses (48 addresses) and
 *      consensus_last_founders_reward_height() exists, but grep over
 *      core/modules/validation, domain/consensus and app/jobs finds NO coinbase-
 *      output check that consults them — ZClassic (unlike Zcash) ships
 *      with ZERO enforced founders reward. Part C asserts this rather than
 *      "fixing" it: a coinbase paying the ENTIRE mainnet subsidy to one
 *      plain output, at a height inside the founders-reward window
 *      (h=100 <= consensus_last_founders_reward_height(mainnet)=840000),
 *      is ACCEPTED. If a partial founders-reward implementation ever lands
 *      and starts rejecting 100%-to-miner blocks in this window, this test
 *      fails loudly and the change must be reviewed as a consensus change.
 *
 * Determinism: Part A is pure arithmetic (no simnet). Parts B/C drive
 * simnet's real connect_block() at heights covered by its synthetic
 * checkpoint (expensive_checks=false) — PoW and scriptSig content are
 * never verified, only coinbase structure and the value/height binding.
 * Every sim is fresh per case (a rejected mint leaves connect_block's
 * mutable `view` cache partially walked — same caveat documented in
 * test_simnet_doublespend.c / test_simnet_value_inflation.c). The global
 * chain-params selection this file makes (CHAIN_REGTEST) is restored to
 * CHAIN_MAIN before returning, so no global state leaks to later groups.
 *
 * Per the harness contract (simnet.h): if a mint is rejected, the fix is
 * always in this file's block construction, never in connect_block. No
 * consensus predicate is touched — this file only pins existing behavior.
 */

#include "test/test_core.h"

#include "sim/simnet.h"
#include "domain/consensus/subsidy.h"
#include "chain/subsidy.h"
#include "chain/chainparams.h"
#include "consensus/params.h"
#include "core/amount.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CSA_CHECK(name, expr) do {         \
    printf("coinbase_subsidy_adversarial: %s... ", (name)); \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* REGTEST is configured (core/modules/chain/src/chainparams.c) with:
 *   nSubsidySlowStartInterval = 0  (no slow-start ramp; shift = 0)
 *   UPGRADE_BUTTERCUP disabled     (NETWORK_UPGRADE_NO_ACTIVATION)
 *   nPreButtercupSubsidyHalvingInterval = 150
 * so consensus_halving() is (nHeight - 0) / 150 for every height, always
 * the pre-Buttercup branch. The first halving boundary lands at h=150. */
#define CSA_REGTEST_INTERVAL 150
#define CSA_FULL ((int64_t)(12.5 * COIN)) /* 1,250,000,000 */

/* Drive the real consensus function and assert success. */
static int64_t csa_subsidy_ok(int h, const struct consensus_params *p, int *ok_out)
{
    int64_t s = -1;
    struct zcl_result r = domain_consensus_block_subsidy(h, p, &s);
    *ok_out = r.ok ? 1 : 0;
    return r.ok ? s : -1;
}

/* Build (and mint) a coinbase-only block at the sim's next height paying
 * `value` to a plain placeholder P2PKH-shaped script. Identical script
 * shape to fund_script in test_simnet_zmsg_onchain.c. */
static bool csa_mint_coinbase_value(struct simnet *sim, int64_t value)
{
    struct script sc;
    script_init(&sc);
    uint8_t pk[3] = {0x76, 0xa9, 0x14};
    script_set(&sc, pk, sizeof(pk));
    return simnet_mint_coinbase_to(sim, &sc, value, NULL);
}

/* Call csa_mint_coinbase_value() while redirecting stderr to a scratch
 * file, so this test can inspect connect_block's reject reason without any
 * change to simnet.c's public API. Mirrors vi_mint_capture() in
 * test_simnet_value_inflation.c. Best-effort: if the capture plumbing
 * itself fails, this runs the mint uncaptured (the boolean return, which
 * every assertion actually relies on, is unaffected either way). */
static bool csa_mint_capture(struct simnet *sim, int64_t value,
                              char *out_reason, size_t out_reason_len)
{
    if (out_reason && out_reason_len > 0)
        out_reason[0] = '\0';

    mkdir("./test-tmp", 0755);
    char path[256];
    snprintf(path, sizeof(path),
             "./test-tmp/coinbase_subsidy_adversarial_stderr_%d.log",
             (int)getpid());

    fflush(stderr);
    int saved_fd = dup(STDERR_FILENO);
    FILE *capf = (saved_fd >= 0) ? fopen(path, "w+") : NULL;
    if (!capf) {
        if (saved_fd >= 0)
            close(saved_fd);
        return csa_mint_coinbase_value(sim, value);
    }
    dup2(fileno(capf), STDERR_FILENO);

    bool ok = csa_mint_coinbase_value(sim, value);

    fflush(stderr);
    dup2(saved_fd, STDERR_FILENO);
    close(saved_fd);

    if (out_reason && out_reason_len > 0) {
        long sz = ftell(capf);
        if (sz > 0) {
            rewind(capf);
            size_t want = (size_t)sz < out_reason_len - 1
                            ? (size_t)sz : out_reason_len - 1;
            size_t rd = fread(out_reason, 1, want, capf);
            out_reason[rd] = '\0';
        }
    }
    fclose(capf);
    unlink(path);
    return ok;
}

int test_coinbase_subsidy_adversarial(void)
{
    printf("\n=== coinbase / subsidy / halving adversarial coverage ===\n");
    int failures = 0;

    /* =====================================================================
     * Part A — exact satoshi values around the ONE real, reachable
     * pre-Buttercup halving boundary (regtest, interval=150, no slow start,
     * Buttercup permanently disabled).
     * ===================================================================== */
    chain_params_select(CHAIN_REGTEST);
    {
        const struct chain_params *cp = chain_params_get();
        const struct consensus_params *params = &cp->consensus;

        CSA_CHECK("regtest sanity: Buttercup is disabled",
                  !consensus_network_upgrade_active(params, 150,
                                                     UPGRADE_BUTTERCUP));
        CSA_CHECK("regtest sanity: halving interval is 150",
                  params->nPreButtercupSubsidyHalvingInterval ==
                  CSA_REGTEST_INTERVAL);

        int ok = 0;
        int64_t below = csa_subsidy_ok(CSA_REGTEST_INTERVAL - 1, params, &ok);
        CSA_CHECK("h=149 (just below 1st regtest halving) == FULL",
                  ok && below == CSA_FULL);

        int64_t at = csa_subsidy_ok(CSA_REGTEST_INTERVAL, params, &ok);
        CSA_CHECK("h=150 (AT 1st regtest halving) == FULL/2",
                  ok && at == CSA_FULL / 2);

        int64_t above = csa_subsidy_ok(CSA_REGTEST_INTERVAL + 1, params, &ok);
        CSA_CHECK("h=151 (just above) == FULL/2 (same halving epoch)",
                  ok && above == CSA_FULL / 2);

        CSA_CHECK("boundary halves exactly (below == 2*at)",
                  below == 2 * at);

        /* Legacy wrapper must agree at the exact boundary. */
        CSA_CHECK("legacy get_block_subsidy() agrees at h=149/150",
                  get_block_subsidy(CSA_REGTEST_INTERVAL - 1, params) == CSA_FULL &&
                  get_block_subsidy(CSA_REGTEST_INTERVAL, params) == CSA_FULL / 2);
    }

    /* =====================================================================
     * Part B — connect_block enforces the height-specific reward across
     * the SAME regtest halving boundary: accept the exact reward on each
     * side, reject one satoshi over on each side, and reject a stale
     * pre-halving reward replayed at the post-halving height.
     * ===================================================================== */
    const int64_t pre_reward = CSA_FULL;          /* h=149 */
    const int64_t post_reward = CSA_FULL / 2;      /* h=150 */

    /* B1: accept the exact pre-halving reward at h=149. */
    {
        struct simnet sim;
        CSA_CHECK("B1: simnet init", simnet_init(&sim));
        CSA_CHECK("B1: mint to h=148",
                  simnet_mint_to_height(&sim, CSA_REGTEST_INTERVAL - 2));
        bool ok = csa_mint_coinbase_value(&sim, pre_reward);
        CSA_CHECK("B1: exact pre-halving reward (h=149) is ACCEPTED", ok);
        CSA_CHECK("B1: tip advanced to 149",
                  simnet_tip_height(&sim) == CSA_REGTEST_INTERVAL - 1);
        simnet_free(&sim);
    }

    /* B2: reject pre-halving reward + 1 at h=149. */
    {
        struct simnet sim;
        CSA_CHECK("B2: simnet init", simnet_init(&sim));
        CSA_CHECK("B2: mint to h=148",
                  simnet_mint_to_height(&sim, CSA_REGTEST_INTERVAL - 2));
        char reason[256];
        bool ok = csa_mint_capture(&sim, pre_reward + 1, reason, sizeof(reason));
        CSA_CHECK("B2: pre-halving reward+1 (h=149) is REJECTED", !ok);
        CSA_CHECK("B2: reject reason is bad-cb-amount",
                  strstr(reason, "bad-cb-amount") != NULL);
        CSA_CHECK("B2: tip did not advance past 148",
                  simnet_tip_height(&sim) == CSA_REGTEST_INTERVAL - 2);
        simnet_free(&sim);
    }

    /* B3: accept the exact post-halving reward at h=150 (crosses the
     * boundary correctly — the FULL-strength positive control). */
    {
        struct simnet sim;
        CSA_CHECK("B3: simnet init", simnet_init(&sim));
        CSA_CHECK("B3: mint to h=149",
                  simnet_mint_to_height(&sim, CSA_REGTEST_INTERVAL - 1));
        bool ok = csa_mint_coinbase_value(&sim, post_reward);
        CSA_CHECK("B3: exact post-halving reward (h=150) is ACCEPTED", ok);
        CSA_CHECK("B3: tip advanced to 150",
                  simnet_tip_height(&sim) == CSA_REGTEST_INTERVAL);
        simnet_free(&sim);
    }

    /* B4: reject post-halving reward + 1 at h=150. */
    {
        struct simnet sim;
        CSA_CHECK("B4: simnet init", simnet_init(&sim));
        CSA_CHECK("B4: mint to h=149",
                  simnet_mint_to_height(&sim, CSA_REGTEST_INTERVAL - 1));
        char reason[256];
        bool ok = csa_mint_capture(&sim, post_reward + 1, reason, sizeof(reason));
        CSA_CHECK("B4: post-halving reward+1 (h=150) is REJECTED", !ok);
        CSA_CHECK("B4: reject reason is bad-cb-amount",
                  strstr(reason, "bad-cb-amount") != NULL);
        CSA_CHECK("B4: tip did not advance past 149",
                  simnet_tip_height(&sim) == CSA_REGTEST_INTERVAL - 1);
        simnet_free(&sim);
    }

    /* B5: the STALE-REWARD-REPLAY attack — resubmit the OLD (larger)
     * pre-halving reward, unchanged, at the post-halving height h=150.
     * This is strictly less than "some huge overclaim"; it is exactly
     * what a validator using a stale/previous-height subsidy constant
     * would wrongly accept. connect_block must reject it. */
    {
        struct simnet sim;
        CSA_CHECK("B5: simnet init", simnet_init(&sim));
        CSA_CHECK("B5: mint to h=149",
                  simnet_mint_to_height(&sim, CSA_REGTEST_INTERVAL - 1));
        char reason[256];
        bool ok = csa_mint_capture(&sim, pre_reward, reason, sizeof(reason));
        CSA_CHECK("B5: stale pre-halving reward replayed at h=150 is REJECTED",
                  !ok);
        CSA_CHECK("B5: reject reason is bad-cb-amount",
                  strstr(reason, "bad-cb-amount") != NULL);
        CSA_CHECK("B5: tip did not advance past 149",
                  simnet_tip_height(&sim) == CSA_REGTEST_INTERVAL - 1);
        simnet_free(&sim);
    }

    /* Restore the default network selection before touching mainnet params
     * again, and before this test group returns (no global state leak to
     * later groups in the same process). */
    chain_params_select(CHAIN_MAIN);

    /* =====================================================================
     * Part C — no founders/dev-fee split is enforced on mainnet, despite
     * vFoundersRewardAddress[]/nFoundersRewardAddresses being populated.
     * A coinbase paying the ENTIRE subsidy to one plain output, inside the
     * founders-reward window, is accepted.
     * ===================================================================== */
    {
        const struct chain_params *cp = chain_params_get();
        const struct consensus_params *params = &cp->consensus;
        CSA_CHECK("mainnet sanity: founders-reward addresses ARE configured",
                  cp->nFoundersRewardAddresses > 0);

        int ok = 0;
        /* First mintable simnet height (100) sits inside the founders-
         * reward window: 100 <= consensus_last_founders_reward_height(). */
        int64_t subsidy_h100 = csa_subsidy_ok(100, params, &ok);
        CSA_CHECK("h=100 is inside the (unenforced) founders-reward window",
                  ok && 100 <= consensus_last_founders_reward_height(params));

        struct simnet sim;
        CSA_CHECK("C: simnet init", simnet_init(&sim));
        bool minted = csa_mint_coinbase_value(&sim, subsidy_h100);
        CSA_CHECK("C: 100%-to-miner coinbase (no founders split) ACCEPTED "
                  "-> ZClassic enforces no founders/dev-fee split",
                  minted);
        simnet_free(&sim);
    }

    /* Belt-and-braces: leave the global network selection at the default
     * for any test group that runs after this one. */
    chain_params_select(CHAIN_MAIN);

    printf("=== coinbase_subsidy_adversarial: %d failures ===\n", failures);
    return failures;
}

/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for domain/consensus/subsidy.{c,h}.
 *
 * These tests pin the pure block-subsidy arithmetic. They DO NOT go
 * through the chain/ wrapper: they exercise the typed zcl_result API
 * directly and cross-check the result against the legacy
 * get_block_subsidy() to prove the extraction was behaviour-preserving.
 */

#include "test/test_core.h"

#include "domain/consensus/subsidy.h"
#include "chain/subsidy.h"
#include "chain/chainparams.h"
#include "consensus/params.h"
#include "core/amount.h"

#include <stdio.h>
#include <string.h>

#define DCS_CHECK(name, expr) do { \
    printf("domain_consensus_subsidy: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

int test_domain_consensus_subsidy(void)
{
    int failures = 0;
    const struct chain_params *cp = chain_params_get();
    const struct consensus_params *params = &cp->consensus;

    /* --- error-path / contract tests --- */

    /* null params -> typed error. */
    {
        int64_t s = -1;
        struct zcl_result r = domain_consensus_block_subsidy(100, NULL, &s);
        DCS_CHECK("null params -> ERR_NULL_PARAMS",
                  !r.ok && r.code == DOMAIN_CONSENSUS_SUBSIDY_ERR_NULL_PARAMS);
    }

    /* null out_subsidy -> typed error. */
    {
        struct zcl_result r = domain_consensus_block_subsidy(100, params, NULL);
        DCS_CHECK("null out -> ERR_NULL_OUT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_SUBSIDY_ERR_NULL_OUT);
    }

    /* negative height -> typed error (new contract; legacy silently
     * computed for negatives). */
    {
        int64_t s = -1;
        struct zcl_result r = domain_consensus_block_subsidy(-1, params, &s);
        DCS_CHECK("negative height -> ERR_NEG_HEIGHT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_SUBSIDY_ERR_NEG_HEIGHT);
    }

    /* --- value tests (pin known points on the curve) --- */

    /* Height 0: slow-start gives zero (multiplier is 0). */
    {
        int64_t s = -1;
        struct zcl_result r = domain_consensus_block_subsidy(0, params, &s);
        DCS_CHECK("height=0 -> OK, subsidy=0", r.ok && s == 0);
    }

    /* Height 1: slow-start, non-zero. */
    {
        int64_t s = -1;
        struct zcl_result r = domain_consensus_block_subsidy(1, params, &s);
        DCS_CHECK("height=1 -> OK, subsidy>0", r.ok && s > 0);
    }

    /* Far past slow-start, pre-buttercup: full 12.5 ZCL. */
    {
        int64_t s = -1;
        struct zcl_result r = domain_consensus_block_subsidy(706999, params, &s);
        DCS_CHECK("height=706999 (pre-buttercup) -> OK, 12.5 COIN",
                  r.ok && s == (int64_t)(12.5 * COIN));
    }

    /* Just past buttercup activation (mainnet activates at 706560
     * historically; we don't hardcode the activation height here, we
     * sample 707001 to land in the post-buttercup regime). */
    {
        int64_t s = -1;
        struct zcl_result r = domain_consensus_block_subsidy(707001, params, &s);
        DCS_CHECK("height=707001 -> OK, smaller per-block reward",
                  r.ok && s > 0 && s < (int64_t)(12.5 * COIN));
    }

    /* --- cross-check: the domain function must match the legacy
     * wrapper for every sampled height. This is the regression seal:
     * if anyone "improves" one side without the other, the test
     * shouts. We sample across the entire interesting range. */
    {
        int heights[] = {
            0, 1, 100, 1000, 10000, 19999, 20000, 100000, 500000,
            706559, 706560, 707000, 1000000, 2000000, 2387000, 2387001,
            5000000, 10000000,
        };
        int n = (int)(sizeof(heights) / sizeof(heights[0]));
        bool all_match = true;
        for (int i = 0; i < n; i++) {
            int h = heights[i];
            int64_t domain_v = -1;
            struct zcl_result r = domain_consensus_block_subsidy(h, params, &domain_v);
            int64_t legacy_v = get_block_subsidy(h, params);
            if (!r.ok || domain_v != legacy_v) {
                printf("\n  MISMATCH height=%d domain=%lld legacy=%lld ok=%d\n",
                       h, (long long)domain_v, (long long)legacy_v, (int)r.ok);
                all_match = false;
            }
        }
        DCS_CHECK("domain matches legacy across sampled heights", all_match);
    }

    return failures;
}

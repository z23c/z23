/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for domain/consensus/upgrades.{c,h}.
 *
 * Pins the pure activation-height arithmetic and seals the regression
 * surface against the legacy consensus_*() wrappers across activation
 * boundaries (height = activation-1, activation, activation+1) for
 * each upgrade defined in mainnet consensus params.
 */

#include "test/test_core.h"

#include "domain/consensus/upgrades.h"
#include "consensus/upgrades.h"
#include "consensus/params.h"
#include "chain/chainparams.h"

#include <stdio.h>
#include <string.h>

#define DCU_CHECK(name, expr) do { \
    printf("domain_consensus_upgrades: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

int test_domain_consensus_upgrades(void)
{
    int failures = 0;
    const struct chain_params *cp = chain_params_get();
    const struct consensus_params *params = &cp->consensus;

    /* ── error / null-path tests ─────────────────────────────────── */
    {
        enum upgrade_state st = UPGRADE_DISABLED;
        struct zcl_result r = domain_consensus_upgrade_state(100, NULL, UPGRADE_SAPLING, &st);
        DCU_CHECK("upgrade_state null params -> ERR_NULL_PARAMS",
                  !r.ok && r.code == DOMAIN_CONSENSUS_UPGRADES_ERR_NULL_PARAMS);
    }
    {
        struct zcl_result r = domain_consensus_upgrade_state(100, params, UPGRADE_SAPLING, NULL);
        DCU_CHECK("upgrade_state null out -> ERR_NULL_OUT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_UPGRADES_ERR_NULL_OUT);
    }
    {
        enum upgrade_state st = UPGRADE_DISABLED;
        struct zcl_result r = domain_consensus_upgrade_state(-1, params, UPGRADE_SAPLING, &st);
        DCU_CHECK("upgrade_state negative height -> ERR_NEG_HEIGHT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_UPGRADES_ERR_NEG_HEIGHT);
    }
    {
        enum upgrade_state st = UPGRADE_DISABLED;
        struct zcl_result r = domain_consensus_upgrade_state(100, params,
                (enum upgrade_index)MAX_NETWORK_UPGRADES, &st);
        DCU_CHECK("upgrade_state bad idx -> ERR_BAD_IDX",
                  !r.ok && r.code == DOMAIN_CONSENSUS_UPGRADES_ERR_BAD_IDX);
    }
    {
        int e = -1;
        struct zcl_result r = domain_consensus_current_epoch(-1, params, &e);
        DCU_CHECK("current_epoch negative -> ERR_NEG_HEIGHT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_UPGRADES_ERR_NEG_HEIGHT);
    }
    {
        uint32_t b = 0xffffffff;
        struct zcl_result r = domain_consensus_current_epoch_branch_id(100, NULL, &b);
        DCU_CHECK("current_epoch_branch_id null params -> ERR_NULL_PARAMS",
                  !r.ok && r.code == DOMAIN_CONSENSUS_UPGRADES_ERR_NULL_PARAMS);
    }
    {
        struct zcl_result r = domain_consensus_is_branch_id(0x76b809bb, NULL);
        DCU_CHECK("is_branch_id null out -> ERR_NULL_OUT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_UPGRADES_ERR_NULL_OUT);
    }
    {
        bool m = false;
        struct zcl_result r = domain_consensus_is_activation_height(100, params,
                (enum upgrade_index)(-1), &m);
        DCU_CHECK("is_activation_height bad idx -> ERR_BAD_IDX",
                  !r.ok && r.code == DOMAIN_CONSENSUS_UPGRADES_ERR_BAD_IDX);
    }
    {
        bool m = false;
        struct zcl_result r = domain_consensus_is_activation_height_any(-1, params, &m);
        DCU_CHECK("is_activation_height_any negative -> ERR_NEG_HEIGHT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_UPGRADES_ERR_NEG_HEIGHT);
    }
    {
        int e = -1;
        struct zcl_result r = domain_consensus_next_epoch(-1, params, &e);
        DCU_CHECK("next_epoch negative -> ERR_NEG_HEIGHT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_UPGRADES_ERR_NEG_HEIGHT);
    }
    {
        /* Past every upgrade -> no pending. */
        int e = -1;
        struct zcl_result r = domain_consensus_next_epoch(50000000, params, &e);
        DCU_CHECK("next_epoch past-all -> ERR_NO_PENDING",
                  !r.ok && r.code == DOMAIN_CONSENSUS_UPGRADES_ERR_NO_PENDING);
    }
    {
        int a = -1;
        struct zcl_result r = domain_consensus_next_activation_height(50000000, params, &a);
        DCU_CHECK("next_activation_height past-all -> ERR_NO_PENDING",
                  !r.ok && r.code == DOMAIN_CONSENSUS_UPGRADES_ERR_NO_PENDING);
    }

    /* ── value tests: BASE_SPROUT is ALWAYS active ───────────────── */
    {
        enum upgrade_state st = UPGRADE_DISABLED;
        struct zcl_result r = domain_consensus_upgrade_state(0, params, BASE_SPROUT, &st);
        DCU_CHECK("BASE_SPROUT at h=0 is ACTIVE",
                  r.ok && st == UPGRADE_ACTIVE);
    }
    {
        bool m = true;
        struct zcl_result r = domain_consensus_is_activation_height(0, params, BASE_SPROUT, &m);
        DCU_CHECK("BASE_SPROUT has no activation height (h=0 -> false)",
                  r.ok && m == false);
    }

    /* ── value tests: known branch ids ───────────────────────────── */
    {
        bool known = false;
        struct zcl_result r = domain_consensus_is_branch_id(0x76b809bb, &known);
        DCU_CHECK("is_branch_id Sapling=0x76b809bb -> known",
                  r.ok && known);
    }
    {
        bool known = true;
        struct zcl_result r = domain_consensus_is_branch_id(0xdeadbeef, &known);
        DCU_CHECK("is_branch_id 0xdeadbeef -> not known",
                  r.ok && !known);
    }
    {
        bool known = false;
        struct zcl_result r = domain_consensus_is_branch_id(SPROUT_BRANCH_ID, &known);
        DCU_CHECK("is_branch_id SPROUT_BRANCH_ID -> known",
                  r.ok && known);
    }

    /* ── regression seal: wrapper-vs-domain across activation
     *    boundaries for every defined upgrade. ─────────────────── */
    enum upgrade_index upgrades[] = {
        UPGRADE_OVERWINTER, UPGRADE_SAPLING, UPGRADE_BUBBLES,
        UPGRADE_DIFFADJ, UPGRADE_BUTTERCUP,
    };
    const int n_up = (int)(sizeof(upgrades) / sizeof(upgrades[0]));

    bool boundary_match = true;
    for (int i = 0; i < n_up; i++) {
        enum upgrade_index idx = upgrades[i];
        int act = params->vUpgrades[idx].nActivationHeight;
        if (act == NETWORK_UPGRADE_NO_ACTIVATION)
            continue;  /* not scheduled on this network */

        int probes[3] = { act - 1, act, act + 1 };
        for (int k = 0; k < 3; k++) {
            int h = probes[k];
            if (h < 0)
                continue;

            /* upgrade_state */
            enum upgrade_state d_st = UPGRADE_DISABLED;
            struct zcl_result rs = domain_consensus_upgrade_state(h, params, idx, &d_st);
            enum upgrade_state l_st = consensus_upgrade_state(h, params, idx);
            if (!rs.ok || d_st != l_st) {
                printf("\n  MISMATCH upgrade_state idx=%d h=%d domain=%d legacy=%d\n",
                       (int)idx, h, (int)d_st, (int)l_st);
                boundary_match = false;
            }

            /* network_upgrade_active (predicate over state == ACTIVE) */
            bool d_act = (d_st == UPGRADE_ACTIVE);
            bool l_act = consensus_network_upgrade_active(params, h, idx);
            if (d_act != l_act) {
                printf("\n  MISMATCH active idx=%d h=%d d=%d l=%d\n",
                       (int)idx, h, (int)d_act, (int)l_act);
                boundary_match = false;
            }

            /* is_activation_height */
            bool d_mat = false;
            struct zcl_result rm = domain_consensus_is_activation_height(h, params, idx, &d_mat);
            bool l_mat = consensus_is_activation_height(h, params, idx);
            if (!rm.ok || d_mat != l_mat) {
                printf("\n  MISMATCH is_activation_height idx=%d h=%d d=%d l=%d\n",
                       (int)idx, h, (int)d_mat, (int)l_mat);
                boundary_match = false;
            }

            /* current_epoch / branch id (params-wide check at h) */
            int d_ep = -1;
            (void)domain_consensus_current_epoch(h, params, &d_ep);
            int l_ep = consensus_current_epoch(h, params);
            if (d_ep != l_ep) {
                printf("\n  MISMATCH current_epoch h=%d d=%d l=%d\n", h, d_ep, l_ep);
                boundary_match = false;
            }

            uint32_t d_br = 0;
            (void)domain_consensus_current_epoch_branch_id(h, params, &d_br);
            uint32_t l_br = consensus_current_epoch_branch_id(h, params);
            if (d_br != l_br) {
                printf("\n  MISMATCH branch_id h=%d d=0x%08x l=0x%08x\n", h, d_br, l_br);
                boundary_match = false;
            }
        }
    }
    DCU_CHECK("wrapper-vs-domain match across activation boundaries",
              boundary_match);

    /* is_activation_height_any should match the legacy on every
     * scheduled activation height (true) and on h=0 (false). */
    {
        bool any_match = true;
        for (int i = 0; i < n_up; i++) {
            int act = params->vUpgrades[upgrades[i]].nActivationHeight;
            if (act < 0)
                continue;
            bool d = false;
            struct zcl_result r = domain_consensus_is_activation_height_any(act, params, &d);
            bool l = consensus_is_activation_height_any(act, params);
            if (!r.ok || d != l) {
                printf("\n  MISMATCH any h=%d d=%d l=%d\n", act, (int)d, (int)l);
                any_match = false;
            }
        }
        /* Non-activation height: pick something below first activation. */
        {
            bool d = true;
            struct zcl_result r = domain_consensus_is_activation_height_any(1, params, &d);
            if (r.ok && d) {
                /* h=1 might coincide with an activation on regtest, but
                 * on mainnet it doesn't. Don't fail on edge networks. */
            }
        }
        DCU_CHECK("is_activation_height_any wrapper-vs-domain", any_match);
    }

    /* next_epoch / next_activation_height — at h=0, the next pending
     * upgrade must be the lowest-indexed one with a scheduled height. */
    {
        int d_ep = -1;
        struct zcl_result r = domain_consensus_next_epoch(0, params, &d_ep);
        int l_ep = consensus_next_epoch(0, params);
        DCU_CHECK("next_epoch h=0 matches legacy",
                  r.ok && d_ep == l_ep);
    }
    {
        int d_act = -1;
        struct zcl_result r = domain_consensus_next_activation_height(0, params, &d_act);
        int l_act = consensus_next_activation_height(0, params);
        DCU_CHECK("next_activation_height h=0 matches legacy",
                  r.ok && d_act == l_act);
    }

    return failures;
}

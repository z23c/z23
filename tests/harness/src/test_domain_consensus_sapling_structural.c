/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for domain/consensus/sapling_structural.{c,h}.
 *
 * These tests pin the PURE height-aware Sapling/Overwinter structural
 * transaction-validation rules extracted from
 * core/modules/validation/src/contextual_check_tx.c, and seal the extraction
 * with a side-by-side comparison against the legacy
 * `contextual_check_transaction()` wrapper for representative tx
 * shapes and heights:
 *
 *   - pre-Overwinter height with overwintered flag set
 *   - Overwinter active without Sapling: version/version-group rules
 *   - Sapling active: version-group, min/max version, flag rules
 *   - Pre-Sapling oversize tx
 *   - Boundary heights (activation - 1, activation, activation + 1)
 *
 * For every shape we assert:
 *   1. domain function returns the same {ok, reject_reason, dos}
 *      pair as the legacy wrapper populates on validation_state.
 *   2. reject_reason strings are byte-identical (strcmp == 0).
 *
 * This is the regression seal: if anyone "improves" one side without
 * the other, the test shouts.
 */

#include "test/test_core.h"

#include "domain/consensus/sapling_structural.h"
#include "validation/contextual_check_tx.h"
/* consensus/consensus.h not included to avoid MAX_BLOCK_SIZE collision
 * with main_constants.h. Mirror the constants we need locally. */
#include "consensus/validation.h"
#include "consensus/params.h"
#include "primitives/transaction.h"
#include "core/amount.h"
#include "core/uint256.h"

#include <stdio.h>
#include <string.h>

/* Mirror canonical constants — used only to build test fixtures. */
#ifndef SAPLING_MIN_TX_VERSION
#define SAPLING_MIN_TX_VERSION     4
#endif
#ifndef SAPLING_MAX_TX_VERSION
#define SAPLING_MAX_TX_VERSION     4
#endif
#ifndef OVERWINTER_MIN_TX_VERSION
#define OVERWINTER_MIN_TX_VERSION  3
#endif
#ifndef OVERWINTER_MAX_TX_VERSION
#define OVERWINTER_MAX_TX_VERSION  3
#endif
#ifndef OVERWINTER_VERSION_GROUP_ID
#define OVERWINTER_VERSION_GROUP_ID 0x03C48270U
#endif
#ifndef SAPLING_VERSION_GROUP_ID
#define SAPLING_VERSION_GROUP_ID    0x892F2085U
#endif
#ifndef MAX_TX_SIZE_BEFORE_SAPLING
#define MAX_TX_SIZE_BEFORE_SAPLING 100000U
#endif

#define DCS_CHECK(name, expr) do { \
    printf("domain_consensus_sapling_structural: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Activation heights for fixture params */
#define ACT_OVERWINTER 100
#define ACT_SAPLING    200

/* Build a synthetic consensus_params with overwinter@100 and sapling@200.
 * Everything else stays zeroed — these tests only touch upgrade arithmetic. */
static void build_test_params(struct consensus_params *cp)
{
    memset(cp, 0, sizeof(*cp));
    for (int i = 0; i < MAX_NETWORK_UPGRADES; i++)
        cp->vUpgrades[i].nActivationHeight = NETWORK_UPGRADE_NO_ACTIVATION;
    cp->vUpgrades[UPGRADE_OVERWINTER].nActivationHeight = ACT_OVERWINTER;
    cp->vUpgrades[UPGRADE_SAPLING].nActivationHeight    = ACT_SAPLING;
}

/* Construct a minimal sprout (pre-Overwinter) tx: not overwintered,
 * version=1, 1 vin (non-null prevout), 1 vout (value=1 COIN). */
static void build_sprout_tx(struct transaction *tx)
{
    transaction_init(tx);
    transaction_alloc(tx, 1, 1);
    tx->overwintered = false;
    tx->version = 1;
    tx->version_group_id = 0;
    uint256_set_null(&tx->vin[0].prevout.hash);
    tx->vin[0].prevout.hash.data[0] = 0x42;
    tx->vin[0].prevout.n = 0;
    tx->vin[0].sequence = 0xFFFFFFFEu;
    tx->vin[0].script_sig.size = 0;
    tx->vout[0].value = 1 * COIN;
    tx->vout[0].script_pub_key.size = 0;
    tx->lock_time = 0;
    tx->expiry_height = 0;
}

/* Construct a minimal Overwinter tx: overwintered=true, version=3,
 * version_group_id=OVERWINTER, 1 vin/1 vout. */
static void build_overwinter_tx(struct transaction *tx)
{
    build_sprout_tx(tx);
    tx->overwintered = true;
    tx->version = OVERWINTER_MIN_TX_VERSION;
    tx->version_group_id = OVERWINTER_VERSION_GROUP_ID;
}

/* Construct a minimal Sapling tx: overwintered=true, version=4,
 * version_group_id=SAPLING, 1 vin/1 vout (no shielded fields). */
static void build_sapling_tx(struct transaction *tx)
{
    build_sprout_tx(tx);
    tx->overwintered = true;
    tx->version = SAPLING_MIN_TX_VERSION;
    tx->version_group_id = SAPLING_VERSION_GROUP_ID;
}

/* Side-by-side: run the legacy wrapper and capture its verdict. */
struct legacy_verdict {
    bool ok;
    char reason[MAX_REJECT_REASON];
    int dos;
};

static struct legacy_verdict run_legacy(const struct transaction *tx,
                                        const struct consensus_params *cp,
                                        int n_height,
                                        int dos_level)
{
    struct validation_state st;
    validation_state_init(&st);
    bool ok = contextual_check_transaction(tx, &st, cp, n_height, dos_level);
    struct legacy_verdict v;
    v.ok = ok;
    v.dos = st.dos;
    strncpy(v.reason, st.reject_reason, sizeof(v.reason) - 1);
    v.reason[sizeof(v.reason) - 1] = '\0';
    return v;
}

struct domain_verdict {
    bool ok;
    const char *reason;
    int dos;
    int code;
};

static struct domain_verdict run_domain(const struct transaction *tx,
                                        const struct consensus_params *cp,
                                        int n_height,
                                        int dos_level)
{
    struct domain_consensus_sapling_structural_failure f = {0};
    struct zcl_result r =
        domain_consensus_check_transaction_sapling_structural(
            tx, cp, n_height, dos_level, &f);
    struct domain_verdict v;
    v.ok = r.ok;
    v.reason = f.reject_reason;
    v.dos = f.dos;
    v.code = r.code;
    return v;
}

/* Compare domain output with legacy. Both must agree on:
 *   - ok bit
 *   - reject_reason (byte-identical)
 *   - dos score
 * If the domain rejected and legacy passed (or vice versa), or if the
 * reason strings differ, that's a peer-visible protocol divergence. */
static bool verdicts_match(const struct domain_verdict *d,
                           const struct legacy_verdict *l)
{
    if (d->ok != l->ok) return false;
    if (d->ok) return true;
    const char *dr = d->reason ? d->reason : "";
    if (strcmp(dr, l->reason) != 0) return false;
    if (d->dos != l->dos) return false;
    return true;
}

int test_domain_consensus_sapling_structural(void)
{
    int failures = 0;
    struct consensus_params cp;
    build_test_params(&cp);

    /* --- contract: NULL tx -> typed error --- */
    {
        struct domain_consensus_sapling_structural_failure f = {0};
        struct zcl_result r =
            domain_consensus_check_transaction_sapling_structural(
                NULL, &cp, 0, 100, &f);
        DCS_CHECK("null tx -> ERR_NULL_TX",
                  !r.ok && r.code == DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_NULL_TX);
    }

    /* --- contract: NULL params -> typed error --- */
    {
        struct transaction tx;
        build_sprout_tx(&tx);
        struct zcl_result r =
            domain_consensus_check_transaction_sapling_structural(
                &tx, NULL, 0, 100, NULL);
        DCS_CHECK("null params -> ERR_NULL_PARAMS",
                  !r.ok && r.code == DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_NULL_PARAMS);
        transaction_free(&tx);
    }

    /* --- contract: negative height -> typed error --- */
    {
        struct transaction tx;
        build_sprout_tx(&tx);
        struct zcl_result r =
            domain_consensus_check_transaction_sapling_structural(
                &tx, &cp, -1, 100, NULL);
        DCS_CHECK("negative height -> ERR_NEG_HEIGHT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_NEG_HEIGHT);
        transaction_free(&tx);
    }

    /* --- contract: NULL out_failure is allowed on success --- */
    {
        struct transaction tx;
        build_sprout_tx(&tx);
        struct zcl_result r =
            domain_consensus_check_transaction_sapling_structural(
                &tx, &cp, 0, 100, NULL);
        DCS_CHECK("sprout tx at h=0, null out_failure tolerated",
                  r.ok && r.code == 0);
        transaction_free(&tx);
    }

    /* --- shape: pre-Overwinter sprout tx at h=ACT_OVERWINTER-1 passes --- */
    {
        struct transaction tx;
        build_sprout_tx(&tx);
        struct domain_verdict d = run_domain(&tx, &cp, ACT_OVERWINTER - 1, 100);
        struct legacy_verdict l = run_legacy(&tx, &cp, ACT_OVERWINTER - 1, 100);
        DCS_CHECK("sprout @ overwinter-1: domain accepts", d.ok);
        DCS_CHECK("sprout @ overwinter-1: verdicts agree",
                  verdicts_match(&d, &l));
        transaction_free(&tx);
    }

    /* --- shape: sprout tx with overwintered flag set BEFORE Overwinter --- */
    {
        struct transaction tx;
        build_sprout_tx(&tx);
        tx.overwintered = true;
        tx.version = OVERWINTER_MIN_TX_VERSION;
        tx.version_group_id = OVERWINTER_VERSION_GROUP_ID;
        struct domain_verdict d = run_domain(&tx, &cp, ACT_OVERWINTER - 1, 10);
        struct legacy_verdict l = run_legacy(&tx, &cp, ACT_OVERWINTER - 1, 10);
        DCS_CHECK("overwintered @ pre-overwinter: rejects tx-overwinter-not-active",
                  !d.ok && d.reason &&
                  strcmp(d.reason, "tx-overwinter-not-active") == 0);
        DCS_CHECK("overwintered @ pre-overwinter: dos=dosLevel(10)", d.dos == 10);
        DCS_CHECK("overwintered @ pre-overwinter: verdicts agree",
                  verdicts_match(&d, &l));
        transaction_free(&tx);
    }

    /* --- shape: Overwinter active, non-overwintered tx with version<3 passes
     *      domain version-group block, then fails on "tx-overwinter-active". */
    {
        struct transaction tx;
        build_sprout_tx(&tx);
        tx.version = 2;  /* < OVERWINTER_MIN_TX_VERSION */
        struct domain_verdict d = run_domain(&tx, &cp, ACT_OVERWINTER, 50);
        struct legacy_verdict l = run_legacy(&tx, &cp, ACT_OVERWINTER, 50);
        DCS_CHECK("overwinter-active, !overwintered, ver<3: tx-overwinter-active",
                  !d.ok && d.reason &&
                  strcmp(d.reason, "tx-overwinter-active") == 0);
        DCS_CHECK("overwinter-active, ver<3: dos=dosLevel(50)", d.dos == 50);
        DCS_CHECK("overwinter-active, ver<3: verdicts agree",
                  verdicts_match(&d, &l));
        transaction_free(&tx);
    }

    /* --- shape: Overwinter active, version>=3 but flag missing --- */
    {
        struct transaction tx;
        build_sprout_tx(&tx);
        tx.version = OVERWINTER_MIN_TX_VERSION;  /* 3 */
        tx.overwintered = false;
        struct domain_verdict d = run_domain(&tx, &cp, ACT_OVERWINTER, 50);
        struct legacy_verdict l = run_legacy(&tx, &cp, ACT_OVERWINTER, 50);
        DCS_CHECK("overwinter-active, ver>=3, !flag: tx-overwinter-flag-not-set",
                  !d.ok && d.reason &&
                  strcmp(d.reason, "tx-overwinter-flag-not-set") == 0);
        DCS_CHECK("ow flag-not-set: dos=dosLevel(50)", d.dos == 50);
        DCS_CHECK("ow flag-not-set: verdicts agree", verdicts_match(&d, &l));
        transaction_free(&tx);
    }

    /* --- shape: Overwinter active, wrong version_group_id --- */
    {
        struct transaction tx;
        build_overwinter_tx(&tx);
        tx.version_group_id = 0xDEADBEEFu;
        struct domain_verdict d = run_domain(&tx, &cp, ACT_OVERWINTER, 50);
        struct legacy_verdict l = run_legacy(&tx, &cp, ACT_OVERWINTER, 50);
        DCS_CHECK("ow active, bad version-group-id: rejects",
                  !d.ok && d.reason &&
                  strcmp(d.reason, "bad-overwinter-tx-version-group-id") == 0);
        DCS_CHECK("bad ow vgid: dos=dosLevel(50)", d.dos == 50);
        DCS_CHECK("bad ow vgid: verdicts agree", verdicts_match(&d, &l));
        transaction_free(&tx);
    }

    /* --- shape: Overwinter active, version > OVERWINTER_MAX (=3) --- */
    {
        struct transaction tx;
        build_overwinter_tx(&tx);
        tx.version = OVERWINTER_MAX_TX_VERSION + 1;  /* 4 — but Sapling not active here */
        struct domain_verdict d = run_domain(&tx, &cp, ACT_OVERWINTER + 1, 50);
        struct legacy_verdict l = run_legacy(&tx, &cp, ACT_OVERWINTER + 1, 50);
        DCS_CHECK("ow active, ver>max: bad-tx-overwinter-version-too-high",
                  !d.ok && d.reason &&
                  strcmp(d.reason, "bad-tx-overwinter-version-too-high") == 0);
        DCS_CHECK("ow ver-too-high: dos=100 (hard)", d.dos == 100);
        DCS_CHECK("ow ver-too-high: verdicts agree", verdicts_match(&d, &l));
        transaction_free(&tx);
    }

    /* --- shape: Sapling-active boundary at ACT_SAPLING --- */
    {
        struct transaction tx;
        build_sapling_tx(&tx);
        struct domain_verdict d = run_domain(&tx, &cp, ACT_SAPLING, 100);
        struct legacy_verdict l = run_legacy(&tx, &cp, ACT_SAPLING, 100);
        DCS_CHECK("Sapling @ activation: domain accepts", d.ok);
        DCS_CHECK("Sapling @ activation: verdicts agree", verdicts_match(&d, &l));
        transaction_free(&tx);
    }

    /* --- shape: Sapling active, sapling tx with non-Sapling version_group_id */
    {
        struct transaction tx;
        build_sapling_tx(&tx);
        tx.version_group_id = OVERWINTER_VERSION_GROUP_ID;
        struct domain_verdict d = run_domain(&tx, &cp, ACT_SAPLING, 50);
        struct legacy_verdict l = run_legacy(&tx, &cp, ACT_SAPLING, 50);
        DCS_CHECK("Sapling active, ow vgid: bad-sapling-tx-version-group-id",
                  !d.ok && d.reason &&
                  strcmp(d.reason, "bad-sapling-tx-version-group-id") == 0);
        DCS_CHECK("bad sapling vgid: dos=dosLevel(50)", d.dos == 50);
        DCS_CHECK("bad sapling vgid: verdicts agree", verdicts_match(&d, &l));
        transaction_free(&tx);
    }

    /* --- shape: Sapling active, version=4 but flag not set --- */
    {
        struct transaction tx;
        build_sapling_tx(&tx);
        tx.overwintered = false;
        struct domain_verdict d = run_domain(&tx, &cp, ACT_SAPLING, 50);
        struct legacy_verdict l = run_legacy(&tx, &cp, ACT_SAPLING, 50);
        DCS_CHECK("Sapling active, !overwintered, ver=4: tx-overwintered-flag-not-set",
                  !d.ok && d.reason &&
                  strcmp(d.reason, "tx-overwintered-flag-not-set") == 0);
        DCS_CHECK("sapling flag-not-set: dos=dosLevel(50)", d.dos == 50);
        DCS_CHECK("sapling flag-not-set: verdicts agree", verdicts_match(&d, &l));
        transaction_free(&tx);
    }

    /* --- shape: Sapling active, version > SAPLING_MAX --- */
    {
        struct transaction tx;
        build_sapling_tx(&tx);
        tx.version = SAPLING_MAX_TX_VERSION + 1;
        struct domain_verdict d = run_domain(&tx, &cp, ACT_SAPLING, 50);
        struct legacy_verdict l = run_legacy(&tx, &cp, ACT_SAPLING, 50);
        DCS_CHECK("Sapling active, ver>max: bad-tx-sapling-version-too-high",
                  !d.ok && d.reason &&
                  strcmp(d.reason, "bad-tx-sapling-version-too-high") == 0);
        DCS_CHECK("sapling ver-too-high: dos=100 (hard)", d.dos == 100);
        DCS_CHECK("sapling ver-too-high: verdicts agree", verdicts_match(&d, &l));
        transaction_free(&tx);
    }

    /* --- shape: Sapling active, overwintered, ver<SAPLING_MIN (=4) --- */
    {
        struct transaction tx;
        build_sapling_tx(&tx);
        tx.version = SAPLING_MIN_TX_VERSION - 1; /* 3 — overwinter-shape */
        /* version_group_id is SAPLING — exercise the overwintered &&
         * version < SAPLING_MIN_TX_VERSION branch. */
        struct domain_verdict d = run_domain(&tx, &cp, ACT_SAPLING, 50);
        struct legacy_verdict l = run_legacy(&tx, &cp, ACT_SAPLING, 50);
        DCS_CHECK("Sapling active, ver<min: bad-tx-sapling-version-too-low",
                  !d.ok && d.reason &&
                  strcmp(d.reason, "bad-tx-sapling-version-too-low") == 0);
        DCS_CHECK("sapling ver-too-low: dos=100 (hard)", d.dos == 100);
        DCS_CHECK("sapling ver-too-low: verdicts agree", verdicts_match(&d, &l));
        transaction_free(&tx);
    }

    /* --- shape: At Sapling activation - 1 (Overwinter only) --- */
    {
        struct transaction tx;
        build_overwinter_tx(&tx);
        struct domain_verdict d = run_domain(&tx, &cp, ACT_SAPLING - 1, 50);
        struct legacy_verdict l = run_legacy(&tx, &cp, ACT_SAPLING - 1, 50);
        DCS_CHECK("Sapling activation-1: overwinter tx accepted", d.ok);
        DCS_CHECK("Sapling activation-1: verdicts agree", verdicts_match(&d, &l));
        transaction_free(&tx);
    }

    /* --- shape: At Sapling activation + 1, accept a sapling tx --- */
    {
        struct transaction tx;
        build_sapling_tx(&tx);
        struct domain_verdict d = run_domain(&tx, &cp, ACT_SAPLING + 1, 50);
        struct legacy_verdict l = run_legacy(&tx, &cp, ACT_SAPLING + 1, 50);
        DCS_CHECK("Sapling activation+1: sapling tx accepted", d.ok);
        DCS_CHECK("Sapling activation+1: verdicts agree", verdicts_match(&d, &l));
        transaction_free(&tx);
    }

    /* --- shape: Overwinter active, !overwintered, ver<3 — must hit
     *      "tx-overwinter-active" (the "MUST be overwintered" guard). */
    {
        struct transaction tx;
        build_sprout_tx(&tx);
        tx.version = 1;
        struct domain_verdict d = run_domain(&tx, &cp, ACT_OVERWINTER, 70);
        struct legacy_verdict l = run_legacy(&tx, &cp, ACT_OVERWINTER, 70);
        DCS_CHECK("ow active, !flag, ver<3: tx-overwinter-active",
                  !d.ok && d.reason &&
                  strcmp(d.reason, "tx-overwinter-active") == 0);
        DCS_CHECK("ow-active guard: dos=dosLevel(70)", d.dos == 70);
        DCS_CHECK("ow-active guard: verdicts agree", verdicts_match(&d, &l));
        transaction_free(&tx);
    }

    /* --- shape: At Overwinter activation - 1: a sprout-style tx with
     *      flag=true must hit "tx-overwinter-not-active". */
    {
        struct transaction tx;
        build_overwinter_tx(&tx);
        struct domain_verdict d = run_domain(&tx, &cp, ACT_OVERWINTER - 1, 50);
        struct legacy_verdict l = run_legacy(&tx, &cp, ACT_OVERWINTER - 1, 50);
        DCS_CHECK("Overwinter activation-1, overwintered flag: rejects",
                  !d.ok && d.reason &&
                  strcmp(d.reason, "tx-overwinter-not-active") == 0);
        DCS_CHECK("Ow-1 overwintered: verdicts agree", verdicts_match(&d, &l));
        transaction_free(&tx);
    }

    /* --- shape: success path summary - sapling tx at high height accepted */
    {
        struct transaction tx;
        build_sapling_tx(&tx);
        struct domain_verdict d = run_domain(&tx, &cp, ACT_SAPLING + 1000, 100);
        struct legacy_verdict l = run_legacy(&tx, &cp, ACT_SAPLING + 1000, 100);
        DCS_CHECK("sapling tx at high height: accepted", d.ok);
        DCS_CHECK("sapling tx at high height: verdicts agree",
                  verdicts_match(&d, &l));
        transaction_free(&tx);
    }

    return failures;
}

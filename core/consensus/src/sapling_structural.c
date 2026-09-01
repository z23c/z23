/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure height-aware Sapling/Overwinter structural transaction checks.
 *
 * Replays from `tx`, `params`, and `n_height` alone — no UTXO reads,
 * no signature/proof verification, no clock, no RNG, no persistent
 * I/O. transaction_serialize_size() uses a local scratch buffer
 * internally that it frees before returning, so observable purity
 * is preserved.
 *
 * Reject-reason strings are byte-identical to the legacy
 * core/modules/validation/src/contextual_check_tx.c, because they are
 * tx-relay-visible (peers DoS-score us against them). The wrapper
 * in core/modules/validation/ copies these literals into validation_state. */

#include "domain/consensus/sapling_structural.h"

#include "consensus/consensus.h"
#include "consensus/params.h"
#include "primitives/transaction.h"

/* Local helper: stamp the failure-out + return a non-ok zcl_result.
 * Captures __FILE__/__LINE__ via ZCL_ERR. */
#define DOMAIN_SAP_FAIL(out, err_code, reason_lit, dos_score, fmt, ...) \
    do {                                                                \
        if ((out)) {                                                    \
            (out)->reject_reason = (reason_lit);                        \
            (out)->dos = (dos_score);                                   \
        }                                                               \
        return ZCL_ERR((err_code), fmt __VA_OPT__(,) __VA_ARGS__);      \
    } while (0)

struct zcl_result domain_consensus_check_transaction_sapling_structural(
        const struct transaction *tx,
        const struct consensus_params *params,
        int n_height,
        int dos_level,
        struct domain_consensus_sapling_structural_failure *out_failure)
{
    if (out_failure) {
        out_failure->reject_reason = NULL;
        out_failure->dos = 0;
    }

    if (!tx)
        return ZCL_ERR(DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_NULL_TX,
                       "check_transaction_sapling_structural: null tx");
    if (!params)
        return ZCL_ERR(DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_NULL_PARAMS,
                       "check_transaction_sapling_structural: null params");
    if (n_height < 0)
        return ZCL_ERR(DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_NEG_HEIGHT,
                       "check_transaction_sapling_structural: negative height %d",
                       n_height);

    bool overwinterActive = consensus_network_upgrade_active(
        params, n_height, UPGRADE_OVERWINTER);
    bool saplingActive = consensus_network_upgrade_active(
        params, n_height, UPGRADE_SAPLING);
    bool isSprout = !overwinterActive;

    /* ── Network upgrade version rules ──────────────────────── */
    if (isSprout && tx->overwintered)
        DOMAIN_SAP_FAIL(out_failure,
            DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_OVERWINTER_NOT_ACTIVE,
            "tx-overwinter-not-active", dos_level,
            "tx is overwintered but Overwinter not active at height %d",
            n_height);

    if (saplingActive) {
        if (tx->version >= SAPLING_MIN_TX_VERSION && !tx->overwintered)
            DOMAIN_SAP_FAIL(out_failure,
                DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_SAPLING_OVERWINTERED_FLAG,
                "tx-overwintered-flag-not-set", dos_level,
                "Sapling-version tx (version=%d) missing overwintered flag",
                (int)tx->version);

        if (tx->overwintered &&
            tx->version_group_id != SAPLING_VERSION_GROUP_ID)
            DOMAIN_SAP_FAIL(out_failure,
                DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_SAPLING_VERSION_GROUP_ID,
                "bad-sapling-tx-version-group-id", dos_level,
                "overwintered tx version_group_id 0x%08x != SAPLING(0x%08x)",
                (unsigned)tx->version_group_id,
                (unsigned)SAPLING_VERSION_GROUP_ID);

        if (tx->overwintered && tx->version < SAPLING_MIN_TX_VERSION)
            DOMAIN_SAP_FAIL(out_failure,
                DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_SAPLING_VERSION_TOO_LOW,
                "bad-tx-sapling-version-too-low", 100,
                "overwintered tx version %d below SAPLING_MIN_TX_VERSION(%d)",
                (int)tx->version, SAPLING_MIN_TX_VERSION);

        if (tx->overwintered && tx->version > SAPLING_MAX_TX_VERSION)
            DOMAIN_SAP_FAIL(out_failure,
                DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_SAPLING_VERSION_TOO_HIGH,
                "bad-tx-sapling-version-too-high", 100,
                "overwintered tx version %d above SAPLING_MAX_TX_VERSION(%d)",
                (int)tx->version, SAPLING_MAX_TX_VERSION);
    } else if (overwinterActive) {
        if (tx->version >= OVERWINTER_MIN_TX_VERSION && !tx->overwintered)
            DOMAIN_SAP_FAIL(out_failure,
                DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_OVERWINTER_FLAG_NOT_SET,
                "tx-overwinter-flag-not-set", dos_level,
                "Overwinter-version tx (version=%d) missing overwintered flag",
                (int)tx->version);

        if (tx->overwintered &&
            tx->version_group_id != OVERWINTER_VERSION_GROUP_ID)
            DOMAIN_SAP_FAIL(out_failure,
                DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_OVERWINTER_VERSION_GROUP_ID,
                "bad-overwinter-tx-version-group-id", dos_level,
                "overwintered tx version_group_id 0x%08x != OVERWINTER(0x%08x)",
                (unsigned)tx->version_group_id,
                (unsigned)OVERWINTER_VERSION_GROUP_ID);

        if (tx->overwintered && tx->version > OVERWINTER_MAX_TX_VERSION)
            DOMAIN_SAP_FAIL(out_failure,
                DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_OVERWINTER_VERSION_TOO_HIGH,
                "bad-tx-overwinter-version-too-high", 100,
                "overwintered tx version %d above OVERWINTER_MAX_TX_VERSION(%d)",
                (int)tx->version, OVERWINTER_MAX_TX_VERSION);
    }

    /* ── Overwinter "must be overwintered" rule ───────────────
     * Mirrors legacy:
     *   if (overwinterActive) REJECT_IF_DOS(!tx->overwintered, ...,
     *                                       "tx-overwinter-active");
     * Note: legacy applies this *after* the version-group checks above
     * (which already gate on `tx->overwintered &&`), so the ordering
     * matters only for the rare path where overwinterActive is true,
     * Sapling is NOT active, and the tx has version >= OVERWINTER_MIN
     * but the overwintered flag is set: in that path the
     * "tx-overwinter-flag-not-set" check is false (flag IS set), so we
     * fall through and this final guard never fires either — both
     * legacy and domain return ok in step. The asymmetric path
     * (flag-not-set with version < OVERWINTER_MIN) returns
     * "tx-overwinter-active" identically in both implementations. */
    if (overwinterActive && !tx->overwintered)
        DOMAIN_SAP_FAIL(out_failure,
            DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_OVERWINTER_ACTIVE,
            "tx-overwinter-active", dos_level,
            "Overwinter active at height %d but tx not overwintered",
            n_height);

    /* ── Pre-Sapling serialized-size limit ──────────────────── */
    if (!saplingActive) {
        size_t tx_size = transaction_serialize_size(tx);
        if (tx_size > MAX_TX_SIZE_BEFORE_SAPLING)
            DOMAIN_SAP_FAIL(out_failure,
                DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_OVERSIZE,
                "bad-txns-oversize", 100,
                "tx size %zu > MAX_TX_SIZE_BEFORE_SAPLING(%u)",
                tx_size, (unsigned)MAX_TX_SIZE_BEFORE_SAPLING);
    }

    return ZCL_OK;
}

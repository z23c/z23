/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure structural transaction checks. Replays from `tx` alone — no
 * UTXO reads, no signature/proof verification, no clock, no RNG, no
 * persistent I/O. The only allocation is a local scratch stream
 * inside `transaction_serialize_size` (primitives helper); the
 * function returns a size_t and frees its own buffer before return,
 * so observable purity holds.
 *
 * Reject-reason strings are byte-identical to the legacy
 * core/modules/validation/src/check_transaction.c, because they are
 * tx-relay-visible (peers DoS-score us against them). The wrapper
 * in core/modules/validation/ copies these literals into validation_state. */

#include "domain/consensus/tx_structural.h"

#include <string.h>

#include "core/amount.h"
#include "core/uint256.h"
#include "consensus/consensus.h"
#include "primitives/transaction.h"

/* Empirical oversize grandfather table: the 413 canonical post-Sapling txs
 * above MAX_TX_SIZE_AFTER_SAPLING (heights 478544..1968856). Generated +
 * zclassicd-verified; see the header comment inside the .inc and
 * docs/CONSENSUS_PARITY_DOCTRINE.md "Empirical oversize grandfather". */
#include "oversize_grandfather_table.inc"

/* Local helper: stamp the failure-out + return a non-ok zcl_result.
 * Captures __FILE__/__LINE__ via ZCL_ERR, so failures still leave a
 * paper trail even when no debug logger is attached. */
#define DOMAIN_TX_FAIL(out, err_code, reason_lit, dos_score, fmt, ...) \
    do {                                                               \
        if ((out)) {                                                   \
            (out)->reject_reason = (reason_lit);                       \
            (out)->dos = (dos_score);                                  \
        }                                                              \
        return ZCL_ERR((err_code), fmt __VA_OPT__(,) __VA_ARGS__);     \
    } while (0)

struct zcl_result domain_consensus_check_transaction_structural(
        const struct transaction *tx,
        enum domain_tx_check_context ctx,
        struct domain_consensus_tx_structural_failure *out_failure)
{
    if (out_failure) {
        out_failure->reject_reason = NULL;
        out_failure->dos = 0;
    }

    if (!tx)
        return ZCL_ERR(DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_NULL_TX,
                       "check_transaction_structural: null tx");

    /* ── Version checks ─────────────────────────────────────── */
    if (!tx->overwintered && tx->version < SPROUT_MIN_TX_VERSION)
        DOMAIN_TX_FAIL(out_failure,
                       DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_VERSION_TOO_LOW,
                       "bad-txns-version-too-low", 100,
                       "version %d below SPROUT_MIN_TX_VERSION (%d)",
                       (int)tx->version, SPROUT_MIN_TX_VERSION);

    if (tx->overwintered) {
        if (tx->version < OVERWINTER_MIN_TX_VERSION)
            DOMAIN_TX_FAIL(out_failure,
                DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_OVERWINTER_VERSION_TOO_LOW,
                "bad-tx-overwinter-version-too-low", 100,
                "overwintered tx version %d below OVERWINTER_MIN_TX_VERSION (%d)",
                (int)tx->version, OVERWINTER_MIN_TX_VERSION);

        if (tx->version_group_id != OVERWINTER_VERSION_GROUP_ID &&
            tx->version_group_id != SAPLING_VERSION_GROUP_ID)
            DOMAIN_TX_FAIL(out_failure,
                DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_VERSION_GROUP_ID,
                "bad-tx-version-group-id", 100,
                "unknown version_group_id 0x%08x",
                (unsigned)tx->version_group_id);

        if (tx->expiry_height >= TX_EXPIRY_HEIGHT_THRESHOLD)
            DOMAIN_TX_FAIL(out_failure,
                DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_EXPIRY_HEIGHT_TOO_HIGH,
                "bad-tx-expiry-height-too-high", 100,
                "expiry_height %u >= threshold %u",
                (unsigned)tx->expiry_height,
                (unsigned)TX_EXPIRY_HEIGHT_THRESHOLD);
    }

    /* ── Input/output existence ─────────────────────────────── */
    if (tx->num_vin == 0 && tx->num_joinsplit == 0 &&
        tx->num_shielded_spend == 0)
        DOMAIN_TX_FAIL(out_failure,
                       DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_VIN_EMPTY,
                       "bad-txns-vin-empty", 10,
                       "no transparent vin, joinsplit, or shielded spend");

    if (tx->num_vout == 0 && tx->num_joinsplit == 0 &&
        tx->num_shielded_output == 0)
        DOMAIN_TX_FAIL(out_failure,
                       DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_VOUT_EMPTY,
                       "bad-txns-vout-empty", 10,
                       "no transparent vout, joinsplit, or shielded output");

    /* ── Size limit ─────────────────────────────────────────── */
    size_t tx_size = transaction_serialize_size(tx);
    if (tx_size > MAX_TX_SIZE_AFTER_SAPLING) {
        /* Empirical grandfather (zclassicd LIVE-behavior parity): the
         * canonical chain carries 413 post-Sapling txs above 102000
         * (mined when the effective cap was MAX_BLOCK_SIZE; zclassicd
         * tightened the constant later without grandfathering, so its
         * own text false-rejects them on resync — proven at block
         * 478544). Excuse exactly those txs, in-block only, under a
         * hard MAX_BLOCK_SIZE structural ceiling. The txid is
         * recomputed from the serialized bytes — never trust a
         * possibly-stale tx->hash on an accept path. Cold path: fires
         * at most 413 times in a full reindex. */
        bool excused = false;
        if (ctx == DOMAIN_TX_CTX_BLOCK && tx_size <= MAX_BLOCK_SIZE) {
            struct uint256 txid;
            if (transaction_hash_serialized(tx, &txid))
                excused = domain_consensus_tx_oversize_grandfathered(
                                  &txid, tx_size);
        }
        if (!excused)
            DOMAIN_TX_FAIL(out_failure,
                           DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_OVERSIZE,
                           "bad-txns-oversize", 100,
                           "serialize_size %zu > %u",
                           tx_size, (unsigned)MAX_TX_SIZE_AFTER_SAPLING);
    }

    /* ── Output value validation ────────────────────────────── */
    int64_t value_out = 0;
    for (size_t i = 0; i < tx->num_vout; i++) {
        if (tx->vout[i].value < 0)
            DOMAIN_TX_FAIL(out_failure,
                DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_VOUT_NEGATIVE,
                "bad-txns-vout-negative", 100,
                "vout[%zu].value=%lld < 0",
                i, (long long)tx->vout[i].value);

        if (tx->vout[i].value > MAX_MONEY)
            DOMAIN_TX_FAIL(out_failure,
                DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_VOUT_TOOLARGE,
                "bad-txns-vout-toolarge", 100,
                "vout[%zu].value=%lld > MAX_MONEY",
                i, (long long)tx->vout[i].value);

        value_out += tx->vout[i].value;
        if (!MoneyRange(value_out))
            DOMAIN_TX_FAIL(out_failure,
                DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_VOUT_TOTAL_TOOLARGE,
                "bad-txns-txouttotal-toolarge", 100,
                "vout running total %lld out of range after index %zu",
                (long long)value_out, i);
    }

    /* ── Sapling valueBalance ───────────────────────────────── */
    if (tx->num_shielded_spend == 0 && tx->num_shielded_output == 0 &&
        tx->value_balance != 0)
        DOMAIN_TX_FAIL(out_failure,
            DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_VALUEBALANCE_NONZERO,
            "bad-txns-valuebalance-nonzero", 100,
            "value_balance=%lld but no shielded spend/output",
            (long long)tx->value_balance);

    if (tx->value_balance > MAX_MONEY || tx->value_balance < -MAX_MONEY)
        DOMAIN_TX_FAIL(out_failure,
            DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_VALUEBALANCE_TOOLARGE,
            "bad-txns-valuebalance-toolarge", 100,
            "value_balance=%lld outside [-MAX_MONEY, MAX_MONEY]",
            (long long)tx->value_balance);

    /* Negative valueBalance takes from transparent pool */
    if (tx->value_balance <= 0) {
        value_out += -tx->value_balance;
        if (!MoneyRange(value_out))
            DOMAIN_TX_FAIL(out_failure,
                DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_VOUT_TOTAL_TOOLARGE,
                "bad-txns-txouttotal-toolarge", 100,
                "vout total + |value_balance| %lld out of range",
                (long long)value_out);
    }

    /* ── JoinSplit value validation ─────────────────────────── */
    for (size_t i = 0; i < tx->num_joinsplit; i++) {
        const struct js_description *js = &tx->v_joinsplit[i];

        if (js->vpub_old < 0)
            DOMAIN_TX_FAIL(out_failure,
                DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_VPUB_OLD_NEGATIVE,
                "bad-txns-vpub_old-negative", 100,
                "joinsplit[%zu].vpub_old=%lld < 0",
                i, (long long)js->vpub_old);
        if (js->vpub_new < 0)
            DOMAIN_TX_FAIL(out_failure,
                DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_VPUB_NEW_NEGATIVE,
                "bad-txns-vpub_new-negative", 100,
                "joinsplit[%zu].vpub_new=%lld < 0",
                i, (long long)js->vpub_new);
        if (js->vpub_old > MAX_MONEY)
            DOMAIN_TX_FAIL(out_failure,
                DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_VPUB_OLD_TOOLARGE,
                "bad-txns-vpub_old-toolarge", 100,
                "joinsplit[%zu].vpub_old=%lld > MAX_MONEY",
                i, (long long)js->vpub_old);
        if (js->vpub_new > MAX_MONEY)
            DOMAIN_TX_FAIL(out_failure,
                DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_VPUB_NEW_TOOLARGE,
                "bad-txns-vpub_new-toolarge", 100,
                "joinsplit[%zu].vpub_new=%lld > MAX_MONEY",
                i, (long long)js->vpub_new);
        if (js->vpub_new != 0 && js->vpub_old != 0)
            DOMAIN_TX_FAIL(out_failure,
                DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_VPUBS_BOTH_NONZERO,
                "bad-txns-vpubs-both-nonzero", 100,
                "joinsplit[%zu] both vpub_old and vpub_new nonzero", i);

        value_out += js->vpub_old;
        if (!MoneyRange(value_out))
            DOMAIN_TX_FAIL(out_failure,
                DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_VOUT_TOTAL_TOOLARGE,
                "bad-txns-txouttotal-toolarge", 100,
                "vout total + vpub_old running %lld out of range after js %zu",
                (long long)value_out, i);
    }

    /* ── Input value overflow check ─────────────────────────── */
    {
        int64_t value_in = 0;
        for (size_t i = 0; i < tx->num_joinsplit; i++) {
            value_in += tx->v_joinsplit[i].vpub_new;
            if (!MoneyRange(tx->v_joinsplit[i].vpub_new) ||
                !MoneyRange(value_in))
                DOMAIN_TX_FAIL(out_failure,
                    DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_TXINTOTAL_TOOLARGE,
                    "bad-txns-txintotal-toolarge", 100,
                    "vpub_new running total %lld out of range after js %zu",
                    (long long)value_in, i);
        }
        if (tx->value_balance >= 0) {
            value_in += tx->value_balance;
            if (!MoneyRange(value_in))
                DOMAIN_TX_FAIL(out_failure,
                    DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_TXINTOTAL_TOOLARGE,
                    "bad-txns-txintotal-toolarge", 100,
                    "vin total + value_balance %lld out of range",
                    (long long)value_in);
        }
    }

    /* ── Duplicate transparent inputs ───────────────────────── */
    for (size_t i = 0; i < tx->num_vin; i++) {
        for (size_t j = i + 1; j < tx->num_vin; j++) {
            if (outpoint_cmp(&tx->vin[i].prevout,
                             &tx->vin[j].prevout) == 0)
                DOMAIN_TX_FAIL(out_failure,
                    DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_INPUTS_DUPLICATE,
                    "bad-txns-inputs-duplicate", 100,
                    "vin[%zu] and vin[%zu] share prevout", i, j);
        }
    }

    /* ── Duplicate JoinSplit nullifiers ──────────────────────── */
    for (size_t i = 0; i < tx->num_joinsplit; i++) {
        for (int ni = 0; ni < ZC_NUM_JS_INPUTS; ni++) {
            const struct uint256 *nf = &tx->v_joinsplit[i].nullifiers[ni];
            for (size_t j = 0; j < i; j++) {
                for (int nj = 0; nj < ZC_NUM_JS_INPUTS; nj++) {
                    if (uint256_cmp(nf,
                                    &tx->v_joinsplit[j].nullifiers[nj]) == 0)
                        DOMAIN_TX_FAIL(out_failure,
                            DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_JS_NULLIFIERS_DUPLICATE,
                            "bad-joinsplits-nullifiers-duplicate", 100,
                            "joinsplit[%zu].nullifier[%d] duplicates joinsplit[%zu].nullifier[%d]",
                            i, ni, j, nj);
                }
            }
            for (int nj = 0; nj < ni; nj++) {
                if (uint256_cmp(nf,
                                &tx->v_joinsplit[i].nullifiers[nj]) == 0)
                    DOMAIN_TX_FAIL(out_failure,
                        DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_JS_NULLIFIERS_DUPLICATE,
                        "bad-joinsplits-nullifiers-duplicate", 100,
                        "joinsplit[%zu] nullifier[%d] duplicates nullifier[%d]",
                        i, ni, nj);
            }
        }
    }

    /* ── Duplicate Sapling nullifiers ───────────────────────── */
    for (size_t i = 0; i < tx->num_shielded_spend; i++) {
        for (size_t j = i + 1; j < tx->num_shielded_spend; j++) {
            if (uint256_cmp(&tx->v_shielded_spend[i].nullifier,
                            &tx->v_shielded_spend[j].nullifier) == 0)
                DOMAIN_TX_FAIL(out_failure,
                    DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_SPEND_NULLIFIERS_DUPLICATE,
                    "bad-spend-description-nullifiers-duplicate", 100,
                    "shielded_spend[%zu] and shielded_spend[%zu] share nullifier",
                    i, j);
        }
    }

    /* ── Coinbase restrictions ──────────────────────────────── */
    if (transaction_is_coinbase(tx)) {
        if (tx->num_joinsplit > 0)
            DOMAIN_TX_FAIL(out_failure,
                DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_CB_HAS_JOINSPLITS,
                "bad-cb-has-joinsplits", 100,
                "coinbase has %zu joinsplits", tx->num_joinsplit);
        if (tx->num_shielded_spend > 0)
            DOMAIN_TX_FAIL(out_failure,
                DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_CB_HAS_SPEND_DESC,
                "bad-cb-has-spend-description", 100,
                "coinbase has %zu shielded spends", tx->num_shielded_spend);
        if (tx->num_shielded_output > 0)
            DOMAIN_TX_FAIL(out_failure,
                DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_CB_HAS_OUTPUT_DESC,
                "bad-cb-has-output-description", 100,
                "coinbase has %zu shielded outputs", tx->num_shielded_output);
        if (tx->vin[0].script_sig.size < 2 ||
            tx->vin[0].script_sig.size > 100)
            DOMAIN_TX_FAIL(out_failure,
                DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_CB_LENGTH,
                "bad-cb-length", 100,
                "coinbase scriptSig size %zu outside [2, 100]",
                tx->vin[0].script_sig.size);
    } else {
        /* Non-coinbase: no null prevouts */
        for (size_t i = 0; i < tx->num_vin; i++) {
            if (outpoint_is_null(&tx->vin[i].prevout))
                DOMAIN_TX_FAIL(out_failure,
                    DOMAIN_CONSENSUS_TX_STRUCTURAL_ERR_PREVOUT_NULL,
                    "bad-txns-prevout-null", 10,
                    "non-coinbase vin[%zu] has null prevout", i);
        }
    }

    return ZCL_OK;
}

bool domain_consensus_tx_oversize_grandfathered(const struct uint256 *txid,
                                                size_t tx_size)
{
    if (!txid)
        return false;
    size_t lo = 0, hi = OVERSIZE_GRANDFATHER_COUNT;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = memcmp(txid->data, g_oversize_grandfather[mid].txid, 32);
        if (c == 0)
            return tx_size == (size_t)g_oversize_grandfather[mid].size;
        if (c < 0) hi = mid;
        else       lo = mid + 1;
    }
    return false;
}

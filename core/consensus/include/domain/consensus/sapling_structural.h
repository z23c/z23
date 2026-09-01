/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * domain/consensus/sapling_structural.h — pure height-aware Sapling /
 * Overwinter structural transaction checks.
 *
 * These checks mirror the PURE branches of legacy
 * core/modules/validation/src/contextual_check_tx.c — the branches that depend
 * only on the transaction fields themselves plus the activation
 * height supplied by the caller (looked up against
 * consensus_params->vUpgrades). They do NOT verify any zk-SNARK
 * proof, JoinSplit Ed25519 signature, Sapling binding signature, or
 * Sprout PHGR13/Groth16 proof — those crypto checks remain in the
 * lib/ wrapper (see contextual_check_transaction()).
 *
 * Scope of "structural" extracted here:
 *   1. pre-Overwinter: tx->overwintered MUST be false
 *   2. Overwinter active: tx->overwintered MUST be true
 *   3. Sapling active: tx version/version_group_id/Sapling version rules
 *   4. Overwinter active (no Sapling): version/version_group_id rules
 *   5. pre-Sapling serialized-size cap (MAX_TX_SIZE_BEFORE_SAPLING)
 *
 * What is NOT here (deliberately left in the lib wrapper):
 *   - tx-overwinter-expired (uses domain_consensus_tx_is_expired)
 *   - JoinSplit Ed25519 signature verification     (crypto)
 *   - Sapling Groth16 spend/output proofs           (crypto)
 *   - Sapling binding signature                     (crypto)
 *   - Sprout Groth16 / PHGR13 JoinSplit proofs      (crypto)
 *   - sighash computation                           (crypto helper)
 *
 * Purity contract:
 *   - No clock, no RNG, no I/O, no global state read or write.
 *   - No allocation. transaction_serialize_size() does allocate a
 *     local scratch buffer internally and frees it before returning,
 *     so observable purity is preserved (mirrors tx_structural.{c,h}).
 *   - Same inputs → same outputs, every call.
 *
 * Reject reasons emitted by these functions are byte-identical to the
 * P2P-visible strings legacy callers produce. They MUST NOT change —
 * peers DoS-score us against them.
 *
 * Layering: domain/consensus/ may #include from util/, core/,
 * consensus/, primitives/.
 */

#ifndef ZCL_DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_H
#define ZCL_DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_H

#include <stdbool.h>
#include <stdint.h>

#include "consensus/params.h"
#include "util/result.h"

struct transaction;

/* On a structural rejection we hand the caller the *exact* legacy
 * (reason, dos) pair so the wrapper can populate `validation_state`
 * byte-identically. The reject_reason is a pointer into a static
 * string literal (never owned, never freed). */
struct domain_consensus_sapling_structural_failure {
    const char *reject_reason;  /* e.g. "tx-overwinter-not-active"; static literal */
    int         dos;            /* legacy DoS score (often the caller-supplied dosLevel) */
};

/* Run all context-aware Sapling/Overwinter structural checks against
 * `tx` at height `n_height` against `params`. The `dos_level` argument
 * is the caller-supplied DoS score used for the "soft" relay-DoS
 * rejections (version-group/overwintered flag mismatches); the "hard"
 * rejections (bad-tx-sapling-version-too-{low,high}, bad-tx-overwinter-
 * version-too-high, bad-txns-oversize) always use DoS=100.
 *
 * On success returns ZCL_OK; if `out_failure` is non-NULL it is
 * zeroed (reject_reason=NULL, dos=0).
 *
 * On the first structural failure returns a non-ok zcl_result whose
 * .code is one of `enum domain_consensus_sapling_structural_err` and
 * whose .message is a printf-formatted explanation. If `out_failure`
 * is non-NULL its `reject_reason` and `dos` fields are populated so
 * the caller can mirror the legacy validation_state semantics
 * verbatim.
 *
 * Pre-conditions:
 *   - tx     != NULL  (else returns ERR_NULL_TX)
 *   - params != NULL  (else returns ERR_NULL_PARAMS)
 *   - n_height >= 0   (else returns ERR_NEG_HEIGHT)
 */
struct zcl_result domain_consensus_check_transaction_sapling_structural(
        const struct transaction *tx,
        const struct consensus_params *params,
        int n_height,
        int dos_level,
        struct domain_consensus_sapling_structural_failure *out_failure);

/* Error codes used by domain/consensus/sapling_structural.{c,h}.
 * Stable across builds; new codes are appended. Returned via
 * zcl_result.code.
 *
 * Codes 1501..1510 cover the 1:1 mapping to the legacy reject_reason
 * tags. The contract-only codes 1500..1502 are for pre-condition
 * violations. */
enum domain_consensus_sapling_structural_err {
    DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_NULL_TX                       = 1500,
    DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_NULL_PARAMS                   = 1501,
    DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_NEG_HEIGHT                    = 1502,

    /* pre-Overwinter: overwintered flag must NOT be set */
    DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_OVERWINTER_NOT_ACTIVE         = 1503,

    /* Sapling active: tx version >= SAPLING_MIN_TX_VERSION but
     * overwintered flag not set */
    DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_SAPLING_OVERWINTERED_FLAG     = 1504,
    /* Sapling active: overwintered tx with wrong version_group_id */
    DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_SAPLING_VERSION_GROUP_ID      = 1505,
    /* Sapling active: overwintered tx with version below Sapling min */
    DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_SAPLING_VERSION_TOO_LOW       = 1506,
    /* Sapling active: overwintered tx with version above Sapling max */
    DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_SAPLING_VERSION_TOO_HIGH      = 1507,

    /* Overwinter active (no Sapling): tx version >= OVERWINTER_MIN_TX_VERSION
     * but overwintered flag not set */
    DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_OVERWINTER_FLAG_NOT_SET       = 1508,
    /* Overwinter active (no Sapling): overwintered tx with wrong
     * version_group_id */
    DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_OVERWINTER_VERSION_GROUP_ID   = 1509,
    /* Overwinter active (no Sapling): overwintered tx with version
     * above Overwinter max */
    DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_OVERWINTER_VERSION_TOO_HIGH   = 1510,

    /* Overwinter active: tx MUST be overwintered */
    DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_OVERWINTER_ACTIVE             = 1511,

    /* pre-Sapling: serialized tx size exceeds MAX_TX_SIZE_BEFORE_SAPLING */
    DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_ERR_OVERSIZE                      = 1512,
};

#endif /* ZCL_DOMAIN_CONSENSUS_SAPLING_STRUCTURAL_H */

/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Root-addressed signed test observations and local admission. */
#ifndef ZCL_DEV_PROOF_OBSERVATION_H
#define ZCL_DEV_PROOF_OBSERVATION_H

#include "dev_proof_receipt.h"

enum zcl_dev_observation_verdict {
    ZCL_DEV_OBSERVATION_MISSING = 0,
    ZCL_DEV_OBSERVATION_PASS,
    ZCL_DEV_OBSERVATION_FAIL,
    ZCL_DEV_OBSERVATION_CONFLICT,
};

/* Records one actual runner outcome. The caller supplies a complete input
 * key, canonical group, and fresh execution result. No key means no leaf. */
bool zcl_dev_observation_record(const char *store_root,
    const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES], const char *group,
    enum zcl_dev_verdict_leaf_verdict verdict, uint64_t elapsed_ms,
    uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES], char *why, size_t why_len);

/* Admit an explicit required root set. Invalid signatures and wrong-key/group
 * leaves are ineligible, not vetoes. An absent addressed object or an
 * eligible PASS/FAIL contradiction refuses. This does not claim that the
 * supplied root set is complete; proof-set coverage must establish that. */
enum zcl_dev_observation_verdict zcl_dev_observation_admit(
    const char *store_root,
    const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES], const char *group,
    const uint8_t (*roots)[ZCL_DEV_PROOF_ROOT_BYTES], size_t n_roots,
    size_t *ineligible, char *why, size_t why_len);

/* Classify the proposed roots together with the receiver's independently
 * retained roots for this key. A proposer cannot suppress a known eligible
 * contradiction by omitting it. The caller must obtain known_roots from its
 * own complete index; this API does not establish index completeness. */
enum zcl_dev_observation_verdict zcl_dev_observation_admit_known(
    const char *store_root,
    const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES], const char *group,
    const uint8_t (*proposed_roots)[ZCL_DEV_PROOF_ROOT_BYTES],
    size_t n_proposed,
    const uint8_t (*known_roots)[ZCL_DEV_PROOF_ROOT_BYTES], size_t n_known,
    size_t *ineligible, char *why, size_t why_len);

#endif

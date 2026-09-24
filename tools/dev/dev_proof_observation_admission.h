/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Receiver-known observation admission without runner-header churn. */
#ifndef ZCL_DEV_PROOF_OBSERVATION_ADMISSION_H
#define ZCL_DEV_PROOF_OBSERVATION_ADMISSION_H

#include "dev_proof_observation.h"

/* Classify proposed roots with the receiver's independently retained roots.
 * A proposer cannot suppress a known eligible contradiction by omitting it.
 * The caller must obtain known_roots from its own complete index; this API
 * does not establish index completeness. */
enum zcl_dev_observation_verdict zcl_dev_observation_admit_known(
    const char *store_root,
    const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES], const char *group,
    const uint8_t (*proposed_roots)[ZCL_DEV_PROOF_ROOT_BYTES],
    size_t n_proposed,
    const uint8_t (*known_roots)[ZCL_DEV_PROOF_ROOT_BYTES], size_t n_known,
    size_t *ineligible, char *why, size_t why_len);

#endif

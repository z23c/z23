/* purpose: Authenticate a checked Ironwood bundle with trusted consensus context. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_VALIDATION_IRONWOOD_BUNDLE_AUTH_H
#define Z23_VALIDATION_IRONWOOD_BUNDLE_AUTH_H

#include "primitives/transaction_v6_sighash.h"
#include "util/result.h"

struct ironwood_verification_setup;

/* Require the checked transaction and its owned wire, the expected consensus
 * branch, ordered authenticated transparent prevouts, and the exact resident
 * verification setup. Verify the Ironwood proof, every spend authorization,
 * and the binding signature against one ZIP-244 sighash. Success does not
 * authorize admission: structural, activation, other-pool, value, anchor,
 * nullifier, and chain-state checks remain mandatory. */
struct zcl_result ironwood_bundle_authenticate_checked(
    const struct transaction *tx, uint32_t expected_branch_id,
    const struct transaction_v6_prevout *prevouts, size_t prevout_count,
    const struct ironwood_verification_setup *setup);

#endif

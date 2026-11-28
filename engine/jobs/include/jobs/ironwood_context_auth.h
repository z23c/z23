/* purpose: Verify a bounded private Ironwood authorization subset. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_CONTEXT_AUTH_H
#define ZCL_IRONWOOD_CONTEXT_AUTH_H
#include "jobs/utxo_apply_stage.h"
#include <stdint.h>
struct transaction;
/* All results other than COMPONENTS_OK require a hold; none establishes a
 * consensus rejection. Even COMPONENTS_OK is not transaction acceptance: the
 * caller must separately bind the authenticated release and branch, verify
 * block auth-data commitment, anchors, nullifiers, values and all other
 * contextual rules. The live resolver must be a stable, authenticated coin
 * view of the candidate parent for the duration of this call. */
enum ironwood_context_auth_result {
    IRONWOOD_CONTEXT_COMPONENTS_OK,
    IRONWOOD_CONTEXT_UNSUPPORTED,
    IRONWOOD_CONTEXT_PREVOUT_UNAVAILABLE,
    IRONWOOD_CONTEXT_CHECK_UNAVAILABLE,
};
/* expected_branch comes from trusted chain context, never from wire bytes.
 * Supports only non-coinbase private-profile v6 transactions with zero or one
 * transparent input, an Ironwood bundle and no Sapling or Orchard bundle.
 * The trusted caller must supply the applicable script flags, including P2SH
 * and CHECKLOCKTIMEVERIFY; omitted required flags hold. A transparent input
 * must spend an exact P2PKH output. Other shapes hold;
 * they are not rejected. Input transaction and coin view remain unchanged. */
enum ironwood_context_auth_result ironwood_context_authenticate(
    const struct transaction *tx, uint32_t expected_branch, unsigned int script_flags,
    utxo_apply_lookup_fn resolve, void *resolve_user);
#endif

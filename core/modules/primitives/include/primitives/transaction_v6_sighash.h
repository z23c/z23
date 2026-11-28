/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Compute ZIP 244 signature hashes from checked v6 transactions.
 */
#ifndef Z23_TRANSACTION_V6_SIGHASH_H
#define Z23_TRANSACTION_V6_SIGHASH_H

#include "primitives/transaction.h"
#include "script/sighashtype.h"

#ifndef NOT_AN_INPUT
#define NOT_AN_INPUT UINT32_MAX
#endif

struct transaction_v6_prevout {
    int64_t amount;
    const uint8_t *script;
    size_t script_size;
};

/* Prevouts supply every transparent input's amount and scriptPubKey when
 * Amounts must satisfy MoneyRange and scripts must satisfy MAX_SCRIPT_SIZE.
 * ANYONECANPAY is absent. script_code and amount describe the signed input.
 * NOT_AN_INPUT is the shielded SIGHASH_ALL form. The checked header branch
 * must equal consensus_branch_id. No signature or proof validity is implied. */
bool transaction_v6_sighash(const struct transaction *tx,
    const struct transaction_v6_prevout *prevouts, size_t prevout_count,
    unsigned int n_in, struct sighash_type hash_type,
    const struct script *script_code, int64_t amount,
    uint32_t consensus_branch_id, struct uint256 *result);

#endif

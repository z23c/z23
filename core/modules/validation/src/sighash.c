/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright (c) 2014-2017 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Epoch-I thin wrapper. The pure signature-hash computation lives in
 * domain/consensus/sighash.{h,c}; this file preserves the existing
 * validation/sighash.h API (struct precomputed_tx_data, enum
 * sig_version, precompute_tx_data, signature_hash_version,
 * signature_hash) so every caller stays unchanged while the new
 * domain function is the single source of truth. */

#include "validation/sighash.h"
#include "domain/consensus/sighash.h"

#include <stddef.h>
#include <string.h>

/* The legacy struct precomputed_tx_data and the domain struct have
 * the same six uint256 fields in the same order. We compile-time
 * assert that on every platform so the cache memcpy below is sound. */
_Static_assert(sizeof(struct precomputed_tx_data) ==
                   sizeof(struct domain_consensus_precomputed_tx_data),
               "precomputed_tx_data layout must match domain mirror");
_Static_assert(offsetof(struct precomputed_tx_data, hash_prevouts) ==
                   offsetof(struct domain_consensus_precomputed_tx_data, hash_prevouts),
               "hash_prevouts offset mismatch");
_Static_assert(offsetof(struct precomputed_tx_data, hash_sequence) ==
                   offsetof(struct domain_consensus_precomputed_tx_data, hash_sequence),
               "hash_sequence offset mismatch");
_Static_assert(offsetof(struct precomputed_tx_data, hash_outputs) ==
                   offsetof(struct domain_consensus_precomputed_tx_data, hash_outputs),
               "hash_outputs offset mismatch");
_Static_assert(offsetof(struct precomputed_tx_data, hash_joinsplits) ==
                   offsetof(struct domain_consensus_precomputed_tx_data, hash_joinsplits),
               "hash_joinsplits offset mismatch");
_Static_assert(offsetof(struct precomputed_tx_data, hash_shielded_spends) ==
                   offsetof(struct domain_consensus_precomputed_tx_data, hash_shielded_spends),
               "hash_shielded_spends offset mismatch");
_Static_assert(offsetof(struct precomputed_tx_data, hash_shielded_outputs) ==
                   offsetof(struct domain_consensus_precomputed_tx_data, hash_shielded_outputs),
               "hash_shielded_outputs offset mismatch");

/* The legacy enum sig_version mirrors the domain enum value-for-value;
 * pin it with static asserts so a future renumbering can't silently
 * desynchronize. */
_Static_assert((int)SIGVERSION_SPROUT     == (int)DOMAIN_CONSENSUS_SIGVERSION_SPROUT,
               "SIGVERSION_SPROUT must match domain mirror");
_Static_assert((int)SIGVERSION_OVERWINTER == (int)DOMAIN_CONSENSUS_SIGVERSION_OVERWINTER,
               "SIGVERSION_OVERWINTER must match domain mirror");
_Static_assert((int)SIGVERSION_SAPLING    == (int)DOMAIN_CONSENSUS_SIGVERSION_SAPLING,
               "SIGVERSION_SAPLING must match domain mirror");

void precompute_tx_data(const struct transaction *tx,
                        struct precomputed_tx_data *out)
{
    domain_consensus_precompute_tx_data(
        tx,
        (struct domain_consensus_precomputed_tx_data *)out);
}

enum sig_version signature_hash_version(const struct transaction *tx)
{
    return (enum sig_version)domain_consensus_signature_hash_version(tx);
}

bool signature_hash(const struct script *script_code,
                    const struct transaction *tx,
                    unsigned int nIn,
                    struct sighash_type hash_type,
                    int64_t amount,
                    uint32_t consensus_branch_id,
                    const struct precomputed_tx_data *cache,
                    struct uint256 *result)
{
    return domain_consensus_signature_hash(
        script_code, tx, nIn, hash_type, amount, consensus_branch_id,
        (const struct domain_consensus_precomputed_tx_data *)cache,
        result);
}

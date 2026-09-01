/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright (c) 2014-2017 The Zcash developers
 * Copyright 2026 Rhett Creighton
 *
 * domain/consensus/sighash.h — pure transaction signature-hash computation.
 *
 * The signature hash is a pure function of (transaction, input index,
 * hash_type, amount, consensus_branch_id, optional precomputed cache).
 * It is the canonical message that a signature commits to:
 *
 *   - Sprout: legacy double-SHA-256 over a transaction-signature
 *     serialization (Bitcoin-style with JoinSplit data appended).
 *   - Overwinter: ZIP-143 BLAKE2b-256 with a per-branch personalization.
 *   - Sapling:    ZIP-243 BLAKE2b-256 with a per-branch personalization,
 *     including shielded-spend / shielded-output digests.
 *
 * No clock, no RNG, no I/O, no UTXO lookups. The function reads only
 * the supplied transaction, script, and scalar arguments; it writes
 * exactly 32 bytes to *result on success. Replays bit-for-bit from
 * inputs alone.
 *
 * Layering: domain/consensus/ may #include from util/, core/, chain/,
 * consensus/, crypto/, sapling/, script/, primitives/. The fact this
 * function depends only on transaction/script/sighash-type/uint256
 * primitives + crypto/blake2b + core/hash + core/serialize is what
 * makes it eligible to live here.
 */

#ifndef ZCL_DOMAIN_CONSENSUS_SIGHASH_H
#define ZCL_DOMAIN_CONSENSUS_SIGHASH_H

#include <stdbool.h>
#include <stdint.h>

#include "core/uint256.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/sighashtype.h"

#ifndef NOT_AN_INPUT
#define NOT_AN_INPUT UINT32_MAX
#endif

enum domain_consensus_sig_version {
    DOMAIN_CONSENSUS_SIGVERSION_SPROUT,
    DOMAIN_CONSENSUS_SIGVERSION_OVERWINTER,
    DOMAIN_CONSENSUS_SIGVERSION_SAPLING,
};

/* Precomputed mid-state used by the ZIP-143/ZIP-243 sighashes. Each
 * field is a 32-byte BLAKE2b digest over a structural component of
 * the transaction, with a Zcash-specific personalization. Building
 * these once per transaction lets every input signature reuse them
 * instead of re-serializing the whole tx for every input. */
struct domain_consensus_precomputed_tx_data {
    struct uint256 hash_prevouts;
    struct uint256 hash_sequence;
    struct uint256 hash_outputs;
    struct uint256 hash_joinsplits;
    struct uint256 hash_shielded_spends;
    struct uint256 hash_shielded_outputs;
};

/* Compute every cached digest from the transaction. Pure. */
void domain_consensus_precompute_tx_data(
        const struct transaction *tx,
        struct domain_consensus_precomputed_tx_data *out);

/* Resolve the on-wire signature-hash version implied by the
 * transaction (overwintered? sapling group id?). Pure. */
enum domain_consensus_sig_version
domain_consensus_signature_hash_version(const struct transaction *tx);

/* Compute the 32-byte signature hash for input n_in under hash_type.
 *
 *   script_code          spend-script being committed to (varint-prefixed
 *                        in Overwinter/Sapling; substituted for the
 *                        signed input's scriptSig in Sprout).
 *   tx                   transaction being signed.
 *   n_in                 input index, or NOT_AN_INPUT for the JoinSplit
 *                        signature hash (no per-input commitment).
 *   hash_type            SIGHASH_{ALL,NONE,SINGLE} | optional ANYONECANPAY.
 *   amount               value (satoshis) of the prevout being signed,
 *                        used by Overwinter/Sapling personalization.
 *   consensus_branch_id  network-upgrade branch id, mixed into the
 *                        BLAKE2b personalization for Overwinter/Sapling.
 *   cache                optional precomputed mid-state. Pass NULL to
 *                        force per-call recomputation (slower but bit-
 *                        for-bit identical).
 *   result               32-byte output. Untouched on failure.
 *
 * Returns true on success. Returns false on contract violation
 * (n_in out of range while n_in != NOT_AN_INPUT, or SIGHASH_SINGLE
 * with n_in >= num_vout in the Sprout regime). The Sprout
 * SIGHASH_SINGLE reject matches zclassicd bug-for-bug (interpreter.cpp
 * :1158-1163 throws logic_error — no Bitcoin uint256(1) sentinel —
 * and CheckSig :1197-1202 catches → false → OP_CHECKSIG pushes false);
 * substituting the sentinel here would fork the chain. On failure a
 * diagnostic is written to stderr in the domain "sighash" via LOG_FAIL
 * — the domain layer remains pure (no allocator, no I/O state, no
 * clock).
 *
 * Bit-for-bit equivalent to validation/sighash.h:signature_hash and
 * pinned by tests/harness/src/test_domain_consensus_sighash.c. */
bool domain_consensus_signature_hash(
        const struct script *script_code,
        const struct transaction *tx,
        unsigned int n_in,
        struct sighash_type hash_type,
        int64_t amount,
        uint32_t consensus_branch_id,
        const struct domain_consensus_precomputed_tx_data *cache,
        struct uint256 *result);

#endif /* ZCL_DOMAIN_CONSENSUS_SIGHASH_H */

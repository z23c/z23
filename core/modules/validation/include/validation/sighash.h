/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_SIGHASH_H
#define ZCL_SIGHASH_H

#include "primitives/transaction.h"
#include "script/script.h"
#include "script/sighashtype.h"
#include "core/uint256.h"
#include <stdbool.h>
#include <stdint.h>

#define NOT_AN_INPUT UINT32_MAX

enum sig_version {
    SIGVERSION_SPROUT,
    SIGVERSION_OVERWINTER,
    SIGVERSION_SAPLING
};

struct precomputed_tx_data {
    struct uint256 hash_prevouts;
    struct uint256 hash_sequence;
    struct uint256 hash_outputs;
    struct uint256 hash_joinsplits;
    struct uint256 hash_shielded_spends;
    struct uint256 hash_shielded_outputs;
};

void precompute_tx_data(const struct transaction *tx,
                        struct precomputed_tx_data *out);

enum sig_version signature_hash_version(const struct transaction *tx);

bool signature_hash(const struct script *script_code,
                    const struct transaction *tx,
                    unsigned int nIn,
                    struct sighash_type hash_type,
                    int64_t amount,
                    uint32_t consensus_branch_id,
                    const struct precomputed_tx_data *cache,
                    struct uint256 *result);

#endif

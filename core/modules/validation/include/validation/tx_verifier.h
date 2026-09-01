/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_TX_VERIFIER_H
#define ZCL_TX_VERIFIER_H

#include "primitives/transaction.h"
#include "keys/pubkey.h"
#include "script/interpreter.h"
#include "validation/sighash.h"
#include <stdbool.h>
#include <stdint.h>

#define LOCKTIME_THRESHOLD 500000000

struct tx_sig_checker {
    const struct transaction *tx;
    unsigned int nIn;
    int64_t amount;
    uint32_t consensus_branch_id;
    const struct precomputed_tx_data *txdata;
};

void tx_sig_checker_init(struct tx_sig_checker *c,
                         const struct transaction *tx,
                         unsigned int nIn,
                         int64_t amount,
                         uint32_t consensus_branch_id,
                         const struct precomputed_tx_data *txdata);

bool tx_sig_checker_check_sig(const struct tx_sig_checker *c,
                              const unsigned char *sig, size_t siglen,
                              const unsigned char *pubkey, size_t pubkeylen,
                              const struct script *script_code);

bool tx_sig_checker_check_lock_time(const struct tx_sig_checker *c,
                                    int64_t lock_time);

struct sig_checker tx_make_sig_checker(struct tx_sig_checker *c);

#endif

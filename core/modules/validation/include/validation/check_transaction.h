/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_CHECK_TRANSACTION_H
#define ZCL_CHECK_TRANSACTION_H

#include "consensus/validation.h"
#include "primitives/transaction.h"
#include <stdbool.h>

/* Context-free structural validation for a STANDALONE transaction
 * (mempool/relay). Strict zclassicd parity: the post-Sapling 102000 size
 * cap applies unconditionally, exactly like zclassicd's
 * AcceptToMemoryPool -> CheckTransaction. */
bool check_transaction(const struct transaction *tx,
                       struct validation_state *state);

/* Identical to check_transaction() except the empirical oversize
 * grandfather is consulted (domain/consensus/tx_structural.h): the 413
 * canonical post-Sapling txs above 102000 (heights 478544..1968856) are
 * accepted, matching zclassicd's LIVE behavior (it never re-checks blocks
 * it already validated, and its own text cannot resync them). Use ONLY for
 * transactions inside a block being validated. */
bool check_transaction_in_block(const struct transaction *tx,
                                struct validation_state *state);

#endif

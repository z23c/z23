/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_SIGOPS_H
#define ZCL_SIGOPS_H

#include "primitives/transaction.h"
#include <stdint.h>

struct coins_view_cache;

uint64_t get_legacy_sig_op_count(const struct transaction *tx, uint32_t flags);

/* Sum of sigops contributed by P2SH redeem scripts for every non-coinbase
 * input in `tx`, resolving prevouts through `view`.  Mirrors zclassicd
 * src/main.cpp::GetP2SHSigOpCount.  Returns 0 for coinbase txs and when
 * the SCRIPT_VERIFY_P2SH flag is not set in `flags`.  No per-input cap is
 * applied (the 15-sigop `MAX_P2SH_SIGOPS` cap is a standardness/policy
 * rule, not consensus).  The total is added to the legacy count before
 * the MAX_BLOCK_SIGOPS consensus limit is checked. */
uint64_t get_p2sh_sig_op_count(const struct transaction *tx,
                                struct coins_view_cache *view,
                                uint32_t flags);

#endif

/* Copyright (c) 2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_CHAINPARAMSBASE_H
#define BITCOIN_CHAINPARAMSBASE_H

#include <stdbool.h>

/* Length of the per-network message-start magic (pchMessageStart). Defined
 * here — co-located with the chain params that own pchMessageStart — so
 * chain/chainparams.h no longer has to reach up into net/protocol.h purely for
 * this array dimension (which broke the sealed-core include boundary). net's
 * own net/protocol.h keeps an identical `#define MESSAGE_START_SIZE 4` for its
 * many P2P consumers; a TU that includes both sees a benign identical macro
 * redefinition (C17 6.10.3p2 — same replacement list, no diagnostic). */
#ifndef MESSAGE_START_SIZE
#define MESSAGE_START_SIZE 4
#endif

enum chain_network {
    CHAIN_MAIN,
    CHAIN_TESTNET,
    CHAIN_REGTEST,
    CHAIN_MAX_NETWORK_TYPES
};

struct base_chain_params {
    int nRPCPort;
    const char *strDataDir;
};

const struct base_chain_params *BaseParams(void);
void SelectBaseParams(enum chain_network network);
bool AreBaseParamsConfigured(void);
const struct base_chain_params *ResearchBaseParams(void);
void SelectResearchBaseParams(void);

#endif

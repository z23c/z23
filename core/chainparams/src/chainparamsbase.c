/* Copyright (c) 2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "chain/chainparamsbase.h"
#include "util/log_macros.h"
#include <assert.h>
#include <stddef.h>

static struct base_chain_params mainParams = { 8023, "" };
static struct base_chain_params testNetParams = { 18023, "testnet3" };
static struct base_chain_params regTestParams = { 18023, "regtest" };

static struct base_chain_params researchParams = { 28023, "ironwood-research" };

static const struct base_chain_params *pCurrentBaseParams = NULL;

const struct base_chain_params *BaseParams(void)
{
    assert(pCurrentBaseParams);
    return pCurrentBaseParams;
}

void SelectBaseParams(enum chain_network network)
{
    switch (network) {
    case CHAIN_MAIN:
        pCurrentBaseParams = &mainParams;
        break;
    case CHAIN_TESTNET:
        pCurrentBaseParams = &testNetParams;
        break;
    case CHAIN_REGTEST:
        pCurrentBaseParams = &regTestParams;
        break;
    default:
        assert(0 && "Unimplemented network");
        return;
    }
}

const struct base_chain_params *ResearchBaseParams(void)
{
    return &researchParams;
}

void SelectResearchBaseParams(void)
{
    pCurrentBaseParams = &researchParams;
}

bool AreBaseParamsConfigured(void)
{
    return pCurrentBaseParams != NULL;
}

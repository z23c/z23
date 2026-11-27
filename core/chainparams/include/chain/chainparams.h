/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_CHAINPARAMS_H
#define ZCL_CHAINPARAMS_H

#include "chain/chainparamsbase.h"   /* MESSAGE_START_SIZE (pchMessageStart dim) */
#include "chain/checkpoints.h"
#include "consensus/params.h"
#include <stdbool.h>
#include <stdint.h>

enum base58_type {
    B58_PUBKEY_ADDRESS,
    B58_SCRIPT_ADDRESS,
    B58_SECRET_KEY,
    B58_EXT_PUBLIC_KEY,
    B58_EXT_SECRET_KEY,
    B58_ZCPAYMENT_ADDRESS,
    B58_ZCSPENDING_KEY,
    B58_ZCVIEWING_KEY,
    B58_MAX_TYPES
};

enum bech32_type {
    BECH32_SAPLING_PAYMENT_ADDRESS,
    BECH32_SAPLING_FULL_VIEWING_KEY,
    BECH32_SAPLING_INCOMING_VIEWING_KEY,
    BECH32_SAPLING_EXTENDED_SPEND_KEY,
    BECH32_MAX_TYPES
};

#define MAX_BASE58_PREFIX_LEN 4
#define MAX_DNS_SEEDS 8
#define MAX_FIXED_SEEDS 64
#define MAX_FOUNDERS_ADDRESSES 48
#define MAX_BECH32_HRP_LEN 32
#define MAX_ALERT_PUBKEY_LEN 65

struct seed_spec6 {
    uint8_t addr[16];
    uint16_t port;
};

struct dns_seed {
    char name[64];
    char host[64];
};

struct chain_params {
    struct consensus_params consensus;

    unsigned char pchMessageStart[MESSAGE_START_SIZE];
    unsigned char vAlertPubKey[MAX_ALERT_PUBKEY_LEN];
    size_t nAlertPubKeyLen;
    int nDefaultPort;
    uint64_t nPruneAfterHeight;
    unsigned int nEquihashN;
    unsigned int nEquihashK;

    struct dns_seed vSeeds[MAX_DNS_SEEDS];
    size_t nSeeds;

    unsigned char base58Prefixes[B58_MAX_TYPES][MAX_BASE58_PREFIX_LEN];
    size_t base58PrefixLengths[B58_MAX_TYPES];

    char bech32HRPs[BECH32_MAX_TYPES][MAX_BECH32_HRP_LEN];

    char strNetworkID[16];
    char strCurrencyUnits[8];
    uint32_t bip44CoinType;

    struct seed_spec6 vFixedSeeds[MAX_FIXED_SEEDS];
    size_t nFixedSeeds;

    /* Tor .onion seed nodes — bootstrap without DNS */
    char onionSeeds[MAX_FIXED_SEEDS][68]; /* v3 .onion = 62 chars + port */
    uint16_t onionSeedPorts[MAX_FIXED_SEEDS];
    size_t nOnionSeeds;

    bool fMiningRequiresPeers;
    bool fDefaultConsistencyChecks;
    bool fRequireStandard;
    bool fMineBlocksOnDemand;
    bool fTestnetToBeDeprecatedFieldRPC;

    struct checkpoint_data checkpointData;

    char vFoundersRewardAddress[MAX_FOUNDERS_ADDRESSES][36];
    size_t nFoundersRewardAddresses;
};

enum chain_research_profile { CHAIN_RESEARCH_IRONWOOD = 1 };

struct chain_research_descriptor {
    enum chain_research_profile id;
    const struct chain_params *chain;
    const struct base_chain_params *base;
    const uint8_t *genesis_wire;
    size_t genesis_wire_len;
};

const struct chain_research_descriptor *chain_research_profile_get(enum chain_research_profile id);
const struct chain_research_descriptor *chain_research_profile_current(void);
bool chain_research_profile_select(enum chain_research_profile id);

const struct chain_params *chain_params_get(void);
void chain_params_select(enum chain_network network);

const unsigned char *chain_params_base58_prefix(const struct chain_params *p,
                                                 enum base58_type type,
                                                 size_t *len_out);

unsigned int chain_params_equihash_n(const struct chain_params *p, int height);
unsigned int chain_params_equihash_k(const struct chain_params *p, int height);

#endif

/* Copyright (c) 2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "chain/chainparams.h"
#include "consensus/upgrades.h"
#include "encoding/utilstrencodings.h"
#include <assert.h>
#include <string.h>

/* Harvested by tools/harvest_checkpoints.sh from local zclassicd.
 * tip=3108561 at harvest time, finalized through height 3108461.
 * 63 entries, every 50,000 blocks from genesis to 3,100,000. Each
 * entry locks 50,000 blocks of history because MAX_REORG_LENGTH < 10
 * (core/modules/validation/include/validation/main_constants.h). */
static struct checkpoint_entry mainnet_checkpoints[] = {
    { 0, {{0}} },
    { 50000, {{0}} },
    { 100000, {{0}} },
    { 150000, {{0}} },
    { 200000, {{0}} },
    { 250000, {{0}} },
    { 300000, {{0}} },
    { 350000, {{0}} },
    { 400000, {{0}} },
    { 450000, {{0}} },
    { 500000, {{0}} },
    { 550000, {{0}} },
    { 600000, {{0}} },
    { 650000, {{0}} },
    { 700000, {{0}} },
    { 750000, {{0}} },
    { 800000, {{0}} },
    { 850000, {{0}} },
    { 900000, {{0}} },
    { 950000, {{0}} },
    { 1000000, {{0}} },
    { 1050000, {{0}} },
    { 1100000, {{0}} },
    { 1150000, {{0}} },
    { 1200000, {{0}} },
    { 1250000, {{0}} },
    { 1300000, {{0}} },
    { 1350000, {{0}} },
    { 1400000, {{0}} },
    { 1450000, {{0}} },
    { 1500000, {{0}} },
    { 1550000, {{0}} },
    { 1600000, {{0}} },
    { 1650000, {{0}} },
    { 1700000, {{0}} },
    { 1750000, {{0}} },
    { 1800000, {{0}} },
    { 1850000, {{0}} },
    { 1900000, {{0}} },
    { 1950000, {{0}} },
    { 2000000, {{0}} },
    { 2050000, {{0}} },
    { 2100000, {{0}} },
    { 2150000, {{0}} },
    { 2200000, {{0}} },
    { 2250000, {{0}} },
    { 2300000, {{0}} },
    { 2350000, {{0}} },
    { 2400000, {{0}} },
    { 2450000, {{0}} },
    { 2500000, {{0}} },
    { 2550000, {{0}} },
    { 2600000, {{0}} },
    { 2650000, {{0}} },
    { 2700000, {{0}} },
    { 2750000, {{0}} },
    { 2800000, {{0}} },
    { 2850000, {{0}} },
    { 2900000, {{0}} },
    { 2950000, {{0}} },
    { 3000000, {{0}} },
    { 3050000, {{0}} },
    { 3100000, {{0}} },
};

static struct checkpoint_entry testnet_checkpoints[] = {
    { 0, {{0}} },
};

static struct checkpoint_entry regtest_checkpoints[] = {
    { 0, {{0}} },
};

static struct chain_params mainParams;
static struct chain_params testNetParams;
static struct chain_params regTestParams;
static const struct chain_params *pCurrentParams = NULL;
static bool params_initialized = false;

static void init_main_params(void)
{
    struct chain_params *p = &mainParams;
    memset(p, 0, sizeof(*p));

    strcpy(p->strNetworkID, "main");
    strcpy(p->strCurrencyUnits, "ZCL");
    p->bip44CoinType = 147;

    p->consensus.fCoinbaseMustBeProtected = true;
    p->consensus.nSubsidySlowStartInterval = 2;
    p->consensus.nPreButtercupSubsidyHalvingInterval = PRE_BUTTERCUP_HALVING_INTERVAL;
    p->consensus.nPostButtercupSubsidyHalvingInterval = POST_BUTTERCUP_HALVING_INTERVAL;
    p->consensus.nMajorityEnforceBlockUpgrade = 750;
    p->consensus.nMajorityRejectBlockOutdated = 950;
    p->consensus.nMajorityWindow = 4000;
    uint256_set_hex(&p->consensus.powLimit,
        "0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    p->consensus.nPowAveragingWindow = 17;
    p->consensus.nPowMaxAdjustDown = 32;
    p->consensus.nPowMaxAdjustUp = 16;
    p->consensus.nPreButtercupPowTargetSpacing = PRE_BUTTERCUP_POW_TARGET_SPACING;
    p->consensus.nPostButtercupPowTargetSpacing = POST_BUTTERCUP_POW_TARGET_SPACING;
    p->consensus.nPowAllowMinDifficultyBlocksAfterHeight = -1;
    p->consensus.nPowAllowMinDifficultyEnabled = false;
    p->consensus.scaleDifficultyAtUpgradeFork = true;

    p->consensus.vUpgrades[BASE_SPROUT].nProtocolVersion = 170002;
    p->consensus.vUpgrades[BASE_SPROUT].nActivationHeight = NETWORK_UPGRADE_ALWAYS_ACTIVE;
    p->consensus.vUpgrades[UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
    p->consensus.vUpgrades[UPGRADE_TESTDUMMY].nActivationHeight = NETWORK_UPGRADE_NO_ACTIVATION;
    p->consensus.vUpgrades[UPGRADE_OVERWINTER].nProtocolVersion = 170005;
    p->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight = 476969;
    p->consensus.vUpgrades[UPGRADE_SAPLING].nProtocolVersion = 170007;
    p->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight = 476969;
    p->consensus.vUpgrades[UPGRADE_BUBBLES].nProtocolVersion = 170009;
    p->consensus.vUpgrades[UPGRADE_BUBBLES].nActivationHeight = 585318;
    p->consensus.vUpgrades[UPGRADE_DIFFADJ].nProtocolVersion = 170010;
    p->consensus.vUpgrades[UPGRADE_DIFFADJ].nActivationHeight = 585322;
    p->consensus.vUpgrades[UPGRADE_BUTTERCUP].nProtocolVersion = 170011;
    p->consensus.vUpgrades[UPGRADE_BUTTERCUP].nActivationHeight = 707000;

    uint256_set_hex(&p->consensus.nMinimumChainWork,
        "000000000000000000000000000000000000000000000000000af996bfd8e482");

    p->pchMessageStart[0] = 0x24;
    p->pchMessageStart[1] = 0xe9;
    p->pchMessageStart[2] = 0x27;
    p->pchMessageStart[3] = 0x64;

    p->nDefaultPort = 8033;
    p->nPruneAfterHeight = 100000;
    p->nEquihashN = 200;
    p->nEquihashK = 9;

    uint256_set_hex(&p->consensus.hashGenesisBlock,
        "0007104ccda289427919efc39dc9e4d499804b7bebc22df55f8b834301260602");

    /* DNS seeders: BOTH historical names (dnsseed.zslp.org, mainnet.zclassic.org)
     * fail to resolve today, so a DNS-seed query is wasted work / a misleading
     * bootstrap dependency. Bootstrap via the hardcoded fixed-IP peers below,
     * the .onion directory seeds, and the operator runtime onion-seeds file
     * (~/.config/zclassic23/onion-seeds, loaded by connman). Re-add a name here
     * only when a live ZCL DNS seeder exists. */
    p->nSeeds = 0;

    /* Hardcoded seed nodes — every entry re-probed 2026-08-26T03:25Z from
     * three consecutive TCP connects each, mainnet P2P port :8033 only.
     *
     * TWO defects were removed here, both of which spent a cold node's dial
     * budget on addresses that cannot answer:
     *
     * 1. Every IP used to be added TWICE — once at :8033 and once at
     *    :18033 — so half of nFixedSeeds was dead BY CONSTRUCTION, not by
     *    churn. :18033 is testnet/regtest's nDefaultPort (see the testnet
     *    and regtest blocks below), and a testnet listener carries a
     *    different pchMessageStart, so even a live :18033 peer could never
     *    complete a mainnet handshake. Measured 2026-08-26T03:25Z: all four
     *    :18033 probes were REFUSED (RST) at the same RTT as the :8033
     *    probe to the same host — 3/3 attempts each. There is exactly one
     *    mainnet P2P port and it is nDefaultPort.
     *
     * 2. 142.54.184.106 was refused on BOTH ports, 3/3 attempts, 32 ms RTT
     *    (host up, nothing listening). Its "reachable 2026-06-28" comment
     *    had gone stale exactly the way the paragraph below warns about.
     *
     * Keep ONLY currently-reachable IPs here and re-verify before each
     * release. A dead seed is worse than a short array. One live seed is
     * enough to start: the rest of the network is discovered via that
     * peer's addrman gossip, the .onion directory seeds, the operator
     * onion-seeds file, and this node's own persisted onion directory.
     * Re-verify with:
     *   for ip in <list>; do timeout 6 bash -c "exec 3<>/dev/tcp/$ip/8033"; done */
    p->nFixedSeeds = 0;
    static const uint8_t fixed_ip4[][4] = {
        {205,209,104,118},  /* :8033 open 3/3, 2026-08-26T03:25Z */
        {140,174,189, 17},  /* :8033 open 3/3, 2026-08-26T03:25Z */
        { 51,178,179, 75},  /* :8033 open 3/3, 2026-08-26T03:25Z */
    };
    for (size_t i = 0; i < sizeof(fixed_ip4)/sizeof(fixed_ip4[0]); i++) {
        if (p->nFixedSeeds + 1 > MAX_FIXED_SEEDS) break;
        struct seed_spec6 *s = &p->vFixedSeeds[p->nFixedSeeds];
        memset(s, 0, sizeof(*s));
        s->addr[10] = 0xFF;
        s->addr[11] = 0xFF;
        memcpy(s->addr + 12, fixed_ip4[i], 4);
        s->port = (uint16_t)p->nDefaultPort;
        p->nFixedSeeds++;
    }

    /* Tor .onion seed nodes — bootstrap without DNS. Each serves
     * /directory.json (its own .onion + the onions and clearnet endpoints
     * it has met), so ONE reachable onion seed re-seeds both the clearnet
     * addrman and this node's own persisted onion directory. More than one
     * removes the single point of failure: a recovering or partitioned node
     * still finds a supplier if any one seed is up.
     *
     * DISCIPLINE, unchanged and non-negotiable: an entry goes in ONLY after
     * confirming (a) it is a zclassic23 onion-directory node the project
     * controls and (b) it answers /directory.json over Tor AT THE TIME OF
     * THE CHANGE. Never invent a hostname — a dead or fabricated seed is
     * strictly worse than a short array, because each depth-0 seed fetch
     * costs a cold node up to 60 s of blocking Tor round-trip
     * (try_onion_seed_fetch_depth, core/modules/net/src/connman.c) before it can
     * move on. Re-verify EVERY entry before each release with an
     * independent Tor client, e.g.
     *   curl --socks5-hostname <tor-socks> http://<host>:80/directory.json
     *
     * 2026-08-26T03:27-03:30Z re-verification, two independent Tor clients:
     *
     *   REMOVED zc23kenfdqqkgamthif3m7lbbdsyrotsl2dlw35qrh3iuzopozmpjnad
     *     — 5/5 attempts failed with SOCKS5 reply 4 (host unreachable: no
     *       descriptor), ~6 s each, from two separate Tor clients. It was
     *       the array's ONLY entry, so until this change a Tor-only
     *       stranger had NO working hardcoded door into the network and
     *       paid the full 60 s timeout to find that out.
     *
     *   ADDED 5wvfod4ikluv4w3lqe3whn2k7xdsympxxu2qkqw452thtjxbar5hrcqd
     *     — HTTP 200, 5528-byte /directory.json, 3/3 attempts in ~1.0 s.
     *       First-party, onion-persisted (-onion-persist), and its address
     *       has never rotated.
     *
     * PORT: onionSeedPorts[] is a genuine per-entry array, but NOTHING
     * READS IT — grep the tree: chainparams.c writes it and no other
     * translation unit ever loads it. The seed path reaches a seed by
     * hostname alone over the onion service's HTTP virtual port 80
     * (tor_integration.c pins application_virtual_port = 80), and
     * tor_integration_fetch_onion_blocking() takes no port argument at
     * all. So the value here is documentation, not behaviour: it records
     * the seed's P2P virtual port for whoever wires a direct onion P2P
     * dial later. It is set PER ENTRY and must stay that way — the two
     * seeds below do NOT share a port, so any future consumer that
     * assumes one shared port would dial the wrong one.
     *
     * ZERO-REBUILD PATH — THE PRIMARY, NOT A FALLBACK. This array is a
     * compiled-in constant that ages the moment it is written; the two
     * runtime sources below outrank it and are consulted FIRST by
     * run_onion_seed_pass() (core/modules/net/src/connman.c):
     *   1. ~/.config/zclassic23/onion-seeds — operator-curated, one .onion
     *      per line ('#' comments, blank lines skipped, 32-line cap). An
     *      operator (or a second/third project node) adds a supplier with
     *      no code change, no rebuild and no restart of anyone else.
     *   2. This node's own persisted onion directory — every host it has
     *      ever learned from a peer's /directory.json or measured itself.
     * See "Onion-Seed Bootstrap" in docs/RUNBOOK.md. */
    {
        static const struct { const char *host; uint16_t p2p_port; }
        kOnionSeeds[] = {
            /* node1 — verified 2026-08-26T03:27:21Z, HTTP 200 3/3. Its
             * P2P virtual port is 8055, NOT the mainnet default. */
            { "5wvfod4ikluv4w3lqe3whn2k7xdsympxxu2qkqw452thtjxbar5hrcqd.onion",
              8055 },
            /* Additional first-party onion-directory seeds are appended
             * here as they come online, each with its own P2P port and its
             * own reachability evidence in the block above. Until a second
             * one lands, a Tor-only stranger with an empty onion-seeds file
             * and an empty directory depends on this single box. */
        };
        size_t n = 0;
        for (size_t i = 0;
             i < sizeof(kOnionSeeds) / sizeof(kOnionSeeds[0]) &&
             n < MAX_FIXED_SEEDS; i++) {
            size_t len = strlen(kOnionSeeds[i].host);
            if (len >= sizeof(p->onionSeeds[0])) continue;
            memcpy(p->onionSeeds[n], kOnionSeeds[i].host, len);
            p->onionSeeds[n][len] = '\0';
            p->onionSeedPorts[n] = kOnionSeeds[i].p2p_port;
            n++;
        }
        p->nOnionSeeds = n;
    }

    /* t1 addresses */
    p->base58Prefixes[B58_PUBKEY_ADDRESS][0] = 0x1C;
    p->base58Prefixes[B58_PUBKEY_ADDRESS][1] = 0xB8;
    p->base58PrefixLengths[B58_PUBKEY_ADDRESS] = 2;
    /* t3 addresses */
    p->base58Prefixes[B58_SCRIPT_ADDRESS][0] = 0x1C;
    p->base58Prefixes[B58_SCRIPT_ADDRESS][1] = 0xBD;
    p->base58PrefixLengths[B58_SCRIPT_ADDRESS] = 2;
    /* 5/K/L WIF */
    p->base58Prefixes[B58_SECRET_KEY][0] = 0x80;
    p->base58PrefixLengths[B58_SECRET_KEY] = 1;
    /* BIP32 xpub */
    p->base58Prefixes[B58_EXT_PUBLIC_KEY][0] = 0x04;
    p->base58Prefixes[B58_EXT_PUBLIC_KEY][1] = 0x88;
    p->base58Prefixes[B58_EXT_PUBLIC_KEY][2] = 0xB2;
    p->base58Prefixes[B58_EXT_PUBLIC_KEY][3] = 0x1E;
    p->base58PrefixLengths[B58_EXT_PUBLIC_KEY] = 4;
    /* BIP32 xprv */
    p->base58Prefixes[B58_EXT_SECRET_KEY][0] = 0x04;
    p->base58Prefixes[B58_EXT_SECRET_KEY][1] = 0x88;
    p->base58Prefixes[B58_EXT_SECRET_KEY][2] = 0xAD;
    p->base58Prefixes[B58_EXT_SECRET_KEY][3] = 0xE4;
    p->base58PrefixLengths[B58_EXT_SECRET_KEY] = 4;
    /* zc payment address */
    p->base58Prefixes[B58_ZCPAYMENT_ADDRESS][0] = 0x16;
    p->base58Prefixes[B58_ZCPAYMENT_ADDRESS][1] = 0x9A;
    p->base58PrefixLengths[B58_ZCPAYMENT_ADDRESS] = 2;
    /* SK spending key */
    p->base58Prefixes[B58_ZCSPENDING_KEY][0] = 0xAB;
    p->base58Prefixes[B58_ZCSPENDING_KEY][1] = 0x36;
    p->base58PrefixLengths[B58_ZCSPENDING_KEY] = 2;
    /* ZiVK viewing key */
    p->base58Prefixes[B58_ZCVIEWING_KEY][0] = 0xA8;
    p->base58Prefixes[B58_ZCVIEWING_KEY][1] = 0xAB;
    p->base58Prefixes[B58_ZCVIEWING_KEY][2] = 0xD3;
    p->base58PrefixLengths[B58_ZCVIEWING_KEY] = 3;

    strcpy(p->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS], "zs");
    strcpy(p->bech32HRPs[BECH32_SAPLING_FULL_VIEWING_KEY], "zviews");
    strcpy(p->bech32HRPs[BECH32_SAPLING_INCOMING_VIEWING_KEY], "zivks");
    strcpy(p->bech32HRPs[BECH32_SAPLING_EXTENDED_SPEND_KEY], "secret-extended-key-main");

    p->fMiningRequiresPeers = true;
    p->fDefaultConsistencyChecks = false;
    p->fRequireStandard = true;
    p->fMineBlocksOnDemand = false;
    p->fTestnetToBeDeprecatedFieldRPC = false;

    /* 63 checkpoints, harvested by tools/harvest_checkpoints.sh from
     * local zclassicd. Source-of-truth at harvest time: tip=3108561,
     * finalized through height 3108461 (100-block safety margin past
     * MAX_REORG_LENGTH). */
    uint256_set_hex(&mainnet_checkpoints[0].hash,
        "0007104ccda289427919efc39dc9e4d499804b7bebc22df55f8b834301260602");
    uint256_set_hex(&mainnet_checkpoints[1].hash,
        "0000001192547cfec21ebcee32be84c85ee13151b9ad57dd1ab5b99660fdbba7");
    uint256_set_hex(&mainnet_checkpoints[2].hash,
        "000000016845a9f945079aa52680def9eafd5ea39c86dfdb5ef5630d18e3e74f");
    uint256_set_hex(&mainnet_checkpoints[3].hash,
        "000000086a7f385f4f3027f9a0615c6174739e479ca0470e1f35d610b04a66be");
    uint256_set_hex(&mainnet_checkpoints[4].hash,
        "00000003eae37fd7c03db6342f7bd79323e845bcf649c8f5dba7959221931903");
    uint256_set_hex(&mainnet_checkpoints[5].hash,
        "000000001e58184b4db769088543b3493c9006b6489715701d9a8100650b0b61");
    uint256_set_hex(&mainnet_checkpoints[6].hash,
        "00000000dd6925eecc752ef271ac731f9bde9a1c4bebeaea58cb18f17ac8fa37");
    uint256_set_hex(&mainnet_checkpoints[7].hash,
        "000000005c751c23e79877bf8cf5b34bd87307c71c336b6525e388168b1fc2df");
    uint256_set_hex(&mainnet_checkpoints[8].hash,
        "000000002e903f1fed722546464fb1c1e46712d1267cf8ec69b35d2730ea8779");
    uint256_set_hex(&mainnet_checkpoints[9].hash,
        "0000000072512aae1e83de04c14865ee91a20c91ed24a4b691ccdf33458a8316");
    uint256_set_hex(&mainnet_checkpoints[10].hash,
        "00000000068bb87ac6e5b52ad17360ffdaed1ff0161b20a73993ed4de0500756");
    uint256_set_hex(&mainnet_checkpoints[11].hash,
        "0000000006abda2bc6060a741a2757bcad66d0bc2d540175a718603b69382c75");
    uint256_set_hex(&mainnet_checkpoints[12].hash,
        "0000005d7286ac9c6f6776685d7132890215924c50c3f17bfb8812480832a6d9");
    uint256_set_hex(&mainnet_checkpoints[13].hash,
        "000000dacdca8bdbb7f06c78cae46c4a6202046cba99631589dc410d49a73b04");
    uint256_set_hex(&mainnet_checkpoints[14].hash,
        "0000006742849baa2fc3a14bca5d2de7624d2a1435de1198fcbfa86a499a4f89");
    uint256_set_hex(&mainnet_checkpoints[15].hash,
        "00000b84fc0a0bc9e55e6bc72d238548e828818f092b8ae84fafbec053ea766c");
    uint256_set_hex(&mainnet_checkpoints[16].hash,
        "000003260ca88e0c9d29def97f02b97841c2fbb351a09357f4e8d55cca63e683");
    uint256_set_hex(&mainnet_checkpoints[17].hash,
        "0000188da1cc7eb79ba5cff835a23f9d881c5b038aa8b17c8abbc8e5b8adbc12");
    uint256_set_hex(&mainnet_checkpoints[18].hash,
        "000000222501a004b13b4b3b12909bc29ed4040b2a9082b8e5986019bbfc8ff0");
    uint256_set_hex(&mainnet_checkpoints[19].hash,
        "00001d2c035853010cfcd28d4d6b9c399be76783bb6b2c22c6dd5f45448ef289");
    uint256_set_hex(&mainnet_checkpoints[20].hash,
        "00001e9a80eef39dd38e4280fd0e9fa6daba1ec1d2bcc26b4835a2991be21502");
    uint256_set_hex(&mainnet_checkpoints[21].hash,
        "000013bb2d4e0a99bbc485148b80d70a0d6d7a41a13853043f6ad8b4056b8e95");
    uint256_set_hex(&mainnet_checkpoints[22].hash,
        "00002067edad8f7c0a43d32fd141ed6b39f9ee3560c2541c7876b804a82417a2");
    uint256_set_hex(&mainnet_checkpoints[23].hash,
        "000018d81f71c9c5d6f23e3c6932b077c8e13ee77e14585106d92053b49a6ba9");
    uint256_set_hex(&mainnet_checkpoints[24].hash,
        "000027e9ef0d54c5ebc5fb1d7c47fb9afd799e5f026f794d8222da44481374ed");
    uint256_set_hex(&mainnet_checkpoints[25].hash,
        "000043402390faa334cec744c8e5bbe619616ee1744dd63f43b0f2f4624df5a8");
    uint256_set_hex(&mainnet_checkpoints[26].hash,
        "00000f742bad132ad7911fb0f28b2648d9cf2f2064968ebbb6497f4db3bdbbdd");
    uint256_set_hex(&mainnet_checkpoints[27].hash,
        "000006c858fdcc5b720969e0f7f89d026775daab568b673bd7ab9f64dd7ea663");
    uint256_set_hex(&mainnet_checkpoints[28].hash,
        "00003fcae06bad5503eb91d81b107af48ff0381137f550dfa133d57e848d8c68");
    uint256_set_hex(&mainnet_checkpoints[29].hash,
        "00003b2bc346234bdf7d6c8c2cc71329d8d3f6376d0a669b426baf5deb3fc84e");
    uint256_set_hex(&mainnet_checkpoints[30].hash,
        "00003026bfd01a2909ad66a43dd231f4ebfd869653fb0797be0f1e7607c5c825");
    uint256_set_hex(&mainnet_checkpoints[31].hash,
        "0000358964240c65f8f42b0eeb58a8736264af4659cb49c0445a0a89476a9100");
    uint256_set_hex(&mainnet_checkpoints[32].hash,
        "00001f9d63dd94c5832d7c7e98aa468e1032d6ee09b6e0c81b4509168fbaa360");
    uint256_set_hex(&mainnet_checkpoints[33].hash,
        "00004a98ed8b402b906952d6e588736921c668cebd82b2d131250356b1e9bfe6");
    uint256_set_hex(&mainnet_checkpoints[34].hash,
        "00005d09484a70d5fc6a1ebe619437d359e242864e6bec627e580cf6b68e5752");
    uint256_set_hex(&mainnet_checkpoints[35].hash,
        "00000e95b22113711d31047a18d80d464abd7cba17cb0c1f31b09c2a57558660");
    uint256_set_hex(&mainnet_checkpoints[36].hash,
        "00000644a340ff1644b1ec20675e35bee6e536205a958c9ebd7ec7ec4a2e28ae");
    uint256_set_hex(&mainnet_checkpoints[37].hash,
        "00000c3166c101054c2824d0346fb91f4b083186b014debbe98c08f0304f1aa5");
    uint256_set_hex(&mainnet_checkpoints[38].hash,
        "0000133682fdd979ec2cb5eef86f023203b632d47356f837d319a46548911bac");
    uint256_set_hex(&mainnet_checkpoints[39].hash,
        "00000ec287eb4a9f672dde3a3fb7abf2d46b88dacd08f0bb4f8a5e58da8abf44");
    uint256_set_hex(&mainnet_checkpoints[40].hash,
        "00000bfde9956d07350de33324802251c51b62a5b0df43d2fb7e240c75bd835b");
    uint256_set_hex(&mainnet_checkpoints[41].hash,
        "00001a3f1cdded96e801ab9a24d8729013afd339a8fcbfde8b9c581c4461c372");
    uint256_set_hex(&mainnet_checkpoints[42].hash,
        "000007cf57c30779f836c953a3b2cbe26d27e7bfb422231cb7d1a4724e3f6f7b");
    uint256_set_hex(&mainnet_checkpoints[43].hash,
        "0000021414f263cd394ba3fe5edbc7407d2c35c219ed532d81224a8f5cac266a");
    uint256_set_hex(&mainnet_checkpoints[44].hash,
        "000047475398f40c0f7d8e2820f100ff33f3e1534a4f9351eba5b0df512c6699");
    uint256_set_hex(&mainnet_checkpoints[45].hash,
        "0000096f21e3a317f08485ba48416ae83fcbe19758dcaa8d4482fff3b93f3765");
    uint256_set_hex(&mainnet_checkpoints[46].hash,
        "0000104a2796574b6d308e511f6eca0a3e0808df46fe74c13f255497a78c5287");
    uint256_set_hex(&mainnet_checkpoints[47].hash,
        "0000051085307b23e74fb281b632ad02568f6088d75580e3d4a172b2b1680689");
    uint256_set_hex(&mainnet_checkpoints[48].hash,
        "000010da75517d6a2e2ec505c9cde4538f6e3ab8d6567be418b0ea84feb18e62");
    uint256_set_hex(&mainnet_checkpoints[49].hash,
        "00006bc6a3bfbb3ddbc4093a21c66978f312274cbb2c560e1d468142deba0fbe");
    uint256_set_hex(&mainnet_checkpoints[50].hash,
        "000019f68479a8bf8b2f8824961a6e65a12c74c4225f0445c8155cfc99ab29b7");
    uint256_set_hex(&mainnet_checkpoints[51].hash,
        "000047ea79927d47625d3ced5a844b80629455f86a01c854c101d8cf587be726");
    uint256_set_hex(&mainnet_checkpoints[52].hash,
        "00001cf494ed090510920b516e778203848aff2cb9f4a3180ad36a2f98c12a8c");
    uint256_set_hex(&mainnet_checkpoints[53].hash,
        "000018d2bd23734894da5a1b7d643cb95cd8d507c9abfb54c84e261ede545755");
    uint256_set_hex(&mainnet_checkpoints[54].hash,
        "0000195b1d8b3abb52279d573b591b21ee2099057f46b50953cea2a7d77cb738");
    uint256_set_hex(&mainnet_checkpoints[55].hash,
        "000015796f1454a03d0ca328dcab4c4c9b19ca4be615e8b650b33bb149a6651a");
    uint256_set_hex(&mainnet_checkpoints[56].hash,
        "0001919c32ab5c65d4f34440306e5d9df5cd02081b712b636ef244e63b32f65c");
    uint256_set_hex(&mainnet_checkpoints[57].hash,
        "000034d1fcfa2c6567c715d8ae459bd9cc2b04d5b6f6a4d4391928d8349a16c4");
    uint256_set_hex(&mainnet_checkpoints[58].hash,
        "000000746aedab2734c87be0ea7c7337523ed14f3ee2cc212eee6b22a442c9af");
    uint256_set_hex(&mainnet_checkpoints[59].hash,
        "00000bcce5aa72a17a672931187c120bd5ab7dfd0a1c51ca513017901b3cebd6");
    uint256_set_hex(&mainnet_checkpoints[60].hash,
        "0000038aee939c8017f4ad353e3fd1313c6a0da565bbc1d3269bbe855fe33505");
    uint256_set_hex(&mainnet_checkpoints[61].hash,
        "0000013c767422c5e118ef7b2efe63a108c03c1dcc8b11f16abce14f4937d2ab");
    uint256_set_hex(&mainnet_checkpoints[62].hash,
        "00000ec39d18a564aea5232468ec07ac692ff39f0059551f8aed20a7911d0605");

    p->checkpointData.entries = mainnet_checkpoints;
    p->checkpointData.nEntries = 63;
    p->checkpointData.nTimeLastCheckpoint = 1774300000;
    p->checkpointData.nTransactionsLastCheckpoint = 5037600;
    p->checkpointData.fTransactionsPerDay = 1060;

    static const char *main_founders[] = {
        "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd",
        "t3cL9AucCajm3HXDhb5jBnJK2vapVoXsop3",
        "t3fqvkzrrNaMcamkQMwAyHRjfDdM2xQvDTR",
        "t3TgZ9ZT2CTSK44AnUPi6qeNaHa2eC7pUyF",
        "t3SpkcPQPfuRYHsP5vz3Pv86PgKo5m9KVmx",
        "t3Xt4oQMRPagwbpQqkgAViQgtST4VoSWR6S",
        "t3ayBkZ4w6kKXynwoHZFUSSgXRKtogTXNgb",
        "t3adJBQuaa21u7NxbR8YMzp3km3TbSZ4MGB",
        "t3K4aLYagSSBySdrfAGGeUd5H9z5Qvz88t2",
        "t3RYnsc5nhEvKiva3ZPhfRSk7eyh1CrA6Rk",
        "t3Ut4KUq2ZSMTPNE67pBU5LqYCi2q36KpXQ",
        "t3ZnCNAvgu6CSyHm1vWtrx3aiN98dSAGpnD",
        "t3fB9cB3eSYim64BS9xfwAHQUKLgQQroBDG",
        "t3cwZfKNNj2vXMAHBQeewm6pXhKFdhk18kD",
        "t3YcoujXfspWy7rbNUsGKxFEWZqNstGpeG4",
        "t3bLvCLigc6rbNrUTS5NwkgyVrZcZumTRa4",
        "t3VvHWa7r3oy67YtU4LZKGCWa2J6eGHvShi",
        "t3eF9X6X2dSo7MCvTjfZEzwWrVzquxRLNeY",
        "t3esCNwwmcyc8i9qQfyTbYhTqmYXZ9AwK3X",
        "t3M4jN7hYE2e27yLsuQPPjuVek81WV3VbBj",
        "t3gGWxdC67CYNoBbPjNvrrWLAWxPqZLxrVY",
        "t3LTWeoxeWPbmdkUD3NWBquk4WkazhFBmvU",
        "t3P5KKX97gXYFSaSjJPiruQEX84yF5z3Tjq",
        "t3f3T3nCWsEpzmD35VK62JgQfFig74dV8C9",
        "t3Rqonuzz7afkF7156ZA4vi4iimRSEn41hj",
        "t3fJZ5jYsyxDtvNrWBeoMbvJaQCj4JJgbgX",
        "t3Pnbg7XjP7FGPBUuz75H65aczphHgkpoJW",
        "t3WeKQDxCijL5X7rwFem1MTL9ZwVJkUFhpF",
        "t3Y9FNi26J7UtAUC4moaETLbMo8KS1Be6ME",
        "t3aNRLLsL2y8xcjPheZZwFy3Pcv7CsTwBec",
        "t3gQDEavk5VzAAHK8TrQu2BWDLxEiF1unBm",
        "t3Rbykhx1TUFrgXrmBYrAJe2STxRKFL7G9r",
        "t3aaW4aTdP7a8d1VTE1Bod2yhbeggHgMajR",
        "t3YEiAa6uEjXwFL2v5ztU1fn3yKgzMQqNyo",
        "t3g1yUUwt2PbmDvMDevTCPWUcbDatL2iQGP",
        "t3dPWnep6YqGPuY1CecgbeZrY9iUwH8Yd4z",
        "t3QRZXHDPh2hwU46iQs2776kRuuWfwFp4dV",
        "t3enhACRxi1ZD7e8ePomVGKn7wp7N9fFJ3r",
        "t3PkLgT71TnF112nSwBToXsD77yNbx2gJJY",
        "t3LQtHUDoe7ZhhvddRv4vnaoNAhCr2f4oFN",
        "t3fNcdBUbycvbCtsD2n9q3LuxG7jVPvFB8L",
        "t3dKojUU2EMjs28nHV84TvkVEUDu1M1FaEx",
        "t3aKH6NiWN1ofGd8c19rZiqgYpkJ3n679ME",
        "t3MEXDF9Wsi63KwpPuQdD6by32Mw2bNTbEa",
        "t3WDhPfik343yNmPTqtkZAoQZeqA83K7Y3f",
        "t3PSn5TbMMAEw7Eu36DYctFezRzpX1hzf3M",
        "t3R3Y5vnBLrEn8L6wFjPjBLnxSUQsKnmFpv",
        "t3Pcm737EsVkGTbhsu2NekKtJeG92mvYyoN",
    };
    p->nFoundersRewardAddresses = 48;
    for (size_t i = 0; i < 48; i++)
        strcpy(p->vFoundersRewardAddress[i], main_founders[i]);
}

/* Base58 prefixes shared by testnet and regtest (mainnet differs). */
static void apply_testnet_b58_prefixes(struct chain_params *p)
{
    /* tm addresses */
    p->base58Prefixes[B58_PUBKEY_ADDRESS][0] = 0x1D;
    p->base58Prefixes[B58_PUBKEY_ADDRESS][1] = 0x25;
    p->base58PrefixLengths[B58_PUBKEY_ADDRESS] = 2;
    /* t2 addresses */
    p->base58Prefixes[B58_SCRIPT_ADDRESS][0] = 0x1C;
    p->base58Prefixes[B58_SCRIPT_ADDRESS][1] = 0xBA;
    p->base58PrefixLengths[B58_SCRIPT_ADDRESS] = 2;
    /* 9/c WIF */
    p->base58Prefixes[B58_SECRET_KEY][0] = 0xEF;
    p->base58PrefixLengths[B58_SECRET_KEY] = 1;
    /* BIP32 tpub */
    p->base58Prefixes[B58_EXT_PUBLIC_KEY][0] = 0x04;
    p->base58Prefixes[B58_EXT_PUBLIC_KEY][1] = 0x35;
    p->base58Prefixes[B58_EXT_PUBLIC_KEY][2] = 0x87;
    p->base58Prefixes[B58_EXT_PUBLIC_KEY][3] = 0xCF;
    p->base58PrefixLengths[B58_EXT_PUBLIC_KEY] = 4;
    /* BIP32 tprv */
    p->base58Prefixes[B58_EXT_SECRET_KEY][0] = 0x04;
    p->base58Prefixes[B58_EXT_SECRET_KEY][1] = 0x35;
    p->base58Prefixes[B58_EXT_SECRET_KEY][2] = 0x83;
    p->base58Prefixes[B58_EXT_SECRET_KEY][3] = 0x94;
    p->base58PrefixLengths[B58_EXT_SECRET_KEY] = 4;
    /* zt payment address */
    p->base58Prefixes[B58_ZCPAYMENT_ADDRESS][0] = 0x16;
    p->base58Prefixes[B58_ZCPAYMENT_ADDRESS][1] = 0xB6;
    p->base58PrefixLengths[B58_ZCPAYMENT_ADDRESS] = 2;
    /* ST spending key */
    p->base58Prefixes[B58_ZCSPENDING_KEY][0] = 0xAC;
    p->base58Prefixes[B58_ZCSPENDING_KEY][1] = 0x08;
    p->base58PrefixLengths[B58_ZCSPENDING_KEY] = 2;
    /* ZiVt viewing key */
    p->base58Prefixes[B58_ZCVIEWING_KEY][0] = 0xA8;
    p->base58Prefixes[B58_ZCVIEWING_KEY][1] = 0xAC;
    p->base58Prefixes[B58_ZCVIEWING_KEY][2] = 0x0C;
    p->base58PrefixLengths[B58_ZCVIEWING_KEY] = 3;
}

static void init_test_params(void)
{
    struct chain_params *p = &testNetParams;
    memset(p, 0, sizeof(*p));

    strcpy(p->strNetworkID, "test");
    strcpy(p->strCurrencyUnits, "ZCT");
    p->bip44CoinType = 1;

    p->consensus.fCoinbaseMustBeProtected = true;
    p->consensus.nSubsidySlowStartInterval = 2;
    p->consensus.nPreButtercupSubsidyHalvingInterval = PRE_BUTTERCUP_HALVING_INTERVAL;
    p->consensus.nPostButtercupSubsidyHalvingInterval = POST_BUTTERCUP_HALVING_INTERVAL;
    p->consensus.nMajorityEnforceBlockUpgrade = 51;
    p->consensus.nMajorityRejectBlockOutdated = 75;
    p->consensus.nMajorityWindow = 400;
    uint256_set_hex(&p->consensus.powLimit,
        "07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    p->consensus.nPowAveragingWindow = 17;
    p->consensus.nPowMaxAdjustDown = 32;
    p->consensus.nPowMaxAdjustUp = 16;
    p->consensus.nPreButtercupPowTargetSpacing = PRE_BUTTERCUP_POW_TARGET_SPACING;
    p->consensus.nPostButtercupPowTargetSpacing = POST_BUTTERCUP_POW_TARGET_SPACING;
    p->consensus.nPowAllowMinDifficultyBlocksAfterHeight = 299187;
    p->consensus.nPowAllowMinDifficultyEnabled = true;
    p->consensus.scaleDifficultyAtUpgradeFork = false;

    p->consensus.vUpgrades[BASE_SPROUT].nProtocolVersion = 170002;
    p->consensus.vUpgrades[BASE_SPROUT].nActivationHeight = NETWORK_UPGRADE_ALWAYS_ACTIVE;
    p->consensus.vUpgrades[UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
    p->consensus.vUpgrades[UPGRADE_TESTDUMMY].nActivationHeight = NETWORK_UPGRADE_NO_ACTIVATION;
    p->consensus.vUpgrades[UPGRADE_OVERWINTER].nProtocolVersion = 170003;
    p->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight = 20;
    p->consensus.vUpgrades[UPGRADE_SAPLING].nProtocolVersion = 170007;
    p->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight = 20;
    p->consensus.vUpgrades[UPGRADE_BUBBLES].nProtocolVersion = 170008;
    p->consensus.vUpgrades[UPGRADE_BUBBLES].nActivationHeight = 6350;
    p->consensus.vUpgrades[UPGRADE_DIFFADJ].nProtocolVersion = 170009;
    p->consensus.vUpgrades[UPGRADE_DIFFADJ].nActivationHeight = NETWORK_UPGRADE_NO_ACTIVATION;
    p->consensus.vUpgrades[UPGRADE_BUTTERCUP].nProtocolVersion = 170010;
    p->consensus.vUpgrades[UPGRADE_BUTTERCUP].nActivationHeight = 78856;

    uint256_set_hex(&p->consensus.nMinimumChainWork,
        "0000000000000000000000000000000000000000000000000000000000000000");

    p->pchMessageStart[0] = 0xfa;
    p->pchMessageStart[1] = 0x1a;
    p->pchMessageStart[2] = 0xf9;
    p->pchMessageStart[3] = 0xbf;

    p->nDefaultPort = 18033;
    p->nPruneAfterHeight = 1000;
    p->nEquihashN = 200;
    p->nEquihashK = 9;

    uint256_set_hex(&p->consensus.hashGenesisBlock,
        "03e1c4bb705c871bf9bfda3e74b7f8f86bff267993c215a89d5795e3708e5e1f");

    p->vSeeds[0] = (struct dns_seed){ "testnet_node1", "167.71.172.5" };
    p->nSeeds = 1;

    apply_testnet_b58_prefixes(p);

    strcpy(p->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS], "ztestsapling");
    strcpy(p->bech32HRPs[BECH32_SAPLING_FULL_VIEWING_KEY], "zviewtestsapling");
    strcpy(p->bech32HRPs[BECH32_SAPLING_INCOMING_VIEWING_KEY], "zivktestsapling");
    strcpy(p->bech32HRPs[BECH32_SAPLING_EXTENDED_SPEND_KEY], "secret-extended-key-test");

    p->fMiningRequiresPeers = true;
    p->fDefaultConsistencyChecks = false;
    p->fRequireStandard = true;
    p->fMineBlocksOnDemand = false;
    p->fTestnetToBeDeprecatedFieldRPC = true;

    uint256_set_hex(&testnet_checkpoints[0].hash,
        "03e1c4bb705c871bf9bfda3e74b7f8f86bff267993c215a89d5795e3708e5e1f");

    p->checkpointData.entries = testnet_checkpoints;
    p->checkpointData.nEntries = 1;
    p->checkpointData.nTimeLastCheckpoint = 0;
    p->checkpointData.nTransactionsLastCheckpoint = 0;
    p->checkpointData.fTransactionsPerDay = 0;

    p->nFoundersRewardAddresses = 0;
}

static void init_regtest_params(void)
{
    struct chain_params *p = &regTestParams;
    memset(p, 0, sizeof(*p));

    strcpy(p->strNetworkID, "regtest");
    strcpy(p->strCurrencyUnits, "REG");
    p->bip44CoinType = 1;

    p->consensus.fCoinbaseMustBeProtected = false;
    p->consensus.nSubsidySlowStartInterval = 0;
    p->consensus.nPreButtercupSubsidyHalvingInterval = PRE_BUTTERCUP_REGTEST_HALVING_INTERVAL;
    p->consensus.nPostButtercupSubsidyHalvingInterval = POST_BUTTERCUP_REGTEST_HALVING_INTERVAL;
    p->consensus.nMajorityEnforceBlockUpgrade = 750;
    p->consensus.nMajorityRejectBlockOutdated = 950;
    p->consensus.nMajorityWindow = 1000;
    uint256_set_hex(&p->consensus.powLimit,
        "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
    p->consensus.nPowAveragingWindow = 17;
    p->consensus.nPowMaxAdjustDown = 0;
    p->consensus.nPowMaxAdjustUp = 0;
    p->consensus.nPreButtercupPowTargetSpacing = PRE_BUTTERCUP_POW_TARGET_SPACING;
    p->consensus.nPostButtercupPowTargetSpacing = POST_BUTTERCUP_POW_TARGET_SPACING;
    p->consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;
    p->consensus.nPowAllowMinDifficultyEnabled = true;
    p->consensus.scaleDifficultyAtUpgradeFork = false;

    p->consensus.vUpgrades[BASE_SPROUT].nProtocolVersion = 170002;
    p->consensus.vUpgrades[BASE_SPROUT].nActivationHeight = NETWORK_UPGRADE_ALWAYS_ACTIVE;
    p->consensus.vUpgrades[UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
    p->consensus.vUpgrades[UPGRADE_TESTDUMMY].nActivationHeight = NETWORK_UPGRADE_NO_ACTIVATION;
    p->consensus.vUpgrades[UPGRADE_OVERWINTER].nProtocolVersion = 170003;
    p->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight = NETWORK_UPGRADE_NO_ACTIVATION;
    p->consensus.vUpgrades[UPGRADE_SAPLING].nProtocolVersion = 170006;
    p->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight = NETWORK_UPGRADE_NO_ACTIVATION;
    p->consensus.vUpgrades[UPGRADE_BUBBLES].nProtocolVersion = 170008;
    p->consensus.vUpgrades[UPGRADE_BUBBLES].nActivationHeight = NETWORK_UPGRADE_NO_ACTIVATION;
    p->consensus.vUpgrades[UPGRADE_DIFFADJ].nProtocolVersion = 170009;
    p->consensus.vUpgrades[UPGRADE_DIFFADJ].nActivationHeight = NETWORK_UPGRADE_NO_ACTIVATION;
    p->consensus.vUpgrades[UPGRADE_BUTTERCUP].nProtocolVersion = 170010;
    p->consensus.vUpgrades[UPGRADE_BUTTERCUP].nActivationHeight = NETWORK_UPGRADE_NO_ACTIVATION;

    uint256_set_hex(&p->consensus.nMinimumChainWork,
        "0000000000000000000000000000000000000000000000000000000000000000");

    p->pchMessageStart[0] = 0xaa;
    p->pchMessageStart[1] = 0xe8;
    p->pchMessageStart[2] = 0x3f;
    p->pchMessageStart[3] = 0x5f;

    p->nDefaultPort = 18033;
    p->nPruneAfterHeight = 1000;
    p->nEquihashN = 48;
    p->nEquihashK = 5;

    uint256_set_hex(&p->consensus.hashGenesisBlock,
        "0575f78ee8dc057deee78ef691876e3be29833aaee5e189bb0459c087451305a");

    p->nSeeds = 0;

    /* Same as testnet prefixes */
    apply_testnet_b58_prefixes(p);

    strcpy(p->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS], "zregtestsapling");
    strcpy(p->bech32HRPs[BECH32_SAPLING_FULL_VIEWING_KEY], "zviewregtestsapling");
    strcpy(p->bech32HRPs[BECH32_SAPLING_INCOMING_VIEWING_KEY], "zivkregtestsapling");
    strcpy(p->bech32HRPs[BECH32_SAPLING_EXTENDED_SPEND_KEY], "secret-extended-key-regtest");

    p->fMiningRequiresPeers = false;
    p->fDefaultConsistencyChecks = true;
    p->fRequireStandard = false;
    p->fMineBlocksOnDemand = true;
    p->fTestnetToBeDeprecatedFieldRPC = false;

    uint256_set_hex(&regtest_checkpoints[0].hash,
        "0575f78ee8dc057deee78ef691876e3be29833aaee5e189bb0459c087451305a");

    p->checkpointData.entries = regtest_checkpoints;
    p->checkpointData.nEntries = 1;
    p->checkpointData.nTimeLastCheckpoint = 0;
    p->checkpointData.nTransactionsLastCheckpoint = 0;
    p->checkpointData.fTransactionsPerDay = 0;

    p->nFoundersRewardAddresses = 1;
    strcpy(p->vFoundersRewardAddress[0], "t2FwcEhFdNXuFMv1tcYwaBJtYVtMj8b1uTg");
}

static void ensure_initialized(void)
{
    if (!params_initialized) {
        init_main_params();
        init_test_params();
        init_regtest_params();
        params_initialized = true;
    }
}

const struct chain_params *chain_params_get(void)
{
    ensure_initialized();
    assert(pCurrentParams);
    return pCurrentParams;
}

void chain_params_select(enum chain_network network)
{
    ensure_initialized();
    SelectBaseParams(network);
    switch (network) {
    case CHAIN_MAIN:    pCurrentParams = &mainParams; break;
    case CHAIN_TESTNET: pCurrentParams = &testNetParams; break;
    case CHAIN_REGTEST: pCurrentParams = &regTestParams; break;
    default: assert(false); break;
    }
}

const unsigned char *chain_params_base58_prefix(const struct chain_params *p,
                                                 enum base58_type type,
                                                 size_t *len_out)
{
    *len_out = p->base58PrefixLengths[type];
    return p->base58Prefixes[type];
}

unsigned int chain_params_equihash_n(const struct chain_params *p, int height)
{
    int epoch = consensus_current_epoch(height, &p->consensus);
    unsigned int n = EquihashUpgradeInfo[epoch].N;
    return (n == EQUIHASH_DEFAULT_PARAMS) ? p->nEquihashN : n;
}

unsigned int chain_params_equihash_k(const struct chain_params *p, int height)
{
    int epoch = consensus_current_epoch(height, &p->consensus);
    unsigned int k = EquihashUpgradeInfo[epoch].K;
    return (k == EQUIHASH_DEFAULT_PARAMS) ? p->nEquihashK : k;
}

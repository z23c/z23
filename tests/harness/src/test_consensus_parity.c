/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_consensus_parity — golden assertion that zclassic23's consensus
 * constants are EXACTLY zclassicd's (the canonical C++ ZClassic daemon).
 *
 * zclassic23 must be bit-for-bit consensus-compatible with zclassicd
 * (docs/CONSENSUS_PARITY_DOCTRINE.md). The values below are golden,
 * cross-referenced against the zclassicd source (src/chainparams.cpp,
 * src/consensus/upgrades.cpp). If a future change drifts a consensus
 * constant off these values, this test fails — by design. To change a
 * value you must change zclassicd FIRST and ship it network-wide; this
 * test is the tripwire that makes silent divergence impossible.
 *
 * Companion guard: tools/scripts/check_consensus_parity.sh (lint gate
 * E13) bans the *mechanism* class (miner-signaled versionbits / dynamic
 * Equihash override). This test pins the *values*.
 */

#include "test/test_core.h"
#include "chain/chainparams.h"
#include "consensus/params.h"
#include "consensus/upgrades.h"
#include "core/uint256.h"
#include "domain/consensus/tx_structural.h"
#include "coins/utxo_commitment.h"   /* C8: pin the UTXO commitment byte-layout */
#include "crypto/sha3.h"

/* The generated empirical oversize-grandfather table (see
 * docs/CONSENSUS_PARITY_DOCTRINE.md "Empirical oversize grandfather"),
 * included directly so the golden pins below bind the artifact, not just
 * the predicate. consensus/consensus.h is NOT included (its unguarded
 * MAX_BLOCK_SIGOPS collides with validation/main_constants.h via
 * test/test_core.h); the 102000 cap is pinned as a literal below. */
#include "../../../core/consensus/src/oversize_grandfather_table.inc"

#include <stdio.h>
#include <string.h>

int test_consensus_parity(void)
{
    int failures = 0;

    /* Pin to mainnet — the chain whose parity with zclassicd is load-bearing. */
    chain_params_select(CHAIN_MAIN);
    const struct chain_params *p = chain_params_get();
    const struct consensus_params *c = &p->consensus;

#define CHECK(desc, cond)                                                 \
    do {                                                                  \
        printf("consensus-parity: %s... ", (desc));                       \
        if (cond) printf("OK\n");                                         \
        else { printf("FAIL\n"); failures++; }                            \
    } while (0)

    /* ── Equihash defaults (zclassicd src/chainparams.cpp: N=200, K=9) ── */
    CHECK("nEquihashN == 200", p->nEquihashN == 200);
    CHECK("nEquihashK == 9",   p->nEquihashK == 9);

    /* ── Equihash per-epoch table (zclassicd consensus/upgrades.cpp).
     * Pre-Bubbles epochs use the chain default (200,9); Bubbles/DiffAdj/
     * Buttercup carry the consensus-active (192,7). The (0,0) sentinel
     * means "fall back to the chain default". ── */
    CHECK("EquihashUpgradeInfo[BASE_SPROUT]    == default(0,0)",
          EquihashUpgradeInfo[BASE_SPROUT].N == EQUIHASH_DEFAULT_PARAMS &&
          EquihashUpgradeInfo[BASE_SPROUT].K == EQUIHASH_DEFAULT_PARAMS);
    CHECK("EquihashUpgradeInfo[UPGRADE_OVERWINTER] == default(0,0)",
          EquihashUpgradeInfo[UPGRADE_OVERWINTER].N == EQUIHASH_DEFAULT_PARAMS &&
          EquihashUpgradeInfo[UPGRADE_OVERWINTER].K == EQUIHASH_DEFAULT_PARAMS);
    CHECK("EquihashUpgradeInfo[UPGRADE_SAPLING]    == default(0,0)",
          EquihashUpgradeInfo[UPGRADE_SAPLING].N == EQUIHASH_DEFAULT_PARAMS &&
          EquihashUpgradeInfo[UPGRADE_SAPLING].K == EQUIHASH_DEFAULT_PARAMS);
    CHECK("EquihashUpgradeInfo[UPGRADE_BUBBLES]   == (192,7)",
          EquihashUpgradeInfo[UPGRADE_BUBBLES].N == 192 &&
          EquihashUpgradeInfo[UPGRADE_BUBBLES].K == 7);
    CHECK("EquihashUpgradeInfo[UPGRADE_DIFFADJ]   == (192,7)",
          EquihashUpgradeInfo[UPGRADE_DIFFADJ].N == 192 &&
          EquihashUpgradeInfo[UPGRADE_DIFFADJ].K == 7);
    CHECK("EquihashUpgradeInfo[UPGRADE_BUTTERCUP] == (192,7)",
          EquihashUpgradeInfo[UPGRADE_BUTTERCUP].N == 192 &&
          EquihashUpgradeInfo[UPGRADE_BUTTERCUP].K == 7);

    /* ── Height-aware getters resolve the table by height: 200,9 before the
     * Bubbles fork (585318), 192,7 at and after. This is the single PoW
     * parameter switch zclassicd performs, and it is HEIGHT-keyed only. ── */
    CHECK("equihash_n(pre-Bubbles 585317) == 200",
          chain_params_equihash_n(p, 585317) == 200);
    CHECK("equihash_k(pre-Bubbles 585317) == 9",
          chain_params_equihash_k(p, 585317) == 9);
    CHECK("equihash_n(Bubbles 585318) == 192",
          chain_params_equihash_n(p, 585318) == 192);
    CHECK("equihash_k(Bubbles 585318) == 7",
          chain_params_equihash_k(p, 585318) == 7);
    CHECK("equihash_n(genesis 0) == 200", chain_params_equihash_n(p, 0) == 200);

    /* ── Network-upgrade activation heights (zclassicd src/chainparams.cpp).
     * These are the agreed flag-day schedule; both nodes must use IDENTICAL
     * heights or they fork. ── */
    CHECK("BASE_SPROUT activation == ALWAYS_ACTIVE(0)",
          c->vUpgrades[BASE_SPROUT].nActivationHeight == NETWORK_UPGRADE_ALWAYS_ACTIVE);
    CHECK("UPGRADE_TESTDUMMY activation == NO_ACTIVATION(-1)",
          c->vUpgrades[UPGRADE_TESTDUMMY].nActivationHeight == NETWORK_UPGRADE_NO_ACTIVATION);
    CHECK("UPGRADE_OVERWINTER activation == 476969",
          c->vUpgrades[UPGRADE_OVERWINTER].nActivationHeight == 476969);
    CHECK("UPGRADE_SAPLING activation == 476969",
          c->vUpgrades[UPGRADE_SAPLING].nActivationHeight == 476969);
    CHECK("UPGRADE_BUBBLES activation == 585318",
          c->vUpgrades[UPGRADE_BUBBLES].nActivationHeight == 585318);
    CHECK("UPGRADE_DIFFADJ activation == 585322",
          c->vUpgrades[UPGRADE_DIFFADJ].nActivationHeight == 585322);
    CHECK("UPGRADE_BUTTERCUP activation == 707000",
          c->vUpgrades[UPGRADE_BUTTERCUP].nActivationHeight == 707000);

    /* ── Per-upgrade protocol versions (zclassicd src/chainparams.cpp). ── */
    CHECK("BASE_SPROUT protocol == 170002",
          c->vUpgrades[BASE_SPROUT].nProtocolVersion == 170002);
    CHECK("UPGRADE_OVERWINTER protocol == 170005",
          c->vUpgrades[UPGRADE_OVERWINTER].nProtocolVersion == 170005);
    CHECK("UPGRADE_SAPLING protocol == 170007",
          c->vUpgrades[UPGRADE_SAPLING].nProtocolVersion == 170007);
    CHECK("UPGRADE_BUBBLES protocol == 170009",
          c->vUpgrades[UPGRADE_BUBBLES].nProtocolVersion == 170009);
    CHECK("UPGRADE_DIFFADJ protocol == 170010",
          c->vUpgrades[UPGRADE_DIFFADJ].nProtocolVersion == 170010);
    CHECK("UPGRADE_BUTTERCUP protocol == 170011",
          c->vUpgrades[UPGRADE_BUTTERCUP].nProtocolVersion == 170011);

    /* ── PoW retargeting constants (zclassicd src/chainparams.cpp). ── */
    CHECK("nPowAveragingWindow == 17", c->nPowAveragingWindow == 17);
    CHECK("nPowMaxAdjustDown == 32",   c->nPowMaxAdjustDown == 32);
    CHECK("nPowMaxAdjustUp == 16",     c->nPowMaxAdjustUp == 16);
    CHECK("nPreButtercupPowTargetSpacing == 150",
          c->nPreButtercupPowTargetSpacing == PRE_BUTTERCUP_POW_TARGET_SPACING);
    CHECK("nPostButtercupPowTargetSpacing == 75",
          c->nPostButtercupPowTargetSpacing == POST_BUTTERCUP_POW_TARGET_SPACING);

    /* ── powLimit + genesis hash (uint256 golden values). ── */
    {
        struct uint256 expect_powlimit, expect_genesis;
        uint256_set_hex(&expect_powlimit,
            "0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        uint256_set_hex(&expect_genesis,
            "0007104ccda289427919efc39dc9e4d499804b7bebc22df55f8b834301260602");
        CHECK("powLimit == 0007ffff…ffff",
              uint256_eq(&c->powLimit, &expect_powlimit));
        CHECK("hashGenesisBlock == 0007104ccda2…",
              uint256_eq(&c->hashGenesisBlock, &expect_genesis));
    }

    /* ── Empirical oversize grandfather (zclassicd LIVE-behavior parity).
     * zclassicd's text caps post-Sapling tx size at 102000 unconditionally
     * (src/consensus/consensus.h:27, main.cpp:1196-1200), but the canonical
     * chain carries exactly 413 post-Sapling txs above it (heights
     * 478544..1968856; complete empirical scan, re-verified
     * per-entry against zclassicd by the generator). Running nodes accept
     * them only because validated blocks are never re-checked, and enforce
     * 102000 on every new block. The pins below freeze that ruleset. ── */
    {
        struct uint256 first, last;
        uint256_set_hex(&first,
            "e3eeb123a79945cc74e6107422b124dc130ddd4b61fe5c74087317c256c79700");
        uint256_set_hex(&last,
            "e28d84f48ac642252519ad7d1ca6009cc2eb0ad2c5aaf5d0761c9105518a1db9");

        CHECK("oversize grandfather: table count == 413",
              OVERSIZE_GRANDFATHER_COUNT == 413u);
        uint32_t max_sz = 0;
        bool sorted = true;
        for (size_t i = 0; i < OVERSIZE_GRANDFATHER_COUNT; i++) {
            if (g_oversize_grandfather[i].size > max_sz)
                max_sz = g_oversize_grandfather[i].size;
            if (i > 0 &&
                memcmp(g_oversize_grandfather[i - 1].txid,
                       g_oversize_grandfather[i].txid, 32) >= 0)
                sorted = false;
        }
        CHECK("oversize grandfather: max tx size == 1922197 (h=685036)",
              max_sz == 1922197u);
        CHECK("oversize grandfather: table strictly sorted (bsearch contract)",
              sorted);
        CHECK("oversize grandfather: first violation (e3eeb123 @478544, 125811) excused",
              domain_consensus_tx_oversize_grandfathered(&first, 125811));
        CHECK("oversize grandfather: last violation (e28d84f4 @1968856, 108629) excused",
              domain_consensus_tx_oversize_grandfathered(&last, 108629));
        CHECK("oversize grandfather: wrong size NOT excused (size-exact match)",
              !domain_consensus_tx_oversize_grandfathered(&first, 125810));
    }

    /* ── Golden vector: canonical UTXO SHA3 commitment byte-layout ──────────
     * utxo_sha3_serialize_record() is the "must-never-fork" consensus encoder
     * behind the UTXO commitment that C8 parity rests on. Pin its exact byte
     * output AND a streamed multi-record SHA3-256 digest to constants computed
     * INDEPENDENTLY (Python hashlib.sha3_256), so a silent layout / endianness /
     * is_coinbase-normalization drift fails LOUD here — a cross-implementation
     * contract, not a zclassic23-vs-zclassic23 self-comparison. Layout:
     * txid[32] || vout(LE32) || value(LE64) || slen(LE32) || script ||
     * height(LE32) || is_coinbase(1 byte, normalized to 0/1). */
    {
        uint8_t a_txid[32];
        for (int i = 0; i < 32; i++) a_txid[i] = (uint8_t)i;
        static const uint8_t a_script[25] = {
            0x76,0xa9,0x14, 0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
            0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11, 0x88,0xac };
        /* serialize(a_txid, vout=7, value=12345678901, a_script, h=654321, cb=0) */
        static const uint8_t A_GOLDEN[78] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,
            0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,
            0x1c,0x1d,0x1e,0x1f,0x07,0x00,0x00,0x00,0x35,0x1c,0xdc,0xdf,0x02,0x00,
            0x00,0x00,0x19,0x00,0x00,0x00,0x76,0xa9,0x14,0x11,0x11,0x11,0x11,0x11,
            0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
            0x11,0x88,0xac,0xf1,0xfb,0x09,0x00,0x00 };

        uint8_t rec[256];
        size_t rlen = 0;
        bool ok_a = utxo_sha3_serialize_record(rec, sizeof(rec), &rlen,
                        a_txid, 7u, (int64_t)12345678901LL,
                        a_script, (uint32_t)sizeof(a_script), 654321u, 0);
        CHECK("utxo sha3 record A: serializes to independent golden bytes",
              ok_a && rlen == sizeof(A_GOLDEN) &&
              memcmp(rec, A_GOLDEN, sizeof(A_GOLDEN)) == 0);

        /* Record B: coinbase, EMPTY script; is_coinbase passed as 2 MUST
         * normalize to the trailing byte 0x01 (not 0x02). */
        uint8_t b_txid[32];
        memset(b_txid, 0xCB, sizeof(b_txid));
        static const uint8_t B_GOLDEN[53] = {
            0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,
            0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,0xcb,
            0xcb,0xcb,0xcb,0xcb,0x00,0x00,0x00,0x00,0x40,0xbe,0x40,0x25,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x76,0xa4,0x2e,0x00,0x01 };
        size_t rlen_b = 0;
        bool ok_b = utxo_sha3_serialize_record(rec, sizeof(rec), &rlen_b,
                        b_txid, 0u, (int64_t)625000000LL,
                        NULL, 0u, 3056758u, 2);
        CHECK("utxo sha3 record B: empty script + is_coinbase 2 -> 0x01 golden",
              ok_b && rlen_b == sizeof(B_GOLDEN) &&
              memcmp(rec, B_GOLDEN, sizeof(B_GOLDEN)) == 0 &&
              B_GOLDEN[sizeof(B_GOLDEN) - 1] == 0x01);

        /* Streamed SHA3-256 over record A then B via the PRODUCTION sponge
         * writer; digest pinned to the independent Python computation. */
        static const uint8_t DIGEST_GOLDEN[32] = {
            0x94,0xf2,0x28,0x4f,0x24,0xd3,0x2f,0xfa,0x44,0x68,0x08,0x37,0xcc,0x1b,
            0xcf,0x97,0x07,0xba,0x39,0x66,0x30,0xcc,0xd2,0x75,0x00,0x82,0x4f,0x32,
            0x00,0xef,0x7a,0xe0 };
        struct sha3_256_ctx sctx;
        sha3_256_init(&sctx);
        utxo_commitment_sha3_write_record(&sctx, a_txid, 7u,
                        (int64_t)12345678901LL, a_script,
                        (uint32_t)sizeof(a_script), 654321u, 0);
        utxo_commitment_sha3_write_record(&sctx, b_txid, 0u,
                        (int64_t)625000000LL, NULL, 0u, 3056758u, 2);
        uint8_t digest[32];
        sha3_256_finalize(&sctx, digest);
        CHECK("utxo sha3 streamed digest(A||B) matches independent golden",
              memcmp(digest, DIGEST_GOLDEN, 32) == 0);
    }

#undef CHECK

    if (failures)
        printf("=== consensus-parity: %d golden constant(s) drifted from "
               "zclassicd — see docs/CONSENSUS_PARITY_DOCTRINE.md ===\n", failures);
    return failures;
}

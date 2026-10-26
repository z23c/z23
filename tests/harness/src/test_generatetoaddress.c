/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_generatetoaddress — a regtest node must be able to mine SPENDABLE coins.
 *
 * GUARD. `generate N` (engine/controllers/src/mining_controller.c) builds
 * coinbases paying a ZERO-LENGTH scriptPubKey: valid blocks, but the subsidy
 * lands on a script nobody owns, so a regtest wallet can never be funded.
 * `generatetoaddress numblocks "address"` decodes a transparent address with
 * the ACTIVE chain's base58 prefixes and pays every coinbase to
 * script_for_destination(dest). Both RPCs share one guard
 * (mining_on_demand_allowed) and one loop (mining_generate_to_script); only
 * the payee script differs.
 *
 * WHAT THIS TEST ASSERTS (real codecs, real consensus, no stubs)
 * -------------------------------------------------------------
 *   1. A regtest address round-trips: key_id -> address -> decode_destination
 *      -> the SAME key_id, and script_for_destination yields the canonical
 *      25-byte P2PKH scriptPubKey.
 *   2. A coinbase built exactly the way create_new_block() builds it, with
 *      that script, carries the subsidy on that scriptPubKey and
 *      script_extract_destination recovers the ORIGINAL key id — i.e. the
 *      coins are addressable by the wallet that holds the key.
 *   3. The resulting block still passes the reducer's intake gate,
 *      check_block(check_pow=true, merkle=true, size=true), after
 *      mine_block_pow() solves the real regtest Equihash (48,5).
 *   4. THE BUG, pinned: the same coinbase built with the empty script has a
 *      zero-length scriptPubKey and NO extractable destination. That is the
 *      precise reason a regtest wallet could never be funded.
 *   5. Cross-network safety: an address encoded with MAINNET prefixes is
 *      REJECTED while regtest params are selected, so generatetoaddress
 *      cannot be talked into paying a mainnet address on regtest.
 */

#include "test/test_core.h"

#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "chain/subsidy.h"
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "domain/consensus/coinbase.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "mining/miner.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "validation/check_block.h"

#include <stdio.h>
#include <string.h>

/* Encode `dest` as a Base58Check address using the ACTIVE chain's prefixes —
 * the same pair rpc_generatetoaddress resolves. */
static bool gta_encode(const struct tx_destination *dest,
                       char *out, size_t out_size)
{
    const struct chain_params *cp = chain_params_get();
    size_t pk_len = 0, sc_len = 0;
    const unsigned char *pk =
        chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sc =
        chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_len);
    return encode_destination(dest, pk, pk_len, sc, sc_len, out, out_size);
}

/* Decode an address with the ACTIVE chain's prefixes — verbatim what
 * rpc_generatetoaddress does before building the coinbase script. */
static bool gta_decode(const char *addr, struct tx_destination *dest)
{
    const struct chain_params *cp = chain_params_get();
    size_t pk_len = 0, sc_len = 0;
    const unsigned char *pk =
        chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sc =
        chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_len);
    return decode_destination(addr, pk, pk_len, sc, sc_len, dest);
}

/* Build a regtest block at `height` the way create_new_block() shapes it: one
 * coinbase tx (subsidy, no fees, the given miner script), merkle root over it,
 * header fields filled, nBits = the regtest powLimit compact. */
static bool gta_build_block(struct block *blk, int height,
                            const struct uint256 *prev_hash,
                            const struct chain_params *cp,
                            const struct script *miner_script,
                            int64_t *out_value)
{
    block_init(blk);
    blk->vtx = calloc(1, sizeof(struct transaction));
    if (!blk->vtx)
        return false;
    blk->num_vtx = 1;

    struct transaction *coinbase = &blk->vtx[0];
    transaction_init(coinbase);
    if (!transaction_alloc(coinbase, 1, 1))
        return false;

    int64_t subsidy = get_block_subsidy(height, &cp->consensus);
    struct domain_consensus_coinbase_inputs cb_in = {
        .n_height     = height,
        .subsidy      = subsidy,
        .total_fees   = 0,
        .miner_script = miner_script,
        .params       = &cp->consensus,
    };
    struct zcl_result r = domain_consensus_coinbase_build(&cb_in, coinbase);
    if (!r.ok)
        return false;

    if (out_value)
        *out_value = subsidy;

    struct uint256 txid = blk->vtx[0].hash;
    blk->header.hashMerkleRoot = compute_merkle_root(&txid, 1);
    blk->header.hashPrevBlock = *prev_hash;
    uint256_set_null(&blk->header.hashFinalSaplingRoot);
    blk->header.nTime = 1600000000u + (uint32_t)height;

    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    blk->header.nBits = arith_uint256_get_compact(&pow_limit, false);

    return true;
}

/* A canonical 25-byte P2PKH scriptPubKey: OP_DUP OP_HASH160 <20-byte key
 * id> OP_EQUALVERIFY OP_CHECKSIG, paying exactly `kid`. */
static bool gta_is_p2pkh_script(const struct script *s,
                                const struct key_id *kid)
{
    return s->size == 25 && s->data[0] == 0x76 &&
           s->data[1] == 0xa9 && s->data[2] == 0x14 &&
           s->data[23] == 0x88 && s->data[24] == 0xac &&
           memcmp(&s->data[3], kid->id.data, 20) == 0;
}

/* The coinbase carries the payee script: a coinbase with exactly one output
 * of the expected value whose scriptPubKey is byte-identical to
 * `pay_script`. */
static bool gta_coinbase_pays_script(const struct transaction *cb,
                                     int64_t value,
                                     const struct script *pay_script)
{
    return transaction_is_coinbase(cb) && cb->num_vout == 1 &&
           cb->vout[0].value == value && cb->vout[0].value > 0 &&
           cb->vout[0].script_pub_key.size == pay_script->size &&
           memcmp(cb->vout[0].script_pub_key.data, pay_script->data,
                  pay_script->size) == 0;
}

/* Assertion (1): the fixed key id encodes to a regtest address, decodes
 * back to the SAME key id, and yields the canonical P2PKH script, left in
 * *pay_script for the mined-block checks. Returns the failure count. */
static int gta_check_address_round_trip(const struct tx_destination *want,
                                        const struct key_id *kid,
                                        struct script *pay_script)
{
    int failures = 0;
    char addr[128] = {0};
    printf("generatetoaddress: key id encodes to a regtest address... ");
    if (gta_encode(want, addr, sizeof(addr))) printf("OK (%s)\n", addr);
    else { printf("FAIL\n"); failures++; }

    struct tx_destination got;
    memset(&got, 0, sizeof(got));
    printf("generatetoaddress: address decodes back to the same key id... ");
    if (gta_decode(addr, &got) && got.type == DEST_KEY_ID &&
        memcmp(got.id.key.id.data, kid->id.data, 20) == 0)
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    script_init(pay_script);
    script_for_destination(pay_script, &got);
    printf("generatetoaddress: destination yields a 25-byte P2PKH script... ");
    if (gta_is_p2pkh_script(pay_script, kid))
        printf("OK\n");
    else { printf("FAIL (size=%zu)\n", (size_t)pay_script->size); failures++; }
    return failures;
}

/* Assertions (2)+(3): the block built the way create_new_block() shapes it
 * pays that address, the subsidy is recoverable as the ORIGINAL key id, and
 * the solved block still passes the reducer's intake gate. Returns the
 * failure count. */
static int gta_check_mined_block_pays_address(
    const struct chain_params *cp, const struct key_id *kid,
    const struct script *pay_script)
{
    int failures = 0;
    struct uint256 prev = cp->consensus.hashGenesisBlock;
    const int height = 1;
    struct block blk;
    int64_t value = 0;

    printf("generatetoaddress: build coinbase paying the address... ");
    if (gta_build_block(&blk, height, &prev, cp, pay_script, &value))
        printf("OK (subsidy=%lld)\n", (long long)value);
    else { printf("FAIL\n"); failures++; block_free(&blk); return failures; }

    {
        const struct transaction *cb = &blk.vtx[0];
        printf("generatetoaddress: coinbase output carries the payee "
               "script... ");
        if (gta_coinbase_pays_script(cb, value, pay_script))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }

        /* The coin is addressable: a wallet holding this key recognises and
         * can spend it after COINBASE_MATURITY. */
        struct tx_destination back;
        memset(&back, 0, sizeof(back));
        printf("generatetoaddress: coinbase output is owned by the address "
               "(destination recoverable)... ");
        if (script_extract_destination(&cb->vout[0].script_pub_key, &back) &&
            back.type == DEST_KEY_ID &&
            memcmp(back.id.key.id.data, kid->id.data, 20) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("generatetoaddress: mine_block_pow solves regtest Equihash "
           "(48,5)... ");
    if (mine_block_pow(&blk, height, cp, 0)) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    {
        struct validation_state vs;
        validation_state_init(&vs);
        printf("generatetoaddress: block passes the reducer's "
               "check_block(pow=true)... ");
        if (check_block(&blk, &vs, cp, true, true, true)) printf("OK\n");
        else {
            printf("FAIL (%s)\n",
                   vs.reject_reason[0] ? vs.reject_reason : "unknown");
            failures++;
        }
    }
    block_free(&blk);
    return failures;
}

/* Assertion (4): the same coinbase built with `generate`'s empty script has
 * a zero-length scriptPubKey and no extractable destination. Returns the
 * failure count. */
static int gta_check_empty_script_coinbase(const struct chain_params *cp)
{
    int failures = 0;
    struct uint256 prev = cp->consensus.hashGenesisBlock;
    const int height = 1;
    struct script empty;
    script_init(&empty);
    struct block eblk;
    int64_t evalue = 0;
    printf("generatetoaddress: empty-script coinbase (what plain "
           "`generate` mints) has NO owner... ");
    if (gta_build_block(&eblk, height, &prev, cp, &empty, &evalue)) {
        struct tx_destination none;
        memset(&none, 0, sizeof(none));
        bool empty_spk = eblk.vtx[0].vout[0].script_pub_key.size == 0;
        bool no_dest =
            !script_extract_destination(&eblk.vtx[0].vout[0].script_pub_key,
                                        &none);
        if (empty_spk && no_dest) printf("OK (unspendable, as designed)\n");
        else { printf("FAIL\n"); failures++; }
    } else { printf("FAIL (build)\n"); failures++; }
    block_free(&eblk);
    return failures;
}

/* Assertion (5): an address encoded with MAINNET prefixes is rejected while
 * regtest params are selected. Returns the failure count. */
static int gta_check_mainnet_address_rejected(bool main_encoded,
                                              const char *mainnet_addr)
{
    int failures = 0;
    printf("generatetoaddress: a MAINNET address is rejected on regtest... ");
    if (main_encoded) {
        struct tx_destination rejected;
        memset(&rejected, 0, sizeof(rejected));
        if (!gta_decode(mainnet_addr, &rejected)) printf("OK\n");
        else { printf("FAIL (accepted %s)\n", mainnet_addr); failures++; }
    } else { printf("FAIL (could not encode a mainnet address)\n"); failures++; }
    return failures;
}

int test_generatetoaddress(void);
int test_generatetoaddress(void)
{
    int failures = 0;
    printf("\n=== generatetoaddress: mine a regtest coinbase that a wallet "
           "address actually owns ===\n");

    /* A fixed, synthetic hash160 standing in for a wallet key's id. */
    struct key_id kid;
    for (int i = 0; i < 20; i++)
        kid.id.data[i] = (uint8_t)(0xA0 + i);

    struct tx_destination want;
    want.type = DEST_KEY_ID;
    want.id.key = kid;

    /* A mainnet-prefixed address, minted before switching to regtest. */
    chain_params_select(CHAIN_MAIN);
    char mainnet_addr[128] = {0};
    bool main_encoded = gta_encode(&want, mainnet_addr, sizeof(mainnet_addr));

    /* ── (0) the gate itself: generatetoaddress, the regtest wallet-projection
     * feed in tip_finalize_post_step and wallet_advance_confirmations sit
     * behind fMineBlocksOnDemand, true on regtest and FALSE on both live
     * networks. */
    {
        chain_params_select(CHAIN_MAIN);
        bool main_on_demand = chain_params_get()->fMineBlocksOnDemand;
        chain_params_select(CHAIN_TESTNET);
        bool test_on_demand = chain_params_get()->fMineBlocksOnDemand;
        chain_params_select(CHAIN_REGTEST);
        bool reg_on_demand = chain_params_get()->fMineBlocksOnDemand;

        printf("generatetoaddress: mine-on-demand is regtest-only "
               "(main=%d testnet=%d regtest=%d)... ",
               (int)main_on_demand, (int)test_on_demand, (int)reg_on_demand);
        if (!main_on_demand && !test_on_demand && reg_on_demand) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();

    /* ── (1) address round-trip ──────────────────────────────────── */
    struct script pay_script;
    failures += gta_check_address_round_trip(&want, &kid, &pay_script);

    /* ── (2)+(3) the mined block pays that address and passes the
     * reducer's intake gate ─────────────────────────────────────── */
    failures += gta_check_mined_block_pays_address(cp, &kid, &pay_script);

    /* ── (4) the bug, pinned: `generate`'s empty script owns nothing ── */
    failures += gta_check_empty_script_coinbase(cp);

    /* ── (5) cross-network safety ────────────────────────────────── */
    failures += gta_check_mainnet_address_rejected(main_encoded, mainnet_addr);

    chain_params_select(CHAIN_MAIN);

    printf("=== generatetoaddress test complete: %d failure(s) ===\n",
           failures);
    return failures;
}

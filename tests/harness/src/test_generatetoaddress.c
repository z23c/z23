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
#include "test/reducer_prebinding_fixture.h"

#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "chain/subsidy.h"
#include "consensus/validation.h"
#include "controllers/mining_controller.h"
#include "controllers/sovereignty_controller.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "domain/consensus/coinbase.h"
#include "domain/consensus/upgrades.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "jobs/reducer_frontier.h"
#include "mining/miner.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sapling/incremental_merkle_tree.h"
#include "script/script.h"
#include "script/standard.h"
#include "rpc/server.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
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

static bool gta_mining_authority(sqlite3 *db)
{
    uint8_t txid[32] = {0x43};
    return db && coins_kv_ensure_schema(db) &&
        coins_kv_add(db, txid, 0, 5000, 50, true, NULL, 0) &&
        sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK &&
        coins_kv_set_applied_height_in_tx(db, 51) &&
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK &&
        coins_kv_mark_migration_complete(db) && coins_kv_mark_self_folded(db);
}

static int gta_testnet_refusal(const struct tx_destination *dest)
{
    int failures = 0;
    char dir[512] = {0}, address[128] = {0}, raw[180];
    struct json_value params = {0}, result = {0};
    struct rpc_table table;
    bool opened = test_mkdtemp(dir, sizeof(dir), "gta_guard") && progress_store_open(dir);
    sqlite3 *db = opened ? progress_store_db() : NULL;
    reducer_frontier_provable_tip_set(50);
    bool ready = gta_mining_authority(db);
    chain_params_select(CHAIN_TESTNET);
    ready = ready && gta_encode(dest, address, sizeof(address));
    snprintf(raw, sizeof(raw), "[1,\"%s\"]", address);
    rpc_table_init(&table);
    register_mining_rpc_commands(&table);
    set_rpc_warmup_finished();
    char reason[96] = {0};
    ready = ready && sovereignty_guard_allow("mint", reason, sizeof(reason)) &&
        json_read(&params, raw, strlen(raw));
    int before = reducer_frontier_provable_tip_cached();
    bool refused = ready && !rpc_table_execute(&table, "generatetoaddress", &params, &result);
    bool ok = refused && result.type == JSON_STR &&
        strstr(json_get_str(&result), "regtest only") &&
        reducer_frontier_provable_tip_cached() == before;
    printf("generatetoaddress: testnet refuses on-demand mining without a block... %s\n",
           ok ? "OK" : "FAIL");
    if (!ok) failures++;
    json_free(&params);
    json_free(&result);
    chain_params_select(CHAIN_MAIN);
    reducer_frontier_provable_tip_reset();
    if (opened) progress_store_close();
    if (dir[0]) test_rm_rf(dir);
    return failures;
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

/* A header commits to the Sapling frontier root after its block, and a block
 * with no shielded outputs carries the previous root. The regtest miner used
 * to stamp the root only on blocks that held shielded outputs, so every other
 * block was mined with a zero root and the wallet refused to spend against
 * such a tip ("the chain has no Sapling root at the tip"). Stamp a
 * commitment-free block against a persisted one-note frontier. */
static bool gta_legacy_evidence(sqlite3 *db, const uint8_t hash[32])
{
    static const uint8_t applied[8] = {7}, one = 1;
    return rf_fixture_build_schema(db) &&
        sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS coins(k BLOB PRIMARY KEY,v BLOB);"
            "INSERT INTO coins VALUES(x'01',x'01')", NULL, NULL, NULL) == SQLITE_OK &&
        progress_meta_set(db, COINS_APPLIED_HEIGHT_KEY, applied, sizeof(applied)) &&
        progress_meta_set(db, COINS_KV_MIGRATION_COMPLETE_KEY, &one, 1) &&
        rf_fixture_insert(db, "INSERT INTO header_admit_log(height,hash,admitted_at) VALUES(?1,?2,0)", 6, hash) &&
        rf_fixture_insert(db, "INSERT INTO validate_headers_log(height,hash,ok) VALUES(?1,?2,1)", 6, hash) &&
        rf_fixture_insert(db, "INSERT INTO script_validate_log(height,block_hash,status,ok) VALUES(?1,?2,'verified',1)", 6, hash) &&
        rf_fixture_insert(db, "INSERT INTO proof_validate_log(height,block_hash,status,ok) VALUES(?1,?2,'verified',1)", 6, hash) &&
        rf_fixture_insert(db, "INSERT INTO utxo_apply_log(height,status,ok) VALUES(?1,'verified',1)", 6, NULL) &&
        rf_fixture_put_utxo_delta(db, 6, hash);
}

static int gta_check_legacy_sapling(const struct chain_params *cp, const struct uint256 *root)
{
    struct block block;
    block_init(&block);
    memset(block.header.hashPrevBlock.data, 0x44, 32);
    struct uint256 zero;
    uint256_set_null(&zero);
    bool ok = gta_legacy_evidence(progress_store_db(), block.header.hashPrevBlock.data) &&
        mining_stamp_sapling_final_root(&block, 7, cp, &zero, false) &&
        uint256_eq(&block.header.hashFinalSaplingRoot, root);
    block.header.hashPrevBlock.data[0] ^= 1;
    ok = ok && !mining_stamp_sapling_final_root(&block, 7, cp, &zero, false);
    printf("generatetoaddress: zero legacy root needs exact validated coins parent... ");
    if (ok) { puts("OK"); return 0; }
    puts("FAIL"); return 1;
}

static int gta_check_sapling_outputs(const struct chain_params *cp,
    struct incremental_merkle_tree *parent_tree, const struct uint256 *parent_root)
{
    struct transaction txs[2] = {0};
    struct output_description outs[2] = {0};
    for (size_t i = 0; i < 2; i++) {
        memset(&outs[i].cm, (int)(0x11 + 0x11 * i), sizeof(outs[i].cm));
        txs[i].num_shielded_output = 1;
        txs[i].v_shielded_output = &outs[i];
        incremental_tree_append(parent_tree, &outs[i].cm);
    }
    struct uint256 expected, missing, zero;
    incremental_tree_root(parent_tree, &expected);
    memset(&missing, 0x77, sizeof(missing));
    uint256_set_null(&zero);
    struct block block;
    block_init(&block);
    block.num_vtx = 2;
    block.vtx = txs;
    bool ok = mining_stamp_sapling_final_root(&block, 7, cp, parent_root, false) &&
        uint256_eq(&block.header.hashFinalSaplingRoot, &expected) &&
        !mining_stamp_sapling_final_root(&block, 7, cp, &missing, false) &&
        !mining_stamp_sapling_final_root(&block, 7, cp, &zero, false);
    printf("generatetoaddress: ordered outputs use the named parent and gaps fail closed... ");
    if (ok) { puts("OK"); return 0; }
    puts("FAIL"); return 1;
}

static int gta_check_sapling_transition(const struct chain_params *cp,
    const struct chain_params *shielded, const struct uint256 *parent_root)
{
    struct incremental_merkle_tree empty;
    struct uint256 empty_root, zero;
    sapling_tree_init(&empty);
    incremental_tree_root(&empty, &empty_root);
    uint256_set_null(&zero);
    struct block genesis, activation, before;
    block_init(&genesis); block_init(&activation); block_init(&before);
    struct chain_params activation_params = *cp;
    activation_params.consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight = 6;
    bool ok = mining_stamp_sapling_final_root(&genesis, 1, shielded, &zero, true) &&
        uint256_eq(&genesis.header.hashFinalSaplingRoot, &empty_root) &&
        mining_stamp_sapling_final_root(&activation, 6, &activation_params, &zero, false) &&
        uint256_eq(&activation.header.hashFinalSaplingRoot, &empty_root) &&
        mining_stamp_sapling_final_root(&before, 6, cp, parent_root, false) &&
        uint256_eq(&before.header.hashFinalSaplingRoot, &zero);
    printf("generatetoaddress: genesis, activation and pre-activation roots... ");
    if (ok) { puts("OK"); return 0; }
    puts("FAIL"); return 1;
}

static int gta_check_sapling_root_stamp(const struct chain_params *cp)
{
    int failures = 0;
    char dir[512] = {0};
    bool opened = test_mkdtemp(dir, sizeof(dir), "gta_root") && progress_store_open(dir);
    bool ready = opened && progress_store_db() && anchor_kv_ensure_schema(progress_store_db());
    struct incremental_merkle_tree tree;
    struct uint256 cm, parent_root, later_root;
    sapling_tree_init(&tree);
    memset(&cm, 0x5a, sizeof(cm));
    incremental_tree_append(&tree, &cm);
    incremental_tree_root(&tree, &parent_root);
    ready = ready && anchor_kv_add_tree(progress_store_db(), ANCHOR_POOL_SAPLING, &tree, 5);
    struct incremental_merkle_tree parent_tree = tree;
    memset(&cm, 0x33, sizeof(cm));
    incremental_tree_append(&tree, &cm);
    incremental_tree_root(&tree, &later_root);
    ready = ready && anchor_kv_add_tree(progress_store_db(), ANCHOR_POOL_SAPLING, &tree, 6);
    struct chain_params shielded = *cp;
    shielded.consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight = 0;
    struct block block;
    block_init(&block);
    bool carries = ready && mining_stamp_sapling_final_root(&block, 7, &shielded, &parent_root, false) &&
        uint256_eq(&block.header.hashFinalSaplingRoot, &parent_root);
    printf("generatetoaddress: commitment-free block carries captured parent root... ");
    if (carries) puts("OK"); else { puts("FAIL"); failures++; }
    if (ready) {
        failures += gta_check_sapling_outputs(&shielded, &parent_tree, &parent_root);
        failures += gta_check_sapling_transition(cp, &shielded, &parent_root);
        failures += gta_check_legacy_sapling(&shielded, &later_root);
    }
    if (opened) progress_store_close();
    if (dir[0]) test_rm_rf(dir);
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
    failures += gta_testnet_refusal(&want);

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

    failures += gta_check_sapling_root_stamp(cp);

    /* ── (5) cross-network safety ────────────────────────────────── */
    failures += gta_check_mainnet_address_rejected(main_encoded, mainnet_addr);

    chain_params_select(CHAIN_MAIN);

    printf("=== generatetoaddress test complete: %d failure(s) ===\n",
           failures);
    return failures;
}

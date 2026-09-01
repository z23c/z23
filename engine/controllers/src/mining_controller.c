/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "views/format_helpers.h"
#include "controllers/mining_controller.h"
#include "controllers/network_controller.h"  /* rpc_net_get_connman */
#include "controllers/sovereignty_controller.h"
#include "controllers/strong_params.h"
#include "net/connman.h"                      /* connman_relay_block */
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "consensus/upgrades.h"
#include "core/core_io.h"
#include "core/serialize.h"
#include "encoding/utilstrencodings.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "keys/key_io.h"                      /* decode_destination */
#include "mining/miner.h"
#include "primitives/block.h"
#include "script/script.h"
#include "script/standard.h"                  /* script_for_destination */
#include "validation/chainstate.h"
#include "validation/process_block.h"
#include "services/chain_activation_service.h"
#include "chain/subsidy.h"
#include "storage/anchor_kv.h"
#include "storage/progress_store.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/util.h"  /* LogPrintf */

struct mining_context {
    struct main_state *main_state;
    struct tx_mempool *mempool;
    struct coins_view_cache *coins_tip;
};

static struct mining_context g_mining_ctx = {0};

static struct mining_context *mining_ctx(void)
{
    return &g_mining_ctx;
}

/* Announce a just-accepted local tip block to connected peers. Locally-minted
 * (`generate`) and externally-submitted (`submitblock`) blocks are accepted
 * through reducer_ingest_block directly, never through the P2P block-receive
 * relay in msg_blocks.c, so without this an already-connected peer never hears
 * about the new tip and can sit one-or-more blocks behind until it re-queries
 * on its own. This is the standard full-node behaviour: a node that accepts a
 * new best-chain tip advertises it. connman_relay_block is bounded (one inv
 * per peer, per-peer known-inventory filtered) and a no-op when there are no
 * handshaked peers, so it is safe on every network. */
static void mining_announce_accepted_block(const struct uint256 *hash)
{
    struct connman *cm = rpc_net_get_connman();
    if (cm)
        connman_relay_block(cm, hash);
}

static bool mining_submit_mined_block(struct block *block)
{
    struct validation_state state;
    validation_state_init(&state);
    bool ok = reducer_ingest_block(boot_activation_controller(), block,
                                   REDUCER_SRC_MINED, true, &state);
    if (ok) {
        struct uint256 h;
        block_get_hash(block, &h);
        mining_announce_accepted_block(&h);
    }
    if (!ok) {
        /* Surface WHY the reducer rejected a locally-mined block. Without
         * this, `generate` returns an empty result array with no clue why
         * the tip didn't advance (the validation_state was dropped on the
         * floor). Log the reject reason + the block hash for the operator. */
        char msg[MAX_REJECT_REASON + 64];
        format_state_message(&state, msg, sizeof(msg));
        struct uint256 h;
        block_get_hash(block, &h);
        char hex[65];
        uint256_get_hex(&h, hex);
        LogPrintf("[mining] submit of mined block %s REJECTED by reducer: %s\n",
                  hex, msg[0] ? msg : "(no reason set)");
    }
    return ok;
}

void rpc_mining_set_state(struct main_state *ms, struct tx_mempool *mp,
                           struct coins_view_cache *coins_tip)
{
    struct mining_context *ctx = mining_ctx();
    ctx->main_state = ms;
    ctx->mempool = mp;
    ctx->coins_tip = coins_tip;
}

static bool rpc_getmininginfo(const struct json_value *params, bool help,
                                struct json_value *result)
{
    struct mining_context *ctx = mining_ctx();
    (void)params;
    RPC_HELP(help, result,
        "getmininginfo\n"
        "Returns mining-related information.");

    if (!ctx->main_state) {
        json_set_str(result, "Mining state not initialized");
        LOG_FAIL("mining", "getmininginfo: ctx->main_state is NULL");
    }

    const struct chain_params *cp = chain_params_get();
    struct block_index *tip = active_chain_tip(&ctx->main_state->chain_active);

    json_set_object(result);
    /* "blocks" reports the PROVABLE tip (H*), matching getblockcount — never a
     * height we cannot prove / that rewinds under a reorg. `tip` (the active
     * tip) is still used below for difficulty and the next-template height,
     * which legitimately build on the live tip; only the externally-reported
     * height field is clamped to H*. */
    int32_t hstar_mining = reducer_frontier_provable_tip_cached();
    json_push_kv_int(result, "blocks", hstar_mining);
    json_push_kv_int(result, "currentblocksize",
                      (int64_t)ctx->main_state->nLastBlockSize);
    json_push_kv_int(result, "currentblocktx",
                      (int64_t)ctx->main_state->nLastBlockTx);

    /* Use the centralized ZCL difficulty helper (pow.h). The inline Bitcoin
     * mantissa math here used the wrong 0x00ffff baseline AND truncated the
     * 3-byte mantissa to its top byte — yielding ~599177 vs the canonical
     * ~71.6 and freezing across retargets (top byte 0x1c is shared). pow.h
     * is the single source of truth every other RPC/explorer surface uses. */
    double difficulty = tip ? difficulty_from_index(tip) : 0.0;
    json_push_kv_real(result, "difficulty", difficulty);

    json_push_kv_str(result, "chain", cp->strNetworkID);
    json_push_kv_bool(result, "generate", false);

    return true;
}

/* Shared admission check for both on-demand mint entry points (`generate`
 * and `generatetoaddress`). Two conditions, in this order:
 *
 *   1. Sovereign guard (docs/work/shielded-history-importer.md §5.3):
 *      refuse to mint on a borrowed-and-not-self-folded (release_assisted)
 *      shielded history. This gates the MINT action only — tip-following
 *      (rpc_submitblock accepting a block relayed/mined by someone else, the
 *      reducer's own forward fold) is never touched here.
 *   2. On-demand mining is a regtest facility. On mainnet/testnet the
 *      Equihash parameters make an in-process solve impractical (and mining
 *      goes through real workers/peers), so we refuse — matching zcashd's
 *      "regtest mode only" contract via fMineBlocksOnDemand.
 *
 * Sets an explanatory error body in `result` and returns false on refusal. */
static bool mining_on_demand_allowed(const char *rpc_name,
                                     struct json_value *result)
{
    char sov_reason[96] = {0};
    if (!sovereignty_guard_allow("mint", sov_reason, sizeof(sov_reason))) {
        json_set_str(result, "Error: mint refused — tip is "
                             "release_assisted (borrowed shielded "
                             "history, not self-folded)");
        LOG_FAIL("mining", "%s: refused — %s", rpc_name, sov_reason);
    }

    const struct chain_params *cp = chain_params_get();
    if (!cp->fMineBlocksOnDemand) {
        char msg[160];
        snprintf(msg, sizeof(msg),
                 "Error: %s is for regtest only "
                 "(this network is not mine-blocks-on-demand)", rpc_name);
        json_set_str(result, msg);
        LOG_FAIL("mining", "%s: refused — chain %s is not "
                 "mine-blocks-on-demand", rpc_name, cp->strNetworkID);
    }

    return true;
}

/* Stamp hashFinalSaplingRoot on a to-be-mined block carrying shielded
 * outputs. The field sits in the PoW preimage, so this MUST run before
 * mine_block_pow. utxo_apply's Sapling fold recomputes the frontier root for
 * any block with shielded outputs and fails closed on mismatch
 * (sapling_frontier_mismatch, engine/jobs/src/utxo_apply_anchors.c), so a miner
 * that leaves zeros wedges its own chain at the first shielded block — the
 * default for a from-genesis chain with Sapling active (e.g.
 * -regtestshielded). The computation is the simnet Lane C pattern
 * (engine/modules/sim/src/simnet.c): root(latest persisted Sapling frontier + this
 * block's shielded-output commitments, in tx/output order) — exactly what
 * the fold will recompute. No-op unless Sapling is active at the new height,
 * the block has shielded outputs (transparent-only blocks skip the fold
 * check), and the anchor store can positively supply the fold's starting
 * tree; on anything but ANCHOR_KV_FOUND the fold raises its own named gap
 * blocker, which is the accurate failure and must not be masked here. */
static void mining_stamp_sapling_final_root(struct block *block, int height,
                                            const struct chain_params *cp)
{
    if (!cp || !consensus_network_upgrade_active(&cp->consensus, height,
                                                 UPGRADE_SAPLING))
        return;
    bool has_outputs = false;
    for (size_t i = 0; i < block->num_vtx && !has_outputs; i++)
        has_outputs = block->vtx[i].num_shielded_output > 0;
    if (!has_outputs)
        return;
    sqlite3 *db = progress_store_db();
    if (!db) {
        LOG_WARN("mining", "sapling final-root stamp: no progress db");
        return;
    }
    struct incremental_merkle_tree tree;
    if (anchor_kv_latest_tree(db, ANCHOR_POOL_SAPLING, &tree, NULL, NULL) !=
        ANCHOR_KV_FOUND)
        return;
    for (size_t i = 0; i < block->num_vtx; i++)
        for (size_t j = 0; j < block->vtx[i].num_shielded_output; j++)
            incremental_tree_append(&tree,
                                    &block->vtx[i].v_shielded_output[j].cm);
    incremental_tree_root(&tree, &block->header.hashFinalSaplingRoot);
}

/* Mine `num_blocks` blocks on demand, paying every coinbase to
 * `coinbase_script`, and push each accepted block hash into `result` (which
 * this sets to an array). Shared by `generate` and `generatetoaddress` — the
 * ONLY difference between the two RPCs is which script the subsidy pays to.
 *
 * Caller must have passed mining_on_demand_allowed() first. */
static bool mining_generate_to_script(const struct script *coinbase_script,
                                      int64_t num_blocks,
                                      struct json_value *result)
{
    struct mining_context *ctx = mining_ctx();
    const struct chain_params *cp = chain_params_get();

    json_set_array(result);

    for (int64_t i = 0; i < num_blocks; i++) {
        struct block_template *tmpl = create_new_block(
            coinbase_script, ctx->main_state, ctx->coins_tip, ctx->mempool, cp);
        if (!tmpl) break;

        struct block_index *tip = active_chain_tip(&ctx->main_state->chain_active);
        unsigned int extra_nonce = 0;
        increment_extra_nonce(&tmpl->block, tip, &extra_nonce);

        /* Solve the Equihash PoW so the block passes the reducer's
         * stateless check_block(check_pow=true) gate. Without this the
         * block carries an empty solution and is rejected at intake, so
         * the tip never advances. Fast for regtest/testnet (small N,K). */
        int new_height = (tip ? tip->nHeight : 0) + 1;
        mining_stamp_sapling_final_root(&tmpl->block, new_height, cp);
        if (!mine_block_pow(&tmpl->block, new_height, cp, 0)) {
            block_template_free(tmpl);
            free(tmpl);
            break;
        }

        if (mining_submit_mined_block(&tmpl->block)) {
            struct uint256 hash;
            block_get_hash(&tmpl->block, &hash);
            char hex[65];
            uint256_get_hex(&hash, hex);
            struct json_value v = {0};
            json_set_str(&v, hex);
            json_push_back(result, &v);
            json_free(&v);
        }

        block_template_free(tmpl);
        free(tmpl);
    }

    return true;
}

/* Shared numblocks argument decode for both mint entry points. Returns -1 and
 * sets an error body on a missing/out-of-range count. */
static int64_t mining_require_numblocks(const struct json_value *params,
                                        struct rpc_params *p,
                                        struct json_value *result)
{
    rpc_params_init(p, params);
    int64_t num_blocks = rpc_require_int(p, 0, "numblocks");
    if (rpc_params_invalid(p)) {
        rpc_params_error(p, result);
        LOG_RETURN(-1, "mining", "numblocks argument missing or not an integer");
    }
    if (num_blocks <= 0 || num_blocks > 1000) {
        json_set_str(result, "Invalid number of blocks");
        LOG_RETURN(-1, "mining", "numblocks %lld outside 1..1000",
                   (long long)num_blocks);
    }
    return num_blocks;
}

static bool rpc_generate(const struct json_value *params, bool help,
                          struct json_value *result)
{
    RPC_HELP(help, result,
        "generate numblocks\n"
        "Mine blocks immediately (regtest only).\n"
        "The coinbase pays to an EMPTY script, so the subsidy is not\n"
        "spendable by anyone — use this only to advance the chain height.\n"
        "To mine SPENDABLE coins, use generatetoaddress.\n"
        "Arguments:\n"
        "1. numblocks (numeric, required) How many blocks to generate");

    if (!mining_on_demand_allowed("generate", result))
        return false;  // raw-return-ok:callee set the error body and logged the refusal


    struct rpc_params p;
    int64_t num_blocks = mining_require_numblocks(params, &p, result);
    if (num_blocks < 0)
        return false;

    /* Height-only mining: no payee. Kept as-is so the existing regtest
     * harnesses that only need the tip to advance are unaffected. */
    struct script coinbase_script;
    script_init(&coinbase_script);
    coinbase_script.size = 0;

    return mining_generate_to_script(&coinbase_script, num_blocks, result);
}

static bool rpc_generatetoaddress(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    RPC_HELP(help, result,
        "generatetoaddress numblocks \"address\"\n"
        "Mine blocks immediately, paying each coinbase to address (regtest only).\n"
        "Unlike generate, the subsidy lands on a real scriptPubKey, so the\n"
        "coinbase output is spendable once it is COINBASE_MATURITY (100)\n"
        "blocks deep. Pair it with getnewaddress to fund a local wallet.\n"
        "Arguments:\n"
        "1. numblocks (numeric, required) How many blocks to generate\n"
        "2. \"address\" (string, required) Transparent address to pay\n"
        "Result:\n"
        "[ \"blockhash\", ... ]  hashes of the blocks that were accepted");

    if (!mining_on_demand_allowed("generatetoaddress", result))
        return false;  // raw-return-ok:callee set the error body and logged the refusal


    struct rpc_params p;
    int64_t num_blocks = mining_require_numblocks(params, &p, result);
    if (num_blocks < 0)
        return false;

    const char *addr = rpc_require_str(&p, 1, "address");
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        return false;
    }

    /* Decode with the ACTIVE chain's base58 prefixes — the same pair every
     * other address surface uses — so a mainnet address cannot be paid on
     * regtest (or vice versa) by accident. */
    const struct chain_params *cp = chain_params_get();
    size_t pk_pfx_len = 0, sc_pfx_len = 0;
    const unsigned char *pk_pfx =
        chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_pfx_len);
    const unsigned char *sc_pfx =
        chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_pfx_len);

    struct tx_destination dest;
    if (!decode_destination(addr, pk_pfx, pk_pfx_len,
                            sc_pfx, sc_pfx_len, &dest) ||
        !tx_destination_is_valid(&dest)) {
        json_set_str(result,
                     "Error: invalid address for this network "
                     "(expected a transparent P2PKH or P2SH address)");
        LOG_FAIL("mining", "generatetoaddress: decode_destination rejected "
                 "the supplied address on chain %s", cp->strNetworkID);
    }

    struct script coinbase_script;
    script_init(&coinbase_script);
    script_for_destination(&coinbase_script, &dest);
    if (coinbase_script.size == 0) {
        json_set_str(result,
                     "Error: could not build a coinbase script for that "
                     "address");
        LOG_FAIL("mining", "generatetoaddress: script_for_destination "
                 "produced an empty script (dest type %d)", (int)dest.type);
    }

    return mining_generate_to_script(&coinbase_script, num_blocks, result);
}

static bool rpc_submitblock(const struct json_value *params, bool help,
                              struct json_value *result)
{
    RPC_HELP(help, result,
        "submitblock \"hexdata\"\n"
        "Attempts to submit new block to network.\n"
        "Arguments:\n"
        "1. \"hexdata\" (string, required) The hex-encoded block data");

    struct rpc_params p;
    rpc_params_init(&p, params);
    const char *hex = rpc_require_str(&p, 0, "hexdata");
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        return false;
    }
    size_t hex_len = strlen(hex);
    size_t bin_len = hex_len / 2;
    unsigned char *bin = zcl_malloc(bin_len, "submitblock_bin");
    if (!bin) LOG_FAIL("mining", "malloc failed for submitblock hex decode (%zu bytes)", bin_len);

    size_t parsed = ParseHex(hex, bin, bin_len);
    if (parsed == 0) {
        free(bin);
        json_set_str(result, "Block decode failed");
        return false;
    }

    struct byte_stream s;
    stream_init_from_data(&s, bin, parsed);

    struct block blk;
    block_init(&blk);
    if (!block_deserialize(&blk, &s)) {
        block_free(&blk);
        stream_free(&s);
        free(bin);
        json_set_str(result, "Block decode failed");
        return false;
    }
    stream_free(&s);
    free(bin);

    struct validation_state state;
    validation_state_init(&state);

    /* submitblock intake: the synchronous reducer_ingest_block drives the
     * staged Job pipeline and fills the validation_state. force=true mirrors
     * the locally-requested relay-pre-filter-skipping semantics submitblock
     * already had. The verdict in `state` flows into format_state_message
     * below, so the RPC still returns null on accept / the reject reason on
     * reject. */
    bool ok = reducer_ingest_block(boot_activation_controller(), &blk,
                                   REDUCER_SRC_SUBMIT, true, &state);
    if (ok) {
        struct uint256 h;
        block_get_hash(&blk, &h);
        mining_announce_accepted_block(&h);
    }
    block_free(&blk);

    if (!ok) {
        char msg[512];
        format_state_message(&state, msg, sizeof(msg));
        if (msg[0])
            json_set_str(result, msg);
        else
            json_set_str(result, "rejected");
        return false;
    }

    json_set_null(result);
    return true;
}

static bool rpc_getblocktemplate(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    struct mining_context *ctx = mining_ctx();
    (void)params;
    RPC_HELP(help, result,
        "getblocktemplate ( \"jsonrequestobject\" )\n"
        "Returns data needed to construct a block to work on.");

    /* Sovereign guard — same rationale as rpc_generate above: refuse to hand
     * out mining work while the tip is release_assisted (borrowed shielded
     * history). Checked before building the template so a real miner never
     * wastes an Equihash solve on work that submitblock/generate would then
     * have refused anyway. */
    {
        char sov_reason[96] = {0};
        if (!sovereignty_guard_allow("mint", sov_reason, sizeof(sov_reason))) {
            json_set_str(result, "Error: mint refused — tip is "
                                 "release_assisted (borrowed shielded "
                                 "history, not self-folded)");
            LOG_FAIL("mining", "getblocktemplate: refused — %s", sov_reason);
        }
    }

    const struct chain_params *cp = chain_params_get();
    struct block_index *tip = active_chain_tip(&ctx->main_state->chain_active);
    if (!tip) {
        json_set_str(result, "No tip available");
        return false;
    }

    struct script coinbase_script;
    coinbase_script.size = 0;

    struct block_template *tmpl = create_new_block(
        &coinbase_script, ctx->main_state, ctx->coins_tip, ctx->mempool, cp);
    if (!tmpl) {
        json_set_str(result, "Could not create block template");
        return false;
    }

    json_set_object(result);

    json_push_kv_int(result, "version", tmpl->block.header.nVersion);

    char prev_hex[65];
    uint256_get_hex(&tmpl->block.header.hashPrevBlock, prev_hex);
    json_push_kv_str(result, "previousblockhash", prev_hex);

    /* Transactions (skip coinbase at index 0) */
    struct json_value txs = {0};
    json_set_array(&txs);
    for (size_t i = 1; i < tmpl->block.num_vtx; i++) {
        struct json_value txobj = {0};
        json_set_object(&txobj);

        char *hex = zcl_malloc(2 * 1024 * 1024, "template_tx_hex");
        if (hex) {
            size_t hlen = encode_hex_tx(&tmpl->block.vtx[i], hex,
                                        2 * 1024 * 1024);
            hex[hlen] = '\0';
            json_push_kv_str(&txobj, "data", hex);
            free(hex);
        }

        transaction_compute_hash(&tmpl->block.vtx[i]);
        char txid[65];
        uint256_get_hex(&tmpl->block.vtx[i].hash, txid);
        json_push_kv_str(&txobj, "hash", txid);

        if (tmpl->tx_fees)
            json_push_kv_int(&txobj, "fee", tmpl->tx_fees[i]);
        if (tmpl->tx_sig_ops)
            json_push_kv_int(&txobj, "sigops",
                             (int64_t)tmpl->tx_sig_ops[i]);

        json_push_back(&txs, &txobj);
        json_free(&txobj);
    }
    json_push_kv(result, "transactions", &txs);
    json_free(&txs);

    /* Coinbase */
    struct json_value coinbase_obj = {0};
    json_set_object(&coinbase_obj);
    char *cb_hex = zcl_malloc(2 * 1024 * 1024, "template_cb_hex");
    if (cb_hex && tmpl->block.num_vtx > 0) {
        size_t hlen = encode_hex_tx(&tmpl->block.vtx[0], cb_hex,
                                    2 * 1024 * 1024);
        cb_hex[hlen] = '\0';
        json_push_kv_str(&coinbase_obj, "data", cb_hex);
    }
    free(cb_hex);
    json_push_kv(result, "coinbasetxn", &coinbase_obj);
    json_free(&coinbase_obj);

    /* Target and bits */
    char bits_str[16];
    snprintf(bits_str, sizeof(bits_str), "%08x", tmpl->block.header.nBits);
    json_push_kv_str(result, "bits", bits_str);

    json_push_kv_int(result, "height", tip->nHeight + 1);
    json_push_kv_int(result, "curtime", (int64_t)tmpl->block.header.nTime);
    json_push_kv_int(result, "mintime",
                     block_index_get_median_time_past(tip) + 1);
    json_push_kv_int(result, "sizelimit", MAX_BLOCK_SIZE);
    json_push_kv_int(result, "sigoplimit", 20000);

    char finalsapling[65];
    uint256_get_hex(&tmpl->block.header.hashFinalSaplingRoot, finalsapling);
    json_push_kv_str(result, "finalsaplingroothash", finalsapling);

    block_template_free(tmpl);
    free(tmpl);
    return true;
}

static bool rpc_getblocksubsidy(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    struct mining_context *ctx = mining_ctx();
    RPC_HELP(help, result,
        "getblocksubsidy height\n"
        "Returns block subsidy reward of block at given height.");

    struct block_index *tip = active_chain_tip(&ctx->main_state->chain_active);
    int default_height = tip ? tip->nHeight : 0;

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 1);
    int height = (int)rpc_permit_int(&p, 0, "height", default_height);
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        return false;
    }

    const struct chain_params *cp = chain_params_get();

    int64_t subsidy = get_block_subsidy(height, &cp->consensus);

    json_set_object(result);
    json_push_kv_real(result, "miner", (double)subsidy / (double)ZATOSHI_PER_ZCL);

    return true;
}

void register_mining_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "mining", "getmininginfo",     rpc_getmininginfo,    true },
        { "mining", "generate",          rpc_generate,         true },
        { "mining", "generatetoaddress", rpc_generatetoaddress, true },
        { "mining", "submitblock",       rpc_submitblock,      true },
        { "mining", "getblocktemplate",  rpc_getblocktemplate, true },
        { "mining", "getblocksubsidy",   rpc_getblocksubsidy,  true },
    };

    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}

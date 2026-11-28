/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "views/format_helpers.h"
#include "base/hex.h"
#include "services/miner_signal_round.h"
#include "services/miner_ballot_template.h"
#include "services/research_block_size.h"
#include "services/private_applied_relay.h"
#include "services/research_rules_tip.h"
#include "services/miner_signal_catalog_pin.h"
#include "controllers/blockchain_controller.h"
#include "controllers/mining_controller.h"
#include "controllers/ballot_network.h"
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
#include "core/hash.h"
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/util.h"  /* LogPrintf */
#include "mining_controller_test_hooks.h"
#include "mining_controller_failure.h"

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

struct mining_template_parent {
    struct block_index *index;
    int height;
    int64_t minimum_time;
    size_t size_limit;
    /* What the ballot suffix is fitted under; not the reported size limit. */
    size_t ballot_limit;
    struct research_tip_rules rules;
};

static bool mining_finish_template(struct block_template *tmpl,
    const struct chain_params *cp, int height, const struct uint256 *parent_root,
    bool genesis, bool reserve_ballot, const struct mining_template_parent *parent, const char **reason)
{
    if (research_block_size_limit(cp) == RESEARCH_BLOCK_SIZE_LIMIT) {
        struct zcl_result fit = miner_research_template_fit(tmpl, cp, height, reserve_ballot,
                                                             parent->size_limit, parent->rules.freeze);
        if (!fit.ok) { *reason = "Could not fit research block template"; return false; }
    }
    if (!mining_stamp_sapling_final_root(&tmpl->block, height, cp, parent_root, genesis)) {
        *reason = "Sapling parent frontier unavailable or invalid";
        return false;
    }
    return true;
}

/* The tip can advance after core assembles a template. Refresh against the
 * parent named by that template, never against a newly sampled active tip. */
static struct block_template *mining_create_template(const struct script *script,
    const struct chain_params *cp, struct mining_template_parent *bound,
    const char **reason, bool reserve_ballot)
{
    mining_test_template();
    struct mining_context *ctx = mining_ctx();
    *reason = "Mining state unavailable";
    if (!ctx->main_state || !ctx->mempool || !ctx->coins_tip || !cp) {
        LOG_WARN("mining", "template refused: %s", *reason);
        return NULL;
    }
    struct block_template *tmpl = create_new_block(script, ctx->main_state,
        ctx->coins_tip, ctx->mempool, cp);
    *reason = "Could not create block template";
    if (!tmpl) {
        LOG_WARN("mining", "template refused: %s", *reason);
        return NULL;
    }
    zcl_mutex_lock(&ctx->main_state->cs_main);
    struct block_index *parent = block_map_find(&ctx->main_state->map_block_index,
        &tmpl->block.header.hashPrevBlock);
    bool ok = false;
    bool genesis = false;
    struct uint256 parent_root;
    *reason = "Block template parent unavailable";
    if (parent && parent->phashBlock &&
        uint256_eq(parent->phashBlock, &tmpl->block.header.hashPrevBlock)) {
        int64_t median = block_index_get_median_time_past(parent);
        *reason = "Block template parent median time plus one exceeds uint32 range";
        if (median < UINT32_MAX) {
            int64_t minimum = median + 1;
            if ((int64_t)tmpl->block.header.nTime < minimum)
                tmpl->block.header.nTime = (uint32_t)minimum;
            tmpl->block.header.nBits = GetNextWorkRequired(parent,
                &tmpl->block.header, &cp->consensus);
            *bound = (struct mining_template_parent){
                .index = parent, .height = parent->nHeight + 1, .minimum_time = minimum
            };
            parent_root = parent->hashFinalSaplingRoot;
            genesis = parent->nHeight == 0 && uint256_eq(parent->phashBlock,
                &cp->consensus.hashGenesisBlock);
            ok = true;
        }
    }
    zcl_mutex_unlock(&ctx->main_state->cs_main);
    if (ok) {
        /* Resolve the parent named by the template, not a newly sampled tip. */
        bound->rules = research_rules_tip_for_parent(bound->index);
        struct research_rules_state state = {0};
        state.active[RESEARCH_RULE_BLOCK_CAP] = bound->rules.capped;
        bound->size_limit = research_block_size_limit_for(cp, &state);
        bound->ballot_limit = research_ballot_template_limit(cp, &state);
    }
    if (ok) ok = mining_finish_template(tmpl, cp, bound->height, &parent_root,
                                         genesis, reserve_ballot, bound, reason);
    if (ok) return tmpl;
    LOG_WARN("mining", "template refused: %s", *reason);
    block_template_free(tmpl);
    free(tmpl);
    return NULL;
}

/* Locally accepted blocks bypass P2P receive; announce to connected peers. */
static void mining_announce_accepted_block(const struct uint256 *hash)
{
    struct connman *cm = rpc_net_get_connman();
    const struct chain_research_descriptor *profile = chain_research_profile_current();
    if (profile && profile->id == CHAIN_RESEARCH_IRONWOOD &&
        chain_params_get() == profile->chain) {
        (void)private_applied_relay_check(boot_activation_controller(), cm);
    } else if (cm) {
        connman_relay_block(cm, hash);
    }
}

static bool mining_submit_mined_block(struct block *block, struct validation_state *state)
{
    validation_state_init(state);
    bool handled = false;
    bool ok = mining_test_submit(block, state, &handled);
    if (!handled) ok = reducer_ingest_block(boot_activation_controller(), block, REDUCER_SRC_MINED, true, state);
    if (ok) {
        struct uint256 h;
        block_get_hash(block, &h);
        mining_announce_accepted_block(&h);
    }
    if (!ok) {
        /* Keep the reducer's rejection and hash visible to the operator. */
        char msg[MAX_REJECT_REASON + 64];
        format_state_message(state, msg, sizeof(msg));
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

static bool mining_rate_span(struct block_index *tip, int64_t lookup, int64_t *rate)
{
    if (tip->nHeight == 0) return true;
    if (lookup <= 0) lookup = chain_params_get()->consensus.nPowAveragingWindow;
    if (lookup > tip->nHeight) lookup = tip->nHeight;
    struct block_index *start = tip;
    int64_t low = tip->nTime, high = low;
    for (int64_t i = 0; i < lookup; i++) {
        start = start->pprev;
        if (!start) return false;
        if (start->nTime < low) low = start->nTime;
        if (start->nTime > high) high = start->nTime;
    }
    if (high == low) return true;
    struct arith_uint256 work;
    arith_uint256_sub(&work, &tip->nChainWork, &start->nChainWork);
    double value = 0, factor = 1;
    for (int i = 0; i < ARITH_UINT256_WIDTH; i++) {
        value += factor * work.pn[i];
        factor *= 4294967296.0;
    }
    value /= (double)(high - low);
    if (value >= 9223372036854775808.0) return false;
    *rate = (int64_t)value;
    return true;
}

static bool mining_network_rate(struct main_state *ms, int64_t lookup, int64_t height, int64_t *rate)
{
    *rate = 0;
    zcl_mutex_lock(&ms->cs_main);
    int32_t public_height = reducer_frontier_provable_tip_cached();
    int selected = height >= 0 && height < public_height ? (int)height : public_height;
    struct active_chain_window_snapshot snapshot;
    bool ok = public_height >= 0 &&
        active_chain_capture_window(&ms->chain_active, selected, &snapshot) &&
        snapshot.requested && snapshot.requested->nHeight == selected &&
        mining_rate_span(snapshot.requested, lookup, rate);
    zcl_mutex_unlock(&ms->cs_main);
    return ok;
}

static bool mining_rate_rpc(const struct json_value *params, struct json_value *result)
{
    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 2);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }
    int64_t values[2] = {120, -1};
    for (size_t i = 0; i < json_size(params); i++) {
        const struct json_value *v = json_at(params, i);
        if (!v || v->type != JSON_INT || json_get_int(v) < INT32_MIN ||
            json_get_int(v) > INT32_MAX) {
            json_set_str(result, "blocks and height must be 32-bit integers");
            return false;
        }
        values[i] = json_get_int(v);
    }
    int64_t rate;
    if (!mining_ctx()->main_state ||
        !mining_network_rate(mining_ctx()->main_state, values[0], values[1], &rate)) {
        json_set_str(result, "Network rate unavailable for the selected chain");
        return false;
    }
    json_set_int(result, rate);
    return true;
}

static bool rpc_getnetworksolps(const struct json_value *params, bool help,
                                struct json_value *result)
{
    RPC_HELP(help, result, "getnetworksolps ( blocks height )\n"
        "Estimated network solutions per second. blocks defaults to 120; "
        "nonpositive uses the difficulty averaging window. height defaults to -1 (tip).");
    return mining_rate_rpc(params, result);
}

static bool rpc_getnetworkhashps(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    RPC_HELP(help, result, "getnetworkhashps ( blocks height )\n"
        "DEPRECATED: use getnetworksolps. Estimated network solutions per second. "
        "blocks defaults to 120; nonpositive uses the difficulty averaging window. "
        "height defaults to -1 (tip).");
    return mining_rate_rpc(params, result);
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

/* Both on-demand RPCs first enforce the mint-only sovereignty guard, then
 * fMineBlocksOnDemand. A refusal logs and sets the result; tip following is
 * unaffected (docs/node/shielded-history-importer.md §5.3). */
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

/* Shared on-demand loop; caller has passed mining_on_demand_allowed(). */
static struct zcl_result mining_template_ballot(const struct json_value *list,
    struct block *block, const struct chain_params *cp, int height, size_t limit);
static bool mining_report_submit_failure(struct json_value *result, int height,
                                         const struct validation_state *state)
{
    struct json_value hashes = *result;
    json_init(result);
    json_set_object(result);
    char *message = mining_failure_message(&hashes, height, state);
    bool ok = message && json_push_kv_int(result, "code", MINING_SUBMIT_ERROR_CODE) &&
              json_push_kv_str(result, "message", message) &&
              json_push_kv_int(result, "height", height) &&
              json_push_kv(result, "hashes", &hashes);
    free(message);
    json_free(&hashes);
    if (!ok) { json_set_str(result, "Cannot report mining failure"); LOG_FAIL("mining", "cannot report rejected block"); }
    return false;
}
static bool mining_ballot_range_allowed(int64_t count, struct json_value *result)
{
    struct mining_context *ctx = mining_ctx();
    const struct chain_params *cp = chain_params_get();
    const struct miner_signal_catalog_pin *pin = rpc_blockchain_ballot_catalog_pin();
    if (!ballot_network_eligible(cp)) {
        json_set_str(result, "Template ballots require testnet, regtest or the selected research profile");
        return false;
    }
    if (!pin || memcmp(pin->genesis, cp->consensus.hashGenesisBlock.data, 32)) {
        json_set_str(result, "No ballot catalog pinned for the selected network");
        return false;
    }
    if (!ctx->main_state) { json_set_str(result, "Mining state unavailable"); return false; }
    zcl_mutex_lock(&ctx->main_state->cs_main);
    struct block_index *tip = active_chain_tip(&ctx->main_state->chain_active);
    int64_t first = tip ? (int64_t)tip->nHeight + 1 : -1;
    zcl_mutex_unlock(&ctx->main_state->cs_main);
    int64_t last = (int64_t)pin->start + pin->window - 1;
    if (first < pin->start || first > last || count > last - first + 1) {
        char message[160];
        snprintf(message, sizeof(message),
                 "Template height outside the pinned voting window (last ballot height %lld)",
                 (long long)last);
        json_set_str(result, message);
        return false;
    }
    return true;
}
static bool mining_generate_to_script(const struct script *coinbase_script,
                                      int64_t num_blocks,
                                      const struct json_value *ballot_request,
                                      struct json_value *result)
{
    const struct chain_params *cp = chain_params_get();
    if (ballot_request && !mining_ballot_range_allowed(num_blocks, result)) return false;
    json_set_array(result);

    for (int64_t i = 0; i < num_blocks; i++) {
        struct mining_template_parent parent;
        const char *reason;
        struct block_template *tmpl = mining_create_template(coinbase_script, cp, &parent, &reason, ballot_request != NULL);
        if (!tmpl) {
            json_set_str(result, reason);
            return false;
        }
        struct zcl_result ballot = mining_template_ballot(ballot_request, &tmpl->block, cp,
                                                           parent.height, parent.ballot_limit);
        if (!ballot.ok) {
            block_template_free(tmpl);
            free(tmpl);
            json_set_str(result, ballot.message);
            return false;
        }
        unsigned int extra_nonce = 0;
        increment_extra_nonce(&tmpl->block, parent.index, &extra_nonce);

        /* Solve the Equihash PoW so the block passes the reducer's
         * stateless check_block(check_pow=true) gate. Without this the
         * block carries an empty solution and is rejected at intake, so
         * the tip never advances. Fast for regtest/testnet (small N,K). */
        int new_height = parent.height;
        if (!mine_block_pow(&tmpl->block, new_height, cp, 0)) {
            block_template_free(tmpl);
            free(tmpl);
            break;
        }

        struct validation_state state;
        if (!mining_submit_mined_block(&tmpl->block, &state)) {
            block_template_free(tmpl);
            free(tmpl);
            return mining_report_submit_failure(result, new_height, &state);
        } else {
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

    return mining_generate_to_script(&coinbase_script, num_blocks, NULL, result);
}

static bool mining_payout_script(const char *addr, struct script *script,
                                 struct json_value *result)
{
    const struct chain_params *cp = chain_params_get();
    size_t pk_len = 0, sc_len = 0;
    const unsigned char *pk = chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sc = chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_len);
    struct tx_destination dest;
    if (!decode_destination(addr, pk, pk_len, sc, sc_len, &dest) ||
        !tx_destination_is_valid(&dest)) {
        json_set_str(result, "Error: invalid address for this network "
                             "(expected a transparent P2PKH or P2SH address)");
        LOG_FAIL("mining", "payout address rejected on chain %s", cp->strNetworkID);
    }
    script_init(script);
    script_for_destination(script, &dest);
    if (!script->size) {
        json_set_str(result, "Error: could not build a coinbase script for that address");
        LOG_FAIL("mining", "payout script could not be built (dest type %d)", (int)dest.type);
    }
    return true;
}

static bool rpc_generatetoaddress(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    RPC_HELP(help, result,
        "generatetoaddress numblocks \"address\" ( ballotslots )\n"
        "Mine blocks immediately, paying each coinbase to address (regtest only).\n"
        "Unlike generate, the subsidy lands on a real scriptPubKey, so the\n"
        "coinbase output is spendable once it is COINBASE_MATURITY (100)\n"
        "blocks deep. Pair it with getnewaddress to fund a local wallet.\n"
        "Arguments:\n"
        "1. numblocks (numeric, required) How many blocks to generate\n"
        "2. \"address\" (string, required) Transparent address to pay\n"
        "3. ballotslots (optional) Signal slots in the pinned catalog.\n"
        "Result:\n"
        "[ \"blockhash\", ... ]  hashes of the blocks that were accepted.\n"
        "On submission failure, the error includes height, reason and accepted hashes.");

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

    struct script coinbase_script;
    if (!mining_payout_script(addr, &coinbase_script, result)) return false;
    return mining_generate_to_script(&coinbase_script, num_blocks, json_at(params, 2), result);
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

static struct zcl_result mining_template_ballot(const struct json_value *list,
    struct block *block, const struct chain_params *cp, int height, size_t limit)
{
    if (!list) return ZCL_OK;
    if (!ballot_network_eligible(cp))
        return ZCL_ERR(-1, "Template ballots require testnet, regtest or the selected research profile");
    const struct miner_signal_catalog_pin *pin = rpc_blockchain_ballot_catalog_pin();
    if (!pin || memcmp(pin->genesis, cp->consensus.hashGenesisBlock.data, 32))
        return ZCL_ERR(-1, "No ballot catalog pinned for the selected network");
    if (height < pin->start || (int64_t)height >= (int64_t)pin->start + pin->window)
        return ZCL_ERR(-1, "Template height outside the pinned voting window");
    uint8_t bits[32] = {0};
    struct zcl_result r = miner_ballot_request_bitmap(list, pin, bits);
    if (!r.ok) return r;
    size_t reserved_size;
    return miner_ballot_template_apply(block, pin->digest, bits, cp, height,
                                       limit, &reserved_size);
}

static bool mining_template_data(const struct transaction *tx, struct json_value *entry,
                                 struct uint256 *hash)
{
    struct byte_stream bytes;
    stream_init(&bytes, 256);
    bool ok = transaction_serialize(tx, &bytes) && !bytes.error && bytes.size <= (SIZE_MAX - 1) / 2;
    char *hex = ok ? zcl_malloc(2 * bytes.size + 1, "mining template transaction hex") : NULL;
    if (hex) {
        zcl_hex_encode(bytes.data, bytes.size, hex);
        ok = json_push_kv_str(entry, "data", hex);
        free(hex);
    } else {
        ok = false;
    }
    if (ok && hash) hash256(bytes.data, bytes.size, hash->data);
    stream_free(&bytes);
    return ok;
}

static bool mining_template_entry(const struct block_template *tmpl, size_t i,
                                  struct json_value *txs)
{
    struct json_value entry = {0};
    struct uint256 hash;
    char txid[65];
    json_set_object(&entry);
    bool ok = mining_template_data(&tmpl->block.vtx[i], &entry, &hash);
    if (ok) {
        uint256_get_hex(&hash, txid);
        ok = json_push_kv_str(&entry, "hash", txid);
    }
    if (ok && tmpl->tx_fees) ok = json_push_kv_int(&entry, "fee", tmpl->tx_fees[i]);
    if (ok && tmpl->tx_sig_ops) ok = json_push_kv_int(&entry, "sigops", tmpl->tx_sig_ops[i]);
    if (ok) ok = json_push_back(txs, &entry);
    json_free(&entry);
    return ok;
}

static bool mining_template_transactions(const struct block_template *tmpl, struct json_value *result)
{
    struct json_value txs = {0}, coinbase = {0};
    json_set_array(&txs);
    json_set_object(&coinbase);
    bool ok = tmpl->block.num_vtx && mining_template_data(&tmpl->block.vtx[0], &coinbase, NULL);
    for (size_t i = 1; ok && i < tmpl->block.num_vtx; ++i)
        ok = mining_template_entry(tmpl, i, &txs);
    if (ok) ok = json_push_kv(result, "transactions", &txs) &&
                 json_push_kv(result, "coinbasetxn", &coinbase);
    json_free(&txs);
    json_free(&coinbase);
    return ok;
}

static bool rpc_getblocktemplate(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    RPC_HELP(help, result,
        "getblocktemplate ( \"jsonrequestobject\" )\n"
        "Returns data needed to construct a block. On testnet or regtest the optional "
        "request field ballotslots adds a final coinbase output signaling the listed "
        "slots in the operator's pinned catalog for this voting window. "
        "The optional payoutaddress field specifies the transparent coinbase recipient. "
        "Pass ballotslots as {\"catalog\":\"<lowercase digest>\",\"slots\":[0]} "
        "to require the miner's expected catalog before producing a voting template.");

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
    struct script coinbase_script;
    script_init(&coinbase_script);
    const struct json_value *payout = json_get(json_at(params, 0), "payoutaddress");
    if (payout && (payout->type != JSON_STR ||
        !mining_payout_script(json_get_str(payout), &coinbase_script, result))) {
        if (payout->type != JSON_STR) json_set_str(result, "Error: payoutaddress must be a string");
        return false;
    }

    struct mining_template_parent parent;
    const char *reason;
    struct block_template *tmpl = mining_create_template(&coinbase_script, cp, &parent, &reason,
        json_get(json_at(params, 0), "ballotslots") != NULL);
    if (!tmpl) {
        json_set_str(result, reason);
        return false;
    }

    struct zcl_result ballot = mining_template_ballot(json_get(json_at(params, 0), "ballotslots"), &tmpl->block, cp, parent.height,
                                                       parent.ballot_limit);
    if (!ballot.ok) {
        block_template_free(tmpl);
        free(tmpl);
        json_set_str(result, ballot.message);
        return false;
    }
    json_set_object(result);
    json_push_kv_int(result, "version", tmpl->block.header.nVersion);

    char prev_hex[65];
    uint256_get_hex(&tmpl->block.header.hashPrevBlock, prev_hex);
    json_push_kv_str(result, "previousblockhash", prev_hex);

    if (!mining_template_transactions(tmpl, result)) {
        json_set_str(result, "Cannot serialize mining template transactions");
        block_template_free(tmpl);
        free(tmpl);
        return false;
    }

    /* Target and bits */
    char bits_str[16];
    snprintf(bits_str, sizeof(bits_str), "%08x", tmpl->block.header.nBits);
    json_push_kv_str(result, "bits", bits_str);

    json_push_kv_int(result, "height", parent.height);
    json_push_kv_int(result, "curtime", (int64_t)tmpl->block.header.nTime);
    json_push_kv_int(result, "mintime",
                     parent.minimum_time);
    json_push_kv_int(result, "sizelimit", (int64_t)parent.size_limit);
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

/* Construct only an optional miner ballot output; this does not count votes
 * or alter block validity. The catalog digest is encoded in supplied byte order. */
static bool rpc_createballotoutput(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    RPC_HELP(help, result,
        "createballotoutput \"catalog_digest\" \"bitmap\"\n"
        "Construct a zero-value Z23V v1 ballot output for a pool coinbase. "
        "Both arguments are exactly 32 bytes in hex; slot zero is bit 0 of "
        "bitmap byte 0. Callers must zero unused slots and append this as the "
        "final coinbase output before computing its transaction ID and Merkle root.");
    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 2, 2);
    const char *catalog = rpc_require_str(&p, 0, "catalog_digest");
    const char *bitmap = rpc_require_str(&p, 1, "bitmap");
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }
    uint8_t digest[32], votes[32], script[MINER_SIGNAL_SCRIPT_BYTES];
    if (!zcl_hex_decode(catalog, digest, sizeof(digest)) ||
        !zcl_hex_decode(bitmap, votes, sizeof(votes))) {
        json_set_str(result, "catalog_digest and bitmap must each be 32 bytes of hex");
        return false;
    }
    miner_signal_ballot_script(digest, votes, script);
    char hex[2 * sizeof(script) + 1];
    zcl_hex_encode(script, sizeof(script), hex);
    json_set_object(result);
    return json_push_kv_int(result, "value", 0) && json_push_kv_str(result, "scriptPubKey", hex);
}

void register_mining_rpc_commands(struct rpc_table *t)
{
    static const struct rpc_command cmds[] = {
        { "mining", "getnetworksolps", rpc_getnetworksolps, true },
        { "mining", "getnetworkhashps", rpc_getnetworkhashps, true },
        { "mining", "getmininginfo",     rpc_getmininginfo,    true },
        { "mining", "generate",          rpc_generate,         true },
        { "mining", "generatetoaddress", rpc_generatetoaddress, true },
        { "mining", "submitblock",       rpc_submitblock,      true },
        { "mining", "getblocktemplate",  rpc_getblocktemplate, true },
        { "mining", "getblocksubsidy",   rpc_getblocksubsidy,  true },
        { "mining", "createballotoutput", rpc_createballotoutput, true },
    };

    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain introspection RPCs for bit-level visibility into the ZClassic dataset.
 * Provides fast, comprehensive views of blocks, transactions, UTXO set,
 * Sapling tree state, and chain statistics. */

#include "platform/time_compat.h"
#include "views/format_helpers.h"
#include "controllers/chain_inspect_controller.h"
#include "controllers/rpc_chainstate_guard.h"
#include "controllers/strong_params.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/subsidy.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include "consensus/upgrades.h"
#include "core/uint256.h"
#include "core/serialize.h"
#include "json/json.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/coins_db.h"
#include "storage/dbwrapper.h"
#include "storage/disk_block_io.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "sapling/incremental_merkle_tree.h"
#include "sapling/fast_scan.h"
#include "models/database.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"

struct chain_inspect_context {
    struct main_state *main_state;
    const char *datadir;
    char datadir_storage[4096];
    struct coins_view_db *coins_db;
    struct coins_view_cache *coins_tip;
    struct node_db *node_db;
};

static struct chain_inspect_context g_chain_inspect_ctx = {0};

static struct chain_inspect_context *chain_inspect_ctx(void)
{
    return &g_chain_inspect_ctx;
}

void rpc_chain_inspect_set_state(struct main_state *ms, const char *datadir,
                                  struct coins_view_db *cvdb,
                                  struct coins_view_cache *coins_tip,
                                  struct node_db *ndb)
{
    struct chain_inspect_context *ctx = chain_inspect_ctx();
    ctx->main_state = ms;
    if (datadir && datadir[0]) {
        (void)snprintf(ctx->datadir_storage, sizeof(ctx->datadir_storage),
                       "%s", datadir);
        ctx->datadir = ctx->datadir_storage;
    } else {
        ctx->datadir_storage[0] = '\0';
        ctx->datadir = NULL;
    }
    ctx->coins_db = cvdb;
    ctx->coins_tip = coins_tip;
    ctx->node_db = ndb;
}

/* chainview height [count]
 * Returns detailed block index data for a range of blocks. */
static bool rpc_chainview(const struct json_value *params, bool help,
                            struct json_value *result)
{
    struct chain_inspect_context *ctx = chain_inspect_ctx();
    RPC_HELP(help, result,
        "chainview height [count=1]\n"
        "Returns detailed block index metadata for blocks at height..height+count-1.\n"
        "Includes: hash, prev, merkle root, sapling root, time, bits, nonce,\n"
        "nTx, file position, status flags, sapling/sprout value deltas.\n"
        "\nArguments:\n"
        "1. height  (int, required) Starting block height\n"
        "2. count   (int, optional, default=1) Number of blocks\n");

    if (!ctx->main_state) {
        json_set_str(result, "Chain not initialized");
        return false;
    }

    struct rpc_params p;
    rpc_params_init(&p, params);
    int height = (int)rpc_require_int(&p, 0, "height");
    int count = (int)rpc_permit_int(&p, 1, "count", 1);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }

    int chain_tip = active_chain_height(&ctx->main_state->chain_active);
    if (height < 0 || height > chain_tip) {
        json_set_str(result, "Height out of range");
        return false;
    }
    if (count < 1) count = 1;
    if (count > 100) count = 100;
    if (height + count - 1 > chain_tip) count = chain_tip - height + 1;

    json_set_array(result);
    const struct chain_params *cparam = chain_params_get();
    const struct consensus_params *cp = cparam ? &cparam->consensus : NULL;

    for (int h = height; h < height + count; h++) {
        const struct block_index *bi =
            active_chain_at(&ctx->main_state->chain_active, h);
        if (!bi) continue;

        struct json_value entry = {0};
        json_set_object(&entry);

        json_push_kv_int(&entry, "height", h);

        char hash_hex[65];
        if (bi->phashBlock)
            uint256_get_hex(bi->phashBlock, hash_hex);
        else
            memset(hash_hex, '0', 64);
        hash_hex[64] = 0;
        json_push_kv_str(&entry, "hash", hash_hex);

        char mr_hex[65], sr_hex[65];
        uint256_get_hex(&bi->hashMerkleRoot, mr_hex);
        uint256_get_hex(&bi->hashFinalSaplingRoot, sr_hex);
        json_push_kv_str(&entry, "merkleroot", mr_hex);
        json_push_kv_str(&entry, "saplingroot", sr_hex);

        json_push_kv_int(&entry, "time", bi->nTime);
        json_push_kv_int(&entry, "nTx", bi->nTx);
        json_push_kv_int(&entry, "file", bi->nFile);
        json_push_kv_int(&entry, "datapos", bi->nDataPos);
        json_push_kv_int(&entry, "status", bi->nStatus);
        json_push_kv_int(&entry, "sapling_value", bi->nSaplingValue);
        json_push_kv_int(&entry, "sprout_value", bi->nSproutValue);

        char bits_hex[9];
        snprintf(bits_hex, sizeof(bits_hex), "%08x", bi->nBits);
        json_push_kv_str(&entry, "bits", bits_hex);

        /* Consensus epoch */
        if (cp) {
            int epoch = consensus_current_epoch(h, cp);
            const char *epoch_names[] = {
                "sprout", "overwinter", "sapling", "blossom",
                "heartwood", "canopy", "bubbles", "buttercup", "diffadj"
            };
            if (epoch >= 0 && epoch < 9)
                json_push_kv_str(&entry, "epoch", epoch_names[epoch]);
        }

        json_push_back(result, &entry);
        json_free(&entry);
    }
    return true;
}

/* chainstats [start_height] [end_height]
 * Returns aggregate chain statistics over a range. */
static bool rpc_chainstats(const struct json_value *params, bool help,
                             struct json_value *result)
{
    struct chain_inspect_context *ctx = chain_inspect_ctx();
    RPC_HELP(help, result,
        "chainstats [start_height] [end_height]\n"
        "Returns aggregate statistics over a block range.\n"
        "Includes: total txs, total sapling value, block time stats,\n"
        "file sizes, Sapling commitment count estimate.\n"
        "\nArguments:\n"
        "1. start_height  (int, optional, default=0)\n"
        "2. end_height    (int, optional, default=tip)\n");

    if (!ctx->main_state) {
        json_set_str(result, "Chain not initialized");
        return false;
    }

    int chain_tip = active_chain_height(&ctx->main_state->chain_active);

    struct rpc_params p;
    rpc_params_init(&p, params);
    int start = (int)rpc_permit_int(&p, 0, "start", 0);
    int end = (int)rpc_permit_int(&p, 1, "end", chain_tip);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }

    if (start < 0) start = 0;
    if (end > chain_tip) end = chain_tip;
    if (start > end) { json_set_str(result, "start > end"); return false; }

    int64_t total_tx = 0;
    int64_t sapling_delta = 0;
    int64_t sprout_delta = 0;
    uint32_t min_time = UINT32_MAX, max_time = 0;
    int blocks_with_data = 0;
    int max_file = 0;

    for (int h = start; h <= end; h++) {
        const struct block_index *bi =
            active_chain_at(&ctx->main_state->chain_active, h);
        if (!bi) continue;
        total_tx += bi->nTx;
        sapling_delta += bi->nSaplingValue;
        sprout_delta += bi->nSproutValue;
        if (bi->nTime < min_time) min_time = bi->nTime;
        if (bi->nTime > max_time) max_time = bi->nTime;
        if (bi->nStatus & BLOCK_HAVE_DATA) blocks_with_data++;
        if (bi->nFile > max_file) max_file = bi->nFile;
    }

    json_set_object(result);
    json_push_kv_int(result, "start_height", start);
    json_push_kv_int(result, "end_height", end);
    json_push_kv_int(result, "blocks", end - start + 1);
    json_push_kv_int(result, "blocks_with_data", blocks_with_data);
    json_push_kv_int(result, "total_transactions", total_tx);
    json_push_kv_int(result, "sapling_value_delta", sapling_delta);
    json_push_kv_int(result, "sprout_value_delta", sprout_delta);
    json_push_kv_int(result, "time_start", min_time);
    json_push_kv_int(result, "time_end", max_time);
    json_push_kv_int(result, "duration_seconds",
                     max_time > min_time ? max_time - min_time : 0);
    json_push_kv_int(result, "max_block_file", max_file);

    /* Estimate total block data size */
    if (ctx->datadir) {
        int64_t total_bytes = 0;
        for (int f = 0; f <= max_file; f++) {
            char path[512];
            snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat", ctx->datadir, f);
            struct stat st;
            if (stat(path, &st) == 0)
                total_bytes += st.st_size;
        }
        char size_str[32];
        snprintf(size_str, sizeof(size_str), "%.2f GB",
                 (double)total_bytes / (1024.0 * 1024.0 * 1024.0));
        json_push_kv_str(result, "total_block_data", size_str);
    }

    return true;
}

/* gettxdetail txid
 * Returns full transaction details from chainstate. */
static bool rpc_gettxdetail(const struct json_value *params, bool help,
                              struct json_value *result)
{
    struct chain_inspect_context *ctx = chain_inspect_ctx();
    RPC_HELP(help, result,
        "gettxdetail txid\n"
        "Returns UTXO details for a transaction from chainstate.\n"
        "Shows which outputs are spent vs unspent, values, script types.\n"
        "\nArguments:\n"
        "1. txid  (hex, required) Transaction ID\n");

    if (!ctx->coins_tip && !ctx->coins_db) {
        json_set_str(result, "Chainstate not available");
        return false;
    }

    struct rpc_params p;
    rpc_params_init(&p, params);
    const char *txid_hex = rpc_require_str(&p, 0, "txid");
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }

    struct uint256 txid;
    uint256_set_hex(&txid, txid_hex);

    if (ctx->coins_tip && !rpc_require_chainstate_lookup_ready(
            ctx->main_state, result, "gettxdetail", "Chainstate lookup"))
        return false;

    struct coins c;
    coins_init(&c);
    bool found = false;
    if (ctx->coins_tip)
        found = coins_view_cache_get_coins(ctx->coins_tip, &txid, &c);
    if (!found && ctx->coins_db)
        found = coins_view_db_get_coins(ctx->coins_db, &txid, &c);

    if (!found) {
        json_set_str(result, "Transaction not found in UTXO set (fully spent or unknown)");
        return false;
    }

    json_set_object(result);
    json_push_kv_str(result, "txid", txid_hex);
    json_push_kv_bool(result, "coinbase", c.is_coinbase);
    json_push_kv_int(result, "height", c.height);
    json_push_kv_int(result, "version", c.version);
    json_push_kv_int(result, "num_outputs", (int64_t)c.num_vout);

    struct json_value outputs = {0};
    json_set_array(&outputs);
    int64_t total_unspent = 0;
    int unspent_count = 0;

    for (size_t i = 0; i < c.num_vout; i++) {
        struct json_value out = {0};
        json_set_object(&out);
        json_push_kv_int(&out, "n", (int64_t)i);

        if (tx_out_is_null(&c.vout[i])) {
            json_push_kv_bool(&out, "spent", true);
        } else {
            json_push_kv_bool(&out, "spent", false);
            char amt[32];
            snprintf(amt, sizeof(amt), "%lld.%08lld",
                     (long long)(c.vout[i].value / ZATOSHI_PER_ZCL),
                     (long long)(c.vout[i].value % ZATOSHI_PER_ZCL));
            json_push_kv_str(&out, "amount", amt);
            json_push_kv_int(&out, "script_size",
                             (int64_t)c.vout[i].script_pub_key.size);
            total_unspent += c.vout[i].value;
            unspent_count++;
        }
        json_push_back(&outputs, &out);
        json_free(&out);
    }

    json_push_kv(result, "outputs", &outputs);
    json_free(&outputs);

    char total_str[32];
    snprintf(total_str, sizeof(total_str), "%lld.%08lld",
             (long long)(total_unspent / ZATOSHI_PER_ZCL),
             (long long)(total_unspent % ZATOSHI_PER_ZCL));
    json_push_kv_str(result, "total_unspent", total_str);
    json_push_kv_int(result, "unspent_outputs", unspent_count);

    coins_free(&c);
    return true;
}

/* saplingtreeinfo
 * Returns Sapling commitment tree state and statistics. */
static bool rpc_saplingtreeinfo(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    struct chain_inspect_context *ctx = chain_inspect_ctx();
    (void)params;
    RPC_HELP(help, result,
        "saplingtreeinfo\n"
        "Returns Sapling commitment tree metadata.\n"
        "Includes: tree size, serialized size, root hash,\n"
        "rescan height, block header comparison.");

    if (!ctx->main_state) {
        json_set_str(result, "Chain not initialized");
        return false;
    }

    json_set_object(result);

    /* Load tree from node_state */
    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    bool have_tree = false;

    if (ctx->node_db) {
        uint8_t tbuf[2048];
        size_t tlen = 0;
        if (node_db_state_get(ctx->node_db, "sapling_tree_rescan",
                tbuf, sizeof(tbuf), &tlen) && tlen > 0) {
            struct byte_stream ts;
            stream_init_from_data(&ts, tbuf, tlen);
            have_tree = incremental_tree_deserialize(&tree, &ts);
            if (have_tree) {
                json_push_kv_int(result, "serialized_bytes", (int64_t)tlen);
            }
        }

        /* Get rescan height */
        uint8_t hbuf[32];
        size_t hlen = 0;
        if (node_db_state_get(ctx->node_db, "sapling_tree_rescan_height",
                hbuf, sizeof(hbuf), &hlen) && hlen > 0 && hlen < sizeof(hbuf)) {
            hbuf[hlen] = 0;
            int rescan_h = (int)strtol((char *)hbuf, NULL, 10);
            json_push_kv_int(result, "rescan_height", rescan_h);

            /* Compare tree root with block header */
            if (have_tree) {
                struct uint256 our_root;
                incremental_tree_root(&tree, &our_root);
                char our_hex[65];
                uint256_get_hex(&our_root, our_hex);
                json_push_kv_str(result, "tree_root", our_hex);
                json_push_kv_int(result, "tree_size",
                                 (int64_t)incremental_tree_size(&tree));

                const struct block_index *bi =
                    active_chain_at(&ctx->main_state->chain_active, rescan_h);
                if (bi) {
                    char blk_hex[65];
                    uint256_get_hex(&bi->hashFinalSaplingRoot, blk_hex);
                    json_push_kv_str(result, "block_header_root", blk_hex);
                    json_push_kv_bool(result, "roots_match",
                        memcmp(our_root.data,
                               bi->hashFinalSaplingRoot.data, 32) == 0);
                }
            }
        }
    }

    if (!have_tree) {
        json_push_kv_str(result, "status", "no tree (run rescanwitnesses)");
    }

    /* Report the selected network's live consensus activation. This matters
     * on regtestshielded, where the runtime override activates Sapling from
     * genesis; a mainnet literal made recovery diagnostics contradict the
     * scanner and the chain actually being validated. */
    const struct chain_params *chain = chain_params_get();
    json_push_kv_int(
        result, "sapling_activation",
        chain
            ? chain->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight
            : NETWORK_UPGRADE_NO_ACTIVATION);

    /* Chain tip sapling root. Read the tip through the single tip accessor
     * (active_chain_tip), not active_chain_at(c, height): the two are
     * identical today (active_chain_at(c, c->height) == active_chain_tip(c))
     * but only active_chain_tip tracks the authoritative reducer tip if the
     * accessor body derives from durable tip_finalize state. */
    int tip = active_chain_height(&ctx->main_state->chain_active);
    const struct block_index *tip_bi =
        active_chain_tip(&ctx->main_state->chain_active);
    if (tip_bi) {
        char tip_hex[65];
        uint256_get_hex(&tip_bi->hashFinalSaplingRoot, tip_hex);
        json_push_kv_str(result, "tip_sapling_root", tip_hex);
        json_push_kv_int(result, "tip_height", tip);
    }

    return true;
}

/* scancommitments start_height end_height
 * Fast-scans blocks for Sapling commitments and reports count. */
static bool rpc_scancommitments(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    struct chain_inspect_context *ctx = chain_inspect_ctx();
    RPC_HELP(help, result,
        "scancommitments start_height end_height\n"
        "Fast-scan blocks for Sapling commitments without building tree.\n"
        "Reports commitment count per block range. Uses mmap + fast_scan.\n"
        "\nArguments:\n"
        "1. start_height  (int, required)\n"
        "2. end_height    (int, required)\n");

    if (!ctx->main_state || !ctx->datadir) {
        json_set_str(result, "Chain/datadir not available");
        return false;
    }

    struct rpc_params p;
    rpc_params_init(&p, params);
    int start = (int)rpc_require_int(&p, 0, "start");
    int end = (int)rpc_require_int(&p, 1, "end");
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }

    int chain_tip = active_chain_height(&ctx->main_state->chain_active);
    if (start < 0) start = 0;
    if (end > chain_tip) end = chain_tip;
    if (end - start > 100000) {
        json_set_str(result, "Range too large (max 100000 blocks)");
        return false;
    }

    int cached_file = -1;
    uint8_t *cached_data = NULL;
    size_t cached_size = 0;
    int64_t total_cms = 0;
    int blocks_with_cms = 0;
    int64_t t0 = (int64_t)platform_time_wall_time_t();

    for (int h = start; h <= end; h++) {
        const struct block_index *bi =
            active_chain_at(&ctx->main_state->chain_active, h);
        if (!bi || !(bi->nStatus & BLOCK_HAVE_DATA)) continue;

        if (bi->nFile != cached_file) {
            if (cached_data) munmap(cached_data, cached_size);
            char path[512];
            snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
                     ctx->datadir, bi->nFile);
            int fd = open(path, O_RDONLY);
            if (fd < 0) { cached_data = NULL; cached_file = -1; continue; }
            struct stat fst;
            if (fstat(fd, &fst) != 0) { close(fd); continue; }
            cached_size = (size_t)fst.st_size;
            cached_data = mmap(NULL, cached_size,
                               PROT_READ, MAP_PRIVATE, fd, 0);
            close(fd);
            if (cached_data == MAP_FAILED) {
                cached_data = NULL; cached_file = -1; continue;
            }
            cached_file = bi->nFile;
        }
        if (!cached_data || bi->nDataPos >= cached_size) continue;

        uint8_t cms[4096][32];
        int n = fast_scan_sapling_commitments(
            cached_data + bi->nDataPos,
            cached_size - bi->nDataPos, cms, 4096);
        if (n > 0) {
            total_cms += n;
            blocks_with_cms++;
        }
    }
    if (cached_data) munmap(cached_data, cached_size);

    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;

    json_set_object(result);
    json_push_kv_int(result, "start_height", start);
    json_push_kv_int(result, "end_height", end);
    json_push_kv_int(result, "blocks_scanned", end - start + 1);
    json_push_kv_int(result, "blocks_with_commitments", blocks_with_cms);
    json_push_kv_int(result, "total_commitments", total_cms);
    json_push_kv_int(result, "elapsed_seconds", elapsed);
    return true;
}

/* verifychainroots start_height end_height
 * Verify our Sapling tree root matches block headers at each height. */
static bool rpc_verifychainroots(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    struct chain_inspect_context *ctx = chain_inspect_ctx();
    RPC_HELP(help, result,
        "verifychainroots start_height end_height\n"
        "Build Sapling commitment tree from scratch and compare root\n"
        "against block header hashFinalSaplingRoot at each checkpoint.\n"
        "Reports first divergence point if any.\n"
        "\nArguments:\n"
        "1. start_height  (int, required) Must be >= Sapling activation\n"
        "2. end_height    (int, required)\n");

    if (!ctx->main_state || !ctx->datadir) {
        json_set_str(result, "Chain/datadir not available");
        return false;
    }

    struct rpc_params p;
    rpc_params_init(&p, params);
    int start = (int)rpc_require_int(&p, 0, "start");
    int end = (int)rpc_require_int(&p, 1, "end");
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }

    int chain_tip = active_chain_height(&ctx->main_state->chain_active);
    if (end > chain_tip) end = chain_tip;

    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);

    int sapling_start = 476969;
    if (start < sapling_start) start = sapling_start;

    int cached_file = -1;
    uint8_t *cached_data = NULL;
    size_t cached_size = 0;
    size_t total_cms = 0;
    int first_mismatch = -1;
    int checkpoints_ok = 0;
    int64_t t0 = (int64_t)platform_time_wall_time_t();

    for (int h = sapling_start; h <= end; h++) {
        const struct block_index *bi =
            active_chain_at(&ctx->main_state->chain_active, h);
        if (!bi) continue;

        if (bi->nStatus & BLOCK_HAVE_DATA) {
            if (bi->nFile != cached_file) {
                if (cached_data) munmap(cached_data, cached_size);
                char path[512];
                snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
                         ctx->datadir, bi->nFile);
                int fd = open(path, O_RDONLY);
                if (fd < 0) { cached_data = NULL; cached_file = -1; goto next; }
                struct stat fst;
                if (fstat(fd, &fst) != 0) { close(fd); goto next; }
                cached_size = (size_t)fst.st_size;
                cached_data = mmap(NULL, cached_size,
                                   PROT_READ, MAP_PRIVATE, fd, 0);
                close(fd);
                if (cached_data == MAP_FAILED) {
                    cached_data = NULL; cached_file = -1; goto next;
                }
                cached_file = bi->nFile;
            }
            if (cached_data && bi->nDataPos < cached_size) {
                uint8_t cms[4096][32];
                int n = fast_scan_sapling_commitments(
                    cached_data + bi->nDataPos,
                    cached_size - bi->nDataPos, cms, 4096);
                for (int ci = 0; ci < n; ci++) {
                    struct uint256 cm;
                    memcpy(cm.data, cms[ci], 32);
                    incremental_tree_append(&tree, &cm);
                    total_cms++;
                }
            }
        }

next:
        /* Check every 10000 heights */
        if (h % 10000 == 0 || h == end) {
            struct uint256 our_root;
            incremental_tree_root(&tree, &our_root);
            if (memcmp(our_root.data,
                       bi->hashFinalSaplingRoot.data, 32) == 0) {
                checkpoints_ok++;
            } else if (first_mismatch < 0) {
                first_mismatch = h;
            }
        }
    }
    if (cached_data) munmap(cached_data, cached_size);

    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;

    json_set_object(result);
    json_push_kv_int(result, "range_start", start);
    json_push_kv_int(result, "range_end", end);
    json_push_kv_int(result, "total_commitments", (int64_t)total_cms);
    json_push_kv_int(result, "checkpoints_verified", checkpoints_ok);
    json_push_kv_int(result, "elapsed_seconds", elapsed);

    struct uint256 final_root;
    incremental_tree_root(&tree, &final_root);
    char fr_hex[65];
    uint256_get_hex(&final_root, fr_hex);
    json_push_kv_str(result, "final_tree_root", fr_hex);
    json_push_kv_int(result, "tree_size", (int64_t)incremental_tree_size(&tree));

    if (first_mismatch >= 0) {
        json_push_kv_int(result, "first_mismatch_height", first_mismatch);
        json_push_kv_bool(result, "fully_verified", false);
    } else {
        json_push_kv_bool(result, "fully_verified", true);
    }

    return true;
}

void register_chain_inspect_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "blockchain", "chainview",          rpc_chainview,          true },
        { "blockchain", "chainstats",         rpc_chainstats,         true },
        { "blockchain", "gettxdetail",        rpc_gettxdetail,       true },
        { "blockchain", "saplingtreeinfo",    rpc_saplingtreeinfo,    true },
        { "blockchain", "scancommitments",    rpc_scancommitments,    true },
        { "blockchain", "verifychainroots",   rpc_verifychainroots,   false },
    };

    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}

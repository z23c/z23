/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "platform/time_compat.h"
#include "controllers/block_intake_json.h"
#include "controllers/download_stats_json.h"
#include "controllers/misc_controller.h"
#include "controllers/node_binary_identity_json.h"
#include "controllers/network_controller.h"
#include "controllers/strong_params.h"
#include "event/event.h"
#include "jobs/reducer_frontier.h"
#include "sync/sync_state.h"
#include "net/connman.h"
#include "validation/contextual_check_tx.h"
#include "controllers/wallet_helpers.h"
#include "coins/coins_view.h"
#include "chain/chainparams.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "core/hash.h"
#include "keys/key_io.h"
#include "validation/chainstate.h"
#include "wallet/keystore.h"
#include "wallet/wallet.h"
#include "wallet/sapling_keys.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"

struct misc_context {
    struct main_state *main_state;
    struct wallet *wallet;
};

static struct misc_context g_misc_ctx = {0};

static struct misc_context *misc_ctx(void)
{
    return &g_misc_ctx;
}

void rpc_misc_set_state(struct main_state *ms)
{
    misc_ctx()->main_state = ms;
}

void rpc_misc_set_wallet(struct wallet *w)
{
    misc_ctx()->wallet = w;
}

static bool rpc_getinfo(const struct json_value *params, bool help,
                          struct json_value *result)
{
    struct misc_context *ctx = misc_ctx();
    (void)params;
    RPC_HELP(help, result,
        "getinfo\n"
        "Returns an object containing various state info.");

    json_set_object(result);
    node_binary_identity_push_json(result, NULL, true);

    /* Report the PROVABLE tip height (H*), not the active/lookahead tip. Do
     * not fall back to active_chain_tip when the H* slot is unresolved; that
     * would name an unprovable block. */
    int32_t hstar = ctx->main_state ? reducer_frontier_provable_tip_cached()
                                    : 0;
    json_push_kv_int(result, "blocks", hstar);
    json_push_kv_int(result, "timeoffset", 0);
    struct connman *cm = rpc_net_get_connman();
    size_t connections = cm ? connman_get_node_count(cm) : 0;
    json_push_kv_int(result, "connections", (int64_t)connections);
    json_push_kv_real(result, "difficulty", 0.0);
    json_push_kv_bool(result, "testnet",
                       strcmp(chain_params_get()->strNetworkID, "test") == 0);
    json_push_kv_real(result, "relayfee", 0.00000100);
    json_push_kv_int(result, "errors", 0);

    return true;
}

static bool rpc_validateaddress(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    struct misc_context *ctx = misc_ctx();
    RPC_HELP(help, result,
        "validateaddress \"address\"\n"
        "Return information about the given ZClassic address.\n"
        "Works for transparent (t1/t3) and shielded (zs1) addresses.");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 1);
    const char *addr = rpc_require_str(&p, 0, "address");
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }
    if (addr[0] == '\0' || strlen(addr) > 128) {
        json_set_str(result, "address must be 1-128 printable characters");
        return false;
    }
    for (const unsigned char *s = (const unsigned char *)addr; *s; s++) {
        if (*s < 33 || *s > 126) {
            json_set_str(result, "address must be 1-128 printable characters");
            return false;
        }
    }
    const struct chain_params *cp = chain_params_get();

    json_set_object(result);
    json_push_kv_str(result, "address", addr);

    /* Try Sapling z-address (zs1...) */
    uint8_t diversifier[11];
    uint8_t pk_d[32];
    if (sapling_decode_payment_address(addr, diversifier, pk_d)) {
        json_push_kv_bool(result, "isvalid", true);
        json_push_kv_str(result, "type", "sapling");

        if (ctx->wallet) {
            bool is_mine = false;
            for (size_t i = 0; i < ctx->wallet->sapling_keys.num_keys; i++) {
                struct sapling_key_entry *e =
                    &ctx->wallet->sapling_keys.keys[i];
                if (e->used &&
                    memcmp(e->diversifier, diversifier, 11) == 0 &&
                    memcmp(e->pk_d, pk_d, 32) == 0) {
                    is_mine = true;
                    break;
                }
            }
            json_push_kv_bool(result, "ismine", is_mine);
        }
        return true;
    }

    /* Try transparent address (t1/t3) */
    size_t pk_len, sc_len;
    const unsigned char *pk_pfx = chain_params_base58_prefix(
        cp, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sc_pfx = chain_params_base58_prefix(
        cp, B58_SCRIPT_ADDRESS, &sc_len);

    struct tx_destination dest;
    bool valid = decode_destination(addr, pk_pfx, pk_len,
                                     sc_pfx, sc_len, &dest);

    json_push_kv_bool(result, "isvalid", valid);
    if (!valid)
        return true;

    if (dest.type == DEST_KEY_ID) {
        json_push_kv_str(result, "type", "pubkeyhash");
        json_push_kv_bool(result, "isscript", false);

        if (ctx->wallet) {
            bool is_mine = keystore_have_key(&ctx->wallet->keystore,
                                               &dest.id.key);
            json_push_kv_bool(result, "ismine", is_mine);

            if (is_mine) {
                struct pubkey pk;
                if (keystore_get_pubkey(&ctx->wallet->keystore,
                                         &dest.id.key, &pk)) {
                    char pk_hex[PUBLIC_KEY_SIZE * 2 + 1];
                    HexStr(pk.vch, pk.size, false, pk_hex, sizeof(pk_hex));
                    json_push_kv_str(result, "pubkey", pk_hex);
                    json_push_kv_bool(result, "iscompressed",
                                      pk.size == COMPRESSED_PUBLIC_KEY_SIZE);
                }
            }
        }
    } else if (dest.type == DEST_SCRIPT_ID) {
        json_push_kv_str(result, "type", "scripthash");
        json_push_kv_bool(result, "isscript", true);

        if (ctx->wallet) {
            bool have = keystore_have_cscript(&ctx->wallet->keystore,
                                                &dest.id.script.hash);
            json_push_kv_bool(result, "ismine", have);
        }
    }

    return true;
}

static bool rpc_stop(const struct json_value *params, bool help,
                       struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "stop\n"
        "Stop ZClassic server.");

    json_set_str(result, "ZClassic server stopping");
    /* Canonical shutdown request — the same flag SIGTERM's handler sets.
     * The main loop drains into app_shutdown() with correct teardown
     * ordering (coins flush before index fsync). A raw exit() here tore
     * the chainstate by design and dropped this RPC reply. */
    thread_registry_request_shutdown();
    return true;
}

static bool rpc_downloadstats(const struct json_value *params, bool help,
                               struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "downloadstats\n"
        "\nReturn block download manager statistics.\n"
        "\nResult:\n"
        "  { \"requested\", \"received\", \"timed_out\", "
        "\"in_flight\", \"queued\", \"oldest_in_flight_age_seconds\", "
        "\"overdue_in_flight\", \"queue_peer_avoid_count\", "
        "\"dispatch_wakes\", "
        "\"message_send_calls\", \"message_process_calls\", "
        "\"last_assign_result\", "
        "\"sync_state\" }\n");

    struct download_stats_snapshot dl_snap;
    download_stats_snapshot_collect(&dl_snap, true);

    json_set_object(result);
    download_stats_push_json(result, &dl_snap, true);

    json_push_kv_str(result, "sync_state", sync_state_name(sync_get_state()));
    controller_json_push_block_intake_stats(result);
    json_push_kv_int(result, "defer_proof_validation_below_height",
                      (int64_t)g_deferred_proof_validation_below_height);
    return true;
}

static bool rpc_coinsinfo(const struct json_value *params, bool help,
                           struct json_value *result)
{
    struct coins_view_cache *tip = wallet_rpc_coins_tip();
    (void)params;
    RPC_HELP(help, result,
        "coinsinfo\n"
        "\nReturn UTXO cache diagnostics.\n");

    if (!tip) {
        json_set_str(result, "coins_tip not initialized");
        return true;
    }
    json_set_object(result);
    json_push_kv_int(result, "cache_size",
                      (int64_t)tip->cache_coins.size);
    json_push_kv_int(result, "cache_buckets",
                      (int64_t)tip->cache_coins.num_buckets);

    struct uint256 best;
    coins_view_cache_get_best_block(tip, &best);
    char hex[65];
    uint256_get_hex(&best, hex);
    json_push_kv_str(result, "best_block", hex);

    /* UTXO commitment — XOR-hash of all UTXOs. Two nodes with the same
     * UTXO set will have the same commitment. Divergence = bug. */
    char commit_hex[65];
    HexStr(tip->commitment.accumulator, 32, false, commit_hex, sizeof(commit_hex));
    json_push_kv_str(result, "utxo_commitment", commit_hex);
    json_push_kv_int(result, "utxo_count", (int64_t)tip->commitment.count);

    return true;
}

/* ── Benchmark RPC ─────────────────────────────────────────── */

static bool rpc_benchmark(const struct json_value *params, bool help,
                          struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "benchmark\n"
        "\nRun performance benchmarks: SHA256 hash, UTXO lookup speed,\n"
        "JSON parse, memory allocation.\n"
        "\nResult: ops/sec for each benchmark.\n");

    json_set_object(result);
    json_push_kv_str(result, "primary_benchmark_source",
                     "build/bin/z23 -bench* writes docs/bench-history.csv");

    struct json_value primaries = {0};
    json_set_array(&primaries);
    const char *names[] = {
        "#1 cold-start to operational",
        "#2 warm-start to operational",
        "#3 stay-in-sync MTBF",
        "#4 RAM steady-state",
        "#5 kill-9 recovery",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        struct json_value row = {0};
        json_set_object(&row);
        json_push_kv_str(&row, "benchmark", names[i]);
        json_push_kv_str(&row, "status", "pending");
        json_push_kv_str(&row, "how", "run build/bin/z23 -bench*");
        json_push_back(&primaries, &row);
    }
    json_push_kv(result, "primary_benchmarks", &primaries);

    /* SHA256 benchmark - 10000 iterations */
    {
        struct timespec t0, t1;
        platform_time_monotonic_timespec(&t0);
        uint8_t buf[64] = {0};
        for (int i = 0; i < 10000; i++) {
            uint8_t out[32];
            hash256(buf, sizeof(buf), out);
            memcpy(buf, out, 32);
        }
        platform_time_monotonic_timespec(&t1);
        double elapsed = (t1.tv_sec - t0.tv_sec) +
                         (t1.tv_nsec - t0.tv_nsec) / 1e9;
        int64_t ops = (int64_t)(10000.0 / elapsed);
        json_push_kv_int(result, "sha256d_ops_per_sec", ops);
    }

    /* Memory alloc+free benchmark - 10000 iterations */
    {
        struct timespec t0, t1;
        platform_time_monotonic_timespec(&t0);
        for (int i = 0; i < 10000; i++) {
            void *p = zcl_malloc(4096, "benchmark alloc");
            if (p) { memset(p, 0, 4096); free(p); }
        }
        platform_time_monotonic_timespec(&t1);
        double elapsed = (t1.tv_sec - t0.tv_sec) +
                         (t1.tv_nsec - t0.tv_nsec) / 1e9;
        int64_t ops = (int64_t)(10000.0 / elapsed);
        json_push_kv_int(result, "malloc_4k_ops_per_sec", ops);
    }

    /* RIPEMD160 benchmark */
    {
        struct timespec t0, t1;
        uint8_t buf2[32] = {1,2,3};
        platform_time_monotonic_timespec(&t0);
        for (int i = 0; i < 10000; i++) {
            uint8_t out[20];
            hash160(buf2, sizeof(buf2), out);
            memcpy(buf2, out, 20);
        }
        platform_time_monotonic_timespec(&t1);
        double elapsed = (t1.tv_sec - t0.tv_sec) +
                         (t1.tv_nsec - t0.tv_nsec) / 1e9;
        int64_t ops = (int64_t)(10000.0 / elapsed);
        json_push_kv_int(result, "hash160_ops_per_sec", ops);
    }

    return true;
}

void register_misc_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "control", "getinfo",          rpc_getinfo,          true },
        { "util",    "validateaddress",  rpc_validateaddress,  true },
        { "control", "stop",             rpc_stop,             true },
        { "control", "downloadstats",    rpc_downloadstats,    true },
        { "control", "coinsinfo",        rpc_coinsinfo,        true },
        { "control", "benchmark",        rpc_benchmark,        true },
    };

    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}

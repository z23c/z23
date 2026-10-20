/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Mining controller unit tests — RPC registration, edge cases. */

#include "test/test_core.h"
#include "controllers/mining_controller.h"
#include "controllers/sovereignty_controller.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "core/arith_uint256.h"
#include "jobs/reducer_frontier.h"
#include "storage/coins_kv.h"
#include "storage/coins_view_kv.h"
#include "storage/progress_store.h"
#include "util/timedata.h"
#include <sqlite3.h>
#include <string.h>

#define MT_CHECK(name, expr) do { \
    printf("mining: %s... %s\n", name, (expr) ? "OK" : (failures++, "FAIL")); \
} while (0)

static bool mining_test_gbt(struct rpc_table *table, struct json_value *out)
{
    struct json_value params = {0};
    json_set_array(&params);
    bool ok = rpc_table_execute(table, "getblocktemplate", &params, out);
    json_free(&params);
    return ok;
}

static int mining_check_gbt(struct rpc_table *table, struct block_index *parent,
                            bool future)
{
    int failures = 0;
    struct json_value out = {0};
    int64_t before = GetAdjustedTime();
    bool ok = mining_test_gbt(table, &out);
    int64_t after = GetAdjustedTime();
    int64_t curtime = json_get_int(json_get(&out, "curtime"));
    int64_t minimum = block_index_get_median_time_past(parent) + 1;
    MT_CHECK("GBT executes through registered RPC with mint authority", ok);
    MT_CHECK("GBT time respects parent median floor", ok && curtime >= minimum);
    MT_CHECK("GBT chooses exact future floor or preserves current clock",
        ok && (future ? curtime == minimum : curtime >= before && curtime <= after));
    char parent_hex[65], bits[16];
    uint256_get_hex(parent->phashBlock, parent_hex);
    const char *previous = json_get_str(json_get(&out, "previousblockhash"));
    MT_CHECK("GBT parent, height and minimum name one parent",
        ok && previous && strcmp(previous, parent_hex) == 0 &&
        json_get_int(json_get(&out, "height")) == parent->nHeight + 1 &&
        json_get_int(json_get(&out, "mintime")) == minimum);
    struct block_header header;
    block_header_init(&header);
    header.nTime = (uint32_t)curtime;
    snprintf(bits, sizeof(bits), "%08x", GetNextWorkRequired(parent, &header, &chain_params_get()->consensus));
    const char *actual_bits = json_get_str(json_get(&out, "bits"));
    MT_CHECK("GBT difficulty matches refreshed timestamp and same parent",
        ok && actual_bits && strcmp(bits, actual_bits) == 0);
    json_free(&out);
    return failures;
}

static bool mining_test_authority(sqlite3 *db, int height)
{
    uint8_t txid[32] = {0x43};
    return coins_kv_ensure_schema(db) && coins_kv_add(db, txid, 0, 5000, 10, true, NULL, 0) &&
        sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK &&
        coins_kv_set_applied_height_in_tx(db, height + 1) &&
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK &&
        coins_kv_mark_migration_complete(db) && coins_kv_mark_self_folded(db);
}

static int mining_template_time_cases(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "mining", "template-time");
    bool opened = progress_store_open(dir);
    MT_CHECK("isolated progress store opens", opened);
    if (!opened) { test_cleanup_tmpdir(dir); return failures; }
    reducer_frontier_provable_tip_set(10);
    MT_CHECK("real mint authority fixture", mining_test_authority(progress_store_db(), 10));
    char reason[96];
    MT_CHECK("mint authority guard allows fixture", sovereignty_guard_allow("mint", reason, sizeof(reason)));
    chain_params_select(CHAIN_REGTEST);
    struct main_state ms;
    main_state_init(&ms);
    struct tx_mempool pool;
    tx_mempool_init(&pool, 0);
    struct coins_view_kv backing;
    coins_view_kv_init(&backing);
    struct coins_view_cache cache;
    coins_view_cache_init(&cache, &backing.view);
    struct block_index ancestors[18];
    struct arith_uint256 limit;
    uint256_to_arith(&limit, &chain_params_get()->consensus.powLimit);
    uint32_t future_time = (uint32_t)(GetAdjustedTime() + 3600);
    for (int h = 0; h < 18; h++) {
        block_index_init(&ancestors[h]);
        ancestors[h].hashBlock.data[0] = (uint8_t)(h + 1);
        ancestors[h].phashBlock = &ancestors[h].hashBlock;
        ancestors[h].nHeight = h;
        ancestors[h].nBits = arith_uint256_get_compact(&limit, false);
        ancestors[h].nTime = future_time;
        ancestors[h].pprev = h ? &ancestors[h - 1] : NULL;
        block_map_insert(&ms.map_block_index, ancestors[h].phashBlock, &ancestors[h]);
    }
    active_chain_move_window_tip(&ms.chain_active, &ancestors[10]);
    rpc_mining_set_state(&ms, &pool, &cache);
    struct rpc_table table;
    rpc_table_init(&table);
    register_mining_rpc_commands(&table);
    set_rpc_warmup_finished();
    failures += mining_check_gbt(&table, &ancestors[10], true);
    for (int h = 0; h < 11; h++) ancestors[h].nTime = (uint32_t)(GetAdjustedTime() - 3600);
    failures += mining_check_gbt(&table, &ancestors[10], false);
    /* Deliberately synthetic index timing makes the time-dependent regtest
     * difficulty branch observable. This is template assembly, not a claim
     * that these cached ancestors passed contextual header validation. */
    for (int h = 0; h < 18; h++) {
        ancestors[h].nTime = future_time;
        ancestors[h].nBits = 0x1f07ffff;
    }
    ancestors[17].nTime = (uint32_t)(GetAdjustedTime() - 100);
    active_chain_move_window_tip(&ms.chain_active, &ancestors[17]);
    reducer_frontier_provable_tip_set(17);
    MT_CHECK("difficulty branch mint authority fixture", mining_test_authority(progress_store_db(), 17));
    struct block_header raw, refreshed;
    block_header_init(&raw);
    block_header_init(&refreshed);
    raw.nTime = (uint32_t)GetAdjustedTime();
    refreshed.nTime = future_time + 1;
    MT_CHECK("fixture time refresh changes required difficulty",
        GetNextWorkRequired(&ancestors[17], &raw, &chain_params_get()->consensus) !=
        GetNextWorkRequired(&ancestors[17], &refreshed, &chain_params_get()->consensus));
    failures += mining_check_gbt(&table, &ancestors[17], true);
    for (int h = 0; h < 18; h++) ancestors[h].nTime = UINT32_MAX;
    struct json_value out = {0};
    MT_CHECK("GBT refuses unrepresentable parent median plus one", !mining_test_gbt(&table, &out));
    json_free(&out);
    rpc_mining_set_state(NULL, NULL, NULL);
    coins_view_cache_free(&cache);
    tx_mempool_free(&pool);
    main_state_free(&ms);
    reducer_frontier_provable_tip_set(-1);
    progress_store_close();
    chain_params_select(CHAIN_MAIN);
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_mining(void)
{
    int failures = 0;

    printf("mining: register_mining_rpc_commands accepts table... ");
    {
        struct rpc_table t;
        rpc_table_init(&t);
        register_mining_rpc_commands(&t);
        /* Should have registered at least getblocktemplate, getmininginfo,
         * getnetworkhashps, generate, setgenerate */
        bool ok = (t.num_commands >= 3);
        if (ok) printf("OK (%zu commands)\n", t.num_commands);
        else { printf("FAIL (%zu commands)\n", t.num_commands); failures++; }
    }

    printf("mining: getmininginfo registered... ");
    {
        struct rpc_table t;
        rpc_table_init(&t);
        register_mining_rpc_commands(&t);
        bool found = false;
        for (size_t i = 0; i < t.num_commands; i++) {
            if (strcmp(t.commands[i].name, "getmininginfo") == 0) {
                found = true;
                break;
            }
        }
        if (found) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("mining: getblocktemplate registered... ");
    {
        struct rpc_table t;
        rpc_table_init(&t);
        register_mining_rpc_commands(&t);
        bool found = false;
        for (size_t i = 0; i < t.num_commands; i++) {
            if (strcmp(t.commands[i].name, "getblocktemplate") == 0) {
                found = true;
                break;
            }
        }
        if (found) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures + mining_template_time_cases();
}

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Mining controller unit tests — RPC registration, edge cases. */

#include "test/test_core.h"
#include "test/test_block_map.h"
#include "controllers/mining_controller.h"
#include "controllers/blockchain_controller.h"
#include "controllers/sovereignty_controller.h"
#include "services/miner_signal_catalog_pin.h"
#include "base/hex.h"
#include "core/serialize.h"
#include "primitives/transaction.h"
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

static bool mining_ballot_call(struct rpc_table *table, const char *catalog,
                               const char *bitmap, struct json_value *out)
{
    struct json_value params = {0}, item = {0};
    json_set_array(&params);
    json_set_str(&item, catalog);
    bool built = json_push_back(&params, &item);
    json_set_str(&item, bitmap);
    built = built && json_push_back(&params, &item);
    json_free(&item);
    bool ok = built && rpc_table_execute(table, "createballotoutput", &params, out);
    json_free(&params);
    return ok;
}

static int mining_ballot_cases(void)
{
    int failures = 0;
    struct rpc_table table;
    rpc_table_init(&table);
    register_mining_rpc_commands(&table);
    struct json_value out = {0};
    const char *catalog = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const char *bitmap = "0100000000000000000000000000000000000000000000000000000000000080";
    bool ok = mining_ballot_call(&table, catalog, bitmap, &out);
    const char *script = json_get_str(json_get(&out, "scriptPubKey"));
    MT_CHECK("ballot exact script and zero value", ok && script &&
        strcmp(script, "6a455a32335601"
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "0100000000000000000000000000000000000000000000000000000000000080") == 0 &&
        json_get(&out, "value") && json_get_int(json_get(&out, "value")) == 0);
    json_set_null(&out);
    MT_CHECK("ballot rejects short digest", !mining_ballot_call(&table, "00", bitmap, &out));
    json_set_null(&out);
    MT_CHECK("ballot rejects nonhex bitmap", !mining_ballot_call(&table, catalog,
        "z100000000000000000000000000000000000000000000000000000000000080", &out));
    json_set_null(&out);
    return failures;
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

static bool mining_slots_call(struct rpc_table *table, const char *raw,
                              struct json_value *out)
{
    struct json_value params = {0};
    bool ok = json_read(&params, raw, strlen(raw)) &&
              rpc_table_execute(table, "getblocktemplate", &params, out);
    json_free(&params);
    return ok;
}

static bool mining_slots_refused(struct rpc_table *table, const char *raw,
                                 const char *message)
{
    struct json_value out = {0};
    bool ok = mining_slots_call(table, raw, &out);
    bool refused = !ok && out.type == JSON_STR && strstr(json_get_str(&out), message);
    json_free(&out);
    return refused;
}

static bool mining_slots_pin(struct miner_signal_catalog_pin *pin)
{
    static const char manifest[] =
        "[\"1111111111111111111111111111111111111111111111111111111111111111\",12,5,"
        "[[\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",18],"
        "[\"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\",19]]]";
    struct json_value doc = {0};
    bool ok = json_read(&doc, manifest, sizeof(manifest) - 1) &&
        miner_signal_catalog_pin_parse(json_at(&doc, 0), json_at(&doc, 1),
            json_at(&doc, 2), json_at(&doc, 3),
            chain_params_get()->consensus.hashGenesisBlock.data, pin).ok;
    json_free(&doc);
    return ok;
}

static bool mining_coinbase_decode(const struct json_value *result,
                                   struct transaction *tx)
{
    const struct json_value *cb = json_get(result, "coinbasetxn");
    const char *hex = cb ? json_get_str(json_get(cb, "data")) : NULL;
    uint8_t raw[8192];
    transaction_init(tx);
    if (!hex || strlen(hex) % 2 || strlen(hex) / 2 > sizeof(raw) ||
        !zcl_hex_decode(hex, raw, strlen(hex) / 2)) return false;
    struct byte_stream s;
    stream_init_from_data(&s, raw, strlen(hex) / 2);
    bool ok = transaction_deserialize(tx, &s) && !stream_remaining(&s);
    if (!ok) transaction_free(tx);
    return ok;
}

static bool mining_ballot_output(const struct transaction *legacy,
                                 const struct transaction *vote,
                                 const struct miner_signal_catalog_pin *pin)
{
    static const uint8_t prefix[] = {0x6a, 0x45, 'Z', '2', '3', 'V', 1};
    if (!legacy->num_vout || vote->num_vout != legacy->num_vout + 1) return false;
    for (size_t i = 0; i < legacy->num_vout; i++) {
        const struct tx_out *a = &legacy->vout[i], *b = &vote->vout[i];
        if (a->value != b->value || a->script_pub_key.size != b->script_pub_key.size ||
            memcmp(a->script_pub_key.data, b->script_pub_key.data, a->script_pub_key.size))
            return false;
    }
    const struct tx_out *out = &vote->vout[vote->num_vout - 1];
    const uint8_t *p = out->script_pub_key.data;
    uint8_t bitmap[32] = {3};
    return out->value == 0 && out->script_pub_key.size == 71 &&
           !memcmp(p, prefix, sizeof(prefix)) && !memcmp(p + 7, pin->digest, 32) &&
           !memcmp(p + 39, bitmap, sizeof(bitmap));
}

static int mining_slots_inside(struct rpc_table *table,
                               const struct miner_signal_catalog_pin *pin)
{
    int failures = 0;
    struct json_value legacy = {0}, voted = {0};
    struct transaction a, b;
    bool a_ok = mining_test_gbt(table, &legacy) && mining_coinbase_decode(&legacy, &a);
    bool b_ok = mining_slots_call(table, "[{\"ballotslots\":[0,1]}]", &voted) &&
                mining_coinbase_decode(&voted, &b);
    MT_CHECK("legacy template coinbase decodes", a_ok);
    MT_CHECK("ballot template coinbase preserves payouts and appends bound zero vote",
             a_ok && b_ok && mining_ballot_output(&a, &b, pin));
    if (a_ok) transaction_free(&a);
    if (b_ok) transaction_free(&b);
    json_free(&legacy); json_free(&voted);
    MT_CHECK("duplicate slots rejected", mining_slots_refused(table,
             "[{\"ballotslots\":[0,0]}]", "Repeated ballot slot"));
    MT_CHECK("invalid slot rejected", mining_slots_refused(table,
             "[{\"ballotslots\":[2]}]", "Slot outside pinned catalog"));
    MT_CHECK("negative slot rejected", mining_slots_refused(table,
             "[{\"ballotslots\":[-1]}]", "Slot outside pinned catalog"));
    MT_CHECK("fractional slot rejected", mining_slots_refused(table,
             "[{\"ballotslots\":[1.5]}]", "Expected an integer ballot slot"));
    return failures;
}

static int mining_slots_cases(struct rpc_table *table, struct main_state *ms,
                              struct block_index *ancestors)
{
    int failures = 0;
    const char *request = "[{\"ballotslots\":[0,1]}]";
    struct miner_signal_catalog_pin pin = {0};
    struct json_value no_pin = {0}, pinned = {0};
    rpc_blockchain_set_ballot_catalog_pin(NULL);
    bool legacy_ok = mining_test_gbt(table, &no_pin);
    MT_CHECK("ballot request requires a pin", mining_slots_refused(table, request,
             "No ballot catalog pinned for the selected network"));
    bool parsed = mining_slots_pin(&pin);
    MT_CHECK("real parsed catalog pin", parsed);
    if (!parsed) { json_free(&no_pin); return failures; }
    rpc_blockchain_set_ballot_catalog_pin(&pin);
    bool pinned_ok = mining_test_gbt(table, &pinned);
    const struct json_value *a = json_get(&no_pin, "coinbasetxn");
    const struct json_value *b = json_get(&pinned, "coinbasetxn");
    const char *acb = a ? json_get_str(json_get(a, "data")) : NULL;
    const char *bcb = b ? json_get_str(json_get(b, "data")) : NULL;
    MT_CHECK("absent option preserves legacy coinbase with pinned catalog",
             legacy_ok && pinned_ok && acb && bcb && !strcmp(acb, bcb));
    json_free(&no_pin); json_free(&pinned);
    MT_CHECK("ballot before window refused", mining_slots_refused(table, request,
             "Template height outside the pinned voting window"));
    active_chain_move_window_tip(&ms->chain_active, &ancestors[11]);
    reducer_frontier_provable_tip_set(11);
    MT_CHECK("ballot mint authority", mining_test_authority(progress_store_db(), 11));
    failures += mining_slots_inside(table, &pin);
    active_chain_move_window_tip(&ms->chain_active, &ancestors[17]);
    reducer_frontier_provable_tip_set(17);
    MT_CHECK("post-window mint authority", mining_test_authority(progress_store_db(), 17));
    MT_CHECK("ballot after window refused", mining_slots_refused(table, request,
             "Template height outside the pinned voting window"));
    rpc_blockchain_set_ballot_catalog_pin(NULL);
    active_chain_move_window_tip(&ms->chain_active, &ancestors[10]);
    reducer_frontier_provable_tip_set(10);
    MT_CHECK("restore mint authority", mining_test_authority(progress_store_db(), 10));
    return failures;
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
        test_block_map_insert(&ms.map_block_index, ancestors[h].phashBlock, &ancestors[h]);
    }
    active_chain_move_window_tip(&ms.chain_active, &ancestors[10]);
    rpc_mining_set_state(&ms, &pool, &cache);
    struct rpc_table table;
    rpc_table_init(&table);
    register_mining_rpc_commands(&table);
    set_rpc_warmup_finished();
    failures += mining_slots_cases(&table, &ms, ancestors);
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

    return failures + mining_template_time_cases() + mining_ballot_cases();
}

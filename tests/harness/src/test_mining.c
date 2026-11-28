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
#include "crypto/common.h"
#include "mining/miner.h"
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

static int mining_guarded_slots(struct rpc_table *table,
                                const struct miner_signal_catalog_pin *pin)
{
    int failures = 0;
    const char *form = "[{\"ballotslots\":{\"catalog\":\"%s\",\"slots\":[0,1]}}]";
    char digest[65], request[160];
    zcl_hex_encode(pin->digest, sizeof(pin->digest), digest);
    snprintf(request, sizeof(request), form, digest);
    struct json_value plain = {0}, guarded = {0};
    bool ok = mining_slots_call(table, "[{\"ballotslots\":[0,1]}]", &plain) &&
              mining_slots_call(table, request, &guarded);
    const char *a = json_get_str(json_get(json_get(&plain, "coinbasetxn"), "data"));
    const char *b = json_get_str(json_get(json_get(&guarded, "coinbasetxn"), "data"));
    MT_CHECK("miner-pinned request produces identical voting coinbase", ok && *a && !strcmp(a, b));
    json_free(&plain); json_free(&guarded);
    digest[0] = digest[0] == '0' ? '1' : '0';
    snprintf(request, sizeof(request), form, digest);
    MT_CHECK("different miner pin refuses a voting template",
             mining_slots_refused(table, request, "differs from node pin"));
    MT_CHECK("missing miner pin refuses the object form", mining_slots_refused(table,
             "[{\"ballotslots\":{\"slots\":[0,1]}}]", "Expected ballotslots object"));
    return failures;
}

static int mining_slots_inside(struct rpc_table *table,
                               const struct miner_signal_catalog_pin *pin)
{
    int failures = 0;
    /* Pin existing behavior: absent catalog is rejected without a production change. */
    struct json_value missing_params = {0}, missing_result = {0};
    const char *missing = "[1,\"tmQMh5UwwJGfi53XvgjVZjTGo6SzZGVz6Q6\",{\"slots\":[0],\"extra\":0}]";
    int before = reducer_frontier_provable_tip_cached();
    bool parsed = json_read(&missing_params, missing, strlen(missing));
    bool missing_refused = parsed && !rpc_table_execute(table, "generatetoaddress",
                                                         &missing_params, &missing_result);
    MT_CHECK("missing ballot catalog refuses without changing height",
        missing_refused && missing_result.type == JSON_STR &&
        strstr(json_get_str(&missing_result), "Expected ballotslots object") &&
        reducer_frontier_provable_tip_cached() == before);
    json_free(&missing_params);
    json_free(&missing_result);
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

static int mining_crossing_window(struct rpc_table *table, struct main_state *ms,
                                  struct block_index *ancestors)
{
    int failures = 0;
    struct json_value params = {0}, out = {0};
    const char *raw = "[3,\"tmQMh5UwwJGfi53XvgjVZjTGo6SzZGVz6Q6\",[0]]";
    active_chain_move_window_tip(&ms->chain_active, &ancestors[14]);
    reducer_frontier_provable_tip_set(14);
    bool ready = mining_test_authority(progress_store_db(), 14) &&
                 json_read(&params, raw, strlen(raw));
    bool refused = ready && !rpc_table_execute(table, "generatetoaddress", &params, &out);
    MT_CHECK("crossing ballot window refuses before mining and names last height",
        refused && out.type == JSON_STR && strstr(json_get_str(&out), "window") &&
        strstr(json_get_str(&out), "16") &&
        active_chain_height(&ms->chain_active) == 14 &&
        reducer_frontier_provable_tip_cached() == 14);
    json_free(&params);
    json_free(&out);
    params = (struct json_value){0};
    out = (struct json_value){0};
    active_chain_move_window_tip(&ms->chain_active, &ancestors[10]);
    reducer_frontier_provable_tip_set(10);
    ready = mining_test_authority(progress_store_db(), 10) &&
            json_read(&params, raw, strlen(raw));
    refused = ready && !rpc_table_execute(table, "generatetoaddress", &params, &out);
    MT_CHECK("ballot before window refuses and names last height",
        refused && out.type == JSON_STR && strstr(json_get_str(&out), "window") &&
        strstr(json_get_str(&out), "16") && active_chain_height(&ms->chain_active) == 10);
    json_free(&params);
    json_free(&out);
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
    failures += mining_guarded_slots(table, &pin);
    failures += mining_crossing_window(table, ms, ancestors);
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

static bool mining_rate_call(struct rpc_table *t, const char *name, const char *args, int64_t expected)
{
    struct json_value p = {0}, out = {0};
    bool ok = json_read(&p, args, strlen(args)) && rpc_table_execute(t, name, &p, &out) &&
        out.type == JSON_INT && json_get_int(&out) == expected;
    json_free(&p);
    json_free(&out);
    return ok;
}

static int mining_rate_extra(struct rpc_table *t, struct block_index *blocks)
{
    int failures = 0;
    const struct rpc_command *alias = rpc_table_find(t, "getnetworkhashps");
    struct json_value args = {0}, out = {0};
    json_set_array(&args);
    bool ok = alias && alias->actor(&args, true, &out);
    const char *help = json_get_str(&out);
    MT_CHECK("network hash alias help names deprecation and defaults", ok && help &&
        strstr(help, "getnetworkhashps") && strstr(help, "DEPRECATED") &&
        strstr(help, "120") && strstr(help, "-1"));
    json_free(&args);
    json_free(&out);
    args = (struct json_value){0};
    out = (struct json_value){0};
    json_read(&args, "[2147483648]", 12);
    MT_CHECK("network rate rejects out of range", !rpc_table_execute(t, "getnetworksolps", &args, &out));
    json_free(&args);
    json_free(&out);
    blocks[0].nTime = 100; blocks[1].nTime = 140;
    blocks[2].nTime = 110; blocks[3].nTime = 120;
    MT_CHECK("network rate uses min and max timestamps", mining_rate_call(t, "getnetworksolps", "[3,3]", 38));
    return failures;
}


static int mining_rate_cases(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);
    struct block_index blocks[4];
    for (int i = 0; i < 4; i++) {
        block_index_init(&blocks[i]);
        blocks[i].nHeight = i;
        blocks[i].nTime = (uint32_t)(100 + i * 10);
        blocks[i].pprev = i ? &blocks[i - 1] : NULL;
        arith_uint256_set_u64(&blocks[i].nChainWork, (uint64_t)(i * i * 170));
    }
    active_chain_move_window_tip(&ms.chain_active, &blocks[3]);
    rpc_mining_set_state(&ms, NULL, NULL);
    reducer_frontier_provable_tip_set(3);
    struct rpc_table t;
    rpc_table_init(&t);
    register_mining_rpc_commands(&t);
    MT_CHECK("network solutions default", mining_rate_call(&t, "getnetworksolps", "[]", 51));
    MT_CHECK("network hash alias and height", mining_rate_call(&t, "getnetworkhashps", "[1,2]", 51));
    MT_CHECK("network averaging window", mining_rate_call(&t, "getnetworksolps", "[-1,1]", 17));
    MT_CHECK("genesis rate zero", mining_rate_call(&t, "getnetworksolps", "[32,0]", 0));
    reducer_frontier_provable_tip_set(2);
    MT_CHECK("network rate uses provable tip", mining_rate_call(&t, "getnetworksolps", "[]", 34));
    reducer_frontier_provable_tip_set(3);
    struct json_value args = {0}, out = {0};
    json_read(&args, "[1,1]", 5);
    ms.chain_active.chain[1] = NULL;
    MT_CHECK("missing historical slot unavailable", !rpc_table_execute(&t, "getnetworksolps", &args, &out));
    ms.chain_active.chain[1] = &blocks[1];
    json_free(&args);
    json_free(&out);
    failures += mining_rate_extra(&t, blocks);
    blocks[0].nTime = blocks[1].nTime = blocks[2].nTime = blocks[3].nTime;
    MT_CHECK("equal times rate zero", mining_rate_call(&t, "getnetworksolps", "[]", 0));
    rpc_mining_set_state(NULL, NULL, NULL);
    reducer_frontier_provable_tip_set(-1);
    main_state_free(&ms);
    return failures;
}


static bool mining_h1_wire_check(struct block_template *tmpl, uint32_t header, uint32_t group)
{
    struct transaction *cb = &tmpl->block.vtx[0];
    struct byte_stream wire; stream_init(&wire, 256);
    struct uint256 fresh;
    struct transaction decoded; transaction_init(&decoded);
    bool ok = transaction_serialize(cb, &wire) && !wire.error && wire.size >= 8;
    if (ok) {
        ok = ReadLE32(wire.data) == header;
        if (group) ok = ok && ReadLE32(wire.data + 4) == group;
    }
    if (ok) {
        struct byte_stream input; stream_init_from_data(&input, wire.data, wire.size);
        ok = transaction_deserialize(&decoded, &input) && !stream_remaining(&input) &&
            decoded.overwintered == (group != 0) && decoded.version_group_id == group &&
            transaction_hash_serialized(cb, &fresh) && uint256_eq(&fresh, &cb->hash) &&
            uint256_eq(&fresh, &tmpl->block.header.hashMerkleRoot);
    }
    transaction_free(&decoded); stream_free(&wire);
    return ok;
}

/* A real template at H1 uses the selected epoch shape. The normal miner
 * updates extranonce before solving; check the final wire and Merkle root. */
static bool mining_h1_wire_case(int32_t overwinter, int32_t sapling,
                                uint32_t header, uint32_t group)
{
    struct chain_params cp = *chain_params_get();
    cp.consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight = overwinter;
    cp.consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight = sapling;
    struct main_state ms; main_state_init(&ms);
    struct tx_mempool pool; tx_mempool_init(&pool, 0);
    struct coins_view_kv backing;
    if (!coins_view_kv_init(&backing)) { tx_mempool_free(&pool); main_state_free(&ms); return false; }
    struct coins_view_cache cache; coins_view_cache_init(&cache, &backing.view);
    struct block_index parent; block_index_init(&parent);
    parent.nHeight = 0; parent.hashBlock.data[0] = 1;
    parent.phashBlock = &parent.hashBlock;
    struct arith_uint256 limit; uint256_to_arith(&limit, &cp.consensus.powLimit);
    parent.nBits = arith_uint256_get_compact(&limit, false);
    parent.nTime = (uint32_t)GetAdjustedTime();
    active_chain_move_window_tip(&ms.chain_active, &parent);
    struct script script; script_init(&script);
    struct block_template *tmpl = create_new_block(&script, &ms, &cache, &pool, &cp);
    bool ok = tmpl && tmpl->block.num_vtx == 1;
    if (ok) {
        unsigned nonce = 0;
        increment_extra_nonce(&tmpl->block, &parent, &nonce);
        ok = mining_h1_wire_check(tmpl, header, group);
    }
    if (tmpl) { block_template_free(tmpl); free(tmpl); }
    coins_view_cache_free(&cache); tx_mempool_free(&pool); main_state_free(&ms);
    return ok;
}

static int mining_h1_wire_cases(void)
{
    int failures = 0;
    MT_CHECK("H1 pre-Overwinter coinbase wire and merkle", mining_h1_wire_case(2, 2, 1, 0));
    MT_CHECK("H1 Overwinter coinbase wire and merkle", mining_h1_wire_case(0, 2, 0x80000003u, 0x03c48270u));
    MT_CHECK("H1 Sapling coinbase wire and merkle", mining_h1_wire_case(0, 0, 0x80000004u, 0x892f2085u));
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

    return failures + mining_h1_wire_cases() + mining_template_time_cases() + mining_ballot_cases() + mining_rate_cases();
}

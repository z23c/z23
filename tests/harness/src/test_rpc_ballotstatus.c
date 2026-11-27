/* purpose: Exercise testnet ballot status through the registered blockchain RPC table. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "controllers/blockchain_controller.h"
#include "chain/chainparams.h"
#include "json/json.h"
#include "base/hex.h"
#include "services/miner_signal_catalog.h"
#include <stdio.h>
#include <string.h>

#define ZERO_CATALOG "0000000000000000000000000000000000000000000000000000000000000000"

static bool ballot_status_refuses(struct rpc_table *table, const char *raw,
                                 const char *expected_message)
{
    struct json_value params = {0}, result = {0};
    bool parsed = json_read(&params, raw, strlen(raw));
    bool ok = parsed && rpc_table_execute(table, "getballotstatus", &params, &result);
    bool refused = parsed && !ok && result.type == JSON_STR &&
                   strstr(json_get_str(&result), expected_message) != NULL;
    if (!refused) fprintf(stderr, "getballotstatus expected '%s' for %s\n", expected_message, raw);
    json_free(&params);
    json_free(&result);
    return refused;
}

#define FORK_ID "1111111111111111111111111111111111111111111111111111111111111111"
#define REV_A "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
#define REV_B "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
#define CATALOG_ARGS "[\"" FORK_ID "\",100,20,[[\"" REV_A "\",122],[\"" REV_B "\",150]],0]"

static bool catalog_selected_first(const struct json_value *result, const struct json_value *params)
{
    const struct json_value *rules = json_at(params, 3);
    const struct json_value *first = json_at(rules, 0);
    return json_get_int(json_get(result, "start")) == 100 &&
           json_get_int(json_get(result, "window")) == 20 &&
           json_get_int(json_get(result, "activation")) == json_get_int(json_at(first, 1)) &&
           json_get_int(json_get(result, "slots")) == (int64_t)json_size(rules) &&
           json_get_int(json_get(result, "slot")) == 0;
}

static bool ballot_catalog_call(struct rpc_table *table, const char *raw,
                                bool want_ok, const char *message, char digest[65])
{
    struct json_value params = {0}, result = {0};
    bool parsed = json_read(&params, raw, strlen(raw));
    bool ok = parsed && rpc_table_execute(table, "getballotcatalog", &params, &result);
    bool pass = parsed && ok == want_ok;
    if (want_ok) {
        const struct json_value *v = json_get(&result, "catalog");
        const char *s = v ? json_get_str(v) : NULL;
        pass = pass && s && strlen(s) == 64 && catalog_selected_first(&result, &params);
        if (pass && digest) memcpy(digest, s, 65);
    } else {
        pass = pass && result.type == JSON_STR && strstr(json_get_str(&result), message);
    }
    if (!pass) fprintf(stderr, "getballotcatalog case failed: %s\n", raw);
    json_free(&params);
    json_free(&result);
    return pass;
}

static int ballot_catalog_cases(struct rpc_table *table)
{
    int failures = 0;
    char regtest_digest[65] = {0}, testnet_digest[65] = {0}, expected[65];
    chain_params_select(CHAIN_REGTEST);
    if (!ballot_catalog_call(table, CATALOG_ARGS, true, NULL, regtest_digest)) failures++;
    /* Window 100..119 leaves block 120 under old rules. */
    if (!ballot_catalog_call(table, "[\"" FORK_ID "\",100,20,[[\"" REV_A "\",121]],0]",
                             true, NULL, NULL)) failures++;
    struct miner_signal_catalog_entry entries[2] = {0};
    struct miner_signal_catalog c = { .start = 100, .window = 20, .count = 2, .entries = entries };
    if (!zcl_hex_decode(FORK_ID, c.network_id, 32) ||
        !zcl_hex_decode(REV_A, entries[0].rule_revision, 32) ||
        !zcl_hex_decode(REV_B, entries[1].rule_revision, 32)) return failures + 1;
    memcpy(c.genesis, chain_params_get()->consensus.hashGenesisBlock.data, 32);
    entries[0].activation = 122; entries[1].activation = 150;
    struct miner_signal_schedule selected = {0};
    if (!miner_signal_catalog_select(&c, 0, &selected).ok) return failures + 1;
    zcl_hex_encode(selected.catalog, 32, expected);
    if (strcmp(regtest_digest, expected)) failures++;
    /* The 5-argument status form must get beyond parsing with a real catalog;
     * the isolated unit fixture intentionally has no attached chain state. */
    rpc_blockchain_set_state(NULL, NULL, NULL);
    if (!ballot_status_refuses(table, CATALOG_ARGS, "unavailable")) failures++;
    static const char *bad[] = {
        "[\"00\",100,20,[[\"" REV_A "\",122]],0]",
        "[\"" FORK_ID "\",100,257,[[\"" REV_A "\",400]],0]",
        "[\"" FORK_ID "\",100,20,[],0]",
        "[\"" FORK_ID "\",100,20,[[\"" REV_A "\",120]],0]",
        "[\"" FORK_ID "\",100,20,[[\"" REV_A "\",122]],1]",
        "[\"" FORK_ID "\",100,20,[[\"" REV_A "\",122],[\"" REV_A "\",150]],0]",
        "[\"" FORK_ID "\",100,20,[[\"" REV_B "\",150],[\"" REV_A "\",122]],0]",
        "[\"" FORK_ID "\",100,20,[[\"" REV_A "\",122.5]],0]",
        "[\"" ZERO_CATALOG "\",100,20,[[\"" REV_A "\",122]],0]"
    };
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i)
        if (!ballot_catalog_call(table, bad[i], false, "Invalid", NULL)) failures++;
    chain_params_select(CHAIN_TESTNET);
    if (!ballot_catalog_call(table, CATALOG_ARGS, true, NULL, testnet_digest) ||
        !strcmp(regtest_digest, testnet_digest)) failures++;
    chain_params_select(CHAIN_MAIN);
    if (!ballot_catalog_call(table, CATALOG_ARGS, false, "testnet and regtest", NULL)) failures++;
    return failures;
}


int test_rpc_ballotstatus(void)
{
    struct rpc_table table;
    rpc_table_init(&table);
    register_blockchain_rpc_commands(&table);
    set_rpc_warmup_finished();
    rpc_blockchain_set_ballot_catalog_pin(NULL);
    static const char *bad[] = {
        "{}", "[1,2,3,1,0]", "[1,2,3,1,0,\"" ZERO_CATALOG "\",0]",
        "[\"1\",1,3,1,0,\"" ZERO_CATALOG "\"]",
        "[1.5,1,3,1,0,\"" ZERO_CATALOG "\"]",
        "[true,1,3,1,0,\"" ZERO_CATALOG "\"]",
        "[1,257,300,1,0,\"" ZERO_CATALOG "\"]",
        "[1,1,3,1,1,\"" ZERO_CATALOG "\"]",
        "[1,1,3,1,0,\"xyz\"]",
        "[1,1,2,1,0,\"" ZERO_CATALOG "\"]"
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        if (!ballot_status_refuses(&table, bad[i], "Invalid")) failures++;
    chain_params_select(CHAIN_MAIN);
    if (!ballot_status_refuses(&table, "[]", "testnet and regtest")) failures++;
    const char *valid = "[1,20,23,1,0,\"" ZERO_CATALOG "\"]";
    if (!ballot_status_refuses(&table, valid, "testnet and regtest")) failures++;
    chain_params_select(CHAIN_REGTEST);
    rpc_blockchain_set_state(NULL, NULL, NULL);
    if (!ballot_status_refuses(&table, "[]", "No ballot catalog pinned")) failures++;
    if (!ballot_status_refuses(&table, valid, "unavailable")) failures++;
    if (!ballot_status_refuses(&table, "[0]", "No ballot catalog pinned")) failures++;
    failures += ballot_catalog_cases(&table);
    chain_params_select(CHAIN_MAIN);
    return failures;
}

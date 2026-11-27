/* purpose: Exercise testnet ballot status through the registered blockchain RPC table. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "controllers/blockchain_controller.h"
#include "chain/chainparams.h"
#include "json/json.h"
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

int test_rpc_ballotstatus(void)
{
    struct rpc_table table;
    rpc_table_init(&table);
    register_blockchain_rpc_commands(&table);
    set_rpc_warmup_finished();
    static const char *bad[] = {
        "{}", "[]", "[1,2,3,1,0]", "[1,2,3,1,0,\"" ZERO_CATALOG "\",0]",
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
    const char *valid = "[1,20,23,1,0,\"" ZERO_CATALOG "\"]";
    if (!ballot_status_refuses(&table, valid, "testnet and regtest")) failures++;
    chain_params_select(CHAIN_REGTEST);
    rpc_blockchain_set_state(NULL, NULL, NULL);
    if (!ballot_status_refuses(&table, valid, "unavailable")) failures++;
    chain_params_select(CHAIN_MAIN);
    return failures;
}

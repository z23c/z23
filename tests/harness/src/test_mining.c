/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Mining controller unit tests — RPC registration, edge cases. */

#include "test/test_core.h"
#include "controllers/mining_controller.h"
#include <string.h>

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

    return failures;
}

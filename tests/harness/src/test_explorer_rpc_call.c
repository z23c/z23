/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test for explorer RPC-proxy failure hygiene. A dead RPC backend
 * must leave a valid empty C string so callers never parse uninitialized stack.
 */

#include "test/test_core.h"
#include "../../../contexts/explorer/controllers/src/explorer_controller_internal.h"

#include <string.h>

int test_explorer_rpc_call(void)
{
    printf("\n=== explorer RPC call guards ===\n");
    int failures = 0;

    explorer_set_state(NULL, NULL, NULL, NULL, NULL);
    explorer_set_rpc("user", "pass", 1);

    printf("rpc_call dead port returns -1 and clears output... ");
    {
        char buf[64];
        memset(buf, 0xA5, sizeof(buf));
        int n = rpc_call("getblockcount", "[]", buf, sizeof(buf));
        bool ok = (n == -1 && buf[0] == '\0');
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("rpc_call rejects zero-sized output buffer... ");
    {
        char buf[1] = { 'x' };
        int n = rpc_call("getblockcount", "[]", buf, 0);
        bool ok = (n == -1 && buf[0] == 'x');
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("rpc_call rejects NULL output buffer... ");
    {
        int n = rpc_call("getblockcount", "[]", NULL, 64);
        bool ok = (n == -1);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("explorer block RPC failure renders not-found view... ");
    {
        uint8_t resp[4096];
        size_t n = explorer_handle_request("GET", "/explorer/block/241",
                                           NULL, 0, resp, sizeof(resp));
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        bool ok = n > 0 &&
                  strstr((const char *)resp, "404 Not Found") != NULL &&
                  strstr((const char *)resp, "Block Not Found") != NULL;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("explorer RPC call guards: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}

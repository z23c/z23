/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fail-closed guarantees of the onion dial path (lib/net/src/onion_stream.c)
 * that hold WITHOUT a live Tor network, so they run in default CI:
 *
 *   1. onion_stream_connect() refuses a non-tor service (usage error).
 *   2. onion_stream_connect() refuses a tor service when the embedded Tor
 *      runtime is not up (stub build OR simply not started in this
 *      process) — the dial fails with a named error instead of falling
 *      back to clearnet.
 *   3. connect_socket_start() refuses a torv3 service outright, so an
 *      onion address that somehow reaches the clearnet dialer can never
 *      connect(2) the all-zero IPv6 address.
 *
 * The happy path (real circuit, byte pump, EOF propagation) needs a live
 * Tor network and a real peer; it is exercised by the operator acceptance
 * flow, not here — same gating posture as test_onion_bootstrap.c. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "net/onion_stream.h"
#include "net/onion_v3_address.h"

#include <string.h>

int test_onion_stream(void);
int test_onion_stream(void)
{
    int failures = 0;

    printf("onion_stream: default connect budget uses two bounded fresh "
           "circuits... ");
    {
        int budgets[2] = {-1, -1};
        size_t attempts = onion_stream_connect_plan_for_test(
            ONION_STREAM_CONNECT_TIMEOUT_MS, budgets);
        bool ok = attempts == 2 &&
                  budgets[0] == ONION_STREAM_RETRY_MIN_TOTAL_MS / 2 &&
                  budgets[1] == ONION_STREAM_RETRY_MIN_TOTAL_MS / 2 &&
                  budgets[0] + budgets[1] ==
                      ONION_STREAM_CONNECT_TIMEOUT_MS;

        budgets[0] = -1;
        budgets[1] = -1;
        attempts = onion_stream_connect_plan_for_test(
            ONION_STREAM_RETRY_MIN_TOTAL_MS - 1, budgets);
        ok = ok && attempts == 1 &&
             budgets[0] == ONION_STREAM_RETRY_MIN_TOTAL_MS - 1 &&
             budgets[1] == 0;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("onion_stream: refuses a non-tor service... ");
    {
        struct net_service svc;
        net_service_init(&svc);
        unsigned char ip4[4] = {10, 0, 0, 9};
        net_addr_set_ipv4(&svc.addr, ip4);
        svc.port = 8033;
        zcl_socket_t sock = ZCL_INVALID_SOCKET;
        bool ok = !onion_stream_connect(&svc, &sock, 1000) &&
                  sock == ZCL_INVALID_SOCKET;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("onion_stream: tor dial fails closed with Tor down... ");
    {
        /* A syntactically valid torv3 service (real checksum via the
         * codec). The connect must fail immediately — named "tor not
         * running/not ready" — never resolve or dial clearnet. */
        uint8_t pub[32];
        for (int i = 0; i < 32; i++)
            pub[i] = (uint8_t)(0x40 + i);
        char host[ONION_V3_ADDRESS_LEN + 1];
        bool ok = onion_v3_address_from_pubkey(pub, host);

        struct net_service svc;
        net_service_init(&svc);
        ok = ok && net_addr_from_onion(host, &svc.addr);
        svc.port = 8033;

        zcl_socket_t sock = ZCL_INVALID_SOCKET;
        ok = ok && !onion_stream_connect(&svc, &sock, 1000) &&
             sock == ZCL_INVALID_SOCKET;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("onion_stream: clearnet dialer refuses torv3... ");
    {
        struct net_service svc;
        net_service_init(&svc);
        svc.addr.has_torv3 = true;
        memset(svc.addr.torv3, 0x77, TORV3_ADDR_SIZE);
        svc.port = 8033;
        zcl_socket_t sock = ZCL_INVALID_SOCKET;
        enum zcl_connect_start st = connect_socket_start(&svc, &sock);
        bool ok = st == ZCL_CONNECT_START_ERROR &&
                  sock == ZCL_INVALID_SOCKET;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

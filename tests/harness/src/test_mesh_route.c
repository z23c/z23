/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Prove bounded, identity-pinned direct mesh route acquisition. */

#include "test/test_core.h"
#include "chain/chainparams.h"
#include "config/boot_mesh_route.h"
#include "net/connman.h"
#include "net/protocol.h"

#include <stdio.h>
#include <string.h>

static void route_endpoint(struct net_address *endpoint, uint8_t host,
                           uint16_t port)
{
    const uint8_t ip[4] = {127, 0, 0, host};
    net_address_init(endpoint);
    net_addr_set_ipv4(&endpoint->svc.addr, ip);
    endpoint->svc.port = port;
}

static void route_pairing_id(char out[65], unsigned value)
{
    (void)snprintf(out, 65, "%064x", value);
}

static int route_test_admission(struct connman *cm)
{
    int failures = 0;
    TEST_CASE("mesh route: admission precedes and does not consume a dial") {
        boot_mesh_route_reset();
        char id[65]; struct net_address endpoint; uint8_t attempts = 99;
        route_pairing_id(id, 1); route_endpoint(&endpoint, 1, 20023);
        ASSERT_EQ(boot_mesh_route_test_step(
                      id, &endpoint, BOOT_MESH_ROUTE_OBS_NONE, false, 1000,
                      cm, &attempts), BOOT_MESH_ROUTE_RESOURCE_DEFERRED);
        ASSERT_EQ(attempts, 0);
        ASSERT(!connman_dht_hint_pending(cm));
    } TEST_END
    return failures;
}

static int route_test_queue(struct connman *cm)
{
    int failures = 0;
    TEST_CASE("mesh route: accepted work queues a Noise-only direct dial") {
        char id[65]; struct net_address endpoint, queued; uint8_t attempts = 0;
        route_pairing_id(id, 1); route_endpoint(&endpoint, 1, 20023);
        ASSERT_EQ(boot_mesh_route_test_step(
                      id, &endpoint, BOOT_MESH_ROUTE_OBS_NONE, true, 1000,
                      cm, &attempts), BOOT_MESH_ROUTE_PENDING);
        ASSERT_EQ(attempts, 1);
        ASSERT(connman_take_dht_hint(cm, &queued));
        ASSERT(net_service_eq(&queued.svc, &endpoint.svc));
        ASSERT((queued.nServices & NODE_NOISE_TRANSPORT) != 0);
        ASSERT_EQ(boot_mesh_route_test_step(
                      id, &endpoint, BOOT_MESH_ROUTE_OBS_NONE, true, 1500,
                      cm, &attempts), BOOT_MESH_ROUTE_PENDING);
        ASSERT_EQ(attempts, 1);
        ASSERT(!connman_dht_hint_pending(cm));
        ASSERT_EQ(boot_mesh_route_test_step(
                      id, &endpoint, BOOT_MESH_ROUTE_OBS_CONNECTING, true,
                      2000, cm, &attempts), BOOT_MESH_ROUTE_PENDING);
        ASSERT_EQ(attempts, 1);
        ASSERT(!connman_dht_hint_pending(cm));
    } TEST_END
    return failures;
}

static int route_test_terminal_recovery(struct connman *cm)
{
    int failures = 0;
    TEST_CASE("mesh route: wrong Noise identity is terminal then recovers") {
        char id[65]; struct net_address endpoint, queued; uint8_t attempts = 0;
        route_pairing_id(id, 1); route_endpoint(&endpoint, 1, 20023);
        ASSERT_EQ(boot_mesh_route_test_step(
                      id, &endpoint, BOOT_MESH_ROUTE_OBS_WRONG_NOISE, true,
                      2100, cm, &attempts),
                  BOOT_MESH_ROUTE_IDENTITY_MISMATCH);
        ASSERT_EQ(boot_mesh_route_test_step(
                      id, &endpoint, BOOT_MESH_ROUTE_OBS_MATCHED_NOISE, true,
                      2200, cm, &attempts),
                  BOOT_MESH_ROUTE_IDENTITY_MISMATCH);
        ASSERT(!connman_dht_hint_pending(cm));
        ASSERT_EQ(boot_mesh_route_test_step(
                      id, &endpoint, BOOT_MESH_ROUTE_OBS_NONE, true, 32100,
                      cm, &attempts), BOOT_MESH_ROUTE_PENDING);
        ASSERT_EQ(attempts, 1);
        ASSERT(connman_take_dht_hint(cm, &queued));
    } TEST_END
    return failures;
}

static int route_test_downgrade(struct connman *cm)
{
    int failures = 0;
    TEST_CASE("mesh route: exact plaintext completion refuses downgrade") {
        boot_mesh_route_reset();
        char id[65]; struct net_address endpoint; uint8_t attempts = 0;
        route_pairing_id(id, 2); route_endpoint(&endpoint, 2, 20024);
        ASSERT_EQ(boot_mesh_route_test_step(
                      id, &endpoint, BOOT_MESH_ROUTE_OBS_PLAINTEXT, true,
                      1000, cm, &attempts), BOOT_MESH_ROUTE_DOWNGRADE);
        ASSERT(!connman_dht_hint_pending(cm));
    } TEST_END
    return failures;
}

static int route_test_match(struct connman *cm)
{
    int failures = 0;
    TEST_CASE("mesh route: matching established Noise acquires without dial") {
        boot_mesh_route_reset();
        char id[65]; struct net_address endpoint; uint8_t attempts = 0;
        route_pairing_id(id, 3); route_endpoint(&endpoint, 3, 20025);
        ASSERT_EQ(boot_mesh_route_test_step(
                      id, &endpoint, BOOT_MESH_ROUTE_OBS_MATCHED_NOISE, true,
                      1000, cm, &attempts), BOOT_MESH_ROUTE_ACQUIRED);
        ASSERT_EQ(attempts, 0);
        ASSERT(!connman_dht_hint_pending(cm));
    } TEST_END
    return failures;
}

static int route_test_exhaustion(struct connman *cm)
{
    int failures = 0;
    TEST_CASE("mesh route: three bounded attempts exhaust without fallback") {
        boot_mesh_route_reset();
        char id[65]; struct net_address endpoint, queued; uint8_t attempts = 0;
        route_pairing_id(id, 4); route_endpoint(&endpoint, 4, 20026);
        const uint64_t attempt_times[BOOT_MESH_ROUTE_MAX_ATTEMPTS] = {
            1000, 2000, 4000,
        };
        for (size_t i = 0; i < BOOT_MESH_ROUTE_MAX_ATTEMPTS; i++) {
            ASSERT_EQ(boot_mesh_route_test_step(
                          id, &endpoint, BOOT_MESH_ROUTE_OBS_NONE, true,
                          attempt_times[i], cm, &attempts),
                      BOOT_MESH_ROUTE_PENDING);
            ASSERT_EQ(attempts, i + 1u);
            ASSERT(connman_take_dht_hint(cm, &queued));
        }
        ASSERT_EQ(boot_mesh_route_test_step(
                      id, &endpoint, BOOT_MESH_ROUTE_OBS_NONE, true, 8000,
                      cm, &attempts), BOOT_MESH_ROUTE_PENDING);
        ASSERT_EQ(attempts, BOOT_MESH_ROUTE_MAX_ATTEMPTS);
        ASSERT(!connman_dht_hint_pending(cm));
        ASSERT_EQ(boot_mesh_route_test_step(
                      id, &endpoint, BOOT_MESH_ROUTE_OBS_NONE, true, 16000,
                      cm, &attempts), BOOT_MESH_ROUTE_EXHAUSTED);
        ASSERT_EQ(boot_mesh_route_test_step(
                      id, &endpoint, BOOT_MESH_ROUTE_OBS_NONE, true, 16100,
                      cm, &attempts), BOOT_MESH_ROUTE_EXHAUSTED);
    } TEST_END
    return failures;
}

static int route_test_abandoned_reclaim(struct connman *cm)
{
    int failures = 0;
    TEST_CASE("mesh route: abandoned acquisitions release bounded slots") {
        boot_mesh_route_reset();
        struct net_address endpoint; uint8_t attempts = 0;
        for (unsigned i = 0; i < BOOT_MESH_ROUTE_MAX; i++) {
            char id[65]; route_pairing_id(id, 100u + i);
            route_endpoint(&endpoint, (uint8_t)(10u + i),
                           (uint16_t)(20100u + i));
            ASSERT_EQ(boot_mesh_route_test_step(
                          id, &endpoint, BOOT_MESH_ROUTE_OBS_NONE, false,
                          1000, cm, &attempts),
                      BOOT_MESH_ROUTE_RESOURCE_DEFERRED);
            ASSERT_EQ(attempts, 0);
        }
        char ninth[65]; route_pairing_id(ninth, 200);
        route_endpoint(&endpoint, 30, 20200);
        ASSERT_EQ(boot_mesh_route_test_step(
                      ninth, &endpoint, BOOT_MESH_ROUTE_OBS_NONE, false,
                      1001, cm, &attempts), BOOT_MESH_ROUTE_BUSY);
        ASSERT_EQ(boot_mesh_route_test_step(
                      ninth, &endpoint, BOOT_MESH_ROUTE_OBS_NONE, false,
                      16000, cm, &attempts),
                  BOOT_MESH_ROUTE_RESOURCE_DEFERRED);
        ASSERT_EQ(attempts, 0);
    } TEST_END
    return failures;
}

int test_mesh_route(void)
{
    chain_params_select(CHAIN_MAIN);
    struct connman cm; struct node_signals signals;
    memset(&signals, 0, sizeof(signals));
    if (!connman_init(&cm, chain_params_get(), &signals)) {
        printf("mesh_route: fixture initialization... FAIL\n");
        return 1;
    }
    int failures = route_test_admission(&cm) + route_test_queue(&cm) +
                   route_test_terminal_recovery(&cm) +
                   route_test_downgrade(&cm) + route_test_match(&cm) +
                   route_test_exhaustion(&cm) +
                   route_test_abandoned_reclaim(&cm);
    boot_mesh_route_reset();
    connman_free(&cm);
    return failures;
}

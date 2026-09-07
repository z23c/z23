/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * connman addnode-fallback scenario checks: DHT-hint/loopback/onion-
 * redial dial fallback, zcl23 peer-source backoff ownership, addnodes-
 * before-addrman drain, remove/compact state, outbound health
 * diversity, and the addrman peer floor across cold start, height, and
 * subnets.
 *
 * Split out of test_connman_addnode_fallback.c (which keeps the
 * includes, the fixture helpers shared across siblings, and the group
 * entry point) so no family member crosses the 1,500-line ceiling. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "coins/undo.h"
#include "net/connman.h"
#include "net/tor_integration.h"
#include "net/onion_v3_address.h"
#include "storage/census_read.h"
#include "util/blocker.h"
#include <unistd.h>
#include "test/test_connman_addnode_fallback_priv.h"


struct test_known_zcl23_ctx {
    struct connman_known_peer peers[8];
    int count;
};

static int test_known_zcl23_peers(void *ctx,
                                  struct connman_known_peer *out,
                                  size_t max)
{
    struct test_known_zcl23_ctx *known = ctx;
    if (!known || !out || max == 0)
        return 0;
    size_t count = (size_t)known->count;
    if (count > max)
        count = max;
    memcpy(out, known->peers, count * sizeof(*out));
    return (int)count;
}

static void test_known_add_ipv4(struct test_known_zcl23_ctx *known,
                                uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                                uint16_t port)
{
    if (!known || known->count >= 8)
        return;
    struct net_address addr;
    test_set_ipv4(&addr, a, b, c, d, port);
    struct connman_known_peer *peer = &known->peers[known->count++];
    memcpy(peer->ip, addr.svc.addr.ip, sizeof(peer->ip));
    peer->port = port;
    peer->services = NODE_NETWORK | NODE_ZCL23;
}

static bool addnode_dht_hint_wait_and_rate_ok(struct connman *cm)
{
    return cm->dht_hint_count == 1 && cm->num_addnodes == 0 &&
           connman_dht_hint_pending(cm) &&
           !connman_connect_only_wait_needed_for_test(true, 1, 1, true) &&
           connman_connect_only_wait_needed_for_test(true, 1, 1, false) &&
           connman_outbound_rate_allowed_for_test(false, false, true) &&
           connman_outbound_rate_allowed_for_test(true, false, false) &&
           connman_outbound_rate_allowed_for_test(false, true, false) &&
           !connman_outbound_rate_allowed_for_test(false, false, false);
}

int check_connman_addnode_dht_hint_priority_dial(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: signed DHT hints get one priority "
           "dial without becoming addnodes... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);
        struct net_address hint;
        test_set_ipv4(&hint, 127, 0, 0, 1, 20023);
        ok = ok && connman_queue_dht_hint(&cm, &hint);
        ok = ok && connman_queue_dht_hint(&cm, &hint);
        ok = ok && addnode_dht_hint_wait_and_rate_ok(&cm);
        struct connman_dial_candidate candidate;
        memset(&candidate, 0, sizeof(candidate));
        size_t n = ok ? connman_gather_dial_candidates(&cm, &candidate, 1) : 0;
        ok = ok && n == 1 &&
             candidate.source == CONNMAN_TARGET_DHT_HINT &&
             candidate.addr.svc.port == 20023 && cm.dht_hint_count == 0 &&
             !connman_dht_hint_pending(&cm) && cm.num_addnodes == 0;
        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static bool addnode_loopback_after_connect_pick(struct connman *cm, bool ok)
{
    cm->next_addnode_cursor = 0;
    struct connman_dial_candidate after_connect[2];
    memset(after_connect, 0, sizeof(after_connect));
    size_t after_n = ok ? connman_gather_dial_candidates(
                              cm, after_connect, 2) : 0;
    ok = ok && after_n == 1 &&
         after_connect[0].addr.svc.port == 20024;
    cm->next_addnode_cursor = 0;
    struct addr_info remaining;
    enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
    memset(&remaining, 0, sizeof(remaining));
    ok = ok && connman_pick_next_outbound_target(
                   cm, &cm->next_addnode_cursor, &remaining, &source,
                   NULL) &&
         source == CONNMAN_TARGET_ADDNODE &&
         remaining.addr.svc.port == 20024;
    return ok;
}

int check_connman_addnode_loopback_edges_distinct(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: explicit loopback edges remain distinct "
           "in one sparse-fixture batch... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);
        test_set_ipv4(&cm.addnodes[0], 127, 0, 0, 1, 20023);
        test_set_ipv4(&cm.addnodes[1], 127, 0, 0, 1, 20024);
        cm.num_addnodes = 2;
        struct connman_dial_candidate candidates[2];
        memset(candidates, 0, sizeof(candidates));
        size_t n = ok ? connman_gather_dial_candidates(&cm, candidates, 2) : 0;
        ok = ok && n == 2 &&
             candidates[0].source == CONNMAN_TARGET_ADDNODE &&
             candidates[1].source == CONNMAN_TARGET_ADDNODE &&
             candidates[0].addr.svc.port != candidates[1].addr.svc.port;
        struct p2p_node *first = add_test_peer(
            &cm, 127, 0, 0, 1, PEER_HANDSHAKE_COMPLETE, false, false);
        ok = ok && first != NULL;
        if (first)
            first->addr.svc.port = 20023;
        ok = addnode_loopback_after_connect_pick(&cm, ok);
        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_custom_port_onion_redial(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: explicit custom-port onion remains "
           "eligible for persistent redial... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        uint8_t pub[32];
        for (int i = 0; i < 32; i++)
            pub[i] = (uint8_t)(0x70 + i);
        char host[ONION_V3_ADDRESS_LEN + 1];
        ok = ok && onion_v3_address_from_pubkey(pub, host);

        struct net_address onion;
        net_address_init(&onion);
        ok = ok && net_addr_from_onion(host, &onion.svc.addr);
        onion.svc.port = 8055;
        cm.addnodes[cm.num_addnodes++] = onion;

        struct connman_dial_candidate candidate;
        memset(&candidate, 0, sizeof(candidate));
        size_t n = ok ? connman_gather_dial_candidates(
                            &cm, &candidate, 1) : 0;
        ok = ok && n == 1 &&
             candidate.source == CONNMAN_TARGET_ADDNODE &&
             net_addr_is_tor(&candidate.addr.svc.addr) &&
             candidate.addr.svc.port == 8055;

        /* The exception belongs only to operator authority.  The identical
         * custom-port endpoint, when merely learned through addrman, remains
         * outside the public reachable-port policy. */
        struct net_addr source;
        net_addr_init(&source);
        ok = ok && connman_remove_addnode(&cm, &onion) &&
             addrman_add(&cm.manager.addrman, &onion, &source, 0);
        memset(&candidate, 0, sizeof(candidate));
        n = ok ? connman_gather_dial_candidates(&cm, &candidate, 1) : 1;
        ok = ok && n == 0;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static bool addnode_zcl23_first_pick_not_owned(size_t n,
    const struct connman_dial_candidate *candidate)
{
    return n == 1 &&
           !(candidate->source == CONNMAN_TARGET_ZCL23_DB &&
             candidate->addr.svc.addr.ip[12] == 140);
}

static bool addnode_zcl23_fell_through_to_general(struct connman *cm, size_t n,
    const struct connman_dial_candidate *candidate)
{
    return n == 1 &&
           candidate->source == CONNMAN_TARGET_ADDRMAN &&
           candidate->addr.svc.addr.ip[12] == 81 &&
           atomic_load(&cm->zcl23_backoff_skips) >= 1 &&
           atomic_load(&cm->zcl23_policy_skips) >= 1;
}

static bool addnode_zcl23_three_day_attempts_bounded(void)
{
    int simulated_attempts = 0;
    int64_t next_attempt = 0;
    for (int64_t second = 0; second < 3 * 86400; second++) {
        if (second < next_attempt)
            continue;
        simulated_attempts++;
        next_attempt = second +
            connman_addrman_retry_cooldown_for_test(simulated_attempts);
    }
    return simulated_attempts <= 20;
}

static bool addnode_zcl23_205_picked(size_t n,
    const struct connman_dial_candidate *candidate)
{
    return n == 1 &&
           candidate->source == CONNMAN_TARGET_ZCL23_DB &&
           candidate->addr.svc.addr.ip[12] == 205;
}

static bool addnode_zcl23_charged_eleven(struct connman *cm,
    const struct connman_dial_candidate *candidate)
{
    struct addr_info charged;
    memset(&charged, 0, sizeof(charged));
    return addrman_find_info(&cm->manager.addrman,
                             &candidate->addr.svc, &charged) &&
           charged.attempts == 11;
}

static bool addnode_zcl23_cooldown_then_recharge(struct connman *cm,
    struct connman_dial_candidate *candidate)
{
    /* Whichever other known endpoint was selected now owns an addrman
     * attempt. Put it into the persisted six-hour tier and prove the
     * next preferred turn falls through to a healthy general peer. */
    int64_t now = (int64_t)platform_time_wall_time_t();
    bool ok = test_addrman_set_fail(cm, 205, 10, now);
    atomic_store(&cm->zcl23_preference_round, 0);
    memset(candidate, 0, sizeof(*candidate));
    size_t n = ok ? connman_gather_dial_candidates(cm, candidate, 1) : 0;
    ok = ok && addnode_zcl23_fell_through_to_general(cm, n, candidate);

    /* Three days of a peer that accepts TCP and immediately closes must
     * remain a small bounded number of scheduler assignments, not the
     * tens-of-thousands/day trajectory observed on node4. */
    ok = ok && addnode_zcl23_three_day_attempts_bounded();

    /* After the durable cooldown expires, the same endpoint is eligible
     * through the shared scheduler again and is charged only once. */
    ok = ok && test_addrman_set_fail(cm, 205, 10, now - 21601);
    atomic_store(&cm->zcl23_preference_round, 0);
    memset(candidate, 0, sizeof(*candidate));
    n = ok ? connman_gather_dial_candidates(cm, candidate, 1) : 0;
    ok = ok && addnode_zcl23_205_picked(n, candidate);
    ok = ok && addnode_zcl23_charged_eleven(cm, candidate);
    return ok;
}

int check_connman_addnode_zcl23_backoff_ownership(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: discovered ZCL23 peers share durable "
           "backoff and reciprocal ownership... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct test_known_zcl23_ctx known;
        struct net_addr source;
        memset(&sigs, 0, sizeof(sigs));
        memset(&known, 0, sizeof(known));
        net_addr_init(&source);
        bool ok = connman_init(&cm, params, &sigs);

        test_known_add_ipv4(&known, 140, 174, 189, 3, 8033);
        test_known_add_ipv4(&known, 205, 209, 104, 118, 8033);
        connman_set_known_zcl23_peer_source(&cm, test_known_zcl23_peers,
                                            &known);

        /* A healthy general candidate proves a cooling/stable ZCL23 set
         * cannot starve the rest of addrman. */
        struct net_address general;
        test_set_ipv4(&general, 81, 214, 132, 20, 8033);
        general.nTime = (uint32_t)platform_time_wall_time_t();
        ok = ok && addrman_add(&cm.manager.addrman, &general, &source, 0);

        /* The first known endpoint is already connected inbound under an
         * ephemeral source port. Exact endpoint comparison would miss it;
         * the handshake-qualified IP ownership rule must suppress the
         * reciprocal outbound collision. */
        struct p2p_node *inbound = add_test_peer(
            &cm, 140, 174, 189, 3, PEER_HANDSHAKE_COMPLETE, true, false);
        ok = ok && inbound != NULL;
        if (inbound) {
            inbound->addr.svc.port = 49152;
            inbound->services = NODE_NETWORK | NODE_ZCL23;
            memcpy(inbound->advertised_service.addr.ip,
                   known.peers[0].ip,
                   sizeof(inbound->advertised_service.addr.ip));
            inbound->advertised_service.port = known.peers[0].port;
            inbound->advertised_service_valid = true;
        }

        struct connman_dial_candidate candidate;
        memset(&candidate, 0, sizeof(candidate));
        size_t n = ok ? connman_gather_dial_candidates(&cm, &candidate, 1) : 0;
        ok = ok && addnode_zcl23_first_pick_not_owned(n, &candidate);
        ok = ok && addnode_zcl23_cooldown_then_recharge(&cm, &candidate);

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static bool addnode_drain_pick_fields_ok(const struct addr_info *pick,
    enum connman_outbound_target_source source, size_t addnode_index, int i,
    const struct net_address *want)
{
    return source == CONNMAN_TARGET_ADDNODE &&
           addnode_index == (size_t)i &&
           net_addr_eq(&pick->addr.svc.addr, &want->svc.addr) &&
           pick->addr.svc.port == want->svc.port;
}

int check_connman_addnode_addnodes_drain_before_addrman(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: addnodes drain before addrman... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        for (int i = 0; ok && i < 10; i++) {
            struct net_address addr;
            test_set_ipv4(&addr, 203, 0, 113, (uint8_t)(10 + i), 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
        }

        for (int i = 0; ok && i < 10; i++) {
            struct net_address want = cm.addnodes[i];
            struct addr_info pick;
            enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
            size_t addnode_index = SIZE_MAX;
            memset(&pick, 0, sizeof(pick));
            ok = connman_pick_next_outbound_target(&cm,
                                                   &cm.next_addnode_cursor,
                                                   &pick,
                                                   &source,
                                                   &addnode_index);
            ok = ok && addnode_drain_pick_fields_ok(&pick, source,
                                                    addnode_index, i, &want);

            /* Simulate a failed dial so the next pick advances instead of
             * returning the same addnode again within the cooldown window. */
            connman_record_addnode_attempt(&cm, addnode_index, false);
        }

        if (ok) {
            struct addr_info pick;
            enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
            struct connman_outbound_health health;
            memset(&pick, 0, sizeof(pick));
            ok = !connman_pick_next_outbound_target(&cm,
                                                    &cm.next_addnode_cursor,
                                                    &pick,
                                                    &source,
                                                    NULL);
            memset(&health, 0, sizeof(health));
            connman_get_outbound_health(&cm, &health);
            ok = ok && health.addnode_count == 10;
            ok = ok && health.addnode_backoff_active == 10;
            ok = ok && health.addnode_tcp_failures == 10;
            ok = ok && health.addnode_protocol_failures == 0;
            connman_record_addnode_failure(&cm, 0,
                                           CONNMAN_ADDNODE_FAILURE_PROTOCOL);
            memset(&health, 0, sizeof(health));
            connman_get_outbound_health(&cm, &health);
            ok = ok && health.addnode_tcp_failures == 10;
            ok = ok && health.addnode_protocol_failures == 1;
        }

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static bool addnode_remove_compacted_ok(struct connman *cm,
    const struct net_address *a, const struct net_address *c,
    const struct net_address *missing)
{
    return cm->num_addnodes == 2 &&
           net_addr_eq(&cm->addnodes[0].svc.addr, &a->svc.addr) &&
           cm->addnodes[0].svc.port == a->svc.port &&
           net_addr_eq(&cm->addnodes[1].svc.addr, &c->svc.addr) &&
           cm->addnodes[1].svc.port == c->svc.port &&
           cm->addnode_last_attempt[1] == 30 &&
           cm->addnode_backoff_sec[1] == 60 &&
           cm->addnode_tcp_failures[1] == 3 &&
           cm->addnode_protocol_failures[1] == 6 &&
           cm->next_addnode_cursor == 1 &&
           !connman_remove_addnode(cm, missing);
}

int check_connman_addnode_remove_compacts_state(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: addnode remove compacts state... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct net_address a;
        struct net_address b;
        struct net_address c;
        struct net_address missing;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        test_set_ipv4(&a, 203, 0, 113, 10, 8033);
        test_set_ipv4(&b, 203, 0, 113, 11, 20022);
        test_set_ipv4(&c, 203, 0, 113, 12, 8033);
        test_set_ipv4(&missing, 203, 0, 113, 99, 8033);

        cm.addnodes[cm.num_addnodes++] = a;
        cm.addnodes[cm.num_addnodes++] = b;
        cm.addnodes[cm.num_addnodes++] = c;
        cm.addnode_last_attempt[0] = 10;
        cm.addnode_last_attempt[1] = 20;
        cm.addnode_last_attempt[2] = 30;
        cm.addnode_backoff_sec[0] = 40;
        cm.addnode_backoff_sec[1] = 50;
        cm.addnode_backoff_sec[2] = 60;
        cm.addnode_tcp_failures[0] = 1;
        cm.addnode_tcp_failures[1] = 2;
        cm.addnode_tcp_failures[2] = 3;
        cm.addnode_protocol_failures[0] = 4;
        cm.addnode_protocol_failures[1] = 5;
        cm.addnode_protocol_failures[2] = 6;
        cm.next_addnode_cursor = 2;

        ok = ok && connman_remove_addnode(&cm, &b);
        ok = ok && addnode_remove_compacted_ok(&cm, &a, &c, &missing);

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static bool addnode_outbound_health_expected(struct connman *cm,
    const struct connman_outbound_health *health)
{
    return health->outbound_total == 4 &&
           health->inbound_total == 1 &&
           health->healthy == 3 &&
           health->inbound_healthy == 1 &&
           health->connecting == 1 &&
           health->handshake_incomplete == 1 &&
           health->inbound_handshake_incomplete == 0 &&
           health->ipv4_group_count == 3 &&
           health->ipv4_max_group_size == 2 &&
           connman_outbound_healthy_count(cm) == 3;
}

int check_connman_addnode_outbound_health_diversity(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: outbound health tracks diversity... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct connman_outbound_health health;
        memset(&sigs, 0, sizeof(sigs));
        memset(&health, 0, sizeof(health));
        bool ok = connman_init(&cm, params, &sigs);

        ok = ok && add_test_peer(&cm, 10, 1, 0, 1,
                                 PEER_HANDSHAKE_COMPLETE,
                                 false, false) != NULL;
        ok = ok && add_test_peer(&cm, 10, 1, 0, 2,
                                 PEER_ACTIVE,
                                 false, false) != NULL;
        ok = ok && add_test_peer(&cm, 172, 16, 0, 1,
                                 PEER_SYNCING_BLOCKS,
                                 false, false) != NULL;
        ok = ok && add_test_peer(&cm, 198, 51, 100, 5,
                                 PEER_CONNECTING,
                                 false, false) != NULL;
        ok = ok && add_test_peer(&cm, 203, 0, 113, 1,
                                 PEER_ACTIVE,
                                 true, false) != NULL;
        ok = ok && add_test_peer(&cm, 203, 0, 113, 2,
                                 PEER_ACTIVE,
                                 false, true) != NULL;

        connman_get_outbound_health(&cm, &health);
        ok = ok && addnode_outbound_health_expected(&cm, &health);

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_non_network_not_floor(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: non-network peers do not satisfy "
           "outbound floor... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct connman_outbound_health health;
        struct p2p_node *no_network = NULL;
        memset(&sigs, 0, sizeof(sigs));
        memset(&health, 0, sizeof(health));
        bool ok = connman_init(&cm, params, &sigs);

        ok = ok && add_test_peer(&cm, 10, 9, 0, 1,
                                 PEER_HANDSHAKE_COMPLETE,
                                 false, false) != NULL;
        ok = ok && add_test_peer(&cm, 172, 20, 0, 1,
                                 PEER_ACTIVE,
                                 false, false) != NULL;
        ok = ok && (no_network = add_test_peer(&cm, 198, 51, 100, 9,
                                               PEER_ACTIVE,
                                               false, false)) != NULL;
        if (ok)
            no_network->services = 0;

        connman_get_outbound_health(&cm, &health);
        ok = ok && health.outbound_total == 3;
        ok = ok && health.healthy == 2;
        ok = ok && connman_outbound_healthy_count(&cm) == 2;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_cold_start_discovery_floor(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: cold-start discovery follows healthy "
           "outbound floor... ");
    {
        bool ok = true;
        ok = ok && connman_seed_discovery_needed_for_test(0);
        ok = ok && connman_seed_discovery_needed_for_test(1);
        ok = ok && connman_seed_discovery_needed_for_test(2);
        ok = ok && !connman_seed_discovery_needed_for_test(3);
        ok = ok && !connman_seed_discovery_needed_for_test(8);
        ok = ok && connman_seed_discovery_interval_for_test(0) == 30;
        ok = ok && connman_seed_discovery_interval_for_test(1) == 60;
        ok = ok && connman_seed_discovery_interval_for_test(2) == 60;
        ok = ok && connman_seed_discovery_interval_for_test(3) == 300;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_max_height_ignores_unusable(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: max peer height ignores unusable slots... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        struct p2p_node *usable = NULL;
        struct p2p_node *connecting = NULL;
        struct p2p_node *disconnecting = NULL;
        struct p2p_node *no_network = NULL;
        ok = ok && (usable = add_test_peer(&cm, 10, 2, 0, 1,
                                           PEER_HANDSHAKE_COMPLETE,
                                           false, false)) != NULL;
        ok = ok && (connecting = add_test_peer(&cm, 10, 2, 0, 2,
                                               PEER_CONNECTING,
                                               false, false)) != NULL;
        ok = ok && (disconnecting = add_test_peer(&cm, 10, 2, 0, 3,
                                                  PEER_ACTIVE,
                                                  false, true)) != NULL;
        ok = ok && (no_network = add_test_peer(&cm, 10, 2, 0, 4,
                                               PEER_ACTIVE,
                                               false, false)) != NULL;
        if (ok) {
            usable->starting_height = 120;
            connecting->starting_height = 900;
            disconnecting->starting_height = 800;
            no_network->starting_height = 700;
            no_network->services = 0;
            ok = connman_max_peer_height(&cm) == 120;
        }

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_peer_floor_diverse_subnets(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: peer-floor addnodes prefer diverse "
           "subnets... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        ok = ok && add_test_peer(&cm, 10, 1, 0, 1,
                                 PEER_HANDSHAKE_COMPLETE,
                                 false, false) != NULL;
        ok = ok && add_test_peer(&cm, 10, 1, 0, 2,
                                 PEER_HANDSHAKE_COMPLETE,
                                 false, false) != NULL;

        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 10, 1, 0, 1, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
            test_set_ipv4(&addr, 10, 1, 0, 2, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
            test_set_ipv4(&addr, 10, 1, 0, 3, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
            test_set_ipv4(&addr, 172, 16, 0, 3, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
        }

        if (ok) {
            struct addr_info pick;
            enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
            size_t addnode_index = SIZE_MAX;
            memset(&pick, 0, sizeof(pick));
            ok = connman_pick_next_outbound_target(&cm,
                                                   &cm.next_addnode_cursor,
                                                   &pick,
                                                   &source,
                                                   &addnode_index);
            ok = ok && source == CONNMAN_TARGET_ADDNODE;
            ok = ok && addnode_index == 3;
            ok = ok && net_addr_is_ipv4(&pick.addr.svc.addr);
            ok = ok && pick.addr.svc.addr.ip[12] == 172;
            ok = ok && pick.addr.svc.addr.ip[13] == 16;
        }

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static bool addnode_saturated_attempt_recorded(struct connman *cm)
{
    for (int i = 0; i < cm->manager.addrman.id_count; i++) {
        struct addr_info *info = &cm->manager.addrman.entries[i];
        if (!info->used)
            continue;
        if (info->addr.svc.addr.ip[12] == 47 &&
            info->addr.svc.addr.ip[13] == 88) {
            return info->attempts == 1 && info->last_try > 0;
        }
    }
    return false;
}

static bool addnode_saturated_pick_is_diverse(struct connman *cm)
{
    struct addr_info pick;
    enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
    memset(&pick, 0, sizeof(pick));
    bool ok = connman_pick_next_outbound_target(cm,
                                               &cm->next_addnode_cursor,
                                               &pick,
                                               &source,
                                               NULL);
    ok = ok && source == CONNMAN_TARGET_ADDRMAN;
    ok = ok && net_addr_is_ipv4(&pick.addr.svc.addr);
    ok = ok && pick.addr.svc.addr.ip[12] == 47;
    ok = ok && pick.addr.svc.addr.ip[13] == 88;
    ok = ok && addnode_saturated_attempt_recorded(cm);
    memset(&pick, 0, sizeof(pick));
    source = CONNMAN_TARGET_NONE;
    ok = ok && !connman_pick_next_outbound_target(
        cm, &cm->next_addnode_cursor, &pick, &source, NULL);
    return ok;
}

int check_connman_addnode_addrman_skips_saturated(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: addrman skips saturated subnets... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct net_addr src;
        memset(&sigs, 0, sizeof(sigs));
        net_addr_init(&src);
        bool ok = connman_init(&cm, params, &sigs);

        ok = ok && add_test_peer(&cm, 51, 178, 0, 1,
                                 PEER_HANDSHAKE_COMPLETE,
                                 false, false) != NULL;
        ok = ok && add_test_peer(&cm, 51, 178, 0, 2,
                                 PEER_HANDSHAKE_COMPLETE,
                                 false, false) != NULL;

        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 51, 178, 0, 3, 8033);
            ok = ok && addrman_add(&cm.manager.addrman, &addr, &src, 0);
            test_set_ipv4(&addr, 51, 178, 0, 4, 8033);
            ok = ok && addrman_add(&cm.manager.addrman, &addr, &src, 0);
            test_set_ipv4(&addr, 47, 88, 87, 154, 8033);
            ok = ok && addrman_add(&cm.manager.addrman, &addr, &src, 0);
        }

        ok = ok && addnode_saturated_pick_is_diverse(&cm);

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_connman_addnode_inbound_ephemeral_not_block(void)
{
    int failures = 0;
    printf("connman_addnode_fallback: inbound ephemeral does not block "
           "advertised addrman dial... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct net_addr src;
        memset(&sigs, 0, sizeof(sigs));
        net_addr_init(&src);
        bool ok = connman_init(&cm, params, &sigs);

        struct p2p_node *inbound = NULL;
        ok = ok && (inbound = add_test_peer(&cm, 66, 70, 182, 44,
                                            PEER_ACTIVE, true, false)) != NULL;
        if (ok)
            inbound->addr.svc.port = 44554;

        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 66, 70, 182, 44, 8033);
            ok = ok && addrman_add(&cm.manager.addrman, &addr, &src, 0);
        }

        if (ok) {
            struct addr_info pick;
            enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
            memset(&pick, 0, sizeof(pick));
            ok = connman_pick_next_outbound_target(&cm,
                                                   &cm.next_addnode_cursor,
                                                   &pick,
                                                   &source,
                                                   NULL);
            ok = ok && source == CONNMAN_TARGET_ADDRMAN;
            ok = ok && net_addr_is_ipv4(&pick.addr.svc.addr);
            ok = ok && pick.addr.svc.addr.ip[12] == 66;
            ok = ok && pick.addr.svc.addr.ip[13] == 70;
            ok = ok && pick.addr.svc.port == 8033;
        }

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}


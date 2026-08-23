/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "coins/undo.h"
#include "net/connman.h"
#include "net/tor_integration.h"
#include "net/onion_v3_address.h"
#include "storage/census_read.h"
#include "util/blocker.h"
#include <unistd.h>

static void test_set_ipv4(struct net_address *addr,
                          uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                          uint16_t port)
{
    net_address_init(addr);
    addr->svc.addr.ip[10] = 0xff;
    addr->svc.addr.ip[11] = 0xff;
    addr->svc.addr.ip[12] = a;
    addr->svc.addr.ip[13] = b;
    addr->svc.addr.ip[14] = c;
    addr->svc.addr.ip[15] = d;
    addr->svc.port = port;
}

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

static struct p2p_node *add_test_peer(struct connman *cm,
                                      uint8_t a, uint8_t b,
                                      uint8_t c, uint8_t d,
                                      enum peer_state state,
                                      bool inbound,
                                      bool disconnect)
{
    if (!cm)
        return NULL;
    if (!cm->manager.nodes) {
        cm->manager.nodes = zcl_calloc(8, sizeof(*cm->manager.nodes),
                                       "connman_test_nodes");
        cm->manager.nodes_cap = 8;
    }
    struct net_address addr;
    test_set_ipv4(&addr, a, b, c, d, 8033);
    struct p2p_node *node = p2p_node_create(
        &cm->manager, ZCL_INVALID_SOCKET, &addr, "connman-test", inbound);
    if (!node)
        return NULL;
    node->state = state;
    node->disconnect = disconnect;
    node->starting_height = 3117074;
    node->services = NODE_NETWORK;
    cm->manager.nodes[cm->manager.num_nodes++] = node;
    return node;
}

/* Force an addrman entry (matched by its IPv4 first octet ip[12], which is
 * unique per address in the dialer-backoff test below) into a chosen
 * consecutive-failure state: `attempts` drives connman_addrman_retry_cooldown,
 * `last_try` places the entry inside or outside its cooldown window. Returns
 * true iff an entry with that octet was found. Direct field pokes are the
 * standard fixture idiom in this file (see "addrman repeated failures cool
 * down"): they set the exact ledger state a real run reaches after N failed
 * dials without needing to actually drive N dials. */
static bool test_addrman_set_fail(struct connman *cm, uint8_t first_octet,
                                  int attempts, int64_t last_try)
{
    for (int i = 0; i < cm->manager.addrman.id_count; i++) {
        struct addr_info *info = &cm->manager.addrman.entries[i];
        if (!info->used || !net_addr_is_ipv4(&info->addr.svc.addr))
            continue;
        if (info->addr.svc.addr.ip[12] == first_octet) {
            info->attempts = attempts;
            info->last_try = last_try;
            info->last_success = 0;   /* never handshook = dead-on-arrival */
            return true;
        }
    }
    return false;
}

int test_connman_addnode_fallback(void)
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
        ok = ok && cm.dht_hint_count == 1 && cm.num_addnodes == 0 &&
             connman_dht_hint_pending(&cm) &&
             !connman_connect_only_wait_needed_for_test(true, 1, 1, true) &&
             connman_connect_only_wait_needed_for_test(true, 1, 1, false);
        ok = ok && connman_outbound_rate_allowed_for_test(false, false, true) &&
             connman_outbound_rate_allowed_for_test(true, false, false) &&
             connman_outbound_rate_allowed_for_test(false, true, false) &&
             !connman_outbound_rate_allowed_for_test(false, false, false);
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
        cm.next_addnode_cursor = 0;
        struct connman_dial_candidate after_connect[2];
        memset(after_connect, 0, sizeof(after_connect));
        size_t after_n = ok ? connman_gather_dial_candidates(
                                  &cm, after_connect, 2) : 0;
        ok = ok && after_n == 1 &&
             after_connect[0].addr.svc.port == 20024;
        cm.next_addnode_cursor = 0;
        struct addr_info remaining;
        enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
        memset(&remaining, 0, sizeof(remaining));
        ok = ok && connman_pick_next_outbound_target(
                       &cm, &cm.next_addnode_cursor, &remaining, &source,
                       NULL) &&
             source == CONNMAN_TARGET_ADDNODE &&
             remaining.addr.svc.port == 20024;
        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

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
        ok = ok && n == 1;
        ok = ok && !(candidate.source == CONNMAN_TARGET_ZCL23_DB &&
                     candidate.addr.svc.addr.ip[12] == 140);

        /* Whichever other known endpoint was selected now owns an addrman
         * attempt. Put it into the persisted six-hour tier and prove the
         * next preferred turn falls through to a healthy general peer. */
        int64_t now = (int64_t)platform_time_wall_time_t();
        ok = ok && test_addrman_set_fail(&cm, 205, 10, now);
        atomic_store(&cm.zcl23_preference_round, 0);
        memset(&candidate, 0, sizeof(candidate));
        n = ok ? connman_gather_dial_candidates(&cm, &candidate, 1) : 0;
        ok = ok && n == 1 &&
             candidate.source == CONNMAN_TARGET_ADDRMAN &&
             candidate.addr.svc.addr.ip[12] == 81;
        ok = ok && atomic_load(&cm.zcl23_backoff_skips) >= 1;
        ok = ok && atomic_load(&cm.zcl23_policy_skips) >= 1;

        /* Three days of a peer that accepts TCP and immediately closes must
         * remain a small bounded number of scheduler assignments, not the
         * tens-of-thousands/day trajectory observed on node4. */
        int simulated_attempts = 0;
        int64_t next_attempt = 0;
        for (int64_t second = 0; second < 3 * 86400; second++) {
            if (second < next_attempt)
                continue;
            simulated_attempts++;
            next_attempt = second +
                connman_addrman_retry_cooldown_for_test(simulated_attempts);
        }
        ok = ok && simulated_attempts <= 20;

        /* After the durable cooldown expires, the same endpoint is eligible
         * through the shared scheduler again and is charged only once. */
        ok = ok && test_addrman_set_fail(&cm, 205, 10, now - 21601);
        atomic_store(&cm.zcl23_preference_round, 0);
        memset(&candidate, 0, sizeof(candidate));
        n = ok ? connman_gather_dial_candidates(&cm, &candidate, 1) : 0;
        ok = ok && n == 1 &&
             candidate.source == CONNMAN_TARGET_ZCL23_DB &&
             candidate.addr.svc.addr.ip[12] == 205;
        struct addr_info charged;
        memset(&charged, 0, sizeof(charged));
        ok = ok && addrman_find_info(&cm.manager.addrman,
                                     &candidate.addr.svc, &charged) &&
             charged.attempts == 11;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

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
            ok = ok && source == CONNMAN_TARGET_ADDNODE;
            ok = ok && addnode_index == (size_t)i;
            ok = ok && net_addr_eq(&pick.addr.svc.addr, &want.svc.addr);
            ok = ok && pick.addr.svc.port == want.svc.port;

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
        ok = ok && cm.num_addnodes == 2;
        ok = ok && net_addr_eq(&cm.addnodes[0].svc.addr, &a.svc.addr);
        ok = ok && cm.addnodes[0].svc.port == a.svc.port;
        ok = ok && net_addr_eq(&cm.addnodes[1].svc.addr, &c.svc.addr);
        ok = ok && cm.addnodes[1].svc.port == c.svc.port;
        ok = ok && cm.addnode_last_attempt[1] == 30;
        ok = ok && cm.addnode_backoff_sec[1] == 60;
        ok = ok && cm.addnode_tcp_failures[1] == 3;
        ok = ok && cm.addnode_protocol_failures[1] == 6;
        ok = ok && cm.next_addnode_cursor == 1;
        ok = ok && !connman_remove_addnode(&cm, &missing);

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

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
        ok = ok && health.outbound_total == 4;
        ok = ok && health.inbound_total == 1;
        ok = ok && health.healthy == 3;
        ok = ok && health.inbound_healthy == 1;
        ok = ok && health.connecting == 1;
        ok = ok && health.handshake_incomplete == 1;
        ok = ok && health.inbound_handshake_incomplete == 0;
        ok = ok && health.ipv4_group_count == 3;
        ok = ok && health.ipv4_max_group_size == 2;
        ok = ok && connman_outbound_healthy_count(&cm) == 3;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

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
            ok = ok && pick.addr.svc.addr.ip[12] == 47;
            ok = ok && pick.addr.svc.addr.ip[13] == 88;

            bool attempt_recorded = false;
            for (int i = 0; i < cm.manager.addrman.id_count; i++) {
                struct addr_info *info = &cm.manager.addrman.entries[i];
                if (!info->used)
                    continue;
                if (info->addr.svc.addr.ip[12] == 47 &&
                    info->addr.svc.addr.ip[13] == 88) {
                    attempt_recorded =
                        info->attempts == 1 && info->last_try > 0;
                    break;
                }
            }
            ok = ok && attempt_recorded;

            memset(&pick, 0, sizeof(pick));
            source = CONNMAN_TARGET_NONE;
            ok = ok && !connman_pick_next_outbound_target(
                &cm, &cm.next_addnode_cursor, &pick, &source, NULL);
        }

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

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

    printf("connman_addnode_fallback: pre-handshake addnode disconnect "
           "backs off as protocol failure... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 51, 178, 179, 75, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
            struct p2p_node *node = add_test_peer(
                &cm, 51, 178, 179, 75, PEER_VERSION_SENT, false, false);
            ok = ok && node != NULL;
            if (node)
                connman_note_addnode_prehandshake_disconnect(
                    &cm, node, "unit-test");
        }

        ok = ok && cm.addnode_protocol_failures[0] == 1;
        ok = ok && cm.addnode_tcp_failures[0] == 0;
        /* First PROTOCOL failure now backs off via the gentle ramp
         * (step 1 = 60s), NOT an instant 900s lockout — a transient drop
         * is re-dialed in time to fill the outbound floor. */
        ok = ok && cm.addnode_backoff_sec[0] == 60;
        ok = ok && cm.addnode_last_attempt[0] > 0;

        /* A second consecutive prehandshake (PROTOCOL) failure ramps but is
         * still well below the 1800s ceiling — proves it is no longer an
         * instant lockout. */
        struct p2p_node *node2 = add_test_peer(
            &cm, 51, 178, 179, 75, PEER_VERSION_SENT, false, false);
        if (node2)
            connman_note_addnode_prehandshake_disconnect(
                &cm, node2, "unit-test-2");
        ok = ok && cm.addnode_protocol_failures[0] == 2;
        ok = ok && cm.addnode_backoff_sec[0] == 120;   /* step 2 */
        ok = ok && cm.addnode_backoff_sec[0] < 1800;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("connman_addnode_fallback: protocol failures back off longer "
           "than TCP failures... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 203, 0, 113, 21, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
            test_set_ipv4(&addr, 203, 0, 113, 22, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
        }

        connman_record_addnode_failure(&cm, 0,
                                       CONNMAN_ADDNODE_FAILURE_TCP);
        connman_record_addnode_failure(&cm, 1,
                                       CONNMAN_ADDNODE_FAILURE_PROTOCOL);
        /* After ONE failure each: TCP=20 (ramp step 0), PROTOCOL=60 (ramp
         * step 1, one ahead). PROTOCOL still backs off longer than TCP —
         * the invariant this test guards — but neither is an instant
         * 900s/120s lockout. */
        ok = ok && cm.addnode_backoff_sec[0] == 20;
        ok = ok && cm.addnode_backoff_sec[1] == 60;
        ok = ok && cm.addnode_backoff_sec[1] > cm.addnode_backoff_sec[0];

        /* A genuinely dead host still reaches the 1800s ceiling: ramp a TCP
         * addnode to 7 consecutive failures (step 6 = the last ramp entry). */
        for (int f = 0; f < 6; f++)
            connman_record_addnode_failure(&cm, 0,
                                           CONNMAN_ADDNODE_FAILURE_TCP);
        ok = ok && cm.addnode_tcp_failures[0] == 7;
        ok = ok && cm.addnode_backoff_sec[0] == 1800;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("connman_addnode_fallback: addrman repeated failures cool down... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct net_addr src;
        memset(&sigs, 0, sizeof(sigs));
        net_addr_init(&src);
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 66, 70, 182, 44, 8033);
            ok = ok && addrman_add(&cm.manager.addrman, &addr, &src, 0);
            test_set_ipv4(&addr, 81, 214, 132, 20, 8033);
            ok = ok && addrman_add(&cm.manager.addrman, &addr, &src, 0);
        }

        if (ok) {
            int64_t now = (int64_t)platform_time_wall_time_t();
            for (int i = 0; i < cm.manager.addrman.id_count; i++) {
                struct addr_info *info = &cm.manager.addrman.entries[i];
                if (!info->used)
                    continue;
                if (info->addr.svc.addr.ip[12] == 66 &&
                    info->addr.svc.addr.ip[13] == 70) {
                    info->attempts = 3;
                    info->last_try = now - 120;
                }
            }
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
            ok = ok && pick.addr.svc.addr.ip[12] == 81;
            ok = ok && pick.addr.svc.addr.ip[13] == 214;
        }

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("connman_addnode_fallback: failure-aware backoff gathers DISTINCT "
           "live candidates and skips recently-dead ones... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct net_addr src;
        memset(&sigs, 0, sizeof(sigs));
        net_addr_init(&src);
        bool ok = connman_init(&cm, params, &sigs);

        int64_t now = (int64_t)platform_time_wall_time_t();

        /* Four addrman addresses, each in a DISTINCT /16 so the /16 diversity
         * cap never rejects them: two "dead-on-arrival" (accumulated failures,
         * last try just now → inside their backoff window) and two "live"
         * (never failed, immediately dialable). */
        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 45, 33, 1, 1, 8033);   /* dead A */
            addr.nTime = (uint32_t)now;
            ok = ok && addrman_add(&cm.manager.addrman, &addr, &src, 0);
            test_set_ipv4(&addr, 51, 178, 1, 1, 8033);  /* dead B */
            addr.nTime = (uint32_t)now;
            ok = ok && addrman_add(&cm.manager.addrman, &addr, &src, 0);
            test_set_ipv4(&addr, 47, 88, 1, 1, 8033);   /* live C */
            addr.nTime = (uint32_t)now;
            ok = ok && addrman_add(&cm.manager.addrman, &addr, &src, 0);
            test_set_ipv4(&addr, 66, 70, 1, 1, 8033);   /* live D */
            addr.nTime = (uint32_t)now;
            ok = ok && addrman_add(&cm.manager.addrman, &addr, &src, 0);
        }

        /* A: 5 consecutive failures → 3600 s cooldown; B: 2 → 300 s. Both
         * tried "just now", so both are firmly inside their backoff windows. */
        ok = ok && test_addrman_set_fail(&cm, 45, 5, now);
        ok = ok && test_addrman_set_fail(&cm, 51, 2, now);

        /* One gather asks for a full 4-candidate batch. Only the two LIVE
         * addresses may come back — the dead ones are in failure-aware
         * backoff — and the two returned candidates must be DISTINCT. */
        struct connman_dial_candidate batch[8];
        size_t n = 0;
        if (ok) {
            n = connman_gather_dial_candidates(&cm, batch, 4);
            ok = ok && n == 2;
        }
        bool saw_c = false, saw_d = false, saw_dead = false;
        for (size_t i = 0; ok && i < n; i++) {
            uint8_t oct = batch[i].addr.svc.addr.ip[12];
            if (oct == 47) saw_c = true;
            else if (oct == 66) saw_d = true;
            else saw_dead = true;   /* 45 or 51 must never appear */
        }
        ok = ok && saw_c && saw_d && !saw_dead;
        /* Distinct: two different services, never the same slot twice. */
        if (ok && n == 2)
            ok = ok && !net_service_eq(&batch[0].addr.svc, &batch[1].addr.svc);

        /* REFILL: B's backoff expires (last try older than its 300 s window).
         * A stays dead (3600 s window intact) and C/D were charged one attempt
         * each by the gather above (60 s cooldown, tried just now), so the only
         * candidate that may refill the floor now is B. */
        ok = ok && test_addrman_set_fail(&cm, 51, 2, now - 400);
        if (ok) {
            size_t n2 = connman_gather_dial_candidates(&cm, batch, 4);
            ok = ok && n2 == 1;
            ok = ok && batch[0].addr.svc.addr.ip[12] == 51;
        }

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* S6 (design item #S6, `sovereign-service-roadmap.md`, removed from the
     * tree — recover with `git log --follow -- docs/work/archive/sovereign-service-roadmap.md`): bootstrap
     * fallback-of-last-resort. With DNS seeds AND the operator addrman
     * file BOTH unavailable, the hardcoded chainparams onion-seed tier
     * (connman.c:281-283 run_onion_seed_pass, addrman.c addrman_add) is
     * the only remaining peer source and must still be reachable/bounded.
     *
     * The embedded Tor stub in this test binary never reports
     * tor_integration_is_ready()==true, so the live onion-directory HTTP
     * fetch (try_onion_seed_fetch -> tor_integration_fetch_onion_blocking)
     * cannot be driven end-to-end without a real bootstrapped Tor circuit
     * (see test_onion_bootstrap.c). This test instead deterministically
     * proves the two halves that make the tier a genuine last resort:
     * (1) with a chainparams copy whose DNS (nSeeds) and hardcoded IP
     *     fixed-seed (nFixedSeeds) tiers are both zeroed, and no
     *     peers.dat on disk (operator addrman file "unavailable"),
     *     connman_kick_seed_discovery + connman_load_addrman leave the
     *     node with zero outbound candidates — proving those tiers are
     *     truly exhausted, not silently still supplying peers;
     * (2) the surviving onionSeeds[] tier is non-empty, and once it
     *     contributes addrman entries (the exact effect
     *     try_onion_seed_fetch has on a successful /directory.json
     *     fetch), a single bounded connman_pick_next_outbound_target
     *     call yields a first peer from CONNMAN_TARGET_ADDRMAN — i.e.
     *     the fallback-of-last-resort tier alone is sufficient. */
    printf("connman_addnode_fallback: onion-seed tier is fallback of last "
           "resort when DNS + addrman file are both unavailable... ");
    {
        chain_params_select(CHAIN_MAIN);
        struct chain_params no_dns_no_fixed = *chain_params_get();
        no_dns_no_fixed.nSeeds = 0;
        no_dns_no_fixed.nFixedSeeds = 0;
        bool ok = no_dns_no_fixed.nOnionSeeds > 0;

        char tmpdir[] = "/tmp/zcl_connman_lastresort_XXXXXX";
        ok = ok && mkdtemp(tmpdir) != NULL;

        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        ok = ok && connman_init(&cm, &no_dns_no_fixed, &sigs);
        if (ok)
            cm.datadir = tmpdir;

        /* DNS (0 seeds) + hardcoded fixed seeds (0) contribute nothing;
         * the operator addrman file does not exist in tmpdir either. */
        if (ok)
            connman_kick_seed_discovery(&cm);
        if (ok)
            connman_load_addrman(&cm);

        struct addr_info pick;
        enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
        memset(&pick, 0, sizeof(pick));
        bool exhausted_before_onion_tier =
            ok && !connman_pick_next_outbound_target(&cm,
                                                     &cm.next_addnode_cursor,
                                                     &pick, &source, NULL);
        ok = ok && exhausted_before_onion_tier;

        /* Simulate the onion-seed tier's real effect: a successful
         * /directory.json fetch from a hardcoded .onion seed adds the
         * discovered clearnet peer via addrman_add (connman.c:232),
         * bounded by nOnionSeeds attempts (the same bound
         * run_onion_seed_pass iterates under, connman.c:282-283). */
        if (ok) {
            struct net_addr src;
            net_addr_init(&src);
            for (size_t i = 0; i < no_dns_no_fixed.nOnionSeeds; i++) {
                struct net_address addr;
                test_set_ipv4(&addr, 45, 33, (uint8_t)(i + 1), 1, 8033);
                ok = ok && addrman_add(&cm.manager.addrman, &addr, &src, 0);
            }
        }

        if (ok) {
            memset(&pick, 0, sizeof(pick));
            source = CONNMAN_TARGET_NONE;
            ok = connman_pick_next_outbound_target(&cm,
                                                    &cm.next_addnode_cursor,
                                                    &pick, &source, NULL);
            ok = ok && source == CONNMAN_TARGET_ADDRMAN;
        }

        connman_free(&cm);
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
        (void)system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("connman_addnode_fallback: IPv6 /32 and three-slot onion "
           "outbound diversity caps enforced... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            cm.manager.nodes = zcl_calloc(8, sizeof(*cm.manager.nodes),
                                          "connman_test_nodes_diversity");
            cm.manager.nodes_cap = 8;
        }

        /* Two already-connected outbound peers in the SAME IPv6 /32
         * group (2600:0100::/32 — a real ARIN-allocated GUA range, NOT
         * the RFC 3849 documentation prefix 2001:0db8::/32, which
         * net_addr_is_valid() deliberately rejects as non-routable and
         * would make every addrman_add() below silently fail) saturate
         * MAX_OUTBOUND_IPV6_GROUP32 (2). Three already-connected outbound
         * onion peers saturate the flat MAX_OUTBOUND_ONION (3) bucket —
         * enough for all remote edges of a four-node mesh while still
         * reserving five of eight outbound slots. Onion has no sub-grouping;
         * see
         * connman_outbound_diversity_capped()'s doc comment. */
        if (ok) {
            const unsigned char ipv6_prefix[4] = {0x26, 0x00, 0x01, 0x00};
            for (int i = 0; i < 2 && ok; i++) {
                struct net_address a;
                net_address_init(&a);
                memcpy(a.svc.addr.ip, ipv6_prefix, 4);
                a.svc.addr.ip[15] = (unsigned char)(i + 1);
                a.svc.port = 8033;
                struct p2p_node *n = p2p_node_create(
                    &cm.manager, ZCL_INVALID_SOCKET, &a, "ipv6-peer", false);
                ok = ok && n != NULL;
                if (n) cm.manager.nodes[cm.manager.num_nodes++] = n;
            }
            for (int i = 0; i < 3 && ok; i++) {
                struct net_address a;
                net_address_init(&a);
                a.svc.addr.has_torv3 = true;
                memset(a.svc.addr.torv3, (int)(0xA0 + i), TORV3_ADDR_SIZE);
                a.svc.port = 8033;
                struct p2p_node *n = p2p_node_create(
                    &cm.manager, ZCL_INVALID_SOCKET, &a, "onion-peer", false);
                ok = ok && n != NULL;
                if (n) cm.manager.nodes[cm.manager.num_nodes++] = n;
            }
        }

        struct net_addr src;
        net_addr_init(&src);

        /* An addrman candidate in the SAME (already-capped) IPv6 group
         * must never be picked. */
        if (ok) {
            struct net_address cand;
            net_address_init(&cand);
            cand.svc.addr.ip[0] = 0x26; cand.svc.addr.ip[1] = 0x00;
            cand.svc.addr.ip[2] = 0x01; cand.svc.addr.ip[3] = 0x00;
            cand.svc.addr.ip[15] = 3;
            cand.svc.port = 8033;
            ok = ok && addrman_add(&cm.manager.addrman, &cand, &src, 0);
        }
        if (ok) {
            struct addr_info pick;
            enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
            memset(&pick, 0, sizeof(pick));
            bool got = connman_pick_next_outbound_target(
                &cm, &cm.next_addnode_cursor, &pick, &source, NULL);
            ok = ok && !got; /* capped IPv6 group -> no usable candidate */
        }

        /* An addrman candidate in a DIFFERENT (uncapped) IPv6 group IS
         * pickable — proves the rejection above was the cap, not some
         * unrelated addrman/connman fixture bug. */
        if (ok) {
            struct net_address cand2;
            net_address_init(&cand2);
            cand2.svc.addr.ip[0] = 0x26; cand2.svc.addr.ip[1] = 0x00;
            cand2.svc.addr.ip[2] = 0x02; cand2.svc.addr.ip[3] = 0x00; /* different /32 */
            cand2.svc.addr.ip[15] = 9;
            cand2.svc.port = 8033;
            ok = ok && addrman_add(&cm.manager.addrman, &cand2, &src, 0);
        }
        if (ok) {
            struct addr_info pick;
            enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
            memset(&pick, 0, sizeof(pick));
            bool got = connman_pick_next_outbound_target(
                &cm, &cm.next_addnode_cursor, &pick, &source, NULL);
            ok = ok && got && source == CONNMAN_TARGET_ADDRMAN &&
                net_addr_is_ipv6(&pick.addr.svc.addr);
        }

        /* An addrman candidate that is onion (already-capped flat
         * bucket) must never be picked either. */
        if (ok) {
            struct net_address cand3;
            net_address_init(&cand3);
            cand3.svc.addr.has_torv3 = true;
            memset(cand3.svc.addr.torv3, 0xCC, TORV3_ADDR_SIZE);
            cand3.svc.port = 8033;
            ok = ok && addrman_add(&cm.manager.addrman, &cand3, &src, 0);
        }
        if (ok) {
            struct addr_info pick;
            enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
            memset(&pick, 0, sizeof(pick));
            bool got = connman_pick_next_outbound_target(
                &cm, &cm.next_addnode_cursor, &pick, &source, NULL);
            /* Only the still-pickable cand2 (a different IPv6 group) or
             * nothing should ever come back — never the capped onion
             * candidate. addrman_select() is random, so we can't assert
             * "nothing" outright if cand2 already got consumed above;
             * assert the STRONGER invariant instead: whatever (if
             * anything) comes back is never onion. */
            ok = ok && (!got || !net_addr_is_tor(&pick.addr.svc.addr));
        }

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* Onion dial routing, no live Tor: an onion addnode is stored like any
     * other, but the connect attempt routes to the onion stream bridge,
     * which is queued on the addnode list and NOT opened via blocking
     * connect_node — onion circuits belong on the dialer thread so RPC /
     * native peers.add stay inside the 250ms FAST budget. No clearnet
     * fallback, no circuit timeout on this call, and no node is registered
     * until the dialer actually connects. */
    printf("connman_addnode_fallback: onion addnode queues without a "
           "blocking connect_node... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            uint8_t pub[32];
            for (int i = 0; i < 32; i++)
                pub[i] = (uint8_t)(0x30 + i);
            char host[ONION_V3_ADDRESS_LEN + 1];
            ok = onion_v3_address_from_pubkey(pub, host);

            struct net_address a;
            net_address_init(&a);
            ok = ok && net_addr_from_onion(host, &a.svc.addr);
            a.svc.port = 8033;

            connman_open_connection(&cm, &a);
            ok = ok && cm.num_addnodes == 1 && cm.manager.num_nodes == 0;
        }

        if (ok) connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* An over-cap max_connections with room left in the reactor (listen
     * sockets alone don't exhaust it) must be CLAMPED to whatever room
     * remains, not refused — a configured max_connections is a ceiling
     * request, not a start-or-die floor. Exercised via the pure admission
     * helper so this stays a fast unit test (no real reactor threads). */
    printf("connman_addnode_fallback: reactor admission clamps "
           "over-cap max_connections when room remains... ");
    {
        bool impossible = true;
        int admitted = connman_reactor_admit_for_test(
            /*listen_sockets=*/0, /*requested_max=*/REACTOR_MAX_FDS + 10,
            &impossible);
        bool ok = !impossible && admitted == REACTOR_MAX_FDS;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* A config that fits within REACTOR_MAX_FDS must pass through
     * unchanged (no clamp, not impossible). */
    printf("connman_addnode_fallback: reactor admission passes through "
           "in-cap config unchanged... ");
    {
        bool impossible = true;
        int admitted = connman_reactor_admit_for_test(
            /*listen_sockets=*/2, /*requested_max=*/125, &impossible);
        bool ok = !impossible && admitted == 125;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* Listen sockets ALONE leaving no room for any peer connection is the
     * one genuinely impossible config: it must still refuse via
     * connman_start(), naming the PERMANENT blocker, never silently
     * clamping to zero/negative connections. */
    printf("connman_addnode_fallback: reactor bound-check refuses "
           "when listen sockets alone exhaust the reactor... ");
    {
        bool impossible = false;
        int admitted = connman_reactor_admit_for_test(
            /*listen_sockets=*/(size_t)REACTOR_MAX_FDS, /*requested_max=*/1,
            &impossible);
        bool ok = impossible;
        (void)admitted;   /* unused on the impossible path */

        blocker_reset_for_testing();
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        ok = ok && connman_init(&cm, params, &sigs);

        /* num_listen_sockets is only claimed synthetically here (no real
         * sockets were bound into cm.manager.listen_sockets, whose backing
         * array is sized far below REACTOR_MAX_FDS) — reset it to 0 before
         * connman_free() so its listen-socket teardown loop doesn't walk
         * past the real (tiny) allocation. */
        cm.manager.num_listen_sockets = REACTOR_MAX_FDS;
        cm.manager.max_connections = 1;

        bool started = connman_start(&cm);
        ok = ok && !started;
        ok = ok && blocker_exists("connman_reactor_overflow");
        ok = ok && blocker_class_for("connman_reactor_overflow") ==
                       BLOCKER_PERMANENT;
        /* Never partially started: no P2P thread should be live to join. */
        ok = ok && !cm.started;

        cm.manager.num_listen_sockets = 0;
        connman_free(&cm);
        blocker_reset_for_testing();
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* Sane configuration (default max_connections, no listen sockets) must
     * NOT trip the reactor bound-check — proves the admission math doesn't
     * false-positive on the ordinary boot path. */
    printf("connman_addnode_fallback: reactor bound-check passes "
           "default config... ");
    {
        blocker_reset_for_testing();
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        ok = ok && !blocker_exists("connman_reactor_overflow");
        struct connman_reactor_stats rs;
        connman_get_reactor_stats(&rs);
        ok = ok && rs.reactor_max_fds == REACTOR_MAX_FDS;

        connman_free(&cm);
        blocker_reset_for_testing();
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── addnode self-healing: RETIRE + HARVEST (net/connman.h) ─────────── */

    printf("connman_addnode_fallback: addnode retirement fires past BOTH "
           "thresholds and excludes it from dial rotation... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 198, 51, 100, 200, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
        }

        int64_t now = (int64_t)platform_time_wall_time_t();
        if (ok) {
            cm.addnode_tcp_failures[0] = ZCL_ADDNODE_RETIRE_MIN_TCP_FAILURES;
            cm.addnode_first_failure_ts[0] =
                now - ZCL_ADDNODE_RETIRE_MIN_WINDOW_SECS - 10;
        }

        /* Healthy outbound AT the floor: retirement is allowed to fire. */
        if (ok)
            connman_retire_dead_addnodes(&cm, (size_t)ZCL_PEER_FLOOR_HEALTHY);

        ok = ok && cm.addnode_retired[0];
        ok = ok && cm.addnode_retired_at[0] > 0;
        ok = ok && cm.addnode_retirements_total == 1;

        /* Idempotent: a second pass over an already-retired entry does not
         * double-count the lifetime counter. */
        if (ok)
            connman_retire_dead_addnodes(&cm, (size_t)ZCL_PEER_FLOOR_HEALTHY);
        ok = ok && cm.addnode_retirements_total == 1;

        /* Excluded from dial rotation: the only addnode present is retired,
         * addrman is empty, so no target is pickable. */
        if (ok) {
            struct addr_info pick;
            enum connman_outbound_target_source source = CONNMAN_TARGET_NONE;
            memset(&pick, 0, sizeof(pick));
            bool got = connman_pick_next_outbound_target(
                &cm, &cm.next_addnode_cursor, &pick, &source, NULL);
            ok = ok && !got;
        }

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("connman_addnode_fallback: addnode retirement needs BOTH the "
           "failure-count AND window thresholds, neither alone... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 198, 51, 100, 201, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
            test_set_ipv4(&addr, 198, 51, 100, 202, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
        }

        int64_t now = (int64_t)platform_time_wall_time_t();
        if (ok) {
            /* addnode[0]: window satisfied, count one short of the floor. */
            cm.addnode_tcp_failures[0] =
                ZCL_ADDNODE_RETIRE_MIN_TCP_FAILURES - 1;
            cm.addnode_first_failure_ts[0] =
                now - ZCL_ADDNODE_RETIRE_MIN_WINDOW_SECS - 10;
            /* addnode[1]: count satisfied, streak just started (window not
             * yet satisfied). */
            cm.addnode_tcp_failures[1] = ZCL_ADDNODE_RETIRE_MIN_TCP_FAILURES;
            cm.addnode_first_failure_ts[1] = now;
        }

        if (ok)
            connman_retire_dead_addnodes(&cm, (size_t)ZCL_PEER_FLOOR_HEALTHY);

        ok = ok && !cm.addnode_retired[0];
        ok = ok && !cm.addnode_retired[1];
        ok = ok && cm.addnode_retirements_total == 0;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("connman_addnode_fallback: addnode retirement is suppressed "
           "below the healthy-outbound floor... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 198, 51, 100, 203, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
        }

        int64_t now = (int64_t)platform_time_wall_time_t();
        if (ok) {
            cm.addnode_tcp_failures[0] = ZCL_ADDNODE_RETIRE_MIN_TCP_FAILURES;
            cm.addnode_first_failure_ts[0] =
                now - ZCL_ADDNODE_RETIRE_MIN_WINDOW_SECS - 10;
        }

        /* Below the floor (ZCL_PEER_FLOOR_HEALTHY - 1 healthy outbound):
         * this addnode is a dial-of-last-resort and must NOT be retired
         * no matter how dead it looks. */
        if (ok)
            connman_retire_dead_addnodes(
                &cm, (size_t)ZCL_PEER_FLOOR_HEALTHY - 1);
        ok = ok && !cm.addnode_retired[0];
        ok = ok && cm.addnode_retirements_total == 0;

        /* Once the floor is met, the SAME state now retires — proves the
         * suppression above was the floor guard, not some other bug. */
        if (ok)
            connman_retire_dead_addnodes(&cm, (size_t)ZCL_PEER_FLOOR_HEALTHY);
        ok = ok && cm.addnode_retired[0];

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("connman_addnode_fallback: retired addnode revives on one "
           "successful dial... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        if (ok) {
            struct net_address addr;
            test_set_ipv4(&addr, 198, 51, 100, 204, 8033);
            cm.addnodes[cm.num_addnodes++] = addr;
        }

        int64_t now = (int64_t)platform_time_wall_time_t();
        if (ok) {
            cm.addnode_tcp_failures[0] = ZCL_ADDNODE_RETIRE_MIN_TCP_FAILURES;
            cm.addnode_first_failure_ts[0] =
                now - ZCL_ADDNODE_RETIRE_MIN_WINDOW_SECS - 10;
            connman_retire_dead_addnodes(&cm, (size_t)ZCL_PEER_FLOOR_HEALTHY);
        }
        ok = ok && cm.addnode_retired[0];

        if (ok)
            connman_record_addnode_attempt(&cm, 0, true);

        ok = ok && !cm.addnode_retired[0];
        ok = ok && cm.addnode_tcp_failures[0] == 0;
        ok = ok && cm.addnode_first_failure_ts[0] == 0;
        ok = ok && cm.addnode_backoff_sec[0] == 0;
        /* The lifetime counter is NOT decremented by a revival — it counts
         * retirement events, not "currently retired". */
        ok = ok && cm.addnode_retirements_total == 1;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("connman_addnode_fallback: retired addnode revives on operator "
           "addnode re-add... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct net_address addr;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        /* Loopback, unused high port: connect_node's real connect() fails
         * (refused) near-instantly instead of hanging — the revival logic
         * under test runs before that connect attempt either way. */
        test_set_ipv4(&addr, 127, 0, 0, 1, 18921);
        if (ok)
            cm.addnodes[cm.num_addnodes++] = addr;

        int64_t now = (int64_t)platform_time_wall_time_t();
        if (ok) {
            cm.addnode_tcp_failures[0] = ZCL_ADDNODE_RETIRE_MIN_TCP_FAILURES;
            cm.addnode_first_failure_ts[0] =
                now - ZCL_ADDNODE_RETIRE_MIN_WINDOW_SECS - 10;
            cm.addnode_backoff_sec[0] = 1800;
            connman_retire_dead_addnodes(&cm, (size_t)ZCL_PEER_FLOOR_HEALTHY);
        }
        ok = ok && cm.addnode_retired[0];

        if (ok)
            connman_open_connection(&cm, &addr);

        ok = ok && !cm.addnode_retired[0];
        ok = ok && cm.addnode_backoff_sec[0] == 0;
        ok = ok && cm.addnode_tcp_failures[0] == 0;
        /* Re-adding an address already on the list must never duplicate
         * the entry. */
        ok = ok && cm.num_addnodes == 1;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("connman_addnode_fallback: census harvest adds proven-reachable "
           "candidates to addrman as discovery entries, not pinned "
           "addnodes... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        char tmpdir[] = "/tmp/zcl_connman_harvest_XXXXXX";
        ok = ok && mkdtemp(tmpdir) != NULL;
        if (ok)
            cm.datadir = tmpdir;

        ok = ok && census_read_test_create_schema(tmpdir);

        int64_t now = (int64_t)platform_time_wall_time_t();
        if (ok) {
            /* Two good candidates: reachable (dial_success_count>0) and a
             * recent last_success — exactly what census_read.c's
             * ev_node_census_observed fold produces for a peer we've
             * actually dialed successfully (peers_projection.c:463+). */
            struct census_node good1;
            memset(&good1, 0, sizeof(good1));
            snprintf(good1.ip, sizeof(good1.ip), "45.33.10.1");
            good1.port = 8033;
            good1.services = 1;
            good1.reported_height = 3200000;
            good1.first_seen = now - 100000;
            good1.last_seen = now - 30;
            good1.last_success = now - 30;
            good1.dial_success_count = 4;
            good1.dial_fail_count = 1;
            ok = ok && census_read_test_insert_node(tmpdir, &good1);

            struct census_node good2 = good1;
            snprintf(good2.ip, sizeof(good2.ip), "45.33.10.2");
            ok = ok && census_read_test_insert_node(tmpdir, &good2);

            /* Never-dialed: seen only via gossip, dial_success_count==0 —
             * must NOT be harvested (no proof it's actually reachable). */
            struct census_node never_dialed = good1;
            snprintf(never_dialed.ip, sizeof(never_dialed.ip), "45.33.10.3");
            never_dialed.dial_success_count = 0;
            never_dialed.last_success = 0;
            ok = ok && census_read_test_insert_node(tmpdir, &never_dialed);

            /* Stale: was reachable once, but its last success is far older
             * than ZCL_ADDNODE_HARVEST_RECENT_SUCCESS_SECS — must NOT be
             * harvested (no longer proven-live). */
            struct census_node stale = good1;
            snprintf(stale.ip, sizeof(stale.ip), "45.33.10.4");
            stale.last_seen = now - 30;   /* passes the coarse list filter */
            stale.last_success =
                now - ZCL_ADDNODE_HARVEST_RECENT_SUCCESS_SECS - 3600;
            ok = ok && census_read_test_insert_node(tmpdir, &stale);
        }

        size_t harvested = 0;
        if (ok)
            harvested = connman_harvest_census_candidates(&cm, -1);
        ok = ok && harvested == 2;

        /* Discovery candidates land in addrman, NEVER in the pinned addnode
         * list — that is the whole point of HARVEST vs a raw addnode add. */
        ok = ok && cm.num_addnodes == 0;

        bool found_good1 = false, found_good2 = false, found_bad = false;
        if (ok) {
            zcl_mutex_lock(&cm.manager.addrman.cs);
            for (int i = 0; i < cm.manager.addrman.id_count; i++) {
                struct addr_info *info = &cm.manager.addrman.entries[i];
                if (!info->used || !net_addr_is_ipv4(&info->addr.svc.addr))
                    continue;
                const uint8_t *ip = info->addr.svc.addr.ip;
                if (ip[12] == 45 && ip[13] == 33 && ip[14] == 10) {
                    if (ip[15] == 1) found_good1 = true;
                    else if (ip[15] == 2) found_good2 = true;
                    else if (ip[15] == 3 || ip[15] == 4) found_bad = true;
                }
            }
            zcl_mutex_unlock(&cm.manager.addrman.cs);
        }
        ok = ok && found_good1 && found_good2 && !found_bad;

        connman_free(&cm);
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
        (void)system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("connman seed discovery: hardcoded fixed seeds load into addrman, "
           "onion bootstrap is a safe no-op without Tor... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        /* NULL-safety: neither entry point may crash on an unwired call. */
        connman_kick_seed_discovery(NULL);
        connman_kick_onion_seeds(NULL);

        ok = ok && addrman_size(&cm.manager.addrman) == 0;

        /* connman_kick_seed_discovery re-adds the compiled hardcoded fixed
         * seeds (in-memory only, no I/O) and re-resolves DNS seeds (a no-op
         * on mainnet today: nSeeds == 0 — see chainparams.c's DNS-seeders
         * comment). This is the fresh-node "hardcoded seed set" path a
         * genuinely offline/DNS-less node falls back to. (nFixedSeeds
         * double-books each hardcoded IP under two ports — see chainparams.c
         * — and addrman's address index keys on IP alone, so the landed
         * entry count is <= nFixedSeeds, not equal to it.) */
        connman_kick_seed_discovery(&cm);
        size_t after_fixed = addrman_size(&cm.manager.addrman);
        ok = ok && params->nFixedSeeds > 0;
        ok = ok && after_fixed > 0 && after_fixed <= (size_t)params->nFixedSeeds;

        /* connman_kick_onion_seeds is the operator/peer-of-last-resort
         * remedy for the /directory.json onion-directory bootstrap
         * (app/conditions/src/peer_floor_violated.c). Without Tor
         * bootstrapped (the default state here) it must be a safe,
         * addrman-preserving no-op — never a crash, never a partial write. */
        ok = ok && !tor_integration_is_ready();
        connman_kick_onion_seeds(&cm);
        ok = ok && addrman_size(&cm.manager.addrman) == after_fixed;

        connman_free(&cm);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* connman_relay_block announces a new tip to handshaked peers only, and
     * is idempotent per peer. This is the miner/submitblock announce seam:
     * a locally-accepted tip never travels the P2P receive-relay path, so
     * connman_relay_block is what makes an already-connected follower hear
     * about it. */
    printf("connman_addnode_fallback: relay_block -> handshaked peers only... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        /* Three peers: one fully handshaked (must receive the announce), one
         * still mid-handshake (must NOT), one handshaked but disconnecting
         * (must NOT). */
        struct p2p_node *ready =
            add_test_peer(&cm, 203, 0, 113, 1, PEER_HANDSHAKE_COMPLETE,
                          false, false);
        struct p2p_node *early =
            add_test_peer(&cm, 203, 0, 113, 2, PEER_CONNECTED, false, false);
        struct p2p_node *leaving =
            add_test_peer(&cm, 203, 0, 113, 3, PEER_HANDSHAKE_COMPLETE,
                          false, true);
        ok = ok && ready && early && leaving;

        struct uint256 blk;
        uint256_set_null(&blk);
        blk.data[0] = 0xab;
        blk.data[31] = 0xcd;

        if (ok) {
            connman_relay_block(&cm, &blk);
            /* Only the fully-handshaked, non-disconnecting peer is queued. */
            ok = ok && ready->inventory_to_send_count == 1;
            ok = ok && early->inventory_to_send_count == 0;
            ok = ok && leaving->inventory_to_send_count == 0;
            /* And it is a MSG_BLOCK inv for exactly this hash. */
            ok = ok && ready->inventory_to_send[0].type == MSG_BLOCK;
            ok = ok && uint256_eq(&ready->inventory_to_send[0].hash, &blk);
        }

        /* Idempotent: once the peer knows the hash, re-announcing the same
         * tip does not enqueue a duplicate inv (no announce storm). */
        if (ok) {
            p2p_node_add_inventory_known(ready, &ready->inventory_to_send[0]);
            connman_relay_block(&cm, &blk);
            ok = ok && ready->inventory_to_send_count == 1;
        }

        /* NULL args are a safe no-op, never a crash. */
        if (ok) {
            connman_relay_block(NULL, &blk);
            connman_relay_block(&cm, NULL);
        }

        connman_free(&cm);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("connman_addnode_fallback: one-shot v2 capability upgrade... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);
        cm.manager.v2_enabled = true;

        struct net_address pinned;
        test_set_ipv4(&pinned, 127, 0, 0, 1, 18444);
        cm.addnodes[cm.num_addnodes++] = pinned;
        cm.addnode_last_attempt[0] = 99;
        cm.addnode_backoff_sec[0] = 60;
        struct p2p_node *node = add_test_peer(
            &cm, 127, 0, 0, 1, PEER_VERSION_RECEIVED, false, false);
        ok = ok && node != NULL;
        if (node) {
            node->addr.svc.port = pinned.svc.port;
            node->services |= NODE_V2TRANSPORT;
            ok = ok && connman_request_v2_upgrade(&cm, node);
            ok = ok && node->disconnect;
            ok = ok &&
                (node->addr.nServices & NODE_V2TRANSPORT) != 0;
            ok = ok &&
                (cm.addnodes[0].nServices & NODE_V2TRANSPORT) != 0;
            ok = ok && cm.addnode_last_attempt[0] == 0 &&
                 cm.addnode_backoff_sec[0] == 0;

            /* The learned bit makes this the only reconnect request.  The
             * next dial snapshot enters Noise in net.c immediately. */
            node->disconnect = false;
            ok = ok && !connman_request_v2_upgrade(&cm, node);

            /* A non-addnode learned hop must retain the exact endpoint for
             * its one controlled Noise reconnect.  In -connect mode addrman
             * is not consulted, and without this queue entry the iterative
             * lookup would leave the candidate permanently unverified. */
            cm.num_addnodes = 0;
            node->addr.svc.port = 18445;
            node->addr.nServices &= ~NODE_V2TRANSPORT;
            node->disconnect = false;
            struct net_address learned_reconnect;
            memset(&learned_reconnect, 0, sizeof(learned_reconnect));
            ok = ok && connman_request_v2_upgrade(&cm, node);
            ok = ok && connman_dht_hint_pending(&cm);
            ok = ok && connman_take_dht_hint(&cm, &learned_reconnect);
            ok = ok && net_service_eq(&learned_reconnect.svc,
                                      &node->addr.svc);
            ok = ok &&
                (learned_reconnect.nServices & NODE_V2TRANSPORT) != 0;

            node->inbound = true;
            node->addr.nServices &= ~NODE_V2TRANSPORT;
            ok = ok && !connman_request_v2_upgrade(&cm, node);
        }

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("connman_addnode_fallback: inbound from a host with a "
           "handshaked outbound is evicted... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct p2p_node *outbound = NULL;
        struct p2p_node *inbound = NULL;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        ok = ok && (outbound = add_test_peer(&cm, 205, 209, 104, 118,
                                             PEER_HANDSHAKE_COMPLETE,
                                             false, false)) != NULL;
        ok = ok && (inbound = add_test_peer(&cm, 205, 209, 104, 118,
                                            PEER_HANDSHAKE_COMPLETE,
                                            true, false)) != NULL;
        if (inbound)
            inbound->addr.svc.port = 49152;
        connman_evict_same_ip_inbound_when_outbound(&cm, outbound);
        ok = ok && outbound && !outbound->disconnect;
        ok = ok && inbound && inbound->disconnect;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("connman_addnode_fallback: inbound-only same-IP stays... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct p2p_node *inbound = NULL;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        ok = ok && (inbound = add_test_peer(&cm, 140, 174, 189, 17,
                                            PEER_HANDSHAKE_COMPLETE,
                                            true, false)) != NULL;
        connman_evict_same_ip_inbound_when_outbound(&cm, inbound);
        ok = ok && inbound && !inbound->disconnect;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("connman_addnode_fallback: operator-local mixed sockets stay... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct p2p_node *outbound = NULL;
        struct p2p_node *inbound = NULL;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        ok = ok && (outbound = add_test_peer(&cm, 127, 0, 0, 1,
                                             PEER_HANDSHAKE_COMPLETE,
                                             false, false)) != NULL;
        ok = ok && (inbound = add_test_peer(&cm, 127, 0, 0, 1,
                                            PEER_HANDSHAKE_COMPLETE,
                                            true, false)) != NULL;
        if (inbound)
            inbound->addr.svc.port = 49152;
        connman_evict_same_ip_inbound_when_outbound(&cm, outbound);
        ok = ok && outbound && !outbound->disconnect;
        ok = ok && inbound && !inbound->disconnect;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("connman_addnode_fallback: feeler outbound does not evict "
           "inbound... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        struct p2p_node *feeler = NULL;
        struct p2p_node *inbound = NULL;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        ok = ok && (feeler = add_test_peer(&cm, 140, 174, 189, 3,
                                           PEER_HANDSHAKE_COMPLETE,
                                           false, false)) != NULL;
        ok = ok && (inbound = add_test_peer(&cm, 140, 174, 189, 3,
                                            PEER_HANDSHAKE_COMPLETE,
                                            true, false)) != NULL;
        if (feeler)
            feeler->is_feeler = true;
        if (inbound)
            inbound->addr.svc.port = 49152;
        connman_evict_same_ip_inbound_when_outbound(&cm, feeler);
        ok = ok && inbound && !inbound->disconnect;

        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

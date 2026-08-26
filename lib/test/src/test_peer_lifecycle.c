/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "platform/time_compat.h"
#include "test/test_core.h"

#include "event/event.h"
#include "net/fast_sync.h"
#include "net/msg_internal.h"
#include "net/peer_lifecycle.h"
#include "net/port_policy.h"
#include "net/version.h"
#include "util/clientversion.h"

#include <time.h>
#include <unistd.h>

static int g_lifecycle_disconnect_events;
static char g_lifecycle_disconnect_payload[EVENT_PAYLOAD_SIZE];
static int g_lifecycle_terminal_timeout_events;
static int g_lifecycle_terminal_reject_events;
static int g_lifecycle_terminal_disconnect_events;

static void lifecycle_disconnect_observer(enum event_type type,
                                          uint32_t peer_id,
                                          const void *payload,
                                          uint32_t payload_len,
                                          void *ctx)
{
    (void)ctx;
    if (type != EV_TCP_DISCONNECTED || peer_id != 77)
        return;
    g_lifecycle_disconnect_events++;
    size_t n = payload_len < sizeof(g_lifecycle_disconnect_payload) - 1
             ? payload_len : sizeof(g_lifecycle_disconnect_payload) - 1;
    if (payload && n > 0)
        memcpy(g_lifecycle_disconnect_payload, payload, n);
    g_lifecycle_disconnect_payload[n] = '\0';
}

static void lifecycle_terminal_observer(enum event_type type,
                                        uint32_t peer_id,
                                        const void *payload,
                                        uint32_t payload_len,
                                        void *ctx)
{
    (void)payload;
    (void)payload_len;
    (void)ctx;
    if (peer_id != 7803)
        return;
    if (type == EV_PEER_CONNECT_TIMEOUT)
        g_lifecycle_terminal_timeout_events++;
    else if (type == EV_PEER_HANDSHAKE_FAILURE)
        g_lifecycle_terminal_reject_events++;
    else if (type == EV_TCP_DISCONNECTED)
        g_lifecycle_terminal_disconnect_events++;
}

static void test_addr_ipv4(struct net_address *addr,
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

static const struct json_value *find_lifecycle_source(
    const struct json_value *arr, const char *source)
{
    if (!arr || arr->type != JSON_ARR || !source)
        return NULL;
    for (size_t i = 0; i < json_size(arr); i++) {
        const struct json_value *entry = json_at(arr, i);
        const struct json_value *name = json_get(entry, "source");
        if (name && strcmp(json_get_str(name), source) == 0)
            return entry;
    }
    return NULL;
}

static const struct json_value *find_lifecycle_obj_str(
    const struct json_value *arr, const char *key, const char *value)
{
    if (!arr || arr->type != JSON_ARR || !key || !value)
        return NULL;
    for (size_t i = 0; i < json_size(arr); i++) {
        const struct json_value *entry = json_at(arr, i);
        const struct json_value *field = json_get(entry, key);
        if (field && strcmp(json_get_str(field), value) == 0)
            return entry;
    }
    return NULL;
}

/* The expected advertised subversion, derived here INDEPENDENTLY of
 * msg_version.c: this test formats it from the build-identity accessor
 * itself, so an implementation that hard-codes, caches, or invents a value
 * cannot satisfy it. Mirrors the shape documented in net/version.h. */
static bool lifecycle_id_is_exact_hex64(const char *s)
{
    if (!s)
        return false;
    for (size_t i = 0; i < 64; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return s[64] == '\0';
}

static int test_peer_lifecycle_user_agent(void)
{
    int failures = 0;
    TEST_CASE("peer_lifecycle: version user agent advertises ZClassic23")
    {
        const char *ua = msg_version_user_agent();
        const char *baked = zcl_build_source_id_sha256();
        char expect[MAX_SUBVERSION_LENGTH];

        /* A binary carrying an exact baked source identity must publish it;
         * an unstamped one must publish the bare product identity rather than
         * a token naming a build it cannot name. Either way the string is
         * fixed by the build, never by anything at run time. */
        if (lifecycle_id_is_exact_hex64(baked))
            snprintf(expect, sizeof(expect), "/ZClassic23:0.1.0(src:%s)/",
                     baked);
        else
            snprintf(expect, sizeof(expect), "/ZClassic23:0.1.0/");

        ASSERT(strcmp(ua, expect) == 0);
        ASSERT(strncmp(ua, "/ZClassic23:0.1.0", 17) == 0);
        ASSERT(ua[strlen(ua) - 1] == '/');
        ASSERT(strlen(ua) < MAX_SUBVERSION_LENGTH);
        ASSERT(strstr(ua, "MagicBean") == NULL);

        /* The published token round-trips through the peer-side reader that
         * every OTHER node uses to learn what we run. */
        char parsed[ZCL_BUILD_IDENTITY_BUFSIZE];
        char local[ZCL_BUILD_IDENTITY_BUFSIZE];
        bool have_local = msg_version_local_build_identity(local,
                                                           sizeof(local));
        ASSERT(have_local == lifecycle_id_is_exact_hex64(baked));
        ASSERT(msg_version_parse_build_identity(ua, parsed, sizeof(parsed)) ==
               have_local);
        if (have_local) {
            ASSERT(strcmp(local, baked) == 0);
            ASSERT(strcmp(parsed, baked) == 0);
        } else {
            ASSERT(local[0] == '\0');
            ASSERT(parsed[0] == '\0');
        }

        /* Privacy: a build identity names a BUILD, never its operator. The
         * advertised string is the product name, a version, and hex. */
        for (const char *p = ua; *p; p++) {
            bool allowed = (*p >= '0' && *p <= '9') ||
                           (*p >= 'a' && *p <= 'z') ||
                           (*p >= 'A' && *p <= 'Z') ||
                           *p == '/' || *p == ':' || *p == '.' ||
                           *p == '(' || *p == ')';
            ASSERT(allowed);
        }
    } TEST_END
    return failures;
}

static int test_peer_lifecycle_classify(void)
{
    int failures = 0;
    TEST_CASE("peer_lifecycle: subver/service classification")
    {
        bool mb = false, z23 = false;
        ASSERT(msg_version_classify_peer("/MagicBean:2.1.2/",
                                         NODE_NETWORK, &mb, &z23));
        ASSERT(mb);
        ASSERT(!z23);
        ASSERT(msg_version_classify_peer("/Satoshi:0.11.2/",
                                         NODE_NETWORK | NODE_ZCL23,
                                         &mb, &z23));
        ASSERT(!mb);
        ASSERT(z23);
        ASSERT(msg_version_classify_peer("/ZClassic23:0.1.0/",
                                         NODE_NETWORK, &mb, &z23));
        ASSERT(!mb);
        ASSERT(z23);
        ASSERT(msg_version_classify_peer("/ZClassic-C23:1.0.0/",
                                         NODE_NETWORK, &mb, &z23));
        ASSERT(!mb);
        ASSERT(z23);
    } TEST_END
    return failures;
}

static int test_peer_lifecycle_version_build(void)
{
    int failures = 0;
    TEST_CASE("peer_lifecycle: version construction includes NODE_ZCL23")
    {
        struct net_manager nm;
        struct msg_processor mp;
        struct p2p_node node;
        struct version_message ver;

        memset(&mp, 0, sizeof(mp));
        memset(&node, 0, sizeof(node));
        net_manager_init(&nm);
        nm.local_host_nonce = 12345;
        mp.net_mgr = &nm;
        test_addr_ipv4(&node.addr, 203, 0, 113, 44, 8033);

        msg_version_build(&ver, &mp, &node, 3117073);
        ASSERT(ver.protocol_version == PROTOCOL_VERSION);
        ASSERT((ver.services & NODE_NETWORK) != 0);
        ASSERT((ver.services & NODE_ZCL23) != 0);
        ASSERT(ver.start_height == 3117073);
        ASSERT(strcmp(ver.sub_version, msg_version_user_agent()) == 0);
        ASSERT(ver.nonce == 12345);
        net_manager_free(&nm);
    } TEST_END
    return failures;
}

static int test_peer_lifecycle_learns_inbound_advertised_addr(void)
{
    int failures = 0;
    TEST_CASE("peer_lifecycle: inbound version advertised address feeds addrman")
    {
        struct net_manager nm;
        struct p2p_node node;
        struct version_message ver;
        struct addr_info selected;

        net_manager_init(&nm);
        memset(&node, 0, sizeof(node));
        version_message_init(&ver);

        node.inbound = true;
        test_addr_ipv4(&node.addr, 81, 214, 132, 20, 52000);
        snprintf(node.addr_name, sizeof(node.addr_name), "81.214.132.20:52000");

        ver.services = NODE_NETWORK;
        test_addr_ipv4(&ver.addr_from, 66, 70, 182, 44, 8033);
        ver.addr_from.nServices = NODE_NETWORK;
        ver.addr_from.nTime = (uint32_t)platform_time_wall_time_t();

        ASSERT(msg_version_learn_advertised_addr(&nm, &node, &ver));
        ASSERT(addrman_size(&nm.addrman) == 1);
        ASSERT(addrman_select(&nm.addrman, true, &selected));
        ASSERT(net_service_eq(&selected.addr.svc, &ver.addr_from.svc));

        net_manager_free(&nm);
    } TEST_END
    return failures;
}

static int test_peer_lifecycle_skips_inbound_ephemeral_cache(void)
{
    int failures = 0;
    TEST_CASE("peer_lifecycle: inbound ephemeral source ports are not cached")
    {
        struct p2p_node inbound;
        struct p2p_node outbound;

        memset(&inbound, 0, sizeof(inbound));
        test_addr_ipv4(&inbound.addr, 40, 160, 53, 56, 53100);
        inbound.inbound = true;
        snprintf(inbound.addr_name, sizeof(inbound.addr_name),
                 "40.160.53.56:53100");

        memset(&outbound, 0, sizeof(outbound));
        test_addr_ipv4(&outbound.addr, 40, 160, 53, 56, 8033);
        outbound.inbound = false;
        snprintf(outbound.addr_name, sizeof(outbound.addr_name),
                 "40.160.53.56:8033");

        ASSERT(!msg_version_should_save_peer(&inbound));
        ASSERT(msg_version_should_save_peer(&outbound));
        ASSERT(!zcl_net_port_is_reachable_candidate(53100));
        ASSERT(zcl_net_port_is_reachable_candidate(8033));
        ASSERT(zcl_net_port_is_reachable_candidate(20022));
        ASSERT(zcl_net_port_is_reachable_candidate(20028));

        inbound.addr.svc.port = 8033;
        ASSERT(msg_version_should_save_peer(&inbound));
    } TEST_END
    return failures;
}

static int test_peer_lifecycle_inbound_ephemeral_skip_is_not_incident(void)
{
    int failures = 0;
    TEST_CASE("peer_lifecycle: active inbound ephemeral cache skip "
              "is not incident")
    {
        struct p2p_node inbound;
        struct p2p_node outbound;
        struct json_value incidents;
        const struct json_value *top;

        peer_lifecycle_reset_for_test();
        memset(&inbound, 0, sizeof(inbound));
        test_addr_ipv4(&inbound.addr, 81, 4, 164, 198, 56435);
        inbound.id = 501;
        inbound.inbound = true;
        inbound.state = PEER_HANDSHAKE_COMPLETE;
        inbound.services = NODE_NETWORK;
        snprintf(inbound.addr_name, sizeof(inbound.addr_name),
                 "81.4.164.198:56435");
        snprintf(inbound.sub_ver, sizeof(inbound.sub_ver),
                 "%s", "/MagicBean:2.1.2-beta6/");

        peer_lifecycle_note_connected(&inbound,
                                      PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_version_received(&inbound, inbound.services,
                                             3171981, inbound.sub_ver);
        peer_lifecycle_note_handshake_complete(&inbound);
        peer_lifecycle_note_active(&inbound);
        peer_lifecycle_note_cache_skipped(&inbound,
                                          "inbound_ephemeral_port");

        json_init(&incidents);
        ASSERT(peer_lifecycle_incidents_json(&incidents));
        ASSERT(json_get_int(json_get(&incidents, "incident_count")) == 0);
        ASSERT(json_get_int(json_get(&incidents,
                                     "bootstrap_useful_count")) == 1);
        top = json_get(&incidents, "top_incidents");
        ASSERT(top && top->type == JSON_ARR);
        ASSERT(json_size(top) == 0);
        json_free(&incidents);

        memset(&outbound, 0, sizeof(outbound));
        test_addr_ipv4(&outbound.addr, 149, 50, 116, 7, 20022);
        outbound.id = 502;
        outbound.state = PEER_HANDSHAKE_COMPLETE;
        outbound.services = NODE_NETWORK;
        snprintf(outbound.addr_name, sizeof(outbound.addr_name),
                 "149.50.116.7:20022");
        snprintf(outbound.sub_ver, sizeof(outbound.sub_ver),
                 "%s", msg_version_user_agent());

        peer_lifecycle_note_connected(&outbound,
                                      PEER_LIFECYCLE_SOURCE_MANUAL);
        peer_lifecycle_note_version_received(&outbound, outbound.services,
                                             3171981, outbound.sub_ver);
        peer_lifecycle_note_handshake_complete(&outbound);
        peer_lifecycle_note_cache_skipped(&outbound, "save_advisory");

        json_init(&incidents);
        ASSERT(peer_lifecycle_incidents_json(&incidents));
        ASSERT(json_get_int(json_get(&incidents, "incident_count")) == 1);
        top = json_get(&incidents, "top_incidents");
        ASSERT(top && top->type == JSON_ARR);
        ASSERT(json_size(top) == 1);
        ASSERT(find_lifecycle_obj_str(top, "addr",
                                      "149.50.116.7:20022") != NULL);
        json_free(&incidents);
    } TEST_END
    return failures;
}

static int test_peer_lifecycle_counters(void)
{
    int failures = 0;
    TEST_CASE("peer_lifecycle: counters track handshake lifecycle")
    {
        struct net_address addr;
        struct p2p_node node;
        struct peer_lifecycle_summary s;
        struct json_value dump;

        peer_lifecycle_reset_for_test();
        memset(&node, 0, sizeof(node));
        test_addr_ipv4(&addr, 198, 51, 100, 7, 8033);
        node.addr = addr;
        node.id = 77;
        node.state = PEER_HANDSHAKE_COMPLETE;
        snprintf(node.addr_name, sizeof(node.addr_name), "198.51.100.7:8033");
        snprintf(node.sub_ver, sizeof(node.sub_ver), "%s",
                 msg_version_user_agent());
        node.services = NODE_NETWORK | NODE_ZCL23;

        peer_lifecycle_note_attempt(&addr, PEER_LIFECYCLE_SOURCE_ADDNODE);
        peer_lifecycle_note_connected(&node, PEER_LIFECYCLE_SOURCE_ADDNODE);
        peer_lifecycle_note_version_sent(&node, node.services, 10,
                                         msg_version_user_agent());
        peer_lifecycle_note_version_received(&node, node.services, 12,
                                             msg_version_user_agent());
        peer_lifecycle_note_verack_received(&node);
        peer_lifecycle_note_handshake_complete(&node);
        peer_lifecycle_note_active(&node);
        peer_lifecycle_note_cache_skipped(&node, "save_advisory");
        node.endpoint_generation = 78;
        ASSERT(p2p_node_request_disconnect(
            &node, P2P_DISCONNECT_PONG_TIMEOUT,
            P2P_DISCONNECT_SOURCE_KEEPALIVE, node.endpoint_generation));
        event_log_init();
        g_lifecycle_disconnect_events = 0;
        g_lifecycle_disconnect_payload[0] = '\0';
        ASSERT(event_observe(EV_TCP_DISCONNECTED,
                             lifecycle_disconnect_observer, NULL));
        peer_lifecycle_note_disconnected(&node, "cleanup");
        peer_lifecycle_get_summary(&s);

        ASSERT(s.attempted == 1);
        ASSERT(s.connected == 1);
        ASSERT(s.version_sent == 1);
        ASSERT(s.version_received == 1);
        ASSERT(s.verack_received == 1);
        ASSERT(s.handshake_complete == 1);
        ASSERT(s.active == 1);
        ASSERT(s.disconnected == 1);
        ASSERT(s.cache_skipped == 1);
        ASSERT(s.magicbean_handshakes == 0);
        ASSERT(s.zcl23_handshakes == 1);
        ASSERT(s.disconnect_reason_counts[P2P_DISCONNECT_PONG_TIMEOUT] == 1);
        ASSERT(s.disconnect_source_counts[P2P_DISCONNECT_SOURCE_KEEPALIVE] == 1);
        ASSERT(s.max_endpoint_generation == 78);
        ASSERT(g_lifecycle_disconnect_events == 1);
        ASSERT(strstr(g_lifecycle_disconnect_payload,
                      "disconnect addr=198.51.100.7:8033") != NULL);
        ASSERT(strstr(g_lifecycle_disconnect_payload,
                      "reason=cleanup") != NULL);
        event_clear_observers(EV_TCP_DISCONNECTED);

        json_init(&dump);
        json_set_object(&dump);
        ASSERT(peer_lifecycle_dump_state_json(&dump, NULL));
        const struct json_value *sources = json_get(&dump, "sources");
        const struct json_value *addnode =
            find_lifecycle_source(sources, "addnode");
        ASSERT(sources && sources->type == JSON_ARR);
        ASSERT(addnode && addnode->type == JSON_OBJ);
        ASSERT(json_get_int(json_get(addnode, "attempted")) == 1);
        ASSERT(json_get_int(json_get(addnode, "connected")) == 1);
        ASSERT(json_get_int(json_get(addnode, "handshake_complete")) == 1);
        ASSERT(json_get_int(json_get(addnode, "active")) == 1);
        ASSERT(json_get_int(json_get(addnode, "disconnected")) == 1);
        ASSERT(json_get_int(json_get(addnode, "cache_skipped")) == 1);
        ASSERT(json_get_int(json_get(addnode, "magicbean_handshakes")) == 0);
        ASSERT(json_get_int(json_get(addnode,
                                      "legacy_compatible_handshakes")) == 0);
        ASSERT(json_get_int(json_get(addnode,
                                      "legacy_magicbean_handshakes")) == 0);
        ASSERT(json_get_int(json_get(addnode, "zclassic23_handshakes")) == 1);
        ASSERT(json_get_int(json_get(addnode, "zclassic_c23_handshakes")) == 1);
        const struct json_value *summary = json_get(&dump, "summary");
        const struct json_value *causes =
            summary ? json_get(summary, "causal_disconnects") : NULL;
        ASSERT(causes &&
               json_get_int(json_get(causes, "pong_timeout")) == 1);
        ASSERT(summary &&
               json_get_int(json_get(summary, "max_endpoint_generation")) == 78);
        json_free(&dump);
    } TEST_END
    return failures;
}

static int test_peer_lifecycle_terminal_idempotency(void)
{
    int failures = 0;
    TEST_CASE("peer_lifecycle: terminal outcome is once per connection")
    {
        struct net_address addr;
        struct p2p_node node;
        struct peer_lifecycle_summary s;
        struct json_value peer;

        peer_lifecycle_reset_for_test();
        memset(&node, 0, sizeof(node));
        test_addr_ipv4(&addr, 198, 51, 100, 78, 8033);
        node.addr = addr;
        node.id = 7803;
        node.state = PEER_CONNECTING;
        snprintf(node.addr_name, sizeof(node.addr_name),
                 "198.51.100.78:8033");
        event_log_init();
        g_lifecycle_terminal_timeout_events = 0;
        g_lifecycle_terminal_reject_events = 0;
        g_lifecycle_terminal_disconnect_events = 0;
        ASSERT(event_observe(EV_PEER_CONNECT_TIMEOUT,
                             lifecycle_terminal_observer, NULL));
        ASSERT(event_observe(EV_PEER_HANDSHAKE_FAILURE,
                             lifecycle_terminal_observer, NULL));
        ASSERT(event_observe(EV_TCP_DISCONNECTED,
                             lifecycle_terminal_observer, NULL));

        /* connman records the timeout first, then its cleanup sweep reports
         * the same node disconnected. Cleanup and any duplicate timeout must
         * not manufacture extra terminal or pre-handshake incidents. */
        peer_lifecycle_note_connected(&node,
                                      PEER_LIFECYCLE_SOURCE_ADDNODE);
        peer_lifecycle_note_timeout(&node, "handshake");
        peer_lifecycle_note_disconnected(&node, "cleanup");
        peer_lifecycle_note_timeout(&node, "handshake-duplicate");
        peer_lifecycle_get_summary(&s);
        ASSERT(s.connected == 1);
        ASSERT(s.timeout == 1);
        ASSERT(s.rejected == 0);
        ASSERT(s.disconnected == 0);
        ASSERT(s.pre_handshake_disconnects == 1);
        ASSERT(g_lifecycle_terminal_timeout_events == 1);
        ASSERT(g_lifecycle_terminal_reject_events == 0);
        ASSERT(g_lifecycle_terminal_disconnect_events == 0);

        json_init(&peer);
        ASSERT(peer_lifecycle_peer_json(&node, &peer));
        ASSERT(json_get_int(json_get(&peer, "timeout")) == 1);
        ASSERT(json_get_int(json_get(&peer, "disconnected")) == 0);
        ASSERT(json_get_int(json_get(&peer,
                                     "pre_handshake_disconnects")) == 1);
        ASSERT(strcmp(json_get_str(json_get(&peer, "last_reason")),
                      "handshake") == 0);
        json_free(&peer);

        /* A new connected generation re-arms exactly one terminal outcome. */
        peer_lifecycle_note_connected(&node,
                                      PEER_LIFECYCLE_SOURCE_ADDNODE);
        peer_lifecycle_note_reject(&node, "protocol-too-old");
        peer_lifecycle_note_disconnected(&node, "cleanup");
        peer_lifecycle_get_summary(&s);
        ASSERT(s.connected == 2);
        ASSERT(s.timeout == 1);
        ASSERT(s.rejected == 1);
        ASSERT(s.disconnected == 0);
        ASSERT(s.pre_handshake_disconnects == 2);
        ASSERT(g_lifecycle_terminal_timeout_events == 1);
        ASSERT(g_lifecycle_terminal_reject_events == 1);
        ASSERT(g_lifecycle_terminal_disconnect_events == 0);

        /* A handshaked generation's ordinary cleanup is independently
         * counted, but is not a pre-handshake incident. */
        peer_lifecycle_note_connected(&node,
                                      PEER_LIFECYCLE_SOURCE_ADDNODE);
        peer_lifecycle_note_handshake_complete(&node);
        peer_lifecycle_note_disconnected(&node, "cleanup");
        peer_lifecycle_note_disconnected(&node, "cleanup-duplicate");
        peer_lifecycle_get_summary(&s);
        ASSERT(s.connected == 3);
        ASSERT(s.timeout == 1);
        ASSERT(s.rejected == 1);
        ASSERT(s.disconnected == 1);
        ASSERT(s.pre_handshake_disconnects == 2);
        ASSERT(g_lifecycle_terminal_timeout_events == 1);
        ASSERT(g_lifecycle_terminal_reject_events == 1);
        ASSERT(g_lifecycle_terminal_disconnect_events == 1);
        event_clear_observers(EV_PEER_CONNECT_TIMEOUT);
        event_clear_observers(EV_PEER_HANDSHAKE_FAILURE);
        event_clear_observers(EV_TCP_DISCONNECTED);
    } TEST_END
    return failures;
}

static int test_peer_lifecycle_addr_lookup(void)
{
    int failures = 0;
    TEST_CASE("peer_lifecycle: exact address lookup returns live readiness")
    {
        struct net_address addr;
        struct p2p_node node;
        struct json_value peer;
        struct json_value missing;

        peer_lifecycle_reset_for_test();
        memset(&node, 0, sizeof(node));
        test_addr_ipv4(&addr, 198, 51, 100, 37, 8033);
        node.addr = addr;
        node.id = 3703;
        node.state = PEER_HANDSHAKE_COMPLETE;
        node.services = NODE_NETWORK | NODE_ZCL23;
        snprintf(node.addr_name, sizeof(node.addr_name),
                 "198.51.100.37:8033");
        snprintf(node.sub_ver, sizeof(node.sub_ver),
                 "%s", msg_version_user_agent());

        peer_lifecycle_note_connected(&node,
                                      PEER_LIFECYCLE_SOURCE_ADDNODE);
        peer_lifecycle_note_version_received(&node, node.services,
                                             3173000, node.sub_ver);
        peer_lifecycle_note_handshake_complete(&node);
        peer_lifecycle_note_active(&node);

        json_init(&peer);
        ASSERT(peer_lifecycle_addr_json("198.51.100.37:8033", &peer));
        ASSERT(strcmp(json_get_str(json_get(&peer, "addr")),
                      "198.51.100.37:8033") == 0);
        ASSERT(json_get_bool(json_get(&peer, "zclassic23")));
        ASSERT(json_get_bool(json_get(&peer, "fast_sync_useful")));
        ASSERT(strcmp(json_get_str(json_get(&peer,
                                            "bootstrap_readiness")),
                      "useful") == 0);
        json_free(&peer);

        json_init(&missing);
        ASSERT(!peer_lifecycle_addr_json("198.51.100.37:18033",
                                         &missing));
        json_free(&missing);
    } TEST_END
    return failures;
}

static int test_peer_lifecycle_inbound_source_bucket(void)
{
    int failures = 0;
    TEST_CASE("peer_lifecycle: inbound source bucket tracks public reachability")
    {
        struct net_address addr;
        struct p2p_node node;
        struct json_value summary;

        peer_lifecycle_reset_for_test();
        memset(&node, 0, sizeof(node));
        test_addr_ipv4(&addr, 203, 0, 113, 9, 8033);
        node.addr = addr;
        node.id = 88;
        node.inbound = true;
        node.state = PEER_HANDSHAKE_COMPLETE;
        snprintf(node.addr_name, sizeof(node.addr_name), "203.0.113.9:8033");
        snprintf(node.sub_ver, sizeof(node.sub_ver), "%s",
                 msg_version_user_agent());
        node.services = NODE_NETWORK | NODE_ZCL23;

        peer_lifecycle_note_connected(&node, PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_version_sent(&node, node.services, 20,
                                         msg_version_user_agent());
        peer_lifecycle_note_version_received(&node, node.services, 21,
                                             msg_version_user_agent());
        peer_lifecycle_note_handshake_complete(&node);

        json_init(&summary);
        ASSERT(peer_lifecycle_summary_json(&summary));
        const struct json_value *sources = json_get(&summary, "sources");
        const struct json_value *inbound =
            find_lifecycle_source(sources, "inbound");
        ASSERT(sources && sources->type == JSON_ARR);
        ASSERT(inbound && inbound->type == JSON_OBJ);
        ASSERT(json_get_int(json_get(inbound, "attempted")) == 0);
        ASSERT(json_get_int(json_get(inbound, "connected")) == 1);
        ASSERT(json_get_int(json_get(inbound, "version_sent")) == 1);
        ASSERT(json_get_int(json_get(inbound, "version_received")) == 1);
        ASSERT(json_get_int(json_get(inbound, "handshake_complete")) == 1);
        ASSERT(json_get_int(json_get(inbound, "magicbean_handshakes")) == 0);
        ASSERT(json_get_int(json_get(inbound,
                                      "legacy_compatible_handshakes")) == 0);
        ASSERT(json_get_int(json_get(inbound,
                                      "legacy_magicbean_handshakes")) == 0);
        ASSERT(json_get_int(json_get(inbound, "zclassic_c23_handshakes")) == 1);
        json_free(&summary);
    } TEST_END
    return failures;
}

static int test_peer_lifecycle_duplicate_connect_duration(void)
{
    int failures = 0;
    TEST_CASE("peer_lifecycle: duplicate connect does not make duration negative")
    {
        struct net_address addr;
        struct p2p_node node;
        struct json_value peer;

        peer_lifecycle_reset_for_test();
        memset(&node, 0, sizeof(node));
        test_addr_ipv4(&addr, 198, 51, 100, 8, 8033);
        node.addr = addr;
        node.id = 99;
        node.state = PEER_HANDSHAKE_COMPLETE;
        snprintf(node.addr_name, sizeof(node.addr_name), "198.51.100.8:8033");
        snprintf(node.sub_ver, sizeof(node.sub_ver), "%s",
                 msg_version_user_agent());
        node.services = NODE_NETWORK | NODE_ZCL23;

        peer_lifecycle_note_connected(&node, PEER_LIFECYCLE_SOURCE_MANUAL);
        peer_lifecycle_note_version_received(&node, node.services, 12,
                                             msg_version_user_agent());
        peer_lifecycle_note_handshake_complete(&node);
        sleep(1);
        peer_lifecycle_note_connected(&node, PEER_LIFECYCLE_SOURCE_MANUAL);

        json_init(&peer);
        json_set_object(&peer);
        ASSERT(peer_lifecycle_peer_json(&node, &peer));
        ASSERT(json_get_int(json_get(&peer, "handshake_duration_secs")) >= 0);
        ASSERT(!json_get_bool(json_get(&peer, "legacy_compatible")));
        ASSERT(json_get_int(json_get(&peer, "handshake_complete_at")) >=
               json_get_int(json_get(&peer, "connected_at")));
        json_free(&peer);
    } TEST_END
    return failures;
}

static int test_peer_lifecycle_inbound_classifies_remote_version(void)
{
    int failures = 0;
    TEST_CASE("peer_lifecycle: inbound C23 count uses remote version")
    {
        struct net_address addr;
        struct p2p_node node;
        struct peer_lifecycle_summary s;

        peer_lifecycle_reset_for_test();
        memset(&node, 0, sizeof(node));
        test_addr_ipv4(&addr, 203, 0, 113, 10, 8033);
        node.addr = addr;
        node.id = 100;
        node.inbound = true;
        node.state = PEER_HANDSHAKE_COMPLETE;
        snprintf(node.addr_name, sizeof(node.addr_name), "203.0.113.10:8033");
        snprintf(node.sub_ver, sizeof(node.sub_ver),
                 "%s", "/MagicBean:2.1.2-beta6/");
        node.services = NODE_NETWORK;

        peer_lifecycle_note_connected(&node, PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_version_received(&node, node.services, 21,
                                             node.sub_ver);
        peer_lifecycle_note_version_sent(&node, NODE_NETWORK | NODE_ZCL23, 20,
                                         msg_version_user_agent());
        peer_lifecycle_note_handshake_complete(&node);
        peer_lifecycle_get_summary(&s);

        ASSERT(s.handshake_complete == 1);
        ASSERT(s.magicbean_handshakes == 1);
        ASSERT(s.legacy_compatible_handshakes == 1);
        ASSERT(s.zcl23_handshakes == 0);
    } TEST_END
    return failures;
}

static int test_peer_lifecycle_incident_view(void)
{
    int failures = 0;
    TEST_CASE("peer_lifecycle: compact incident view groups reconnecting hosts")
    {
        struct p2p_node zigma_a;
        struct p2p_node zigma_b;
        struct p2p_node stable;
        struct json_value incidents;
        struct json_value keyed;

        peer_lifecycle_reset_for_test();
        memset(&zigma_a, 0, sizeof(zigma_a));
        test_addr_ipv4(&zigma_a.addr, 40, 160, 53, 56, 45474);
        zigma_a.id = 201;
        zigma_a.inbound = true;
        zigma_a.state = PEER_HANDSHAKE_COMPLETE;
        zigma_a.services = NODE_NETWORK;
        snprintf(zigma_a.addr_name, sizeof(zigma_a.addr_name),
                 "40.160.53.56:45474");
        snprintf(zigma_a.sub_ver, sizeof(zigma_a.sub_ver),
                 "%s", "/Zigma:0.1.0/");

        peer_lifecycle_note_connected(&zigma_a,
                                      PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_version_received(&zigma_a, zigma_a.services,
                                             3170406, zigma_a.sub_ver);
        peer_lifecycle_note_handshake_complete(&zigma_a);
        peer_lifecycle_note_active(&zigma_a);
        peer_lifecycle_note_disconnected(&zigma_a, "cleanup");
        sleep(1);
        peer_lifecycle_note_connected(&zigma_a,
                                      PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_version_received(&zigma_a, zigma_a.services,
                                             3170407, zigma_a.sub_ver);
        peer_lifecycle_note_handshake_complete(&zigma_a);
        peer_lifecycle_note_active(&zigma_a);

        memset(&zigma_b, 0, sizeof(zigma_b));
        test_addr_ipv4(&zigma_b.addr, 40, 160, 53, 56, 39030);
        zigma_b.id = 202;
        zigma_b.inbound = true;
        zigma_b.state = PEER_CONNECTING;
        zigma_b.services = NODE_NETWORK;
        snprintf(zigma_b.addr_name, sizeof(zigma_b.addr_name),
                 "40.160.53.56:39030");
        snprintf(zigma_b.sub_ver, sizeof(zigma_b.sub_ver),
                 "%s", "/Zigma:0.1.0/");
        peer_lifecycle_note_connected(&zigma_b,
                                      PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_timeout(&zigma_b, "handshake_timeout");

        memset(&stable, 0, sizeof(stable));
        test_addr_ipv4(&stable.addr, 198, 51, 100, 10, 8033);
        stable.id = 203;
        stable.state = PEER_HANDSHAKE_COMPLETE;
        stable.services = NODE_NETWORK;
        snprintf(stable.addr_name, sizeof(stable.addr_name),
                 "198.51.100.10:8033");
        snprintf(stable.sub_ver, sizeof(stable.sub_ver),
                 "%s", "/MagicBean:2.1.2-beta6/");
        peer_lifecycle_note_connected(&stable,
                                      PEER_LIFECYCLE_SOURCE_ADDNODE);
        peer_lifecycle_note_version_received(&stable, stable.services,
                                             3171817, stable.sub_ver);
        peer_lifecycle_note_handshake_complete(&stable);
        peer_lifecycle_note_active(&stable);

        json_init(&incidents);
        ASSERT(peer_lifecycle_incidents_json(&incidents));
        ASSERT(strcmp(json_get_str(json_get(&incidents, "schema")),
                      "zcl.peer_incidents.v2") == 0);
        ASSERT(json_get_bool(json_get(&incidents, "bounded")));
        ASSERT(json_get_int(json_get(&incidents, "incident_count")) == 2);
        ASSERT(json_get_int(json_get(&incidents,
                                     "duplicate_host_group_count")) == 1);
        ASSERT(json_get_int(json_get(&incidents,
                                     "duplicate_open_host_group_count")) == 0);
        ASSERT(json_get_int(json_get(&incidents,
                                     "duplicate_handshaked_host_group_count"))
               == 0);
        ASSERT(json_get_int(json_get(&incidents,
                                     "current_open_connection_count")) == 2);
        ASSERT(json_get_int(json_get(&incidents,
                                     "current_handshaked_connection_count"))
               == 2);
        ASSERT(json_get_int(json_get(&incidents,
                                     "bootstrap_useful_count")) == 2);
        ASSERT(json_get_int(json_get(&incidents,
                                     "host_incident_limit")) == 8);
        ASSERT(json_get_int(json_get(&incidents,
                                     "host_incident_count")) == 1);
        ASSERT(json_get_int(json_get(&incidents,
                                     "host_count_returned")) == 1);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "safe_next_action")),
                      "inspect primary_host_issue and top_host_incidents")
               == 0);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "primary_issue_host")),
                      "40.160.53.56") == 0);
        ASSERT(json_get_int(json_get(&incidents,
                                     "primary_issue_score")) > 0);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "primary_issue_class")),
                      "reconnect_timeout_pressure") == 0);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "primary_issue_next_action")),
                      "inspect_peer_timeline_for_reconnect_timeouts") == 0);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "bootstrap_readiness")),
                      "ready") == 0);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "fast_sync_readiness")),
                      "no_zclassic23_fast_sync_peer") == 0);
        ASSERT(!json_get_bool(json_get(&incidents, "bootstrap_blocked")));
        ASSERT(json_get_bool(json_get(&incidents, "fast_sync_blocked")));
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "incident_severity")),
                      "attention") == 0);
        ASSERT(json_get_bool(json_get(&incidents, "stability_blocker")));

        const struct json_value *groups =
            json_get(&incidents, "duplicate_host_groups");
        const struct json_value *group =
            find_lifecycle_obj_str(groups, "host", "40.160.53.56");
        ASSERT(group && group->type == JSON_OBJ);
        ASSERT(json_get_int(json_get(group, "incident_score")) > 0);
        ASSERT(strcmp(json_get_str(json_get(group, "issue_class")),
                      "reconnect_timeout_pressure") == 0);
        ASSERT(strcmp(json_get_str(json_get(group, "next_action")),
                      "inspect_peer_timeline_for_reconnect_timeouts") == 0);
        ASSERT(json_get_int(json_get(group, "entries")) == 2);
        ASSERT(json_get_int(json_get(group, "inbound_entries")) == 2);
        ASSERT(json_get_int(json_get(group, "outbound_entries")) == 0);
        ASSERT(strcmp(json_get_str(json_get(group, "direction")),
                      "inbound") == 0);
        ASSERT(!json_get_bool(json_get(group, "mixed_direction")));
        ASSERT(json_get_int(json_get(group, "open_connections")) == 1);
        ASSERT(strcmp(json_get_str(json_get(group,
                                            "current_open_direction")),
                      "inbound") == 0);
        ASSERT(!json_get_bool(json_get(group,
                                       "current_open_mixed_direction")));
        ASSERT(json_get_int(json_get(group,
            "current_open_inbound_connections")) == 1);
        ASSERT(json_get_int(json_get(group,
            "current_open_outbound_connections")) == 0);
        ASSERT(json_get_int(json_get(group,
                                     "handshaked_open_connections")) == 1);
        ASSERT(strcmp(json_get_str(json_get(group,
                                            "current_handshaked_direction")),
                      "inbound") == 0);
        ASSERT(!json_get_bool(json_get(group,
            "current_handshaked_mixed_direction")));
        ASSERT(json_get_int(json_get(group,
            "current_handshaked_inbound_connections")) == 1);
        ASSERT(json_get_int(json_get(group,
            "current_handshaked_outbound_connections")) == 0);
        ASSERT(json_get_int(json_get(group,
                                     "handshaked_network_connections")) == 1);
        ASSERT(json_get_int(json_get(group,
            "handshaked_advertised_height_connections")) == 1);
        ASSERT(json_get_int(json_get(group,
            "handshaked_trusted_advertised_height_connections")) == 1);
        ASSERT(json_get_int(json_get(group,
            "handshaked_untrusted_advertised_height_connections")) == 0);
        ASSERT(json_get_int(json_get(group,
                                     "handshaked_zclassic23_connections"))
               == 0);
        ASSERT(json_get_int(json_get(group,
                                     "bootstrap_useful_connections")) == 1);
        ASSERT(!json_get_bool(json_get(group,
                                       "duplicate_current_connections")));
        ASSERT(!json_get_bool(json_get(group,
                                       "duplicate_handshaked_connections")));
        ASSERT(json_get_int(json_get(group, "reconnects")) == 1);
        ASSERT(json_get_int(json_get(group,
                                     "last_reconnect_interval_secs")) >= 1);
        ASSERT(json_get_int(json_get(group,
                                     "min_reconnect_interval_secs")) >= 1);
        ASSERT(json_get_int(json_get(group,
                                     "max_reconnect_interval_secs")) >=
               json_get_int(json_get(group,
                                     "min_reconnect_interval_secs")));
        ASSERT(json_get_int(json_get(group, "timeout")) == 1);
        ASSERT(json_get_int(json_get(group,
                                     "pre_handshake_disconnects")) == 1);
        ASSERT(strcmp(json_get_str(json_get(group, "bootstrap_readiness")),
                      "useful") == 0);
        ASSERT(strcmp(json_get_str(json_get(group, "fast_sync_readiness")),
                      "missing_zclassic23_fast_sync") == 0);
        ASSERT(json_get_bool(json_get(group, "bootstrap_useful")));

        const struct json_value *primary =
            json_get(&incidents, "primary_host_issue");
        ASSERT(primary && primary->type == JSON_OBJ);
        ASSERT(strcmp(json_get_str(json_get(primary, "status")),
                      "attention") == 0);
        ASSERT(strcmp(json_get_str(json_get(primary, "host")),
                      "40.160.53.56") == 0);
        ASSERT(strcmp(json_get_str(json_get(primary, "issue_class")),
                      "reconnect_timeout_pressure") == 0);
        ASSERT(strcmp(json_get_str(json_get(primary, "direction")),
                      "inbound") == 0);
        ASSERT(!json_get_bool(json_get(primary, "mixed_direction")));
        ASSERT(json_get_int(json_get(primary, "timeout")) == 1);
        ASSERT(strcmp(json_get_str(json_get(primary, "bootstrap_readiness")),
                      "useful") == 0);
        ASSERT(strcmp(json_get_str(json_get(primary, "fast_sync_readiness")),
                      "missing_zclassic23_fast_sync") == 0);

        const struct json_value *host_incidents =
            json_get(&incidents, "top_host_incidents");
        const struct json_value *host_pick =
            find_lifecycle_obj_str(host_incidents, "host", "40.160.53.56");
        ASSERT(host_pick && host_pick->type == JSON_OBJ);
        ASSERT(strcmp(json_get_str(json_get(host_pick, "issue_class")),
                      "reconnect_timeout_pressure") == 0);

        const struct json_value *top =
            json_get(&incidents, "top_incidents");
        const struct json_value *a =
            find_lifecycle_obj_str(top, "addr", "40.160.53.56:45474");
        const struct json_value *b =
            find_lifecycle_obj_str(top, "addr", "40.160.53.56:39030");
        ASSERT(a && a->type == JSON_OBJ);
        ASSERT(b && b->type == JSON_OBJ);
        ASSERT(json_get_int(json_get(a, "duplicate_host_entries")) == 2);
        ASSERT(json_get_int(json_get(a, "reconnects")) == 1);
        ASSERT(json_get_int(json_get(a,
                                     "last_reconnect_interval_secs")) >= 1);
        ASSERT(strcmp(json_get_str(json_get(a, "direction")), "inbound") == 0);
        ASSERT(strstr(json_get_str(json_get(a, "services_summary")),
                      "NODE_NETWORK") != NULL);
        ASSERT(json_get_int(json_get(a, "advertised_height")) == 3170407);
        ASSERT(strcmp(json_get_str(json_get(a,
                                            "advertised_height_trust")),
                      "trusted") == 0);
        ASSERT(json_get_bool(json_get(a, "advertised_height_trusted")));
        ASSERT(json_get_int(json_get(a, "handshake_age_secs")) >= 0);
        ASSERT(strcmp(json_get_str(json_get(a, "bootstrap_readiness")),
                      "useful") == 0);
        ASSERT(json_get_bool(json_get(a, "bootstrap_useful")));
        ASSERT(!json_get_bool(json_get(a, "fast_sync_useful")));
        ASSERT(json_get_int(json_get(b, "timeout")) == 1);
        ASSERT(json_get_int(json_get(b,
                                     "pre_handshake_disconnects")) == 1);
        ASSERT(strcmp(json_get_str(json_get(b, "bootstrap_readiness")),
                      "not_connected") == 0);
        ASSERT(strcmp(json_get_str(json_get(b, "last_disconnect_reason")),
                      "handshake_timeout") == 0);
        ASSERT(!json_get_bool(json_get(b, "bootstrap_useful")));
        json_free(&incidents);

        json_init(&keyed);
        json_set_object(&keyed);
        ASSERT(peer_lifecycle_dump_state_json(&keyed, "incidents"));
        ASSERT(strcmp(json_get_str(json_get(&keyed, "schema")),
                      "zcl.peer_incidents.v2") == 0);
        ASSERT(json_get(&keyed, "peers") == NULL);
        json_free(&keyed);
    } TEST_END
    return failures;
}

static int test_peer_lifecycle_duplicate_current_bootstrap_view(void)
{
    int failures = 0;
    TEST_CASE("peer_lifecycle: compact view shows current duplicate "
              "bootstrap peers")
    {
        struct p2p_node first;
        struct p2p_node second;
        struct json_value incidents;

        peer_lifecycle_reset_for_test();

        memset(&first, 0, sizeof(first));
        test_addr_ipv4(&first.addr, 203, 0, 113, 42, 45474);
        first.id = 301;
        first.inbound = true;
        first.state = PEER_HANDSHAKE_COMPLETE;
        first.services = NODE_NETWORK;
        snprintf(first.addr_name, sizeof(first.addr_name),
                 "203.0.113.42:45474");
        snprintf(first.sub_ver, sizeof(first.sub_ver),
                 "%s", "/MagicBean:2.1.2-beta6/");

        peer_lifecycle_note_connected(&first,
                                      PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_version_received(&first, first.services,
                                             3172091, first.sub_ver);
        peer_lifecycle_note_handshake_complete(&first);
        peer_lifecycle_note_active(&first);

        memset(&second, 0, sizeof(second));
        test_addr_ipv4(&second.addr, 203, 0, 113, 42, 39030);
        second.id = 302;
        second.inbound = true;
        second.state = PEER_HANDSHAKE_COMPLETE;
        second.services = NODE_NETWORK | NODE_ZCL23;
        snprintf(second.addr_name, sizeof(second.addr_name),
                 "203.0.113.42:39030");
        snprintf(second.sub_ver, sizeof(second.sub_ver),
                 "%s", msg_version_user_agent());

        peer_lifecycle_note_connected(&second,
                                      PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_version_received(&second, second.services,
                                             3172092, second.sub_ver);
        peer_lifecycle_note_handshake_complete(&second);
        peer_lifecycle_note_active(&second);

        json_init(&incidents);
        ASSERT(peer_lifecycle_incidents_json(&incidents));
        ASSERT(json_get_int(json_get(&incidents, "incident_count")) == 2);
        ASSERT(json_get_int(json_get(&incidents,
                                     "duplicate_host_group_count")) == 1);
        ASSERT(json_get_int(json_get(&incidents,
                                     "duplicate_open_host_group_count")) == 1);
        ASSERT(json_get_int(json_get(&incidents,
                                     "duplicate_handshaked_host_group_count"))
               == 1);
        ASSERT(json_get_int(json_get(&incidents,
                                     "current_open_connection_count")) == 2);
        ASSERT(json_get_int(json_get(&incidents,
                                     "current_handshaked_connection_count"))
               == 2);
        ASSERT(json_get_int(json_get(&incidents,
                                     "bootstrap_useful_count")) == 2);
        ASSERT(json_get_int(json_get(&incidents,
                                     "fast_sync_useful_count")) == 1);
        ASSERT(json_get_int(json_get(&incidents,
                                     "host_incident_count")) == 1);
        ASSERT(json_get_int(json_get(&incidents,
                                     "host_count_returned")) == 1);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "safe_next_action")),
                      "inspect primary_host_issue and top_host_incidents")
               == 0);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "primary_issue_host")),
                      "203.0.113.42") == 0);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "primary_issue_class")),
                      "duplicate_handshaked_connections") == 0);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "primary_issue_next_action")),
                      "inspect_duplicate_current_connections_for_host") == 0);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "bootstrap_readiness")),
                      "ready") == 0);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "fast_sync_readiness")),
                      "ready") == 0);
        ASSERT(!json_get_bool(json_get(&incidents, "bootstrap_blocked")));
        ASSERT(!json_get_bool(json_get(&incidents, "fast_sync_blocked")));
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "incident_severity")),
                      "attention") == 0);

        const struct json_value *groups =
            json_get(&incidents, "duplicate_host_groups");
        const struct json_value *group =
            find_lifecycle_obj_str(groups, "host", "203.0.113.42");
        ASSERT(group && group->type == JSON_OBJ);
        ASSERT(json_get_int(json_get(group, "incident_score")) > 0);
        ASSERT(strcmp(json_get_str(json_get(group, "issue_class")),
                      "duplicate_handshaked_connections") == 0);
        ASSERT(strcmp(json_get_str(json_get(group, "next_action")),
                      "inspect_duplicate_current_connections_for_host") == 0);
        ASSERT(json_get_int(json_get(group, "entries")) == 2);
        ASSERT(strcmp(json_get_str(json_get(group, "direction")),
                      "inbound") == 0);
        ASSERT(!json_get_bool(json_get(group, "mixed_direction")));
        ASSERT(json_get_int(json_get(group, "open_connections")) == 2);
        ASSERT(strcmp(json_get_str(json_get(group,
                                            "current_open_direction")),
                      "inbound") == 0);
        ASSERT(!json_get_bool(json_get(group,
                                       "current_open_mixed_direction")));
        ASSERT(json_get_int(json_get(group,
            "current_open_inbound_connections")) == 2);
        ASSERT(json_get_int(json_get(group,
            "current_open_outbound_connections")) == 0);
        ASSERT(json_get_int(json_get(group,
                                     "handshaked_open_connections")) == 2);
        ASSERT(strcmp(json_get_str(json_get(group,
                                            "current_handshaked_direction")),
                      "inbound") == 0);
        ASSERT(!json_get_bool(json_get(group,
            "current_handshaked_mixed_direction")));
        ASSERT(json_get_int(json_get(group,
            "current_handshaked_inbound_connections")) == 2);
        ASSERT(json_get_int(json_get(group,
            "current_handshaked_outbound_connections")) == 0);
        ASSERT(json_get_int(json_get(group,
                                     "handshaked_network_connections")) == 2);
        ASSERT(json_get_int(json_get(group,
            "handshaked_advertised_height_connections")) == 2);
        ASSERT(json_get_int(json_get(group,
            "handshaked_trusted_advertised_height_connections")) == 2);
        ASSERT(json_get_int(json_get(group,
            "handshaked_untrusted_advertised_height_connections")) == 0);
        ASSERT(json_get_int(json_get(group,
                                     "handshaked_zclassic23_connections"))
               == 1);
        ASSERT(json_get_int(json_get(group,
                                     "bootstrap_useful_connections")) == 2);
        ASSERT(json_get_int(json_get(group,
                                     "fast_sync_useful_connections")) == 1);
        ASSERT(json_get_bool(json_get(group,
                                      "duplicate_current_connections")));
        ASSERT(json_get_bool(json_get(group,
                                      "duplicate_handshaked_connections")));
        ASSERT(strstr(json_get_str(json_get(group, "services_summary")),
                      "NODE_NETWORK") != NULL);
        ASSERT(strstr(json_get_str(json_get(group, "services_summary")),
                      "NODE_ZCL23") != NULL);
        ASSERT(json_get_int(json_get(group, "max_advertised_height"))
               == 3172092);
        ASSERT(strcmp(json_get_str(json_get(group,
                                            "advertised_height_trust")),
                      "trusted") == 0);
        ASSERT(strcmp(json_get_str(json_get(group, "bootstrap_readiness")),
                      "useful") == 0);
        ASSERT(strcmp(json_get_str(json_get(group, "fast_sync_readiness")),
                      "useful") == 0);

        const struct json_value *primary =
            json_get(&incidents, "primary_host_issue");
        ASSERT(primary && primary->type == JSON_OBJ);
        ASSERT(strcmp(json_get_str(json_get(primary, "host")),
                      "203.0.113.42") == 0);
        ASSERT(strcmp(json_get_str(json_get(primary, "issue_class")),
                      "duplicate_handshaked_connections") == 0);
        ASSERT(strcmp(json_get_str(json_get(primary, "direction")),
                      "inbound") == 0);
        ASSERT(!json_get_bool(json_get(primary, "mixed_direction")));
        ASSERT(json_get_bool(json_get(primary,
                                      "duplicate_handshaked_connections")));
        ASSERT(strcmp(json_get_str(json_get(primary, "bootstrap_readiness")),
                      "useful") == 0);
        ASSERT(strcmp(json_get_str(json_get(primary, "fast_sync_readiness")),
                      "useful") == 0);

        const struct json_value *host_incidents =
            json_get(&incidents, "top_host_incidents");
        const struct json_value *host_pick =
            find_lifecycle_obj_str(host_incidents, "host", "203.0.113.42");
        ASSERT(host_pick && host_pick->type == JSON_OBJ);
        ASSERT(json_get_int(json_get(host_pick,
                                     "fast_sync_useful_connections")) == 1);

        const struct json_value *top =
            json_get(&incidents, "top_incidents");
        const struct json_value *fast =
            find_lifecycle_obj_str(top, "addr", "203.0.113.42:39030");
        ASSERT(fast && fast->type == JSON_OBJ);
        ASSERT(strcmp(json_get_str(json_get(fast, "bootstrap_readiness")),
                      "useful") == 0);
        ASSERT(strcmp(json_get_str(json_get(fast,
                                            "advertised_height_trust")),
                      "trusted") == 0);
        ASSERT(json_get_bool(json_get(fast, "advertised_height_trusted")));
        ASSERT(json_get_bool(json_get(fast, "bootstrap_useful")));
        ASSERT(json_get_bool(json_get(fast, "fast_sync_useful")));
        ASSERT(strstr(json_get_str(json_get(fast, "services_summary")),
                      "NODE_ZCL23") != NULL);
        json_free(&incidents);
    } TEST_END
    return failures;
}

static int test_peer_lifecycle_mixed_direction_host_view(void)
{
    int failures = 0;
    TEST_CASE("peer_lifecycle: host incident view names mixed directions")
    {
        struct p2p_node inbound;
        struct p2p_node outbound;
        struct json_value incidents;

        peer_lifecycle_reset_for_test();

        memset(&inbound, 0, sizeof(inbound));
        test_addr_ipv4(&inbound.addr, 203, 0, 113, 77, 45111);
        inbound.id = 351;
        inbound.inbound = true;
        inbound.state = PEER_HANDSHAKE_COMPLETE;
        inbound.services = NODE_NETWORK;
        snprintf(inbound.addr_name, sizeof(inbound.addr_name),
                 "203.0.113.77:45111");
        snprintf(inbound.sub_ver, sizeof(inbound.sub_ver),
                 "%s", "/MagicBean:2.1.2-beta6/");

        peer_lifecycle_note_connected(&inbound,
                                      PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_version_received(&inbound, inbound.services,
                                             3172101, inbound.sub_ver);
        peer_lifecycle_note_handshake_complete(&inbound);
        peer_lifecycle_note_active(&inbound);

        memset(&outbound, 0, sizeof(outbound));
        test_addr_ipv4(&outbound.addr, 203, 0, 113, 77, 8033);
        outbound.id = 352;
        outbound.state = PEER_HANDSHAKE_COMPLETE;
        outbound.services = NODE_NETWORK | NODE_ZCL23;
        snprintf(outbound.addr_name, sizeof(outbound.addr_name),
                 "203.0.113.77:8033");
        snprintf(outbound.sub_ver, sizeof(outbound.sub_ver),
                 "%s", msg_version_user_agent());

        peer_lifecycle_note_connected(&outbound,
                                      PEER_LIFECYCLE_SOURCE_MANUAL);
        peer_lifecycle_note_version_received(&outbound, outbound.services,
                                             3172102, outbound.sub_ver);
        peer_lifecycle_note_handshake_complete(&outbound);
        peer_lifecycle_note_active(&outbound);

        json_init(&incidents);
        ASSERT(peer_lifecycle_incidents_json(&incidents));
        const struct json_value *groups =
            json_get(&incidents, "duplicate_host_groups");
        const struct json_value *group =
            find_lifecycle_obj_str(groups, "host", "203.0.113.77");
        ASSERT(group && group->type == JSON_OBJ);
        ASSERT(strcmp(json_get_str(json_get(group, "direction")),
                      "mixed") == 0);
        ASSERT(json_get_bool(json_get(group, "mixed_direction")));
        ASSERT(strcmp(json_get_str(json_get(group,
                                            "current_open_direction")),
                      "mixed") == 0);
        ASSERT(json_get_bool(json_get(group,
                                      "current_open_mixed_direction")));
        ASSERT(strcmp(json_get_str(json_get(group,
                                            "current_handshaked_direction")),
                      "mixed") == 0);
        ASSERT(json_get_bool(json_get(group,
            "current_handshaked_mixed_direction")));
        ASSERT(json_get_int(json_get(group, "inbound_entries")) == 1);
        ASSERT(json_get_int(json_get(group, "outbound_entries")) == 1);
        ASSERT(json_get_int(json_get(group,
            "current_open_inbound_connections")) == 1);
        ASSERT(json_get_int(json_get(group,
            "current_open_outbound_connections")) == 1);
        ASSERT(json_get_int(json_get(group,
            "current_handshaked_inbound_connections")) == 1);
        ASSERT(json_get_int(json_get(group,
            "current_handshaked_outbound_connections")) == 1);
        ASSERT(json_get_int(json_get(group,
                                     "bootstrap_useful_connections")) == 2);
        ASSERT(json_get_int(json_get(group,
                                     "fast_sync_useful_connections")) == 1);

        const struct json_value *primary =
            json_get(&incidents, "primary_host_issue");
        ASSERT(primary && primary->type == JSON_OBJ);
        ASSERT(strcmp(json_get_str(json_get(primary, "host")),
                      "203.0.113.77") == 0);
        ASSERT(strcmp(json_get_str(json_get(primary, "direction")),
                      "mixed") == 0);
        ASSERT(json_get_bool(json_get(primary, "mixed_direction")));
        json_free(&incidents);
    } TEST_END
    return failures;
}

static int test_peer_lifecycle_host_readiness_reasons(void)
{
    int failures = 0;
    TEST_CASE("peer_lifecycle: host readiness names current blockers")
    {
        struct p2p_node first;
        struct p2p_node second;
        struct json_value incidents;

        peer_lifecycle_reset_for_test();
        memset(&first, 0, sizeof(first));
        test_addr_ipv4(&first.addr, 192, 0, 2, 21, 41001);
        first.id = 401;
        first.inbound = true;
        first.state = PEER_HANDSHAKE_COMPLETE;
        first.services = 0;
        snprintf(first.addr_name, sizeof(first.addr_name),
                 "192.0.2.21:41001");
        snprintf(first.sub_ver, sizeof(first.sub_ver),
                 "%s", "/MagicBean:2.1.2-beta6/");
        peer_lifecycle_note_connected(&first,
                                      PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_version_received(&first, first.services,
                                             3172093, first.sub_ver);
        peer_lifecycle_note_handshake_complete(&first);
        peer_lifecycle_note_active(&first);

        memset(&second, 0, sizeof(second));
        test_addr_ipv4(&second.addr, 192, 0, 2, 21, 41002);
        second.id = 402;
        second.inbound = true;
        second.state = PEER_HANDSHAKE_COMPLETE;
        second.services = 0;
        snprintf(second.addr_name, sizeof(second.addr_name),
                 "192.0.2.21:41002");
        snprintf(second.sub_ver, sizeof(second.sub_ver),
                 "%s", "/MagicBean:2.1.2-beta6/");
        peer_lifecycle_note_connected(&second,
                                      PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_version_received(&second, second.services,
                                             3172094, second.sub_ver);
        peer_lifecycle_note_handshake_complete(&second);
        peer_lifecycle_note_active(&second);

        json_init(&incidents);
        ASSERT(peer_lifecycle_incidents_json(&incidents));
        const struct json_value *groups =
            json_get(&incidents, "duplicate_host_groups");
        const struct json_value *missing =
            find_lifecycle_obj_str(groups, "host", "192.0.2.21");
        ASSERT(missing && missing->type == JSON_OBJ);
        ASSERT(strcmp(json_get_str(json_get(missing,
                                            "bootstrap_readiness")),
                      "missing_NODE_NETWORK") == 0);
        ASSERT(strcmp(json_get_str(json_get(missing,
                                            "fast_sync_readiness")),
                      "missing_NODE_NETWORK") == 0);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "bootstrap_readiness")),
                      "no_bootstrap_useful_peer") == 0);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "fast_sync_readiness")),
                      "no_bootstrap_useful_peer") == 0);
        ASSERT(json_get_bool(json_get(&incidents, "bootstrap_blocked")));
        ASSERT(json_get_bool(json_get(&incidents, "fast_sync_blocked")));
        ASSERT(json_get_bool(json_get(&incidents, "stability_blocker")));
        ASSERT(json_get_int(json_get(missing,
                                     "handshaked_network_connections")) == 0);
        ASSERT(json_get_int(json_get(missing,
            "handshaked_advertised_height_connections")) == 2);
        ASSERT(json_get_int(json_get(missing,
            "handshaked_trusted_advertised_height_connections")) == 0);
        ASSERT(json_get_int(json_get(missing,
            "handshaked_untrusted_advertised_height_connections")) == 2);
        ASSERT(strcmp(json_get_str(json_get(missing,
                                            "advertised_height_trust")),
                      "untrusted_missing_NODE_NETWORK") == 0);
        ASSERT(!json_get_bool(json_get(missing, "bootstrap_useful")));
        json_free(&incidents);

        peer_lifecycle_reset_for_test();
        memset(&first, 0, sizeof(first));
        test_addr_ipv4(&first.addr, 192, 0, 2, 22, 41001);
        first.id = 403;
        first.inbound = true;
        first.state = PEER_HANDSHAKE_COMPLETE;
        first.services = 0;
        snprintf(first.addr_name, sizeof(first.addr_name),
                 "192.0.2.22:41001");
        snprintf(first.sub_ver, sizeof(first.sub_ver),
                 "%s", msg_version_user_agent());
        peer_lifecycle_note_connected(&first,
                                      PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_version_received(&first, first.services,
                                             3172095, first.sub_ver);
        peer_lifecycle_note_handshake_complete(&first);
        peer_lifecycle_note_active(&first);

        memset(&second, 0, sizeof(second));
        test_addr_ipv4(&second.addr, 192, 0, 2, 22, 41002);
        second.id = 404;
        second.inbound = true;
        second.state = PEER_HANDSHAKE_COMPLETE;
        second.services = NODE_NETWORK;
        snprintf(second.addr_name, sizeof(second.addr_name),
                 "192.0.2.22:41002");
        snprintf(second.sub_ver, sizeof(second.sub_ver),
                 "%s", "/MagicBean:2.1.2-beta6/");
        peer_lifecycle_note_connected(&second,
                                      PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_version_received(&second, second.services,
                                             0, second.sub_ver);
        peer_lifecycle_note_handshake_complete(&second);
        peer_lifecycle_note_active(&second);

        json_init(&incidents);
        ASSERT(peer_lifecycle_incidents_json(&incidents));
        groups = json_get(&incidents, "duplicate_host_groups");
        const struct json_value *split =
            find_lifecycle_obj_str(groups, "host", "192.0.2.22");
        ASSERT(split && split->type == JSON_OBJ);
        ASSERT(strcmp(json_get_str(json_get(split,
                                            "bootstrap_readiness")),
                      "split_bootstrap_capabilities") == 0);
        ASSERT(strcmp(json_get_str(json_get(split,
                                            "fast_sync_readiness")),
                      "split_bootstrap_capabilities") == 0);
        ASSERT(json_get_int(json_get(split,
                                     "handshaked_network_connections")) == 1);
        ASSERT(json_get_int(json_get(split,
            "handshaked_advertised_height_connections")) == 1);
        ASSERT(json_get_int(json_get(split,
            "handshaked_trusted_advertised_height_connections")) == 0);
        ASSERT(json_get_int(json_get(split,
            "handshaked_untrusted_advertised_height_connections")) == 1);
        ASSERT(strcmp(json_get_str(json_get(split,
                                            "advertised_height_trust")),
                      "split_bootstrap_capabilities") == 0);
        ASSERT(json_get_int(json_get(split,
                                     "handshaked_zclassic23_connections"))
               == 1);
        ASSERT(!json_get_bool(json_get(split, "bootstrap_useful")));
        ASSERT(!json_get_bool(json_get(split, "fast_sync_useful")));
        json_free(&incidents);
    } TEST_END
    return failures;
}

static int test_peer_lifecycle_empty_incident_readiness(void)
{
    int failures = 0;
    TEST_CASE("peer_lifecycle: empty incident view names bootstrap blocker")
    {
        struct json_value incidents;

        peer_lifecycle_reset_for_test();
        json_init(&incidents);
        ASSERT(peer_lifecycle_incidents_json(&incidents));
        ASSERT(strcmp(json_get_str(json_get(&incidents, "schema")),
                      "zcl.peer_incidents.v2") == 0);
        ASSERT(json_get_int(json_get(&incidents, "incident_count")) == 0);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "bootstrap_readiness")),
                      "no_current_open_connection") == 0);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "fast_sync_readiness")),
                      "no_current_open_connection") == 0);
        ASSERT(json_get_bool(json_get(&incidents, "bootstrap_blocked")));
        ASSERT(json_get_bool(json_get(&incidents, "fast_sync_blocked")));
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "incident_severity")),
                      "ok") == 0);
        ASSERT(json_get_bool(json_get(&incidents, "stability_blocker")));
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "safe_next_action")),
                      "add_or_fix_bootstrap_peers") == 0);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "primary_issue_host")),
                      "") == 0);
        ASSERT(json_get_int(json_get(&incidents,
                                     "primary_issue_score")) == 0);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "primary_issue_class")),
                      "none") == 0);
        ASSERT(strcmp(json_get_str(json_get(&incidents,
                                            "primary_issue_next_action")),
                      "monitor_peer_lifecycle") == 0);
        json_free(&incidents);
    } TEST_END
    return failures;
}

int test_peer_lifecycle(void)
{
    int failures = 0;
    failures += test_peer_lifecycle_user_agent();
    failures += test_peer_lifecycle_classify();
    failures += test_peer_lifecycle_version_build();
    failures += test_peer_lifecycle_learns_inbound_advertised_addr();
    failures += test_peer_lifecycle_skips_inbound_ephemeral_cache();
    failures += test_peer_lifecycle_inbound_ephemeral_skip_is_not_incident();
    failures += test_peer_lifecycle_counters();
    failures += test_peer_lifecycle_terminal_idempotency();
    failures += test_peer_lifecycle_addr_lookup();
    failures += test_peer_lifecycle_inbound_source_bucket();
    failures += test_peer_lifecycle_duplicate_connect_duration();
    failures += test_peer_lifecycle_inbound_classifies_remote_version();
    failures += test_peer_lifecycle_incident_view();
    failures += test_peer_lifecycle_duplicate_current_bootstrap_view();
    failures += test_peer_lifecycle_mixed_direction_host_view();
    failures += test_peer_lifecycle_host_readiness_reasons();
    failures += test_peer_lifecycle_empty_incident_readiness();

    return failures;
}

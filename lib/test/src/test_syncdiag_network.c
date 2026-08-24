/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * getnetworkinfo / peerincidents / bootstrapstatus cases: reachability schema, external endpoint, duplicate-host telemetry, and the versioned P2P + snapshot-authority posture.
 */

#include "test/syncdiag_rpc_fixture.h"
#include "net/onion_stream.h"

int syncdiag_cases_network(void)
{
    int failures = 0;

    printf("onionstatus: exposes one coherent bootstrap-state contract... ");
    {
        struct rpc_table tbl;
        struct json_value params;
        struct json_value result;

        rpc_table_init(&tbl);
        register_net_rpc_commands(&tbl);
        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        bool ok = rpc_table_execute(&tbl, "onionstatus", &params, &result);
        const struct json_value *state = json_get(&result,
                                                   "bootstrap_state");
        const struct json_value *tor_ready = json_get(&result, "tor_ready");
        const struct json_value *service_ready =
            json_get(&result, "onion_service_ready");
        const struct json_value *address = json_get(&result,
                                                     "onion_address");
        const struct json_value *p2p_ready = json_get(
            &result, "p2p_publish_ready");
        const struct json_value *setup_state = json_get(&result,
                                                        "setup_state");
        const struct json_value *mapping = json_get(&result,
                                                     "port_mapping");
        const struct json_value *routes = mapping
            ? json_get(mapping, "routes") : NULL;
        const struct json_value *streams = json_get(&result,
                                                     "outbound_streams");
        const struct json_value *handshake = json_get(&result,
                                                       "p2p_handshake");
        const struct json_value *recent_dials = json_get(&result,
                                                          "recent_dials");

        ok = ok && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.onion_status.v1") == 0;
        ok = ok && state && state->type == JSON_STR;
        ok = ok && tor_ready && tor_ready->type == JSON_BOOL;
        ok = ok && service_ready && service_ready->type == JSON_BOOL;
        ok = ok && address && address->type == JSON_STR;
        ok = ok && p2p_ready && p2p_ready->type == JSON_BOOL;
        ok = ok && setup_state && setup_state->type == JSON_STR;
        ok = ok && mapping && mapping->type == JSON_OBJ;
        ok = ok && json_get(mapping, "state") != NULL;
        ok = ok && json_get(mapping, "complete") != NULL;
        ok = ok && json_get(mapping, "expected_route_count") != NULL;
        ok = ok && json_get(mapping, "installed_route_count") != NULL;
        ok = ok && routes && routes->type == JSON_ARR;
        ok = ok && routes && json_size(routes) == 2;
        ok = ok && streams && streams->type == JSON_OBJ;
        ok = ok &&
             strcmp(json_get_str(json_get(streams, "schema")),
                    "zcl.onion_stream_stages.v1") == 0;
        static const char *stream_counts[] = {
            "dial_started", "stream_queued", "circuit_ready", "bridge_up",
            "open_refused", "circuit_timeout", "circuit_torn_down",
            "bridge_closed", "bytes_to_peer", "bytes_from_peer",
            "peers_answered",
        };
        for (size_t i = 0;
             ok && i < sizeof(stream_counts) / sizeof(stream_counts[0]); i++) {
            const struct json_value *count = json_get(streams,
                                                       stream_counts[i]);
            ok = count && count->type == JSON_INT && json_get_int(count) >= 0;
        }
        ok = ok && handshake && handshake->type == JSON_OBJ;
        ok = ok && recent_dials && recent_dials->type == JSON_ARR;
        ok = ok && recent_dials && json_size(recent_dials) == 0;
        ok = ok &&
             strcmp(json_get_str(json_get(handshake, "schema")),
                    "zcl.onion_handshake_stages.v1") == 0;
        ok = ok &&
             strcmp(json_get_str(json_get(handshake,
                                           "first_incomplete_stage")),
                    "tor_disabled") == 0;
        static const char *handshake_counts[] = {
            "attempted", "connected", "version_sent", "version_received",
            "verack_received", "handshake_complete",
            "pre_handshake_disconnects",
        };
        for (size_t i = 0;
             ok && i < sizeof(handshake_counts) /
                        sizeof(handshake_counts[0]); i++) {
            const struct json_value *count = json_get(
                handshake, handshake_counts[i]);
            ok = count && count->type == JSON_INT && json_get_int(count) >= 0;
        }
        struct onion_stream_stages stream = {0};
        struct peer_lifecycle_summary peer = {0};
        ok = ok && strcmp(network_onion_first_incomplete_stage(
                              true, true, NULL, &peer),
                          "invalid_snapshot") == 0;
        ok = ok && strcmp(network_onion_first_incomplete_stage(
                              false, false, &stream, &peer),
                          "tor_disabled") == 0;
        ok = ok && strcmp(network_onion_first_incomplete_stage(
                              true, false, &stream, &peer),
                          "tor_dial_not_ready") == 0;
        stream.dial_started = 1;
        stream.stream_queued = 1;
        stream.circuit_ready = 1;
        stream.bridge_up = 1;
        stream.bytes_to_peer = 1;
        peer.connected = 1;
        peer.version_sent = 1;
        ok = ok && strcmp(network_onion_first_incomplete_stage(
                              true, true, &stream, &peer),
                          "p2p_bytes_not_received") == 0;
        stream.bytes_from_peer = 1;
        ok = ok && strcmp(network_onion_first_incomplete_stage(
                              true, true, &stream, &peer),
                          "version_not_received") == 0;
        peer.version_received = 1;
        ok = ok && strcmp(network_onion_first_incomplete_stage(
                              true, true, &stream, &peer),
                          "verack_not_received") == 0;
        peer.verack_received = 1;
        ok = ok && strcmp(network_onion_first_incomplete_stage(
                              true, true, &stream, &peer),
                          "handshake_not_complete") == 0;
        peer.handshake_complete = 1;
        ok = ok && strcmp(network_onion_first_incomplete_stage(
                              true, true, &stream, &peer),
                          "complete") == 0;
        if (ok && strcmp(json_get_str(state), "ready") == 0) {
            const char *hostname = json_get_str(address);
            size_t hostname_len = strlen(hostname);
            ok = json_get_bool(tor_ready) && json_get_bool(service_ready) &&
                 hostname_len > 6 &&
                 strcmp(hostname + hostname_len - 6, ".onion") == 0;
        }

        json_free(&params);
        json_free(&result);
        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("getnetworkinfo: reports stable startup reachability schema "
           "(RED)... ");
    {
        struct rpc_table tbl;
        struct json_value params;
        struct json_value result;

        rpc_table_init(&tbl);
        register_net_rpc_commands(&tbl);
        rpc_net_set_connman(NULL);

        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        bool ok = rpc_table_execute(&tbl, "getnetworkinfo",
                                    &params, &result);

        const struct json_value *inbound =
            json_get(&result, "inbound_connections");
        const struct json_value *outbound =
            json_get(&result, "outbound_connections");
        const struct json_value *handshaked =
            json_get(&result, "handshaked_connections");
        const struct json_value *inbound_hs =
            json_get(&result, "inbound_handshaked_connections");
        const struct json_value *outbound_hs =
            json_get(&result, "outbound_handshaked_connections");
        const struct json_value *listen_count =
            json_get(&result, "listen_socket_count");
        const struct json_value *listening =
            json_get(&result, "listening");
        const struct json_value *inbound_seen =
            json_get(&result, "inbound_handshake_seen");
        const struct json_value *remote_seen =
            json_get(&result, "remote_handshake_seen");
        const struct json_value *life =
            json_get(&result, "peer_lifecycle");
        const struct json_value *life_sources =
            life ? json_get(life, "sources") : NULL;
        const struct json_value *addnodes =
            json_get(&result, "addnode_status");

        ok = ok && result.type == JSON_OBJ;
        ok = ok && inbound && json_get_int(inbound) == 0;
        ok = ok && outbound && json_get_int(outbound) == 0;
        ok = ok && handshaked && json_get_int(handshaked) == 0;
        ok = ok && inbound_hs && json_get_int(inbound_hs) == 0;
        ok = ok && outbound_hs && json_get_int(outbound_hs) == 0;
        ok = ok && listen_count && json_get_int(listen_count) == 0;
        ok = ok && listening && !json_get_bool(listening);
        ok = ok && inbound_seen && !json_get_bool(inbound_seen);
        ok = ok && remote_seen && !json_get_bool(remote_seen);
        ok = ok && life && life->type == JSON_OBJ;
        ok = ok && life && json_get(life, "attempted") != NULL;
        ok = ok && life && json_get(life, "connected") != NULL;
        ok = ok && life && json_get(life, "version_sent") != NULL;
        ok = ok && life && json_get(life, "version_received") != NULL;
        ok = ok && life && json_get(life, "verack_received") != NULL;
        ok = ok && life && json_get(life, "handshake_complete") != NULL;
        ok = ok && life && json_get(life, "active") != NULL;
        ok = ok && life && json_get(life, "disconnected") != NULL;
        ok = ok && life && json_get(life, "timeout") != NULL;
        ok = ok && life && json_get(life, "rejected") != NULL;
        ok = ok && life && json_get(life, "cache_skipped") != NULL;
        ok = ok && life && json_get(life, "magicbean_handshakes") != NULL;
        ok = ok && life && json_get(life, "zclassic23_handshakes") != NULL;
        ok = ok && life && json_get(life, "zclassic_c23_handshakes") != NULL;
        ok = ok && life_sources && life_sources->type == JSON_ARR;
        ok = ok && addnodes && addnodes->type == JSON_ARR;
        ok = ok && json_size(addnodes) == 0;
        ok = ok && find_source_json(life_sources, "unknown") != NULL;
        ok = ok && find_source_json(life_sources, "inbound") != NULL;
        ok = ok && find_source_json(life_sources, "addnode") != NULL;
        ok = ok && find_source_json(life_sources, "addrman") != NULL;
        ok = ok && find_source_json(life_sources, "zcl23_db") != NULL;
        ok = ok && find_source_json(life_sources, "manual") != NULL;

        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("peerincidents: exposes compact duplicate host telemetry "
           "(RED)... ");
    {
        struct rpc_table tbl;
        struct json_value params;
        struct json_value result;
        struct p2p_node zigma_a;
        struct p2p_node zigma_b;

        peer_lifecycle_reset_for_test();
        memset(&zigma_a, 0, sizeof(zigma_a));
        syncdiag_set_ipv4(&zigma_a.addr, 40, 160, 53, 56, 45474);
        zigma_a.id = 7701;
        zigma_a.inbound = true;
        zigma_a.state = PEER_HANDSHAKE_COMPLETE;
        zigma_a.services = NODE_NETWORK;
        snprintf(zigma_a.addr_name, sizeof(zigma_a.addr_name),
                 "40.160.53.56:45474");
        snprintf(zigma_a.sub_ver, sizeof(zigma_a.sub_ver),
                 "%s", "/Zigma:0.1.0/");

        memset(&zigma_b, 0, sizeof(zigma_b));
        syncdiag_set_ipv4(&zigma_b.addr, 40, 160, 53, 56, 39030);
        zigma_b.id = 7702;
        zigma_b.inbound = true;
        zigma_b.state = PEER_HANDSHAKE_COMPLETE;
        zigma_b.services = NODE_NETWORK;
        snprintf(zigma_b.addr_name, sizeof(zigma_b.addr_name),
                 "40.160.53.56:39030");
        snprintf(zigma_b.sub_ver, sizeof(zigma_b.sub_ver),
                 "%s", "/Zigma:0.1.0/");

        peer_lifecycle_note_connected(&zigma_a,
                                      PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_version_received(&zigma_a, zigma_a.services,
                                             3172229, zigma_a.sub_ver);
        peer_lifecycle_note_handshake_complete(&zigma_a);
        peer_lifecycle_note_active(&zigma_a);

        peer_lifecycle_note_connected(&zigma_b,
                                      PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_version_received(&zigma_b, zigma_b.services,
                                             3172230, zigma_b.sub_ver);
        peer_lifecycle_note_handshake_complete(&zigma_b);
        peer_lifecycle_note_active(&zigma_b);

        rpc_table_init(&tbl);
        register_net_rpc_commands(&tbl);
        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        bool ok = rpc_table_execute(&tbl, "peerincidents",
                                    &params, &result);
        const struct json_value *primary =
            json_get(&result, "primary_host_issue");
        const struct json_value *hosts =
            json_get(&result, "duplicate_host_groups");
        const struct json_value *top_hosts =
            json_get(&result, "top_host_incidents");
        ok = ok && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.peer_incidents.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "method")),
                          "peerincidents") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "native_command")),
                          "z23 peerincidents") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "contract_source")),
                          "agent_contracts.def") == 0;
        ok = ok && json_get_bool(json_get(&result, "bounded"));
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "bootstrap_readiness")),
                          "ready") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "fast_sync_readiness")),
                          "no_zclassic23_fast_sync_peer") == 0;
        ok = ok && !json_get_bool(json_get(&result,
                                           "bootstrap_blocked"));
        ok = ok && json_get_bool(json_get(&result,
                                          "fast_sync_blocked"));
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "incident_severity")),
                          "attention") == 0;
        ok = ok && json_get_bool(json_get(&result,
                                          "stability_blocker"));
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "primary_issue_host")),
                          "40.160.53.56") == 0;
        ok = ok && json_get_int(json_get(&result,
                                         "primary_issue_score")) > 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "primary_issue_class")),
                          "duplicate_handshaked_connections") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "primary_issue_next_action")),
                          "inspect_duplicate_current_connections_for_host")
            == 0;
        ok = ok && json_get_int(json_get(&result,
                         "duplicate_host_group_count")) == 1;
        ok = ok && json_get_int(json_get(&result,
                         "duplicate_open_host_group_count")) == 1;
        ok = ok && json_get_int(json_get(&result,
                         "duplicate_handshaked_host_group_count")) == 1;
        ok = ok && primary && primary->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(primary, "host")),
                          "40.160.53.56") == 0;
        ok = ok && json_get_bool(json_get(primary,
                                          "duplicate_current_connections"));
        ok = ok && json_get_bool(json_get(primary,
                                          "bootstrap_useful"));
        ok = ok && hosts && hosts->type == JSON_ARR;
        ok = ok && json_size(hosts) == 1;
        ok = ok && top_hosts && top_hosts->type == JSON_ARR;
        ok = ok && json_size(top_hosts) == 1;

        json_free(&params);
        json_free(&result);
        peer_lifecycle_reset_for_test();

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("peerincidents: normalizes dumpstate compatibility fallback "
           "(RED)... ");
    {
        struct json_value state;
        struct json_value dumpstate;
        struct json_value result;

        peer_lifecycle_reset_for_test();
        json_init(&state);
        json_init(&dumpstate);
        json_init(&result);
        bool ok = peer_lifecycle_incidents_json(&state);
        json_set_object(&dumpstate);
        json_push_kv_str(&dumpstate, "subsystem", "peer_lifecycle");
        json_push_kv_str(&dumpstate, "description", "fixture");
        json_push_kv(&dumpstate, "state", &state);
        ok = ok && peer_incidents_from_dumpstate_result_json(
            &dumpstate, &result, "target_peerincidents_method_not_found");
        ok = ok && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.peer_incidents.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "method")),
                          "peerincidents") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "native_command")),
                          "z23 peerincidents") == 0;
        ok = ok && json_get_bool(json_get(&result,
                                          "compatibility_fallback"));
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "compatibility_source")),
                          "dumpstate peer_lifecycle incidents") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "compatibility_reason")),
                          "target_peerincidents_method_not_found") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "fallback_native_command")),
                          "z23 dumpstate peer_lifecycle incidents")
            == 0;

        json_free(&result);
        json_free(&dumpstate);
        json_free(&state);
        peer_lifecycle_reset_for_test();

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("getnetworkinfo: exposes configured external endpoint "
           "(RED)... ");
    {
        struct rpc_table tbl;
        struct json_value params;
        struct json_value result;

        msg_version_clear_external_ip_for_test();
        msg_version_set_external_ip("203.0.113.7:8023", 8033);
        rpc_table_init(&tbl);
        register_net_rpc_commands(&tbl);
        rpc_net_set_connman(NULL);

        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        bool ok = rpc_table_execute(&tbl, "getnetworkinfo",
                                    &params, &result);

        const struct json_value *localaddrs =
            json_get(&result, "localaddresses");
        const struct json_value *first =
            localaddrs && localaddrs->type == JSON_ARR
                ? json_at(localaddrs, 0)
                : NULL;
        ok = ok && result.type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(&result,
                                          "externalip_configured"));
        ok = ok && localaddrs && localaddrs->type == JSON_ARR;
        ok = ok && json_size(localaddrs) == 1;
        ok = ok && first && strcmp(json_get_str(json_get(first, "address")),
                                   "203.0.113.7") == 0;
        ok = ok && first &&
             json_get_int(json_get(first, "port")) == 8023;
        ok = ok && first &&
             json_get_int(json_get(first, "score")) == 1;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "advertised_subver")),
                          msg_version_user_agent()) == 0;

        json_free(&params);
        json_free(&result);
        rpc_net_set_connman(NULL);
        msg_version_clear_external_ip_for_test();

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("bootstrapstatus: exposes versioned P2P and beta6 "
           "snapshot contract (RED)... ");
    {
        progress_store_close();
        struct connman cm;
        struct node_signals sigs;
        struct rpc_table tbl;
        struct json_value params = {0};
        struct json_value result = {0};
        char tmp_template[] = "/tmp/zcl-bootstrapstatus-XXXXXX";
        char *tmp_dir = mkdtemp(tmp_template);
        char snap_path[512] = {0};
        char index_path[512] = {0};
        int snap_n = tmp_dir ? snprintf(snap_path, sizeof(snap_path),
                                        "%s/utxo-seed-3170000.snapshot",
                                        tmp_dir) : -1;
        int index_n = tmp_dir ? snprintf(index_path, sizeof(index_path),
                                         "%s/block_index.bin", tmp_dir) : -1;

        chain_params_select(CHAIN_MAIN);
        memset(&cm, 0, sizeof(cm));
        memset(&sigs, 0, sizeof(sigs));
        bool ok = tmp_dir != NULL &&
                  snap_n > 0 && (size_t)snap_n < sizeof(snap_path) &&
                  index_n > 0 && (size_t)index_n < sizeof(index_path);
        ok = ok && syncdiag_touch_file(snap_path);
        ok = ok && syncdiag_touch_file(index_path);
        ok = ok && connman_init(&cm, chain_params_get(), &sigs);
        if (ok) {
            cm.manager.listen_sockets =
                zcl_calloc(1, sizeof(*cm.manager.listen_sockets),
                           "syncdiag_listen_socket");
            ok = cm.manager.listen_sockets != NULL;
        }
        if (ok) {
            cm.manager.listen_sockets[0].socket = ZCL_INVALID_SOCKET;
            cm.manager.num_listen_sockets = 1;
            cm.manager.listen_sockets_cap = 1;
        }
        reducer_frontier_provable_tip_set(3170000);
        msg_version_clear_external_ip_for_test();
        msg_version_set_external_ip("203.0.113.7:8033", 8033);

        if (ok) {
            struct net_address addr;
            struct net_addr src;
            syncdiag_set_ipv4(&addr, 8, 8, 8, 8, 8033);
            addr.nServices = NODE_NETWORK;
            net_addr_init(&src);
            unsigned char src_ip[4] = {1, 2, 3, 4};
            net_addr_set_ipv4(&src, src_ip);
            ok = addrman_add(&cm.manager.addrman, &addr, &src, 0);
        }

        struct p2p_node *zcl_a = ok
            ? syncdiag_add_peer(&cm, 21, false, PEER_HANDSHAKE_COMPLETE)
            : NULL;
        struct p2p_node *zcl_b = ok
            ? syncdiag_add_peer(&cm, 22, true, PEER_HANDSHAKE_COMPLETE)
            : NULL;
        struct p2p_node *zcl_b_dup = ok
            ? syncdiag_add_peer(&cm, 22, false, PEER_HANDSHAKE_COMPLETE)
            : NULL;
        struct p2p_node *legacy_peer = ok
            ? syncdiag_add_peer(&cm, 23, false, PEER_HANDSHAKE_COMPLETE)
            : NULL;
        struct p2p_node *self_hairpin = ok
            ? syncdiag_add_peer(&cm, 24, true, PEER_HANDSHAKE_COMPLETE)
            : NULL;
        ok = ok && zcl_a && zcl_b && zcl_b_dup && legacy_peer &&
             self_hairpin;
        if (ok) {
            snprintf(zcl_a->addr_name, sizeof(zcl_a->addr_name),
                     "198.51.100.21:8033");
            zcl_a->starting_height = 3170000;
            syncdiag_note_peer_lifecycle_active(
                zcl_a, PEER_LIFECYCLE_SOURCE_ADDNODE);

            snprintf(zcl_b->addr_name, sizeof(zcl_b->addr_name),
                     "198.51.100.22:8033");
            zcl_b->starting_height = 3169999;
            syncdiag_note_peer_lifecycle_active(
                zcl_b, PEER_LIFECYCLE_SOURCE_INBOUND);

            syncdiag_set_ipv4(&zcl_b_dup->addr, 198, 51, 100, 22, 8033);
            snprintf(zcl_b_dup->addr_name, sizeof(zcl_b_dup->addr_name),
                     "198.51.100.22:8033");
            zcl_b_dup->starting_height = 3170000;
            syncdiag_note_peer_lifecycle_active(
                zcl_b_dup, PEER_LIFECYCLE_SOURCE_ADDRMAN);

            legacy_peer->services = NODE_NETWORK;
            snprintf(legacy_peer->addr_name,
                     sizeof(legacy_peer->addr_name),
                     "198.51.100.23:8033");
            snprintf(legacy_peer->sub_ver, sizeof(legacy_peer->sub_ver),
                     "%s", "/MagicBean:2.1.2-beta6/");
            snprintf(legacy_peer->clean_sub_ver,
                     sizeof(legacy_peer->clean_sub_ver),
                     "%s", legacy_peer->sub_ver);
            legacy_peer->starting_height = 3170000;
            syncdiag_note_peer_lifecycle_active(
                legacy_peer, PEER_LIFECYCLE_SOURCE_ADDRMAN);

            snprintf(self_hairpin->addr_name,
                     sizeof(self_hairpin->addr_name),
                     "203.0.113.7:49152");
            self_hairpin->starting_height = 3170000;
            syncdiag_note_peer_lifecycle_active(
                self_hairpin, PEER_LIFECYCLE_SOURCE_INBOUND);
        }

        rpc_table_init(&tbl);
        register_net_rpc_commands(&tbl);
        rpc_net_set_connman(&cm);
        rpc_net_set_boot_context(tmp_dir, snap_path);

        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "bootstrapstatus",
                                     &params, &result);

        ok = ok && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.bootstrap_status.v1") == 0;
        ok = ok && json_get_int(json_get(&result,
                                          "schema_version")) == 1;
        ok = ok && json_get_bool(json_get(&result,
                                          "serving_p2p_bootstrap"));
        ok = ok && json_get_bool(json_get(&result,
                                          "serving_addr_bootstrap"));
        ok = ok && !json_get_bool(json_get(&result,
                                           "serving_snapshot_bootstrap"));
        ok = ok && strcmp(json_get_str(json_get(&result, "readiness")),
                          "ready_p2p_and_addr") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
            "fresh_node_next_action")),
                          "connect_direct_p2p_and_request_headers_blocks") == 0;
        ok = ok && json_get_bool(json_get(&result,
                                          "zclassic23_fast_sync_compatible"));
        ok = ok && json_get_bool(json_get(&result,
            "zclassicd_beta6_p2p_compatible"));
        ok = ok && !json_get_bool(json_get(&result,
            "zclassicd_beta6_fast_bootstrap_compatible"));

        const struct json_value *p2p = json_get(&result, "p2p");
        ok = ok && p2p && p2p->type == JSON_OBJ;
        ok = ok && json_get_int(json_get(p2p, "protocolversion")) ==
                  PROTOCOL_VERSION;
        ok = ok && json_get_int(json_get(p2p,
                                          "minimum_peer_protocol")) ==
                  MIN_PEER_PROTO_VERSION;
        ok = ok && json_get_bool(json_get(p2p, "node_network"));
        ok = ok && json_get_bool(json_get(p2p, "node_zclassic23"));
        ok = ok && !json_get_bool(json_get(p2p, "node_bootstrap"));
        ok = ok && json_get_int(json_get(p2p,
                                          "advertised_start_height")) ==
                  3170000;

        const struct json_value *peers = json_get(&result, "peers");
        const struct json_value *verified =
            peers ? json_get(peers,
                "verified_zclassic23_bootstrap_peers") : NULL;
        const struct json_value *first_verified =
            verified && json_size(verified) > 0 ? json_at(verified, 0) : NULL;
        ok = ok && peers && peers->type == JSON_OBJ;
        ok = ok && json_get_int(json_get(peers, "connections")) == 5;
        ok = ok && json_get_int(json_get(peers,
            "zclassic23_peers")) == 2;
        ok = ok && json_get_int(json_get(peers,
            "zclassic23_peer_connections")) == 3;
        ok = ok && json_get_int(json_get(peers,
            "zclassic23_duplicate_connections_excluded")) == 1;
        ok = ok && json_get_int(json_get(peers,
            "zclassic23_self_connections_excluded")) == 1;
        ok = ok && json_get_bool(json_get(peers,
            "local_zclassic23_node_included"));
        ok = ok && json_get_int(json_get(peers,
            "zclassic23_nodes_seen")) == 3;
        ok = ok && json_get_bool(json_get(peers,
            "zclassic23_two_node_floor_met"));
        ok = ok && json_get_bool(json_get(peers,
            "local_zclassic23_bootstrap_node_verified"));
        ok = ok && json_get_int(json_get(peers,
            "verified_zclassic23_bootstrap_nodes_seen")) == 3;
        ok = ok && json_get_bool(json_get(peers,
            "verified_zclassic23_two_node_floor_met"));
        ok = ok && json_get_int(json_get(peers,
            "legacy_compatible_peers")) == 1;
        ok = ok && json_get_int(json_get(peers,
            "verified_zclassic23_bootstrap_peer_count")) == 2;
        ok = ok && json_get_int(json_get(peers,
            "verified_zclassic23_bootstrap_connection_count")) == 3;
        ok = ok && json_get_int(json_get(peers,
            "verified_zclassic23_duplicate_connections_excluded")) == 1;
        ok = ok && json_get_int(json_get(peers,
            "verified_zclassic23_self_connections_excluded")) == 1;
        ok = ok && json_get_int(json_get(peers,
            "fast_sync_useful_zclassic23_peer_count")) == 2;
        ok = ok && json_get_int(json_get(peers,
            "fast_sync_useful_zclassic23_connection_count")) == 3;
        ok = ok && json_get_int(json_get(peers,
            "zclassic23_bootstrap_quorum_target")) == 2;
        ok = ok && json_get_bool(json_get(peers,
            "zclassic23_bootstrap_quorum_met"));
        ok = ok && json_get_bool(json_get(peers,
            "zclassic23_fast_sync_quorum_met"));
        ok = ok && strcmp(json_get_str(json_get(peers,
            "zclassic23_bootstrap_quorum_status")),
                          "redundant") == 0;
        ok = ok && verified && verified->type == JSON_ARR;
        ok = ok && json_size(verified) == 2;
        ok = ok && first_verified && first_verified->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(first_verified,
            "verified_by")), "live_handshake") == 0;
        ok = ok && json_get_bool(json_get(first_verified,
            "bootstrap_useful"));
        ok = ok && json_get_bool(json_get(first_verified,
            "fast_sync_useful"));
        ok = ok && strcmp(json_get_str(json_get(first_verified,
            "bootstrap_readiness")), "useful") == 0;

        const struct json_value *addrman = json_get(&result, "addrman");
        ok = ok && addrman && addrman->type == JSON_OBJ;
        ok = ok && json_get_int(json_get(addrman, "entries")) == 1;
        ok = ok && json_get_bool(json_get(addrman,
                                          "addr_relay_ready"));

        const struct json_value *zcl23 =
            json_get(&result, "zclassic23_bootstrap");
        ok = ok && zcl23 && zcl23->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(zcl23, "schema")),
                          "zcl.bootstrap.zclassic23.v1") == 0;
        ok = ok && json_get_bool(json_get(zcl23, "serving"));
        ok = ok && json_get_bool(json_get(zcl23,
            "preferred_for_fresh_zclassic23"));
        ok = ok && json_get_bool(json_get(zcl23, "full_node_bootstrap"));
        ok = ok && json_get_bool(json_get(zcl23, "addr_relay_ready"));
        ok = ok && strcmp(json_get_str(json_get(zcl23,
            "route_preference")),
                          "direct_p2p_then_znam_onion_fallback") == 0;
        ok = ok && strcmp(json_get_str(json_get(zcl23,
            "endpoint_record_schema")),
                          "zcl.names.service_record.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(zcl23,
            "clearnet_address")), "203.0.113.7") == 0;
        ok = ok && json_get_int(json_get(zcl23, "p2p_port")) == 8033;
        ok = ok && json_array_has_str(json_get(zcl23,
            "fresh_node_flow"), "fallback_to_onion_endpoint");

        const struct json_value *loader =
            json_get(&result, "snapshot_loader");
        ok = ok && loader && loader->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(loader, "schema")),
                          "zcl.snapshot_loader.v1") == 0;
        ok = ok && json_get_int(json_get(loader, "schema_version")) == 1;
        ok = ok && json_get_bool(json_get(loader, "bundle_present"));
        ok = ok && json_get_int(json_get(loader,
                                         "bundle_seed_height")) == 3170000;
        ok = ok && strcmp(json_get_str(json_get(loader, "bundle_path")),
                          snap_path) == 0;
        ok = ok && json_get_bool(json_get(loader,
                                          "block_index_present"));
        ok = ok && json_get_bool(json_get(loader, "bootable_bundle"));
        ok = ok && json_get_bool(json_get(loader,
            "active_loader_configured"));
        ok = ok && strcmp(json_get_str(json_get(loader,
            "active_loader_path")), snap_path) == 0;
        ok = ok && json_get_bool(json_get(loader,
            "active_loader_matches_bundle"));
        ok = ok && strcmp(json_get_str(json_get(loader,
            "recovery_hint")), "loader_active") == 0;
        const struct json_value *authority = json_get(loader, "authority");
        ok = ok && authority && authority->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(authority, "schema")),
                          "zcl.snapshot_loader_authority.v1") == 0;
        ok = ok && !json_get_bool(json_get(authority,
                                           "progress_store_open"));
        ok = ok && !json_get_bool(json_get(authority,
                                           "coins_kv_proven_authority"));
        ok = ok && !json_get_bool(json_get(authority,
                                           "fast_rebuild_authority_ready"));
        ok = ok && strcmp(json_get_str(json_get(authority,
            "authority_posture")), "unknown_no_progress_store") == 0;

        const struct json_value *legacy =
            json_get(&result, "legacy_p2p_bootstrap");
        ok = ok && legacy && legacy->type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(legacy, "serving"));
        ok = ok && json_array_has_str(json_get(legacy, "messages"),
                                      "getheaders");
        ok = ok && json_array_has_str(json_get(legacy, "messages"),
                                      "getaddr");

        const struct json_value *beta6 =
            json_get(&result, "beta6_snapshot_bootstrap");
        ok = ok && beta6 && beta6->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(beta6,
                                                "required_service_bit")),
                          "NODE_BOOTSTRAP") == 0;
        ok = ok && json_get_int(json_get(beta6,
                                          "required_service_bit_value")) ==
                  NODE_BOOTSTRAP;
        ok = ok && !json_get_bool(json_get(beta6, "advertised"));
        ok = ok && !json_get_bool(json_get(beta6, "serving"));
        ok = ok && json_array_has_str(json_get(beta6, "messages"),
                                      "getbsman");
        ok = ok && json_array_has_str(json_get(beta6, "messages"),
                                      "getbschk");

        ok = ok && json_array_has_str(json_get(&result, "blockers"),
                                      "beta6_NODE_BOOTSTRAP_not_advertised");

        /* A transport-ready, tip-published node must still refuse every
         * serving/readiness claim while security posture requires review. */
        agent_security_posture_test_override_review_required(1);
        json_free(&result);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "bootstrapstatus",
                                     &params, &result);
        zcl23 = json_get(&result, "zclassic23_bootstrap");
        legacy = json_get(&result, "legacy_p2p_bootstrap");
        ok = ok && !json_get_bool(json_get(&result, "ok"));
        ok = ok && json_get_bool(json_get(&result, "transport_ready"));
        ok = ok && json_get_bool(json_get(
            &result, "security_review_required"));
        ok = ok && !json_get_bool(json_get(
            &result, "security_posture_ok"));
        ok = ok && strcmp(json_get_str(json_get(
            &result, "security_posture_status")),
            "review_required_test") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "readiness")),
                          "blocked") == 0;
        ok = ok && !json_get_bool(json_get(
            &result, "serving_p2p_bootstrap"));
        ok = ok && !json_get_bool(json_get(
            &result, "serving_addr_bootstrap"));
        ok = ok && !json_get_bool(json_get(
            &result, "zclassic23_fast_sync_compatible"));
        ok = ok && zcl23 && !json_get_bool(json_get(zcl23, "serving"));
        ok = ok && legacy && !json_get_bool(json_get(legacy, "serving"));
        ok = ok && json_array_has_str(json_get(&result, "blockers"),
                                      "review_required_test");
        agent_security_posture_test_override_review_required(0);

        ok = ok && unlink(index_path) == 0;
        rpc_net_set_boot_context(tmp_dir, NULL);
        json_free(&result);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "bootstrapstatus",
                                     &params, &result);
        loader = json_get(&result, "snapshot_loader");
        ok = ok && loader && loader->type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(loader, "bundle_present"));
        ok = ok && !json_get_bool(json_get(loader,
                                           "block_index_present"));
        ok = ok && !json_get_bool(json_get(loader, "bootable_bundle"));
        ok = ok && !json_get_bool(json_get(loader,
            "active_loader_configured"));
        ok = ok && strcmp(json_get_str(json_get(loader,
            "recovery_hint")), "install_tip_seed_snapshot") == 0;

        json_free(&params);
        json_free(&result);
        rpc_net_set_connman(NULL);
        rpc_net_set_boot_context(NULL, NULL);
        msg_version_clear_external_ip_for_test();
        reducer_frontier_provable_tip_reset();
        connman_free(&cm);
        if (tmp_dir) {
            unlink(snap_path);
            unlink(index_path);
            rmdir(tmp_dir);
        }

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("bootstrapstatus: exposes snapshot authority posture (RED)... ");
    {
        test_reset_shared_globals();
        progress_store_close();
        chain_params_select(CHAIN_MAIN);

        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "syncdiag", "bootstrap_authority");

        struct rpc_table tbl;
        struct json_value params = {0};
        struct json_value result = {0};
        sqlite3 *pdb = NULL;
        uint8_t txid[32] = {0};
        const uint8_t one = 0x01;
        bool ok = progress_store_open(dir);
        if (ok)
            pdb = progress_store_db();
        if (ok) {
            memset(txid, 0xB7, sizeof(txid));
            ok = pdb &&
                 coins_kv_ensure_schema(pdb) &&
                 syncdiag_seed_reducer_frontier_at_anchor(
                     pdb, REDUCER_FRONTIER_TRUSTED_ANCHOR) &&
                 coins_kv_add(pdb, txid, 0, 5000000000LL,
                              REDUCER_FRONTIER_TRUSTED_ANCHOR, true,
                              NULL, 0) &&
                 syncdiag_set_coins_applied(
                     pdb, REDUCER_FRONTIER_TRUSTED_ANCHOR + 1) &&
                 progress_meta_set(pdb, COINS_KV_MIGRATION_COMPLETE_KEY,
                                   &one, sizeof(one));
        }

        rpc_table_init(&tbl);
        register_net_rpc_commands(&tbl);
        rpc_net_set_connman(NULL);
        rpc_net_set_boot_context(dir, NULL);

        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "bootstrapstatus",
                                     &params, &result);

        const struct json_value *loader =
            json_get(&result, "snapshot_loader");
        const struct json_value *authority =
            loader ? json_get(loader, "authority") : NULL;
        ok = ok && authority && authority->type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(authority,
                                          "progress_store_open"));
        ok = ok && json_get_bool(json_get(authority,
                                          "hstar_available"));
        ok = ok && json_get_int(json_get(authority, "hstar")) ==
                  REDUCER_FRONTIER_TRUSTED_ANCHOR;
        ok = ok && json_get_bool(json_get(authority,
                                          "coins_applied_height_readable"));
        ok = ok && json_get_bool(json_get(authority,
                                          "coins_applied_height_present"));
        ok = ok && json_get_int(json_get(authority,
                                         "coins_applied_height")) ==
                  REDUCER_FRONTIER_TRUSTED_ANCHOR + 1;
        ok = ok && json_get_bool(json_get(authority,
                                          "coins_kv_proven_authority"));
        ok = ok && json_get_bool(json_get(authority,
                                          "coins_cover_hstar"));
        ok = ok && json_get_bool(json_get(authority,
                                          "fast_rebuild_authority_ready"));
        ok = ok && !json_get_bool(json_get(authority,
                                           "self_folded_marker"));
        ok = ok && !json_get_bool(json_get(authority,
            "self_derived_tip_static_checks"));
        ok = ok && strcmp(json_get_str(json_get(authority,
            "self_derived_reason")), "borrowed_seed_no_refold_marker") == 0;
        ok = ok && strcmp(json_get_str(json_get(authority,
            "authority_posture")), "proven_but_not_self_folded") == 0;

        json_free(&result);
        json_init(&result);
        ok = ok && coins_kv_mark_self_folded(pdb);
        ok = ok && rpc_table_execute(&tbl, "bootstrapstatus",
                                     &params, &result);
        loader = json_get(&result, "snapshot_loader");
        authority = loader ? json_get(loader, "authority") : NULL;
        ok = ok && authority && authority->type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(authority,
                                          "self_folded_marker"));
        ok = ok && json_get_bool(json_get(authority,
            "self_derived_tip_static_checks"));
        ok = ok && strcmp(json_get_str(json_get(authority,
            "self_derived_reason")), "ok") == 0;
        ok = ok && strcmp(json_get_str(json_get(authority,
            "authority_posture")), "self_folded_marker_present") == 0;

        json_free(&params);
        json_free(&result);
        rpc_net_set_connman(NULL);
        rpc_net_set_boot_context(NULL, NULL);
        progress_store_close();
        test_cleanup_tmpdir(dir);
        test_reset_shared_globals();

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("getnetworkinfo: separates inbound reachability from outbound "
           "handshakes (RED)... ");
    {
        struct connman cm;
        struct node_signals sigs;
        struct rpc_table tbl;
        struct json_value params = {0};
        struct json_value result = {0};

        chain_params_select(CHAIN_MAIN);
        memset(&cm, 0, sizeof(cm));
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, chain_params_get(), &sigs);
        struct p2p_node *outbound = syncdiag_add_peer(
            &cm, 11, false, PEER_HANDSHAKE_COMPLETE);
        struct p2p_node *inbound = syncdiag_add_peer(
            &cm, 12, true, PEER_HANDSHAKE_COMPLETE);
        ok = ok && outbound != NULL && inbound != NULL;
        if (inbound)
            inbound->accepted_local_port = 8055;
        if (!ok)
            goto syncdiag_net_split_done;
        if (ok) {
            struct net_address addr;
            struct net_service svc;
            net_address_init(&addr);
            ok = lookup_numeric("51.178.179.75:8033", &svc,
                                cm.manager.default_port);
            if (ok) {
                addr.svc = svc;
                cm.addnodes[cm.num_addnodes++] = addr;
                connman_record_addnode_failure(&cm, 0,
                                               CONNMAN_ADDNODE_FAILURE_TCP);
            }
        }

        rpc_table_init(&tbl);
        register_net_rpc_commands(&tbl);
        rpc_net_set_connman(&cm);

        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "getnetworkinfo",
                                     &params, &result);

        ok = ok && result.type == JSON_OBJ;
        ok = ok && json_get_int(json_get(&result, "handshaked_connections"))
                  == 2;
        ok = ok && json_get_int(json_get(&result,
                                          "inbound_handshaked_connections"))
                  == 1;
        ok = ok && json_get_int(json_get(&result,
                                          "outbound_handshaked_connections"))
                  == 1;
        ok = ok && json_get_bool(json_get(&result,
                                          "inbound_handshake_seen"));
        ok = ok && json_get_bool(json_get(&result,
                                          "remote_handshake_seen"));
        ok = ok && json_get_int(json_get(&result,
                                          "legacy_compatible_peers")) ==
                  json_get_int(json_get(&result, "magicbean_peers"));
        ok = ok && json_get_int(json_get(&result,
                                          "legacy_magicbean_peers")) ==
                  json_get_int(json_get(&result, "magicbean_peers"));
        ok = ok && json_get_int(json_get(&result, "zclassic23_peers")) ==
                  json_get_int(json_get(&result, "zclassic_c23_peers"));
        const struct json_value *addnodes =
            json_get(&result, "addnode_status");
        const struct json_value *first =
            addnodes && addnodes->type == JSON_ARR ? json_at(addnodes, 0)
                                                   : NULL;
        ok = ok && addnodes && addnodes->type == JSON_ARR;
        ok = ok && json_size(addnodes) == 1;
        ok = ok && first && json_get(first, "address") != NULL;
        ok = ok && first && json_get_int(json_get(first, "index")) == 0;
        ok = ok && first && !json_get_bool(json_get(first, "connected"));
        ok = ok && first &&
             json_get_int(json_get(first, "backoff_seconds")) > 0;
        ok = ok && first &&
             json_get_int(json_get(first, "backoff_remaining_seconds")) >= 0;
        ok = ok && first &&
             json_get_int(json_get(first, "tcp_failures")) == 1;
        ok = ok && first &&
             json_get_int(json_get(first, "protocol_failures")) == 0;
        if (!ok)
            goto syncdiag_net_split_done;

        json_free(&params);
        json_init(&params);
        json_set_array(&params);
        struct json_value v;
        json_init(&v);
        json_set_str(&v, "51.178.179.75:8033");
        ok = ok && json_push_back(&params, &v);
        json_free(&v);
        json_init(&v);
        json_set_str(&v, "remove");
        ok = ok && json_push_back(&params, &v);
        json_free(&v);

        json_free(&result);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "addnode", &params, &result);
        if (!ok)
            goto syncdiag_net_split_done;

        json_free(&params);
        json_init(&params);
        json_set_array(&params);
        json_free(&result);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "getnetworkinfo",
                                     &params, &result);
        addnodes = json_get(&result, "addnode_status");
        ok = ok && addnodes && addnodes->type == JSON_ARR;
        ok = ok && json_size(addnodes) == 0;
        if (!ok)
            goto syncdiag_net_split_done;

        json_free(&params);
        json_init(&params);
        json_set_array(&params);
        json_init(&v);
        json_set_str(&v, "51.178.179.75:8033");
        ok = ok && json_push_back(&params, &v);
        json_free(&v);
        json_init(&v);
        json_set_str(&v, "remove");
        ok = ok && json_push_back(&params, &v);
        json_free(&v);
        json_free(&result);
        json_init(&result);
        ok = ok && !rpc_table_execute(&tbl, "addnode", &params, &result);
        ok = ok && strstr(json_get_str(&result), "not found") != NULL;
        if (!ok)
            goto syncdiag_net_split_done;

        json_free(&params);
        json_init(&params);
        json_set_array(&params);
        json_init(&v);
        json_set_str(&v, "51.178.179.75:8033");
        ok = ok && json_push_back(&params, &v);
        json_free(&v);
        json_init(&v);
        json_set_str(&v, "bogus");
        ok = ok && json_push_back(&params, &v);
        json_free(&v);
        json_free(&result);
        json_init(&result);
        ok = ok && !rpc_table_execute(&tbl, "addnode", &params, &result);
        ok = ok && strstr(json_get_str(&result), "must be") != NULL;
        if (!ok)
            goto syncdiag_net_split_done;

        json_free(&params);
        json_init(&params);
        json_set_array(&params);
        json_free(&result);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "getpeerinfo",
                                     &params, &result);
        const struct json_value *peer0 =
            result.type == JSON_ARR ? json_at(&result, 0) : NULL;
        const struct json_value *peer1 =
            result.type == JSON_ARR ? json_at(&result, 1) : NULL;
        ok = ok && peer0 && json_get_bool(json_get(peer0, "zclassic23"));
        ok = ok && peer0 && json_get_bool(json_get(peer0, "zclassic_c23"));
        ok = ok && peer0 && json_get(peer0, "lifecycle") == NULL;
        ok = ok && peer0 &&
             json_get_int(json_get(peer0, "accepted_local_port")) == 0;
        ok = ok && peer1 &&
             json_get_int(json_get(peer1, "accepted_local_port")) == 8055;
        ok = ok && peer1 &&
             !json_get_bool(json_get(peer1, "source_is_loopback"));
        ok = ok && peer1 &&
             !json_get_bool(json_get(peer1, "onion_ingress_candidate"));

syncdiag_net_split_done:
        json_free(&params);
        json_free(&result);
        rpc_net_set_connman(NULL);
        connman_free(&cm);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }


    return failures;
}

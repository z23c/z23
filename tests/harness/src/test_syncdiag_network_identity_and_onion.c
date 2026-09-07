/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * network sibling: machine_identity, onionstatus (ready and
 * unavailable), getnetworkinfo's startup reachability schema,
 * peerincidents' duplicate-host telemetry and dumpstate compatibility
 * fallback, and getnetworkinfo's configured external endpoint. Each
 * scenario is its own function that builds its fixture, calls the RPC,
 * asserts on the result, and frees what it owns; the assertion helpers
 * above each scenario are private to that scenario and add no
 * file-scope mutable state of their own.
 */

#include "test/syncdiag_rpc_fixture.h"
#include "net/onion_stream.h"
#include "net/tor_integration.h"
#include "test/test_syncdiag_network_priv.h"

static bool sd_machine_identity_contract_and_sections(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *platform = json_get(result, "platform");
    const struct json_value *build = json_get(result, "build");
    const struct json_value *transport = json_get(result, "transport");
    const struct json_value *dht = json_get(result,
                                            "authenticated_dht");
    ok = ok && result->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(result, "schema")),
                      "zcl.machine_mesh_identity.v1") == 0;
    ok = ok && platform && platform->type == JSON_OBJ;
    ok = ok && build && build->type == JSON_OBJ;
    ok = ok && transport && transport->type == JSON_OBJ;
    ok = ok && json_get(transport, "identity_loaded") != NULL;
    ok = ok && json_get(transport,
                        "local_noise_fingerprint_sha3") != NULL;
    ok = ok && dht && dht->type == JSON_OBJ;
    return ok;
}

static bool sd_machine_identity_pairing_posture(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *pairing = json_get(result, "pairing");
    const struct json_value *local_authority =
        pairing ? json_get(pairing, "local_authority_implemented") : NULL;
    const struct json_value *remote_protocol = pairing
        ? json_get(pairing, "remote_status_protocol_implemented") : NULL;
    const struct json_value *mesh_ready =
        pairing ? json_get(pairing, "private_mesh_ready") : NULL;
    ok = ok && pairing && pairing->type == JSON_OBJ;
    ok = ok && local_authority && local_authority->type == JSON_BOOL &&
         json_get_bool(local_authority);
    ok = ok && remote_protocol && remote_protocol->type == JSON_BOOL &&
         json_get_bool(remote_protocol);
    ok = ok && mesh_ready && mesh_ready->type == JSON_BOOL &&
         !json_get_bool(mesh_ready);
    return ok;
}

static bool sd_machine_identity_no_secret_leak(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *blockers = json_get(result, "blockers");
    char encoded[4096];
    size_t encoded_len = json_write(result, encoded, sizeof(encoded));
    ok = ok && blockers && blockers->type == JSON_ARR;
    ok = ok && !json_array_has_str(
                       blockers, "REMOTE_STATUS_PROTOCOL_UNAVAILABLE");

    ok = ok && encoded_len > 0 && encoded_len < sizeof(encoded);
    ok = ok && strstr(encoded, "identity_priv") == NULL;
    ok = ok && strstr(encoded, "private_key") == NULL;
    ok = ok && strstr(encoded, "datadir") == NULL;
    ok = ok && strstr(encoded, "exe_path") == NULL;
    return ok;
}


/* case: machine_identity reports independent live facts (platform,
 * build, transport, DHT, pairing posture) without ever leaking a
 * secret through the encoded JSON payload. */
bool sd_machine_identity_scenario(void)
{
    struct json_value result = {0};
    bool ok = machine_identity_dump_state_json(&result, NULL);
    ok = sd_machine_identity_contract_and_sections(&result) && ok;
    ok = sd_machine_identity_pairing_posture(&result) && ok;
    ok = sd_machine_identity_no_secret_leak(&result) && ok;
    json_free(&result);
    return ok;
}

static bool sd_onionstatus_ready_contract(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *state = json_get(result, "bootstrap_state");
    const struct json_value *tor_ready = json_get(result, "tor_ready");
    const struct json_value *service_ready =
        json_get(result, "onion_service_ready");
    const struct json_value *address = json_get(result, "onion_address");
    const struct json_value *p2p_ready = json_get(
        result, "p2p_publish_ready");
    const struct json_value *setup_state = json_get(result,
                                                    "setup_state");
    ok = ok && result->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(result, "schema")),
                      "zcl.onion_status.v1") == 0;
    ok = ok && state && state->type == JSON_STR;
    ok = ok && tor_ready && tor_ready->type == JSON_BOOL;
    ok = ok && service_ready && service_ready->type == JSON_BOOL;
    ok = ok && address && address->type == JSON_STR;
    ok = ok && p2p_ready && p2p_ready->type == JSON_BOOL;
    ok = ok && setup_state && setup_state->type == JSON_STR;
    return ok;
}

static bool sd_onionstatus_ready_port_mapping(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *mapping = json_get(result,
                                                 "port_mapping");
    const struct json_value *routes = mapping
        ? json_get(mapping, "routes") : NULL;
    ok = ok && mapping && mapping->type == JSON_OBJ;
    ok = ok && json_get(mapping, "state") != NULL;
    ok = ok && json_get(mapping, "complete") != NULL;
    ok = ok && json_get(mapping, "expected_route_count") != NULL;
    ok = ok && json_get(mapping, "installed_route_count") != NULL;
    ok = ok && routes && routes->type == JSON_ARR;
    ok = ok && routes && json_size(routes) == 2;
    return ok;
}

static bool sd_onionstatus_ready_outbound_stream_counts(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *streams = json_get(result,
                                                 "outbound_streams");
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
    return ok;
}

static bool sd_onionstatus_ready_handshake_contract(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *handshake = json_get(result,
                                                   "p2p_handshake");
    const struct json_value *recent_dials = json_get(result,
                                                      "recent_dials");
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
    return ok;
}

static bool sd_onionstatus_ready_last_outbound_dial(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *last_dial = json_get(result,
                                                   "last_outbound_dial");
    ok = ok && last_dial && last_dial->type == JSON_OBJ;
    ok = ok &&
         strcmp(json_get_str(json_get(last_dial, "schema")),
                "zcl.onion_last_dial.v1") == 0;
    ok = ok && json_get(last_dial, "target") &&
         json_get(last_dial, "target")->type == JSON_STR;
    ok = ok && json_get(last_dial, "attempted_unix") &&
         json_get(last_dial, "attempted_unix")->type == JSON_INT;
    ok = ok && json_get(last_dial, "result") &&
         json_get(last_dial, "result")->type == JSON_STR &&
         strcmp(json_get_str(json_get(last_dial, "result")),
                "none") == 0;
    return ok;
}

static bool sd_onionstatus_ready_handshake_counts(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *handshake = json_get(result,
                                                   "p2p_handshake");
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
    ok = ok && json_get(result, "tor_requested") &&
         json_get(result, "tor_requested")->type == JSON_BOOL;
    return ok;
}

/* Walks network_onion_first_incomplete_stage() through every stage of a
 * dial+handshake, one field flip at a time, checking the first-incomplete
 * label it reports after each flip. */
static bool sd_onionstatus_ready_incomplete_stage_walk(void)
{
    bool ok = true;
    struct onion_stream_stages stream = {0};
    struct peer_lifecycle_summary peer = {0};
    ok = ok && strcmp(network_onion_first_incomplete_stage(
                          true, true, true, NULL, &peer),
                      "invalid_snapshot") == 0;
    ok = ok && strcmp(network_onion_first_incomplete_stage(
                          false, false, false, &stream, &peer),
                      "tor_disabled") == 0;
    ok = ok && strcmp(network_onion_first_incomplete_stage(
                          false, true, false, &stream, &peer),
                      "tor_unavailable") == 0;
    ok = ok && strcmp(network_onion_first_incomplete_stage(
                          true, true, false, &stream, &peer),
                      "tor_dial_not_ready") == 0;
    stream.dial_started = 1;
    stream.stream_queued = 1;
    stream.circuit_ready = 1;
    stream.bridge_up = 1;
    stream.bytes_to_peer = 1;
    peer.connected = 1;
    peer.version_sent = 1;
    ok = ok && strcmp(network_onion_first_incomplete_stage(
                          true, true, true, &stream, &peer),
                      "p2p_bytes_not_received") == 0;
    stream.bytes_from_peer = 1;
    ok = ok && strcmp(network_onion_first_incomplete_stage(
                          true, true, true, &stream, &peer),
                      "version_not_received") == 0;
    peer.version_received = 1;
    ok = ok && strcmp(network_onion_first_incomplete_stage(
                          true, true, true, &stream, &peer),
                      "verack_not_received") == 0;
    peer.verack_received = 1;
    ok = ok && strcmp(network_onion_first_incomplete_stage(
                          true, true, true, &stream, &peer),
                      "handshake_not_complete") == 0;
    peer.handshake_complete = 1;
    ok = ok && strcmp(network_onion_first_incomplete_stage(
                          true, true, true, &stream, &peer),
                      "complete") == 0;
    return ok;
}

/* case: onionstatus reports a coherent bootstrap-state contract: schema
 * fields, port-mapping routes, stream/handshake stage counters, the
 * last-dial record, the first-incomplete-stage narrative walk, and (once
 * the snapshot reads "ready") a well-formed .onion hostname. */
static bool sd_onionstatus_ready_hostname_check(const struct json_value *result,
                                                bool ok)
{
    const struct json_value *state = json_get(result, "bootstrap_state");
    const struct json_value *tor_ready = json_get(result, "tor_ready");
    const struct json_value *service_ready =
        json_get(result, "onion_service_ready");
    const struct json_value *address = json_get(result, "onion_address");
    if (ok && strcmp(json_get_str(state), "ready") == 0) {
        const char *hostname = json_get_str(address);
        size_t hostname_len = strlen(hostname);
        ok = json_get_bool(tor_ready) && json_get_bool(service_ready) &&
             hostname_len > 6 &&
             strcmp(hostname + hostname_len - 6, ".onion") == 0;
    }
    return ok;
}

bool sd_onionstatus_ready_scenario(void)
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
    ok = sd_onionstatus_ready_contract(&result) && ok;
    ok = sd_onionstatus_ready_port_mapping(&result) && ok;
    ok = sd_onionstatus_ready_outbound_stream_counts(&result) && ok;
    ok = sd_onionstatus_ready_handshake_contract(&result) && ok;
    ok = sd_onionstatus_ready_last_outbound_dial(&result) && ok;
    ok = sd_onionstatus_ready_handshake_counts(&result) && ok;
    ok = sd_onionstatus_ready_incomplete_stage_walk() && ok;
    ok = sd_onionstatus_ready_hostname_check(&result, ok);

    json_free(&params);
    json_free(&result);
    return ok;
}

/* case: -tor requested but not running reports "unavailable", not
 * "disabled". */
bool sd_onionstatus_unavailable_scenario(void)
{
    struct rpc_table tbl;
    struct json_value params;
    struct json_value result;

    tor_integration_stop();
    tor_integration_mark_requested();
    rpc_table_init(&tbl);
    register_net_rpc_commands(&tbl);
    json_init(&params);
    json_set_array(&params);
    json_init(&result);
    bool ok = rpc_table_execute(&tbl, "onionstatus", &params, &result);
    const char *state = json_get_str(json_get(&result, "bootstrap_state"));
    const char *setup = json_get_str(json_get(&result, "setup_state"));
    const struct json_value *requested = json_get(&result, "tor_requested");
    const struct json_value *handshake = json_get(&result, "p2p_handshake");
    ok = ok && state && strcmp(state, "unavailable") == 0;
    ok = ok && setup && strcmp(setup, "tor_start_failed") == 0;
    ok = ok && requested && json_get_bool(requested);
    ok = ok && !json_get_bool(json_get(&result, "tor_enabled"));
    ok = ok && strcmp(state, "disabled") != 0;
    ok = ok && handshake &&
         strcmp(json_get_str(json_get(handshake, "first_incomplete_stage")),
                "tor_unavailable") == 0;
    json_free(&params);
    json_free(&result);
    tor_integration_stop();
    return ok;
}

static bool sd_getnetworkinfo_startup_zero_connections(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *inbound =
        json_get(result, "inbound_connections");
    const struct json_value *outbound =
        json_get(result, "outbound_connections");
    const struct json_value *handshaked =
        json_get(result, "handshaked_connections");
    const struct json_value *inbound_hs =
        json_get(result, "inbound_handshaked_connections");
    const struct json_value *outbound_hs =
        json_get(result, "outbound_handshaked_connections");
    ok = ok && result->type == JSON_OBJ;
    ok = ok && inbound && json_get_int(inbound) == 0;
    ok = ok && outbound && json_get_int(outbound) == 0;
    ok = ok && handshaked && json_get_int(handshaked) == 0;
    ok = ok && inbound_hs && json_get_int(inbound_hs) == 0;
    ok = ok && outbound_hs && json_get_int(outbound_hs) == 0;
    return ok;
}

static bool sd_getnetworkinfo_startup_listen_and_lifecycle(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *listen_count =
        json_get(result, "listen_socket_count");
    const struct json_value *listening =
        json_get(result, "listening");
    const struct json_value *inbound_seen =
        json_get(result, "inbound_handshake_seen");
    const struct json_value *remote_seen =
        json_get(result, "remote_handshake_seen");
    const struct json_value *life =
        json_get(result, "peer_lifecycle");
    ok = ok && listen_count && json_get_int(listen_count) == 0;
    ok = ok && listening && !json_get_bool(listening);
    ok = ok && inbound_seen && !json_get_bool(inbound_seen);
    ok = ok && remote_seen && !json_get_bool(remote_seen);
    ok = ok && life && life->type == JSON_OBJ;
    ok = ok && life && json_get(life, "attempted") != NULL;
    return ok;
}

static bool sd_getnetworkinfo_startup_lifecycle_handshake_counters(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *life =
        json_get(result, "peer_lifecycle");
    ok = ok && life && json_get(life, "connected") != NULL;
    ok = ok && life && json_get(life, "version_sent") != NULL;
    ok = ok && life && json_get(life, "version_received") != NULL;
    ok = ok && life && json_get(life, "verack_received") != NULL;
    ok = ok && life && json_get(life, "handshake_complete") != NULL;
    ok = ok && life && json_get(life, "active") != NULL;
    return ok;
}

static bool sd_getnetworkinfo_startup_lifecycle_outcome_counters(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *life =
        json_get(result, "peer_lifecycle");
    ok = ok && life && json_get(life, "disconnected") != NULL;
    ok = ok && life && json_get(life, "timeout") != NULL;
    ok = ok && life && json_get(life, "rejected") != NULL;
    ok = ok && life && json_get(life, "cache_skipped") != NULL;
    ok = ok && life && json_get(life, "magicbean_handshakes") != NULL;
    ok = ok && life && json_get(life, "zclassic23_handshakes") != NULL;
    return ok;
}

static bool sd_getnetworkinfo_startup_lifecycle_sources(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *life =
        json_get(result, "peer_lifecycle");
    const struct json_value *life_sources =
        life ? json_get(life, "sources") : NULL;
    const struct json_value *addnodes =
        json_get(result, "addnode_status");

    ok = ok && life && json_get(life, "zclassic_c23_handshakes") != NULL;
    ok = ok && life_sources && life_sources->type == JSON_ARR;
    ok = ok && addnodes && addnodes->type == JSON_ARR;
    ok = ok && json_size(addnodes) == 0;
    ok = ok && find_source_json(life_sources, "unknown") != NULL;
    ok = ok && find_source_json(life_sources, "inbound") != NULL;
    ok = ok && find_source_json(life_sources, "addnode") != NULL;
    ok = ok && find_source_json(life_sources, "addrman") != NULL;
    ok = ok && find_source_json(life_sources, "zcl23_db") != NULL;
    return ok;
}

static bool sd_getnetworkinfo_startup_lifecycle_manual_source(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *life =
        json_get(result, "peer_lifecycle");
    const struct json_value *life_sources =
        life ? json_get(life, "sources") : NULL;
    ok = ok && find_source_json(life_sources, "manual") != NULL;
    return ok;
}

/* case: getnetworkinfo reports the stable startup reachability schema —
 * zero connections, zero listen sockets, and the peer-lifecycle counter
 * and source fields all present. */
bool sd_getnetworkinfo_startup_scenario(void)
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
    ok = sd_getnetworkinfo_startup_zero_connections(&result) && ok;
    ok = sd_getnetworkinfo_startup_listen_and_lifecycle(&result) && ok;
    ok = sd_getnetworkinfo_startup_lifecycle_handshake_counters(&result) && ok;
    ok = sd_getnetworkinfo_startup_lifecycle_outcome_counters(&result) && ok;
    ok = sd_getnetworkinfo_startup_lifecycle_sources(&result) && ok;
    ok = sd_getnetworkinfo_startup_lifecycle_manual_source(&result) && ok;

    json_free(&params);
    json_free(&result);
    return ok;
}

static bool sd_peerincidents_duplicate_host_contract(const struct json_value *result)
{
    bool ok = true;
    ok = ok && result->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(result, "schema")),
                      "zcl.peer_incidents.v2") == 0;
    ok = ok && strcmp(json_get_str(json_get(result, "method")),
                      "peerincidents") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "native_command")),
                      "z23 peerincidents") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "contract_source")),
                      "agent_contracts.def") == 0;
    ok = ok && json_get_bool(json_get(result, "bounded"));
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "bootstrap_readiness")),
                      "ready") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "fast_sync_readiness")),
                      "no_zclassic23_fast_sync_peer") == 0;
    ok = ok && !json_get_bool(json_get(result,
                                       "bootstrap_blocked"));
    ok = ok && json_get_bool(json_get(result,
                                      "fast_sync_blocked"));
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "incident_severity")),
                      "attention") == 0;
    ok = ok && json_get_bool(json_get(result,
                                      "stability_blocker"));
    return ok;
}

static bool sd_peerincidents_duplicate_host_primary_issue(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *primary =
        json_get(result, "primary_host_issue");
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "primary_issue_host")),
                      "40.160.53.56") == 0;
    ok = ok && json_get_int(json_get(result,
                                     "primary_issue_score")) > 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "primary_issue_class")),
                      "duplicate_handshaked_connections") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "primary_issue_next_action")),
                      "inspect_duplicate_current_connections_for_host")
        == 0;
    ok = ok && json_get_int(json_get(result,
                     "duplicate_host_group_count")) == 1;
    ok = ok && json_get_int(json_get(result,
                     "duplicate_open_host_group_count")) == 1;
    ok = ok && json_get_int(json_get(result,
                     "duplicate_handshaked_host_group_count")) == 1;
    ok = ok && primary && primary->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(primary, "host")),
                      "40.160.53.56") == 0;
    ok = ok && json_get_bool(json_get(primary,
                                      "duplicate_current_connections"));
    ok = ok && json_get_bool(json_get(primary,
                                      "bootstrap_useful"));
    return ok;
}

static bool sd_peerincidents_duplicate_host_groups_and_top_hosts(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *hosts =
        json_get(result, "duplicate_host_groups");
    const struct json_value *top_hosts =
        json_get(result, "top_host_incidents");
    ok = ok && hosts && hosts->type == JSON_ARR;
    ok = ok && json_size(hosts) == 1;
    ok = ok && top_hosts && top_hosts->type == JSON_ARR;
    ok = ok && json_size(top_hosts) == 1;
    return ok;
}


/* case: peerincidents surfaces compact duplicate-host telemetry — two
 * handshaked peers sharing one host produce a primary_host_issue,
 * a duplicate_host_groups entry, and a top_host_incidents entry. */
bool sd_peerincidents_duplicate_host_scenario(void)
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
    ok = sd_peerincidents_duplicate_host_contract(&result) && ok;
    ok = sd_peerincidents_duplicate_host_primary_issue(&result) && ok;
    ok = sd_peerincidents_duplicate_host_groups_and_top_hosts(&result) && ok;

    json_free(&params);
    json_free(&result);
    peer_lifecycle_reset_for_test();
    return ok;
}

/* case: peerincidents falls back to the dumpstate peer_lifecycle payload
 * when the target RPC method is not found, and says so. */
bool sd_peerincidents_dumpstate_fallback_scenario(void)
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
    return ok;
}

/* case: getnetworkinfo exposes the configured -externalip endpoint as a
 * scored local address, alongside the advertised subversion string. */
static bool sd_getnetworkinfo_external_endpoint_asserts(
    const struct json_value *result, bool ok)
{
    const struct json_value *localaddrs =
        json_get(result, "localaddresses");
    const struct json_value *first =
        localaddrs && localaddrs->type == JSON_ARR
            ? json_at(localaddrs, 0)
            : NULL;
    ok = ok && result->type == JSON_OBJ;
    ok = ok && json_get_bool(json_get(result,
                                      "externalip_configured"));
    ok = ok && localaddrs && localaddrs->type == JSON_ARR;
    ok = ok && json_size(localaddrs) == 1;
    ok = ok && first && strcmp(json_get_str(json_get(first, "address")),
                               "203.0.113.7") == 0;
    ok = ok && first &&
         json_get_int(json_get(first, "port")) == 8023;
    ok = ok && first &&
         json_get_int(json_get(first, "score")) == 1;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "advertised_subver")),
                      msg_version_user_agent()) == 0;
    return ok;
}

bool sd_getnetworkinfo_external_endpoint_scenario(void)
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
    ok = sd_getnetworkinfo_external_endpoint_asserts(&result, ok);

    json_free(&params);
    json_free(&result);
    rpc_net_set_connman(NULL);
    msg_version_clear_external_ip_for_test();
    return ok;
}

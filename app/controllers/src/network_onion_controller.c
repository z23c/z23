/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: one coherent RPC contract for embedded Tor/onion readiness. */

#include "controllers/network_controller.h"

#include "controllers/strong_params.h"
#include "json/json.h"
#include "net/onion_peer_merge.h"
#include "net/onion_service.h"
#include "net/onion_stream.h"
#include "net/peer_lifecycle.h"
#include "net/tor_integration.h"

#include <stdbool.h>
#include <string.h>

const char *network_onion_first_incomplete_stage(
    bool tor_enabled, bool dial_ready,
    const struct onion_stream_stages *stream,
    const struct peer_lifecycle_summary *peer)
{
    if (!stream || !peer) return "invalid_snapshot";
    if (!tor_enabled) return "tor_disabled";
    if (!dial_ready) return "tor_dial_not_ready";
    if (stream->dial_started == 0) return "dial_not_started";
    if (stream->stream_queued == 0) return "stream_not_queued";
    if (stream->circuit_ready == 0) return "circuit_not_ready";
    if (stream->bridge_up == 0) return "bridge_not_up";
    if (peer->connected == 0) return "p2p_not_connected";
    if (peer->version_sent == 0) return "version_not_sent";
    if (stream->bytes_to_peer == 0) return "p2p_bytes_not_sent";
    if (stream->bytes_from_peer == 0) return "p2p_bytes_not_received";
    if (peer->version_received == 0) return "version_not_received";
    if (peer->verack_received == 0) return "verack_not_received";
    if (peer->handshake_complete == 0) return "handshake_not_complete";
    return "complete";
}

bool network_onion_status_rpc(const struct json_value *params, bool help,
                              struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "onionstatus\n"
        "Returns embedded Tor readiness, the published onion address, and "
        "the live virtual-port mapping contract.");

    bool tor_enabled = tor_integration_is_enabled();
    bool tor_ready = tor_integration_is_ready();
    bool dial_ready = tor_integration_is_dial_ready();
    const char *tor_address = tor_integration_get_onion_address();
    const char *service_address = onion_service_get_address();
    bool service_ready = service_address && service_address[0] != '\0';
    bool address_valid = service_ready && onion_hostname_valid(service_address);
    bool address_matches = address_valid && tor_address &&
                           strcmp(service_address, tor_address) == 0;
    bool ready = tor_ready && address_matches;
    const char *state = ready ? "ready" :
                        !tor_enabled ? "disabled" :
                        !tor_ready ? "bootstrapping" :
                        !service_ready ? "publishing" :
                        !address_valid ? "invalid_address" :
                        "address_mismatch";
    const char *address = service_ready ? service_address :
                          tor_address ? tor_address : "";
    struct tor_onion_port_map port_map;
    tor_integration_port_map_snapshot(&port_map);
    bool p2p_publish_ready = port_map.p2p_route_installed;
    const char *setup_state =
        !tor_enabled ? "enable_tor" :
        !port_map.persistent_identity ? "enable_persistent_identity" :
        !port_map.p2p_route_expected ? "configure_p2p_port" :
        port_map.state == TOR_ONION_PORT_MAP_FAILED ? "inspect_tor_log" :
        !p2p_publish_ready ? "wait_for_registration" :
        "ready";

    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.onion_status.v1");
    json_push_kv_str(result, "bootstrap_state", state);
    json_push_kv_bool(result, "tor_enabled", tor_enabled);
    json_push_kv_bool(result, "tor_ready", tor_ready);
    json_push_kv_bool(result, "dial_ready", dial_ready);
    json_push_kv_bool(result, "onion_service_ready", service_ready);
    json_push_kv_str(result, "onion_address", address);
    json_push_kv_bool(result, "p2p_publish_ready", p2p_publish_ready);
    json_push_kv_str(result, "setup_state", setup_state);

    /* The raw-stream layer already owns a monotonic stage ledger so onion
     * acceptance never has to infer transport state from a rotated log. Keep
     * it in the public read contract: a published service and a dial-ready
     * Tor are only the two local setup halves, while these counters identify
     * how far real outbound circuits and peer bytes have progressed. */
    struct onion_stream_stages stream_stages;
    onion_stream_get_stages(&stream_stages);
    struct json_value outbound_streams = {0};
    json_set_object(&outbound_streams);
    json_push_kv_str(&outbound_streams, "schema",
                     "zcl.onion_stream_stages.v1");
    json_push_kv_str(&outbound_streams, "semantics",
                     "monotonic process-lifetime counters; deltas across a "
                     "bounded dial observation identify progress without "
                     "attributing concurrent attempts to one endpoint");
    json_push_kv_int(&outbound_streams, "dial_started",
                     (int64_t)stream_stages.dial_started);
    json_push_kv_int(&outbound_streams, "stream_queued",
                     (int64_t)stream_stages.stream_queued);
    json_push_kv_int(&outbound_streams, "circuit_ready",
                     (int64_t)stream_stages.circuit_ready);
    json_push_kv_int(&outbound_streams, "bridge_up",
                     (int64_t)stream_stages.bridge_up);
    json_push_kv_int(&outbound_streams, "open_refused",
                     (int64_t)stream_stages.open_refused);
    json_push_kv_int(&outbound_streams, "circuit_timeout",
                     (int64_t)stream_stages.circuit_timeout);
    json_push_kv_int(&outbound_streams, "circuit_torn_down",
                     (int64_t)stream_stages.circuit_torn_down);
    json_push_kv_int(&outbound_streams, "bridge_closed",
                     (int64_t)stream_stages.bridge_closed);
    json_push_kv_int(&outbound_streams, "bytes_to_peer",
                     (int64_t)stream_stages.bytes_to_peer);
    json_push_kv_int(&outbound_streams, "bytes_from_peer",
                     (int64_t)stream_stages.bytes_from_peer);
    json_push_kv_int(&outbound_streams, "peers_answered",
                     (int64_t)stream_stages.peers_answered);
    json_push_kv(result, "outbound_streams", &outbound_streams);

    /* Join the transport ledger to the P2P lifecycle ledger in one native
     * read.  These remain process aggregates: on a busy node the operator
     * compares deltas around one bounded dial; an isolated probe can read the
     * first-incomplete label directly without grepping or correlating logs. */
    struct peer_lifecycle_summary handshake_totals;
    peer_lifecycle_get_summary(&handshake_totals);
    struct json_value handshake = {0};
    json_set_object(&handshake);
    json_push_kv_str(&handshake, "schema",
                     "zcl.onion_handshake_stages.v1");
    json_push_kv_str(&handshake, "semantics",
                     "process-lifetime aggregate; compare deltas around one "
                     "bounded dial, or read directly in an isolated probe");
    json_push_kv_str(&handshake, "first_incomplete_stage",
                     network_onion_first_incomplete_stage(
                         tor_enabled, dial_ready, &stream_stages,
                         &handshake_totals));
    json_push_kv_int(&handshake, "attempted", handshake_totals.attempted);
    json_push_kv_int(&handshake, "connected", handshake_totals.connected);
    json_push_kv_int(&handshake, "version_sent",
                     handshake_totals.version_sent);
    json_push_kv_int(&handshake, "version_received",
                     handshake_totals.version_received);
    json_push_kv_int(&handshake, "verack_received",
                     handshake_totals.verack_received);
    json_push_kv_int(&handshake, "handshake_complete",
                     handshake_totals.handshake_complete);
    json_push_kv_int(&handshake, "pre_handshake_disconnects",
                     handshake_totals.pre_handshake_disconnects);
    json_push_kv(result, "p2p_handshake", &handshake);

    struct onion_last_dial last_dial;
    onion_stream_get_last_dial(&last_dial);
    struct json_value last = {0};
    json_set_object(&last);
    json_push_kv_str(&last, "schema", "zcl.onion_last_dial.v1");
    json_push_kv_str(&last, "target", last_dial.target);
    json_push_kv_int(&last, "attempted_unix", last_dial.attempted_unix);
    json_push_kv_str(&last, "result", last_dial.result);
    json_push_kv(result, "last_outbound_dial", &last);
    json_free(&last);

    struct json_value mapping = {0};
    struct json_value routes = {0};
    struct json_value app_route = {0};
    struct json_value p2p_route = {0};
    json_set_object(&mapping);
    json_push_kv_str(&mapping, "state",
                     tor_onion_port_map_state_name(port_map.state));
    json_push_kv_bool(&mapping, "complete", port_map.complete);
    json_push_kv_bool(&mapping, "persistent_identity",
                      port_map.persistent_identity);
    json_push_kv_int(&mapping, "expected_route_count",
                     port_map.expected_route_count);
    json_push_kv_int(&mapping, "installed_route_count",
                     port_map.installed_route_count);

    json_set_array(&routes);
    json_set_object(&app_route);
    json_push_kv_str(&app_route, "name", "application_dynhost");
    json_push_kv_int(&app_route, "virtual_port",
                     port_map.application_virtual_port);
    json_push_kv_str(&app_route, "target", "in_process_callback");
    json_push_kv_bool(&app_route, "installed",
                      port_map.application_route_installed);
    json_push_back(&routes, &app_route);

    json_set_object(&p2p_route);
    json_push_kv_str(&p2p_route, "name", "p2p_tcp");
    json_push_kv_int(&p2p_route, "virtual_port",
                     port_map.p2p_virtual_port);
    json_push_kv_str(&p2p_route, "target_host", "127.0.0.1");
    json_push_kv_int(&p2p_route, "target_port",
                     port_map.p2p_target_port);
    json_push_kv_bool(&p2p_route, "expected",
                      port_map.p2p_route_expected);
    json_push_kv_bool(&p2p_route, "installed",
                      port_map.p2p_route_installed);
    json_push_back(&routes, &p2p_route);
    json_push_kv(&mapping, "routes", &routes);
    json_push_kv(result, "port_mapping", &mapping);

    json_free(&p2p_route);
    json_free(&app_route);
    json_free(&routes);
    json_free(&mapping);
    json_free(&handshake);
    json_free(&outbound_streams);
    return true;
}

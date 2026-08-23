/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: one coherent RPC contract for embedded Tor/onion readiness. */

#include "controllers/network_controller.h"

#include "controllers/strong_params.h"
#include "json/json.h"
#include "net/onion_peer_merge.h"
#include "net/onion_service.h"
#include "net/tor_integration.h"

#include <stdbool.h>
#include <string.h>

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
    return true;
}

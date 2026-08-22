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
        "Returns the embedded Tor bootstrap state and published onion "
        "address.");

    bool tor_enabled = tor_integration_is_enabled();
    bool tor_ready = tor_integration_is_ready();
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

    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.onion_status.v1");
    json_push_kv_str(result, "bootstrap_state", state);
    json_push_kv_bool(result, "tor_enabled", tor_enabled);
    json_push_kv_bool(result, "tor_ready", tor_ready);
    json_push_kv_bool(result, "onion_service_ready", service_ready);
    json_push_kv_str(result, "onion_address", address);
    return true;
}

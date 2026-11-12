/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The attestation-flight wrapper. It contributes no node,
 *          transport, or cleanup authority; it only selects the flight
 *          hook and execs the DHT acceptance. */

#include "attestation_flight.h"

#include "dht_acceptance_launch.h"

int zcl_attestation_flight_launch(const char *script_dir)
{
    return zcl_dht_acceptance_launch(script_dir, "attestation_flight_hook.sh");
}

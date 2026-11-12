/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The sovereign-source acceptance wrapper. It contributes no node,
 *          transport, or cleanup authority; it only selects the publication
 *          hook and execs the DHT acceptance. */

#include "dht_acceptance_launch.h"
#include "sovereign_source_network.h"

int zcl_sovereign_source_network_launch(const char *script_dir)
{
    return zcl_dht_acceptance_launch(script_dir,
                                     "sovereign_source_network_hook.sh");
}

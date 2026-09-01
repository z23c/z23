/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot-time wiring of the onion peer-discovery sources. */

#ifndef ZCL_CONFIG_BOOT_ONION_DISCOVERY_H
#define ZCL_CONFIG_BOOT_ONION_DISCOVERY_H

#include "net/onion_service.h"

/* Register EVERY discovery source with the onion service, and close the
 * chain binding that signed endpoint records need:
 *   - the unsigned wallet scrape passed in as `peer_discover` (kept:
 *     peer discovery is liveness-critical and its fallbacks are
 *     deliberate — nothing is removed or disabled here);
 *   - the signed zdesc descriptor directory (vcs/zdesc_swarm.h), which
 *     core/modules/net cannot reach itself because it is ranked below lib/vcs;
 *   - signed endpoint records (vcs/zendp_swarm.h), whose signing key is
 *     resolved against the on-chain identity projection. The lookup
 *     that makes that possible is registered here too.
 * Sources are additive and capacity-reserved: see the file comment in
 * engine/composition/src/boot_onion_discovery.c. `blog_serve` is passed straight
 * through to the app handlers. */
void boot_onion_discovery_register(onion_blog_serve_fn blog_serve,
                                   onion_peer_discover_fn peer_discover,
                                   const char *datadir);

#endif

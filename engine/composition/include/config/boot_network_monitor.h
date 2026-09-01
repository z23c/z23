/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot glue for the network-observability maintenance services — registers the
 * supervised network-monitor sampler and the whole-network crawler as OPTIONAL
 * maintenance services on a service kernel. Extracted from boot.c so the boot
 * service table stays small (file-size ceiling). */

#ifndef ZCL_CONFIG_BOOT_NETWORK_MONITOR_H
#define ZCL_CONFIG_BOOT_NETWORK_MONITOR_H

#include <stdbool.h>

struct zcl_service_kernel;
struct node_db;

/* Register the network_monitor service (start/stop wrappers + spec) on kernel k,
 * with db as the retained-history backing store. Returns the register result. */
bool boot_register_network_monitor_service(struct zcl_service_kernel *k,
                                           struct node_db *db);

/* Register the network_crawler service (whole-network observatory) on kernel k.
 * The crawler's address-table seed is fetched from the live connman at start
 * time (sync_monitor_connman + connman_addrman). ON by default; -netcrawl=0 /
 * ZCL_NETWORK_CRAWLER=0 opts out (the worker still registers and idles).
 * Returns the register result. */
bool boot_register_network_crawler_service(struct zcl_service_kernel *k);

/* Register the mesh_observation service: this node's own observation sampler
 * plus the reader-side collector (services/mesh_observation.h). Reports only —
 * it pronounces no verdict, gates no block, and feeds no watchdog. Returns the
 * register result. */
bool boot_register_mesh_observation_service(struct zcl_service_kernel *k);

/* Register the whole network-observability family (monitor + crawler +
 * mesh observation) on kernel k in one call, so the boot service table names
 * the family and this module owns its members. Returns the AND of the three
 * register results. */
bool boot_register_network_observability_services(struct zcl_service_kernel *k,
                                                  struct node_db *db);

#endif /* ZCL_CONFIG_BOOT_NETWORK_MONITOR_H */

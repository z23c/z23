/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Resident RPCs that fetch a signed plugin package root from the
 *          node's swarm peers and install it as a new generation without
 *          stopping the node (plugin_fetch_begin, plugin_fetch_poll). */
#ifndef ZCL_CONFIG_BOOT_PLUGIN_FETCH_H
#define ZCL_CONFIG_BOOT_PLUGIN_FETCH_H

struct rpc_table;

void boot_plugin_fetch_register_rpc(struct rpc_table *table);
/* Moves running fetch jobs on. Call with no swarm or store lock held. */
void boot_plugin_fetch_tick(void);

#endif

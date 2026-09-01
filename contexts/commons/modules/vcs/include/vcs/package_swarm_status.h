/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Read-only dumpstate snapshot of the node-global ZCODE package swarm
 * engine. Reports presence, peer count, active downloads, bounded
 * per-peer served/fetched bytes, and advertised roots. Never exposes
 * keys, wallet material, or datadir paths. */

#ifndef ZCL_VCS_PACKAGE_SWARM_STATUS_H
#define ZCL_VCS_PACKAGE_SWARM_STATUS_H

#include <stdbool.h>

struct json_value;

/* See AGENTS.md "Adding state introspection". Reentrant-safe.
 * Reports {"enabled":false,"present":false} when no global engine is
 * wired. The key is ignored: this is an engine-wide snapshot. */
bool vcs_package_swarm_status_dump_state_json(struct json_value *out,
                                              const char *key);

#endif /* ZCL_VCS_PACKAGE_SWARM_STATUS_H */

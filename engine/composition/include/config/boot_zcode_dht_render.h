/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: JSON wire rendering shared by the ZCODE DHT RPCs and tests. */

#ifndef ZCL_CONFIG_BOOT_ZCODE_DHT_RENDER_H
#define ZCL_CONFIG_BOOT_ZCODE_DHT_RENDER_H

#include "json/json.h"
#include "vcs/package_swarm_node.h"
#include "vcs/zcode_dht_service.h"

/* Render one published record row. include_wire adds the signed record_wire
 * hex (evidence mode); the plain listing omits it. */
void boot_zcode_dht_record_json(struct json_value *row,
                                const struct vcs_zcode_dht_record *record,
                                bool include_wire);

/* Render a bounded public lookup's state/result snapshot. */
void boot_zcode_dht_lookup_json(
    struct json_value *result,
    const struct vcs_zcode_dht_lookup_result *lookup);

/* Render the authenticated provider-route outcome, fetch result included. */
void boot_zcode_dht_provider_route_json(
    struct json_value *result,
    const struct vcs_zcode_dht_provider_route *route,
    enum vcs_swarm_fetch_result fetched);

#endif

/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_SERVICES_OPERATOR_PEER_SNAPSHOT_SERVICE_H
#define ZCL_SERVICES_OPERATOR_PEER_SNAPSHOT_SERVICE_H

#include "net/connman.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Coherent peer telemetry record.  The live path copies under cs_nodes; the
 * busy fallback reads one seqlocked cache generation. */
struct agent_peer_snapshot {
    size_t peer_count;
    size_t inbound_count;
    size_t outbound_count;
    size_t ready_count;
    size_t magicbean_peer_count;
    size_t zclassic_c23_peer_count;
    int peer_best_height;
    int64_t age_seconds;
    uint64_t generation;
    bool available;
    bool stale;
    bool direction_known;
    bool ready_known;
    bool peer_best_height_known;
    const char *warning_reason;
};

void agent_peer_snapshot_collect(struct agent_peer_snapshot *out,
                                 struct connman *cm);

#endif

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Private lane naming shared by the publication CAS decision layer
 * and its record/run/dumpstate surfaces. */

#ifndef ZCL_SERVICES_CONSENSUS_STATE_PUBLICATION_CAS_INTERNAL_H
#define ZCL_SERVICES_CONSENSUS_STATE_PUBLICATION_CAS_INTERNAL_H

#include "config/consensus_state_snapshot_install.h"

#include <stddef.h>

/* NULL for a lane this node will not publish into. Total over the enum. */
static inline const char *lane_name(enum consensus_state_target_lane lane)
{
    switch (lane) {
    case CONSENSUS_STATE_TARGET_LANE_COPY_PROOF: return "copy-proof";
    case CONSENSUS_STATE_TARGET_LANE_DEV: return "dev";
    case CONSENSUS_STATE_TARGET_LANE_SOAK: return "soak";
    case CONSENSUS_STATE_TARGET_LANE_CANONICAL: return "canonical";
    case CONSENSUS_STATE_TARGET_LANE_UNKNOWN: return NULL;
    }
    return NULL;
}

#endif /* ZCL_SERVICES_CONSENSUS_STATE_PUBLICATION_CAS_INTERNAL_H */

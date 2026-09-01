/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Content-verify progress heartbeat for consensus_state_bundle_validate.c's
 * O(bundle-size) coins/anchors/nullifiers scans: at least one log line every
 * 60s per stage, so a long deep scan is never silent. Header-only (single
 * translation unit consumer); `VALIDATE_SUBSYS` must already be defined by
 * the includer. */

#ifndef ZCL_CONSENSUS_STATE_BUNDLE_VALIDATE_HEARTBEAT_H
#define ZCL_CONSENSUS_STATE_BUNDLE_VALIDATE_HEARTBEAT_H

#include "core/utiltime.h"
#include "util/log_macros.h"

#include <stdint.h>

#define VALIDATE_HEARTBEAT_INTERVAL_US (60 * 1000000LL)

struct validate_heartbeat {
    const char *stage;
    int64_t started_us;
    int64_t last_log_us;
    uint64_t total;
};

static inline void heartbeat_begin(struct validate_heartbeat *hb,
                                   const char *stage, uint64_t total)
{
    hb->stage = stage;
    hb->started_us = GetTimeMicros();
    hb->last_log_us = hb->started_us;
    hb->total = total;
}

static inline void heartbeat_tick(struct validate_heartbeat *hb,
                                  uint64_t processed)
{
    int64_t now = GetTimeMicros();
    if (now - hb->last_log_us < VALIDATE_HEARTBEAT_INTERVAL_US)
        return;
    hb->last_log_us = now;
    double elapsed_s = (double)(now - hb->started_us) / 1000000.0;
    if (hb->total > 0)
        LOG_INFO(VALIDATE_SUBSYS,
                 "content verify progress: stage=%s rows=%llu/%llu "
                 "(%.1f%%) elapsed=%.0fs",
                 hb->stage, (unsigned long long)processed,
                 (unsigned long long)hb->total,
                 100.0 * (double)processed / (double)hb->total, elapsed_s);
    else
        LOG_INFO(VALIDATE_SUBSYS,
                 "content verify progress: stage=%s rows=%llu elapsed=%.0fs",
                 hb->stage, (unsigned long long)processed, elapsed_s);
}

#endif /* ZCL_CONSENSUS_STATE_BUNDLE_VALIDATE_HEARTBEAT_H */

/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_VALIDATION_MIRROR_CONSENSUS_H
#define ZCL_VALIDATION_MIRROR_CONSENSUS_H

#include "core/uint256.h"
#include "util/blocker.h"
#include <stdbool.h>
#include <stdint.h>

struct mirror_consensus_stats {
    bool enabled;
    bool override_active;
    bool last_override_safe;
    int64_t overrides_total;
    int64_t unsafe_overrides_total;
    int64_t blockers_total;
    int last_override_height;
    char last_override_reason[128];
    char last_override_scope[32];
    enum blocker_class activation_blocker_class;
    char activation_blocker_reason[128];
};

void mirror_consensus_set_enabled(bool enabled);

enum blocker_class mirror_consensus_classify_blocker_reason(
    const char *reason);
void mirror_consensus_record_override(int height, const char *reason);
void mirror_consensus_record_blocker(const char *reason);
/* Clear hash-disagreement from both the mirror latch and typed registry after
 * an exact common-height comparison proves agreement.  No other blocker can
 * be cleared through this automatic recovery surface. */
bool mirror_consensus_resolve_hash_disagreement(void);
/* Resolve only the two allowlisted transient hash-observation failures after
 * a later exact common-height comparison succeeds. */
bool mirror_consensus_resolve_observation_blocker(const char *reason);
void mirror_consensus_stats_snapshot(struct mirror_consensus_stats *out);
void mirror_consensus_reset_for_test(void);

#endif /* ZCL_VALIDATION_MIRROR_CONSENSUS_H */

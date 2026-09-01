/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "validation/checkpoint.h"
#include "validation/sync_evidence_policy.h"

bool reorg_is_allowed(int tip_h, int target_fork_h,
                      const char **reason_out)
{
    return zcl_reorg_allowed(tip_h, target_fork_h, false, reason_out);
}

bool height_is_immutable(int tip_h, int h)
{
    int immutable = zcl_immutable_height(tip_h);
    return immutable >= 0 && h <= immutable;
}

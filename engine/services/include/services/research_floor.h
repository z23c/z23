/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal work floor. */
#ifndef ZCL_RESEARCH_FLOOR_H
#define ZCL_RESEARCH_FLOOR_H

#include "base/result.h"

/* Work accounting for the Ironwood rehearsal descriptor.
 * work_floor is the minimum chain work, 32 raw bytes.
 * pow_limit is the easiest allowed proof-of-work target, 32 raw bytes.
 * scale_at_fork is 1 when an upgrade height rescales difficulty.
 * Does not select the chain, open a socket, or write a store. On failure
 * *out is left untouched. */
struct research_floor_view {
    unsigned char work_floor[32];
    unsigned char pow_limit[32];
    int scale_at_fork;
};

struct zcl_result research_floor_read(struct research_floor_view *out);

#endif

/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal block spacing. */
#ifndef ZCL_RESEARCH_SPACING_H
#define ZCL_RESEARCH_SPACING_H

#include "base/result.h"

#include <stdint.h>

/* Target spacing and retarget bounds for one Ironwood rehearsal height.
 * spacing is seconds between blocks. adjust_up and adjust_down are the
 * percent caps. min_difficulty is 1 when a block may use the minimum
 * target. mine_on_demand is 1 when the descriptor mines without peers.
 * Does not select the chain or write a store. On failure *out is left
 * untouched. */
struct research_spacing_view {
    int64_t spacing;
    int adjust_up;
    int adjust_down;
    int min_difficulty;
    int mine_on_demand;
};

struct zcl_result research_spacing_read(int height,
                                        struct research_spacing_view *out);

#endif

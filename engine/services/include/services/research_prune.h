/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal prune policy. */
#ifndef ZCL_RESEARCH_PRUNE_H
#define ZCL_RESEARCH_PRUNE_H

#include "base/result.h"

#include <stdint.h>

/* Retention policy for the Ironwood rehearsal descriptor.
 * prune_after is the height after which spent history may be dropped.
 * consistency_checks is 1 when the descriptor defaults those checks on.
 * Does not select the chain, open a socket, or write a store. On failure
 * *out is left untouched. */
struct research_prune_view {
    uint64_t prune_after;
    int consistency_checks;
};

struct zcl_result research_prune_read(struct research_prune_view *out);

#endif

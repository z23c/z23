/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal acceptance policy. */
#ifndef ZCL_RESEARCH_POLICY_H
#define ZCL_RESEARCH_POLICY_H

#include "base/result.h"

/* Acceptance gates for the Ironwood rehearsal descriptor.
 * require_standard is 1 when only standard transactions are admitted.
 * mining_requires_peers is 1 when a miner must see peers first.
 * Does not select the chain, open a socket, or write a store. On failure
 * *out is left untouched. */
struct research_policy_view {
    int require_standard;
    int mining_requires_peers;
};

struct zcl_result research_policy_read(struct research_policy_view *out);

#endif

/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal upgrade versions. */
#ifndef ZCL_RESEARCH_VERSION_H
#define ZCL_RESEARCH_VERSION_H

#include "base/result.h"

/* Protocol versions for the Ironwood rehearsal descriptor.
 * Each field is the nProtocolVersion of that network upgrade.
 * Does not select the chain, open a socket, or write a store. On failure
 * *out is left untouched. */
struct research_version_view {
    int overwinter;
    int sapling;
    int bubbles;
    int diffadj;
    int buttercup;
};

struct zcl_result research_version_read(struct research_version_view *out);

#endif

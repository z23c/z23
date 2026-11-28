/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal upgrade versions. */

#include "services/research_version.h"

#include "chain/chainparams.h"

#include <string.h>

struct zcl_result research_version_read(struct research_version_view *out)
{
    const struct chain_research_descriptor *d;
    const struct consensus_params *c;
    struct research_version_view got;

    if (!out)
        return ZCL_ERR(-1, "Missing version");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain)
        return ZCL_ERR(-2, "Research version missing");
    memset(&got, 0, sizeof got);
    c = &d->chain->consensus;
    got.overwinter = c->vUpgrades[UPGRADE_OVERWINTER].nProtocolVersion;
    got.sapling = c->vUpgrades[UPGRADE_SAPLING].nProtocolVersion;
    got.bubbles = c->vUpgrades[UPGRADE_BUBBLES].nProtocolVersion;
    got.diffadj = c->vUpgrades[UPGRADE_DIFFADJ].nProtocolVersion;
    got.buttercup = c->vUpgrades[UPGRADE_BUTTERCUP].nProtocolVersion;
    *out = got;
    return ZCL_OK;
}

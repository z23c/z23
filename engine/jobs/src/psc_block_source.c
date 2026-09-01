/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * psc_block_source — production block provider + audit worker sizing for the
 * Parallel State Compiler. See jobs/psc_block_source.h.
 */
#include "jobs/psc_block_source.h"

#include "chain/chain.h"                 /* block_index_status_load, BLOCK_HAVE_DATA */
#include "primitives/block.h"
#include "storage/disk_block_io.h"       /* read_block_from_disk_index_pread */
#include "util/cpu_topology.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"       /* active_chain_at */
#include "validation/main_state.h"

#include <stdlib.h>

bool psc_prod_block_provider(uint32_t height, struct block *blk, void *user)
{
    struct psc_prod_source *src = user;
    if (!blk || !src || !src->ms) {
        LOG_WARN("psc", "[psc] prod provider: NULL blk/src/ms at height=%u",
                 height);
        return false;
    }

    struct block_index *bi = active_chain_at(&src->ms->chain_active, (int)height);
    if (!bi || !bi->phashBlock ||
        !(block_index_status_load(bi) & BLOCK_HAVE_DATA)) {
        LOG_WARN("psc", "[psc] prod provider: no have-data block at height=%u",
                 height);
        return false;
    }

    const char *dir = src->datadir ? src->datadir : "";
    if (!read_block_from_disk_index_pread(blk, bi, dir)) {
        LOG_WARN("psc", "[psc] prod provider: pread failed at height=%u", height);
        return false;
    }
    return true;
}

int psc_audit_default_workers(void)
{
    const char *env = getenv("ZCL_PSC_WORKERS");
    if (env && env[0]) {
        int w = atoi(env);
        if (w < 1) w = 1;
        if (w > PSC_AUDIT_MAX_WORKERS) w = PSC_AUDIT_MAX_WORKERS;
        return w;
    }
    int cores = cpu_topology_physical_cores();
    if (cores < 1) cores = 1;
    if (cores > PSC_AUDIT_MAX_WORKERS) cores = PSC_AUDIT_MAX_WORKERS;
    return cores;
}

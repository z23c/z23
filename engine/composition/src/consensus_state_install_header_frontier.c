/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Checkpoint-header view used by the sovereign state installer. */

#include "config/consensus_state_install_runtime.h"

#include "chain/chain.h"
#include "chain/checkpoints.h"
#include "jobs/validate_headers_stage.h"
#include "services/chain_state_service.h"
#include "util/log_macros.h"
#include "validation/main_state.h"

#include <string.h>

#define ICB_SUBSYS "install_consensus_bundle"

bool consensus_state_checkpoint_header_ready(struct main_state *ms)
{
    if (!ms)
        return false;
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp || cp->height < 0)
        return false;
    struct block_index *header = ms->pindex_best_header;
    if (!header || header->nHeight < cp->height)
        return false;
    struct block_index *at =
        block_index_get_ancestor(header, (int)cp->height);
    return at && at->phashBlock &&
           memcmp(at->phashBlock->data, cp->block_hash, 32) == 0;
}

bool consensus_state_install_restore_checkpoint_header_frontier(
    struct main_state *ms)
{
    if (!ms)
        return false;
    if (consensus_state_checkpoint_header_ready(ms))
        return true;

    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp || cp->height < 0)
        return false;

    /* Only the baked checkpoint hash may use this recovery path. */
    struct uint256 cp_hash;
    memcpy(cp_hash.data, cp->block_hash, 32);
    struct block_index *candidate =
        block_map_find(&ms->map_block_index, &cp_hash);
    if (!candidate || candidate->nHeight != cp->height ||
        !candidate->phashBlock) {
        LOG_INFO(ICB_SUBSYS,
                 "checkpoint header h=%d absent from imported block map; "
                 "install remains deferred", (int)cp->height);
        return false;
    }

    /* Frozen full PoW + Equihash validation precedes the durable fact. */
    if (!validate_headers_stage_ensure_pass_record(ms, cp->height)) {
        LOG_WARN(ICB_SUBSYS,
                 "checkpoint header h=%d failed frozen validation; refusing "
                 "frontier restore", (int)cp->height);
        return false;
    }

    int previous = ms->pindex_best_header
        ? ms->pindex_best_header->nHeight : -1;
    bool promoted = false;
    enum csr_result rc = csr_promote_header_tip(
        csr_instance(), &ms->chain_active, &ms->pindex_best_header, candidate,
        "instant_on_checkpoint_frontier", &promoted);
    if (rc != CSR_OK) {
        LOG_WARN(ICB_SUBSYS,
                 "checkpoint header frontier restore rejected h=%d code=%s",
                 (int)cp->height, csr_result_name(rc));
        return false;
    }
    if (promoted) {
        LOG_INFO(ICB_SUBSYS,
                 "checkpoint header frontier restored h=%d from=%d after "
                 "frozen validation", (int)cp->height, previous);
    }
    return consensus_state_checkpoint_header_ready(ms);
}

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the boot-time fresh-genesis seed and the gate that withholds it
 * from a header-seeded node whose checkpoint install can still run at this
 * boot. Split out of engine/composition/src/boot_services.c (at its line
 * ceiling); the one caller stays there (boot_register_core_liveness_and_
 * reducer). Contracts: config/boot_internal.h.
 */
#include "config/boot_internal.h"
#include "config/consensus_state_install_runtime.h"  /* checkpoint_header_ready, autodetect */
#include "config/consensus_state_snapshot_install.h" /* read_authority_stamp */
#include "jobs/stage_helpers.h"                      /* stage_log_row_count */
#include "jobs/tip_finalize_stage.h"                 /* tip_finalize_stage_cursor, active_chain_tip */
#include "services/reducer_ingest_service.h"         /* reducer_ingest_try_seed_anchor */
#include "storage/coins_kv.h"                        /* coins_kv_get_applied_height */
#include "storage/progress_store.h"                  /* progress_store_db */
#include "util/log_macros.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Nothing applied: empty tip_finalize_log, no coins frontier key, no install
 * stamp. Any read error counts as applied. */
static bool genesis_seed_nothing_applied(sqlite3 *pdb)
{
    int32_t applied = -1;
    bool coins = true, stamped = true;
    struct consensus_state_install_stamp stamp;
    return pdb && stage_log_row_count(pdb, "boot", "tip_finalize_log") == 0 &&
           coins_kv_get_applied_height(pdb, &applied, &coins) && !coins &&
           consensus_state_install_read_authority_stamp(pdb, &stamp, &stamped) &&
           !stamped;
}

bool boot_genesis_seed_withheld_for_header_seed(struct main_state *ms, sqlite3 *pdb,
                                                const char *datadir, char *bundle,
                                                size_t bundle_cap)
{
    if (bundle && bundle_cap)
        bundle[0] = '\0';
    if (!consensus_state_checkpoint_header_ready(ms) || !genesis_seed_nothing_applied(pdb))
        return false;
    /* NULL when installed, when bundles/ holds no installable bundle, when every
     * candidate carries a .failed sibling, and on a failed allocation. */
    char *staged = datadir ? boot_autodetect_consensus_bundle(datadir) : NULL;
    if (!staged)
        return false;
    if (bundle && bundle_cap)
        (void)snprintf(bundle, bundle_cap, "%s", staged);
    free(staged);
    return true;
}

void boot_seed_fresh_genesis(struct main_state *ms, const struct chain_params *params,
                             const char *datadir)
{
    struct block_index *g = ms && params ? active_chain_tip(&ms->chain_active) : NULL;
    if (!g || !g->phashBlock || g->nHeight != 0 || tip_finalize_stage_cursor() != 0 ||
        !uint256_eq(g->phashBlock, &params->consensus.hashGenesisBlock))
        return;
    char bundle[PATH_MAX];
    if (!boot_genesis_seed_withheld_for_header_seed(ms, progress_store_db(), datadir, bundle,
                                                    sizeof(bundle))) {
        reducer_ingest_try_seed_anchor(0, g->phashBlock->data, "fresh-genesis-boot");
        return;
    }
    LOG_INFO("boot", "fresh-genesis seed withheld: the header chain (best h=%d) owns the "
             "compiled checkpoint, nothing is applied (tip_finalize cursor 0, empty "
             "tip_finalize_log, no coins frontier, no install stamp) and the installable "
             "bundle %s is staged; every cursor stays 0 for the checkpoint install, as on "
             "the first boot",
             ms->pindex_best_header ? ms->pindex_best_header->nHeight : -1, bundle);
}

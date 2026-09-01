/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: internal contract for the POST-INSTALL derived-state reconciliation
 * of the sovereign consensus-state install, shared between
 * engine/composition/src/consensus_state_install_derived_state.c (the reconciliation) and
 * engine/composition/src/consensus_state_install_runtime.c (the install engine that runs
 * it once activation has durably committed).
 *
 * Split out of engine/composition/src/consensus_state_install_runtime.c when that file
 * passed its shape ceiling.
 */

#ifndef ZCL_CONSENSUS_STATE_INSTALL_DERIVED_STATE_INTERNAL_H
#define ZCL_CONSENSUS_STATE_INSTALL_DERIVED_STATE_INTERNAL_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

struct node_db;


/* Post-install derived-state reconciliation: reset the process-local
 * provable-tip cache, confirm the installed coin tip sits exactly at
 * bundle_height, and replace node.db's Sapling tree pair with the frontier the
 * activation installed. True iff every derived store is now consistent. */
bool icb_invalidate_derived_state(struct node_db *ndb, sqlite3 *progress_db,
                                  int32_t bundle_height);

/* Wholesale reset of node.db's DERIVED `utxos` mirror plus its sync cursor, so
 * utxo_mirror_sync_service rebuilds straight from the just-installed coins_kv.
 * Best-effort by design — see the definition's doc comment. */
bool icb_reset_utxo_mirror(struct node_db *ndb);

#endif /* ZCL_CONSENSUS_STATE_INSTALL_DERIVED_STATE_INTERNAL_H */

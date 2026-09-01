/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * node_db_catchup_proven — the proven-authority read of the bulk catchup
 * walk, split out of node_db_catchup_service.c so the service stays under
 * the E1 file-size ratchet (same split pattern as node_db_catchup_decrypt.c
 * / node_db_catchup_sparse.c). The TRYLOCK rationale moves with it.
 *
 * TRYLOCK, never block: the catchup pass runs on the db_service WORKER, and
 * the reducer drain holds g_tx_lock across whole stage steps — including
 * tip_finalize's post-finalize node.db write, which submits a job to THIS
 * worker and cond-waits for its completion (db_service_submit_job). A
 * blocking acquisition here is a textbook ABBA deadlock: the drain holds
 * the tx and waits on the worker; the worker holds the job slot and waits
 * on the tx. Observed live under on-demand regtest mining: the first
 * concurrent catchup job froze the whole node (RPC workers, supervisor tick
 * runner, utxo_mirror, self-heal all queued behind g_tx_lock). Skipping
 * the read when the tx is contended only downgrades THIS pass's
 * sparse-projection-tip inputs (the result feeds
 * node_db_catchup_sparse_prefix_target and nothing else); the catchup pass
 * re-runs periodically and the next uncontended pass reads the truth.
 *
 * one-result-type-ok:contention-skip-read — the one export is a bool
 * downgrade-read whose false means "tx contended, try next pass", never an
 * error; there is no failure reason to carry. */

// one-result-type-ok:contention-skip-read — bool downgrade-read, no fallible service surface

#include "node_db_catchup_internal.h"

#include "storage/coins_kv.h"
#include "storage/progress_store.h"

bool node_db_catchup_read_proven_authority(sqlite3 *progress_db,
                                           int32_t *applied_out)
{
    if (!progress_store_tx_trylock())
        return false; /* raw-return-ok:trylock-contention-is-a-planned-skip — the next uncontended pass reads the truth; logging the routine case would storm */
    bool authority = coins_kv_is_proven_authority(progress_db, applied_out);
    progress_store_tx_unlock();
    return authority;
}

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_stage_lookup - production live-prevout resolver for the
 * utxo_apply Job. Kept separate from the stage step so the stage TU owns only
 * cursor/write flow while this TU owns read-side UTXO lookup semantics. */

#include "jobs/utxo_apply_stage.h"
#include "utxo_apply_stage_internal.h"

#include "coins/coins.h"
#include "core/uint256.h"
#include "storage/coins_kv.h"
#include "storage/coins_ram.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

/* One prepared prevout reader per outer utxo_apply batch. The batch is owned
 * by one reducer thread and one progress.kv handle, so this thread-local cache
 * has no cross-thread or rebind hazard. Outside a batch the established
 * prepare/read/finalize path remains unchanged. */
static _Thread_local sqlite3 *t_lookup_batch_db;
static _Thread_local sqlite3_stmt *t_prevout_stmt;

void utxo_apply_lookup_batch_begin(sqlite3 *db)
{
    if (t_prevout_stmt)
        sqlite3_finalize(t_prevout_stmt);
    t_prevout_stmt = NULL;
    t_lookup_batch_db = db;
}

void utxo_apply_lookup_batch_end(void)
{
    if (t_prevout_stmt)
        sqlite3_finalize(t_prevout_stmt);
    t_prevout_stmt = NULL;
    t_lookup_batch_db = NULL;
}

/* Production prevout resolver for utxo_apply, the init-time default for
 * g_lookup - the analogue of script_validate's created_index_prevout
 * self-default, but with the CORRECT semantics for utxo_apply: found must
 * mean "currently UNSPENT". coins_kv DELETEs a coin on spend, so a hit from
 * coins_kv_get_coins == the coin is live (double-spend-safe); a creation
 * index (which never deletes spent rows) would report found=true for an
 * already-spent coin and let utxo_apply accept a double-spend (monetary
 * inflation / hard fork) AND false-trip BIP30 collision - it MUST NOT be
 * used here. The full pre-image (value/height/is_coinbase/script) is
 * required for the inverse-delta restore-ADD. A genuine miss returns
 * found=false (compute_block_delta then records spend_unknown_utxo with the
 * exact outpoint - never a silent pass).
 *
 * FRESHNESS CONTRACT: reads the authoritative coins set on the progress.kv
 * handle inside the apply path's progress_store_tx_lock, and apply_coins_kv
 * authors coins_kv IN the stage txn - a coin created by an earlier block is
 * already committed before a later block's step_apply resolves it, so reads
 * are inherently fresh with no catch_up dependency. */
bool utxo_apply_stage_lookup_live(const struct uint256 *txid, uint32_t vout,
                                  struct utxo_apply_lookup *out, void *user)
{
    (void)user;
    if (!txid || !out)
        return false;
    memset(out, 0, sizeof(*out));

    sqlite3 *db = progress_store_db();
    if (!db)
        return true;   /* store not open yet -> treat as absent (found=0),
                        * matching the lookup==NULL "all external absent"
                        * contract; never a false-accept. */

    int64_t value = 0;
    int32_t height = 0;
    bool is_coinbase = false;
    size_t slen = 0;
    bool found;
    if (t_lookup_batch_db == db && !coins_ram_active())
        found = coins_kv_get_prevout_sqlite_cached(
            db, &t_prevout_stmt, txid->data, vout, &value, out->script,
            UTXO_APPLY_SCRIPT_MAX, &slen, &height, &is_coinbase);
    else
        found = coins_kv_get_prevout(
            db, txid->data, vout, &value, out->script,
            UTXO_APPLY_SCRIPT_MAX, &slen, &height, &is_coinbase);
    if (!found)
        return true;   /* no live output at this txid -> found stays false */

    if (slen > UTXO_APPLY_SCRIPT_MAX) {
        /* Contract violation (a UTXO scriptPubKey is <= MAX_SCRIPT_SIZE ==
         * UTXO_APPLY_SCRIPT_MAX). Fail the resolver (compute_block_delta turns
         * this into an internal_error) rather than silently truncate. */
        return false;
    }
    out->found       = true;
    out->value       = value;
    out->height      = (uint32_t)(height < 0 ? 0 : height);
    out->is_coinbase = is_coinbase;
    out->script_len  = (uint32_t)slen;
    return true;
}

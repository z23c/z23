/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_mirror_delta — incremental (delta) apply for the node.db `utxos` mirror.
 *
 * The wholesale rebuild (utxo_mirror_sync_service.c mirror_rebuild_from_coins_kv)
 * does DELETE FROM utxos + re-INSERT of the ENTIRE ~1.3M-row UTXO set inside one
 * node.db write transaction on essentially every accepted block. That giant
 * write holds the WAL write lock for seconds, starving the wallet-key flush and
 * every other node.db writer. This module applies ONLY the coins that changed
 * since the mirror cursor:
 *   - adds  = live coins_kv rows whose creation height ∈ [cursor, frontier)
 *             (a coin created-and-spent within the range is not live, so it is
 *              correctly never inserted),
 *   - deletes = the outpoints in utxo_apply_delta.spent_blob for those heights,
 *   - derived caches (addresses, wallet_utxos) are re-derived only for the
 *     addresses touched by the delta (db_utxo_refresh_caches_for_address).
 * The final mirror equals the live coins_kv set at the next-height cursor
 * regardless of
 * chunk boundaries or the node advancing mid-catch-up, and the whole apply is
 * idempotent (INSERT OR REPLACE / no-op DELETE / re-derive), so a crash between
 * the COMMIT and the cursor persist simply re-applies the same range.
 *
 * SAFETY BOUNDARY: reads coins_kv + utxo_apply_delta through an independent
 * READ-ONLY connection to progress.kv; WRITES only node.db (utxos + the two
 * derived caches). It never writes coins_kv and never touches the consensus
 * path. The mirror is an explicitly rebuildable, non-authoritative read model.
 */

#ifndef ZCL_SERVICES_UTXO_MIRROR_DELTA_H
#define ZCL_SERVICES_UTXO_MIRROR_DELTA_H

#include <stdbool.h>
#include <stdint.h>

struct node_db;

/* Result of one delta pass. */
enum utxo_mirror_delta_status {
    UTXO_MIRROR_DELTA_OK       = 0,  /* applied; *out_applied_through advanced */
    UTXO_MIRROR_DELTA_ERROR    = -1, /* node.db write failed; caller rolls back */
    UTXO_MIRROR_DELTA_FALLBACK = -2, /* delta unsafe/unavailable; quarantine */
};

/* Apply coin changes in [cursor, min(frontier,cursor+max_heights)) into the
 * node.db mirror + derived caches. `cursor_key` is persisted in the SAME
 * transaction as those rows and the commitment checkpoint. On OK,
 * *out_applied_through is the next-height cursor the mirror now covers and
 * *out_rows_changed is the number of add+delete row ops performed.
 *
 * Preconditions the caller must have checked: cursor >= 0, frontier > cursor,
 * mirror non-empty. `max_heights` bounds the per-pass work so a large post-
 * outage gap never holds the write lock too long (<=0 means no cap).
 * Returns UTXO_MIRROR_DELTA_FALLBACK when a required utxo_apply_delta row is
 * missing. The caller must quarantine the derived mirror; a missing causal
 * delta must never trigger an automatic whole-table rebuild loop. */
int utxo_mirror_delta_apply(struct node_db *ndb,
                            int32_t cursor, int32_t frontier,
                            int32_t max_heights,
                            const char *cursor_key,
                            int32_t *out_applied_through,
                            int64_t *out_rows_changed);

#endif /* ZCL_SERVICES_UTXO_MIRROR_DELTA_H */

/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * snapshot_store_port — storage interface for the fast-sync UTXO
 * snapshot subsystem's sqlite surface.
 *
 * The snapshot subsystem (snapshot_offer.c / snapshot_fetch.c /
 * snapshot_sync_service.c) negotiates, receives, and verifies a full
 * UTXO-set snapshot from a peer. It is CONSENSUS-ADJACENT: the snapshot
 * is pinned to a SHA3-256 UTXO commitment, so the bytes written to the
 * staging table and the rows counted out of it must be bit-for-bit
 * identical.
 *
 * This port captures exactly the raw-sqlite STORAGE access for those three
 * files against `node_db->db` (and the cached
 * `stmt_snapshot_staging_insert` statement). The SHA3 commitment math
 * itself — fast_sync_compute_utxo_root_db() and
 * utxo_commitment_sha3_compute_table() — is NOT part of this seam: it
 * stays in the service, called with the live sqlite handle, untouched.
 * Only the surrounding storage reads/writes move behind this interface.
 *
 * Captured operations (the raw-sqlite sites; node_db_* helper calls such
 * as state_get/state_set/exec/begin/commit are already a seam and are
 * left as-is in the service):
 *
 *   utxo_count(out)            "SELECT COUNT(*) FROM utxos" over the bound
 *                              node_db. The active-UTXO-set size, read in
 *                              three places (accept-offer skip guard,
 *                              awaiting-utxos guard, recovery manifest).
 *                              Returns true and sets *out on the row; false
 *                              (out untouched) on prepare/step miss.
 *
 *   staging_count()            "SELECT COUNT(*) FROM snapshot_staging_utxos"
 *                              — number of staged (not-yet-promoted) rows.
 *                              Returns the count, or -1 on prepare/step
 *                              miss.
 *
 *   tip_chainwork(hash,out)    "SELECT chain_work FROM blocks WHERE hash=?"
 *                              — the 32-byte chainwork blob for a block.
 *                              Returns true and fills out[32] only when the
 *                              row exists, the blob is >= 32 bytes, AND the
 *                              chainwork is non-zero; false otherwise.
 *
 *   staging_insert(u)          the cached INSERT OR REPLACE INTO
 *                              snapshot_staging_utxos statement — the hot
 *                              chunk-apply write. Binds the db_utxo fields
 *                              in the same order; returns true on
 *                              SQLITE_DONE. This is the only write this port
 *                              owns; it goes through the AR cached-save
 *                              lifecycle in the adapter.
 *
 *   set_busy_timeout(ms)       sqlite3_busy_timeout(db, ms) — the
 *                              receive-mode busy timeout knob.
 *
 * No sqlite type appears in this header. The adapter under
 * platform/adapters/outbound/persistence/ is the only thing that includes sqlite
 * for this subsystem. The bind wraps the already-open node_db connection
 * (owned by boot) and never closes it.
 *
 * Threading: the live adapter wraps the single node_db opened by boot.
 * Callers serialise through the snapshot service lock / db_service write
 * runner; the port adds no locking.
 */

#ifndef ZCL_PORTS_SNAPSHOT_STORE_PORT_H
#define ZCL_PORTS_SNAPSHOT_STORE_PORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct db_utxo;   /* models/utxo.h — plain model type, no sqlite */

struct snapshot_store_port {
    void *self;

    /* "SELECT COUNT(*) FROM utxos" over the bound connection. Sets *out and
     * returns true on the single returned row; false (out untouched) on any
     * prepare/step miss or NULL/closed connection. */
    bool (*utxo_count)(void *self, int64_t *out);

    /* "SELECT COUNT(*) FROM snapshot_staging_utxos". Returns the count, or
     * -1 on NULL/closed connection or prepare/step miss. */
    int64_t (*staging_count)(void *self);

    /* "SELECT chain_work FROM blocks WHERE hash=?". Fills out[32] and returns
     * true only when the row exists, the blob is at least 32 bytes, and the
     * decoded chainwork is non-zero; false otherwise (out may be partially
     * written only on the success path). */
    bool (*tip_chainwork)(void *self, const uint8_t hash[32], uint8_t out[32]);

    /* Cached INSERT OR REPLACE INTO snapshot_staging_utxos. Binds u's fields
     * (txid, vout, value, script, script_type, address_hash|NULL, height,
     * is_coinbase) in column order and runs the cached statement. Returns
     * true on SQLITE_DONE. false on NULL/closed connection, missing cached
     * statement, or step failure. */
    bool (*staging_insert)(void *self, const struct db_utxo *u);

    /* sqlite3_busy_timeout(db, ms) on the bound connection. No-op (returns
     * false) on NULL/closed connection. */
    bool (*set_busy_timeout)(void *self, int ms);
};

#endif /* ZCL_PORTS_SNAPSHOT_STORE_PORT_H */

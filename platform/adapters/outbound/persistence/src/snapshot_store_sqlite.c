/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * snapshot_store_sqlite — sqlite implementation of snapshot_store_port.
 *
 * The five methods below implement the port for the raw sqlite snapshot
 * storage ops (utxo count, staging count, tip chainwork read, staging
 * insert, busy-timeout knob). The SQL text, bind order, column extraction,
 * chainwork guards, and step semantics are bit-for-bit identical to the
 * snapshot subsystem's storage path, so the staging rows written and the
 * counts read match exactly.
 *
 * Reads use the AR_STEP_ROW_READONLY macro. The staging insert uses a
 * cached-statement raw step with a `raw-sql-ok` lint suppression because
 * the chunk-apply caller handles the return code per-row.
 *
 * The SHA3 commitment math (fast_sync_compute_utxo_root_db /
 * utxo_commitment_sha3_compute_table) is NOT here — it stays in the service.
 */

#include "adapters/outbound/persistence/snapshot_store_sqlite.h"

#include "models/database.h"
#include "models/utxo.h"
#include "util/ar_step_readonly.h"
#include "validation/sync_evidence_policy.h"

#include <sqlite3.h>
#include <stddef.h>
#include <string.h>

static inline struct snapshot_store_sqlite_ctx *ctx_of(void *self)
{
    return (struct snapshot_store_sqlite_ctx *)self;
}

/* "SELECT COUNT(*) FROM utxos" over the bound node_db. */
static bool snap_store_utxo_count(void *self, int64_t *out)
{
    struct snapshot_store_sqlite_ctx *c = ctx_of(self);
    if (!c || !c->ndb || !c->ndb->open || !c->ndb->db || !out)
        return false;
    sqlite3_stmt *s = NULL;
    bool ok = false;
    if (sqlite3_prepare_v2(c->ndb->db, "SELECT COUNT(*) FROM utxos",
                           -1, &s, NULL) == SQLITE_OK && s) {
        if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
            *out = sqlite3_column_int64(s, 0);
            ok = true;
        }
        sqlite3_finalize(s);
    }
    return ok;
}

/* "SELECT COUNT(*) FROM snapshot_staging_utxos"; -1 sentinel on miss. */
static int64_t snap_store_staging_count(void *self)
{
    struct snapshot_store_sqlite_ctx *c = ctx_of(self);
    if (!c || !c->ndb || !c->ndb->open || !c->ndb->db)
        return -1;
    sqlite3_stmt *st = NULL;
    int64_t result = -1;
    /* Staging table name matches SNAPSYNC_STAGING_TABLE in the service's
     * snapshot_sync_internal.h; inlined here so the adapter does not depend
     * on a service-private header. */
    if (sqlite3_prepare_v2(c->ndb->db,
            "SELECT COUNT(*) FROM snapshot_staging_utxos",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (AR_STEP_ROW_READONLY(st) == SQLITE_ROW)
        result = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return result;
}

/* "SELECT chain_work FROM blocks WHERE hash=?" — fills out[32] only on a
 * non-zero chainwork hit. */
static bool snap_store_tip_chainwork(void *self, const uint8_t hash[32],
                                     uint8_t out[32])
{
    struct snapshot_store_sqlite_ctx *c = ctx_of(self);
    sqlite3_stmt *s = NULL;
    bool ok = false;

    if (!c || !c->ndb || !c->ndb->open || !c->ndb->db || !hash || !out)
        return false;
    if (sqlite3_prepare_v2(c->ndb->db,
            "SELECT chain_work FROM blocks WHERE hash=?",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;
    sqlite3_bind_blob(s, 1, hash, 32, SQLITE_STATIC);
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        const void *cw = sqlite3_column_blob(s, 0);
        if (cw && sqlite3_column_bytes(s, 0) >= 32) {
            memcpy(out, cw, 32);
            ok = !zcl_chainwork_is_zero(out);
        }
    }
    sqlite3_finalize(s);
    return ok;
}

/* Cached INSERT OR REPLACE INTO snapshot_staging_utxos, using the
 * cached-statement raw step (caller handles the per-row return code). */
static bool snap_store_staging_insert(void *self, const struct db_utxo *u)
{
    struct snapshot_store_sqlite_ctx *c = ctx_of(self);
    sqlite3_stmt *s;

    if (!c || !c->ndb || !c->ndb->stmt_snapshot_staging_insert || !u)
        return false;
    s = c->ndb->stmt_snapshot_staging_insert;
    sqlite3_reset(s);
    sqlite3_clear_bindings(s);
    sqlite3_bind_blob(s, 1, u->txid, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, (int)u->vout);
    sqlite3_bind_int64(s, 3, u->value);
    sqlite3_bind_blob(s, 4, u->script, (int)u->script_len, SQLITE_STATIC);
    sqlite3_bind_int(s, 5, (int)u->script_type);
    if (u->has_address)
        sqlite3_bind_blob(s, 6, u->address_hash, 20, SQLITE_STATIC);
    else
        sqlite3_bind_null(s, 6);
    sqlite3_bind_int(s, 7, u->height);
    sqlite3_bind_int(s, 8, u->is_coinbase ? 1 : 0);
    return sqlite3_step(s) == SQLITE_DONE;  // raw-sql-ok:state-kv-write-caller-handles-rc
}

/* sqlite3_busy_timeout(db, ms) on the bound connection. */
static bool snap_store_set_busy_timeout(void *self, int ms)
{
    struct snapshot_store_sqlite_ctx *c = ctx_of(self);
    if (!c || !c->ndb || !c->ndb->open || !c->ndb->db)
        return false;
    sqlite3_busy_timeout(c->ndb->db, ms);
    return true;
}

bool snapshot_store_sqlite_bind(struct snapshot_store_sqlite_ctx *ctx,
                                struct node_db *ndb,
                                struct snapshot_store_port *out_port)
{
    if (!ctx || !out_port)
        return false;
    ctx->ndb = ndb;
    *out_port = (struct snapshot_store_port){
        .self             = ctx,
        .utxo_count       = snap_store_utxo_count,
        .staging_count    = snap_store_staging_count,
        .tip_chainwork    = snap_store_tip_chainwork,
        .staging_insert   = snap_store_staging_insert,
        .set_busy_timeout = snap_store_set_busy_timeout,
    };
    return true;
}

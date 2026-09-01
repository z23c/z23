/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * node_health_store_sqlite — sqlite implementation of
 * node_health_store_port.
 *
 * The three methods below are the raw health reads (fixed-SQL int /
 * int64 queries, and the sqlite3_db_filename + WAL stat). The EXACT SQL
 * text and the WAL-path construction are load-bearing: they must stay
 * identical so the health snapshot is bit-for-bit identical.
 */

#include "adapters/outbound/persistence/node_health_store_sqlite.h"

#include "util/ar_step_readonly.h"

#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>

static inline struct node_health_store_sqlite_ctx *ctx_of(void *self)
{
    return (struct node_health_store_sqlite_ctx *)self;
}

/* "SELECT COALESCE(MAX(height), -1) FROM blocks" — read on query_db. */
static bool nhs_tip_height_from_blocks(void *self, int *out)
{
    struct node_health_store_sqlite_ctx *c = ctx_of(self);
    if (!c || !c->query_db || !out)
        return false;
    sqlite3_stmt *stmt = NULL;
    bool ok = false;
    if (sqlite3_prepare_v2(c->query_db,
                           "SELECT COALESCE(MAX(height), -1) FROM blocks",
                           -1, &stmt, NULL) != SQLITE_OK)
        return false;
    if (AR_STEP_ROW_READONLY(stmt) == SQLITE_ROW) {
        *out = sqlite3_column_int(stmt, 0);
        ok = true;
    }
    sqlite3_finalize(stmt);
    return ok;
}

/* "SELECT count(*) FROM utxos" — read on query_db. */
static bool nhs_utxo_count(void *self, int64_t *out)
{
    struct node_health_store_sqlite_ctx *c = ctx_of(self);
    if (!c || !c->query_db || !out)
        return false;
    sqlite3_stmt *stmt = NULL;
    bool ok = false;
    if (sqlite3_prepare_v2(c->query_db,
                           "SELECT count(*) FROM utxos",
                           -1, &stmt, NULL) != SQLITE_OK)
        return false;
    if (AR_STEP_ROW_READONLY(stmt) == SQLITE_ROW) {
        *out = sqlite3_column_int64(stmt, 0);
        ok = true;
    }
    sqlite3_finalize(stmt);
    return ok;
}

/* Resolve the primary node DB's "main" filename, then stat "<path>-wal".
 * Read on node_db. */
static bool nhs_wal_size_bytes(void *self, int64_t *out)
{
    struct node_health_store_sqlite_ctx *c = ctx_of(self);
    if (!c || !c->node_db || !out)
        return false;
    const char *db_path = sqlite3_db_filename(c->node_db, "main");
    if (!db_path || !db_path[0])
        return false;
    char wal_path[1024];
    struct stat wal_st;
    snprintf(wal_path, sizeof(wal_path), "%s-wal", db_path);
    if (stat(wal_path, &wal_st) != 0)
        return false;
    *out = wal_st.st_size;
    return true;
}

bool node_health_store_sqlite_bind(struct node_health_store_sqlite_ctx *ctx,
                                   sqlite3 *query_db,
                                   sqlite3 *node_db,
                                   struct node_health_store_port *out_port)
{
    if (!ctx || !out_port)
        return false;
    ctx->query_db = query_db;
    ctx->node_db = node_db;
    *out_port = (struct node_health_store_port){
        .self                  = ctx,
        .tip_height_from_blocks = nhs_tip_height_from_blocks,
        .utxo_count            = nhs_utxo_count,
        .wal_size_bytes        = nhs_wal_size_bytes,
    };
    return true;
}

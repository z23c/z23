/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * block_index_sidecar_sqlite — sqlite implementation of
 * block_index_sidecar_port.
 *
 * The lookup below is the raw cross-check read backing bii_verify():
 * prepare "SELECT height FROM blocks WHERE hash=?", bind the 32-byte tip
 * hash as a blob, single-shot readonly step, read column-0 as int64,
 * finalize. The EXACT SQL text, bind order, step, and column read are
 * load-bearing so the bii_verify() verdict is bit-for-bit identical.
 */

#include "adapters/outbound/persistence/block_index_sidecar_sqlite.h"

#include "util/ar_step_readonly.h"

#include <stddef.h>
#include <stdint.h>

static inline struct block_index_sidecar_sqlite_ctx *ctx_of(void *self)
{
    return (struct block_index_sidecar_sqlite_ctx *)self;
}

/* "SELECT height FROM blocks WHERE hash=?". Returns the three-way
 * lookup result. */
static enum bii_height_lookup bii_sql_lookup_block_height(void *self,
                                                          const uint8_t hash32[32],
                                                          int64_t *out_height)
{
    struct block_index_sidecar_sqlite_ctx *c = ctx_of(self);
    if (!c || !c->db || !hash32)
        return BII_HEIGHT_UNAVAILABLE;  /* skip cross-check */

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->db,
            "SELECT height FROM blocks WHERE hash=?", -1, &st, NULL) != SQLITE_OK)
        return BII_HEIGHT_UNAVAILABLE;  /* schema may not be ready */

    sqlite3_bind_blob(st, 1, hash32, 32, SQLITE_STATIC);
    int rc = AR_STEP_ROW_READONLY(st);
    enum bii_height_lookup result;
    if (rc == SQLITE_ROW) {
        if (out_height)
            *out_height = sqlite3_column_int64(st, 0);
        result = BII_HEIGHT_FOUND;
    } else {
        result = BII_HEIGHT_NOT_FOUND;
    }
    sqlite3_finalize(st);
    return result;
}

bool block_index_sidecar_sqlite_bind(struct block_index_sidecar_sqlite_ctx *ctx,
                                     sqlite3 *db,
                                     struct block_index_sidecar_port *out_port)
{
    if (!ctx || !out_port)
        return false;
    ctx->db = db;
    *out_port = (struct block_index_sidecar_port){
        .self                = ctx,
        .lookup_block_height = bii_sql_lookup_block_height,
    };
    return true;
}

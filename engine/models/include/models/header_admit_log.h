/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_DB_MODEL_HEADER_ADMIT_LOG_H
#define ZCL_DB_MODEL_HEADER_ADMIT_LOG_H

#include "models/activerecord.h"
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

/* ActiveRecord model: HeaderAdmitLog
 *
 * One row per admitted header in the `header_admit` staged-sync reducer
 * stage. The table lives in `progress.kv` (the durable cursor store),
 * NOT node.db — so this model carries its own thin handle wrapper that
 * exposes a `sqlite3 *db` member, the only contract the AR_* macros
 * require (see engine/models/include/models/activerecord.h, "Database-handle
 * genericity"). The progress_store singleton owns the handle's lifetime;
 * this wrapper merely borrows it for one save.
 *
 * Schema (identical to the legacy inline DDL it replaces):
 *   header_admit_log(
 *     height      INTEGER PRIMARY KEY,
 *     hash        BLOB    NOT NULL,
 *     parent_hash BLOB,            -- NULL only at genesis (height 0)
 *     admitted_at INTEGER NOT NULL -- wall-clock unix seconds
 *   )
 *
 * validates :height, numericality: { >= 0 }
 * validates :hash, presence: true (32-byte blob)
 *
 * after_save -> emit EV_MODEL_SAVED */

struct db_header_admit_log {
    int64_t height;
    uint8_t hash[32];
    uint8_t parent_hash[32];   /* zero + has_parent=false at genesis */
    bool    has_parent;
    int64_t admitted_at;       /* wall-clock unix seconds */
};

/* Thin borrowed-handle wrapper. The AR_* macros only touch `.db`. */
struct header_admit_log_db {
    sqlite3 *db;
};

/* Callbacks — register before/after save hooks. */
struct ar_callbacks *db_header_admit_log_callbacks(void);

/* Validate — runs before save, returns true if valid. */
bool db_header_admit_log_validate(const struct db_header_admit_log *r,
                                  struct ar_errors *errors);

/* Ensure the `header_admit_log` table exists on `db` (idempotent). */
bool db_header_admit_log_ensure_schema(sqlite3 *db);

/* INSERT OR REPLACE one row through the AR lifecycle. `db` is the
 * progress.kv handle (progress_store_db()). Returns false (and logs the
 * exact reason) on validation failure or SQL error. */
bool db_header_admit_log_save(sqlite3 *db,
                              const struct db_header_admit_log *r);

#endif /* ZCL_DB_MODEL_HEADER_ADMIT_LOG_H */

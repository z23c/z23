/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Materialize every durable log table consumed by H-star. */

#include "jobs/reducer_frontier_schema.h"

#include "body_persist_log_store.h"
#include "proof_validate_log_store.h"
#include "script_validate_log_store.h"
#include "tip_finalize_log_store.h"
#include "utxo_apply_log_store.h"
#include "validate_headers_log_store.h"
#include "util/log_macros.h"

bool reducer_frontier_ensure_schema(struct sqlite3 *db)
{
    if (!db)
        LOG_FAIL("reducer", "frontier schema ensure requires a database");

    if (!validate_headers_log_ensure_schema(db) ||
        !script_validate_log_ensure_schema(db) ||
        !body_persist_log_ensure_schema(db) ||
        !proof_validate_log_ensure_schema(db) ||
        !utxo_apply_log_ensure_schema(db) ||
        !ensure_log_schema(db))
        LOG_FAIL("reducer", "frontier schema ensure failed");

    return true;
}

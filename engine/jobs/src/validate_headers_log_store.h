/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * validate_headers_log_store — durable validate_headers_log schema + write
 * helpers, split out of validate_headers_stage.c to keep that file under the
 * framework file-size ceiling. Pure sqlite kernel helpers: they take a
 * sqlite3 handle and touch no validate_headers module state. */

#ifndef ZCL_JOBS_VALIDATE_HEADERS_LOG_STORE_H
#define ZCL_JOBS_VALIDATE_HEADERS_LOG_STORE_H

#include "core/uint256.h"

#include <stdbool.h>

struct sqlite3;

bool validate_headers_log_ensure_schema(struct sqlite3 *db);

/* Insert (or replace) one validate_headers_log row. `hash` is the block's own
 * hash; `reason` may be NULL/"" on a pass and is persisted only on a failure. */
bool validate_headers_log_insert(struct sqlite3 *db, int height,
                                 const struct uint256 *hash, bool ok,
                                 const char *reason);

#endif /* ZCL_JOBS_VALIDATE_HEADERS_LOG_STORE_H */

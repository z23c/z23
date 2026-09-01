/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * body_fetch_log_store — durable body_fetch_log schema + read/write helpers,
 * split out of body_fetch_stage.c to keep that file under the framework
 * file-size ceiling. Pure sqlite kernel helpers: they take a sqlite3 handle
 * and touch no body_fetch module state. */

#ifndef ZCL_JOBS_BODY_FETCH_LOG_STORE_H
#define ZCL_JOBS_BODY_FETCH_LOG_STORE_H

#include "core/uint256.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct sqlite3;

bool body_fetch_log_ensure_schema(struct sqlite3 *db);

bool body_fetch_log_insert(struct sqlite3 *db, int height,
                           const struct uint256 *hash,
                           const char *source, int64_t bytes,
                           bool ok, const char *reason);

/* Read the complete authority tuple from validate_headers_log. A found row is
 * accepted only when its hash is exactly 32 bytes. Returns 1 if a valid row
 * was found, 0 if absent, -1 on a query/integrity error. */
int body_fetch_vh_log_at(struct sqlite3 *db, int height, int *out_ok,
                         struct uint256 *out_hash,
                         char *out_reason, size_t reason_size);

#endif /* ZCL_JOBS_BODY_FETCH_LOG_STORE_H */

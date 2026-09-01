/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_log_store — durable utxo_apply_log schema + read/write helpers,
 * split out of utxo_apply_stage.c to keep that file under the framework
 * file-size ceiling. Pure sqlite kernel helpers: they take a sqlite3 handle
 * and touch no utxo_apply module state. */

#ifndef ZCL_JOBS_UTXO_APPLY_LOG_STORE_H
#define ZCL_JOBS_UTXO_APPLY_LOG_STORE_H

#include "core/uint256.h"
#include "jobs/mint_skip_crypto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct sqlite3;

/* One upstream proof_validate_log ok-flag at a given height. */
struct proof_validate_row {
    int ok;
    enum mint_validation_evidence evidence;
    bool has_block_hash;
    struct uint256 block_hash;
};

bool utxo_apply_log_ensure_schema(struct sqlite3 *db);

/* Read the upstream proof_validate_log ok-flag at `height`. Returns 1 if a
 * row was found, 0 if not, -1 on a query error. */
int utxo_apply_proof_validate_log_at(struct sqlite3 *db, int height,
                                     struct proof_validate_row *out);

bool utxo_apply_log_insert(struct sqlite3 *db, int height,
                           const char *status, bool ok,
                           size_t spent_count, size_t added_count,
                           int64_t total_value_delta,
                           const char *failure_kind,
                           const uint8_t failure_detail[36]);

#endif /* ZCL_JOBS_UTXO_APPLY_LOG_STORE_H */

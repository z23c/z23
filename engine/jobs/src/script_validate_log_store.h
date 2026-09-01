/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * script_validate_log_store — durable script_validate_log schema (+ idempotent
 * migrations) and read/write helpers, split out of script_validate_stage.c to
 * keep that file under the framework file-size ceiling. Pure sqlite kernel
 * helpers: they take a sqlite3 handle and touch no script_validate module
 * state. */

#ifndef ZCL_JOBS_SCRIPT_VALIDATE_LOG_STORE_H
#define ZCL_JOBS_SCRIPT_VALIDATE_LOG_STORE_H

#include "core/uint256.h"
#include "jobs/mint_skip_crypto.h"
#include "script/script_error.h"

#include <stdbool.h>
#include <stddef.h>

struct sqlite3;

/* One upstream body_persist_log row (source + ok-flag) at a given height. */
struct body_persist_row {
    int ok;
    char source[64];
};

/* One script_validate_log verdict row at a given height: the ok flag plus
 * the (possibly absent) block-hash binding. Rows predating the block_hash
 * column report has_block_hash == false. */
struct script_validate_verdict_row {
    int ok;
    enum mint_validation_evidence evidence;
    bool has_block_hash;
    struct uint256 block_hash;  /* valid only when has_block_hash */
};

bool script_validate_log_ensure_schema(struct sqlite3 *db);

/* Read the upstream body_persist_log {source, ok} at `height`. Returns 1 if a
 * row was found, 0 if not, -1 on a query error. */
int script_validate_body_persist_log_at(struct sqlite3 *db, int height,
                                        struct body_persist_row *out);

/* Read the script_validate_log {ok, block_hash} at `height` — the hash-bound
 * verdict consumers (tip_finalize's self-heal gate, utxo_apply's label-splice
 * gate) use to prove a height-keyed row belongs to the block they are about
 * to act on. Returns 1 if a row was found, 0 if not, -1 on a query error
 * (logged). */
int script_validate_log_verdict_at(struct sqlite3 *db, int height,
                                   struct script_validate_verdict_row *out);

bool script_validate_log_insert(struct sqlite3 *db, int height,
                                const char *status, bool ok,
                                size_t tx_count, size_t input_count,
                                const struct uint256 *first_failure_txid,
                                int first_failure_vin,
                                ScriptError first_failure_serror,
                                const struct uint256 *block_hash);

/* Finalize this thread's cached INSERT statement and invalidate the cached
 * source-epoch blob. Called at script_validate drain teardown (both are
 * per-batch caches on the single drain thread). */
void script_validate_log_store_batch_reset(void);

/* NULL-block_hash re-arm helpers (twin of proof_validate_log_store's). The
 * pre-stamping artifact (rows authored before script_validate_log_insert
 * stamped block_hash) leaves ok=1 rows with block_hash=NULL that utxo_apply's
 * label_splice guard correctly refuses. These let a contained re-arm rewind
 * script_validate's cursor and delete the NULL suffix so the current binary
 * re-derives + re-stamps block_hash on the next fold. */

/* Lowest ok=1/NULL-block_hash height in [floor_height, ceil_height), plus the
 * count of such rows. Returns 1 if any found (out_height/out_count set), 0 if
 * none, -1 on a query error (logged). An empty/inverted range is a clean 0. */
int script_validate_log_lowest_null_block_hash(struct sqlite3 *db,
                                               int floor_height,
                                               int ceil_height,
                                               int *out_height,
                                               int64_t *out_count);

/* Delete every NULL-block_hash row at or above `from_height`. out_deleted (may
 * be NULL) reports the row count removed. Returns false on a store error. */
bool script_validate_log_delete_null_block_hash_suffix(struct sqlite3 *db,
                                                       int from_height,
                                                       int64_t *out_deleted);

#endif /* ZCL_JOBS_SCRIPT_VALIDATE_LOG_STORE_H */

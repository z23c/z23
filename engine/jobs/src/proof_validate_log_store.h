/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * proof_validate_log_store — durable proof_validate_log schema + read/write
 * helpers, split out of proof_validate_stage.c to keep that file under the
 * framework file-size ceiling. Pure sqlite kernel helpers: they take a
 * sqlite3 handle and touch no proof_validate module state. */

#ifndef ZCL_JOBS_PROOF_VALIDATE_LOG_STORE_H
#define ZCL_JOBS_PROOF_VALIDATE_LOG_STORE_H

#include "core/uint256.h"
#include "jobs/mint_skip_crypto.h"

#include <stdbool.h>
#include <stddef.h>

struct sqlite3;

/* One upstream script_validate_log ok-flag at a given height. */
struct script_validate_row {
    int ok;
    enum mint_validation_evidence evidence;
    bool has_block_hash;
    struct uint256 block_hash;
};

bool proof_validate_log_ensure_schema(struct sqlite3 *db);

/* Read the upstream script_validate_log ok-flag at `height`. Returns 1 if a
 * row was found, 0 if not, -1 on a query error. */
int proof_validate_script_validate_log_at(struct sqlite3 *db, int height,
                                          struct script_validate_row *out);

bool proof_validate_log_insert(struct sqlite3 *db, int height,
                               const char *status, bool ok,
                               size_t sapling_spends_total,
                               size_t sapling_outputs_total,
                               size_t sprout_joinsplits_total,
                               const struct uint256 *block_hash,
                               const struct uint256 *first_failure_txid,
                               const char *first_failure_proof_type);

/* Scan for the LOWEST proof_validate_log height in [floor_height, ceil_height)
 * whose row is ok=1 but has a NULL block_hash — the pre-stamping artifact class
 * (rows written before proof_validate_log_insert learned to stamp
 * bi->phashBlock). utxo_apply's label_splice guard correctly refuses such a
 * hashless proof verdict, so a NULL-block_hash row at or above utxo_apply's
 * cursor is a hard wedge.
 *
 * Returns 1 and writes *out_height (the lowest matching height) + *out_count
 * (how many ok=1/NULL-block_hash rows exist in the range) when at least one is
 * found; 0 when the range is clean; -1 on a query error (logged). out params
 * are optional. */
int proof_validate_log_lowest_null_block_hash(struct sqlite3 *db,
                                              int floor_height,
                                              int ceil_height,
                                              int *out_height,
                                              int64_t *out_count);

/* Delete the NULL-block_hash suffix at/above `from_height`
 * (height >= from_height AND block_hash IS NULL) so the reducer re-derives and
 * re-stamps those heights on the next fold. Returns true on success and writes
 * *out_deleted (rows removed) when non-NULL; false on error (logged). */
bool proof_validate_log_delete_null_block_hash_suffix(struct sqlite3 *db,
                                                      int from_height,
                                                      int64_t *out_deleted);

#endif /* ZCL_JOBS_PROOF_VALIDATE_LOG_STORE_H */

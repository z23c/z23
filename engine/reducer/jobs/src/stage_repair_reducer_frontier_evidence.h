/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Declare reusable exact stage evidence reads for frontier repair. */
#ifndef ZCL_JOBS_STAGE_REPAIR_REDUCER_FRONTIER_EVIDENCE_H
#define ZCL_JOBS_STAGE_REPAIR_REDUCER_FRONTIER_EVIDENCE_H

#include <stdbool.h>

struct block_index;
struct uint256;
struct sqlite3;
struct sqlite3_stmt;

struct rf_log_evidence {
    bool validate_ok_hash;
    bool script_ok_hash;
    bool body_ok;
    bool proof_ok_hash;
    bool utxo_ok_hash;
};

struct rf_evidence_stmts {
    struct sqlite3_stmt *validate_hash;
    struct sqlite3_stmt *script_hash;
    struct sqlite3_stmt *body_ok;
    struct sqlite3_stmt *proof_ok;
    struct sqlite3_stmt *utxo_ok;
};

bool rf_evidence_stmts_prepare(struct sqlite3 *db,
                               struct rf_evidence_stmts *es);
void rf_evidence_stmts_finalize(struct rf_evidence_stmts *es);
bool rf_evidence_for_block_unlocked(struct rf_evidence_stmts *es,
                                    const struct block_index *bi,
                                    struct rf_log_evidence *ev);
bool rf_utxo_branch_evidence_at(struct sqlite3 *db, int height,
                                const struct uint256 *want,
                                bool *row_present, bool *matches);

#endif /* ZCL_JOBS_STAGE_REPAIR_REDUCER_FRONTIER_EVIDENCE_H */

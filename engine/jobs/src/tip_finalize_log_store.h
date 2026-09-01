/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tip_finalize_log_store — durable tip_finalize_log / utxo_apply_log read +
 * write helpers, split out of tip_finalize_stage.c to keep that file under
 * the framework file-size ceiling. Pure sqlite kernel helpers: they take a
 * sqlite3 handle and touch no tip_finalize module state. */

#ifndef ZCL_JOBS_TIP_FINALIZE_LOG_STORE_H
#define ZCL_JOBS_TIP_FINALIZE_LOG_STORE_H

#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "jobs/mint_skip_crypto.h"

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;

struct utxo_apply_row {
    int ok;
    enum mint_validation_evidence evidence;
    bool is_anchor;
    int64_t spent_count;
    int64_t added_count;
};

struct finalized_tip_row {
    bool found;
    bool ok;
    bool has_tip_hash;
    /* True when status=="anchor": a tip SEED, whose tip_hash is the block's
     * OWN hash (row H -> hash H), NOT the finalized lookahead convention
     * (row H -> hash H+1). The reorg-rewind must skip these or it false-detects
     * a divergence comparing hash(H) to active_chain_at(H+1). */
    bool is_anchor;
    struct uint256 tip_hash;
};

bool ensure_log_schema(struct sqlite3 *db);
int  utxo_apply_log_at(struct sqlite3 *db, int height,
                       struct utxo_apply_row *out);
bool utxo_apply_sums_through(struct sqlite3 *db, int height,
                             int64_t *spent_out, int64_t *added_out);
/* O(1)-per-finalize cache of utxo_apply_sums_through(): advances by the
 * just-finalized height's own ok=1 (spent,added), falling back to the full SUM
 * on any doubt (see the .c). Caller passes THIS height's ok=1 counts (the
 * upstream utxo_apply row it already loaded). Reset drops the cache. */
bool utxo_apply_sum_through_incremental(struct sqlite3 *db, int height,
                                        int64_t this_spent, int64_t this_added,
                                        int64_t *spent_out, int64_t *added_out);
void utxo_apply_sum_through_reset(void);
bool log_insert(struct sqlite3 *db, int height, const char *status, bool ok,
                const struct arith_uint256 *work_delta,
                int64_t utxo_size_after, int reorg_depth,
                const struct uint256 *tip_hash);
bool finalized_tip_row_at(struct sqlite3 *db, int height,
                          struct finalized_tip_row *out);

#endif /* ZCL_JOBS_TIP_FINALIZE_LOG_STORE_H */

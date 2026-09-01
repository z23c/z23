/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Exact dependency-generation memo for shielded-history reducer holds. */

#ifndef ZCL_JOBS_UTXO_APPLY_HISTORY_HOLD_H
#define ZCL_JOBS_UTXO_APPLY_HISTORY_HOLD_H

#include <stdbool.h>

struct sqlite3;
struct uint256;

#define UTXO_APPLY_STALE_UPSTREAM_HASH_BLOCKER_ID \
    "utxo_apply.stale_upstream_hash"

enum utxo_apply_history_hold_state {
    UTXO_HISTORY_HOLD_CHANGED = 0,
    UTXO_HISTORY_HOLD_MATCHES,
    UTXO_HISTORY_HOLD_BLOCK_CHANGED,
    UTXO_HISTORY_HOLD_ERROR,
};

bool utxo_apply_history_hold_active(void);
bool utxo_apply_history_hold_should_park(
    struct sqlite3 *db, int height, const struct uint256 *block_hash,
    bool proof_has_hash, const struct uint256 *proof_hash,
    bool script_has_hash, const struct uint256 *script_hash);
enum utxo_apply_history_hold_state utxo_apply_history_hold_check(
    struct sqlite3 *db, int height, const struct uint256 *block_hash,
    int *kind_out);
bool utxo_apply_history_hold_record(struct sqlite3 *db, int height, int kind,
                                    const struct uint256 *block_hash);
void utxo_apply_history_hold_clear(void);

#endif /* ZCL_JOBS_UTXO_APPLY_HISTORY_HOLD_H */

/* purpose: Bound private first-time Ironwood checkpoint reconstruction. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_UTXO_APPLY_IRONWOOD_BOOTSTRAP_INTERNAL_H
#define ZCL_UTXO_APPLY_IRONWOOD_BOOTSTRAP_INTERNAL_H
#include "jobs/utxo_apply_ironwood_bootstrap.h"
#include "jobs/utxo_apply_ironwood_history.h"
#include "storage/ironwood_frontier_store.h"
#include <sqlite3.h>

enum { IRONWOOD_BOOTSTRAP_MAX_STEPS = 16 };
struct ironwood_bootstrap_cursor { // hardening-ok: In-memory replay state, not a byte reader.
    sqlite3 *db;
    uint64_t epoch;
    int target_height;
    int64_t next_height;
    int64_t generation, persisted_tip;
    bool active, retarget, completed;
    int replacement_height;
    int64_t divergence;
    struct uint256 replacement_hash;
    struct uint256 target_hash, previous;
    struct ironwood_note_frontier frontier;
    uint8_t root[32];
    struct ironwood_history_event last;
    struct ironwood_checkpoint_session storage;
};
struct ironwood_bootstrap_item {
    struct uint256 previous;
    struct ironwood_note_frontier frontier;
    uint8_t root[32];
    struct ironwood_history_event event;
};
struct ironwood_bootstrap_slice {
    struct ironwood_bootstrap_cursor base;
    size_t count;
    bool ready;
    struct ironwood_bootstrap_item items[IRONWOOD_BOOTSTRAP_MAX_STEPS];
};
enum ironwood_bootstrap_result {
    IRONWOOD_BOOTSTRAP_ERROR = -1,
    IRONWOOD_BOOTSTRAP_MORE = 0,
    IRONWOOD_BOOTSTRAP_DONE = 1
};
/* Private in-memory scratch: only accept a slice produced by prepare in this
 * process; it is neither serialized nor a caller-authenticated plan. */
enum ironwood_bootstrap_result utxo_ironwood_bootstrap_prepare(
    const struct block_index *parent, const struct ironwood_bootstrap_cursor *cursor,
    ironwood_history_reader_fn reader, const char *datadir, void *user,
    struct ironwood_bootstrap_slice *out);
/* Existing caller transaction, selected private profile, and pinned parent.
 * Replay is bounded by MAX_STEPS; commit before retaining `out` for retry.
 * On failure `out` is unchanged. A restart reauthenticates persisted rows. */
enum ironwood_bootstrap_result utxo_ironwood_bootstrap_step(sqlite3 *db,
    uint64_t epoch, const struct block_index *parent, const struct block_index *old_parent,
    const struct ironwood_bootstrap_slice *slice,
    const struct ironwood_bootstrap_cursor *in, struct ironwood_bootstrap_cursor *out);
bool utxo_ironwood_bootstrap_completed(sqlite3 *db, uint64_t epoch,
    const struct block_index *parent, struct ironwood_history_event *event,
    struct ironwood_note_frontier *frontier, struct ironwood_checkpoint_session *store);
#ifdef ZCL_TESTING
void utxo_ironwood_bootstrap_publish_for_test(const struct ironwood_bootstrap_cursor *cursor);
#endif
#endif

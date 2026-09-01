/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_log_rows — the O(1) published row-count for a stage's *_log table
 * (Program O1). The dump-state views used to report `log_rows` with a blocking
 * SELECT COUNT(*) over a multi-million-row table WHILE holding the recursive
 * progress-store lock — so a `dumpstate <stage>` during catch-up queued behind
 * the fold and the whole observability front door disappeared exactly when the
 * node was busiest. This module replaces that with an incrementally-maintained
 * counter published through the seqlock snapshot plane
 * (util/subsystem_snapshot.h):
 *
 *   - seed once per progress-store epoch (boot) from ONE COUNT(*) — never on
 *     the hot dump path;
 *   - bump on each successful log insert (writer side, under the progress lock);
 *   - decrement at the reorg/repair delete choke points;
 *   - the dumper reads the atomic lock-free and emits the uniform staleness
 *     label — never the blocking COUNT, never an empty body.
 *
 * Accuracy contract: the counter is exact for the forward fold (each height is
 * logged once) and for reorg (the delete choke points decrement, and the
 * re-fold re-inserts genuinely-new rows). It can transiently over-count only if
 * a stage RE-LOGS an already-present height without first deleting it (a rare
 * repair path); every value is reconciled back to the exact COUNT at the next
 * boot's seed. It is a diagnostic, published labeled with its staleness.
 *
 * Only the tables enumerated in stage_log_rows.c are tracked; calls naming an
 * unknown table are silent no-ops (get returns -1), so callers need not guard.
 */
#ifndef ZCL_JOBS_STAGE_LOG_ROWS_H
#define ZCL_JOBS_STAGE_LOG_ROWS_H

#include <stdint.h>

struct sqlite3;
struct json_value;

/* Seed the in-memory counter for `table` from one COUNT(*), at most once per
 * progress-store epoch. Safe (and cheap after the first call per epoch) to call
 * from every ensure_schema. Takes progress_store_tx_lock internally. */
void stage_log_rows_seed(struct sqlite3 *db, const char *table);

/* Writer side: a successful log insert completed for `table`. Call under the
 * progress-store writer lock (the log insert already holds it). */
void stage_log_rows_note_insert(const char *table);

/* Writer side: `removed` rows were deleted from `table` (pass sqlite3_changes()
 * from the DELETE). Negative/zero is ignored; the counter floors at 0. */
void stage_log_rows_note_delete(const char *table, int64_t removed);

/* Lock-free read of the published row count for `table` (-1 if untracked or
 * never seeded). */
int64_t stage_log_rows_value(const char *table);

/* Dumper side: push out[count_key] = the published row count (lock-free), plus
 * out["<count_key>_snapshot"] = the uniform staleness label. No blocking, no
 * COUNT(*). No-op when `table` is untracked. */
void stage_log_rows_emit(struct json_value *out, const char *table,
                         const char *count_key);

#endif /* ZCL_JOBS_STAGE_LOG_ROWS_H */

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ar_after_commit — fire a model hook when the TRANSACTION commits, not when
 * the statement steps.
 *
 * ── Why this exists ───────────────────────────────────────────────────────
 * ActiveRecord's after_save runs the moment the INSERT/UPDATE statement
 * succeeds. Saves do happen inside transactions (blog_publication.c wraps
 * db_blog_post_save in db_txn_begin/db_txn_commit), and after_save hooks have
 * effects the database cannot take back: wallet_tx_after_save emits
 * EV_WALLET_TX_SAVED and pushes a wallet projection. Put those two facts
 * together and an external observer can be told about a record that a later
 * ROLLBACK erases. No path in the tree does both today — this is latent, not
 * live — so the fix is strictly additive: after_save keeps firing exactly
 * when it always did, and a hook that must not outrun durability registers as
 * after_commit instead.
 *
 * ── Semantics ─────────────────────────────────────────────────────────────
 * Hooks registered with ar_register_after_commit() are QUEUED as records are
 * saved and fired once each, in registration order, after the OUTERMOST
 * transaction commits successfully. On rollback the queue is discarded and
 * nothing fires. A save outside any transaction fires its after_commit
 * immediately, right after the statement succeeds. A nested begin does not
 * fire early; only the outermost commit drains.
 *
 * A queued hook receives a COPY of the record, because the caller's record is
 * routinely a stack local that is gone by commit time. That is why
 * ar_register_after_commit takes the record size: a hook cannot be registered
 * without declaring what to copy, and a save whose copy cannot be made
 * REFUSES rather than handing a hook a dangling pointer.
 *
 * ── Scope, stated plainly ─────────────────────────────────────────────────
 * The queue and the nesting depth are per-THREAD, not per-node_db handle.
 * ar_run_after_commit is reached from AR_FINISH_SAVE, which has the record
 * and the callbacks but not the database handle, so there is nothing else to
 * key on. That is exact for the way this tree uses transactions — one open
 * write transaction per thread of control, and db_txn_begin refuses to nest —
 * and it errs in the safe direction if that ever stops holding: a rollback
 * discards the whole thread's queue, so the failure mode is a hook that does
 * not fire, never a hook that announces a row that was rolled back.
 *
 * The depth counter sees transactions opened through node_db_begin /
 * node_db_begin_immediate. Seven files under app/services still open one with
 * a raw sqlite3_exec("BEGIN IMMEDIATE") on their own handle — projection and
 * cache writers that do not use the ActiveRecord save lifecycle at all (zero
 * db_*_save calls between them, checked). A save inside such a transaction
 * would see depth zero and fire its after_commit immediately, which is
 * exactly today's after_save timing: the guarantee would be absent, not
 * wrong. Routing those through node_db_begin would close the gap.
 */

#ifndef ZCL_MODELS_AR_AFTER_COMMIT_H
#define ZCL_MODELS_AR_AFTER_COMMIT_H

#include <stdbool.h>
#include <stddef.h>

/* Most hooks a model queues per transaction. A transaction that queues more
 * than this is a bulk path that should not be announcing rows one at a time;
 * the enqueue REFUSES (and the save with it) rather than silently dropping an
 * observer notification. */
#define AR_AFTER_COMMIT_MAX_QUEUED 4096

/* ── Transaction boundary notifications ────────────────────────────────────
 * Called by node_db_begin / node_db_begin_immediate / node_db_commit /
 * node_db_rollback. Nothing else should call these. */

/* A transaction opened successfully on this thread. */
void ar_after_commit_note_begin(void);

/* A COMMIT completed. `committed` false means the COMMIT failed and the
 * transaction is still open (SQLite leaves it so on, e.g., a deferred foreign
 * key violation): the queue is kept intact for the ROLLBACK that must follow.
 * When the outermost transaction commits, the queue drains in registration
 * order. */
void ar_after_commit_note_commit(bool committed);

/* A ROLLBACK was issued. SQLite's ROLLBACK aborts the whole transaction, so
 * the entire queue is discarded and the depth returns to zero. Nothing fires.
 * Safe to call when no transaction is open. */
void ar_after_commit_note_rollback(void);

/* ── Enqueue ───────────────────────────────────────────────────────────────
 * Queue one hook against the open transaction, copying `record_size` bytes of
 * `record`. Outside any transaction the hook fires immediately against the
 * caller's own record and nothing is copied.
 *
 * Returns false when the hook can neither fire nor be queued (no record size,
 * the per-transaction cap, or an allocation failure). The caller must treat
 * that as a failed save: an observer that will never be told is a silent
 * hole, not a warning. */
bool ar_after_commit_enqueue(void (*fn)(void *record, void *ctx), void *ctx,
                             void *record, size_t record_size);

/* ── Introspection (tests and diagnostics) ────────────────────────────── */

/* Open transaction nesting depth on this thread. */
int ar_after_commit_depth(void);

/* Hooks currently queued on this thread and waiting for a commit. */
int ar_after_commit_pending(void);

/* Drop the queue and zero the depth without firing anything. Test isolation
 * only — production discards go through ar_after_commit_note_rollback. */
void ar_after_commit_reset(void);

#endif /* ZCL_MODELS_AR_AFTER_COMMIT_H */

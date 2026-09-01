/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * db_txn — scoped, labelled, leak-detected database transactions.
 *
 * Motivation
 * ----------
 * A destructive multi-table recovery path that calls a raw sequence of
 * `node_db_exec("DELETE ...")` / `node_db_begin` / `node_db_commit`
 * statements leaves partial state on crash or early return. This
 * module wraps the existing `node_db_{begin,commit,rollback}` primitives
 * in a value type that:
 *
 *   - carries a human-readable label so events name the caller
 *   - tracks commit/rollback state so rollback is idempotent
 *   - integrates with `__attribute__((cleanup))` via DB_TXN_SCOPE,
 *     auto-rolling-back and emitting EV_DB_TXN_LEAKED if the caller
 *     exits the scope without committing (programmer error)
 *   - refuses to nest: if the node_db already has an open transaction
 *     when db_txn_begin is called, it returns NULL and emits a REJECT
 *     event. Destructive recovery paths are expected to own the whole
 *     transaction — nesting silently commits the outer parent when the
 *     inner closes, which is exactly the pattern we're trying to kill.
 *
 * Typical usage
 * -------------
 *
 *     DB_TXN_SCOPE(txn, ndb, "snapshot.prepare_receive");
 *     if (!txn) return false;
 *     if (!first_destructive_step(ndb))  return false;  // auto-rollback
 *     if (!second_destructive_step(ndb)) return false;  // auto-rollback
 *     if (!db_txn_commit(txn))           return false;
 *     return true;
 *
 * If the function returns early because a destructive step fails,
 * the DB_TXN_SCOPE cleanup fires, db_txn_rollback runs, and
 * EV_DB_TXN_LEAKED is emitted with the label so an operator can trace
 * which destructive step left a mess.
 *
 * Thread safety
 * -------------
 * db_txn is not thread-safe itself. The underlying node_db owns the
 * transaction state under its own mutex; db_txn is a thin wrapper on
 * top of that. Concurrent transactions against the SAME node_db are
 * rejected by the node_db layer (which only supports one tx at a
 * time). Concurrent transactions against DIFFERENT node_db handles
 * are fine and are covered by a dedicated test.
 */

#ifndef ZCL_MODELS_DB_TXN_H
#define ZCL_MODELS_DB_TXN_H

#include "models/database.h"

#include <stdbool.h>
#include <stdint.h>

/* ── Max label length ──────────────────────────────────────────
 * Labels are copied on begin and logged to events. 64 bytes is
 * enough for every real reason string and keeps the struct small. */
#define DB_TXN_LABEL_MAX 64

/* ── Handle type ────────────────────────────────────────────────
 * Allocated by db_txn_begin, freed by the destructor (either
 * db_txn_commit + explicit free, or the auto-rollback cleanup).
 * Callers never need to touch the fields directly — the API is
 * complete — but they're public so tests can inspect state. */
struct db_txn {
    struct node_db *db;                    /* non-owning */
    char            label[DB_TXN_LABEL_MAX];
    int64_t         started_us;            /* now_us() at begin */
    bool            committed;             /* set by db_txn_commit */
    bool            rolled_back;           /* set by db_txn_rollback */
};

/* ── Lifecycle ──────────────────────────────────────────────────
 * Begin a transaction on `db` with human-readable `label`. Refuses
 * to nest: if the node_db already has tx_open when called, returns
 * NULL after emitting EV_DB_TXN_REJECTED. `label` must be non-NULL
 * and non-empty (asserted in events, truncated to DB_TXN_LABEL_MAX).
 *
 * On success, returns a heap-allocated handle. Free it by calling
 * exactly one of:
 *   - db_txn_commit(txn)   — commits and deallocates
 *   - db_txn_rollback(txn) — rolls back and deallocates
 *   - falling out of a DB_TXN_SCOPE — auto-rollback + deallocate +
 *     EV_DB_TXN_LEAKED if not already committed/rolled-back.
 */
struct db_txn *db_txn_begin(struct node_db *db, const char *label);

/* Commit and deallocate. Returns true on success, false if the
 * underlying node_db_commit failed (in which case the handle has
 * still been deallocated — the caller should treat the tx as lost).
 * Calling commit twice is a bug and emits EV_DB_TXN_LEAKED with a
 * "double_commit" flag. */
bool db_txn_commit(struct db_txn *txn);

/* Roll back and deallocate. Idempotent — calling rollback on an
 * already-rolled-back handle is a no-op (the handle is still freed
 * only on the first call). Safe to call after commit: it detects
 * the committed flag and becomes a no-op without emitting an event. */
void db_txn_rollback(struct db_txn *txn);

/* ── RAII helper ───────────────────────────────────────────────
 * Helper for __attribute__((cleanup)). Not for direct calls. */
void db_txn_auto_rollback(struct db_txn **p);

/* ── Disk-critical probe (hexagonal seam) ────────────────────────
 * db_txn_begin refuses to open a NEW write transaction while the disk
 * free-space watchdog (engine/services/disk_monitor.c) reports CRITICAL, so a
 * near-full filesystem never accumulates more write pressure. models/ must
 * not #include services/ directly (see check_shape_include_direction.sh), so
 * the probe is a registered function pointer instead of a direct call —
 * mirrors node_db_set_quick_check_skip_probe() in models/database.h. Default
 * (unset) = never critical, identical to prior behavior on nodes/tests
 * without the disk monitor running. Registered by disk_monitor_start()
 * itself (engine/services/src/disk_monitor.c) as part of its own start
 * lifecycle, to keep app/models decoupled from app/services. */
typedef bool (*db_txn_disk_critical_probe_fn)(void);
void db_txn_set_disk_critical_probe(db_txn_disk_critical_probe_fn fn);

/* DB_TXN_SCOPE(name, db, label)
 *
 * Expands to a `struct db_txn *name` local that is auto-cleaned up
 * at scope exit. If the scope exits without calling db_txn_commit,
 * auto-rollback fires and EV_DB_TXN_LEAKED is emitted with the label.
 *
 * The resulting handle may be NULL if db_txn_begin rejected the
 * request (e.g., nesting or NULL args). Callers MUST check for
 * NULL before using it. */
#define DB_TXN_SCOPE(name, db, label) \
    __attribute__((cleanup(db_txn_auto_rollback))) \
    struct db_txn *name = db_txn_begin((db), (label))

#endif /* ZCL_MODELS_DB_TXN_H */

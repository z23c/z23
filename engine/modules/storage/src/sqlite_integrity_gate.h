/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sqlite_integrity_gate — shared open-time corruption gate for the storage
 * layer's SQLite-backed singleton stores (progress_store's consensus.db,
 * projection_store's progress.kv). Both stores hold state that is either the
 * consensus kernel itself or a fully re-derivable projection of it; either
 * way a mid-fold SQLITE_CORRUPT surfaces as a JOB_FATAL that pins H* forever
 * with no named blocker. These two helpers give every caller the same
 * auto-terminating self-heal: detect corruption via PRAGMA quick_check, then
 * quarantine the corrupt file trio aside with a timestamped/pid/seq-unique
 * suffix and emit a NAMED EV_RECOVERY_ACTION so the caller can reopen a
 * fresh file instead of pinning silently.
 *
 * Internal to engine/modules/storage — not part of the public storage/include API.
 * Each caller supplies its own `log_tag` (the bracketed prefix on every log
 * line, e.g. "progress_store") and `event_action` (the EV_RECOVERY_ACTION
 * action= value, e.g. "progress_store_quarantine") so behavior stays
 * identical to what each store logged/emitted before this was shared out. */

#ifndef ZCL_STORAGE_SQLITE_INTEGRITY_GATE_H
#define ZCL_STORAGE_SQLITE_INTEGRITY_GATE_H

#include <sqlite3.h>
#include <stdbool.h>

/* PRAGMA quick_check(1) on `db`, logging under "[log_tag] ...". Returns true
 * only when quick_check reports exactly "ok". A prepare/step failure (the
 * connection itself is wedged on a corrupt file) counts as NOT ok. */
bool sqlite_integrity_quick_check_ok(sqlite3 *db, const char *log_tag);

/* Move `path` (+ its -wal / -shm siblings, if present) aside with one shared
 * timestamped + pid + process-local-sequence suffix so repeated quarantines
 * never collide (ENOENT on a sibling is success — it may not exist). Emits
 * EV_RECOVERY_ACTION action=<event_action> reason=quick_check_failed
 * path=<path> suffix=<suffix>. Logs under "[log_tag] ...". */
void sqlite_integrity_quarantine_corrupt(const char *path, const char *log_tag,
                                         const char *event_action);

#endif /* ZCL_STORAGE_SQLITE_INTEGRITY_GATE_H */

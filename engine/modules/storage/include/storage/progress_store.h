/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * progress_store — singleton owner of the `progress.kv` SQLite file.
 *
 * Why this exists
 * ----------------
 * The staged-sync pipeline decomposes chain advance into eight reducer
 * stages, each of which owns a 64-bit cursor on disk. Crash-mid-step
 * replays the step idempotently because the cursor is unchanged on next
 * boot. The F-2 `stage` primitive already implements that contract on
 * top of any sqlite3 handle, via the `stage_cursor` table; what was
 * missing was a *home* for that table.
 *
 * `progress.kv` is that home: a small dedicated SQLite file alongside
 * `node.db`, opened once at boot, shared by every stage. Keeping it
 * separate from `node.db` matters because:
 *
 *   - Cursor commits are tiny and on the hot path; a dedicated WAL keeps
 *     them out of the way of the much larger node.db txns.
 *   - `progress.kv` is a distinct storage engine (the durable cursor store;
 *     see docs/FRAMEWORK.md). One file == one writer-actor.
 *   - Future stages may want to use blob columns, FTS, or LMDB without
 *     dragging node.db's schema along.
 *
 * Threading
 * ----------
 * One process-wide handle. `progress_store_db()` is only a pointer load;
 * callers that execute SQL on the handle must hold
 * progress_store_tx_lock(). The lock is recursive so read helpers remain
 * usable from inside stage transactions. */

#ifndef ZCL_STORAGE_PROGRESS_STORE_H
#define ZCL_STORAGE_PROGRESS_STORE_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Open <datadir>/progress.kv in WAL mode and ensure the stage_cursor
 * table exists. Idempotent — a second call with the same datadir is a
 * no-op and returns true. A second call with a *different* datadir
 * returns false (one process, one progress store). */
bool progress_store_open(const char *datadir);

/* Singleton handle. NULL if not yet opened or already closed. */
sqlite3 *progress_store_db(void);

/* Monotonic open-epoch: 0 before the first open, then incremented on every
 * successful progress_store_open(). In-memory caches seeded from a table (e.g.
 * the stage_log_rows row counters) key their one-time-per-boot re-seed on this
 * so a reopen (new datadir, or a test reopening the singleton) re-seeds without
 * a COUNT(*) on every schema-ensure call. */
uint64_t progress_store_epoch(void);

/* Max length of the progress.kv path (sizing buffers for progress_store_path). */
#define PROGRESS_STORE_PATH_MAX 1024

/* Snapshot the open progress.kv file path into out[cap] (false + out[0]='\0'
 * when not open or it would not fit). For a reader that needs its OWN
 * connection — e.g. a bulk scan that must NOT hold progress_store_tx_lock for
 * its whole duration (which would stall the reducer drive on that lock). */
bool progress_store_path(char *out, size_t cap);

/* Open an independent READONLY connection to the exact retained-directory
 * capability backing the singleton.  Observational surfaces use this instead
 * of waiting behind a long reducer transaction on the shared handle.  The
 * caller owns the returned handle and must sqlite3_close() it.  A 25 ms busy
 * timeout bounds WAL/schema contention; NULL means unavailable/busy. */
sqlite3 *progress_store_open_reader(void);

/* Prove that `db` is the process singleton opened through the exact directory
 * capability `dir_fd`.  The store retains its own directory descriptor for
 * the lifetime of the SQLite handle, so this comparison is by device/inode,
 * never by a path spelling that may have been swapped after boot. */
bool progress_store_directory_matches_fd(sqlite3 *db, int dir_fd);

/* Serialize operations on the singleton progress.kv handle. SQLite
 * connections cannot run more than one statement/transaction safely across
 * threads unless the caller serializes them. This lock is recursive so a
 * stage step can call read helpers while its outer transaction is active. */
void progress_store_tx_lock(void);
/* Non-blocking counterpart for observational surfaces. Returns true with the
 * recursive lock held, or false immediately when a reducer batch owns it. */
bool progress_store_tx_trylock(void);
void progress_store_tx_unlock(void);

/* Switch the durability PRAGMA on the open progress.kv handle.
 *
 * Pure I/O performance control — changes ONLY when bytes are flushed to
 * disk, never WHAT is computed, written, or accepted:
 *   - ibd == true  → `PRAGMA synchronous=OFF`  (initial block download /
 *                    bodies-only refold: cursor commits do not fsync, so
 *                    the from-blocks fold is not fsync-bound).
 *   - ibd == false → `PRAGMA synchronous=NORMAL` (the safe at-tip default;
 *                    identical to the mode applied at open).
 *
 * MUST be reverted to NORMAL once at-tip — leaving OFF permanently widens
 * the crash-durability window for the live tip. The caller gates this on
 * the existing IBD/at-tip signal (is_initial_block_download) and only
 * issues the PRAGMA on a transition. No-op (returns false) if the store is
 * not open. Takes progress_store_tx_lock internally. */
bool progress_store_set_sync_mode(bool ibd);

/* Checkpoint+truncate the WAL on the open progress.kv handle NOW, returning
 * the WAL file's high-water bytes to the filesystem WITHOUT closing the
 * connection. The disk_full reclaim path calls this so a near-full disk can
 * free derived bytes (the 3.1M-row cursor log's WAL) and clear. Takes
 * progress_store_tx_lock internally. Returns false (no-op) when not open or
 * the checkpoint fails. */
bool progress_store_checkpoint(void);

/* Graceful close: PRAGMA wal_checkpoint(TRUNCATE), sqlite3_close. Safe
 * to call repeatedly and from shutdown paths. */
void progress_store_close(void);

/* For `z23 dumpstate progress` (dump-state convention). `out` is
 * expected to have been json_set_object'd by the caller; this function
 * also calls json_set_object(out) defensively. `key` is unused. */
struct json_value;
bool progress_store_dump_state_json(struct json_value *out, const char *key);

/* ── progress_meta — small key/value table on the same store ──
 *
 * A general-purpose blob k/v table colocated with stage_cursor in
 * progress.kv. The schema is `(key TEXT PRIMARY KEY, value BLOB)`.
 *
 * This table hosts:
 *   - `import_in_progress` sentinel (1-byte blob {0x01})
 *   - `legacy_attach_tip_hash` (32 bytes, little-endian)
 *   - `legacy_attach_tip_height` (4 bytes int32, native byte order)
 *
 * Callers wanting transactional grouping with a stage_cursor advance
 * (the saga atomicity contract) must call `_tx` variants inside their
 * own `BEGIN IMMEDIATE`. The non-`_tx` variants commit immediately
 * via implicit BEGIN/COMMIT — convenient for boot-time wiring.
 *
 * Values are opaque blobs to this layer; the caller owns serialization. */

bool progress_meta_table_ensure(sqlite3 *db);

/* Standalone (own-txn) helpers — use during boot / outside saga steps. */
bool progress_meta_set(sqlite3 *db, const char *key,
                       const void *value, size_t value_len);
bool progress_meta_get(sqlite3 *db, const char *key,
                       void *out_buf, size_t out_cap,
                       size_t *out_len, bool *out_found);
/* Authority-bearing metadata must use this reader. It accepts only SQLite's
 * exact BLOB storage class and never truncates into `out_buf`; TEXT/INTEGER/
 * REAL values that SQLite could coerce to bytes fail closed. A missing key is
 * still a successful read with out_found=false. */
bool progress_meta_get_blob_exact(sqlite3 *db, const char *key,
                                  void *out_buf, size_t out_cap,
                                  size_t *out_len, bool *out_found);
bool progress_meta_delete(sqlite3 *db, const char *key);

/* Transactional variant — caller has an outer BEGIN IMMEDIATE on `db`.
 * No BEGIN/COMMIT issued; the value participates in the caller's txn. */
bool progress_meta_set_in_tx(sqlite3 *db, const char *key,
                             const void *value, size_t value_len);
bool progress_meta_delete_in_tx(sqlite3 *db, const char *key);

/* Raise-only u64 write of `key` (stored as an 8-byte LITTLE-ENDIAN blob — the
 * coins_applied_height / trusted-base storage convention). Reads the current
 * value with exact-BLOB semantics: an absent key is treated as "no floor" (any
 * value writes); a present value of any storage class other than an 8-byte BLOB
 * is malformed and fails closed (returns false, zero side effects) so a coerced
 * value can never silently lower the floor. Writes `value` iff it is STRICTLY
 * greater than the stored value (or the key was absent). On success *raised is
 * set true iff this call wrote, and *winner (may be NULL) to the post-call
 * stored value == max(value, prior). The primitive IS the raise-only check — it
 * replaces the by-convention "read prev, compare, write" the trusted-base seed
 * open-coded. Runs in the CALLER's ambient transaction (an `_in_tx` primitive —
 * the caller MUST already own an open BEGIN IMMEDIATE on `db`). */
bool progress_meta_raise_u64_in_tx(sqlite3 *db, const char *key, uint64_t value,
                                   bool *raised, uint64_t *winner);

#endif /* ZCL_STORAGE_PROGRESS_STORE_H */

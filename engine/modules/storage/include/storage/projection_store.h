/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * projection_store — the owner of the `progress.kv` projection file.
 *
 * Why this exists (Wave A2 / D4 → A3 flip)
 * ----------------------------------------
 * The reducer kernel folds chain state under progress_store_tx_lock() +
 * BEGIN IMMEDIATE on the progress_store connection. Projection co-writers
 * (the -addressindex / -txindex folds) historically shared that ONE handle
 * and ONE tx lock, so a projection batch's BEGIN IMMEDIATE serialised on the
 * exact mutex the reducer drive needs — projection work could stall H*.
 *
 * A2/D4 gave those co-writers their OWN connection + recursive tx mutex. The
 * A3 flip then moved the kernel tables into their own physical file
 * (consensus.db, owned by progress_store), leaving progress.kv as the
 * dedicated projection file this store owns outright. A projection BEGIN
 * IMMEDIATE now shares neither the reducer's process mutex NOR its WAL journal
 * — full physical isolation of the two write actors.
 *
 * LOCK ORDER LAW (inviolable)
 * ---------------------------
 * The reducer drive holds the kernel progress lock. The projection lock is
 * only ever taken AFTER the kernel lock is released — never nested inside it.
 * Do not take progress_store_tx_lock while holding projection_store_tx_lock
 * either; the two lock domains are strictly non-overlapping.
 *
 * Only the projection STAY set (address_index, address_index_state, txindex,
 * txindex_state) is written through this handle. Consensus/kernel tables
 * (coins_kv, anchor_kv, nullifier_kv, stage_cursor, and every *_log) stay on
 * the progress_store handle. The replayable created_outputs resolver cache is
 * also co-located in the kernel file because reducer stages write/read it; it
 * is not consensus truth. See consensus_db.h for the executable migration
 * boundary. This handle separation proves physical isolation, not one
 * code-level writer for each kernel fact.
 *
 * Threading
 * ---------
 * One process-wide handle behind an atomic pointer; projection_store_db() is
 * a relaxed-atomic load with no mutex. Callers executing SQL on the handle
 * must hold projection_store_tx_lock() (recursive, so read helpers stay
 * usable inside a projection transaction). */

#ifndef ZCL_STORAGE_PROJECTION_STORE_H
#define ZCL_STORAGE_PROJECTION_STORE_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Max length of the progress.kv path (sizing buffers). It deliberately uses
 * the same bound as the separate consensus.db path. */
#define PROJECTION_STORE_PATH_MAX 1024

/* Open the <datadir>/progress.kv projection file in WAL mode, creating it if
 * absent (this store OWNS it after the A3 flip — the kernel now lives in
 * consensus.db). The Class C projection tables it holds are fully rebuildable,
 * so this does not run the kernel's candidate-refusal gate (there is no
 * consensus-state candidate to refuse here). It DOES run the same PRAGMA
 * quick_check integrity gate as the kernel store on a dirty/unknown open: a
 * non-"ok" verdict
 * quarantines the file trio aside (timestamped/pid-unique rename) and
 * reopens a FRESH, empty file — safe because every table here re-derives from
 * the kernel on the next fold. A successful WAL checkpoint + close writes a
 * single-use receipt bound to the exact file identity and SQLite header; an
 * unchanged WAL-free reopen consumes that receipt and skips the O(file-size)
 * scan. Any mismatch, WAL, crash, or malformed receipt takes the full gate.
 * Idempotent: a second call with the same
 * datadir is a no-op returning true; a different datadir returns false (one
 * process, one projection store). */
bool projection_store_open(const char *datadir);

/* Singleton handle. NULL if not yet opened or already closed. */
sqlite3 *projection_store_db(void);

/* Serialize operations on the singleton projection handle. Recursive so a
 * projection step can call read helpers while its outer transaction is
 * active. This is a DIFFERENT mutex than progress_store_tx_lock — the two lock
 * domains must never nest (see LOCK ORDER LAW above). */
void projection_store_tx_lock(void);
/* Non-blocking counterpart: true with the recursive lock held, or false
 * immediately when another projection batch owns it. */
bool projection_store_tx_trylock(void);
void projection_store_tx_unlock(void);

/* Graceful close: checkpoint+close of this projection handle and its own WAL.
 * Safe to call repeatedly and from shutdown paths. The kernel store has a
 * separate file, handle, and WAL lifecycle. */
void projection_store_close(void);

/* For `z23 dumpstate projection_store` (dump-state convention). `out` is
 * json_set_object'd by the caller; this also calls json_set_object(out)
 * defensively. `key` is unused. */
struct json_value;
bool projection_store_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_STORAGE_PROJECTION_STORE_H */

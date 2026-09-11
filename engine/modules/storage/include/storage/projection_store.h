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
 * the kernel on the next fold. A successful WAL checkpoint + close of a
 * store proven intact this run writes a single-use receipt bound to file
 * identity and a full-content SHA3 digest.
 * A WAL-free reopen scans O(file-size) bytes to verify that digest and can
 * then skip SQLite's structural check. Any mismatch, old receipt version,
 * WAL, crash, or malformed receipt takes the full integrity gate.
 * Idempotent: a second call with the same
 * datadir is a no-op returning true; a different datadir returns false (one
 * process, one projection store). */
bool projection_store_open(const char *datadir);

/* ── running that integrity scan OFF the boot thread ──────────────────
 *
 * THE INCIDENT. A 2.36 GB progress.kv with no clean-close receipt put the
 * boot thread inside ONE synchronous, unpaced sqlite3_step("PRAGMA
 * quick_check(1)") for 62 minutes on a 7200 rpm fleet box. RPC, P2P and the
 * sd_notify READY the unit waits for were all downstream of that step, so
 * `systemctl status` said `activating (start)` for an hour while the disk
 * worked perfectly. A restart before projection_store_close re-arms the same
 * scan, so the box could not boot its way out of it either.
 *
 * THE FIX IS NOT TO SKIP THE SCAN. It is to stop running it on the thread
 * that owes the operator a listening node. node.db solved the identical
 * problem first (see config/boot_fast_restart.h): an existing store with no
 * verified-clean binding defers its quick_check to one paced background scan
 * that runs after READY, in slices under the storage-pacing maintenance
 * token, and fail-closes through EV_OPERATOR_NEEDED. This is the same
 * contract for progress.kv, wired the same way — through a probe the boot
 * layer installs, so a plain projection_store_open() (tests, tools, any
 * non-boot caller) keeps the synchronous gate it has always had.
 *
 * The probe is asked ONLY when there is no clean-close receipt, and answers
 * "is deferring this file's scan the right call for this boot". Returning
 * false keeps the blocking scan; that is what a fresh or absent file wants,
 * because quick_check on it costs nothing. NULL clears (the default). */
typedef bool (*projection_quick_check_defer_probe_fn)(const char *path);
void projection_store_set_quick_check_defer_probe(
    projection_quick_check_defer_probe_fn fn);

/* True when this open deferred its integrity scan and no verdict has come
 * back yet; `out_path` then holds the capability path the scanner must open.
 * `out_path` is cleared before anything can fail, so a false return never
 * leaves a caller reading a stale buffer. */
bool projection_store_integrity_pending(char *out_path, size_t out_n);

/* The deferred scan's verdict, reported from the background scanner thread.
 * `ok` true closes the scan out (and is what lets the next clean close
 * publish a receipt at all). `ok` false is an integrity FINDING and is
 * handled exactly as strongly as the synchronous gate's quarantine, with the
 * one difference that the live handle cannot be swapped out from under the
 * projection folds mid-run: writes are refused immediately
 * (projection_store_db() returns NULL, which every co-writer already treats
 * as "idle this tick"), the quarantine is ARMED on disk so the next open
 * renames the corrupt file family aside and mints a fresh one, and
 * EV_OPERATOR_NEEDED latches the health surface. Call at most once per
 * pending scan; a call with nothing pending is a no-op. */
void projection_store_integrity_scan_result(bool ok);

/* Singleton handle. NULL if not yet opened or already closed — and NULL once
 * a deferred scan reported corruption, so no co-writer can write another row
 * into a file the node has already condemned. */
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
/* ── size bound ───────────────────────────────────────────────────────
 *
 * What progress.kv actually occupies, measured from the file itself rather
 * than from a row count. `file_bytes` is what `ls` shows; `free_bytes` is
 * the part of it that holds nothing because SQLite returned those pages to
 * the freelist instead of to the filesystem; `live_bytes` is the difference.
 * Every field is -1 when the store is closed or the measurement failed, so a
 * failed measurement can never read as "nothing is free". */
struct projection_store_usage {
    int64_t page_size;
    int64_t page_count;
    int64_t free_pages;
    int64_t file_bytes;
    int64_t live_bytes;
    int64_t free_bytes;
};

bool projection_store_usage(struct projection_store_usage *out);

/* PURE predicate: is this store both bigger than `floor_bytes` AND more than
 * `ratio_pct` percent of its own live set? Both conditions are required — see
 * the implementation comment for why either alone is the wrong bound. A
 * ratio at or below 100, a non-positive floor, and an unmeasured usage all
 * answer false. Exposed so the bound can be tested without a disk. */
bool projection_store_over_bound(const struct projection_store_usage *usage,
                                 int64_t floor_bytes, int ratio_pct);

/* Compact progress.kv when it is over that bound, and report the usage
 * before and (on success) after. Returns true only when a compaction
 * actually ran and succeeded.
 *
 * COSTS A FULL REWRITE when it fires. The caller owns the decision to run it
 * at all: the periodic housekeeping runs it behind the storage-pacing
 * maintenance token so it never overlaps another maintenance writer, and
 * boot runs it once before the node starts serving. `before` and `after` may
 * be NULL. */
bool projection_store_compact_if_needed(int64_t floor_bytes, int ratio_pct,
                                        struct projection_store_usage *before,
                                        struct projection_store_usage *after);

bool projection_store_dump_state_json(struct json_value *out, const char *key);


#endif /* ZCL_STORAGE_PROJECTION_STORE_H */

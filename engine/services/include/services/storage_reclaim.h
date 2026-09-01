/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * storage_reclaim — return DERIVED bytes to a near-full filesystem.
 *
 * Motivation
 * ----------
 * The disk_monitor watchdog can SEE a near-full disk (disk_monitor_is_critical)
 * and the write paths apply back-pressure on it, but back-pressure alone never
 * frees a byte — without a reclaim the disk_full_pause condition would re-arm
 * forever with nothing to clear it (a latch by another name). This module is
 * the missing reclaim entry point: it returns DERIVED bytes (rebuildable from
 * the consensus log) to the filesystem so the condition is AUTO-TERMINATING.
 *
 * What it reclaims (all DERIVED — never committed consensus state):
 *   1. progress.kv WAL  — PRAGMA wal_checkpoint(TRUNCATE) (the cursor log).
 *   2. node.db WAL      — PRAGMA wal_checkpoint(TRUNCATE) (UTXO + explorer).
 *   3. stale "<x>.tmp"  — crash orphans from a write-then-rename that died
 *                         mid-write (the atomic-save pattern used widely).
 *
 * Safety: it NEVER deletes a live WAL out from under an open handle (the
 * checkpoint truncates the WAL via sqlite, it does not unlink it), and it
 * NEVER deletes an in-flight atomic-write .tmp (only orphans older than the
 * min-age guard below — a real rename completes in well under a second).
 */

#ifndef ZCL_SERVICES_STORAGE_RECLAIM_H
#define ZCL_SERVICES_STORAGE_RECLAIM_H

#include <stdbool.h>
#include <stdint.h>

/* A stray "<x>.tmp" younger than this (seconds) is LEFT ALONE: the
 * write-then-rename atomic-save pattern used across the node (coins_kv
 * snapshot, rolling anchor, sapling/sha3 sidecars, wallet backup, connman)
 * creates "<path>.tmp" and renames it within well under a second. Only a .tmp
 * older than this guard is a crash orphan safe to unlink. */
#define STORAGE_RECLAIM_TMP_MIN_AGE_SECS 600

struct storage_reclaim_result {
    int     sources_total;      /* derived stores asked to checkpoint */
    int     sources_ok;         /* checkpoints that succeeded         */
    int     tmp_files_removed;  /* stale *.tmp crash orphans unlinked */
    int64_t tmp_bytes_removed;  /* bytes returned by the *.tmp sweep  */
};

/* Reclaim DERIVED bytes NOW (the disk_full_pause remedy entry point):
 *   - PRAGMA wal_checkpoint(TRUNCATE) on progress.kv and node.db (best-effort:
 *     a not-open / not-started store is skipped, not an error), then
 *   - sweep stale "<x>.tmp" crash orphans under `datadir` top level
 *     (non-recursive; NULL datadir skips the sweep).
 * Never deletes a live WAL or an in-flight atomic-write .tmp. Safe to call
 * from any thread; one failing source never aborts the others. */
struct storage_reclaim_result storage_reclaim_derived(const char *datadir);

/* Lifetime count of storage_reclaim_derived() invocations — introspection
 * and tests (proves the remedy actually fired, not just that it didn't crash). */
int64_t storage_reclaim_run_count(void);

#endif /* ZCL_SERVICES_STORAGE_RECLAIM_H */

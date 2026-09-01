/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet Restore Service — merge a wallet backup file back into a datadir.
 *
 * Why this exists
 * ---------------
 * The backup half of this stack was well built and well tested. The
 * restore half was `cp`, an undocumented sequence of RPCs, and hand-written
 * SQL. A user whose machine died had a directory full of verified backup
 * files and no supported way to turn one back into a working wallet. This
 * is that way.
 *
 * The three things it refuses to do
 * ---------------------------------
 * 1. Touch a datadir a node is holding. <datadir>/zclassic23.pid is the
 *    single-writer lock; two writers on one node.db corrupt both stores.
 *    The service takes and immediately releases a non-blocking exclusive
 *    flock on that file to prove nobody else holds it, and refuses with
 *    the holder's pid otherwise. Stop the node, then restore.
 * 2. Install the backup file AS node.db. The backup's tables were made
 *    with "CREATE TABLE t AS SELECT * FROM src.t", which copies values and
 *    drops primary keys, CHECK constraints and indexes. The service opens
 *    the TARGET through the normal node schema path and merges rows into
 *    the real tables instead.
 * 3. Overwrite anything. The collision policy is KEEP-EXISTING: a backup
 *    row whose primary key already exists in the target is not written,
 *    and the count of such rows is reported per table. A restore can add
 *    keys; it can never roll a wallet backwards.
 *
 * What it reports
 * ---------------
 * Per table: rows the backup held, rows inserted, rows that collided with
 * an existing row, rows the target's schema rejected, and the target's
 * count before and after. Plus what the backup file's own manifest claimed
 * it held, so a short copy shows up as a manifest mismatch rather than as
 * a quiet zero.
 *
 * After a restore
 * ---------------
 * Merging rows does not rebuild derived state. The caller (and the docs)
 * must send the user on to `core wallet rescan` for transparent history
 * and `core wallet rescan-witnesses` for the Sapling witnesses a shielded
 * note needs before it can be spent.
 */

#ifndef ZCL_SERVICES_WALLET_RESTORE_SERVICE_H
#define ZCL_SERVICES_WALLET_RESTORE_SERVICE_H

#include "ports/wallet_restore_store_port.h"
#include "util/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Upper bound on the wallet table set (currently eight). */
#define WALLET_RESTORE_TABLE_MAX 16

struct wallet_restore_request {
    const char *backup_path;  /* .sqlite or .sqlite.enc; required */
    const char *datadir;      /* target datadir; required */
    const char *password;     /* NULL => WALLET_BACKUP_PASSWORD from the env */
    bool        dry_run;      /* count everything, write nothing */
};

struct wallet_restore_report {
    char    backup_path[1024];   /* as given */
    char    target_db[1024];     /* <datadir>/node.db */
    bool    dry_run;
    bool    source_was_encrypted;
    bool    target_created;      /* node.db did not exist before this run */

    size_t  n_tables;
    struct wallet_restore_table_report tables[WALLET_RESTORE_TABLE_MAX];

    int64_t total_rows_in_backup;
    int64_t total_inserted;
    int64_t total_collided;
    int64_t total_rejected;

    int     tables_in_backup;      /* of n_tables, how many the file had */
    int     manifest_rows;         /* tables carrying a manifest row */
    int     manifest_mismatches;   /* manifest count != actual count */
    char    warnings[512];         /* comma-joined, empty when clean */
};

/* Prove nobody is holding `datadir`. ZCL_OK means the datadir is free
 * (including when no pidfile exists at all — a fresh recovery directory is
 * the common case). A non-ok result's .message is the one-line reason,
 * naming the holder pid when it could be read. Read-only: it never creates
 * the pidfile and releases any flock it takes. */
struct zcl_result wallet_restore_datadir_free(const char *datadir);

/* ── the WRITER's lock, held across check-then-write ──────────────────
 *
 * wallet_restore_datadir_free() above answers a question and lets go. That
 * is right for a read, and WRONG for a writer: two recoveries into the same
 * empty datadir both asked "is a wallet already here?", both got no, and
 * both wrote — leaving one datadir holding 480 keys from two different
 * seeds under a single seed row, which is verbatim the state the refusal
 * text says it exists to prevent (reproduced 3 times out of 3).
 *
 * So a writer takes an EXCLUSIVE lock on <datadir>/wallet-recovery.lock and
 * holds it from before the "is a wallet already here?" read until after the
 * flush. The second caller then either loses the lock race and is refused
 * by name, or arrives afterwards and sees the first caller's keys.
 *
 * The lock file is its own file, not the node pidfile: the pidfile may not
 * exist at all (a fresh recovery directory is the normal case) and minting
 * one would look to every other tool like a node holding the datadir. The
 * datadir must already exist. It is advisory flock(2), so it binds this
 * node's writers, not a stray `cp`.
 *
 * hold_end() is safe on a zeroed or already-released guard, so the caller
 * can release unconditionally on every exit path. */
struct wallet_restore_datadir_lock {
    int  fd;             /* -1 when not held */
    char path[1200];
};

struct zcl_result wallet_restore_datadir_hold(
    const char *datadir, struct wallet_restore_datadir_lock *lock);
void wallet_restore_datadir_release(struct wallet_restore_datadir_lock *lock);

/* Merge `req->backup_path` into `req->datadir`. Fills `out` (required) on
 * both success and failure — a failed run still reports whatever it learned
 * about the backup file, which is what the user needs to decide the next
 * move. Returns ZCL_OK only when the merge (or, for a dry run, the counted
 * rehearsal) completed. */
struct zcl_result wallet_restore_run(const struct wallet_restore_request *req,
                                     struct wallet_restore_report *out);

#endif /* ZCL_SERVICES_WALLET_RESTORE_SERVICE_H */

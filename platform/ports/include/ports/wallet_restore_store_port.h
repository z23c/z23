/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * wallet_restore_store_port — storage interface for merging a wallet
 * backup file back into a datadir's node.db.
 *
 * The backup half of this stack has existed for a long time; the restore
 * half was `cp`, an undocumented sequence of RPCs, and hand-written SQL.
 * This port is the storage surface of the real one. Two operations, no
 * sqlite type in the header — the adapter under
 * platform/adapters/outbound/persistence/ is the only thing that includes sqlite.
 *
 * Why merge instead of copy
 * -------------------------
 * The obvious "restore" is to drop the backup file into place as node.db.
 * That is wrong twice over. First, the backup file's tables were produced
 * by "CREATE TABLE t AS SELECT * FROM src.t", a construct that copies
 * column names and row values and DROPS the primary keys, CHECK
 * constraints, NOT NULL declarations and indexes — so a backup file's
 * wallet_utxos has no PRIMARY KEY (txid,vout) and its wallet_sapling_notes
 * has no UNIQUE(nullifier). Installing it as node.db installs that damage
 * permanently. Second, it discards whatever the target already had.
 *
 * So the restore opens the TARGET through the normal schema path (every
 * key, constraint and index correct by construction) and merges rows in.
 *
 * Collision policy: KEEP-EXISTING
 * -------------------------------
 * A backup row whose primary key already exists in the target is NOT
 * written. The target's row wins. Rationale: the live datadir is the more
 * recent state, and a restore must never be able to roll a wallet
 * backwards or overwrite a key the user is currently using. The counts
 * make the choice visible instead of implicit — every table reports rows
 * read, rows inserted, rows that collided with an existing row, and rows
 * the target's schema rejected outright.
 *
 * `rows_rejected` is the interesting one: a backup row that did NOT
 * collide on the primary key and still did not land violated some other
 * constraint (a NOT NULL column the old backup lacked, a duplicate
 * nullifier, a CHECK). A non-zero count there is a real integrity signal,
 * which is exactly why the number is reported rather than swallowed.
 */

#ifndef ZCL_PORTS_WALLET_RESTORE_STORE_PORT_H
#define ZCL_PORTS_WALLET_RESTORE_STORE_PORT_H

#include "ports/wallet_backup_store_port.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum wallet_restore_store_status {
    WR_STORE_OK = 0,
    WR_STORE_OPEN_BACKUP_FAILED,  /* backup file missing/unreadable/not sqlite */
    WR_STORE_ATTACH_FAILED,       /* ATTACH of the backup onto the target failed */
    WR_STORE_NO_TARGET,           /* no bound target connection */
    WR_STORE_MERGE_FAILED,        /* a per-table merge statement failed */
};

/* Per-table outcome. Every count is -1 when it was not measured, so a
 * caller can never mistake "not measured" for zero. */
struct wallet_restore_table_report {
    char    table[WALLET_BACKUP_TABLE_NAME_MAX];

    /* What the backup FILE holds. */
    bool    in_backup;            /* the file has this table at all */
    int64_t rows_in_backup;       /* -1 when absent */

    /* What the file's own manifest CLAIMS (see WALLET_BACKUP_MANIFEST_TABLE).
     * manifest_row_count == -1 means the file predates the manifest or the
     * row is missing; a manifest_row_count that disagrees with
     * rows_in_backup means the file was truncated/short-copied after the
     * backup verified — the whole reason the manifest is written. */
    bool    manifest_present_in_source;
    int64_t manifest_row_count;   /* -1 when unknown */

    /* What happened in the TARGET. */
    int64_t rows_before;
    int64_t rows_inserted;
    int64_t rows_collided;        /* PK already present; target's row kept */
    int64_t rows_rejected;        /* schema refused the row (see header) */
    int64_t rows_after;
};

struct wallet_restore_store_port {
    void *self;

    /* Read-only pass over `backup_path`: for each of the `n_tables`
     * `tables[]`, fill in_backup / rows_in_backup and the manifest fields.
     * Leaves the target untouched. `reports` must point at `n_tables`
     * entries; every entry is fully initialised (including the table name)
     * even on failure. */
    enum wallet_restore_store_status (*inspect_backup)(
        void *self,
        const char *backup_path,
        const char *const *tables,
        size_t n_tables,
        struct wallet_restore_table_report *reports,
        char *err, size_t err_cap);

    /* ATTACH `backup_path` onto the bound target connection and merge each
     * table with the keep-existing policy, inside ONE transaction. When
     * `dry_run` is true the transaction is rolled back, so the reported
     * counts are exactly what a real run would produce and nothing is
     * written. Fills rows_before/inserted/collided/rejected/after.
     *
     * Only the intersection of the target's and the backup's column names
     * is copied, so an older backup missing a column still restores its
     * other columns rather than failing wholesale. */
    enum wallet_restore_store_status (*merge_into_target)(
        void *self,
        const char *backup_path,
        const char *const *tables,
        size_t n_tables,
        bool dry_run,
        struct wallet_restore_table_report *reports,
        char *err, size_t err_cap);
};

#endif /* ZCL_PORTS_WALLET_RESTORE_STORE_PORT_H */

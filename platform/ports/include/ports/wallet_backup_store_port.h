/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * wallet_backup_store_port — storage interface for the wallet-backup
 * service's sqlite surface.
 *
 * wallet_backup_service.c is a NON-CONSENSUS but WALLET-SENSITIVE Job: a
 * background thread that periodically snapshots the handful of wallet_*
 * tables out of node.db into a small, external, versioned backup file.
 * The crypto path (PBKDF2 + ChaCha20-Poly1305) lives in
 * wallet_backup_crypto.c and names no sqlite; rotation/listing is plain
 * dirent/stat. Everything in the service that touches sqlite is captured
 * here, so the service never names sqlite once it depends on this port.
 *
 * This port captures exactly four operations:
 *
 *   source_path(out,cap)        sqlite3_db_filename(src,"main") — the
 *                               absolute on-disk path backing the source
 *                               connection. NULL/empty for an in-memory
 *                               source. Needed both to ATTACH the source
 *                               at backup time and to refuse backing up
 *                               into the source's own directory.
 *
 *   count_rows(table,out)       "SELECT count(*) FROM <table>" over the
 *                               source connection — used to read the
 *                               source wallet_keys count for round-trip
 *                               verification.
 *
 *   write_snapshot(...)         the core primitive: open a fresh dst file,
 *                               ATTACH the source by its absolute path,
 *                               and for each wallet table that exists in
 *                               the source run
 *                               "CREATE TABLE t AS SELECT * FROM src.t",
 *                               then write the per-table manifest and
 *                               DETACH + close. Reports which stage
 *                               failed so the caller can preserve the
 *                               file-on-disk-for-forensics behaviour and
 *                               compose the same error messages. Also
 *                               reports, per table, whether the SOURCE had
 *                               it and how many rows it held — a table the
 *                               source did not have is RECORDED, never
 *                               silently skipped.
 *
 *   count_rows_in_file(...)     reopen a backup file READ-ONLY and count
 *                               rows in a table — the verify reopen. This
 *                               operates on an arbitrary file path, not
 *                               the bound source, so it is a static method
 *                               (self may be NULL).
 *
 * No sqlite type appears in this header. The adapter under
 * platform/adapters/outbound/persistence/ is the only thing that includes sqlite
 * for this subsystem. The bind wraps the already-open source connection
 * (the node_db that owns the wallet tables) and never closes it. The
 * write/verify methods open and close their OWN destination connections.
 *
 * Key-material safety: the snapshot copies wallet_* rows verbatim through
 * sqlite's own "CREATE TABLE AS SELECT"; the bytes (encrypted blobs and
 * all) are never decoded, decrypted, or surfaced through this interface.
 * No method returns key, privkey, or seed material — only paths, row
 * counts, and a stage code. Whatever security property a wallet_* row had
 * at rest in node.db it retains, byte-for-byte, in the snapshot file.
 *
 * Threading: the live adapter wraps the single node_db connection opened
 * by boot. The backup thread is the only caller; wallet_backup_now() may
 * also run on a request thread; the service mutex serialises them, and the
 * port adds no locking.
 */

#ifndef ZCL_PORTS_WALLET_BACKUP_STORE_PORT_H
#define ZCL_PORTS_WALLET_BACKUP_STORE_PORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Outcome of write_snapshot(). The caller maps each non-ok stage to the
 * exact zcl_result code + message for each stage, so the RPC / event surface
 * is fixed. WB_STORE_OK means every existing wallet table was copied; the
 * dst file is on disk and closed. */
enum wallet_backup_store_status {
    WB_STORE_OK = 0,            /* snapshot written, dst closed */
    WB_STORE_OPEN_DST_FAILED,   /* sqlite3_open_v2(dst) failed */
    WB_STORE_ATTACH_FAILED,     /* prepare/step ATTACH DATABASE failed */
    WB_STORE_COPY_FAILED,       /* a CREATE TABLE AS SELECT failed */
    WB_STORE_MANIFEST_FAILED,   /* the per-table manifest could not be written */
};

/* Name of the per-table manifest table the snapshot writes into every
 * backup file, and its columns. One row per wallet table the snapshot was
 * ASKED to copy — including the ones the source did not have. Without it a
 * short copy is indistinguishable from a wallet that genuinely had no
 * shielded keys, which is exactly the confusion that loses funds. */
#define WALLET_BACKUP_MANIFEST_TABLE "wallet_backup_manifest"
#define WALLET_BACKUP_MANIFEST_DDL \
    "CREATE TABLE " WALLET_BACKUP_MANIFEST_TABLE " (" \
    "table_name TEXT PRIMARY KEY," \
    "present_in_source INTEGER NOT NULL," \
    "row_count INTEGER NOT NULL)"

/* Longest wallet table name plus headroom; the manifest keys on this. */
#define WALLET_BACKUP_TABLE_NAME_MAX 48

/* What the snapshot found in the SOURCE for one requested table. */
struct wallet_backup_table_stat {
    char    table[WALLET_BACKUP_TABLE_NAME_MAX];
    bool    present_in_source;  /* source had the table at all */
    int64_t rows;               /* rows copied; -1 when absent from source */
};

struct wallet_backup_store_port {
    void *self;

    /* Absolute on-disk path backing the bound source connection. Writes
     * the NUL-terminated path into out (truncated to cap) and returns true
     * on success; returns false (out untouched) if self/out is NULL, the
     * source handle is NULL, or the source has no on-disk filename (an
     * in-memory DB). */
    bool (*source_path)(void *self, char *out, size_t cap);

    /* "SELECT count(*) FROM <table>" over the bound source connection.
     * Sets *out and returns true on the single returned row; false (out
     * untouched, leaving the caller's -1 sentinel) on any prepare/step
     * miss or NULL arg. `table` is a trusted internal identifier (one of
     * the WALLET_TABLES constants), interpolated as a trusted internal
     * identifier. */
    bool (*count_rows)(void *self, const char *table, int64_t *out);

    /* Core primitive. Opens `dst_path` as a fresh empty DB, ATTACHes the
     * bound source by `src_path` under alias "src", and for each of the
     * `n_tables` `tables[]` that exists in the source runs
     * "CREATE TABLE t AS SELECT * FROM src.t", then writes
     * WALLET_BACKUP_MANIFEST_TABLE with one row per REQUESTED table.
     * DETACHes and closes the dst connection before returning (even on copy
     * failure, so the file is left on disk for forensics). On
     * WB_STORE_COPY_FAILED, `out_copy_err` (if non-NULL) is filled with
     * "copy <table>: <sqlite msg>". self may NOT be NULL (source path is
     * supplied by the caller via `src_path`, but the method still needs a
     * bound adapter).
     *
     * `out_stats`, when non-NULL, must point at `n_tables` entries; each is
     * filled with the table name, whether the SOURCE had it, and the row
     * count copied (-1 when absent). Entries for tables not reached because
     * an earlier copy failed keep present_in_source=false / rows=-1. */
    enum wallet_backup_store_status (*write_snapshot)(
        void *self,
        const char *dst_path,
        const char *src_path,
        const char *const *tables,
        size_t n_tables,
        struct wallet_backup_table_stat *out_stats,
        char *out_copy_err,
        size_t copy_err_cap);

    /* Reopen `file_path` READ-ONLY and return count(*) of `table`, or -1 on
     * open/prepare/step failure. Operates on the given file, not the bound
     * source, so self is unused (may be NULL). The verify reopen: count rows
     * in the freshly written backup. */
    int64_t (*count_rows_in_file)(void *self,
                                  const char *file_path,
                                  const char *table);
};

#endif /* ZCL_PORTS_WALLET_BACKUP_STORE_PORT_H */

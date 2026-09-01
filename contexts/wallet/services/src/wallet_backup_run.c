/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet Backup Service — the ONE-SHOT snapshot primitive and its
 * verification. The lifecycle half (thread, config, status, supervisor
 * contract) is wallet_backup_service.c; rotation is
 * wallet_backup_rotation.c; the WBE1 crypto is wallet_backup_crypto.c.
 *
 * Strategy: open the destination as a fresh DB, ATTACH the source by its
 * on-disk path, "CREATE TABLE t AS SELECT * FROM src.t" per wallet table,
 * write the per-table manifest, then reopen the file read-only and verify
 * the row count of EVERY wallet table against the source.
 *
 * Verifying one table of the complete wallet set — which is what this did
 * for a long time —
 * let a copy that dropped wallet_sapling_keys, wallet_seed, or
 * wallet_sapling_notes verify clean and emit a SUCCESS event. The user
 * found out at restore time, which is the one moment they cannot afford
 * to. A table the SOURCE did not have is not a failure, but it is
 * RECORDED (in `vout->missing`, in the file's manifest, and in the emitted
 * event) rather than skipped in silence.
 *
 * On any failure the destination file is LEFT ON DISK — operators need the
 * bytes even when verification fails.
 */

#include "platform/time_compat.h"
#include "platform/file_metadata.h"
#include "platform/private_directory.h"
#include "services/wallet_backup_internal.h"
#include "services/wallet_backup_service.h"

#include "event/event.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>

#include "adapters/outbound/persistence/wallet_backup_store_sqlite.h"
#include "ports/wallet_backup_store_port.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"

static _Atomic int64_t g_wbs_last_backup_path_us = 0;

/* ── Wallet table list ──────────────────────────────────────────
 *
 * ONE list, owned here, exposed through wallet_backup_tables() so the
 * RESTORE side merges back exactly the set the backup captures. Backup and
 * restore can never disagree about what a complete wallet is. */

static const char *const WALLET_TABLES[] = {
    "wallet_keys",
    "wallet_keypool",
    "wallet_key_encryption",
    "wallet_sapling_keys",
    "wallet_seed",
    "wallet_scripts",
    "wallet_transactions",
    "wallet_utxos",
    "wallet_sapling_notes",
};


#define WALLET_TABLE_COUNT (sizeof(WALLET_TABLES) / sizeof(WALLET_TABLES[0]))

const char *const *wallet_backup_tables(size_t *out_count)
{
    if (out_count)
        *out_count = WALLET_TABLE_COUNT;
    return WALLET_TABLES;
}


/* Append `table` to a comma-joined list, never overflowing `cap`. */
static void wbs_append_missing(char *list, size_t cap, const char *table)
{
    size_t used = strlen(list);
    size_t need = strlen(table) + (used ? 1 : 0) + 1;
    if (used + need > cap)
        return;
    if (used)
        list[used++] = ',';
    snprintf(list + used, cap - used, "%s", table);
}


/* Create backup_dir with mode 0700 if missing. Returns true if the
 * directory exists on successful return. */
struct zcl_result wbs_ensure_backup_dir(const char *dir)
{
    if (!dir || !*dir) {
        LOG_WARN("wallet_backup", "backup dir is NULL or empty");
        return ZCL_ERR(-2, "backup dir is NULL or empty");
    }
    if (!platform_private_directory_ensure(dir)) {
        LOG_WARN("wallet_backup", "cannot ensure private backup dir %s: %s",
                 dir, strerror(errno));
        return ZCL_ERR(-2, "cannot create backup dir %s: %s", dir,
                       strerror(errno));
    }
    return ZCL_OK;
}

/* Bind the default sqlite adapter to the source node_db connection.
 * Returns true (filling ctx and port) when db has an open sqlite handle. */
static bool wbs_bind_store(struct node_db *db,
                           struct wallet_backup_store_sqlite_ctx *ctx,
                           struct wallet_backup_store_port *port)
{
    if (!db || !db->open || !db->db || !ctx || !port)
        return false;
    return wallet_backup_store_sqlite_bind(ctx, db->db, port);
}

/* Write the on-disk path backing the source connection into `out`.
 * Returns false for memory databases (out untouched / empty). */
struct zcl_result wbs_source_path(struct node_db *db, char *out, size_t cap)
{
    struct wallet_backup_store_sqlite_ctx ctx;
    struct wallet_backup_store_port port = {0};
    if (out && cap) out[0] = '\0';
    if (!wbs_bind_store(db, &ctx, &port)) {
        LOG_WARN("wallet_backup", "source_path: NULL/closed db handle");
        return ZCL_ERR(-3, "source_path: NULL/closed db handle");
    }
    if (!port.source_path(port.self, out, cap)) {
        LOG_WARN("wallet_backup", "source_path: db has no file path");
        return ZCL_ERR(-3, "source db has no file path (in-memory?)");
    }
    return ZCL_OK;
}

static int64_t wbs_unique_backup_timestamp_us(void)
{
    int64_t now = platform_time_realtime_us();
    int64_t prev = atomic_load(&g_wbs_last_backup_path_us);
    for (;;) {
        int64_t next = now > prev ? now : prev + 1;
        if (atomic_compare_exchange_weak(&g_wbs_last_backup_path_us,
                                         &prev, next))
            return next;
    }
}

/* SHA-style filename: wallet_backup_<unix_ts>_<usec>.sqlite. The usec
 * component is monotonicized to disambiguate rapid successive runs (tests call
 * run_once several times back-to-back). */
static void wbs_build_backup_path(const char *dir, char *out, size_t cap)
{
    int64_t now_us = wbs_unique_backup_timestamp_us();
    snprintf(out, cap, "%s/%s%lld_%06ld%s",
             dir,
             WALLET_BACKUP_FILENAME_PREFIX,
             (long long)(now_us / 1000000LL),
             (long)(now_us % 1000000LL),
             WALLET_BACKUP_FILENAME_SUFFIX);
}

/* ── Core primitive ─────────────────────────────────────────── */

/* Copy a non-ok result's message into the caller's err_out buffer
 * (the legacy buffer-form diagnostic) and return the result. The
 * zcl_result is the source of truth; err_out is a convenience mirror. */
#define WBS_FAIL(err_out, err_cap, code, ...) do {                       \
    struct zcl_result _wbs_r = ZCL_ERR((code), __VA_ARGS__);             \
    if ((err_out) && (err_cap))                                          \
        snprintf((err_out), (err_cap), "%s", _wbs_r.message);            \
    return _wbs_r;                                                       \
} while (0)

/* The whole run. `vout` (never NULL) receives the per-table verification
 * result so wbs_run_one_locked — which already holds g_wbs.lock — can record
 * it without re-entering a non-recursive mutex. */
struct zcl_result wbs_run_once_impl(const char *backup_dir,
                             struct node_db *db,
                             char *out_path, size_t out_path_cap,
                             int64_t *out_key_count,
                             char *err_out, size_t err_cap,
                             struct wbs_verify_out *vout)
{
    vout->tables_verified = 0;
    vout->missing[0] = '\0';
    if (err_out && err_cap) err_out[0] = '\0';
    if (out_path && out_path_cap) out_path[0] = '\0';
    if (out_key_count) *out_key_count = -1;

    if (!backup_dir || !db || !db->open || !db->db)
        WBS_FAIL(err_out, err_cap, -1, "null arg or db not open");

    struct zcl_result dir_r = wbs_ensure_backup_dir(backup_dir);
    if (!dir_r.ok)
        WBS_FAIL(err_out, err_cap, -2, "%s", dir_r.message);

    /* Bind the sqlite adapter to the source connection. All sqlite
     * work below goes through the port. */
    struct wallet_backup_store_sqlite_ctx store_ctx;
    struct wallet_backup_store_port store = {0};
    if (!wbs_bind_store(db, &store_ctx, &store))
        WBS_FAIL(err_out, err_cap, -3, "cannot bind wallet backup store");

    char src_path[1024];
    if (!store.source_path(store.self, src_path, sizeof(src_path)))
        WBS_FAIL(err_out, err_cap, -3, "source db has no file path (in-memory?)");

    /* In-memory source is valid for tests: use the ATTACH TO
     * "file::memory:?cache=shared" form only if the caller opened
     * it with a real filename. Here we simply require a disk file
     * — tests that want to exercise the primitive use a tmpdir. */

    char dst_path[640];
    wbs_build_backup_path(backup_dir, dst_path, sizeof(dst_path));

    /* Open dst, ATTACH source, CREATE TABLE AS SELECT per wallet table,
     * write the per-table manifest, DETACH, close — all inside the adapter.
     * The AS SELECT form copies both schema and rows; a source table that
     * does not exist is not copied but IS recorded in `stats` (and in the
     * file's manifest). */
    char copy_err[ZCL_RESULT_MSG_MAX] = "";
    struct wallet_backup_table_stat stats[WALLET_TABLE_COUNT];
    enum wallet_backup_store_status status =
        store.write_snapshot(store.self, dst_path, src_path,
                             WALLET_TABLES, WALLET_TABLE_COUNT,
                             stats, copy_err, sizeof(copy_err));

    if (status == WB_STORE_OPEN_DST_FAILED)
        WBS_FAIL(err_out, err_cap, -4, "open dst failed: %s", dst_path);
    if (status == WB_STORE_ATTACH_FAILED)
        WBS_FAIL(err_out, err_cap, -5, "attach source failed: %s", src_path);

    if (status == WB_STORE_COPY_FAILED || status == WB_STORE_MANIFEST_FAILED) {
        /* Leave the dst file on disk for forensics, but emit the
         * failure event and bail out. */
        struct platform_file_metadata metadata;
        int64_t bytes = platform_file_metadata_read(dst_path, &metadata) ==
                                PLATFORM_FILE_METADATA_OK &&
                            metadata.size <= INT64_MAX
                            ? (int64_t)metadata.size : -1;
        struct zcl_result r = ZCL_ERR(status == WB_STORE_MANIFEST_FAILED ? -9 : -7,
                                      "%s", copy_err);
        if (err_out) snprintf(err_out, err_cap, "%s", r.message);
        event_emitf(EV_WALLET_BACKUP_FAILED, 0,
                    "path=%s bytes=%lld reason=%s",
                    dst_path, (long long)bytes, r.message);
        return r;
    }

    /* Round-trip verification over ALL wallet tables: reopen the
     * backup file read-only and compare each table's row count against the
     * source's. Verifying only wallet_keys let a copy that dropped
     * wallet_sapling_keys / wallet_seed / wallet_sapling_notes emit a
     * SUCCESS event. If any count differs the file is left on disk but we
     * return non-ok so the caller knows the output is not usable. */
    char *missing = vout->missing;
    const size_t missing_cap = sizeof(vout->missing);
    int verified = 0;
    for (size_t i = 0; i < WALLET_TABLE_COUNT; i++) {
        const char *table = WALLET_TABLES[i];
        int64_t dst_n = store.count_rows_in_file(store.self, dst_path, table);
        if (!stats[i].present_in_source) {
            /* Source never had it. Not a failure — but the destination must
             * not have invented it either, and the operator is TOLD. */
            wbs_append_missing(missing, missing_cap, table);
            if (dst_n >= 0) {
                struct zcl_result r = ZCL_ERR(-8,
                    "verify: %s absent from source but present in backup "
                    "with %lld rows", table, (long long)dst_n);
                if (err_out) snprintf(err_out, err_cap, "%s", r.message);
                event_emitf(EV_WALLET_BACKUP_FAILED, 0,
                            "path=%s reason=%s", dst_path, r.message);
                return r;
            }
            continue;
        }
        int64_t src_n = -1;
        if (!store.count_rows(store.self, table, &src_n))
            src_n = stats[i].rows;
        if (dst_n < 0 || dst_n != src_n) {
            struct zcl_result r = ZCL_ERR(-8,
                    "verify row count mismatch table=%s src=%lld dst=%lld",
                    table, (long long)src_n, (long long)dst_n);
            if (err_out) snprintf(err_out, err_cap, "%s", r.message);
            event_emitf(EV_WALLET_BACKUP_FAILED, 0,
                        "path=%s reason=%s", dst_path, r.message);
            return r;
        }
        verified++;
    }

    int64_t dst_key_count =
        store.count_rows_in_file(store.self, dst_path, "wallet_keys");
    if (dst_key_count < 0)
        dst_key_count = 0;

    vout->tables_verified = verified;

    struct platform_file_metadata metadata;
    int64_t bytes = platform_file_metadata_read(dst_path, &metadata) ==
                            PLATFORM_FILE_METADATA_OK &&
                        metadata.size <= INT64_MAX
                        ? (int64_t)metadata.size : -1;
    event_emitf(EV_WALLET_BACKUP, 0,
                "path=%s bytes=%lld keys=%lld tables_verified=%d "
                "tables_absent_in_source=%s",
                dst_path, (long long)bytes, (long long)dst_key_count,
                verified, missing[0] ? missing : "none");

    if (out_path) snprintf(out_path, out_path_cap, "%s", dst_path);
    if (out_key_count) *out_key_count = dst_key_count;

    return ZCL_OK;
}

struct zcl_result wallet_backup_run_once(const char *backup_dir,
                             struct node_db *db,
                             char *out_path, size_t out_path_cap,
                             int64_t *out_key_count,
                             char *err_out, size_t err_cap)
{
    struct wbs_verify_out vout;
    return wbs_run_once_impl(backup_dir, db, out_path, out_path_cap,
                             out_key_count, err_out, err_cap, &vout);
}

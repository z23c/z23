/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet Backup Service — the ONE-SHOT snapshot primitive and its
 * verification. The lifecycle half (thread, config, status, supervisor
 * contract) is wallet_backup_service.c; rotation is
 * wallet_backup_rotation.c; the WBE1 crypto is wallet_backup_crypto.c.
 *
 * Strategy: open the destination as a fresh DB under a TEMPORARY name (the
 * final name plus ".tmp", which listing, rotation and restore never treat
 * as a backup), ATTACH the source by its on-disk path, "CREATE TABLE t AS
 * SELECT * FROM src.t" per wallet table, write the per-table manifest,
 * close and flush it, then reopen it read-only and verify the row count of
 * EVERY wallet table against the source. Only a verified file is renamed
 * (no-clobber; a checked plain rename where the filesystem rejects that
 * flag) to its final name, after which the directory is flushed.
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
 * On any failure before the rename the temporary file is REMOVED, and a
 * failure to remove it is reported: a partial or unverified file under a
 * backup name sorted newest, took a max_versions slot (so rotation deleted
 * one more verified backup), and could be restored as if complete. A crash
 * leaves at most a temporary file, which wallet_backup_rotate's bounded
 * sweep removes once it is old enough to belong to no live run.
 */

#include "platform/time_compat.h"
#include "platform/file_metadata.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
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

/* Appended to the final backup name while the snapshot is written and
 * verified. wallet_backup_rotation.c sweeps exactly this name shape. */
#define WBS_TEMP_SUFFIX ".tmp"

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
    "wallet_watch_only",
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
static struct zcl_result wbs_build_backup_path(const char *dir,
                                                char *out, size_t cap,
                                                const char *result_out,
                                                size_t result_cap)
{
    int64_t now_us = wbs_unique_backup_timestamp_us();
    int n = snprintf(out, cap, "%s/%s%lld_%06ld%s", dir,
                     WALLET_BACKUP_FILENAME_PREFIX,
                     (long long)(now_us / 1000000LL),
                     (long)(now_us % 1000000LL),
                     WALLET_BACKUP_FILENAME_SUFFIX);
    if (n < 0 || (size_t)n >= cap)
        return ZCL_ERR(-1, "backup path is too long");
    if (result_out && ((size_t)n >= result_cap))
        return ZCL_ERR(-1, "backup output path buffer is too small");
    return ZCL_OK;
}

static struct zcl_result wbs_admit_backup_run(
    const char *backup_dir, const struct node_db *db,
    char *dst_path, size_t dst_path_cap,
    const char *result_out, size_t result_cap)
{
    if (!backup_dir || !db || !db->open || !db->db)
        return ZCL_ERR(-1, "null arg or db not open");
    return wbs_build_backup_path(backup_dir, dst_path, dst_path_cap,
                                 result_out, result_cap);
}

#ifdef ZCL_TESTING
/* Fixture-only seam, declared by the wallet-backup fixture: runs after the
 * snapshot is written and closed, before it is verified, with the path of
 * the written file. A fixture uses it to change the source mid-run (a
 * genuine verify mismatch) or to observe the directory as a crash at that
 * moment would leave it. */
static void (*_Atomic g_wbs_test_snapshot_hook)(const char *written_path);
void wallet_backup_test_set_snapshot_hook(void (*fn)(const char *written_path))
{
    atomic_store(&g_wbs_test_snapshot_hook, fn);
}
#endif

static void wbs_test_after_snapshot(const char *written_path)
{
#ifdef ZCL_TESTING
    void (*fn)(const char *) = atomic_load(&g_wbs_test_snapshot_hook);
    if (fn)
        fn(written_path);
#else
    (void)written_path;
#endif
}

/* Publish stages a fixture can fault (ZCL_TESTING only). */
enum { WBS_TEST_STAGE_RENAME = 0, WBS_TEST_STAGE_PARENT_FLUSH = 1 };

#ifdef ZCL_TESTING
/* Fixture-only seam, declared by the wallet-backup fixture: runs before the
 * no-clobber rename (stage 0) and before the directory flush after it
 * (stage 1) with the final path. A non-zero return is the errno that step
 * then reports without running; a fixture may also plant files first. */
static int (*_Atomic g_wbs_test_publish_hook)(int stage,
                                              const char *final_path);
void wallet_backup_test_set_publish_hook(int (*fn)(int stage,
                                                   const char *final_path))
{
    atomic_store(&g_wbs_test_publish_hook, fn);
}
#endif

/* 0 lets the real step run; otherwise the errno the step reports. Always 0
 * in a production build. */
static int wbs_test_publish_fault(int stage, const char *final_path)
{
#ifdef ZCL_TESTING
    int (*fn)(int, const char *) = atomic_load(&g_wbs_test_publish_hook);
    return fn ? fn(stage, final_path) : 0;
#else
    (void)stage;
    (void)final_path;
    return 0;
#endif
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

/* Reset every caller-visible output before any work happens: a failed
 * run must leave empty strings and -1, never a previous run's values. */
static void wbs_reset_run_outputs(struct wbs_verify_out *vout,
                                  char *out_path, size_t out_path_cap,
                                  int64_t *out_key_count,
                                  char *err_out, size_t err_cap)
{
    vout->tables_verified = 0;
    vout->missing[0] = '\0';
    if (err_out && err_cap) err_out[0] = '\0';
    if (out_path && out_path_cap) out_path[0] = '\0';
    if (out_key_count) *out_key_count = -1;
}

/* Turn a write_snapshot copy/manifest failure into the run's failing
 * result. ZCL_OK means `status` is not a copy/manifest failure and the
 * run may continue. */
static struct zcl_result wbs_fail_on_copy_status(
    enum wallet_backup_store_status status, const char *dst_path,
    const char *copy_err, char *err_out, size_t err_cap)
{
    if (status == WB_STORE_COPY_FAILED || status == WB_STORE_MANIFEST_FAILED) {
        /* Report the size of what was written; the caller then removes
         * the temporary file. */
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
    return ZCL_OK;
}

/* Round-trip verification over ALL wallet tables: reopen the
 * backup file read-only and compare each table's row count against the
 * source's. Verifying only wallet_keys let a copy that dropped
 * wallet_sapling_keys / wallet_seed / wallet_sapling_notes emit a
 * SUCCESS event. If any count differs we return non-ok and the caller
 * removes the temporary file, which was never published. */
static struct zcl_result wbs_verify_all_tables(
    struct wallet_backup_store_port *store, const char *dst_path,
    const struct wallet_backup_table_stat *stats,
    char *missing, size_t missing_cap,
    char *err_out, size_t err_cap, int *out_verified)
{
    int verified = 0;
    for (size_t i = 0; i < WALLET_TABLE_COUNT; i++) {
        const char *table = WALLET_TABLES[i];
        int64_t dst_n = store->count_rows_in_file(store->self, dst_path, table);
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
        if (!store->count_rows(store->self, table, &src_n))
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
    *out_verified = verified;
    return ZCL_OK;
}

/* Emit the SUCCESS event for a verified backup and publish the run's
 * outputs (path copy and key count). */
static void wbs_report_backup_success(
    struct wallet_backup_store_port *store, const char *dst_path,
    const char *missing, int verified,
    struct wbs_verify_out *vout,
    char *out_path, int64_t *out_key_count)
{
    int64_t dst_key_count =
        store->count_rows_in_file(store->self, dst_path, "wallet_keys");
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

    if (out_path)
        memcpy(out_path, dst_path, strlen(dst_path) + 1);
    if (out_key_count) *out_key_count = dst_key_count;
}

/* Open the temporary file, ATTACH source, CREATE TABLE AS SELECT per wallet
 * table, write the per-table manifest, DETACH, close and flush — all inside
 * the adapter — then verify every table ON THAT FILE. The AS SELECT form
 * copies both schema and rows; a source table that does not exist is not
 * copied but IS recorded in `stats` (and in the file's manifest). Any
 * non-ok result leaves the temporary file for the caller to remove. */
static struct zcl_result wbs_snapshot_verified(
    struct wallet_backup_store_port *store, const char *src_path,
    const char *tmp_path, struct wbs_verify_out *vout,
    char *err_out, size_t err_cap, int *out_verified)
{
    char copy_err[ZCL_RESULT_MSG_MAX] = "";
    struct wallet_backup_table_stat stats[WALLET_TABLE_COUNT];
    enum wallet_backup_store_status status =
        store->write_snapshot(store->self, tmp_path, src_path,
                              WALLET_TABLES, WALLET_TABLE_COUNT,
                              stats, copy_err, sizeof(copy_err));

    if (status == WB_STORE_OPEN_DST_FAILED)
        WBS_FAIL(err_out, err_cap, -4, "open dst failed: %s", tmp_path);
    if (status == WB_STORE_ATTACH_FAILED)
        WBS_FAIL(err_out, err_cap, -5, "attach source failed: %s", src_path);

    struct zcl_result copy_r = wbs_fail_on_copy_status(
        status, tmp_path, copy_err, err_out, err_cap);
    if (!copy_r.ok)
        return copy_r;
    wbs_test_after_snapshot(tmp_path);

    return wbs_verify_all_tables(store, tmp_path, stats, vout->missing,
                                 sizeof(vout->missing), err_out, err_cap,
                                 out_verified);
}

/* True when a rename failed only because this directory's filesystem does
 * not support the no-clobber flag (renameat2 RENAME_NOREPLACE on Linux,
 * renameatx_np RENAME_EXCL on Darwin, or no such primitive at all). Never
 * true for EEXIST, an I/O error or a permission error. */
static bool wbs_rename_flag_unsupported(int err)
{
    if (err == EINVAL || err == ENOSYS)
        return true;
#ifdef ENOTSUP
    if (err == ENOTSUP)
        return true;
#endif
#ifdef EOPNOTSUPP
    if (err == EOPNOTSUPP)
        return true;
#endif
    return false;
}

static _Atomic bool g_wbs_plain_rename_logged = false;

/* Tier 2, only after tier 1 reported the flag unsupported: confirm the
 * final name is absent (lstat says ENOENT; any other answer fails the run
 * and names it), then rename with the identity-checked plain-rename helper.
 * This is no weaker than the code before the temporary name, which opened
 * the final name directly with SQLITE_OPEN_CREATE and had no clobber
 * protection at all; the name carries a per-process monotonic microsecond
 * stamp, so only a foreign writer racing the window between the check and
 * the rename could be replaced. */
static struct zcl_result wbs_rename_checked_plain(
    struct platform_private_file *file, const char *tmp_real,
    const char *dst_real, int flag_err)
{
    errno = 0;
    bool absent = platform_private_path_absent(dst_real);
    int lerr = errno;
    if (!absent || lerr != ENOENT)
        return ZCL_ERR(-14, "no-clobber rename unsupported (%s) and backup "
                       "name %s not confirmed absent (%s); refusing a plain "
                       "rename", strerror(flag_err), dst_real,
                       lerr ? strerror(lerr) : "it exists");
    if (!platform_private_file_replace(file, tmp_real, dst_real))
        return ZCL_ERR(-14, "checked plain rename of verified backup to %s "
                       "failed: %s", dst_real, strerror(errno));
    if (!atomic_exchange(&g_wbs_plain_rename_logged, true))
        LOG_INFO("wallet_backup", "backup directory does not support the "
                 "no-clobber rename (%s); used a checked plain rename",
                 strerror(flag_err));
    return ZCL_OK;
}

/* Tier 1: the no-clobber rename. errno is cleared first, so only an errno
 * the rename itself set can read as "flag unsupported" (the helper leaves
 * the rename's errno in place on failure; its earlier fstat, lstat and
 * flush steps already succeeded on this file in the snapshot step). */
static struct zcl_result wbs_rename_verified(
    struct platform_private_file *file, const char *tmp_real,
    const char *dst_real)
{
    bool exists = false;
    errno = 0;
    int err = wbs_test_publish_fault(WBS_TEST_STAGE_RENAME, dst_real);
    bool moved = err == 0 && platform_private_file_publish_no_clobber(
                                 file, tmp_real, dst_real, &exists);
    if (err == 0)
        err = errno;
    if (exists || (!moved && err == EEXIST))
        return ZCL_ERR(-14, "backup name %s already exists; refusing to "
                       "replace it", dst_real);
    if (moved)
        return ZCL_OK;
    if (wbs_rename_flag_unsupported(err))
        return wbs_rename_checked_plain(file, tmp_real, dst_real, err);
    return ZCL_ERR(-14, "cannot rename verified backup to %s: %s",
                   dst_real, strerror(err));
}

/* Rename the verified, already flushed temporary file to its final name
 * without ever replacing an existing file, then flush the directory.
 * `*published` turns true once the final name exists: from then on the
 * file is a complete, verified backup and is never removed here. If the
 * directory flush then fails, the run fails (as for any failed durability
 * barrier) with the file KEPT, since deleting it would delete a verified
 * backup; the caller's pending-and-retry makes another one. */
static struct zcl_result wbs_publish_backup(const char *tmp_path,
                                            const char *dst_path,
                                            bool *published)
{
    char tmp_real[1024], tmp_parent[1024], dst_real[1024], dst_parent[1024];
    if (!platform_private_destination_resolve(tmp_path, tmp_real,
            sizeof(tmp_real), tmp_parent, sizeof(tmp_parent)) ||
        !platform_private_destination_resolve(dst_path, dst_real,
            sizeof(dst_real), dst_parent, sizeof(dst_parent)))
        return ZCL_ERR(-14, "cannot resolve backup paths to publish %s",
                       dst_path);

    struct platform_private_file file;
    platform_private_file_init(&file);
    if (!platform_private_file_open_locked(tmp_real, &file))
        return ZCL_ERR(-14, "cannot reopen verified backup %s to publish it",
                       tmp_real);
    struct zcl_result moved = wbs_rename_verified(&file, tmp_real, dst_real);
    platform_private_file_close(&file);
    if (!moved.ok)
        return moved;
    *published = true;
    int fault = wbs_test_publish_fault(WBS_TEST_STAGE_PARENT_FLUSH, dst_real);
    errno = fault;
    if (fault || !platform_private_parent_flush(dst_parent))
        return ZCL_ERR(-14, "backup is complete and verified and was kept, "
                       "but its directory entry may not survive a power "
                       "loss (directory flush failed: %s): %s",
                       strerror(errno), dst_real);
    return ZCL_OK;
}

/* The publish step with the run's failure reporting: the error buffer and
 * the failure event, as for a verify failure. */
static struct zcl_result wbs_publish_step(const char *tmp_path,
                                          const char *dst_path,
                                          bool *published,
                                          char *err_out, size_t err_cap)
{
    struct zcl_result r = wbs_publish_backup(tmp_path, dst_path, published);
    if (r.ok)
        return r;
    if (err_out && err_cap)
        snprintf(err_out, err_cap, "%s", r.message);
    event_emitf(EV_WALLET_BACKUP_FAILED, 0, "path=%s reason=%s",
                *published ? dst_path : tmp_path, r.message);
    return r;
}

/* Remove the never-published temporary file after a failed run. A removal
 * failure is logged and appended to the run's reason, never hidden. */
static struct zcl_result wbs_discard_temp(struct zcl_result r,
                                          const char *tmp_path,
                                          char *err_out, size_t err_cap)
{
    if (platform_private_file_unlink_missing_ok(tmp_path))
        return r;
    const char *why = strerror(errno);
    LOG_WARN("wallet_backup", "cannot remove failed temporary backup %s: %s",
             tmp_path, why);
    size_t used = strlen(r.message);
    if (used + 1 < sizeof(r.message))
        snprintf(r.message + used, sizeof(r.message) - used,
                 "; temporary %s not removed: %s", tmp_path, why);
    if (err_out && err_cap)
        snprintf(err_out, err_cap, "%s", r.message);
    return r;
}

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
    wbs_reset_run_outputs(vout, out_path, out_path_cap, out_key_count,
                          err_out, err_cap);

    char dst_path[640];
    struct zcl_result admission = wbs_admit_backup_run(
        backup_dir, db, dst_path, sizeof(dst_path), out_path, out_path_cap);
    if (!admission.ok)
        WBS_FAIL(err_out, err_cap, admission.code, "%s", admission.message);

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

    char tmp_path[sizeof(dst_path) + sizeof(WBS_TEMP_SUFFIX)];
    int tn = snprintf(tmp_path, sizeof(tmp_path), "%s%s", dst_path,
                      WBS_TEMP_SUFFIX);
    if (tn < 0 || (size_t)tn >= sizeof(tmp_path))
        WBS_FAIL(err_out, err_cap, -1, "temporary backup path is too long");

    int verified = 0;
    bool published = false;
    struct zcl_result r = wbs_snapshot_verified(
        &store, src_path, tmp_path, vout, err_out, err_cap, &verified);
    if (r.ok)
        r = wbs_publish_step(tmp_path, dst_path, &published,
                             err_out, err_cap);
    if (!r.ok)
        return published ? r : wbs_discard_temp(r, tmp_path,
                                                err_out, err_cap);

    wbs_report_backup_success(&store, dst_path, vout->missing, verified,
                              vout, out_path, out_key_count);

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

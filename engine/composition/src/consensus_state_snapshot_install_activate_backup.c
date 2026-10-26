/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: capture the PRIOR GENERATION of the live progress store before an
 * ACTIVATE cutover — the store health/identity probes (quick_check, "the file
 * under this handle has not moved", the data-version fence) and the
 * VACUUM INTO capture that publishes a standalone, independently reopened,
 * quick-checked, fsynced, sidecar-free, name-durable image of the pre-install
 * database through the retained directory capability.
 *
 * Split out of consensus_state_snapshot_install_activate.c along the
 * file-size ceiling seam (E1). That file keeps the CUTOVER — the row stream,
 * the single atomic install transaction, destination and terminal
 * verification, and the entry point. Full contract:
 * config/consensus_state_snapshot_install.h; the symbols that cross the seam
 * live in consensus_state_snapshot_install_activate_internal.h.
 */

#include "config/consensus_state_snapshot_install.h"
#include "consensus_state_snapshot_install_activate_internal.h"
#include "platform/fd_path.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#if !defined(_WIN32)

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool activate_sqlite_quick_check(sqlite3 *db)
{
    sqlite3_stmt *stmt = NULL;
    if (!db || sqlite3_prepare_v2(db, "PRAGMA quick_check(1)", -1, &stmt,
                                  NULL) != SQLITE_OK)
        return false;
    int rc = sqlite3_step(stmt); // raw-sql-ok:read-only-introspection
    bool ok = rc == SQLITE_ROW &&
              sqlite3_column_type(stmt, 0) == SQLITE_TEXT;
    const unsigned char *text = ok ? sqlite3_column_text(stmt, 0) : NULL;
    ok = ok && text && strcmp((const char *)text, "ok") == 0;
    rc = ok ? sqlite3_step(stmt) : SQLITE_ERROR; // raw-sql-ok:read-only-introspection
    ok = ok && rc == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

/* Fail if the singleton's already-open main inode no longer occupies its
 * original name. This VFS-backed check catches out-of-band rename/replacement
 * around backup and cutover. */
bool activate_progress_file_unmoved(sqlite3 *db)
{
    int moved = 1;
    return db &&
           sqlite3_file_control(db, "main", SQLITE_FCNTL_HAS_MOVED, &moved) ==
               SQLITE_OK &&
           moved == 0;
}

bool activate_data_version(sqlite3 *db, sqlite3_int64 *version)
{
    sqlite3_stmt *stmt = NULL;
    if (!db || !version ||
        sqlite3_prepare_v2(db, "PRAGMA data_version", -1, &stmt, NULL) !=
            SQLITE_OK)
        return false;
    int rc = sqlite3_step(stmt); // raw-sql-ok:read-only-introspection
    bool ok = rc == SQLITE_ROW &&
              sqlite3_column_type(stmt, 0) == SQLITE_INTEGER;
    if (ok)
        *version = sqlite3_column_int64(stmt, 0);
    rc = ok ? sqlite3_step(stmt) : SQLITE_ERROR; // raw-sql-ok:read-only-introspection
    ok = ok && rc == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

static bool activate_backup_sidecars_absent(int datadir_fd, const char *name)
{
    static const char *const suffixes[] = {"-journal", "-wal", "-shm"};
    char sidecar[160];
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        int n = snprintf(sidecar, sizeof(sidecar), "%s%s", name,
                         suffixes[i]);
        struct stat st;
        errno = 0;
        if (n <= 0 || (size_t)n >= sizeof(sidecar) ||
            fstatat(datadir_fd, sidecar, &st, AT_SYMLINK_NOFOLLOW) == 0 ||
            errno != ENOENT)
            return false;
    }
    return true;
}

enum {
    ACTIVATE_BACKUP_OK = 0,
    ACTIVATE_BACKUP_SILENT = 1,
    ACTIVATE_BACKUP_CLEAR = 2,
    ACTIVATE_BACKUP_TARGET_EXISTS = 3,
    ACTIVATE_BACKUP_PATH_FAILED = 4,
    ACTIVATE_BACKUP_VERSION_BEFORE = 5,
    ACTIVATE_BACKUP_PREPARE_FAIL = 6,
    ACTIVATE_BACKUP_BIND_FAIL = 7,
    ACTIVATE_BACKUP_STEP_FAIL = 8,
    ACTIVATE_BACKUP_VERSION_AFTER = 9,
    ACTIVATE_BACKUP_VERSION_CHANGED = 10,
    ACTIVATE_BACKUP_CHANGES_CHANGED = 11,
    ACTIVATE_BACKUP_MOVED = 12,
    ACTIVATE_BACKUP_SIDECAR_PRESENT = 13,
    ACTIVATE_BACKUP_REOPEN_FAIL = 14,
    ACTIVATE_BACKUP_DURABILITY_FAIL = 15,
    ACTIVATE_BACKUP_QUICK_CHECK_FAIL = 16,
    ACTIVATE_BACKUP_NAME_FAIL = 17,
    ACTIVATE_BACKUP_PARENT_FSYNC_FAIL = 18,
    ACTIVATE_BACKUP_DISPLAY_FAIL = 19,
    ACTIVATE_BACKUP_CLEAN_OWNED_FAIL = 20,
    ACTIVATE_BACKUP_CLEAN_NAME_CHANGED = 21,
    ACTIVATE_BACKUP_CLEAN_PARTIAL_FAIL = 22
};

static bool activate_backup_args_ready(sqlite3 *progress_db, int datadir_fd,
                                      const char *datadir_display,
                                      char *out_path, size_t out_cap,
                                      sqlite3_int64 *data_version_out,
                                      sqlite3_int64 *changes_out)
{
    return progress_db && datadir_fd >= 0 && datadir_display &&
           datadir_display[0] && out_path && out_cap != 0 &&
           data_version_out && changes_out &&
           sqlite3_get_autocommit(progress_db) != 0 &&
           activate_progress_file_unmoved(progress_db);
}

static bool activate_backup_directory_matches(int datadir_fd,
                                             const char *datadir_display,
                                             struct stat *dir_st,
                                             struct stat *display_st)
{
    return fstat(datadir_fd, dir_st) == 0 && S_ISDIR(dir_st->st_mode) &&
           stat(datadir_display, display_st) == 0 &&
           S_ISDIR(display_st->st_mode) &&
           display_st->st_dev == dir_st->st_dev &&
           display_st->st_ino == dir_st->st_ino;
}

static int activate_backup_format_names(int datadir_fd,
                                       const char *datadir_display,
                                       char *out_path, size_t out_cap,
                                       char *name, size_t name_cap,
                                       int64_t stamp, uint64_t seq)
{
    int n = snprintf(name, name_cap,
                     "consensus.db.preinstall.%lld.%ld.%llu",
                     (long long)stamp, (long)getpid(),
                     (unsigned long long)seq);
    if (n <= 0 || (size_t)n >= name_cap)
        return ACTIVATE_BACKUP_SILENT;
    n = snprintf(out_path, out_cap, "%s/%s", datadir_display, name);
    if (n <= 0 || (size_t)n >= out_cap)
        return ACTIVATE_BACKUP_CLEAR;
    if (!activate_backup_sidecars_absent(datadir_fd, name))
        return ACTIVATE_BACKUP_CLEAR;
    return ACTIVATE_BACKUP_OK;
}

/* macOS SQLite VACUUM INTO refuses any pre-existing output file, so we
 * reserve the leaf by proving it (and its sidecars) do not exist, then
 * write directly to the datadir path. The resulting file is reopened for
 * identity/fsync verification after the VACUUM completes. */
static int activate_backup_claim_leaf(int datadir_fd, const char *name,
                                     char *destination_name_path,
                                     size_t destination_cap)
{
    struct stat absent_st;
    if (fstatat(datadir_fd, name, &absent_st, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT)
        return ACTIVATE_BACKUP_TARGET_EXISTS;
    if (!platform_dirfd_child_path(destination_name_path, destination_cap,
                                   datadir_fd, name))
        return ACTIVATE_BACKUP_PATH_FAILED;
    return ACTIVATE_BACKUP_OK;
}

static int activate_backup_capture_version_before(sqlite3 *progress_db,
                                                 sqlite3_int64 *version_before,
                                                 sqlite3_int64 *changes_before)
{
    *version_before = -1;
    *changes_before = sqlite3_total_changes64(progress_db);
    if (!activate_data_version(progress_db, version_before))
        return ACTIVATE_BACKUP_VERSION_BEFORE;
    return ACTIVATE_BACKUP_OK;
}

static int activate_backup_run_vacuum_into(sqlite3 *progress_db,
                                          const char *destination_name_path,
                                          bool *created_output, int *rc_out)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(progress_db, "VACUUM main INTO ?1", -1,
                                &stmt, NULL);
    int status = ACTIVATE_BACKUP_OK;
    if (rc != SQLITE_OK) {
        status = ACTIVATE_BACKUP_PREPARE_FAIL;
    } else {
        rc = sqlite3_bind_text(stmt, 1, destination_name_path, -1,
                               SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            status = ACTIVATE_BACKUP_BIND_FAIL;
        } else {
            *created_output = true; /* VACUUM INTO may create/partially write name */
            rc = sqlite3_step(stmt); // raw-sql-ok:progress-kv-kernel-store
            if (rc != SQLITE_DONE)
                status = ACTIVATE_BACKUP_STEP_FAIL;
        }
    }
    if (stmt)
        sqlite3_finalize(stmt);
    *rc_out = rc;
    return status;
}

static int activate_backup_confirm_vacuum_fence(sqlite3 *progress_db,
                                               int datadir_fd, const char *name,
                                               sqlite3_int64 version_before,
                                               sqlite3_int64 *version_after,
                                               sqlite3_int64 changes_before)
{
    *version_after = -1;
    if (!activate_data_version(progress_db, version_after))
        return ACTIVATE_BACKUP_VERSION_AFTER;
    if (version_before != *version_after)
        return ACTIVATE_BACKUP_VERSION_CHANGED;
    if (changes_before != sqlite3_total_changes64(progress_db))
        return ACTIVATE_BACKUP_CHANGES_CHANGED;
    if (!activate_progress_file_unmoved(progress_db))
        return ACTIVATE_BACKUP_MOVED;
    if (!activate_backup_sidecars_absent(datadir_fd, name))
        return ACTIVATE_BACKUP_SIDECAR_PRESENT;
    return ACTIVATE_BACKUP_OK;
}

static int activate_backup_vacuum_if_ok(int status, sqlite3 *progress_db,
                                       int datadir_fd, const char *name,
                                       const char *destination_name_path,
                                       bool *created_output,
                                       sqlite3_int64 version_before,
                                       sqlite3_int64 *version_after,
                                       sqlite3_int64 changes_before,
                                       int *rc_out)
{
    if (status != ACTIVATE_BACKUP_OK)
        return status;
    status = activate_backup_run_vacuum_into(progress_db,
                                             destination_name_path,
                                             created_output, rc_out);
    if (status != ACTIVATE_BACKUP_OK)
        return status;
    return activate_backup_confirm_vacuum_fence(progress_db, datadir_fd, name,
                                                version_before, version_after,
                                                changes_before);
}

static int activate_backup_reopen_output(int datadir_fd, const char *name,
                                        int *fd, struct stat *st,
                                        dev_t *reserved_dev, ino_t *reserved_ino,
                                        bool *reserved_identity)
{
    *fd = openat(datadir_fd, name, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (*fd < 0 || fstat(*fd, st) != 0 || !S_ISREG(st->st_mode) ||
        st->st_nlink != 1)
        return ACTIVATE_BACKUP_REOPEN_FAIL;
    *reserved_identity = true;
    *reserved_dev = st->st_dev;
    *reserved_ino = st->st_ino;
    return ACTIVATE_BACKUP_OK;
}

static bool activate_backup_file_durable(int fd, int datadir_fd,
                                        const char *name, dev_t reserved_dev,
                                        ino_t reserved_ino, struct stat *st,
                                        struct stat *named_st)
{
    return fstat(fd, st) == 0 && S_ISREG(st->st_mode) && st->st_nlink == 1 &&
           st->st_dev == reserved_dev && st->st_ino == reserved_ino &&
           fstatat(datadir_fd, name, named_st, AT_SYMLINK_NOFOLLOW) == 0 &&
           S_ISREG(named_st->st_mode) && named_st->st_nlink == 1 &&
           named_st->st_dev == reserved_dev &&
           named_st->st_ino == reserved_ino &&
           fchmod(fd, 0400) == 0 && fsync(fd) == 0;
}

static bool activate_backup_reopen_quick_check(const char *destination_name_path)
{
    sqlite3 *verify = NULL;
    bool ok = sqlite3_open_v2(destination_name_path, &verify,
                              SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
                              NULL) == SQLITE_OK && verify &&
              sqlite3_db_readonly(verify, "main") == 1 &&
              activate_sqlite_quick_check(verify);
    if (verify) {
        int close_rc = sqlite3_close(verify);
        if (close_rc != SQLITE_OK) {
            ok = false;
            (void)sqlite3_close_v2(verify);
        }
    }
    return ok;
}

static bool activate_backup_name_still_reserved(int datadir_fd,
                                               const char *name,
                                               dev_t reserved_dev,
                                               ino_t reserved_ino,
                                               struct stat *named_st)
{
    return fstatat(datadir_fd, name, named_st, AT_SYMLINK_NOFOLLOW) == 0 &&
           S_ISREG(named_st->st_mode) && named_st->st_nlink == 1 &&
           named_st->st_dev == reserved_dev &&
           named_st->st_ino == reserved_ino;
}

static int activate_backup_publish_parent(int datadir_fd,
                                         const char *datadir_display,
                                         const struct stat *dir_st,
                                         struct stat *display_st)
{
    if (fsync(datadir_fd) != 0)
        return ACTIVATE_BACKUP_PARENT_FSYNC_FAIL;
    if (stat(datadir_display, display_st) != 0 ||
        display_st->st_dev != dir_st->st_dev ||
        display_st->st_ino != dir_st->st_ino)
        return ACTIVATE_BACKUP_DISPLAY_FAIL;
    return ACTIVATE_BACKUP_OK;
}

static int activate_backup_finish_published(int *fd, int datadir_fd,
                                           const char *name,
                                           const char *destination_name_path,
                                           const char *datadir_display,
                                           dev_t reserved_dev,
                                           ino_t reserved_ino, struct stat *st,
                                           struct stat *named_st,
                                           const struct stat *dir_st,
                                           struct stat *display_st)
{
    if (!activate_backup_file_durable(*fd, datadir_fd, name, reserved_dev,
                                     reserved_ino, st, named_st))
        return ACTIVATE_BACKUP_DURABILITY_FAIL;
    if (!activate_backup_reopen_quick_check(destination_name_path))
        return ACTIVATE_BACKUP_QUICK_CHECK_FAIL;
    /* Re-check the published name after the independent reopen. */
    if (!activate_backup_name_still_reserved(datadir_fd, name, reserved_dev,
                                            reserved_ino, named_st))
        return ACTIVATE_BACKUP_NAME_FAIL;
    (void)close(*fd);
    *fd = -1;
    return activate_backup_publish_parent(datadir_fd, datadir_display, dir_st,
                                          display_st);
}

static void activate_backup_close_open_fd(int *fd)
{
    int held = *fd;
    if (held >= 0)
        (void)close(held);
    *fd = -1;
}

static int activate_backup_cleanup_output(bool reserved_identity,
                                         bool created_output, int datadir_fd,
                                         const char *name, dev_t reserved_dev,
                                         ino_t reserved_ino)
{
    struct stat cleanup_st;
    bool owned_name = reserved_identity &&
        fstatat(datadir_fd, name, &cleanup_st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(cleanup_st.st_mode) && cleanup_st.st_dev == reserved_dev &&
        cleanup_st.st_ino == reserved_ino;
    if (owned_name) {
        if (unlinkat(datadir_fd, name, 0) != 0 && errno != ENOENT)
            return ACTIVATE_BACKUP_CLEAN_OWNED_FAIL;
        return ACTIVATE_BACKUP_OK;
    }
    if (reserved_identity)
        return ACTIVATE_BACKUP_CLEAN_NAME_CHANGED;
    if (created_output) {
        /* A failed/partial VACUUM left a file under the reserved random name.
         * The name was unique when we checked, so clean it up. */
        if (unlinkat(datadir_fd, name, 0) != 0 && errno != ENOENT)
            return ACTIVATE_BACKUP_CLEAN_PARTIAL_FAIL;
    }
    return ACTIVATE_BACKUP_OK;
}

/* Dispatch stays a macro so each LOG_WARN below still runs inside
 * activate_backup_prior_generation (__func__ and the message text). */
#define ACTIVATE_BACKUP_DISPATCH(fail_status) \
    do { \
        switch (fail_status) { \
        case ACTIVATE_BACKUP_OK: \
            break; \
        case ACTIVATE_BACKUP_TARGET_EXISTS: \
            goto activate_backup_log_target_exists; \
        case ACTIVATE_BACKUP_PATH_FAILED: \
            goto activate_backup_log_path_failed; \
        case ACTIVATE_BACKUP_VERSION_BEFORE: \
            goto activate_backup_log_version_before; \
        case ACTIVATE_BACKUP_PREPARE_FAIL: \
            goto activate_backup_log_prepare; \
        case ACTIVATE_BACKUP_BIND_FAIL: \
            goto activate_backup_log_bind; \
        case ACTIVATE_BACKUP_STEP_FAIL: \
            goto activate_backup_log_step; \
        case ACTIVATE_BACKUP_VERSION_AFTER: \
            goto activate_backup_log_version_after; \
        case ACTIVATE_BACKUP_VERSION_CHANGED: \
            goto activate_backup_log_version_changed; \
        case ACTIVATE_BACKUP_CHANGES_CHANGED: \
            goto activate_backup_log_changes_changed; \
        case ACTIVATE_BACKUP_MOVED: \
            goto activate_backup_log_moved; \
        case ACTIVATE_BACKUP_SIDECAR_PRESENT: \
            goto activate_backup_log_sidecars; \
        case ACTIVATE_BACKUP_REOPEN_FAIL: \
            goto activate_backup_log_reopen; \
        case ACTIVATE_BACKUP_DURABILITY_FAIL: \
            goto activate_backup_log_durability; \
        case ACTIVATE_BACKUP_QUICK_CHECK_FAIL: \
            goto activate_backup_log_quick_check; \
        case ACTIVATE_BACKUP_NAME_FAIL: \
            goto activate_backup_log_name_identity; \
        case ACTIVATE_BACKUP_PARENT_FSYNC_FAIL: \
            goto activate_backup_log_parent_fsync; \
        case ACTIVATE_BACKUP_DISPLAY_FAIL: \
            goto activate_backup_log_display; \
        default: \
            goto cleanup; \
        } \
    } while (0)

/* Capture a physically restorable prior generation through the retained
 * directory capability.  The caller MUST hold progress_store_tx_lock while
 * progress_db remains in autocommit. VACUUM INTO reads the already-open
 * singleton (never a pathname-reopened source). The caller immediately takes
 * BEGIN IMMEDIATE and compares the returned data-version/total-change fence
 * before making any cutover write, closing the only inter-process commit
 * window. A successful return means the standalone SQLite image was
 * independently reopened, quick-checked, file-fsynced, sidecar-free, and made
 * name-durable by fsyncing its parent directory. */
bool activate_backup_prior_generation(sqlite3 *progress_db,
                                      int datadir_fd,
                                      const char *datadir_display,
                                      char *out_path, size_t out_cap,
                                      sqlite3_int64 *data_version_out,
                                      sqlite3_int64 *changes_out)
{
    static _Atomic uint64_t s_backup_seq = 0;
    if (!activate_backup_args_ready(progress_db, datadir_fd, datadir_display,
                                   out_path, out_cap, data_version_out,
                                   changes_out))
        return false;
    out_path[0] = '\0';
    int fd = -1;
    bool reserved_identity = false;
    bool created_output = false;
    dev_t reserved_dev = 0;
    ino_t reserved_ino = 0;
    struct stat dir_st;
    struct stat display_st;
    struct stat st;
    struct stat named_st;
    char name[128]; /* A4: VACUUM backs up the consensus.db kernel singleton */
    char destination_name_path[PATH_MAX];
    int status = ACTIVATE_BACKUP_OK;
    int rc = SQLITE_OK;
    sqlite3_int64 version_before = -1;
    sqlite3_int64 version_after = -1;
    sqlite3_int64 changes_before = 0;
    if (!activate_backup_directory_matches(datadir_fd, datadir_display,
                                          &dir_st, &display_st))
        return false;

    int64_t stamp = (int64_t)platform_time_wall_time_t();
    uint64_t seq = atomic_fetch_add_explicit(&s_backup_seq, 1,
                                             memory_order_relaxed) + 1;
    status = activate_backup_format_names(datadir_fd, datadir_display,
                                          out_path, out_cap, name,
                                          sizeof(name), stamp, seq);
    if (status == ACTIVATE_BACKUP_SILENT)
        return false;
    if (status == ACTIVATE_BACKUP_CLEAR) {
        out_path[0] = '\0';
        return false;
    }
    status = activate_backup_claim_leaf(datadir_fd, name,
                                       destination_name_path,
                                       sizeof(destination_name_path));
    ACTIVATE_BACKUP_DISPATCH(status);

    status = activate_backup_capture_version_before(progress_db,
                                                   &version_before,
                                                   &changes_before);
    status = activate_backup_vacuum_if_ok(status, progress_db, datadir_fd,
                                          name, destination_name_path,
                                          &created_output, version_before,
                                          &version_after, changes_before,
                                          &rc);
    ACTIVATE_BACKUP_DISPATCH(status);

    status = activate_backup_reopen_output(datadir_fd, name, &fd, &st,
                                          &reserved_dev, &reserved_ino,
                                          &reserved_identity);
    ACTIVATE_BACKUP_DISPATCH(status);

    status = activate_backup_finish_published(&fd, datadir_fd, name,
                                             destination_name_path,
                                             datadir_display, reserved_dev,
                                             reserved_ino, &st, &named_st,
                                             &dir_st, &display_st);
    ACTIVATE_BACKUP_DISPATCH(status);

    *data_version_out = version_after;
    *changes_out = changes_before;
    return true;

activate_backup_log_target_exists:
    LOG_WARN(ACTIVATE_SUBSYS,
             "prior-generation backup target already exists: %s", name);
    goto cleanup;
activate_backup_log_path_failed:
    LOG_WARN(ACTIVATE_SUBSYS,
             "prior-generation backup path construction failed");
    goto cleanup;
activate_backup_log_version_before:
    LOG_WARN(ACTIVATE_SUBSYS,
             "data_version probe before VACUUM failed");
    goto activate_backup_log_fence;
activate_backup_log_prepare:
    LOG_WARN(ACTIVATE_SUBSYS,
             "prepare VACUUM main INTO failed (rc=%d)", rc);
    goto activate_backup_log_fence;
activate_backup_log_bind:
    LOG_WARN(ACTIVATE_SUBSYS,
             "bind VACUUM destination failed (rc=%d)", rc);
    goto activate_backup_log_fence;
activate_backup_log_step:
    LOG_WARN(ACTIVATE_SUBSYS,
             "VACUUM main INTO step failed (rc=%d)", rc);
    goto activate_backup_log_fence;
activate_backup_log_version_after:
    LOG_WARN(ACTIVATE_SUBSYS,
             "data_version probe after VACUUM failed");
    goto activate_backup_log_fence;
activate_backup_log_version_changed:
    LOG_WARN(ACTIVATE_SUBSYS,
             "data_version changed across VACUUM: before=%lld after=%lld",
             (long long)version_before, (long long)version_after);
    goto activate_backup_log_fence;
activate_backup_log_changes_changed:
    LOG_WARN(ACTIVATE_SUBSYS,
             "total_changes changed across VACUUM: before=%lld after=%lld",
             (long long)changes_before,
             (long long)sqlite3_total_changes64(progress_db));
    goto activate_backup_log_fence;
activate_backup_log_moved:
    LOG_WARN(ACTIVATE_SUBSYS,
             "progress store file moved during backup");
    goto activate_backup_log_fence;
activate_backup_log_sidecars:
    LOG_WARN(ACTIVATE_SUBSYS,
             "backup sidecars are not absent");
    goto activate_backup_log_fence;
activate_backup_log_fence:
    LOG_WARN(ACTIVATE_SUBSYS,
             "prior-generation VACUUM/data-version fence failed while "
             "the progress-store lock was held");
    (void)close(fd);
    fd = -1;
    goto cleanup;
activate_backup_log_reopen:
    LOG_WARN(ACTIVATE_SUBSYS,
             "prior-generation backup output reopen failed: %s",
             strerror(errno));
    activate_backup_close_open_fd(&fd);
    goto cleanup;
activate_backup_log_durability:
    LOG_WARN(ACTIVATE_SUBSYS,
             "prior-generation file durability verification failed");
    (void)close(fd);
    fd = -1;
    goto cleanup;
activate_backup_log_quick_check:
    LOG_WARN(ACTIVATE_SUBSYS,
             "prior-generation independent reopen/quick_check failed");
    (void)close(fd);
    fd = -1;
    goto cleanup;
activate_backup_log_name_identity:
    LOG_WARN(ACTIVATE_SUBSYS,
             "prior-generation backup name no longer identifies the "
             "reserved inode");
    (void)close(fd);
    fd = -1;
    goto cleanup;
activate_backup_log_parent_fsync:
    LOG_WARN(ACTIVATE_SUBSYS,
             "prior-generation parent directory fsync failed: %s",
             strerror(errno));
    goto cleanup;
activate_backup_log_display:
    LOG_WARN(ACTIVATE_SUBSYS, "prior-generation display path no longer "
                             "identifies the pinned directory");
    goto cleanup;

cleanup:
    activate_backup_close_open_fd(&fd);
    status = activate_backup_cleanup_output(reserved_identity, created_output,
                                           datadir_fd, name, reserved_dev,
                                           reserved_ino);
    if (status == ACTIVATE_BACKUP_CLEAN_OWNED_FAIL)
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation owned-output cleanup failed: %s",
                 strerror(errno));
    else if (status == ACTIVATE_BACKUP_CLEAN_NAME_CHANGED)
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation output name changed; refusing to unlink "
                 "an unowned replacement");
    else if (status == ACTIVATE_BACKUP_CLEAN_PARTIAL_FAIL)
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation partial-output cleanup failed: %s",
                 strerror(errno));
    if (!activate_backup_sidecars_absent(datadir_fd, name))
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation sidecar remains; refusing unsafe cleanup");
    (void)fsync(datadir_fd);
    out_path[0] = '\0';
    return false;
}

#endif /* !_WIN32 */

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
    if (!progress_db || datadir_fd < 0 || !datadir_display ||
        !datadir_display[0] || !out_path || out_cap == 0 ||
        !data_version_out || !changes_out ||
        sqlite3_get_autocommit(progress_db) == 0 ||
        !activate_progress_file_unmoved(progress_db))
        return false;
    out_path[0] = '\0';
    int fd = -1;
    bool reserved_identity = false;
    bool created_output = false;
    dev_t reserved_dev = 0;
    ino_t reserved_ino = 0;
    struct stat dir_st;
    struct stat display_st;
    if (fstat(datadir_fd, &dir_st) != 0 || !S_ISDIR(dir_st.st_mode) ||
        stat(datadir_display, &display_st) != 0 ||
        !S_ISDIR(display_st.st_mode) || display_st.st_dev != dir_st.st_dev ||
        display_st.st_ino != dir_st.st_ino)
        return false;

    int64_t stamp = (int64_t)platform_time_wall_time_t();
    uint64_t seq = atomic_fetch_add_explicit(&s_backup_seq, 1,
                                             memory_order_relaxed) + 1;
    char name[128]; /* A4: VACUUM backs up the consensus.db kernel singleton */
    int n = snprintf(name, sizeof(name),
                     "consensus.db.preinstall.%lld.%ld.%llu",
                     (long long)stamp, (long)getpid(),
                     (unsigned long long)seq);
    if (n <= 0 || (size_t)n >= sizeof(name))
        return false;

    char destination_name_path[PATH_MAX];
    n = snprintf(out_path, out_cap, "%s/%s", datadir_display, name);
    if (n <= 0 || (size_t)n >= out_cap) {
        out_path[0] = '\0';
        return false;
    }

    if (!activate_backup_sidecars_absent(datadir_fd, name)) {
        out_path[0] = '\0';
        return false;
    }

    /* macOS SQLite VACUUM INTO refuses any pre-existing output file, so we
     * reserve the leaf by proving it (and its sidecars) do not exist, then
     * write directly to the datadir path. The resulting file is reopened for
     * identity/fsync verification after the VACUUM completes. */
    struct stat absent_st;
    if (fstatat(datadir_fd, name, &absent_st, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) {
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation backup target already exists: %s", name);
        goto cleanup;
    }
    if (!platform_dirfd_child_path(destination_name_path,
                                   sizeof(destination_name_path),
                                   datadir_fd, name)) {
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation backup path construction failed");
        goto cleanup;
    }
    struct stat st;

    sqlite3_int64 version_before = -1;
    sqlite3_int64 version_after = -1;
    sqlite3_int64 changes_before = sqlite3_total_changes64(progress_db);
    sqlite3_stmt *stmt = NULL;
    bool ok = activate_data_version(progress_db, &version_before);
    if (!ok)
        LOG_WARN(ACTIVATE_SUBSYS,
                 "data_version probe before VACUUM failed");
    int rc = SQLITE_OK;
    if (ok) {
        rc = sqlite3_prepare_v2(progress_db, "VACUUM main INTO ?1", -1,
                                &stmt, NULL);
        if (rc != SQLITE_OK) {
            ok = false;
            LOG_WARN(ACTIVATE_SUBSYS,
                     "prepare VACUUM main INTO failed (rc=%d)", rc);
        }
    }
    if (ok) {
        rc = sqlite3_bind_text(stmt, 1, destination_name_path, -1,
                               SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            ok = false;
            LOG_WARN(ACTIVATE_SUBSYS,
                     "bind VACUUM destination failed (rc=%d)", rc);
        }
    }
    if (ok) {
        created_output = true; /* VACUUM INTO may create/partially write name */
        rc = sqlite3_step(stmt); // raw-sql-ok:progress-kv-kernel-store
        if (rc != SQLITE_DONE) {
            ok = false;
            LOG_WARN(ACTIVATE_SUBSYS,
                     "VACUUM main INTO step failed (rc=%d)", rc);
        }
    }
    if (stmt)
        sqlite3_finalize(stmt);
    if (ok && !activate_data_version(progress_db, &version_after)) {
        ok = false;
        LOG_WARN(ACTIVATE_SUBSYS,
                 "data_version probe after VACUUM failed");
    }
    if (ok && version_before != version_after) {
        ok = false;
        LOG_WARN(ACTIVATE_SUBSYS,
                 "data_version changed across VACUUM: before=%lld after=%lld",
                 (long long)version_before, (long long)version_after);
    }
    if (ok && changes_before != sqlite3_total_changes64(progress_db)) {
        ok = false;
        LOG_WARN(ACTIVATE_SUBSYS,
                 "total_changes changed across VACUUM: before=%lld after=%lld",
                 (long long)changes_before,
                 (long long)sqlite3_total_changes64(progress_db));
    }
    if (ok && !activate_progress_file_unmoved(progress_db)) {
        ok = false;
        LOG_WARN(ACTIVATE_SUBSYS,
                 "progress store file moved during backup");
    }
    if (ok && !activate_backup_sidecars_absent(datadir_fd, name)) {
        ok = false;
        LOG_WARN(ACTIVATE_SUBSYS,
                 "backup sidecars are not absent");
    }
    if (!ok) {
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation VACUUM/data-version fence failed while "
                 "the progress-store lock was held");
        (void)close(fd);
        fd = -1;
        goto cleanup;
    }

    fd = openat(datadir_fd, name,
                O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_nlink != 1) {
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation backup output reopen failed: %s",
                 strerror(errno));
        if (fd >= 0)
            (void)close(fd);
        fd = -1;
        ok = false;
        goto cleanup;
    }
    reserved_identity = true;
    reserved_dev = st.st_dev;
    reserved_ino = st.st_ino;

    struct stat named_st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_dev != reserved_dev || st.st_ino != reserved_ino ||
        fstatat(datadir_fd, name, &named_st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(named_st.st_mode) || named_st.st_nlink != 1 ||
        named_st.st_dev != reserved_dev || named_st.st_ino != reserved_ino ||
        fchmod(fd, 0400) != 0 || fsync(fd) != 0) {
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation file durability verification failed");
        (void)close(fd);
        fd = -1;
        ok = false;
        goto cleanup;
    }

    sqlite3 *verify = NULL;
    ok = sqlite3_open_v2(destination_name_path, &verify,
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
    if (!ok) {
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation independent reopen/quick_check failed");
        (void)close(fd);
        fd = -1;
        goto cleanup;
    }
    /* Re-check the published name after the independent reopen. */
    if (fstatat(datadir_fd, name, &named_st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(named_st.st_mode) || named_st.st_nlink != 1 ||
        named_st.st_dev != reserved_dev || named_st.st_ino != reserved_ino) {
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation backup name no longer identifies the "
                 "reserved inode");
        (void)close(fd);
        fd = -1;
        goto cleanup;
    }
    (void)close(fd);
    fd = -1;
    if (fsync(datadir_fd) != 0) {
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation parent directory fsync failed: %s",
                 strerror(errno));
        ok = false;
        goto cleanup;
    }
    if (stat(datadir_display, &display_st) != 0 ||
        display_st.st_dev != dir_st.st_dev ||
        display_st.st_ino != dir_st.st_ino) {
        LOG_WARN(ACTIVATE_SUBSYS, "prior-generation display path no longer "
                                 "identifies the pinned directory");
        ok = false;
        goto cleanup;
    }
    *data_version_out = version_after;
    *changes_out = changes_before;
    return true;

cleanup:
    if (fd >= 0)
        (void)close(fd);
    struct stat cleanup_st;
    bool owned_name = reserved_identity &&
        fstatat(datadir_fd, name, &cleanup_st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(cleanup_st.st_mode) && cleanup_st.st_dev == reserved_dev &&
        cleanup_st.st_ino == reserved_ino;
    if (owned_name) {
        if (unlinkat(datadir_fd, name, 0) != 0 && errno != ENOENT)
            LOG_WARN(ACTIVATE_SUBSYS,
                     "prior-generation owned-output cleanup failed: %s",
                     strerror(errno));
    } else if (reserved_identity) {
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation output name changed; refusing to unlink "
                 "an unowned replacement");
    } else if (created_output) {
        /* A failed/partial VACUUM left a file under the reserved random name.
         * The name was unique when we checked, so clean it up. */
        if (unlinkat(datadir_fd, name, 0) != 0 && errno != ENOENT)
            LOG_WARN(ACTIVATE_SUBSYS,
                     "prior-generation partial-output cleanup failed: %s",
                     strerror(errno));
    }
    if (!activate_backup_sidecars_absent(datadir_fd, name))
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation sidecar remains; refusing unsafe cleanup");
    (void)fsync(datadir_fd);
    out_path[0] = '\0';
    return false;
}

#endif /* !_WIN32 */

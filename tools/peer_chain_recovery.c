/* purpose: copy-first recovery of peer_chain_observations with no source writes or output clobbering */
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "multicall.h"
#include "platform/file_sync.h"
#include "platform/time_compat.h"
#include "platform/windows_path.h"
#include "util/ar_step_readonly.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define RECOVERY_STALL_MS 30000
#define RECOVERY_SUFFIX ".peer_chain_recovery.tmp"
#define OBSERVATION_TABLE "peer_chain_observations"
#define OBSERVATION_INDEX "idx_peer_chain_obs_observed_at"

struct recovery_schema {
    char *sql;
    sqlite3_int64 rootpage;
};

static bool recovery_path_absent(const char *path, const char *label)
{
#if defined(_WIN32)
    wchar_t wide[32768];
    WIN32_FILE_ATTRIBUTE_DATA data;
    if (!platform_windows_wide_path(path, wide)) {
        fprintf(stderr, "peer_chain_recovery: unsafe %s path\n", label);
        return false;
    }
    if (GetFileAttributesExW(wide, GetFileExInfoStandard, &data)) {
        fprintf(stderr, "peer_chain_recovery: %s already exists: %s\n", label, path);
        return false;
    }
    DWORD error = GetLastError();
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
        fprintf(stderr, "peer_chain_recovery: cannot inspect %s (%lu)\n",
                label, (unsigned long)error);
        return false;
    }
#else
    struct stat st;
    if (lstat(path, &st) == 0) {
        fprintf(stderr, "peer_chain_recovery: %s already exists: %s\n", label, path);
        return false;
    }
    if (errno != ENOENT) {
        fprintf(stderr, "peer_chain_recovery: cannot inspect %s: %s\n",
                label, strerror(errno));
        return false;
    }
#endif
    return true;
}

static bool recovery_source_regular(const char *path)
{
#if defined(_WIN32)
    wchar_t wide[32768];
    WIN32_FILE_ATTRIBUTE_DATA data;
    bool ok = platform_windows_wide_path(path, wide) &&
              GetFileAttributesExW(wide, GetFileExInfoStandard, &data) &&
              !(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
              !(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
#else
    struct stat st;
    bool ok = lstat(path, &st) == 0 && S_ISREG(st.st_mode);
#endif
    if (!ok)
        fprintf(stderr, "peer_chain_recovery: source must be a regular, non-link file: %s\n",
                path);
    return ok;
}

static bool recovery_remove(const char *path)
{
#if defined(_WIN32)
    wchar_t wide[32768];
    if (!platform_windows_wide_path(path, wide)) return false;
    if (DeleteFileW(wide)) return true;
    DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return true;
#else
    if (unlink(path) == 0 || errno == ENOENT) return true;
#endif
    fprintf(stderr, "peer_chain_recovery: cannot remove temporary path: %s\n", path);
    return false;
}

static bool recovery_sidecars(const char *base, bool remove, const char *label)
{
    static const char *const suffixes[] = {"-wal", "-shm", "-journal"};
    bool ok = true;
    for (size_t i = 0; i < sizeof suffixes / sizeof suffixes[0]; i++) {
        char *path = sqlite3_mprintf("%s%s", base, suffixes[i]);
        if (!path) {
            fputs("peer_chain_recovery: out of memory\n", stderr);
            ok = false;
            continue;
        }
        bool one = remove ? recovery_remove(path) : recovery_path_absent(path, label);
        if (!one) ok = false;
        sqlite3_free(path);
    }
    return ok;
}

static bool recovery_create_temporary(const char *path)
{
#if defined(_WIN32)
    wchar_t wide[32768];
    if (!platform_windows_wide_path(path, wide)) return false;
    HANDLE handle = CreateFileW(wide, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
        NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "peer_chain_recovery: exclusive temporary creation failed (%lu)\n",
                (unsigned long)GetLastError());
        return false;
    }
    if (!CloseHandle(handle)) {
        fputs("peer_chain_recovery: cannot close temporary file\n", stderr);
        if (!recovery_remove(path))
            fputs("peer_chain_recovery: temporary close cleanup failed\n", stderr);
        return false;
    }
#else
    int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int fd = open(path, flags, 0600);
    if (fd < 0) {
        fprintf(stderr, "peer_chain_recovery: exclusive temporary creation failed: %s\n",
                strerror(errno));
        return false;
    }
    if (close(fd) != 0) {
        fprintf(stderr, "peer_chain_recovery: cannot close temporary file: %s\n",
                strerror(errno));
        if (!recovery_remove(path))
            fputs("peer_chain_recovery: temporary close cleanup failed\n", stderr);
        return false;
    }
#endif
    return true;
}

static bool recovery_open(sqlite3 **db, const char *path, int flags,
                          const char *label)
{
    int rc = sqlite3_open_v2(path, db, flags, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "peer_chain_recovery: %s open failed: %s\n", label,
                *db ? sqlite3_errmsg(*db) : "out of memory");
        return false;
    }
    rc = sqlite3_busy_timeout(*db, 100);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "peer_chain_recovery: %s busy setup failed: %s\n",
                label, sqlite3_errmsg(*db));
        return false;
    }
    return true;
}

static bool recovery_close(sqlite3 **db, const char *label)
{
    if (!*db) return true;
    int rc = sqlite3_close(*db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "peer_chain_recovery: %s close failed: %s\n",
                label, sqlite3_errmsg(*db));
        return false;
    }
    *db = NULL;
    return true;
}

struct recovery_progress {
    int best_copied;
    int64_t last;
    bool clock_bad, stalled;
};

/* Bound an unchanged high-water mark; healthy large copies keep advancing. */
static void recovery_progress_note(struct recovery_progress *progress,
                                   sqlite3_backup *backup, int rc)
{
    int64_t now = platform_time_monotonic_ms();
    if (now <= 0 || now < progress->last) {
        progress->clock_bad = true;
        return;
    }
    if (rc == SQLITE_OK) {
        int copied = sqlite3_backup_pagecount(backup) - sqlite3_backup_remaining(backup);
        if (copied > progress->best_copied) {
            progress->best_copied = copied;
            progress->last = now;
        }
    }
    if (rc != SQLITE_DONE && now - progress->last >= RECOVERY_STALL_MS)
        progress->stalled = true;
}

static bool recovery_backup_retryable(int rc)
{
    return rc == SQLITE_OK || rc == SQLITE_BUSY || rc == SQLITE_LOCKED;
}

static bool recovery_backup(sqlite3 *source, sqlite3 *copy)
{
    sqlite3_backup *backup = sqlite3_backup_init(copy, "main", source, "main");
    if (!backup) {
        fprintf(stderr, "peer_chain_recovery: backup init failed: %s\n", sqlite3_errmsg(copy));
        return false;
    }
    int rc = SQLITE_OK, retries = 0;
    struct recovery_progress progress = { .best_copied = -1,
        .last = platform_time_monotonic_ms() };
    progress.clock_bad = progress.last <= 0;
    while (!progress.clock_bad && !progress.stalled &&
           recovery_backup_retryable(rc)) {
        if (rc != SQLITE_OK && ++retries > 50) break;
        if (rc != SQLITE_OK) sqlite3_sleep(10);
        rc = sqlite3_backup_step(backup, 128);
        recovery_progress_note(&progress, backup, rc);
    }
    if (progress.clock_bad || progress.stalled) {
        fprintf(stderr, "peer_chain_recovery: %s\n", progress.clock_bad ?
                "monotonic clock unavailable or reversed" :
                "backup stalled without progress for 30 seconds");
        rc = SQLITE_ABORT;
    }
    if (rc == SQLITE_DONE) rc = SQLITE_OK;
    int finish = sqlite3_backup_finish(backup);
    if (rc == SQLITE_OK) rc = finish;
    if (rc != SQLITE_OK) {
        fprintf(stderr, "peer_chain_recovery: online backup failed: %s\n", sqlite3_errmsg(copy));
        return false;
    }
    return true;
}

static bool recovery_exec(sqlite3 *db, const char *sql, const char *label)
{
    char *error = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &error);
    if (rc == SQLITE_OK) return true;
    fprintf(stderr, "peer_chain_recovery: %s failed: %s\n", label,
            error ? error : sqlite3_errmsg(db));
    sqlite3_free(error);
    return false;
}

/* WAL permits a fixed read snapshot without blocking writers; it can retain WAL
 * pages until the backup finishes. Rollback-journal mode stays unpinned. */
static bool recovery_snapshot_backup(sqlite3 *source, sqlite3 *copy)
{
    if (!recovery_exec(source, "BEGIN", "begin source snapshot")) return false;
    bool ok = recovery_exec(source, "SELECT count(*) FROM sqlite_schema", "pin source snapshot");
    sqlite3_stmt *mode = NULL;
    int rc = ok ? sqlite3_prepare_v2(source, "PRAGMA journal_mode", -1, &mode, NULL) : SQLITE_ERROR;
    if (ok && rc != SQLITE_OK) {
        fprintf(stderr, "peer_chain_recovery: journal mode prepare failed rc=%d: %s\n", rc, sqlite3_errmsg(source));
        ok = false;
    }
    bool wal = false;
    if (ok) {
        rc = sqlite3_step(mode);
        const unsigned char *name = rc == SQLITE_ROW ? sqlite3_column_text(mode, 0) : NULL;
        if (!name) {
            fprintf(stderr, "peer_chain_recovery: journal mode step failed rc=%d: %s\n", rc, sqlite3_errmsg(source));
            ok = false;
        } else {
            wal = sqlite3_stricmp((const char *)name, "wal") == 0;
        }
    }
    if (mode) {
        int final = sqlite3_finalize(mode);
        if (final != SQLITE_OK) {
            fprintf(stderr, "peer_chain_recovery: journal mode finalize failed rc=%d: %s\n", final, sqlite3_errmsg(source));
            ok = false;
        }
    }
    if (ok && wal) ok = recovery_backup(source, copy);
    if (!recovery_exec(source, "ROLLBACK", "release source snapshot")) ok = false;
    if (ok && !wal) ok = recovery_backup(source, copy);
    return ok;
}

static bool recovery_pre_check(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA quick_check(1)", -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "peer_chain_recovery: pre-recovery quick_check prepare failed: %s\n",
                sqlite3_errmsg(db));
        return false;
    }
    int rc = sqlite3_step(st); // raw-sql-ok:standalone-dev-tool
    const unsigned char *result = rc == SQLITE_ROW ? sqlite3_column_text(st, 0) : NULL;
    bool ok = true;
    if (result) {
        printf("peer_chain_recovery: pre-recovery quick_check: %s\n", result);
    } else if (rc == SQLITE_CORRUPT) {
        printf("peer_chain_recovery: pre-recovery quick_check: %s\n", sqlite3_errmsg(db));
    } else {
        fprintf(stderr, "peer_chain_recovery: pre-recovery quick_check failed: %s\n",
                sqlite3_errmsg(db));
        ok = false;
    }
    int finish = sqlite3_finalize(st);
    if (finish != SQLITE_OK && !(rc == SQLITE_CORRUPT && finish == SQLITE_CORRUPT))
        ok = false;
    return ok;
}

static bool recovery_schema_read(sqlite3 *db, const char *type, const char *name,
                                 struct recovery_schema *schema)
{
    static const char *const sql =
        "SELECT sql, rootpage FROM sqlite_schema "
        "WHERE type=?1 AND name=?2 AND tbl_name='" OBSERVATION_TABLE "'";
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_bind_text(st, 1, type, -1, SQLITE_STATIC) == SQLITE_OK;
    if (ok) ok = sqlite3_bind_text(st, 2, name, -1, SQLITE_STATIC) == SQLITE_OK;
    if (ok) ok = ar_step_checked(st, "peer chain recovery read", NULL) ==
                 ZCL_STEP_ROW;
    if (ok) {
        const unsigned char *text = sqlite3_column_text(st, 0);
        schema->rootpage = sqlite3_column_int64(st, 1);
        schema->sql = text ? sqlite3_mprintf("%s", text) : NULL;
        ok = schema->sql && schema->sql[0] && schema->rootpage > 0;
    }
    if (ok) ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:standalone-dev-tool
    if (sqlite3_finalize(st) != SQLITE_OK) ok = false;
    if (!ok) {
        fprintf(stderr, "peer_chain_recovery: expected %s %s is missing or unreadable: %s\n",
                type, name, sqlite3_errmsg(db));
        sqlite3_free(schema->sql);
        schema->sql = NULL;
    }
    return ok;
}

static bool recovery_roots_distinct(sqlite3 *db, const struct recovery_schema *table,
                                    const struct recovery_schema *index)
{
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_prepare_v2(db,
        "SELECT count(*) FROM sqlite_schema WHERE rootpage IN (?1, ?2)",
        -1, &st, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_bind_int64(st, 1, table->rootpage) == SQLITE_OK;
    if (ok) ok = sqlite3_bind_int64(st, 2, index->rootpage) == SQLITE_OK;
    if (ok) ok = ar_step_checked(st, "peer chain recovery read", NULL) ==
                 ZCL_STEP_ROW &&
                 sqlite3_column_int64(st, 0) == 2;
    if (sqlite3_finalize(st) != SQLITE_OK) ok = false;
    if (!ok)
        fputs("peer_chain_recovery: observation roots are shared or unsafe; refusing reset\n",
              stderr);
    return ok;
}

static bool recovery_schema_exec(sqlite3 *db, const char *sql, const char *label)
{
    sqlite3_stmt *st = NULL;
    const char *tail = NULL;
    bool ok = sqlite3_prepare_v2(db, sql, -1, &st, &tail) == SQLITE_OK;
    /* sqlite_schema supplies one preserved definition, never a SQL script. */
    while (ok && *tail && strchr(" \t\r\n\f\v;", *tail)) tail++;
    if (ok) ok = !*tail && sqlite3_bind_parameter_count(st) == 0;
    if (ok) ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:standalone-dev-tool
    if (!ok)
        fprintf(stderr, "peer_chain_recovery: %s failed: %s\n", label, sqlite3_errmsg(db));
    if (sqlite3_finalize(st) != SQLITE_OK) ok = false;
    return ok;
}

static bool recovery_schema_version(sqlite3 *db, int *version)
{
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_prepare_v2(db, "PRAGMA schema_version", -1, &st, NULL) == SQLITE_OK;
    if (ok) ok = ar_step_checked(st, "recovery schema version", NULL) == ZCL_STEP_ROW;
    if (ok) {
        *version = sqlite3_column_int(st, 0);
        ok = *version >= 0 && *version < 2147483647;
    }
    if (sqlite3_finalize(st) != SQLITE_OK) ok = false;
    return ok;
}

static bool recovery_forget_statistics(sqlite3 *db)
{
    static const char *const tables[] = {
        "sqlite_stat1", "sqlite_stat2", "sqlite_stat3", "sqlite_stat4"
    };
    for (size_t i = 0; i < sizeof tables / sizeof tables[0]; i++) {
        sqlite3_stmt *st = NULL;
        bool ok = sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1",
            -1, &st, NULL) == SQLITE_OK;
        if (ok) ok = sqlite3_bind_text(st, 1, tables[i], -1, SQLITE_STATIC) == SQLITE_OK;
        enum zcl_step step = ZCL_STEP_DONE;
        if (ok) step = ar_step_checked(st, "recovery statistics table lookup", NULL);
        if (step == ZCL_STEP_ERROR) ok = false;
        if (sqlite3_finalize(st) != SQLITE_OK) ok = false;
        if (!ok) {
            fprintf(stderr, "peer_chain_recovery: cannot inspect %s: %s\n",
                    tables[i], sqlite3_errmsg(db));
            return false;
        }
        if (step == ZCL_STEP_DONE) continue;
        char *sql = sqlite3_mprintf("DELETE FROM %s WHERE tbl='" OBSERVATION_TABLE "'",
                                    tables[i]);
        if (!sql) {
            fputs("peer_chain_recovery: out of memory\n", stderr);
            return false;
        }
        ok = recovery_exec(db, sql, "observation statistics removal");
        sqlite3_free(sql);
        if (!ok) return false;
    }
    return true;
}

static bool recovery_forget(sqlite3 *db)
{
    int version = 0;
    if (!recovery_schema_version(db, &version)) {
        fputs("peer_chain_recovery: cannot read a safe schema cookie\n", stderr);
        return false;
    }
    char *cookie = sqlite3_mprintf("PRAGMA schema_version=%d", version + 1);
    if (!cookie) {
        fputs("peer_chain_recovery: out of memory\n", stderr);
        return false;
    }
    bool ok = recovery_exec(db, "PRAGMA writable_schema=ON", "copy writable_schema enable") &&
              recovery_exec(db, "BEGIN IMMEDIATE", "schema removal transaction begin") &&
              recovery_exec(db,
                  "DELETE FROM sqlite_schema WHERE tbl_name='" OBSERVATION_TABLE "' "
                  "AND ((type='table' AND name='" OBSERVATION_TABLE "') "
                  "OR (type='index' AND name='" OBSERVATION_INDEX "'))",
                  "observation schema removal");
    if (ok && sqlite3_changes(db) != 2) {
        fputs("peer_chain_recovery: observation schema removal did not match exactly two rows\n",
              stderr);
        ok = false;
    }
    if (ok) {
        ok = recovery_exec(db,
            "DELETE FROM sqlite_sequence WHERE name='" OBSERVATION_TABLE "'",
            "observation sequence removal") && sqlite3_changes(db) <= 1;
    }
    if (ok) ok = recovery_forget_statistics(db);
    if (ok) ok = recovery_exec(db, cookie, "schema cookie advance");
    if (ok) ok = recovery_exec(db, "COMMIT", "schema removal transaction commit");
    if (!ok && !recovery_exec(db, "ROLLBACK", "schema removal transaction rollback"))
        fputs("peer_chain_recovery: schema removal rollback also failed\n", stderr);
    if (!recovery_exec(db, "PRAGMA writable_schema=OFF", "copy writable_schema disable"))
        ok = false;
    sqlite3_free(cookie);
    return ok;
}

static bool recovery_rebuild(sqlite3 *db, const struct recovery_schema *table,
                             const struct recovery_schema *index)
{
    /* Reopen after writable_schema removal: VACUUM copies only live schema,
     * so every orphan page from the undecodable observation tree is discarded. */
    if (!recovery_exec(db, "VACUUM", "full copy rebuild")) return false;
    if (!recovery_exec(db, "BEGIN IMMEDIATE", "schema recreation transaction begin"))
        return false;
    bool ok = recovery_schema_exec(db, table->sql, "observation table recreation") &&
              recovery_schema_exec(db, index->sql, "observation index recreation") &&
              recovery_exec(db, "COMMIT", "schema recreation transaction commit");
    if (!ok && !recovery_exec(db, "ROLLBACK", "schema recreation transaction rollback"))
        fputs("peer_chain_recovery: schema recreation rollback also failed\n", stderr);
    return ok;
}

static bool recovery_final_check(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    const unsigned char *result = NULL;
    bool ok = sqlite3_prepare_v2(db, "PRAGMA quick_check(1)", -1, &st, NULL) == SQLITE_OK;
    if (ok) ok = ar_step_checked(st, "peer chain recovery read", NULL) == ZCL_STEP_ROW;
    if (ok) {
        result = sqlite3_column_text(st, 0);
        ok = result && strcmp((const char *)result, "ok") == 0;
    }
    if (!ok) {
        if (!result) result = (const unsigned char *)sqlite3_errmsg(db);
        fprintf(stderr, "peer_chain_recovery: final quick_check is not ok: %s\n", result);
    }
    if (ok) ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:standalone-dev-tool
    if (sqlite3_finalize(st) != SQLITE_OK) ok = false;
    return ok;
}

static bool recovery_empty(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_prepare_v2(db,
        "SELECT count(*) FROM " OBSERVATION_TABLE, -1, &st, NULL) == SQLITE_OK;
    if (ok) ok = ar_step_checked(st, "peer chain recovery read", NULL) ==
                 ZCL_STEP_ROW &&
                 sqlite3_column_int64(st, 0) == 0;
    if (sqlite3_finalize(st) != SQLITE_OK) ok = false;
    if (!ok)
        fputs("peer_chain_recovery: recovered observation table is missing or not empty\n",
              stderr);
    return ok;
}

static bool recovery_schema_unchanged(sqlite3 *db,
                                      const struct recovery_schema *table,
                                      const struct recovery_schema *index)
{
    struct recovery_schema actual_table = {0}, actual_index = {0};
    bool ok = recovery_schema_read(db, "table", OBSERVATION_TABLE, &actual_table) &&
              recovery_schema_read(db, "index", OBSERVATION_INDEX, &actual_index) &&
              strcmp(actual_table.sql, table->sql) == 0 &&
              strcmp(actual_index.sql, index->sql) == 0;
    if (!ok)
        fputs("peer_chain_recovery: recreated schema differs from preserved schema\n", stderr);
    sqlite3_free(actual_table.sql);
    sqlite3_free(actual_index.sql);
    return ok;
}

static bool recovery_sync_temporary(const char *temporary)
{
#if defined(_WIN32)
    wchar_t wide[32768];
    if (!platform_windows_wide_path(temporary, wide)) return false;
    HANDLE handle = CreateFileW(wide, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "peer_chain_recovery: recovered file open for sync failed (%lu)\n",
                (unsigned long)GetLastError());
        return false;
    }
    bool ok = FlushFileBuffers(handle) != 0;
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!CloseHandle(handle) && ok) {
        ok = false;
        error = GetLastError();
    }
    if (!ok)
        fprintf(stderr, "peer_chain_recovery: recovered file sync or close failed (%lu)\n",
                (unsigned long)error);
    return ok;
#else
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int fd = open(temporary, flags);
    if (fd < 0) {
        fprintf(stderr, "peer_chain_recovery: recovered file open for sync failed: %s\n",
                strerror(errno));
        return false;
    }
    int synced = platform_file_sync(fd);
    int sync_error = errno;
    int closed = close(fd);
    int close_error = errno;
    if (synced != 0 || closed != 0) {
        fprintf(stderr, "peer_chain_recovery: recovered file sync or close failed: %s\n",
                strerror(synced != 0 ? sync_error : close_error));
        return false;
    }
    return true;
#endif
}

#if !defined(_WIN32)
static bool recovery_sync_parent(const char *destination)
{
    char *parent = sqlite3_mprintf("%s", destination);
    if (!parent) {
        fputs("peer_chain_recovery: out of memory\n", stderr);
        return false;
    }
    char *slash = strrchr(parent, '/');
    if (slash == parent) {
        slash[1] = '\0';
    } else if (slash) {
        *slash = '\0';
    } else {
        memcpy(parent, ".", 2);
    }
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
    int fd = open(parent, flags);
    sqlite3_free(parent);
    if (fd < 0) {
        fprintf(stderr, "peer_chain_recovery: parent directory sync failed for %s: %s\n",
                destination, strerror(errno));
        return false;
    }
    int synced = platform_file_sync(fd);
    int sync_error = errno;
    int closed = close(fd);
    int close_error = errno;
    bool ok = (synced == 0 || sync_error == EINVAL) && closed == 0;
    if (!ok)
        fprintf(stderr, "peer_chain_recovery: parent directory sync failed for %s: %s\n",
                destination,
                strerror(synced != 0 && sync_error != EINVAL ? sync_error : close_error));
    return ok;
}
#endif

static bool recovery_publish(const char *temporary, const char *destination,
                             bool *temporary_created, bool *published)
{
    if (!recovery_sync_temporary(temporary)) return false;
#if defined(_WIN32)
    wchar_t from[32768], to[32768];
    bool ok = platform_windows_wide_path(temporary, from) &&
              platform_windows_wide_path(destination, to) &&
              MoveFileExW(from, to, MOVEFILE_WRITE_THROUGH);
    if (ok) {
        *published = true;
        *temporary_created = false;
    }
#else
    bool ok = link(temporary, destination) == 0;
    if (ok) {
        *published = true;
        if (unlink(temporary) == 0) {
            *temporary_created = false;
        } else {
            fprintf(stderr, "peer_chain_recovery: published %s; temporary unlink needs cleanup: %s\n",
                    destination, strerror(errno));
        }
        ok = recovery_sync_parent(destination);
    }
#endif
    if (!ok && !*published)
        fprintf(stderr, "peer_chain_recovery: no-replace publication failed for %s\n",
                destination);
    return ok;
}

struct recovery_job {
    const char *source_path;
    const char *destination;
    char *temporary;
    struct recovery_schema table;
    struct recovery_schema index;
    sqlite3 *source;
    sqlite3 *copy;
    bool temporary_created;
    bool published;
};

static bool recovery_preflight(struct recovery_job *job)
{
    return job->temporary && recovery_source_regular(job->source_path) &&
           recovery_path_absent(job->destination, "destination") &&
           recovery_path_absent(job->temporary, "temporary") &&
           recovery_sidecars(job->temporary, false, "temporary sidecar") &&
           recovery_sidecars(job->destination, false, "destination sidecar") &&
           recovery_open(&job->source, job->source_path, SQLITE_OPEN_READONLY, "source");
}

static bool recovery_repair_copy(struct recovery_job *job)
{
    return recovery_forget(job->copy) &&
           recovery_close(&job->copy, "schema-removal copy") &&
           recovery_open(&job->copy, job->temporary, SQLITE_OPEN_READWRITE, "rebuild copy") &&
           recovery_rebuild(job->copy, &job->table, &job->index) &&
           recovery_final_check(job->copy) &&
           recovery_empty(job->copy) &&
           recovery_schema_unchanged(job->copy, &job->table, &job->index);
}

static bool recovery_work(struct recovery_job *job)
{
    if (!recovery_create_temporary(job->temporary)) return false;
    job->temporary_created = true;
    return recovery_open(&job->copy, job->temporary, SQLITE_OPEN_READWRITE, "copy") &&
           recovery_snapshot_backup(job->source, job->copy) &&
           recovery_close(&job->source, "source") &&
           recovery_pre_check(job->copy) &&
           recovery_schema_read(job->copy, "table", OBSERVATION_TABLE, &job->table) &&
           recovery_schema_read(job->copy, "index", OBSERVATION_INDEX, &job->index) &&
           recovery_roots_distinct(job->copy, &job->table, &job->index) &&
           recovery_repair_copy(job) &&
           recovery_close(&job->copy, "copy") &&
           recovery_sidecars(job->destination, false, "destination sidecar") &&
           recovery_publish(job->temporary, job->destination,
                            &job->temporary_created, &job->published);
}

static bool recovery_cleanup(struct recovery_job *job)
{
    if (!job->temporary_created) return true;
    bool ok = recovery_remove(job->temporary);
    if (!recovery_sidecars(job->temporary, true, "temporary sidecar")) ok = false;
    return ok;
}

static int recovery_finish(struct recovery_job *job, bool recovered)
{
    int status = recovered ? 0 : 1;
    bool closed = recovery_close(&job->source, "source");
    if (!recovery_close(&job->copy, "copy")) closed = false;
    bool cleaned = recovery_cleanup(job);
    if (!closed || !cleaned) {
        if (job->published) {
            fputs("peer_chain_recovery: destination is published; cleanup needs operator attention\n",
                  stderr);
        } else {
            status = 1;
        }
    }
    if (status == 0) {
        printf("peer_chain_recovery: final quick_check: ok\n");
        printf("peer_chain_recovery: published recovered copy: %s\n", job->destination);
    }
    sqlite3_free(job->table.sql);
    sqlite3_free(job->index.sql);
    sqlite3_free(job->temporary);
    return status;
}

int peer_chain_recovery_main(int argc, char **argv)
{
    if (argc != 3 || !argv[1][0] || !argv[2][0] || strcmp(argv[1], argv[2]) == 0) {
        fputs("usage: peer_chain_recovery SOURCE_DB DEST_DB\n"
              "source and destination must be distinct; destination must not exist\n",
              stderr);
        return 1;
    }
    struct recovery_job job = {
        .source_path = argv[1],
        .destination = argv[2],
        .temporary = sqlite3_mprintf("%s%s", argv[2], RECOVERY_SUFFIX),
    };
    bool recovered = recovery_preflight(&job) && recovery_work(&job);
    return recovery_finish(&job, recovered);
}

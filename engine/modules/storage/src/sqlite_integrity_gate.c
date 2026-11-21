/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sqlite_integrity_gate — implementation. See sqlite_integrity_gate.h.
 *
 * Raw sqlite3_prepare_v2/sqlite3_step calls here carry the kernel-primitive
 * marker: this module sits below the AR lifecycle, same as the two callers
 * it serves (progress_store, projection_store). */

#include "sqlite_integrity_gate.h"

#include "platform/time_compat.h"
#include "event/event.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int64_t wall_now_s(void)
{
    struct timespec ts;
    platform_time_realtime_timespec(&ts);
    return (int64_t)ts.tv_sec;
}

static enum sqlite_integrity_result integrity_error(int rc)
{
    int primary = rc & 0xff;
    return primary == SQLITE_CORRUPT || primary == SQLITE_NOTADB
        ? SQLITE_INTEGRITY_CORRUPT : SQLITE_INTEGRITY_INCOMPLETE;
}

static enum sqlite_integrity_result integrity_row(sqlite3_stmt *stmt, const char *log_tag)
{
    if (sqlite3_column_type(stmt, 0) != SQLITE_TEXT)
        return SQLITE_INTEGRITY_INCOMPLETE;
    const unsigned char *text = sqlite3_column_text(stmt, 0);
    int bytes = sqlite3_column_bytes(stmt, 0);
    if (!text || bytes <= 0)
        return SQLITE_INTEGRITY_INCOMPLETE;
    if (bytes == 2 && memcmp(text, "ok", 2) == 0)
        return SQLITE_INTEGRITY_CLEAN;
    fprintf(stderr,  // obs-ok:sqlite-integrity-gate
            "[%s] quick_check found corruption: %s\n", log_tag, text);
    return SQLITE_INTEGRITY_CORRUPT;
}

enum sqlite_integrity_result sqlite_integrity_quick_check(sqlite3 *db,
                                                         const char *log_tag)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, "PRAGMA quick_check(1)", -1, &stmt, NULL);
    if (rc == SQLITE_OK && stmt)
        rc = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
    enum sqlite_integrity_result result = rc == SQLITE_ROW
        ? integrity_row(stmt, log_tag) : integrity_error(rc);
    if (result == SQLITE_INTEGRITY_CLEAN) {
        rc = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
        if (rc != SQLITE_DONE) result = integrity_error(rc);
    }
    int final_rc = sqlite3_finalize(stmt);
    if (final_rc != SQLITE_OK) {
        rc = final_rc;
        result = integrity_error(rc);
    }
    if (result == SQLITE_INTEGRITY_INCOMPLETE || (result == SQLITE_INTEGRITY_CORRUPT && rc != SQLITE_ROW))
        fprintf(stderr,  // obs-ok:sqlite-integrity-gate
                "[%s] quick_check rc=%d: %s\n", log_tag, rc, sqlite3_errmsg(db));
    return result;
}

/* Rename one <path>-family file out of the way with a timestamped, pid+seq-
 * unique suffix. ENOENT is success (the file may not exist). */
static void quarantine_one(const char *path, const char *suffix,
                           const char *log_tag)
{
    if (access(path, F_OK) != 0)
        return;  /* nothing to move (e.g. -wal/-shm absent) */
    char dst[1024 + 96];
    int n = snprintf(dst, sizeof(dst), "%s.%s", path, suffix);
    if (n <= 0 || (size_t)n >= sizeof(dst)) {
        fprintf(stderr,  // obs-ok:sqlite-integrity-gate
                "[%s] quarantine dest too long for %s\n", log_tag, path);
        return;
    }
    if (rename(path, dst) == 0)
        fprintf(stderr,  // obs-ok:sqlite-integrity-gate
                "[%s] quarantined %s -> %s\n", log_tag, path, dst);
    else
        fprintf(stderr,  // obs-ok:sqlite-integrity-gate
                "[%s] failed to quarantine %s: %s\n",
                log_tag, path, strerror(errno));
}

void sqlite_integrity_quarantine_corrupt(const char *path, const char *log_tag,
                                         const char *event_action)
{
    static _Atomic(unsigned) s_seq;
    unsigned seq = atomic_fetch_add_explicit(&s_seq, 1u,
                                             memory_order_relaxed) + 1u;
    char suffix[80];
    time_t now = (time_t)wall_now_s();
    snprintf(suffix, sizeof(suffix), "corrupt.%lld.%ld.%u",
             (long long)now, (long)getpid(), seq);

    char wal[1024 + 8];
    char shm[1024 + 8];
    snprintf(wal, sizeof(wal), "%s-wal", path);
    snprintf(shm, sizeof(shm), "%s-shm", path);

    quarantine_one(path, suffix, log_tag);
    quarantine_one(wal, suffix, log_tag);
    quarantine_one(shm, suffix, log_tag);

    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=%s reason=quick_check_failed path=%s suffix=%s",
                event_action, path, suffix);
}

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * projection_store — implementation. See storage/projection_store.h.
 *
 * The owner of the progress.kv projection file (the kernel moved to consensus.db
 * in the A3 flip), behind an atomic pointer with a one-shot init/close mutex.
 * Projection co-writers use this handle + their OWN recursive tx mutex so their
 * BEGIN IMMEDIATE never serialises on the reducer drive's kernel tx lock — and,
 * post-flip, never shares the kernel's WAL journal either.
 *
 * Raw sqlite3_exec/step here carry the projection-store marker: like
 * progress_store this module sits below the AR lifecycle (the projection
 * tables it fronts are not models). */

#include "platform/fd_path.h"
#include "platform/file_metadata.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/time_compat.h"
#include "base/serialize_le.h"
#include "storage/projection_store.h"
#include "storage/progress_store.h"

#include "sqlite_integrity_gate.h"
#include "event/event.h"
#include "json/json.h"
#include "util/hw_profile.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define PROJECTION_STORE_FILENAME "progress.kv"
#define PROJECTION_CLEAN_RECEIPT_SUFFIX ".clean"
#define PROJECTION_CLEAN_RECEIPT_MAGIC "ZCLPROJCLEAN"
#define PROJECTION_CLEAN_RECEIPT_VERSION 1

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_tx_lock;
static pthread_once_t g_tx_lock_once = PTHREAD_ONCE_INIT;
static _Atomic(sqlite3 *) g_db = NULL;
static char g_path[PROJECTION_STORE_PATH_MAX];
static char g_display_path[PROJECTION_STORE_PATH_MAX];
#ifdef _WIN32
static uintptr_t g_dir_handle;
#else
static int g_dir_fd = -1;
#endif
static int64_t g_opened_at;

static void projection_store_tx_lock_init(void)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_tx_lock, &attr);
    pthread_mutexattr_destroy(&attr);
}

static int64_t wall_now_s(void)
{
    struct timespec ts;
    platform_time_realtime_timespec(&ts);
    return (int64_t)ts.tv_sec;
}

struct projection_file_identity {
    unsigned long long dev;
    unsigned long long ino;
    long long size;
    long long mtime_sec;
    long long mtime_nsec;
    long long ctime_sec;
    long long ctime_nsec;
    uint32_t change_counter;
    uint32_t version_valid_for;
};

static bool projection_file_identity_read(
    const char *path, struct projection_file_identity *out)
{
    if (!path || !out)
        return false;
    memset(out, 0, sizeof(*out));
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &before) || before.size < 100)
        return false;
    unsigned char hdr[100];
    int64_t nr = platform_positioned_file_read(&file, hdr, sizeof(hdr), 0);
    bool stable = platform_positioned_file_snapshot(&file, &after) &&
        memcmp(&before, &after, sizeof(before)) == 0;
    platform_positioned_file_close(&file);
    if (!stable || nr != (int64_t)sizeof(hdr) ||
        memcmp(hdr, "SQLite format 3\000", 16) != 0)
        return false;
    out->dev = before.volume;
    out->ino = before.file_low;
    out->size = (long long)before.size;
    out->mtime_sec = before.modified_seconds;
    out->mtime_nsec = before.modified_nanoseconds;
    out->ctime_sec = before.changed_seconds;
    out->ctime_nsec = before.changed_nanoseconds;
    out->change_counter = zcl_read_u32_be(hdr + 24);
    out->version_valid_for = zcl_read_u32_be(hdr + 92);
    return true;
}

static bool projection_wal_absent(const char *path)
{
    char wal[PROJECTION_STORE_PATH_MAX + 8];
    int n = snprintf(wal, sizeof(wal), "%s-wal", path);
    if (n <= 0 || (size_t)n >= sizeof(wal))
        return false;
    struct platform_file_metadata metadata;
    enum platform_file_metadata_result result =
        platform_file_metadata_read(wal, &metadata);
    return result == PLATFORM_FILE_METADATA_MISSING ||
           (result == PLATFORM_FILE_METADATA_OK && metadata.size == 0);
}

static long long projection_file_size_or_neg1(const char *path)
{
    struct platform_file_metadata metadata;
    return path && platform_file_metadata_read(path, &metadata) ==
                       PLATFORM_FILE_METADATA_OK
        ? (long long)metadata.size : -1;
}

static bool projection_receipt_path(char *out, size_t out_n,
                                    const char *path)
{
    int n = snprintf(out, out_n, "%s%s", path,
                     PROJECTION_CLEAN_RECEIPT_SUFFIX);
    return n > 0 && (size_t)n < out_n;
}

/* A receipt is single-use and binds the exact post-close file identity. ctime
 * makes an in-place page corruption fail the binding even if an attacker or
 * restore tool puts mtime back; inode rejects replacement. A non-empty WAL is
 * always a dirty boot. Any ambiguity falls through to the full quick_check. */
static bool projection_clean_receipt_consume(const char *path)
{
    char receipt[PROJECTION_STORE_PATH_MAX + 16];
    if (!projection_receipt_path(receipt, sizeof(receipt), path))
        return false;
    FILE *fp = fopen(receipt, "rb");
    if (!fp)
        return false;
    char buf[768];
    size_t nr = fread(buf, 1, sizeof(buf) - 1, fp);
    bool eof = feof(fp) != 0;
    (void)fclose(fp);
    (void)unlink(receipt); /* consume on every parse/match outcome */
    if (!eof || nr == 0 || nr >= sizeof(buf) - 1)
        return false;
    buf[nr] = '\0';

    struct projection_file_identity want;
    memset(&want, 0, sizeof(want));
    int consumed = 0;
    int fields = sscanf(
        buf,
        "magic=" PROJECTION_CLEAN_RECEIPT_MAGIC "\n"
        "version=" "1" "\n"
        "dev=%llu\nino=%llu\nsize=%lld\n"
        "mtime_sec=%lld\nmtime_nsec=%lld\n"
        "ctime_sec=%lld\nctime_nsec=%lld\n"
        "change_counter=%u\nversion_valid_for=%u\n%n",
        &want.dev, &want.ino, &want.size,
        &want.mtime_sec, &want.mtime_nsec,
        &want.ctime_sec, &want.ctime_nsec,
        &want.change_counter, &want.version_valid_for, &consumed);
    if (fields != 9 || consumed <= 0 || (size_t)consumed != nr)
        return false;

    struct projection_file_identity have;
    if (!projection_file_identity_read(path, &have) ||
        !projection_wal_absent(path))
        return false;
    return memcmp(&want, &have, sizeof(want)) == 0;
}

static bool projection_clean_receipt_write(const char *path)
{
    struct projection_file_identity id;
    if (!projection_file_identity_read(path, &id) ||
        !projection_wal_absent(path))
        return false;
    char receipt[PROJECTION_STORE_PATH_MAX + 16];
    char tmp[PROJECTION_STORE_PATH_MAX + 64];
    if (!projection_receipt_path(receipt, sizeof(receipt), path))
        return false;
    int tn = snprintf(tmp, sizeof(tmp), "%s.tmp.%llu", receipt,
                      (unsigned long long)os_proc_current_pid());
    if (tn <= 0 || (size_t)tn >= sizeof(tmp))
        return false;
    char content[768];
    int cn = snprintf(
        content, sizeof(content),
        "magic=" PROJECTION_CLEAN_RECEIPT_MAGIC "\n"
        "version=%d\n"
        "dev=%llu\nino=%llu\nsize=%lld\n"
        "mtime_sec=%lld\nmtime_nsec=%lld\n"
        "ctime_sec=%lld\nctime_nsec=%lld\n"
        "change_counter=%u\nversion_valid_for=%u\n",
        PROJECTION_CLEAN_RECEIPT_VERSION,
        id.dev, id.ino, id.size,
        id.mtime_sec, id.mtime_nsec, id.ctime_sec, id.ctime_nsec,
        id.change_counter, id.version_valid_for);
    if (cn <= 0 || (size_t)cn >= sizeof(content))
        return false;
    (void)platform_private_file_unlink_missing_ok(tmp);
    struct platform_private_file staged;
    platform_private_file_init(&staged);
    if (!platform_private_file_create(tmp, &staged))
        return false;
    bool ok = platform_private_file_write_at(&staged, content, (size_t)cn, 0) &&
              platform_private_file_truncate(&staged, (uint64_t)cn) &&
              platform_private_file_flush(&staged) &&
              platform_private_file_replace(&staged, tmp, receipt);
    platform_private_file_close(&staged);
    if (!ok) (void)platform_private_file_unlink_missing_ok(tmp);
    char resolved[PROJECTION_STORE_PATH_MAX + 16];
    char parent[PROJECTION_STORE_PATH_MAX + 16];
    if (ok && (!platform_private_path_resolve(receipt, resolved,
                                              sizeof(resolved), parent,
                                              sizeof(parent)) ||
               !platform_private_parent_flush(parent)))
        ok = false;
    if (!ok) (void)platform_private_file_unlink_missing_ok(receipt);
    return ok;
}

/* The projection handle is a SECONDARY connection: it shares the WAL the
 * kernel connection scaled, so it takes modest fixed page-cache / mmap
 * windows rather than doubling the kernel's RAM budget. WAL/synchronous/
 * foreign_keys/busy_timeout mirror progress_store's per-connection settings so
 * both handles honour the same durability + contention discipline on the same
 * file. */
#define PROJECTION_STORE_CACHE_KIB   (64 * 1024)             /* 64 MiB */
#define PROJECTION_STORE_MMAP_BYTES  (256LL * 1024 * 1024)   /* 256 MiB */

static bool apply_pragmas(sqlite3 *db)
{
    char cache_pragma[64], mmap_pragma[64];
    snprintf(cache_pragma, sizeof(cache_pragma), "PRAGMA cache_size=-%lld",
             (long long)PROJECTION_STORE_CACHE_KIB);
    snprintf(mmap_pragma, sizeof(mmap_pragma), "PRAGMA mmap_size=%lld",
             (long long)PROJECTION_STORE_MMAP_BYTES);

    const char *const pragmas[] = {
        "PRAGMA journal_mode=WAL",
        "PRAGMA synchronous=NORMAL",
        "PRAGMA foreign_keys=ON",
        "PRAGMA busy_timeout=5000",
        cache_pragma,
        mmap_pragma,
        NULL,
    };
    for (size_t i = 0; pragmas[i]; i++) {
        char *err = NULL;
        if (sqlite3_exec(db, pragmas[i], NULL, NULL, &err) != SQLITE_OK) {
            fprintf(stderr,  // obs-ok:projection-store-open-failure
                    "[projection_store] pragma failed (%s): %s\n",
                    pragmas[i], err ? err : "(no message)");
            if (err) sqlite3_free(err);
            return false;
        }
    }
    return true;
}

bool projection_store_open(const char *datadir)
{
    if (!datadir || !datadir[0]) LOG_FAIL("projection_store",
        "open: empty datadir");

    char display_path[PROJECTION_STORE_PATH_MAX];
    int n = snprintf(display_path, sizeof(display_path), "%s/%s",
                     datadir, PROJECTION_STORE_FILENAME);
    if (n <= 0 || (size_t)n >= sizeof(display_path))
        LOG_FAIL("projection_store", "open: datadir path too long");

#ifdef _WIN32
    uintptr_t opened_dir_handle = 0;
    if (!platform_private_directory_open_validated(datadir,
                                                    &opened_dir_handle))
        LOG_FAIL("projection_store", "open: private datadir capability failed");
    char path[PROJECTION_STORE_PATH_MAX];
    snprintf(path, sizeof(path), "%s", display_path);
#else
    int opened_dir_fd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (opened_dir_fd < 0)
        LOG_FAIL("projection_store", "open: datadir capability failed: %s",
                 strerror(errno));
    char path[PROJECTION_STORE_PATH_MAX];
    if (!platform_dirfd_child_path(path, sizeof(path), opened_dir_fd,
                                   PROJECTION_STORE_FILENAME)) {
        (void)close(opened_dir_fd);
        LOG_FAIL("projection_store", "open: capability path too long");
    }
#endif

    pthread_mutex_lock(&g_lock);

    if (atomic_load_explicit(&g_db, memory_order_relaxed) != NULL) {
#ifdef _WIN32
        bool same = strcmp(g_display_path, display_path) == 0;
        platform_private_directory_close(opened_dir_handle);
#else
        struct stat have;
        struct stat want;
        bool same = g_dir_fd >= 0 && fstat(g_dir_fd, &have) == 0 &&
                    fstat(opened_dir_fd, &want) == 0 &&
                    have.st_dev == want.st_dev && have.st_ino == want.st_ino;
        (void)close(opened_dir_fd);
#endif
        pthread_mutex_unlock(&g_lock);
        if (!same)
            LOG_FAIL("projection_store",
                "open: already opened at a different directory (%s vs %s)",
                g_display_path, display_path);
        return true;
    }

    /* CREATE: after the Wave A3 consensus.db flip the kernel handle
     * (progress_store) opens consensus.db, NOT progress.kv — so progress_store
     * no longer creates progress.kv. projection_store now OWNS progress.kv as
     * the dedicated projection file: on a fresh node it must mint it here (the
     * Class C address_index / txindex projections are fully rebuildable, so a
     * fresh or re-derived projection file is always safe; created_outputs is
     * a KERNEL table written through the consensus.db handle, not here — see
     * consensus_db.c's projection-stay exclusion list). */
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(path, &db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:projection-store-open-failure
                "[projection_store] sqlite3_open_v2(%s) failed: %s\n",
                path, db ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
        if (db) sqlite3_close(db);
#ifdef _WIN32
        platform_private_directory_close(opened_dir_handle);
#else
        (void)close(opened_dir_fd);
#endif
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    bool verified_clean = projection_clean_receipt_consume(display_path);

    /* Integrity gate. progress.kv's projection tables (address_index / txindex
     * / created_outputs and kin) are fully rebuildable, but a corrupt file
     * left in place would otherwise surface as a mid-fold SQLITE_CORRUPT deep
     * inside a projection job — a JOB_FATAL with no named blocker. On a
     * non-"ok" quick_check, quarantine the file aside and reopen a FRESH one;
     * whichever projection job runs next re-creates its schema (CREATE TABLE
     * IF NOT EXISTS) and re-derives its rows from the kernel, same as a
     * brand-new node. AUTO-TERMINATING + idempotent: a fresh, just-created
     * store that ALSO fails quick_check is a disk/fs fault, not corrupt
     * derived state — fail the open instead of quarantine-looping. */
    int64_t quick_check_started = platform_time_monotonic_ms();
    if (verified_clean) {
        fprintf(stderr,  // obs-ok:projection-store-lifecycle
                "[projection_store] quick_check skipped "
                "(content-bound clean-close receipt) path=%s\n", display_path);
    } else {
        fprintf(stderr,  // obs-ok:projection-store-lifecycle
                "[projection_store] quick_check start path=%s bytes=%lld\n",
                display_path, projection_file_size_or_neg1(display_path));
    }
    if (!verified_clean &&
        !sqlite_integrity_quick_check_ok(db, "projection_store")) {
        fprintf(stderr,  // obs-ok:projection-store-open-failure
                "[projection_store] %s failed integrity quick_check; "
                "quarantining + re-deriving\n", path);
        sqlite3_close(db);
        db = NULL;
        sqlite_integrity_quarantine_corrupt(path, "projection_store",
                                            "projection_store_quarantine");

        rc = sqlite3_open_v2(path, &db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr,  // obs-ok:projection-store-open-failure
                    "[projection_store] reopen after quarantine of %s failed: "
                    "%s — disk/fs fault\n",
                    path, db ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
            if (db) sqlite3_close(db);
#ifdef _WIN32
            platform_private_directory_close(opened_dir_handle);
#else
            (void)close(opened_dir_fd);
#endif
            event_emitf(EV_RECOVERY_ACTION, 0,
                        "action=projection_store_reopen_failed "
                        "reason=disk_fault path=%s", path);
            pthread_mutex_unlock(&g_lock);
            return false;
        }
        if (!sqlite_integrity_quick_check_ok(db, "projection_store")) {
            /* A freshly-created, empty DB that fails quick_check cannot be
             * derived-state corruption — the underlying storage is broken.
             * Do NOT quarantine again (that would loop); fail terminally. */
            fprintf(stderr,  // obs-ok:projection-store-open-failure
                    "[projection_store] FRESH %s still fails quick_check — "
                    "terminal disk/fs fault, refusing to loop\n", path);
            sqlite3_close(db);
#ifdef _WIN32
            platform_private_directory_close(opened_dir_handle);
#else
            (void)close(opened_dir_fd);
#endif
            event_emitf(EV_RECOVERY_ACTION, 0,
                        "action=projection_store_fresh_corrupt "
                        "reason=disk_fault path=%s", path);
            pthread_mutex_unlock(&g_lock);
            return false;
        }
        fprintf(stderr,  // obs-ok:projection-store-lifecycle
                "[projection_store] fresh %s opened after quarantine "
                "(projections re-derive on next fold)\n", path);
    }
    if (!verified_clean) {
        fprintf(stderr,  // obs-ok:projection-store-lifecycle
                "[projection_store] quick_check done path=%s elapsed_ms=%lld\n",
                display_path,
                (long long)(platform_time_monotonic_ms() - quick_check_started));
    }

    if (!apply_pragmas(db)) {
        sqlite3_close(db);
#ifdef _WIN32
        platform_private_directory_close(opened_dir_handle);
#else
        (void)close(opened_dir_fd);
#endif
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    snprintf(g_path, sizeof(g_path), "%s", path);
    snprintf(g_display_path, sizeof(g_display_path), "%s", display_path);
#ifdef _WIN32
    g_dir_handle = opened_dir_handle;
#else
    g_dir_fd = opened_dir_fd;
#endif
    g_opened_at = wall_now_s();
    atomic_store_explicit(&g_db, db, memory_order_release);

    pthread_mutex_unlock(&g_lock);

    fprintf(stderr,  // obs-ok:projection-store-lifecycle
            "[projection_store] opened %s (WAL, secondary handle)\n",
            display_path);
    return true;
}

sqlite3 *projection_store_db(void)
{
    return atomic_load_explicit(&g_db, memory_order_acquire);
}

void projection_store_tx_lock(void)
{
    pthread_once(&g_tx_lock_once, projection_store_tx_lock_init);
    pthread_mutex_lock(&g_tx_lock);
}

bool projection_store_tx_trylock(void)
{
    pthread_once(&g_tx_lock_once, projection_store_tx_lock_init);
    return pthread_mutex_trylock(&g_tx_lock) == 0;
}

void projection_store_tx_unlock(void)
{
    pthread_mutex_unlock(&g_tx_lock);
}

void projection_store_close(void)
{
    pthread_mutex_lock(&g_lock);
    projection_store_tx_lock();
    sqlite3 *db = atomic_exchange_explicit(&g_db, NULL,
                                            memory_order_acq_rel);
    if (!db) {
        projection_store_tx_unlock();
        pthread_mutex_unlock(&g_lock);
        return;
    }

    int log_frames = 0;
    int checkpointed_frames = 0;
    int checkpoint_rc = sqlite3_wal_checkpoint_v2(
        db, NULL, SQLITE_CHECKPOINT_TRUNCATE,
        &log_frames, &checkpointed_frames);
    int rc = sqlite3_close(db);
    if (rc != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:projection-store-lifecycle
                "[projection_store] sqlite3_close: rc=%d (%s)\n",
                rc, sqlite3_errstr(rc));
    } else {
        fprintf(stderr,  // obs-ok:projection-store-lifecycle
                "[projection_store] closed %s\n", g_display_path);
    }

    if (checkpoint_rc == SQLITE_OK && rc == SQLITE_OK) {
        if (!projection_clean_receipt_write(g_display_path))
            fprintf(stderr,  // obs-ok:projection-store-lifecycle
                    "[projection_store] clean-close receipt unavailable; "
                    "next boot will run full quick_check path=%s\n",
                    g_display_path);
    } else {
        char receipt[PROJECTION_STORE_PATH_MAX + 16];
        if (projection_receipt_path(receipt, sizeof(receipt), g_display_path))
            (void)unlink(receipt);
        fprintf(stderr,  // obs-ok:projection-store-lifecycle
                "[projection_store] dirty close checkpoint_rc=%d close_rc=%d "
                "log_frames=%d checkpointed_frames=%d; no receipt\n",
                checkpoint_rc, rc, log_frames, checkpointed_frames);
    }

#ifdef _WIN32
    if (g_dir_handle != 0)
        platform_private_directory_close(g_dir_handle);
    g_dir_handle = 0;
#else
    if (g_dir_fd >= 0)
        (void)close(g_dir_fd);
    g_dir_fd = -1;
#endif
    g_path[0] = '\0';
    g_display_path[0] = '\0';
    g_opened_at = 0;
    projection_store_tx_unlock();
    pthread_mutex_unlock(&g_lock);
}

bool projection_store_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    sqlite3 *db = projection_store_db();
    json_push_kv_bool(out, "open", db != NULL);
    pthread_mutex_lock(&g_lock);
    char path_snap[PROJECTION_STORE_PATH_MAX];
    snprintf(path_snap, sizeof(path_snap), "%s", g_display_path);
    int64_t opened_at_snap = g_opened_at;
    pthread_mutex_unlock(&g_lock);
    json_push_kv_str(out, "path", path_snap);
    json_push_kv_int(out, "opened_at", opened_at_snap);
    /* Prove the split: this handle is a distinct sqlite3 connection from the
     * kernel's progress_store handle (both fronting the same physical file). */
    json_push_kv_bool(out, "independent_of_kernel",
                      db != NULL && db != progress_store_db());
    return true;
}

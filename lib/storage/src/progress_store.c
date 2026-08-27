/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * progress_store — implementation. See storage/progress_store.h.
 *
 * One handle, one path, opened at boot once. The handle lives behind
 * an atomic pointer so `progress_store_db()` is a relaxed-atomic load
 * with no mutex; opens and closes serialise on a one-shot init mutex.
 *
 * Direct sqlite3_exec / sqlite3_step calls here carry the kernel-
 * primitive marker because, like the stage primitive itself, this
 * module sits below the AR lifecycle — the stage_cursor row is not a
 * model. */

#include "platform/fd_path.h"
#include "platform/time_compat.h"
#include "storage/progress_store.h"

#include "sqlite_integrity_gate.h"
#include "storage/consensus_db.h"
#include "storage/repair_marker.h"
#include "event/event.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "util/hw_profile.h"
#include "util/log_macros.h"
#include "util/stage.h"
#include "util/subsystem_snapshot.h"

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

/* THE kernel store filename is now consensus.db (Wave A3 physical flip): the
 * reducer's consensus kernel (coins / anchors / nullifiers / stage cursors /
 * progress_meta + the stage *_log journals it commits with) lives in its OWN
 * SQLite file so its fsync-bearing batch commit stops sharing a WAL journal with
 * the projection co-writers. progress.kv survives only as the projection file
 * (projection_store's handle) holding the Class C address_index / txindex /
 * created_outputs tables. progress_store_open() migrates a legacy progress.kv
 * kernel into consensus.db in place before opening it, so the public API is
 * unchanged. */
#define PROGRESS_STORE_FILENAME  CONSENSUS_DB_FILENAME
/* PROGRESS_STORE_PATH_MAX comes from storage/progress_store.h. */

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_tx_lock;
static pthread_once_t g_tx_lock_once = PTHREAD_ONCE_INIT;
static _Atomic(sqlite3 *) g_db = NULL;
/* g_path is the retained-dirfd path SQLite actually opened.  Keeping the
 * directory descriptor alive also keeps later WAL and independent-reader
 * opens on the same directory capability even if the caller's path is
 * renamed or replaced.  g_display_path is observational only. */
static char g_path[PROGRESS_STORE_PATH_MAX];
static char g_display_path[PROGRESS_STORE_PATH_MAX];
static int g_dir_fd = -1;
static int64_t g_opened_at;
/* Monotonic open-epoch. Bumped on every successful open so in-memory caches
 * seeded from the store (e.g. the log-row counters in stage_log_rows) can
 * detect a reopen — a new datadir, or a test reopening the singleton — and
 * re-seed exactly once per boot rather than per schema-ensure call. Starts at
 * 0 ("never opened"); the first open makes it 1. */
static _Atomic uint64_t g_epoch;

static void progress_store_tx_lock_init(void)
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

/* A contained consensus-state candidate deliberately carries convincing
 * reducer rows but has not passed selected-chain, rollback, or activation CAS
 * authority. Refuse it before schema creation or any other write so a manual
 * rename to progress.kv cannot turn admission-only evidence into runtime
 * consensus state. A future promoter must consume the candidate into a new
 * generation and remove this table only inside its bound activation protocol. */
static bool progress_store_candidate_state(sqlite3 *db, bool *contained)
{
    if (!db || !contained)
        return false;
    *contained = false;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(
            db,
            "SELECT 1 FROM sqlite_schema WHERE type='table' AND "
            "name='consensus_state_candidate_meta'",
            -1, &stmt, NULL) != SQLITE_OK)
        return false;
    int rc = sqlite3_step(stmt); // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *contained = true;
        rc = sqlite3_step(stmt); // raw-sql-ok:progress-kv-kernel-store
    }
    bool ok = rc == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

/* progress.kv's page cache + mmap window scale with measured RAM (via
 * hw_profile), capped at this file's historical ceilings (1 GiB cache, 2
 * GiB mmap — a pure read-path/memory-residency control, unrelated to WAL
 * journaling or on-disk format). Same fixed values on any >=32 GiB-RAM box;
 * scales DOWN on constrained ones instead of unconditionally requesting a 1
 * GiB cache + 2 GiB mmap window for one connection regardless of RAM. */
#define PROGRESS_STORE_CACHE_FLOOR_KIB   (64 * 1024)                /* 64 MiB */
#define PROGRESS_STORE_CACHE_CEIL_KIB    (1024 * 1024)              /* 1 GiB */
#define PROGRESS_STORE_MMAP_FLOOR_BYTES  (256LL * 1024 * 1024)      /* 256 MiB */
#define PROGRESS_STORE_MMAP_CEIL_BYTES   (2LL * 1024 * 1024 * 1024) /* 2 GiB */

/* Apply WAL + reasonable durability/recovery pragmas. Errors here are
 * fatal for the open (caller will close & fail). */
static bool apply_pragmas(sqlite3 *db)
{
    hw_profile_init(NULL);
    int64_t ram = hw_profile_ram_bytes();
    int64_t cache_kib = hw_profile_sqlite_cache_kib(
        ram, PROGRESS_STORE_CACHE_FLOOR_KIB, PROGRESS_STORE_CACHE_CEIL_KIB);
    int64_t mmap_bytes = hw_profile_sqlite_mmap_bytes(
        ram, PROGRESS_STORE_MMAP_FLOOR_BYTES, PROGRESS_STORE_MMAP_CEIL_BYTES);

    char cache_pragma[64], mmap_pragma[64];
    snprintf(cache_pragma, sizeof(cache_pragma), "PRAGMA cache_size=-%lld",
             (long long)cache_kib);
    snprintf(mmap_pragma, sizeof(mmap_pragma), "PRAGMA mmap_size=%lld",
             (long long)mmap_bytes);

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
            fprintf(stderr,  // obs-ok:progress-store-open-failure
                    "[progress_store] pragma failed (%s): %s\n",
                    pragmas[i], err ? err : "(no message)");
            if (err) sqlite3_free(err);
            return false;
        }
    }
    return true;
}

/* Integrity gate on open. Mirrors node.db's db_quick_check_ok
 * (app/models/src/database.c). progress.kv hosts every stage cursor AND the
 * coins_kv UTXO table; if SQLite reports a malformed file, a mid-fold
 * SQLITE_CORRUPT turns into a permanent JOB_FATAL that pins H* forever with no
 * named blocker. Detecting it here lets the open path quarantine + re-derive
 * instead. Returns true only when PRAGMA quick_check reports exactly "ok". A
 * prepare/step failure (the connection itself is wedged on a corrupt file) is
 * treated as NOT ok so the caller quarantines. */
static bool progress_store_quick_check_ok(sqlite3 *db)
{
    return sqlite_integrity_quick_check_ok(db, "progress_store");
}

/* Move the corrupt consensus.db (+ -wal/-shm) aside so the reopen creates a
 * FRESH, empty store. progress.kv/consensus.db is a DERIVED store: the
 * coins_kv UTXO set it holds is re-seeded at boot from consensus_snapshot.db
 * (or the anchor), and the stage cursors re-fold from there. An empty store
 * therefore triggers the normal re-derivation rather than serving torn state.
 * Emits a NAMED recovery event (not a silent stop). */
static void progress_store_quarantine_corrupt(const char *path)
{
    sqlite_integrity_quarantine_corrupt(path, "progress_store",
                                        "progress_store_quarantine");
}

bool progress_store_open(const char *datadir)
{
    if (!datadir || !datadir[0]) LOG_FAIL("progress_store",
        "open: empty datadir");

    /* Rename-in-place flip: migrate a legacy progress.kv kernel into
     * consensus.db before opening it. Idempotent (a no-op once consensus.db
     * exists, and a clean no-op on a fresh node where there is no progress.kv —
     * the open below then creates consensus.db from scratch). A real migration
     * integrity failure returns false here and MUST abort the open: creating a
     * fresh empty consensus.db would orphan the kernel still sitting in
     * progress.kv. */
    {
        char merr[256];
        merr[0] = '\0';
        if (!consensus_db_migrate_from_progress(datadir, merr, sizeof(merr))) {
            fprintf(stderr,  // obs-ok:progress-store-open-failure
                    "[progress_store] consensus.db migration failed: %s\n",
                    merr[0] ? merr : "(no message)");
            return false;
        }
    }

    char display_path[PROGRESS_STORE_PATH_MAX];
    int n = snprintf(display_path, sizeof(display_path), "%s/%s",
                     datadir, PROGRESS_STORE_FILENAME);
    if (n <= 0 || (size_t)n >= sizeof(display_path))
        LOG_FAIL("progress_store", "open: datadir path too long");

    int opened_dir_fd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (opened_dir_fd < 0)
        LOG_FAIL("progress_store", "open: datadir capability failed: %s",
                 strerror(errno));
    char path[PROGRESS_STORE_PATH_MAX];
    if (!platform_dirfd_child_path(path, sizeof(path), opened_dir_fd,
                                   PROGRESS_STORE_FILENAME)) {
        (void)close(opened_dir_fd);
        LOG_FAIL("progress_store", "open: capability path too long");
    }

    pthread_mutex_lock(&g_lock);

    /* Already open with this path → idempotent success. */
    if (atomic_load_explicit(&g_db, memory_order_relaxed) != NULL) {
        struct stat have;
        struct stat want;
        bool same = g_dir_fd >= 0 && fstat(g_dir_fd, &have) == 0 &&
                    fstat(opened_dir_fd, &want) == 0 &&
                    have.st_dev == want.st_dev && have.st_ino == want.st_ino;
        (void)close(opened_dir_fd);
        pthread_mutex_unlock(&g_lock);
        if (!same)
            LOG_FAIL("progress_store",
                "open: already opened at a different directory (%s vs %s)",
                g_display_path, display_path);
        return true;
    }

    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(path, &db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:progress-store-open-failure
                "[progress_store] sqlite3_open_v2(%s) failed: %s\n",
                path, db ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
        if (db) sqlite3_close(db);
        (void)close(opened_dir_fd);
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    /* Integrity gate. progress.kv is the authority store for the stage cursors
     * and the coins_kv UTXO table; a corrupt file otherwise surfaces as a
     * mid-fold SQLITE_CORRUPT → JOB_FATAL that pins H* permanently with no
     * named blocker. On a non-"ok" quick_check, quarantine the file and reopen
     * a FRESH one — boot re-seeds coins_kv from consensus_snapshot.db / the
     * anchor and re-folds the stages from there (progress.kv is a derived
     * projection, not the source of truth). AUTO-TERMINATING + idempotent: a
     * fresh, just-created store that ALSO fails quick_check is a disk/fs fault,
     * not corrupt derived state — log a terminal blocker and fail the open
     * instead of quarantine-looping. */
    if (!progress_store_quick_check_ok(db)) {
        fprintf(stderr,  // obs-ok:progress-store-open-failure
                "[progress_store] %s failed integrity quick_check; "
                "quarantining + re-deriving from snapshot/anchor\n", path);
        sqlite3_close(db);
        db = NULL;
        progress_store_quarantine_corrupt(path);

        rc = sqlite3_open_v2(path, &db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr,  // obs-ok:progress-store-open-failure
                    "[progress_store] reopen after quarantine of %s failed: "
                    "%s — disk/fs fault\n",
                    path, db ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
            if (db) sqlite3_close(db);
            (void)close(opened_dir_fd);
            event_emitf(EV_RECOVERY_ACTION, 0,
                        "action=progress_store_reopen_failed reason=disk_fault "
                        "path=%s", path);
            pthread_mutex_unlock(&g_lock);
            return false;
        }
        if (!progress_store_quick_check_ok(db)) {
            /* A freshly-created, empty DB that fails quick_check cannot be
             * derived-state corruption — the underlying storage is broken.
             * Do NOT quarantine again (that would loop); fail terminally with
             * a named blocker. */
            fprintf(stderr,  // obs-ok:progress-store-open-failure
                    "[progress_store] FRESH %s still fails quick_check — "
                    "terminal disk/fs fault, refusing to loop\n", path);
            sqlite3_close(db);
            (void)close(opened_dir_fd);
            event_emitf(EV_RECOVERY_ACTION, 0,
                        "action=progress_store_fresh_corrupt reason=disk_fault "
                        "path=%s", path);
            pthread_mutex_unlock(&g_lock);
            return false;
        }
        fprintf(stderr,  // obs-ok:progress-store-lifecycle
                "[progress_store] fresh %s opened after quarantine "
                "(coins_kv will re-seed from snapshot/anchor at boot)\n", path);
    }

    bool contained_candidate = false;
    if (!progress_store_candidate_state(db, &contained_candidate) ||
        contained_candidate) {
        if (contained_candidate) {
            fprintf(stderr,  // obs-ok:progress-store-open-failure
                    "[progress_store] refusing contained consensus-state "
                    "candidate at %s; selected-chain activation evidence "
                    "is absent\n", path);
            event_emitf(EV_RECOVERY_ACTION, 0,
                        "action=progress_store_candidate_refused "
                        "reason=activation_authority_absent path=%s", path);
        } else {
            fprintf(stderr,  // obs-ok:progress-store-open-failure
                    "[progress_store] candidate containment inspection "
                    "failed for %s\n", path);
        }
        sqlite3_close(db);
        (void)close(opened_dir_fd);
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    if (!apply_pragmas(db) || !stage_table_ensure(db) ||
        !progress_meta_table_ensure(db) ||
        !repair_marker_table_ensure(db) ||
        !repair_marker_migrate_from_progress_meta(db)) {
        sqlite3_close(db);
        (void)close(opened_dir_fd);
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    /* A FUTURE consensus.db schema marker means this binary is OLDER than the
     * one that last wrote this datadir (a binary downgrade). Silently
     * proceeding would let consensus_db_finalize_flip() treat it as
     * "not yet flipped" and overwrite the newer marker with this binary's
     * OLDER version. Refuse the open outright — the caller (boot) already
     * FATALs+exits on progress_store_open() returning false
     * (boot_snapshot_install_gate_boot), so this is a loud, fail-fast boot
     * refusal naming both versions, never a silent re-flip. */
    {
        uint32_t marker_v = 0;
        char derr[256] = "";
        if (consensus_db_schema_is_downgrade(db, &marker_v, derr, sizeof(derr))) {
            fprintf(stderr,  // obs-ok:progress-store-open-failure
                    "[progress_store] FATAL: %s\n", derr);
            sqlite3_close(db);
            (void)close(opened_dir_fd);
            event_emitf(EV_RECOVERY_ACTION, 0,
                        "action=progress_store_downgrade_refused "
                        "reason=schema_marker_future marker_version=%u "
                        "binary_version=%u path=%s", marker_v,
                        (unsigned)CONSENSUS_DB_SCHEMA_VERSION, path);
            pthread_mutex_unlock(&g_lock);
            return false;
        }
    }

    snprintf(g_path, sizeof(g_path), "%s", path);
    snprintf(g_display_path, sizeof(g_display_path), "%s", display_path);
    g_dir_fd = opened_dir_fd;
    g_opened_at = wall_now_s();
    atomic_fetch_add_explicit(&g_epoch, 1, memory_order_release);
    atomic_store_explicit(&g_db, db, memory_order_release);

    pthread_mutex_unlock(&g_lock);

    fprintf(stderr,  // obs-ok:progress-store-lifecycle
            "[progress_store] opened %s (WAL)\n", display_path);
    return true;
}

sqlite3 *progress_store_db(void)
{
    return atomic_load_explicit(&g_db, memory_order_acquire);
}

uint64_t progress_store_epoch(void)
{
    return atomic_load_explicit(&g_epoch, memory_order_acquire);
}

bool progress_store_path(char *out, size_t cap)
{
    if (!out || cap == 0) return false;
    /* g_path is set once under g_lock in progress_store_open and only cleared
     * on close; a brief lock gives a torn-free snapshot. Empty => not open. */
    pthread_mutex_lock(&g_lock);
    bool ok = g_path[0] != '\0' && strlen(g_path) < cap;
    if (ok) snprintf(out, cap, "%s", g_path);
    else    out[0] = '\0';
    pthread_mutex_unlock(&g_lock);
    return ok;
}

sqlite3 *progress_store_open_reader(void)
{
    sqlite3 *reader = NULL;
    pthread_mutex_lock(&g_lock);
    /* g_path is rooted at the directory descriptor retained for the lifetime
     * of the singleton, so this cannot be redirected by a pathname swap. Hold
     * g_lock through sqlite3_open_v2 so shutdown cannot close that capability
     * between the snapshot and the open. */
    bool available = atomic_load_explicit(&g_db, memory_order_acquire) != NULL &&
                     g_path[0] != '\0';
    int rc = available
        ? sqlite3_open_v2(g_path, &reader,
                          SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, NULL)
        : SQLITE_CANTOPEN;
    pthread_mutex_unlock(&g_lock);
    if (rc != SQLITE_OK) {
        if (reader)
            sqlite3_close(reader);
        return NULL;
    }
    (void)sqlite3_busy_timeout(reader, 25);
    return reader;
}

bool progress_store_directory_matches_fd(sqlite3 *db, int dir_fd)
{
    if (!db || dir_fd < 0)
        return false;
    pthread_mutex_lock(&g_lock);
    struct stat have;
    struct stat want;
    bool ok = atomic_load_explicit(&g_db, memory_order_acquire) == db &&
              g_dir_fd >= 0 && fstat(g_dir_fd, &have) == 0 &&
              fstat(dir_fd, &want) == 0 && S_ISDIR(have.st_mode) &&
              S_ISDIR(want.st_mode) && have.st_dev == want.st_dev &&
              have.st_ino == want.st_ino;
    pthread_mutex_unlock(&g_lock);
    return ok;
}

void progress_store_tx_lock(void)
{
    pthread_once(&g_tx_lock_once, progress_store_tx_lock_init);
    pthread_mutex_lock(&g_tx_lock);
}

bool progress_store_tx_trylock(void)
{
    pthread_once(&g_tx_lock_once, progress_store_tx_lock_init);
    return pthread_mutex_trylock(&g_tx_lock) == 0;
}

void progress_store_tx_unlock(void)
{
    pthread_mutex_unlock(&g_tx_lock);
}

bool progress_store_set_sync_mode(bool ibd)
{
    sqlite3 *db = progress_store_db();
    if (!db) return false;

    /* OFF during IBD (cursor commits don't fsync → the from-blocks fold is
     * not fsync-bound); NORMAL at-tip (the safe default applied at open).
     * This is a pure durability/flush-timing control — it changes nothing
     * about WHAT is written or committed, only when the OS flushes it. */
    const char *pragma = ibd ? "PRAGMA synchronous=OFF"
                             : "PRAGMA synchronous=NORMAL";

    progress_store_tx_lock();
    char *err = NULL;
    int rc = sqlite3_exec(db, pragma, NULL, NULL, &err);
    progress_store_tx_unlock();
    if (rc != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:progress-store-lifecycle
                "[progress_store] set_sync_mode(%s) failed: %s\n",
                pragma, err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    if (err) sqlite3_free(err);
    fprintf(stderr,  // obs-ok:progress-store-lifecycle
            "[progress_store] %s (%s)\n", pragma, ibd ? "IBD" : "at-tip");
    return true;
}

bool progress_store_checkpoint(void)
{
    /* Same checkpoint+truncate as the close path, but WITHOUT closing the
     * connection — returns the WAL file's high-water bytes to the filesystem
     * while the store stays open. Used by the disk_full reclaim path so a
     * near-full disk can free derived bytes and clear the condition. */
    progress_store_tx_lock();
    sqlite3 *db = progress_store_db();
    if (!db) {
        progress_store_tx_unlock();
        return false;
    }
    char *err = NULL;
    int rc = sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)",
                          NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:progress-store-lifecycle
                "[progress_store] checkpoint(reclaim): %s\n",
                err ? err : "(no message)");
    }
    if (err) sqlite3_free(err);
    progress_store_tx_unlock();
    return rc == SQLITE_OK;
}

void progress_store_close(void)
{
    pthread_mutex_lock(&g_lock);
    progress_store_tx_lock();
    sqlite3 *db = atomic_exchange_explicit(&g_db, NULL,
                                            memory_order_acq_rel);
    if (!db) {
        progress_store_tx_unlock();
        pthread_mutex_unlock(&g_lock);
        return;
    }

    /* Best-effort checkpoint so the WAL truncates cleanly. Failures
     * here are not fatal — sqlite3_close still runs. */
    char *err = NULL;
    if (sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)",
                     NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:progress-store-lifecycle
                "[progress_store] checkpoint on close: %s\n",
                err ? err : "(no message)");
    }
    if (err) sqlite3_free(err);

    int rc = sqlite3_close(db);
    if (rc != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:progress-store-lifecycle
                "[progress_store] sqlite3_close: rc=%d (%s)\n",
                rc, sqlite3_errstr(rc));
    } else {
        fprintf(stderr,  // obs-ok:progress-store-lifecycle
                "[progress_store] closed %s\n", g_display_path);
    }

    if (g_dir_fd >= 0)
        (void)close(g_dir_fd);
    g_dir_fd = -1;
    g_path[0] = '\0';
    g_display_path[0] = '\0';
    g_opened_at = 0;
    progress_store_tx_unlock();
    pthread_mutex_unlock(&g_lock);
}

/* ── progress_meta ─────────────────────────────────────────────────────
 *
 * Tiny k/v table colocated with stage_cursor. See header for purpose.
 * Same kernel-primitive justification as stage_cursor — raw sqlite3_step
 * carries the `// raw-sql-ok:kernel-primitive` marker. */

bool progress_meta_table_ensure(sqlite3 *db)
{
    if (!db) return false;
    char *err = NULL;
    int rc = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS progress_meta ("
        "  key   TEXT PRIMARY KEY,"
        "  value BLOB NOT NULL"
        ")",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:progress-store-open-failure
                "[progress_store] progress_meta CREATE failed: %s\n",
                err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

static bool progress_meta_set_stmt(sqlite3 *db, const char *key,
                                   const void *value, size_t value_len)
{
    if (!db || !key || !key[0]) return false;
    if (value_len > 0 && !value) return false;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO progress_meta(key, value) VALUES(?, ?)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, value ? value : "", (int)value_len,
                      SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

static bool progress_meta_delete_stmt(sqlite3 *db, const char *key)
{
    if (!db || !key || !key[0]) return false;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM progress_meta WHERE key = ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool progress_meta_set_in_tx(sqlite3 *db, const char *key,
                             const void *value, size_t value_len)
{
    return progress_meta_set_stmt(db, key, value, value_len);
}

bool progress_meta_delete_in_tx(sqlite3 *db, const char *key)
{
    return progress_meta_delete_stmt(db, key);
}

bool progress_meta_raise_u64_in_tx(sqlite3 *db, const char *key, uint64_t value,
                                   bool *raised, uint64_t *winner)
{
    if (raised) *raised = false;
    if (winner) *winner = value;
    if (!db || !key || !key[0]) return false;

    /* Read the current floor with exact-BLOB semantics (fail closed on any
     * coercible non-BLOB / wrong-length value). Reuses the caller's open txn —
     * progress_meta_get_blob_exact takes the recursive lock internally. */
    uint8_t blob[8] = {0};
    size_t n = 0;
    bool present = false;
    if (!progress_meta_get_blob_exact(db, key, blob, sizeof(blob), &n,
                                      &present))
        return false;
    uint64_t prior = 0;
    if (present) {
        if (n != sizeof(blob))
            return false;  /* malformed floor — never overwrite, fail closed */
        for (int i = 7; i >= 0; i--)
            prior = (prior << 8) | blob[i];
    }

    if (present && value <= prior) {
        if (winner) *winner = prior;
        return true;  /* raise-only: a non-greater value is a no-op */
    }

    uint8_t out[8];
    for (int i = 0; i < 8; i++)
        out[i] = (uint8_t)((value >> (8 * i)) & 0xff);
    if (!progress_meta_set_in_tx(db, key, out, sizeof(out)))
        return false;
    if (raised) *raised = true;
    if (winner) *winner = value;
    return true;
}

/* Single-source the transaction discipline shared by progress_meta_set and
 * progress_meta_delete: lock, open a transaction, run op, commit on success /
 * roll back on failure, unlock. op binds and steps its own statement.
 *
 * Batch-aware (same proven pattern as stage.c cursor_txn_*): when a
 * transaction is already open on this connection (an outer drain batch or a
 * caller BEGIN — sqlite3_get_autocommit(db)==0), a bare BEGIN IMMEDIATE would
 * fail with "cannot start a transaction within a transaction". Nest as a named
 * SAVEPOINT instead so the op enrolls in the outer transaction and commits /
 * rolls back atomically with it. The savepoint name is distinct from
 * STAGE_CURSOR_SP so it never collides. progress_store_tx_lock is recursive, so
 * re-acquiring inside a batch is safe. This removes the latent nested-BEGIN
 * class for bare call sites (e.g. stage_repair_coin_backfill*) that were safe
 * before only by call ordering. */
#define PROGRESS_META_SP "progress_meta_write"
static void progress_meta_txn_rollback(sqlite3 *db, bool nested)
{
    if (nested) {
        sqlite3_exec(db, "ROLLBACK TO SAVEPOINT " PROGRESS_META_SP,
                     NULL, NULL, NULL);
        sqlite3_exec(db, "RELEASE SAVEPOINT " PROGRESS_META_SP, NULL, NULL, NULL);
    } else {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    }
}
static bool progress_meta_run_in_tx(sqlite3 *db,
                                    bool (*op)(sqlite3 *, void *), void *arg)
{
    if (!db) return false;
    progress_store_tx_lock();
    bool nested = sqlite3_get_autocommit(db) == 0;
    char *err = NULL;
    if (sqlite3_exec(db, nested ? "SAVEPOINT " PROGRESS_META_SP
                                : "BEGIN IMMEDIATE",
                     NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        return false;
    }
    bool ok = op(db, arg);
    if (!ok) {
        progress_meta_txn_rollback(db, nested);
        progress_store_tx_unlock();
        return false;
    }
    const char *fini = nested ? "RELEASE SAVEPOINT " PROGRESS_META_SP : "COMMIT";
    if (sqlite3_exec(db, fini, NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        /* Commit/release failed: roll the op back so we never leave a
         * half-applied write inside the outer transaction, then report it. */
        progress_meta_txn_rollback(db, nested);
        progress_store_tx_unlock();
        return false;
    }
    progress_store_tx_unlock();
    return ok;
}

struct progress_meta_set_args {
    const char *key;
    const void *value;
    size_t value_len;
};

static bool progress_meta_set_op(sqlite3 *db, void *arg)
{
    struct progress_meta_set_args *a = arg;
    return progress_meta_set_stmt(db, a->key, a->value, a->value_len);
}

static bool progress_meta_delete_op(sqlite3 *db, void *arg)
{
    return progress_meta_delete_stmt(db, (const char *)arg);
}

bool progress_meta_set(sqlite3 *db, const char *key,
                       const void *value, size_t value_len)
{
    struct progress_meta_set_args a = { key, value, value_len };
    return progress_meta_run_in_tx(db, progress_meta_set_op, &a);
}

bool progress_meta_delete(sqlite3 *db, const char *key)
{
    return progress_meta_run_in_tx(db, progress_meta_delete_op, (void *)key);
}

bool progress_meta_get(sqlite3 *db, const char *key,
                       void *out_buf, size_t out_cap,
                       size_t *out_len, bool *out_found)
{
    if (out_found) *out_found = false;
    if (out_len) *out_len = 0;
    if (!db || !key || !key[0]) return false;

    progress_store_tx_lock();
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT value FROM progress_meta WHERE key = ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        progress_store_tx_unlock();
        return false;
    }
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
    bool ok = true;
    if (rc == SQLITE_ROW) {
        if (out_found) *out_found = true;
        int n = sqlite3_column_bytes(stmt, 0);
        const void *blob = sqlite3_column_blob(stmt, 0);
        if (out_len) *out_len = (size_t)n;
        if (out_buf && out_cap > 0) {
            size_t copy = (size_t)n < out_cap ? (size_t)n : out_cap;
            if (blob && copy > 0) memcpy(out_buf, blob, copy);
        }
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(stmt);
    progress_store_tx_unlock();
    return ok;
}

bool progress_meta_get_blob_exact(sqlite3 *db, const char *key,
                                  void *out_buf, size_t out_cap,
                                  size_t *out_len, bool *out_found)
{
    if (out_found) *out_found = false;
    if (out_len) *out_len = 0;
    if (out_buf && out_cap > 0)
        memset(out_buf, 0, out_cap);
    if (!db || !key || !key[0]) return false;

    progress_store_tx_lock();
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT value FROM progress_meta WHERE key = ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        progress_store_tx_unlock();
        return false;
    }
    if (sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        progress_store_tx_unlock();
        return false;
    }

    rc = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
    bool ok = true;
    if (rc == SQLITE_ROW) {
        if (out_found) *out_found = true;
        if (sqlite3_column_type(stmt, 0) != SQLITE_BLOB) {
            ok = false;
        } else {
            int n = sqlite3_column_bytes(stmt, 0);
            const void *blob = sqlite3_column_blob(stmt, 0);
            if (n < 0 || (n > 0 && !blob) ||
                (out_buf && (size_t)n > out_cap)) {
                ok = false;
            } else if (out_buf && n > 0) {
                memcpy(out_buf, blob, (size_t)n);
            }
            if (ok && out_len) *out_len = (size_t)n;
        }
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(stmt);
    progress_store_tx_unlock();
    return ok;
}

bool progress_store_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    sqlite3 *db = progress_store_db();
    json_push_kv_bool(out, "open", db != NULL);
    /* g_display_path/g_opened_at are written under g_lock in
     * progress_store_open;
     * snapshot both under the same lock so the dump never reads a torn or
     * mid-update value. (g_lock is not held on this diagnostic path.) */
    pthread_mutex_lock(&g_lock);
    char path_snap[PROGRESS_STORE_PATH_MAX];
    snprintf(path_snap, sizeof(path_snap), "%s", g_display_path);
    int64_t opened_at_snap = g_opened_at;
    pthread_mutex_unlock(&g_lock);
    json_push_kv_str (out, "path", path_snap);
    json_push_kv_int (out, "opened_at", opened_at_snap);

    /* stage_cursor_rows: the O(1) published counter (util/stage.h), read
     * lock-free — never a blocking COUNT(*) under progress_store_tx_lock on the
     * RPC dump path. The uniform staleness label rides alongside. */
    json_push_kv_int(out, "stage_cursor_rows", stage_cursor_rows_value());
    struct json_value cursor_label;
    json_init(&cursor_label);
    json_set_object(&cursor_label);
    zcl_snapshot_emit_label(&cursor_label, stage_cursor_rows_env(),
                            /*torn=*/false, platform_time_monotonic_us());
    json_push_kv(out, "stage_cursor_rows_snapshot", &cursor_label);
    json_free(&cursor_label);
    return true;
}

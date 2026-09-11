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
#include "base/hex.h"
#include "crypto/sha3.h"
#include "storage/projection_store.h"
#include "storage/progress_store.h"
#include "progress_store_directory.h"
#ifdef _WIN32
#include "storage/sqlite_vfs_dir.h"
#endif

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
/* Sidecar that carries a corruption verdict ACROSS a restart. Written when a
 * deferred scan fails, when the live handle is already published and cannot
 * be swapped; honoured (and consumed) by the next open, where nothing holds
 * the file and the rename is safe. A SIGKILL between the two loses nothing:
 * without a receipt the next boot scans again and reaches the same verdict. */
#define PROJECTION_QUARANTINE_ARM_SUFFIX ".quarantine"
#define PROJECTION_CLEAN_RECEIPT_MAGIC "ZCLPROJCLEAN"
#define PROJECTION_CLEAN_RECEIPT_VERSION 2

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_tx_lock;
static pthread_once_t g_tx_lock_once = PTHREAD_ONCE_INIT;
static _Atomic(sqlite3 *) g_db = NULL;
static char g_path[PROJECTION_STORE_PATH_MAX];
static char g_display_path[PROJECTION_STORE_PATH_MAX];
#ifdef _WIN32
static uintptr_t g_dir_handle = UINTPTR_MAX;
static char g_vfs_name[SQLITE_VFS_DIR_NAME_MAX];
#else
static int g_dir_fd = -1;
#endif
static int64_t g_opened_at;

/* ── integrity state for this open ────────────────────────────────────
 * Three atomics, because the heartbeat/scanner threads read them while the
 * boot thread publishes them and neither may block the other.
 *   pending  — a scan was deferred and has not answered.
 *   verified — THIS file has been proven intact this run (receipt matched,
 *              synchronous gate passed, or the deferred scan said ok). It is
 *              the only thing that entitles close() to publish a receipt: a
 *              scan that never finished must never be cashed in as clean,
 *              or the deferral would silently delete the check.
 *   failed   — a scan came back with a finding; the handle is withheld. */
static _Atomic bool g_integrity_pending;
static _Atomic bool g_integrity_verified;
static _Atomic bool g_integrity_failed;
static int64_t g_integrity_started_ms;   /* under g_lock */
static projection_quick_check_defer_probe_fn g_defer_probe;

/* What this open will do about integrity, decided once. */
enum projection_integrity_plan {
    PROJECTION_INTEGRITY_SKIP = 0,  /* content-bound clean-close receipt   */
    PROJECTION_INTEGRITY_SCAN_NOW,  /* blocking quick_check, as it always was */
    PROJECTION_INTEGRITY_DEFER,     /* paced background scan after READY   */
};

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

#ifndef _WIN32
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
    char content_sha3[65];
};

static bool projection_content_digest(
    struct platform_positioned_file *file, uint64_t size, char out[65])
{
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    unsigned char chunk[4096];
    uint64_t offset = 0;
    while (offset < size) {
        size_t want = size - offset < sizeof(chunk)
            ? (size_t)(size - offset) : sizeof(chunk);
        int64_t got = platform_positioned_file_read(file, chunk, want, offset);
        if (got <= 0 || (uint64_t)got > want) {
            LOG_ERROR("projection_store", "content digest read failed at %llu",
                      (unsigned long long)offset);
            return false;
        }
        sha3_256_write(&hash, chunk, (size_t)got);
        offset += (uint64_t)got;
    }
    unsigned char digest[32];
    sha3_256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

static bool projection_file_identity_read(
    const char *path, struct projection_file_identity *out)
{
    if (!path || !out)
        return false;
    memset(out, 0, sizeof(*out));
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return false;
    if (!platform_positioned_file_snapshot(&file, &before) || before.size < 100) {
        platform_positioned_file_close(&file);
        return false;
    }
    unsigned char hdr[100];
    int64_t nr = platform_positioned_file_read(&file, hdr, sizeof(hdr), 0);
    /* Field-wise, never memcmp: the snapshot struct's alignment padding is
     * undefined, so a whole-object compare can report an unchanged file as
     * changed and reject a perfectly good projection. */
    bool stable = projection_content_digest(&file, before.size, out->content_sha3) &&
        platform_positioned_file_snapshot(&file, &after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
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
#endif

static long long projection_file_size_or_neg1(const char *path)
{
    struct platform_file_metadata metadata;
    return path && platform_file_metadata_read(path, &metadata) ==
                       PLATFORM_FILE_METADATA_OK
        ? (long long)metadata.size : -1;
}

#ifndef _WIN32
static bool projection_receipt_path(char *out, size_t out_n,
                                    const char *path)
{
    int n = snprintf(out, out_n, "%s%s", path,
                     PROJECTION_CLEAN_RECEIPT_SUFFIX);
    return n > 0 && (size_t)n < out_n;
}

/* A receipt is single-use and binds the full post-close file content. File
 * timestamps can coincide across rapid writes, so metadata alone cannot
 * qualify a clean reopen. The digest covers every page. A non-empty WAL is
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
        "version=" "2" "\n"
        "dev=%llu\nino=%llu\nsize=%lld\n"
        "mtime_sec=%lld\nmtime_nsec=%lld\n"
        "ctime_sec=%lld\nctime_nsec=%lld\n"
        "change_counter=%u\nversion_valid_for=%u\ncontent_sha3=%64[0-9a-f]\n%n",
        &want.dev, &want.ino, &want.size,
        &want.mtime_sec, &want.mtime_nsec,
        &want.ctime_sec, &want.ctime_nsec,
        &want.change_counter, &want.version_valid_for, want.content_sha3, &consumed);
    if (fields != 10 || strlen(want.content_sha3) != 64 ||
        consumed <= 0 || (size_t)consumed != nr)
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
        "change_counter=%u\nversion_valid_for=%u\ncontent_sha3=%s\n",
        PROJECTION_CLEAN_RECEIPT_VERSION,
        id.dev, id.ino, id.size,
        id.mtime_sec, id.mtime_nsec, id.ctime_sec, id.ctime_nsec,
        id.change_counter, id.version_valid_for, id.content_sha3);
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
#endif

/* <path><suffix>, or false when that does not fit or path is empty. One
 * helper for both sidecars (the clean-close receipt and the armed
 * quarantine). The empty-path refusal matters for the quarantine sidecar:
 * a verdict that arrives after projection_store_close() has cleared g_path
 * must not fall back to a bare "<suffix>" in the process CWD. */
static bool projection_sidecar_path(char *out, size_t out_n, const char *path,
                                    const char *suffix)
{
    if (out && out_n > 0)
        out[0] = '\0';
    if (out_n == 0 || !path || path[0] == '\0')
        return false;
    int n = snprintf(out, out_n, "%s%s", path, suffix);
    return n > 0 && (size_t)n < out_n;
}

void projection_store_set_quick_check_defer_probe(
    projection_quick_check_defer_probe_fn fn)
{
    /* Taken under the open/close mutex so the probe cannot change while an
     * open is deciding; the READER runs inside projection_store_open with
     * that same mutex already held, and must not re-take it. */
    pthread_mutex_lock(&g_lock);
    g_defer_probe = fn;
    pthread_mutex_unlock(&g_lock);
}

/* Decide, once per open, what to do about integrity. Call with g_lock held.
 * Consumes the clean-close receipt (single-use, on every outcome) exactly as
 * before; only the no-receipt branch is new. */
static enum projection_integrity_plan projection_integrity_plan_for(
    const char *path)
{
#ifdef _WIN32
    /* The clean receipt implementation is pathname-based, and so is the
     * armed quarantine. The projection is small enough that a full
     * quick_check is preferable to letting an observational path regain
     * authority on native Windows. */
    (void)path;
    return PROJECTION_INTEGRITY_SCAN_NOW;
#else
    if (projection_clean_receipt_consume(path))
        return PROJECTION_INTEGRITY_SKIP;
    projection_quick_check_defer_probe_fn probe = g_defer_probe;
    if (!probe || !probe(path))
        return PROJECTION_INTEGRITY_SCAN_NOW;
    return PROJECTION_INTEGRITY_DEFER;
#endif
}

/* Say what this open decided. This is the operator's only warning that a
 * boot is either about to spend an hour inside quick_check or has handed
 * that hour to the paced scanner. */
static void projection_integrity_announce(enum projection_integrity_plan plan,
                                          const char *display_path)
{
    if (plan == PROJECTION_INTEGRITY_DEFER) {
        fprintf(stderr,  // obs-ok:projection-store-lifecycle
                "[projection_store] quick_check deferred to the paced "
                "background scan (no clean-close receipt) path=%s "
                "bytes=%lld\n",
                display_path, projection_file_size_or_neg1(display_path));
        return;
    }
    fprintf(stderr,  // obs-ok:projection-store-lifecycle
            "[projection_store] quick_check start path=%s bytes=%lld\n",
            display_path, projection_file_size_or_neg1(display_path));
}

/* Publish this open's integrity state. Call with g_lock held, once the
 * handle is live. `verified` is false ONLY for a deferred scan: a scan that
 * has not answered can never be cashed in as a clean close. */
static void projection_integrity_publish(enum projection_integrity_plan plan,
                                         int64_t started_ms)
{
    g_integrity_started_ms = started_ms;
    atomic_store_explicit(&g_integrity_failed, false, memory_order_relaxed);
    atomic_store_explicit(&g_integrity_verified,
                          plan != PROJECTION_INTEGRITY_DEFER,
                          memory_order_relaxed);
    atomic_store_explicit(&g_integrity_pending,
                          plan == PROJECTION_INTEGRITY_DEFER,
                          memory_order_release);
}

/* Honour a quarantine a previous run's background scan armed. Runs before
 * anything is opened, which is the whole reason the verdict was written to
 * disk instead of acted on live: here the rename is safe. */
static void projection_quarantine_if_armed(const char *path)
{
#ifdef _WIN32
    (void)path;
#else
    char armed[PROJECTION_STORE_PATH_MAX + 24];
    if (!projection_sidecar_path(armed, sizeof(armed), path,
                                 PROJECTION_QUARANTINE_ARM_SUFFIX) ||
        access(armed, F_OK) != 0)
        return;
    fprintf(stderr,  // obs-ok:projection-store-lifecycle
            "[projection_store] armed quarantine found for %s — a background "
            "scan condemned this file; renaming it aside + re-deriving\n",
            path);
    sqlite_integrity_quarantine_corrupt(path, "projection_store",
                                        "projection_store_quarantine");
    (void)unlink(armed);
#endif
}

/* Write the quarantine sidecar durably: the verdict has to survive a SIGKILL
 * between the finding and the next open, or a corrupt file would be reopened
 * as if nothing had been found. */
static bool projection_quarantine_arm_write(const char *armed)
{
#ifdef _WIN32
    (void)armed;
    return false;
#else
    static const char body[] = "projection_store quarantine armed\n";
    (void)platform_private_file_unlink_missing_ok(armed);
    struct platform_private_file staged;
    platform_private_file_init(&staged);
    if (!platform_private_file_create(armed, &staged))
        return false;
    bool ok = platform_private_file_write_at(&staged, body, sizeof(body) - 1,
                                             0) &&
              platform_private_file_truncate(&staged, sizeof(body) - 1) &&
              platform_private_file_flush(&staged);
    platform_private_file_close(&staged);
    char resolved[PROJECTION_STORE_PATH_MAX + 24];
    char parent[PROJECTION_STORE_PATH_MAX + 24];
    if (ok && (!platform_private_path_resolve(armed, resolved,
                                              sizeof(resolved), parent,
                                              sizeof(parent)) ||
               !platform_private_parent_flush(parent)))
        ok = false;
    return ok;
#endif
}

/* The deferred scan found corruption. Reach the SAME end state as the
 * synchronous gate — the corrupt file renamed aside, a fresh one in its
 * place, projections re-derived from the kernel — with the one ordering
 * difference the live handle forces.
 *
 * `path` and `display` are a snapshot the caller took under g_lock at the
 * same time it consumed the pending flag — NOT a fresh read of g_path here.
 * Re-reading g_path in this function would reopen the exact race this
 * split is meant to close: projection_store_close() can run, and clear
 * g_path, in the gap between the caller releasing g_lock and this call. */
static void projection_integrity_condemn(const char *path,
                                         const char *display)
{
    /* Withhold the handle FIRST. The handle itself is NOT closed here: every
     * co-writer reads projection_store_db() BEFORE taking the tx lock
     * (engine/services/src/txindex_projection_service.c:207 and :232,
     * engine/services/src/address_index_service.c:192 and :314), so closing
     * it under them would be a use-after-free. A NULL handle is a state they
     * all already handle — the fold idles its tick. */
    atomic_store_explicit(&g_integrity_failed, true, memory_order_release);

    if (path[0] == '\0') {
        /* The store closed between the scan winning its exchange and this
         * call. There is no live path to quarantine beside, so refuse by
         * name instead of letting projection_sidecar_path fall back to a
         * bare suffix in the process CWD. Nothing is written. */
        fprintf(stderr,  // obs-ok:projection-store-open-failure
                "[projection_store] background integrity scan FAILED after "
                "close; verdict dropped, no quarantine written\n");
        event_emitf(EV_DB_ERROR, 0,
                    "projection_store bg quick_check failed after close "
                    "verdict_dropped=1");
        return;
    }

    char armed[PROJECTION_STORE_PATH_MAX + 24];
    bool armed_ok = projection_sidecar_path(
                        armed, sizeof(armed), path,
                        PROJECTION_QUARANTINE_ARM_SUFFIX) &&
                    projection_quarantine_arm_write(armed);

    fprintf(stderr,  // obs-ok:projection-store-open-failure
            "[projection_store] %s FAILED the background integrity scan; "
            "projection writes refused now, quarantine %s for the next "
            "start\n",
            display, armed_ok ? "armed" : "NOT armed (sidecar unwritable)");
    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=projection_store_quarantine_armed "
                "reason=bg_quick_check_failed path=%s armed=%d",
                display, armed_ok ? 1 : 0);
    event_emitf(EV_DB_ERROR, 0,
                "projection_store bg quick_check failed path=%s", display);
    event_emitf(EV_OPERATOR_NEEDED, 0,
                "condition=projection_store_corrupt "
                "detail=progress_kv_integrity");
}

bool projection_store_integrity_pending(char *out_path, size_t out_n)
{
    if (out_path && out_n > 0)
        out_path[0] = '\0';
    if (!atomic_load_explicit(&g_integrity_pending, memory_order_acquire))
        return false;
    pthread_mutex_lock(&g_lock);
    int n = (out_path && out_n > 0)
        ? snprintf(out_path, out_n, "%s", g_path) : -1;
    pthread_mutex_unlock(&g_lock);
    return n > 0 && (size_t)n < out_n;
}

void projection_store_integrity_scan_result(bool ok)
{
    char display[PROJECTION_STORE_PATH_MAX];
    char path[PROJECTION_STORE_PATH_MAX];
    display[0] = '\0';
    path[0] = '\0';

    /* Single-use: a second report (or one for a store that never deferred)
     * must not re-open a closed verdict. Consuming the flag and snapshotting
     * the path this verdict is ABOUT happen under the SAME g_lock that
     * projection_store_close() clears both under — that is what makes the
     * verdict and the close mutually exclusive. Consuming the flag first and
     * only then taking the lock (the old order) let close() run in between:
     * it would clear g_path while this function still held a stale one, and
     * the eventual quarantine write would land beside an empty path. */
    pthread_mutex_lock(&g_lock);
    if (!atomic_exchange_explicit(&g_integrity_pending, false,
                                  memory_order_acq_rel)) {
        pthread_mutex_unlock(&g_lock);
        return;
    }
    int64_t started = g_integrity_started_ms;
    snprintf(display, sizeof(display), "%s", g_display_path);
    snprintf(path, sizeof(path), "%s", g_path);
    pthread_mutex_unlock(&g_lock);

    fprintf(stderr,  // obs-ok:projection-store-lifecycle
            "[projection_store] quick_check done path=%s elapsed_ms=%lld "
            "result=%s (paced background scan)\n",
            display, (long long)(platform_time_monotonic_ms() - started),
            ok ? "ok" : "FAILED");

    if (ok) {
        atomic_store_explicit(&g_integrity_verified, true,
                              memory_order_release);
        return;
    }
    projection_integrity_condemn(path, display);
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
        bool same = progress_directory_same(g_dir_handle,
                                            opened_dir_handle);
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

    /* A verdict a previous run's background scan reached, acted on here
     * because here nothing holds the file open. No-op when nothing is
     * armed. */
    projection_quarantine_if_armed(path);

    /* CREATE: after the Wave A3 consensus.db flip the kernel handle
     * (progress_store) opens consensus.db, NOT progress.kv — so progress_store
     * no longer creates progress.kv. projection_store now OWNS progress.kv as
     * the dedicated projection file: on a fresh node it must mint it here (the
     * Class C address_index / txindex projections are fully rebuildable, so a
     * fresh or re-derived projection file is always safe; created_outputs is
     * a KERNEL table written through the consensus.db handle, not here — see
     * consensus_db.c's projection-stay exclusion list). */
    sqlite3 *db = NULL;
#ifdef _WIN32
    char opened_vfs_name[SQLITE_VFS_DIR_NAME_MAX] = {0};
    if (!sqlite_vfs_dir_register(opened_dir_handle,
                                 PROJECTION_STORE_FILENAME,
                                 opened_vfs_name)) {
        platform_private_directory_close(opened_dir_handle);
        pthread_mutex_unlock(&g_lock);
        return false;
    }
    const char *sqlite_path = PROJECTION_STORE_FILENAME;
    const char *sqlite_vfs = opened_vfs_name;
#else
    const char *sqlite_path = path;
    const char *sqlite_vfs = NULL;
#endif
    int rc = sqlite3_open_v2(sqlite_path, &db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        sqlite_vfs);
    if (rc != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:projection-store-open-failure
                "[projection_store] sqlite3_open_v2(%s) failed: %s\n",
                path, db ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
        if (db) sqlite3_close(db);
#ifdef _WIN32
        (void)sqlite_vfs_dir_unregister(opened_vfs_name);
        platform_private_directory_close(opened_dir_handle);
#else
        (void)close(opened_dir_fd);
#endif
        pthread_mutex_unlock(&g_lock);
        return false;
    }

#ifdef _WIN32
    /* Prove the connection actually opened progress.kv through the VFS bound
     * to this exact retained directory object.  Registration alone is not
     * evidence: an accidental NULL zVfs would silently restore pathname
     * authority and inherited ACLs. */
    uint64_t volume_serial = 0;
    uint64_t file_index = 0;
    uint64_t file_size = 0;
    if (!sqlite_vfs_dir_main_file_info(
            db, opened_dir_handle, PROJECTION_STORE_FILENAME,
            &volume_serial, &file_index, &file_size)) {
        fprintf(stderr,  // obs-ok:projection-store-open-failure
                "[projection_store] retained-directory main-file audit "
                "failed for %s\n", display_path);
        sqlite3_close(db);
        (void)sqlite_vfs_dir_unregister(opened_vfs_name);
        platform_private_directory_close(opened_dir_handle);
        pthread_mutex_unlock(&g_lock);
        return false;
    }
#endif

    enum projection_integrity_plan plan = projection_integrity_plan_for(path);

    /* Integrity gate. progress.kv's projection tables (address_index / txindex
     * and their state rows) are fully rebuildable, but a corrupt file
     * left in place would otherwise surface as a mid-fold SQLITE_CORRUPT deep
     * inside a projection job — a JOB_FATAL with no named blocker. On a
     * non-"ok" quick_check, quarantine the file aside and reopen a FRESH one;
     * whichever projection job runs next re-creates its schema (CREATE TABLE
     * IF NOT EXISTS) and re-derives its rows from the kernel, same as a
     * brand-new node. AUTO-TERMINATING + idempotent: a fresh, just-created
     * store that ALSO fails quick_check is a disk/fs fault, not corrupt
     * derived state — fail the open instead of quarantine-looping.
     *
     * WHERE THAT SCAN RUNS is the other half. On a boot that installed the
     * deferral probe, an existing progress.kv with no receipt does NOT hold
     * the boot thread here for the length of a multi-GB quick_check — it is
     * handed to the paced background scanner after READY (see
     * storage/projection_store.h and config/boot_fast_restart.h). The scan
     * is never skipped or shortened; only its thread changes. */
    int64_t quick_check_started = platform_time_monotonic_ms();
    if (plan == PROJECTION_INTEGRITY_SKIP) {
        fprintf(stderr,  // obs-ok:projection-store-lifecycle
                "[projection_store] quick_check skipped "
                "(content-bound clean-close receipt) path=%s\n", display_path);
    } else {
        projection_integrity_announce(plan, display_path);
    }
    if (plan == PROJECTION_INTEGRITY_SCAN_NOW &&
        !sqlite_integrity_quick_check_ok(db, "projection_store")) {
#ifdef _WIN32
        fprintf(stderr,  // obs-ok:projection-store-open-failure
                "[projection_store] %s failed integrity quick_check; native "
                "Windows retained-directory quarantine is unavailable, "
                "refusing without mutation\n", display_path);
        sqlite3_close(db);
        (void)sqlite_vfs_dir_unregister(opened_vfs_name);
        platform_private_directory_close(opened_dir_handle);
        pthread_mutex_unlock(&g_lock);
        return false;
#else
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
#endif
    }
    if (plan == PROJECTION_INTEGRITY_SCAN_NOW) {
        fprintf(stderr,  // obs-ok:projection-store-lifecycle
                "[projection_store] quick_check done path=%s elapsed_ms=%lld\n",
                display_path,
                (long long)(platform_time_monotonic_ms() - quick_check_started));
    }

    if (!apply_pragmas(db)) {
        sqlite3_close(db);
#ifdef _WIN32
        (void)sqlite_vfs_dir_unregister(opened_vfs_name);
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
    snprintf(g_vfs_name, sizeof(g_vfs_name), "%s", opened_vfs_name);
#else
    g_dir_fd = opened_dir_fd;
#endif
    g_opened_at = wall_now_s();
    projection_integrity_publish(plan, quick_check_started);
    atomic_store_explicit(&g_db, db, memory_order_release);

    pthread_mutex_unlock(&g_lock);

    fprintf(stderr,  // obs-ok:projection-store-lifecycle
            "[projection_store] opened %s (WAL, secondary handle)\n",
            display_path);
    return true;
}

sqlite3 *projection_store_db(void)
{
    /* A condemned store hands out nothing. Refusing the handle is what makes
     * the deferred scan's finding as strong as the synchronous gate's: no
     * further row is written into a file the node has already decided to
     * quarantine, and every co-writer already idles on a NULL handle. */
    if (atomic_load_explicit(&g_integrity_failed, memory_order_acquire))
        return NULL;
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

#ifdef ZCL_TESTING
static _Atomic bool g_force_checkpoint_busy;

void projection_store_force_checkpoint_busy_for_test(void)
{
    atomic_store_explicit(&g_force_checkpoint_busy, true,
                          memory_order_release);
}
#endif

/* Drain the WAL back into the main file at close.
 *
 * TRUNCATE is what a close wants: it copies every frame back AND zeroes the
 * WAL, which is what lets the NEXT open see an absent WAL and take the fast
 * receipt path instead of a full quick_check. But TRUNCATE needs the
 * exclusive lock, so any live reader makes it SQLITE_BUSY — and this store
 * now has one more reader than it used to, the background integrity scan's
 * read-only handle.
 *
 * A reader-blocked TRUNCATE says "somebody is reading". It says nothing
 * about the bytes, and treating it as a dirty close cost the next boot a
 * full multi-GB scan for no reason at all. So fall back to PASSIVE, which
 * copies the frames back without the exclusive lock, and let the two things
 * that DO speak about the bytes decide: sqlite3_close() (which checkpoints
 * and removes the WAL when it is the last connection) and the receipt
 * writer's own WAL-absent + full-content-digest checks. A receipt is still
 * never written after a failed close. */
static int projection_checkpoint_for_close(sqlite3 *db, int *log_frames,
                                           int *checkpointed_frames)
{
    int rc = sqlite3_wal_checkpoint_v2(db, NULL, SQLITE_CHECKPOINT_TRUNCATE,
                                       log_frames, checkpointed_frames);
#ifdef ZCL_TESTING
    if (atomic_exchange_explicit(&g_force_checkpoint_busy, false,
                                 memory_order_acq_rel))
        rc = SQLITE_BUSY;
#endif
    if (rc != SQLITE_BUSY)
        return rc;
    fprintf(stderr,  // obs-ok:projection-store-lifecycle
            "[projection_store] TRUNCATE checkpoint is reader-blocked; "
            "draining the WAL with PASSIVE instead\n");
    return sqlite3_wal_checkpoint_v2(db, NULL, SQLITE_CHECKPOINT_PASSIVE,
                                     log_frames, checkpointed_frames);
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
    int checkpoint_rc = projection_checkpoint_for_close(
        db, &log_frames, &checkpointed_frames);
    int rc = sqlite3_close(db);
    if (rc != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:projection-store-lifecycle
                "[projection_store] sqlite3_close: rc=%d (%s)\n",
                rc, sqlite3_errstr(rc));
    } else {
        fprintf(stderr,  // obs-ok:projection-store-lifecycle
                "[projection_store] closed %s\n", g_display_path);
    }

    /* A receipt is a claim that THIS file was proven intact this run. A
     * deferred scan that never answered, and one that answered with a
     * finding, both refuse it — otherwise moving the scan off the boot
     * thread would quietly delete the check on the next boot instead of
     * rescheduling it. */
    bool integrity_clean =
        atomic_load_explicit(&g_integrity_verified, memory_order_acquire) &&
        !atomic_load_explicit(&g_integrity_failed, memory_order_acquire);
    if (rc == SQLITE_OK && integrity_clean) {
#ifdef _WIN32
        /* No pathname receipt on Windows; see the open-side authority note. */
#else
        /* Private publication requires the retained absolute capability path;
         * g_display_path may be relative and is observational only. */
        if (!projection_clean_receipt_write(g_path))
            fprintf(stderr,  // obs-ok:projection-store-lifecycle
                    "[projection_store] clean-close receipt unavailable; "
                    "next boot will run full quick_check path=%s\n",
                    g_display_path);
#endif
    } else {
#ifndef _WIN32
        char receipt[PROJECTION_STORE_PATH_MAX + 16];
        if (projection_receipt_path(receipt, sizeof(receipt), g_path))
            (void)unlink(receipt);
#endif
        fprintf(stderr,  // obs-ok:projection-store-lifecycle
                "[projection_store] dirty close checkpoint_rc=%d close_rc=%d "
                "log_frames=%d checkpointed_frames=%d integrity_clean=%d; "
                "no receipt\n",
                checkpoint_rc, rc, log_frames, checkpointed_frames,
                integrity_clean ? 1 : 0);
    }

#ifdef _WIN32
    if (g_vfs_name[0] != '\0') {
        (void)sqlite_vfs_dir_unregister(g_vfs_name);
        g_vfs_name[0] = '\0';
    }
    if (g_dir_handle != UINTPTR_MAX)
        platform_private_directory_close(g_dir_handle);
    g_dir_handle = UINTPTR_MAX;
#else
    if (g_dir_fd >= 0)
        (void)close(g_dir_fd);
    g_dir_fd = -1;
#endif
    g_path[0] = '\0';
    g_display_path[0] = '\0';
    g_opened_at = 0;
    g_integrity_started_ms = 0;
    atomic_store_explicit(&g_integrity_pending, false, memory_order_relaxed);
    atomic_store_explicit(&g_integrity_verified, false, memory_order_relaxed);
    atomic_store_explicit(&g_integrity_failed, false, memory_order_release);
    projection_store_tx_unlock();
    pthread_mutex_unlock(&g_lock);
}


/* ── size bound ───────────────────────────────────────────────────────
 *
 * progress.kv reached 2,874 MB on a field box while a sibling box at the
 * same chain height held 1 MB, and nothing in this file ever looked at
 * either number. The store had no compaction of any kind: no auto_vacuum,
 * no incremental_vacuum, no VACUUM, and no measurement. The Class C
 * projections it holds (address_index, txindex and their state rows) are
 * rewritten and deleted from constantly — every rollback, every reorg, every
 * re-derivation — and in an ordinary SQLite database a deleted page is
 * returned to the FREELIST inside the file, never to the filesystem. So the
 * file only ever tracked the high-water mark of everything the node had ever
 * indexed, and on a spinning disk that is 2.9 GB of seek surface under every
 * projection read for the rest of the node's life.
 *
 * The measurement is exact and costs two pragmas: page_count is the whole
 * file in pages, freelist_count is the part of it that holds nothing.
 *
 * The bound is a floor AND a ratio, and both are needed. A ratio alone would
 * compact a 4 MB store forever, because a small store is nearly always some
 * multiple of its live set. A floor alone would compact a store that is
 * legitimately large and dense, paying a full rewrite for nothing. Together
 * they say the only thing worth acting on: this file is big, and most of it
 * is empty.
 */

/* One pragma that returns a single integer. -1 when it cannot be read, so a
 * failed measurement can never be mistaken for "zero free pages". */
static int64_t projection_pragma_i64(sqlite3 *db, const char *pragma)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, pragma, -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    int64_t value = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW)  // raw-sql-ok:projection-store-primitive
        value = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return value;
}

bool projection_store_usage(struct projection_store_usage *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    out->file_bytes = -1;
    out->live_bytes = -1;
    out->free_bytes = -1;

    sqlite3 *db = projection_store_db();
    if (!db)
        return false;

    projection_store_tx_lock();
    int64_t page_size = projection_pragma_i64(db, "PRAGMA page_size");
    int64_t page_count = projection_pragma_i64(db, "PRAGMA page_count");
    int64_t freelist = projection_pragma_i64(db, "PRAGMA freelist_count");
    projection_store_tx_unlock();

    if (page_size <= 0 || page_count < 0 || freelist < 0)
        return false;
    if (freelist > page_count)
        freelist = page_count;  /* defensive: never report negative live bytes */

    out->page_size = page_size;
    out->page_count = page_count;
    out->free_pages = freelist;
    out->file_bytes = page_count * page_size;
    out->free_bytes = freelist * page_size;
    out->live_bytes = out->file_bytes - out->free_bytes;
    return true;
}

bool projection_store_over_bound(const struct projection_store_usage *usage,
                                 int64_t floor_bytes, int ratio_pct)
{
    if (!usage || usage->file_bytes < 0 || usage->live_bytes < 0)
        return false;
    if (floor_bytes <= 0 || ratio_pct <= 100)
        return false;
    if (usage->file_bytes <= floor_bytes)
        return false;
    /* A store whose live set is genuinely zero (a fresh datadir with no
     * projections enabled) is over ANY ratio, so the floor above is what
     * keeps this from firing on a 4 MB file. Above the floor, an empty live
     * set is exactly the case worth compacting. */
    if (usage->live_bytes == 0)
        return true;
    /* Integer arithmetic, in bytes, with the ratio applied to the live side:
     * file * 100 > live * ratio. Both sides fit comfortably in int64 for any
     * file a filesystem can hold. */
    return usage->file_bytes * 100 > usage->live_bytes * (int64_t)ratio_pct;
}

bool projection_store_compact_if_needed(int64_t floor_bytes, int ratio_pct,
                                        struct projection_store_usage *before,
                                        struct projection_store_usage *after)
{
    struct projection_store_usage usage;
    if (!projection_store_usage(&usage))
        return false;
    if (before)
        *before = usage;
    if (after)
        *after = usage;
    if (!projection_store_over_bound(&usage, floor_bytes, ratio_pct))
        return false;

    sqlite3 *db = projection_store_db();
    if (!db)
        return false;

    int64_t started = platform_time_monotonic_ms();
    projection_store_tx_lock();
    char *err = NULL;
    /* VACUUM, not incremental_vacuum: this store was created without
     * auto_vacuum, so it has no pointer-map pages and incremental_vacuum is
     * a documented no-op on it. VACUUM rebuilds the file, which is why it
     * only ever runs behind the floor+ratio gate above and behind the
     * storage-pacing maintenance token — never on every tick, and never
     * beside another maintenance writer on a spinning disk. */
    int rc = sqlite3_exec(db, "VACUUM", NULL, NULL, &err);  // raw-sql-ok:projection-store-primitive
    projection_store_tx_unlock();

    if (rc != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:projection-store-lifecycle
                "[projection_store] compaction failed rc=%d (%s)\n", rc,
                err ? err : sqlite3_errstr(rc));
        if (err)
            sqlite3_free(err);
        return false;
    }
    if (err)
        sqlite3_free(err);

    struct projection_store_usage post;
    if (projection_store_usage(&post) && after)
        *after = post;

    fprintf(stderr,  // obs-ok:projection-store-lifecycle
            "[projection_store] compacted %s: %lld -> %lld bytes "
            "(live %lld, bound %lld/%d%%) in %lld ms\n",
            g_display_path, (long long)usage.file_bytes,
            (long long)(after ? after->file_bytes : post.file_bytes),
            (long long)usage.live_bytes, (long long)floor_bytes, ratio_pct,
            (long long)(platform_time_monotonic_ms() - started));
    return true;
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

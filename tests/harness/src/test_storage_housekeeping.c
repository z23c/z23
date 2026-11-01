/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Registered test group for the storage housekeeping service
 * (engine/services/src/storage_housekeeping.c) — the one periodic writer
 * that keeps a datadir bounded: progress.kv compaction, topology.db WAL
 * truncation, and Tor log rotation, paced by util/storage_pacing.h.
 *
 * The service is built so its whole behaviour is one synchronous function
 * (storage_housekeeping_sweep) that the background thread only calls on a
 * timer, so every bound is tested WITHOUT starting a thread or sleeping for
 * a tick. The pacing organ's test seams pin the solid-state class (no
 * maintenance-gap waits) and its documented environment overrides shrink
 * every bound to 1 MiB, so each bound is crossed with kilobyte-scale
 * fixtures rather than the real 128-256 MiB compiled-in defaults.
 *
 * Coverage:
 *   - start/stop round trip on an empty datadir (boot sweep runs, stop
 *     joins, second stop is a safe no-op)
 *   - start refuses a NULL, empty, or absent datadir with a named
 *     zcl_result — a sweeper with nothing to bound is a misconfiguration
 *   - storage_housekeeping_register_service() registers an OPTIONAL
 *     service whose start/stop wrappers call through to the singleton
 *   - one sweep performs each bound when the inputs cross it: an
 *     oversized fake tor.log is rotated, an over-bound topology.db WAL is
 *     truncated, and an over-bound progress.kv is compacted
 *   - a sweep with every input under its bound changes nothing
 *   - stop() while a tick's work is due returns (a deadlock here hangs the
 *     group and the runner's watchdog fails the run; no clock-graded
 *     assertion is used — see tools/lint/lintc/gate_no_wallclock_assertion.c)
 */

#include "test/test_core.h"

#include "kernel/service_kernel.h"
#include "net/netaddr.h"
#include "net/tor_integration.h"
#include "platform/time_compat.h"
#include "services/storage_housekeeping.h"
#include "storage/projection_store.h"
#include "storage/topology_store.h"
#include "util/storage_pacing.h"

#include "test/setup_result.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SHK_CHECK(name, expr) do { \
    printf("storage_housekeeping: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

#define SHK_CHECK_RESULT(name, r) do { \
    printf("storage_housekeeping: %s... ", (name)); \
    if ((r).ok) printf("OK\n"); \
    else { printf("FAIL (%d: %s)\n", (r).code, (r).message); failures++; } \
} while (0)

#define SHK_CHECK_REFUSED(name, r) do { \
    printf("storage_housekeeping: %s... ", (name)); \
    if (!(r).ok && (r).code != 0 && (r).message[0]) \
        printf("OK (refused: %s)\n", (r).message); \
    else { printf("FAIL (expected a named refusal)\n"); failures++; } \
} while (0)

/* ── fixture helpers ───────────────────────────────────────────────── */

/* Shrink every bound to 1 MiB and pin the solid-state class, whose
 * maintenance token does not serialize (so a sweep never waits out a gap).
 * The overrides are the pacing organ's own documented test/operator seam. */
static void shk_small_bounds(void)
{
    setenv("ZCL_LOG_ROTATE_MB", "1", 1);
    setenv("ZCL_WAL_TRUNCATE_MB", "1", 1);
    setenv("ZCL_COMPACT_FLOOR_MB", "1", 1);
    storage_pacing_force_class_for_testing(PLATFORM_STORAGE_CLASS_SOLID);
}

static void shk_restore_pacing(void)
{
    unsetenv("ZCL_LOG_ROTATE_MB");
    unsetenv("ZCL_WAL_TRUNCATE_MB");
    unsetenv("ZCL_COMPACT_FLOOR_MB");
    storage_pacing_reset_for_testing();
}

static int64_t shk_file_size(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return -1;
    return (int64_t)st.st_size;
}

/* Write `bytes` of filler without allocating: a fixed 4 KiB stack chunk. */
static bool shk_write_file(const char *path, int64_t bytes)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    char chunk[4096];
    memset(chunk, 'x', sizeof(chunk));
    while (bytes > 0) {
        size_t want = bytes > (int64_t)sizeof(chunk) ? sizeof(chunk)
                                                     : (size_t)bytes;
        if (fwrite(chunk, 1, want, f) != want) {
            fclose(f);
            return false;
        }
        bytes -= (int64_t)want;
    }
    fclose(f);
    return true;
}

static struct net_addr shk_ipv4(unsigned char a, unsigned char b,
                                unsigned char c, unsigned char d)
{
    struct net_addr addr;
    net_addr_init(&addr);
    unsigned char ip4[4] = { a, b, c, d };
    net_addr_set_ipv4(&addr, ip4);
    return addr;
}

/* One sweep of work, asserted from the outside: write an oversized fake
 * tor.log into `datadir`. Returns the log path by out-parameter. */
static bool shk_oversized_tor_log(const char *datadir, int64_t bound,
                                  char *path_out, size_t path_n)
{
    if (!tor_log_path(datadir, path_out, path_n))
        return false;
    return shk_write_file(path_out, bound + 4096);
}

/* Poll (bounded count, never graded on elapsed time) until the sweep counter
 * reaches `want`. */
static bool shk_wait_sweeps(int64_t want)
{
    for (int i = 0; i < 500; i++) {
        struct storage_housekeeping_stats s;
        storage_housekeeping_stats(&s);
        if (s.sweeps >= want)
            return true;
        platform_sleep_ms(20);
    }
    return false;
}

/* Sweeps that ran to their end, whatever the outcome (completed, failed or
 * skipped). An interrupted sweep never counts. */
static int64_t shk_finished(const struct storage_housekeeping_stats *s)
{
    return s->sweeps_completed + s->sweeps_failed + s->sweeps_skipped;
}

static bool shk_wait_finished(int64_t want)
{
    for (int i = 0; i < 500; i++) {
        struct storage_housekeeping_stats s;
        storage_housekeeping_stats(&s);
        if (shk_finished(&s) >= want)
            return true;
        platform_sleep_ms(20);
    }
    return false;
}

/* ── 1b. the boot service start must not wait on a held storage lock ── */
struct shk_boot_start_ctx {
    struct zcl_service_kernel kernel;
    atomic_bool start_returned;
};

static void *shk_boot_start_thread(void *arg)
{
    struct shk_boot_start_ctx *c = arg;
    (void)zcl_service_kernel_start_all(&c->kernel);
    atomic_store(&c->start_returned, true);
    return NULL;
}

/* The maintenance token is held by this thread, as a long writer would hold
 * it. The registered boot service's start must still return (its first sweep
 * is deferred to the service thread); the sweep itself only completes once
 * the token is released. Red when start runs its first sweep inline: start
 * then blocks on the token and never returns inside the poll budget. */
static int shk_case_boot_start_not_blocked_by_held_lock(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "storage_housekeeping", "bootstart");
    storage_pacing_force_class_for_testing(PLATFORM_STORAGE_CLASS_ROTATIONAL);

    struct shk_boot_start_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    atomic_init(&ctx.start_returned, false);
    zcl_service_kernel_init(&ctx.kernel);
    SHK_CHECK("boot start: service registered",
              storage_housekeeping_register_service(&ctx.kernel, dir));

    struct storage_housekeeping_stats before;
    storage_housekeeping_stats(&before);
    SHK_CHECK("boot start: token taken", storage_pacing_maintenance_begin());

    pthread_t th;
    int rc = pthread_create(&th, NULL, shk_boot_start_thread, &ctx);
    SHK_CHECK("boot start: launcher thread spawned", rc == 0);
    if (rc != 0) {
        storage_pacing_maintenance_end();
        storage_pacing_force_class_for_testing(PLATFORM_STORAGE_CLASS_SOLID);
        test_cleanup_tmpdir(dir);
        return failures;
    }
    bool returned = false;
    for (int i = 0; i < 250 && !returned; i++) {
        returned = atomic_load(&ctx.start_returned);
        if (!returned)
            platform_sleep_ms(20);
    }
    SHK_CHECK("boot start returns while the maintenance token is held",
              returned);

    storage_pacing_maintenance_end();
    pthread_join(th, NULL);
    SHK_CHECK("the deferred boot sweep completes once the token is free",
              shk_wait_finished(shk_finished(&before) + 1));

    zcl_service_kernel_stop_all(&ctx.kernel);
    storage_pacing_force_class_for_testing(PLATFORM_STORAGE_CLASS_SOLID);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 1c. stop must end a first sweep that is blocked on the token ── */
static void *shk_stop_thread(void *arg)
{
    atomic_bool *done = arg;
    storage_housekeeping_stop();
    atomic_store(done, true);
    return NULL;
}

/* The token is held by this thread for the whole case, so the deferred first
 * sweep sits waiting for it. storage_housekeeping_stop() must still return
 * (the join cannot wait out a token held for minutes at boot). Red with the
 * plain blocking begin(): stop never returns while the token is held. */
static int shk_case_stop_ends_sweep_blocked_on_token(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "storage_housekeeping", "stopblocked");
    storage_pacing_force_class_for_testing(PLATFORM_STORAGE_CLASS_ROTATIONAL);

    struct storage_housekeeping_stats before;
    storage_housekeeping_stats(&before);
    SHK_CHECK("stop blocked: token taken", storage_pacing_maintenance_begin());
    struct zcl_result r = storage_housekeeping_start_deferred(dir);
    SHK_CHECK("stop blocked: deferred start ok", r.ok);
    SHK_CHECK("stop blocked: first sweep entered",
              shk_wait_sweeps(before.sweeps + 1));

    atomic_bool done;
    atomic_init(&done, false);
    pthread_t th;
    int rc = pthread_create(&th, NULL, shk_stop_thread, &done);
    SHK_CHECK("stop blocked: stopper thread spawned", rc == 0);
    if (rc != 0) {
        storage_pacing_maintenance_end();
        storage_housekeeping_stop();
        storage_pacing_force_class_for_testing(PLATFORM_STORAGE_CLASS_SOLID);
        test_cleanup_tmpdir(dir);
        return failures;
    }
    bool stopped = false;
    for (int i = 0; i < 250 && !stopped; i++) {
        stopped = atomic_load(&done);
        if (!stopped)
            platform_sleep_ms(20);
    }
    SHK_CHECK("stop returns while the first sweep waits on the token",
              stopped);

    storage_pacing_maintenance_end();
    pthread_join(th, NULL);

    struct storage_housekeeping_stats mid;
    storage_housekeeping_stats(&mid);
    SHK_CHECK("the abandoned first sweep is counted as interrupted",
              mid.sweeps_interrupted == before.sweeps_interrupted + 1);
    SHK_CHECK("the abandoned first sweep is not counted as completed",
              mid.sweeps_completed == before.sweeps_completed);

    /* A normal sweep still completes, and stays uncancelable although the
     * stop request is still latched (only the service thread honours it). */
    SHK_CHECK("direct sweep fixture: topology store opens",
              topology_store_open(dir));
    struct net_addr edge = shk_ipv4(66, 70, 182, 9);
    SHK_CHECK("direct sweep fixture: an edge gives the WAL a file",
              topology_store_record_self_edge(&edge, 8233, 1, NULL));
    SHK_CHECK("direct sweep fixture: projection store opens",
              projection_store_open(dir));
    storage_housekeeping_sweep(dir);
    struct storage_housekeeping_stats after;
    storage_housekeeping_stats(&after);
    SHK_CHECK("a direct sweep counts as completed",
              after.sweeps_completed == mid.sweeps_completed + 1);
    SHK_CHECK("a direct sweep is not counted as interrupted",
              after.sweeps_interrupted == mid.sweeps_interrupted);

    /* A sweep whose log step has no datadir skipped a bound: it is counted
     * as skipped, never as completed. */
    storage_housekeeping_sweep(NULL);
    struct storage_housekeeping_stats last;
    storage_housekeeping_stats(&last);
    SHK_CHECK("a sweep with a skipped log step is counted as skipped",
              last.sweeps_skipped == after.sweeps_skipped + 1);
    SHK_CHECK("a sweep with a skipped log step is not counted as completed",
              last.sweeps_completed == after.sweeps_completed);
    SHK_CHECK("a sweep with a skipped log step is not counted as interrupted",
              last.sweeps_interrupted == after.sweeps_interrupted);
    topology_store_close();
    projection_store_close();
    storage_pacing_force_class_for_testing(PLATFORM_STORAGE_CLASS_SOLID);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 1. start/stop round trip on an empty datadir ── */
static int shk_case_start_stop_round_trip(void)
{
    int failures = 0;
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "storage_housekeeping", "empty");

        struct storage_housekeeping_stats before, after;
        storage_housekeeping_stats(&before);

        struct zcl_result r = storage_housekeeping_start(dir);
        SHK_CHECK_RESULT("start succeeds on an empty datadir", r);

        storage_housekeeping_stats(&after);
        SHK_CHECK("the synchronous boot sweep ran",
                  after.sweeps >= before.sweeps + 1);
        SHK_CHECK("an unmeasured projection reports unavailable byte counts",
                  after.projection_file_bytes == -1 &&
                  after.projection_live_bytes == -1);

        storage_housekeeping_stop();
        SHK_CHECK("stop joins and returns on an empty datadir", true);
        storage_housekeeping_stop(); /* safe no-op, like db_maintenance */
        SHK_CHECK("second stop is a safe no-op", true);

        test_cleanup_tmpdir(dir);
    }

    return failures;
}

/* ── 2. start refuses NULL/empty/absent datadirs by name ── */
static int shk_case_start_refuses_bad_datadirs(void)
{
    int failures = 0;
    {
        struct zcl_result rnull = storage_housekeeping_start(NULL);
        SHK_CHECK_REFUSED("start refuses a NULL datadir", rnull);

        struct zcl_result rempty = storage_housekeeping_start("");
        SHK_CHECK_REFUSED("start refuses an empty datadir", rempty);

        char absent[256];
        test_fmt_tmpdir(absent, sizeof(absent), "storage_housekeeping",
                        "absent");
        struct zcl_result rmiss = storage_housekeeping_start(absent);
        SHK_CHECK_REFUSED("start refuses a datadir that does not exist",
                          rmiss);
    }

    return failures;
}

/* ── 3. service registration: OPTIONAL, wrappers call through ── */
static int shk_case_service_registration(void)
{
    int failures = 0;
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "storage_housekeeping", "kernel");

        struct zcl_service_kernel kernel;
        zcl_service_kernel_init(&kernel);
        SHK_CHECK("register_service returns true",
                  storage_housekeeping_register_service(&kernel, dir));

        const struct zcl_service_entry *entry =
            zcl_service_kernel_find(&kernel, "storage_housekeeping");
        SHK_CHECK("the service is findable by name", entry != NULL);
        SHK_CHECK("the service is OPTIONAL",
                  entry && (entry->spec.flags & ZCL_SERVICE_OPTIONAL));
        SHK_CHECK("start/stop wrappers are installed",
                  entry && entry->spec.start && entry->spec.stop);
        SHK_CHECK("a registered service starts in REGISTERED",
                  entry && entry->state == ZCL_SERVICE_REGISTERED);

        struct storage_housekeeping_stats before, after;
        storage_housekeeping_stats(&before);

        SHK_CHECK("start_all returns true",
                  zcl_service_kernel_start_all(&kernel));
        entry = zcl_service_kernel_find(&kernel, "storage_housekeeping");
        SHK_CHECK("entry is STARTED after start_all",
                  entry && entry->state == ZCL_SERVICE_STARTED);
        /* The boot start is deferred: the sweep runs on the service's own
         * thread, so wait (bounded by a poll count, not a clock) for it. */
        SHK_CHECK("the start wrapper called through (boot sweep ran)",
                  shk_wait_finished(shk_finished(&before) + 1));
        storage_housekeeping_stats(&after);

        zcl_service_kernel_stop_all(&kernel);
        entry = zcl_service_kernel_find(&kernel, "storage_housekeeping");
        SHK_CHECK("entry is STOPPED after stop_all",
                  entry && entry->state == ZCL_SERVICE_STOPPED);

        /* The stop wrapper must have stopped the real singleton: a direct
         * start now succeeds (it would refuse -1 if the thread lived). */
        struct zcl_result direct = storage_housekeeping_start(dir);
        SHK_CHECK_RESULT("direct restart after stop_all proves the "
                         "singleton stopped", direct);
        storage_housekeeping_stop();

        /* The OPTIONAL contract: a start failure is named on the entry and
         * does not fail start_all. */
        struct zcl_service_kernel bad_kernel;
        zcl_service_kernel_init(&bad_kernel);
        char absent[256];
        test_fmt_tmpdir(absent, sizeof(absent), "storage_housekeeping",
                        "kernel_absent");
        SHK_CHECK("register with an absent datadir still returns true",
                  storage_housekeeping_register_service(&bad_kernel, absent));
        SHK_CHECK("start_all tolerates the optional failure",
                  zcl_service_kernel_start_all(&bad_kernel));
        const struct zcl_service_entry *bad =
            zcl_service_kernel_find(&bad_kernel, "storage_housekeeping");
        SHK_CHECK("the failed optional entry is FAILED with a reason",
                  bad && bad->state == ZCL_SERVICE_FAILED &&
                  bad->failure_reason != NULL);

        test_cleanup_tmpdir(dir);
    }

    return failures;
}

/* ── 4. one sweep performs each bound when crossed ── */
struct shk_sweep_bound_ctx {
    char dir[256];
    int64_t wal_before;
    struct projection_store_usage usage;
    char log_path[512];
    char log_prev[520];
    int64_t log_before;
};

/* topology.db WAL over its bound: feed real edges through the store's own
 * API until the WAL file crosses the pacing bound. */
static int shk_drive_wal_over_bound(struct shk_sweep_bound_ctx *ctx,
                                    const struct storage_pacing *pacing)
{
    int failures = 0;
    SHK_CHECK("topology_store opens in the fixture datadir",
              topology_store_open(ctx->dir));
    int n = 0;
    while (topology_store_wal_bytes() <= pacing->wal_truncate_bytes &&
          n < 60000) {
        struct net_addr advertised =
            shk_ipv4(66, (unsigned char)((n >> 8) & 0xff),
                     (unsigned char)(n & 0xff), 7);
        if (!topology_store_record_self_edge(&advertised, 8233, n + 1, NULL))
            break;
        n++;
    }
    SHK_CHECK("fixture drove the WAL over its bound",
              topology_store_wal_bytes() > pacing->wal_truncate_bytes);
    ctx->wal_before = topology_store_wal_bytes();
    return failures;
}

/* progress.kv over floor AND ratio: 3 MiB of committed junk, all of it then
 * deleted, so the file keeps the high-water mark while the live set
 * collapses. */
static int shk_drive_progress_kv_over_bound(struct shk_sweep_bound_ctx *ctx,
                                            const struct storage_pacing *pacing)
{
    int failures = 0;
    SHK_CHECK("projection_store opens in the fixture datadir",
              projection_store_open(ctx->dir));
    sqlite3 *proj = projection_store_db();
    SHK_CHECK("projection handle is available", proj != NULL);
    if (proj) {
        projection_store_tx_lock();
        int rc = sqlite3_exec(proj,
                              "CREATE TABLE IF NOT EXISTS shk_junk("
                              "k INTEGER PRIMARY KEY, b BLOB)",
                              NULL, NULL, NULL);
        if (rc == SQLITE_OK)
            rc = sqlite3_exec(proj, "BEGIN", NULL, NULL, NULL);
        for (int k = 0; rc == SQLITE_OK && k < 192; k++) {
            char sql[128];
            snprintf(sql, sizeof(sql),
                     "INSERT INTO shk_junk(k, b) "
                     "VALUES(%d, zeroblob(16384))", k);
            rc = sqlite3_exec(proj, sql, NULL, NULL, NULL);
        }
        if (rc == SQLITE_OK)
            rc = sqlite3_exec(proj, "COMMIT", NULL, NULL, NULL);
        /* Land the committed junk in the main file so the bound sees
         * the file itself, not the WAL. */
        if (sqlite3_exec(proj, "PRAGMA wal_checkpoint(TRUNCATE)",
                         NULL, NULL, NULL) != SQLITE_OK)
            rc = SQLITE_BUSY;
        if (rc == SQLITE_OK)
            rc = sqlite3_exec(proj, "DELETE FROM shk_junk", NULL, NULL, NULL);
        projection_store_tx_unlock();
        SHK_CHECK("projection junk fixture built and deleted", rc == SQLITE_OK);
    }
    char kv_path[512];
    snprintf(kv_path, sizeof(kv_path), "%s/progress.kv", ctx->dir);
    int64_t kv_before = shk_file_size(kv_path);
    SHK_CHECK("progress.kv crossed the compaction floor",
              kv_before > pacing->compact_floor_bytes);
    SHK_CHECK("the over-bound predicate fires on the fixture",
              projection_store_usage(&ctx->usage) &&
              projection_store_over_bound(&ctx->usage,
                                          pacing->compact_floor_bytes,
                                          pacing->compact_ratio_pct));
    return failures;
}

/* tor.log over its bound. */
static int shk_drive_tor_log_over_bound(struct shk_sweep_bound_ctx *ctx,
                                        const struct storage_pacing *pacing)
{
    int failures = 0;
    SHK_CHECK("oversized fake tor.log written",
              shk_oversized_tor_log(ctx->dir, pacing->log_rotate_bytes,
                                    ctx->log_path, sizeof(ctx->log_path)));
    snprintf(ctx->log_prev, sizeof(ctx->log_prev), "%s.1", ctx->log_path);
    ctx->log_before = shk_file_size(ctx->log_path);
    return failures;
}

/* The tick under test, plus every postcondition it must satisfy. */
static int shk_sweep_tick_and_verify(struct shk_sweep_bound_ctx *ctx,
                                     const struct storage_pacing *pacing)
{
    int failures = 0;
    struct storage_housekeeping_stats before, after;
    storage_housekeeping_stats(&before);
    storage_housekeeping_sweep(ctx->dir);
    storage_housekeeping_stats(&after);

    SHK_CHECK("sweep counted exactly one sweep",
              after.sweeps == before.sweeps + 1);
    SHK_CHECK("oversized tor.log rotated",
              after.log_rotations == before.log_rotations + 1 &&
              shk_file_size(ctx->log_path) == 0 &&
              shk_file_size(ctx->log_prev) == ctx->log_before);
    SHK_CHECK("over-bound topology WAL truncated",
              after.topology_checkpoints == before.topology_checkpoints + 1 &&
              topology_store_wal_bytes() < ctx->wal_before &&
              topology_store_wal_bytes() <= pacing->wal_truncate_bytes);
    /* VACUUM shrinks the store's LOGICAL size (page_count, what the
     * bound measures and what ls shows once the WAL checkpoints back);
     * the physical file only catches up at the next checkpoint, so the
     * postcondition is read through the service's own measure. */
    struct projection_store_usage compacted_usage;
    SHK_CHECK("over-bound progress.kv compacted",
              after.projection_compactions == before.projection_compactions + 1 &&
              projection_store_usage(&compacted_usage) &&
              compacted_usage.file_bytes < ctx->usage.file_bytes &&
              compacted_usage.file_bytes <= pacing->compact_floor_bytes);
    return failures;
}

static int shk_case_sweep_performs_each_bound(const struct storage_pacing *pacing)
{
    struct shk_sweep_bound_ctx ctx = {0};
    test_make_tmpdir(ctx.dir, sizeof(ctx.dir), "storage_housekeeping", "over");

    int failures = shk_drive_wal_over_bound(&ctx, pacing);
    failures += shk_drive_progress_kv_over_bound(&ctx, pacing);
    failures += shk_drive_tor_log_over_bound(&ctx, pacing);
    failures += shk_sweep_tick_and_verify(&ctx, pacing);

    topology_store_close();
    projection_store_close();
    test_cleanup_tmpdir(ctx.dir);

    return failures;
}

/* ── 5. a sweep with every input under its bound changes nothing ── */
static int shk_case_sweep_under_bound_noop(const struct storage_pacing *pacing)
{
    int failures = 0;
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "storage_housekeeping", "under");

        SHK_CHECK("topology_store opens for the under-bound case",
                  topology_store_open(dir));
        struct net_addr a = shk_ipv4(66, 70, 182, 7);
        SHK_CHECK("a few real edges are recorded",
                  topology_store_record_self_edge(&a, 8233, 1, NULL));
        SHK_CHECK("the WAL is under its bound",
                  topology_store_wal_bytes() <= pacing->wal_truncate_bytes);
        int64_t wal_before = topology_store_wal_bytes();

        SHK_CHECK("projection_store opens for the under-bound case",
                  projection_store_open(dir));
        sqlite3 *proj = projection_store_db();
        if (proj) {
            projection_store_tx_lock();
            sqlite3_exec(proj,
                         "CREATE TABLE shk_small(k INTEGER PRIMARY KEY);"
                         "INSERT INTO shk_small VALUES(1);"
                         "PRAGMA wal_checkpoint(TRUNCATE)",
                         NULL, NULL, NULL);
            projection_store_tx_unlock();
        }
        char kv_path[512];
        snprintf(kv_path, sizeof(kv_path), "%s/progress.kv", dir);
        int64_t kv_before = shk_file_size(kv_path);
        SHK_CHECK("progress.kv is under its floor",
                  kv_before <= pacing->compact_floor_bytes);

        char log_path[512], log_prev[520];
        snprintf(log_path, sizeof(log_path), "%s/tor.log", dir);
        snprintf(log_prev, sizeof(log_prev), "%s.1", log_path);
        SHK_CHECK("small fake tor.log written",
                  shk_write_file(log_path, 64 * 1024));

        struct storage_housekeeping_stats before, after;
        storage_housekeeping_stats(&before);
        storage_housekeeping_sweep(dir);
        storage_housekeeping_stats(&after);

        SHK_CHECK("the tick ran (sweeps advanced)",
                  after.sweeps == before.sweeps + 1);
        SHK_CHECK("no rotation under the bound",
                  after.log_rotations == before.log_rotations &&
                  shk_file_size(log_path) == 64 * 1024 &&
                  shk_file_size(log_prev) < 0);
        SHK_CHECK("no WAL truncation under the bound",
                  after.topology_checkpoints ==
                          before.topology_checkpoints &&
                  topology_store_wal_bytes() == wal_before);
        SHK_CHECK("no compaction under the bound",
                  after.projection_compactions ==
                          before.projection_compactions &&
                  shk_file_size(kv_path) == kv_before);

        topology_store_close();
        projection_store_close();
        test_cleanup_tmpdir(dir);
    }

    return failures;
}

/* ── 6. stop while a tick's work is due does not deadlock ── */
static int shk_case_stop_with_tick_due(const struct storage_pacing *pacing)
{
    int failures = 0;
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "storage_housekeeping",
                         "stoptick");
        char log_path[512], log_prev[520];
        SHK_CHECK("oversized fake tor.log written for the stop test",
                  shk_oversized_tor_log(dir, pacing->log_rotate_bytes,
                                        log_path, sizeof(log_path)));
        snprintf(log_prev, sizeof(log_prev), "%s.1", log_path);

        struct storage_housekeeping_stats before, after;
        storage_housekeeping_stats(&before);

        struct zcl_result r = storage_housekeeping_start(dir);
        SHK_CHECK_RESULT("start runs its synchronous boot sweep", r);
        storage_housekeeping_stats(&after);
        SHK_CHECK("the boot sweep rotated the oversized log",
                  after.log_rotations == before.log_rotations + 1);

        /* Make a tick's work due again, then stop at once. If stop()
         * deadlocked the group would hang here and the runner's watchdog
         * would fail the run; reaching the next line is the proof. The
         * elapsed time is printed for the transcript only — it is not
         * graded (gate_no_wallclock_assertion.c). */
        SHK_CHECK("tick work made due again before stop",
                  shk_write_file(log_path, pacing->log_rotate_bytes + 4096));
        int64_t t0 = platform_time_monotonic_ms();
        storage_housekeeping_stop();
        printf("storage_housekeeping: stop() with a tick due took %lld ms "
               "(transcript only)\n",
               (long long)(platform_time_monotonic_ms() - t0));

        struct zcl_result restart = storage_housekeeping_start(dir);
        SHK_CHECK_RESULT("restart after stop proves the thread exited",
                         restart);
        storage_housekeeping_stats(&after);
        SHK_CHECK("the restart boot sweep rotated the due tick's log",
                  after.log_rotations == before.log_rotations + 2);
        storage_housekeeping_stop();
        SHK_CHECK("tor.log is bounded and the previous copy is intact",
                  shk_file_size(log_path) == 0 &&
                  shk_file_size(log_prev) ==
                          pacing->log_rotate_bytes + 4096);

        test_cleanup_tmpdir(dir);
    }
    return failures;
}

/* ── 6. every step outcome maps to exactly one sweep stat ── */
enum shk_st { SHK_ST_DONE, SHK_ST_SKIP, SHK_ST_FAIL };
enum shk_log { SHK_LOG_DONE, SHK_LOG_NODIR, SHK_LOG_FAIL };
enum shk_want { SHK_WANT_COMPLETED, SHK_WANT_SKIPPED, SHK_WANT_FAILED };

struct shk_row {
    const char *name;
    enum shk_st topology;
    enum shk_st projection;
    enum shk_log logs;
    enum shk_want want;
};

struct shk_fixture {
    sqlite3 *wal_reader;     /* second connection pinning topology.db's WAL */
    sqlite3_stmt *kv_active; /* in-flight statement: VACUUM must refuse */
    char blocker_dir[560];   /* tor.log.1 as a non-empty directory */
    char blocker_file[620];
};

static void shk_fixture_topology(struct shk_fixture *fx,
                                 struct shk_sweep_bound_ctx *ctx,
                                 const struct storage_pacing *pacing,
                                 enum shk_st st, int *failures_out)
{
    int failures = 0;
    if (st == SHK_ST_DONE) {
        SHK_CHECK("row: topology opens", topology_store_open(ctx->dir));
        struct net_addr a = shk_ipv4(66, 70, 182, 11);
        SHK_CHECK("row: topology edge recorded",
                  topology_store_record_self_edge(&a, 8233, 1, NULL));
    } else if (st == SHK_ST_FAIL) {
        failures += shk_drive_wal_over_bound(ctx, pacing);
        char path[300];
        snprintf(path, sizeof(path), "%s/topology.db", ctx->dir);
        SHK_CHECK("row: WAL-pinning reader opens",
                  sqlite3_open(path, &fx->wal_reader) == SQLITE_OK);
        SHK_CHECK("row: reader holds a read snapshot",
                  fx->wal_reader &&
                  sqlite3_exec(fx->wal_reader,
                               "BEGIN; SELECT count(*) FROM sqlite_master;",
                               NULL, NULL, NULL) == SQLITE_OK);
    }
    *failures_out += failures;
}

static void shk_fixture_projection(struct shk_fixture *fx,
                                   struct shk_sweep_bound_ctx *ctx,
                                   const struct storage_pacing *pacing,
                                   enum shk_st st, int *failures_out)
{
    int failures = 0;
    if (st == SHK_ST_DONE) {
        SHK_CHECK("row: projection opens", projection_store_open(ctx->dir));
    } else if (st == SHK_ST_FAIL) {
        failures += shk_drive_progress_kv_over_bound(ctx, pacing);
        sqlite3 *proj = projection_store_db();
        SHK_CHECK("row: projection handle for the in-flight statement",
                  proj != NULL);
        if (proj) {
            projection_store_tx_lock();
            int rc = sqlite3_exec(proj,
                                  "CREATE TABLE IF NOT EXISTS shk_keep(k INTEGER);"
                                  "INSERT INTO shk_keep VALUES(1),(2)",
                                  NULL, NULL, NULL);
            projection_store_tx_unlock();
            SHK_CHECK("row: keep rows written", rc == SQLITE_OK);
            SHK_CHECK("row: statement left in flight",
                      sqlite3_prepare_v2(proj, "SELECT k FROM shk_keep", -1,
                                         &fx->kv_active, NULL) == SQLITE_OK &&
                      sqlite3_step(fx->kv_active) == SQLITE_ROW);
        }
    }
    *failures_out += failures;
}

static int shk_run_row(const struct shk_row *row,
                       const struct storage_pacing *pacing)
{
    int failures = 0;
    struct shk_sweep_bound_ctx ctx = {0};
    struct shk_fixture fx = {0};
    printf("storage_housekeeping: row [%s]\n", row->name);
    test_make_tmpdir(ctx.dir, sizeof(ctx.dir), "storage_housekeeping", "row");

    shk_fixture_topology(&fx, &ctx, pacing, row->topology, &failures);
    shk_fixture_projection(&fx, &ctx, pacing, row->projection, &failures);
    if (row->logs == SHK_LOG_FAIL) {
        SHK_CHECK("row: oversized tor.log written",
                  shk_oversized_tor_log(ctx.dir, pacing->log_rotate_bytes,
                                        ctx.log_path, sizeof(ctx.log_path)));
        snprintf(fx.blocker_dir, sizeof(fx.blocker_dir), "%s.1", ctx.log_path);
        snprintf(fx.blocker_file, sizeof(fx.blocker_file), "%s/keep",
                 fx.blocker_dir);
        SHK_CHECK("row: rotation target made unwritable",
                  mkdir(fx.blocker_dir, 0700) == 0 &&
                  shk_write_file(fx.blocker_file, 16));
    }

    struct storage_housekeeping_stats b, a;
    storage_housekeeping_stats(&b);
    storage_housekeeping_sweep(row->logs == SHK_LOG_NODIR ? NULL : ctx.dir);
    storage_housekeeping_stats(&a);

    SHK_CHECK("row: one sweep started", a.sweeps == b.sweeps + 1);
    SHK_CHECK("row: completed moved only for the all-done row",
              a.sweeps_completed ==
              b.sweeps_completed + (row->want == SHK_WANT_COMPLETED ? 1 : 0));
    SHK_CHECK("row: skipped stat is exact",
              a.sweeps_skipped ==
              b.sweeps_skipped + (row->want == SHK_WANT_SKIPPED ? 1 : 0));
    SHK_CHECK("row: failed stat is exact",
              a.sweeps_failed ==
              b.sweeps_failed + (row->want == SHK_WANT_FAILED ? 1 : 0));
    SHK_CHECK("row: interrupted did not move",
              a.sweeps_interrupted == b.sweeps_interrupted);

    if (fx.kv_active)
        sqlite3_finalize(fx.kv_active);
    if (fx.wal_reader)
        sqlite3_close(fx.wal_reader);
    if (fx.blocker_file[0])
        remove(fx.blocker_file);
    if (fx.blocker_dir[0])
        rmdir(fx.blocker_dir);
    topology_store_close();
    projection_store_close();
    test_cleanup_tmpdir(ctx.dir);
    return failures;
}

static int shk_case_step_outcome_table(const struct storage_pacing *pacing)
{
    static const struct shk_row rows[] = {
        { "all steps done", SHK_ST_DONE, SHK_ST_DONE, SHK_LOG_DONE,
          SHK_WANT_COMPLETED },
        { "topology store closed", SHK_ST_SKIP, SHK_ST_DONE, SHK_LOG_DONE,
          SHK_WANT_SKIPPED },
        { "projection store closed", SHK_ST_DONE, SHK_ST_SKIP, SHK_LOG_DONE,
          SHK_WANT_SKIPPED },
        { "no datadir for the log bound", SHK_ST_DONE, SHK_ST_DONE,
          SHK_LOG_NODIR, SHK_WANT_SKIPPED },
        { "topology checkpoint cannot truncate", SHK_ST_FAIL, SHK_ST_DONE,
          SHK_LOG_DONE, SHK_WANT_FAILED },
        { "projection compaction refused", SHK_ST_DONE, SHK_ST_FAIL,
          SHK_LOG_DONE, SHK_WANT_FAILED },
        { "log rotation cannot write", SHK_ST_DONE, SHK_ST_DONE,
          SHK_LOG_FAIL, SHK_WANT_FAILED },
        { "failed outranks skipped", SHK_ST_SKIP, SHK_ST_FAIL, SHK_LOG_NODIR,
          SHK_WANT_FAILED },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
        failures += shk_run_row(&rows[i], pacing);
    return failures;
}

int test_storage_housekeeping(void)
{
    printf("\n=== storage_housekeeping tests ===\n");
    int failures = 0;

    shk_small_bounds();
    const struct storage_pacing *pacing = storage_pacing();
    SHK_CHECK("1 MiB test bounds are published",
              pacing->log_rotate_bytes == 1LL << 20 &&
              pacing->wal_truncate_bytes == 1LL << 20 &&
              pacing->compact_floor_bytes == 1LL << 20);

    failures += shk_case_start_stop_round_trip();
    failures += shk_case_start_refuses_bad_datadirs();
    failures += shk_case_service_registration();
    failures += shk_case_sweep_performs_each_bound(pacing);
    failures += shk_case_sweep_under_bound_noop(pacing);
    failures += shk_case_stop_with_tick_due(pacing);
    failures += shk_case_boot_start_not_blocked_by_held_lock();
    failures += shk_case_stop_ends_sweep_blocked_on_token();
    failures += shk_case_step_outcome_table(pacing);

    shk_restore_pacing();
    if (failures == 0)
        printf("=== storage_housekeeping tests: ALL PASS ===\n");
    else
        printf("=== storage_housekeeping tests: %d FAILURES ===\n",
               failures);
    return failures + ZCL_TEST_SETUP_FAILURES();
}

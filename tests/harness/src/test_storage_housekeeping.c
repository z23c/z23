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
 *     assertion is used — see tools/lint/check_no_wallclock_assertion.sh)
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

    /* ── 1. start/stop round trip on an empty datadir ───────────────── */
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

        storage_housekeeping_stop();
        SHK_CHECK("stop joins and returns on an empty datadir", true);
        storage_housekeeping_stop(); /* safe no-op, like db_maintenance */
        SHK_CHECK("second stop is a safe no-op", true);

        test_cleanup_tmpdir(dir);
    }

    /* ── 2. start refuses NULL/empty/absent datadirs by name ────────── */
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

    /* ── 3. service registration: OPTIONAL, wrappers call through ───── */
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
        storage_housekeeping_stats(&after);
        SHK_CHECK("the start wrapper called through (boot sweep ran)",
                  after.sweeps >= before.sweeps + 1);

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

    /* ── 4. one sweep performs each bound when crossed ──────────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "storage_housekeeping", "over");

        /* topology.db WAL over its bound: feed real edges through the
         * store's own API until the WAL file crosses the pacing bound. */
        SHK_CHECK("topology_store opens in the fixture datadir",
                  topology_store_open(dir));
        int n = 0;
        while (topology_store_wal_bytes() <= pacing->wal_truncate_bytes &&
               n < 60000) {
            struct net_addr advertised =
                shk_ipv4(66, (unsigned char)((n >> 8) & 0xff),
                         (unsigned char)(n & 0xff), 7);
            if (!topology_store_record_self_edge(&advertised, 8233,
                                                 n + 1, NULL))
                break;
            n++;
        }
        SHK_CHECK("fixture drove the WAL over its bound",
                  topology_store_wal_bytes() > pacing->wal_truncate_bytes);
        int64_t wal_before = topology_store_wal_bytes();

        /* progress.kv over floor AND ratio: 3 MiB of committed junk, all
         * of it then deleted, so the file keeps the high-water mark while
         * the live set collapses. */
        SHK_CHECK("projection_store opens in the fixture datadir",
                  projection_store_open(dir));
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
                rc = sqlite3_exec(proj, "DELETE FROM shk_junk", NULL, NULL,
                                  NULL);
            projection_store_tx_unlock();
            SHK_CHECK("projection junk fixture built and deleted",
                      rc == SQLITE_OK);
        }
        char kv_path[512];
        snprintf(kv_path, sizeof(kv_path), "%s/progress.kv", dir);
        int64_t kv_before = shk_file_size(kv_path);
        struct projection_store_usage usage;
        SHK_CHECK("progress.kv crossed the compaction floor",
                  kv_before > pacing->compact_floor_bytes);
        SHK_CHECK("the over-bound predicate fires on the fixture",
                  projection_store_usage(&usage) &&
                  projection_store_over_bound(&usage,
                                              pacing->compact_floor_bytes,
                                              pacing->compact_ratio_pct));

        /* tor.log over its bound. */
        char log_path[512], log_prev[520];
        SHK_CHECK("oversized fake tor.log written",
                  shk_oversized_tor_log(dir, pacing->log_rotate_bytes,
                                        log_path, sizeof(log_path)));
        snprintf(log_prev, sizeof(log_prev), "%s.1", log_path);
        int64_t log_before = shk_file_size(log_path);

        /* The tick under test. */
        struct storage_housekeeping_stats before, after;
        storage_housekeeping_stats(&before);
        storage_housekeeping_sweep(dir);
        storage_housekeeping_stats(&after);

        SHK_CHECK("sweep counted exactly one sweep",
                  after.sweeps == before.sweeps + 1);
        SHK_CHECK("oversized tor.log rotated",
                  after.log_rotations == before.log_rotations + 1 &&
                  shk_file_size(log_path) == 0 &&
                  shk_file_size(log_prev) == log_before);
        SHK_CHECK("over-bound topology WAL truncated",
                  after.topology_checkpoints ==
                          before.topology_checkpoints + 1 &&
                  topology_store_wal_bytes() < wal_before &&
                  topology_store_wal_bytes() <=
                          pacing->wal_truncate_bytes);
        /* VACUUM shrinks the store's LOGICAL size (page_count, what the
         * bound measures and what ls shows once the WAL checkpoints back);
         * the physical file only catches up at the next checkpoint, so the
         * postcondition is read through the service's own measure. */
        struct projection_store_usage compacted_usage;
        SHK_CHECK("over-bound progress.kv compacted",
                  after.projection_compactions ==
                          before.projection_compactions + 1 &&
                  projection_store_usage(&compacted_usage) &&
                  compacted_usage.file_bytes < usage.file_bytes &&
                  compacted_usage.file_bytes <=
                          pacing->compact_floor_bytes);

        topology_store_close();
        projection_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── 5. a sweep with every input under its bound changes nothing ── */
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

    /* ── 6. stop while a tick's work is due does not deadlock ───────── */
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
         * graded (check_no_wallclock_assertion.sh). */
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

    shk_restore_pacing();
    if (failures == 0)
        printf("=== storage_housekeeping tests: ALL PASS ===\n");
    else
        printf("=== storage_housekeeping tests: %d FAILURES ===\n",
               failures);
    return failures + ZCL_TEST_SETUP_FAILURES();
}

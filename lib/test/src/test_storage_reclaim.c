/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fault-injection test for the disk-full survival path (never-stuck roadmap
 * gaps R1/R2): the node must SURVIVE a full / near-full disk on its own.
 *
 * What is asserted (gates on actual RECOVERY, not "didn't crash"):
 *   1. storage_reclaim_derived() actually frees derived bytes — it sweeps a
 *      STALE *.tmp crash orphan while LEAVING a fresh .tmp (an in-flight
 *      atomic write) and a non-.tmp file untouched, and bumps the run count.
 *   2. Under an injected CRITICAL disk condition, writes back off:
 *      db_txn_begin() refuses (returns NULL) and ibd_throttle blocks.
 *   3. On recovery (space returns) the condition CLEARS: db_txn_begin()
 *      succeeds again and ibd_throttle hands out tokens again.
 *
 * No real disk fill: the disk_monitor threshold trick from test_disk_monitor.c
 * is reused — refuse=INT64_MAX classifies any real free-space value as
 * CRITICAL; refuse=1 classifies it as OK. The stale .tmp is aged via utimes().
 */

#include "test/test_core.h"

#include "platform/time_compat.h"
#include "services/storage_reclaim.h"
#include "services/disk_monitor.h"
#include "services/ibd_throttle.h"
#include "models/db_txn.h"
#include "models/database.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#if defined(_WIN32)
#include <utime.h>
#endif
#include <unistd.h>

/* Scratch datadir. Lives INSIDE the suite's one scratch root (./test-tmp) so
 * a `ls` of the checkout shows one ignored scratch dir, not two. Static
 * (not test_make_tmpdir) because every path below is a compile-time
 * concatenation, and this group never runs twice in one process. */
#define SR_DIR "./test-tmp/storage-reclaim"

#define SR_CHECK(name, expr) do { \
    printf("%s... ", (name));     \
    if ((expr)) printf("OK\n");   \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static void sr_write_file(const char *path, const char *bytes)
{
    FILE *f = fopen(path, "w");
    if (f) { fputs(bytes, f); fclose(f); }
}

static bool sr_exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

/* Age a file's mtime so it reads as a crash orphan older than the guard. */
static void sr_age_file(const char *path, int seconds_old)
{
    time_t old = platform_time_wall_time_t() - seconds_old;
#if defined(_WIN32)
    /* No utimes(2) in the UCRT; _utime sets both times from one value. */
    struct _utimbuf tb = { old, old };
    (void)_utime(path, &tb);
#else
    struct timeval tv[2] = { { .tv_sec = old }, { .tv_sec = old } };
    (void)utimes(path, tv);
#endif
}

int test_storage_reclaim(void)
{
    printf("\n=== storage_reclaim / disk-full survival tests ===\n");
    int failures = 0;

    /* Clean slate: a fresh scratch dir under the suite's scratch root. */
    mkdir("./test-tmp", 0755);
    mkdir(SR_DIR, 0755);
    unlink(SR_DIR "/stale.tmp");
    unlink(SR_DIR "/fresh.tmp");
    unlink(SR_DIR "/keep.dat");

    /* ── 1. Reclaim sweeps STALE *.tmp, leaves fresh + non-tmp ── */
    {
        sr_write_file(SR_DIR "/stale.tmp", "orphaned-mid-write-payload");
        sr_write_file(SR_DIR "/fresh.tmp", "in-flight-atomic-write");
        sr_write_file(SR_DIR "/keep.dat",  "real-data-never-touch");
        /* Make the orphan provably older than the min-age guard. */
        sr_age_file(SR_DIR "/stale.tmp",
                    STORAGE_RECLAIM_TMP_MIN_AGE_SECS + 120);

        int64_t runs_before = storage_reclaim_run_count();
        struct storage_reclaim_result r = storage_reclaim_derived(SR_DIR);

        SR_CHECK("sr: reclaim removed the stale .tmp orphan",
                 r.tmp_files_removed >= 1 && !sr_exists(SR_DIR "/stale.tmp"));
        SR_CHECK("sr: reclaim freed a positive byte count",
                 r.tmp_bytes_removed > 0);
        SR_CHECK("sr: reclaim LEFT the fresh .tmp (possible in-flight write)",
                 sr_exists(SR_DIR "/fresh.tmp"));
        SR_CHECK("sr: reclaim LEFT the non-.tmp data file untouched",
                 sr_exists(SR_DIR "/keep.dat"));
        SR_CHECK("sr: reclaim run count advanced (remedy actually fired)",
                 storage_reclaim_run_count() == runs_before + 1);
        /* Both DB WAL sources are always attempted; whether each succeeds is
         * environment-dependent (progress.kv / node.db may or may not be open
         * in this process) and best-effort, so we only assert they were tried. */
        SR_CHECK("sr: both DB WAL sources attempted (best-effort)",
                 r.sources_total == 2 && r.sources_ok >= 0 && r.sources_ok <= 2);
    }

    /* ── 2. CRITICAL disk → writes back off ────────────────────── */
    {
        struct disk_monitor_config cfg;
        disk_monitor_config_defaults(&cfg);
        cfg.datadir           = SR_DIR;
        cfg.warn_free_bytes   = INT64_MAX;
        cfg.refuse_free_bytes = INT64_MAX;  /* every free value < refuse → CRIT */
        cfg.poll_seconds      = 3600;
        bool crit_started = disk_monitor_start(&cfg).ok;
        SR_CHECK("sr: disk_monitor injected CRITICAL", crit_started &&
                 disk_monitor_is_critical());

        /* db_txn back-pressure: a new transaction is refused while critical. */
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        bool opened = node_db_open(&ndb, ":memory:");
        struct db_txn *blocked = opened ? db_txn_begin(&ndb, "sr.blocked")
                                        : (struct db_txn *)0xdead;
        SR_CHECK("sr: db_txn_begin REFUSES under critical disk (back-pressure)",
                 opened && blocked == NULL);

        /* ibd_throttle back-pressure: even a freshly-started (full) bucket
         * hands out no tokens while critical. */
        ibd_throttle_stop();
        struct ibd_throttle_config tc;
        ibd_throttle_config_defaults(&tc);
        (void)ibd_throttle_start(&tc);
        bool got_token_crit = ibd_throttle_try_acquire();
        SR_CHECK("sr: ibd_throttle BLOCKS under critical disk",
                 !got_token_crit);
        ibd_throttle_stop();

        if (opened) node_db_close(&ndb);
        disk_monitor_stop();
    }

    /* ── 3. Recovery: space returns → condition CLEARS, writes resume ── */
    {
        struct disk_monitor_config cfg;
        disk_monitor_config_defaults(&cfg);
        cfg.datadir           = SR_DIR;
        cfg.warn_free_bytes   = 1;          /* free >= 1 → OK */
        cfg.refuse_free_bytes = 1;
        cfg.poll_seconds      = 3600;
        bool ok_started = disk_monitor_start(&cfg).ok;
        SR_CHECK("sr: disk_monitor recovers to OK (space returned)",
                 ok_started && !disk_monitor_is_critical());

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        bool opened = node_db_open(&ndb, ":memory:");
        struct db_txn *resumed = opened ? db_txn_begin(&ndb, "sr.resumed")
                                        : NULL;
        SR_CHECK("sr: db_txn_begin RESUMES after recovery",
                 opened && resumed != NULL);
        if (resumed) { (void)db_txn_commit(resumed);
                       db_txn_auto_rollback(&resumed); }

        ibd_throttle_stop();
        struct ibd_throttle_config tc;
        ibd_throttle_config_defaults(&tc);
        (void)ibd_throttle_start(&tc);
        bool got_token_ok = ibd_throttle_try_acquire();
        SR_CHECK("sr: ibd_throttle hands out tokens again after recovery",
                 got_token_ok);
        ibd_throttle_stop();

        if (opened) node_db_close(&ndb);
        disk_monitor_stop();
    }

    /* Teardown: leave the singletons clean for any sibling test in-process. */
    ibd_throttle_stop();
    disk_monitor_stop();
    unlink(SR_DIR "/fresh.tmp");
    unlink(SR_DIR "/keep.dat");
    test_cleanup_tmpdir(SR_DIR);

    return failures;
}

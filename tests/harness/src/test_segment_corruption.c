/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the segment_corruption healer's real detect + repair flow, driven
 * through its directory-scoped pure helpers (no running node): a bounded
 * round-robin spot-verify catches a tampered sealed segment, and the repair
 * unlinks it + rebuilds the manifest so the range is no longer served corrupt
 * (reads fall back to blk*.dat). The network-refetch seam is node-coupled and
 * is intentionally out of scope here.
 */

#include "test/test_core.h"

#include "conditions/segment_corruption.h"
#include "event/event.h"
#include "framework/condition.h"
#include "storage/chain_segment.h"
#include "util/blocker.h"
#include "util/util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SC_CHECK(name, expr) do {                                            \
    if (expr) { printf("  segment_corruption: %s... OK\n", (name)); }         \
    else { printf("  segment_corruption: %s... FAIL\n", (name)); failures++; }\
} while (0)

static bool tiny_body(void *user, uint32_t h, uint8_t **bytes, size_t *len)
{
    (void)user;
    size_t n = 24;
    uint8_t *b = malloc(n); // raw-alloc-ok:test
    if (!b) return false;
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(h * 7u + i);
    *bytes = b; *len = n;
    return true;
}

/* ── Mutation-gap cases: the pure helpers' edges and the registered condition's
 * detect / remedy / witness driven through the real engine on an isolated
 * fixture datadir (SetDataDir to a private tmpdir, never a live datadir). ── */

static void sc_seal(const char *segdir, uint32_t first, uint32_t count)
{
    char err[256];
    (void)chain_segment_seal_range(segdir, tiny_body, NULL, first, count, err,
                                   sizeof(err));
}

/* Flip one byte inside the first block body of seg-<first>-<count>.dat so the
 * whole-segment digest fails. */
static bool sc_tamper(const char *segdir, uint32_t first, uint32_t count)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/seg-%u-%u.dat", segdir, first, count);
    (void)chmod(path, 0644);
    FILE *f = fopen(path, "r+b");
    if (!f)
        return false;
    long off = 32 + (long)count * 48 + 3;
    fseek(f, off, SEEK_SET);
    int c = fgetc(f);
    fseek(f, off, SEEK_SET);
    fputc(c ^ 0xff, f);
    fclose(f);
    return true;
}

static bool sc_exists(const char *segdir, uint32_t first, uint32_t count)
{
    char path[512];
    struct stat sb;
    snprintf(path, sizeof(path), "%s/seg-%u-%u.dat", segdir, first, count);
    return stat(path, &sb) == 0;
}

/* Fresh, empty segments dir (replacing whatever, even a plain file, was there). */
static void sc_fresh_dir(const char *segdir)
{
    (void)unlink(segdir);
    (void)unlink(segdir);
    (void)test_rm_rf_recursive(segdir);
    (void)mkdir(segdir, 0700);
}

/* A directory the caller cannot unlink from. False when permissions do not
 * bind (running as root), so the caller skips instead of failing. */
static bool sc_lock_dir(const char *segdir)
{
    (void)chmod(segdir, 0555);
    return access(segdir, W_OK) != 0;
}

static int sc_pure_scan_edges(const char *base)
{
    int failures = 0;
    char err[256];
    char segdir[512];
    snprintf(segdir, sizeof(segdir), "%s/scan", base);
    uint32_t cursor = 0, first = 999, count = 999;

    /* A missing directory is an empty store: NOT_FOUND, outputs zeroed. */
    (void)unlink(segdir);
    (void)test_rm_rf_recursive(segdir);
    enum cseg_status st = segment_corruption_scan_one(segdir, &cursor, &first,
                                                      &count, err, sizeof(err));
    SC_CHECK("missing dir -> NOT_FOUND with zeroed range",
             st == CSEG_ERR_NOT_FOUND && first == 0 && count == 0);

    /* A segments path that is a regular file cannot be opened: the IO error is
     * returned as-is and the range outputs stay zeroed. */
    {
        FILE *f = fopen(segdir, "w");
        if (f) fclose(f);
    }
    first = 999; count = 999;
    st = segment_corruption_scan_one(segdir, &cursor, &first, &count, err,
                                     sizeof(err));
    SC_CHECK("non-directory store -> IO error, zeroed range",
             st == CSEG_ERR_IO && first == 0 && count == 0);

    /* Exactly one sealed segment: scanned (not mistaken for empty). */
    sc_fresh_dir(segdir);
    sc_seal(segdir, 0, 10);
    cursor = 0; first = 999; count = 999;
    st = segment_corruption_scan_one(segdir, &cursor, &first, &count, err,
                                     sizeof(err));
    SC_CHECK("single segment verifies OK", st == CSEG_OK && first == 0 &&
                                           count == 10);
    SC_CHECK("cursor advanced by one", cursor == 1);

    /* Two segments: the cursor wraps modulo the count; a NULL cursor means
     * index 0. */
    sc_seal(segdir, 500, 7);
    cursor = 5;
    st = segment_corruption_scan_one(segdir, &cursor, &first, &count, err,
                                     sizeof(err));
    SC_CHECK("cursor 5 of 2 scans index 1", st == CSEG_OK && first == 500 &&
                                            count == 7 && cursor == 6);
    st = segment_corruption_scan_one(segdir, NULL, &first, &count, err,
                                     sizeof(err));
    SC_CHECK("NULL cursor scans index 0", st == CSEG_OK && first == 0 &&
                                          count == 10);
    (void)unlink(segdir);
    (void)test_rm_rf_recursive(segdir);
    return failures;
}

static int sc_pure_repair_edges(const char *base)
{
    int failures = 0;
    char err[256] = {0};
    char segdir[512];
    snprintf(segdir, sizeof(segdir), "%s/rep", base);

    /* A segment that is already gone is a successful repair (idempotent). */
    sc_fresh_dir(segdir);
    SC_CHECK("repair of an absent segment is OK",
             segment_corruption_repair(segdir, 40, 3, err, sizeof(err)) ==
                 CSEG_OK);

    /* Success must not depend on a stale errno left by an earlier call. */
    sc_seal(segdir, 0, 10);
    errno = EIO;
    SC_CHECK("repair OK despite stale errno",
             segment_corruption_repair(segdir, 0, 10, err, sizeof(err)) ==
                 CSEG_OK);
    SC_CHECK("repaired segment is gone", !sc_exists(segdir, 0, 10));

    /* An unlink that really fails is an IO error that names the path, and a
     * NULL err buffer with a nonzero length is tolerated. */
    sc_seal(segdir, 0, 10);
    if (sc_lock_dir(segdir)) {
        err[0] = 0;
        enum cseg_status st =
            segment_corruption_repair(segdir, 0, 10, err, sizeof(err));
        SC_CHECK("unlink failure -> IO error", st == CSEG_ERR_IO);
        SC_CHECK("unlink failure names the path", strstr(err, "unlink(") &&
                                                  strstr(err, "seg-0-10.dat"));
        SC_CHECK("failed repair left the segment",
                 sc_exists(segdir, 0, 10));
        SC_CHECK("NULL err buffer tolerated",
                 segment_corruption_repair(segdir, 0, 10, NULL, 64) ==
                     CSEG_ERR_IO);
    } else {
        printf("  segment_corruption: unlink-failure cases skipped (perms "
               "do not bind)\n");
    }
    (void)chmod(segdir, 0700);
    (void)unlink(segdir);
    (void)test_rm_rf_recursive(segdir);
    return failures;
}

/* One engine tick on a freshly registered condition. Reports the snapshot after
 * the tick and how many witnessed clears that tick produced. */
static void sc_tick(struct condition_runtime_snapshot *snap, int *cleared)
{
    struct condition_runtime_snapshot before;
    condition_engine_reset_for_testing();
    register_segment_corruption();
    memset(&before, 0, sizeof(before));
    (void)condition_engine_get_registered_snapshot("segment_corruption",
                                                   &before);
    condition_engine_tick();
    memset(snap, 0, sizeof(*snap));
    (void)condition_engine_get_registered_snapshot("segment_corruption", snap);
    *cleared = snap->cleared_count - before.cleared_count;
}

/* Tick (at most twice: the sweep is round-robin over two segments) until the
 * condition fires; the same tick runs the remedy and the witness. */
static int sc_tick_until_fired(struct condition_runtime_snapshot *snap,
                               int *cleared)
{
    int ticks = 0;
    do {
        sc_tick(snap, cleared);
        ticks++;
    } while (ticks < 2 && !snap->currently_active && *cleared == 0);
    return ticks;
}

static int sc_case_repair(const char *name, const char *segdir,
                          uint32_t bad_first, uint32_t bad_count,
                          uint32_t good_first, uint32_t good_count)
{
    int failures = 0;
    char label[160];
    struct condition_runtime_snapshot snap;
    int cleared = 0;

    sc_fresh_dir(segdir);
    sc_seal(segdir, bad_first, bad_count);
    sc_seal(segdir, good_first, good_count);
    snprintf(label, sizeof(label), "%s: tamper", name);
    SC_CHECK(label, sc_tamper(segdir, bad_first, bad_count));

    (void)sc_tick_until_fired(&snap, &cleared);
    snprintf(label, sizeof(label), "%s: witnessed clear (repaired)", name);
    SC_CHECK(label, cleared == 1 && !snap.currently_active);
    snprintf(label, sizeof(label), "%s: corrupt segment unlinked", name);
    SC_CHECK(label, !sc_exists(segdir, bad_first, bad_count));
    snprintf(label, sizeof(label), "%s: clean segment untouched", name);
    SC_CHECK(label, sc_exists(segdir, good_first, good_count));

    uint32_t cur = 0, f = 999, c = 999;
    char err[256];
    snprintf(label, sizeof(label), "%s: survivor still verifies", name);
    SC_CHECK(label,
             segment_corruption_scan_one(segdir, &cur, &f, &c, err,
                                         sizeof(err)) == CSEG_OK &&
                 f == good_first && c == good_count);
    return failures;
}

static int sc_case_quiet(const char *segdir)
{
    int failures = 0;
    struct condition_runtime_snapshot snap;
    int cleared = 0;

    /* Two clean segments: two sweeps cover both and nothing fires. */
    sc_fresh_dir(segdir);
    sc_seal(segdir, 0, 10);
    sc_seal(segdir, 500, 7);
    for (int i = 0; i < 2; i++) {
        sc_tick(&snap, &cleared);
        SC_CHECK("clean sweep: detect stays quiet",
                 !snap.currently_active && snap.attempts == 0 && cleared == 0);
    }
    SC_CHECK("clean sweep: both segments kept",
             sc_exists(segdir, 0, 10) && sc_exists(segdir, 500, 7));

    /* An empty segments dir and a missing one are an empty store, not damage. */
    sc_fresh_dir(segdir);
    sc_tick(&snap, &cleared);
    SC_CHECK("empty store: detect stays quiet",
             !snap.currently_active && snap.attempts == 0);
    (void)unlink(segdir);
    (void)test_rm_rf_recursive(segdir);
    sc_tick(&snap, &cleared);
    SC_CHECK("missing store: detect stays quiet",
             !snap.currently_active && snap.attempts == 0);
    return failures;
}

/* A segments path that is not a directory is reported as damage (detect fires)
 * but names no range, so the remedy refuses to unlink anything. */
static int sc_case_no_range(const char *segdir)
{
    int failures = 0;
    struct condition_runtime_snapshot snap;
    int cleared = 0;

    (void)unlink(segdir);
    (void)test_rm_rf_recursive(segdir);
    FILE *f = fopen(segdir, "w");
    if (f) fclose(f);
    sc_tick(&snap, &cleared);
    SC_CHECK("unopenable store: detect fires and remedy ran once",
             snap.currently_active && snap.attempts == 1);
    SC_CHECK("unopenable store: remedy refused (no range named), not repaired",
             snap.last_outcome == COND_REMEDY_SKIP && cleared == 0);
    (void)unlink(segdir);
    (void)test_rm_rf_recursive(segdir);
    return failures;
}

/* A remedy whose unlink fails is FAILED and keeps the episode open; once the
 * segment is replaced by a clean one the witness (which re-verifies the
 * still-covering segment) clears it with no further remedy. */
static int sc_case_failed_then_witnessed(const char *segdir)
{
    int failures = 0;
    struct condition_runtime_snapshot snap;
    int cleared = 0;

    sc_fresh_dir(segdir);
    sc_seal(segdir, 0, 1);
    sc_seal(segdir, 500, 7);
    (void)sc_tamper(segdir, 0, 1);
    if (!sc_lock_dir(segdir)) {
        printf("  segment_corruption: failed-remedy case skipped (perms do "
               "not bind)\n");
        (void)chmod(segdir, 0700);
        return 0;
    }
    (void)sc_tick_until_fired(&snap, &cleared);
    SC_CHECK("failed unlink: remedy FAILED, episode stays open",
             snap.currently_active && snap.attempts == 1 &&
                 snap.last_outcome == COND_REMEDY_FAILED && cleared == 0);
    SC_CHECK("failed unlink: corrupt segment still there",
             sc_exists(segdir, 0, 1));

    (void)chmod(segdir, 0700);
    char path[512];
    snprintf(path, sizeof(path), "%s/seg-0-1.dat", segdir);
    (void)chmod(path, 0644);
    (void)unlink(path);
    sc_seal(segdir, 0, 1);

    struct condition_runtime_snapshot before = snap;
    condition_engine_tick(); /* same episode: witness re-verifies seg-0-1 */
    memset(&snap, 0, sizeof(snap));
    (void)condition_engine_get_registered_snapshot("segment_corruption", &snap);
    SC_CHECK("replaced segment: witness clears the open episode",
             snap.cleared_count == before.cleared_count + 1 &&
                 !snap.currently_active);
    SC_CHECK("replaced segment: no remedy ran", snap.attempts == 0);
    return failures;
}

static int sc_case_registration(void)
{
    int failures = 0;
    struct condition_runtime_snapshot snap;
    condition_engine_reset_for_testing();
    register_segment_corruption();
    memset(&snap, 0, sizeof(snap));
    SC_CHECK("registered",
             condition_engine_get_registered_snapshot("segment_corruption",
                                                      &snap) &&
                 snap.registered);
    SC_CHECK("cadence 30s poll / 60s backoff / 3 attempts / 60s witness",
             snap.poll_secs == 30 && snap.backoff_secs == 60 &&
                 snap.max_attempts == 3 && snap.witness_window_secs == 60);
    SC_CHECK("WARN severity, legacy latch (no cooldown re-arm)",
             snap.severity == COND_WARN && snap.cooldown_secs == 0 &&
                 snap.cooldown_max_rearms == 0);
    return failures;
}

static int sc_engine_cases(const char *base)
{
    int failures = 0;
    char netdir[1024];
    char segdir[1100];

    event_log_init();
    (void)blocker_module_init();
    bool pinned = SetDataDir(base);
    SC_CHECK("pin fixture datadir", pinned);
    /* Unpinned, GetDataDir falls back to another datadir and these cases
     * would clear its segments. */
    if (!pinned)
        return failures;
    GetDataDir(true, netdir, sizeof(netdir));
    snprintf(segdir, sizeof(segdir), "%s/segments", netdir);

    failures += sc_case_registration();
    failures += sc_case_quiet(segdir);
    failures += sc_case_no_range(segdir);
    /* seg-0-1 has first==0 and count==1: the remedy's lowest legal range. */
    failures += sc_case_repair("first=0,count=1", segdir, 0, 1, 500, 7);
    failures += sc_case_repair("first=500,count=7", segdir, 500, 7, 0, 10);
    failures += sc_case_failed_then_witnessed(segdir);

    (void)chmod(segdir, 0700);
    condition_engine_reset_for_testing();
    ClearDataDirCache();
    return failures;
}

int test_segment_corruption(void);
int test_segment_corruption(void)
{
    printf("\n=== segment_corruption (detect + repair) ===\n");
    int failures = 0;
    char err[256];
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "segment_corruption", "flow");

    /* Two sealed segments: seg-0-10 (clean) and seg-500-7 (we corrupt it). */
    chain_segment_seal_range(dir, tiny_body, NULL, 0, 10, err, sizeof(err));
    chain_segment_seal_range(dir, tiny_body, NULL, 500, 7, err, sizeof(err));

    /* A clean spot-verify of index 0 reports OK and names the range. */
    uint32_t cursor = 0, first = 999, count = 999;
    enum cseg_status st = segment_corruption_scan_one(dir, &cursor, &first,
                                                      &count, err, sizeof(err));
    SC_CHECK("clean segment verifies OK", st == CSEG_OK &&
                                          first == 0 && count == 10);

    /* Corrupt seg-500-7.dat: flip a byte in its block-data region so the
     * whole-segment digest fails on open. */
    char path[512];
    snprintf(path, sizeof(path), "%s/seg-500-7.dat", dir);
    chmod(path, 0644);
    FILE *f = fopen(path, "r+b");
    bool tampered = false;
    if (f) {
        long off = 32 + 7 * 48 + 3; /* header + index(7*48) + into first body */
        fseek(f, off, SEEK_SET); int c = fgetc(f);
        fseek(f, off, SEEK_SET); fputc(c ^ 0xff, f);
        fclose(f); tampered = true;
    }
    SC_CHECK("tamper write", tampered);

    /* Spot-verify index 1 (round-robin cursor=1) now DETECTS corruption and
     * names the corrupt range — the real detect path. */
    cursor = 1; first = 999; count = 999;
    st = segment_corruption_scan_one(dir, &cursor, &first, &count,
                                     err, sizeof(err));
    SC_CHECK("corrupt segment detected",
             st != CSEG_OK && st != CSEG_ERR_NOT_FOUND &&
             first == 500 && count == 7);

    /* Repair: unlink the corrupt segment + rebuild the manifest. */
    st = segment_corruption_repair(dir, 500, 7, err, sizeof(err));
    SC_CHECK("repair returns ok", st == CSEG_OK);
    {
        struct stat sb;
        SC_CHECK("corrupt segment file removed", stat(path, &sb) != 0);
    }

    /* Witness-equivalent: the store no longer covers the corrupt range (reads
     * fall back to blk*.dat), and the surviving segment still verifies clean. */
    {
        struct chain_segment_store *store = NULL;
        enum cseg_status ost = chain_segment_store_open(dir, &store, err, sizeof(err));
        SC_CHECK("store reopen ok", ost == CSEG_OK && store != NULL);
        SC_CHECK("corrupt range no longer covered",
                 store && !chain_segment_store_covers(store, 500));
        SC_CHECK("survivor still covered + count 1",
                 store && chain_segment_store_covers(store, 0) &&
                 chain_segment_store_segment_count(store) == 1);
        SC_CHECK("survivor verifies clean",
                 store && chain_segment_store_verify_index(store, 0, err,
                                                           sizeof(err)) == CSEG_OK);
        chain_segment_store_close(store);
    }

    test_rm_rf_recursive(dir);

    char more[256];
    test_make_tmpdir(more, sizeof(more), "segment_corruption", "edges");
    failures += sc_pure_scan_edges(more);
    failures += sc_pure_repair_edges(more);
    failures += sc_engine_cases(more);
    test_rm_rf_recursive(more);
    printf("segment_corruption: %d failures\n", failures);
    return failures;
}

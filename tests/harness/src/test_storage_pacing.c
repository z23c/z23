/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the storage pacing organ (platform/modules/util/src/
 * storage_pacing.c) and the storage probe under it
 * (platform/modules/platform/src/storage_probe.c).
 *
 * The point of the module is that a deployed node picks its own IO bounds
 * from the disk it landed on, with no per-host tuning. So the tests pin the
 * two halves of that claim separately:
 *
 *   - the DECISION RULE is pure, so each storage class is forced and the
 *     pacing it implies is asserted field by field. This is the test that
 *     would catch someone quietly giving a spinning disk the SSD bounds.
 *   - the MEASUREMENT is exercised against a real file on the test host,
 *     asserting only what is true everywhere: a median is produced for a
 *     large enough file, and nothing is produced (rather than something
 *     invented) when no file qualifies.
 *   - the ordering of evidence — an explicit override beats everything —
 *     and the maintenance token's serialisation.
 */

#include "test/test_core.h"

#include "json/json.h"
#include "platform/storage_probe.h"
#include "platform/time_compat.h"
#include "storage/projection_store.h"
#include "util/log_rotate.h"
#include "util/storage_pacing.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SPC(name, expr) do { \
    printf("storage_pacing: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── the decision rule ─────────────────────────────────────────────── */

static int test_pacing_per_class(void)
{
    int failures = 0;

    struct storage_pacing hdd =
        storage_pacing_for_class(PLATFORM_STORAGE_CLASS_ROTATIONAL);
    struct storage_pacing ssd =
        storage_pacing_for_class(PLATFORM_STORAGE_CLASS_SOLID);
    struct storage_pacing unknown =
        storage_pacing_for_class(PLATFORM_STORAGE_CLASS_UNKNOWN);

    SPC("rotational asks for sequential readahead", hdd.sequential_readahead);
    SPC("rotational readahead window is non-zero",
        hdd.boot_readahead_window_bytes > 0);
    SPC("solid does not pay for readahead syscalls",
        !ssd.sequential_readahead && ssd.boot_readahead_window_bytes == 0);

    SPC("rotational serialises maintenance writers", hdd.serialize_maintenance);
    SPC("rotational leaves an idle gap between them",
        hdd.maintenance_gap_ms > 0);
    SPC("solid runs maintenance without a gap",
        !ssd.serialize_maintenance && ssd.maintenance_gap_ms == 0);

    /* Every write-heavy bound is STRICTLY tighter on a spinning disk. This
     * is the whole contract; a regression that loosens one of them here is
     * exactly the 65%-IO-pressure defect coming back. */
    SPC("rotational WAL bound is tighter",
        hdd.wal_truncate_bytes < ssd.wal_truncate_bytes);
    SPC("rotational log rotation is tighter",
        hdd.log_rotate_bytes < ssd.log_rotate_bytes);
    SPC("rotational compaction floor is tighter",
        hdd.compact_floor_bytes < ssd.compact_floor_bytes);
    SPC("rotational compaction ratio is tighter",
        hdd.compact_ratio_pct < ssd.compact_ratio_pct);

    /* Every bound is still BOUNDED on solid state: an SSD does not make an
     * unbounded log or an uncompacted store correct. */
    SPC("solid bounds are finite",
        ssd.wal_truncate_bytes > 0 && ssd.log_rotate_bytes > 0 &&
        ssd.compact_floor_bytes > 0 && ssd.compact_ratio_pct > 100);

    /* UNKNOWN is paced like solid state but must REPORT unknown, so a
     * status reader can tell a measured answer from a default. */
    SPC("unknown is paced like solid state",
        unknown.wal_truncate_bytes == ssd.wal_truncate_bytes &&
        unknown.log_rotate_bytes == ssd.log_rotate_bytes &&
        unknown.compact_ratio_pct == ssd.compact_ratio_pct);
    SPC("unknown still reports unknown",
        unknown.klass == PLATFORM_STORAGE_CLASS_UNKNOWN);

    return failures;
}

/* ── forcing a class drives the published pacing ───────────────────── */

static int test_forced_class(void)
{
    int failures = 0;

    storage_pacing_force_class_for_testing(PLATFORM_STORAGE_CLASS_ROTATIONAL);
    SPC("forced rotational is published",
        storage_pacing_class() == PLATFORM_STORAGE_CLASS_ROTATIONAL);
    SPC("forced rotational publishes readahead",
        storage_pacing()->sequential_readahead);
    SPC("forced rotational names its source",
        strcmp(storage_pacing_source(), "forced") == 0);

    /* init() must not undo an explicit force, whatever the real disk is. */
    storage_pacing_init(".");
    SPC("init respects a forced class",
        storage_pacing_class() == PLATFORM_STORAGE_CLASS_ROTATIONAL);

    storage_pacing_force_class_for_testing(PLATFORM_STORAGE_CLASS_SOLID);
    SPC("forced solid is published",
        storage_pacing_class() == PLATFORM_STORAGE_CLASS_SOLID);
    SPC("forced solid drops readahead",
        !storage_pacing()->sequential_readahead);

    storage_pacing_force_class_for_testing(PLATFORM_STORAGE_CLASS_UNKNOWN);
    SPC("forced unknown is published",
        storage_pacing_class() == PLATFORM_STORAGE_CLASS_UNKNOWN);

    storage_pacing_reset_for_testing();
    return failures;
}

/* ── the resolution ordering ───────────────────────────────────────── */

static int test_override_wins(void)
{
    int failures = 0;

    storage_pacing_reset_for_testing();
    setenv("ZCL_STORAGE_CLASS", "rotational", 1);
    storage_pacing_init(".");
    SPC("ZCL_STORAGE_CLASS=rotational is honoured",
        storage_pacing_class() == PLATFORM_STORAGE_CLASS_ROTATIONAL);
    SPC("override names itself as the source",
        strcmp(storage_pacing_source(), "override") == 0);

    storage_pacing_reset_for_testing();
    setenv("ZCL_STORAGE_CLASS", "ssd", 1);
    storage_pacing_init(".");
    SPC("ZCL_STORAGE_CLASS=ssd is honoured",
        storage_pacing_class() == PLATFORM_STORAGE_CLASS_SOLID);

    /* A bound override is optional and independent of the class. */
    storage_pacing_reset_for_testing();
    setenv("ZCL_STORAGE_CLASS", "rotational", 1);
    setenv("ZCL_LOG_ROTATE_MB", "7", 1);
    storage_pacing_init(".");
    SPC("ZCL_LOG_ROTATE_MB overrides the compiled-in bound",
        storage_pacing()->log_rotate_bytes == 7LL * 1024 * 1024);
    unsetenv("ZCL_LOG_ROTATE_MB");

    /* Nonsense is ignored, never obeyed: an unparseable override must leave
     * the compiled-in number alone rather than zero a bound. */
    storage_pacing_reset_for_testing();
    setenv("ZCL_LOG_ROTATE_MB", "not-a-number", 1);
    storage_pacing_init(".");
    SPC("a malformed override leaves the compiled-in bound",
        storage_pacing()->log_rotate_bytes ==
            storage_pacing_for_class(PLATFORM_STORAGE_CLASS_ROTATIONAL)
                .log_rotate_bytes);
    unsetenv("ZCL_LOG_ROTATE_MB");
    unsetenv("ZCL_STORAGE_CLASS");
    storage_pacing_reset_for_testing();
    return failures;
}

/* ── the classification rule over a measured median ────────────────── */

static int test_class_from_median(void)
{
    int failures = 0;

    SPC("40us is solid state",
        platform_storage_class_from_median_us(40) ==
            PLATFORM_STORAGE_CLASS_SOLID);
    SPC("1999us is still solid state",
        platform_storage_class_from_median_us(1999) ==
            PLATFORM_STORAGE_CLASS_SOLID);
    SPC("2000us is a seek",
        platform_storage_class_from_median_us(2000) ==
            PLATFORM_STORAGE_CLASS_ROTATIONAL);
    SPC("9ms is a seek",
        platform_storage_class_from_median_us(9000) ==
            PLATFORM_STORAGE_CLASS_ROTATIONAL);
    SPC("a negative median is not a classification",
        platform_storage_class_from_median_us(-1) ==
            PLATFORM_STORAGE_CLASS_UNKNOWN);

    SPC("names round-trip",
        platform_storage_class_parse(platform_storage_class_name(
            PLATFORM_STORAGE_CLASS_ROTATIONAL)) ==
                PLATFORM_STORAGE_CLASS_ROTATIONAL &&
        platform_storage_class_parse(platform_storage_class_name(
            PLATFORM_STORAGE_CLASS_SOLID)) == PLATFORM_STORAGE_CLASS_SOLID);
    SPC("an unrecognised name is not a class",
        platform_storage_class_parse("auto") ==
            PLATFORM_STORAGE_CLASS_UNKNOWN &&
        platform_storage_class_parse(NULL) == PLATFORM_STORAGE_CLASS_UNKNOWN);
    return failures;
}

/* ── the probe itself ──────────────────────────────────────────────── */

static int test_probe_measures_and_refuses(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "storage_probe", "measure");

    int64_t median = -1;
    /* Nothing in the directory yet: the honest answer is "nothing measured",
     * NOT a plausible-looking number. */
    SPC("an empty directory yields no measurement",
        !platform_storage_random_read_median_us(dir, 16, 4096, 4096 * 16,
                                                &median));

    /* A file below the floor must not be measured either — a small file is
     * all page cache and would report every disk as flash. */
    char small[600];
    snprintf(small, sizeof(small), "%s/small.bin", dir);
    FILE *f = fopen(small, "wb");
    if (f) {
        char block[4096];
        memset(block, 0x5a, sizeof(block));
        for (int i = 0; i < 4; i++)
            fwrite(block, 1, sizeof(block), f);
        fclose(f);
    }
    SPC("a file under the floor is refused",
        !platform_storage_random_read_median_us(dir, 16, 4096,
                                                1024 * 1024, &median));

    /* A file above the floor is measured. Only the SHAPE of the answer is
     * asserted: the value depends on the test host's disk and cache, and a
     * test that pinned it would be testing the host, not the code. */
    char big[600];
    snprintf(big, sizeof(big), "%s/big.bin", dir);
    f = fopen(big, "wb");
    bool wrote = false;
    if (f) {
        char block[4096];
        memset(block, 0x5a, sizeof(block));
        wrote = true;
        for (int i = 0; i < 512 && wrote; i++)
            wrote = fwrite(block, 1, sizeof(block), f) == sizeof(block);
        fclose(f);
    }
    if (wrote) {
        median = -1;
        bool ok = platform_storage_random_read_median_us(dir, 32, 4096,
                                                         1024 * 1024, &median);
        SPC("a large enough file is measured", ok);
        SPC("the median is a non-negative latency", !ok || median >= 0);
        SPC("the median classifies without crashing",
            !ok || platform_storage_class_from_median_us(median) !=
                       PLATFORM_STORAGE_CLASS_UNKNOWN);
    } else {
        SPC("fixture file written", false);
    }

    SPC("a NULL directory is refused",
        !platform_storage_random_read_median_us(NULL, 32, 4096, 4096, &median));
    SPC("a NULL out parameter is refused",
        !platform_storage_random_read_median_us(dir, 32, 4096, 4096, NULL));

    test_rm_rf_recursive(dir);
    return failures;
}

/* ── the maintenance token ─────────────────────────────────────────── */

static int test_maintenance_token(void)
{
    int failures = 0;

    /* On solid state the token is free: no lock, no gap, no cost to the
     * callers that take it unconditionally. */
    storage_pacing_force_class_for_testing(PLATFORM_STORAGE_CLASS_SOLID);
    int64_t t0 = platform_time_monotonic_ms();
    for (int i = 0; i < 4; i++) {
        SPC("solid maintenance token is granted",
            storage_pacing_maintenance_begin());
        storage_pacing_maintenance_end();
    }
    SPC("solid maintenance costs no wall time",
        platform_time_monotonic_ms() - t0 < 100);

    /* On a spinning disk the SECOND writer waits out the gap rather than
     * queueing behind the first one's head movement. */
    setenv("ZCL_MAINTENANCE_GAP_MS", "40", 1);
    storage_pacing_force_class_for_testing(PLATFORM_STORAGE_CLASS_ROTATIONAL);
    SPC("the gap override is applied",
        storage_pacing()->maintenance_gap_ms == 40);
    SPC("first rotational token is granted",
        storage_pacing_maintenance_begin());
    storage_pacing_maintenance_end();
    t0 = platform_time_monotonic_ms();
    SPC("second rotational token is granted",
        storage_pacing_maintenance_begin());
    int64_t waited = platform_time_monotonic_ms() - t0;
    storage_pacing_maintenance_end();
    SPC("the second writer waited out the idle gap", waited >= 30);
    unsetenv("ZCL_MAINTENANCE_GAP_MS");

    storage_pacing_reset_for_testing();
    return failures;
}

/* ── the typed status surface ──────────────────────────────────────── */

static int test_dump_state(void)
{
    int failures = 0;
    storage_pacing_force_class_for_testing(PLATFORM_STORAGE_CLASS_ROTATIONAL);

    struct json_value v;
    json_init(&v);
    SPC("dump_state_json succeeds", storage_pacing_dump_state_json(&v, NULL));

    const struct json_value *klass = json_get(&v, "class");
    const struct json_value *source = json_get(&v, "source");
    const struct json_value *wal = json_get(&v, "wal_truncate_bytes");
    const struct json_value *rot = json_get(&v, "log_rotate_bytes");
    SPC("status names the class",
        klass && json_get_str(klass) &&
            strcmp(json_get_str(klass), "rotational") == 0);
    SPC("status names the source",
        source && json_get_str(source) &&
            strcmp(json_get_str(source), "forced") == 0);
    SPC("status publishes the WAL bound", wal && json_get_int(wal) > 0);
    SPC("status publishes the rotation bound", rot && json_get_int(rot) > 0);

    char buf[1024];
    SPC("status serialises", json_write(&v, buf, sizeof(buf)) > 0);
    json_free(&v);

    SPC("dump_state_json refuses a NULL sink",
        !storage_pacing_dump_state_json(NULL, NULL));

    storage_pacing_reset_for_testing();
    return failures;
}

/* ── size-bounded log rotation (util/log_rotate.h) ─────────────────── */

static bool spc_write_file(const char *path, size_t bytes, char fill)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    char block[4096];
    memset(block, fill, sizeof(block));
    size_t left = bytes;
    bool ok = true;
    while (ok && left > 0) {
        size_t want = left > sizeof(block) ? sizeof(block) : left;
        ok = fwrite(block, 1, want, f) == want;
        left -= want;
    }
    fclose(f);
    return ok;
}

static int64_t spc_size(const char *path)
{
    return log_rotate_file_size(path);
}

static int test_log_rotation(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "log_rotate", "bound");

    char log[600], previous[640];
    snprintf(log, sizeof(log), "%s/fake.log", dir);
    snprintf(previous, sizeof(previous), "%s/fake.log.1", dir);

    SPC("a missing log is not rotated", !log_rotate_if_over(log, 4096, NULL));

    /* Under the bound: untouched, and NO previous generation is created —
     * a rotation that fires early would throw away live log lines. */
    SPC("fixture under the bound written", spc_write_file(log, 8192, 'a'));
    SPC("an under-bound log is left alone",
        !log_rotate_if_over(log, 64 * 1024, NULL));
    SPC("an under-bound log keeps its bytes", spc_size(log) == 8192);
    SPC("no previous generation is invented", spc_size(previous) < 0);

    /* Over the bound: the log is emptied and its contents survive at .1. */
    SPC("fixture over the bound written", spc_write_file(log, 200 * 1024, 'b'));
    int64_t rotated = -1;
    SPC("an over-bound log is rotated",
        log_rotate_if_over(log, 64 * 1024, &rotated));
    SPC("the rotation reports what it retired", rotated == 200 * 1024);
    SPC("the log is empty afterwards", spc_size(log) == 0);
    SPC("the previous generation holds the retired bytes",
        spc_size(previous) == 200 * 1024);

    /* The bound holds across rounds. The first implementation of this used
     * an exclusive create for the ".1" file, which silently refused from the
     * SECOND rotation onward and left the log unbounded for the rest of the
     * process's life — so the second round is the case worth pinning. */
    SPC("second round fixture written", spc_write_file(log, 300 * 1024, 'c'));
    SPC("a second rotation also fires",
        log_rotate_if_over(log, 64 * 1024, NULL));
    SPC("the log is empty after the second round", spc_size(log) == 0);
    SPC("the previous generation was REPLACED, not appended",
        spc_size(previous) == 300 * 1024);

    /* Only ONE previous generation is ever kept. */
    char older[640];
    snprintf(older, sizeof(older), "%s/fake.log.2", dir);
    SPC("no second-previous generation accumulates", spc_size(older) < 0);

    SPC("a non-positive bound disables rotation",
        !log_rotate_if_over(log, 0, NULL) &&
        !log_rotate_if_over(log, -1, NULL));
    SPC("a NULL path is refused", !log_rotate_if_over(NULL, 4096, NULL));

    test_rm_rf_recursive(dir);
    return failures;
}

/* ── the projection store's compaction bound ───────────────────────── */

/* PURE predicate, so the bound that decides whether a 2.9 GB progress.kv
 * gets compacted is pinned here without a database. */
static int test_projection_bound(void)
{
    int failures = 0;
    const int64_t MB = 1024 * 1024;

    struct projection_store_usage small_and_wasteful = {
        .page_size = 4096, .page_count = 1024, .free_pages = 1000,
        .file_bytes = 4 * MB, .live_bytes = 96 * 1024, .free_bytes = 4 * MB,
    };
    struct projection_store_usage big_and_dense = {
        .page_size = 4096, .page_count = 262144, .free_pages = 1024,
        .file_bytes = 1024 * MB, .live_bytes = 1020 * MB, .free_bytes = 4 * MB,
    };
    struct projection_store_usage big_and_wasteful = {
        .page_size = 4096, .page_count = 745472, .free_pages = 600000,
        .file_bytes = 2874 * MB, .live_bytes = 400 * MB,
        .free_bytes = 2474 * MB,
    };
    struct projection_store_usage unmeasured = {
        .file_bytes = -1, .live_bytes = -1, .free_bytes = -1,
    };

    /* A small store is mostly free space almost all the time. Compacting it
     * would be a rewrite every tick and would buy back four megabytes. */
    SPC("a small wasteful store is under the bound",
        !projection_store_over_bound(&small_and_wasteful, 64 * MB, 250));
    /* A big store that is actually full has nothing to give back. */
    SPC("a big dense store is under the bound",
        !projection_store_over_bound(&big_and_dense, 64 * MB, 250));
    /* The field case: 2,874 MB of file over 400 MB of live data. */
    SPC("the field case is over the bound",
        projection_store_over_bound(&big_and_wasteful, 64 * MB, 250));
    /* Same file, looser ratio — still over, because 7x is over any ratio a
     * sane policy would set. */
    SPC("the field case is over even a loose ratio",
        projection_store_over_bound(&big_and_wasteful, 256 * MB, 400));

    SPC("an unmeasured usage is never over the bound",
        !projection_store_over_bound(&unmeasured, 64 * MB, 250));
    SPC("a NULL usage is never over the bound",
        !projection_store_over_bound(NULL, 64 * MB, 250));
    SPC("a nonsense ratio never triggers a rewrite",
        !projection_store_over_bound(&big_and_wasteful, 64 * MB, 100) &&
        !projection_store_over_bound(&big_and_wasteful, 64 * MB, 0));
    SPC("a non-positive floor never triggers a rewrite",
        !projection_store_over_bound(&big_and_wasteful, 0, 250));

    /* Above the floor, a store with NO live data at all is the clearest
     * possible case for compaction and must not fall through the ratio
     * arithmetic (which would divide the decision by zero live bytes). */
    struct projection_store_usage big_and_empty = {
        .page_size = 4096, .file_bytes = 512 * MB, .live_bytes = 0,
        .free_bytes = 512 * MB,
    };
    SPC("a big empty store is over the bound",
        projection_store_over_bound(&big_and_empty, 64 * MB, 250));

    /* The pacing table must actually select bounds this predicate acts on:
     * the field case has to be over the ROTATIONAL bound. */
    struct storage_pacing hdd =
        storage_pacing_for_class(PLATFORM_STORAGE_CLASS_ROTATIONAL);
    SPC("the rotational pacing would compact the field case",
        projection_store_over_bound(&big_and_wasteful, hdd.compact_floor_bytes,
                                    hdd.compact_ratio_pct));
    return failures;
}

int test_storage_pacing(void)

{
    int failures = 0;
    printf("\n=== storage_pacing tests ===\n");
    failures += test_pacing_per_class();
    failures += test_forced_class();
    failures += test_override_wins();
    failures += test_class_from_median();
    failures += test_probe_measures_and_refuses();
    failures += test_maintenance_token();
    failures += test_dump_state();
    failures += test_log_rotation();
    failures += test_projection_bound();
    if (failures == 0)
        printf("=== storage_pacing tests: ALL PASS ===\n");
    else
        printf("=== storage_pacing tests: %d FAILURES ===\n", failures);
    return failures;
}

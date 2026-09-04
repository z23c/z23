/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the hardware bench organ (platform/modules/util/src/hw_bench.c).
 *
 * Coverage:
 *   - derived-tunable formulas (hw_bench_batch_size, hw_bench_verify_workers)
 *     via the test-only measurement setter: monotonicity, clamps, and the
 *     unmeasured-passthrough fallback — deterministic, no real I/O timing.
 *   - end-to-end probe + flat-file cache round trip against a /tmp fixture
 *     datadir (NEVER a real host datadir): first init measures-or-skips and
 *     (when anything measured) persists a cache; a second init on the SAME
 *     fixture loads that cache instead of re-probing.
 *   - fingerprint invalidation: corrupting the cached fingerprint forces a
 *     re-probe on the next init instead of trusting stale numbers.
 *   - dump_state_json: well-formed, every documented key present.
 */

#include "test/test_core.h"
#include "util/hw_bench.h"
#include "util/hw_profile.h"
#include "json/json.h"
#include "platform/device_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define HWB_CHECK(name, expr) do { \
    printf("hw_bench: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Plant a >=128KiB regular file in `dir` so bench_pread has something to
 * sample from. Returns true on success. */
static bool hwb_plant_sample_file(const char *dir)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/sample.dat", dir);
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return false;
    char buf[4096];
    memset(buf, 0x42, sizeof(buf));
    bool ok = true;
    for (int i = 0; i < 40; i++) { /* 40*4096 = 160 KiB, above the 128 KiB floor */
        if (write(fd, buf, sizeof(buf)) != (ssize_t)sizeof(buf)) { ok = false; break; }
    }
    close(fd);
    return ok;
}

/* Rewrite the "fingerprint=" line of a cache file so the next load sees a
 * mismatch (forcing a re-probe) without touching any other field. */
static bool hwb_corrupt_cache_fingerprint(const char *cache_path)
{
    FILE *in = fopen(cache_path, "r");
    if (!in) return false;
    char lines[8][256];
    int n = 0;
    while (n < 8 && fgets(lines[n], sizeof(lines[n]), in)) n++;
    fclose(in);

    FILE *out = fopen(cache_path, "w");
    if (!out) return false;
    for (int i = 0; i < n; i++) {
        if (strncmp(lines[i], "fingerprint=", 12) == 0) {
            fprintf(out, "fingerprint=deadbeefdeadbeef\n");
        } else {
            fputs(lines[i], out);
        }
    }
    fclose(out);
    return true;
}

/* ── fixture helpers for the hw_profile-poisoning regression below ──── */

static bool hwb_mkdir_p(const char *path)
{
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", path);
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(buf, 0700);
            *p = '/';
        }
    }
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
}

static bool hwb_write_file(const char *path, const char *contents)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    bool ok = fputs(contents, f) >= 0;
    fclose(f);
    return ok;
}

/* Plants root/devices/fakehdd/block/sdfake/queue/rotational=1 (HDD-shaped:
 * no partition indirection), then symlinks root/dev/block/<maj>:<min> at it.
 * Mirrors hwp_plant_hdd_wholedisk() in test_hw_profile.c (duplicated rather
 * than shared: one small fixture, no cross-test-file dependency). */
static void hwb_plant_hdd_wholedisk(const char *root, unsigned maj,
                                    unsigned min)
{
    char dir[512], path[600], link[600];
    snprintf(dir, sizeof(dir), "%s/devices/fakehdd/block/sdfake/queue", root);
    hwb_mkdir_p(dir);
    snprintf(path, sizeof(path), "%s/rotational", dir);
    hwb_write_file(path, "1\n");
    snprintf(link, sizeof(link), "%s/dev/block/%u:%u", root, maj, min);
    unlink(link);
    symlink("../../devices/fakehdd/block/sdfake", link);
}

int test_hw_bench(void)
{
    int failures = 0;

    /* ── derived-tunable formulas (deterministic, via the test setter) ── */
    {
        hw_bench_reset_for_testing();
        hw_bench_set_measured_for_testing(-1, -1);
        HWB_CHECK("unmeasured fsync: batch_size passthrough",
                  hw_bench_batch_size(100) == 100);
        HWB_CHECK("unmeasured pread: verify_workers passthrough",
                  hw_bench_verify_workers(4) == 4);
        HWB_CHECK("unmeasured: hw_bench_measured() is false",
                  !hw_bench_measured());

        hw_bench_reset_for_testing();
        hw_bench_set_measured_for_testing(500 /* fast, below baseline */, 50);
        HWB_CHECK("fast fsync (below baseline): batch_size unchanged",
                  hw_bench_batch_size(100) == 100);
        HWB_CHECK("fast pread (below baseline): verify_workers unchanged",
                  hw_bench_verify_workers(4) == 4);
        HWB_CHECK("fast measurement: hw_bench_measured() is true",
                  hw_bench_measured());

        hw_bench_reset_for_testing();
        hw_bench_set_measured_for_testing(4000 /* 2x baseline */, 400 /* 2x baseline */);
        int b2 = hw_bench_batch_size(100);
        int w2 = hw_bench_verify_workers(4);
        HWB_CHECK("2x-baseline fsync: batch_size scales up",
                  b2 > 100 && b2 <= 2000);
        HWB_CHECK("2x-baseline pread: verify_workers scales down",
                  w2 < 4 && w2 >= 1);

        hw_bench_reset_for_testing();
        hw_bench_set_measured_for_testing(40000 /* 20x baseline: slow HDD */, 4000);
        int b3 = hw_bench_batch_size(100);
        int w3 = hw_bench_verify_workers(4);
        HWB_CHECK("very slow fsync: batch_size never exceeds ceiling",
                  b3 == 2000);
        HWB_CHECK("very slow pread: verify_workers never below 1",
                  w3 == 1);
        HWB_CHECK("batch_size monotone: 2x <= 20x", b2 <= b3);
        HWB_CHECK("verify_workers monotone (non-increasing): 2x >= 20x", w2 >= w3);

        hw_bench_reset_for_testing();
        hw_bench_set_measured_for_testing(-1, 400 /* pread measured, fsync not */);
        HWB_CHECK("fsync unmeasured alone still passes through batch_size",
                  hw_bench_batch_size(100) == 100);
        HWB_CHECK("pread measured alone still scales verify_workers",
                  hw_bench_verify_workers(4) < 4);

        HWB_CHECK("floor clamp: normal_batch<=0 treated as 1",
                  hw_bench_batch_size(0) >= 1);
        HWB_CHECK("floor clamp: normal_workers<=0 treated as 1",
                  hw_bench_verify_workers(0) >= 1);
    }

    /* ── regression test: hw_bench_batch_size() must NEVER trigger the
     * probe (the hot-path-fsync-under-a-held-mutex defect this file's
     * boot-time-init split fixes — see reducer_drain.c's
     * reducer_drain_to_convergence). With NO cache on disk and NO prior
     * hw_bench_init() call, hw_bench_batch_size/verify_workers must return
     * the topology fallback immediately, without running a single probe
     * pass; only an EXPLICIT hw_bench_init() call may run the probe, and
     * exactly once. ─────────────────────────────────────────────────── */
    {
        hw_bench_reset_for_testing();
        int probes0 = hw_bench_probe_run_count_for_testing();

        HWB_CHECK("no init yet: batch_size returns fallback",
                  hw_bench_batch_size(100) == 100);
        HWB_CHECK("no init yet: verify_workers returns fallback",
                  hw_bench_verify_workers(4) == 4);
        HWB_CHECK("no init yet: hw_bench_measured() is false",
                  !hw_bench_measured());
        HWB_CHECK("no init yet: hw_bench_fsync_us() is -1",
                  hw_bench_fsync_us() == -1);
        HWB_CHECK("no init yet: hw_bench_pread_us() is -1",
                  hw_bench_pread_us() == -1);
        HWB_CHECK("querying batch_size/verify_workers/fsync/pread/measured "
                  "with no init did NOT run the probe",
                  hw_bench_probe_run_count_for_testing() == probes0);

        char tmpl3[] = "/tmp/zcl_hwb_noprobeXXXXXX";
        char *root3 = mkdtemp(tmpl3);
        HWB_CHECK("probe-count fixture mkdtemp succeeds", root3 != NULL);
        if (root3) {
            HWB_CHECK("sample file planted (probe-count fixture)",
                      hwb_plant_sample_file(root3));

            /* Explicit init — like boot.c's boot-time call or
             * bg_validation_init's own-service call — is the ONLY thing
             * allowed to run the probe, and runs it exactly once. */
            HWB_CHECK("explicit hw_bench_init runs the probe",
                      hw_bench_init(root3));
            HWB_CHECK("hw_bench_init ran the probe exactly once",
                      hw_bench_probe_run_count_for_testing() == probes0 + 1);

            int probes1 = hw_bench_probe_run_count_for_testing();
            (void)hw_bench_batch_size(100);
            (void)hw_bench_verify_workers(4);
            (void)hw_bench_fsync_us();
            (void)hw_bench_measured();
            HWB_CHECK("post-init queries serve the cached measurement "
                      "without re-probing",
                      hw_bench_probe_run_count_for_testing() == probes1);

            /* A second explicit hw_bench_init() call after reset, on the
             * SAME fixture (same fingerprint), loads the on-disk cache
             * instead of re-probing — but only if the first probe actually
             * measured something to cache (a real filesystem, not a mock;
             * total measurement failure is a rare environment-dependent
             * skip, same guard the round-trip test below uses). */
            bool measured3 = hw_bench_measured();
            hw_bench_reset_for_testing();
            HWB_CHECK("second explicit init on same fixture returns true",
                      hw_bench_init(root3));
            if (measured3) {
                HWB_CHECK("second init loaded from cache, not another probe",
                          hw_bench_probe_run_count_for_testing() == probes1);
            }
        }
        hw_bench_reset_for_testing();
    }

    /* ── end-to-end probe + cache round trip on a /tmp fixture ─────────
     * NEVER a real host datadir — a fresh mkdtemp() fixture every time. */
    {
        char tmpl[] = "/tmp/zcl_hwb_fixtureXXXXXX";
        char *root = mkdtemp(tmpl);
        HWB_CHECK("fixture mkdtemp succeeds", root != NULL);
        if (root) {
            HWB_CHECK("sample file planted", hwb_plant_sample_file(root));

            hw_bench_reset_for_testing();
            HWB_CHECK("first init on fixture returns true",
                      hw_bench_init(root));
            bool measured_first = hw_bench_measured();
            bool from_cache_first = hw_bench_from_cache();
            HWB_CHECK("first init on a writable+populated fixture is NOT "
                      "from cache", !from_cache_first);
            /* A writable /tmp fixture with a real sample file should
             * measure at least one of the two latencies; this is a real
             * filesystem, not a mock, so treat total failure as a (rare,
             * environment-dependent) skip rather than a hard failure. */
            if (measured_first) {
                const char *fp1 = hw_bench_fingerprint_hex();
                HWB_CHECK("fingerprint is 16 hex chars",
                          fp1 && strlen(fp1) == 16);

                char cache_path[700];
                snprintf(cache_path, sizeof(cache_path), "%s/hw_bench.kv", root);
                struct stat cst;
                HWB_CHECK("cache file was written after a measured probe",
                          stat(cache_path, &cst) == 0);

                /* Second init on the SAME fixture (same fingerprint) must
                 * load the cache instead of re-probing. */
                hw_bench_reset_for_testing();
                HWB_CHECK("second init on same fixture returns true",
                          hw_bench_init(root));
                HWB_CHECK("second init loaded from cache",
                          hw_bench_from_cache());
                HWB_CHECK("second init fingerprint matches the first",
                          strcmp(hw_bench_fingerprint_hex(), fp1) == 0);

                /* Fingerprint invalidation: corrupt the cached fingerprint,
                 * reset, init again -> must NOT trust the stale cache. */
                HWB_CHECK("corrupt cached fingerprint",
                          hwb_corrupt_cache_fingerprint(cache_path));
                hw_bench_reset_for_testing();
                HWB_CHECK("init after fingerprint corruption returns true",
                          hw_bench_init(root));
                HWB_CHECK("fingerprint mismatch forces a fresh probe "
                          "(not from cache)", !hw_bench_from_cache());
                HWB_CHECK("re-probed fingerprint is corrected back",
                          strcmp(hw_bench_fingerprint_hex(), fp1) == 0);
            }
        }
    }

    /* ── dump_state_json ─────────────────────────────────────────────── */
    {
        hw_bench_reset_for_testing();
        hw_bench_set_measured_for_testing(3000, 300);
        struct json_value v;
        json_init(&v);
        HWB_CHECK("dump_state_json succeeds", hw_bench_dump_state_json(&v, NULL));
        HWB_CHECK("dump has fsync_us",
                  json_get(&v, "fsync_us") &&
                  json_get_int(json_get(&v, "fsync_us")) == 3000);
        HWB_CHECK("dump has pread_us",
                  json_get(&v, "pread_us") &&
                  json_get_int(json_get(&v, "pread_us")) == 300);
        HWB_CHECK("dump has fsync_source == measured",
                  json_get(&v, "fsync_source") &&
                  strcmp(json_get_str(json_get(&v, "fsync_source")), "measured") == 0);
        HWB_CHECK("dump has fingerprint", json_get(&v, "fingerprint") != NULL);
        HWB_CHECK("dump has from_cache", json_get(&v, "from_cache") != NULL);
        HWB_CHECK("dump has age_seconds", json_get(&v, "age_seconds") != NULL);
        HWB_CHECK("dump has measured == true",
                  json_get(&v, "measured") &&
                  json_get_bool(json_get(&v, "measured")));
        HWB_CHECK("dump has derived object", json_get(&v, "derived") != NULL);
        json_free(&v);

        hw_bench_reset_for_testing();
        hw_bench_set_measured_for_testing(-1, -1);
        struct json_value v2;
        json_init(&v2);
        HWB_CHECK("dump_state_json succeeds when unmeasured",
                  hw_bench_dump_state_json(&v2, NULL));
        HWB_CHECK("dump has measured == false when unmeasured",
                  json_get(&v2, "measured") &&
                  !json_get_bool(json_get(&v2, "measured")));
        HWB_CHECK("dump has fsync_source == fallback when unmeasured",
                  json_get(&v2, "fsync_source") &&
                  strcmp(json_get_str(json_get(&v2, "fsync_source")), "fallback") == 0);
        json_free(&v2);
    }

    /* ── regression: hw_bench_init() must not starve hw_profile's sysfs
     * rotational probe of the real datadir ──────────────────────────
     *
     * hw_profile_init() is a one-shot latch: whichever caller reaches it
     * FIRST decides rotational_known for the rest of the process. Before
     * this fix, hw_bench_init()'s internal fingerprint computation called
     * hw_profile_init(NULL) — and since hw_bench_init() runs very early in
     * boot (boot_datadir_lock_acquire, right before storage_pacing_init),
     * it always won that race. storage_pacing's own later
     * hw_profile_init(datadir) call became a silent no-op, so the sysfs
     * "queue/rotational" answer was permanently unknown and every box —
     * spinning disk included — fell through to the bench/probe fallback
     * classification instead of the direct, cheap sysfs one. Prove the
     * fix: hw_bench_init(datadir) must leave hw_profile with the REAL
     * datadir's rotational verdict, not NULL's. */
    {
        hw_bench_reset_for_testing();
        hw_profile_reset_for_testing();

        char tmpl[] = "/tmp/zcl_hwb_block_fixtureXXXXXX";
        char *root = mkdtemp(tmpl);
        HWB_CHECK("hw_profile-poisoning fixture mkdtemp succeeds",
                  root != NULL);
        if (root) {
            char datadir[600];
            snprintf(datadir, sizeof(datadir), "%s/test_datadir", root);
            hwb_mkdir_p(datadir);
            HWB_CHECK("hw_profile-poisoning fixture has a sample file",
                      hwb_plant_sample_file(datadir));

            struct stat st;
            bool have_stat = stat(datadir, &st) == 0;
            HWB_CHECK("hw_profile-poisoning fixture datadir stat() OK",
                      have_stat);
            if (have_stat) {
                unsigned maj = platform_device_major(st.st_dev);
                unsigned min = platform_device_minor(st.st_dev);
                char block_root[600];
                snprintf(block_root, sizeof(block_root), "%s/blockroot", root);
                char dev_block_dir[700];
                snprintf(dev_block_dir, sizeof(dev_block_dir), "%s/dev/block",
                         block_root);
                hwb_mkdir_p(dev_block_dir);
                hw_profile_set_block_root_for_testing(dev_block_dir);
                hwb_plant_hdd_wholedisk(block_root, maj, min);

                /* This is the exact call order boot_datadir_lock_acquire()
                 * uses: hw_bench_init(datadir) first, nothing having
                 * touched hw_profile before it. */
                hw_bench_init(datadir);

                bool known = false;
                bool rotational = hw_profile_datadir_rotational(&known);
                HWB_CHECK(
                    "hw_bench_init(datadir) leaves the sysfs verdict known",
                    known);
                HWB_CHECK(
                    "hw_bench_init(datadir) reports the FIXTURE's class "
                    "(rotational), not NULL's",
                    known && rotational);
            }
            hw_profile_set_block_root_for_testing(NULL);
        }

        hw_bench_reset_for_testing();
        hw_profile_reset_for_testing();
        hw_profile_init(NULL);
    }

    /* Leave a clean slate for any test running after this one. */
    hw_bench_reset_for_testing();

    if (failures == 0)
        printf("=== hw_bench tests: ALL PASS ===\n\n");
    else
        printf("=== hw_bench tests: %d FAILURE(S) ===\n\n", failures);
    return failures;
}

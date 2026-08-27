/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the hardware profile organ (lib/util/src/hw_profile.c).
 *
 * Coverage:
 *   - init: probes sane non-zero values on THIS host (online/physical
 *     cores, ram_bytes, isa struct populated without crashing)
 *   - dump_state_json: well-formed, every documented key present
 *   - derived tunables are monotone (non-decreasing) as their input grows,
 *     and respect floor/ceiling clamps
 *   - asymmetric-L3 detection parses a SYNTHETIC sysfs fixture (two L3
 *     domains of different sizes) correctly, independent of whatever the
 *     real test host's topology happens to be
 *   - storage-rotational probe resolves a SYNTHETIC /sys/dev/block fixture
 *     (both the "partition -> walk up to parent" case and the
 *     "whole-disk, no partition marker" case), and degrades to
 *     known=false on a broken/missing symlink
 *   - pin_reducer_thread: false (advisory, no crash) on a symmetric
 *     topology, true on the synthetic asymmetric fixture */

#include "test/test_core.h"
#include "util/hw_profile.h"
#include "util/cpu_topology.h"
#include "json/json.h"
#include "platform/device_compat.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define HWP_CHECK(name, expr) do { \
    printf("hw_profile: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Fixture helpers ──────────────────────────────────────────────── */

static bool hwp_mkdir_p(const char *path)
{
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", path);
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(buf, 0755); /* ignore EEXIST */
            *p = '/';
        }
    }
    return mkdir(buf, 0755) == 0 || errno == EEXIST;
}

static bool hwp_write_file(const char *path, const char *contents)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    fputs(contents, f);
    fclose(f);
    return true;
}

/* Builds a synthetic 4-cpu, 2-domain (asymmetric L3) sysfs tree under
 * `root`: cpu0/cpu1 share a 32 MiB L3 (domain 0), cpu2/cpu3 share a 64
 * MiB L3 (domain 1) — a miniature 7950X3D-shaped layout. */
static void hwp_build_l3_fixture(const char *root)
{
    struct { int cpu; int pkg; int core; const char *l3_size; const char *shared; } rows[] = {
        { 0, 0, 0, "32768K", "0-1" },
        { 1, 0, 1, "32768K", "0-1" },
        { 2, 0, 2, "65536K", "2-3" },
        { 3, 0, 3, "65536K", "2-3" },
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        char dir[512], path[600], val[32];
        snprintf(dir, sizeof(dir), "%s/cpu%d/topology", root, rows[i].cpu);
        hwp_mkdir_p(dir);
        snprintf(path, sizeof(path), "%s/physical_package_id", dir);
        snprintf(val, sizeof(val), "%d\n", rows[i].pkg);
        hwp_write_file(path, val);
        snprintf(path, sizeof(path), "%s/core_id", dir);
        snprintf(val, sizeof(val), "%d\n", rows[i].core);
        hwp_write_file(path, val);

        /* cpu_topology's find_l3_cache() walks index0..index15 looking for
         * level==3 and gives up (break) the first time an index dir is
         * missing past index0 — real kernels always have index0-2
         * (L1d/L1i/L2) ahead of the L3 entry, so plant harmless L1/L2
         * placeholders too or the scan never reaches our L3 entry. */
        for (int idx = 0; idx < 3; idx++) {
            snprintf(dir, sizeof(dir), "%s/cpu%d/cache/index%d", root,
                     rows[i].cpu, idx);
            hwp_mkdir_p(dir);
            snprintf(path, sizeof(path), "%s/level", dir);
            snprintf(val, sizeof(val), "%d\n", idx == 2 ? 2 : 1);
            hwp_write_file(path, val);
        }

        snprintf(dir, sizeof(dir), "%s/cpu%d/cache/index3", root, rows[i].cpu);
        hwp_mkdir_p(dir);
        snprintf(path, sizeof(path), "%s/level", dir);
        hwp_write_file(path, "3\n");
        snprintf(path, sizeof(path), "%s/size", dir);
        snprintf(val, sizeof(val), "%s\n", rows[i].l3_size);
        hwp_write_file(path, val);
        snprintf(path, sizeof(path), "%s/shared_cpu_list", dir);
        snprintf(val, sizeof(val), "%s\n", rows[i].shared);
        hwp_write_file(path, val);
    }
}

/* Plants root/devices/fakessd/block/nvmefake/nvmefakep1/partition +
 * .../nvmefake/queue/rotational=0 (SSD-shaped: partition marker present,
 * rotational lives one level up at the parent whole-disk dir), then
 * symlinks root/dev/block/<maj>:<min> at it. */
static void hwp_plant_ssd_partition(const char *root, unsigned maj,
                                    unsigned min)
{
    char dir[512], path[600], link[600];
    snprintf(dir, sizeof(dir), "%s/devices/fakessd/block/nvmefake/nvmefakep1",
             root);
    hwp_mkdir_p(dir);
    snprintf(path, sizeof(path), "%s/partition", dir);
    hwp_write_file(path, "1\n");
    snprintf(dir, sizeof(dir), "%s/devices/fakessd/block/nvmefake/queue",
             root);
    hwp_mkdir_p(dir);
    snprintf(path, sizeof(path), "%s/rotational", dir);
    hwp_write_file(path, "0\n");
    snprintf(link, sizeof(link), "%s/dev/block/%u:%u", root, maj, min);
    symlink("../../devices/fakessd/block/nvmefake/nvmefakep1", link);
}

/* Plants root/devices/fakehdd/block/sdfake/queue/rotational=1 (HDD-shaped:
 * no partition indirection, rotational lives directly in the device's own
 * dir), then symlinks root/dev/block/<maj>:<min> at it. Caller unlinks the
 * previous entry at the same maj:min first if reusing one real dev_t for
 * both the SSD and HDD case in sequence. */
static void hwp_plant_hdd_wholedisk(const char *root, unsigned maj,
                                    unsigned min)
{
    char dir[512], path[600], link[600];
    snprintf(dir, sizeof(dir), "%s/devices/fakehdd/block/sdfake/queue", root);
    hwp_mkdir_p(dir);
    snprintf(path, sizeof(path), "%s/rotational", dir);
    hwp_write_file(path, "1\n");
    snprintf(link, sizeof(link), "%s/dev/block/%u:%u", root, maj, min);
    unlink(link); /* drop a prior entry at this maj:min, if any */
    symlink("../../devices/fakehdd/block/sdfake", link);
}

int test_hw_profile(void)
{
    int failures = 0;

    /* ── real-host probe ─────────────────────────────────────────── */
    hw_profile_reset_for_testing();
    cpu_topology_reset_for_testing();
    cpu_topology_set_sysfs_root_for_testing(NULL);
    hw_profile_set_block_root_for_testing(NULL);

    HWP_CHECK("init succeeds", hw_profile_init(NULL));
    HWP_CHECK("init idempotent", hw_profile_init(NULL));

    int online = hw_profile_online_cores();
    int physical = hw_profile_physical_cores();
    int64_t ram = hw_profile_ram_bytes();

    HWP_CHECK("online_cores >= 1", online >= 1);
    HWP_CHECK("physical_cores >= 1", physical >= 1);
    HWP_CHECK("physical_cores <= online_cores", physical <= online);
    HWP_CHECK("ram_bytes > 0", ram > 0);

    const struct hw_profile_isa *isa = hw_profile_isa();
    HWP_CHECK("isa pointer non-NULL", isa != NULL);

    bool known = true;
    (void)hw_profile_datadir_rotational(&known);
    HWP_CHECK("datadir_rotational(NULL datadir) reports unknown", !known);

    /* ── dump_state_json ──────────────────────────────────────────── */
    {
        struct json_value v;
        json_init(&v);
        HWP_CHECK("dump_state_json succeeds", hw_profile_dump_state_json(&v, NULL));
        HWP_CHECK("dump has online_cores",
                  json_get(&v, "online_cores") &&
                  json_get_int(json_get(&v, "online_cores")) == online);
        HWP_CHECK("dump has physical_cores", json_get(&v, "physical_cores") != NULL);
        HWP_CHECK("dump has ram_bytes",
                  json_get(&v, "ram_bytes") &&
                  json_get_int(json_get(&v, "ram_bytes")) == ram);
        HWP_CHECK("dump has ram_class", json_get(&v, "ram_class") != NULL);
        HWP_CHECK("dump has isa object", json_get(&v, "isa") != NULL);
        const struct json_value *isa_dump = json_get(&v, "isa");
        HWP_CHECK("dump names active SHA-256 transform",
                  json_get(isa_dump, "sha256_transform") != NULL);
        HWP_CHECK("dump names active Equihash BLAKE2b batch tier",
                  json_get(isa_dump, "equihash_blake2b_batch") != NULL);
        HWP_CHECK("dump has storage object", json_get(&v, "storage") != NULL);
        HWP_CHECK("dump has l3 object", json_get(&v, "l3") != NULL);
        HWP_CHECK("dump has derived object", json_get(&v, "derived") != NULL);
        HWP_CHECK("dump has pin_reducer_available",
                  json_get(&v, "pin_reducer_available") != NULL);
        json_free(&v);
    }

    /* ── derived tunables: monotonicity + clamps ─────────────────── */
    {
        int64_t r1 = 1LL * 1024 * 1024 * 1024;    /* 1 GiB */
        int64_t r2 = 4LL * 1024 * 1024 * 1024;    /* 4 GiB */
        int64_t r3 = 16LL * 1024 * 1024 * 1024;   /* 16 GiB */
        int64_t r4 = 128LL * 1024 * 1024 * 1024;  /* 128 GiB */

        int64_t c1 = hw_profile_sqlite_cache_kib(r1, 0, 0);
        int64_t c2 = hw_profile_sqlite_cache_kib(r2, 0, 0);
        int64_t c3 = hw_profile_sqlite_cache_kib(r3, 0, 0);
        int64_t c4 = hw_profile_sqlite_cache_kib(r4, 0, 0);
        HWP_CHECK("sqlite_cache_kib monotone non-decreasing",
                  c1 <= c2 && c2 <= c3 && c3 <= c4);
        HWP_CHECK("sqlite_cache_kib respects default floor (16 MiB)",
                  hw_profile_sqlite_cache_kib(0, 0, 0) == 16 * 1024);
        HWP_CHECK("sqlite_cache_kib respects default ceiling (1 GiB)",
                  c4 == 1024 * 1024);
        HWP_CHECK("sqlite_cache_kib custom floor/ceiling clamps",
                  hw_profile_sqlite_cache_kib(r4, 8 * 1024, 32 * 1024) == 32 * 1024);

        int64_t m1 = hw_profile_sqlite_mmap_bytes(r1, 0, 0);
        int64_t m2 = hw_profile_sqlite_mmap_bytes(r2, 0, 0);
        int64_t m3 = hw_profile_sqlite_mmap_bytes(r3, 0, 0);
        int64_t m4 = hw_profile_sqlite_mmap_bytes(r4, 0, 0);
        HWP_CHECK("sqlite_mmap_bytes monotone non-decreasing",
                  m1 <= m2 && m2 <= m3 && m3 <= m4);
        HWP_CHECK("sqlite_mmap_bytes never exceeds a low caller ceiling "
                  "(the node.db 256 MiB landmine bound)",
                  hw_profile_sqlite_mmap_bytes(r4, 0, 256LL * 1024 * 1024) ==
                  256LL * 1024 * 1024);
        HWP_CHECK("sqlite_mmap_bytes(0 ram) == 0",
                  hw_profile_sqlite_mmap_bytes(0, 0, 0) == 0);

        int w1 = hw_profile_verify_workers(1);
        int w2 = hw_profile_verify_workers(4);
        int w3 = hw_profile_verify_workers(16);
        int w4 = hw_profile_verify_workers(64);
        HWP_CHECK("verify_workers monotone non-decreasing",
                  w1 <= w2 && w2 <= w3 && w3 <= w4);
        HWP_CHECK("verify_workers floor is 2", w1 == 2);
        HWP_CHECK("verify_workers ceiling is 4", w4 == 4);

        HWP_CHECK("script_batch_cap: low RAM (4 GiB) capped at 10000",
                  hw_profile_script_batch_cap(4LL * 1024 * 1024 * 1024) == 10000);
        HWP_CHECK("script_batch_cap: high RAM (16 GiB) unlimited",
                  hw_profile_script_batch_cap(16LL * 1024 * 1024 * 1024) == 0);
        HWP_CHECK("script_batch_cap: unknown RAM (0) unlimited",
                  hw_profile_script_batch_cap(0) == 0);

        HWP_CHECK("ram_class_of low", hw_profile_ram_class_of(4LL << 30) == HW_PROFILE_RAM_LOW);
        HWP_CHECK("ram_class_of medium", hw_profile_ram_class_of(16LL << 30) == HW_PROFILE_RAM_MEDIUM);
        HWP_CHECK("ram_class_of high", hw_profile_ram_class_of(64LL << 30) == HW_PROFILE_RAM_HIGH);

        /* ── K3 derived drain batch ──────────────────────────────── */
        int many_cores = 32; /* enough that RAM is the binding cap */
        int d1 = hw_profile_drain_batch(r1, many_cores, 1000);
        int d2 = hw_profile_drain_batch(r2, many_cores, 1000);
        int d3 = hw_profile_drain_batch(r3, many_cores, 1000);
        int d4 = hw_profile_drain_batch(r4, many_cores, 1000);
        HWP_CHECK("drain_batch monotone non-decreasing in RAM",
                  d1 <= d2 && d2 <= d3 && d3 <= d4);
        HWP_CHECK("drain_batch floor is the baseline (small/unknown host)",
                  hw_profile_drain_batch(0, many_cores, 1000) == 1000 &&
                  hw_profile_drain_batch(r4, 1 /*cores*/, 1000) == 1000);
        HWP_CHECK("drain_batch never below baseline floor", d1 >= 1000);
        HWP_CHECK("drain_batch ceiling is 8x baseline",
                  d4 == 8000 &&
                  hw_profile_drain_batch(1024LL << 30, many_cores, 1000) == 8000);
        HWP_CHECK("drain_batch honors the 100 baseline too (header path)",
                  hw_profile_drain_batch(0, many_cores, 100) == 100 &&
                  hw_profile_drain_batch(1024LL << 30, many_cores, 100) == 800);
        HWP_CHECK("drain_batch: cores cap the multiplier (4 cores -> 1x)",
                  hw_profile_drain_batch(1024LL << 30, 4, 1000) == 1000);

        /* Runtime gate: OFF by default -> baseline; ON -> derived. */
        HWP_CHECK("derive gate default OFF",
                  !hw_profile_derive_drain_batch_enabled());
        HWP_CHECK("effective returns baseline while gate OFF",
                  hw_profile_drain_batch_effective(1000) == 1000 &&
                  hw_profile_drain_batch_effective(100) == 100);
        hw_profile_set_derive_drain_batch(true);
        HWP_CHECK("derive gate reads back ON",
                  hw_profile_derive_drain_batch_enabled());
        HWP_CHECK("effective while ON is >= baseline (measured host)",
                  hw_profile_drain_batch_effective(1000) >= 1000 &&
                  hw_profile_drain_batch_effective(1000) <= 8000);
        hw_profile_set_derive_drain_batch(false); /* restore default */
        HWP_CHECK("effective returns baseline after gate restored OFF",
                  hw_profile_drain_batch_effective(1000) == 1000);
    }

    /* ── symmetric topology: no asymmetric CCD, pin is a no-op ─────── */
    {
        cpu_topology_reset_for_testing();
        cpu_topology_set_sysfs_root_for_testing(
            "/nonexistent/zcl_hw_profile_symmetric_fixture_12345");
        cpu_topology_init(); /* falls back to ONE synthetic domain */

        HWP_CHECK("symmetric/fallback topology is not asymmetric",
                  !hw_profile_l3_asymmetric());
        HWP_CHECK("symmetric topology has no large L3 domain",
                  hw_profile_large_l3_domain() == -1);
        HWP_CHECK("pin_reducer_thread returns false on symmetric topology",
                  !hw_profile_pin_reducer_thread(pthread_self()));
    }

    /* ── synthetic asymmetric-L3 fixture ─────────────────────────── */
    {
        char tmpl[] = "/tmp/zcl_hwp_l3_fixtureXXXXXX";
        char *root = mkdtemp(tmpl);
        HWP_CHECK("l3 fixture mkdtemp succeeds", root != NULL);
        if (root) {
            hwp_build_l3_fixture(root);
            cpu_topology_reset_for_testing();
            cpu_topology_set_sysfs_root_for_testing(root);
            HWP_CHECK("l3 fixture cpu_topology_init succeeds", cpu_topology_init());
            HWP_CHECK("l3 fixture: 4 logical cpus",
                      cpu_topology_logical_cpus() == 4);
            HWP_CHECK("l3 fixture: 2 L3 domains",
                      cpu_topology_l3_domains() == 2);
            HWP_CHECK("l3 fixture is detected asymmetric",
                      hw_profile_l3_asymmetric());

            int large = hw_profile_large_l3_domain();
            HWP_CHECK("l3 fixture large domain is valid", large >= 0);
            struct cpu_topology_domain snap;
            bool got = cpu_topology_domain_at(large, &snap);
            HWP_CHECK("l3 fixture large domain has the 64 MiB L3",
                      got && snap.l3_size_bytes == 65536LL * 1024);
            HWP_CHECK("l3 fixture large domain cpus are {2,3}",
                      got && snap.cpu_count == 2 &&
                      ((snap.cpus[0] == 2 && snap.cpus[1] == 3) ||
                       (snap.cpus[0] == 3 && snap.cpus[1] == 2)));

            HWP_CHECK("pin_reducer_thread succeeds on asymmetric fixture",
                      hw_profile_pin_reducer_thread(pthread_self()));
        }

        /* restore real topology for anything running after this test */
        cpu_topology_reset_for_testing();
        cpu_topology_set_sysfs_root_for_testing(NULL);
        cpu_topology_init();
    }

    /* ── synthetic storage-rotational fixture ────────────────────── */
    {
        char tmpl[] = "/tmp/zcl_hwp_block_fixtureXXXXXX";
        char *root = mkdtemp(tmpl);
        HWP_CHECK("block fixture mkdtemp succeeds", root != NULL);
        if (root) {
            /* The probe never calls stat() on a real block device here —
             * it only resolves the symlink named after whatever dev_t the
             * caller's datadir stat() produced. Drive it via ONE real
             * datadir's real maj:min (any two dirs under the same mkdtemp
             * root are near-certainly on the same filesystem/device, so
             * using two different datadirs would collide on the same
             * maj:min symlink name): plant the SSD-shaped target, probe,
             * then swap the same symlink to the HDD-shaped target and
             * probe again. */
            char datadir[600];
            snprintf(datadir, sizeof(datadir), "%s/test_datadir", root);
            hwp_mkdir_p(datadir);

            struct stat st;
            bool have_stat = stat(datadir, &st) == 0;
            HWP_CHECK("block fixture datadir stat() OK", have_stat);

            if (have_stat) {
                unsigned maj = platform_device_major(st.st_dev);
                unsigned min = platform_device_minor(st.st_dev);
                char block_root[600];
                snprintf(block_root, sizeof(block_root), "%s/blockroot", root);
                hwp_mkdir_p(block_root);
                char dev_block_dir[700];
                snprintf(dev_block_dir, sizeof(dev_block_dir), "%s/dev/block",
                         block_root);
                hwp_mkdir_p(dev_block_dir);
                hw_profile_set_block_root_for_testing(dev_block_dir);

                hwp_plant_ssd_partition(block_root, maj, min);
                hw_profile_reset_for_testing();
                hw_profile_init(datadir);
                bool ssd_known = false;
                bool ssd_rot = hw_profile_datadir_rotational(&ssd_known);
                HWP_CHECK("partition-shaped SSD fixture: probe succeeded",
                          ssd_known);
                HWP_CHECK("partition-shaped SSD fixture: rotational == false",
                          ssd_known && !ssd_rot);

                hwp_plant_hdd_wholedisk(block_root, maj, min);
                hw_profile_reset_for_testing();
                hw_profile_init(datadir);
                bool hdd_known = false;
                bool hdd_rot = hw_profile_datadir_rotational(&hdd_known);
                HWP_CHECK("whole-disk HDD fixture: probe succeeded", hdd_known);
                HWP_CHECK("whole-disk HDD fixture: rotational == true",
                          hdd_known && hdd_rot);
            }

            /* broken symlink case: a datadir whose maj:min has no entry
             * under the fixture block root at all -> known == false. */
            char orphan_datadir[600];
            snprintf(orphan_datadir, sizeof(orphan_datadir), "%s/orphan_datadir",
                     root);
            hwp_mkdir_p(orphan_datadir);
            char empty_block_root[600];
            snprintf(empty_block_root, sizeof(empty_block_root),
                     "%s/empty_blockroot/dev/block", root);
            hwp_mkdir_p(empty_block_root);
            hw_profile_set_block_root_for_testing(empty_block_root);
            hw_profile_reset_for_testing();
            hw_profile_init(orphan_datadir);
            bool orphan_known = true;
            hw_profile_datadir_rotational(&orphan_known);
            HWP_CHECK("missing block-device symlink degrades to known=false",
                      !orphan_known);
        }

        hw_profile_set_block_root_for_testing(NULL);
        hw_profile_reset_for_testing();
        hw_profile_init(NULL);
    }

    if (failures == 0) {
        printf("=== hw_profile tests: ALL PASS ===\n\n");
    } else {
        printf("=== hw_profile tests: %d FAILURE(S) ===\n\n", failures);
    }
    return failures;
}

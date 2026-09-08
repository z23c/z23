/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The eviction policy for abandoned ROM downloads
 * (engine/composition/src/rom_fetch_orphan_sweep.c).
 *
 * Every fixture here is named for what it represents, not indexed, because
 * the whole point of the sweep is WHICH pair it may touch:
 *
 *   an_orphaned_pair            no registered target, long idle  → removed
 *   a_fresh_pair                no registered target, just wrote → kept
 *   a_registered_targets_pair   idle, but its target is offered  → kept
 *   a_lone_part / a_lone_journal    not a pair at all            → untouched
 *
 * Deterministic with no clock injection and no sleeping: the "idle" fixtures
 * get an explicit absolute mtime far in the past via utimensat, so their age
 * is a property of the fixture rather than of how long the test took to run.
 * The scratch datadir comes from test_mkdtemp — never a real datadir. */

#include "test/test_core.h"

#include "config/rom_fetch_orphan_sweep.h"
#include "net/rom_fetch.h"
#include "net/rom_seed.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Bytes written into each fixture half — small, distinct, and above nothing
 * in particular: the sweep never reads a pair's contents. */
#define OS_PART_BYTES    600u
#define OS_JOURNAL_BYTES 120u

/* Far enough in the past that no plausible horizon covers it (2001-09-09). */
#define OS_ANCIENT_UNIX 1000000000

static bool os_write_bytes(const char *path, size_t n, uint8_t fill)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return false;
    uint8_t buf[1024];
    memset(buf, fill, sizeof(buf));
    size_t off = 0;
    while (off < n) {
        size_t want = n - off > sizeof(buf) ? sizeof(buf) : n - off;
        ssize_t w = write(fd, buf, want);
        if (w <= 0) { close(fd); return false; }
        off += (size_t)w;
    }
    close(fd);
    return true;
}

static bool os_exists(const char *dir, const char *name)
{
    char p[PATH_MAX];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    struct stat st;
    return stat(p, &st) == 0;
}

static bool os_size_is(const char *dir, const char *name, uint64_t want)
{
    char p[PATH_MAX];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    struct stat st;
    return stat(p, &st) == 0 && (uint64_t)st.st_size == want;
}

/* The `find <bundles> -name '*.part*'` measurement, taken by the test itself:
 * how many staging/journal files are on disk and what they cost. */
static void os_part_census(const char *dir, uint32_t *out_files,
                           uint64_t *out_bytes)
{
    *out_files = 0;
    *out_bytes = 0;
    DIR *d = opendir(dir);
    if (!d)
        return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!strstr(ent->d_name, ROM_FETCH_PART_SUFFIX))
            continue;
        char p[PATH_MAX];
        snprintf(p, sizeof(p), "%s/%s", dir, ent->d_name);
        struct stat st;
        if (stat(p, &st) != 0)
            continue;
        (*out_files)++;
        *out_bytes += (uint64_t)st.st_size;
    }
    closedir(d);
}

/* Stamp an absolute past mtime on a file so "idle" is a fixture property. */
static bool os_age(const char *dir, const char *name)
{
    char p[PATH_MAX];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    struct timespec ts[2];
    ts[0].tv_sec = OS_ANCIENT_UNIX;
    ts[0].tv_nsec = 0;
    ts[1] = ts[0];
    return utimensat(AT_FDCWD, p, ts, 0) == 0;
}

/* Write `<bundles>/<target>.part` + its journal. `aged` stamps both halves
 * with the ancient mtime; otherwise they keep the just-written stamp. */
static bool os_make_pair(const char *bundles, const char *target, bool aged)
{
    char part[PATH_MAX];
    char jrnl[PATH_MAX];
    char part_name[256];
    char jrnl_name[288];
    snprintf(part_name, sizeof(part_name), "%s%s", target,
             ROM_FETCH_PART_SUFFIX);
    snprintf(jrnl_name, sizeof(jrnl_name), "%s.journal", part_name);
    snprintf(part, sizeof(part), "%s/%s", bundles, part_name);
    snprintf(jrnl, sizeof(jrnl), "%s/%s", bundles, jrnl_name);
    if (!os_write_bytes(part, OS_PART_BYTES, 0xA1) ||
        !os_write_bytes(jrnl, OS_JOURNAL_BYTES, 0xB2))
        return false;
    if (!aged)
        return true;
    return os_age(bundles, part_name) && os_age(bundles, jrnl_name);
}

/* A minimal file the ROM registry will accept as a consensus-state bundle. */
static bool os_write_bundle(const char *bundles, const char *name)
{
    char p[PATH_MAX];
    snprintf(p, sizeof(p), "%s/%s", bundles, name);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return false;
    static const uint8_t magic[16] = "SQLite format 3";
    bool ok = write(fd, magic, sizeof(magic)) == (ssize_t)sizeof(magic) &&
              ftruncate(fd, 8192) == 0;
    close(fd);
    return ok;
}

/* ── (a) The whole policy on one fixture ──────────────────────────────── */

static int test_orphan_sweep_policy(void)
{
    int failures = 0;
    TEST("rom_fetch_orphan_sweep: removes only pairs that are BOTH "
         "unregistered and idle — a fresh pair, a registered target's pair, "
         "and a lone half are all left exactly as they were") {
        rom_seed_reset();

        char droot[PATH_MAX];
        char *dd = test_mkdtemp(droot, sizeof(droot), "zcl_romsweep_dd");
        ASSERT(dd != NULL);
        char bundles[PATH_MAX];
        snprintf(bundles, sizeof(bundles), "%s/%s", dd,
                 ROM_SEED_BUNDLES_SUBDIR);
        ASSERT(mkdir(bundles, 0700) == 0);

        /* Three downloads nobody will ever finish. */
        ASSERT(os_make_pair(bundles, "consensus-state-bundle-100.sqlite",
                            true));
        ASSERT(os_make_pair(bundles, "consensus-state-bundle-200.sqlite",
                            true));
        ASSERT(os_make_pair(bundles, "consensus-state-bundle-300.sqlite",
                            true));
        /* One download that just wrote a chunk. */
        ASSERT(os_make_pair(bundles, "consensus-state-bundle-400.sqlite",
                            false));
        /* One idle pair whose target IS still a registered artifact. */
        ASSERT(os_write_bundle(bundles, "consensus-state-bundle-500.sqlite"));
        ASSERT(rom_seed_register(dd,
                                 "bundles/consensus-state-bundle-500.sqlite",
                                 NULL, NULL) == ROM_REG_OK);
        ASSERT(os_make_pair(bundles, "consensus-state-bundle-500.sqlite",
                            true));
        /* Two halves that are not pairs: neither is this sweep's business. */
        char lone[PATH_MAX];
        snprintf(lone, sizeof(lone), "%s/consensus-state-bundle-600.sqlite%s",
                 bundles, ROM_FETCH_PART_SUFFIX);
        ASSERT(os_write_bytes(lone, OS_PART_BYTES, 0xC3));
        ASSERT(os_age(bundles, "consensus-state-bundle-600.sqlite.part"));
        snprintf(lone, sizeof(lone),
                 "%s/consensus-state-bundle-700.sqlite%s.journal", bundles,
                 ROM_FETCH_PART_SUFFIX);
        ASSERT(os_write_bytes(lone, OS_JOURNAL_BYTES, 0xD4));
        ASSERT(os_age(bundles,
                      "consensus-state-bundle-700.sqlite.part.journal"));

        /* BEFORE: five pairs' worth of halves plus the two lone files. */
        uint32_t files_before = 0;
        uint64_t bytes_before = 0;
        os_part_census(bundles, &files_before, &bytes_before);
        printf("\n  BEFORE: %u *.part* file(s), %llu bytes\n",
               (unsigned)files_before, (unsigned long long)bytes_before);
        ASSERT_EQ(files_before, 12u);
        ASSERT_EQ(bytes_before,
                  5ull * (OS_PART_BYTES + OS_JOURNAL_BYTES) +
                      OS_PART_BYTES + OS_JOURNAL_BYTES);

        struct rom_fetch_orphan_sweep_result r;
        ASSERT(rom_fetch_orphan_sweep_run(dd, 3600u, &r));

        uint32_t files_after = 0;
        uint64_t bytes_after = 0;
        os_part_census(bundles, &files_after, &bytes_after);
        printf("  AFTER:  %u *.part* file(s), %llu bytes "
               "(reclaimed %u file(s), %llu bytes)\n",
               (unsigned)files_after, (unsigned long long)bytes_after,
               (unsigned)(files_before - files_after),
               (unsigned long long)(bytes_before - bytes_after));
        ASSERT_EQ(files_after, 6u);
        ASSERT_EQ(bytes_before - bytes_after, r.bytes_reclaimed);

        /* Five pairs seen; the three orphans go, the other two stay. */
        ASSERT_EQ(r.pairs_seen, 5u);
        ASSERT_EQ(r.pairs_removed, 3u);
        ASSERT_EQ(r.pairs_kept, 2u);
        ASSERT_EQ(r.pairs_failed, 0u);
        ASSERT(!r.capped);
        ASSERT_EQ(r.bytes_reclaimed,
                  3ull * (OS_PART_BYTES + OS_JOURNAL_BYTES));

        /* BOTH halves of every removed pair are gone — never one alone. */
        ASSERT(!os_exists(bundles, "consensus-state-bundle-100.sqlite.part"));
        ASSERT(!os_exists(bundles,
                          "consensus-state-bundle-100.sqlite.part.journal"));
        ASSERT(!os_exists(bundles, "consensus-state-bundle-200.sqlite.part"));
        ASSERT(!os_exists(bundles,
                          "consensus-state-bundle-200.sqlite.part.journal"));
        ASSERT(!os_exists(bundles, "consensus-state-bundle-300.sqlite.part"));
        ASSERT(!os_exists(bundles,
                          "consensus-state-bundle-300.sqlite.part.journal"));

        /* The fresh download is untouched, to the byte. */
        ASSERT(os_size_is(bundles, "consensus-state-bundle-400.sqlite.part",
                          OS_PART_BYTES));
        ASSERT(os_size_is(bundles,
                          "consensus-state-bundle-400.sqlite.part.journal",
                          OS_JOURNAL_BYTES));
        /* So is the pair whose target is still offered. */
        ASSERT(os_size_is(bundles, "consensus-state-bundle-500.sqlite.part",
                          OS_PART_BYTES));
        ASSERT(os_size_is(bundles,
                          "consensus-state-bundle-500.sqlite.part.journal",
                          OS_JOURNAL_BYTES));
        /* And the registered bundle itself was never a candidate. */
        ASSERT(os_exists(bundles, "consensus-state-bundle-500.sqlite"));
        /* Neither lone half is a pair, so neither is swept. */
        ASSERT(os_size_is(bundles, "consensus-state-bundle-600.sqlite.part",
                          OS_PART_BYTES));
        ASSERT(os_size_is(bundles,
                          "consensus-state-bundle-700.sqlite.part.journal",
                          OS_JOURNAL_BYTES));

        rom_seed_reset();
        test_cleanup_tmpdir(bundles);
        test_cleanup_tmpdir(dd);
        PASS();
    } _test_next:;
    return failures;
}

/* ── (b) The horizon is what protects a live download ─────────────────── */

static int test_orphan_sweep_horizon_protects(void)
{
    int failures = 0;
    TEST("rom_fetch_orphan_sweep: the same unregistered idle pair is kept "
         "under a horizon wider than its age and removed under a narrower "
         "one — nothing else decides") {
        rom_seed_reset();

        char droot[PATH_MAX];
        char *dd = test_mkdtemp(droot, sizeof(droot), "zcl_romsweep_hz");
        ASSERT(dd != NULL);
        char bundles[PATH_MAX];
        snprintf(bundles, sizeof(bundles), "%s/%s", dd,
                 ROM_SEED_BUNDLES_SUBDIR);
        ASSERT(mkdir(bundles, 0700) == 0);
        ASSERT(os_make_pair(bundles, "consensus-state-bundle-900.sqlite",
                            false));

        /* Just-written: a horizon of one hour keeps it. */
        struct rom_fetch_orphan_sweep_result kept;
        ASSERT(rom_fetch_orphan_sweep_run(dd, 3600u, &kept));
        ASSERT_EQ(kept.pairs_seen, 1u);
        ASSERT_EQ(kept.pairs_removed, 0u);
        ASSERT_EQ(kept.pairs_kept, 1u);
        ASSERT(os_exists(bundles, "consensus-state-bundle-900.sqlite.part"));

        /* Age the very same pair; the very same call now reclaims it. */
        ASSERT(os_age(bundles, "consensus-state-bundle-900.sqlite.part"));
        ASSERT(os_age(bundles,
                      "consensus-state-bundle-900.sqlite.part.journal"));
        struct rom_fetch_orphan_sweep_result swept;
        ASSERT(rom_fetch_orphan_sweep_run(dd, 3600u, &swept));
        ASSERT_EQ(swept.pairs_seen, 1u);
        ASSERT_EQ(swept.pairs_removed, 1u);
        ASSERT_EQ(swept.pairs_kept, 0u);
        ASSERT_EQ(swept.bytes_reclaimed,
                  (uint64_t)(OS_PART_BYTES + OS_JOURNAL_BYTES));
        ASSERT(!os_exists(bundles, "consensus-state-bundle-900.sqlite.part"));
        ASSERT(!os_exists(bundles,
                          "consensus-state-bundle-900.sqlite.part.journal"));

        /* A second sweep over the emptied directory is a clean no-op. */
        struct rom_fetch_orphan_sweep_result again;
        ASSERT(rom_fetch_orphan_sweep_run(dd, 3600u, &again));
        ASSERT_EQ(again.pairs_seen, 0u);
        ASSERT_EQ(again.pairs_removed, 0u);

        rom_seed_reset();
        test_cleanup_tmpdir(bundles);
        test_cleanup_tmpdir(dd);
        PASS();
    } _test_next:;
    return failures;
}

/* ── (c) Nothing to sweep is a completed pass, not a failure ──────────── */

static int test_orphan_sweep_empty_datadir(void)
{
    int failures = 0;
    TEST("rom_fetch_orphan_sweep: a datadir with no bundles/ directory is a "
         "clean no-op, and a NULL datadir is refused") {
        char droot[PATH_MAX];
        char *dd = test_mkdtemp(droot, sizeof(droot), "zcl_romsweep_mt");
        ASSERT(dd != NULL);

        struct rom_fetch_orphan_sweep_result r;
        ASSERT(rom_fetch_orphan_sweep_run(dd, 3600u, &r));
        ASSERT_EQ(r.pairs_seen, 0u);
        ASSERT_EQ(r.pairs_removed, 0u);
        ASSERT_EQ(r.pairs_failed, 0u);

        /* No datadir means the sweep could not run at all. */
        struct rom_fetch_orphan_sweep_result none;
        ASSERT(!rom_fetch_orphan_sweep_run(NULL, 3600u, &none));
        ASSERT_EQ(none.pairs_seen, 0u);
        ASSERT(!rom_fetch_orphan_sweep_run("", 3600u, NULL));

        test_cleanup_tmpdir(dd);
        PASS();
    } _test_next:;
    return failures;
}

/* ── (d) A typo in the horizon must not shorten it ────────────────────── */

static int test_orphan_sweep_horizon_flag(void)
{
    int failures = 0;
    TEST("rom_fetch_orphan_sweep: ZCL_ROM_FETCH_ORPHAN_HORIZON_SEC sets the "
         "horizon, and a zero/negative/malformed value is ignored rather "
         "than obeyed") {
        (void)unsetenv("ZCL_ROM_FETCH_ORPHAN_HORIZON_SEC");
        ASSERT_EQ(rom_fetch_orphan_sweep_horizon_sec(),
                  (uint32_t)ROM_FETCH_ORPHAN_HORIZON_SEC_DEFAULT);

        ASSERT(setenv("ZCL_ROM_FETCH_ORPHAN_HORIZON_SEC", "900", 1) == 0);
        ASSERT_EQ(rom_fetch_orphan_sweep_horizon_sec(), 900u);

        /* Zero would put every live download in reach — refuse it. */
        ASSERT(setenv("ZCL_ROM_FETCH_ORPHAN_HORIZON_SEC", "0", 1) == 0);
        ASSERT_EQ(rom_fetch_orphan_sweep_horizon_sec(),
                  (uint32_t)ROM_FETCH_ORPHAN_HORIZON_SEC_DEFAULT);
        ASSERT(setenv("ZCL_ROM_FETCH_ORPHAN_HORIZON_SEC", "-1", 1) == 0);
        ASSERT_EQ(rom_fetch_orphan_sweep_horizon_sec(),
                  (uint32_t)ROM_FETCH_ORPHAN_HORIZON_SEC_DEFAULT);
        ASSERT(setenv("ZCL_ROM_FETCH_ORPHAN_HORIZON_SEC", "6 hours", 1) == 0);
        ASSERT_EQ(rom_fetch_orphan_sweep_horizon_sec(),
                  (uint32_t)ROM_FETCH_ORPHAN_HORIZON_SEC_DEFAULT);

        (void)unsetenv("ZCL_ROM_FETCH_ORPHAN_HORIZON_SEC");
        PASS();
    } _test_next:;
    return failures;
}

int test_rom_fetch_orphan_sweep(void)
{
    int failures = 0;
    failures += test_orphan_sweep_policy();
    failures += test_orphan_sweep_horizon_protects();
    failures += test_orphan_sweep_empty_datadir();
    failures += test_orphan_sweep_horizon_flag();
    return failures;
}

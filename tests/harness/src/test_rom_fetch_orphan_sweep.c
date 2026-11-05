/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The eviction policy for abandoned ROM downloads
 * (engine/composition/src/rom_fetch_orphan_sweep.c).
 *
 * Fixtures are named for what they represent:
 *
 *   an_orphaned_pair            no registered target, long idle  → removed
 *   a_fresh_pair                no registered target, just wrote → kept
 *   a_registered_targets_pair   idle, but its target is offered  → kept
 *   a_lone_part / a_lone_journal    not a pair at all            → untouched
 *
 * Deterministic: "idle" fixtures get an explicit past mtime via utimensat.
 * The scratch datadir comes from test_mkdtemp. */

#include "test/test_core.h"

#include "config/rom_fetch_orphan_sweep.h"
#include "net/rom_fetch.h"
#include "net/rom_seed.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Bytes written into each fixture half; the sweep never reads contents. */
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

/* ── Mutation-gap tests (survivor sweep 1105) ───────────────────────── */

static bool os_age_path_to(const char *path, time_t t)
{
    struct timespec ts[2];
    ts[0].tv_sec = t;
    ts[0].tv_nsec = 0;
    ts[1] = ts[0];
    return utimensat(AT_FDCWD, path, ts, 0) == 0;
}

/* Lengthen `base` to exactly `total` characters with "/." components (and one
 * trailing '/'): the kernel resolves the same directory, the string is as
 * long as the case needs. */
static void os_padded(const char *base, size_t total, char *out, size_t cap)
{
    size_t n = (size_t)snprintf(out, cap, "%s", base);
    while (n + 2 <= total && n + 3 < cap) {
        out[n++] = '/';
        out[n++] = '.';
    }
    while (n < total && n + 1 < cap)
        out[n++] = '/';
    out[n] = '\0';
}

static uint32_t os_entry_count(const char *dir)
{
    uint32_t n = 0;
    DIR *d = opendir(dir);
    if (!d)
        return 0;
    while (readdir(d) != NULL)
        n++;
    closedir(d);
    return n;
}

/* Open descriptors of this process, or -1 when /proc is not there. */
static int os_fd_count(void)
{
    DIR *d = opendir("/proc/self/fd");
    if (!d)
        return -1;
    int n = 0;
    while (readdir(d) != NULL)
        n++;
    closedir(d);
    return n;
}

static bool os_mk_bundles(const char *tag, char *dd_out, char *bundles_out)
{
    char *dd = test_mkdtemp(dd_out, PATH_MAX, tag);
    if (!dd)
        return false;
    snprintf(bundles_out, PATH_MAX, "%s/%s", dd, ROM_SEED_BUNDLES_SUBDIR);
    return mkdir(bundles_out, 0700) == 0;
}

/* The horizon variable: a one-character value, the smallest and largest
 * accepted values, and a value one past the largest. */
static int test_orphan_sweep_horizon_edges(void)
{
    int failures = 0;
    TEST("rom_fetch_orphan_sweep: horizon value 1 and 4294967295 are taken "
         "as written, 4294967296 and an empty value fall back") {
        const char *k = "ZCL_ROM_FETCH_ORPHAN_HORIZON_SEC";
        ASSERT(setenv(k, "7", 1) == 0);
        ASSERT_EQ(rom_fetch_orphan_sweep_horizon_sec(), 7u);
        ASSERT(setenv(k, "1", 1) == 0);
        ASSERT_EQ(rom_fetch_orphan_sweep_horizon_sec(), 1u);
        ASSERT(setenv(k, "4294967295", 1) == 0);
        ASSERT_EQ(rom_fetch_orphan_sweep_horizon_sec(), 4294967295u);
        ASSERT(setenv(k, "4294967296", 1) == 0);
        ASSERT_EQ(rom_fetch_orphan_sweep_horizon_sec(),
                  (uint32_t)ROM_FETCH_ORPHAN_HORIZON_SEC_DEFAULT);
        ASSERT(setenv(k, "", 1) == 0);
        ASSERT_EQ(rom_fetch_orphan_sweep_horizon_sec(),
                  (uint32_t)ROM_FETCH_ORPHAN_HORIZON_SEC_DEFAULT);
        (void)unsetenv(k);
        PASS();
    } _test_next:;
    return failures;
}

/* A datadir whose `<datadir>/bundles` is exactly PATH_MAX, or longer, cannot
 * be named: the sweep refuses instead of walking a truncated path. */
static int test_orphan_sweep_overlong_datadir(void)
{
    int failures = 0;
    TEST("rom_fetch_orphan_sweep: a datadir whose bundles path fills or "
         "overflows PATH_MAX is refused; one byte shorter is a clean no-op") {
        char droot[PATH_MAX];
        char *dd = test_mkdtemp(droot, sizeof(droot), "zcl_romsweep_ld");
        ASSERT(dd != NULL);
        size_t sub = strlen(ROM_SEED_BUNDLES_SUBDIR);
        char padded[PATH_MAX + 64];
        struct rom_fetch_orphan_sweep_result r;

        os_padded(dd, PATH_MAX - 1 - sub, padded, sizeof(padded));
        ASSERT(!rom_fetch_orphan_sweep_run(padded, 3600u, &r));
        os_padded(dd, PATH_MAX + 10, padded, sizeof(padded));
        ASSERT(!rom_fetch_orphan_sweep_run(padded, 3600u, &r));
        os_padded(dd, PATH_MAX - 2 - sub, padded, sizeof(padded));
        ASSERT(rom_fetch_orphan_sweep_run(padded, 3600u, &r));
        ASSERT_EQ(r.pairs_seen, 0u);

        test_cleanup_tmpdir(dd);
        PASS();
    } _test_next:;
    return failures;
}

/* A journal path that would be exactly PATH_MAX is not a journal: the file
 * one character short of it must not be mistaken for one. */
static int test_orphan_sweep_overlong_journal(void)
{
    int failures = 0;
    TEST("rom_fetch_orphan_sweep: a .part whose journal path would fill "
         "PATH_MAX is not a pair, and a look-alike truncated journal name "
         "is not taken for its journal") {
        rom_seed_reset();
        char droot[PATH_MAX];
        char *dd = test_mkdtemp(droot, sizeof(droot), "zcl_romsweep_lj");
        ASSERT(dd != NULL);
        char real_bundles[PATH_MAX];
        snprintf(real_bundles, sizeof(real_bundles), "%s/%s", dd,
                 ROM_SEED_BUNDLES_SUBDIR);
        ASSERT(mkdir(real_bundles, 0700) == 0);

        static const char name[] = "consensus-state-bundle-800.sqlite.part";
        /* journal path = padded + "/bundles/" + name + ".journal" */
        size_t padlen = PATH_MAX - (1 + strlen(ROM_SEED_BUNDLES_SUBDIR) + 1 +
                                    (sizeof(name) - 1) + 8);
        char padded[PATH_MAX + 64];
        os_padded(dd, padlen, padded, sizeof(padded));
        char part[PATH_MAX];
        char lookalike[PATH_MAX];
        snprintf(part, sizeof(part), "%s/%s/%s", padded,
                 ROM_SEED_BUNDLES_SUBDIR, name);
        snprintf(lookalike, sizeof(lookalike), "%s/%s/%s.journa", padded,
                 ROM_SEED_BUNDLES_SUBDIR, name);
        ASSERT(strlen(lookalike) == PATH_MAX - 1);
        ASSERT(os_write_bytes(part, OS_PART_BYTES, 0xA1));
        ASSERT(os_write_bytes(lookalike, OS_JOURNAL_BYTES, 0xB2));
        ASSERT(os_age_path_to(part, OS_ANCIENT_UNIX));
        ASSERT(os_age_path_to(lookalike, OS_ANCIENT_UNIX));

        struct rom_fetch_orphan_sweep_result r;
        ASSERT(rom_fetch_orphan_sweep_run(padded, 3600u, &r));
        ASSERT_EQ(r.pairs_seen, 0u);
        ASSERT_EQ(r.pairs_removed, 0u);
        ASSERT_EQ(r.pairs_failed, 0u);
        ASSERT(os_size_is(real_bundles, name, OS_PART_BYTES));
        ASSERT(os_exists(real_bundles, "consensus-state-bundle-800.sqlite."
                                       "part.journa"));

        test_cleanup_tmpdir(real_bundles);
        test_cleanup_tmpdir(dd);
        PASS();
    } _test_next:;
    return failures;
}

/* Things that look like a pair but are not: a directory or a dangling link
 * where the staging file should be, a directory where the journal should be,
 * and a bare ".part" with a ".part.journal". All idle, none unregistered
 * targets — they must be left exactly as found. */
static int test_orphan_sweep_not_a_pair(void)
{
    int failures = 0;
    TEST("rom_fetch_orphan_sweep: a non-regular .part or journal, and a "
         "name that is only the suffix, are never swept") {
        rom_seed_reset();
        char dd[PATH_MAX];
        char bundles[PATH_MAX];
        ASSERT(os_mk_bundles("zcl_romsweep_np", dd, bundles));
        char p[PATH_MAX];

        /* staging file is a directory; journal is a regular file */
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-810.sqlite.part",
                 bundles);
        ASSERT(mkdir(p, 0700) == 0);
        snprintf(p, sizeof(p), "%s/%s", bundles,
                 "consensus-state-bundle-810.sqlite.part.journal");
        ASSERT(os_write_bytes(p, OS_JOURNAL_BYTES, 0xB2));
        ASSERT(os_age_path_to(p, OS_ANCIENT_UNIX));
        /* staging file is a dangling symlink */
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-820.sqlite.part",
                 bundles);
        ASSERT(symlink("no-such-target", p) == 0);
        snprintf(p, sizeof(p), "%s/%s", bundles,
                 "consensus-state-bundle-820.sqlite.part.journal");
        ASSERT(os_write_bytes(p, OS_JOURNAL_BYTES, 0xB2));
        ASSERT(os_age_path_to(p, OS_ANCIENT_UNIX));
        /* journal is a directory; staging file is regular and idle */
        ASSERT(os_make_pair(bundles, "consensus-state-bundle-830.sqlite",
                            true));
        snprintf(p, sizeof(p), "%s/%s", bundles,
                 "consensus-state-bundle-830.sqlite.part.journal");
        ASSERT(unlink(p) == 0);
        ASSERT(mkdir(p, 0700) == 0);
        /* nothing but the suffix */
        snprintf(p, sizeof(p), "%s/.part", bundles);
        ASSERT(os_write_bytes(p, OS_PART_BYTES, 0xA1));
        ASSERT(os_age_path_to(p, OS_ANCIENT_UNIX));
        snprintf(p, sizeof(p), "%s/.part.journal", bundles);
        ASSERT(os_write_bytes(p, OS_JOURNAL_BYTES, 0xB2));
        ASSERT(os_age_path_to(p, OS_ANCIENT_UNIX));

        struct rom_fetch_orphan_sweep_result r;
        ASSERT(rom_fetch_orphan_sweep_run(dd, 3600u, &r));
        ASSERT_EQ(r.pairs_seen, 0u);
        ASSERT_EQ(r.pairs_removed, 0u);
        ASSERT_EQ(r.pairs_failed, 0u);
        ASSERT_EQ(r.bytes_reclaimed, 0ull);
        ASSERT(os_size_is(bundles, "consensus-state-bundle-810.sqlite.part."
                                   "journal", OS_JOURNAL_BYTES));
        ASSERT(os_size_is(bundles, "consensus-state-bundle-820.sqlite.part."
                                   "journal", OS_JOURNAL_BYTES));
        ASSERT(os_size_is(bundles, "consensus-state-bundle-830.sqlite.part",
                          OS_PART_BYTES));
        ASSERT(os_size_is(bundles, ".part", OS_PART_BYTES));
        ASSERT(os_size_is(bundles, ".part.journal", OS_JOURNAL_BYTES));

        test_cleanup_tmpdir(bundles);
        test_cleanup_tmpdir(dd);
        PASS();
    } _test_next:;
    return failures;
}

/* `bundles` that is not a directory is "nothing to sweep", not a failure. */
static int test_orphan_sweep_bundles_is_a_file(void)
{
    int failures = 0;
    TEST("rom_fetch_orphan_sweep: a regular file named bundles is a clean "
         "no-op") {
        char droot[PATH_MAX];
        char *dd = test_mkdtemp(droot, sizeof(droot), "zcl_romsweep_bf");
        ASSERT(dd != NULL);
        char p[PATH_MAX];
        snprintf(p, sizeof(p), "%s/%s", dd, ROM_SEED_BUNDLES_SUBDIR);
        ASSERT(os_write_bytes(p, 16, 0x5A));
        struct rom_fetch_orphan_sweep_result r;
        ASSERT(rom_fetch_orphan_sweep_run(dd, 3600u, &r));
        ASSERT_EQ(r.pairs_seen, 0u);
        ASSERT_EQ(r.pairs_failed, 0u);
        test_cleanup_tmpdir(dd);
        PASS();
    } _test_next:;
    return failures;
}

/* The scan walks exactly ROM_SEED_SCAN_ENTRY_CAP directory entries: that many
 * is a complete walk, one more is capped. */
static int test_orphan_sweep_scan_cap(void)
{
    int failures = 0;
    TEST("rom_fetch_orphan_sweep: a directory of exactly the scan cap is "
         "walked whole; one more entry sets capped") {
        char dd[PATH_MAX];
        char bundles[PATH_MAX];
        ASSERT(os_mk_bundles("zcl_romsweep_sc", dd, bundles));
        uint32_t made = 0;
        while (os_entry_count(bundles) < ROM_SEED_SCAN_ENTRY_CAP) {
            char p[PATH_MAX];
            snprintf(p, sizeof(p), "%s/junk-%05u", bundles, (unsigned)made++);
            ASSERT(os_write_bytes(p, 1, 0x11));
        }
        ASSERT_EQ(os_entry_count(bundles), (uint32_t)ROM_SEED_SCAN_ENTRY_CAP);
        struct rom_fetch_orphan_sweep_result r;
        ASSERT(rom_fetch_orphan_sweep_run(dd, 3600u, &r));
        ASSERT(!r.capped);

        char extra[PATH_MAX];
        snprintf(extra, sizeof(extra), "%s/junk-extra", bundles);
        ASSERT(os_write_bytes(extra, 1, 0x11));
        ASSERT(rom_fetch_orphan_sweep_run(dd, 3600u, &r));
        ASSERT(r.capped);

        test_cleanup_tmpdir(bundles);
        test_cleanup_tmpdir(dd);
        PASS();
    } _test_next:;
    return failures;
}

/* More pairs than the sweep may hold: it stops at the bound and says so. */
static int test_orphan_sweep_pair_cap(void)
{
    int failures = 0;
    TEST("rom_fetch_orphan_sweep: one pair past ROM_FETCH_ORPHAN_SWEEP_MAX_"
         "PAIRS is left for the next pass and sets capped") {
        rom_seed_reset();
        char dd[PATH_MAX];
        char bundles[PATH_MAX];
        ASSERT(os_mk_bundles("zcl_romsweep_pc", dd, bundles));
        for (uint32_t i = 0; i < ROM_FETCH_ORPHAN_SWEEP_MAX_PAIRS + 1u; i++) {
            char target[64];
            snprintf(target, sizeof(target), "consensus-state-bundle-%u.sqlite",
                     (unsigned)(900 + i));
            ASSERT(os_make_pair(bundles, target, true));
        }
        struct rom_fetch_orphan_sweep_result r;
        ASSERT(rom_fetch_orphan_sweep_run(dd, 3600u, &r));
        ASSERT(r.capped);
        ASSERT_EQ(r.pairs_seen, (uint32_t)ROM_FETCH_ORPHAN_SWEEP_MAX_PAIRS);
        ASSERT_EQ(r.pairs_removed, (uint32_t)ROM_FETCH_ORPHAN_SWEEP_MAX_PAIRS);
        uint32_t files = 0;
        uint64_t bytes = 0;
        os_part_census(bundles, &files, &bytes);
        ASSERT_EQ(files, 2u);

        ASSERT(rom_fetch_orphan_sweep_run(dd, 3600u, &r));
        ASSERT(!r.capped);
        ASSERT_EQ(r.pairs_removed, 1u);
        os_part_census(bundles, &files, &bytes);
        ASSERT_EQ(files, 0u);

        test_cleanup_tmpdir(bundles);
        test_cleanup_tmpdir(dd);
        PASS();
    } _test_next:;
    return failures;
}

/* Age boundary: a pair idle for exactly the horizon is stale; one 600
 * seconds inside it is not. Idle time is only ever >= the stamp offset (the
 * sweep reads the wall clock after the stamp), so the first case holds on a
 * busy host too. */
static int test_orphan_sweep_age_boundary(void)
{
    int failures = 0;
    TEST("rom_fetch_orphan_sweep: idle for the full horizon is removed, "
         "600 s short of it is kept") {
        rom_seed_reset();
        char dd[PATH_MAX];
        char bundles[PATH_MAX];
        ASSERT(os_mk_bundles("zcl_romsweep_ab", dd, bundles));
        ASSERT(os_make_pair(bundles, "consensus-state-bundle-950.sqlite",
                            false));
        ASSERT(os_make_pair(bundles, "consensus-state-bundle-951.sqlite",
                            false));
        time_t now = time(NULL);
        const char *halves[] = {
            "consensus-state-bundle-950.sqlite.part",
            "consensus-state-bundle-950.sqlite.part.journal"};
        const char *near[] = {
            "consensus-state-bundle-951.sqlite.part",
            "consensus-state-bundle-951.sqlite.part.journal"};
        for (int i = 0; i < 2; i++) {
            char p[PATH_MAX];
            snprintf(p, sizeof(p), "%s/%s", bundles, halves[i]);
            ASSERT(os_age_path_to(p, now - 3600));
            snprintf(p, sizeof(p), "%s/%s", bundles, near[i]);
            ASSERT(os_age_path_to(p, now - 3000));
        }
        struct rom_fetch_orphan_sweep_result r;
        ASSERT(rom_fetch_orphan_sweep_run(dd, 3600u, &r));
        ASSERT_EQ(r.pairs_seen, 2u);
        ASSERT_EQ(r.pairs_removed, 1u);
        ASSERT_EQ(r.pairs_kept, 1u);
        ASSERT(!os_exists(bundles, halves[0]));
        ASSERT(!os_exists(bundles, halves[1]));
        ASSERT(os_exists(bundles, near[0]));
        ASSERT(os_exists(bundles, near[1]));
        test_cleanup_tmpdir(bundles);
        test_cleanup_tmpdir(dd);
        PASS();
    } _test_next:;
    return failures;
}

/* A directory that cannot be read or written: the sweep reports failure and
 * removes nothing. Skipped where the process can ignore permissions. */
static int test_orphan_sweep_unreadable_dir(void)
{
    int failures = 0;
    TEST("rom_fetch_orphan_sweep: an unreadable bundles/ fails the pass, "
         "touching nothing") {
        rom_seed_reset();
        char dd[PATH_MAX];
        char bundles[PATH_MAX];
        ASSERT(os_mk_bundles("zcl_romsweep_ur", dd, bundles));
        ASSERT(os_make_pair(bundles, "consensus-state-bundle-960.sqlite",
                            true));
        ASSERT(chmod(bundles, 0) == 0);
        DIR *probe = opendir(bundles);
        bool can_ignore = probe != NULL;
        if (probe)
            closedir(probe);
        struct rom_fetch_orphan_sweep_result r;
        bool ok = rom_fetch_orphan_sweep_run(dd, 3600u, &r);
        ASSERT(chmod(bundles, 0700) == 0);
        if (!can_ignore) {
            ASSERT(!ok);
            ASSERT_EQ(r.pairs_seen, 0u);
        }
        ASSERT(os_exists(bundles, "consensus-state-bundle-960.sqlite.part"));
        test_cleanup_tmpdir(bundles);
        test_cleanup_tmpdir(dd);
        PASS();
    } _test_next:;
    return failures;
}

static int test_orphan_sweep_unwritable_dir(void)
{
    int failures = 0;
    TEST("rom_fetch_orphan_sweep: when a pair's journal cannot be unlinked "
         "it is counted failed, nothing is claimed reclaimed, the pass "
         "reports failure") {
        rom_seed_reset();
        char dd[PATH_MAX];
        char bundles[PATH_MAX];
        ASSERT(os_mk_bundles("zcl_romsweep_uw", dd, bundles));
        ASSERT(os_make_pair(bundles, "consensus-state-bundle-970.sqlite",
                            true));
        ASSERT(chmod(bundles, 0500) == 0);
        bool can_ignore = access(bundles, W_OK) == 0;
        struct rom_fetch_orphan_sweep_result r;
        bool ok = rom_fetch_orphan_sweep_run(dd, 3600u, &r);
        ASSERT(chmod(bundles, 0700) == 0);
        if (!can_ignore) {
            ASSERT(!ok);
            ASSERT_EQ(r.pairs_seen, 1u);
            ASSERT_EQ(r.pairs_failed, 1u);
            ASSERT_EQ(r.pairs_removed, 0u);
            ASSERT_EQ(r.bytes_reclaimed, 0ull);
        }
        ASSERT(os_size_is(bundles, "consensus-state-bundle-970.sqlite.part",
                          OS_PART_BYTES));
        ASSERT(os_size_is(bundles,
                          "consensus-state-bundle-970.sqlite.part.journal",
                          OS_JOURNAL_BYTES));
        test_cleanup_tmpdir(bundles);
        test_cleanup_tmpdir(dd);
        PASS();
    } _test_next:;
    return failures;
}

/* The directory handle is closed on every pass. */
static int test_orphan_sweep_no_fd_leak(void)
{
    int failures = 0;
    TEST("rom_fetch_orphan_sweep: a pass leaves the process's descriptor "
         "count where it found it") {
        rom_seed_reset();
        char dd[PATH_MAX];
        char bundles[PATH_MAX];
        ASSERT(os_mk_bundles("zcl_romsweep_fd", dd, bundles));
        ASSERT(os_make_pair(bundles, "consensus-state-bundle-980.sqlite",
                            true));
        struct rom_fetch_orphan_sweep_result r;
        /* Warm-up pass: anything the first pass opens once and keeps (a log
         * sink, say) must not be counted as a leak. */
        ASSERT(rom_fetch_orphan_sweep_run(dd, 3600u, &r));
        ASSERT_EQ(r.pairs_removed, 1u);
        ASSERT(os_make_pair(bundles, "consensus-state-bundle-981.sqlite",
                            true));
        int before = os_fd_count();
        ASSERT(rom_fetch_orphan_sweep_run(dd, 3600u, &r));
        ASSERT_EQ(r.pairs_removed, 1u);
        ASSERT_EQ(os_fd_count(), before);
        test_cleanup_tmpdir(bundles);
        test_cleanup_tmpdir(dd);
        PASS();
    } _test_next:;
    return failures;
}

static int rom_fetch_orphan_sweep_gap_tests(void)
{
    int failures = 0;
    failures += test_orphan_sweep_horizon_edges();
    failures += test_orphan_sweep_overlong_datadir();
    failures += test_orphan_sweep_overlong_journal();
    failures += test_orphan_sweep_not_a_pair();
    failures += test_orphan_sweep_bundles_is_a_file();
    failures += test_orphan_sweep_scan_cap();
    failures += test_orphan_sweep_pair_cap();
    failures += test_orphan_sweep_age_boundary();
    failures += test_orphan_sweep_unreadable_dir();
    failures += test_orphan_sweep_unwritable_dir();
    failures += test_orphan_sweep_no_fd_leak();
    return failures;
}

int test_rom_fetch_orphan_sweep(void)
{
    int failures = 0;
    failures += test_orphan_sweep_policy();
    failures += test_orphan_sweep_horizon_protects();
    failures += test_orphan_sweep_empty_datadir();
    failures += test_orphan_sweep_horizon_flag();
    failures += rom_fetch_orphan_sweep_gap_tests();
    return failures;
}

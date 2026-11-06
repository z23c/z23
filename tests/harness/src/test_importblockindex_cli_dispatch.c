/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_importblockindex_cli_dispatch — proves the literal
 * `z23 --importblockindex <src-datadir> [<target-node.db>]` CLI
 * invocation (step 1 of the two-step cold-sync recipe, docs/node/SYNC.md Method 3)
 * is ROUTED by engine/entry/main.c's argv dispatch chain to the real importer,
 * not swallowed by an earlier branch (`is_cli_mode()`, the `argc == 1` status
 * shortcut, or an unrelated `if`).
 *
 * test_importblockindex_roundtrip.c covers snapshot_import_block_index()
 * directly; this test covers the argv routing in main() by forking the real
 * built binary the way an operator invokes it.
 *
 * Skips (does not fail) if build/bin/zclassic23 is missing or stale vs the
 * source files that define this behavior — matching the guard pattern in
 * the native command integration tests.
 *
 * make t ONLY=importblockindex_cli_dispatch
 */

#include "test/test_core.h"
#include "test/importblockindex_fixture.h"
#include "coins/compressor.h"
#include "core/serialize.h"
#include "storage/dbwrapper.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>
#if !defined(_WIN32)

#define ICD_BIN "build/bin/zclassic23"

static bool icd_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static long icd_file_mtime(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long)st.st_mtime;
}

/* Witness sources for the CLI dispatch and importer; if newer than the binary,
 * SKIP with a clear message. */
static const char *const icd_stale_witnesses[] = {
    "engine/entry/main.c",
    "engine/entry/main_cli_modes.c",
    "engine/controllers/src/snapshot_controller_import.c",
    "engine/services/src/utxo_import_pipeline.c",
    NULL,
};

static bool icd_bin_is_fresh(const char **stale_path_out)
{
    long bin_mt = icd_file_mtime(ICD_BIN);
    if (bin_mt < 0) return false;
    for (size_t i = 0; icd_stale_witnesses[i]; i++) {
        long src_mt = icd_file_mtime(icd_stale_witnesses[i]);
        if (src_mt < 0) continue; /* missing -> ignore */
        if (src_mt > bin_mt) {
            if (stale_path_out) *stale_path_out = icd_stale_witnesses[i];
            return false;
        }
    }
    return true;
}

static void icd_mkdir_p(const char *path)
{
    /* Best-effort: failure surfaces as the test's own ASSERTs downstream. */
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        fprintf(stderr, "icd_mkdir_p: mkdir(%s) failed: %s\n",
                path, strerror(errno));
}

/* Fork/exec argv (the exec target is always ICD_BIN), capturing stdout+stderr
 * into out (NUL-terminated, truncated to cap-1; excess is drained). Returns the
 * child's exit code, or a negative sentinel on spawn/wait failure or signal. */
static int icd_run_with_home(char *const argv[], const char *home, char *out,
                             size_t cap)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        if (home && setenv("HOME", home, 1) != 0)
            _exit(126);
        execv(ICD_BIN, argv);
        _exit(127);
    }

    close(pipefd[1]);
    size_t pos = 0;
    char buf[4096];
    ssize_t r;
    while ((r = read(pipefd[0], buf, sizeof(buf))) > 0) {
        size_t take = (size_t)r;
        size_t room = (pos + 1 < cap) ? (cap - 1 - pos) : 0;
        if (take > room) take = room;
        if (take > 0) {
            memcpy(out + pos, buf, take);
            pos += take;
        }
        /* Excess bytes beyond `room` are dropped; keep draining the pipe. */
    }
    out[pos < cap ? pos : cap - 1] = 0;
    close(pipefd[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return -100 - WTERMSIG(status);
    return -1;
}

static int icd_run(char *const argv[], char *out, size_t cap)
{
    return icd_run_with_home(argv, NULL, out, cap);
}

static bool icd_contains(const char *hay, const char *needle)
{
    return hay && needle && strstr(hay, needle) != NULL;
}

/* One `_test_next:` label per function is a constraint of the TEST()/ASSERT()
 * macros, so each case is its own static helper. */

static int icd_test_dispatch_reaches_importer(const char *src_dir,
                                               const char *target_db)
{
    int failures = 0;
    TEST("importblockindex CLI: `--importblockindex <src> <db>` as argv[1] "
         "reaches the real block-index importer") {
        char *argv[] = {
            (char *)ICD_BIN, (char *)"--importblockindex",
            (char *)src_dir, (char *)target_db, NULL,
        };
        char out[16384] = {0};
        int rc = icd_run(argv, out, sizeof(out));
        ASSERT(rc == 0);
        ASSERT(icd_contains(out, "ZClassic Block-Index (header) Import"));
        struct stat st;
        ASSERT(stat(target_db, &st) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int icd_test_flaglike_target_refused(const char *src_dir)
{
    int failures = 0;
    TEST("importblockindex CLI: a flag-like third (dbpath) arg is refused "
         "with a usage message, never silently accepted as a filename") {
        char *argv[] = {
            (char *)ICD_BIN, (char *)"--importblockindex", (char *)src_dir,
            (char *)"-datadir=/should/not/be/treated/as/a/db/path", NULL,
        };
        char out[16384] = {0};
        int rc = icd_run(argv, out, sizeof(out));
        ASSERT(rc == 1);
        ASSERT(icd_contains(out, "usage: z23 --importblockindex"));
        PASS();
    } _test_next:;
    return failures;
}

/* --importblockindex dispatches from any argv position: the anywhere-in-argv
 * scan (engine/entry/main.c main()) routes to the real importer when a node
 * flag (-datadir=) precedes the verb. */
static int icd_test_nonfirst_position_dispatches(const char *src_dir,
                                                  const char *target_db)
{
    int failures = 0;
    TEST("importblockindex CLI: --importblockindex in a NON-first argv "
         "position (after -datadir=) still dispatches the real importer, "
         "never silently falling through to a normal boot") {
        char *argv[] = {
            (char *)ICD_BIN,
            (char *)"-datadir=/tmp/zcl_icd_unused_datadir_should_not_boot",
            (char *)"--importblockindex", (char *)src_dir,
            (char *)target_db, NULL,
        };
        char out[16384] = {0};
        int rc = icd_run(argv, out, sizeof(out));
        ASSERT(rc == 0);
        ASSERT(icd_contains(out, "ZClassic Block-Index (header) Import"));
        /* argv_pos=2: --importblockindex is argv[2] here, not argv[1] —
         * proves the scan found it away from the canonical position. */
        ASSERT(icd_contains(out, "argv_pos=2"));
        struct stat st;
        ASSERT(stat(target_db, &st) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* A missing/invalid source path REFUSES loudly and immediately, named and
 * with a non-zero exit. */
static int icd_test_bad_path_refuses(void)
{
    int failures = 0;
    char missing_src[300];
    snprintf(missing_src, sizeof(missing_src),
             "/tmp/zcl_icd_totally_missing_src_%d", (int)getpid());

    TEST("importblockindex CLI: a nonexistent source datadir REFUSES "
         "loudly (named error, exit 1) instead of silently proceeding") {
        char *argv[] = {
            (char *)ICD_BIN, (char *)"--importblockindex",
            (char *)missing_src, NULL,
        };
        char out[16384] = {0};
        int rc = icd_run(argv, out, sizeof(out));
        ASSERT(rc == 1);
        ASSERT(icd_contains(out, "REFUSING"));
        ASSERT(icd_contains(out, missing_src));
        PASS();
    } _test_next:;

    return failures;
}

static int icd_test_missing_source_arg_refuses(void)
{
    int failures = 0;
    TEST("importblockindex CLI: the verb present with NO source argument "
         "at all REFUSES loudly instead of falling through to a normal "
         "boot") {
        char *argv[] = {
            (char *)ICD_BIN, (char *)"--importblockindex", NULL,
        };
        char out[16384] = {0};
        int rc = icd_run(argv, out, sizeof(out));
        ASSERT(rc == 1);
        ASSERT(icd_contains(out, "missing <source-datadir>"));
        PASS();
    } _test_next:;
    return failures;
}

/* The CLI importer has one code path, so a fresh target node.db always takes
 * it, proven via the LOG_INFO `mode=bulk` marker every dispatch emits. The
 * normal-boot bulk-hydrate rung is unit-tested in test_boot_phase.c. */
static int icd_test_fresh_datadir_chooses_bulk(const char *src_dir,
                                               const char *target_db)
{
    int failures = 0;
    TEST("importblockindex CLI: a fresh (never-before-seen) target node.db "
         "deterministically selects the bulk import path (INFO marker "
         "mode=bulk)") {
        char *argv[] = {
            (char *)ICD_BIN, (char *)"--importblockindex",
            (char *)src_dir, (char *)target_db, NULL,
        };
        char out[16384] = {0};
        int rc = icd_run(argv, out, sizeof(out));
        ASSERT(rc == 0);
        ASSERT(icd_contains(out, "mode=bulk"));
        ASSERT(icd_contains(out, "bulk import complete"));
        PASS();
    } _test_next:;
    return failures;
}

/* One coin record with two pay-to-key-hash outputs at height 7. */
static bool icd_write_coin_record(struct db_wrapper *db)
{
    struct byte_stream s;
    char key[33];
    uint8_t hash[20];
    bool ok;

    stream_init(&s, 96);
    memset(hash, 0x51, sizeof(hash));
    ok = stream_write_varint(&s, 1);
    ok &= stream_write_varint(&s, 0x06);
    for (int i = 0; i < 2; i++) {
        ok &= stream_write_varint(&s, compress_amount(1));
        ok &= stream_write_varint(&s, 0);
        ok &= stream_write_bytes(&s, hash, sizeof(hash));
    }
    ok &= stream_write_varint(&s, 7);
    memset(key, 0x33, sizeof(key));
    key[0] = 'c';
    ok = ok && !s.error &&
         db_write(db, key, sizeof(key), (const char *)s.data, s.size, false);
    stream_free(&s);
    return ok;
}

/* --importchainstate: a chainstate whose best block is not the checkpoint block,
 * so a run that reaches the importer exits 0. The children get their own HOME:
 * the bare form writes to $HOME/.zclassic-c23/node.db. */
static bool icd_chainstate_fixture_build(const char *path)
{
    struct db_wrapper db;
    uint8_t best[32];
    bool ok;

    memset(&db, 0, sizeof(db));
    memset(best, 0x5a, sizeof(best));
    if (!db_wrapper_open(&db, path, 1u << 20, false, true))
        return false;
    ok = db_write(&db, "B", 1, (const char *)best, sizeof(best), false) &&
         icd_write_coin_record(&db);
    db_wrapper_close(&db);
    return ok;
}

static int icd_test_importchainstate_bare_path(const char *cs, const char *home)
{
    int failures = 0;
    TEST("importchainstate CLI: `--importchainstate <path>` reaches the importer "
         "and writes under HOME") {
        char *argv[] = {
            (char *)ICD_BIN, (char *)"--importchainstate", (char *)cs, NULL,
        };
        char out[16384] = {0};
        char db_path[PATH_MAX];
        struct stat st;
        int rc = icd_run_with_home(argv, home, out, sizeof(out));

        ASSERT(icd_contains(out, "=== ZClassic UTXO Import ==="));
        ASSERT(icd_contains(out, "not compared"));
        ASSERT(rc == 0);
        snprintf(db_path, sizeof(db_path), "%s/.zclassic-c23/node.db", home);
        ASSERT(stat(db_path, &st) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int icd_test_importchainstate_explicit_target(const char *cs,
                                                     const char *home,
                                                     const char *target)
{
    int failures = 0;
    TEST("importchainstate CLI: `--importchainstate <path> <db>` reaches the "
         "importer and writes to the target") {
        char *argv[] = {
            (char *)ICD_BIN, (char *)"--importchainstate", (char *)cs,
            (char *)target, NULL,
        };
        char out[16384] = {0};
        struct stat st;
        int rc = icd_run_with_home(argv, home, out, sizeof(out));

        ASSERT(icd_contains(out, "=== ZClassic UTXO Import ==="));
        ASSERT(rc == 0);
        ASSERT(stat(target, &st) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int icd_test_importchainstate_usage(const char *cs, const char *home)
{
    int failures = 0;
    TEST("importchainstate CLI: no path, or a flag as the target, prints the usage") {
        char *no_path[] = {
            (char *)ICD_BIN, (char *)"--importchainstate", NULL,
        };
        char *flag_target[] = {
            (char *)ICD_BIN, (char *)"--importchainstate", (char *)cs,
            (char *)"-datadir=/nonexistent", NULL,
        };
        char out[16384] = {0};

        ASSERT(icd_run_with_home(no_path, home, out, sizeof(out)) == 1);
        ASSERT(icd_contains(out, "usage: z23 --importchainstate"));
        memset(out, 0, sizeof(out));
        ASSERT(icd_run_with_home(flag_target, home, out, sizeof(out)) == 1);
        ASSERT(icd_contains(out, "usage: z23 --importchainstate"));
        PASS();
    } _test_next:;
    return failures;
}

static int icd_test_importchainstate_missing_source(const char *base,
                                                    const char *home)
{
    int failures = 0;
    TEST("importchainstate CLI: a missing chainstate path refuses and creates "
         "nothing") {
        char missing[PATH_MAX];
        char target[PATH_MAX + 16];
        struct stat st;

        snprintf(missing, sizeof(missing), "%s/no_such_chainstate", base);
        snprintf(target, sizeof(target), "%s/missing.db", base);
        char *argv[] = {
            (char *)ICD_BIN, (char *)"--importchainstate", missing, target, NULL,
        };
        char out[16384] = {0};
        int rc = icd_run_with_home(argv, home, out, sizeof(out));

        ASSERT(rc == 1);
        ASSERT(icd_contains(out, "nothing was changed"));
        ASSERT(stat(missing, &st) != 0);
        ASSERT(stat(target, &st) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int icd_test_importchainstate(const char *base)
{
    char cs[PATH_MAX], home[PATH_MAX], home_dir[PATH_MAX + 32], target[PATH_MAX];
    int failures = 0;

    snprintf(cs, sizeof(cs), "%s/chainstate", base);
    snprintf(home, sizeof(home), "%s/home", base);
    /* The node.db the bare form writes under the tmp HOME, less its file name. */
    snprintf(home_dir, sizeof(home_dir), "%s/.zclassic-c23/node.db", home);
    *strrchr(home_dir, '/') = '\0';
    snprintf(target, sizeof(target), "%s/import_target.db", base);
    icd_mkdir_p(home);
    icd_mkdir_p(home_dir);
    if (!icd_chainstate_fixture_build(cs)) {
        fprintf(stderr, "importchainstate CLI: failed to build chainstate fixture\n");
        return 1;
    }
    failures += icd_test_importchainstate_bare_path(cs, home);
    failures += icd_test_importchainstate_explicit_target(cs, home, target);
    failures += icd_test_importchainstate_usage(cs, home);
    failures += icd_test_importchainstate_missing_source(base, home);
    return failures;
}

static int test_importblockindex_cli_dispatch_platform_arm(void);

static int test_importblockindex_cli_dispatch_platform_arm(void)
{
    int failures = 0;

    if (!icd_file_exists(ICD_BIN)) {
        printf("importblockindex_cli_dispatch: %s not built — SKIP "
               "(run `make` to build it)\n", ICD_BIN);
        return 0;
    }
    const char *stale_path = NULL;
    if (!icd_bin_is_fresh(&stale_path)) {
        printf("importblockindex_cli_dispatch: %s is stale — newer source: "
               "%s — SKIP (run `make` to rebuild)\n",
               ICD_BIN, stale_path ? stale_path : "(unknown)");
        return 0;
    }

    char base[PATH_MAX];
    test_make_tmpdir(base, sizeof(base), "importblockindex_cli_dispatch",
                     "main");
    char src_dir[PATH_MAX], target_db[PATH_MAX], target_db2[PATH_MAX];
    char target_db3[PATH_MAX];
    snprintf(src_dir, sizeof(src_dir), "%s/legacy_src", base);
    snprintf(target_db, sizeof(target_db), "%s/node1.db", base);
    snprintf(target_db2, sizeof(target_db2), "%s/node2.db", base);
    snprintf(target_db3, sizeof(target_db3), "%s/node3.db", base);
    icd_mkdir_p(src_dir);
    if (!test_importblockindex_fixture_build_minimal(src_dir)) {
        fprintf(stderr, "importblockindex_cli_dispatch: failed to build "
                "real legacy blocks/index fixture\n");
        (void)test_rm_rf_recursive(base);
        return 1;
    }

    failures += icd_test_dispatch_reaches_importer(src_dir, target_db);
    failures += icd_test_flaglike_target_refused(src_dir);
    failures += icd_test_nonfirst_position_dispatches(src_dir, target_db2);
    failures += icd_test_bad_path_refuses();
    failures += icd_test_missing_source_arg_refuses();
    failures += icd_test_fresh_datadir_chooses_bulk(src_dir, target_db3);
    failures += icd_test_importchainstate(base);

    /* LevelDB and SQLite both own nested/sidecar files. */
    (void)test_rm_rf_recursive(base);

    return failures;
}
#else  /* _WIN32 */
/* Windows has no fork()/waitpid process model; this group's forked CLI-dispatch child lane
 * cannot run here. Skipped loudly rather than faked. */
static int test_importblockindex_cli_dispatch_platform_arm(void)
{
    printf("importblockindex_cli_dispatch: SKIP (Windows): forked CLI-dispatch child lane\n");
    return 0;
}
#endif

int test_importblockindex_cli_dispatch(void)
{
    return test_importblockindex_cli_dispatch_platform_arm();
}

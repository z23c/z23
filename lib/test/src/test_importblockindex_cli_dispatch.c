/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_importblockindex_cli_dispatch — proves the literal
 * `zclassic23 --importblockindex <src-datadir> [<target-node.db>]` CLI
 * invocation (step 1 of the two-step cold-sync recipe — CLAUDE.md
 * "Tenacity & recovery", docs/SYNC.md Method 3) is actually ROUTED by
 * src/main.c's argv dispatch chain to the real importer, not silently
 * swallowed by an earlier branch (`is_cli_mode()` -> cli_main, the
 * `argc == 1` status shortcut, or an unrelated `if` returning first).
 *
 * test_importblockindex_roundtrip.c already gives snapshot_import_block_index()
 * itself (app/controllers/src/snapshot_controller_import.c) full execution
 * coverage by calling it directly. This test covers the layer above it —
 * the argv routing in main() — by forking the REAL built binary exactly the
 * way an operator (or the two-step recipe) invokes it. Before this test,
 * that routing layer had zero execution coverage: a regression that
 * re-routes or drops the dispatch (e.g. a reordered `if`-chain, a widened
 * `is_cli_mode()`, or an early return inserted above it) would silently turn
 * the documented cold-sync recipe into a no-op, exactly the shape of the
 * historical `-cold-import=`/`-fastimport=` flag removal that CLAUDE.md and
 * docs/SYNC.md warn about.
 *
 * Skips (does not fail) if build/bin/zclassic23 is missing or stale vs the
 * source files that define this behavior — matching the guard pattern in
 * the native command integration tests.
 *
 * make t ONLY=importblockindex_cli_dispatch
 */

#include "test/test_core.h"
#include "test/importblockindex_fixture.h"

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

/* Witness sources for the CLI dispatch + the importer it calls. If either
 * is newer than the binary, the binary predates the behavior this test
 * exercises — SKIP with a clear message instead of a confusing failure. */
static const char *const icd_stale_witnesses[] = {
    "src/main.c",
    "app/controllers/src/snapshot_controller_import.c",
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
    /* Best-effort: a failure here surfaces as the test's own ASSERTs
     * failing downstream (e.g. the target db never appearing), which is
     * more actionable than a silent partial-setup skip. */
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        fprintf(stderr, "icd_mkdir_p: mkdir(%s) failed: %s\n",
                path, strerror(errno));
}

/* Fork/exec argv (argv[0] is cosmetic; the real exec target is always
 * ICD_BIN), capture combined stdout+stderr into out (NUL-terminated,
 * truncated to cap-1 bytes; excess child output is drained and discarded
 * so the child never blocks on a full pipe). Returns the child's exit
 * code, or a negative sentinel on spawn/wait failure or signal death. */
static int icd_run(char *const argv[], char *out, size_t cap)
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
        /* Excess bytes beyond `room` are intentionally dropped — we keep
         * draining the pipe so a chatty child never blocks on write(). */
    }
    out[pos < cap ? pos : cap - 1] = 0;
    close(pipefd[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return -100 - WTERMSIG(status);
    return -1;
}

static bool icd_contains(const char *hay, const char *needle)
{
    return hay && needle && strstr(hay, needle) != NULL;
}

/* One `_test_next:` label per function is a hard C constraint of the
 * TEST()/ASSERT() macros (see test_flyclient.c for the established
 * one-case-per-function convention), so each case below is its own
 * static helper. */

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

/* Determinism fix #1: --importblockindex used to dispatch ONLY as the
 * literal argv[1] (a raw strcmp(argv[1], "--importblockindex")). Any other
 * position fell through every check in main()'s argv chain and silently
 * ran a normal node boot — the historical footgun this whole test group
 * guards against (see the file header). This proves the anywhere-in-argv
 * scan (src/main.c main()) dispatches the real importer when a node flag
 * (-datadir=) precedes the verb, matching the documented usage. */
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

/* Determinism fix #2: a missing/invalid source path used to either fall
 * through to a normal boot (missing source arg entirely — argc<3 made the
 * old literal-argv[1] check simply not match) or fail deep inside the
 * importer with a generic, easy-to-miss "Block-index import failed". Both
 * shapes now REFUSE loudly and immediately, named and non-zero-exit. */
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

/* Determinism fix #3 (boot.c bulk-vs-P2P dispatch, config/src/boot.c +
 * config/src/boot_legacy_import.c boot_need_blocks_table_hydrate): the CLI
 * importer itself has exactly one code path (there is no incremental
 * alternative inside snapshot_import_block_index), so a fresh target
 * node.db always takes it — proven here via the LOG_INFO `mode=bulk`
 * marker every dispatch emits. The companion NORMAL-BOOT determinism fix
 * (an earlier loader rung's stale small map no longer blocks the
 * `blocks`-table bulk hydrate rung) is unit-tested directly against
 * boot_need_blocks_table_hydrate in test_boot_phase.c — a full boot fork
 * here would need real P2P networking to observe, which this CLI-only
 * harness deliberately does not spin up. */
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

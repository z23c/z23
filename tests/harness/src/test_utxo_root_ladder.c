/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the golden-height UTXO root ladder (chain/utxo_root_ladder.h,
 * tools/gen_utxo_root_ladder.c) and its live tripwire companion
 * (models/utxo_root_ladder_verify.h). Mirrors test_sha3_windows.c's
 * placeholder-safe structure (the generated table may legitimately hold
 * anywhere from 0 to many rungs depending on what the operator's node.db
 * copy could populate) plus test_self_folded_anchor.c's env-gated heavy
 * section for the dense mmb_root layer, which needs a real ~100 MB
 * mmb_leaves.bin fixture to exercise for real. */

#include "test/test_core.h"

#include "chain/mmb.h"
#include "chain/utxo_root_ladder.h"
#include "models/mmb_leaf_store.h"
#include "models/utxo_root_ladder_verify.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "platform/clock.h"
#endif

#if !defined(_WIN32)
static bool test_ladder_wait_child(pid_t pid, int *status)
{
    int64_t until = clock_now_monotonic_ns() + INT64_C(20000000000);
    bool killed = false;
    for (;;) {
        pid_t r = waitpid(pid, status, WNOHANG);
        if (r == pid) return !killed;
        if (r < 0 && errno != EINTR) {
            printf("FAIL (waitpid: %s)\n", strerror(errno));
            return false;
        }
        if (clock_now_monotonic_ns() >= until) {
            if (killed) {
                printf("FAIL (killed generator exit unobserved)\n");
                return false;
            }
            printf("FAIL (generator exceeded the 20s budget)\n");
            if (kill(pid, SIGKILL) != 0 && errno != ESRCH) {
                printf("FAIL (kill: %s)\n", strerror(errno));
                return false;
            }
            killed = true;
            until = clock_now_monotonic_ns() + INT64_C(30000000000);
        }
        const struct timespec tick = {0, 50 * 1000 * 1000};
        if (nanosleep(&tick, NULL) != 0 && errno != EINTR)
            fprintf(stderr, "ladder watchdog sleep failed: %s\n", strerror(errno));
    }
}

/* Craft the malformed source db: one best-chain block at height
 * 2147483600, within one default stride of INT32_MAX. */
static bool test_ladder_huge_fixture(const char *db_path)
{
    sqlite3 *db = NULL;
    bool ok = sqlite3_open(db_path, &db) == SQLITE_OK &&
              sqlite3_exec(db,
                      "CREATE TABLE blocks(height INTEGER PRIMARY KEY,"
                      " hash BLOB, status INTEGER);"
                      "INSERT INTO blocks(height,hash,status)"
                      " VALUES(2147483600, zeroblob(32), 3);",
                      NULL, NULL, NULL) == SQLITE_OK;
    if (db)
        sqlite3_close(db);
    return ok;
}

/* Exec the generator against the crafted huge-height source db.
 * Pre-fix the tool's stride loop overflowed `h += stride` to a negative
 * height and never terminated; the fixed tool must refuse with a named
 * message and a nonzero exit, well inside the 20 s budget. Returns the
 * failure count and prints OK/FAIL itself. */
static int test_generator_refuses_huge_height(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "utxo_root_ladder_huge", "main");
    char db_path[300];
    char kdb_arg[320];
    snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
    snprintf(kdb_arg, sizeof(kdb_arg), "--source-kernel-db=%s", db_path);

    if (!test_ladder_huge_fixture(db_path)) {
        printf("FAIL (crafted fixture db could not be created at %s)\n",
               db_path);
        test_rm_rf_recursive(dir);
        return 1;
    }

    int cerr_pipe[2];
    if (pipe(cerr_pipe) != 0) {
        printf("FAIL (pipe: %s)\n", strerror(errno));
        test_rm_rf_recursive(dir);
        return 1;
    }
    if (fcntl(cerr_pipe[0], F_SETFL, O_NONBLOCK) < 0) {
        printf("FAIL (nonblocking stderr: %s)\n", strerror(errno));
        close(cerr_pipe[0]);
        close(cerr_pipe[1]);
        test_rm_rf_recursive(dir);
        return 1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        printf("FAIL (fork: %s)\n", strerror(errno));
        close(cerr_pipe[0]);
        close(cerr_pipe[1]);
        test_rm_rf_recursive(dir);
        return 1;
    }
    if (pid == 0) {
        close(cerr_pipe[0]);
        if (dup2(cerr_pipe[1], STDERR_FILENO) < 0) _exit(126);
        close(cerr_pipe[1]);
        execl("build/bin/gen_utxo_root_ladder",
              "gen_utxo_root_ladder", db_path,
              kdb_arg, "--stride=100000", NULL);
        _exit(127);
    }
    close(cerr_pipe[1]);

    int status = 0;
    bool reaped = test_ladder_wait_child(pid, &status);
    char err[2048];
    ssize_t n = reaped ? read(cerr_pipe[0], err, sizeof(err) - 1) : -1;
    close(cerr_pipe[0]);
    if (n < 0)
        n = 0;
    err[n] = 0;
    test_rm_rf_recursive(dir);

    if (!reaped) {
        printf("FAIL (generator hung past the 20s budget — stride-loop "
               "overflow)\n");
        return failures + 1;
    }
    if (!(WIFEXITED(status) && WEXITSTATUS(status) != 0)) {
        printf("FAIL (exit=%d, want nonzero refusal)\n", status);
        return failures + 1;
    }
    if (!strstr(err, "refusing")) {
        printf("FAIL (stderr lacks the named refusal, saw: %.160s)\n", err);
        return failures + 1;
    }
    printf("OK\n");
    return failures;
}
#endif /* !_WIN32 */

/* Section (4) body: utxo_root_ladder_verify_against_store() must refuse a
 * NULL db. Returns the failure count and prints OK/FAIL itself. */
static int test_ladder_null_db_refusal_failures(void)
{
    bool ok = utxo_root_ladder_verify_against_store(NULL, NULL, 0, NULL);
    if (!ok) {
        printf("OK\n");
        return 0;
    }
    printf("FAIL\n");
    return 1;
}

/* True when the compiled table carries no dense anchor
 * (g_utxo_root_ladder_dense_height == -1), so the real-leaf-store
 * reproduction cannot apply. */
static bool test_ladder_dense_anchor_absent(void)
{
    return g_utxo_root_ladder_dense_height < 0;
}

/* True when the env-gated heavy run is both requested
 * (ZCL_UTXO_LADDER_HEAVY set, non-empty and not "0") and pointed at a
 * non-empty ZCL_UTXO_LADDER_LEAF_STORE path. */
static bool test_ladder_heavy_run_requested(const char *heavy,
                                            const char *store_path)
{
    bool run_heavy = heavy && heavy[0] && strcmp(heavy, "0") != 0;
    return run_heavy && store_path && store_path[0];
}

/* Print the lane's final verdict line for the accumulated failure
 * count. */
static void test_ladder_print_summary(int failures)
{
    if (failures == 0)
        printf("=== test_utxo_root_ladder: all cases passed ===\n");
    else
        printf("=== test_utxo_root_ladder: %d failure(s) ===\n", failures);
}

int test_utxo_root_ladder(void)
{
    int failures = 0;

    printf("\n=== test_utxo_root_ladder ===\n");

    /* (1) The table is always internally consistent, whether it is the
     * placeholder (count==0) or populated: lookup() must find every entry
     * it advertises and reject a height no entry has. */
    printf("utxo_root_ladder: lookup() agrees with the compiled table... ");
    {
        ASSERT(utxo_root_ladder_count() == g_utxo_root_ladder_count);
        for (size_t i = 0; i < g_utxo_root_ladder_count; i++) {
            const struct utxo_root_ladder_entry *e =
                utxo_root_ladder_lookup(g_utxo_root_ladder[i].height);
            ASSERT(e != NULL);
            ASSERT(e == &g_utxo_root_ladder[i]);
        }
        /* A height that is never a stride multiple and never the
         * checkpoint height must not resolve. */
        ASSERT(utxo_root_ladder_lookup(-1) == NULL);
        ASSERT(utxo_root_ladder_lookup(1234567) == NULL);
        printf("OK (count=%zu)\n", g_utxo_root_ladder_count);
    }

    /* (2) Every entry carries the provenance the generator promises:
     * SINGLE/DUAL are stride rungs (height % UTXO_ROOT_LADDER_STRIDE == 0),
     * CHECKPOINT is the one zclassicd-verified anchor and its utxo_root/
     * block_hash must never be the all-zero sentinel. */
    printf("utxo_root_ladder: every entry has a real (non-zero) root... ");
    {
        uint8_t zero[32] = {0};
        for (size_t i = 0; i < g_utxo_root_ladder_count; i++) {
            const struct utxo_root_ladder_entry *e = &g_utxo_root_ladder[i];
            ASSERT(memcmp(e->utxo_root, zero, 32) != 0);
            ASSERT(memcmp(e->block_hash, zero, 32) != 0);
            if (e->provenance == UTXO_ROOT_LADDER_SOURCE_CHECKPOINT) {
                /* The one anchor the plan requires: it must appear in the
                 * ladder. */
                ASSERT(e->height == 3056758);
            } else {
                ASSERT((e->height % UTXO_ROOT_LADDER_STRIDE) == 0);
            }
        }
        printf("OK\n");
    }

    /* (3) utxo_root_ladder_verify_against_store() on a FRESH (empty)
     * boundary-root store: every rung reports NOT_YET_REACHED and the
     * aggregate verdict is healthy (true) — an empty store is normal, not
     * a divergence. Then write the FIRST rung's exact root and confirm
     * MATCH; then corrupt it and confirm DIVERGENT flips the aggregate to
     * false. This is the real "state-wrong coin detected" tripwire this
     * lane exists to prove. */
    printf("utxo_root_ladder: verify_against_store detects match vs "
          "divergence... ");
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "utxo_root_ladder", "main");
        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        ASSERT(coins_kv_ensure_schema(db));

        struct utxo_root_ladder_verify_result results[128];
        size_t n = 0;
        bool ok = utxo_root_ladder_verify_against_store(db, results,
                                                        sizeof(results) /
                                                            sizeof(results[0]),
                                                        &n);
        ASSERT(ok);
        ASSERT(n == g_utxo_root_ladder_count);
        for (size_t i = 0; i < n; i++)
            ASSERT(results[i].status == UTXO_ROOT_LADDER_VERIFY_NOT_YET_REACHED);

        if (g_utxo_root_ladder_count > 0) {
            const struct utxo_root_ladder_entry *rung = &g_utxo_root_ladder[0];

            ASSERT(coins_kv_boundary_root_set(db, rung->height,
                                              rung->utxo_root));
            ok = utxo_root_ladder_verify_against_store(db, results,
                                                       sizeof(results) /
                                                           sizeof(results[0]),
                                                       &n);
            ASSERT(ok);
            ASSERT(results[0].height == rung->height);
            ASSERT(results[0].status == UTXO_ROOT_LADDER_VERIFY_MATCH);

            uint8_t corrupted[32];
            memcpy(corrupted, rung->utxo_root, 32);
            corrupted[0] ^= 0xff;
            ASSERT(coins_kv_boundary_root_set(db, rung->height, corrupted));
            ok = utxo_root_ladder_verify_against_store(db, results,
                                                       sizeof(results) /
                                                           sizeof(results[0]),
                                                       &n);
            ASSERT(!ok);
            ASSERT(results[0].status == UTXO_ROOT_LADDER_VERIFY_DIVERGENT);
        }

        progress_store_close();
        test_rm_rf_recursive(dir);
        printf("OK\n");
    }

    /* (4) utxo_root_ladder_verify_against_store() rejects a NULL db
     * (defensive-coding contract: log + return false, never crash). */
    printf("utxo_root_ladder: verify_against_store rejects NULL db... ");
    failures += test_ladder_null_db_refusal_failures();

    /* (5) Dense-layer fast path: a store that does not yet cover
     * g_utxo_root_ladder_dense_height must report "not yet reached" (true),
     * never a false divergence — exercised with a tiny synthetic store so
     * this stays hermetic (no multi-MB fixture needed). When the dense
     * anchor is absent (height==-1, e.g. a freshly-regenerated placeholder
     * table with no --leaf-store given), the same call must also return
     * true trivially. */
    printf("utxo_root_ladder: dense anchor matches and detects mismatch... ");
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "utxo_root_ladder_dense", "main");
        char store_path[300];
        snprintf(store_path, sizeof(store_path), "%s/mmb_leaves_tiny.bin", dir);

        struct mmb_leaf_store store;
        ASSERT(mmb_leaf_store_open(&store, store_path));
        /* Append far fewer leaves than any plausible dense_height (which is
         * always in the millions once populated) — the store legitimately
         * cannot cover it yet. */
        uint8_t h[32] = {0};
        for (int i = 0; i < 3; i++) {
            h[0] = (uint8_t)i;
            ASSERT(mmb_leaf_store_append(&store, h));
        }
        ASSERT(mmb_leaf_store_remap(&store));

        uint8_t mismatch[32];
        bool ok = utxo_root_ladder_verify_dense_anchor(&store, mismatch);
        ASSERT(ok);

        struct mmb expected_mmb;
        mmb_init(&expected_mmb);
        for (uint64_t i = 0; i < store.num_leaves; i++)
            ASSERT(mmb_append_hash(
                &expected_mmb, mmb_leaf_store_get(&store, i)) >= 0);
        uint8_t expected[32];
        mmb_root(&expected_mmb, expected);
        ASSERT(utxo_root_ladder_verify_dense_anchor_for_test(
            &store, 2, expected, mismatch));

        uint8_t wrong[32];
        memcpy(wrong, expected, sizeof(wrong));
        wrong[0] ^= 1u;
        ASSERT(!utxo_root_ladder_verify_dense_anchor_for_test(
            &store, 2, wrong, mismatch));
        ASSERT(memcmp(mismatch, expected, sizeof(expected)) == 0);

        mmb_leaf_store_close(&store);
        test_rm_rf_recursive(dir);
        printf("OK\n");
    }

    /* (6) The generator tool must REFUSE a source db whose best-chain
     * height sits within one stride of INT32_MAX: pre-fix, the stride
     * loop's final `h += c.stride` overflowed to a negative height, the
     * `h <= max_h` test stayed true, and the loop never terminated (two
     * sqlite queries per wrapped iteration, climbing and wrapping
     * forever). The crafted db below carries one best-chain block at
     * height 2147483600 with default stride 100000; the tool is exec'd
     * against it with a hard timeout and must exit nonzero with a named
     * refusal well inside the budget. */
#if !defined(_WIN32)
    printf("utxo_root_ladder: generator refuses a near-INT32_MAX source "
           "height instead of looping forever... ");
    failures += test_generator_refuses_huge_height();
#else
    printf("utxo_root_ladder: generator refuses a near-INT32_MAX source "
           "height instead of looping forever... skipped on Windows "
           "(fork/exec harness)\n");
#endif

    /* (7) NIGHTLY ADDITION: recompute mmb_root() from a REAL
     * mmb_leaves.bin copy
     * (millions of leaves) and confirm it reproduces the locked dense
     * anchor bit-for-bit — opt-in, mirrors test_self_folded_anchor.c's
     * ZCL_SELF_FOLD_ANCHOR_FIXTURE convention.
     *
     *   ZCL_UTXO_LADDER_HEAVY=1 \
     *   ZCL_UTXO_LADDER_LEAF_STORE=/path/to/mmb_leaves.bin \
     *     build/bin/test_parallel --only=utxo_root_ladder
     */
    printf("utxo_root_ladder: dense anchor reproduces from a real leaf "
          "store (opt-in)... ");
    {
        const char *heavy = getenv("ZCL_UTXO_LADDER_HEAVY");
        const char *store_path = getenv("ZCL_UTXO_LADDER_LEAF_STORE");

        if (test_ladder_dense_anchor_absent()) {
            printf("not applicable (no compiled dense anchor)\n");
        } else if (!test_ladder_heavy_run_requested(heavy, store_path)) {
            printf("covered hermetically; simnet-nightly adds the real "
                  "leaf-store observation\n");
        } else {
            struct mmb_leaf_store store;
            ASSERT(mmb_leaf_store_open(&store, store_path));
            uint8_t mismatch[32] = {0};
            bool ok = utxo_root_ladder_verify_dense_anchor(&store, mismatch);
            mmb_leaf_store_close(&store);
            if (!ok) {
                printf("FAIL (recomputed mmb_root does not match the locked "
                      "dense anchor at h=%d)\n", g_utxo_root_ladder_dense_height);
                failures++;
                goto _test_next;
            }
            printf("OK (reproduced dense mmb_root @ h=%d)\n",
                  g_utxo_root_ladder_dense_height);
        }
    }

    goto _done;
_test_next:
    printf("(section aborted)\n");
_done:
    test_ladder_print_summary(failures);
    return failures;
}

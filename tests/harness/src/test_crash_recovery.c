/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_crash_recovery — regressions for the crash-recovery harness's
 * path-argument handling (tools/crash_recovery_test.c ->
 * build/bin/crash_recovery_test).
 *
 * The harness copies --datadir/--connect into fixed buffers with snprintf
 * and never checked the would-have-written length. A truncated datadir
 * reached sqlite3_open_v2, popen's stderr redirect and the spawned node's
 * -datadir; a truncated connect reached -connect. These cases pin the
 * refusal: an over-long path argument exits 2 naming the flag before any
 * spawn or open, and help still exits successfully. */

#include "test/test_core.h"
#include "util/spawn.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#if defined(_WIN32)
#define CRASH_RECOVERY_BIN "build/bin/crash_recovery_test.exe"
#else
#define CRASH_RECOVERY_BIN "build/bin/crash_recovery_test"
#endif

/* 699 chars: over every fixed path buffer the harness copies into. */
static const char *cr_long_arg(void)
{
    static char arg[700];
    memset(arg, 'x', sizeof(arg) - 1);
    arg[sizeof(arg) - 1] = '\0';
    return arg;
}

/* Run the harness with merged stdout+stderr (the refusal goes to
 * stderr); returns the exit status, or -1 on a spawn failure. */
static int cr_run_merged(char *out, size_t out_size, bool *timed_out,
                         const char *const argv[])
{
    return zcl_spawn_capture_merged_observed(argv, out, out_size, 30000,
                                             timed_out);
}

static int test_crash_recovery_datadir_refused(void)
{
    int failures = 0;
    char buf[4096] = {0};
    char flag[720] = {0};
    bool timed_out = false;
    int n = snprintf(flag, sizeof(flag), "--datadir=%s", cr_long_arg());
    TEST("crash_recovery: over-long --datadir refused before any spawn") {
        ASSERT(n > 0 && (size_t)n < sizeof(flag));
        const size_t lengths[] = {699, 512};
        for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
            flag[10 + lengths[i]] = '\0';
            const char *const argv[] = {
                CRASH_RECOVERY_BIN, "--datadir=", flag, "--regtest",
                "--iterations=1", "--seed=1", NULL};
            int rc = cr_run_merged(buf, sizeof(buf), &timed_out, argv);
            ASSERT(rc == 2);
            ASSERT(!timed_out);
            ASSERT(strstr(buf, "path argument too long: --datadir (max 511 characters)") != NULL);
            ASSERT(strstr(buf, "crash_recovery_test:\n") == NULL);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_crash_recovery_connect_refused(void)
{
    int failures = 0;
    char buf[4096] = {0};
    char flag[720] = {0};
    char root[512] = {0};
    char datadir_flag[540] = {0};
    bool created = false;
    bool timed_out = false;
    int n = snprintf(flag, sizeof(flag), "--connect=%s", cr_long_arg());
    TEST("crash_recovery: over-long --connect refused before any spawn") {
        ASSERT(n > 0 && (size_t)n < sizeof(flag));
        ASSERT(test_mkdtemp(root, sizeof(root), "crash_recovery") != NULL);
        created = true;
        n = snprintf(datadir_flag, sizeof(datadir_flag), "--datadir=%s/absent", root);
        ASSERT(n > 10 && n < 522);
        struct stat st;
        ASSERT(stat(datadir_flag + 10, &st) != 0 && errno == ENOENT);
        const size_t lengths[] = {699, 128};
        for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
            flag[10 + lengths[i]] = '\0';
            const char *const argv[] = {
                CRASH_RECOVERY_BIN, "--connect=", flag, datadir_flag,
                "--regtest", "--iterations=1", "--seed=1", NULL};
            int rc = cr_run_merged(buf, sizeof(buf), &timed_out, argv);
            ASSERT(rc == 2);
            ASSERT(!timed_out);
            ASSERT(strstr(buf, "path argument too long: --connect (max 127 characters)") != NULL);
            ASSERT(strstr(buf, "crash_recovery_test:\n") == NULL);
            ASSERT(stat(datadir_flag + 10, &st) != 0 && errno == ENOENT);
        }
        PASS();
    } _test_next:;
    if (created && rmdir(root) != 0) {
        fprintf(stderr, "crash_recovery: cannot remove fixture %s: %s\n", root, strerror(errno));
        failures++;
    }
    return failures;
}

static int test_crash_recovery_datadir_limit(void)
{
    int failures = 0;
    char buf[4096] = {0};
    char datadir_flag[522] = "--datadir=";
    char connect_flag[139] = "--connect=";
    bool timed_out = false;
    memset(datadir_flag + 10, 'x', 511);
    memset(connect_flag + 10, 'x', 128);
    TEST("crash_recovery: 511-character datadir reaches connect validation") {
        const char *const argv[] = {
            CRASH_RECOVERY_BIN, datadir_flag, connect_flag, "--seed=1", NULL};
        int rc = cr_run_merged(buf, sizeof(buf), &timed_out, argv);
        ASSERT(rc == 2);
        ASSERT(!timed_out);
        ASSERT(strstr(buf, "path argument too long: --connect (max 127 characters)") != NULL);
        ASSERT(strstr(buf, "path argument too long: --datadir") == NULL);
        ASSERT(strstr(buf, "crash_recovery_test:\n") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* Both final values must win over earlier oversized options. The selected
 * datadir is absent beneath an owned fixture, so successful parsing cannot
 * enter recovery, even when the node and RPC executables are available. */
static int test_crash_recovery_last_paths_win(void)
{
    int failures = 0;
    char buf[4096] = {0};
    char oversized_datadir[720], oversized_connect[720];
    char root[512] = {0}, datadir_flag[540], expected[550];
    char connect_flag[138] = "--connect=";
    bool created = false, timed_out = false;
    memset(connect_flag + 10, 'x', 127);
    TEST("crash_recovery: final paths win and 127-character connect fits") {
        int n = snprintf(oversized_datadir, sizeof(oversized_datadir),
                         "--datadir=%s", cr_long_arg());
        ASSERT(n > 0 && (size_t)n < sizeof(oversized_datadir));
        n = snprintf(oversized_connect, sizeof(oversized_connect),
                     "--connect=%s", cr_long_arg());
        ASSERT(n > 0 && (size_t)n < sizeof(oversized_connect));
        ASSERT(test_mkdtemp(root, sizeof(root), "crash_recovery_last") != NULL);
        created = true;
        n = snprintf(datadir_flag, sizeof(datadir_flag), "--datadir=%s/absent", root);
        ASSERT(n > 10 && n < 522);
        struct stat st;
        ASSERT(stat(datadir_flag + 10, &st) != 0 && errno == ENOENT);
        n = snprintf(expected, sizeof(expected), "  datadir:      %s\n", datadir_flag + 10);
        ASSERT(n > 0 && (size_t)n < sizeof(expected));
        const char *const argv[] = {
            CRASH_RECOVERY_BIN, oversized_datadir, oversized_connect,
            datadir_flag, connect_flag, "--regtest", "--iterations=1", "--seed=1", NULL};
        int rc = cr_run_merged(buf, sizeof(buf), &timed_out, argv);
        ASSERT(!timed_out);
        ASSERT(strstr(buf, "crash_recovery_test:\n") != NULL);
        ASSERT(strstr(buf, expected) != NULL);
        ASSERT(strstr(buf, "path argument too long:") == NULL);
        /* A parse-only group builds the harness, not the node/RPC pair.
         * Accept only the two known exits before recovery can start. */
        if (rc == 0)
            ASSERT(strstr(buf, "does not exist — SKIP") != NULL);
        else {
            ASSERT(rc == 2);
            ASSERT(strstr(buf, "node or RPC binary missing;") != NULL);
        }
        ASSERT(stat(datadir_flag + 10, &st) != 0 && errno == ENOENT);
        PASS();
    } _test_next:;
    if (created && rmdir(root) != 0) {
        fprintf(stderr, "crash_recovery: cannot remove fixture %s: %s\n", root, strerror(errno));
        failures++;
    }
    return failures;
}

static int test_crash_recovery_help_still_works(void)
{
    int failures = 0;
    char buf[4096] = {0};
    char datadir_flag[720] = {0};
    char connect_flag[720] = {0};
    bool timed_out = false;
    TEST("crash_recovery: help short-circuits even with over-long paths") {
        int n = snprintf(datadir_flag, sizeof(datadir_flag), "--datadir=%s", cr_long_arg());
        ASSERT(n > 0 && (size_t)n < sizeof(datadir_flag));
        n = snprintf(connect_flag, sizeof(connect_flag), "--connect=%s", cr_long_arg());
        ASSERT(n > 0 && (size_t)n < sizeof(connect_flag));
        const char *const cases[][5] = {
            {CRASH_RECOVERY_BIN, "--help", NULL},
            {CRASH_RECOVERY_BIN, datadir_flag, connect_flag, "--help", NULL},
            {CRASH_RECOVERY_BIN, "-h", datadir_flag, connect_flag, NULL},
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            int rc = cr_run_merged(buf, sizeof(buf), &timed_out, cases[i]);
            ASSERT(rc == 0);
            ASSERT(!timed_out);
            ASSERT(strstr(buf, "Usage: crash_recovery_test") != NULL);
            ASSERT(strstr(buf, "path argument too long:") == NULL);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* Save and restore both default-path inputs before assertions can leave the
 * test. Fixed storage avoids introducing allocator call sites. */
static int cr_run_defaults(const char *datadir, const char *home,
                            char *out, size_t out_size, bool *timed_out)
{
    const char *const names[] = {"ZCL_CRASH_DATADIR", "HOME"};
    const char *const values[] = {datadir, home};
    char saved[2][8192] = {{0}};
    bool present[2] = {false, false};
    *timed_out = false;
    out[0] = '\0';
    for (size_t i = 0; i < 2; i++) {
        const char *value = getenv(names[i]);
        present[i] = value != NULL;
        if (!value) continue;
        int n = snprintf(saved[i], sizeof(saved[i]), "%s", value);
        if (n < 0 || (size_t)n >= sizeof(saved[i])) {
            fprintf(stderr, "crash_recovery: cannot save %s for fixture\n", names[i]);
            return -1;
        }
    }
    int rc = -1;
    size_t changed = 0;
    for (; changed < 2; changed++) {
        if (setenv(names[changed], values[changed], 1) != 0) {
            fprintf(stderr, "crash_recovery: cannot set %s: %s\n",
                    names[changed], strerror(errno));
            goto restore;
        }
    }
    const char *const argv[] = {CRASH_RECOVERY_BIN, "--help", NULL};
    rc = cr_run_merged(out, out_size, timed_out, argv);
restore:
    for (size_t i = 0; i < changed; i++) {
        int restored = present[i] ? setenv(names[i], saved[i], 1) : unsetenv(names[i]);
        if (restored != 0) {
            fprintf(stderr, "crash_recovery: cannot restore %s: %s\n",
                    names[i], strerror(errno));
            rc = -1;
        }
    }
    return rc;
}

static int test_crash_recovery_defaults_refused(void)
{
    int failures = 0;
    char buf[4096] = {0};
    char env[700] = {0};
    bool timed_out = false;
    memcpy(env, cr_long_arg(), sizeof(env));
    TEST("crash_recovery: over-long environment datadir warns before --help") {
        const size_t lengths[] = {699, 512};
        for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
            env[lengths[i]] = '\0';
            int rc = cr_run_defaults(env, ".", buf, sizeof(buf), &timed_out);
            ASSERT(rc == 0);
            ASSERT(!timed_out);
            ASSERT(strstr(buf, "ZCL_CRASH_DATADIR too long (max 511 characters); "
                               "using the default datadir") != NULL);
            ASSERT(strstr(buf, "HOME default datadir") == NULL);
            ASSERT(strstr(buf, "Usage: crash_recovery_test") != NULL);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_crash_recovery_home_refused(void)
{
    int failures = 0;
    char buf[4096] = {0};
    char home[700] = {0};
    bool timed_out = false;
    memcpy(home, cr_long_arg(), sizeof(home));
    TEST("crash_recovery: over-long HOME default warns before --help") {
        /* The suffix occupies 24 bytes: 487 + 24 fits, 488 + 24 does not. */
        const size_t lengths[] = {699, 488};
        for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
            home[lengths[i]] = '\0';
            int rc = cr_run_defaults("", home, buf, sizeof(buf), &timed_out);
            ASSERT(rc == 0);
            ASSERT(!timed_out);
            ASSERT(strstr(buf, "HOME default datadir too long or invalid; "
                               "using the default datadir") != NULL);
            ASSERT(strstr(buf, "ZCL_CRASH_DATADIR too long") == NULL);
            ASSERT(strstr(buf, "Usage: crash_recovery_test") != NULL);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* One receipt line per run, read back through the shared evidence reader.
 * The selftest owns a temp ledger, appends a malformed row between two good
 * receipts, and must report exactly the two valid rows back. */
static int test_crash_recovery_receipt_roundtrip(void)
{
    int failures = 0;
    char buf[4096] = {0};
    char root[512] = {0};
    char ledger[600] = {0};
    char flag[640] = {0};
    bool created = false;
    bool timed_out = false;
    TEST("crash_recovery: receipt round-trips and a malformed row is skipped") {
        ASSERT(test_mkdtemp(root, sizeof(root), "crash_receipt") != NULL);
        created = true;
        int n = snprintf(ledger, sizeof(ledger), "%s/receipts.jsonl", root);
        ASSERT(n > 0 && (size_t)n < sizeof(ledger));
        n = snprintf(flag, sizeof(flag), "--receipt-selftest=%s", ledger);
        ASSERT(n > 0 && (size_t)n < sizeof(flag));
        const char *const argv[] = {CRASH_RECOVERY_BIN, flag, NULL};
        int rc = cr_run_merged(buf, sizeof(buf), &timed_out, argv);
        ASSERT(!timed_out);
        ASSERT(rc == 0);
        ASSERT(strstr(buf, "crash receipt selftest: PASS") != NULL);
        ASSERT(strstr(buf, "valid=2 skipped=1") != NULL);
        PASS();
    } _test_next:;
    if (created) {
        if (unlink(ledger) != 0 && errno != ENOENT) {
            fprintf(stderr, "crash_recovery: cannot remove receipt %s: %s\n", ledger, strerror(errno));
            failures++;
        }
        if (rmdir(root) != 0) {
            fprintf(stderr, "crash_recovery: cannot remove fixture %s: %s\n", root, strerror(errno));
            failures++;
        }
    }
    return failures;
}

int test_crash_recovery(void)
{
    int failures = 0;
    struct stat st;
    if (stat(CRASH_RECOVERY_BIN, &st) != 0 || (st.st_mode & S_IXUSR) == 0) {
        fprintf(stderr, "crash_recovery: required " CRASH_RECOVERY_BIN " missing (run: "
                        "make crash_recovery_test)\n");
        return 1;
    }
    failures += test_crash_recovery_datadir_refused();
    failures += test_crash_recovery_connect_refused();
    failures += test_crash_recovery_datadir_limit();
    failures += test_crash_recovery_last_paths_win();
    failures += test_crash_recovery_help_still_works();
    failures += test_crash_recovery_defaults_refused();
    failures += test_crash_recovery_home_refused();
    failures += test_crash_recovery_receipt_roundtrip();
    return failures;
}

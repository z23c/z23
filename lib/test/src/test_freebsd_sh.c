/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_freebsd_sh — smoke acceptance for the vendored FreeBSD /bin/sh
 * (vendor/freebsd-sh, built standalone as build/bin/fbsh by `make fbsh`).
 * Drives the real binary through zcl_spawn_capture exactly the way an
 * operator invokes it, and asserts exact stdout so a codegen, compat, or
 * build regression (builtins.c/nodes.c/syntax.c generation, the
 * d_namlen build-time patch, the setmode/getmode + sys_signame shims)
 * fails loudly instead of degrading silently.
 *
 * Skips (does not fail) if build/bin/fbsh is missing — the binary is a
 * standalone target deliberately kept out of `all` and out of the test
 * binaries' prerequisites (fbsh is Linux-only today, and the shared dev
 * loop also runs on macOS). Build it first:
 *
 *   make fbsh
 *   make t-fast ONLY=freebsd_sh
 */

#include "test/test_core.h"
#include "util/spawn.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define FBSH_BIN "build/bin/fbsh"

static bool fbsh_available(void)
{
    struct stat st;
    return stat(FBSH_BIN, &st) == 0 && (st.st_mode & S_IXUSR) != 0;
}

/* Exact-output assertion over one `fbsh -c` invocation. */
static int fbsh_run(const char *script, char *buf, size_t buflen)
{
    const char *argv[] = { FBSH_BIN, "-c", script, NULL };
    return zcl_spawn_capture(argv, buf, buflen, 5000);
}

/* Case 1: the headline smoke — -c, echo builtin, for loop, $i. */
static int test_fbsh_c_echo_for(void)
{
    int failures = 0;
    TEST("fbsh: -c echo and for loop") {
        char buf[256] = {0};
        int rc = fbsh_run("echo ok; for i in 1 2 3; do echo $i; done",
                          buf, sizeof(buf));
        ASSERT(rc == 0);
        ASSERT(strcmp(buf, "ok\n1\n2\n3\n") == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Case 2: POSIX-ish script — pipeline, redirect, command substitution,
 * quoting, arithmetic loop, test builtin. Exact stdout asserted. */
static int test_fbsh_posix_script(void)
{
    int failures = 0;
    TEST("fbsh: pipeline/redirect/substitution/quoting/arithmetic") {
        char buf[512] = {0};
        int rc = fbsh_run(
            "set -e; d=/tmp/fbsh_test_$$; "
            "mkdir -p \"$d\"; "
            "echo \"hello world\" | tr a-z A-Z > \"$d/out.txt\"; "
            "x=$(printf '%s' \"q u o t e\"); "
            "[ \"$x\" = \"q u o t e\" ]; "
            "n=0; for f in a b c; do n=$((n + 1)); done; "
            "[ \"$n\" -eq 3 ]; "
            "cat \"$d/out.txt\"; "
            "rm -rf \"$d\"; "
            "echo done",
            buf, sizeof(buf));
        ASSERT(rc == 0);
        ASSERT(strcmp(buf, "HELLO WORLD\ndone\n") == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Case 3: the ported seams — pathname expansion through the build-time
 * d_namlen patch in expand.c, and the umask builtin through the compat
 * setmode/getmode. */
static int test_fbsh_glob_and_symbolic_umask(void)
{
    int failures = 0;
    TEST("fbsh: glob (d_namlen patch) and symbolic umask (setmode compat)") {
        char buf[512] = {0};
        int rc = fbsh_run(
            "set -e; d=/tmp/fbsh_test_$$; "
            "mkdir -p \"$d/g\"; touch \"$d/g/alpha\" \"$d/g/gamma\"; "
            "(cd \"$d/g\" && set -- a* g* && echo \"glob:$1,$2\"); "
            "umask 022; umask u=rwx,g=rx,o=; umask; "
            "rm -rf \"$d\"",
            buf, sizeof(buf));
        ASSERT(rc == 0);
        ASSERT(strcmp(buf, "glob:alpha,gamma\n0027\n") == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Case 4: kill builtin signal-name table (compat sys_signame/sys_nsig)
 * and real exit-status propagation. */
static int test_fbsh_kill_and_exit_status(void)
{
    int failures = 0;
    TEST("fbsh: kill -l name table and exit status") {
        char buf[256] = {0};
        int rc = fbsh_run("kill -l 9; kill -l 15; exit 3", buf, sizeof(buf));
        ASSERT(rc == 3);
        ASSERT(strcmp(buf, "kill\nterm\n") == 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_freebsd_sh(void)
{
    int failures = 0;
    printf("\n=== FreeBSD sh (fbsh) Smoke Tests ===\n");

    if (!fbsh_available()) {
        printf("freebsd_sh: " FBSH_BIN " not built — SKIP "
               "(run `make fbsh` first)\n");
        printf("FreeBSD sh: 0 failures (skipped)\n");
        return 0;
    }

    failures += test_fbsh_c_echo_for();
    failures += test_fbsh_posix_script();
    failures += test_fbsh_glob_and_symbolic_umask();
    failures += test_fbsh_kill_and_exit_status();

    printf("FreeBSD sh: %d failures\n", failures);
    return failures;
}

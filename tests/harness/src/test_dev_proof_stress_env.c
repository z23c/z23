/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_dev_proof_stress_env — regressions for the proof worker's test
 * environment and libclang runtime admission.
 *
 * Roughly sixteen registered groups carry a guard shaped exactly like:
 *
 *     if (!getenv("ZCL_STRESS_TESTS")) {
 *         printf("SKIP (set ZCL_STRESS_TESTS=1 to run ...)\n");
 *         return 0;
 *     }
 *
 * (tests/harness/src/test_kill9_recovery.c, test_cold_start_sync.c,
 * test_onion_bootstrap.c, test_chain_advance_atomicity.c, and others — see
 * `git grep -n ZCL_STRESS_TESTS tests/harness/src`). The push proof's test
 * dimension execs its runner with execvp(), which reuses this process's own
 * `environ` — there is no separate envp built per child, so whatever this
 * process last set is exactly what every forked test child inherits. A
 * resident proof daemon forks many cycles from one long-lived process and
 * keeps the environment it started with, so until tools/dev/dev_proof.c set
 * this unconditionally right before launching the test dimension, every one
 * of those guards read absent and every push proof silently admitted a
 * commit having never run its stress lane.
 *
 * Driving one of the real stress groups here would pull a fork-heavy,
 * sleep-driven, or Tor-network fixture into a fast registered group just to
 * watch it NOT print "SKIP (" — too heavy for this tier. Instead this proves
 * the narrower, load-bearing fact directly: calling
 * zcl_dev_proof_test_stress_env_prepare() — the ZCL_TESTING seam onto the
 * exact static helper (dev_proof.c's proof_stress_tests_env_prepare()) that
 * proof_worker() calls right before the test dimension launches — flips the
 * same getenv() every guard above reads, unconditionally, regardless of
 * what the variable held before the call. */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"

#include "dev_proof.h"
#include "dev_proof_budget.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#if defined(__APPLE__)
#include <fcntl.h>
#endif

#if defined(__linux__) && defined(__x86_64__)
static bool dps_clang_runtime_environment(int mode)
{
    if (mode == 0)
        return unsetenv("CLANG_MANIFEST_LLVM_DIR") == 0 &&
               unsetenv("CLANG_MANIFEST_SYSTEM_LIB") == 0;
    char untrusted[PATH_MAX];
    if ((mode == 1 || mode == 2) &&
        !test_mkdtemp(untrusted, sizeof untrusted, "proof_clang_runtime"))
        return false;
    if (mode == 1)
        return setenv("CLANG_MANIFEST_LLVM_DIR", untrusted, 1) == 0 &&
               unsetenv("CLANG_MANIFEST_SYSTEM_LIB") == 0;
    return setenv("CLANG_MANIFEST_LLVM_DIR", "/usr", 1) == 0 &&
           setenv("CLANG_MANIFEST_SYSTEM_LIB",
                  mode == 2 ? untrusted :
                              "/usr/lib/libclang.so.22.1", 1) == 0;
}

static int dps_clang_runtime_child(int mode)
{
    char why[80] = {0};
    if (!dps_clang_runtime_environment(mode)) return 1;
    bool accepted = zcl_dev_proof_test_clang_runtime_check(why, sizeof(why));
    if (mode == 0) return accepted ? 0 : 2;
    if (mode == 3) {
        const char *path = zcl_dev_proof_test_clang_runtime_path();
        return accepted && path &&
               strcmp(path, "/usr/lib/libclang.so.22.1") == 0 ? 0 : 4;
    }
    const char *expected = mode == 1 ? "proof_clang_runtime_unpinned" :
                                       "proof_clang_system_lib_untrusted";
    return !accepted && strcmp(why, expected) == 0 ? 0 : 5;
}

static int test_dps_clang_runtime(void)
{
    int failures = 0;
    TEST_CASE("dev_proof: system libclang accepts only pinned root-owned paths")
    {
        int last = access("/usr/include/clang-c/Index.h", F_OK) == 0 &&
                   access("/usr/lib/libclang.so.22.1", F_OK) == 0 ? 3 : 2;
        for (int mode = 0; mode <= last; mode++) {
            pid_t child = fork();
            ASSERT(child >= 0);
            if (child == 0) _exit(dps_clang_runtime_child(mode));
            int status = 0;
            ASSERT(waitpid(child, &status, 0) == child);
            ASSERT(WIFEXITED(status));
            ASSERT(WEXITSTATUS(status) == 0);
        }
    }
    TEST_END
    return failures;
}
#endif

static int test_dps_absent_becomes_present(void)
{
    int failures = 0;
    TEST_CASE("dev_proof_stress_env: absent before, exec-visible after")
    {
        /* Start from the state a resident daemon's stale first environment
         * would leave: the variable absent, which is exactly the branch
         * every self-skipping group's `if (!getenv("ZCL_STRESS_TESTS"))`
         * takes. */
        (void)unsetenv("ZCL_STRESS_TESTS");
        ASSERT(getenv("ZCL_STRESS_TESTS") == NULL);

        char why[160] = {0};
        ASSERT(zcl_dev_proof_test_stress_env_prepare(why, sizeof(why)));
        ASSERT(why[0] == '\0');

        /* Every self-skip guard in the suite reads exactly this call's
         * effect via getenv("ZCL_STRESS_TESTS"). */
        const char *value = getenv("ZCL_STRESS_TESTS");
        ASSERT(value != NULL);
        ASSERT_STR_EQ(value, "1");
    }
    TEST_END
    (void)unsetenv("ZCL_STRESS_TESTS");
    return failures;
}

static int test_dps_unconditional_overwrite(void)
{
    int failures = 0;
    TEST_CASE("dev_proof_stress_env: unconditional, overwrites a stale value")
    {
        /* A prior tool, or a resident daemon's very first environment,
         * could have exported a falsy value. The proof must not defer to
         * it — the whole point of the fix is that the test dimension no
         * longer depends on what invoked this binary. */
        ASSERT(setenv("ZCL_STRESS_TESTS", "0", 1) == 0);
        ASSERT_STR_EQ(getenv("ZCL_STRESS_TESTS"), "0");

        char why[160] = {0};
        ASSERT(zcl_dev_proof_test_stress_env_prepare(why, sizeof(why)));
        ASSERT_STR_EQ(getenv("ZCL_STRESS_TESTS"), "1");
    }
    TEST_END
    (void)unsetenv("ZCL_STRESS_TESTS");
    return failures;
}

#if defined(__APPLE__)
/* The worker's descriptors are authority even when the child cannot open
 * their original paths. Exercise the real step launcher after lowering the
 * descriptor ceiling: a loop bounded by the new limit would miss fd 512. */
static int test_dps_mac_child_descriptors(void)
{
    int failures = 0;
    TEST_CASE("dev_proof: Mac steps inherit neither stdin nor high descriptors")
    {
        char root[4096], input[4096], log[4096];
        test_make_tmpdir(root, sizeof(root), "proof_descriptors", "mac");
        ASSERT(snprintf(input, sizeof(input), "%s/input", root) > 0);
        ASSERT(snprintf(log, sizeof(log), "%s/child.log", root) > 0);
        int source = open(input, O_RDWR | O_CREAT | O_TRUNC, 0600);
        ASSERT(source >= 0);
        ASSERT(write(source, "fixture-authority\n", 18) == 18);
        ASSERT(lseek(source, 0, SEEK_SET) == 0);
        /* Only the fixture subprocess changes its stdin and limits. */
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            if (dup2(source, 512) != 512 ||
                dup2(source, STDIN_FILENO) != STDIN_FILENO)
                _exit(70);
            struct rlimit limit;
            if (getrlimit(RLIMIT_NOFILE, &limit) != 0) _exit(71);
            limit.rlim_cur = 128;
            if (setrlimit(RLIMIT_NOFILE, &limit) != 0) _exit(72);
            const struct zcl_dev_proof_budget budget = {
                .budget_ms = 5000, .ceiling_ms = 5000,
                .no_progress_ms = 5000,
            };
            const char *fds[] = {
                "/bin/sh", "-c", "test ! -e /dev/fd/512", NULL,
            };
            const char *stdin_probe[] = {
                "/bin/sh", "-c", "if IFS= read -r line; then exit 1; fi",
                NULL,
            };
            int fd_rc = zcl_dev_proof_run_watched(
                ".", log, fds, &budget, NULL);
            int stdin_rc = zcl_dev_proof_run_watched(
                ".", log, stdin_probe, &budget, NULL);
            _exit(fd_rc == 0 && stdin_rc == 0 ? 0 : 73);
        }
        int status = 0;
        ASSERT(waitpid(child, &status, 0) == child);
        ASSERT(close(source) == 0);
        ASSERT(WIFEXITED(status));
        ASSERT(WEXITSTATUS(status) == 0);
        ASSERT(test_rm_rf_recursive(root) == 0);
    }
    TEST_END
    return failures;
}
#endif

#if defined(__linux__) || defined(__APPLE__)
static bool dps_read_phase(const char *path, char *body, size_t cap)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return false;
    size_t n = fread(body, 1, cap - 1, fp);
    bool ok = n > 0 && !ferror(fp);
    body[n] = '\0';
    return fclose(fp) == 0 && ok;
}

static bool dps_owned_cpu(const char *log, struct zcl_dev_proof_step_report *report)
{
    struct zcl_dev_proof_step step = {0};
    const struct zcl_dev_proof_budget budget = {5000, 5000, 5000};
    const char *argv[] = {"/bin/sh", "-c", "exit 7", NULL};
    if (!zcl_dev_proof_step_start(&step, ".", log, argv, &budget)) return false;
    bool ok = !step.report.cpu_available;
    pid_t other = fork();
    if (other == 0) _exit(0);
    int status = 0;
    pid_t got = -1;
    if (other > 0) do { got = waitpid(other, &status, 0); } while (got < 0 && errno == EINTR);
    if (other < 0 || got != other || !WIFEXITED(status)) ok = false;
    (void)zcl_dev_proof_steps_wait(&step, 1);
    if (!step.finished) zcl_dev_proof_step_cancel(&step);
    *report = step.report;
    return ok && step.finished && report->rc == 7 && report->cpu_available &&
           report->cpu_user_us >= 0 && report->cpu_system_us >= 0;
}

static int test_dps_step_cpu(void)
{
    int failures = 0;
    TEST_CASE("dev_proof: watched child CPU is present only after owned reap") {
        char root[4096], log[4096], phases[4096], body[2048] = {0};
        test_make_tmpdir(root, sizeof(root), "proof_cpu", "child");
        ASSERT(snprintf(log, sizeof(log), "%s/log", root) > 0);
        ASSERT(snprintf(phases, sizeof(phases), "%s/phases", root) > 0);
        struct zcl_dev_proof_step_report report = {0};
        ASSERT(zcl_dev_proof_phase_record(phases, "unavailable", &report));
        ASSERT(dps_read_phase(phases, body, sizeof(body)) && !strstr(body, "cpu_user_us="));
        ASSERT(dps_owned_cpu(log, &report));
        zcl_dev_proof_test_cpu_sample(&report, 2, 123, 3, 456);
        ASSERT(report.cpu_available && report.cpu_user_us == 2000123 && report.cpu_system_us == 3000456);
        ASSERT(zcl_dev_proof_phase_record(phases, "bundle", &report));
        zcl_dev_proof_test_cpu_sample(&report, 4, 789, 5, 678);
        ASSERT(zcl_dev_proof_phase_record(phases, "bundle", &report));
        memset(body, 0, sizeof(body));
        ASSERT(dps_read_phase(phases, body, sizeof(body)));
        ASSERT(strstr(body, "cpu_user_us=2000123") && strstr(body, "cpu_system_us=3000456"));
        ASSERT(strstr(body, "cpu_user_us=4000789") && strstr(body, "cpu_system_us=5000678"));
        ASSERT(test_rm_rf_recursive(root) == 0);
    } TEST_END
    return failures;
}
#endif

int test_dev_proof_stress_env(void)
{
    int failures = 0;
    failures += test_dps_absent_becomes_present();
    failures += test_dps_unconditional_overwrite();
#if defined(__linux__) || defined(__APPLE__)
    failures += test_dps_step_cpu();
#endif
#if defined(__linux__) && defined(__x86_64__)
    failures += test_dps_clang_runtime();
#endif
#if defined(__APPLE__)
    failures += test_dps_mac_child_descriptors();
#endif
    return failures;
}

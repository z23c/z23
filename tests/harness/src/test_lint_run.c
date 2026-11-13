/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: `z23-lint run` (tools/lint/lintc/run_*.c), the C23 lint driver, on
 *          fixture gates: pass, fail (rc and log), silent fail, killed, a
 *          && chain, and a rendezvous pair that only passes when two gates
 *          really run at once. Also the shell-free command parser, the
 *          check_*.sh wrapper rewrite, the compiled gate table, the
 *          serial and long-pole ordering, and the artifacts it leaves.
 *          check-core-seal's pipe reaches EOF and keeps core_seal's rc.
 * Vendor dispatch uses the real table with fixture programs; the actual
 * vendor gates and Make wiring are not exercised here. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"

#include "lint/lintc/run_priv.h"

#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(_WIN32)

struct lrun_fx {
    char root[PATH_MAX];
};

static bool lrun_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    return fputs(text, f) >= 0 && fclose(f) == 0;
}

static bool lrun_read(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    size_t n;
    if (!f)
        return false;
    n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    (void)fclose(f);
    return true;
}

#define LRUN_RV "sh -c 'touch %s/%s; i=0; while [ ! -e %s/%s ] && [ $i -lt 15 ]; " \
    "do sleep 0.1; i=$((i+1)); done; [ -e %s/%s ]'"

/* Fixture gate -> command. Names: check-fx-<kind>; check-fx-ord-<tag> appends
 * <tag> to <root>/order; the rendezvous pair waits for each other's file. */
static int lrun_resolve(void *ctx, const char *gate, char *cmd, size_t cap)
{
    const struct lrun_fx *fx = ctx;
    const char *r = fx->root;
    if (strcmp(gate, "check-capability-inventory-generated") == 0)
        return lrun_resolve(ctx, "check-fx-ord-generator", cmd, cap);
    if (strcmp(gate, "check-vendor-provenance") == 0) {
        static struct lr_table t;
        if (lr_table_load(&t) != 0)
            return 1;
        const struct lr_table_row *row = lr_table_find(&t, gate);
        if (!row)
            return 1;
        int n = snprintf(cmd, cap, "%s", row->cmd);
        return n < 0 || (size_t)n >= cap;
    }
    if (strcmp(gate, "check-fx-pass") == 0)
        return snprintf(cmd, cap, "true") < 0;
    if (strcmp(gate, "check-fx-fail") == 0)
        return snprintf(cmd, cap, "sh -c 'echo boom-diagnosis; exit 3'") < 0;
    if (strcmp(gate, "check-fx-silent") == 0)
        return snprintf(cmd, cap, "false") < 0;
    if (strcmp(gate, "check-fx-crash") == 0)
        return snprintf(cmd, cap, "sh -c 'kill -KILL $$'") < 0;
    if (strcmp(gate, "check-fx-chain") == 0)
        return snprintf(cmd, cap, "true && sh -c 'exit 5' && sh -c 'echo ran > %s/never'", r) < 0;
    if (strcmp(gate, "check-fx-noexec") == 0)
        return snprintf(cmd, cap, "/nonexistent/lrun-fixture-binary") < 0;
    if (strcmp(gate, "check-fx-rv-a") == 0)
        return snprintf(cmd, cap, LRUN_RV, r, "ra", r, "rb", r, "rb") < 0;
    if (strcmp(gate, "check-fx-rv-b") == 0)
        return snprintf(cmd, cap, LRUN_RV, r, "rb", r, "ra", r, "ra") < 0;
    if (strncmp(gate, "check-fx-ord-", 13) == 0)
        return snprintf(cmd, cap, "sh -c 'echo %s >> %s/order'", gate + 13, r) < 0;
    return 1;
}

static bool lrun_vendor_setup(const char *root)
{
    static const char *dirs[] = {"build", "build/bin", "tools", "tools/scripts",
                                 "vendor", "vendor/patches", "vendor/provenance",
                                 "fakebin"};
    static const char *programs[] = {"build/bin/z23-lint", "tools/scripts/test_vendor_provenance.sh",
        "tools/scripts/build_vendor_offline_selftest.sh", "build/bin/repro-network-policy-selftest",
        "fakebin/sha256sum"};
    static const char script[] = "#!/bin/sh\n"
        "printf '%s %s\\n' \"$0\" \"$*\" >> trace\n"
        "case $0 in *build_vendor_offline_selftest.sh) [ ! -f fail-offline ] || exit 7;; esac\n"
        "case $0 in *sha256sum) [ \"$1\" = --check ] || printf 'fixture  -\\n';; esac\n";
    char path[PATH_MAX + 128];
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
        (void)snprintf(path, sizeof path, "%s/%s", root, dirs[i]);
        if (mkdir(path, 0700) != 0) return false;
    }
    for (size_t i = 0; i < sizeof programs / sizeof programs[0]; i++) {
        (void)snprintf(path, sizeof path, "%s/%s", root, programs[i]);
        if (!lrun_write(path, script) || chmod(path, 0700) != 0) return false;
    }
    (void)snprintf(path, sizeof path, "%s/vendor/patches/tor-dynhost-stream-shutdown.patch", root);
    if (!lrun_write(path, "fixture\n")) return false;
    (void)snprintf(path, sizeof path, "%s/vendor/provenance/tor.manifest", root);
    return lrun_write(path, "build_time_patch_sha256=fixture\n");
}

static bool lrun_plant(struct lrun_fx *fx);

static bool lrun_epoch_file(const char *root, const char *rel, const char *body,
                            bool executable)
{
    char path[PATH_MAX + 128];
    int n = snprintf(path, sizeof path, "%s/%s", root, rel);
    return n > 0 && (size_t)n < sizeof path && lrun_write(path, body) &&
           (!executable || chmod(path, 0700) == 0);
}

static bool lrun_epoch_setup(const char *root)
{
    static const char *const inputs[] = {
        "tools/dev/publish-build-alias.sh", "tools/dev/build-epoch-lock-wait.sh",
        "tools/dev/compile-epoch-object.sh", "tools/dev/build-epoch-session.sh",
        "tools/dev/build-epoch-open-file-identity.sh", "tools/dev/process-start-token.sh",
        "tools/dev/source-identity.sh", "tools/dev/make_depfile_scope_selftest.c",
        "tools/dev/make_depfile_scope_process.h", "Makefile",
    };
    static const char build_probe[] = "#!/bin/sh\necho run >> build.trace\n"
        "[ \"$(cat tools/dev/source_identity_batch.c)\" = good ]\n";
    static const char dep_probe[] = "#!/bin/sh\necho run >> dep.trace\n"
        "[ -z \"${MAKEFILES:-}\" ]\n";
    static const char key_tool[] = "#!/bin/sh\nprintf '%064d\\n' 0\n";
    char driver[16384], lint[PATH_MAX], target[PATH_MAX + 64], dir[PATH_MAX + 32];
    if (!lrun_read("tools/dev/build-epoch-integrity-cached.sh", driver, sizeof driver) ||
        !realpath("build/bin/z23-lint", lint)) return false;
    const char *dirs[] = {"tools", "tools/dev", "build", "build/bin"};
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
        (void)snprintf(dir, sizeof dir, "%s/%s", root, dirs[i]);
        if (mkdir(dir, 0700) != 0) return false;
    }
    for (size_t i = 0; i < sizeof inputs / sizeof inputs[0]; i++)
        if (!lrun_epoch_file(root, inputs[i], "fixture\n", false)) return false;
    (void)snprintf(target, sizeof target, "%s/build/bin/z23-lint", root);
    return symlink(lint, target) == 0 &&
        lrun_epoch_file(root, "tools/dev/build-epoch-integrity-cached.sh", driver, true) &&
        lrun_epoch_file(root, "tools/dev/build-epoch-key.sh", key_tool, true) &&
        lrun_epoch_file(root, "tools/dev/build-epoch-selftest.sh", build_probe, true) &&
        lrun_epoch_file(root, "build/bin/depfile-scope-launch", dep_probe, true) &&
        lrun_epoch_file(root, "tools/dev/source_identity_batch.c", "good\n", false) &&
        lrun_epoch_file(root, "poison.mk", "$(error fixture poison)\n", false);
}

static int lrun_epoch_driver(const char *root, bool poison)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        char cache[PATH_MAX + 32], makefiles[PATH_MAX + 32];
        (void)snprintf(cache, sizeof cache, "%s/cache", root);
        (void)snprintf(makefiles, sizeof makefiles, "%s/poison.mk", root);
        if (chdir(root) != 0 || setenv("ZCL_BUILD_EPOCH_CACHE_DIR", cache, 1) != 0 ||
            (poison ? setenv("MAKEFILES", makefiles, 1) : unsetenv("MAKEFILES")) != 0)
            _exit(127);
        execlp("bash", "bash", "tools/dev/build-epoch-integrity-cached.sh", (char *)NULL);
        _exit(127);
    }
    int status = 0;
    pid_t got;
    do { got = waitpid(pid, &status, 0); } while (got < 0 && errno == EINTR);
    return got == pid && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static size_t lrun_epoch_calls(const char *root, const char *name)
{
    char path[PATH_MAX + 64], data[256];
    (void)snprintf(path, sizeof path, "%s/%s", root, name);
    if (!lrun_read(path, data, sizeof data)) return 0;
    size_t count = 0;
    for (const char *p = data; *p; p++) if (*p == '\n') count++;
    return count;
}

static bool lrun_epoch_fixture(void)
{
    struct lrun_fx fx;
    if (!lrun_plant(&fx)) return false;
    bool setup = lrun_epoch_setup(fx.root);
    int rc[4] = {-1, -1, -1, -1};
    if (setup) {
        rc[0] = lrun_epoch_driver(fx.root, false);
        rc[1] = lrun_epoch_driver(fx.root, false);
        bool changed = lrun_epoch_file(fx.root, "tools/dev/source_identity_batch.c", "bad\n", false);
        if (changed) rc[2] = lrun_epoch_driver(fx.root, false);
        changed = lrun_epoch_file(fx.root, "tools/dev/source_identity_batch.c", "good\n", false);
        if (changed) rc[3] = lrun_epoch_driver(fx.root, true);
    }
    size_t build_calls = lrun_epoch_calls(fx.root, "build.trace");
    size_t dep_calls = lrun_epoch_calls(fx.root, "dep.trace");
    bool ok = setup && rc[0] == 0 && rc[1] == 0 && rc[2] == 1 && rc[3] == 1 &&
              build_calls == 4 && dep_calls == 4;
    if (!ok)
        fprintf(stderr, "epoch driver fixture setup=%d rc=%d,%d,%d,%d probe_calls=%zu,%zu\n",
                setup, rc[0], rc[1], rc[2], rc[3], build_calls, dep_calls);
    (void)test_rm_rf_recursive(fx.root);
    return ok;
}

static int test_lrun_epoch_driver(void)
{
    int failures = 0;
    TEST_CASE("lint_run: epoch probes rerun and refuse changed hidden inputs") {
        ASSERT(lrun_epoch_fixture());
    } TEST_END
    return failures;
}

struct lrun_cfg {
    int jobs;
    const char *pro, *epi, *poles;
};

/* Run GATES under the fixture resolver; capture both streams. */
static int lrun_go_prereq(struct lrun_fx *fx, const struct lrun_cfg *c, char *const *gates,
                   int n, char *out, char *err, size_t cap, const char *prereq)
{
    char state[PATH_MAX + 16];
    FILE *fo = tmpfile(), *fe = tmpfile();
    int rc;
    size_t k;
    (void)snprintf(state, sizeof state, "%s/state", fx->root);
    struct lr_opts o = { c->jobs, state, NULL, NULL, 75, false, fo, fe, lrun_resolve, fx,
                         c->pro, c->epi, c->poles };
    rc = lr_execute_with_prerequisite(&o, gates, n, prereq);
    rewind(fo);
    rewind(fe);
    k = fread(out, 1, cap - 1, fo);
    out[k] = '\0';
    k = fread(err, 1, cap - 1, fe);
    err[k] = '\0';
    (void)fclose(fo);
    (void)fclose(fe);
    return rc;
}
static int lrun_go(struct lrun_fx *fx, const struct lrun_cfg *c, char *const *gates,
                   int n, char *out, char *err, size_t cap)
{ return lrun_go_prereq(fx, c, gates, n, out, err, cap, NULL); }

static bool lrun_plant(struct lrun_fx *fx)
{
    memset(fx, 0, sizeof *fx);
    return test_mkdtemp(fx->root, sizeof fx->root, "lintrun") != NULL;
}

static int lrun_vendor_go(struct lrun_fx *fx)
{
    pid_t pid = fork();
    int status;
    if (pid < 0) return -1;
    if (pid == 0) {
        char path[PATH_MAX + 32], out[4096], err[4096];
        char *gates[] = {(char *)"check-vendor-provenance"};
        struct lrun_cfg c = {1, "", "", ""};
        (void)snprintf(path, sizeof path, "%s/fakebin:/usr/bin:/bin", fx->root);
        if (chdir(fx->root) != 0 || setenv("PATH", path, 1) != 0) _exit(99);
        _exit(lrun_go(fx, &c, gates, 1, out, err, sizeof out));
    }
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

static bool lrun_foreign_ready(pid_t pid)
{
    siginfo_t info = {0};
    int rc;
    do { rc = waitid(P_PID, (id_t)pid, &info, WEXITED | WNOWAIT); }
    while (rc < 0 && errno == EINTR);
    return rc == 0 && info.si_pid == pid && info.si_code == CLD_EXITED && info.si_status == 37;
}

static bool lrun_foreign_wait(pid_t pid)
{
    int status = 0;
    pid_t got;
    do { got = waitpid(pid, &status, 0); } while (got < 0 && errno == EINTR);
    return got == pid && WIFEXITED(status) && WEXITSTATUS(status) == 37;
}

static bool lrun_owned_verdicts(const char *out, const struct lrun_fx *fx)
{
    char path[PATH_MAX + 32], data[8192];
    (void)snprintf(path, sizeof path, "%s/state/last-run.json", fx->root);
    return strstr(out, "PASS check-fx-rv-a ") && strstr(out, "PASS check-fx-rv-b ") &&
           lrun_read(path, data, sizeof data) && strstr(data, "\"name\":\"check-fx-rv-a\"") &&
           strstr(data, "\"name\":\"check-fx-rv-b\"");
}

static void lrun_reap_fixture_children(void)
{
    int status;
    pid_t got;
    do {
        got = waitpid(-1, &status, 0);
    } while (got > 0 || (got < 0 && errno == EINTR));
}

/* This process owns only the fixture's foreign child and lint workers. */
static int lrun_foreign_worker(void)
{
    struct lrun_fx fx;
    if (!lrun_plant(&fx)) return 1;
    pid_t foreign = fork();
    if (foreign == 0) _exit(37);
    bool ready = foreign > 0 && lrun_foreign_ready(foreign);
    char out[8192] = "", err[8192] = "";
    char *gates[] = {(char *)"check-fx-rv-a", (char *)"check-fx-rv-b"};
    struct lrun_cfg c = {2, "", "", ""};
    int rc = ready ? lrun_go(&fx, &c, gates, 2, out, err, sizeof out) : -1;
    bool owned = foreign > 0 && lrun_foreign_wait(foreign);
    bool verdicts = lrun_owned_verdicts(out, &fx);
    lrun_reap_fixture_children();
    if (!ready || !owned || rc != 0 || !verdicts)
        fprintf(stderr, "lint foreign child: ready=%d owner_wait=%d rc=%d verdicts=%d\n%s\n%s\n",
                ready, owned, rc, verdicts, out, err);
    (void)test_rm_rf_recursive(fx.root);
    return ready && owned && rc == 0 && verdicts ? 0 : 1;
}

static int test_lrun_foreign_child(void)
{
    int failures = 0;
    TEST_CASE("lint_run: unrelated waitable child remains owned and all verdicts appear") {
        pid_t worker = fork();
        if (worker == 0) {
            _exit(lrun_foreign_worker());
        }
        int status = 0;
        pid_t got = -1;
        if (worker > 0)
            do { got = waitpid(worker, &status, 0); } while (got < 0 && errno == EINTR);
        ASSERT(worker > 0 && got == worker && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    } TEST_END
    return failures;
}

static int lrun_wait_error_worker(void)
{
    struct lrun_fx fx;
    if (!lrun_plant(&fx)) return 1;
    struct sigaction ignored = {0}, saved;
    ignored.sa_handler = SIG_IGN;
    if (sigemptyset(&ignored.sa_mask) != 0 || sigaction(SIGCHLD, &ignored, &saved) != 0) {
        (void)test_rm_rf_recursive(fx.root);
        return 1;
    }
    char out[8192] = "", err[8192] = "";
    char *gates[] = {(char *)"check-fx-pass", (char *)"check-fx-rv-a"};
    struct lrun_cfg c = {2, "", "", ""};
    int rc = lrun_go(&fx, &c, gates, 2, out, err, sizeof out);
    int status;
    pid_t got;
    do { got = waitpid(-1, &status, WNOHANG); } while (got < 0 && errno == EINTR);
    int wait_error = errno;
    bool quiescent = got == -1 && wait_error == ECHILD;
    bool restored = sigaction(SIGCHLD, &saved, NULL) == 0;
    lrun_reap_fixture_children();
    if (rc != 1 || !quiescent || !restored)
        fprintf(stderr, "lint wait error: rc=%d quiescent=%d waitpid=%ld errno=%d restored=%d\n%s\n%s\n",
                rc, quiescent, (long)got, wait_error, restored, out, err);
    (void)test_rm_rf_recursive(fx.root);
    return rc == 1 && quiescent && restored ? 0 : 1;
}

static int test_lrun_wait_error_drain(void)
{
    int failures = 0;
    TEST_CASE("lint_run: wait failure drains remaining workers") {
        pid_t worker = fork();
        if (worker == 0) _exit(lrun_wait_error_worker());
        int status = 0;
        pid_t got = -1;
        if (worker > 0)
            do { got = waitpid(worker, &status, 0); } while (got < 0 && errno == EINTR);
        ASSERT(worker > 0 && got == worker && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    } TEST_END
    return failures;
}

static int test_lrun_verdicts(void)
{
    int failures = 0;
    TEST_CASE("lint_run: PASS/FAIL lines, rc, timing table, banner and FAIL logs") {
        struct lrun_fx fx;
        char out[8192], err[8192], p[PATH_MAX + 64], body[64];
        char *gates[] = { (char *)"check-fx-pass", (char *)"check-fx-fail",
                          (char *)"check-fx-silent", (char *)"check-fx-crash" };
        struct lrun_cfg c = { 2, "", "", "" };
        ASSERT(lrun_plant(&fx));
        ASSERT_EQ(lrun_go(&fx, &c, gates, 4, out, err, sizeof out), 1);
        ASSERT(strstr(out, "PASS check-fx-pass ") != NULL);
        ASSERT(strstr(out, " ms\n") != NULL);
        ASSERT(strstr(out, "FAIL check-fx-fail ") != NULL);
        ASSERT(strstr(out, " ms (rc=3)\n") != NULL);
        ASSERT(strstr(out, " ms (rc=1)\n") != NULL);
        ASSERT(strstr(out, " ms (rc=137)\n") != NULL);
        ASSERT(strstr(out, "\xe2\x94\x80\xe2\x94\x80 lint timing: 4 gates, wall ") != NULL);
        ASSERT(strstr(out, " ms, jobs 2 \xe2\x94\x80\xe2\x94\x80\n") != NULL);
        ASSERT(strstr(err, "\xe2\x95\x90\xe2\x95\x90 LINT: 3 of 4 gates FAILED \xe2\x95\x90\xe2\x95\x90\n") != NULL);
        ASSERT(strstr(err, "  \xe2\x9c\x97 check-fx-fail\n") != NULL);
        ASSERT(strstr(err, "FAIL log: check-fx-fail ") != NULL);
        ASSERT(strstr(err, "boom-diagnosis\n") != NULL);
        ASSERT(strstr(err, "(this gate produced NO output at all)") != NULL);
        ASSERT(strstr(err, "step killed by signal 9") != NULL);
        /* artifacts the doc-claims gate and the fleet readers use */
        (void)snprintf(p, sizeof p, "%s/check-fx-fail.rc", getenv("ZCL_LINT_GATES_DIR_X"));
        ASSERT(lrun_read(p, body, sizeof body));
        ASSERT_STR_EQ(body, "3\n");
        (void)snprintf(p, sizeof p, "%s/state/last-run.json", fx.root);
        ASSERT(lrun_read(p, out, sizeof out));
        ASSERT(strstr(out, "\"schema\":\"zcl.lint_timing.v1\"") != NULL);
        ASSERT(strstr(out, "\"failed_count\":3") != NULL);
        ASSERT(strstr(out, "\"name\":\"check-fx-fail\",\"ms\":") != NULL);
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}

static int test_lrun_green(void)
{
    int failures = 0;
    TEST_CASE("lint_run: every gate green is exit 0 with no banner") {
        struct lrun_fx fx;
        char out[4096], err[4096];
        char *gates[] = { (char *)"check-fx-pass" };
        struct lrun_cfg c = { 4, "", "", "" };
        ASSERT(lrun_plant(&fx));
        ASSERT_EQ(lrun_go(&fx, &c, gates, 1, out, err, sizeof out), 0);
        ASSERT(strstr(out, "PASS check-fx-pass ") != NULL);
        ASSERT(strstr(err, "FAILED") == NULL);
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}

static int test_lrun_chain(void)
{
    int failures = 0;
    TEST_CASE("lint_run: && stops at the first failing step; a missing binary is rc 127") {
        struct lrun_fx fx;
        char out[4096], err[4096], p[PATH_MAX + 16];
        char *gates[] = { (char *)"check-fx-chain", (char *)"check-fx-noexec" };
        struct lrun_cfg c = { 2, "", "", "" };
        ASSERT(lrun_plant(&fx));
        ASSERT_EQ(lrun_go(&fx, &c, gates, 2, out, err, sizeof out), 1);
        ASSERT(strstr(out, "FAIL check-fx-chain") != NULL);
        ASSERT(strstr(out, " ms (rc=5)\n") != NULL);
        ASSERT(strstr(out, " ms (rc=127)\n") != NULL);
        (void)snprintf(p, sizeof p, "%s/never", fx.root);
        ASSERT(access(p, F_OK) != 0);
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}

static int test_lrun_parallel(void)
{
    int failures = 0;
    TEST_CASE("lint_run: --jobs 2 runs two gates at once; --jobs 1 does not") {
        struct lrun_fx fx;
        char out[4096], err[4096];
        char *gates[] = { (char *)"check-fx-rv-a", (char *)"check-fx-rv-b" };
        struct lrun_cfg two = { 2, "", "", "" }, one = { 1, "", "", "" };
        ASSERT(lrun_plant(&fx));
        ASSERT_EQ(lrun_go(&fx, &two, gates, 2, out, err, sizeof out), 0);
        ASSERT(strstr(out, "PASS check-fx-rv-a") != NULL);
        ASSERT(strstr(out, "PASS check-fx-rv-b") != NULL);
        test_rm_rf_recursive(fx.root);
        ASSERT(lrun_plant(&fx));
        ASSERT_EQ(lrun_go(&fx, &one, gates, 2, out, err, sizeof out), 1);
        ASSERT(strstr(out, "FAIL check-fx-rv-a") != NULL);
        ASSERT(strstr(out, "PASS check-fx-rv-b") != NULL);
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}

static int test_lrun_refill(void)
{
    int failures = 0;
    TEST_CASE("lint_run: a completed later worker frees a slot") {
        struct lrun_fx fx;
        char out[4096] = "", err[4096] = "";
        char *gates[] = {(char *)"check-fx-rv-a", (char *)"check-fx-pass",
                         (char *)"check-fx-rv-b"};
        struct lrun_cfg c = {2, "", "", ""};
        bool planted = lrun_plant(&fx);
        int rc = planted ? lrun_go(&fx, &c, gates, 3, out, err, sizeof out) : -1;
        bool ok = planted && rc == 0 && strstr(out, "PASS check-fx-rv-a") &&
                  strstr(out, "PASS check-fx-pass") && strstr(out, "PASS check-fx-rv-b");
        if (planted) (void)test_rm_rf_recursive(fx.root);
        ASSERT(ok);
    } TEST_END
    return failures;
}

static int test_lrun_order(void)
{
    int failures = 0;
    TEST_CASE("lint_run: serial prologue first, long poles first, serial epilogue last") {
        struct lrun_fx fx;
        char out[4096], err[4096], p[PATH_MAX + 16], order[256];
        char *gates[] = { (char *)"check-fx-ord-b", (char *)"check-fx-ord-epi",
                          (char *)"check-fx-ord-a", (char *)"check-fx-ord-pole",
                          (char *)"check-fx-ord-pro" };
        struct lrun_cfg c = { 1, " check-fx-ord-pro ", " check-fx-ord-epi ",
                              " check-fx-ord-pole " };
        ASSERT(lrun_plant(&fx));
        ASSERT_EQ(lrun_go(&fx, &c, gates, 5, out, err, sizeof out), 0);
        (void)snprintf(p, sizeof p, "%s/order", fx.root);
        ASSERT(lrun_read(p, order, sizeof order));
        ASSERT_STR_EQ(order, "pro\npole\nb\na\nepi\n");
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}

static int test_lrun_inventory_prerequisite(void)
{
    int failures = 0;
    TEST_CASE("lint_run: selected inventory prerequisite runs once before readers") {
        struct lrun_fx fx; char out[4096], err[4096], p[PATH_MAX + 16], order[256];
        char *gates[] = {(char *)"check-fx-ord-reader", (char *)"check-capability-inventory-generated"};
        char *duplicate[] = {(char *)"check-capability-inventory-generated", (char *)"check-capability-inventory-generated"};
        struct lrun_cfg c = {2, "", "", ""};
        ASSERT(lrun_plant(&fx));
        ASSERT(lr_inventory_prerequisite("build/bin/gen_capability_inventory", "build/bin", gates, 2));
        ASSERT(!lr_inventory_prerequisite(NULL, "build/bin", gates, 2));
        ASSERT(!lr_inventory_prerequisite("other/gen_capability_inventory", "build/bin", gates, 2));
        ASSERT(!lr_inventory_prerequisite("build/bin/gen_capability_inventory", "build/bin", duplicate, 2));
        ASSERT(!lr_inventory_prerequisite("build/bin/gen_capability_inventory", "build/bin", gates, 1));
        ASSERT_EQ(lrun_go_prereq(&fx, &c, gates, 2, out, err, sizeof out, gates[1]), 0);
        (void)snprintf(p, sizeof p, "%s/order", fx.root);
        ASSERT(lrun_read(p, order, sizeof order)); ASSERT_STR_EQ(order, "generator\nreader\n");
        ASSERT(strstr(out, "PASS check-capability-inventory-generated") != NULL);
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}
static int test_lrun_prerequisite_failure(void)
{
    int failures = 0;
    TEST_CASE("lint_run: failed prerequisite reports blocked readers without running them") {
        struct lrun_fx fx; char out[4096], err[4096], p[PATH_MAX + 32], body[4096];
        char *gates[] = {(char *)"check-fx-fail", (char *)"check-fx-ord-reader"};
        struct lrun_cfg c = {2, "", "", ""};
        ASSERT(lrun_plant(&fx));
        ASSERT_EQ(lrun_go_prereq(&fx, &c, gates, 2, out, err, sizeof out, gates[0]), 1);
        ASSERT(strstr(out, "FAIL check-fx-fail") != NULL);
        ASSERT(strstr(err, "check-fx-ord-reader (not run: prerequisite failed)") != NULL);
        (void)snprintf(p, sizeof p, "%s/order", fx.root); ASSERT(access(p, F_OK) != 0);
        (void)snprintf(p, sizeof p, "%s/state/last-run.json", fx.root);
        ASSERT(lrun_read(p, body, sizeof body));
        ASSERT(strstr(body, "\"gate_count\":2") && strstr(body, "\"blocked_count\":1") &&
            strstr(body, "\"blocked\":[\"check-fx-ord-reader\"]"));
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}

static int test_lrun_unknown(void)
{
    int failures = 0;
    TEST_CASE("lint_run: a gate with no command is exit 2 and nothing runs") {
        struct lrun_fx fx;
        char out[4096], err[4096], p[PATH_MAX + 16];
        char *gates[] = { (char *)"check-fx-ord-x", (char *)"check-fx-nosuch" };
        struct lrun_cfg c = { 2, "", "", "" };
        ASSERT(lrun_plant(&fx));
        ASSERT_EQ(lrun_go(&fx, &c, gates, 2, out, err, sizeof out), 2);
        ASSERT(strstr(err, "gate 'check-fx-nosuch' has no invocation-table entry") != NULL);
        (void)snprintf(p, sizeof p, "%s/order", fx.root);
        ASSERT(access(p, F_OK) != 0);
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}

static int test_lrun_parse(void)
{
    int failures = 0;
    TEST_CASE("lint_run: the parser reads quotes, $VAR, NAME=v and && with no shell") {
        static struct lr_plan p;
        char err[LR_ERR];
        ASSERT_EQ(setenv("LRUN_FX_DIR", "/fx", 1), 0);
        ASSERT_EQ(lr_parse_command("A=1 B=\"x y\" prog --opt 'q r $z' \"$LRUN_FX_DIR/z\" && other ${LRUN_FX_DIR}",
                                   NULL, &p, err, sizeof err), 0);
        ASSERT_EQ(p.nsteps, 2);
        ASSERT_EQ(p.steps[0].nenv, 2);
        ASSERT_STR_EQ(p.steps[0].env[1], "B=x y");
        ASSERT_EQ(p.steps[0].argc, 4);
        ASSERT_STR_EQ(p.steps[0].argv[2], "q r $z");
        ASSERT_STR_EQ(p.steps[0].argv[3], "/fx/z");
        ASSERT_STR_EQ(p.steps[1].argv[1], "/fx");
    } TEST_END
    return failures;
}

static int test_lrun_refuse(void)
{
    int failures = 0;
    TEST_CASE("lint_run: shell syntax the parser cannot honour is refused") {
        static struct lr_plan p;
        char err[LR_ERR];
        ASSERT(lr_parse_command("a | b", NULL, &p, err, sizeof err) != 0);
        ASSERT(lr_parse_command("a; b", NULL, &p, err, sizeof err) != 0);
        ASSERT(lr_parse_command("a > f", NULL, &p, err, sizeof err) != 0);
        ASSERT(lr_parse_command("echo $(x)", NULL, &p, err, sizeof err) != 0);
        ASSERT(lr_parse_command("a &&", NULL, &p, err, sizeof err) != 0);
        ASSERT(lr_parse_command("'open", NULL, &p, err, sizeof err) != 0);
        ASSERT(lr_parse_command("   ", NULL, &p, err, sizeof err) != 0);
        ASSERT(strlen(err) > 0);
    } TEST_END
    return failures;
}

static int test_lrun_wrapper(void)
{
    int failures = 0;
    TEST_CASE("lint_run: a check_*.sh wrapper that only execs z23-lint runs z23-lint directly") {
        static struct lr_plan p;
        struct lrun_fx fx;
        char err[LR_ERR], dir[PATH_MAX + 32], pure[PATH_MAX + 64], impure[PATH_MAX + 64];
        char cmd[PATH_MAX * 2 + 64];
        ASSERT(lrun_plant(&fx));
        (void)snprintf(dir, sizeof dir, "%s/tools", fx.root);
        ASSERT_EQ(mkdir(dir, 0755), 0);
        (void)snprintf(dir, sizeof dir, "%s/tools/scripts", fx.root);
        ASSERT_EQ(mkdir(dir, 0755), 0);
        (void)snprintf(pure, sizeof pure, "%s/check_pure.sh", dir);
        (void)snprintf(impure, sizeof impure, "%s/check_impure.sh", dir);
        ASSERT(lrun_write(pure, "#!/bin/sh\n# note\n\nexec \"$(dirname \"$0\")/../../build/bin/z23-lint\" check-fx-wrapped \"$@\"\n"));
        ASSERT(lrun_write(impure, "#!/bin/sh\necho extra\nexec \"$(dirname \"$0\")/../../build/bin/z23-lint\" check-fx-wrapped \"$@\"\n"));
        (void)snprintf(cmd, sizeof cmd, "%s --selftest && bash %s", pure, pure);
        ASSERT_EQ(lr_parse_command(cmd, "build/bin/z23-lint", &p, err, sizeof err), 0);
        ASSERT_STR_EQ(p.steps[0].argv[0], "build/bin/z23-lint");
        ASSERT_STR_EQ(p.steps[0].argv[1], "check-fx-wrapped");
        ASSERT_STR_EQ(p.steps[0].argv[2], "--selftest");
        ASSERT_EQ(p.steps[0].argc, 3);
        ASSERT_STR_EQ(p.steps[1].argv[0], "build/bin/z23-lint");
        ASSERT_EQ(p.steps[1].argc, 2);
        (void)snprintf(cmd, sizeof cmd, "%s --selftest", impure);
        ASSERT_EQ(lr_parse_command(cmd, "build/bin/z23-lint", &p, err, sizeof err), 0);
        ASSERT_STR_EQ(p.steps[0].argv[0], impure);
        ASSERT_EQ(lr_parse_command(cmd, NULL, &p, err, sizeof err), 0);
        ASSERT_STR_EQ(p.steps[0].argv[0], impure);
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}

static int test_lrun_table(void)
{
    int failures = 0;
    TEST_CASE("lint_run: the compiled gate_commands.def table loads, one row per name") {
        static struct lr_table t;
        const struct lr_table_row *row;
        ASSERT_EQ(lr_table_load(&t), 0);
        ASSERT(t.n > 80);
        row = lr_table_find(&t, "check-toolchain");
        ASSERT(row != NULL);
        ASSERT_STR_EQ(row->cmd,
            "./tools/dev/check-toolchain.sh --selftest && ./tools/dev/check-toolchain.sh");
        row = lr_table_find(&t, "check-core-seal");
        ASSERT(row != NULL);
        ASSERT_STR_EQ(row->cmd, LR_CORE_SEAL);
        row = lr_table_find(&t, "check-observability-pairing");
        ASSERT(row != NULL);
        ASSERT_STR_EQ(row->cmd, "\"$ZCL_LINT_BIN_DIR/check_observability_pairing\"");
        ASSERT(lr_table_find(&t, "check-no-such-gate") == NULL);
        for (int i = 0; i < t.n; i++)
            for (int j = i + 1; j < t.n; j++)
                ASSERT(strcmp(t.rows[i].name, t.rows[j].name) != 0);
    } TEST_END
    return failures;
}

static int test_lrun_vendor(void)
{
    int failures = 0;
    TEST_CASE("lint_run: vendor gate dispatches all provenance checks and refuses failures") {
        struct lrun_fx fx;
        char path[PATH_MAX + 128], trace[4096];
        ASSERT(lrun_plant(&fx));
        ASSERT(lrun_vendor_setup(fx.root));
        (void)snprintf(path, sizeof path, "%s/fail-offline", fx.root);
        ASSERT(lrun_write(path, "fail\n"));
        ASSERT_EQ(lrun_vendor_go(&fx), 1);
        ASSERT_EQ(unlink(path), 0);
        (void)snprintf(path, sizeof path, "%s/trace", fx.root);
        ASSERT(lrun_read(path, trace, sizeof trace));
        ASSERT(strstr(trace, "build_vendor_offline_selftest.sh") != NULL);
        ASSERT(strstr(trace, "repro-network-policy-selftest") == NULL);
        ASSERT(strstr(trace, "check-tor-provenance") == NULL);
        ASSERT(lrun_write(path, ""));
        ASSERT_EQ(lrun_vendor_go(&fx), 0);
        ASSERT(lrun_read(path, trace, sizeof trace));
        ASSERT(strstr(trace, "test_vendor_provenance.sh") != NULL);
        ASSERT(strstr(trace, "build_vendor_offline_selftest.sh") != NULL);
        ASSERT(strstr(trace, "repro-network-policy-selftest") != NULL);
        ASSERT(strstr(trace, "vendor/rgfw/SHA256SUMS") != NULL);
        ASSERT(strstr(trace, "vendor/qrcodegen/SHA256SUMS") != NULL);
        ASSERT(strstr(trace, "vendor/typography/SHA256SUMS") != NULL);
        ASSERT(strstr(trace, "vendor/x11/SHA256SUMS") != NULL);
        ASSERT(strstr(trace, "vendor/freebsd-sh/SHA256SUMS") != NULL);
        ASSERT(strstr(trace, "check-tor-provenance") != NULL);
        ASSERT(lrun_write(path, ""));
        (void)snprintf(path, sizeof path, "%s/vendor/provenance/tor.manifest", fx.root);
        ASSERT(lrun_write(path, "build_time_patch_sha256=wrong\n"));
        ASSERT_EQ(lrun_vendor_go(&fx), 1);
        (void)snprintf(path, sizeof path, "%s/trace", fx.root);
        ASSERT(lrun_read(path, trace, sizeof trace));
        ASSERT(strstr(trace, "check-tor-provenance") == NULL);
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}

static int lrun_seal_in_dir(const char *root, const char *bin)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (chdir(root) != 0) _exit(99);
        (void)alarm(30);
        _exit(lr_core_seal(bin));
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* check-core-seal's in-process pipe: a stub core_seal that, like the real
 * one, reads stdin to EOF must see EOF once git ls-files exits. A pipe end
 * leaked into the reader would hang it; alarm turns that hang into a kill. */
static int test_lrun_seal(void)
{
    int failures = 0;
    TEST_CASE("lint_run: check-core-seal feeds git ls-files to core_seal, which sees EOF, and keeps its rc") {
        struct lrun_fx fx;
        char bin[PATH_MAX + 8], stub[PATH_MAX + 24], in[PATH_MAX + 16], text[PATH_MAX + 96];
        static char got[1 << 16];
        int st = 0;
        ASSERT(lrun_plant(&fx));
        (void)snprintf(bin, sizeof bin, "%s/bin", fx.root);
        ASSERT_EQ(mkdir(bin, 0755), 0);
        (void)snprintf(stub, sizeof stub, "%s/core_seal", bin);
        (void)snprintf(in, sizeof in, "%s/seal-in", fx.root);
        (void)snprintf(text, sizeof text, "#!/bin/sh\ncat > '%s'\nexit 7\n", in);
        ASSERT(lrun_write(stub, text));
        ASSERT_EQ(chmod(stub, 0755), 0);
        (void)fflush(NULL);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0) {
            (void)alarm(30);
            _exit(lr_core_seal(bin));
        }
        ASSERT_EQ(waitpid(pid, &st, 0), pid);
        ASSERT(WIFEXITED(st));            /* a leaked write end ends in SIGALRM */
        ASSERT_EQ(WEXITSTATUS(st), 7);    /* core_seal's rc is the gate's rc */
        ASSERT(lrun_read(in, got, sizeof got));
        ASSERT(strstr(got, "core/MANIFEST.sha3") != NULL);
        char token[PATH_MAX + 32], target[PATH_MAX + 32];
        (void)snprintf(token, sizeof token, "%s/.core-unseal-token", fx.root);
        (void)snprintf(target, sizeof target, "%s/token-target", fx.root);
        ASSERT_EQ(mkdir(token, 0700), 0);
        ASSERT_EQ(lrun_seal_in_dir(fx.root, bin), 7);
        ASSERT_EQ(rmdir(token), 0);
        ASSERT_EQ(mkfifo(token, 0600), 0);
        ASSERT_EQ(lrun_seal_in_dir(fx.root, bin), 7);
        ASSERT_EQ(unlink(token), 0);
        ASSERT(lrun_write(target, "owner token\n"));
        ASSERT_EQ(symlink(target, token), 0);
        ASSERT_EQ(lrun_seal_in_dir(fx.root, bin), 0);
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}

/* The actual public tool must use the platform's checked build-job cap. */
static void lrun_build_jobs_child(FILE *capture, const char *cap, bool extra)
{
    int nullfd = open("/dev/null", O_WRONLY);
    if (nullfd < 0 || dup2(fileno(capture), STDOUT_FILENO) < 0 ||
        dup2(nullfd, STDERR_FILENO) < 0 || setenv("ZCL_BUILD_MAX_JOBS", cap, 1) != 0)
        _exit(125);
    close(nullfd);
    if (extra) execl("build/bin/z23-lint", "z23-lint", "build-jobs", "extra", (char *)NULL);
    else execl("build/bin/z23-lint", "z23-lint", "build-jobs", (char *)NULL);
    _exit(125);
}

static int lrun_build_jobs(const char *cap, bool extra, char *out, size_t size)
{
    FILE *capture = tmpfile();
    if (!capture || size < 2) { if (capture) fclose(capture); return -1; }
    pid_t pid = fork();
    if (pid == 0) lrun_build_jobs_child(capture, cap, extra);
    if (pid < 0) { fclose(capture); return -1; }
    int status = 0;
    pid_t waited;
    do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    int result = -1;
    if (waited == pid && WIFEXITED(status) && fseek(capture, 0, SEEK_SET) == 0) {
        size_t n = fread(out, 1, size - 1, capture);
        out[n] = '\0';
        if (!ferror(capture) && feof(capture)) result = WEXITSTATUS(status);
    }
    fclose(capture);
    return result;
}

static int test_lrun_build_jobs(void)
{
    int failures = 0;
    TEST_CASE("lint_run: build-jobs respects the native cap and refuses invalid inputs") {
        char out[128];
        ASSERT_EQ(lrun_build_jobs("1", false, out, sizeof(out)), 0);
        ASSERT_STR_EQ(out, "-j1\n");
        const char *invalid[] = {"", "0", "bad", "4294967296"};
        for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
            ASSERT(lrun_build_jobs(invalid[i], false, out, sizeof(out)) > 0);
            ASSERT_STR_EQ(out, "");
        }
        ASSERT(lrun_build_jobs("1", true, out, sizeof(out)) > 0);
        ASSERT_STR_EQ(out, "");
    } TEST_END
    return failures;
}

int test_lint_run(void)
{
    int failures = 0;
    failures += test_lrun_build_jobs();
    failures += test_lrun_seal();
    failures += test_lrun_verdicts();
    failures += test_lrun_green();
    failures += test_lrun_chain();
    failures += test_lrun_parallel();
    failures += test_lrun_foreign_child();
    failures += test_lrun_wait_error_drain();
    failures += test_lrun_refill();
    failures += test_lrun_order();
    failures += test_lrun_inventory_prerequisite();
    failures += test_lrun_prerequisite_failure();
    failures += test_lrun_unknown();
    failures += test_lrun_parse();
    failures += test_lrun_refuse();
    failures += test_lrun_wrapper();
    failures += test_lrun_table();
    failures += test_lrun_vendor();
    failures += test_lrun_epoch_driver();
    return failures;
}

#else

int test_lint_run(void)
{
    printf("lint_run: SKIP — the driver forks gate workers; not built on Windows\n");
    return 0;
}

#endif

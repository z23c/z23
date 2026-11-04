/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: `z23-lint run` (tools/lint/lintc/run_*.c), the C23 lint driver, on
 *          fixture gates: pass, fail (rc and log), silent fail, killed, a
 *          && chain, and a rendezvous pair that only passes when two gates
 *          really run at once. Also the shell-free command parser, the
 *          check_*.sh wrapper rewrite, the compiled gate table, the
 *          serial and long-pole ordering, and the artifacts it leaves.
 *          check-core-seal's pipe reaches EOF and keeps core_seal's rc.
 * NOT proven here: the real gates, or the Make wiring. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"

#include "lint/lintc/run_priv.h"

#include <limits.h>
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

struct lrun_cfg {
    int jobs;
    const char *pro, *epi, *poles;
};

/* Run GATES under the fixture resolver; capture both streams. */
static int lrun_go(struct lrun_fx *fx, const struct lrun_cfg *c, char *const *gates,
                   int n, char *out, char *err, size_t cap)
{
    char state[PATH_MAX + 16];
    FILE *fo = tmpfile(), *fe = tmpfile();
    int rc;
    size_t k;
    (void)snprintf(state, sizeof state, "%s/state", fx->root);
    struct lr_opts o = { c->jobs, state, NULL, NULL, 75, false, fo, fe, lrun_resolve, fx,
                         c->pro, c->epi, c->poles };
    rc = lr_execute(&o, gates, n);
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

static bool lrun_plant(struct lrun_fx *fx)
{
    memset(fx, 0, sizeof *fx);
    return test_mkdtemp(fx->root, sizeof fx->root, "lintrun") != NULL;
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
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}

int test_lint_run(void)
{
    int failures = 0;
    failures += test_lrun_seal();
    failures += test_lrun_verdicts();
    failures += test_lrun_green();
    failures += test_lrun_chain();
    failures += test_lrun_parallel();
    failures += test_lrun_order();
    failures += test_lrun_unknown();
    failures += test_lrun_parse();
    failures += test_lrun_refuse();
    failures += test_lrun_wrapper();
    failures += test_lrun_table();
    return failures;
}

#else

int test_lint_run(void)
{
    printf("lint_run: SKIP — the driver forks gate workers; not built on Windows\n");
    return 0;
}

#endif

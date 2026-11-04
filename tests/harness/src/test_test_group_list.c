/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_test_group_list: the C form of test-group-list.sh and
 * test-registry-report.sh (tools/dev/test_group_list*.c) on fixture sources:
 * a three-group registry, a runner source naming one params-gated group, and
 * run artifacts. Covers the report verdicts (accounted, UNEXPLAINED, stale,
 * unknown executed name), the refusal when the runner policy has no names,
 * the exact-set diagnostics and the suggestion fallback. */

#include "test/test_core.h"
#include "test/test_home_isolation.h"
#include "command/native_command.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "test_group_list.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

#define TGL_T_OUT 16384

struct tglt {
    char root[1024];
    struct tgl_sources src;
    char registry[1100], runner[1100], families[1100], umbrellas[1100];
    char timing[1100];
};

static bool tglt_put(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    bool ok = f && fputs(text, f) >= 0;
    if (f && fclose(f) != 0)
        ok = false;
    return ok;
}

static bool tglt_setup(struct tglt *t, const char *tag, const char *runner_body)
{
    test_make_tmpdir(t->root, sizeof(t->root), "tgl_report", tag);
    (void)snprintf(t->registry, sizeof(t->registry), "%s/catalog.def", t->root);
    (void)snprintf(t->runner, sizeof(t->runner), "%s/runner.c", t->root);
    (void)snprintf(t->families, sizeof(t->families), "%s/families.def", t->root);
    (void)snprintf(t->umbrellas, sizeof(t->umbrellas), "%s/umbrellas.def", t->root);
    (void)snprintf(t->timing, sizeof(t->timing), "%s/last-run.json", t->root);
    t->src = (struct tgl_sources){t->registry, t->runner, t->families,
                                  t->umbrellas, t->timing};
    return tglt_put(t->registry, "ZCL_TEST_GROUP(alpha)\nZCL_TEST_GROUP(beta)\n"
                                 "ZCL_SPEC_GROUP(gamma)\n") &&
           tglt_put(t->runner, runner_body) &&
           tglt_put(t->families, "/* none */\n") &&
           tglt_put(t->umbrellas, "/* none */\n");
}

/* Runs one invocation; stdout and stderr land in `out` and `err`. */
static int tglt_run(const struct tglt *t, const char *const *argv, int argc,
                    char *out, char *err)
{
    FILE *o = tmpfile(), *e = tmpfile();
    int rc = -1;
    out[0] = err[0] = '\0';
    if (o && e) {
        rc = tgl_run(&t->src, argc, argv, o, e);
        rewind(o);
        rewind(e);
        out[fread(out, 1, TGL_T_OUT - 1, o)] = '\0';
        err[fread(err, 1, TGL_T_OUT - 1, e)] = '\0';
    }
    if (o)
        fclose(o);
    if (e)
        fclose(e);
    return rc;
}

static const char TGLT_RUNNER[] =
    "static bool group_is_params_heavy(const char *name)\n{\n"
    "    return strcmp(name, \"beta\") == 0;\n}\n";

static int test_report_verdicts(void)
{
    int failures = 0;
    TEST("report: accounted, UNEXPLAINED, stale and unknown-name verdicts") {
        struct tglt t;
        const char *rep[] = {"--report"};
        char out[TGL_T_OUT], err[TGL_T_OUT];
        ASSERT(tglt_setup(&t, "verdicts", TGLT_RUNNER));
        ASSERT_EQ(tglt_run(&t, rep, 1, out, err), 0); /* no artifact */
        ASSERT(strstr(out, "executed_groups=UNKNOWN") != NULL);
        ASSERT(strstr(out, "  test_beta\n") != NULL);
        ASSERT(tglt_put(t.timing, "{\n  \"group_count\":3,\n  \"mode\":\"cold\",\n"
            "  \"groups\":[\n{\"name\":\"test_alpha\"},{\"name\":\"spec_gamma\"}\n]}\n"));
        ASSERT_EQ(tglt_run(&t, rep, 1, out, err), 0); /* beta is gated */
        ASSERT(strstr(out, "params-heavy gate") != NULL);
        ASSERT(strstr(out, "VERDICT: every registered group is accounted for.") != NULL);
        ASSERT(tglt_put(t.timing, "{\n  \"group_count\":3,\n"
            "  \"groups\":[\n{\"name\":\"test_alpha\"},{\"name\":\"test_ghost\"}\n]}\n"));
        ASSERT_EQ(tglt_run(&t, rep, 1, out, err), 1);
        ASSERT(strstr(out, "spec_gamma") != NULL && strstr(out, "UNEXPLAINED") != NULL);
        ASSERT(strstr(out, "  test_ghost\n") != NULL);
        ASSERT(tglt_put(t.timing, "{\n  \"group_count\":9,\n"
            "  \"groups\":[\n{\"name\":\"test_alpha\"},{\"name\":\"spec_gamma\"}\n]}\n"));
        ASSERT_EQ(tglt_run(&t, rep, 1, out, err), 1);
        ASSERT(strstr(out, "STALE ARTIFACT: the run recorded 9") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_params_gated_refusal(void)
{
    int failures = 0;
    TEST("params-gated: a runner without the policy function exits 2") {
        struct tglt t;
        const char *gated[] = {"--params-gated"};
        char out[TGL_T_OUT], err[TGL_T_OUT];
        ASSERT(tglt_setup(&t, "gated", "int unrelated(void) { return 0; }\n"));
        ASSERT_EQ(tglt_run(&t, gated, 1, out, err), 2);
        ASSERT(out[0] == '\0');
        ASSERT(strstr(err, "yielded no names") != NULL);
        ASSERT(tglt_put(t.runner, TGLT_RUNNER));
        ASSERT_EQ(tglt_run(&t, gated, 1, out, err), 0);
        ASSERT_STR_EQ(out, "test_beta\n");
        PASS();
    } _test_next:;
    return failures;
}

static int test_exact_set_and_suggest(void)
{
    int failures = 0;
    TEST("exact set dedups in order; suggest falls back to the longest token") {
        struct tglt t;
        const char *set[] = {"--resolve-exact-set", "gamma,alpha,gamma"};
        const char *bad[] = {"--resolve-exact-set", "alph"};
        const char *sug[] = {"--suggest", "alphaz"};
        const char *miss[] = {"--resolve-exact", "spec_gamma", "nope"};
        char out[TGL_T_OUT], err[TGL_T_OUT];
        ASSERT(tglt_setup(&t, "exact", TGLT_RUNNER));
        ASSERT_EQ(tglt_run(&t, set, 2, out, err), 0);
        ASSERT_STR_EQ(out, "spec_gamma,test_alpha\n");
        ASSERT_EQ(tglt_run(&t, bad, 2, out, err), 1);
        ASSERT(out[0] == '\0');
        ASSERT(strstr(err, "closest registered names:\n  test_alpha\n") != NULL);
        ASSERT_EQ(tglt_run(&t, sug, 2, out, err), 0);
        ASSERT_STR_EQ(out, "test_alpha\n");
        ASSERT_EQ(tglt_run(&t, miss, 3, out, err), 1);
        ASSERT_STR_EQ(out, "spec_gamma\n");
        PASS();
    } _test_next:;
    return failures;
}

/* The leaf writes to the process stdout and stderr, so each call is captured
 * by pointing fds 1 and 2 at temp files for its duration. */
static bool tglt_slurp(FILE *f, char *buf)
{
    long n;
    (void)fflush(f);
    n = ftell(f);
    rewind(f);
    buf[0] = '\0';
    if (n < 0 || n >= TGL_T_OUT)
        return false;
    buf[fread(buf, 1, (size_t)n, f)] = '\0';
    return true;
}

/* Points the five source variables the leaf reads at the fixture, or (t NULL)
 * clears them. */
static bool tglt_env(const struct tglt *t)
{
    static const char *const names[] = {
        "ZCL_TEST_REGISTRY_SRC", "ZCL_TEST_RUNNER_SRC",
        "ZCL_TEST_PROOF_FAMILIES_SRC", "ZCL_TEST_UMBRELLAS_SRC",
        "ZCL_TEST_TIMING_JSON"};
    const char *vals[5] = {0};
    bool ok = true;
    if (t) {
        vals[0] = t->registry, vals[1] = t->runner, vals[2] = t->families;
        vals[3] = t->umbrellas, vals[4] = t->timing;
    }
    for (int i = 0; i < 5; i++)
        ok = (t ? setenv(names[i], vals[i], 1) : unsetenv(names[i])) == 0 && ok;
    return ok;
}

static bool tglt_leaf(const struct tglt *t, const char *mode, const char *args,
                      char *out, char *err, struct zcl_command_reply *reply)
{
    struct json_value in;
    struct zcl_command_request req = {.input = &in};
    FILE *o = tmpfile(), *e = tmpfile();
    int so, se;
    bool ok = o && e;
    json_init(&in);
    json_set_object(&in);
    ok = ok && json_push_kv_str(&in, "mode", mode) &&
         json_push_kv_str(&in, "args", args);
    ok = ok && tglt_env(t);
    zcl_command_reply_init(reply, "zcl.dev_test_groups.v1");
    if (ok) {
        (void)fflush(stdout);
        (void)fflush(stderr);
        so = dup(STDOUT_FILENO);
        se = dup(STDERR_FILENO);
        ok = so >= 0 && se >= 0;
        if (ok) {
            (void)dup2(fileno(o), STDOUT_FILENO);
            (void)dup2(fileno(e), STDERR_FILENO);
            zcl_native_handle_dev_test_groups(&req, reply);
            (void)fflush(stdout);
            (void)fflush(stderr);
            (void)dup2(so, STDOUT_FILENO);
            (void)dup2(se, STDERR_FILENO);
        }
        if (so >= 0)
            close(so);
        if (se >= 0)
            close(se);
        ok = ok && tglt_slurp(o, out) && tglt_slurp(e, err);
    }
    (void)tglt_env(NULL);
    if (o)
        fclose(o);
    if (e)
        fclose(e);
    json_free(&in);
    return ok;
}

static int test_leaf_end_to_end(void)
{
    int failures = 0;
    TEST("dev.test.groups leaf: --mode/--args splitting, stdout lines, reply status") {
        struct tglt t;
        struct zcl_command_reply r;
        char out[TGL_T_OUT], err[TGL_T_OUT];
        ASSERT(tglt_setup(&t, "leaf", TGLT_RUNNER));
        ASSERT(tglt_leaf(&t, "list", "", out, err, &r));
        ASSERT_EQ((int)r.status, (int)ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strstr(out, "test_alpha\n") != NULL);
        ASSERT(strstr(out, "spec_gamma\n") != NULL);
        zcl_command_reply_free(&r);
        ASSERT(tglt_leaf(&t, "report", "", out, err, &r));
        ASSERT_EQ((int)r.status, (int)ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strstr(out, "executed_groups=UNKNOWN") != NULL);
        zcl_command_reply_free(&r);
        /* operand splitting: blanks, tabs and a newline separate operands */
        ASSERT(tglt_leaf(&t, "resolve-exact", " spec_gamma\t test_alpha\n", out,
                         err, &r));
        ASSERT_EQ((int)r.status, (int)ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(out, "spec_gamma\ntest_alpha\n");
        zcl_command_reply_free(&r);
        ASSERT(tglt_put(t.runner, "int unrelated(void) { return 0; }\n"));
        ASSERT(tglt_leaf(&t, "params-gated", "", out, err, &r));
        ASSERT_EQ((int)r.status, (int)ZCL_COMMAND_STATUS_FAILED);
        ASSERT_EQ((int)r.exit_code, (int)ZCL_COMMAND_EXIT_INVALID);
        ASSERT(out[0] == '\0');
        ASSERT(strstr(err, "yielded no names") != NULL);
        zcl_command_reply_free(&r);
        ASSERT(tglt_leaf(&t, "resolve-exact", "no_such_group", out, err, &r));
        ASSERT_EQ((int)r.status, (int)ZCL_COMMAND_STATUS_FAILED);
        ASSERT_EQ((int)r.exit_code, (int)ZCL_COMMAND_EXIT_FAILED);
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

int test_test_group_list(void)
{
    int failures = 0;
    failures += test_report_verdicts();
    failures += test_params_gated_refusal();
    failures += test_exact_set_and_suggest();
    failures += test_leaf_end_to_end();
    return failures;
}

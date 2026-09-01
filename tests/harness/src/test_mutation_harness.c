/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The mutation harness, proved on a subject whose answer is already known.
 *
 * A harness that measures test quality is worth nothing if it is not itself
 * measured, and there are exactly three ways it can lie:
 *
 *   1. It can call a mutant KILLED that nothing killed — flattering a suite.
 *   2. It can call a mutant SURVIVED that the test did catch — inventing a
 *      hole and sending a reader to fix a test that is already right.
 *   3. It can leave the file it mutated on disk, which is worse than not
 *      existing at all. `dev.agent.mutate` shipped with exactly that shape
 *      of bug: its write path opened the source "wb" — truncating on the
 *      spot — so a write that failed afterwards left the file cut in half.
 *
 * So this group builds a two-function subject with one rule the runner
 * checks and one rule it never calls, runs a REAL campaign over it with a
 * real compiler and a real link, and asserts the harness says KILLED about
 * the first and SURVIVED about the second. Then it asserts the subject's
 * SHA3-256 is unchanged — after a completed run AND after a run stopped
 * partway, which is the case that corrupts a checkout.
 *
 * The strongest assertion here is the cheapest one: the subject file is
 * chmod 0444 for the whole campaign. This harness compiles mutants from a
 * scratch copy and never opens the target for writing, so a read-only
 * subject is not an obstacle; a harness that edited in place could not get
 * past its first mutant. That is structural proof rather than a hopeful
 * assertion about a restore path.
 *
 * Everything runs under the suite's own temp directory. No datadir, no
 * node, no network, and no file in the checkout is touched.
 */

#include "test/test_core.h"

#include "mutation_harness.h"
#include "platform/directory_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── the fixture ─────────────────────────────────────────────────────── */

/* Two rules, one watched and one not. `tmh_in_range` is driven at both ends
 * by the runner below, so a boundary or comparison mutation in it must go
 * red. `tmh_unwatched` is compiled and linked and never called, which is the
 * ordinary shape of a hole: real code, real tests, no test for THIS. */
static const char *const k_subject =
    "#include <stdbool.h>\n"                 /* 1 */
    "\n"                                     /* 2 */
    "bool tmh_in_range(int v);\n"            /* 3 */
    "int tmh_unwatched(int v);\n"            /* 4 */
    "\n"                                     /* 5 */
    "bool tmh_in_range(int v)\n"             /* 6 */
    "{\n"                                    /* 7 */
    "    if (v < 0)\n"                       /* 8 */
    "        return false;\n"                /* 9 */
    "    if (v > 100)\n"                     /* 10 */
    "        return false;\n"                /* 11 */
    "    return true;\n"                     /* 12 */
    "}\n"                                    /* 13 */
    "\n"                                     /* 14 */
    "int tmh_unwatched(int v)\n"             /* 15 */
    "{\n"                                    /* 16 */
    "    if (v > 7)\n"                       /* 17 */
    "        return 1;\n"                    /* 18 */
    "    return 0;\n"                        /* 19 */
    "}\n";                                   /* 20 */

#define TMH_WATCHED_LINE   10 /* `if (v > 100)` — the runner checks 100/101 */
#define TMH_REFUSAL_LINE    9 /* `return false;` — the runner checks -1 */
#define TMH_UNWATCHED_LINE 17 /* `if (v > 7)` — nothing calls this function */

/* A stand-in for test_parallel: same contract, no suite. It prints one
 * SUITE VERDICT line with the fields the harness reads and exits nonzero
 * when a check fails, so classification is exercised through the same
 * parser the real runner feeds. */
static const char *const k_runner =
    "#include <stdbool.h>\n"
    "#include <stdio.h>\n"
    "\n"
    "bool tmh_in_range(int v);\n"
    "\n"
    "int main(void)\n"
    "{\n"
    "    int bad = 0;\n"
    "    if (tmh_in_range(-1)) bad++;\n"
    "    if (!tmh_in_range(0)) bad++;\n"
    "    if (!tmh_in_range(100)) bad++;\n"
    "    if (tmh_in_range(101)) bad++;\n"
    "    printf(\"SUITE VERDICT mode=cold groups_total=1 groups_ran=1 \"\n"
    "           \"groups_cached=0 groups_gated=0 groups_failed=%d \"\n"
    "           \"self_skips=0 env_unobserved=0 toolkey=fixture\\n\",\n"
    "           bad ? 1 : 0);\n"
    "    return bad ? 1 : 0;\n"
    "}\n";

static bool tmh_write(const char *dir, const char *name, const char *text)
{
    char path[1024];
    if (snprintf(path, sizeof path, "%s/%s", dir, name) >= (int)sizeof path)
        return false;
    return zcl_mut_write_file(path, text, strlen(text));
}

static const char *tmh_cc(void)
{
    const char *cc = getenv("CC");
    return cc && cc[0] ? cc : "cc";
}

/* $CC is a COMMAND LINE, not a program name, and the difference is not
 * academic here.
 *
 * This tree sets CC to the compiler-cache wrapper followed by the compiler --
 * "<abs>/build/bin/zcc cc" -- and make exports that to every recipe. So a run
 * from `make t-fast` sees TWO tokens where a run straight from a shell sees
 * none at all. Handing the whole string to execve as argv[0] asks the kernel
 * for a program whose filename contains a space, which cannot exist, so the
 * fixture failed to build and the group failed.
 *
 * It failed only under the build. Every by-hand run passed, because a
 * developer's shell has no CC. That is the worst shape a defect can have: it
 * is invisible exactly where people look for it, and it fails only in the
 * gate, where it reads as flakiness.
 *
 * Split on spaces and tabs, and no quote handling on purpose: make splits CC
 * the same way, so a compiler path containing a space would have broken the
 * build long before it reached this test.
 *
 * `buf` receives a mutable copy and must outlive the argv pointing into it.
 * Returns the token count, or 0 if CC does not fit -- never a partial argv,
 * because a truncated compiler invocation would fail somewhere much less
 * obvious than here. */
static int tmh_cc_split(char *buf, size_t bufsz, char *out[], int max)
{
    const char *cc = tmh_cc();
    size_t len = strlen(cc);
    if (len >= bufsz)
        return 0;
    memcpy(buf, cc, len + 1u);
    int n = 0;
    char *p = buf;
    while (*p) {
        while (*p == ' ' || *p == '\t')
            *p++ = '\0';
        if (!*p)
            break;
        if (n >= max)
            return 0;
        out[n++] = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
    }
    return n;
}

/* Build the runner object once, and the response file that names it beside
 * the placeholder the campaign swaps for its own mutant object. */
static bool tmh_prepare(const char *dir)
{
    char runner_o[1024], runner_c[1024], rsp[1024], rsp_text[2200];
    if (snprintf(runner_o, sizeof runner_o, "%s/runner.o", dir) >=
            (int)sizeof runner_o ||
        snprintf(runner_c, sizeof runner_c, "%s/runner.c", dir) >=
            (int)sizeof runner_c ||
        snprintf(rsp, sizeof rsp, "%s/link.rsp.in", dir) >= (int)sizeof rsp)
        return false;
    char ccbuf[512];
    char *argv[16];
    int n = tmh_cc_split(ccbuf, sizeof ccbuf, argv, 8);
    if (n == 0) {
        fprintf(stderr, "tmh_prepare: cannot use CC=\"%s\" — empty, or more "
                        "than 8 tokens, or longer than %zu bytes\n",
                tmh_cc(), sizeof ccbuf);
        return false;
    }
    argv[n++] = (char *)"-std=c23";
    argv[n++] = (char *)"-O0";
    argv[n++] = (char *)"-c";
    argv[n++] = (char *)"-o";
    argv[n++] = runner_o;
    argv[n++] = runner_c;
    argv[n] = NULL;
    /* Name the compiler and the directory on failure. Without this the group
     * reports only "FAIL ... (tmh_prepare(dir))", which is true and useless:
     * it does not distinguish a compiler that could not be spawned from one
     * that ran and rejected the fixture. */
    if (zcl_mut_spawn(dir, argv, 120000, NULL, NULL) != 0) {
        fprintf(stderr, "tmh_prepare: fixture compile failed in %s using "
                        "CC=\"%s\" (argv[0]=\"%s\")\n",
                dir, tmh_cc(), argv[0]);
        return false;
    }
    if (snprintf(rsp_text, sizeof rsp_text, "%s/PLACEHOLDER.o %s\n", dir,
                 runner_o) >= (int)sizeof rsp_text)
        return false;
    return zcl_mut_write_file(rsp, rsp_text, strlen(rsp_text));
}

/* The same shape zcl_mut_plan_from_dryrun produces, built by hand so the
 * campaign is exercised without a `make` in the loop. */
static bool tmh_plan(const char *dir, struct zcl_mut_plan *plan)
{
    memset(plan, 0, sizeof *plan);
    char compile[1024], link[1024];
    (void)snprintf(compile, sizeof compile, "%s -std=c23 -O0 -Wall -Werror",
                   tmh_cc());
    (void)snprintf(link, sizeof link, "%s -o %%OUT%% @%s/link.rsp.in",
                   tmh_cc(), dir);
    (void)snprintf(link, sizeof link, "%s -o %%OUT%% %%RSP%%", tmh_cc());
    if (!zcl_mut_shell_split(compile, &plan->compile) ||
        !zcl_mut_shell_split(link, &plan->link))
        return false;
    (void)snprintf(plan->rsp, sizeof plan->rsp, "%s/link.rsp.in", dir);
    (void)snprintf(plan->object, sizeof plan->object, "%s/PLACEHOLDER.o", dir);
    return true;
}

static const struct zcl_mut_result *tmh_find(const struct zcl_mut_report *r,
                                             size_t line, const char *rule)
{
    for (size_t i = 0; i < r->result_count; i++) {
        if (r->results[i].site.line == line &&
            strcmp(r->results[i].site.rule, rule) == 0)
            return &r->results[i];
    }
    return NULL;
}

int test_mutation_harness(void);
int test_mutation_harness(void)
{
    int failures = 0;

    /* Everything the cleanup at the bottom touches is declared and zeroed
     * here: an ASSERT jumps straight to that label, so nothing below may be
     * read or freed unless it is already in a safe state. */
    struct zcl_mut_report report;
    struct zcl_mut_report cut;
    struct zcl_mut_plan plan;
    memset(&report, 0, sizeof report);
    memset(&cut, 0, sizeof cut);
    memset(&plan, 0, sizeof plan);
    char reldir[512] = { 0 };
    char dir[700] = { 0 };
    char work[900] = { 0 };
    char subject_path[900] = { 0 };
    bool ran = false, cut_ran = false;

    /* ────────────────── operators, with no build at all ───────────────── */

    TEST("a mutation inside a string, a comment or an #include never fires") {
        const char *src =
            "#include <stdio.h>\n"
            "/* a comment with == and && and 42 in it */\n"
            "static const char *k = \"x == y && 7\";\n"
            "// trailing == comment\n";
        ASSERT_EQ(zcl_mut_enumerate(src, strlen(src), NULL, 0), (size_t)0);
        PASS();
    }

    TEST("#define keeps its constant mutable; other directives do not") {
        const char *src = "#define CAP 32\n#if CAP > 8\n#endif\n";
        struct zcl_mut_site sites[8];
        size_t n = zcl_mut_enumerate(src, strlen(src), sites, 8);
        /* 32 -> 33 and 32 -> 31, and nothing at all from the #if */
        ASSERT_EQ(n, (size_t)2);
        ASSERT_EQ(sites[0].line, (size_t)1);
        ASSERT_STR_EQ(sites[0].rule, "int_inc");
        ASSERT_STR_EQ(sites[0].after, "33");
        ASSERT_STR_EQ(sites[1].rule, "int_dec");
        ASSERT_STR_EQ(sites[1].after, "31");
        PASS();
    }

    TEST("a return substitution replaces the whole statement, not a token") {
        const char *src = "int f(int a) { return a + 1; }\n";
        struct zcl_mut_site sites[8];
        size_t n = zcl_mut_enumerate(src, strlen(src), sites, 8);
        const struct zcl_mut_site *ret = NULL;
        for (size_t i = 0; i < n; i++)
            if (strcmp(sites[i].rule, "ret_true") == 0)
                ret = &sites[i];
        ASSERT(ret != NULL);
        char *image = NULL;
        size_t ilen = 0;
        ASSERT(zcl_mut_apply(src, strlen(src), ret, &image, &ilen));
        ASSERT_STR_EQ(image, "int f(int a) { return true; }\n");
        free(image);
        PASS();
    }

    TEST("a compound assignment is never mistaken for a comparison") {
        const char *src = "void f(int *a) { *a <<= 1; *a >>= 1; *a += 1; }\n";
        struct zcl_mut_site sites[16];
        size_t n = zcl_mut_enumerate(src, strlen(src), sites, 16);
        ASSERT(n > 0);
        for (size_t i = 0; i < n; i++)
            ASSERT_EQ((int)sites[i].cls, (int)ZCL_MUT_CLASS_BOUNDARY);
        PASS();
    }

    TEST("a call statement is deletable; a declaration that looks like one is not") {
        const char *src =
            "void g(int);\n"
            "void f(void)\n"
            "{\n"
            "    g(1);\n"
            "}\n";
        struct zcl_mut_site sites[16];
        size_t n = zcl_mut_enumerate(src, strlen(src), sites, 16);
        size_t deletions = 0;
        for (size_t i = 0; i < n; i++) {
            if (strcmp(sites[i].rule, "stmt_delete") != 0)
                continue;
            deletions++;
            ASSERT_EQ(sites[i].line, (size_t)4);
            ASSERT_STR_EQ(sites[i].after, "(void)0;");
        }
        ASSERT_EQ(deletions, (size_t)1);
        PASS();
    }

    TEST("the plan parser recovers a compile and a link from make -n") {
        const char *dry =
            "gen_templates: nothing to do\n"
            "tools/dev/compile-epoch-object.sh dep \"build/o/lib/x/src/y.o\" "
            "\"lib/x/src/y.c\" \\\n  \"aa\" \"1\" \"bb\" -- \\\n"
            "  build/bin/zcc cc -std=c23 -O2 -Ilib/x/include\n"
            "set -eu; \\\ntmp=\"$(mktemp t.XXXX)\"; \\\n"
            "build/bin/zcc cc -std=c23 -o \"$tmp\" \"@build/o/link.rsp\" -lm; \\\n"
            "mv -f -- \"$tmp\" out\n";
        struct zcl_mut_plan p;
        char err[256];
        ASSERT(zcl_mut_plan_from_dryrun(dry, "lib/x/src/y.c", &p, err,
                                        sizeof err));
        ASSERT_STR_EQ(p.object, "build/o/lib/x/src/y.o");
        ASSERT_STR_EQ(p.rsp, "build/o/link.rsp");
        ASSERT_STR_EQ(p.compile.argv[0], "build/bin/zcc");
        ASSERT_STR_EQ(p.compile.argv[1], "cc");
        ASSERT_STR_EQ(p.link.argv[p.link.count - 1], "-lm");
        bool saw_out = false, saw_rsp = false;
        for (size_t i = 0; i < p.link.count; i++) {
            if (strcmp(p.link.argv[i], "%OUT%") == 0)
                saw_out = true;
            if (strcmp(p.link.argv[i], "%RSP%") == 0)
                saw_rsp = true;
        }
        ASSERT(saw_out);
        ASSERT(saw_rsp);
        zcl_mut_plan_free(&p);
        PASS();
    }

    TEST("invalid plan inputs leave a non-null output free-safe") {
        struct zcl_mut_plan p;
        char err[256];

        memset(&p, 0xa5, sizeof p);
        ASSERT(!zcl_mut_plan_from_dryrun(NULL, "lib/x/src/y.c", &p, err,
                                         sizeof err));
        ASSERT_EQ(p.compile.count, (size_t)0);
        ASSERT_EQ(p.link.count, (size_t)0);
        ASSERT(p.compile.argv[0] == NULL);
        ASSERT(p.link.argv[0] == NULL);
        ASSERT_EQ(p.object[0], '\0');
        ASSERT_EQ(p.rsp[0], '\0');
        zcl_mut_plan_free(&p);

        memset(&p, 0xa5, sizeof p);
        ASSERT(!zcl_mut_plan_from_dryrun("make: nothing to be done\n", NULL,
                                         &p, err, sizeof err));
        ASSERT_EQ(p.compile.count, (size_t)0);
        ASSERT_EQ(p.link.count, (size_t)0);
        ASSERT(p.compile.argv[0] == NULL);
        ASSERT(p.link.argv[0] == NULL);
        ASSERT_EQ(p.object[0], '\0');
        ASSERT_EQ(p.rsp[0], '\0');
        zcl_mut_plan_free(&p);
        PASS();
    }

    TEST("a transcript that names no compile for the file is refused") {
        struct zcl_mut_plan p;
        char err[256];
        ASSERT(!zcl_mut_plan_from_dryrun("make: nothing to be done\n",
                                         "lib/x/src/y.c", &p, err,
                                         sizeof err));
        ASSERT(err[0] != '\0');
        PASS();
    }

    /* ─────────── a real campaign, on a subject with a known answer ─────── */

    TEST("the fixture stages") {
        test_make_tmpdir(reldir, sizeof reldir, "mutation", "harness");
        ASSERT(test_abs_path(reldir, dir, sizeof dir));
        ASSERT(platform_directory_ensure(dir, 0700));
        ASSERT(tmh_write(dir, "subject.c", k_subject));
        ASSERT(tmh_write(dir, "runner.c", k_runner));
        ASSERT(tmh_prepare(dir));
        ASSERT(snprintf(work, sizeof work, "%s/work", dir) < (int)sizeof work);
        ASSERT(snprintf(subject_path, sizeof subject_path, "%s/subject.c",
                        dir) < (int)sizeof subject_path);
        /* Read-only from here on: a harness that edits the file in place
         * cannot complete a single mutant against this. */
        ASSERT_EQ(chmod(subject_path, 0444), 0);
        ASSERT(tmh_plan(dir, &plan));
        PASS();
    }

    struct zcl_mut_config cfg = {
        .root = dir,
        .src_rel = "subject.c",
        .group = "fixture",
        .work_dir = work,
        .runner_arg_fmt = "--exact=%s",
        .build_timeout_ms = 120000,
        .test_timeout_ms = 60000,
        .use_cache = false,
        .verbose = false,
        .abort_after = 0,
    };

    TEST("the campaign runs to completion against a READ-ONLY subject") {
        ran = zcl_mut_campaign_run(&cfg, &plan, &report);
        if (!ran)
            printf("(campaign error: %s) ", report.error);
        ASSERT(ran);
        ASSERT(report.result_count > 0);
        ASSERT_EQ(report.result_count, report.total_sites);
        PASS();
    }

    TEST("a comparison the runner checks at its edge is reported KILLED") {
        /* `if (v > 100)` widened to `>=` makes tmh_in_range(100) false, and
         * the runner checks exactly that. */
        const struct zcl_mut_result *r =
            tmh_find(&report, TMH_WATCHED_LINE, "gt_to_ge");
        ASSERT(r != NULL);
        ASSERT_EQ((int)r->outcome, (int)ZCL_MUT_OUTCOME_KILLED);
        ASSERT_STR_EQ(r->killed_by, "test");
        PASS();
    }

    TEST("the boundary constant behind that comparison is reported KILLED") {
        const struct zcl_mut_result *inc =
            tmh_find(&report, TMH_WATCHED_LINE, "int_inc");
        const struct zcl_mut_result *dec =
            tmh_find(&report, TMH_WATCHED_LINE, "int_dec");
        ASSERT(inc != NULL && dec != NULL);
        ASSERT_EQ((int)inc->outcome, (int)ZCL_MUT_OUTCOME_KILLED);
        ASSERT_EQ((int)dec->outcome, (int)ZCL_MUT_OUTCOME_KILLED);
        PASS();
    }

    TEST("a refusal turned into an acceptance is reported KILLED") {
        /* `return false;` -> `return true;` on the out-of-range path. This
         * is the audit's worst defect, in miniature. */
        const struct zcl_mut_result *r =
            tmh_find(&report, TMH_REFUSAL_LINE, "ret_true");
        ASSERT(r != NULL);
        ASSERT_EQ((int)r->outcome, (int)ZCL_MUT_OUTCOME_KILLED);
        PASS();
    }

    TEST("a mutation in code no test calls is reported SURVIVED") {
        const struct zcl_mut_result *r =
            tmh_find(&report, TMH_UNWATCHED_LINE, "gt_to_ge");
        ASSERT(r != NULL);
        ASSERT_EQ((int)r->outcome, (int)ZCL_MUT_OUTCOME_SURVIVED);
        PASS();
    }

    TEST("the score counts only killed and survived, and every bucket adds up") {
        size_t k = report.counts[ZCL_MUT_OUTCOME_KILLED];
        size_t s = report.counts[ZCL_MUT_OUTCOME_SURVIVED];
        size_t sb = report.counts[ZCL_MUT_OUTCOME_STILLBORN];
        size_t eq = report.counts[ZCL_MUT_OUTCOME_EQUIVALENT];
        size_t er = report.counts[ZCL_MUT_OUTCOME_ERROR];
        ASSERT(k > 0);
        ASSERT(s > 0);
        ASSERT_EQ(k + s + sb + eq + er, report.result_count);
        /* A stillborn or equivalent mutant must never inflate the score:
         * the denominator is killed + survived and nothing else. */
        int score = zcl_mut_score_tenths(&report);
        ASSERT_EQ(score, (int)((k * 2000 + (k + s)) / ((k + s) * 2)));
        ASSERT(score > 0 && score < 1000);
        PASS();
    }

    TEST("a completed run leaves the subject byte-identical") {
        ASSERT(report.source_unchanged);
        ASSERT_EQ(memcmp(report.source_digest_before,
                         report.source_digest_after, 32), 0);
        PASS();
    }

    /* ─────────────── the interrupted run: the corrupting case ─────────── */

    TEST("a run stopped partway still leaves the subject byte-identical") {
        struct zcl_mut_config cut_cfg = cfg;
        cut_cfg.abort_after = 2; /* stop mid-campaign, as an interrupt would */
        cut_ran = zcl_mut_campaign_run(&cut_cfg, &plan, &cut);
        ASSERT(cut_ran);
        ASSERT(cut.aborted);
        ASSERT_EQ(cut.result_count, (size_t)2);
        ASSERT(cut.source_unchanged);
        ASSERT_EQ(memcmp(cut.source_digest_before,
                         report.source_digest_before, 32), 0);
        ASSERT_EQ(memcmp(cut.source_digest_after,
                         report.source_digest_before, 32), 0);
        PASS();
    }

    TEST("the subject on disk still holds exactly the bytes it started with") {
        size_t len = 0;
        char *now = zcl_mut_read_file(subject_path, &len);
        ASSERT(now != NULL);
        ASSERT_EQ(len, strlen(k_subject));
        ASSERT_EQ(memcmp(now, k_subject, len), 0);
        free(now);
        PASS();
    }

_test_next:;
    if (subject_path[0])
        (void)chmod(subject_path, 0644);
    zcl_mut_report_free(&report);
    zcl_mut_report_free(&cut);
    zcl_mut_plan_free(&plan);
    if (failures == 0)
        printf("test_mutation_harness: all passed\n");
    else
        printf("test_mutation_harness: %d FAILED\n", failures);
    return failures;
}

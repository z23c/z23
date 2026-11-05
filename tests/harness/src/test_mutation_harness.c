/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The mutation harness, proved on a subject whose answer is already known.
 *
 * The harness must not lie in three ways: call a mutant KILLED that nothing
 * killed, call a mutant SURVIVED that a test caught, or leave the mutated
 * file altered on disk.
 *
 * This group builds a two-function subject with one rule the runner checks
 * and one it never calls, runs a real campaign (real compiler and link), and
 * asserts KILLED for the first and SURVIVED for the second. It then asserts
 * the subject's SHA3-256 is unchanged after a completed run and after a run
 * stopped partway.
 *
 * The subject is chmod 0444 for the whole campaign: mutants compile from a
 * scratch copy and the target is never opened for writing.
 *
 * Everything runs under the suite's temp directory: no datadir, node,
 * network, or checkout file is touched.
 */

#include "test/test_core.h"

#include "mutation_harness.h"
#include "platform/directory_compat.h"
#include "platform/clock.h"
#include "util/supervised_retirement.h"
#include "util/thread_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static struct zcl_mut_owner tmh_owner = ZCL_MUT_OWNER_INIT;

#include "platform/file_sync.h"
static unsigned tmh_sync_count, tmh_sync_fail;
static int tmh_sync(int fd)
{
    if (++tmh_sync_count == tmh_sync_fail) {
        errno = EIO;
        return -1;
    }
    return platform_file_sync(fd);
}
/* Compile the actual writer with only its storage barrier intercepted. */
#define platform_file_sync tmh_sync
#define zcl_native_handle_dev_agent_mutate tmh_mutate_command
#include "../../../tools/command/native_devagent_mutate_command.c"
#undef zcl_native_handle_dev_agent_mutate
#undef platform_file_sync

static bool tmh_exact(const char *path, const char *expected)
{
    char bytes[128] = {0};
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    size_t n = fread(bytes, 1, sizeof(bytes), f);
    bool ok = !ferror(f) && n == strlen(expected);
    if (fclose(f) != 0) ok = false;
    return ok && memcmp(bytes, expected, n) == 0;
}

static int tmh_pending_case(unsigned fail)
{
    int failures = 0;
    char root[512] = {0}, build[600], dir[700], blob[800], marker[800], source[800];
    const char *original = "int example(void){return 1;}\n";
    ASSERT(test_mkdtemp(root, sizeof(root), "pending-arm") != NULL);
    ASSERT(zcl_path_join(build, sizeof(build), root, "build"));
    ASSERT(platform_directory_ensure(build, 0700));
    ASSERT(zcl_path_join(dir, sizeof(dir), root, "tools"));
    ASSERT(platform_directory_ensure(dir, 0700));
    ASSERT(zcl_path_join(source, sizeof(source), root, "tools/example.c"));
    ASSERT(dvm_write_file(source, original, strlen(original)));
    ASSERT(zcl_path_join(dir, sizeof(dir), root, DVM_PENDING_DIR));
    ASSERT(platform_directory_ensure(dir, 0700));
    ASSERT(zcl_path_join(blob, sizeof(blob), root, DVM_PENDING_BYTES));
    ASSERT(zcl_path_join(marker, sizeof(marker), root, DVM_PENDING_PATH));
    ASSERT(dvm_write_file(blob, original, strlen(original)));
    tmh_sync_count = 0; tmh_sync_fail = fail;
    bool armed = dvm_pending_arm(root, "tools/example.c", original, strlen(original));
    tmh_sync_fail = 0;
    ASSERT_EQ(armed, fail == 0);
    ASSERT_EQ(tmh_sync_count, fail ? fail : 2u);
    ASSERT(tmh_exact(blob, original));
    ASSERT(tmh_exact(source, original));
    if (fail) ASSERT_EQ(access(marker, F_OK), -1);
    else ASSERT(tmh_exact(marker, "tools/example.c"));
_test_next:;
    tmh_sync_fail = 0;
    /* The helper removes files, then each owned directory from the leaf up. */
    if (root[0]) {
        (void)zcl_path_join(dir, sizeof(dir), root, "tools"); test_cleanup_tmpdir(dir);
        (void)zcl_path_join(dir, sizeof(dir), root, DVM_PENDING_DIR);
        test_cleanup_tmpdir(dir);
        (void)zcl_path_join(build, sizeof(build), root, "build");
        test_cleanup_tmpdir(build); test_cleanup_tmpdir(root);
    }
    return failures;
}

static int tmh_pending_tests(void)
{
    (void)tmh_sync; /* Keep the failing-first fixture buildable on the old writer. */
    return tmh_pending_case(1) + tmh_pending_case(2) + tmh_pending_case(0);
}

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
    "#define _POSIX_C_SOURCE 200809L\n"
    "#include <stdbool.h>\n"
    "#include <stdio.h>\n"
    "#include <stdlib.h>\n"
    "#include <string.h>\n"
    "#include <unistd.h>\n"
    "#include <time.h>\n"
    "\n"
    "bool tmh_in_range(int v);\n"
    "static unsigned deep(unsigned n) { volatile unsigned char bytes[131072];\n"
    "    for (unsigned i=0; i<sizeof(bytes); i+=4096) bytes[i]=1;\n"
    "    unsigned child=n?deep(n-1):0; return child+bytes[0]; }\n"
    "\n"
    "int main(int argc, char **argv)\n"
    "{\n"
    "    if (argc > 1 && !strcmp(argv[1], \"--complete-env\")) {\n"
    "        for(int i=0;i<65;i++){ char key[40],value[80];\n"
    "            snprintf(key,sizeof(key),\"Z23_MUT_ENV_%d\",i);\n"
    "            snprintf(value,sizeof(value),\"%d a b utf8-\\xc3\\xa9\",i);\n"
    "            const char *actual=getenv(key); if(!actual||strcmp(actual,value)) return 44; } return 0;\n"
    "    }\n"
    "    if (argc > 1 && !strcmp(argv[1], \"--deep-stack\")) return deep(128)==129?0:41;\n"
    "    if (argc > 1 && !strcmp(argv[1], \"--complete-argv\")) {\n"
    "        const char *parts[]={\"\",\"a b\",\"quote\\\"\",\"slash\\\\\",\"utf8-\\xc3\\xa9\"};\n"
    "        if(argc!=512) return 42;\n"
    "        for(int i=2;i<argc;i++) if(strcmp(argv[i],parts[i%5])) return 43; return 0;\n"
    "    }\n"
    "    if (argc > 1 && !strcmp(argv[1], \"--early-eof\")) {\n"
    "        close(1); close(2); struct timespec t = {1, 0}; nanosleep(&t, 0); return 0;\n"
    "    }\n"
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

/* $CC is a command line (e.g. "<abs>/build/bin/zcc cc"), not a program name:
 * split it on spaces and tabs into argv, as make does, with no quote handling.
 * `buf` receives a mutable copy and must outlive argv. Returns the token
 * count, or 0 if CC does not fit -- never a partial argv. */
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
    /* Name the compiler and directory on failure so a spawn error is
     * distinguishable from a rejected fixture. */
    if (zcl_mut_spawn_owned(&tmh_owner, dir, argv, 120000, NULL, NULL) != 0) {
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

static bool tmh_plan_budget_exact(const struct zcl_mut_plan *plan, size_t compiler)
{
    return plan->compile.count == compiler &&
        strcmp(plan->object, "object -- name.o") == 0 &&
        strcmp(plan->compile.argv[compiler - 1], "-DVALUE_507=a b") == 0;
}

static int tmh_plan_token_budget(size_t prefix, size_t compiler, bool delimiter)
{
    char text[32768];
    size_t used = (size_t)snprintf(text, sizeof(text),
        "zcc --epoch-object 'object -- name.o' subject.c");
    for (size_t i = 4; i < prefix; ++i) {
        int n = snprintf(text + used, sizeof(text) - used, " 'prefix -- quoted'");
        if (n < 0 || (size_t)n >= sizeof(text) - used) return false;
        used += (size_t)n;
    }
    int n = snprintf(text + used, sizeof(text) - used, "%scc", delimiter ? " -- " : " ' -- ' ");
    if (n < 0 || (size_t)n >= sizeof(text) - used) return false;
    used += (size_t)n;
    for (size_t i = 1; i < compiler; ++i) {
        n = snprintf(text + used, sizeof(text) - used, " '-DVALUE_%zu=a b'", i);
        if (n < 0 || (size_t)n >= sizeof(text) - used) return false;
        used += (size_t)n;
    }
    n = snprintf(text + used, sizeof(text) - used, "\ncc -o out @subject.rsp\n");
    if (n < 0 || (size_t)n >= sizeof(text) - used) return false;
    struct zcl_mut_plan plan = {0};
    char error[256];
    bool parsed = zcl_mut_plan_from_dryrun(text, "subject.c", &plan, error, sizeof(error));
    bool exact = parsed && tmh_plan_budget_exact(&plan, compiler);
    zcl_mut_plan_free(&plan);
    return parsed ? (exact ? 1 : 2) : 0;
}

static int tmh_parser_budget_tests(void)
{
    int failures = 0;
    TEST("wrapper and executable token budgets are separate and never truncated") {
        ASSERT_EQ(tmh_plan_token_budget(6, ZCL_MUT_ARGV_MAX - 4, true), 1);
        ASSERT_EQ(tmh_plan_token_budget(ZCL_MUT_ARGV_MAX, ZCL_MUT_ARGV_MAX - 4, true), 1);
        ASSERT_EQ(tmh_plan_token_budget(ZCL_MUT_ARGV_MAX + 1, ZCL_MUT_ARGV_MAX - 4, true), 0);
        ASSERT_EQ(tmh_plan_token_budget(6, ZCL_MUT_ARGV_MAX - 3, true), 0);
        ASSERT_EQ(tmh_plan_token_budget(6, ZCL_MUT_ARGV_MAX - 4, false), 0);
        PASS();
    }
    TEST("oversized plain quoted and escaped words refuse rather than truncate") {
        char text[16385];
        struct zcl_mut_argv words = {0};
        memset(text, 'x', 8191); text[8191] = 0;
        ASSERT(zcl_mut_shell_split(text, &words));
        ASSERT_EQ(strlen(words.argv[0]), (size_t)8191); zcl_mut_argv_free(&words);
        text[8191] = 'x'; text[8192] = 0;
        ASSERT(!zcl_mut_shell_split(text, &words)); ASSERT_EQ(words.count, (size_t)0);
        text[0] = '"'; memset(text + 1, 'x', 8192); text[8193] = '"'; text[8194] = 0;
        ASSERT(!zcl_mut_shell_split(text, &words)); ASSERT_EQ(words.count, (size_t)0);
        text[0] = '\''; text[8193] = '\'';
        ASSERT(!zcl_mut_shell_split(text, &words)); ASSERT_EQ(words.count, (size_t)0);
        for (size_t i = 0; i < 8192; ++i) { text[i * 2] = '\\'; text[i * 2 + 1] = 'x'; }
        text[16384] = 0;
        ASSERT(!zcl_mut_shell_split(text, &words)); ASSERT_EQ(words.count, (size_t)0);
        ASSERT(!zcl_mut_shell_split("'unterminated", &words));
        PASS();
    }
    TEST("public shell splitting still accepts512 words and refuses513") {
        char text[ZCL_MUT_ARGV_MAX * 2 + 3];
        struct zcl_mut_argv words = {0};
        for (size_t i = 0; i < ZCL_MUT_ARGV_MAX; ++i) { text[i * 2] = 'x'; text[i * 2 + 1] = ' '; }
        text[ZCL_MUT_ARGV_MAX * 2] = 0;
        ASSERT(zcl_mut_shell_split(text, &words));
        ASSERT_EQ(words.count, (size_t)ZCL_MUT_ARGV_MAX); zcl_mut_argv_free(&words);
        text[ZCL_MUT_ARGV_MAX * 2] = 'x'; text[ZCL_MUT_ARGV_MAX * 2 + 1] = 0;
        ASSERT(!zcl_mut_shell_split(text, &words)); ASSERT_EQ(words.count, (size_t)0);
        PASS();
    }


_test_next:;
    return failures;
}

/* Seed an exact key through the campaign, then replace its record bytes. */
static int tmh_cache_records(const struct zcl_mut_config *cfg,
                             const struct zcl_mut_plan *plan)
{
    int failures = 0;
    struct zcl_mut_report r = { 0 };
    struct zcl_mut_config cached = *cfg;
    cached.use_cache = true;
    cached.abort_after = 1;
    char path[1200], cache[1000];
    DIR *d = NULL;
    static const char records[][40] = {
        "KILLED test\0garbage\n", "KILLED test\nSURVIVED -\n",
        "KILLED testx\n", "KILLED \n", "KILLED test\n", "KILLED test"
    };
    static const size_t lengths[] = { 20, 23, 13, 8, 12, 11 };
    TEST("cache records refuse hidden bytes and preserve complete outcomes") {
        ASSERT(zcl_mut_campaign_run(&cached, plan, &r));
        zcl_mut_report_free(&r);
        ASSERT(snprintf(cache, sizeof cache, "%s/cache", cfg->work_dir) <
               (int)sizeof cache);
        d = opendir(cache);
        ASSERT(d != NULL);
        struct dirent *e;
        path[0] = '\0';
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') continue;
            ASSERT(snprintf(path, sizeof path, "%s/%s", cache, e->d_name) <
                   (int)sizeof path);
            break;
        }
        ASSERT(path[0] != '\0');
        for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; i++) {
            ASSERT(zcl_mut_write_file(path, records[i], lengths[i]));
            ASSERT(zcl_mut_campaign_run(&cached, plan, &r));
            ASSERT_EQ(r.result_count, (size_t)1);
            ASSERT_EQ(r.results[0].cached, i >= 4);
            if (i >= 4) {
                ASSERT_EQ(r.results[0].outcome, ZCL_MUT_OUTCOME_KILLED);
                ASSERT_STR_EQ(r.results[0].killed_by, "test");
            }
            zcl_mut_report_free(&r);
        }
        PASS();
    }
    TEST("cache hits preserve exactly the six producer outcome/reason tuples") {
        static const struct {
            const char *record;
            bool hit;
            enum zcl_mut_outcome outcome;
            const char *reason;
        } tuples[] = {
            {"KILLED test\n", true, ZCL_MUT_OUTCOME_KILLED, "test"},
            {"KILLED timeout\n", true, ZCL_MUT_OUTCOME_KILLED, "timeout"},
            {"KILLED crash\n", true, ZCL_MUT_OUTCOME_KILLED, "crash"},
            {"SURVIVED -\n", true, ZCL_MUT_OUTCOME_SURVIVED, ""},
            {"STILLBORN -\n", true, ZCL_MUT_OUTCOME_STILLBORN, ""},
            {"EQUIVALENT -\n", true, ZCL_MUT_OUTCOME_EQUIVALENT, ""},
            {"KILLED -\n", false, ZCL_MUT_OUTCOME_KILLED, "test"},
            {"SURVIVED test\n", false, ZCL_MUT_OUTCOME_KILLED, "test"},
            {"SURVIVED timeout\n", false, ZCL_MUT_OUTCOME_KILLED, "test"},
            {"SURVIVED crash\n", false, ZCL_MUT_OUTCOME_KILLED, "test"},
            {"STILLBORN test\n", false, ZCL_MUT_OUTCOME_KILLED, "test"},
            {"STILLBORN timeout\n", false, ZCL_MUT_OUTCOME_KILLED, "test"},
            {"STILLBORN crash\n", false, ZCL_MUT_OUTCOME_KILLED, "test"},
            {"EQUIVALENT test\n", false, ZCL_MUT_OUTCOME_KILLED, "test"},
            {"EQUIVALENT timeout\n", false, ZCL_MUT_OUTCOME_KILLED, "test"},
            {"EQUIVALENT crash\n", false, ZCL_MUT_OUTCOME_KILLED, "test"},
            {"ERROR -\n", false, ZCL_MUT_OUTCOME_KILLED, "test"},
            {"ERROR test\n", false, ZCL_MUT_OUTCOME_KILLED, "test"},
            {"ERROR timeout\n", false, ZCL_MUT_OUTCOME_KILLED, "test"},
            {"ERROR crash\n", false, ZCL_MUT_OUTCOME_KILLED, "test"},
        };
        for (size_t i = 0; i < sizeof tuples / sizeof tuples[0]; i++) {
            ASSERT(zcl_mut_write_file(path, tuples[i].record,
                                      strlen(tuples[i].record)));
            ASSERT(zcl_mut_campaign_run(&cached, plan, &r));
            ASSERT_EQ(r.result_count, (size_t)1);
            ASSERT_EQ(r.results[0].cached, tuples[i].hit);
            ASSERT_EQ(r.results[0].outcome, tuples[i].outcome);
            ASSERT_STR_EQ(r.results[0].killed_by, tuples[i].reason);
            if (!tuples[i].hit)
                ASSERT(tmh_exact(path, "KILLED test\n"));
            zcl_mut_report_free(&r);
        }
        PASS();
    }
_test_next:;
    if (d) (void)closedir(d);
    zcl_mut_report_free(&r);
    return failures;
}

/* Unused macro flags keep the baseline binary identical, so only the compiler
 * argv identity can distinguish these campaigns. Never execute the old
 * overflowing path in red: the safe 8190-byte omission case comes first. */
static int tmh_compiler_identity(const struct zcl_mut_config *cfg,
                                  const struct zcl_mut_plan *plan)
{
    int failures = 0;
    struct zcl_mut_report r = {0};
    struct zcl_mut_config cached = *cfg;
    struct zcl_mut_plan variant = *plan; /* borrowed argv; do not free it */
    char work[1200], pad[9001];
    size_t prefix = 0, base = plan->compile.count;
    static const struct {
        bool oversized;
        const char *tail;
        bool expected_hit;
    } cases[] = {
        {false, "-DMUT_TAIL=1", false}, {false, "-DMUT_TAIL=1", true},
        {false, "-DMUT_TAIL=2", false}, {false, "-DMUT_TAIL=2", true},
        {true, "-DMUT_TAIL=1", false}, {true, "-DMUT_TAIL=1", true},
        {true, "-DMUT_TAIL=2", false}, {true, "-DMUT_TAIL=2", true},
    };
    cached.use_cache = true;
    cached.abort_after = 1;
    TEST("compiler identity includes flags past 8190 bytes and oversized arguments") {
        ASSERT(base + 6 <= ZCL_MUT_ARGV_MAX);
        for (size_t i = 0; i < base; i++)
            prefix += strlen(plan->compile.argv[i]) + 1;
        ASSERT(prefix < 8000);
        ASSERT(snprintf(work, sizeof work, "%s/compiler", cfg->work_dir) <
               (int)sizeof work);
        cached.work_dir = work;
        variant.compile.count = base + 2;
        variant.compile.argv[base] = pad;
        variant.compile.argv[base + 2] = NULL;
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            size_t n = cases[i].oversized ? sizeof pad - 1 : 8189 - prefix;
            memset(pad, 'x', n);
            memcpy(pad, "-DMUT_PAD=", strlen("-DMUT_PAD="));
            pad[n] = '\0';
            variant.compile.argv[base + 1] = (char *)cases[i].tail;
            ASSERT(zcl_mut_campaign_run(&cached, &variant, &r));
            ASSERT_EQ(r.result_count, (size_t)1);
            ASSERT_EQ(r.results[0].cached, cases[i].expected_hit);
            ASSERT_EQ(r.results[0].outcome, ZCL_MUT_OUTCOME_KILLED);
            ASSERT_STR_EQ(r.results[0].killed_by, "test");
            zcl_mut_report_free(&r);
        }
        PASS();
    }
    TEST("compiler identity preserves argv boundaries including internal spaces") {
        static const struct { bool split, expected_hit; } boundaries[] = {
            {false, false}, {false, true}, {true, false}, {true, true}, {false, true}
        };
        for (size_t i = 0; i < sizeof boundaries / sizeof boundaries[0]; i++) {
            bool split = boundaries[i].split;
            variant.compile.count = base + (split ? 2 : 1);
            variant.compile.argv[base] = (char *)(split ? "-DMUT_PAIR=a"
                                                       : "-DMUT_PAIR=a -DMUT_TAIL=b");
            variant.compile.argv[base + 1] = split ? (char *)"-DMUT_TAIL=b" : NULL;
            variant.compile.argv[base + 2] = NULL;
            ASSERT(zcl_mut_campaign_run(&cached, &variant, &r));
            ASSERT_EQ(r.result_count, (size_t)1);
            ASSERT_EQ(r.results[0].cached, boundaries[i].expected_hit);
            zcl_mut_report_free(&r);
        }
        PASS();
    }
_test_next:;
    zcl_mut_report_free(&r);
    return failures;
}

#if defined(__linux__)
/* A real compiler wrapper disappears after its successful baseline invocation.
 * The next compile therefore reaches the actual exec-failure boundary. */
static bool tmh_missing_compiler_report(const struct zcl_mut_report *report,
    const struct zcl_mut_owner *borrower, const char *path)
{
    return borrower->failed && report->source_unchanged && report->result_count == 0 &&
        report->counts[ZCL_MUT_OUTCOME_STILLBORN] == 0 &&
        report->counts[ZCL_MUT_OUTCOME_KILLED] == 0 &&
        strstr(report->error, "plan/compiler/link") != NULL && access(path, F_OK) != 0;
}

static bool tmh_missing_compiler(const char *root, const char *dir,
    const struct zcl_mut_config *cfg, const struct zcl_mut_plan *plan)
{
    static const char code[] =
        "#define _POSIX_C_SOURCE 200809L\n#include <unistd.h>\nint main(int n,char **v) {\n"
        "if(n<2 || unlink(v[0])) return 126; execvp(v[1],v+1); return 127; }\n";
    char path[1024], source[1024], work[1024], ccbuf[512];
    if (snprintf(path, sizeof(path), "%s/compile-once", dir) >= (int)sizeof(path) ||
        snprintf(source, sizeof(source), "%s/compile-once.c", dir) >= (int)sizeof(source) ||
        snprintf(work, sizeof(work), "%s/exec-failure", dir) >= (int)sizeof(work) ||
        !tmh_write(dir, "compile-once.c", code)) return false;
    char *compile[16];
    int count = tmh_cc_split(ccbuf, sizeof(ccbuf), compile, 8);
    if (!count) return false;
    compile[count++] = "-std=c23"; compile[count++] = "-O0";
    compile[count++] = "-o"; compile[count++] = path; compile[count++] = source;
    compile[count] = NULL;
    if (zcl_mut_spawn_owned(&tmh_owner, dir, compile, 120000, NULL, NULL) != 0) return false;
    struct zcl_mut_owner borrower = ZCL_MUT_OWNER_INIT;
    if (!zcl_mut_owner_open(&borrower, root)) return false;
    struct zcl_mut_plan variant = *plan; /* Borrow original words; never free this copy. */
    if (variant.compile.count >= ZCL_MUT_ARGV_MAX) {
        (void)zcl_mut_owner_close(&borrower);
        return false;
    }
    for (size_t i = variant.compile.count; i > 0; --i)
        variant.compile.argv[i] = variant.compile.argv[i - 1];
    variant.compile.argv[0] = path;
    variant.compile.argv[++variant.compile.count] = NULL;
    struct zcl_mut_config broken = *cfg;
    broken.owner = &borrower; broken.work_dir = work; broken.use_cache = true;
    struct zcl_mut_report report = {0};
    bool completed = zcl_mut_campaign_run(&broken, &variant, &report);
    bool correct = !completed && tmh_missing_compiler_report(&report, &borrower, path);
    zcl_mut_report_free(&report);
    bool closed = zcl_mut_owner_close(&borrower);
    return correct && closed;
}

/* Hold the actual supervisor's cleanup at the existing platform fixture gate.
 * Failed transactional wakes must retain the exact borrower until late ACK. */
static bool tmh_pending_retirement(const char *root, const char *dir, const char *work)
{
    char binary[1024];
    if (snprintf(binary, sizeof(binary), "%s/subject.bin", work) >= (int)sizeof(binary)) return false;
    struct zcl_mut_owner borrower = ZCL_MUT_OWNER_INIT;
    if (!zcl_mut_owner_open(&borrower, root)) return false;
    int gate[2];
    if (pipe(gate) != 0) { (void)zcl_mut_owner_close(&borrower); return false; }
    platform_supervised_fixture_cleanup_gate(gate[0]);
    zcl_mut_fixture_retirement_refuse(true);
    char *arguments[] = {binary, "--early-eof", NULL};
    int status = zcl_mut_spawn_owned(&borrower, dir, arguments, 60, NULL, NULL);
    void *retained = borrower.pending;
    bool refused = !zcl_mut_owner_close(&borrower);
    bool stable = retained && borrower.pending == retained;
    /* No more launches in this fixture: preauthorized transfer must remain
     * possible after admission is stopped. All release actions precede asserts. */
    zcl_supervised_retirement_request_stop();
    zcl_mut_fixture_retirement_refuse(false);
    platform_supervised_fixture_cleanup_gate(-1);
    bool released = write(gate[1], "x", 1) == 1;
    (void)close(gate[1]); (void)close(gate[0]);
    bool closed = zcl_mut_owner_close(&borrower);
    bool drained = zcl_supervised_retirement_drain(clock_now_monotonic_ns() + 1000000000);
    return status == -1 && borrower.failed && refused && stable && released && closed && drained;
}
#endif

#if defined(__linux__)
static int tmh_execution_deadline_tests(const char *source, const char *dir, const char *work,
    const struct zcl_mut_config *cfg, const struct zcl_mut_plan *plan)
{
    int failures = 0;
    TEST("a compiler missing after baseline aborts without STILLBORN cache credit") {
        ASSERT(tmh_missing_compiler(source, dir, cfg, plan));
        ASSERT_EQ(zcl_supervised_retirement_phase(), ZCL_RETIREMENT_RUNNING);
        PASS();
    }
    TEST("early pipe EOF does not discharge a live engine or its deadline") {
        char binary[1024];
        ASSERT(snprintf(binary, sizeof(binary), "%s/subject.bin", work) < (int)sizeof(binary));
        char *arguments[] = {binary, "--early-eof", NULL};
        ASSERT_EQ(zcl_mut_spawn_owned(&tmh_owner, dir, arguments, 80, NULL, NULL), -2);
        ASSERT_EQ(zcl_supervised_retirement_fixture_pending(), 0u);
        ASSERT(tmh_owner.pending == NULL);
        ASSERT(!tmh_owner.failed);
        ASSERT_EQ(zcl_supervised_retirement_phase(), ZCL_RETIREMENT_RUNNING);
        PASS();
    }

_test_next:;
    return failures;
}

static int tmh_vector_tests(const char *source, const char *dir, const char *work)
{
    int failures = 0;
    TEST("complete target argv512 and deep child stack preserve native execution") {
        char binary[1024];
        ASSERT(snprintf(binary, sizeof(binary), "%s/subject.bin", work) < (int)sizeof(binary));
        char *arguments[ZCL_MUT_ARGV_MAX + 2];
        static char *const parts[] = {"", "a b", "quote\"", "slash\\", "utf8-\xc3\xa9"};
        arguments[0] = binary; arguments[1] = "--complete-argv";
        for (size_t i = 2; i < ZCL_MUT_ARGV_MAX; ++i) arguments[i] = parts[i % 5];
        arguments[ZCL_MUT_ARGV_MAX] = NULL;
        ASSERT_EQ(zcl_mut_spawn_owned(&tmh_owner, dir, arguments, 5000, NULL, NULL), 0);
        arguments[1] = "--deep-stack"; arguments[2] = NULL;
        ASSERT_EQ(zcl_mut_spawn_owned(&tmh_owner, dir, arguments, 5000, NULL, NULL), 0);
        ASSERT(!tmh_owner.failed && tmh_owner.pending == NULL);
        PASS();
    }
    TEST("target argv513 refuses before engine custody without truncation") {
        struct zcl_mut_owner borrower = ZCL_MUT_OWNER_INIT;
        ASSERT(zcl_mut_owner_open(&borrower, source));
        char *arguments[ZCL_MUT_ARGV_MAX + 2];
        arguments[0] = "unexecuted-fixture";
        for (size_t i = 1; i <= ZCL_MUT_ARGV_MAX; ++i) arguments[i] = "argument";
        arguments[ZCL_MUT_ARGV_MAX + 1] = NULL;
        int status = zcl_mut_spawn_owned(&borrower, dir, arguments, 5000, NULL, NULL);
        bool rejected = status == -1 && borrower.failed && borrower.pending == NULL;
        bool closed = zcl_mut_owner_close(&borrower);
        ASSERT(rejected && closed);
        ASSERT_EQ(zcl_supervised_retirement_phase(), ZCL_RETIREMENT_RUNNING);
        PASS();
    }
    TEST("complete inherited environment65 preserves bytes and explicit empty environments") {
        extern char **environ;
        char **saved = environ;
        char values[65][128];
        char *complete[66];
        for (size_t i = 0; i < 65; ++i) {
            (void)snprintf(values[i], sizeof(values[i]), "Z23_MUT_ENV_%zu=%zu a b utf8-\xc3\xa9", i, i);
            complete[i] = values[i];
        }
        complete[65] = NULL;
        char binary[1024];
        ASSERT(snprintf(binary, sizeof(binary), "%s/subject.bin", work) < (int)sizeof(binary));
        char *arguments[] = {binary, "--complete-env", NULL};
        environ = complete;
        int populated = zcl_mut_spawn_owned(&tmh_owner, dir, arguments, 5000, NULL, NULL);
        environ = NULL; arguments[1] = "--deep-stack";
        int null_empty = zcl_mut_spawn_owned(&tmh_owner, dir, arguments, 5000, NULL, NULL);
        char *empty[] = {NULL}; environ = empty;
        int explicit_empty = zcl_mut_spawn_owned(&tmh_owner, dir, arguments, 5000, NULL, NULL);
        environ = saved; /* Restore before every assertion, including failure. */
        ASSERT_EQ(populated, 0); ASSERT_EQ(null_empty, 0); ASSERT_EQ(explicit_empty, 0);
        ASSERT(environ == saved);
        ASSERT(!tmh_owner.failed && tmh_owner.pending == NULL);
        PASS();
    }

_test_next:;
    return failures;
}

static int tmh_failure_custody_tests(const char *source, const char *dir, const char *work,
    const struct zcl_mut_config *cfg, const struct zcl_mut_plan *plan)
{
    int failures = 0;
    TEST("observation failure aborts campaign without mutant or cache credit") {
        struct zcl_mut_config broken = *cfg;
        struct zcl_mut_report unavailable = {0};
        broken.use_cache = true;
        platform_supervised_fixture_observation_error_once();
        bool completed = zcl_mut_campaign_run(&broken, plan, &unavailable);
        bool no_credit = unavailable.result_count == 0 &&
            unavailable.counts[ZCL_MUT_OUTCOME_STILLBORN] == 0 &&
            unavailable.counts[ZCL_MUT_OUTCOME_KILLED] == 0;
        zcl_mut_report_free(&unavailable);
        ASSERT(!completed && no_credit);
        ASSERT(tmh_owner.failed);
        PASS();
    }
    TEST("repeated retirement refusal retains custody until late transfer after stop") {
        ASSERT(tmh_pending_retirement(source, dir, work));
        ASSERT_EQ(zcl_supervised_retirement_phase(), ZCL_RETIREMENT_STOPPED);
        PASS();
    }
_test_next:;
    return failures;
}

static bool tmh_owner_begin(const char **source, char *root, size_t capacity)
{
    *source = getenv("ZCL_DEV_SOURCE_ROOT");
    if (!*source) *source = getcwd(root, capacity);
    if (!*source || !zcl_supervised_retirement_begin() || !zcl_mut_owner_open(&tmh_owner, *source)) {
        printf("mutation_harness: qualified lifecycle setup failed: %s\n", tmh_owner.error);
        return false;
    }
    return true;
}

static int tmh_owner_finish(void)
{
    int failures = 0;
    if (!zcl_mut_owner_close(&tmh_owner)) failures++;
    zcl_supervised_retirement_request_stop();
    bool drained = zcl_supervised_retirement_drain(clock_now_monotonic_ns() + 1000000000);
    if (!drained || thread_registry_join_all(1) != 0) failures++;
    return failures;
}

#endif

static int tmh_operator_tests(void)
{
    int failures = 0;
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


_test_next:;
    return failures;
}

int test_mutation_harness(void);
int test_mutation_harness(void)
{
    int failures = tmh_pending_tests();

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
#if defined(__linux__)
    char root[PATH_MAX];
    const char *source;
    if (!tmh_owner_begin(&source, root, sizeof(root))) return failures + 1;
#endif

    /* ────────────────── operators, with no build at all ───────────────── */

    int operator_failures = tmh_operator_tests();
    failures += operator_failures;
    if (operator_failures) goto _test_next;

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
    int parser_failures = tmh_parser_budget_tests();
    failures += parser_failures;
    if (parser_failures) goto _test_next;

    /* The build's own spelling, with the blank line and the bare `test -s`
     * of the response file a real transcript carries before the link. */
    TEST("the plan parser reads a zcc recipe past a blank line") {
        const char *dry =
            "build/bin/zcc --epoch-object dep \"build/o/lib/x/src/y.o\" "
            "\"lib/x/src/y.c\" \\\n  \"aa\" \"1\" \"bb\" -- \\\n"
            "  build/bin/zcc cc -std=c23 -O2 -Ilib/x/include\n"
            "\n"
            "test -s \"build/o/link.rsp\"\n"
            "true;\n"
            "set -eu; \\\ntmp=\"$(mktemp t.XXXX)\"; \\\n"
            "build/bin/zcc cc -std=c23 -o \"$tmp\" \"@build/o/link.rsp\" -lm; \\\n"
            "mv -f -- \"$tmp\" out\n";
        struct zcl_mut_plan p;
        char err[256];
        ASSERT(zcl_mut_plan_from_dryrun(dry, "lib/x/src/y.c", &p, err,
                                        sizeof err));
        ASSERT_STR_EQ(p.object, "build/o/lib/x/src/y.o");
        ASSERT_STR_EQ(p.rsp, "build/o/link.rsp");
        ASSERT_STR_EQ(p.compile.argv[1], "cc");
        ASSERT_STR_EQ(p.link.argv[p.link.count - 1], "-lm");
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
        .owner = &tmh_owner,
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

    failures += tmh_cache_records(&cfg, &plan);
    failures += tmh_compiler_identity(&cfg, &plan);

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

#if defined(__linux__)
    int runtime_failures = tmh_execution_deadline_tests(source, dir, work, &cfg, &plan);
    failures += runtime_failures;
    if (runtime_failures) goto _test_next;
    runtime_failures = tmh_vector_tests(source, dir, work);
    failures += runtime_failures;
    if (runtime_failures) goto _test_next;
    failures += tmh_failure_custody_tests(source, dir, work, &cfg, &plan);
#endif

_test_next:;
    if (subject_path[0])
        (void)chmod(subject_path, 0644);
    zcl_mut_report_free(&report);
    zcl_mut_report_free(&cut);
    zcl_mut_plan_free(&plan);
#if defined(__linux__)
    failures += tmh_owner_finish();
#endif
    if (failures == 0)
        printf("test_mutation_harness: all passed\n");
    else
        printf("test_mutation_harness: %d FAILED\n", failures);
    return failures;
}

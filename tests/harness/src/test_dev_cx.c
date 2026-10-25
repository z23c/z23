/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance tests for dev.cx.next and dev.cx.check
 * (tools/command/native_dev_cx_next.c, native_dev_cx_check.c) against
 * throwaway git repositories. The complexity metric is the real
 * build/bin/z23-lint copied into each fixture lane, so the fixtures prove the
 * leaves drive the shipped gate and not a stand-in. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_dev_cx.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
int test_dev_cx(void);
int test_dev_cx(void)
{
    printf("test_dev_cx: skipped on Windows\n");
    return 0;
}
#else
#include <sys/stat.h>
#include <unistd.h>

#define CXT_PATH 1100
#define CXT_LINT_SRC "build/bin/z23-lint"
#define CXT_BASE ZCL_CX_BASELINE_REL

struct cxt_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void cxt_die(const char *what)
{
    fprintf(stderr, "dev_cx fixture: %s\n", what);
    abort();
}

static void cxt_git(const char *dir, const char *a, const char *b,
                    const char *c, const char *d, const char *e)
{
    const char *argv[] = {"git", "-c", "user.name=t", "-c",
                          "user.email=t@example.invalid", "-c",
                          "commit.gpgsign=false", a, b, c, d, e, NULL};
    char out[512];
    if (cx_run(dir, argv, out, sizeof(out), 30000, true) != 0) {
        fprintf(stderr, "dev_cx fixture: git %s failed: %s\n", a, out);
        abort();
    }
}

static void cxt_mkdirs(const char *path)
{
    char tmp[CXT_PATH];
    (void)snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        (void)mkdir(tmp, 0700);
        *p = '/';
    }
}

static void cxt_put(const char *dir, const char *rel, const char *text)
{
    char path[CXT_PATH];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, rel);
    cxt_mkdirs(path);
    if (!cx_write_file(path, text, strlen(text)))
        cxt_die("cannot write a fixture file");
}

/* A function with `ifs` decisions: cyclomatic complexity ifs + 1. */
static void cxt_fn(char *buf, size_t cap, const char *name, int ifs)
{
    size_t n = strlen(buf);
    n += (size_t)snprintf(buf + n, cap - n, "int %s(int x)\n{\n    int r = 0;\n",
                          name);
    for (int i = 0; i < ifs; i++)
        n += (size_t)snprintf(buf + n, cap - n, "    if (x == %d)\n        r++;\n",
                              i);
    (void)snprintf(buf + n, cap - n, "    return r;\n}\n");
}

static void cxt_src(const char *dir, const char *rel, int ifs_a, int ifs_b)
{
    static char text[16384];
    text[0] = '\0';
    cxt_fn(text, sizeof(text), "big_a", ifs_a);
    if (ifs_b)
        cxt_fn(text, sizeof(text), "big_b", ifs_b);
    cxt_put(dir, rel, text);
}

static void cxt_copy_lint(const char *dir)
{
    char dst[CXT_PATH];
    size_t len = 0;
    char *bin = cx_read_file(CXT_LINT_SRC, &len);
    if (!bin)
        cxt_die("build/bin/z23-lint is missing; build it first");
    (void)snprintf(dst, sizeof(dst), "%s/build/bin/z23-lint", dir);
    cxt_mkdirs(dst);
    if (!cx_write_file(dst, bin, len) || chmod(dst, 0755) != 0)
        cxt_die("cannot copy z23-lint");
    free(bin);
}

static void cxt_pin_and_commit(const char *dir)
{
    const char *argv[] = {"build/bin/z23-lint", "check-cyclomatic-complexity",
                          "--write-baseline", NULL};
    char out[1024];
    cxt_git(dir, "add", "-A", NULL, NULL, NULL);
    cxt_copy_lint(dir);
    cxt_put(dir, "tools/lint/.keep", "");
    if (cx_run(dir, argv, out, sizeof(out), 120000, true) != 0)
        cxt_die("z23-lint --write-baseline failed");
    cxt_git(dir, "add", "-A", NULL, NULL, NULL);
    cxt_git(dir, "commit", "-q", "-m", "fixture", NULL);
    cxt_git(dir, "update-ref", "refs/remotes/origin/main", "HEAD", NULL, NULL);
}

static void cxt_new_repo(char *dir, size_t cap, const char *tag)
{
    test_make_tmpdir(dir, cap, "dev_cx", tag);
    cxt_git(dir, "init", "-q", NULL, NULL, NULL);
    cxt_put(dir, ".gitignore", "build/\n");
    cxt_put(dir, "Makefile", "print-includes:\n\t@echo -I.\n");
}

/* ── calls ───────────────────────────────────────────────────────────────── */

static void cxt_begin(struct cxt_call *c, const char *schema)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, schema);
}

static void cxt_end(struct cxt_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static void cxt_next(struct cxt_call *c, const char *repo, int count,
                     const char *exclude, const char *prefix)
{
    cxt_begin(c, "zcl.dev_cx_next.v1");
    (void)json_push_kv_str(&c->input, "cwd", repo);
    if (count > 0)
        (void)json_push_kv_int(&c->input, "count", count);
    if (exclude)
        (void)json_push_kv_str(&c->input, "exclude", exclude);
    if (prefix)
        (void)json_push_kv_str(&c->input, "prefix", prefix);
    zcl_native_handle_dev_cx_next(&c->request, &c->reply);
}

static void cxt_check(struct cxt_call *c, const char *repo, const char *file,
                      const char *funcs)
{
    cxt_begin(c, "zcl.dev_cx_check.v1");
    (void)json_push_kv_str(&c->input, "worktree", repo);
    (void)json_push_kv_str(&c->input, "file", file);
    (void)json_push_kv_str(&c->input, "functions", funcs);
    zcl_native_handle_dev_cx_check(&c->request, &c->reply);
}

static bool cxt_ok(const struct cxt_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static bool cxt_code_is(const struct cxt_call *c, const char *code)
{
    return c->reply.status != ZCL_COMMAND_STATUS_PASSED &&
           strcmp(c->reply.error.code, code) == 0;
}

/* The file names of the returned units, comma joined. */
static void cxt_order(const struct cxt_call *c, char *out, size_t cap)
{
    const struct json_value *units = json_get(&c->reply.data, "units");
    size_t used = 0;
    out[0] = '\0';
    for (size_t i = 0; units && i < json_size(units); i++) {
        const char *f = json_get_str(json_get(json_at(units, i), "file"));
        int w = snprintf(out + used, cap - used, "%s%s", i ? "," : "",
                         f ? f : "?");
        if (w < 0 || used + (size_t)w >= cap)
            break;
        used += (size_t)w;
    }
}

static int64_t cxt_skipped(const struct cxt_call *c, const char *kind)
{
    const struct json_value *s = json_get(&c->reply.data, "skipped");
    const struct json_value *v = s ? json_get(s, kind) : NULL;
    return v ? json_get_int(v) : -1;
}

static bool cxt_baseline_has(const char *repo, const char *row)
{
    char path[CXT_PATH];
    char *text;
    bool has;
    (void)snprintf(path, sizeof(path), "%s/%s", repo, CXT_BASE);
    text = cx_read_file(path, NULL);
    has = text && strstr(text, row);
    free(text);
    return has;
}

static char *cxt_baseline(const char *repo)
{
    char path[CXT_PATH];
    (void)snprintf(path, sizeof(path), "%s/%s", repo, CXT_BASE);
    return cx_read_file(path, NULL);
}

/* ── dev.cx.next ─────────────────────────────────────────────────────────── */

static void cxt_next_repo(char *dir, size_t cap)
{
    char wt[CXT_PATH], big[200000];
    cxt_new_repo(dir, cap, "next");
    cxt_src(dir, "src/two.c", 16, 17);
    cxt_src(dir, "src/one_low.c", 16, 0);
    cxt_src(dir, "src/one_low2.c", 16, 0);
    cxt_src(dir, "src/one_hi.c", 19, 0);
    cxt_src(dir, "other/outside.c", 16, 0);
    cxt_src(dir, "core/sealed.c", 16, 0);
    cxt_src(dir, "contexts/wallet/w.c", 16, 0);
    cxt_src(dir, "contexts/commons/packages/p/p.c", 16, 0);
    cxt_src(dir, "src/vault_x.c", 16, 0);
    cxt_src(dir, "src/changed.c", 16, 0);
    cxt_src(dir, "src/excl.c", 16, 0);
    big[0] = '\0';
    for (int i = 0; i < 1400; i++)
        (void)strncat(big, "/* pad */\n", sizeof(big) - strlen(big) - 1);
    cxt_fn(big, sizeof(big), "big_a", 16);
    cxt_put(dir, "src/large.c", big);
    cxt_pin_and_commit(dir);
    (void)snprintf(wt, sizeof(wt), "%s-lane", dir);
    cxt_git(dir, "worktree", "add", "-q", "--detach", wt);
    cxt_src(wt, "src/changed.c", 16, 1);
}

static int cxt_test_next_order(const char *repo)
{
    int failures = 0;
    struct cxt_call c, d;
    char first[1024], again[1024];
    TEST("dev.cx.next: fewest functions first, then lowest max score, then path") {
        cxt_next(&c, repo, 50, NULL, NULL);
        ASSERT(cxt_ok(&c));
        cxt_order(&c, first, sizeof(first));
        ASSERT_STR_EQ(first, "other/outside.c,src/excl.c,src/one_low.c,src/one_low2.c,"
                             "src/one_hi.c,src/two.c");
        cxt_next(&d, repo, 50, NULL, NULL);
        cxt_order(&d, again, sizeof(again));
        ASSERT_STR_EQ(first, again);
        cxt_end(&d);
        cxt_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int cxt_test_next_skips(const char *repo, const char *excl_list)
{
    int failures = 0;
    struct cxt_call c;
    char order[1024];
    TEST("dev.cx.next: skips each excluded class") {
        cxt_next(&c, repo, 50, excl_list, NULL);
        ASSERT(cxt_ok(&c));
        cxt_order(&c, order, sizeof(order));
        ASSERT(strstr(order, "core/") == NULL);
        ASSERT(strstr(order, "contexts/wallet/") == NULL);
        ASSERT(strstr(order, "contexts/commons/packages/") == NULL);
        ASSERT(strstr(order, "vault_x") == NULL);
        ASSERT(strstr(order, "large.c") == NULL);
        ASSERT(strstr(order, "changed.c") == NULL);
        ASSERT(strstr(order, "excl.c") == NULL);
        ASSERT_EQ(cxt_skipped(&c, "sealed"), 1);
        ASSERT_EQ(cxt_skipped(&c, "custody"), 2);
        ASSERT_EQ(cxt_skipped(&c, "packages"), 1);
        ASSERT_EQ(cxt_skipped(&c, "large"), 1);
        ASSERT_EQ(cxt_skipped(&c, "changed"), 1);
        ASSERT_EQ(cxt_skipped(&c, "excluded"), 1);
        cxt_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int cxt_test_next_window(const char *repo)
{
    int failures = 0;
    struct cxt_call c;
    char order[1024];
    TEST("dev.cx.next: count and prefix narrow the answer") {
        cxt_next(&c, repo, 2, NULL, "src/");
        ASSERT(cxt_ok(&c));
        cxt_order(&c, order, sizeof(order));
        ASSERT_STR_EQ(order, "src/excl.c,src/one_low.c");
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "returned")), 2);
        cxt_end(&c);
        cxt_next(&c, repo, 0, NULL, "other/,src/two");
        cxt_order(&c, order, sizeof(order));
        ASSERT_STR_EQ(order, "other/outside.c,src/two.c");
        cxt_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int cxt_test_next_refusals(const char *repo)
{
    int failures = 0;
    struct cxt_call c;
    char bare[CXT_PATH];
    TEST("dev.cx.next: no origin/main and a bad count refuse") {
        cxt_new_repo(bare, sizeof(bare), "bare");
        cxt_src(bare, "src/a.c", 16, 0);
        cxt_pin_and_commit(bare);
        cxt_git(bare, "update-ref", "-d", "refs/remotes/origin/main", NULL,
                NULL);
        cxt_next(&c, bare, 5, NULL, NULL);
        ASSERT(cxt_code_is(&c, "NEXT_NO_ORIGIN_MAIN"));
        cxt_end(&c);
        cxt_next(&c, repo, 100000, NULL, NULL);
        ASSERT(cxt_code_is(&c, "NEXT_BAD_INPUT"));
        cxt_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

/* ── dev.cx.check ────────────────────────────────────────────────────────── */

/* A lane whose src/split.c carries one function at complexity 17 (`big_a`)
 * and whose src/other.c is a bystander. */
static void cxt_lane(char *dir, size_t cap, const char *tag)
{
    cxt_new_repo(dir, cap, tag);
    cxt_src(dir, "src/split.c", 16, 0);
    cxt_src(dir, "src/other.c", 3, 0);
    cxt_pin_and_commit(dir);
}

/* big_a rebuilt as two small helpers: complexity 9 each, big_a itself 3. */
static void cxt_split_ok(const char *dir)
{
    static char text[16384];
    text[0] = '\0';
    cxt_fn(text, sizeof(text), "part_a", 8);
    cxt_fn(text, sizeof(text), "part_b", 8);
    (void)strcat(text, "int big_a(int x)\n{\n    return part_a(x) + part_b(x);\n}\n");
    cxt_put(dir, "src/split.c", text);
}

static int cxt_test_check_pass(void)
{
    int failures = 0;
    struct cxt_call c;
    char dir[CXT_PATH];
    TEST("dev.cx.check: a real split passes and deletes only its row") {
        cxt_lane(dir, sizeof(dir), "pass");
        ASSERT(cxt_baseline_has(dir, "src/split.c:big_a:17"));
        cxt_split_ok(dir);
        cxt_check(&c, dir, "src/split.c", "big_a");
        ASSERT(cxt_ok(&c));
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "verdict")), "pass");
        ASSERT_EQ(json_size(json_get(&c.reply.data, "rows_deleted")), (size_t)1);
        ASSERT_STR_EQ(json_get_str(json_at(json_get(&c.reply.data,
                                                    "rows_deleted"), 0)),
                      "src/split.c:big_a:17");
        ASSERT(!cxt_baseline_has(dir, "src/split.c:big_a"));
        cxt_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int cxt_test_check_scope(void)
{
    int failures = 0;
    struct cxt_call c;
    char dir[CXT_PATH];
    char *before, *after;
    TEST("dev.cx.check: CX_SCOPE when another file is touched or nothing changed") {
        cxt_lane(dir, sizeof(dir), "scope");
        before = cxt_baseline(dir);
        cxt_check(&c, dir, "src/split.c", "big_a");
        ASSERT(cxt_code_is(&c, "CX_SCOPE"));
        cxt_end(&c);
        cxt_split_ok(dir);
        cxt_src(dir, "src/other.c", 4, 0);
        cxt_check(&c, dir, "src/split.c", "big_a");
        ASSERT(cxt_code_is(&c, "CX_SCOPE"));
        cxt_end(&c);
        cxt_src(dir, "src/other.c", 3, 0);
        cxt_put(dir, "src/new_file.c", "int z;\n");
        cxt_check(&c, dir, "src/split.c", "big_a");
        ASSERT(cxt_code_is(&c, "CX_SCOPE"));
        cxt_end(&c);
        after = cxt_baseline(dir);
        ASSERT(before && after && strcmp(before, after) == 0);
        free(before);
        free(after);
        PASS();
    }
_test_next:;
    return failures;
}

static int cxt_test_check_compile(void)
{
    int failures = 0;
    struct cxt_call c;
    char dir[CXT_PATH];
    TEST("dev.cx.check: CX_COMPILE on a syntax error") {
        cxt_lane(dir, sizeof(dir), "compile");
        cxt_put(dir, "src/split.c", "int big_a(int x)\n{\n    return x +;\n}\n");
        cxt_check(&c, dir, "src/split.c", "big_a");
        ASSERT(cxt_code_is(&c, "CX_COMPILE"));
        ASSERT(cxt_baseline_has(dir, "src/split.c:big_a:17"));
        cxt_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int cxt_test_check_over(void)
{
    int failures = 0;
    struct cxt_call c;
    char dir[CXT_PATH];
    char *text, *before, *after;
    TEST("dev.cx.check: CX_STILL_OVER names a function that did not drop") {
        cxt_lane(dir, sizeof(dir), "over");
        before = cxt_baseline(dir);
        text = calloc(1, 16384);
        ASSERT(text != NULL);
        (void)strcpy(text, "/* still big */\n");
        cxt_fn(text, 16384, "big_a", 16);
        cxt_put(dir, "src/split.c", text);
        free(text);
        cxt_check(&c, dir, "src/split.c", "big_a");
        ASSERT(cxt_code_is(&c, "CX_STILL_OVER"));
        ASSERT(strstr(json_get_str(json_get(&c.reply.data, "detail")), "big_a:17"));
        cxt_end(&c);
        after = cxt_baseline(dir);
        ASSERT(before && after && strcmp(before, after) == 0);
        free(before);
        free(after);
        PASS();
    }
_test_next:;
    return failures;
}

static int cxt_test_check_added(void)
{
    int failures = 0;
    struct cxt_call c;
    char dir[CXT_PATH];
    char *before, *after;
    TEST("dev.cx.check: CX_BASELINE_ADDED when tightening rewrites a pin") {
        cxt_lane(dir, sizeof(dir), "added");
        before = cxt_baseline(dir);
        cxt_src(dir, "src/split.c", 15, 0);
        cxt_check(&c, dir, "src/split.c", "big_a");
        ASSERT(cxt_code_is(&c, "CX_BASELINE_ADDED"));
        cxt_end(&c);
        after = cxt_baseline(dir);
        ASSERT(before && after && strcmp(before, after) == 0);
        free(before);
        free(after);
        PASS();
    }
_test_next:;
    return failures;
}

static int cxt_test_check_gate(void)
{
    int failures = 0;
    struct cxt_call c;
    char dir[CXT_PATH];
    char *text, *before, *after;
    TEST("dev.cx.check: CX_GATE when the split leaves a new offender") {
        cxt_lane(dir, sizeof(dir), "gate");
        before = cxt_baseline(dir);
        text = calloc(1, 16384);
        ASSERT(text != NULL);
        cxt_fn(text, 16384, "helper_hot", 16);
        (void)strcat(text, "int big_a(int x)\n{\n    return helper_hot(x);\n}\n");
        cxt_put(dir, "src/split.c", text);
        free(text);
        cxt_check(&c, dir, "src/split.c", "big_a");
        ASSERT(cxt_code_is(&c, "CX_GATE"));
        cxt_end(&c);
        after = cxt_baseline(dir);
        ASSERT(before && after && strcmp(before, after) == 0);
        free(before);
        free(after);
        PASS();
    }
_test_next:;
    return failures;
}

int test_dev_cx(void);
int test_dev_cx(void)
{
    char repo[CXT_PATH], excl[CXT_PATH], list[CXT_PATH];
    int failures = 0;
    cxt_next_repo(repo, sizeof(repo));
    (void)snprintf(excl, sizeof(excl), "%s-exclude", repo);
    cxt_put(excl, "list.txt", "src/excl.c\n");
    (void)snprintf(list, sizeof(list), "%s/list.txt", excl);
    failures += cxt_test_next_order(repo);
    failures += cxt_test_next_skips(repo, list);
    failures += cxt_test_next_window(repo);
    failures += cxt_test_next_refusals(repo);
    failures += cxt_test_check_pass();
    failures += cxt_test_check_scope();
    failures += cxt_test_check_compile();
    failures += cxt_test_check_over();
    failures += cxt_test_check_added();
    failures += cxt_test_check_gate();
    return failures;
}
#endif

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for code.count (tools/command/native_code_count_command.c).
 *
 * A fixture git repository with known blobs gives exact counts: the leaf
 * reads committed objects (an uncommitted edit never moves the answer), the
 * per-blob cache turns a second run into hits and a later commit into a count
 * of only its new blobs, and --at, --path and --exclude select what they say.
 * Both counting paths run: a cold tree with more misses than the named-blob
 * limit (scope grep) and a later commit with two (named blobs).
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "codeindex/codeindex.h"
#include "codeindex/codeindex_build.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct cc_fix {
    char dir[512];
    char commit1[64];
};

#if defined(ZCL_TESTING) && !defined(_WIN32)
static bool cct_write(const struct cc_fix *fx, const char *rel, const char *text);

static bool cct_impact_wire(const char *text, size_t n)
{
    struct json_value wire; json_init(&wire);
    bool parsed = json_read(&wire, text, n);
    const struct json_value *data = json_get(&wire, "data");
    const struct json_value *includes = json_get(data, "direct_includes");
    bool ok = parsed && json_get_bool(json_get(&wire, "ok")) &&
        !strcmp(json_get_str(json_get(&wire, "status")),
                zcl_command_status_name(ZCL_COMMAND_STATUS_PASSED)) &&
        !strcmp(json_get_str(json_get(&wire, "data_schema")), "zcl.code_impact.v1") &&
        !strcmp(json_get_str(json_get(data, "path")), "src/impact.c") &&
        includes && includes->type == JSON_INT && json_get_int(includes) == 1;
    json_free(&wire); return ok;
}

static bool cct_dispatch_impact(const struct zcl_native_standalone_runtime *runtime)
{
    FILE *out = tmpfile();
    int saved = out ? dup(STDOUT_FILENO) : -1;
    if (saved < 0) { if (out) fclose(out); return false; }
    fflush(stdout);
    if (dup2(fileno(out), STDOUT_FILENO) < 0) {
        close(saved); fclose(out); return false;
    }
    const char *args[] = {"impact", "src/impact.c"};
    int rc = zcl_native_command_main_standalone("code", args, 2, "", 0,
                                                 CHAIN_MAIN, false, runtime);
    fflush(stdout);
    bool restored = dup2(saved, STDOUT_FILENO) >= 0;
    close(saved);
    rewind(out);
    char text[4096]; size_t n = fread(text, 1, sizeof text - 1, out);
    bool read_ok = !ferror(out); text[n] = '\0';
    bool closed = fclose(out) == 0;
    return restored && read_ok && closed && rc == 0 && cct_impact_wire(text, n);
}

static bool cct_oneshot_check(const struct zcl_native_standalone_runtime *runtime,
                              uint64_t walks, uint64_t seals, uint64_t expected)
{
    bool dispatched = cct_dispatch_impact(runtime);
    uint64_t actual_walks = codeindex_test_freshness_walks();
    uint64_t actual_seals = codeindex_test_freshness_seals();
    bool ok = dispatched && actual_walks == walks + expected && actual_seals == seals;
    if (!ok) printf("code.impact one-shot dispatch=%d walks_delta=%llu expected=%llu seals_delta=%lld\n",
                    dispatched, (unsigned long long)(actual_walks - walks),
                    (unsigned long long)expected, (long long)(actual_seals - seals));
    return ok;
}

static bool cct_policy_calls(void)
{
    struct zcl_native_standalone_runtime normal = {0};
    struct zcl_native_standalone_runtime once = {.one_shot_process = true};
    if (!cct_dispatch_impact(&normal)) {
        printf("code.impact normal dispatch failed\n"); return false;
    }
    uint64_t walks = codeindex_test_freshness_walks();
    uint64_t seals = codeindex_test_freshness_seals();
    if (!cct_dispatch_impact(NULL) || codeindex_test_freshness_walks() != walks ||
        codeindex_test_freshness_seals() != seals) {
        printf("code.impact null runtime did not reuse memo\n"); return false;
    }
    if (!cct_dispatch_impact(&normal) || codeindex_test_freshness_walks() != walks ||
        codeindex_test_freshness_seals() != seals) {
        printf("code.impact false runtime did not reuse memo\n"); return false;
    }
    for (uint64_t i = 1; i <= 2; i++)
        if (!cct_oneshot_check(&once, walks, seals, i)) return false;
    return true;
}

static bool cct_dispatch_policy(const struct cc_fix *fx)
{
    const char *previous = getenv("ZCL_DEV_SOURCE_ROOT");
    char *saved = previous ? strdup(previous) : NULL;
    if (previous && !saved) return false;
    bool ok = cct_write(fx, "src/impact_fixture.h", "#define IMPACT_VALUE 1\n") &&
              cct_write(fx, "src/impact.c", "#include \"impact_fixture.h\"\nint impact_fixture(void) { return IMPACT_VALUE; }\n") &&
              cct_write(fx, "build/fixture.d", "build/fixture.o: src/impact.c src/impact_fixture.h\n") &&
              setenv("ZCL_DEV_SOURCE_ROOT", fx->dir, 1) == 0;
    struct codeindex *ci = ok ? codeindex_open(fx->dir) : NULL;
    ok = ok && ci != NULL;
    if (!ok) printf("code.impact one-shot fixture/index setup failed\n");
    codeindex_close(ci);
    if (ok) ok = cct_policy_calls();
    int restored = saved ? setenv("ZCL_DEV_SOURCE_ROOT", saved, 1) : unsetenv("ZCL_DEV_SOURCE_ROOT");
    free(saved);
    return ok && restored == 0;
}

static bool cct_isolated_dispatch_policy(void)
{
    struct cc_fix fx = {0};
    if (!test_mkdtemp(fx.dir, sizeof fx.dir, "code_impact_policy")) return false;
    bool ok = cct_dispatch_policy(&fx);
    bool cleaned = test_rm_rf_recursive(fx.dir) == 0;
    return ok && cleaned;
}
#endif

static int cct_git(const struct cc_fix *fx, char *out, size_t cap,
                   const char *a, const char *b, const char *c, const char *d)
{
    const char *argv[16] = {"git", "-C", fx->dir, "-c", "user.name=t", "-c",
                            "user.email=t@example.invalid", "-c",
                            "commit.gpgsign=false"};
    size_t n = 9;
    const char *rest[4] = {a, b, c, d};
    for (size_t i = 0; i < 4 && rest[i]; i++)
        argv[n++] = rest[i];
    argv[n] = NULL;
    char scratch[256];
    return zcl_spawn_capture(argv, out ? out : scratch, out ? cap : sizeof scratch,
                             30000);
}

static bool cct_write(const struct cc_fix *fx, const char *rel, const char *text)
{
    char path[640];
    (void)snprintf(path, sizeof path, "%s/%s", fx->dir, rel);
    for (char *p = path + strlen(fx->dir) + 1; *p; p++)
        if (*p == '/') {
            *p = '\0';
            (void)mkdir(path, 0777);
            *p = '/';
        }
    FILE *fp = fopen(path, "wb");
    if (!fp)
        return false;
    bool ok = fputs(text, fp) >= 0;
    return fclose(fp) == 0 && ok;
}

struct cct_call {
    struct json_value input;
    struct zcl_command_context ctx;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void cct_begin(struct cct_call *c, const struct cc_fix *fx)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->ctx, 0, sizeof c->ctx);
    c->ctx.source_root = fx->dir;
    memset(&c->request, 0, sizeof c->request);
    c->request.input = &c->input;
    c->request.context = &c->ctx;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), "code.count", NULL);
    zcl_command_reply_init(&c->reply, "zcl.code_count.v1");
}

static void cct_arg(struct cct_call *c, const char *key, const char *value)
{
    (void)json_push_kv_str(&c->input, key, value);
}

static void cct_end(struct cct_call *c)
{
    json_free(&c->input);
    zcl_command_reply_free(&c->reply);
}

static int64_t cct_int(const struct cct_call *c, const char *key)
{
    return json_get_int(json_get(&c->reply.data, key));
}

static int64_t cct_sub(const struct cct_call *c, const char *obj, const char *key)
{
    return json_get_int(json_get(json_get(&c->reply.data, obj), key));
}

static bool cct_run(struct cct_call *c)
{
    char why[192];
    if (!zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof why)) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_code_count(&c->request, &c->reply);
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static bool cct_build_fixture(struct cc_fix *fx)
{
    char name[64];
    if (!test_mkdtemp(fx->dir, sizeof fx->dir, "code_count"))
        return false;
    bool ok = cct_git(fx, NULL, 0, "init", "-q", NULL, NULL) == 0 &&
              cct_write(fx, "a.c", "x\ny\nz\n") &&
              cct_write(fx, "src/b.h", "one") &&
              cct_write(fx, "tests/t.c", "a\nb\n") &&
              cct_write(fx, "vendor/v.c", "1\n2\n3\n4\n5\n") &&
              cct_write(fx, "empty.c", "") &&
              cct_write(fx, "README.md", "doc\ndoc\n");
    for (int i = 0; ok && i < 8; i++) {
        (void)snprintf(name, sizeof name, "gen/g%d.c", i);
        char body[16];
        (void)snprintf(body, sizeof body, "line%d\n", i);
        ok = cct_write(fx, name, body);
    }
    char link[640];
    (void)snprintf(link, sizeof link, "%s/link.c", fx->dir);
    ok = ok && symlink("a.c", link) == 0 &&
         cct_git(fx, NULL, 0, "add", "-A", NULL, NULL) == 0 &&
         cct_git(fx, NULL, 0, "commit", "-q", "-m", "one") == 0;
    char out[128] = "";
    ok = ok && cct_git(fx, out, sizeof out, "rev-parse", "HEAD", NULL, NULL) == 0;
    out[strcspn(out, "\n")] = '\0';
    (void)snprintf(fx->commit1, sizeof fx->commit1, "%s", out);
    return ok;
}

static bool cct_moving_setup(const struct cc_fix *fx, const char *next,
                             const char *old_path)
{
    static const char script[] =
        "#!/bin/sh\nd=${0%/*}\nIFS= read -r PATH < \"$d/path\" || exit 1\n"
        "export PATH\nIFS= read -r target < \"$d/target\" || exit 1\n"
        "case \"$*\" in\n"
        "*'moving^{commit}'*) git \"$@\"; r=$?; "
        "if [ \"$r\" = 0 ]; then git -C \"$d/..\" update-ref "
        "refs/heads/moving \"$target\" || exit 1; fi; exit \"$r\";;\n"
        "*) exec git \"$@\";;\nesac\n";
    char shim[640], path_line[1024], target_line[128];
    if (cct_git(fx, NULL, 0, "branch", "moving", fx->commit1, NULL))
        return false;
    int n = snprintf(path_line, sizeof path_line, "%s\n", old_path);
    int m = snprintf(target_line, sizeof target_line, "%s\n", next);
    if (n < 0 || (size_t)n >= sizeof path_line || m < 0 ||
        (size_t)m >= sizeof target_line)
        return false;
    if (!cct_write(fx, "shim/path", path_line) ||
        !cct_write(fx, "shim/target", target_line) ||
        !cct_write(fx, "shim/git", script))
        return false;
    (void)snprintf(shim, sizeof shim, "%s/shim/git", fx->dir);
    return chmod(shim, 0700) == 0;
}

static bool cct_moving_result(const struct cct_call *c, const struct cc_fix *fx,
                              const char *tree, const char *moved, const char *next,
                              bool installed, bool ran, bool restored)
{
    const char *commit = json_get_str(json_get(&c->reply.data, "commit"));
    const char *actual_tree = json_get_str(json_get(&c->reply.data, "tree"));
    bool ok = installed && ran && restored && commit && actual_tree &&
              strcmp(commit, fx->commit1) == 0 && strcmp(actual_tree, tree) == 0 &&
              cct_int(c, "files") == 12 && cct_int(c, "lines") == 14 &&
              strcmp(moved, next) == 0;
    if (!ok)
        printf("[moving installed=%d ran=%d restored=%d commit=%s expected=%s "
               "tree=%s expected=%s files=%lld lines=%lld moved=%s expected=%s] ",
               installed, ran, restored, commit ? commit : "(null)", fx->commit1,
               actual_tree ? actual_tree : "(null)", tree,
               (long long)cct_int(c, "files"), (long long)cct_int(c, "lines"),
               moved, next);
    return ok;
}

/* Move only this fixture's branch after Git has returned its first lookup. */
static bool cct_moving_ref(const struct cc_fix *fx, const char *next)
{
    char tree[128] = "", path[1024], moved[128] = "";
    if (cct_git(fx, tree, sizeof tree, "rev-parse", "HEAD~1^{tree}", NULL, NULL))
        return false;
    tree[strcspn(tree, "\n")] = '\0';
    const char *old = getenv("PATH");
    char *saved = old ? strdup(old) : NULL;
    if (old && !saved)
        return false;
    bool setup = saved && cct_moving_setup(fx, next, saved);
    int n = snprintf(path, sizeof path, "%s/shim:%s", fx->dir, saved ? saved : "");
    bool installed = setup && n >= 0 && (size_t)n < sizeof path &&
                     setenv("PATH", path, 1) == 0;
    struct cct_call c;
    cct_begin(&c, fx);
    cct_arg(&c, "at", "moving");
    bool ran = installed && cct_run(&c);
    bool restored = !installed || setenv("PATH", saved, 1) == 0;
    free(saved);
    if (restored)
        (void)cct_git(fx, moved, sizeof moved, "rev-parse", "moving", NULL, NULL);
    moved[strcspn(moved, "\n")] = '\0';
    bool ok = cct_moving_result(&c, fx, tree, moved, next, installed, ran, restored);
    cct_end(&c);
    return ok;
}

static bool cct_revision_case(const struct cc_fix *fx, const char *revision,
                              bool accepted)
{
    struct cct_call c;
    cct_begin(&c, fx);
    cct_arg(&c, "at", revision);
    bool passed = cct_run(&c);
    bool ok = passed == accepted;
    if (accepted && passed) {
        const char *commit = json_get_str(json_get(&c.reply.data, "commit"));
        ok = commit && strcmp(commit, fx->commit1) == 0;
    }
    cct_end(&c);
    return ok;
}

static bool cct_tree_fixture(const struct cc_fix *fx, size_t entries, bool fail,
                             size_t *bytes)
{
    char name[640];
    (void)snprintf(name, sizeof name, "%s/shim/listing", fx->dir);
    FILE *fp = fopen(name, "wb");
    if (!fp)
        return false;
    bool ok = true;
    for (size_t i = 0; i < entries; i++) {
        int n = fprintf(fp, "100644 blob 0000000000000000000000000000000000000000 0\tfile%06zu.c\n", i);
        if (n < 0) { ok = false; break; }
        *bytes += (size_t)n;
    }
    if (fclose(fp) != 0)
        ok = false;
    (void)snprintf(name, sizeof name, "%s/shim/fail", fx->dir);
    if (fail)
        ok = cct_write(fx, "shim/fail", "fail\n") && ok;
    else if (unlink(name) != 0 && access(name, F_OK) == 0)
        ok = false;
    return cct_write(fx, "shim/calls", "") && ok;
}

static bool cct_tree_shim(const struct cc_fix *fx, const char *old)
{
    static const char script[] =
        "#!/bin/sh\nd=${0%/*}\nIFS= read -r PATH < \"$d/path\" || exit 1\n"
        "export PATH\ncase \"$*\" in\n"
        "*ls-tree*) printf x >> \"$d/calls\" || exit 1; "
        "cat \"$d/listing\" || exit 1; [ ! -f \"$d/fail\" ] || exit 1;;\n"
        "*) exec git \"$@\";;\nesac\n";
    char path_line[1024], shim[640];
    int n = snprintf(path_line, sizeof path_line, "%s\n", old);
    if (n < 0 || (size_t)n >= sizeof path_line ||
        !cct_write(fx, "shim/path", path_line) || !cct_write(fx, "shim/git", script))
        return false;
    (void)snprintf(shim, sizeof shim, "%s/shim/git", fx->dir);
    return chmod(shim, 0700) == 0;
}

static bool cct_tree_result(const struct cc_fix *fx, const struct cct_call *c,
                            size_t entries, size_t bytes, bool fail, long expected,
                            bool ran, bool installed, bool restored)
{
    char path[640];
    struct stat st;
    (void)snprintf(path, sizeof path, "%s/shim/calls", fx->dir);
    long calls = stat(path, &st) == 0 ? (long)st.st_size : -1;
    bool ok = installed && restored && (fail ? !ran : ran) && calls == (fail ? 1 : expected);
    if (fail)
        ok = ok && strcmp(c->reply.error.code, "CODE_COUNT_TREE") == 0 &&
             json_get(&c->reply.data, "files") == NULL;
    else
        ok = ok && cct_int(c, "files") == (int64_t)entries && cct_int(c, "lines") == 0;
    if (!ok)
        printf("[tree bytes=%zu entries=%zu fail=%d installed=%d restored=%d ran=%d "
               "status=%d calls=%ld expected=%ld files=%lld lines=%lld code=%s] ",
               bytes, entries, fail, installed, restored, ran, (int)c->reply.status,
               calls, fail ? 1L : expected, (long long)cct_int(c, "files"),
               (long long)cct_int(c, "lines"), c->reply.error.code);
    return ok;
}

static bool cct_tree_capture(const struct cc_fix *fx, size_t entries, bool fail,
                             long expected)
{
    const char *old = getenv("PATH");
    char *saved = old ? strdup(old) : NULL;
    if (!saved)
        return false;
    size_t bytes = 0;
    bool setup = cct_tree_shim(fx, saved) && cct_tree_fixture(fx, entries, fail, &bytes);
    size_t lower = entries == 20000 ? 1024 * 1024 : 2 * 1024 * 1024;
    bool size_ok = bytes > lower && bytes < lower * 2;
    char path[1024];
    int n = snprintf(path, sizeof path, "%s/shim:%s", fx->dir, saved);
    bool installed = setup && size_ok && n >= 0 && (size_t)n < sizeof path &&
                     setenv("PATH", path, 1) == 0;
    struct cct_call c;
    cct_begin(&c, fx);
    bool ran = installed && cct_run(&c);
    bool restored = !installed || setenv("PATH", saved, 1) == 0;
    free(saved);
    bool ok = cct_tree_result(fx, &c, entries, bytes, fail, expected, ran, installed, restored);
    cct_end(&c);
    return ok;
}

struct cct_cache_case {
    const char *name;
    const char *value;
    size_t len;
    bool hit;
    int64_t lines;
};

static bool cct_cache_case(const struct cc_fix *fx, const char *blob,
                           const struct cct_cache_case *test)
{
    char path[640];
    (void)snprintf(path, sizeof path, "%s/.codeindex/code_count.v1", fx->dir);
    FILE *fp = fopen(path, "wb");
    if (!fp)
        return false;
    bool wrote = fprintf(fp, "%s ", blob) == 41 &&
                 fwrite(test->value, 1, test->len, fp) == test->len;
    if (fclose(fp) != 0)
        wrote = false;
    struct cct_call c;
    cct_begin(&c, fx);
    cct_arg(&c, "at", "HEAD");
    cct_arg(&c, "path", "a.c");
    bool ran = wrote && cct_run(&c);
    int64_t hits = cct_sub(&c, "cache", "hits");
    int64_t counted = cct_sub(&c, "cache", "counted");
    int64_t lines = cct_int(&c, "lines");
    bool ok = ran && cct_int(&c, "files") == 1 && lines == test->lines &&
              hits == (test->hit ? 1 : 0) && counted == (test->hit ? 0 : 1);
    if (!ok)
        printf("[cache case=%s wrote=%d ran=%d hits=%lld counted=%lld lines=%lld "
               "expected_hit=%d expected_lines=%lld] ", test->name, wrote, ran,
               (long long)hits, (long long)counted, (long long)lines,
               test->hit, (long long)test->lines);
    cct_end(&c);
    return ok;
}

static bool cct_cache_numbers(const struct cc_fix *fx)
{
#define CCT_CASE(label, text, accepted, result) \
    {label, text, sizeof(text) - 1, accepted, result}
    static const struct cct_cache_case cases[] = {
        CCT_CASE("minus", "-1\n", false, 5),
        CCT_CASE("plus", "+1\n", false, 5),
        CCT_CASE("space", " 1\n", false, 5),
        CCT_CASE("tab", "\t1\n", false, 5),
        CCT_CASE("overflow", "18446744073709551616\n", false, 5),
        CCT_CASE("missing", "\n", false, 5),
        CCT_CASE("junk", "5x\n", false, 5),
        CCT_CASE("torn", "5", false, 5),
        CCT_CASE("nul-before", "\0" "5\n", false, 5),
        CCT_CASE("nul-after", "5\0junk\n", false, 5),
        CCT_CASE("ordinary", "5\n", true, 5),
        CCT_CASE("leading-zero", "0005\n", true, 5),
        CCT_CASE("zero-syntax", "0\n", true, 0),
    };
#undef CCT_CASE
    char blob[128] = "";
    if (cct_git(fx, blob, sizeof blob, "rev-parse", "HEAD:a.c", NULL, NULL) != 0)
        return false;
    blob[strcspn(blob, "\n")] = '\0';
    bool ok = true;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++)
        if (!cct_cache_case(fx, blob, &cases[i]))
            ok = false;
    return ok;
}

int test_code_count(void);
int test_code_count(void)
{
    int failures = 0;
    struct cc_fix fx = {0};
    char head[128] = "";

    TEST("code.count: the fixture repository builds") {
        ASSERT(cct_build_fixture(&fx));
        PASS();
    }

    TEST("code.count: cold run is exact, splits tests/, skips vendor, empties, symlinks") {
        struct cct_call c;
        cct_begin(&c, &fx);
        ASSERT(cct_run(&c));
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "commit")), fx.commit1);
        ASSERT_EQ(cct_int(&c, "files"), 12);
        ASSERT_EQ(cct_int(&c, "lines"), 14);
        ASSERT_EQ(cct_sub(&c, "tests", "files"), 1);
        ASSERT_EQ(cct_sub(&c, "tests", "lines"), 2);
        ASSERT_EQ(cct_sub(&c, "other", "files"), 11);
        ASSERT_EQ(cct_sub(&c, "other", "lines"), 12);
        ASSERT_EQ(cct_sub(&c, "cache", "hits"), 0);
        ASSERT_EQ(cct_sub(&c, "cache", "counted"), 11);
        cct_end(&c);
        PASS();
    }

    TEST("code.count: a second run is all cache hits with the same answer") {
        struct cct_call c;
        cct_begin(&c, &fx);
        ASSERT(cct_run(&c));
        ASSERT_EQ(cct_int(&c, "lines"), 14);
        ASSERT_EQ(cct_sub(&c, "cache", "hits"), 11);
        ASSERT_EQ(cct_sub(&c, "cache", "counted"), 0);
        cct_end(&c);
        PASS();
    }

    TEST("code.count: a later commit counts only the blobs it has not seen") {
        ASSERT(cct_write(&fx, "a.c", "1\n2\n3\n4\n5\n"));
        ASSERT(cct_write(&fx, "src/c.c", "p\nq\n"));
        ASSERT(cct_git(&fx, NULL, 0, "add", "-A", NULL, NULL) == 0);
        ASSERT(cct_git(&fx, NULL, 0, "commit", "-q", "-m", "two") == 0);
        ASSERT_EQ(cct_git(&fx, head, sizeof head, "rev-parse", "HEAD", NULL, NULL), 0);
        head[strcspn(head, "\n")] = '\0';
        struct cct_call c;
        cct_begin(&c, &fx);
        ASSERT(cct_run(&c));
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "commit")), head);
        ASSERT_EQ(cct_int(&c, "files"), 13);
        ASSERT_EQ(cct_int(&c, "lines"), 18);
        ASSERT_EQ(cct_sub(&c, "cache", "hits"), 10);
        ASSERT_EQ(cct_sub(&c, "cache", "counted"), 2);
        cct_end(&c);
        PASS();
    }

    TEST("code.count: --at selects the commit and an uncommitted edit changes nothing") {
        ASSERT(cct_write(&fx, "a.c", "dirty\n"));
        ASSERT(cct_write(&fx, "new_uncommitted.c", "u\nv\nw\n"));
        struct cct_call c;
        cct_begin(&c, &fx);
        cct_arg(&c, "at", fx.commit1);
        ASSERT(cct_run(&c));
        ASSERT_EQ(cct_int(&c, "files"), 12);
        ASSERT_EQ(cct_int(&c, "lines"), 14);
        ASSERT_EQ(cct_sub(&c, "cache", "hits"), 11);
        cct_end(&c);
        cct_begin(&c, &fx);
        ASSERT(cct_run(&c));
        ASSERT_EQ(cct_int(&c, "lines"), 18);
        cct_end(&c);
        PASS();
    }

    TEST("code.count: moving a ref cannot mix commit and tree") {
        ASSERT(cct_moving_ref(&fx, head));
        PASS();
    }

    TEST("code.count: revision expressions retain single-commit semantics") {
        ASSERT_EQ(cct_git(&fx, NULL, 0, "tag", "fixture-tag", fx.commit1, NULL), 0);
        ASSERT(cct_revision_case(&fx, "fixture-tag", true));
        ASSERT(cct_revision_case(&fx, "HEAD~1", true));
        ASSERT(cct_revision_case(&fx, "HEAD~1..HEAD", false));
        ASSERT(cct_revision_case(&fx, "HEAD^{tree}", false));
        PASS();
    }

    TEST("code.count: one capture handles a tree above 1 MiB") {
        ASSERT(cct_tree_capture(&fx, 20000, false, 1));
        PASS();
    }

    TEST("code.count: a tree above 2 MiB is retried completely") {
        ASSERT(cct_tree_capture(&fx, 40000, false, 2));
        PASS();
    }

    TEST("code.count: failing tree capture never returns partial counts") {
        ASSERT(cct_tree_capture(&fx, 40000, true, 1));
        PASS();
    }

    TEST("code.count: --path restricts to a prefix and --exclude=none counts vendor") {
        struct cct_call c;
        cct_begin(&c, &fx);
        cct_arg(&c, "path", "tests/");
        ASSERT(cct_run(&c));
        ASSERT_EQ(cct_int(&c, "files"), 1);
        ASSERT_EQ(cct_int(&c, "lines"), 2);
        cct_end(&c);
        cct_begin(&c, &fx);
        cct_arg(&c, "path", "src");
        ASSERT(cct_run(&c));
        ASSERT_EQ(cct_int(&c, "files"), 2);
        ASSERT_EQ(cct_int(&c, "lines"), 3);
        cct_end(&c);
        cct_begin(&c, &fx);
        cct_arg(&c, "exclude", "none");
        ASSERT(cct_run(&c));
        ASSERT_EQ(cct_int(&c, "files"), 14);
        ASSERT_EQ(cct_int(&c, "lines"), 23);
        cct_end(&c);
        cct_begin(&c, &fx);
        cct_arg(&c, "path", "vendor");
        ASSERT(cct_run(&c));
        ASSERT_EQ(cct_int(&c, "files"), 0);
        cct_end(&c);
        PASS();
    }

    TEST("code.count: a damaged cache is ignored, never trusted") {
        char cache[640];
        (void)snprintf(cache, sizeof cache, "%s/.codeindex/code_count.v1", fx.dir);
        FILE *fp = fopen(cache, "ab");
        ASSERT(fp != NULL);
        (void)fputs("garbage line\n0123 9\n", fp);
        (void)fputs("00000000000000000000000000000000000000ff 77", fp);
        (void)fclose(fp);
        struct cct_call c;
        cct_begin(&c, &fx);
        ASSERT(cct_run(&c));
        ASSERT_EQ(cct_int(&c, "lines"), 18);
        cct_end(&c);
        PASS();
    }

    TEST("code.count: cache numbers require complete unsigned decimal rows") {
        ASSERT(cct_cache_numbers(&fx));
        PASS();
    }

    TEST("code.count: bad input and an unknown revision are refused") {
        struct cct_call c;
        cct_begin(&c, &fx);
        cct_arg(&c, "path", "../outside");
        ASSERT(!cct_run(&c));
        ASSERT_STR_EQ(c.reply.error.code, "BAD_CODE_COUNT_PATH");
        cct_end(&c);
        cct_begin(&c, &fx);
        cct_arg(&c, "at", "--output=x");
        ASSERT(!cct_run(&c));
        ASSERT_STR_EQ(c.reply.error.code, "BAD_CODE_COUNT_AT");
        cct_end(&c);
        cct_begin(&c, &fx);
        cct_arg(&c, "lang", "rust");
        ASSERT(!cct_run(&c));
        ASSERT_STR_EQ(c.reply.error.code, "BAD_CODE_COUNT_LANG");
        cct_end(&c);
        cct_begin(&c, &fx);
        cct_arg(&c, "at", "no-such-revision");
        ASSERT(!cct_run(&c));
        ASSERT_STR_EQ(c.reply.error.code, "CODE_COUNT_REV");
        cct_end(&c);
        PASS();
    }

    TEST("code.count: the leaf is registered with its option keys") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), "code.count", NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->handler != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "exclude") != NULL);
        PASS();
    }

#if defined(ZCL_TESTING) && !defined(_WIN32)
    TEST("code.impact: standalone one-shot freshness is explicit") {
        ASSERT(cct_isolated_dispatch_policy());
        PASS();
    }
#endif

_test_next:;
    if (fx.dir[0])
        (void)test_rm_rf_recursive(fx.dir);
    if (failures == 0)
        printf("test_code_count: all passed\n");
    else
        printf("test_code_count: %d FAILED\n", failures);
    return failures;
}

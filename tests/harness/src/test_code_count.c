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

_test_next:;
    if (fx.dir[0])
        (void)test_rm_rf_recursive(fx.dir);
    if (failures == 0)
        printf("test_code_count: all passed\n");
    else
        printf("test_code_count: %d FAILED\n", failures);
    return failures;
}

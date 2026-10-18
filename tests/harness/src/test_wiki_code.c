/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * discover.wiki and discover.read under the code/ prefix over a repository
 * tree built per run: directory and file listings, summaries from AGENTS.md
 * and file purposes, paging, the refusals (traversal, excluded directories,
 * vendor depth, escaping symlinks), file reads and worst-case reply size. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct wc_tree {
    char base[PATH_MAX], repo[PATH_MAX + 8], solo[PATH_MAX + 16];
};

struct wc_file {
    const char *rel, *text;
};

#define WC_LIC "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"

static const struct wc_file wc_files[] = {
    { "repo/AGENTS.md", "# Fixture repo\n\nRoot agents.\n" },
    { "repo/notes_top.md", "# Top\n\nTop-level file.\n" },
    { "repo/docs/README.md", "# Docs\n\nDocs root.\n" },
    { "repo/tools/AGENTS.md", "# tools/\n\nNative handlers and gates.\n" },
    { "repo/tools/alpha.c", WC_LIC " * purpose: alpha - the first fixture file. */\n\nint alpha(void);\n" },
    { "repo/tools/plain.c", WC_LIC " *\n * plain - derives the summary from the first comment line.\n */\n\nint plain(void);\n" },
    { "repo/tools/bare.c", "int bare(void);\n/* a late comment */\n" },
    { "repo/tools/run.sh", "#!/bin/sh\n# Copyright 2026 Rhett Creighton\n# Runs the fixture.\nexit 0\n" },
    { "repo/tools/defs.def", "/* purpose: fixture table of entries. */\nX(1)\n" },
    { "repo/tools/notes.md", "# Notes\n\nNotes page summary.\n" },
    { "repo/tools/skip.txt", "not a source file\n" },
    { "repo/tools/sub/x.c", "/* purpose: x. */\n" },
    { "repo/tools/sub/y.h", "/* purpose: y. */\n" },
    { "repo/apps/README.md", "# Apps\n\nApplication fixtures.\n" },
    { "repo/apps/a.c", "/* purpose: app a. */\n" },
    { "repo/lib/z.c", "/* purpose: z. */\n" },
    { "repo/build/x.c", "/* purpose: build output. */\n" },
    { "repo/test-tmp/x.c", "/* purpose: scratch. */\n" },
    { "repo/dist/x.c", "/* purpose: dist. */\n" },
    { "repo/.git/x.c", "/* purpose: git. */\n" },
    { "repo/vendor/AGENTS.md", "# vendor/\n\nPinned third-party code.\n" },
    { "repo/vendor/lib1/README.md", "# Lib one\n\nVendored library.\n" },
    { "repo/vendor/lib1/f.c", "/* purpose: vendored file. */\n" },
    { "repo/vendor/lib1/inner/g.c", "/* purpose: vendored inner. */\n" },
    { "outside/secret.c", "/* purpose: outside the repository. */\n" },
    { "solo/docs/README.md", "# Solo\n\nDocs without a repository.\n" },
};

/* Creates every directory of `path` below the first `skip` bytes. */
static bool wc_mkdirs(const char *path, size_t skip)
{
    char tmp[PATH_MAX + 256];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + skip; ; p++) {
        char c = *p;
        if (c != '/' && c != '\0')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
            return false;
        if (c == '\0')
            return true;
        *p = '/';
    }
}

static bool wc_put(const char *base, const char *rel, const char *text)
{
    char path[PATH_MAX + 256], dir[PATH_MAX + 256], *slash;
    snprintf(path, sizeof(path), "%s/%s", base, rel);
    snprintf(dir, sizeof(dir), "%s", path);
    slash = strrchr(dir, '/');
    *slash = '\0';
    if (!wc_mkdirs(dir, strlen(base) + 1))
        return false;
    FILE *fp = fopen(path, "wb");
    bool ok = fp && fputs(text, fp) >= 0;
    return (fp ? fclose(fp) == 0 : false) && ok;
}

static bool wc_link(const struct wc_tree *t, const char *target,
                    const char *rel)
{
    char path[PATH_MAX + 256];
    snprintf(path, sizeof(path), "%s/%s", t->base, rel);
    return symlink(target, path) == 0;
}

static bool wc_make_many(const struct wc_tree *t)
{
    for (int i = 0; i < 66; i++) {
        char rel[64];
        snprintf(rel, sizeof(rel), "repo/many/p%02d.c", i);
        if (!wc_put(t->base, rel, "/* purpose: one of many. */\n"))
            return false;
    }
    return true;
}

static bool wc_make(struct wc_tree *t)
{
    char out[PATH_MAX + 64], a[PATH_MAX + 64];
    if (!test_mkdtemp(t->base, sizeof(t->base), "wiki_code"))
        return false;
    snprintf(t->repo, sizeof(t->repo), "%s/repo", t->base);
    snprintf(t->solo, sizeof(t->solo), "%s/solo", t->base);
    for (size_t i = 0; i < sizeof(wc_files) / sizeof(wc_files[0]); i++)
        if (!wc_put(t->base, wc_files[i].rel, wc_files[i].text))
            return false;
    snprintf(out, sizeof(out), "%s/outside", t->base);
    snprintf(a, sizeof(a), "%s/outside/secret.c", t->base);
    return wc_make_many(t) && wc_link(t, a, "repo/tools/esc.c") &&
           wc_link(t, out, "repo/tools/escdir") &&
           wc_link(t, out, "repo/ext") &&
           wc_link(t, "alpha.c", "repo/tools/in.c");
}

typedef void (*wc_handler)(const struct zcl_command_request *,
                           struct zcl_command_reply *);

static bool wc_run(wc_handler handler, const char *input_json,
                   const char *schema, struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    bool ok = json_read(&input, input_json, strlen(input_json));
    struct zcl_command_request request = { .input = &input };
    zcl_command_reply_init(reply, schema);
    if (ok)
        handler(&request, reply);
    json_free(&input);
    return ok;
}

/* `dirs` selects the inputs: "codedir" names the repository, "docsdir" only
 * the docs directory beside it, "solo" a docs directory with no repository. */
static bool wc_wiki(const struct wc_tree *t, const char *dirs,
                    const char *topic, int64_t after,
                    struct zcl_command_reply *reply)
{
    char in[PATH_MAX * 2 + 256];
    if (!strcmp(dirs, "codedir"))
        snprintf(in, sizeof(in), "{\"codedir\":\"%s\",\"topic\":\"%s\","
                 "\"after\":%lld}", t->repo, topic, (long long)after);
    else
        snprintf(in, sizeof(in), "{\"docsdir\":\"%s/docs\",\"topic\":\"%s\","
                 "\"after\":%lld}", !strcmp(dirs, "solo") ? t->solo : t->repo,
                 topic, (long long)after);
    return wc_run(zcl_native_handle_discover_wiki, in, "zcl.wiki_node.v1",
                  reply);
}

static bool wc_read(const struct wc_tree *t, const char *page, int64_t offset,
                    int64_t bytes, struct zcl_command_reply *reply)
{
    char in[PATH_MAX * 2 + 256];
    snprintf(in, sizeof(in), "{\"codedir\":\"%s\",\"docsdir\":\"%s/docs\","
             "\"page\":\"%s\",\"offset\":%lld,\"bytes\":%lld}", t->repo,
             t->repo, page, (long long)offset, (long long)bytes);
    return wc_run(zcl_native_handle_discover_read, in, "zcl.wiki_page.v1",
                  reply);
}

static const struct json_value *wc_child(const struct json_value *data,
                                         const char *path)
{
    const struct json_value *kids = json_get(data, "children");
    for (size_t i = 0; i < json_size(kids); i++)
        if (!strcmp(json_get_str(json_get(json_at(kids, i), "path")), path))
            return json_at(kids, i);
    return NULL;
}

static bool wc_has(const struct json_value *arr, const char *s)
{
    for (size_t i = 0; i < json_size(arr); i++)
        if (!strcmp(json_get_str(json_at(arr, i)), s))
            return true;
    return false;
}

static const char *wc_summary(const struct json_value *data, const char *path)
{
    const struct json_value *c = wc_child(data, path);
    return c ? json_get_str(json_get(c, "summary")) : "(missing)";
}

static int wc_root(const struct wc_tree *t)
{
    int failures = 0;
    TEST("wiki code: the root lists top-level source directories only") {
        struct zcl_command_reply r;
        ASSERT(wc_wiki(t, "codedir", "code", 0, &r));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "title")), "Source code");
        ASSERT_STR_EQ(wc_summary(&r.data, "code/apps"),
                      "Application fixtures.");
        ASSERT_STR_EQ(wc_summary(&r.data, "code/lib"), "1 file");
        ASSERT_STR_EQ(wc_summary(&r.data, "code/tools"),
                      "Native handlers and gates.");
        ASSERT(wc_child(&r.data, "code/vendor") != NULL);
        static const char *const hidden[] = {
            "code/build", "code/test-tmp", "code/dist", "code/docs",
            "code/.git", "code/ext", "code/notes_top.md", "code/AGENTS.md",
        };
        for (size_t i = 0; i < sizeof(hidden) / sizeof(hidden[0]); i++)
            ASSERT(wc_child(&r.data, hidden[i]) == NULL);
        ASSERT(wc_has(json_get(&r.data, "next"), "z23 wiki code/apps"));
        ASSERT_EQ(json_size(json_get(&r.data, "commands")), 0);
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int wc_dir(const struct wc_tree *t)
{
    int failures = 0;
    TEST("wiki code: a directory lists files with purpose summaries") {
        struct zcl_command_reply r;
        ASSERT(wc_wiki(t, "codedir", "code/tools/", 0, &r));
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "path")), "code/tools");
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "title")), "tools/");
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "summary")),
                      "Native handlers and gates.");
        ASSERT_STR_EQ(wc_summary(&r.data, "code/tools/alpha.c"),
                      "alpha - the first fixture file.");
        ASSERT_STR_EQ(wc_summary(&r.data, "code/tools/plain.c"),
                      "derives the summary from the first comment line.");
        ASSERT_STR_EQ(wc_summary(&r.data, "code/tools/bare.c"), "");
        ASSERT_STR_EQ(wc_summary(&r.data, "code/tools/run.sh"), "Runs the fixture.");
        ASSERT_STR_EQ(wc_summary(&r.data, "code/tools/defs.def"),
                      "fixture table of entries.");
        ASSERT_STR_EQ(wc_summary(&r.data, "code/tools/notes.md"),
                      "Notes page summary.");
        ASSERT_STR_EQ(wc_summary(&r.data, "code/tools/sub"), "2 files");
        ASSERT_STR_EQ(json_get_str(json_get(wc_child(&r.data, "code/tools/sub"),
                                            "kind")), "topic");
        ASSERT(wc_child(&r.data, "code/tools/in.c") != NULL);
        ASSERT(wc_child(&r.data, "code/tools/esc.c") == NULL);
        ASSERT(wc_child(&r.data, "code/tools/escdir") == NULL);
        ASSERT(wc_child(&r.data, "code/tools/skip.txt") == NULL);
        ASSERT(wc_has(json_get(&r.data, "next"), "z23 wiki code/tools/sub"));
        ASSERT(wc_has(json_get(&r.data, "next"),
                      "z23 discover read code/tools/AGENTS.md"));
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int wc_entry(const struct wc_tree *t)
{
    int failures = 0;
    TEST("wiki code: the docs root points at code; no repository means CODE_UNAVAILABLE") {
        struct zcl_command_reply r;
        ASSERT(wc_wiki(t, "docsdir", "", 0, &r));
        ASSERT(wc_has(json_get(&r.data, "next"), "z23 wiki code"));
        zcl_command_reply_free(&r);
        ASSERT(wc_wiki(t, "docsdir", "code/apps", 0, &r));
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "title")), "Apps");
        zcl_command_reply_free(&r);
        ASSERT(wc_wiki(t, "solo", "", 0, &r));
        ASSERT(!wc_has(json_get(&r.data, "next"), "z23 wiki code"));
        zcl_command_reply_free(&r);
        ASSERT(wc_wiki(t, "solo", "code", 0, &r));
        ASSERT_STR_EQ(r.error.code, "CODE_UNAVAILABLE");
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int wc_refusals(const struct wc_tree *t)
{
    int failures = 0;
    TEST("wiki code: traversal, excluded directories, vendor depth and escapes refuse") {
        static const struct { const char *topic, *code; } cases[] = {
            { "code/../x", "BAD_TOPIC" },
            { "code/tools/..", "BAD_TOPIC" },
            { "code/build", "EXCLUDED_PATH" },
            { "code/test-tmp", "EXCLUDED_PATH" },
            { "code/dist", "EXCLUDED_PATH" },
            { "code/docs", "EXCLUDED_PATH" },
            { "code/.git", "EXCLUDED_PATH" },
            { "code/vendor/lib1/inner", "EXCLUDED_PATH" },
            { "code/tools/escdir", "OUTSIDE_CODE" },
            { "code/ext", "OUTSIDE_CODE" },
            { "code/nope/deeper", "UNKNOWN_TOPIC" },
        };
        struct zcl_command_reply r;
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            ASSERT(wc_wiki(t, "codedir", cases[i].topic, 0, &r));
            ASSERT_STR_EQ(r.error.code, cases[i].code);
            zcl_command_reply_free(&r);
        }
        ASSERT(wc_wiki(t, "codedir", "code/tools/nope", 0, &r));
        ASSERT_STR_EQ(r.error.evidence, "code/tools");
        zcl_command_reply_free(&r);
        ASSERT(wc_wiki(t, "codedir", "code/vendor", 0, &r));
        ASSERT_STR_EQ(wc_summary(&r.data, "code/vendor/lib1"), "Vendored library.");
        zcl_command_reply_free(&r);
        ASSERT(wc_wiki(t, "codedir", "code/vendor/lib1", 0, &r));
        ASSERT_EQ(json_get_int(json_get(&r.data, "children_total")), 0);
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int wc_paging(const struct wc_tree *t)
{
    int failures = 0;
    TEST("wiki code: at most 64 children per reply, resume with after") {
        struct zcl_command_reply r;
        ASSERT(wc_wiki(t, "codedir", "code/many", 0, &r));
        ASSERT_EQ(json_size(json_get(&r.data, "children")), 64);
        ASSERT_EQ(json_get_int(json_get(&r.data, "children_total")), 66);
        ASSERT_EQ(json_get_int(json_get(&r.data, "next_after")), 64);
        ASSERT(wc_has(json_get(&r.data, "next"),
                      "z23 wiki code/many --after=64"));
        ASSERT(wc_child(&r.data, "code/many/p63.c") != NULL);
        ASSERT(wc_child(&r.data, "code/many/p64.c") == NULL);
        zcl_command_reply_free(&r);
        ASSERT(wc_wiki(t, "codedir", "code/many", 64, &r));
        ASSERT_EQ(json_size(json_get(&r.data, "children")), 2);
        ASSERT(json_get(&r.data, "next_after") == NULL);
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int wc_reads(const struct wc_tree *t)
{
    int failures = 0;
    TEST("wiki code: source files read in chunks; excluded and escaping files refuse") {
        struct zcl_command_reply r;
        ASSERT(wc_read(t, "code/tools/alpha.c", 0, 16, &r));
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "title")), "alpha.c");
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "text")),
                      "/* Copyright 202");
        ASSERT_EQ(json_get_int(json_get(&r.data, "next_offset")), 16);
        zcl_command_reply_free(&r);
        ASSERT(wc_read(t, "code/tools/AGENTS.md", 0, 64, &r));
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "title")), "tools/");
        zcl_command_reply_free(&r);
        static const struct { const char *page, *code; } cases[] = {
            { "code/tools/esc.c", "OUTSIDE_CODE" },
            { "code/build/x.c", "EXCLUDED_PATH" },
            { "code/vendor/lib1/f.c", "EXCLUDED_PATH" },
            { "code/tools/skip.txt", "BAD_PAGE" },
            { "code/tools", "BAD_PAGE" },
            { "code/../x.c", "BAD_PAGE" },
            { "code/tools/none.c", "UNKNOWN_PAGE" },
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            ASSERT(wc_read(t, cases[i].page, 0, 16, &r));
            ASSERT_STR_EQ(r.error.code, cases[i].code);
            zcl_command_reply_free(&r);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* Worst case: a three-level path of long names holding WC_PAGES files with
 * maximal names and purpose lines made of characters that JSON escapes. */
enum { WC_PAGES = 28, WC_NAME = 127, WC_LEVEL = 100, WC_OUT = 65536 };

static void wc_name(char *out, size_t len, const char *prefix, const char *tail)
{
    size_t o = (size_t)snprintf(out, len + 1, "%s", prefix);
    size_t room = len - strlen(tail);
    for (; o + 1 < room; o += 2)
        memcpy(out + o, "\"x", 2);
    for (; o < room; o++)
        out[o] = 'x';
    snprintf(out + o, strlen(tail) + 1, "%s", tail);
}

static bool wc_worst_make(const struct wc_tree *t, char *topic, size_t cap)
{
    char dir[PATH_MAX + 512], rel[PATH_MAX + 1024], name[WC_NAME + 1];
    char text[1200];
    size_t o = (size_t)snprintf(topic, cap, "code");
    snprintf(dir, sizeof(dir), "%s/repo", t->base);
    for (int l = 0; l < 3; l++) {
        char level[WC_LEVEL + 1], tag[4];
        snprintf(tag, sizeof(tag), "L%d", l);
        wc_name(level, WC_LEVEL, tag, "");
        o += (size_t)snprintf(topic + o, cap - o, "/%s", level);
        snprintf(dir + strlen(dir), sizeof(dir) - strlen(dir), "/%s", level);
    }
    snprintf(text, sizeof(text), "/* purpose: ");
    while (strlen(text) < 300)
        snprintf(text + strlen(text), sizeof(text) - strlen(text),
                 "a\"b\\c \xc3\xa9 ");
    snprintf(text + strlen(text), sizeof(text) - strlen(text), " */\n");
    for (int i = 0; i < WC_PAGES; i++) {
        char prefix[8];
        snprintf(prefix, sizeof(prefix), "%02d", i);
        wc_name(name, WC_NAME, prefix, ".c");
        snprintf(rel, sizeof(rel), "%s/%s", dir + strlen(t->base) + 1, name);
        if (!wc_put(t->base, rel, text))
            return false;
    }
    return true;
}

static bool wc_worst_page(const struct json_value *root, int *seen, bool *more,
                          int64_t *next_after)
{
    const struct json_value *data = json_get(root, "data");
    const struct json_value *kids = json_get(data, "children");
    for (size_t i = 0; i < json_size(kids); i++) {
        const char *p = strrchr(json_get_str(json_get(json_at(kids, i),
                                                      "path")), '/');
        int idx = p ? atoi(p + 1) : -1;
        if (idx < 0 || idx >= WC_PAGES || seen[idx]++)
            return false;
    }
    *more = json_get(data, "next_after") != NULL;
    *next_after = json_get_int(json_get(data, "next_after"));
    return json_get_bool(json_get(root, "ok")) && json_size(kids) > 0;
}

static bool wc_worst_call(const struct wc_tree *t, const char *topic,
                          int64_t after, const struct zcl_command_spec *spec,
                          char *out, struct json_value *root)
{
    char in[PATH_MAX + 2048];
    struct json_value input;
    enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t o = (size_t)snprintf(in, sizeof(in), "{\"codedir\":\"%s/repo\","
                                "\"topic\":\"", t->base);
    for (const char *p = topic; *p && o + 8 < sizeof(in); p++) {
        if (*p == '"')
            in[o++] = '\\';
        in[o++] = *p;
    }
    snprintf(in + o, sizeof(in) - o, "\",\"after\":%lld}", (long long)after);
    json_init(&input);
    bool ok = json_read(&input, in, strlen(in));
    size_t len = ok ? zcl_command_registry_execute_json(
        zcl_command_catalog(), spec, NULL, &input, false, NULL, NULL, 0, 0,
        NULL, out, WC_OUT, &code) : 0;
    json_free(&input);
    json_init(root);
    return len > 0 && len <= (size_t)spec->budget_bytes &&
           code == ZCL_COMMAND_EXIT_OK && json_read(root, out, len);
}

static int wc_worst(const struct wc_tree *t)
{
    int failures = 0;
    TEST("wiki code: worst-case pages fit the leaf budget and a walk lists each file once") {
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            zcl_command_catalog(), "discover.wiki", NULL);
        char topic[3 * (WC_LEVEL + 1) + 8], *out = malloc(WC_OUT);
        int seen[WC_PAGES] = { 0 };
        int64_t after = 0, next_after = 0;
        size_t pages = 0;
        bool more = true;
        ASSERT(out != NULL && spec != NULL);
        ASSERT(wc_worst_make(t, topic, sizeof(topic)));
        while (more && pages < 16) {
            struct json_value root;
            ASSERT(wc_worst_call(t, topic, after, spec, out, &root));
            bool ok = wc_worst_page(&root, seen, &more, &next_after);
            json_free(&root);
            ASSERT(ok);
            after = next_after;
            pages++;
        }
        ASSERT(!more && pages >= 3);
        for (size_t i = 0; i < WC_PAGES; i++)
            ASSERT_EQ(seen[i], 1);
        free(out);
        PASS();
    } _test_next:;
    return failures;
}

int test_wiki_code(void)
{
    int failures = 0;
    struct wc_tree t;
    TEST("wiki code: the repository tree is built") {
        ASSERT(wc_make(&t));
        PASS();
    } _test_next:;
    if (failures)
        return failures;
    failures += wc_root(&t);
    failures += wc_dir(&t);
    failures += wc_entry(&t);
    failures += wc_refusals(&t);
    failures += wc_paging(&t);
    failures += wc_reads(&t);
    failures += wc_worst(&t);
    TEST_DISCARD(test_rm_rf_recursive(t.base));
    return failures;
}

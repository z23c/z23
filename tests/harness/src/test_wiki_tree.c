/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * discover.wiki and discover.read over the fixture tree in
 * tests/fixtures/wiki_docs: summary extraction, children and paging, the
 * Commands line, confinement refusals, UTF-8 cuts and the response budget. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define WT_DOCS "tests/fixtures/wiki_docs"

typedef void (*wt_handler)(const struct zcl_command_request *,
                           struct zcl_command_reply *);

static bool wt_run(wt_handler handler, const char *input_json,
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

static bool wt_wiki(const char *topic, int64_t after,
                    struct zcl_command_reply *reply)
{
    char in[256];
    snprintf(in, sizeof(in), "{\"docsdir\":\"" WT_DOCS "\",\"topic\":\"%s\","
             "\"after\":%lld}", topic, (long long)after);
    return wt_run(zcl_native_handle_discover_wiki, in, "zcl.wiki_node.v1",
                  reply);
}

static bool wt_read(const char *page, int64_t offset, int64_t bytes,
                    struct zcl_command_reply *reply)
{
    char in[256];
    snprintf(in, sizeof(in), "{\"docsdir\":\"" WT_DOCS "\",\"page\":\"%s\","
             "\"offset\":%lld,\"bytes\":%lld}", page, (long long)offset,
             (long long)bytes);
    return wt_run(zcl_native_handle_discover_read, in, "zcl.wiki_page.v1",
                  reply);
}

static const struct json_value *wt_child(const struct json_value *data,
                                         const char *path)
{
    const struct json_value *kids = json_get(data, "children");
    for (size_t i = 0; i < json_size(kids); i++)
        if (!strcmp(json_get_str(json_get(json_at(kids, i), "path")), path))
            return json_at(kids, i);
    return NULL;
}

static bool wt_has(const struct json_value *arr, const char *s)
{
    for (size_t i = 0; i < json_size(arr); i++)
        if (!strcmp(json_get_str(json_at(arr, i)), s))
            return true;
    return false;
}

static bool wt_utf8_ok(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        size_t k = *p < 0x80 ? 1 : (*p & 0xE0) == 0xC0 ? 2
                   : (*p & 0xF0) == 0xE0 ? 3 : (*p & 0xF8) == 0xF0 ? 4 : 0;
        if (k == 0)
            return false;
        for (size_t i = 1; i < k; i++)
            if ((p[i] & 0xC0) != 0x80)
                return false;
        p += k;
    }
    return true;
}

/* A docs tree whose symlinks leave the root cannot live in git (the build
 * refuses symlinks under tests/), so it is made per run: docs/ holds one
 * file symlink and one directory symlink to a sibling directory, plus a
 * symlink that stays inside docs/. */
struct wt_escape {
    char base[PATH_MAX], docs[PATH_MAX + 8], outside[PATH_MAX + 16];
};

static bool wt_write(const char *dir, const char *name, const char *text)
{
    char path[PATH_MAX + 64];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *fp = fopen(path, "wb");
    bool ok = fp && fputs(text, fp) >= 0;
    return (fp ? fclose(fp) == 0 : false) && ok;
}

static bool wt_escape_make(struct wt_escape *e)
{
    char link[PATH_MAX + 64], target[PATH_MAX + 64];
    if (!test_mkdtemp(e->base, sizeof(e->base), "wiki_tree"))
        return false;
    snprintf(e->docs, sizeof(e->docs), "%s/docs", e->base);
    snprintf(e->outside, sizeof(e->outside), "%s/outside", e->base);
    snprintf(link, sizeof(link), "%s/escape.md", e->docs);
    snprintf(target, sizeof(target), "%s/secret.md", e->outside);
    bool ok = mkdir(e->docs, 0700) == 0 && mkdir(e->outside, 0700) == 0 &&
              wt_write(e->docs, "README.md", "# Tmp\n\nTmp docs.\n") &&
              wt_write(e->outside, "secret.md", "# Secret\n\nOutside.\n") &&
              symlink(target, link) == 0;
    snprintf(link, sizeof(link), "%s/escape_dir", e->docs);
    ok = ok && symlink(e->outside, link) == 0;
    snprintf(link, sizeof(link), "%s/inside.md", e->docs);
    return ok && symlink("README.md", link) == 0;
}

static void wt_escape_drop(const struct wt_escape *e)
{
    static const char *const docs[] = { "escape.md", "escape_dir", "inside.md",
                                        "README.md" };
    char path[PATH_MAX + 64];
    for (size_t i = 0; i < sizeof(docs) / sizeof(docs[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", e->docs, docs[i]);
        TEST_DISCARD(unlink(path));
    }
    snprintf(path, sizeof(path), "%s/secret.md", e->outside);
    TEST_DISCARD(unlink(path));
    TEST_DISCARD(rmdir(e->docs));
    TEST_DISCARD(rmdir(e->outside));
    TEST_DISCARD(rmdir(e->base));
}

static bool wt_run_in(wt_handler handler, const struct wt_escape *e,
                      const char *key, const char *value,
                      struct zcl_command_reply *reply)
{
    char in[PATH_MAX + 128];
    snprintf(in, sizeof(in), "{\"docsdir\":\"%s\",\"%s\":\"%s\"}", e->docs,
             key, value);
    return wt_run(handler, in, "zcl.wiki_node.v1", reply);
}

static int wt_escapes(void)
{
    int failures = 0;
    struct wt_escape e;
    bool made = false;
    TEST("wiki tree: symlinks leaving docs/ are refused and unlisted; inside links resolve") {
        struct zcl_command_reply r;
        made = true;
        ASSERT(wt_escape_make(&e));
        ASSERT(wt_run_in(zcl_native_handle_discover_wiki, &e, "topic", "", &r));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(json_size(json_get(&r.data, "children")), 1);
        ASSERT(wt_child(&r.data, "inside.md") != NULL);
        zcl_command_reply_free(&r);
        ASSERT(wt_run_in(zcl_native_handle_discover_wiki, &e, "topic",
                         "escape_dir", &r));
        ASSERT_STR_EQ(r.error.code, "OUTSIDE_DOCS");
        zcl_command_reply_free(&r);
        ASSERT(wt_run_in(zcl_native_handle_discover_read, &e, "page",
                         "escape.md", &r));
        ASSERT_STR_EQ(r.error.code, "OUTSIDE_DOCS");
        zcl_command_reply_free(&r);
        ASSERT(wt_run_in(zcl_native_handle_discover_read, &e, "page",
                         "escape_dir/secret.md", &r));
        ASSERT_STR_EQ(r.error.code, "OUTSIDE_DOCS");
        zcl_command_reply_free(&r);
        ASSERT(wt_run_in(zcl_native_handle_discover_read, &e, "page",
                         "inside.md", &r));
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "title")), "Tmp");
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    if (made)
        wt_escape_drop(&e);
    return failures;
}

static int wt_root_node(void)
{
    int failures = 0;
    TEST("wiki tree: root title, summary, children and commands") {
        struct zcl_command_reply r;
        ASSERT(wt_wiki("", 0, &r));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "path")), "");
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "title")), "Fixture root");
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "summary")),
                      "The fixture root holds \"quoted\" text and continues "
                      "on a second line.");
        const struct json_value *cmds = json_get(&r.data, "commands");
        ASSERT_EQ(json_size(cmds), 2);
        ASSERT(wt_has(cmds, "discover.read") && wt_has(cmds, "discover.help"));
        ASSERT_EQ(json_get_int(json_get(&r.data, "commands_unresolved")), 1);
        const struct json_value *alpha = wt_child(&r.data, "alpha");
        ASSERT(alpha != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(alpha, "kind")), "topic");
        ASSERT_STR_EQ(json_get_str(json_get(alpha, "title")), "Alpha topic");
        ASSERT_STR_EQ(json_get_str(json_get(alpha, "summary")),
                      "Alpha explains the first nested topic.");
        const struct json_value *acc = wt_child(&r.data, "accents.md");
        ASSERT(acc != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(acc, "kind")), "page");
        ASSERT(wt_child(&r.data, "README.md") == NULL);
        ASSERT(wt_child(&r.data, "gamma") == NULL);
        const struct json_value *kids = json_get(&r.data, "children");
        for (size_t i = 1; i < json_size(kids); i++)
            ASSERT(strcmp(json_get_str(json_get(json_at(kids, i - 1), "path")),
                          json_get_str(json_get(json_at(kids, i), "path"))) < 0);
        const struct json_value *next = json_get(&r.data, "next");
        ASSERT(wt_has(next, "z23 wiki alpha"));
        ASSERT(wt_has(next, "z23 discover read accents.md"));
        ASSERT(wt_has(next, "z23 discover read README.md"));
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int wt_nested(void)
{
    int failures = 0;
    TEST("wiki tree: nested topics join paths and drop unresolved commands") {
        struct zcl_command_reply r;
        ASSERT(wt_wiki("alpha/", 0, &r));
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "path")), "alpha");
        ASSERT(wt_child(&r.data, "alpha/page.md") != NULL);
        ASSERT(wt_child(&r.data, "alpha/beta") != NULL);
        const struct json_value *cmds = json_get(&r.data, "commands");
        ASSERT_EQ(json_size(cmds), 1);
        ASSERT(wt_has(cmds, "discover.wiki"));
        ASSERT_EQ(json_get_int(json_get(&r.data, "commands_unresolved")), 2);
        zcl_command_reply_free(&r);
        ASSERT(wt_wiki("alpha/beta", 0, &r));
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "title")), "Beta topic");
        ASSERT(wt_child(&r.data, "alpha/beta/deep.md") != NULL);
        ASSERT_EQ(json_size(json_get(&r.data, "commands")), 0);
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int wt_paging(void)
{
    int failures = 0;
    TEST("wiki tree: at most 64 children per reply, resume with after") {
        struct zcl_command_reply r;
        ASSERT(wt_wiki("many", 0, &r));
        ASSERT_EQ(json_size(json_get(&r.data, "children")), 64);
        ASSERT_EQ(json_get_int(json_get(&r.data, "children_total")), 66);
        ASSERT_EQ(json_get_int(json_get(&r.data, "next_after")), 64);
        ASSERT(wt_has(json_get(&r.data, "next"), "z23 wiki many --after=64"));
        ASSERT(wt_child(&r.data, "many/p63.md") != NULL);
        ASSERT(wt_child(&r.data, "many/p64.md") == NULL);
        zcl_command_reply_free(&r);
        ASSERT(wt_wiki("many", 64, &r));
        ASSERT_EQ(json_size(json_get(&r.data, "children")), 2);
        ASSERT(json_get(&r.data, "next_after") == NULL);
        ASSERT(wt_child(&r.data, "many/p65.md") != NULL);
        zcl_command_reply_free(&r);
        ASSERT(wt_wiki("many", 500, &r));
        ASSERT_EQ(json_size(json_get(&r.data, "children")), 0);
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int wt_summary_cut(void)
{
    int failures = 0;
    TEST("wiki tree: summaries are cut on a UTF-8 boundary at 200 bytes") {
        struct zcl_command_reply r;
        ASSERT(wt_wiki("", 0, &r));
        const struct json_value *c2 = wt_child(&r.data, "cut2.md");
        const struct json_value *c3 = wt_child(&r.data, "cut3.md");
        ASSERT(c2 != NULL && c3 != NULL);
        const char *s2 = json_get_str(json_get(c2, "summary"));
        const char *s3 = json_get_str(json_get(c3, "summary"));
        ASSERT_EQ(strlen(s2), 199);
        ASSERT_EQ(strlen(s3), 198);
        ASSERT(wt_utf8_ok(s2) && wt_utf8_ok(s3));
        const char *bs = json_get_str(json_get(wt_child(&r.data, "broken.md"),
                                               "summary"));
        ASSERT_STR_EQ(bs, "bad ? byte and ? lone lead.");
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int wt_tree_refusals(void)
{
    int failures = 0;
    TEST("wiki tree: traversal, escapes, unknown topics and missing docs refuse") {
        static const char *const bad[] = {
            "../x", "/etc", "alpha/../..", "a//b", "alpha\\\\x", "./alpha",
        };
        struct zcl_command_reply r;
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            ASSERT(wt_wiki(bad[i], 0, &r));
            ASSERT_STR_EQ(r.error.code, "BAD_TOPIC");
            zcl_command_reply_free(&r);
        }
        ASSERT(wt_wiki("alpha/nope/deeper", 0, &r));
        ASSERT_STR_EQ(r.error.code, "UNKNOWN_TOPIC");
        ASSERT_STR_EQ(r.error.evidence, "alpha");
        zcl_command_reply_free(&r);
        ASSERT(wt_wiki("gamma", 0, &r));
        ASSERT_STR_EQ(r.error.code, "UNKNOWN_TOPIC");
        ASSERT_STR_EQ(r.error.evidence, "(root)");
        zcl_command_reply_free(&r);
        ASSERT(wt_run(zcl_native_handle_discover_wiki,
                      "{\"docsdir\":\"tests/fixtures/absent\"}",
                      "zcl.wiki_node.v1", &r));
        ASSERT_STR_EQ(r.error.code, "DOCS_UNAVAILABLE");
        ASSERT_STR_EQ(r.error.evidence, "docsdir");
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int wt_read_pages(void)
{
    int failures = 0;
    TEST("wiki read: chunks reassemble the page and never split a character") {
        struct zcl_command_reply r;
        char whole[256] = "";
        int64_t off = 0;
        int guard = 0;
        while (off >= 0 && guard++ < 64) {
            ASSERT(wt_read("accents.md", off, 5, &r));
            ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
            const char *t = json_get_str(json_get(&r.data, "text"));
            ASSERT(wt_utf8_ok(t));
            ASSERT(strlen(t) <= 5);
            ASSERT_EQ(json_get_int(json_get(&r.data, "offset")), off);
            ASSERT_STR_EQ(json_get_str(json_get(&r.data, "title")), "Accents");
            strncat(whole, t, sizeof(whole) - strlen(whole) - 1);
            const struct json_value *n = json_get(&r.data, "next_offset");
            off = n && !json_is_null(n) ? json_get_int(n) : -1;
            zcl_command_reply_free(&r);
        }
        ASSERT(off == -1);
        ASSERT_STR_EQ(whole, "# Accents\n\n\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9"
                      "\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\n");
        PASS();
    } _test_next:;
    return failures;
}

static int wt_read_offsets(void)
{
    int failures = 0;
    TEST("wiki read: offsets inside a character, past the end, and invalid bytes") {
        struct zcl_command_reply r;
        ASSERT(wt_read("accents.md", 11, 4, &r));
        ASSERT_EQ(json_get_int(json_get(&r.data, "offset")), 11);
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "text")), "\xc3\xa9\xc3\xa9");
        zcl_command_reply_free(&r);
        ASSERT(wt_read("accents.md", 12, 4, &r));
        ASSERT_EQ(json_get_int(json_get(&r.data, "offset")), 13);
        zcl_command_reply_free(&r);
        ASSERT(wt_read("accents.md", 1000, 4, &r));
        ASSERT_STR_EQ(r.error.code, "BAD_RANGE");
        zcl_command_reply_free(&r);
        ASSERT(wt_read("accents.md", 32, 4, &r));
        ASSERT_EQ(json_get_int(json_get(&r.data, "size")), 32);
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "text")), "");
        ASSERT(json_is_null(json_get(&r.data, "next_offset")));
        zcl_command_reply_free(&r);
        ASSERT(wt_read("broken.md", 0, 4096, &r));
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "text")),
                      "# Broken\n\nbad ? byte and ? lone lead.\n");
        zcl_command_reply_free(&r);
        ASSERT(wt_read("accents.md", 0, 1, &r));
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "text")), "#");
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int wt_read_refusals(void)
{
    int failures = 0;
    TEST("wiki read: traversal, escapes, non-Markdown, missing pages and ranges refuse") {
        static const struct { const char *page; const char *code; } cases[] = {
            { "../README.md", "BAD_PAGE" }, { "/etc/passwd.md", "BAD_PAGE" },
            { "alpha", "BAD_PAGE" }, { "", "BAD_PAGE" },
            { "nope.md", "UNKNOWN_PAGE" }, { "alpha/beta.md", "UNKNOWN_PAGE" },
        };
        struct zcl_command_reply r;
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            ASSERT(wt_read(cases[i].page, 0, 16, &r));
            ASSERT_STR_EQ(r.error.code, cases[i].code);
            zcl_command_reply_free(&r);
        }
        ASSERT(wt_read("accents.md", 0, 0, &r));
        ASSERT_STR_EQ(r.error.code, "BAD_RANGE");
        zcl_command_reply_free(&r);
        ASSERT(wt_read("accents.md", -1, 4, &r));
        ASSERT_STR_EQ(r.error.code, "BAD_RANGE");
        zcl_command_reply_free(&r);
        ASSERT(wt_run(zcl_native_handle_discover_read,
                      "{\"page\":\"README.md\",\"docsdir\":\"tests/fixtures/absent\"}",
                      "zcl.wiki_page.v1", &r));
        ASSERT_STR_EQ(r.error.code, "DOCS_UNAVAILABLE");
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static bool wt_execute(const char *path, const char *input_json, char *out,
                       size_t cap)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, path, NULL);
    struct json_value input;
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    json_init(&input);
    bool ok = spec && json_read(&input, input_json, strlen(input_json));
    if (ok)
        ok = zcl_command_registry_execute_json(reg, spec, NULL, &input, false,
                                               NULL, NULL, 0, 0, NULL, out, cap,
                                               &exit_code) > 0 &&
             exit_code == ZCL_COMMAND_EXIT_OK;
    json_free(&input);
    return ok;
}

static int wt_registry(void)
{
    int failures = 0;
    TEST("wiki registry: bare alias, input typing and the maximum-chunk response budget") {
        const struct zcl_command_registry *reg = zcl_command_catalog();
        bool alias = false;
        const struct zcl_command_spec *w = zcl_command_registry_find(reg, "wiki", &alias);
        ASSERT(w != NULL && alias);
        ASSERT_STR_EQ(w->path, "discover.wiki");
        ASSERT_STR_EQ(zcl_command_registry_find(reg, "fleet.wiki.find", NULL)->path,
                      "fleet.wiki.find");
        char *out = malloc(ZCL_COMMAND_EXTENDED_LIST_BUDGET * 4);
        ASSERT(out != NULL);
        size_t cap = ZCL_COMMAND_EXTENDED_LIST_BUDGET * 4;
        ASSERT(wt_execute("discover.wiki",
                          "{\"docsdir\":\"" WT_DOCS "\",\"topic\":\"many\"}", out, cap));
        ASSERT(strstr(out, "\"next_after\":64") != NULL);
        ASSERT(wt_execute("discover.read",
                          "{\"docsdir\":\"" WT_DOCS "\",\"page\":\"quotes.md\","
                          "\"offset\":10,\"bytes\":16384}", out, cap));
        ASSERT(strstr(out, "\"next_offset\":16394") != NULL);
        ASSERT(!wt_execute("discover.read",
                           "{\"docsdir\":\"" WT_DOCS "\",\"page\":\"quotes.md\","
                           "\"bytes\":16385}", out, cap));
        ASSERT(!wt_execute("discover.read",
                           "{\"docsdir\":\"" WT_DOCS "\",\"page\":\"quotes.md\","
                           "\"offset\":\"1\"}", out, cap));
        free(out);
        PASS();
    } _test_next:;
    return failures;
}

int test_wiki_tree(void)
{
    int failures = 0;
    failures += wt_escapes();
    failures += wt_root_node();
    failures += wt_nested();
    failures += wt_paging();
    failures += wt_summary_cut();
    failures += wt_tree_refusals();
    failures += wt_read_pages();
    failures += wt_read_offsets();
    failures += wt_read_refusals();
    failures += wt_registry();
    return failures;
}

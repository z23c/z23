/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_cli_render_wiki - human rendering of `z23 wiki` / `discover read`
 * (tools/command/cli_render_wiki.c) and the byte-identity of the piped JSON.
 *
 *   1. Unit: fixed canonical documents through zcl_cli_render_wiki (parsed
 *      value in, no TTY needed) and through zcl_cli_render_doc.
 *   2. Contract: with stdout a pipe the built binary prints the canonical
 *      JSON for `wiki`, `wiki adr` and `discover help`, with or without
 *      ZCL_HUMAN=0 or --json; ZCL_HUMAN=1 forces the human text. Skips (does
 *      not fail) when build/bin/z23-dev is missing.
 *
 * make t-fast ONLY=cli_render (runs from test_cli_render)
 */

#include "test/test_core.h"

#include "command/cli_render.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *const WIKI_NODE =
    "{\"schema\":\"zcl.result.v1\",\"command\":\"discover.wiki\",\"ok\":true,"
    "\"data_schema\":\"zcl.wiki_node.v1\",\"data\":{\"path\":\"\","
    "\"title\":\"Z23 documentation map\",\"children_total\":3,\"children\":["
    "{\"kind\":\"page\",\"path\":\"PARAMS.md\",\"title\":\"Proving parameters\"},"
    "{\"kind\":\"topic\",\"path\":\"adr\",\"title\":\"Architecture decisions\"},"
    "{\"kind\":\"topic\",\"path\":\"node\",\"title\":\"Node references\"}],"
    "\"next\":[\"z23 wiki adr\"]}}";

static const char *const WIKI_PAGE =
    "{\"schema\":\"zcl.result.v1\",\"command\":\"discover.read\",\"ok\":true,"
    "\"data_schema\":\"zcl.wiki_page.v1\",\"data\":{\"path\":\"PARAMS.md\","
    "\"title\":\"Proving parameters\",\"text\":\"# Heading\\n\\nBody text.\\n\","
    "\"next_offset\":4096}}";

static struct zcl_cli_render_env wk_env(bool human, int width)
{
    struct zcl_cli_render_env e = {
        .human = human, .ansi = false, .width = width, .max_rows = 24,
    };
    return e;
}

static int test_wiki_node_unit(void)
{
    int failures = 0;
    TEST("wiki node renders one slug+title line per child and a next hint") {
        struct json_value root;
        ASSERT(json_read(&root, WIKI_NODE, strlen(WIKI_NODE)));
        struct zcl_cli_render_env e = wk_env(true, 80);
        char out[4096];
        size_t n = zcl_cli_render_wiki(&root, &e, out, sizeof(out));
        json_free(&root);
        ASSERT(n > 0 && n == strlen(out));
        ASSERT(strstr(out, "Z23 documentation map\n") == out);
        ASSERT(strstr(out, "  PARAMS.md  Proving parameters\n") != NULL);
        ASSERT(strstr(out, "  adr        Architecture decisions\n") != NULL);
        ASSERT(strstr(out, "next: z23 wiki adr\n") != NULL);
        ASSERT(strchr(out, '{') == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_wiki_node_refusals(void)
{
    int failures = 0;
    TEST("wiki node is refused for machines and unknown shapes") {
        struct json_value root;
        ASSERT(json_read(&root, WIKI_NODE, strlen(WIKI_NODE)));
        struct zcl_cli_render_env off = wk_env(false, 80);
        char out[4096];
        ASSERT(zcl_cli_render_wiki(&root, &off, out, sizeof(out)) == 0);
        struct zcl_cli_render_env e = wk_env(true, 80);
        ASSERT(zcl_cli_render_wiki(&root, &e, out, 40) == 0); /* too small */
        json_free(&root);
        const char *other = "{\"schema\":\"zcl.result.v1\",\"ok\":true,"
                            "\"data_schema\":\"zcl.other.v1\",\"data\":{}}";
        ASSERT(json_read(&root, other, strlen(other)));
        ASSERT(zcl_cli_render_wiki(&root, &e, out, sizeof(out)) == 0);
        json_free(&root);
        PASS();
    } _test_next:;
    return failures;
}

static int test_wiki_page_and_doc_dispatch(void)
{
    int failures = 0;
    TEST("wiki page renders its text; render_doc routes both wiki leaves") {
        struct zcl_cli_render_env e = wk_env(true, 80);
        char out[4096];
        size_t n = zcl_cli_render_doc(WIKI_PAGE, strlen(WIKI_PAGE),
                                      "discover.read", &e, out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(strstr(out, "Body text.") != NULL);
        ASSERT(strstr(out, "more: z23 discover read PARAMS.md --offset=4096")
               != NULL);
        n = zcl_cli_render_doc(WIKI_NODE, strlen(WIKI_NODE), "discover.wiki",
                               &e, out, sizeof(out));
        ASSERT(n > 0 && strstr(out, "Node references") != NULL);
        struct zcl_cli_render_env off = wk_env(false, 80);
        ASSERT(zcl_cli_render_doc(WIKI_NODE, strlen(WIKI_NODE),
                                  "discover.wiki", &off, out,
                                  sizeof(out)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── contract against the built binary ─────────────────────────────── */

#define WK_BIN "build/bin/z23-dev"

static int wk_run(const char *cmd, char *out, size_t cap)
{
    FILE *f = popen(cmd, "r");
    if (!f)
        return -1;
    size_t n = fread(out, 1, cap - 1, f);
    out[n] = '\0';
    return pclose(f);
}

/* Drop the volatile timing fields (and the budget flag they drive) so two
 * runs compare equal. */
static void wk_strip_timing(char *s)
{
    static const char *const keys[] = { "\"elapsed_us\":", "\"elapsed_ms\":",
                                            "\"budget_exceeded\":" };
    for (size_t k = 0; k < 3; k++) {
        char *p;
        while ((p = strstr(s, keys[k])) != NULL) {
            char *v = p + strlen(keys[k]);
            while ((*v >= '0' && *v <= '9') || (k == 2 && *v >= 'a' && *v <= 'z'))
                v++;
            memmove(p, v, strlen(v) + 1);
        }
    }
}

static int wk_pipe_same(const char *cmd_a, const char *cmd_b, const char *prefix)
{
    static char a[262144], b[262144];
    if (wk_run(cmd_a, a, sizeof(a)) != 0 || wk_run(cmd_b, b, sizeof(b)) != 0)
        return 0;
    wk_strip_timing(a);
    wk_strip_timing(b);
    return strcmp(a, b) == 0 && strncmp(a, prefix, strlen(prefix)) == 0;
}

static int test_pipe_contract(void)
{
    int failures = 0;
    TEST("piped wiki / discover help stay canonical JSON (human opt-out, --json)") {
        ASSERT(wk_pipe_same(
            WK_BIN " wiki 2>&1 | cat",
            "ZCL_HUMAN=0 " WK_BIN " wiki --json 2>&1 | cat",
            "{\"schema\":\"zcl.result.v1\",\"command\":\"discover.wiki\""));
        ASSERT(wk_pipe_same(
            WK_BIN " wiki adr 2>&1 | cat",
            "ZCL_HUMAN=0 " WK_BIN " wiki adr 2>&1 | cat",
            "{\"schema\":\"zcl.result.v1\""));
        ASSERT(wk_pipe_same(
            WK_BIN " discover help 2>&1 | cat",
            "ZCL_HUMAN=0 " WK_BIN " discover help --json 2>&1 | cat",
            "{\"schema\":\"zcl.command_menu.v1\""));
        PASS();
    } _test_next:;
    return failures;
}

static int test_forced_human(void)
{
    int failures = 0;
    TEST("ZCL_HUMAN=1 wiki prints readable text, not JSON") {
        static char out[262144];
        ASSERT(wk_run("ZCL_HUMAN=1 " WK_BIN " wiki 2>&1", out,
                      sizeof(out)) == 0);
        ASSERT(out[0] != '{' && strchr(out, '\n') != NULL);
        ASSERT(strstr(out, "Z23 documentation map") != NULL);
        ASSERT(strstr(out, "\"schema\"") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

int cli_render_wiki_cases(void)
{
    int failures = 0;
    failures += test_wiki_node_unit();
    failures += test_wiki_node_refusals();
    failures += test_wiki_page_and_doc_dispatch();
    if (access(WK_BIN, X_OK) == 0)
        failures += test_pipe_contract() + test_forced_human();
    else
        printf("cli_render_wiki: %s missing - SKIP contract half\n", WK_BIN);
    printf("=== cli_render_wiki: %d failures ===\n", failures);
    return failures;
}

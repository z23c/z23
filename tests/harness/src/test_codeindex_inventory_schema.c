/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Prove the codeindex inventory schema: symbols.end_line spans,
 * files.line_count, the sealed docs table, and the two readers over them. */

#include "test/test_core.h"

#include "codeindex/codeindex.h"
#include "codeindex/codeindex_build.h"
#include "codeindex/codeindex_docs.h"
#include "codeindex/codeindex_pages.h"
#include "platform/directory_compat.h"
#include "platform/temp_directory.h"
#include "command/native_code_pages.h"
#include "util/spawn.h"
#include "base/hex.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "json/json.h"

#include <sqlite3.h>

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define CIS_CHECK(name, expression)                                    \
    do {                                                               \
        bool cis_ok_ = (expression);                                   \
        printf("codeindex_inventory_schema: %s %s\n",                  \
               cis_ok_ ? "OK  " : "FAIL", (name));                     \
        if (!cis_ok_) failures++;                                      \
    } while (0)

static const char cis_spans[] =
    "/* Purpose: span fixture. */\n"          /* 1 */
    "#define SPAN_MACRO(x) \\\n"              /* 2 */
    "    ((x) + 1)\n"                          /* 3 */
    "\n"                                       /* 4 */
    "static int one(int x)\n"                  /* 5 */
    "{\n"                                      /* 6 */
    "    return x;\n"                          /* 7 */
    "}\n"                                      /* 8 */
    "\n"                                       /* 9 */
    "int two(int x)\n"                         /* 10 */
    "{\n"                                      /* 11 */
    "    if (x) {\n"                           /* 12 */
    "        return one(x);\n"                 /* 13 */
    "    }\n"                                  /* 14 */
    "    return 0;\n"                          /* 15 */
    "}\n"                                      /* 16 */
    "\n"                                       /* 17 */
    "int proto(int x);\n";                     /* 18 */

static const char cis_guide[] =
    "# Gossip Guide\n"
    "Intro text about peers\n"
    "and relay.\n"
    "\n"
    "## Peer Setup\n"
    "\n"
    "```c\n"
    "# not a heading\n"
    "```\n"
    "Second paragraph.\n";

static bool cis_put(const char *root, const char *rel, const char *text)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", root, rel);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    for (char *at = path + strlen(root) + 1; *at; at++) {
        if (*at != '/') continue;
        *at = '\0';
        bool made = platform_directory_ensure(path, 0700);
        *at = '/';
        if (!made) return false;
    }
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    size_t length = strlen(text);
    bool ok = fwrite(text, 1, length, file) == length;
    return fclose(file) == 0 && ok;
}

static bool cis_fixture(const char *root)
{
    return cis_put(root, "lib/net/src/spans.c", cis_spans) &&
           cis_put(root, "docs/guide.md", cis_guide) &&
           cis_put(root, "AGENTS.md", "# Root Rules\n\nAlways run the gate.\n") &&
           cis_put(root, "lib/net/README.md", "# Net Lib\n\nPeer sockets.\n") &&
           cis_put(root, "docs/notes.txt", "# Not Markdown\n") &&
           cis_put(root, "scratch/README.md", "# Outside The Roots\n");
}

static bool cis_exec(const char *root, const char *sql)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/.codeindex/index.kv", root);
    sqlite3 *db = NULL;
    if (n <= 0 || (size_t)n >= sizeof(path) ||
        sqlite3_open(path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    bool ok = sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(db);
    return ok;
}

static bool cis_span(struct codeindex *ix, const char *name, int def, int end)
{
    struct ci_symbol s = {0};
    bool found = false;
    return codeindex_symbol(ix, name, &s, &found) && found &&
           s.def_line == def && s.end_line == end;
}

static bool cis_enclosing(struct codeindex *ix, int line, const char *want)
{
    struct ci_symbol s = {0};
    bool found = true;
    bool ok = codeindex_symbol_at(ix, "lib/net/src/spans.c", line, &s, &found);
    return want ? ok && found && strcmp(s.name, want) == 0 : ok && !found;
}

static bool cis_spans_ok(struct codeindex *ix)
{
    return cis_span(ix, "one", 5, 8) && cis_span(ix, "two", 10, 16) &&
           cis_span(ix, "SPAN_MACRO", 2, 3) && cis_span(ix, "proto", 0, 18);
}

static bool cis_symbol_at_ok(struct codeindex *ix)
{
    return cis_enclosing(ix, 5, "one") && cis_enclosing(ix, 7, "one") &&
           cis_enclosing(ix, 8, "one") && cis_enclosing(ix, 10, "two") &&
           cis_enclosing(ix, 13, "two") && cis_enclosing(ix, 16, "two") &&
           cis_enclosing(ix, 4, NULL) && cis_enclosing(ix, 9, NULL) &&
           cis_enclosing(ix, 18, NULL) && cis_enclosing(ix, 99, NULL);
}

static bool cis_file_lines(struct codeindex *ix)
{
    struct ci_file f = {0};
    bool found = false;
    return codeindex_file(ix, "lib/net/src/spans.c", &f, &found) && found &&
           f.line_count == 18;
}

static bool cis_docs_rows(struct codeindex *ix)
{
    struct ci_doc d[8];
    int n = codeindex_docs_match(ix, "gossip relay", d, 8);
    return n == 1 && strcmp(d[0].path, "docs/guide.md") == 0 &&
           strcmp(d[0].title, "Gossip Guide") == 0 &&
           strcmp(d[0].summary, "Intro text about peers and relay.") == 0 &&
           strcmp(d[0].headings, "Gossip Guide | Peer Setup") == 0 &&
           d[0].line_count == 10 && d[0].score == 7 && !d[0].stale;
}

static bool cis_docs_scope(struct codeindex *ix)
{
    struct ci_doc d[8];
    int rules = codeindex_docs_match(ix, "rules", d, 8);
    bool agents = rules == 1 && strcmp(d[0].path, "AGENTS.md") == 0 &&
                  d[0].score == 6; /* title 4 + headings 2 */
    int peer = codeindex_docs_match(ix, "Peer, peers!", d, 8);
    bool ranked = peer == 2 && strcmp(d[0].path, "docs/guide.md") == 0 &&
                  strcmp(d[1].path, "lib/net/README.md") == 0;
    return agents && ranked &&
           codeindex_docs_match(ix, "outside markdown", d, 8) == 0 &&
           codeindex_docs_match(ix, "peer", d, 1) == 1 &&
           codeindex_docs_match(ix, "  ", d, 8) == 0;
}

static bool cis_stale_flag(struct codeindex *ix, const char *root)
{
    struct ci_doc d[2];
    bool edited = cis_put(root, "docs/guide.md", "# Gossip Guide\nchanged\n");
    int n = codeindex_docs_match(ix, "gossip", d, 2);
    return edited && n == 1 && d[0].stale;
}

/* A tampered docs row and an old schema tag must both rebuild. */
static int cis_rebuild_checks(bool ready, const char *root)
{
    int failures = 0;
    struct ci_doc d[2];
    bool poisoned = ready &&
        cis_exec(root, "UPDATE docs SET title='poison' WHERE path='AGENTS.md'");
    struct codeindex *healed = poisoned ? codeindex_open_retrieval_view(root)
                                        : NULL;
    CIS_CHECK("a poisoned docs row is rejected and rebuilt",
              healed && codeindex_docs_match(healed, "rules", d, 2) == 1 &&
              strcmp(d[0].title, "Root Rules") == 0);
    codeindex_close(healed);

    bool aged = ready && cis_exec(root,
        "UPDATE meta SET v=CAST('ret6' AS BLOB) WHERE k='ci_schema_version';"
        "DELETE FROM docs");
    struct codeindex *rebuilt = aged ? codeindex_open(root) : NULL;
    CIS_CHECK("a ret6 generation rebuilds with end_line and docs",
              rebuilt && cis_spans_ok(rebuilt) &&
              codeindex_docs_match(rebuilt, "rules", d, 2) == 1);
    codeindex_close(rebuilt);
    bool page_poisoned = ready && cis_exec(root,
        "INSERT INTO pages(directory,tree_oid,source_commit,body,artifact_root) "
        "VALUES('lib/net','0000000000000000000000000000000000000000',"
        "'0000000000000000000000000000000000000000','poison',zeroblob(32))");
    struct codeindex *page_healed = page_poisoned ? codeindex_open_retrieval_view(root) : NULL;
    struct ci_page page;
    bool prior_untrusted = false;
    CIS_CHECK("unsealed page insertion is rejected and its availability is unknown",
              page_healed && codeindex_pages_list(page_healed, "lib/net", &page, 1, &prior_untrusted) == 0 &&
              prior_untrusted);
    codeindex_close(page_healed);
    return failures;
}

/* The span, line-count, docs and staleness checks over one open index. */
static int cis_index_checks(struct codeindex *ix, const char *root)
{
    int failures = 0;
    CIS_CHECK("end_line covers each definition and declaration",
              cis_spans_ok(ix));
    CIS_CHECK("codeindex_symbol_at maps lines to the enclosing function",
              cis_symbol_at_ok(ix));
    CIS_CHECK("files.line_count counts the fixture lines",
              cis_file_lines(ix));
    CIS_CHECK("docs row carries title, paragraph, headings, line count",
              cis_docs_rows(ix));
    CIS_CHECK("docs scope and ranking follow the brief",
              cis_docs_scope(ix));
    CIS_CHECK("an edited doc is flagged stale, not misread",
              cis_stale_flag(ix, root));
    struct ci_page page;
    bool prior_untrusted = true;
    CIS_CHECK("fresh index reports no imported page instead of a store error",
              codeindex_pages_list(ix, "lib/net", &page, 1, &prior_untrusted) == 0 && !prior_untrusted);
    return failures;
}

/* A prose walk must refuse an oversized tree instead of sealing a prefix. */
static bool cis_doc_limit(void)
{
    char root[PLATFORM_TEMP_PATH_MAX] = {0};
    if (!platform_temp_directory_create("z23-doc-limit-", root, sizeof(root)))
        return false;
    bool ready = true;
    int made = 0;
    for (; ready && made <= 16384; made++) {
        char rel[64];
        snprintf(rel, sizeof(rel), "docs/cap-%d.md", made);
        ready = cis_put(root, rel, "# Bounded prose\n");
    }
    struct codeindex *ix = ready ? codeindex_open_retrieval_view(root) : NULL;
    bool refused = ready && !ix;
    codeindex_close(ix);
    for (int i = 0; i < made; i++) {
        char path[PLATFORM_TEMP_PATH_MAX + 64];
        snprintf(path, sizeof(path), "%s/docs/cap-%d.md", root, i);
        if (remove(path) != 0) refused = false;
    }
    return refused;
}

static bool cis_page_replacement(const char *root, const char *commit, const char *expected)
{
    char output[256], replacement[65], actual[65];
    const char *add[] = {"git", "-C", root, "add", "--", "module/file.c", NULL};
    const char *save[] = {"git", "-C", root, "-c", "user.name=Fixture", "-c",
                          "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                          "-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture", NULL};
    const char *head[] = {"git", "-C", root, "rev-parse", "HEAD", NULL};
    if (!cis_put(root, "module/file.c", "int other_value;\n") ||
        zcl_spawn_capture(add, output, sizeof(output), 10000) != 0 ||
        zcl_spawn_capture(save, output, sizeof(output), 10000) != 0 ||
        zcl_spawn_capture(head, output, sizeof(output), 10000) != 0) return false;
    output[strcspn(output, "\r\n")] = '\0';
    if (strlen(output) != 40) return false;
    memcpy(replacement, output, 41);
    const char *replace[] = {"git", "-C", root, "replace", commit, replacement, NULL};
    return zcl_spawn_capture(replace, output, sizeof(output), 10000) == 0 &&
           zcl_code_pages_subject(root, commit, "module", actual) &&
           strcmp(actual, expected) == 0;
}

static bool cis_page_subject(void)
{
    char root[PLATFORM_TEMP_PATH_MAX] = {0}, output[256], commit[65], expected[65], actual[65];
    if (!platform_temp_directory_create("z23-page-subject-", root, sizeof(root)) ||
        !cis_put(root, "module/file.c", "int test_value;\n")) return false;
    const char *init[] = {"git", "-C", root, "init", "-q", NULL};
    const char *add[] = {"git", "-C", root, "add", "--", "module/file.c", NULL};
    const char *save[] = {"git", "-C", root, "-c", "user.name=Fixture", "-c",
                          "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                          "-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture", NULL};
    const char *head[] = {"git", "-C", root, "rev-parse", "HEAD", NULL};
    const char *tree[] = {"git", "-C", root, "rev-parse", "HEAD:module", NULL};
    if (zcl_spawn_capture(init, output, sizeof(output), 10000) != 0 ||
        zcl_spawn_capture(add, output, sizeof(output), 10000) != 0 ||
        zcl_spawn_capture(save, output, sizeof(output), 10000) != 0 ||
        zcl_spawn_capture(head, output, sizeof(output), 10000) != 0) return false;
    output[strcspn(output, "\r\n")] = '\0';
    if (strlen(output) != 40) return false;
    memcpy(commit, output, 41);
    if (zcl_spawn_capture(tree, output, sizeof(output), 10000) != 0) return false;
    output[strcspn(output, "\r\n")] = '\0';
    if (strlen(output) != 40) return false;
    memcpy(expected, output, 41);
    bool valid = zcl_code_pages_subject(root, commit, "module", actual) &&
           strcmp(actual, expected) == 0 &&
           !zcl_code_pages_subject(root, commit, "../module", actual) &&
           !zcl_code_pages_subject(root, "HEAD", "module", actual) &&
           !zcl_code_pages_subject(root, commit, "missing", actual);
    return valid && cis_page_replacement(root, commit, expected);
}

static bool cis_bad_page_import(struct codeindex *ci, const struct ci_page *good)
{
    struct ci_page bad = *good;
    static const char duplicate[] = "{\"dir\":\"lib/net\",\"dir\":\"lib/net\","
        "\"tree\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"topic\":\"net\","
        "\"summary\":\"bad\",\"lessons\":[],\"applies_to\":[],\"updated\":\"2026-11-04T00:00:00Z\"}";
    static const char nul[] = "{\"dir\":\"lib/net\",\"tree\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
        "\"topic\":\"net\",\"summary\":\"bad\\u0000hidden\",\"lessons\":[],\"applies_to\":[],"
        "\"updated\":\"2026-11-04T00:00:00Z\"}";
    uint8_t root[32];
    snprintf(bad.body, sizeof(bad.body), "%s", duplicate);
    if (codeindex_pages_import_hints(ci, duplicate, strlen(duplicate), &bad, 1, root)) return false;
    snprintf(bad.body, sizeof(bad.body), "%s", nul);
    return !codeindex_pages_import_hints(ci, nul, strlen(nul), &bad, 1, root);
}

static bool cis_corrupt_page_artifact(const char *root, const uint8_t artifact[32],
                                      struct codeindex *ci)
{
    char hex[65], path[PLATFORM_TEMP_PATH_MAX + 96];
    zcl_hex_encode(artifact, 32, hex);
    int n = snprintf(path, sizeof(path), "%s/.zvcs/objects/%.2s/%s", root, hex, hex + 2);
    if (n <= 0 || (size_t)n >= sizeof(path) || chmod(path, 0600) != 0) return false;
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    bool written = fwrite("corrupt", 1, 7, file) == 7;
    if (fclose(file) != 0 || !written) return false;
    struct ci_page out;
    bool prior_untrusted = false;
    return codeindex_pages_list(ci, "lib/net", &out, 1, &prior_untrusted) == -2;
}

static bool cis_native_output(const struct zcl_command_reply *reply, const char *commit,
                              const char *state, int64_t accepted, int64_t stale)
{
    if (!state)
        return json_get_int(json_get(&reply->data, "accepted")) == accepted &&
               json_get_int(json_get(&reply->data, "stale")) == stale;
    const char *actual = json_get_str(json_get(&reply->data, "state"));
    const char *overlay = json_get_str(json_get(&reply->data, "live_overlay"));
    bool ok = actual && !strcmp(actual, state) && overlay && !strcmp(overlay, "unknown") &&
              json_get_int(json_get(&reply->data, "matches")) == accepted;
    if (ok && !strcmp(state, "committed_match")) {
        const char *source = json_get_str(json_get(&reply->data, "source_commit"));
        const char *artifact = json_get_str(json_get(&reply->data, "artifact_root"));
        ok = source && !strcmp(source, commit) && artifact && strlen(artifact) == 64;
    }
    if (ok && !strcmp(state, "ambiguous")) ok = json_get(&reply->data, "body") == NULL;
    return ok;
}

static bool cis_native_call(const char *root, const char *command, const char *commit,
                            const char *key, const char *value, const char *state,
                            int64_t accepted, int64_t stale)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    bool ok = json_push_kv_str(&input, "commit", commit) && json_push_kv_str(&input, key, value);
    struct zcl_command_context context = {.source_root = root};
    struct zcl_command_request request = {.input = &input, .context = &context};
    request.spec = zcl_command_registry_find(zcl_command_catalog(), command, NULL);
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.pages.v1");
    char why[192];
    ok = ok && request.spec && zcl_command_registry_input_validate(request.spec, &input, why, sizeof(why));
    if (ok && !strcmp(command, "code.pages.import")) zcl_native_handle_code_pages_import(&request, &reply);
    else if (ok) zcl_native_handle_code_pages_get(&request, &reply);
    ok = ok && reply.status == ZCL_COMMAND_STATUS_PASSED;
    if (ok) ok = cis_native_output(&reply, commit, state, accepted, stale);
    zcl_command_reply_free(&reply);
    json_free(&input);
    return ok;
}

static bool cis_native_git_setup(const char *root, char commit[65], char tree[65])
{
    char output[256];
    if (!cis_put(root, "module/file.c", "int one;\n") || !cis_put(root, "module2/file.c", "int two;\n")) return false;
    const char *init[] = {"git", "-C", root, "init", "-q", NULL};
    const char *add[] = {"git", "-C", root, "add", "--", "module", "module2", NULL};
    const char *save[] = {"git", "-C", root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                          "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture", NULL};
    const char *head[] = {"git", "-C", root, "rev-parse", "HEAD", NULL};
    if (zcl_spawn_capture(init, output, sizeof(output), 10000) != 0 ||
        zcl_spawn_capture(add, output, sizeof(output), 10000) != 0 ||
        zcl_spawn_capture(save, output, sizeof(output), 10000) != 0 ||
        zcl_spawn_capture(head, output, sizeof(output), 10000) != 0) return false;
    output[strcspn(output, "\r\n")] = '\0';
    if (strlen(output) != 40) return false;
    memcpy(commit, output, 41);
    return zcl_code_pages_subject(root, commit, "module", tree);
}

static bool cis_native_artifact(const char *root, const char *tree, char *artifact, size_t cap)
{
    char lines[2048];
    int n = snprintf(lines, sizeof(lines),
        "{\"dir\":\"module\",\"tree\":\"%s\",\"topic\":\"module\",\"summary\":\"first\",\"lessons\":[],\"applies_to\":[],\"updated\":\"2026-11-04T00:00:00Z\"}\n"
        "{\"dir\":\"module2\",\"tree\":\"0000000000000000000000000000000000000000\",\"topic\":\"module2\",\"summary\":\"stale\",\"lessons\":[],\"applies_to\":[],\"updated\":\"2026-11-04T00:00:00Z\"}\n", tree);
    if (n <= 0 || (size_t)n >= sizeof(lines) || !cis_put(root, "cards.jsonl", lines)) return false;
    n = snprintf(artifact, cap, "%s/cards.jsonl", root);
    return n > 0 && (size_t)n < cap && chmod(artifact, 0644) == 0;
}

static bool cis_native_second(const char *root, const char *commit, const char *tree,
                              const char *artifact, const char *summary,
                              const char *state, int matches)
{
    char line[1024];
    int n = snprintf(line, sizeof(line),
        "{\"dir\":\"module\",\"tree\":\"%s\",\"topic\":\"module\",\"summary\":\"%s\",\"lessons\":[],\"applies_to\":[],\"updated\":\"2026-11-04T00:00:00Z\"}\n", tree, summary);
    return n > 0 && (size_t)n < sizeof(line) && cis_put(root, "cards.jsonl", line) &&
           chmod(artifact, 0644) == 0 &&
           cis_native_call(root, "code.pages.import", commit, "artifact", artifact, NULL, 1, 0) &&
           cis_native_call(root, "code.pages.get", commit, "path", "module", state, matches, 0);
}

static bool cis_native_pages(void)
{
    char root[PLATFORM_TEMP_PATH_MAX] = {0}, commit[65], tree[65], artifact[PLATFORM_TEMP_PATH_MAX + 32];
    if (!platform_temp_directory_create("z23-native-pages-", root, sizeof(root)) ||
        !cis_native_git_setup(root, commit, tree) ||
        !cis_native_artifact(root, tree, artifact, sizeof(artifact))) return false;
    return cis_native_call(root, "code.pages.import", commit, "artifact", artifact, NULL, 1, 1) &&
           cis_native_call(root, "code.pages.get", commit, "path", "module", "committed_match", 1, 0) &&
           cis_native_call(root, "code.pages.get", commit, "path", "module2", "missing", 0, 0) &&
           cis_native_second(root, commit, tree, artifact, "first", "committed_match", 2) &&
           cis_put(root, "module/file.c", "int uncommitted;\n") &&
           cis_native_call(root, "code.pages.get", commit, "path", "module", "committed_match", 2, 0) &&
           cis_native_second(root, commit, tree, artifact, "conflict", "ambiguous", 3);
}

static bool cis_page_roundtrip(const char *root)
{
    static const char body[] = "{\"dir\":\"lib/net\",\"tree\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
        "\"topic\":\"net\",\"summary\":\"Network model hint\",\"lessons\":[],\"applies_to\":[],"
        "\"updated\":\"2026-11-04T00:00:00Z\"}";
    struct ci_page in = {0}, out = {0};
    snprintf(in.directory, sizeof(in.directory), "%s", "lib/net");
    snprintf(in.tree_oid, sizeof(in.tree_oid), "%s", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    snprintf(in.source_commit, sizeof(in.source_commit), "%s", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    snprintf(in.body, sizeof(in.body), "%s", body);
    struct codeindex *older = codeindex_open_retrieval_view(root);
    struct codeindex *ci = codeindex_open_retrieval_view(root);
    uint8_t artifact[32] = {0};
    bool prior_untrusted = false;
    bool ok = older && ci && cis_bad_page_import(ci, &in) &&
              codeindex_pages_import_hints(ci, body, strlen(body), &in, 1, artifact) &&
              codeindex_pages_list(ci, "lib/net", &out, 1, &prior_untrusted) == 1 &&
              strcmp(out.body, body) == 0 && memcmp(out.artifact_root, artifact, 32) == 0 &&
              codeindex_rebuild(older);
    struct codeindex *fresh = ok ? codeindex_open_retrieval_view(root) : NULL;
    ok = ok && fresh && codeindex_pages_list(fresh, "lib/net", &out, 1, &prior_untrusted) == 1 &&
              strcmp(out.body, body) == 0 && memcmp(out.artifact_root, artifact, 32) == 0 &&
              cis_corrupt_page_artifact(root, artifact, fresh);
    codeindex_close(fresh);
    codeindex_close(older);
    codeindex_close(ci);
    return ok;
}

int test_codeindex_inventory_schema(void)
{
    int failures = 0;
    char temporary[PLATFORM_TEMP_PATH_MAX] = {0}, root[PLATFORM_TEMP_PATH_MAX];
    bool ready = platform_temp_directory_create("z23-codeindex-schema-",
                                                temporary, sizeof(temporary)) &&
                 platform_directory_canonical_real(temporary, root,
                                                   sizeof(root)) &&
                 cis_fixture(root);
    CIS_CHECK("fixture tree is written", ready);
    CIS_CHECK("page subject resolves exact commit tree and refuses invalid input", cis_page_subject());
    CIS_CHECK("native import excludes stale cards and never claims live overlay freshness", cis_native_pages());

    struct codeindex *ix = ready ? codeindex_open_retrieval_view(root) : NULL;
    CIS_CHECK("fixture index opens", ix != NULL);
    if (ix) failures += cis_index_checks(ix, root);
    codeindex_close(ix);

    failures += cis_rebuild_checks(ready, root);
    CIS_CHECK("imported hint survives a sealed rebuild", ready && cis_page_roundtrip(root));
    CIS_CHECK("more than 16384 prose files refuses the generation",
              cis_doc_limit());
    return failures;
}

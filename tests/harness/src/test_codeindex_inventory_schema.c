/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Prove the codeindex inventory schema: symbols.end_line spans,
 * files.line_count, the sealed docs table, and the two readers over them. */

#include "test/test_core.h"

#include "codeindex/codeindex.h"
#include "codeindex/codeindex_build.h"
#include "codeindex/codeindex_docs.h"
#include "platform/directory_compat.h"
#include "platform/temp_directory.h"

#include <sqlite3.h>

#include <limits.h>
#include <stdio.h>
#include <string.h>

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
    return failures;
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

    struct codeindex *ix = ready ? codeindex_open_retrieval_view(root) : NULL;
    CIS_CHECK("fixture index opens", ix != NULL);
    if (ix) failures += cis_index_checks(ix, root);
    codeindex_close(ix);

    failures += cis_rebuild_checks(ready, root);
    return failures;
}

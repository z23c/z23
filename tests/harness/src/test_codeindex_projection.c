/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Prove retrieval never adopts a logically poisoned code index. */

#include "test/test_core.h"

#include "codeindex/codeindex.h"
#include "codeindex/codeindex_build.h"
#include "config/file_ops.h"
#include "platform/directory_compat.h"
#include "platform/temp_directory.h"

#include <sqlite3.h>

#include <limits.h>
#include <stdio.h>
#include <string.h>

#define CIP_CHECK(name, expression)                                    \
    do {                                                               \
        bool cip_ok_ = (expression);                                   \
        printf("codeindex_projection: %s %s\n",                      \
               cip_ok_ ? "OK  " : "FAIL", (name));                  \
        if (!cip_ok_) failures++;                                      \
    } while (0)

static const char cip_source[] =
    "/* Purpose: retrieval projection integrity fixture. */\n"
    "static int projection_leaf(int x)\n"
    "{\n"
    "    return x + 1;\n"
    "}\n"
    "static int projection_aux(int x)\n"
    "{\n"
    "    return projection_leaf(x);\n"
    "}\n"
    "int projection_main(int x)\n"
    "{\n"
    "    return projection_leaf(x) + projection_aux(x);\n"
    "}\n";

static bool cip_write(const char *root)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/lib/net/src/projection.c", root);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    for (char *at = path + 1; *at; at++) {
        if (*at != '/') continue;
        *at = '\0';
        if (!platform_directory_ensure(path, 0700)) {
            *at = '/';
            return false;
        }
        *at = '/';
    }
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    size_t length = strlen(cip_source);
    bool ok = fwrite(cip_source, 1, length, file) == length;
    if (fclose(file) != 0) ok = false;
    return ok;
}

static bool cip_index_path(const char *root, char out[PATH_MAX])
{
    int n = snprintf(out, PATH_MAX, "%s/.codeindex/index.kv", root);
    return n > 0 && n < PATH_MAX;
}

static bool cip_exec_one(const char *root, const char *sql)
{
    char path[PATH_MAX];
    if (!cip_index_path(root, path)) return false;
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    bool ok = sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK &&
              sqlite3_changes(db) == 1;
    sqlite3_close(db);
    return ok;
}

static bool cip_quick_check(const char *root)
{
    char path[PATH_MAX];
    if (!cip_index_path(root, path)) return false;
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    sqlite3_stmt *statement = NULL;
    bool ok = sqlite3_prepare_v2(db, "PRAGMA quick_check", -1, &statement,
                                 NULL) == SQLITE_OK &&
              sqlite3_step(statement) == SQLITE_ROW;
    if (ok) {
        const unsigned char *answer = sqlite3_column_text(statement, 0);
        ok = answer && strcmp((const char *)answer, "ok") == 0;
    }
    if (statement) sqlite3_finalize(statement);
    sqlite3_close(db);
    return ok;
}

static bool cip_generation_matches(struct codeindex *index,
                                   const uint8_t source_root[32],
                                   const uint8_t projection_root[32])
{
    uint8_t source[32], projection[32];
    return index && codeindex_source_root_sha3(index, source) &&
           codeindex_retrieval_projection_root_sha3(index, projection) &&
           memcmp(source, source_root, 32) == 0 &&
           memcmp(projection, projection_root, 32) == 0;
}

static bool cip_queries_intact(struct codeindex *index)
{
    struct ci_file file = {0};
    struct ci_symbol symbol = {0};
    struct ci_ref refs[8];
    bool file_found = false, symbol_found = false;
    int callees = index ? codeindex_callees(index, "projection_main", refs,
                                             8) : -1;
    return index &&
           codeindex_file(index, "lib/net/src/projection.c", &file,
                          &file_found) && file_found &&
           strcmp(file.group, "lib/net") == 0 &&
           codeindex_symbol(index, "projection_main", &symbol,
                            &symbol_found) && symbol_found &&
           strcmp(symbol.def_path, "lib/net/src/projection.c") == 0 &&
           callees == 2 &&
           strcmp(refs[0].callee, "projection_leaf") == 0 &&
           strcmp(refs[1].callee, "projection_aux") == 0;
}

/* Creates the temporary workspace and writes both fixture trees. */
static bool cip_fixture_pair_ready(char temporary[PLATFORM_TEMP_PATH_MAX],
                                   char workspace[PLATFORM_TEMP_PATH_MAX],
                                   char first[PATH_MAX], char second[PATH_MAX])
{
    bool ready = platform_temp_directory_create(
        "z23-codeindex-projection-", temporary, PLATFORM_TEMP_PATH_MAX);
    ready = ready && platform_directory_canonical_real(
        temporary, workspace, PLATFORM_TEMP_PATH_MAX);
    int first_n = ready ? snprintf(first, PATH_MAX, "%s/first", workspace)
                        : -1;
    int second_n = ready ? snprintf(second, PATH_MAX, "%s/second", workspace)
                         : -1;
    return ready && first_n > 0 && (size_t)first_n < PATH_MAX &&
           second_n > 0 && (size_t)second_n < PATH_MAX &&
           cip_write(first) && cip_write(second);
}

/* Opens both retrieval views and captures their four canonical roots. */
static bool cip_open_paired_views(bool ready, const char *first,
                                  const char *second,
                                  struct codeindex **one_view,
                                  struct codeindex **two_view,
                                  uint8_t source_root[32],
                                  uint8_t projection_root[32],
                                  uint8_t second_source[32],
                                  uint8_t second_projection[32])
{
    *one_view = ready ? codeindex_open_retrieval_view(first) : NULL;
    *two_view = ready ? codeindex_open_retrieval_view(second) : NULL;
    return *one_view && *two_view &&
        codeindex_source_root_sha3(*one_view, source_root) &&
        codeindex_retrieval_projection_root_sha3(*one_view, projection_root) &&
        codeindex_source_root_sha3(*two_view, second_source) &&
        codeindex_retrieval_projection_root_sha3(*two_view,
                                                 second_projection);
}

/* Applies one SQL statement when rooted, reopening the index if it took. */
static struct codeindex *cip_open_after_sql(bool rooted, const char *root,
                                            const char *sql)
{
    return rooted && cip_exec_one(root, sql)
        ? codeindex_open_existing(root) : NULL;
}

/* True when the reopened index stays current and generation-matched. */
static bool cip_logical_root_preserved(struct codeindex *existing,
                                       const uint8_t source_root[32],
                                       const uint8_t projection_root[32])
{
    bool current = false;
    return existing && codeindex_retrieval_projection_is_current(
                           existing, &current) && current &&
           cip_generation_matches(existing, source_root, projection_root);
}

/* Applies one poison statement and confirms SQLite still self-checks. */
static bool cip_poison_applied(const char *root, const char *sql)
{
    return cip_exec_one(root, sql) && cip_quick_check(root);
}

/* True when the reopened index reports its projection no longer current. */
static bool cip_projection_refused(struct codeindex *witness)
{
    bool projection_current = true;
    return witness && codeindex_retrieval_projection_is_current(
                          witness, &projection_current) &&
           !projection_current;
}

/* True when the witness view does not adopt the poisoned symbol row. */
static bool cip_symbol_not_adopted(struct codeindex *witness)
{
    struct ci_symbol symbol = {0};
    bool found = false;
    return witness && codeindex_symbol(witness, "projection_main", &symbol,
                                       &found) && !found;
}

/* Resets the exact-read counter, then reopens the view when poisoned. */
static struct codeindex *cip_open_healed_view(const char *root, bool poisoned)
{
    codeindex_test_reset_exact_bytes_read();
    return poisoned ? codeindex_open_retrieval_view(root) : NULL;
}

/* True when the healed view read exact bytes and stayed fully intact. */
static bool cip_healed_view_rebuilt(struct codeindex *healed,
                                    const uint8_t source_root[32],
                                    const uint8_t projection_root[32])
{
    return healed && codeindex_test_exact_bytes_read() > 0 &&
           cip_generation_matches(healed, source_root, projection_root) &&
           cip_queries_intact(healed);
}

struct cip_poison {
    const char *name;
    const char *sql;
};

int test_codeindex_projection_integrity(void)
{
    int failures = 0;
    char temporary[PLATFORM_TEMP_PATH_MAX] = {0};
    char workspace[PLATFORM_TEMP_PATH_MAX] = {0};
    char first[PATH_MAX], second[PATH_MAX];
    bool ready = cip_fixture_pair_ready(temporary, workspace, first, second);
    CIP_CHECK("two independent fixtures are ready", ready);

    struct codeindex *one = NULL, *two = NULL;
    uint8_t source_root[32], projection_root[32];
    uint8_t second_source[32], second_projection[32];
    bool rooted = cip_open_paired_views(ready, first, second, &one, &two,
                                        source_root, projection_root,
                                        second_source, second_projection);
    CIP_CHECK("equal source trees have equal source and projection roots",
              rooted && memcmp(source_root, second_source, 32) == 0 &&
              memcmp(projection_root, second_projection, 32) == 0);
    CIP_CHECK("baseline retrieval queries are intact",
              rooted && cip_queries_intact(one));
    codeindex_close(one);
    codeindex_close(two);

    struct codeindex *existing = cip_open_after_sql(
        rooted,
        first,
        "UPDATE files SET mtime=mtime+1 "
        "WHERE path='lib/net/src/projection.c'");
    CIP_CHECK("non-retrieval mtime change preserves the logical root",
              cip_logical_root_preserved(existing, source_root,
                                         projection_root));
    codeindex_close(existing);

    existing = cip_open_after_sql(
        rooted,
        first,
        "UPDATE refs SET rowid=rowid+1000000 "
        "WHERE rowid=(SELECT MIN(rowid) FROM refs "
        "WHERE enclosing='projection_main')");
    CIP_CHECK("physical row order does not change the canonical projection",
              cip_logical_root_preserved(existing, source_root,
                                         projection_root));
    codeindex_close(existing);

    static const struct cip_poison poisons[] = {
        {"group row change",
         "UPDATE groups SET purpose=purpose||' poison' WHERE path='lib/net'"},
        {"file row change",
         "UPDATE files SET purpose='poison' "
         "WHERE path='lib/net/src/projection.c'"},
        {"full-width symbol line change",
         "UPDATE symbols SET def_line=def_line+65536 "
         "WHERE name='projection_main' "
         "AND def_path='lib/net/src/projection.c'"},
        {"reference deletion",
         "DELETE FROM refs WHERE rowid=(SELECT MIN(rowid) FROM refs "
         "WHERE enclosing='projection_main')"},
        {"duplicate reference insertion",
         "INSERT INTO refs(callee_name,ref_file,ref_line,enclosing) "
         "SELECT callee_name,ref_file,ref_line,enclosing FROM refs "
         "WHERE enclosing='projection_main' ORDER BY rowid LIMIT 1"},
        {"out-of-range reference line",
         "UPDATE refs SET ref_line=ref_line+4294967296 "
         "WHERE rowid=(SELECT MIN(rowid) FROM refs "
         "WHERE enclosing='projection_main')"},
        {"wrong SQLite text storage class",
         "UPDATE refs SET enclosing=X'61' "
         "WHERE rowid=(SELECT MIN(rowid) FROM refs "
         "WHERE enclosing='projection_main')"},
    };
    for (size_t i = 0; rooted && i < sizeof(poisons) / sizeof(poisons[0]); i++) {
        bool poisoned = cip_poison_applied(first, poisons[i].sql);
        struct codeindex *witness = poisoned
            ? codeindex_open_existing(first) : NULL;
        bool refused = cip_projection_refused(witness);
        if (strcmp(poisons[i].name, "full-width symbol line change") == 0) {
            CIP_CHECK("full-width line poison also fails per-row adoption",
                      cip_symbol_not_adopted(witness));
        }
        codeindex_close(witness);

        struct codeindex *healed = cip_open_healed_view(first, poisoned);
        bool rebuilt = cip_healed_view_rebuilt(healed, source_root,
                                               projection_root);
        char detection_name[160], rebuild_name[160];
        (void)snprintf(detection_name, sizeof(detection_name),
                       "%s is detected while SQLite remains valid",
                       poisons[i].name);
        (void)snprintf(rebuild_name, sizeof(rebuild_name),
                       "%s triggers exact deterministic rebuild",
                       poisons[i].name);
        CIP_CHECK(detection_name, poisoned && refused);
        CIP_CHECK(rebuild_name, rebuilt);
        codeindex_close(healed);
    }

    if (workspace[0])
        dir_remove_tree(workspace);
    else if (temporary[0])
        dir_remove_tree(temporary);
    return failures;
}

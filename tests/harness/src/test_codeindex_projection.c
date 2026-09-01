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

struct cip_poison {
    const char *name;
    const char *sql;
};

int test_codeindex_projection_integrity(void)
{
    int failures = 0;
    char temporary[PLATFORM_TEMP_PATH_MAX] = {0};
    char first[PATH_MAX], second[PATH_MAX];
    bool ready = platform_temp_directory_create(
        "z23-codeindex-projection-", temporary, sizeof(temporary));
    int first_n = ready ? snprintf(first, sizeof(first), "%s/first", temporary)
                        : -1;
    int second_n = ready ? snprintf(second, sizeof(second), "%s/second", temporary)
                         : -1;
    ready = ready && first_n > 0 && (size_t)first_n < sizeof(first) &&
            second_n > 0 && (size_t)second_n < sizeof(second) &&
            cip_write(first) && cip_write(second);
    CIP_CHECK("two independent fixtures are ready", ready);

    struct codeindex *one = ready ? codeindex_open_retrieval_view(first) : NULL;
    struct codeindex *two = ready ? codeindex_open_retrieval_view(second) : NULL;
    uint8_t source_root[32], projection_root[32];
    uint8_t second_source[32], second_projection[32];
    bool rooted = one && two &&
        codeindex_source_root_sha3(one, source_root) &&
        codeindex_retrieval_projection_root_sha3(one, projection_root) &&
        codeindex_source_root_sha3(two, second_source) &&
        codeindex_retrieval_projection_root_sha3(two, second_projection);
    CIP_CHECK("equal source trees have equal source and projection roots",
              rooted && memcmp(source_root, second_source, 32) == 0 &&
              memcmp(projection_root, second_projection, 32) == 0);
    CIP_CHECK("baseline retrieval queries are intact",
              rooted && cip_queries_intact(one));
    codeindex_close(one);
    codeindex_close(two);

    bool physical_only = rooted && cip_exec_one(
        first,
        "UPDATE files SET mtime=mtime+1 "
        "WHERE path='lib/net/src/projection.c'");
    struct codeindex *existing = physical_only
        ? codeindex_open_existing(first) : NULL;
    bool physical_current = false;
    CIP_CHECK("non-retrieval mtime change preserves the logical root",
              existing && codeindex_retrieval_projection_is_current(
                  existing, &physical_current) && physical_current &&
              cip_generation_matches(existing, source_root, projection_root));
    codeindex_close(existing);

    bool reordered = rooted && cip_exec_one(
        first,
        "UPDATE refs SET rowid=rowid+1000000 "
        "WHERE rowid=(SELECT MIN(rowid) FROM refs "
        "WHERE enclosing='projection_main')");
    existing = reordered ? codeindex_open_existing(first) : NULL;
    bool reorder_current = false;
    CIP_CHECK("physical row order does not change the canonical projection",
              existing && codeindex_retrieval_projection_is_current(
                  existing, &reorder_current) && reorder_current &&
              cip_generation_matches(existing, source_root, projection_root));
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
        bool poisoned = cip_exec_one(first, poisons[i].sql) &&
                        cip_quick_check(first);
        struct codeindex *witness = poisoned
            ? codeindex_open_existing(first) : NULL;
        bool projection_current = true;
        bool refused = witness &&
            codeindex_retrieval_projection_is_current(
                witness, &projection_current) && !projection_current;
        if (strcmp(poisons[i].name, "full-width symbol line change") == 0) {
            struct ci_symbol symbol = {0};
            bool found = false;
            CIP_CHECK("full-width line poison also fails per-row adoption",
                      witness &&
                      codeindex_symbol(witness, "projection_main", &symbol,
                                       &found) && !found);
        }
        codeindex_close(witness);

        codeindex_test_reset_exact_bytes_read();
        struct codeindex *healed = poisoned
            ? codeindex_open_retrieval_view(first) : NULL;
        bool rebuilt = healed && codeindex_test_exact_bytes_read() > 0 &&
                       cip_generation_matches(healed, source_root,
                                              projection_root) &&
                       cip_queries_intact(healed);
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

    if (temporary[0]) dir_remove_tree(temporary);
    return failures;
}

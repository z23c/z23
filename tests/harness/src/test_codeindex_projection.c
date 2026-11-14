/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Prove retrieval never adopts a logically poisoned code index. */

#include "test/test_core.h"

#include "codeindex/codeindex.h"
#include "codeindex/codeindex_build.h"
#include "../../../cognition/modules/codeindex/src/codeindex_priv.h"
#include "config/file_ops.h"
#include "platform/directory_compat.h"
#include "platform/temp_directory.h"

#include <sqlite3.h>

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

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

/* Confirm SQLite retained a TEXT value with a byte suffix after its NUL. */
static bool cip_nul_shape(const char *root, const char *mutation)
{
    const char *sql = NULL;
    if (strstr(mutation, "SET callee_name="))
        sql = "SELECT count(*) FROM refs WHERE typeof(callee_name)='text' AND instr(callee_name,char(0))>0 AND length(CAST(callee_name AS BLOB))>length(callee_name)";
    else if (strstr(mutation, "SET enclosing="))
        sql = "SELECT count(*) FROM refs WHERE typeof(enclosing)='text' AND instr(enclosing,char(0))>0 AND length(CAST(enclosing AS BLOB))>length(enclosing)";
    else if (strstr(mutation, "SET purpose="))
        sql = "SELECT count(*) FROM files WHERE typeof(purpose)='text' AND instr(purpose,char(0))>0 AND length(CAST(purpose AS BLOB))>length(purpose)";
    else if (strstr(mutation, "SET \"group\"="))
        sql = "SELECT count(*) FROM files WHERE typeof(\"group\")='text' AND instr(\"group\",char(0))>0 AND length(CAST(\"group\" AS BLOB))>length(\"group\")";
    if (!sql) return false;
    char path[PATH_MAX]; sqlite3 *db = NULL; sqlite3_stmt *stmt = NULL;
    bool ok = cip_index_path(root, path) && sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 1;
    if (stmt) sqlite3_finalize(stmt);
    if (db) sqlite3_close(db);
    return ok;
}

/* Applies one poison statement and confirms SQLite still self-checks. */
static bool cip_poison_applied(const char *root, const char *sql)
{
    return cip_exec_one(root, sql) && cip_quick_check(root) &&
           (!strstr(sql, "char(0)") || cip_nul_shape(root, sql));
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

static bool cip_symbol_put(struct ci_store *s, const char *name, const char *def, const char *decl)
{
    struct ci_symbol sym = {0};
    snprintf(sym.name, sizeof sym.name, "%s", name);
    snprintf(sym.def_path, sizeof sym.def_path, "%s", def);
    snprintf(sym.decl_path, sizeof sym.decl_path, "%s", decl);
    sym.kind = 'T'; sym.def_line = *def ? 1 : 0; sym.decl_line = *decl ? 2 : 0;
    return ci_store_put_symbol(s, &sym);
}

static bool cip_symbol_seed(struct ci_store *s)
{
    struct ci_file file = {0}; uint8_t sha[32] = {0}; int64_t id;
    snprintf(file.path, sizeof file.path, "a.c");
    return ci_store_put_file(s, &file, sha, 0, &id) &&
        cip_symbol_put(s, "alpha", "a.c", "") &&
        cip_symbol_put(s, "beta", "", "a.c") &&
        cip_symbol_put(s, "both", "a.c", "a.c") &&
        cip_symbol_put(s, "dup", "a.c", "") &&
        cip_symbol_put(s, "dup", "a.c", "") &&
        cip_symbol_put(s, "nullable", "", "a.c") &&
        cip_symbol_put(s, "blobpath", "", "a.c") &&
        cip_symbol_put(s, "other", "b.c", "b.c");
}

static bool cip_column_equal(sqlite3_stmt *a, sqlite3_stmt *b, int col)
{
    int type = sqlite3_column_type(a, col);
    if (type != sqlite3_column_type(b, col)) return false;
    if (type == SQLITE_NULL) return true;
    if (type == SQLITE_INTEGER) return sqlite3_column_int64(a, col) == sqlite3_column_int64(b, col);
    if (type != SQLITE_TEXT && type != SQLITE_BLOB) return false;
    int len = sqlite3_column_bytes(a, col);
    if (len != sqlite3_column_bytes(b, col)) return false;
    const void *av = sqlite3_column_blob(a, col), *bv = sqlite3_column_blob(b, col);
    return len == 0 || (av && bv && memcmp(av, bv, (size_t)len) == 0);
}

static bool cip_symbol_rows_equal(sqlite3_stmt *a, sqlite3_stmt *b)
{
    for (int col = 0; col < 13; ++col)
        if (!cip_column_equal(a, b, col)) return false;
    return true;
}

static bool cip_symbol_compare_rows(sqlite3_stmt *ref, sqlite3_stmt *actual)
{
    static const char *const names[] = {"alpha", "beta", "blobpath", "both", "dup", "dup", "nullable"};
    int ar = SQLITE_ERROR, br = SQLITE_ERROR, rows = 0;
    bool ok = true;
    while (ok) {
        ar = sqlite3_step(ref); br = sqlite3_step(actual);
        if (ar != SQLITE_ROW || br != SQLITE_ROW) break;
        const unsigned char *name = sqlite3_column_text(ref, 0);
        ok = rows < 7 && name && !strcmp((const char *)name, names[rows]) && cip_symbol_rows_equal(ref, actual);
        ++rows;
    }
    if (!ok || ar != SQLITE_DONE || br != SQLITE_DONE || rows != 7)
        fprintf(stderr, "shard symbol parity rows=%d ref=%d actual=%d\n", rows, ar, br);
    return ok && ar == SQLITE_DONE && br == SQLITE_DONE && rows == 7;
}

static bool cip_symbol_compare(struct ci_store *s)
{
    static const char sql[] = "SELECT " CI_SYM_COLS " FROM symbols WHERE def_path=?1 OR decl_path=?1 ORDER BY "
        "name COLLATE BINARY,kind COLLATE BINARY,def_path COLLATE BINARY,def_line,"
        "decl_path COLLATE BINARY,decl_line,signature COLLATE BINARY,doc COLLATE BINARY,"
        "guard COLLATE BINARY,\"group\" COLLATE BINARY,partial,row_sha3";
    sqlite3_stmt *ref = NULL; struct ci_scan_shard_writer w = {0};
    bool ok = ci_scan_shard_writer_open(&w, s, false) &&
        sqlite3_prepare_v2(ci_store_db(s), sql, -1, &ref, NULL) == SQLITE_OK &&
        sqlite3_bind_text(ref, 1, "a.c", -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_text(w.symbols, 1, "a.c", -1, SQLITE_STATIC) == SQLITE_OK;
    if (ok) ok = cip_symbol_compare_rows(ref, w.symbols);
    bool closed = !ref || sqlite3_finalize(ref) == SQLITE_OK;
    if (!ci_scan_shard_writer_close(&w)) closed = false;
    return ok && closed;
}

static bool cip_symbol_bad_hash(struct ci_store *s, const char *sql)
{
    sqlite3 *db = ci_store_db(s);
    if (sqlite3_exec(db, "SAVEPOINT poison", NULL, NULL, NULL) != SQLITE_OK) return false;
    bool changed = sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK && sqlite3_changes(db) == 1;
    bool refused = changed && !ci_store_scan_shard_refresh(s, "a.c");
    bool restored = sqlite3_exec(db, "ROLLBACK TO poison; RELEASE poison", NULL, NULL, NULL) == SQLITE_OK;
    return refused && restored && ci_store_scan_shard_refresh(s, "a.c");
}

static bool cip_symbol_query_fixture(void)
{
    struct ci_store *s = ci_store_open_path(":memory:");
    if (!s) return false;
    bool ok = cip_symbol_seed(s) && ci_store_scan_shard_refresh(s, "a.c");
    sqlite3 *db = ci_store_db(s);
    /* Nullable copy permits observing SQL three-valued logic and raw types;
     * it is not a claim that all malformed fields are rejected today. */
    ok = ok && sqlite3_exec(db, "CREATE TABLE nullable_symbols AS SELECT * FROM symbols;"
        "DROP TABLE symbols; ALTER TABLE nullable_symbols RENAME TO symbols;"
        "UPDATE symbols SET def_path=NULL WHERE name='nullable';"
        "UPDATE symbols SET def_path=x'' WHERE name='blobpath'", NULL, NULL, NULL) == SQLITE_OK;
    if (ok) ok = cip_symbol_compare(s) && ci_store_scan_shard_refresh(s, "a.c");
    if (ok) ok = cip_symbol_bad_hash(s, "UPDATE symbols SET row_sha3=NULL WHERE name='alpha'");
    if (ok) ok = cip_symbol_bad_hash(s, "UPDATE symbols SET row_sha3='invalid' WHERE name='alpha'");
    ci_store_close(s);
    return ok;
}

static bool cip_shard_ref_row(sqlite3_stmt *stmt, int row)
{
    static const char *const names[] = {"projection_aux", "projection_leaf", "projection_leaf"};
    static const int lines[] = {12, 8, 12};
    static const char *const enclosing[] = {"projection_main", "projection_aux", "projection_main"};
    if (row < 0 || row >= 3) return false;
    const unsigned char *name = sqlite3_column_text(stmt, 0);
    const unsigned char *caller = sqlite3_column_text(stmt, 2);
    return name && caller && strcmp((const char *)name, names[row]) == 0 &&
        sqlite3_column_int(stmt, 1) == lines[row] &&
        strcmp((const char *)caller, enclosing[row]) == 0;
}

/* Run the production shard writer's prepared query, not a copied SQL string. */
static bool cip_shard_ref_sort(struct codeindex *index, bool expect_sort)
{
    struct ci_scan_shard_writer writer = {0};
    if (!ci_scan_shard_writer_open(&writer, index->store, false)) return false;
    sqlite3_stmt *stmt = writer.refs;
    bool ok = sqlite3_bind_text(stmt, 1, "lib/net/src/projection.c", -1, SQLITE_STATIC) == SQLITE_OK;
    int rc = SQLITE_ERROR, rows = 0;
    while (ok && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        ok = cip_shard_ref_row(stmt, rows);
        ++rows;
    }
    int sorts = sqlite3_stmt_status(stmt, SQLITE_STMTSTATUS_SORT, 0);
    bool closed = ci_scan_shard_writer_close(&writer);
    bool sort_ok = expect_sort ? sorts > 0 : sorts == 0;
    if (!ok || rc != SQLITE_DONE || rows != 3 || !sort_ok || !closed)
        fprintf(stderr, "shard refs rows=%d rc=%d sorts=%d closed=%d\n", rows, rc, sorts, closed);
    return ok && rc == SQLITE_DONE && rows == 3 && sort_ok && closed;
}

static bool cip_shard_ref_order(struct codeindex *index)
{
    return cip_shard_ref_sort(index, false);
}

static bool cip_legacy_ref_index(const char *root)
{
    char path[PATH_MAX]; sqlite3 *db = NULL;
    if (!cip_index_path(root, path) || sqlite3_open(path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    bool ok = sqlite3_exec(db,
        "DROP INDEX IF EXISTS idx_refs_file_ordered; DROP INDEX IF EXISTS idx_refs_file;"
        "CREATE INDEX idx_refs_file ON refs(ref_file);"
        "DROP INDEX IF EXISTS idx_refs_enclosing_ordered; DROP INDEX IF EXISTS idx_refs_enclosing;"
        "CREATE INDEX idx_refs_enclosing ON refs(enclosing);"
        "DROP INDEX IF EXISTS idx_symbols_name_ordered; DROP INDEX IF EXISTS idx_symbols_name;"
        "CREATE INDEX idx_symbols_name ON symbols(name)", NULL, NULL, NULL) == SQLITE_OK;
    return sqlite3_close(db) == SQLITE_OK && ok;
}

static bool cip_index_names(struct codeindex *ci, bool upgraded)
{
    sqlite3 *db = ci_store_db(ci->store); sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT (SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_refs_file'),"
                      "(SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_refs_file_ordered'),"
                      "(SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_refs_enclosing'),"
                      "(SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_refs_enclosing_ordered'),"
                      "(SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_symbols_name'),"
                      "(SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_symbols_name_ordered')";
    bool ok = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == !upgraded &&
        sqlite3_column_int(stmt, 1) == upgraded && sqlite3_column_int(stmt, 2) == !upgraded &&
        sqlite3_column_int(stmt, 3) == upgraded && sqlite3_column_int(stmt, 4) == !upgraded &&
        sqlite3_column_int(stmt, 5) == upgraded;
    if (stmt && sqlite3_finalize(stmt) != SQLITE_OK) ok = false;
    return ok;
}
static int cip_callee_trace(unsigned type, void *ctx, void *statement, void *unused)
{
    (void)unused; const char *sql = sqlite3_sql(statement);
    if (type == SQLITE_TRACE_PROFILE && sql && strstr(sql, "FROM refs WHERE enclosing=? ORDER BY"))
        *(int *)ctx += sqlite3_stmt_status(statement, SQLITE_STMTSTATUS_SORT, 1);
    return 0;
}
static bool cip_callee_parity(struct codeindex *old, struct codeindex *next)
{
    struct ci_ref a[8], b[8]; int sorts[2] = {0};
    sqlite3 *da = ci_store_db(old->store), *db = ci_store_db(next->store);
    if (sqlite3_trace_v2(da, SQLITE_TRACE_PROFILE, cip_callee_trace, &sorts[0]) != SQLITE_OK ||
        sqlite3_trace_v2(db, SQLITE_TRACE_PROFILE, cip_callee_trace, &sorts[1]) != SQLITE_OK) return false;
    bool ok = true;
    for (int cap = 1; cap <= 8; cap *= 8) {
        int na = codeindex_callees(old, "projection_main", a, cap);
        int nb = codeindex_callees(next, "projection_main", b, cap);
        ok = ok && na > 0 && na == nb && !memcmp(a, b, (size_t)na * sizeof(*a));
    }
    ok = sqlite3_trace_v2(da, 0, NULL, NULL) == SQLITE_OK && ok;
    ok = sqlite3_trace_v2(db, 0, NULL, NULL) == SQLITE_OK && ok;
    return ok && sorts[0] > 0 && sorts[1] == 0;
}

static bool cip_append(const char *root, const char *suffix, const char *text)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof path, "%s/lib/net/src/%s", root, suffix);
    if (n <= 0 || (size_t)n >= sizeof path) return false;
    FILE *f = fopen(path, "ab"); if (!f) return false;
    bool ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok;
}

static bool cip_old_generation_ok(struct codeindex *old, const uint8_t source[32],
                                  const uint8_t projection[32])
{
    bool valid = false;
    return cip_generation_matches(old, source, projection) &&
        ci_store_retrieval_projection_is_valid(old->store, &valid) && valid &&
        cip_index_names(old, false) && cip_shard_ref_sort(old, true);
}

static bool cip_upgrade_next_ok(struct codeindex *next, const uint8_t source[32],
                                const uint8_t projection[32], bool *current)
{
    uint8_t new_source[32], new_projection[32];
    return next && codeindex_test_source_scans() == 1 &&
        codeindex_source_root_sha3(next, new_source) &&
        codeindex_retrieval_projection_root_sha3(next, new_projection) &&
        memcmp(source, new_source, 32) != 0 && memcmp(projection, new_projection, 32) != 0 &&
        codeindex_retrieval_projection_is_current(next, current) && *current &&
        cip_queries_intact(next) && cip_index_names(next, true) && cip_shard_ref_order(next);
}

static bool cip_upgrade_step(const char *root, const char *comment,
                             struct codeindex *old, const uint8_t source[32],
                             const uint8_t projection[32])
{
    if (!cip_append(root, "projection.c", comment)) return false;
    codeindex_test_source_scans_reset();
    struct codeindex *next = codeindex_open(root);
    bool current = false;
    bool ok = cip_upgrade_next_ok(next, source, projection, &current) &&
              cip_old_generation_ok(old, source, projection) && cip_callee_parity(old, next);
    if (!ok) fprintf(stderr, "legacy refs upgrade: next=%d scans=%llu current=%d\n",
                     next != NULL, (unsigned long long)codeindex_test_source_scans(), current);
    codeindex_close(next);
    return ok;
}

static bool cip_incremental_ref_upgrade(const char *workspace)
{
    char root[PATH_MAX], spare[PATH_MAX];
    int n = snprintf(root, sizeof root, "%s/legacy-index", workspace);
    if (n <= 0 || (size_t)n >= sizeof root || !cip_write(root) ||
        !cip_append(root, "second.c", "int second(void) { return 1; }\n")) return false;
    struct codeindex *initial = codeindex_open(root);
    uint8_t source[32], projection[32];
    bool ok = initial && codeindex_source_root_sha3(initial, source) &&
        codeindex_retrieval_projection_root_sha3(initial, projection);
    codeindex_close(initial);
    if (!ok || !cip_legacy_ref_index(root)) return false;
    struct codeindex *old = codeindex_open_existing(root);
    ok = old && cip_old_generation_ok(old, source, projection);
    n = snprintf(spare, sizeof spare, "%s/.codeindex/index.kv.spare", root);
    ok = ok && n > 0 && (size_t)n < sizeof spare;
    if (ok) ok = cip_upgrade_step(root, "/* first edit */\n", old, source, projection);
    struct stat st;
    if (ok) ok = stat(spare, &st) == 0;
    if (ok) ok = cip_upgrade_step(root, "/* second edit */\n", old, source, projection);
    codeindex_close(old);
    return ok;
}

/* Both conflicting names are legal SQLite schema but unusable as our index. */
static bool cip_conflicting_ref_index(const char *root, int mode)
{
    char path[PATH_MAX]; sqlite3 *db = NULL;
    if (!cip_index_path(root, path) || sqlite3_open(path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    static const char *const sqls[] = {
        "CREATE INDEX idx_refs_file_ordered ON refs(ref_line)",
        "CREATE TABLE idx_refs_file_ordered(v INTEGER)",
        "CREATE INDEX idx_refs_enclosing_ordered ON refs(ref_line)",
        "CREATE TABLE idx_refs_enclosing_ordered(v INTEGER)",
        "CREATE INDEX idx_refs_enclosing_ordered ON refs(enclosing,ref_file,ref_line) WHERE ref_line>0",
        "CREATE INDEX idx_symbols_name_ordered ON symbols(def_line)",
        "CREATE TABLE idx_symbols_name_ordered(v INTEGER)",
        "CREATE INDEX idx_symbols_name_ordered ON symbols(name,def_path,def_line) WHERE def_line>0"
    };
    if (mode < 0 || (size_t)mode >= sizeof(sqls)/sizeof(sqls[0])) { sqlite3_close(db); return false; }
    bool ok = sqlite3_exec(db, sqls[mode], NULL, NULL, NULL) == SQLITE_OK;
    return sqlite3_close(db) == SQLITE_OK && ok;
}

static bool cip_published_unchanged(const char *root, const struct stat *before,
                                    const uint8_t source[32], const uint8_t projection[32])
{
    char path[PATH_MAX]; struct stat after;
    if (!cip_index_path(root, path) || stat(path, &after) != 0 ||
        before->st_dev != after.st_dev || before->st_ino != after.st_ino) return false;
    struct codeindex *view = codeindex_open_existing(root);
    bool valid = false;
    bool ok = view && cip_generation_matches(view, source, projection) &&
        ci_store_retrieval_projection_is_valid(view->store, &valid) && valid;
    codeindex_close(view);
    return ok;
}

static bool cip_conflict_setup(const char *root, int mode,
                               uint8_t source[32], uint8_t projection[32])
{
    if (!cip_write(root) || !cip_append(root, "second.c", "int second(void) { return 1; }\n")) return false;
    struct codeindex *initial = codeindex_open(root);
    bool ok = initial && codeindex_source_root_sha3(initial, source) &&
        codeindex_retrieval_projection_root_sha3(initial, projection);
    codeindex_close(initial);
    return ok && cip_legacy_ref_index(root) && cip_conflicting_ref_index(root, mode);
}

static bool cip_conflicting_upgrade(const char *workspace, int mode)
{
    char root[PATH_MAX], path[PATH_MAX];
    uint8_t source[32], projection[32];
    int n = snprintf(root, sizeof root, "%s/conflict-%d", workspace, mode);
    if (n <= 0 || (size_t)n >= sizeof root || !cip_conflict_setup(root, mode, source, projection)) return false;
    struct stat before;
    bool ok = cip_index_path(root, path) && stat(path, &before) == 0 &&
        cip_published_unchanged(root, &before, source, projection) &&
        cip_append(root, "projection.c", "/* conflicting index edit */\n");
    codeindex_test_source_scans_reset();
    struct codeindex *attempt = ok ? codeindex_open(root) : NULL;
    bool refused = ok && !attempt;
    codeindex_close(attempt);
    bool unchanged = ok && cip_published_unchanged(root, &before, source, projection);
    if (!refused || !unchanged)
        fprintf(stderr, "conflicting refs index table=%d setup=%d refused=%d unchanged=%d scans=%llu\n",
                mode, ok, refused, unchanged,
                (unsigned long long)codeindex_test_source_scans());
    return refused && unchanged;
}

static int cip_deny_enclosing(void *context, int action, const char *one,
                              const char *two, const char *db, const char *trigger)
{
    (void)context; (void)two; (void)db; (void)trigger;
    return action == SQLITE_CREATE_INDEX && one && !strcmp(one, "idx_refs_enclosing_ordered")
        ? SQLITE_DENY : SQLITE_OK;
}
static int cip_deny_symbol(void *context, int action, const char *one,
                           const char *two, const char *db, const char *trigger)
{
    (void)context; (void)two; (void)db; (void)trigger;
    return action == SQLITE_CREATE_INDEX && one && !strcmp(one, "idx_symbols_name_ordered")
        ? SQLITE_DENY : SQLITE_OK;
}
static bool cip_symbol_ddl_refusal(void)
{
    struct ci_store *store = ci_store_open_path(":memory:");
    if (!store) return false;
    sqlite3 *db = ci_store_db(store); sqlite3_stmt *stmt = NULL;
    bool ok = sqlite3_exec(db, "DROP INDEX idx_symbols_name_ordered; CREATE INDEX idx_symbols_name ON symbols(name)", NULL, NULL, NULL) == SQLITE_OK &&
        sqlite3_set_authorizer(db, cip_deny_symbol, NULL) == SQLITE_OK &&
        !ci_store_ensure_ordered_indexes(db) && sqlite3_set_authorizer(db, NULL, NULL) == SQLITE_OK;
    ok = ok && sqlite3_prepare_v2(db, "SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_symbols_name'", -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 1;
    if (stmt && sqlite3_finalize(stmt) != SQLITE_OK) ok = false;
    ci_store_close(store); return ok;
}
static int cip_defs_trace(unsigned type, void *ctx, void *statement, void *unused)
{
    (void)unused; const char *sql = sqlite3_sql(statement);
    if (type == SQLITE_TRACE_PROFILE && sql && !strcmp(sql,
        "SELECT " CI_SYM_COLS " FROM symbols WHERE name=? ORDER BY def_path ASC, def_line ASC"))
        *(int *)ctx += sqlite3_stmt_status(statement, SQLITE_STMTSTATUS_SORT, 1);
    return 0;
}
static bool cip_defs_put(struct ci_store *s, char kind, const char *def, const char *decl)
{
    struct ci_symbol sym = {0};
    snprintf(sym.name, sizeof sym.name, "mixed"); sym.kind = kind;
    snprintf(sym.def_path, sizeof sym.def_path, "%s", def);
    snprintf(sym.decl_path, sizeof sym.decl_path, "%s", decl);
    sym.def_line = *def ? 3 : 0; sym.decl_line = *decl ? 4 : 0;
    return ci_store_put_symbol(s, &sym);
}
static bool cip_defs_identity(struct ci_store *a, struct ci_store *b)
{
    struct ci_symbol x[8], y[8]; bool fa = false, fb = false;
    if (!ci_store_symbol_by_name(a, "mixed", x, &fa) || !ci_store_symbol_by_name(b, "mixed", y, &fb) ||
        !fa || fa != fb || memcmp(x, y, sizeof(*x))) return false;
    if (!ci_store_symbol_by_name_path(a, "mixed", "a.c", x, &fa) ||
        !ci_store_symbol_by_name_path(b, "mixed", "a.c", y, &fb) || !fa || fa != fb || memcmp(x, y, sizeof(*x))) return false;
    return true;
}
static bool cip_defs_compare(struct ci_store *a, struct ci_store *b)
{
    struct ci_symbol x[8], y[8];
    if (!cip_defs_identity(a, b)) return false;
    struct codeindex ca = {.store=a}, cb = {.store=b};
    for (int cap = 1; cap <= 8; cap *= 8) {
        int na = ci_store_defs_by_name(a, "mixed", x, cap), nb = ci_store_defs_by_name(b, "mixed", y, cap);
        if (na <= 0 || na != nb || memcmp(x, y, (size_t)na * sizeof(*x))) return false;
        int ea = 0, eb = 0;
        enum codeindex_exact_status sa = codeindex_find_exact_checked(&ca, "mixed", x, cap, &ea);
        enum codeindex_exact_status sb = codeindex_find_exact_checked(&cb, "mixed", y, cap, &eb);
        if (sa != sb || ea != eb || memcmp(x, y, (size_t)ea * sizeof(*x))) return false;
    }
    return true;
}
static struct ci_store *cip_defs_copy(struct ci_store *a)
{
    struct ci_store *b = ci_store_open_path(":memory:"); if (!b) return NULL;
    sqlite3 *db = ci_store_db(b); sqlite3_backup *backup = sqlite3_backup_init(db, "main", ci_store_db(a), "main");
    if (!backup) { ci_store_close(b); return NULL; }
    bool copied = sqlite3_backup_step(backup, -1) == SQLITE_DONE;
    if (sqlite3_backup_finish(backup) != SQLITE_OK || !copied || !ci_store_ensure_ordered_indexes(db)) {
        ci_store_close(b); return NULL;
    }
    return b;
}
static bool cip_defs_traced(struct ci_store *a, struct ci_store *b)
{
    sqlite3 *da = ci_store_db(a), *db = ci_store_db(b); int sorts[2] = {0};
    if (sqlite3_trace_v2(da, SQLITE_TRACE_PROFILE, cip_defs_trace, &sorts[0]) != SQLITE_OK ||
        sqlite3_trace_v2(db, SQLITE_TRACE_PROFILE, cip_defs_trace, &sorts[1]) != SQLITE_OK) return false;
    bool ok = cip_defs_compare(a, b);
    ok = sqlite3_trace_v2(da, 0, NULL, NULL) == SQLITE_OK && ok;
    ok = sqlite3_trace_v2(db, 0, NULL, NULL) == SQLITE_OK && ok;
    return ok && sorts[0] > 0 && sorts[1] == 0;
}
static bool cip_definition_index_fixture(void)
{
    struct ci_store *a = ci_store_open_path(":memory:"), *b = NULL; bool ok = false;
    if (!a || !cip_defs_put(a, 'T', "a.c", "") || !cip_defs_put(a, 't', "a.c", "") ||
        !cip_defs_put(a, 'T', "", "decl.h")) goto done;
    sqlite3 *da = ci_store_db(a);
    if (sqlite3_exec(da, "DROP INDEX idx_symbols_name_ordered; CREATE INDEX idx_symbols_name ON symbols(name)", NULL, NULL, NULL) != SQLITE_OK) goto done;
    b = cip_defs_copy(a); if (!b) goto done;
    ok = cip_defs_traced(a, b);
done:
    if (b) ci_store_close(b);
    if (a) ci_store_close(a);
    return ok;
}
static bool cip_enclosing_ddl_refusal(void)
{
    struct ci_store *store = ci_store_open_path(":memory:");
    if (!store) return false;
    sqlite3 *db = ci_store_db(store);
    bool ok = sqlite3_exec(db, "DROP INDEX idx_refs_enclosing_ordered; CREATE INDEX idx_refs_enclosing ON refs(enclosing)", NULL, NULL, NULL) == SQLITE_OK &&
        sqlite3_set_authorizer(db, cip_deny_enclosing, NULL) == SQLITE_OK &&
        !ci_store_ensure_ordered_indexes(db) && sqlite3_set_authorizer(db, NULL, NULL) == SQLITE_OK;
    sqlite3_stmt *stmt = NULL;
    ok = ok && sqlite3_prepare_v2(db, "SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_refs_enclosing'", -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 1;
    if (stmt && sqlite3_finalize(stmt) != SQLITE_OK) ok = false;
    ci_store_close(store); return ok;
}

static int cip_check_index_migration(bool ready, const char *workspace)
{
    int failures = 0;
    CIP_CHECK("legacy reference index upgrades during incremental publication",
              ready && cip_incremental_ref_upgrade(workspace));
    CIP_CHECK("wrong-shape reference index refuses staged publication",
              ready && cip_conflicting_upgrade(workspace, false));
    CIP_CHECK("index-name table collision refuses staged publication",
              ready && cip_conflicting_upgrade(workspace, true));
    CIP_CHECK("wrong-shape enclosing index refuses staged publication",
              ready && cip_conflicting_upgrade(workspace, 2));
    CIP_CHECK("enclosing index-name table collision refuses staged publication",
              ready && cip_conflicting_upgrade(workspace, 3));
    CIP_CHECK("partial enclosing index refuses staged publication",
              ready && cip_conflicting_upgrade(workspace, 4));
    CIP_CHECK("enclosing DDL refusal retains legacy index", cip_enclosing_ddl_refusal());
    CIP_CHECK("wrong-shape symbol index refuses staged publication", ready && cip_conflicting_upgrade(workspace, 5));
    CIP_CHECK("symbol index-name table collision refuses staged publication", ready && cip_conflicting_upgrade(workspace, 6));
    CIP_CHECK("partial symbol index refuses staged publication", ready && cip_conflicting_upgrade(workspace, 7));
    CIP_CHECK("symbol DDL refusal retains legacy index", cip_symbol_ddl_refusal());
    CIP_CHECK("definition index preserves typed identities and tie order", cip_definition_index_fixture());
    return failures;
}

int test_codeindex_projection_integrity(void)
{
    int failures = 0;
    CIP_CHECK("shard symbol query preserves typed OR rows and rejects corrupt hashes",
              cip_symbol_query_fixture());
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
    CIP_CHECK("shard reference ordering needs no sort and preserves projection",
              rooted && cip_shard_ref_order(one) &&
              cip_generation_matches(one, source_root, projection_root));
    codeindex_close(one);
    codeindex_close(two);
    failures += cip_check_index_migration(ready, workspace);

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

    existing = cip_open_after_sql(
        rooted, first, "UPDATE pages_state SET state=2 WHERE id=1");
    bool untrusted_same = cip_logical_root_preserved(existing, source_root,
                                                     projection_root);
    codeindex_close(existing);
    existing = cip_open_after_sql(
        rooted, first, "UPDATE pages_state SET state=0 WHERE id=1");
    CIP_CHECK("a pages_state flip between 2 and 0 is accepted without changing the root",
              untrusted_same && cip_logical_root_preserved(
                                    existing, source_root, projection_root));
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
        {"reference callee embedded NUL suffix",
         "UPDATE refs SET callee_name=callee_name||char(0)||'suffix' "
         "WHERE rowid=(SELECT MIN(rowid) FROM refs WHERE enclosing='projection_main')"},
        {"reference enclosing embedded NUL suffix",
         "UPDATE refs SET enclosing=enclosing||char(0)||'suffix' "
         "WHERE rowid=(SELECT MIN(rowid) FROM refs WHERE enclosing='projection_main')"},
        {"file group embedded NUL suffix",
         "UPDATE files SET \"group\"=\"group\"||char(0)||'suffix' "
         "WHERE path='lib/net/src/projection.c'"},
        {"file purpose embedded NUL suffix",
         "UPDATE files SET purpose=purpose||char(0)||'suffix' "
         "WHERE path='lib/net/src/projection.c'"},
        {"file line count exceeds int32",
         "UPDATE files SET line_count=line_count+4294967296 "
         "WHERE path='lib/net/src/projection.c'"},
        {"file line count has a text suffix",
         "UPDATE files SET line_count=CAST(line_count AS TEXT)||'suffix' "
         "WHERE path='lib/net/src/projection.c'"},
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

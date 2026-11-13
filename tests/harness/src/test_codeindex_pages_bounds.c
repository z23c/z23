/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Prove page hint storage stays bounded and readable: a list past its
 * cap is cut, not failed; the store row limit is refused before it can break a
 * rebuild; a pre-feature prior is not marked untrusted; an incremental
 * refresh keeps imported hints. */

#include "test/test_core.h"

#include "codeindex/codeindex.h"
#include "codeindex/codeindex_build.h"
#include "codeindex/codeindex_pages.h"
#include "../../../cognition/modules/codeindex/src/codeindex_priv.h"
#include "config/file_ops.h"
#include "platform/directory_compat.h"
#include "platform/temp_directory.h"

#include <sqlite3.h>

#include <limits.h>
#include <stdio.h>
#include <string.h>

#define CPB_CHECK(name, expression)                                    \
    do {                                                               \
        bool cpb_ok_ = (expression);                                   \
        printf("codeindex_pages_bounds: %s %s\n",                      \
               cpb_ok_ ? "OK  " : "FAIL", (name));                     \
        if (!cpb_ok_) failures++;                                      \
    } while (0)

enum { CPB_BATCH_MAX = 24, CPB_MANIFEST_MAX = 8192 };

static bool cpb_put(const char *root, const char *rel, const char *text)
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

static bool cpb_exec(const char *root, const char *sql)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/.codeindex/index.kv", root);
    sqlite3 *db = NULL;
    if (n <= 0 || (size_t)n >= sizeof(path) || sqlite3_open(path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    bool ok = sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(db);
    return ok;
}

static bool cpb_fixture(const char *root)
{
    return cpb_put(root, "lib/net/src/net.c", "int net_leaf(int x)\n{\n    return x + 1;\n}\n");
}

/* Pages first..first+count-1 for lib/net, one tree each, with their manifest. */
static bool cpb_batch(struct ci_page *pages, char *manifest, size_t manifest_cap,
                      int first, int count)
{
    size_t used = 0;
    for (int i = 0; i < count; i++) {
        struct ci_page *p = &pages[i];
        memset(p, 0, sizeof(*p));
        snprintf(p->directory, sizeof(p->directory), "lib/net");
        snprintf(p->tree_oid, sizeof(p->tree_oid), "%040x", (unsigned)(first + i + 1));
        snprintf(p->source_commit, sizeof(p->source_commit), "%040x", 0xbbbbbbu);
        int n = snprintf(p->body, sizeof(p->body),
            "{\"dir\":\"lib/net\",\"tree\":\"%s\",\"topic\":\"net\",\"summary\":\"hint %d\","
            "\"lessons\":[],\"applies_to\":[],\"updated\":\"2026-11-04T00:00:00Z\"}",
            p->tree_oid, first + i);
        if (n <= 0 || (size_t)n >= sizeof(p->body) || used + (size_t)n + 1 >= manifest_cap) return false;
        memcpy(manifest + used, p->body, (size_t)n);
        used += (size_t)n;
        manifest[used++] = '\n';
    }
    manifest[used] = '\0';
    return true;
}

static bool cpb_import(struct codeindex *ci, int first, int count)
{
    static struct ci_page pages[CPB_BATCH_MAX];
    static char manifest[CPB_MANIFEST_MAX];
    uint8_t artifact[32];
    return cpb_batch(pages, manifest, sizeof(manifest), first, count) &&
           codeindex_pages_import_hints(ci, manifest, strlen(manifest), pages, (size_t)count, artifact);
}

static int cpb_row_count(const char *root)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/.codeindex/index.kv", root), rows = -1;
    sqlite3 *db = NULL;
    sqlite3_stmt *s = NULL;
    if (n > 0 && (size_t)n < sizeof(path) && sqlite3_open(path, &db) == SQLITE_OK &&
        sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM pages", -1, &s, NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW) rows = sqlite3_column_int(s, 0);
    if (s) sqlite3_finalize(s);
    if (db) sqlite3_close(db);
    return rows;
}

/* 17 rows: the first 16 come back cut and flagged; a larger cap returns all. */
static bool cpb_truncation(const char *root)
{
    struct codeindex *ci = codeindex_open_retrieval_view(root);
    static struct ci_page out[17];
    bool untrusted = true, truncated = false;
    bool imported = ci && cpb_import(ci, 0, 17);
    codeindex_close(ci);
    ci = imported ? codeindex_open_retrieval_view(root) : NULL;
    bool cut = ci && codeindex_pages_list_bounded(ci, "lib/net", out, 16, &untrusted, &truncated) == 16 &&
               truncated && !untrusted &&
               strcmp(out[0].tree_oid, "0000000000000000000000000000000000000001") == 0 &&
               strcmp(out[15].tree_oid, "0000000000000000000000000000000000000010") == 0;
    bool strict = ci && codeindex_pages_list(ci, "lib/net", out, 16, &untrusted) == -1;
    bool all = ci && codeindex_pages_list_bounded(ci, "lib/net", out, 17, &untrusted, &truncated) == 17 &&
               !truncated;
    codeindex_close(ci);
    return cut && strict && all;
}

/* At the row limit an import is refused before publication and nothing changes. */
static bool cpb_cap(const char *root)
{
    struct codeindex *ci = codeindex_open_retrieval_view(root);
    codeindex_pages_test_set_store_cap(20);
    bool fits = ci && codeindex_pages_capacity_ok(ci, 3) && cpb_import(ci, 17, 3);
    codeindex_close(ci);
    ci = codeindex_open_retrieval_view(root);
    bool full = ci && !codeindex_pages_capacity_ok(ci, 1);
    bool refused = ci && !cpb_import(ci, 20, 1);
    codeindex_close(ci);
    codeindex_pages_test_set_store_cap(0);
    return fits && full && refused && cpb_row_count(root) == 20;
}

/* A store from before pages existed has nothing to carry: it must not read as untrusted. */
static bool cpb_legacy_prior(const char *root)
{
    struct ci_page out[1];
    bool untrusted = true, truncated = false;
    bool aged = cpb_exec(root, "DROP TABLE pages; DROP TABLE pages_state");
    struct codeindex *ci = aged ? codeindex_open_retrieval_view(root) : NULL;
    bool ok = ci && codeindex_pages_list_bounded(ci, "lib/net", out, 1, &untrusted, &truncated) == 0 &&
              !untrusted && !truncated;
    codeindex_close(ci);
    return ok;
}

/* An incremental refresh after an import keeps the hint and the seal. */
static bool cpb_incremental(const char *root)
{
    struct ci_page out[1];
    bool untrusted = true, truncated = false;
    struct codeindex *ci = codeindex_open_retrieval_view(root);
    bool imported = ci && cpb_import(ci, 0, 1);
    codeindex_close(ci);
    bool edited = imported &&
        cpb_put(root, "lib/net/src/net.c", "int net_leaf(int x)\n{\n    return x + 2;\n}\n");
    ci = edited ? codeindex_open_retrieval_view(root) : NULL;
    bool ok = ci && codeindex_pages_list_bounded(ci, "lib/net", out, 1, &untrusted, &truncated) == 1 &&
              !untrusted && !truncated;
    codeindex_close(ci);
    return ok;
}

static bool cpb_in_fresh_root(bool (*check)(const char *root))
{
    char temporary[PLATFORM_TEMP_PATH_MAX] = {0}, root[PLATFORM_TEMP_PATH_MAX];
    bool ok = platform_temp_directory_create("z23-pages-bounds-", temporary, sizeof(temporary)) &&
              platform_directory_canonical_real(temporary, root, sizeof(root)) && cpb_fixture(root) &&
              check(root);
    if (temporary[0]) dir_remove_tree(temporary);
    return ok;
}

static bool cpb_truncation_and_cap(const char *root)
{
    return cpb_truncation(root) && cpb_cap(root);
}

static bool cpb_import_then_legacy(const char *root)
{
    struct codeindex *ci = codeindex_open_retrieval_view(root);
    bool imported = ci && cpb_import(ci, 0, 1);
    codeindex_close(ci);
    return imported && cpb_legacy_prior(root);
}

struct cpb_interrupt { sqlite3 *db; int rows; };

static int cpb_interrupt_row(unsigned event, void *ctx, void *statement, void *unused)
{
    (void)statement; (void)unused;
    struct cpb_interrupt *fault = ctx;
    if (event == SQLITE_TRACE_ROW && ++fault->rows == 1)
        sqlite3_interrupt(fault->db);
    return 0;
}

static bool cpb_page_fault(sqlite3 *db, struct codeindex *ci, const char *sql)
{
    struct ci_file rows[4];
    if (sqlite3_exec(db, "SAVEPOINT page_fault", NULL, NULL, NULL) != SQLITE_OK)
        return false;
    bool changed = sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
    bool refused = changed && codeindex_files_page(ci, 0, rows, 4) < 0;
    bool restored = sqlite3_exec(db, "ROLLBACK TO page_fault; RELEASE page_fault", NULL, NULL, NULL) == SQLITE_OK;
    if (!changed || !refused || !restored)
        fprintf(stderr, "file page fault: changed=%d refused=%d restored=%d sql=%s\n", changed, refused, restored, sql);
    return refused && restored;
}

/* Corrupt only a private writable copy; codeindex_open returns a read-only store. */
static struct ci_store *cpb_writable_copy(struct codeindex *ci)
{
    struct ci_store *store = ci_store_open_path(":memory:");
    if (!store) return NULL;
    sqlite3_backup *backup = sqlite3_backup_init(ci_store_db(store), "main", ci_store_db(ci->store), "main");
    bool ok = backup && sqlite3_backup_step(backup, -1) == SQLITE_DONE;
    if (backup && sqlite3_backup_finish(backup) != SQLITE_OK) ok = false;
    if (!ok) { ci_store_close(store); return NULL; }
    return store;
}

static bool cpb_file_count_fault(struct codeindex *ci)
{
    sqlite3 *db = ci_store_db(ci->store);
    if (codeindex_file_count(ci) != 1) return false;
    struct cpb_interrupt fault = {.db = db};
    if (sqlite3_trace_v2(db, SQLITE_TRACE_ROW, cpb_interrupt_row, &fault) != SQLITE_OK) return false;
    int interrupted = codeindex_file_count(ci);
    bool cleared = sqlite3_trace_v2(db, 0, NULL, NULL) == SQLITE_OK;
    int recovered = codeindex_file_count(ci);
    bool ok = fault.rows == 1 && interrupted < 0 && cleared && recovered == 1;
    if (!ok) fprintf(stderr, "file count interrupt rows=%d rc=%d cleared=%d recovered=%d\n",
                     fault.rows, interrupted, cleared, recovered);
    return ok;
}

static bool cpb_file_page_faults(struct codeindex *ci)
{
    sqlite3 *db = ci_store_db(ci->store);
    struct ci_file rows[4];
    bool ok = db && codeindex_files_page(ci, 0, rows, 4) == 1 &&
        strcmp(rows[0].path, "lib/net/src/net.c") == 0 &&
        codeindex_files_page(ci, 1, rows, 4) == 0;
    struct cpb_interrupt fault = {.db = db};
    if (ok) ok = sqlite3_trace_v2(db, SQLITE_TRACE_ROW, cpb_interrupt_row, &fault) == SQLITE_OK;
    if (ok) {
        int interrupted = codeindex_files_page(ci, 0, rows, 4);
        ok = interrupted < 0 && fault.rows == 1;
        if (!ok) fprintf(stderr, "file page interrupt: rc=%d rows=%d\n", interrupted, fault.rows);
    }
    if (db && sqlite3_trace_v2(db, 0, NULL, NULL) != SQLITE_OK) ok = false;
    if (ok) ok = cpb_page_fault(db, ci, "UPDATE files SET path=printf('%0300d',1)");
    if (ok) ok = cpb_page_fault(db, ci, "UPDATE files SET purpose=CAST(x'610062' AS TEXT)");
    if (ok) ok = cpb_page_fault(db, ci, "UPDATE files SET line_count=-1");
    if (ok) ok = cpb_page_fault(db, ci, "UPDATE files SET line_count=2147483648");
    if (ok) ok = codeindex_files_page(ci, 0, rows, 4) == 1;
    return ok;
}

static bool cpb_file_pages(const char *root)
{
    struct codeindex *ci = codeindex_open(root);
    if (!ci) return false;
    struct ci_file rows[4];
    bool original = codeindex_files_page(ci, 0, rows, 4) == 1 &&
        !strcmp(rows[0].path, "lib/net/src/net.c") &&
        codeindex_files_page(ci, 1, rows, 4) == 0;
    struct ci_store *store = original ? cpb_writable_copy(ci) : NULL;
    struct codeindex copy = *ci;
    copy.store = store;
    bool pages = store && cpb_file_page_faults(&copy);
    bool count = store && cpb_file_count_fault(&copy);
    bool ok = pages && count;
    if (store) ci_store_close(store);
    codeindex_close(ci);
    if (!ok) fprintf(stderr, "file page fixture: original=%d writable_copy=%d\n", original, store != NULL);
    return ok;
}

int test_codeindex_pages_bounds(void)
{
    int failures = 0;
    CPB_CHECK("a 17th row is cut and flagged, not an error; a larger cap returns all",
              cpb_in_fresh_root(cpb_truncation));
    CPB_CHECK("an import past the row limit is refused before it can break a rebuild",
              cpb_in_fresh_root(cpb_truncation_and_cap));
    CPB_CHECK("a prior generation without page tables rebuilds clean, not untrusted",
              cpb_in_fresh_root(cpb_import_then_legacy));
    CPB_CHECK("an incremental refresh after an import keeps the hint and stays valid",
              cpb_in_fresh_root(cpb_incremental));
    CPB_CHECK("file pages refuse interrupted and malformed rows, then recover",
              cpb_in_fresh_root(cpb_file_pages));
    return failures;
}

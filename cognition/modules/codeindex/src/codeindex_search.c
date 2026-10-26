/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: explained full-text queries over the rebuildable code index. */

#include "codeindex_priv.h"

#include "base/safe_alloc.h"
#include "retrieval/retrieval.h"
#include "util/log_macros.h"

#include <sqlite3.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

enum { CI_STORY_INITIAL_ROWS = 64, CI_STORY_MAX_ROWS = 65536 };

static bool story_add_size(size_t *total, size_t add)
{
    if (!total || SIZE_MAX - *total < add)
        LOG_FAIL("codeindex", "story document size overflow");
    *total += add;
    return true;
}

static bool story_append(char *out, size_t cap, size_t *used,
                         const char *field)
{
    size_t len = strlen(field);
    if (*used > cap || len > cap - *used || cap - *used - len < 1)
        LOG_FAIL("codeindex", "story document exceeded its allocation");
    memcpy(out + *used, field, len);
    *used += len;
    out[(*used)++] = '\n';
    return true;
}

static char *story_document(const struct ci_file *file,
                            const struct ci_symbol *symbols,
                            size_t symbol_count)
{
    size_t need = 1;
    const char *base[] = { file->path, file->group, file->purpose };
    for (size_t i = 0; i < sizeof(base) / sizeof(base[0]); i++)
        if (!story_add_size(&need, strlen(base[i]) + 1u)) return NULL;
    for (size_t i = 0; i < symbol_count; i++) {
        const char *fields[] = { symbols[i].name, symbols[i].signature,
                                 symbols[i].doc, symbols[i].guard };
        for (size_t j = 0; j < sizeof(fields) / sizeof(fields[0]); j++)
            if (!story_add_size(&need, strlen(fields[j]) + 1u)) return NULL;
    }
    char *out = zcl_malloc(need, "codeindex story document");
    if (!out) return NULL;
    size_t used = 0;
    for (size_t i = 0; i < sizeof(base) / sizeof(base[0]); i++)
        if (!story_append(out, need, &used, base[i])) {
            free(out);
            return NULL;
        }
    for (size_t i = 0; i < symbol_count; i++) {
        const char *fields[] = { symbols[i].name, symbols[i].signature,
                                 symbols[i].doc, symbols[i].guard };
        for (size_t j = 0; j < sizeof(fields) / sizeof(fields[0]); j++)
            if (!story_append(out, need, &used, fields[j])) {
                free(out);
                return NULL;
            }
    }
    out[used] = '\0';
    return out;
}

static bool story_load_groups(struct codeindex *ci, struct ci_group **out,
                              size_t *count)
{
    int cap = CI_STORY_INITIAL_ROWS;
    struct ci_group *rows = NULL;
    for (;;) {
        struct ci_group *grown = zcl_realloc(
            rows, (size_t)cap * sizeof(*rows), "codeindex story groups");
        if (!grown) {
            free(rows);
            return false;
        }
        rows = grown;
        int n = codeindex_groups(ci, rows, cap);
        if (n < 0) {
            free(rows);
            return false;
        }
        if (n < cap) {
            *out = rows;
            *count = (size_t)n;
            return true;
        }
        if (cap >= CI_STORY_MAX_ROWS) {
            free(rows);
            LOG_FAIL("codeindex", "story group corpus exceeds bound");
        }
        cap *= 2;
    }
}

static bool story_load_files(struct codeindex *ci, const char *group,
                             struct ci_file **out, size_t *count)
{
    int cap = CI_STORY_INITIAL_ROWS;
    struct ci_file *rows = NULL;
    for (;;) {
        struct ci_file *grown = zcl_realloc(
            rows, (size_t)cap * sizeof(*rows), "codeindex story files");
        if (!grown) {
            free(rows);
            return false;
        }
        rows = grown;
        int n = codeindex_files_in_group(ci, group, rows, cap);
        if (n < 0) {
            free(rows);
            return false;
        }
        if (n < cap) {
            *out = rows;
            *count = (size_t)n;
            return true;
        }
        if (cap >= CI_STORY_MAX_ROWS) {
            free(rows);
            LOG_FAIL("codeindex", "story file group exceeds bound");
        }
        cap *= 2;
    }
}

static bool story_load_symbols(struct codeindex *ci, const char *path,
                               struct ci_symbol **out, size_t *count)
{
    int cap = CI_STORY_INITIAL_ROWS;
    struct ci_symbol *rows = NULL;
    for (;;) {
        struct ci_symbol *grown = zcl_realloc(
            rows, (size_t)cap * sizeof(*rows), "codeindex story symbols");
        if (!grown) {
            free(rows);
            return false;
        }
        rows = grown;
        int n = codeindex_symbols_in_file(ci, path, rows, cap);
        if (n < 0) {
            free(rows);
            return false;
        }
        if (n < cap) {
            *out = rows;
            *count = (size_t)n;
            return true;
        }
        if (cap >= CI_STORY_MAX_ROWS) {
            free(rows);
            LOG_FAIL("codeindex", "story symbol file exceeds bound: %s", path);
        }
        cap *= 2;
    }
}

static int story_file_cmp(const void *left, const void *right)
{
    return strcmp(((const struct ci_file *)left)->path,
                  ((const struct ci_file *)right)->path);
}

/* qsort's base is declared nonnull; sorting 0 or 1 entries is a no-op. */
static void story_files_sort(struct ci_file *files, size_t n)
{
    if (n > 1) qsort(files, n, sizeof(*files), story_file_cmp);
}

static bool story_collect_files(struct codeindex *ci, struct ci_file **out,
                                size_t *count)
{
    struct ci_group *groups = NULL;
    struct ci_file *all = NULL;
    size_t group_count = 0, used = 0, cap = 0;
    if (!story_load_groups(ci, &groups, &group_count)) return false;
    for (size_t g = 0; g < group_count; g++) {
        struct ci_file *files = NULL;
        size_t file_count = 0;
        if (!story_load_files(ci, groups[g].path, &files, &file_count)) {
            free(groups);
            free(all);
            return false;
        }
        if (file_count > SIZE_MAX - used) {
            free(files); free(groups); free(all);
            LOG_FAIL("codeindex", "story file count overflow");
        }
        size_t want = used + file_count;
        if (want > cap) {
            size_t next = cap ? cap : CI_STORY_INITIAL_ROWS;
            while (next < want && next <= SIZE_MAX / 2u) next *= 2u;
            if (next < want || next > CI_STORY_MAX_ROWS) {
                free(files); free(groups); free(all);
                LOG_FAIL("codeindex", "story file corpus exceeds bound");
            }
            struct ci_file *grown = zcl_realloc(
                all, next * sizeof(*all), "codeindex story file corpus");
            if (!grown) {
                free(files); free(groups); free(all);
                return false;
            }
            all = grown;
            cap = next;
        }
        if (file_count) memcpy(all + used, files, file_count * sizeof(*files));
        used += file_count;
        free(files);
    }
    free(groups);
    story_files_sort(all, used);
    for (size_t i = 1; i < used; i++) {
        if (strcmp(all[i - 1u].path, all[i].path) == 0) {
            free(all);
            LOG_FAIL("codeindex", "story file belongs to multiple groups");
        }
    }
    *out = all;
    *count = used;
    return true;
}

static int search_text_check_args(struct ci_store *s, const char *q,
                                  struct ci_search_hit *out, int cap)
{
    if (!s || !q || !q[0] || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to search_text");
    return 0;
}

static bool search_text_prepare(struct ci_store *s, sqlite3_stmt **stmt)
{
    static const char sql[] =
        "SELECT " CI_SYM_COLS ","
        " instr(lower(name),lower(?1))>0 AS in_name,"
        " instr(lower(signature),lower(?1))>0 AS in_signature,"
        " (instr(lower(def_path),lower(?1))>0 OR"
        "  instr(lower(decl_path),lower(?1))>0) AS in_path,"
        " instr(lower(doc),lower(?1))>0 AS in_doc,"
        " CASE WHEN lower(name)=lower(?1) THEN 0"
        "      WHEN instr(lower(name),lower(?1))=1 THEN 1"
        "      WHEN instr(lower(name),lower(?1))>0 THEN 2"
        "      WHEN instr(lower(signature),lower(?1))>0 THEN 3"
        "      WHEN instr(lower(def_path),lower(?1))>0 OR"
        "           instr(lower(decl_path),lower(?1))>0 THEN 4"
        "      ELSE 5 END AS rank"
        " FROM symbols"
        " WHERE instr(lower(name),lower(?1))>0"
        "    OR instr(lower(signature),lower(?1))>0"
        "    OR instr(lower(def_path),lower(?1))>0"
        "    OR instr(lower(decl_path),lower(?1))>0"
        "    OR instr(lower(doc),lower(?1))>0"
        " ORDER BY rank ASC,name ASC,(def_path='') ASC,def_path ASC,def_line ASC";
    sqlite3 *db = ci_store_db(s);
    return db && sqlite3_prepare_v2(db, sql, -1, stmt, NULL) == SQLITE_OK;
}

static bool search_text_fill_hit(sqlite3_stmt *stmt, struct ci_search_hit *hit)
{
    memset(hit, 0, sizeof(*hit));
    if (!ci_store_fill_symbol(stmt, &hit->symbol))
        return false;
    if (sqlite3_column_int(stmt, 12))
        hit->match_mask |= CI_SEARCH_MATCH_NAME;
    if (sqlite3_column_int(stmt, 13))
        hit->match_mask |= CI_SEARCH_MATCH_SIGNATURE;
    if (sqlite3_column_int(stmt, 14))
        hit->match_mask |= CI_SEARCH_MATCH_PATH;
    if (sqlite3_column_int(stmt, 15))
        hit->match_mask |= CI_SEARCH_MATCH_DOC;
    hit->score = 1000 - sqlite3_column_int(stmt, 16) * 100;
    return true;
}

int ci_store_search_text(struct ci_store *s, const char *q,
                         struct ci_search_hit *out, int cap)
{
    if (search_text_check_args(s, q, out, cap) < 0) return -1;
    ci_store_lock(s);
    sqlite3_stmt *stmt = NULL;
    if (!search_text_prepare(s, &stmt)) {
        ci_store_unlock(s);
        LOG_ERR("codeindex", "prepare search_text");
    }
    sqlite3_bind_text(stmt, 1, q, -1, SQLITE_TRANSIENT);
    int n = 0;
    int rc = SQLITE_DONE;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        struct ci_search_hit hit;
        if (!search_text_fill_hit(stmt, &hit))
            continue;
        out[n++] = hit;
    }
    bool ok = rc == SQLITE_ROW || rc == SQLITE_DONE;
    sqlite3_finalize(stmt);
    ci_store_unlock(s);
    if (!ok) LOG_ERR("codeindex", "step search_text");
    return n;
}

static int story_check_args(struct codeindex *ci, const char *query,
                            struct ci_story_hit *out, int cap,
                            size_t *corpus_files, bool *truncated)
{
    if (corpus_files) *corpus_files = 0;
    if (truncated) *truncated = false;
    if (!ci || !query || !query[0] || !out || cap <= 0 || !corpus_files ||
        !truncated || cap == INT_MAX)
        LOG_ERR("codeindex", "bad arg to search_story");
    return 0;
}

static bool story_index_files(struct codeindex *ci, const struct ci_file *files,
                              size_t file_count,
                              struct zcl_retrieval *retrieval)
{
    for (size_t i = 0; i < file_count; i++) {
        struct ci_symbol *symbols = NULL;
        size_t symbol_count = 0;
        if (!story_load_symbols(ci, files[i].path, &symbols, &symbol_count))
            return false;
        char *document = story_document(&files[i], symbols, symbol_count);
        free(symbols);
        if (!document || zcl_retrieval_add(
                retrieval, files[i].path, document) == 0) {
            free(document);
            return false;
        }
        free(document);
    }
    return true;
}

static bool story_copy_hits(struct zcl_retrieval *retrieval,
                            const struct zcl_retrieval_hit *hits,
                            struct ci_story_hit *out, size_t shown)
{
    for (size_t i = 0; i < shown; i++) {
        const char *path = zcl_retrieval_name(retrieval, hits[i].doc);
        int n = path ? snprintf(out[i].path, sizeof(out[i].path),
                                "%s", path) : -1;
        if (n < 0 || (size_t)n >= sizeof(out[i].path))
            return false;
        out[i].score = hits[i].score;
    }
    return true;
}

static int story_rank_hits(struct zcl_retrieval *retrieval, const char *query,
                           struct ci_story_hit *out, int cap, bool *truncated)
{
    int result = -1;
    size_t hit_cap = (size_t)cap + 1u;
    struct zcl_retrieval_hit *hits = zcl_calloc(
        hit_cap, sizeof(*hits), "codeindex story hits");
    size_t count = 0;
    if (hits && zcl_retrieval_query_checked(
            retrieval, query, hits, hit_cap, &count)) {
        *truncated = count > (size_t)cap;
        size_t shown = *truncated ? (size_t)cap : count;
        if (story_copy_hits(retrieval, hits, out, shown))
            result = (int)shown;
    }
    free(hits);
    return result;
}

int codeindex_search_story(struct codeindex *ci, const char *query,
                           struct ci_story_hit *out, int cap,
                           size_t *corpus_files, bool *truncated)
{
    if (story_check_args(ci, query, out, cap, corpus_files, truncated) < 0)
        return -1;
    struct ci_file *files = NULL;
    size_t file_count = 0;
    if (!story_collect_files(ci, &files, &file_count) || file_count == 0) {
        free(files);
        LOG_ERR("codeindex", "story file corpus is unavailable or empty");
    }
    struct zcl_retrieval *retrieval = zcl_retrieval_create();
    if (!retrieval) {
        free(files);
        LOG_ERR("codeindex", "story retrieval allocation failed");
    }
    bool indexed = story_index_files(ci, files, file_count, retrieval);
    int result = -1;
    if (indexed)
        result = story_rank_hits(retrieval, query, out, cap, truncated);
    *corpus_files = file_count;
    zcl_retrieval_destroy(retrieval);
    free(files);
    if (result < 0) LOG_ERR("codeindex", "story ranking failed");
    return result;
}

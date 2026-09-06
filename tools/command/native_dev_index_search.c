/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.index search — FTS5 MATCH over rows_fts joined back to rows. See
 * native_dev_index_search.h. Every direct sqlite3_step call here carries the
 * `// raw-sql-ok:index-store` marker for the same reason as
 * native_dev_index_ingest.c (a standalone store below the AR layer).
 */

#include "command/native_dev_index_search.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

/* Appends one word from *p (advanced past it) to out as an FTS5-quoted
 * string, doubling any embedded '"' the way FTS5's quoting requires.
 * Split out of dev_index_build_match_query so that function stays one
 * word-splitting loop plus one call. */
static void dev_index_append_quoted_word(const char **p, char *out,
                                         size_t *used, size_t out_cap)
{
    if (*used > 0 && *used + 1 < out_cap)
        out[(*used)++] = ' ';
    if (*used + 1 < out_cap)
        out[(*used)++] = '"';
    while (**p && **p != ' ' && **p != '\t' && *used + 2 < out_cap) {
        if (**p == '"') {
            out[(*used)++] = '"';
            out[(*used)++] = '"';
        } else {
            out[(*used)++] = **p;
        }
        (*p)++;
    }
    if (*used + 1 < out_cap)
        out[(*used)++] = '"';
}

/* FTS5's query syntax gives ':' a meaning (a column-name filter) our single-
 * column `doc` schema does not have, so a bare "kind:result" query would
 * fail with "no such column: kind" instead of matching the literal
 * kind:result term rows_fts was populated with. Quoting each whitespace-
 * separated word turns off every special character (column filters,
 * AND/OR/NOT, prefix `*`) for that word while still tokenizing it through
 * the same unicode61+tokenchars(':') tokenizer used at ingest time, so
 * "kind:result" quoted matches the one kind:result term literally.
 * Multiple quoted words stay implicitly ANDed, FTS5's default between
 * adjacent terms. */
static void dev_index_build_match_query(const char *query, char *out,
                                        size_t out_cap)
{
    size_t used = 0;
    const char *p = query;
    while (*p && used + 3 < out_cap) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        dev_index_append_quoted_word(&p, out, &used, out_cap);
    }
    out[used] = '\0';
}

static bool dev_index_prepare_search(sqlite3 *db, const char *match_query,
                                     const char *source_id_filter,
                                     size_t limit, sqlite3_stmt **out_st,
                                     char *err, size_t err_cap)
{
    bool has_filter = source_id_filter && source_id_filter[0];
    const char *sql =
        has_filter
            ? "SELECT r.source_id, r.ts, r.text FROM rows_fts f "
              "JOIN rows r ON r.id = f.rowid "
              "WHERE rows_fts MATCH ?1 AND r.source_id = ?2 "
              "ORDER BY r.ts DESC, r.id DESC LIMIT ?3"
            : "SELECT r.source_id, r.ts, r.text FROM rows_fts f "
              "JOIN rows r ON r.id = f.rowid "
              "WHERE rows_fts MATCH ?1 "
              "ORDER BY r.ts DESC, r.id DESC LIMIT ?2";
    if (sqlite3_prepare_v2(db, sql, -1, out_st, NULL) != SQLITE_OK) {
        if (err && err_cap)
            (void)snprintf(err, err_cap, "search prepare failed: %s",
                          sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_text(*out_st, 1, match_query, -1, SQLITE_TRANSIENT);
    if (has_filter) {
        sqlite3_bind_text(*out_st, 2, source_id_filter, -1, SQLITE_STATIC);
        sqlite3_bind_int64(*out_st, 3, (int64_t)limit);
    } else {
        sqlite3_bind_int64(*out_st, 2, (int64_t)limit);
    }
    return true;
}

static void dev_index_fill_hit(sqlite3_stmt *st,
                               struct dev_index_search_hit *hit)
{
    const unsigned char *sid = sqlite3_column_text(st, 0);
    const unsigned char *ts = sqlite3_column_text(st, 1);
    const unsigned char *text = sqlite3_column_text(st, 2);
    (void)snprintf(hit->source_id, sizeof(hit->source_id), "%s",
                  sid ? (const char *)sid : "");
    (void)snprintf(hit->ts, sizeof(hit->ts), "%s", ts ? (const char *)ts : "");
    (void)snprintf(hit->text, sizeof(hit->text), "%s",
                  text ? (const char *)text : "");
}

bool dev_index_search(sqlite3 *db, const char *query,
                      const char *source_id_filter, size_t limit,
                      struct dev_index_search_result *out, char *err,
                      size_t err_cap)
{
    memset(out, 0, sizeof(*out));
    if (!query || !query[0]) {
        if (err && err_cap)
            (void)snprintf(err, err_cap, "query must be non-empty");
        return false;
    }
    if (limit == 0)
        limit = DEV_INDEX_SEARCH_DEFAULT_LIMIT;
    if (limit > DEV_INDEX_SEARCH_MAX_HITS)
        limit = DEV_INDEX_SEARCH_MAX_HITS;

    char match_query[1024];
    dev_index_build_match_query(query, match_query, sizeof(match_query));

    sqlite3_stmt *st = NULL;
    if (!dev_index_prepare_search(db, match_query, source_id_filter, limit,
                                  &st, err, err_cap))
        return false;

    int rc;
    while (out->count < DEV_INDEX_SEARCH_MAX_HITS &&
          (rc = sqlite3_step(st)) == SQLITE_ROW) // raw-sql-ok:index-store
        dev_index_fill_hit(st, &out->hits[out->count++]);
    bool ok = rc == SQLITE_DONE || rc == SQLITE_ROW;
    if (!ok && err && err_cap)
        (void)snprintf(err, err_cap, "search query failed: %s",
                      sqlite3_errmsg(db));
    sqlite3_finalize(st);
    return ok;
}

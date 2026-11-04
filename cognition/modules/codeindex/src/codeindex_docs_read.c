/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Query the codeindex docs table for prose matching some terms and
 * the symbol table for the function enclosing a path:line. */

#include "codeindex_priv.h"
#include "codeindex/codeindex_docs.h"

#include "util/log_macros.h"

#include <sqlite3.h>

#include <ctype.h>
#include <stdint.h>
#include <string.h>

enum { DOC_MAX_TERMS = 8, DOC_TERM_MAX = 48 };

struct doc_terms {
    char word[DOC_MAX_TERMS][DOC_TERM_MAX];
    int n;
};

/* Lowercase alphanumeric/underscore runs of 2+ bytes, first DOC_MAX_TERMS. */
static void doc_split_terms(const char *text, struct doc_terms *t)
{
    memset(t, 0, sizeof(*t));
    size_t at = 0, len = strlen(text);
    while (at < len && t->n < DOC_MAX_TERMS) {
        while (at < len && !isalnum((unsigned char)text[at]) &&
               text[at] != '_')
            at++;
        size_t n = 0;
        while (at < len && (isalnum((unsigned char)text[at]) ||
                            text[at] == '_')) {
            if (n + 1 < DOC_TERM_MAX)
                t->word[t->n][n++] = (char)tolower((unsigned char)text[at]);
            at++;
        }
        t->word[t->n][n] = '\0';
        if (n >= 2) t->n++;
    }
}

static bool doc_contains(const char *haystack, const char *needle)
{
    size_t hn = strlen(haystack), nn = strlen(needle);
    for (size_t i = 0; i + nn <= hn; i++) {
        size_t j = 0;
        while (j < nn && tolower((unsigned char)haystack[i + j]) == needle[j])
            j++;
        if (j == nn) return true;
    }
    return false;
}

static int doc_score(const struct doc_terms *t, const struct ci_doc *d)
{
    int score = 0;
    for (int i = 0; i < t->n; i++) {
        score += doc_contains(d->title, t->word[i]) ? 4 : 0;
        score += doc_contains(d->path, t->word[i]) ? 3 : 0;
        score += doc_contains(d->headings, t->word[i]) ? 2 : 0;
        score += doc_contains(d->summary, t->word[i]) ? 1 : 0;
    }
    return score;
}

static bool doc_ranks_before(const struct ci_doc *a, const struct ci_doc *b)
{
    return a->score != b->score ? a->score > b->score
                                : strcmp(a->path, b->path) < 0;
}

/* Insert `d` into the best-first window out[0..*n), dropping the worst. */
static void doc_window_add(struct ci_doc *out, int *n, int cap,
                           const struct ci_doc *d)
{
    int at = *n;
    while (at > 0 && doc_ranks_before(d, &out[at - 1])) at--;
    if (at >= cap) return;
    int last = *n < cap ? *n : cap - 1;
    for (int i = last; i > at; i--) out[i] = out[i - 1];
    out[at] = *d;
    if (*n < cap) (*n)++;
}

static void doc_fill_row(sqlite3_stmt *stmt, struct ci_doc *d)
{
    memset(d, 0, sizeof(*d));
    ci_cpy(d->path, sizeof(d->path), (const char *)sqlite3_column_text(stmt, 0));
    ci_cpy(d->title, sizeof(d->title), (const char *)sqlite3_column_text(stmt, 1));
    ci_cpy(d->summary, sizeof(d->summary),
           (const char *)sqlite3_column_text(stmt, 2));
    ci_cpy(d->headings, sizeof(d->headings),
           (const char *)sqlite3_column_text(stmt, 3));
    d->line_count = sqlite3_column_int(stmt, 4);
    if (sqlite3_column_bytes(stmt, 5) == 32)
        memcpy(d->content_sha3, sqlite3_column_blob(stmt, 5), 32);
}

static void doc_mark_stale(const char *root, struct ci_doc *d)
{
    uint8_t now[32];
    d->stale = !ci_docs_hash_file(root, d->path, now) ||
               memcmp(now, d->content_sha3, sizeof(now)) != 0;
}

int codeindex_docs_match(struct codeindex *ci, const char *terms,
                         struct ci_doc *out, int cap)
{
    if (!ci || !ci->store || !terms || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to codeindex_docs_match");
    struct doc_terms t;
    doc_split_terms(terms, &t);
    if (t.n == 0) return 0;
    sqlite3 *db = ci_store_db(ci->store);
    sqlite3_stmt *stmt = NULL;
    ci_store_lock(ci->store);
    if (sqlite3_prepare_v2(db,
            "SELECT path,title,summary,headings,line_count,content_sha3 "
            "FROM docs", -1, &stmt, NULL) != SQLITE_OK) {
        ci_store_unlock(ci->store);
        LOG_ERR("codeindex", "prepare docs_match: %s", sqlite3_errmsg(db));
    }
    int n = 0, rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) { // raw-sql-ok:codeindex-derived
        struct ci_doc d;
        doc_fill_row(stmt, &d);
        d.score = doc_score(&t, &d);
        if (d.score > 0) doc_window_add(out, &n, cap, &d);
    }
    sqlite3_finalize(stmt);
    ci_store_unlock(ci->store);
    if (rc != SQLITE_DONE) LOG_ERR("codeindex", "step docs_match rc=%d", rc);
    for (int i = 0; i < n; i++) doc_mark_stale(ci->root, &out[i]);
    return n;
}

bool codeindex_symbol_at(struct codeindex *ci, const char *path, int line,
                         struct ci_symbol *out, bool *found)
{
    if (found) *found = false;
    if (!ci || !ci->store || !path || !out || !found || line < 1)
        LOG_FAIL("codeindex", "bad arg to codeindex_symbol_at");
    sqlite3 *db = ci_store_db(ci->store);
    sqlite3_stmt *stmt = NULL;
    ci_store_lock(ci->store);
    if (sqlite3_prepare_v2(db,
            "SELECT " CI_SYM_COLS " FROM symbols WHERE def_path=?1 AND "
            "kind IN ('T','t') AND def_line>0 AND def_line<=?2 AND "
            "end_line>=?2 ORDER BY def_line DESC, end_line ASC LIMIT 1", -1,
            &stmt, NULL) != SQLITE_OK) {
        ci_store_unlock(ci->store);
        LOG_FAIL("codeindex", "prepare symbol_at: %s", sqlite3_errmsg(db));
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, line);
    int rc = sqlite3_step(stmt); // raw-sql-ok:codeindex-derived
    bool ok = rc == SQLITE_DONE;
    if (rc == SQLITE_ROW) {
        ok = true;
        *found = ci_store_fill_symbol(stmt, out);
    }
    sqlite3_finalize(stmt);
    ci_store_unlock(ci->store);
    if (!ok) LOG_FAIL("codeindex", "step symbol_at rc=%d", rc);
    return true;
}

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The mutation-surface census engine: re-derives, per durable named slot,
 * each source mutation site the declared derivations can resolve. The three
 * derivations are mechanical and stated in
 * controllers/fact_store_writers.def and nowhere else:
 *
 *   API writers    — call sites of the store's declared write entry points
 *                    (located through cognition/modules/codeindex refs), keyed by whichever
 *                    string literal or string-valued macro the call passes.
 *   RAW writers    — a SQL mutation statement naming the store's table, keyed by
 *                    the literal in its `<key_column>=` / `IN (...)` predicate or
 *                    its `VALUES('<key>',…)` clause. These are the paths that
 *                    BYPASS the declared API, which is where an unreviewed
 *                    mutation surface hides.
 *   LOCAL wrappers — a mutation whose key was BOUND carries no name, so the
 *                    function enclosing it is read out of the file and treated
 *                    as that file's own write entry point; its same-file call
 *                    sites then resolve normally.
 *
 * Nothing is remembered between runs: no store, no baseline, no recorded set
 * of known findings. The answer is a pure function of the tree. The answer is
 * reachability evidence, not an ownership verdict: target database, execution
 * role, serialization, and capability transfer are outside this analyzer.
 */

#define _GNU_SOURCE
#include "fact_writers_priv.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "codeindex/codeindex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── accumulator ────────────────────────────────────────────────────────── */

struct fw_acc {
    struct fact_writers_report *rep;
    struct fw_macros macros;
    int comment_skips;
};

static struct fact_store_stat *fw_stat(struct fw_acc *a, const char *store)
{
    for (int i = 0; i < a->rep->n_stores; i++)
        if (strcmp(a->rep->stores[i].store, store) == 0)
            return &a->rep->stores[i];
    if (a->rep->n_stores >= FACT_STORES_MAX) return NULL;
    struct fact_store_stat *s = &a->rep->stores[a->rep->n_stores++];
    snprintf(s->store, sizeof(s->store), "%s", store);
    return s;
}

/* One site that could not be resolved to a key, against its store and the report. */
static void fw_count_unresolved(struct fw_acc *a, struct fact_store_stat *st)
{
    if (st) st->sites_unresolved++;
    a->rep->sites_unresolved++;
}

/* Record one writer of one slot, creating the slot's row on first sight. */
static bool fw_add_site(struct fw_acc *a, const char *store, const char *key,
                       const char *path, int line, const char *via_name,
                       enum fact_write_via via)
{
    struct fact_writers_report *r = a->rep;
    struct fact_row *row = NULL;
    for (int i = 0; i < r->n_rows; i++)
        if (strcmp(r->rows[i].store, store) == 0 &&
            strcmp(r->rows[i].key, key) == 0) { row = &r->rows[i]; break; }
    if (!row) {
        if (r->n_rows >= FACT_ROWS_MAX) { r->rows_dropped++; return true; }
        row = &r->rows[r->n_rows++];
        snprintf(row->store, sizeof(row->store), "%s", store);
        snprintf(row->key, sizeof(row->key), "%s", key);
    }
    /* Same (path,line,via_name) can be reached twice when a joined window
     * overlaps; a repeat is not a second writer. */
    for (int i = 0; i < row->n_sites; i++)
        if (row->sites[i].line == line &&
            strcmp(row->sites[i].path, path) == 0 &&
            strcmp(row->sites[i].via_name, via_name) == 0)
            return true;
    row->writer_sites++;
    r->sites_total++;
    bool new_file = true;
    for (int i = 0; i < row->n_sites; i++)
        if (strcmp(row->sites[i].path, path) == 0) { new_file = false; break; }
    /* writer_files is counted from the RENDERED site list, so it is exact only
     * while the list is not truncated; the truncation flag says so. */
    if (new_file) row->writer_files++;
    if (row->n_sites < FACT_SITES_PER_FACT) {
        struct fact_writer_site *s = &row->sites[row->n_sites++];
        snprintf(s->path, sizeof(s->path), "%s", path);
        s->line = line;
        snprintf(s->via_name, sizeof(s->via_name), "%s", via_name);
        s->via = via;
    } else {
        row->sites_truncated = true;
    }
    struct fact_store_stat *st = fw_stat(a, store);
    if (st) st->sites_resolved++;
    return true;
}

/* Append `src` to buf[*o] (at most cap-1 bytes in all), then one separating
 * space, keeping buf NUL-terminated at *o. */
static void fw_append_piece(char *buf, size_t *o, size_t cap, const char *src)
{
    for (const char *q = src; *q && *o + 2 < cap; q++)
        buf[(*o)++] = *q;
    if (*o + 1 < cap) buf[(*o)++] = ' ';
    buf[*o] = '\0';
}

/* ── raw-SQL writers ────────────────────────────────────────────────────── */

static const char *const fw_sql_verbs[] = { "INSERT", "REPLACE", "UPDATE",
                                            "DELETE" };

/* The first mutation verb a source line carries, or NULL. */
static const char *fw_line_sql_verb(const char *line)
{
    for (size_t v = 0; v < sizeof(fw_sql_verbs) / sizeof(fw_sql_verbs[0]); v++)
        if (fw_find_word(line, fw_sql_verbs[v], 0) >= 0)
            return fw_sql_verbs[v];
    return NULL;
}

/* Copy the key literal that starts at `p` (just past its opening quote) into
 * key, stopping at the closing quote, the end of the text, or the buffer's
 * capacity. A closing quote is consumed; the result points past it. */
static const char *fw_take_key(const char *p, char *key, size_t cap)
{
    size_t k = 0;
    while (*p && *p != '\'' && k + 1 < cap) key[k++] = *p++;
    key[k] = '\0';
    if (*p == '\'') p++;
    return p;
}

/* A raw statement being attributed: its store row, the place it sits, and the
 * verb that mutates. */
struct fw_stmt {
    struct fw_acc *a;
    const struct fw_store_row *sr;
    const char *path;
    int line;
    const char *verb;
};

/* Record one literal key of a raw statement; 1 when it named a plausible slot. */
static int fw_note_raw_key(const struct fw_stmt *st, const char *key)
{
    if (!fw_key_plausible(key)) return 0;
    (void)fw_add_site(st->a, st->sr->store, key, st->path, st->line, st->verb,
                      FACT_VIA_RAW_SQL);
    return 1;
}

/* `<key_column> = '<key>'`: p points just past the '='. */
static int fw_sql_eq_key(const struct fw_stmt *st, const char *p)
{
    while (*p == ' ') p++;
    if (*p != '\'') return 0;
    char key[FACT_KEY_MAX];
    (void)fw_take_key(p + 1, key, sizeof(key));
    return fw_note_raw_key(st, key);
}

/* True when p opens the SQL keyword IN as a whole word. */
static bool fw_at_in_keyword(const char *p)
{
    return (p[0] == 'I' || p[0] == 'i') && (p[1] == 'N' || p[1] == 'n') &&
           !fw_ident_char(p[2]);
}

/* `<key_column> IN ('<key>', ...)`: p points just past the IN keyword. */
static int fw_sql_in_keys(const struct fw_stmt *st, const char *p)
{
    int found = 0;
    while (*p == ' ') p++;
    if (*p != '(') return 0;
    p++;
    while (*p && *p != ')') {
        if (*p != '\'') { p++; continue; }
        char key[FACT_KEY_MAX];
        p = fw_take_key(p + 1, key, sizeof(key));
        found += fw_note_raw_key(st, key);
    }
    return found;
}

/* An INSERT spells its key in the VALUES clause, not in a predicate:
 *   INSERT OR REPLACE INTO node_state(key,value) VALUES('utxo_commitment',?)
 * Recognised only when the column list OPENS with the key column, so the
 * first quoted literal after VALUES is that column's value. */
static int fw_sql_values_key(const struct fw_stmt *st, const char *sql)
{
    char open_col[FACT_KEY_MAX];
    (void)snprintf(open_col, sizeof(open_col), "(%s,", st->sr->key_column);
    const char *cols = strstr(sql, open_col);
    const char *values = cols ? strstr(cols, "VALUES") : NULL;
    if (!values) return 0;
    const char *p = values + 6;
    while (*p && *p != '\'' && *p != ';') {
        if (*p == ')') break;
        p++;
    }
    if (*p != '\'') return 0;
    char key[FACT_KEY_MAX];
    (void)fw_take_key(p + 1, key, sizeof(key));
    return fw_note_raw_key(st, key);
}

/* ── file-local keyed wrappers ───────────────────────────────────────────
 *
 * A raw mutation whose key is a bound `?` parameter hides its slot from both
 * derivations above — the SQL text carries no name, and the enclosing helper is
 * not a declared entry point. Those helpers exist (a snapshot builder writes
 * seven progress_meta slots through one local `insert_meta_blob`), so the
 * census discovers them instead of shrugging: the function ENCLOSING a
 * bound-key mutation of a store table, if it takes a `const char *` parameter,
 * IS that file's own write entry point, and its call sites in the same file are
 * writers. Nothing about which helpers exist is written down; the enclosing
 * function's name is read out of the file being scanned. */

struct fw_wrapper {
    char fn[FW_MACRO_NAME_MAX];
    const struct fw_store_row *store;
    int key_arg;
};

enum { FW_WRAPPERS_PER_FILE = 8 };

struct fw_wrappers {
    struct fw_wrapper v[FW_WRAPPERS_PER_FILE];
    int n;
};

/* A line that cannot open a definition, so the backward scan steps over it.
 * The opening brace of a body sits at column 0 too, hence the braces. */
static bool fw_decl_skip_line(const char *line)
{
    return line[0] == '\0' || (unsigned char)line[0] <= ' ' || line[0] == '#' ||
           line[0] == '}' || line[0] == '{' || line[0] == ')' ||
           line[0] == '/' || line[0] == '*';
}

/* The nearest line at or above `ln` that can open a definition; 0 when none. */
static size_t fw_decl_start(const struct fw_file *f, size_t ln)
{
    for (size_t back = ln; back > 0; back--) {
        char line[1024];
        fw_file_line(f, back, line, sizeof(line));
        if (!fw_decl_skip_line(line)) return back;
    }
    return 0;
}

/* Join up to 8 raw lines from `back` into one string, through the line that
 * closes the parameter list, so a multi-line signature is one string. */
static void fw_join_decl(const struct fw_file *f, size_t back, char *decl,
                         size_t cap)
{
    size_t o = 0;
    decl[0] = '\0';
    for (size_t i = 0; i < 8 && back + i <= f->nlines; i++) {
        char cur[1024];
        fw_file_line(f, back + i, cur, sizeof(cur));
        fw_append_piece(decl, &o, cap, cur);
        if (strchr(cur, ')')) break;
    }
}

/* The function name in a joined declaration: the identifier left of its first
 * '('. false when there is no '(', the name is empty or too long, or nothing
 * (no return type) precedes it, which marks a bare call rather than a definition. */
static bool fw_decl_fn_name(const char *decl, char *fn, size_t cap)
{
    const char *open = strchr(decl, '(');
    if (!open) return false;
    const char *e = open;
    while (e > decl && (unsigned char)e[-1] <= ' ') e--;
    const char *s = e;
    while (s > decl && fw_ident_char(s[-1])) s--;
    size_t nlen = (size_t)(e - s);
    if (nlen == 0 || nlen >= cap) return false;
    if (s == decl) return false;         /* no return type: a bare call */
    memcpy(fn, s, nlen);
    fn[nlen] = '\0';
    return true;
}

/* Register `fn` as this file's keyed write entry point for `sr`, unless it is
 * already registered or is a declared API of the store. */
static void fw_wrapper_add(struct fw_wrappers *ws,
                           const struct fw_store_row *sr, const char *fn,
                           int idx)
{
    for (int i = 0; i < ws->n; i++)
        if (strcmp(ws->v[i].fn, fn) == 0) return;
    if (fw_api_claimed(sr->store, fn)) return;   /* already a declared API */
    snprintf(ws->v[ws->n].fn, FW_MACRO_NAME_MAX, "%s", fn);
    ws->v[ws->n].store = sr;
    ws->v[ws->n].key_arg = idx;
    ws->n++;
}

/* Walk back from `ln` to the nearest function definition opening at column 0,
 * and register it as this file's keyed write entry point for `sr`. */
static void fw_wrapper_discover(struct fw_wrappers *ws,
                                const struct fw_store_row *sr,
                                const struct fw_file *f, size_t ln)
{
    if (ws->n >= FW_WRAPPERS_PER_FILE) return;
    size_t back = fw_decl_start(f, ln);
    if (back == 0) return;
    char decl[1024];
    fw_join_decl(f, back, decl, sizeof(decl));
    char fn[FW_MACRO_NAME_MAX];
    if (!fw_decl_fn_name(decl, fn, sizeof(fn))) return;
    int idx = fw_key_param_index(decl);
    if (idx < 0) return;
    fw_wrapper_add(ws, sr, fn, idx);
}

/* Pull every literal key out of `sql` for the given key column and record it. */
static void fw_sql_keys(struct fw_acc *a, const struct fw_store_row *sr,
                        const char *sql, const char *path, int line,
                        const char *verb, struct fw_wrappers *ws,
                        const struct fw_file *f)
{
    struct fw_stmt st = { .a = a, .sr = sr, .path = path, .line = line,
                          .verb = verb };
    int found = 0;
    long at = 0;
    while ((at = fw_find_word(sql, sr->key_column, at)) >= 0) {
        const char *p = sql + at + strlen(sr->key_column);
        at += 1;
        while (*p == ' ') p++;
        if (*p == '=') found += fw_sql_eq_key(&st, p + 1);
        else if (fw_at_in_keyword(p)) found += fw_sql_in_keys(&st, p + 2);
    }
    found += fw_sql_values_key(&st, sql);

    if (found == 0) {
        fw_count_unresolved(a, fw_stat(a, sr->store));
        /* The key was bound, not spelled: the enclosing helper is this file's
         * own write entry point. Find it so its callers ARE attributed. */
        if (ws && f) fw_wrapper_discover(ws, sr, f, (size_t)line);
    }
}

/* The key a call passes as argument `key_arg` of `fn` in `joined`, resolved to
 * its string and plausible; false when any of those steps fails. */
static bool fw_call_key(const char *joined, const char *fn, int key_arg,
                        const struct fw_macros *m, char *key, size_t cap)
{
    char argtext[512];
    return fw_call_arg(joined, fn, key_arg, argtext, sizeof(argtext)) &&
           fw_resolve_key(argtext, m, key, cap) &&
           fw_key_plausible(key);
}

/* Attribute call sites of a discovered file-local wrapper. */
static void fw_scan_wrapper_calls(struct fw_acc *a, const struct fw_file *f,
                                  const char *path,
                                  const struct fw_wrappers *ws)
{
    for (int w = 0; w < ws->n; w++) {
        const struct fw_wrapper *wr = &ws->v[w];
        for (size_t ln = 1; ln <= f->nlines; ln++) {
            char line[1024];
            fw_file_line(f, ln, line, sizeof(line));
            if (fw_comment_line(line)) continue;
            if (fw_find_word(line, wr->fn, 0) < 0) continue;
            char joined[4096];
            fw_join_call(f, ln, joined, sizeof(joined));
            char key[FACT_KEY_MAX];
            if (!fw_call_key(joined, wr->fn, wr->key_arg, &a->macros,
                             key, sizeof(key)))
                continue;   /* the definition line and reads land here */
            (void)fw_add_site(a, wr->store->store, key, path, (int)ln, wr->fn,
                              FACT_VIA_API);
        }
    }
}

/* Append the string-literal content of one source line to the statement in sql. */
static void fw_append_literals(struct fw_acc *a, const char *cur, char *sql,
                               size_t *o, size_t cap)
{
    for (const char *p = cur; *p; ) {
        if (*p != '"') { p++; continue; }
        char piece[1024];
        p = fw_join_literals(p, &a->macros, piece, sizeof(piece));
        fw_append_piece(sql, o, cap, piece);
    }
}

/* Accumulate the string-literal CONTENT of the statement starting at `ln`: this
 * line, plus continuation lines until one carries the terminating ';'. */
static void fw_collect_statement(struct fw_acc *a, const struct fw_file *f,
                                 size_t ln, char *sql, size_t cap)
{
    size_t o = 0;
    sql[0] = '\0';
    for (size_t i = 0; i < FW_SQL_WINDOW && ln + i <= f->nlines; i++) {
        char cur[1024];
        fw_file_line(f, ln + i, cur, sizeof(cur));
        fw_append_literals(a, cur, sql, &o, cap);
        if (strchr(cur, ';')) break;
    }
}

static void fw_scan_raw_sql(struct fw_acc *a, const struct fw_file *f,
                            const char *path)
{
    struct fw_wrappers wrappers = {0};
    char line[1024];
    for (size_t ln = 1; ln <= f->nlines; ln++) {
        fw_file_line(f, ln, line, sizeof(line));
        if (fw_comment_line(line)) continue;
        const char *verb = fw_line_sql_verb(line);
        if (!verb) continue;
        char sql[2048];
        fw_collect_statement(a, f, ln, sql, sizeof(sql));
        if (sql[0] == '\0') continue;
        if (fw_find_word(sql, verb, 0) < 0) continue;
        size_t nstores = 0;
        const struct fw_store_row *stores = fw_store_rows(&nstores);
        for (size_t s = 0; s < nstores; s++) {
            if (fw_find_word(sql, stores[s].table, 0) < 0) continue;
            fw_sql_keys(a, &stores[s], sql, path, (int)ln, verb, &wrappers, f);
        }
    }
    if (wrappers.n > 0) fw_scan_wrapper_calls(a, f, path, &wrappers);
}

/* ── file list, taken from the code index's own enumeration ─────────────── */

struct fw_paths {
    char (*v)[FACT_PATH_MAX];
    size_t n, cap;
};

static bool fw_paths_push(struct fw_paths *ps, const char *p)
{
    if (strncmp(p, "tests/harness/include/test/", 9) == 0) return true;   /* fixtures excluded */
    size_t path_len = strlen(p);
    if (path_len >= FACT_PATH_MAX)
        return false;
    if (ps->n == ps->cap) {
        size_t ncap = ps->cap ? ps->cap * 2 : 1024;
        char (*nb)[FACT_PATH_MAX] = zcl_realloc(ps->v, ncap * FACT_PATH_MAX,
                                                "fw_paths");
        if (!nb) LOG_FAIL(FW_DOMAIN, "grow path list");
        ps->v = nb;
        ps->cap = ncap;
    }
    memcpy(ps->v[ps->n], p, path_len + 1);
    ps->n++;
    return true;
}

static int fw_path_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static bool fw_collect_paths(struct codeindex *ci, struct fw_paths *ps)
{
    static struct ci_group groups[768];
    int ng = codeindex_groups(ci, groups, (int)(sizeof(groups) / sizeof(groups[0])));
    if (ng < 0) LOG_FAIL(FW_DOMAIN, "codeindex_groups failed");
    static struct ci_file files[4096];
    for (int g = 0; g < ng; g++) {
        int nf = codeindex_files_in_group(ci, groups[g].path, files,
                                         (int)(sizeof(files) / sizeof(files[0])));
        if (nf < 0) LOG_FAIL(FW_DOMAIN, "files_in_group(%s)", groups[g].path);
        for (int i = 0; i < nf; i++)
            if (!fw_paths_push(ps, files[i].path)) return false;
    }
    if (ps->n == 0) LOG_FAIL(FW_DOMAIN, "code index yielded no files");
    qsort(ps->v, ps->n, FACT_PATH_MAX, fw_path_cmp);
    /* de-dup (a file stamped into two groups would otherwise be read twice) */
    size_t w = 1;
    for (size_t i = 1; i < ps->n; i++)
        if (strcmp(ps->v[i], ps->v[w - 1]) != 0)
            memmove(ps->v[w++], ps->v[i], FACT_PATH_MAX);
    ps->n = w;
    return true;
}

/* ── API writers, located through codeindex refs ────────────────────────── */

struct fw_ref {
    char path[FACT_PATH_MAX];
    int line;
    int api;                /* index into fw_api_rows() */
};

static int fw_ref_cmp(const void *a, const void *b)
{
    const struct fw_ref *x = a, *y = b;
    int c = strcmp(x->path, y->path);
    if (c) return c;
    if (x->line != y->line) return x->line < y->line ? -1 : 1;
    return x->api - y->api;
}

/* Append one collected ref; false when the list cannot grow, with *all and
 * *cap left as they were. */
static bool fw_refs_push(struct fw_ref **all, size_t *n, size_t *cap,
                         const char *path, int line, int api)
{
    if (*n == *cap) {
        size_t ncap = *cap ? *cap * 2 : 512;
        struct fw_ref *nb = zcl_realloc(*all, ncap * sizeof(*nb), "fw_refs");
        if (!nb) return false;
        *all = nb;
        *cap = ncap;
    }
    struct fw_ref *r = &(*all)[*n];
    snprintf(r->path, sizeof(r->path), "%s", path);
    r->line = line;
    r->api = api;
    (*n)++;
    return true;
}

/* Attribute one API call site: its key is the store's declared key argument. */
static void fw_scan_api_ref(struct fw_acc *a, const struct fw_file *f,
                            const struct fw_ref *ref,
                            const struct fw_api_row *api)
{
    char line[1024];
    fw_file_line(f, (size_t)ref->line, line, sizeof(line));
    if (fw_comment_line(line)) { a->comment_skips++; return; }
    char joined[4096];
    fw_join_call(f, (size_t)ref->line, joined, sizeof(joined));
    struct fact_store_stat *st = fw_stat(a, api->store);
    char key[FACT_KEY_MAX];
    if (!fw_call_key(joined, api->fn, api->key_arg, &a->macros,
                     key, sizeof(key))) {
        fw_count_unresolved(a, st);
        return;
    }
    (void)fw_add_site(a, api->store, key, ref->path, ref->line, api->fn,
                      FACT_VIA_API);
}

/* Attribute the n refs of one file, which is read once for all of them. */
static void fw_scan_api_group(struct fw_acc *a, const char *root,
                              const struct fw_api_row *apis,
                              const struct fw_ref *refs, size_t n)
{
    struct fw_file f;
    if (!fw_file_load(root, refs[0].path, &f)) return;
    for (size_t k = 0; k < n; k++)
        fw_scan_api_ref(a, &f, &refs[k], &apis[refs[k].api]);
    fw_file_free(&f);
}

/* Group the sorted refs by file, and attribute each group. */
static void fw_scan_api_files(struct fw_acc *a, const char *root,
                              const struct fw_api_row *apis,
                              const struct fw_ref *all, size_t n)
{
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && strcmp(all[j].path, all[i].path) == 0) j++;
        fw_scan_api_group(a, root, apis, &all[i], j - i);
        i = j;
    }
}

static bool fw_scan_api_writers(struct fw_acc *a, const char *root,
                                struct codeindex *ci)
{
    static struct ci_ref refs[2048];
    struct fw_ref *all = NULL;
    size_t n = 0, cap = 0;
    size_t napis = 0;
    const struct fw_api_row *apis = fw_api_rows(&napis);
    for (size_t i = 0; i < napis; i++) {
        int nr = codeindex_refs(ci, apis[i].fn, refs,
                                (int)(sizeof(refs) / sizeof(refs[0])));
        if (nr < 0) { free(all); LOG_FAIL(FW_DOMAIN, "refs(%s)", apis[i].fn); }
        for (int r = 0; r < nr; r++) {
            if (strncmp(refs[r].ref_file, "tests/harness/include/test/", 9) == 0) continue;
            if (!fw_refs_push(&all, &n, &cap, refs[r].ref_file,
                              refs[r].ref_line, (int)i)) {
                free(all);
                LOG_FAIL(FW_DOMAIN, "grow refs");
            }
        }
    }
    if (n > 1) qsort(all, n, sizeof(*all), fw_ref_cmp);
    fw_scan_api_files(a, root, apis, all, n);
    free(all);
    return true;
}

/* ── report assembly ────────────────────────────────────────────────────── */

static int fw_row_cmp(const void *a, const void *b)
{
    const struct fact_row *x = a, *y = b;
    if (x->writer_files != y->writer_files)
        return y->writer_files - x->writer_files;
    if (x->writer_sites != y->writer_sites)
        return y->writer_sites - x->writer_sites;
    int c = strcmp(x->store, y->store);
    if (c) return c;
    return strcmp(x->key, y->key);
}

struct fw_loaded_file {
    struct fw_file file;
    const char *path;
};

/* Raw-store discovery only recognizes these canonical uppercase SQL verbs.
 * Retain that small candidate set after the macro pass so pass 2 does not
 * reopen and re-index every source file in the repository. False positives
 * cost memory for one call; false negatives would hide a writer, so this gate
 * deliberately tests only the verb and leaves table/key filtering to the
 * existing scanner. */
static bool fw_file_may_have_raw_writer(const struct fw_file *file)
{
    if (!file || !file->buf)
        return false;
    for (size_t i = 0;
         i < sizeof(fw_sql_verbs) / sizeof(fw_sql_verbs[0]); i++)
        if (strstr(file->buf, fw_sql_verbs[i]))
            return true;
    return false;
}

static void fw_loaded_files_free(struct fw_loaded_file *files, size_t count)
{
    if (!files)
        return;
    for (size_t i = 0; i < count; i++)
        fw_file_free(&files[i].file);
    free(files);
}

/* Pass 1: harvest the string-valued macros from every file, and keep each raw-SQL
 * candidate, indexed, in sql_files; *n_sql_files counts those kept. false on the
 * first failure, with the file in hand already released; the caller releases the
 * candidates kept so far. */
static bool fw_scan_macro_pass(struct fw_acc *a, const char *root,
                               const struct fw_paths *paths,
                               struct fw_loaded_file *sql_files,
                               size_t *n_sql_files)
{
    for (size_t i = 0; i < paths->n; i++) {
        struct fw_file f;
        if (!fw_file_load_unindexed(root, paths->v[i], &f)) continue;
        if (!fw_collect_macros(&f, &a->macros)) {
            fw_file_free(&f);
            return false;
        }
        if (!fw_file_may_have_raw_writer(&f)) {
            fw_file_free(&f);
            continue;
        }
        if (!fw_file_index_lines(&f)) {
            fw_file_free(&f);
            return false;
        }
        sql_files[*n_sql_files].file = f;
        sql_files[*n_sql_files].path = paths->v[i];
        (*n_sql_files)++;
    }
    return true;
}

/* Sort the rows into report order, then total the facts and their multi-writer
 * counts, overall and per store. */
static void fw_finish_report(struct fw_acc *a)
{
    struct fact_writers_report *rep = a->rep;
    if (rep->n_rows > 1)
        qsort(rep->rows, (size_t)rep->n_rows, sizeof(rep->rows[0]), fw_row_cmp);
    rep->facts_total = rep->n_rows;
    for (int i = 0; i < rep->n_rows; i++) {
        struct fact_store_stat *st = fw_stat(a, rep->rows[i].store);
        if (st) st->facts++;
        if (rep->rows[i].writer_files > 1) {
            rep->facts_multi_writer++;
            if (st) st->facts_multi_writer++;
        }
    }
}

struct fact_writers_report *fact_writers_analyze(const char *root,
                                                 struct codeindex *ci)
{
    if (!root || !ci) LOG_NULL(FW_DOMAIN, "null arg to analyze");
    struct fact_writers_report *rep = zcl_calloc(1, sizeof(*rep), "fw_report");
    if (!rep) LOG_NULL(FW_DOMAIN, "alloc report (%zu bytes)", sizeof(*rep));
    struct fw_acc acc = { .rep = rep };

    struct fw_paths paths = {0};
    if (!fw_collect_paths(ci, &paths)) goto fail;
    rep->files_scanned = (int)paths.n;
    struct fw_loaded_file *sql_files = zcl_calloc(
        paths.n, sizeof(*sql_files), "fw_sql_candidates");
    size_t n_sql_files = 0;
    if (!sql_files) goto fail;

    /* Pass 1: the string-valued macro table must be complete before any key is
     * resolved, so it is built over the whole tree first. The macro harvest is
     * a sequential whole-buffer walk and does not need a line index. Build
     * line offsets only for the much smaller raw-SQL candidate set retained by
     * pass 2; indexing every one of the 2,700+ files made this command miss its
     * latency contract under parallel CI load. */
    if (!fw_scan_macro_pass(&acc, root, &paths, sql_files, &n_sql_files))
        goto fail_loaded;

    /* Pass 2: raw-SQL writers over the retained candidate set. */
    for (size_t i = 0; i < n_sql_files; i++)
        fw_scan_raw_sql(&acc, &sql_files[i].file, sql_files[i].path);
    fw_loaded_files_free(sql_files, n_sql_files);
    sql_files = NULL;
    n_sql_files = 0;

    /* Pass 3: API writers, addressed by codeindex refs. */
    if (!fw_scan_api_writers(&acc, root, ci)) goto fail;

    fw_finish_report(&acc);

    free(paths.v);
    free(acc.macros.v);
    return rep;

fail_loaded:
    fw_loaded_files_free(sql_files, n_sql_files);
fail:
    free(paths.v);
    free(acc.macros.v);
    free(rep);
    return NULL;
}

void fact_writers_report_free(struct fact_writers_report *report)
{
    free(report);
}

const struct fact_row *fact_writers_find(const struct fact_writers_report *r,
                                         const char *store, const char *key)
{
    if (!r || !key) return NULL;
    for (int i = 0; i < r->n_rows; i++) {
        if (store && strcmp(r->rows[i].store, store) != 0) continue;
        if (strcmp(r->rows[i].key, key) == 0) return &r->rows[i];
    }
    return NULL;
}

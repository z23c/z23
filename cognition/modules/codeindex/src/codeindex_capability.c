/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: rank in-tree CAPABILITIES for a concept query, and derive the
 * exists/partial/absent verdict from the same evidence the caller renders.
 *
 * Contract, rationale, and the honest limits are in
 * include/codeindex/codeindex_capability.h. This file is the mechanism:
 * stemming, the two candidate scans, anchor aggregation, the usage count, and
 * the verdict thresholds.
 *
 * Cost shape. Both candidate scans push their matching into SQLite's
 * case-insensitive LIKE operator so the 69k symbol rows and 6.3k file rows are
 * filtered in C without being marshalled out. This avoids recomputing
 * lower(column) for every query stem while retaining ASCII case folding; only
 * rows that matched a stem cross into this file. The expensive per-candidate
 * step is the usage count, so it runs for the top CI_CAP_RANK_POOL anchors
 * only, AFTER the cheap score has ordered them — then the pool is re-ranked
 * with the usage number in hand, because "how many files actually call this"
 * is the fact the caller came for.
 */

#include "codeindex_priv.h"
#include "codeindex/codeindex_capability.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>

/* Anchors held while ranking. Beyond this the scan stops admitting NEW
 * anchors and sets q->truncated; it never silently drops evidence for an
 * anchor already admitted. */
#define CI_CAP_ANCHOR_CAP 4096
/* Anchors that pay for a usage count and are then re-ranked by it.
 *
 * This is the number that decides whether the RIGHT answer is even eligible to
 * win. The cheap score saturates: a broad query like "validation" leaves
 * dozens of anchors tied at the symbol-name ceiling, and at a pool of 8 the
 * tie was broken alphabetically — which put three block-validation stages on
 * the podium and left the ActiveRecord validation macros, used by twice as
 * many files, outside the pool entirely. The usage count is what actually
 * separates them, so the pool has to be wide enough for it to do its job. */
#define CI_CAP_RANK_POOL  24

/* Score weights. Named so the ranking is readable rather than a pile of
 * integers: a matched symbol NAME is the strongest single signal, a matched
 * file purpose is next, and doc-comment matches are supporting evidence that
 * must not let one enormous well-documented file outrank a small exact one. */
enum {
    CI_W_SYM_NAME      = 25,   /* per symbol whose name matched */
    CI_W_SYM_NAME_CAP  = 600,
    CI_W_SYM_DOC       = 4,    /* per symbol whose doc/signature matched */
    CI_W_SYM_DOC_CAP   = 60,
    CI_W_FILE_PURPOSE  = 60,   /* per distinct stem found in the purpose */
    CI_W_FILE_PATH     = 50,   /* per distinct stem found in the path */
    CI_W_FILE_GROUP    = 15,   /* per distinct stem found in the group id */
    /* A header is an API; a .c is an implementation. The caller is deciding
     * what to REUSE, and what you reuse is the thing you can include. */
    CI_W_HEADER        = 100,
};

/* Verdict thresholds. One place, read by both the per-candidate confidence
 * and the overall verdict, so the two cannot drift apart. */
enum {
    CI_CONF_HIGH_MIN_USERS = 3,
    CI_CONF_MED_MIN_USERS  = 1,
};

struct cap_anchor {
    char     path[256];
    char     group[64];
    uint32_t name_mask;      /* stems found in some symbol NAME here */
    uint32_t doc_mask;       /* stems found in some symbol doc/signature */
    uint32_t purpose_mask;   /* stems found in the file purpose */
    uint32_t path_mask;      /* stems found in the repo path */
    uint32_t group_mask;     /* stems found in the group id */
    int      name_hits;
    int      doc_hits;
    int      syms_listed;
    char     last_name[128];   /* dedupe of adjacent equal names */
    char     syms[CI_CAPABILITY_SYMBOL_CAP][128];
};

/* Open-addressed path → anchor index. Without it the lookup is a linear walk
 * of every admitted anchor for every matched row, which on a broad query is
 * millions of strcmp() and is the difference between this leaf being reflexive
 * and being something nobody calls twice. Power of two, load factor 1/2. */
#define CI_CAP_SLOTS (CI_CAP_ANCHOR_CAP * 2)

struct cap_scan {
    struct cap_anchor *a;
    int                n;
    int                cap;
    bool               truncated;
    int               *slot;      /* CI_CAP_SLOTS entries; -1 == empty */
};

static uint32_t cap_hash(const char *s)
{
    uint32_t h = 2166136261u;               /* FNV-1a */
    for (; *s; s++) { h ^= (unsigned char)*s; h *= 16777619u; }
    return h;
}

/* ── stemming ─────────────────────────────────────────────────────────── */

static const char *const cap_stopwords[] = {
    "a", "an", "the", "of", "for", "to", "in", "on", "and", "or", "do",
    "does", "is", "are", "it", "that", "this", "any", "we", "have", "has",
    "already", "something", "anything", "with", "my", "our", "some", "be",
    NULL,
};

static bool cap_is_stopword(const char *w)
{
    for (size_t i = 0; cap_stopwords[i]; i++)
        if (strcmp(w, cap_stopwords[i]) == 0) return true;
    return false;
}

/* Suffix table, longest first. Each entry strips `drop` bytes; a strip that
 * would leave fewer than three characters is refused, because a two-letter
 * stem matches most of the tree and is worse than no reduction at all.
 *
 * "ation" strips five rather than three deliberately: "validation" → "valid"
 * reaches `validates_*` and `validate_*` alike, where "validat" would reach
 * only the first, and "serialization" → "serializ" reaches `serialize` where
 * "serializat" reaches nothing. */
static const struct { const char *suf; size_t drop; } cap_suffixes[] = {
    { "ations", 6 }, { "ation", 5 },
    { "ments",  5 }, { "ment",  4 },
    { "ions",   4 }, { "ion",   3 },
    { "ings",   4 }, { "ing",   3 },
    { "ness",   4 },
    { "ies",    3 },
    { "ers",    3 }, { "ors",   3 },
    { "er",     2 },
    { "ed",     2 }, { "es",    2 }, { "s", 1 },
    { NULL,     0 },
};

void ci_capability_stem(char *word)
{
    if (!word) return;
    size_t n = strlen(word);
    bool stripped = false;
    for (size_t i = 0; cap_suffixes[i].suf; i++) {
        size_t sl = strlen(cap_suffixes[i].suf);
        if (n <= sl) continue;
        if (strcmp(word + n - sl, cap_suffixes[i].suf) != 0) continue;
        size_t left = n - cap_suffixes[i].drop;
        if (left < 3) continue;      /* refuse: too short to discriminate */
        word[left] = '\0';
        n = left;
        stripped = true;
        break;
    }
    /* "logging" → "logg" → "log": a strip commonly exposes the consonant
     * English doubled before the suffix. Collapse it so the stem matches the
     * base word it came from.
     *
     * ONLY after a strip. A word that kept its own ending keeps its own
     * spelling — collapsing unconditionally would turn "full" into "ful" and
     * "buzz" into "buz", changing words the query never suffixed. */
    if (stripped && n > 3 && word[n - 1] == word[n - 2] &&
        !strchr("aeiou", word[n - 1]))
        word[n - 1] = '\0';
}

/* Split `text` into at most CI_CAPABILITY_TERM_CAP stems. Returns the count. */
static int cap_terms(const char *text, struct ci_capability_query *q)
{
    q->term_count = 0;
    q->terms_dropped = 0;
    const char *p = text;
    while (*p) {
        while (*p && !isalnum((unsigned char)*p)) p++;
        if (!*p) break;
        char word[CI_CAPABILITY_TERM_MAX];
        size_t k = 0;
        while (*p && (isalnum((unsigned char)*p) || *p == '_')) {
            if (k + 1 < sizeof(word))
                word[k++] = (char)tolower((unsigned char)*p);
            p++;
        }
        word[k] = '\0';
        if (k < 3 || cap_is_stopword(word)) continue;
        ci_capability_stem(word);
        /* A stem already present adds nothing and would double-count its
         * weight, so drop the duplicate rather than the query. */
        bool dup = false;
        for (int i = 0; i < q->term_count; i++)
            if (strcmp(q->stems[i], word) == 0) dup = true;
        if (dup) continue;
        if (q->term_count >= CI_CAPABILITY_TERM_CAP) { q->terms_dropped++; continue; }
        snprintf(q->stems[q->term_count], CI_CAPABILITY_TERM_MAX, "%s", word);
        q->term_count++;
    }
    return q->term_count;
}

/* ── anchor table ─────────────────────────────────────────────────────── */

static struct cap_anchor *cap_anchor_for(struct cap_scan *s, const char *path)
{
    if (!path || !path[0]) return NULL;
    uint32_t h = cap_hash(path) & (CI_CAP_SLOTS - 1u);
    for (uint32_t probe = 0; probe < CI_CAP_SLOTS; probe++) {
        uint32_t k = (h + probe) & (CI_CAP_SLOTS - 1u);
        int idx = s->slot[k];
        if (idx < 0) {
            if (s->n >= s->cap) { s->truncated = true; return NULL; }
            idx = s->n++;
            s->slot[k] = idx;
            memset(&s->a[idx], 0, sizeof(s->a[idx]));
            ci_cpy(s->a[idx].path, sizeof(s->a[idx].path), path);
            return &s->a[idx];
        }
        if (strcmp(s->a[idx].path, path) == 0) return &s->a[idx];
    }
    s->truncated = true;
    return NULL;
}

/* The file that OWNS an API: the declaring header when there is one, else the
 * defining translation unit. A caller looking for "what already does X" wants
 * the header it would include, not the .c it would never touch. */
static const char *cap_anchor_path(const char *def_path, const char *decl_path)
{
    size_t n = decl_path ? strlen(decl_path) : 0;
    if (n >= 2 && decl_path[n - 2] == '.' && decl_path[n - 1] == 'h')
        return decl_path;
    if (def_path && def_path[0]) return def_path;
    return decl_path && decl_path[0] ? decl_path : NULL;
}

/* An include guard is a macro, so the index records it as a symbol — but
 * `ZCL_CONSENSUS_VALIDATION_H` is not part of anything's API, and listing it
 * beside `validates_blob_size` both wastes a slot in a short list and inflates
 * the symbol count a reader is being invited to check by hand.
 *
 * The test is shape, not lookup: a macro whose name is entirely uppercase,
 * digits and underscores and ends in "_H". That is the guard convention this
 * tree uses everywhere. It can in principle exclude a real all-caps macro
 * named `*_H`; nothing in this tree is, and quietly dropping one from a
 * capability list is a far smaller error than teaching every reader to skip
 * the first line of every result. */
static bool cap_is_include_guard(const char *name, char kind)
{
    if (kind != 'M' || !name) return false;
    size_t n = strlen(name);
    if (n < 3 || name[n - 1] != 'H' || name[n - 2] != '_') return false;
    for (size_t i = 0; i < n; i++) {
        char c = name[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
            return false;
    }
    return true;
}

static bool cap_contains(const char *hay, const char *needle)
{
    if (!hay || !needle || !needle[0]) return false;
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i] &&
               tolower((unsigned char)p[i]) == (unsigned char)needle[i])
            i++;
        if (i == nl) return true;
    }
    return false;
}

/* Build "(<col> LIKE ?k ESCAPE '\\' OR ...)" over `cols` for every stem.
 * The wildcard patterns are BOUND, never spliced, so this is a shape, not a
 * value. SQLite LIKE folds ASCII case without allocating a lower-case copy of
 * every candidate column for every term. */
static bool cap_where(char *sql, size_t cap, const char *const *cols,
                      int ncols, int nterms)
{
    size_t used = 0;
    int written = 0;
    for (int t = 0; t < nterms; t++) {
        for (int c = 0; c < ncols; c++) {
            int n = snprintf(sql + used, cap - used,
                             "%s%s LIKE ?%d ESCAPE '\\'",
                             written ? " OR " : "", cols[c], t + 1);
            if (n < 0 || (size_t)n >= cap - used) return false;
            used += (size_t)n;
            written++;
        }
    }
    return written > 0;
}

static void cap_bind_patterns(sqlite3_stmt *stmt,
                              const struct ci_capability_query *q)
{
    for (int t = 0; t < q->term_count; t++) {
        char pattern[2 * CI_CAPABILITY_TERM_MAX + 3];
        size_t at = 0;
        pattern[at++] = '%';
        for (size_t i = 0; q->stems[t][i]; i++) {
            char c = q->stems[t][i];
            if (c == '%' || c == '_' || c == '\\') pattern[at++] = '\\';
            pattern[at++] = c;
        }
        pattern[at++] = '%';
        pattern[at] = '\0';
        sqlite3_bind_text(stmt, t + 1, pattern, -1, SQLITE_TRANSIENT);
    }
}

/* ── candidate scans ──────────────────────────────────────────────────── */

static bool cap_scan_symbols(struct ci_store *st, struct cap_scan *s,
                             struct ci_capability_query *q)
{
    static const char *const cols[] = { "name", "doc", "signature" };
    char where[1024];
    if (!cap_where(where, sizeof(where), cols, 3, q->term_count))
        LOG_FAIL("codeindex", "capability symbol predicate overflow");
    char sql[1400];
    if (snprintf(sql, sizeof(sql),
                 "SELECT name,def_path,decl_path,\"group\",doc,signature,kind"
                 " FROM symbols WHERE %s ORDER BY name ASC,def_path ASC",
                 where) >= (int)sizeof(sql))
        LOG_FAIL("codeindex", "capability symbol sql overflow");

    sqlite3 *db = ci_store_db(st);
    sqlite3_stmt *stmt = NULL;
    if (!db || sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        LOG_FAIL("codeindex", "prepare capability symbol scan");
    cap_bind_patterns(stmt, q);

    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        const char *name = (const char *)sqlite3_column_text(stmt, 0);
        const char *defp = (const char *)sqlite3_column_text(stmt, 1);
        const char *declp = (const char *)sqlite3_column_text(stmt, 2);
        const char *grp = (const char *)sqlite3_column_text(stmt, 3);
        const char *doc = (const char *)sqlite3_column_text(stmt, 4);
        const char *sig = (const char *)sqlite3_column_text(stmt, 5);
        const char *kindtext = (const char *)sqlite3_column_text(stmt, 6);
        char kind = kindtext && kindtext[0] ? kindtext[0] : '\0';
        const char *anchor = cap_anchor_path(defp, declp);
        if (!name || !anchor) continue;
        if (cap_is_include_guard(name, kind)) continue;
        q->symbol_rows++;
        struct cap_anchor *a = cap_anchor_for(s, anchor);
        if (!a) continue;
        if (!a->group[0] && grp) ci_cpy(a->group, sizeof(a->group), grp);

        uint32_t nm = 0, dm = 0;
        for (int t = 0; t < q->term_count; t++) {
            if (cap_contains(name, q->stems[t])) nm |= 1u << t;
            else if (cap_contains(doc, q->stems[t]) ||
                     cap_contains(sig, q->stems[t])) dm |= 1u << t;
        }
        if (nm) {
            a->name_mask |= nm;
            /* The scan is ORDER BY name, so a name that appears twice for one
             * anchor (a declaration and a definition of the same symbol) is
             * adjacent. Count and list it once: `symbol_count` is a count of
             * the API, not of index rows, and a caller checking it by hand
             * against the listed names must get the same number. */
            if (a->last_name[0] && strcmp(a->last_name, name) == 0) continue;
            ci_cpy(a->last_name, sizeof(a->last_name), name);
            a->name_hits++;
            if (a->syms_listed < CI_CAPABILITY_SYMBOL_CAP)
                ci_cpy(a->syms[a->syms_listed++], sizeof(a->syms[0]), name);
        } else if (dm) {
            a->doc_mask |= dm;
            a->doc_hits++;
        }
    }
    bool ok = rc == SQLITE_DONE;
    sqlite3_finalize(stmt);
    if (!ok) LOG_FAIL("codeindex", "step capability symbol scan");
    return true;
}

static bool cap_scan_files(struct ci_store *st, struct cap_scan *s,
                           struct ci_capability_query *q)
{
    static const char *const cols[] = { "path", "purpose", "\"group\"" };
    char where[1024];
    if (!cap_where(where, sizeof(where), cols, 3, q->term_count))
        LOG_FAIL("codeindex", "capability file predicate overflow");
    char sql[1400];
    if (snprintf(sql, sizeof(sql),
                 "SELECT path,\"group\",purpose FROM files WHERE %s"
                 " ORDER BY path ASC", where) >= (int)sizeof(sql))
        LOG_FAIL("codeindex", "capability file sql overflow");

    sqlite3 *db = ci_store_db(st);
    sqlite3_stmt *stmt = NULL;
    if (!db || sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        LOG_FAIL("codeindex", "prepare capability file scan");
    cap_bind_patterns(stmt, q);

    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        const char *path = (const char *)sqlite3_column_text(stmt, 0);
        const char *grp = (const char *)sqlite3_column_text(stmt, 1);
        const char *purpose = (const char *)sqlite3_column_text(stmt, 2);
        if (!path) continue;
        q->file_rows++;
        struct cap_anchor *a = cap_anchor_for(s, path);
        if (!a) continue;
        if (!a->group[0] && grp) ci_cpy(a->group, sizeof(a->group), grp);
        for (int t = 0; t < q->term_count; t++) {
            if (cap_contains(purpose, q->stems[t])) a->purpose_mask |= 1u << t;
            if (cap_contains(path, q->stems[t]))    a->path_mask |= 1u << t;
            if (cap_contains(grp, q->stems[t]))     a->group_mask |= 1u << t;
        }
    }
    bool ok = rc == SQLITE_DONE;
    sqlite3_finalize(stmt);
    if (!ok) LOG_FAIL("codeindex", "step capability file scan");
    return true;
}

/* ── usage: the number the caller actually came for ───────────────────── */

/* Distinct files with a recorded call site of this anchor's symbols, and the
 * lowest-sorting one. `name_matched` selects the two bases documented on
 * ci_capability.count_basis: the stem-matched symbols of the anchor, or all of
 * them when nothing matched by name.
 *
 * The anchor is excluded from its own count. A header that declares a symbol
 * and a .c that defines it are different files, so a definition site is not
 * counted as a use of the header — only real callers are. */
static bool cap_usage(struct ci_store *st, const struct ci_capability_query *q,
                      const char *anchor, bool name_matched,
                      int *out_files, char *example, size_t example_cap)
{
    *out_files = 0;
    if (example && example_cap) example[0] = '\0';

    char names[1024] = "";
    if (name_matched) {
        static const char *const cols[] = { "name" };
        char w[900];
        if (!cap_where(w, sizeof(w), cols, 1, q->term_count))
            LOG_FAIL("codeindex", "capability usage predicate overflow");
        if (snprintf(names, sizeof(names), " AND (%s)", w) >= (int)sizeof(names))
            LOG_FAIL("codeindex", "capability usage predicate overflow");
    }
    char sql[1600];
    /* ?%d is the anchor: bound after the stems so the stem indices stay
     * 1..term_count in every statement this file builds. */
    int anchor_idx = q->term_count + 1;
    if (snprintf(sql, sizeof(sql),
                 "SELECT COUNT(DISTINCT ref_file),MIN(ref_file) FROM refs"
                 " WHERE ref_file<>?%d AND callee_name IN"
                 " (SELECT name FROM symbols"
                 "   WHERE (def_path=?%d OR decl_path=?%d)%s)",
                 anchor_idx, anchor_idx, anchor_idx, names)
        >= (int)sizeof(sql))
        LOG_FAIL("codeindex", "capability usage sql overflow");

    sqlite3 *db = ci_store_db(st);
    sqlite3_stmt *stmt = NULL;
    if (!db || sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        LOG_FAIL("codeindex", "prepare capability usage");
    cap_bind_patterns(stmt, q);
    sqlite3_bind_text(stmt, anchor_idx, anchor, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    if (rc == SQLITE_ROW) {
        *out_files = sqlite3_column_int(stmt, 0);
        const char *first = (const char *)sqlite3_column_text(stmt, 1);
        if (example && example_cap && first) ci_cpy(example, example_cap, first);
    }
    bool ok = rc == SQLITE_ROW || rc == SQLITE_DONE;
    sqlite3_finalize(stmt);
    if (!ok) LOG_FAIL("codeindex", "step capability usage");
    return true;
}

/* ── ranking + rendering ──────────────────────────────────────────────── */

static int cap_popcount(uint32_t v)
{
    int n = 0;
    while (v) { n += (int)(v & 1u); v >>= 1; }
    return n;
}

static bool cap_is_header(const char *path)
{
    size_t n = path ? strlen(path) : 0;
    return n >= 2 && path[n - 2] == '.' && path[n - 1] == 'h';
}

static int cap_score(const struct cap_anchor *a)
{
    int name = a->name_hits * CI_W_SYM_NAME;
    if (name > CI_W_SYM_NAME_CAP) name = CI_W_SYM_NAME_CAP;
    int doc = a->doc_hits * CI_W_SYM_DOC;
    if (doc > CI_W_SYM_DOC_CAP) doc = CI_W_SYM_DOC_CAP;
    return name + doc +
           cap_popcount(a->purpose_mask) * CI_W_FILE_PURPOSE +
           cap_popcount(a->path_mask) * CI_W_FILE_PATH +
           cap_popcount(a->group_mask) * CI_W_FILE_GROUP +
           (cap_is_header(a->path) ? CI_W_HEADER : 0);
}

static int cap_terms_matched(const struct cap_anchor *a)
{
    return cap_popcount(a->name_mask | a->doc_mask | a->purpose_mask |
                        a->path_mask | a->group_mask);
}

/* File stem: basename minus its extension. */
static void cap_stem_of_path(const char *path, char *out, size_t cap)
{
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    size_t i = 0;
    while (base[i] && base[i] != '.' && i + 1 < cap) { out[i] = base[i]; i++; }
    out[i] = '\0';
}

/* The longest common prefix of the listed symbol names, "" when shorter than
 * three characters. `validates_presence_of` + `validates_range` + … yields
 * "validates_", which is what makes the rendered label a fact about the code
 * rather than a phrase this file invented. */
static void cap_common_prefix(const struct ci_capability *c, char *out,
                              size_t cap)
{
    out[0] = '\0';
    if (c->symbols_listed < 2) return;
    size_t n = strlen(c->symbols[0]);
    for (int i = 1; i < c->symbols_listed; i++) {
        size_t k = 0;
        while (k < n && c->symbols[i][k] &&
               c->symbols[i][k] == c->symbols[0][k]) k++;
        n = k;
    }
    if (n < 3 || n >= cap) return;
    memcpy(out, c->symbols[0], n);
    out[n] = '\0';
}

static void cap_label(struct ci_capability *c)
{
    char stem[128];
    cap_stem_of_path(c->header, stem, sizeof(stem));
    char prefix[128];
    cap_common_prefix(c, prefix, sizeof(prefix));
    if (prefix[0] && c->symbol_count > 0)
        snprintf(c->what, sizeof(c->what), "%s: %s* (%d symbol%s)", stem,
                 prefix, c->symbol_count, c->symbol_count == 1 ? "" : "s");
    else if (c->symbol_count > 0)
        snprintf(c->what, sizeof(c->what), "%s (%d matching symbol%s)", stem,
                 c->symbol_count, c->symbol_count == 1 ? "" : "s");
    else
        snprintf(c->what, sizeof(c->what), "%s", stem);
}

int codeindex_capabilities(struct codeindex *ci, const char *text,
                           struct ci_capability *out, int cap,
                           struct ci_capability_query *q)
{
    if (!ci || !ci->store || !text || !out || cap <= 0 || !q)
        LOG_ERR("codeindex", "bad arg to codeindex_capabilities");
    memset(q, 0, sizeof(*q));
    if (cap_terms(text, q) == 0)
        return 0;   /* nothing searchable survived stopword/length filtering */

    struct cap_scan s = { 0 };
    s.cap = CI_CAP_ANCHOR_CAP;
    s.a = zcl_calloc((size_t)s.cap, sizeof(*s.a), "ci_cap_anchors");
    s.slot = zcl_malloc(CI_CAP_SLOTS * sizeof(*s.slot), "ci_cap_slots");
    if (!s.a || !s.slot) {
        free(s.a);
        free(s.slot);
        LOG_ERR("codeindex", "alloc capability anchors");
    }
    for (size_t i = 0; i < CI_CAP_SLOTS; i++) s.slot[i] = -1;

    ci_store_lock(ci->store);
    bool ok = cap_scan_symbols(ci->store, &s, q) &&
              cap_scan_files(ci->store, &s, q);
    ci_store_unlock(ci->store);
    free(s.slot);
    s.slot = NULL;
    if (!ok) { free(s.a); LOG_ERR("codeindex", "capability scan failed"); }
    q->candidates = s.n;
    q->truncated = s.truncated;

    /* Admission. Every stem must be matched. Only if that is empty do we drop
     * to n-1, and then only for a multi-term query — a one-term query that
     * matched nothing has nothing to relax to, and relaxing it would return
     * the whole tree. */
    int need = q->term_count;
    int pool_idx[CI_CAP_RANK_POOL];
    int pool_n = 0;
    for (int round = 0; round < 2 && pool_n == 0; round++) {
        if (round == 1) {
            if (q->term_count < 2) break;
            need = q->term_count - 1;
            q->relaxed = true;
        }
        for (int i = 0; i < s.n; i++) {
            if (cap_terms_matched(&s.a[i]) < need) continue;
            int sc = cap_score(&s.a[i]);
            if (sc <= 0) continue;
            /* insertion sort into the fixed pool, by score then path */
            int at = pool_n;
            while (at > 0) {
                int prev = pool_idx[at - 1];
                int psc = cap_score(&s.a[prev]);
                if (psc > sc ||
                    (psc == sc && strcmp(s.a[prev].path, s.a[i].path) < 0))
                    break;
                if (at < CI_CAP_RANK_POOL) pool_idx[at] = prev;
                at--;
            }
            if (at < CI_CAP_RANK_POOL) {
                pool_idx[at] = i;
                if (pool_n < CI_CAP_RANK_POOL) pool_n++;
            }
        }
    }
    if (pool_n == 0) { free(s.a); return 0; }

    /* Materialise the pool, then buy the usage count for it. */
    struct ci_capability pool[CI_CAP_RANK_POOL];
    memset(pool, 0, sizeof(pool));
    for (int i = 0; i < pool_n; i++) {
        struct cap_anchor *a = &s.a[pool_idx[i]];
        struct ci_capability *c = &pool[i];
        ci_cpy(c->header, sizeof(c->header), a->path);
        ci_cpy(c->group, sizeof(c->group), a->group);
        c->symbols_listed = a->syms_listed;
        for (int k = 0; k < a->syms_listed; k++)
            ci_cpy(c->symbols[k], sizeof(c->symbols[k]), a->syms[k]);
        c->symbol_count = a->name_hits;
        c->score = cap_score(a);
        c->terms_matched = cap_terms_matched(a);

        struct ci_file f;
        bool found = false;
        if (codeindex_file(ci, c->header, &f, &found) && found)
            ci_cpy(c->purpose, sizeof(c->purpose), f.purpose);

        bool by_name = c->symbol_count > 0;
        ci_cpy(c->count_basis, sizeof(c->count_basis),
               by_name ? CI_CAPABILITY_BASIS_MATCHED
                       : CI_CAPABILITY_BASIS_FILE);
        ci_store_lock(ci->store);
        bool uok = cap_usage(ci->store, q, c->header, by_name,
                             &c->used_by_files, c->example_caller,
                             sizeof(c->example_caller));
        ci_store_unlock(ci->store);
        if (!uok) { free(s.a); LOG_ERR("codeindex", "capability usage failed"); }
        cap_label(c);
    }
    free(s.a);

    /* Re-rank with usage in hand: terms first (a candidate that answered more
     * of the question wins), then how load-bearing it is, then the cheap
     * score, then path for determinism. */
    for (int i = 1; i < pool_n; i++) {
        struct ci_capability key = pool[i];
        int j = i - 1;
        while (j >= 0) {
            const struct ci_capability *p = &pool[j];
            bool p_first =
                p->terms_matched > key.terms_matched ||
                (p->terms_matched == key.terms_matched &&
                 (p->used_by_files > key.used_by_files ||
                  (p->used_by_files == key.used_by_files &&
                   (p->score > key.score ||
                    (p->score == key.score &&
                     strcmp(p->header, key.header) <= 0)))));
            if (p_first) break;
            pool[j + 1] = pool[j];
            j--;
        }
        pool[j + 1] = key;
    }

    int n = pool_n < cap ? pool_n : cap;
    for (int i = 0; i < n; i++) out[i] = pool[i];
    return n;
}

/* ── verdict: derived from the emitted records, nothing else ──────────── */

const char *codeindex_capability_confidence(const struct ci_capability *c,
                                            const struct ci_capability_query *q)
{
    if (!c || !q) return "low";
    /* A relaxed search answered a question the caller did not ask, so it can
     * never reach "high" however good the numbers look. */
    if (!q->relaxed && c->terms_matched >= q->term_count &&
        c->symbol_count > 0 && c->used_by_files >= CI_CONF_HIGH_MIN_USERS)
        return "high";
    if (c->terms_matched >= 1 && c->used_by_files >= CI_CONF_MED_MIN_USERS)
        return "medium";
    return "low";
}

enum ci_capability_verdict codeindex_capability_verdict(
    const struct ci_capability *caps, int n,
    const struct ci_capability_query *q)
{
    if (!caps || n <= 0 || !q) return CI_CAPABILITY_NOT_FOUND;
    const char *conf = codeindex_capability_confidence(&caps[0], q);
    if (strcmp(conf, "high") == 0) return CI_CAPABILITY_ALREADY_EXISTS;
    if (strcmp(conf, "medium") == 0) return CI_CAPABILITY_PARTIAL;
    /* Something ranked, but nothing uses it and/or it answered part of the
     * question. Reporting that as an answer is the failure this whole query
     * exists to prevent, so it is NOT FOUND — the candidates still ship, and
     * the caller can look at them and decide. */
    return CI_CAPABILITY_NOT_FOUND;
}

const char *codeindex_capability_verdict_label(enum ci_capability_verdict v)
{
    switch (v) {
    case CI_CAPABILITY_ALREADY_EXISTS: return "ALREADY EXISTS";
    case CI_CAPABILITY_PARTIAL:        return "PARTIAL";
    case CI_CAPABILITY_NOT_FOUND:      break;
    }
    return "NOT FOUND";
}

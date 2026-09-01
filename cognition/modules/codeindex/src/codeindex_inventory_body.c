/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Derive include edges, normalized function bodies, and test roots. */

#include "codeindex_inventory_internal.h"

#include "base/checked.h"
#include "sha3/sha3.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool inv_ident_start(unsigned char c)
{
    return isalpha(c) || c == '_';
}

static bool inv_ident_char(unsigned char c)
{
    return isalnum(c) || c == '_';
}

static bool inv_include_push(struct inv_scan *s, int file_index, int line,
                             const char *token, size_t len)
{
    if (len == 0 || len >= sizeof(s->includes[0].token)) return true;
    if (s->include_count == s->include_cap) {
        int cap = s->include_cap ? s->include_cap * 2 : 4096;
        void *p = zcl_realloc(s->includes, (size_t)cap * sizeof(*s->includes),
                              "ci_inventory_includes");
        if (!p) return false;
        s->includes = p;
        s->include_cap = cap;
    }
    struct inv_include *row = &s->includes[s->include_count++];
    memset(row, 0, sizeof(*row));
    memcpy(row->token, token, len);
    row->token[len] = '\0';
    row->file_index = file_index;
    row->line = line;
    return true;
}

static void inv_scan_includes(struct inv_scan *s, int file_index,
                              const char *src, size_t len)
{
    int line = 1;
    size_t i = 0;
    while (i < len) {
        size_t end = i;
        while (end < len && src[end] != '\n') end++;
        size_t p = i;
        while (p < end && (src[p] == ' ' || src[p] == '\t')) p++;
        if (p < end && src[p] == '#') {
            p++;
            while (p < end && (src[p] == ' ' || src[p] == '\t')) p++;
            static const char word[] = "include";
            if (p + sizeof(word) - 1 <= end &&
                memcmp(src + p, word, sizeof(word) - 1) == 0) {
                p += sizeof(word) - 1;
                while (p < end && (src[p] == ' ' || src[p] == '\t')) p++;
                char close = 0;
                if (p < end && src[p] == '"') close = '"';
                else if (p < end && src[p] == '<') close = '>';
                if (close) {
                    size_t start = ++p;
                    while (p < end && src[p] != close) p++;
                    if (p < end && !inv_include_push(s, file_index, line,
                                                     src + start, p - start)) {
                        s->failed = true;
                        return;
                    }
                }
            }
        }
        i = end < len ? end + 1 : end;
        line++;
    }
}

/* Build a same-length structural buffer. Comments and literal interiors are
 * blank; the opening byte of a string/character literal is retained as @/$ so
 * the body fingerprint can bind the exact literal from the original bytes
 * without letting braces or comment markers inside it perturb structure. */
static char *inv_clean_source(const char *src, size_t len)
{
    char *out = zcl_malloc(len ? len : 1, "ci_inventory_clean");
    if (!out) return NULL;
    enum { NORMAL, LINE_COMMENT, BLOCK_COMMENT, STRING, CHARACTER } state = NORMAL;
    for (size_t i = 0; i < len; i++) {
        char c = src[i];
        if (state == NORMAL) {
            if (c == '/' && i + 1 < len && src[i + 1] == '/') {
                out[i] = ' '; out[++i] = ' '; state = LINE_COMMENT;
            } else if (c == '/' && i + 1 < len && src[i + 1] == '*') {
                out[i] = ' '; out[++i] = ' '; state = BLOCK_COMMENT;
            } else if (c == '"') {
                out[i] = '@'; state = STRING;
            } else if (c == '\'') {
                out[i] = '$'; state = CHARACTER;
            } else {
                out[i] = c;
            }
        } else if (state == LINE_COMMENT) {
            out[i] = c == '\n' ? '\n' : ' ';
            if (c == '\n') state = NORMAL;
        } else if (state == BLOCK_COMMENT) {
            if (c == '*' && i + 1 < len && src[i + 1] == '/') {
                out[i] = ' '; out[++i] = ' '; state = NORMAL;
            } else out[i] = c == '\n' ? '\n' : ' ';
        } else {
            out[i] = c == '\n' ? '\n' : ' ';
            if (c == '\\' && i + 1 < len) {
                i++;
                out[i] = src[i] == '\n' ? '\n' : ' ';
            } else if ((state == STRING && c == '"') ||
                       (state == CHARACTER && c == '\'')) {
                state = NORMAL;
            }
        }
    }
    return out;
}

static bool inv_keyword(const char *token)
{
    static const char *const words[] = {
        "if", "else", "for", "while", "do", "switch", "case", "default",
        "return", "break", "continue", "goto", "sizeof", "alignof",
        "static", "extern", "const", "volatile", "restrict", "inline",
        "void", "char", "short", "int", "long", "float", "double",
        "signed", "unsigned", "struct", "union", "enum", "typedef",
        "bool", "true", "false", "NULL", "_Atomic", "_Bool", NULL
    };
    for (size_t i = 0; words[i]; i++)
        if (strcmp(token, words[i]) == 0) return true;
    return false;
}

static void inv_hash_token(struct sha3_256_ctx *sha, const char *token,
                           size_t len)
{
    sha3_256_write(sha, (const unsigned char *)token, len);
    static const unsigned char sep = 0;
    sha3_256_write(sha, &sep, 1);
}

static size_t inv_literal_end(const char *src, size_t len, size_t start,
                              char quote)
{
    size_t i = start + 1;
    while (i < len) {
        if (src[i] == '\\' && i + 1 < len) { i += 2; continue; }
        if (src[i] == quote) return i + 1;
        i++;
    }
    return len;
}

static bool inv_constant_tokens(char tokens[64][32], int count,
                                char value[16])
{
    int i = 0;
    while (i + 4 < count && strcmp(tokens[i], "(") == 0 &&
           strcmp(tokens[i + 1], "void") == 0 &&
           strcmp(tokens[i + 2], ")") == 0 &&
           strcmp(tokens[i + 4], ";") == 0) {
        i += 5;
    }
    if (i + 2 != count - 1 || strcmp(tokens[i], "return") != 0 ||
        strcmp(tokens[i + 2], ";") != 0)
        return false;
    const char *v = tokens[i + 1];
    if (strcmp(v, "true") != 0 && strcmp(v, "false") != 0 &&
        strcmp(v, "0") != 0 && strcmp(v, "1") != 0 &&
        strcmp(v, "NULL") != 0)
        return false;
    inv_cpy(value, 16, v);
    return true;
}

static void inv_body_fingerprints(const char *src, const char *clean,
                                  size_t start, size_t end,
                                  struct inv_body *body)
{
    struct sha3_256_ctx exact, shape;
    static const char exact_domain[] = "zcl.code_body.normalized.v1";
    static const char shape_domain[] = "zcl.code_body.alpha_shape.v1";
    sha3_256_init(&exact); sha3_256_init(&shape);
    inv_hash_token(&exact, exact_domain, sizeof(exact_domain));
    inv_hash_token(&shape, shape_domain, sizeof(shape_domain));
    char small[64][32];
    int small_count = 0;
    int tokens = 0;
    size_t i = start;
    while (i < end) {
        unsigned char c = (unsigned char)clean[i];
        if (isspace(c)) { i++; continue; }
        char exact_token[160];
        char shape_token[32];
        size_t exact_len = 0;
        size_t next = i + 1;
        if (c == '@' || c == '$') {
            char quote = c == '@' ? '"' : '\'';
            next = inv_literal_end(src, end, i, quote);
            exact_len = next - i;
            if (exact_len >= sizeof(exact_token)) exact_len = sizeof(exact_token) - 1;
            memcpy(exact_token, src + i, exact_len);
            exact_token[exact_len] = '\0';
            inv_cpy(shape_token, sizeof(shape_token), c == '@' ? "STR" : "CHR");
        } else if (inv_ident_start(c)) {
            next = i + 1;
            while (next < end && inv_ident_char((unsigned char)clean[next])) next++;
            exact_len = next - i;
            if (exact_len >= sizeof(exact_token)) exact_len = sizeof(exact_token) - 1;
            memcpy(exact_token, clean + i, exact_len);
            exact_token[exact_len] = '\0';
            if (inv_keyword(exact_token)) {
                inv_cpy(shape_token, sizeof(shape_token), exact_token);
            } else {
                size_t look = next;
                while (look < end && isspace((unsigned char)clean[look])) look++;
                if (look < end && clean[look] == '(')
                    inv_cpy(shape_token, sizeof(shape_token), "CALL");
                else {
                    size_t back = i;
                    while (back > start && isspace((unsigned char)clean[back - 1])) back--;
                    bool member = back > start && clean[back - 1] == '.';
                    if (back > start + 1 && clean[back - 1] == '>' &&
                        clean[back - 2] == '-') member = true;
                    inv_cpy(shape_token, sizeof(shape_token), member ? "MEMBER" : "ID");
                }
            }
        } else if (isdigit(c)) {
            next = i + 1;
            while (next < end &&
                   (isalnum((unsigned char)clean[next]) || clean[next] == '.' ||
                    clean[next] == '\'' || clean[next] == '_')) next++;
            exact_len = next - i;
            if (exact_len >= sizeof(exact_token)) exact_len = sizeof(exact_token) - 1;
            memcpy(exact_token, clean + i, exact_len);
            exact_token[exact_len] = '\0';
            inv_cpy(shape_token, sizeof(shape_token), "NUM");
        } else {
            exact_token[0] = (char)c;
            exact_token[1] = '\0';
            exact_len = 1;
            if (next < end) {
                char pair[3] = { (char)c, clean[next], '\0' };
                static const char *const pairs[] = {
                    "==", "!=", "<=", ">=", "++", "--", "->", "&&", "||",
                    "<<", ">>", "+=", "-=", "*=", "/=", "%=", "&=", "|=",
                    "^=", "::", NULL
                };
                for (size_t p = 0; pairs[p]; p++) if (strcmp(pair, pairs[p]) == 0) {
                    exact_token[1] = clean[next]; exact_token[2] = '\0';
                    exact_len = 2; next++; break;
                }
            }
            inv_cpy(shape_token, sizeof(shape_token), exact_token);
        }
        inv_hash_token(&exact, exact_token, exact_len);
        inv_hash_token(&shape, shape_token, strlen(shape_token));
        if (small_count < 64) inv_cpy(small[small_count++], 32, exact_token);
        tokens++;
        i = next;
    }
    sha3_256_finalize(&exact, body->exact_sha3);
    sha3_256_finalize(&shape, body->shape_sha3);
    body->token_count = tokens;
    body->constant_return = tokens == small_count &&
        inv_constant_tokens(small, small_count, body->constant_value);
}

static bool inv_has_top_eq(const char *clean, size_t start, size_t end)
{
    int paren = 0, bracket = 0;
    for (size_t i = start; i < end; i++) {
        if (clean[i] == '(') paren++;
        else if (clean[i] == ')' && paren > 0) paren--;
        else if (clean[i] == '[') bracket++;
        else if (clean[i] == ']' && bracket > 0) bracket--;
        else if (clean[i] == '=' && paren == 0 && bracket == 0) {
            char before = i > start ? clean[i - 1] : 0;
            char after = i + 1 < end ? clean[i + 1] : 0;
            if (before != '=' && before != '!' && before != '<' && before != '>' &&
                after != '=') return true;
        }
    }
    return false;
}

static bool inv_function_name(const char *clean, size_t start, size_t end,
                              char name[128])
{
    while (start < end && isspace((unsigned char)clean[start])) start++;
    if (start == end || inv_has_top_eq(clean, start, end)) return false;
    char first[32] = "";
    size_t f = start;
    if (inv_ident_start((unsigned char)clean[f])) {
        size_t e = f + 1;
        while (e < end && inv_ident_char((unsigned char)clean[e])) e++;
        size_t n = e - f < sizeof(first) - 1 ? e - f : sizeof(first) - 1;
        memcpy(first, clean + f, n); first[n] = '\0';
    }
    if (strcmp(first, "typedef") == 0 || strcmp(first, "struct") == 0 ||
        strcmp(first, "union") == 0 || strcmp(first, "enum") == 0)
        return false;
    size_t lp = start;
    while (lp < end && clean[lp] != '(') lp++;
    if (lp == end) return false;
    size_t p = lp;
    while (p > start && isspace((unsigned char)clean[p - 1])) p--;
    size_t name_end = p;
    while (p > start && inv_ident_char((unsigned char)clean[p - 1])) p--;
    if (p == name_end || !inv_ident_start((unsigned char)clean[p])) return false;
    size_t before = start;
    while (before < p && isspace((unsigned char)clean[before])) before++;
    if (before == p) return false; /* macro invocation, no return type */
    size_t n = name_end - p;
    if (n >= 128) n = 127;
    memcpy(name, clean + p, n); name[n] = '\0';
    return true;
}

static bool inv_macro_invocation_segment(const char *clean, size_t start,
                                         size_t end)
{
    while (start < end && isspace((unsigned char)clean[start])) start++;
    if (start == end || !inv_ident_start((unsigned char)clean[start]))
        return false;
    bool has_upper = false;
    size_t p = start;
    while (p < end && inv_ident_char((unsigned char)clean[p])) {
        unsigned char c = (unsigned char)clean[p];
        if (isupper(c)) has_upper = true;
        else if (islower(c)) return false;
        p++;
    }
    while (p < end && isspace((unsigned char)clean[p])) p++;
    return has_upper && p < end && clean[p] == '(';
}

/* Sorted index over ONE file's symbol occurrences, keyed by (name,
 * def_path), so inv_body_push can recover a function body's preprocessor
 * guard in O(log n + matches) instead of rescanning the whole corpus-so-far
 * `s->occurrences` array for every body found -- that scan was the single
 * dominant cost of the generator (98.6% of runtime by gprof), because it is
 * O(bodies x occurrences).
 *
 * A per-file index is sufficient, not a global or incrementally-maintained
 * one: the very first test in the original linear scan is
 * `occ->file_index != file_index`, so an occurrence from any other file can
 * never match. `inv_scan_all` (codeindex_inventory_scan.c) runs
 * `ci_scan_text` for a file -- which appends that file's occurrences to the
 * tail of `s->occurrences` -- and then immediately calls
 * `inv_scan_includes_and_bodies` for the same file, before any other file's
 * occurrences are appended. So by the time this file's bodies are scanned,
 * exactly that file's occurrences are present, as one contiguous run at the
 * tail of `s->occurrences`, and nothing is appended to that run afterward.
 * Building the index once per file, right before scanning that file's
 * bodies, is therefore both correct and sufficient. */
struct inv_guard_key {
    const char *name;
    const char *def_path;
    const char *guard;
    int def_line;
    int order; /* Position among this file's occurrences in the original
                * (ci_scan_text emission) order.  The original loop keeps
                * overwriting the guard on `def_line >= best_line`, so on a
                * def_line tie the LAST-emitted occurrence wins; sorting with
                * `order` as the final tie-break, and reading the last
                * matching entry in sorted order, reproduces that exactly. */
};

static int inv_guard_key_cmp(const void *a, const void *b)
{
    const struct inv_guard_key *x = a, *y = b;
    int c = strcmp(x->name, y->name);
    if (c) return c;
    c = strcmp(x->def_path, y->def_path);
    if (c) return c;
    return (x->order > y->order) - (x->order < y->order);
}

/* Lower-bound: first index whose (name, def_path) is not less than the
 * given pair. */
static int inv_guard_key_lower(const struct inv_guard_key *keys, int count,
                               const char *name, const char *def_path)
{
    int lo = 0, hi = count;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        int c = strcmp(keys[mid].name, name);
        if (!c) c = strcmp(keys[mid].def_path, def_path);
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

/* Builds the guard-lookup index for the file whose occurrences form the
 * (already-appended) tail of `s->occurrences`. `*out_keys`/`*out_count` are
 * always set (possibly to NULL/0 for a file with no occurrences); the
 * caller owns `*out_keys` and must free() it. Returns false only on
 * allocation/overflow failure. */
static bool inv_guard_index_build(struct inv_scan *s, int file_index,
                                  struct inv_guard_key **out_keys,
                                  int *out_count)
{
    *out_keys = NULL;
    *out_count = 0;
    int end = s->occurrence_count;
    int start = end;
    while (start > 0 && s->occurrences[start - 1].file_index == file_index)
        start--;
    int n = end - start;
    if (n == 0) return true;
    size_t bytes;
    if (!zcl_size_mul((size_t)n, sizeof(struct inv_guard_key), &bytes))
        LOG_FAIL("codeindex.inventory",
                 "body guard index byte-size overflow");
    struct inv_guard_key *keys =
        zcl_malloc(bytes, "ci_inventory_body_guard_index");
    if (!keys) return false;
    int k = 0;
    for (int i = start; i < end; i++) {
        const struct inv_symbol_occurrence *occ = &s->occurrences[i];
        /* def_line <= 0 can never satisfy the original loop's guard, so
         * dropping it here changes nothing but the index size. */
        if (occ->symbol.def_line <= 0) continue;
        keys[k].name = occ->symbol.name;
        keys[k].def_path = occ->symbol.def_path;
        keys[k].guard = occ->symbol.guard;
        keys[k].def_line = occ->symbol.def_line;
        keys[k].order = k;
        k++;
    }
    qsort(keys, (size_t)k, sizeof(*keys), inv_guard_key_cmp);
    *out_keys = keys;
    *out_count = k;
    return true;
}

static bool inv_body_push(struct inv_scan *s, int file_index, const char *src,
                          const char *clean, const char *name,
                          size_t open, size_t close,
                          int open_line, int close_line,
                          const struct inv_guard_key *guard_keys,
                          int guard_key_count)
{
    if (s->body_count == s->body_cap) {
        int cap = s->body_cap ? s->body_cap * 2 : 2048;
        void *p = zcl_realloc(s->bodies, (size_t)cap * sizeof(*s->bodies),
                              "ci_inventory_bodies");
        if (!p) return false;
        s->bodies = p;
        s->body_cap = cap;
    }
    struct inv_body *body = &s->bodies[s->body_count++];
    memset(body, 0, sizeof(*body));
    inv_cpy(body->name, sizeof(body->name), name);
    inv_cpy(body->path, sizeof(body->path), s->paths[file_index].path);
    body->file_index = file_index;
    body->line = open_line;
    body->end_line = close_line;
    int best_line = 0;
    int at = inv_guard_key_lower(guard_keys, guard_key_count, name,
                                 body->path);
    for (; at < guard_key_count && strcmp(guard_keys[at].name, name) == 0 &&
           strcmp(guard_keys[at].def_path, body->path) == 0; at++) {
        const struct inv_guard_key *k = &guard_keys[at];
        if (k->def_line > body->line || k->def_line < best_line)
            continue;
        best_line = k->def_line;
        inv_cpy(body->preprocessor_guard, sizeof(body->preprocessor_guard),
                k->guard);
    }
    inv_body_fingerprints(src, clean, open + 1, close, body);
    return true;
}

static void inv_scan_bodies(struct inv_scan *s, int file_index,
                            const char *src, size_t len)
{
    struct inv_guard_key *guard_keys = NULL;
    int guard_key_count = 0;
    if (!inv_guard_index_build(s, file_index, &guard_keys, &guard_key_count)) {
        s->failed = true;
        return;
    }
    char *clean = inv_clean_source(src, len);
    if (!clean) { free(guard_keys); s->failed = true; return; }
    /* Preprocessor rows are declaration data, never function bodies. */
    size_t line_start = 0;
    bool directive_continues = false;
    for (size_t i = 0; i <= len; i++) {
        if (i < len && src[i] != '\n') continue;
        size_t p = line_start;
        while (p < i && (src[p] == ' ' || src[p] == '\t')) p++;
        bool directive = directive_continues || (p < i && src[p] == '#');
        size_t tail = i;
        while (tail > line_start &&
               (src[tail - 1] == ' ' || src[tail - 1] == '\t' ||
                src[tail - 1] == '\r')) tail--;
        directive_continues = directive && tail > line_start &&
                              src[tail - 1] == '\\';
        if (directive)
            for (size_t j = line_start; j < i; j++) clean[j] = ' ';
        line_start = i + 1;
    }
    size_t segment = 0, open = 0;
    int brace = 0, paren = 0;
    /* Tracks the 1-based line of `clean[i]` (== `src[i]`'s line -- every
     * position, including every '\n', is carried through 1:1 by both
     * inv_clean_source and the directive-blanking pass above) without
     * rescanning from the start of the file for every body: `cur_line` is
     * correct for index i at the top of each iteration, and gets bumped
     * once per newline as the scan crosses it.  Recomputing this per body
     * via a full O(0..offset) rescan (the previous `inv_line_of` helper)
     * made body-line attribution O(bodies_in_file x file_size); this makes
     * the whole file's line attribution O(file_size) once. */
    int cur_line = 1;
    char prev_char = '\0';
    int open_line = 0;
    char active[128] = "";
    for (size_t i = 0; i < len; i++) {
        if (prev_char == '\n') cur_line++;
        char c = clean[i];
        prev_char = c;
        if (c == '\n' && brace == 0 && paren == 0 &&
            inv_macro_invocation_segment(clean, segment, i)) {
            segment = i + 1;
            continue;
        }
        if (brace == 0) {
            if (c == '(') { paren++; continue; }
            if (c == ')') { if (paren > 0) paren--; continue; }
            if (paren == 0 && c == '{') {
                active[0] = '\0';
                (void)inv_function_name(clean, segment, i, active);
                open = i;
                open_line = cur_line;
                brace = 1;
                continue;
            }
            if (paren == 0 && (c == ';' || c == '}')) segment = i + 1;
        } else {
            if (c == '{') brace++;
            else if (c == '}') {
                brace--;
                if (brace == 0) {
                    if (active[0] && !inv_body_push(s, file_index, src, clean,
                                                    active, open, i,
                                                    open_line, cur_line,
                                                    guard_keys,
                                                    guard_key_count)) {
                        s->failed = true;
                        break;
                    }
                    active[0] = '\0';
                    segment = i + 1;
                }
            }
        }
    }
    free(clean);
    free(guard_keys);
}

void inv_scan_includes_and_bodies(struct inv_scan *s, int file_index,
                                  const char *src, size_t len)
{
    inv_scan_includes(s, file_index, src, len);
    if (!s->failed)
        inv_scan_bodies(s, file_index, src, len);
}

static bool inv_group_push(struct inv_scan *s, const char *name,
                           const char *prefix)
{
    if (!name || !name[0]) return true;
    if (s->group_count == s->group_cap) {
        int cap = s->group_cap ? s->group_cap * 2 : 512;
        void *p = zcl_realloc(s->groups, (size_t)cap * sizeof(*s->groups),
                              "ci_inventory_test_groups");
        if (!p) return false;
        s->groups = p;
        s->group_cap = cap;
    }
    struct inv_registered_group *g = &s->groups[s->group_count++];
    memset(g, 0, sizeof(*g));
    inv_cpy(g->name, sizeof(g->name), name);
    (void)snprintf(g->root_symbol, sizeof(g->root_symbol), "%s%s", prefix, name);
    return true;
}

bool inv_read_registered_groups(struct inv_scan *s)
{
    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/tools/dev/test_group_catalog.def",
                     s->root);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    char line[512];
    bool ok = true;
    while (ok && fgets(line, sizeof(line), f)) {
        const char *prefix = NULL;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "ZCL_TEST_GROUP(", strlen("ZCL_TEST_GROUP(")) == 0) {
            p += strlen("ZCL_TEST_GROUP("); prefix = "test_";
        } else if (strncmp(p, "ZCL_SPEC_GROUP(",
                           strlen("ZCL_SPEC_GROUP(")) == 0) {
            p += strlen("ZCL_SPEC_GROUP("); prefix = "spec_";
        } else continue;
        while (*p == ' ' || *p == '\t') p++;
        char name[128];
        size_t used = 0;
        while (inv_ident_char((unsigned char)*p) && used + 1 < sizeof(name))
            name[used++] = *p++;
        name[used] = '\0';
        while (*p == ' ' || *p == '\t') p++;
        if (used && *p == ')') ok = inv_group_push(s, name, prefix);
    }
    if (ferror(f)) ok = false;
    fclose(f);
    return ok && s->group_count > 0;
}

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Parse the frozen shadow-selection corpus, its cost weights and
 * its patch bytes; derive each patch's contract token roots. */

#include "dev_shadow_select.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#define SHADOW_FIELDS_MAX 8u

static void shadow_why(char *why, size_t why_len, const char *fmt, ...)
{
    if (!why || why_len == 0) return;
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(why, why_len, fmt, ap);
    va_end(ap);
}

/* One line of `text` starting at *pos, without its newline. */
static bool shadow_next_line(const char *text, size_t len, size_t *pos,
                             const char **line, size_t *line_len)
{
    if (*pos >= len) return false;
    size_t end = *pos;
    while (end < len && text[end] != '\n') end++;
    *line = text + *pos;
    *line_len = end - *pos;
    *pos = end < len ? end + 1 : end;
    return true;
}

/* Split one tab-separated line into NUL-terminated copies. */
static size_t shadow_split(const char *line, size_t len, char *buf,
                           size_t buf_len, char **fields, size_t cap)
{
    if (len + 1 > buf_len) return 0;
    memcpy(buf, line, len);
    buf[len] = '\0';
    size_t n = 0;
    char *cursor = buf;
    while (n < cap) {
        fields[n++] = cursor;
        char *tab = strchr(cursor, '\t');
        if (!tab) break;
        *tab = '\0';
        cursor = tab + 1;
    }
    return n;
}

static bool shadow_copy(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);
    if (n == 0 || n >= cap) return false;
    memcpy(dst, src, n + 1);
    return true;
}

static bool shadow_is_hex40(const char *s)
{
    if (strlen(s) != 40) return false;
    for (size_t i = 0; i < 40; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

static bool shadow_parse_files(struct zcl_shadow_entry *e, char *list)
{
    e->file_count = 0;
    char *tok = list;
    for (;;) {
        char *comma = strchr(tok, ',');
        if (comma) *comma = '\0';
        if (e->file_count >= ZCL_SHADOW_MAX_FILES ||
            !shadow_copy(e->files[e->file_count], ZCL_SHADOW_PATH_MAX, tok))
            return false;
        e->file_count++;
        if (!comma) return true;
        tok = comma + 1;
    }
}

static bool shadow_parse_entry(char **f, struct zcl_shadow_entry *e)
{
    memset(e, 0, sizeof(*e));
    return shadow_copy(e->id, sizeof(e->id), f[0]) &&
           zcl_shadow_kind_parse(f[1], &e->kind) &&
           shadow_copy(e->component, sizeof(e->component), f[2]) &&
           shadow_is_hex40(f[3]) &&
           shadow_copy(e->commit, sizeof(e->commit), f[3]) &&
           zcl_hex_decode_lower(f[4], e->patch_sha3,
                                sizeof(e->patch_sha3)) &&
           shadow_parse_files(e, f[5]);
}

static bool shadow_id_unique(const struct zcl_shadow_corpus *c, const char *id)
{
    for (size_t i = 0; i < c->count; i++)
        if (strcmp(c->entries[i].id, id) == 0) return false;
    return true;
}

bool zcl_shadow_corpus_parse(const char *text, size_t len,
                             struct zcl_shadow_corpus *out, char *why,
                             size_t why_len)
{
    if (!text || !out) return false;
    out->count = 0;
    size_t pos = 0, lineno = 0;
    const char *line;
    size_t line_len;
    char buf[1024];
    while (shadow_next_line(text, len, &pos, &line, &line_len)) {
        lineno++;
        if (line_len == 0 || line[0] == '#') continue;
        char *f[SHADOW_FIELDS_MAX];
        size_t n = shadow_split(line, line_len, buf, sizeof(buf), f,
                                SHADOW_FIELDS_MAX);
        if (n != 6 || out->count >= ZCL_SHADOW_MAX_ENTRIES ||
            !shadow_parse_entry(f, &out->entries[out->count]) ||
            !shadow_id_unique(out, out->entries[out->count].id)) {
            shadow_why(why, why_len, "corpus_row_invalid_line_%zu", lineno);
            return false;
        }
        out->count++;
    }
    if (out->count == 0) shadow_why(why, why_len, "corpus_empty");
    return out->count > 0;
}

bool zcl_shadow_real_patch_argv(const char *root, const char *commit,
                                const char **argv, size_t argv_cap)
{
    static char parent[48];
    static const char *const fixed[] = {
        "-c", "core.quotepath=off", "-c", "diff.noprefix=false",
        "-c", "diff.mnemonicPrefix=false", "--no-pager", "diff-tree", "-p",
        "--no-color", "--no-renames", "--no-ext-diff", "--full-index",
    };
    size_t nfixed = sizeof(fixed) / sizeof(fixed[0]);
    if (!root || !commit || !argv || argv_cap < nfixed + 6 ||
        !shadow_is_hex40(commit))
        return false;
    (void)snprintf(parent, sizeof(parent), "%s^", commit);
    argv[0] = "git";
    argv[1] = "-C";
    argv[2] = root;
    for (size_t i = 0; i < nfixed; i++) argv[3 + i] = fixed[i];
    argv[3 + nfixed] = parent;
    argv[4 + nfixed] = commit;
    argv[5 + nfixed] = NULL;
    return true;
}

/* ── weights ──────────────────────────────────────────────────────────── */

static int shadow_weight_cmp(enum zcl_shadow_obligation ak, const char *an,
                             enum zcl_shadow_obligation bk, const char *bn)
{
    if (ak != bk) return ak < bk ? -1 : 1;
    return strcmp(an, bn);
}

static bool shadow_parse_u32(const char *s, uint32_t *out)
{
    char *end = NULL;
    if (!s[0]) return false;
    unsigned long v = strtoul(s, &end, 10);
    if (!end || *end || v > UINT32_MAX) return false;
    *out = (uint32_t)v;
    return true;
}

static bool shadow_parse_weight(char **f, struct zcl_shadow_weight *w)
{
    if (strcmp(f[0], "lint_gate") == 0)
        w->kind = ZCL_SHADOW_OBLIGATION_LINT_GATE;
    else if (strcmp(f[0], "test_group") == 0)
        w->kind = ZCL_SHADOW_OBLIGATION_TEST_GROUP;
    else
        return false;
    return shadow_copy(w->name, sizeof(w->name), f[1]) &&
           shadow_parse_u32(f[2], &w->mean_ms) &&
           shadow_parse_u32(f[3], &w->samples) && w->samples > 0;
}

static size_t shadow_count_rows(const char *text, size_t len)
{
    size_t rows = 0, pos = 0, line_len;
    const char *line;
    while (shadow_next_line(text, len, &pos, &line, &line_len))
        rows += (line_len > 0 && line[0] != '#') ? 1u : 0u;
    return rows;
}

static bool shadow_weight_row(struct zcl_shadow_weights *out, const char *line,
                              size_t line_len)
{
    char buf[256];
    char *f[SHADOW_FIELDS_MAX];
    size_t n = shadow_split(line, line_len, buf, sizeof(buf), f,
                            SHADOW_FIELDS_MAX);
    struct zcl_shadow_weight *w = &out->rows[out->count];
    if (n != 4 || !shadow_parse_weight(f, w)) return false;
    if (out->count > 0) {
        const struct zcl_shadow_weight *prev = &out->rows[out->count - 1];
        if (shadow_weight_cmp(prev->kind, prev->name, w->kind, w->name) >= 0)
            return false;
    }
    out->count++;
    return true;
}

bool zcl_shadow_weights_parse(const char *text, size_t len,
                              struct zcl_shadow_weights *out, char *why,
                              size_t why_len)
{
    if (!text || !out) return false;
    out->rows = NULL;
    out->count = 0;
    size_t rows = shadow_count_rows(text, len);
    if (rows == 0) {
        shadow_why(why, why_len, "weights_empty");
        return false;
    }
    out->rows = zcl_calloc(rows, sizeof(*out->rows), "shadow_weights");
    if (!out->rows) return false;
    size_t pos = 0, line_len, lineno = 0;
    const char *line;
    while (shadow_next_line(text, len, &pos, &line, &line_len)) {
        lineno++;
        if (line_len == 0 || line[0] == '#') continue;
        if (!shadow_weight_row(out, line, line_len)) {
            shadow_why(why, why_len, "weights_row_invalid_line_%zu", lineno);
            zcl_shadow_weights_free(out);
            return false;
        }
    }
    return true;
}

void zcl_shadow_weights_free(struct zcl_shadow_weights *weights)
{
    if (!weights) return;
    free(weights->rows);
    weights->rows = NULL;
    weights->count = 0;
}

bool zcl_shadow_weight_ms(const struct zcl_shadow_weights *weights,
                          enum zcl_shadow_obligation kind, const char *name,
                          uint32_t *out_ms)
{
    if (!weights || !name || !out_ms) return false;
    size_t lo = 0, hi = weights->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const struct zcl_shadow_weight *w = &weights->rows[mid];
        int c = shadow_weight_cmp(w->kind, w->name, kind, name);
        if (c == 0) {
            *out_ms = w->mean_ms;
            return true;
        }
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return false;
}

size_t zcl_shadow_weights_count(const struct zcl_shadow_weights *weights,
                                enum zcl_shadow_obligation kind)
{
    size_t n = 0;
    for (size_t i = 0; weights && i < weights->count; i++)
        n += weights->rows[i].kind == kind ? 1u : 0u;
    return n;
}

static int shadow_u32_cmp(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

uint32_t zcl_shadow_weights_median(const struct zcl_shadow_weights *weights,
                                   enum zcl_shadow_obligation kind)
{
    size_t n = zcl_shadow_weights_count(weights, kind);
    if (n == 0) return 0;
    uint32_t *v = zcl_calloc(n, sizeof(*v), "shadow_median");
    if (!v) return 0;
    size_t k = 0;
    for (size_t i = 0; i < weights->count; i++)
        if (weights->rows[i].kind == kind) v[k++] = weights->rows[i].mean_ms;
    qsort(v, n, sizeof(*v), shadow_u32_cmp);
    uint32_t median = v[n / 2];
    free(v);
    return median;
}

/* ── patch facts ──────────────────────────────────────────────────────── */

struct shadow_buf {
    char *bytes;
    size_t len;
    size_t cap;
};

static bool shadow_buf_put(struct shadow_buf *b, const char *s, size_t n)
{
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 1024;
        while (cap < b->len + n + 1) cap *= 2;
        char *grown = zcl_realloc(b->bytes, cap, "shadow_buf");
        if (!grown) return false;
        b->bytes = grown;
        b->cap = cap;
    }
    memcpy(b->bytes + b->len, s, n);
    b->len += n;
    b->bytes[b->len] = '\0';
    return true;
}

/* Skip a string or character literal starting at s[i]; returns the index
 * just past it and copies it to `out`. */
static size_t shadow_copy_literal(const char *s, size_t n, size_t i,
                                  struct shadow_buf *out, bool *ok)
{
    char quote = s[i];
    size_t j = i + 1;
    while (j < n && s[j] != quote) j += (s[j] == '\\' && j + 1 < n) ? 2 : 1;
    j = j < n ? j + 1 : n;
    *ok = *ok && shadow_buf_put(out, s + i, j - i);
    return j;
}

static size_t shadow_skip_comment(const char *s, size_t n, size_t i)
{
    if (s[i + 1] == '/') {
        while (i < n && s[i] != '\n') i++;
        return i;
    }
    i += 2;
    while (i + 1 < n && !(s[i] == '*' && s[i + 1] == '/')) i++;
    return i + 1 < n ? i + 2 : n;
}

/* Comments dropped, every whitespace run collapsed to one space, trimmed.
 * Literals are kept byte-exact. */
static bool shadow_normalize(const char *s, size_t n, struct shadow_buf *out)
{
    bool ok = true, space = false;
    out->len = 0;
    if (!shadow_buf_put(out, "", 0)) return false;
    for (size_t i = 0; i < n && ok;) {
        char c = s[i];
        if (c == '/' && i + 1 < n && (s[i + 1] == '*' || s[i + 1] == '/')) {
            i = shadow_skip_comment(s, n, i);
            space = true;
            continue;
        }
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            space = true;
            i++;
            continue;
        }
        if (space && out->len > 0) ok = shadow_buf_put(out, " ", 1);
        space = false;
        if (c == '"' || c == '\'') {
            i = shadow_copy_literal(s, n, i, out, &ok);
            continue;
        }
        ok = ok && shadow_buf_put(out, &c, 1);
        i++;
    }
    return ok;
}

struct shadow_patch_state {
    const char *component;
    struct zcl_shadow_patch_facts *facts;
    struct sha3_256_ctx before;
    struct sha3_256_ctx after;
    struct shadow_buf side_before;
    struct shadow_buf side_after;
    struct shadow_buf removed;
    struct shadow_buf added;
    struct shadow_buf norm_a;
    struct shadow_buf norm_b;
    bool in_header;
    bool current_contract;
    bool any_moved;
    bool any_changed;
};

static void shadow_state_free(struct shadow_patch_state *st)
{
    free(st->side_before.bytes);
    free(st->side_after.bytes);
    free(st->removed.bytes);
    free(st->added.bytes);
    free(st->norm_a.bytes);
    free(st->norm_b.bytes);
}

static void shadow_hash_side(struct sha3_256_ctx *ctx, const char *path,
                             const struct shadow_buf *norm)
{
    sha3_256_write(ctx, (const unsigned char *)path, strlen(path) + 1);
    if (norm->len)
        sha3_256_write(ctx, (const unsigned char *)norm->bytes, norm->len);
    sha3_256_write(ctx, (const unsigned char *)"\n", 1);
}

/* Fold the finished file's contract sides into the roots and the verdict. */
static bool shadow_flush_file(struct shadow_patch_state *st)
{
    struct zcl_shadow_patch_facts *f = st->facts;
    if (f->file_count == 0 || !st->current_contract) return true;
    const char *path = f->files[f->file_count - 1];
    if (!shadow_normalize(st->side_before.bytes, st->side_before.len,
                          &st->norm_a) ||
        !shadow_normalize(st->side_after.bytes, st->side_after.len,
                          &st->norm_b))
        return false;
    shadow_hash_side(&st->before, path, &st->norm_a);
    shadow_hash_side(&st->after, path, &st->norm_b);
    bool same = st->norm_a.len == st->norm_b.len &&
                memcmp(st->norm_a.bytes, st->norm_b.bytes, st->norm_a.len) == 0;
    if (!same) {
        st->any_changed = true;
        if (!shadow_normalize(st->removed.bytes, st->removed.len,
                              &st->norm_a))
            return false;
        st->any_moved = st->any_moved || st->norm_a.len > 0;
    }
    st->side_before.len = st->side_after.len = 0;
    st->removed.len = st->added.len = 0;
    return true;
}

static bool shadow_begin_file(struct shadow_patch_state *st, const char *line,
                              size_t len)
{
    struct zcl_shadow_patch_facts *f = st->facts;
    if (!shadow_flush_file(st)) return false;
    const char *b = NULL;
    for (size_t i = 0; i + 3 <= len; i++)
        if (memcmp(line + i, " b/", 3) == 0) b = line + i + 3;
    if (!b || f->file_count >= ZCL_SHADOW_MAX_FILES) return false;
    size_t plen = (size_t)(line + len - b);
    if (plen == 0 || plen >= ZCL_SHADOW_PATH_MAX) return false;
    memcpy(f->files[f->file_count], b, plen);
    f->files[f->file_count][plen] = '\0';
    f->created[f->file_count] = false;
    st->current_contract =
        zcl_shadow_path_is_contract(st->component, f->files[f->file_count]);
    f->file_count++;
    st->in_header = true;
    return true;
}

static bool shadow_body_line(struct shadow_patch_state *st, const char *line,
                             size_t len)
{
    if (!st->current_contract || len == 0) return true;
    const char *body = line + 1;
    size_t n = len - 1;
    bool ok = true;
    if (line[0] == ' ' || line[0] == '-')
        ok = shadow_buf_put(&st->side_before, body, n) &&
             shadow_buf_put(&st->side_before, "\n", 1);
    if (ok && (line[0] == ' ' || line[0] == '+'))
        ok = shadow_buf_put(&st->side_after, body, n) &&
             shadow_buf_put(&st->side_after, "\n", 1);
    if (ok && line[0] == '-')
        ok = shadow_buf_put(&st->removed, body, n) &&
             shadow_buf_put(&st->removed, "\n", 1);
    if (ok && line[0] == '+')
        ok = shadow_buf_put(&st->added, body, n) &&
             shadow_buf_put(&st->added, "\n", 1);
    return ok;
}

static bool shadow_patch_line(struct shadow_patch_state *st, const char *line,
                              size_t len)
{
    struct zcl_shadow_patch_facts *f = st->facts;
    if (len >= 11 && memcmp(line, "diff --git ", 11) == 0)
        return shadow_begin_file(st, line, len);
    if (f->file_count == 0) return true; /* preamble before the first diff */
    if (len >= 2 && memcmp(line, "@@", 2) == 0) {
        st->in_header = false;
        f->hunks++;
        f->contract_hunks += st->current_contract ? 1u : 0u;
        return true;
    }
    if (st->in_header) {
        if (len >= 13 && memcmp(line, "new file mode", 13) == 0)
            f->created[f->file_count - 1] = true;
        return true;
    }
    if (line[0] == '\\') return true;
    return shadow_body_line(st, line, len);
}

static void shadow_patch_begin(struct shadow_patch_state *st,
                               const char *component,
                               struct zcl_shadow_patch_facts *out)
{
    memset(st, 0, sizeof(*st));
    memset(out, 0, sizeof(*out));
    st->component = component;
    st->facts = out;
    static const char domain[] = "zcl.shadow.contract_delta.v1";
    sha3_256_init(&st->before);
    sha3_256_init(&st->after);
    sha3_256_write(&st->before, (const unsigned char *)domain, sizeof(domain));
    sha3_256_write(&st->after, (const unsigned char *)domain, sizeof(domain));
    sha3_256_write(&st->before, (const unsigned char *)component,
                   strlen(component) + 1);
    sha3_256_write(&st->after, (const unsigned char *)component,
                   strlen(component) + 1);
}

bool zcl_shadow_patch_analyze(const char *component, const uint8_t *bytes,
                              size_t len, struct zcl_shadow_patch_facts *out,
                              char *why, size_t why_len)
{
    if (!component || !bytes || !out) return false;
    struct shadow_patch_state st;
    shadow_patch_begin(&st, component, out);
    size_t pos = 0, line_len;
    const char *line;
    bool ok = true;
    while (ok && shadow_next_line((const char *)bytes, len, &pos, &line,
                                  &line_len))
        ok = shadow_patch_line(&st, line, line_len);
    ok = ok && shadow_flush_file(&st) && out->file_count > 0 &&
         out->hunks > 0;
    sha3_256_finalize(&st.before, out->contract_before);
    sha3_256_finalize(&st.after, out->contract_after);
    out->contract_change = !st.any_changed ? ZCL_SHADOW_CONTRACT_NONE
                           : st.any_moved  ? ZCL_SHADOW_CONTRACT_MOVED
                                           : ZCL_SHADOW_CONTRACT_ADDITIVE;
    shadow_state_free(&st);
    if (!ok) shadow_why(why, why_len, "patch_unparseable");
    return ok;
}

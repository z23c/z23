/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * code.packet source access: the bounded, once-per-request file cache, the
 * verbatim excerpt builder (head and tail elision past max_lines), and the
 * line-anchored scans of the governed definition files (module capabilities,
 * remote command classes, the test-group catalog). Every byte is read through
 * code_read_source_file under a per-request total; nothing here writes,
 * locks, spawns or walks a directory. See native_code_packet_priv.h. */

#include "command/native_code_packet_priv.h"

#include "base/safe_alloc.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── growable text ──────────────────────────────────────────────────────── */

void pk_sb_free(struct pk_sb *sb)
{
    free(sb->p);
    memset(sb, 0, sizeof(*sb));
}

static bool pk_sb_reserve(struct pk_sb *sb, size_t extra)
{
    if (sb->len + extra + 1 > PK_SB_MAX) {
        sb->over = true;
        return false;
    }
    if (sb->len + extra + 1 <= sb->cap)
        return true;
    size_t want = sb->cap ? sb->cap : 1024;
    while (want < sb->len + extra + 1)
        want *= 2;
    char *np = zcl_realloc(sb->p, want, "code_packet_text");
    if (!np) {
        sb->over = true;
        return false;
    }
    sb->p = np;
    sb->cap = want;
    return true;
}

void pk_sb_raw(struct pk_sb *sb, const char *s, size_t n)
{
    if (sb->over || !pk_sb_reserve(sb, n))
        return;
    memcpy(sb->p + sb->len, s, n);
    sb->len += n;
    sb->p[sb->len] = '\0';
}

void pk_sb_add(struct pk_sb *sb, const char *fmt, ...)
{
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0) {
        sb->over = true;
        return;
    }
    if ((size_t)n < sizeof(tmp)) {
        pk_sb_raw(sb, tmp, (size_t)n);
        return;
    }
    char *big = zcl_malloc((size_t)n + 1, "code_packet_fmt");
    if (!big) {
        sb->over = true;
        return;
    }
    va_start(ap, fmt);
    (void)vsnprintf(big, (size_t)n + 1, fmt, ap);
    va_end(ap);
    pk_sb_raw(sb, big, (size_t)n);
    free(big);
}

/* ── the bounded source cache ───────────────────────────────────────────── */

static const struct pk_src *pk_cached(const struct pk_ctx *ctx, const char *rel)
{
    for (int i = 0; i < ctx->ncache; i++)
        if (strcmp(ctx->cache[i].path, rel) == 0)
            return &ctx->cache[i];
    return NULL;
}

/* Read `e->path` under the per-request and per-file budgets. */
static void pk_read_entry(struct pk_ctx *ctx, struct pk_src *e)
{
    char full[4096];
    int pn = snprintf(full, sizeof(full), "%s/%s", ctx->root, e->path);
    size_t remaining = PK_READ_TOTAL_MAX > ctx->bytes_read
                           ? PK_READ_TOTAL_MAX - ctx->bytes_read : 0;
    size_t max = remaining < PK_READ_FILE_MAX ? remaining : PK_READ_FILE_MAX;
    if (pn > 0 && (size_t)pn < sizeof(full) && max > 0)
        e->text = code_read_source_file(full, max, &e->len);
    if (e->text) {
        ctx->bytes_read += e->len;
        e->ok = true;
        return;
    }
    e->why = max == 0 ? "read_budget" : "source_unreadable";
    ctx->budget_hit = ctx->budget_hit || max == 0;
}

const struct pk_src *pk_load(struct pk_ctx *ctx, const char *rel,
                             const char **why)
{
    const struct pk_src *hit = pk_cached(ctx, rel);
    if (!hit) {
        if (ctx->ncache >= PK_CACHE_N ||
            strlen(rel) >= sizeof(ctx->cache[0].path)) {
            if (why) *why = "source_cache_full";
            return NULL;
        }
        struct pk_src *e = &ctx->cache[ctx->ncache++];
        memset(e, 0, sizeof(*e));
        (void)snprintf(e->path, sizeof(e->path), "%s", rel);
        pk_read_entry(ctx, e);
        hit = e;
    }
    if (!hit->ok && why) *why = hit->why;
    return hit->ok ? hit : NULL;
}

void pk_ctx_free(struct pk_ctx *ctx)
{
    for (int i = 0; i < ctx->ncache; i++)
        free(ctx->cache[i].text);
    ctx->ncache = 0;
}

/* ── lines ──────────────────────────────────────────────────────────────── */

static int pk_line_count(const char *t, size_t len)
{
    int n = 0;
    for (size_t i = 0; i < len; i++)
        if (t[i] == '\n') n++;
    if (len > 0 && t[len - 1] != '\n') n++;
    return n;
}

/* Offset of 1-based `line`'s first byte; len when past the end. */
static size_t pk_line_start(const char *t, size_t len, int line)
{
    size_t i = 0;
    for (int cur = 1; cur < line && i < len; cur++) {
        while (i < len && t[i] != '\n') i++;
        if (i < len) i++;
    }
    return i;
}

static int pk_line_end_of(const char *t, size_t len, size_t off)
{
    int n = 0;
    for (size_t i = 0; i < off && i < len; i++)
        if (t[i] == '\n') n++;
    return n;
}

/* Append lines [a, b] verbatim, each newline-terminated. */
static void pk_emit_lines(struct pk_sb *sb, const char *t, size_t len, int a,
                          int b)
{
    size_t i = pk_line_start(t, len, a);
    for (int cur = a; cur <= b && i < len; cur++) {
        size_t e = i;
        while (e < len && t[e] != '\n') e++;
        pk_sb_raw(sb, t + i, e - i);
        pk_sb_raw(sb, "\n", 1);
        i = e < len ? e + 1 : e;
    }
}

int pk_find_line(const struct pk_src *src, const char *needle)
{
    size_t nl = strlen(needle);
    int line = 1;
    size_t i = 0;
    while (i < src->len) {
        size_t s = i;
        while (s < src->len && (src->text[s] == ' ' || src->text[s] == '\t'))
            s++;
        if (src->len - s >= nl && memcmp(src->text + s, needle, nl) == 0)
            return line;
        while (i < src->len && src->text[i] != '\n') i++;
        i++;
        line++;
    }
    return 0;
}

/* Last line of a one-statement declaration beginning on `line`: the first
 * line at or after it carrying a `;`, within 12 lines. */
static int pk_stmt_end_line(const char *t, size_t len, int line)
{
    size_t i = pk_line_start(t, len, line);
    for (int cur = line; cur < line + 12 && i < len; cur++) {
        size_t e = i;
        bool semi = false;
        while (e < len && t[e] != '\n') {
            if (t[e] == ';') semi = true;
            e++;
        }
        if (semi) return cur;
        i = e < len ? e + 1 : e;
    }
    return line;
}

/* Last line of a #define: follows backslash continuations (at most 200). */
static int pk_macro_end_line(const char *t, size_t len, int line)
{
    size_t i = pk_line_start(t, len, line);
    int cur = line;
    for (; cur < line + 200 && i < len; cur++) {
        size_t e = i;
        while (e < len && t[e] != '\n') e++;
        size_t k = e;
        while (k > i && (t[k - 1] == '\r' || t[k - 1] == ' ' ||
                         t[k - 1] == '\t'))
            k--;
        if (k == i || t[k - 1] != '\\') return cur;
        i = e < len ? e + 1 : e;
    }
    return cur;
}

/* ── excerpts ───────────────────────────────────────────────────────────── */

static void pk_window_fill(struct pk_excerpt *ex, const struct pk_src *src,
                           int max_lines)
{
    int n = ex->last - ex->first + 1;
    if (n <= max_lines) {
        pk_emit_lines(&ex->text, src->text, src->len, ex->first, ex->last);
        ex->shown = n;
        return;
    }
    int tail = max_lines / 4;
    int head = max_lines - 1 - tail;
    ex->elide_from = ex->first + head;
    ex->elide_to = ex->last - tail;
    pk_emit_lines(&ex->text, src->text, src->len, ex->first,
                  ex->elide_from - 1);
    pk_sb_add(&ex->text, "/* ... %d lines elided (L%d-L%d) ... */\n",
              ex->elide_to - ex->elide_from + 1, ex->elide_from, ex->elide_to);
    pk_emit_lines(&ex->text, src->text, src->len, ex->elide_to + 1, ex->last);
    ex->shown = head + tail;
}

void pk_excerpt_free(struct pk_excerpt *ex)
{
    pk_sb_free(&ex->text);
}

static int pk_definition_end(const struct pk_src *src, const struct ci_symbol *s,
                             int line, bool has_def, const char **status)
{
    if (!has_def)
        return pk_stmt_end_line(src->text, src->len, line);
    if (s->kind == 'M')
        return pk_macro_end_line(src->text, src->len, line);
    size_t st = 0, en = 0;
    if (code_source_extent(src->text, src->len, line, &st, &en))
        return line + pk_line_end_of(src->text + st, en - st + 1, en - st);
    if (s->kind == 'T' || s->kind == 't')
        *status = "no_body";
    return pk_stmt_end_line(src->text, src->len, line);
}

void pk_excerpt_symbol(struct pk_ctx *ctx, const struct ci_symbol *s,
                       int context, int max_lines, struct pk_excerpt *ex)
{
    memset(ex, 0, sizeof(*ex));
    (void)snprintf(ex->symbol, sizeof(ex->symbol), "%s", s->name);
    ex->kind = s->kind;
    bool has_def = s->def_path[0] != '\0' && s->def_line >= 1;
    const char *file = has_def ? s->def_path : s->decl_path;
    ex->site_line = has_def ? s->def_line : s->decl_line;
    (void)snprintf(ex->file, sizeof(ex->file), "%s", file);
    ex->status = has_def ? "ok" : "declaration_only";
    const char *why = NULL;
    const struct pk_src *src = file[0] ? pk_load(ctx, file, &why) : NULL;
    if (!src || ex->site_line < 1) {
        ex->status = why ? why : "source_unreadable";
        return;
    }
    int total = pk_line_count(src->text, src->len);
    if (ex->site_line > total) {
        ex->status = "no_body";
        return;
    }
    ex->end_line = pk_definition_end(src, s, ex->site_line, has_def,
                                     &ex->status);
    ex->first = ex->site_line > context ? ex->site_line - context : 1;
    ex->last = ex->end_line + context < total ? ex->end_line + context : total;
    pk_window_fill(ex, src, max_lines);
}

void pk_excerpt_neighborhood(struct pk_ctx *ctx, const struct ci_symbol *s,
                             int first, int last, int max_lines,
                             struct pk_excerpt *ex)
{
    pk_excerpt_symbol(ctx, s, 0, max_lines, ex);
    if (!ex->text.len) return;
    const struct pk_src *src = pk_load(ctx, ex->file, NULL);
    if (!src) return;
    int total = pk_line_count(src->text, src->len);
    int spare = max_lines - (last - first + 1);
    ex->first = first - spare / 2;
    if (ex->first < 1) ex->first = 1;
    ex->last = ex->first + max_lines - 1;
    if (ex->last > total) {
        ex->last = total;
        ex->first = total - max_lines + 1;
        if (ex->first < 1) ex->first = 1;
    }
    pk_sb_free(&ex->text);
    ex->shown = ex->elide_from = ex->elide_to = 0;
    pk_window_fill(ex, src, max_lines);
}

void pk_excerpt_site(struct pk_ctx *ctx, const char *file, int line,
                     int context, struct pk_excerpt *ex)
{
    memset(ex, 0, sizeof(*ex));
    (void)snprintf(ex->file, sizeof(ex->file), "%s", file);
    ex->site_line = line;
    ex->status = "ok";
    const char *why = NULL;
    const struct pk_src *src = pk_load(ctx, file, &why);
    if (!src || line < 1) {
        ex->status = why ? why : "source_unreadable";
        return;
    }
    int total = pk_line_count(src->text, src->len);
    ex->end_line = line;
    ex->first = line > context ? line - context : 1;
    ex->last = line + context < total ? line + context : total;
    pk_window_fill(ex, src, PK_LINES_MAX);
}

/* ── the governed definition-file scans ─────────────────────────────────── */

/* Copy the body of the literal at *s (just past its opening quote) into out,
 * unescaping backslashes; "..." marks a body longer than cap. Leaves *s on
 * the closing quote or the terminator. */
static void pk_quoted_body(const char **s, char *out, size_t cap)
{
    size_t n = 0;
    const char *p = *s;
    while (*p && *p != '"' && n + 4 < cap) {
        if (*p == '\\' && p[1]) p++;
        out[n++] = *p++;
    }
    out[n] = '\0';
    if (*p && *p != '"') {
        memcpy(out + n, "...", 4);
        while (*p && *p != '"') {
            if (*p == '\\' && p[1]) p++;
            p++;
        }
    }
    *s = p;
}

/* Copy one double-quoted literal at *p (after blanks) into out; advance. */
static void pk_quoted(const char **p, char *out, size_t cap)
{
    const char *s = *p;
    while (*s == ' ' || *s == '\t' || *s == '\n') s++;
    out[0] = '\0';
    if (*s == '"') {
        s++;
        pk_quoted_body(&s, out, cap);
        if (*s == '"') s++;
    }
    *p = s;
}

/* Fill row from the macro call starting after `("key",`: TOKEN, "note". */
static void pk_row_args(const char *after, struct pk_row *row)
{
    while (*after == ' ' || *after == '\t') after++;
    size_t n = 0;
    while (*after && *after != ',' && *after != ')' && n + 1 < sizeof(row->caps))
        row->caps[n++] = *after++;
    while (n > 0 && (row->caps[n - 1] == ' ' || row->caps[n - 1] == '\n'))
        n--;
    row->caps[n] = '\0';
    if (*after == ',') {
        after++;
        pk_quoted(&after, row->note, sizeof(row->note));
    }
}

/* The macro call `macro("key", ...)` at a line start in `src`; line 0 when
 * absent. Never matches inside a comment (only blanks may precede it). */
static int pk_scan_macro(const struct pk_src *src, const char *macro,
                         const char *key, struct pk_row *row)
{
    char needle[600];
    int nn = snprintf(needle, sizeof(needle), "%s(\"%s\",", macro, key);
    if (nn <= 0 || (size_t)nn >= sizeof(needle))
        return 0;
    int line = pk_find_line(src, needle);
    if (line == 0)
        return 0;
    size_t off = pk_line_start(src->text, src->len, line);
    const char *at = strstr(src->text + off, needle);
    if (at)
        pk_row_args(at + nn, row);
    return line;
}

static void pk_row_over(struct pk_ctx *ctx, const char *const *defs, size_t nd,
                        const char *macro, const char *key, struct pk_row *row)
{
    memset(row, 0, sizeof(*row));
    for (size_t i = 0; i < nd && !row->found; i++) {
        const struct pk_src *src = pk_load(ctx, defs[i], NULL);
        if (!src)
            continue;
        int line = pk_scan_macro(src, macro, key, row);
        if (line > 0) {
            row->found = true;
            row->line = line;
            (void)snprintf(row->source, sizeof(row->source), "%s", defs[i]);
        }
    }
}

void pk_capability_row(struct pk_ctx *ctx, const char *path, struct pk_row *row)
{
    static const char *const defs[] = {
        "engine/composition/module_capabilities.def",
        "engine/composition/module_capabilities_linux.def",
        "engine/composition/module_capabilities_windows.def",
    };
    pk_row_over(ctx, defs, 3, "ZCL_MODULE_CAPABILITY", path, row);
}

void pk_remote_class_row(struct pk_ctx *ctx, const char *command,
                         struct pk_row *row)
{
    static const char *const defs[] = {
        "engine/composition/remote_command_classes.def",
    };
    pk_row_over(ctx, defs, 1, "REMOTE_COMMAND_CLASS", command, row);
}

int pk_catalog_line(struct pk_ctx *ctx, const char *full_id)
{
    const struct pk_src *src =
        pk_load(ctx, "tools/dev/test_group_catalog.def", NULL);
    if (!src)
        return 0;
    const char *macro = strncmp(full_id, "spec_", 5) == 0 ? "ZCL_SPEC_GROUP"
                                                          : "ZCL_TEST_GROUP";
    char needle[160];
    (void)snprintf(needle, sizeof(needle), "%s(%s)", macro, full_id + 5);
    return pk_find_line(src, needle);
}

bool pk_git_head(const struct pk_ctx *ctx, char *out, size_t cap)
{
    return zcl_native_workspace_head(ctx->root, out, cap);
}

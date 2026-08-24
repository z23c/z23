/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * cli_render — human presentation layer for the native command registry.
 * See cli_render.h for the prime directive (pipes stay byte-identical
 * canonical JSON; only a TTY / ZCL_HUMAN=1 gets these renderings).
 *
 * One module, four shared emitters — section header, kv line, table, and a
 * bounded JSON tree — that every per-shape renderer below composes. Design
 * tokens are structural, not color gimmicks: bold for the thing named,
 * dim for labels, red/green only where the value IS the signal (error
 * codes, sync state, blockers). No allocation anywhere: every renderer
 * writes into the caller's buffer through struct buf. */

#include "command/cli_render.h"

#include "json/json.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* ── output buffer ─────────────────────────────────────────────────── */

struct buf {
    char *p;
    size_t cap;
    size_t len;
    bool overflow;
};

static void buf_putn(struct buf *b, const char *s, size_t n)
{
    if (b->overflow)
        return;
    if (b->len + n >= b->cap) {
        b->overflow = true;
        return;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void buf_puts(struct buf *b, const char *s)
{
    if (s)
        buf_putn(b, s, strlen(s));
}

static void buf_putc(struct buf *b, char c)
{
    buf_putn(b, &c, 1);
}

static void buf_printf(struct buf *b, const char *fmt, ...)
{
    if (b->overflow)
        return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= b->cap - b->len) {
        b->overflow = true;
        return;
    }
    b->len += (size_t)n;
}

/* ── environment ───────────────────────────────────────────────────── */

static bool env_bool(const char *name, bool *decided)
{
    const char *v = getenv(name);
    if (!v || !v[0])
        return false;
    *decided = true;
    return strcmp(v, "1") == 0 || strcmp(v, "true") == 0 ||
           strcmp(v, "yes") == 0 || strcmp(v, "on") == 0;
}

struct zcl_cli_render_env zcl_cli_render_resolve(int fd)
{
    struct zcl_cli_render_env env = {
        .human = false, .ansi = false, .width = 80, .max_rows = 24,
    };

    bool decided = false;
    bool forced = env_bool("ZCL_HUMAN", &decided);
    env.human = decided ? forced : (isatty(fd) != 0);

    const char *term = getenv("TERM");
    /* NO_COLOR: presence disables, even empty (no-color.org convention). */
    env.ansi = env.human && !getenv("NO_COLOR") &&
               !(term && strcmp(term, "dumb") == 0);

    struct winsize ws;
    if (fd >= 0 && ioctl(fd, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        env.width = ws.ws_col;
    else {
        const char *cols = getenv("COLUMNS");
        if (cols && cols[0]) {
            int c = atoi(cols);
            if (c > 0)
                env.width = c;
        }
    }
    if (env.width < 40)
        env.width = 40;
    if (env.width > 240)
        env.width = 240;
    return env;
}

/* ── ANSI tokens ───────────────────────────────────────────────────── */

static void ansi_bold(struct buf *b, const struct zcl_cli_render_env *e,
                      const char *s)
{
    if (e->ansi)
        buf_puts(b, "\033[1m");
    buf_puts(b, s);
    if (e->ansi)
        buf_puts(b, "\033[0m");
}

static void ansi_dim(struct buf *b, const struct zcl_cli_render_env *e,
                     const char *s)
{
    if (e->ansi)
        buf_puts(b, "\033[2m");
    buf_puts(b, s);
    if (e->ansi)
        buf_puts(b, "\033[0m");
}

/* color: 31 red, 32 green, 33 yellow */
static void ansi_color(struct buf *b, const struct zcl_cli_render_env *e,
                       int color, const char *s)
{
    if (e->ansi)
        buf_printf(b, "\033[%dm", color);
    buf_puts(b, s);
    if (e->ansi)
        buf_puts(b, "\033[0m");
}

/* ── text measurement / truncation ─────────────────────────────────── */

/* Display columns: every byte that is not a UTF-8 continuation byte. */
static size_t dwidth(const char *s)
{
    size_t n = 0;
    for (const unsigned char *p = (const unsigned char *)s; p && *p; p++)
        if ((*p & 0xC0) != 0x80)
            n++;
    return n;
}

/* Emit at most `cols` display columns of s, never splitting a UTF-8
 * sequence; if the string did not fit, end it with a one-column ellipsis.
 * Returns the columns emitted. */
static size_t buf_puts_trunc(struct buf *b, const char *s, size_t cols)
{
    if (!s)
        return 0;
    if (dwidth(s) <= cols) {
        buf_puts(b, s);
        return dwidth(s);
    }
    if (cols == 0)
        return 0;
    size_t budget = cols - 1; /* reserve one column for the ellipsis */
    size_t emitted = 0;
    const unsigned char *p = (const unsigned char *)s;
    while (*p && emitted < budget) {
        size_t seqlen = 1;
        if ((*p & 0x80) != 0) {
            if ((*p & 0xE0) == 0xC0)
                seqlen = 2;
            else if ((*p & 0xF0) == 0xE0)
                seqlen = 3;
            else if ((*p & 0xF8) == 0xF0)
                seqlen = 4;
        }
        buf_putn(b, (const char *)p, seqlen);
        p += seqlen;
        emitted++;
    }
    buf_puts(b, "…");
    return emitted + 1;
}

/* ── shared emitters ───────────────────────────────────────────────── */

/* Section header: bold text on its own line, capped at the width. */
static void emit_header(struct buf *b, const struct zcl_cli_render_env *e,
                        const char *text)
{
    if (e->ansi)
        buf_puts(b, "\033[1m");
    buf_puts_trunc(b, text, (size_t)e->width);
    if (e->ansi)
        buf_puts(b, "\033[0m");
    buf_putc(b, '\n');
}

/* One kv line: two-space indent, dim key padded to `kw` columns, value
 * truncated to the remaining width. */
static void emit_kv(struct buf *b, const struct zcl_cli_render_env *e,
                    size_t kw, const char *key, const char *value)
{
    buf_puts(b, "  ");
    size_t klen = strlen(key);
    char kpadded[64];
    if (klen < sizeof(kpadded)) {
        memcpy(kpadded, key, klen + 1);
        while (klen < kw && klen < sizeof(kpadded) - 1) {
            kpadded[klen] = ' ';
            kpadded[++klen] = '\0';
        }
        ansi_dim(b, e, kpadded);
    } else {
        ansi_dim(b, e, key);
    }
    buf_puts(b, "  ");
    size_t used = 2 + kw + 2;
    size_t room = (size_t)e->width > used ? (size_t)e->width - used : 1;
    buf_puts_trunc(b, value ? value : "", room);
    buf_putc(b, '\n');
}

/* A table: headers[ncols], cells row-major rows*ncols (borrowed pointers).
 * When the natural widths exceed the terminal, the widest column yields one
 * column at a time (floor 6) until everything fits — the long
 * summary/description columns absorb most of the slack by construction.
 * Caller caps rows and prints the "... (N more, ...)" footer itself. */
static void emit_table(struct buf *b, const struct zcl_cli_render_env *e,
                       int ncols, const char *const *headers,
                       const char *const *cells, size_t rows)
{
    size_t w[8] = {0};
    for (int c = 0; c < ncols && c < 8; c++) {
        w[c] = dwidth(headers[c]);
        for (size_t r = 0; r < rows; r++) {
            size_t cw = dwidth(cells[r * (size_t)ncols + (size_t)c]);
            if (cw > w[c])
                w[c] = cw;
        }
        if (w[c] > 48)
            w[c] = 48;
    }
    size_t total = 2; /* leading indent */
    for (int c = 0; c < ncols; c++)
        total += w[c];
    total += 2 * (size_t)(ncols - 1);
    while (total > (size_t)e->width) {
        int widest = -1;
        for (int c = 0; c < ncols; c++)
            if (w[c] > 6 && (widest < 0 || w[c] > w[widest]))
                widest = c;
        if (widest < 0)
            break;
        w[widest]--;
        total--;
    }

    buf_puts(b, "  ");
    for (int c = 0; c < ncols; c++) {
        if (c + 1 == ncols) {
            ansi_bold(b, e, headers[c]);
            break;
        }
        char hdr[64];
        size_t hn = snprintf(hdr, sizeof(hdr), "%s", headers[c]);
        size_t pad = w[c] > hn ? w[c] - hn : 0;
        if (hn + pad >= sizeof(hdr))
            pad = sizeof(hdr) - 1 - hn;
        memset(hdr + hn, ' ', pad);
        hdr[hn + pad] = '\0';
        ansi_bold(b, e, hdr);
        buf_puts(b, "  ");
    }
    buf_putc(b, '\n');

    for (size_t r = 0; r < rows; r++) {
        buf_puts(b, "  ");
        for (int c = 0; c < ncols; c++) {
            const char *cell = cells[r * (size_t)ncols + (size_t)c];
            size_t used = buf_puts_trunc(b, cell ? cell : "", w[c]);
            for (size_t pad = used; c + 1 < ncols && pad < w[c]; pad++)
                buf_putc(b, ' ');
            if (c + 1 < ncols)
                buf_puts(b, "  ");
        }
        buf_putc(b, '\n');
    }
}

static void emit_more_footer(struct buf *b, size_t more)
{
    buf_printf(b, "... (%zu more, pipe to JSON for full)\n", more);
}

/* "next: <shell>" / "run: <shell>" hint line, width-capped. */
static void emit_hint_line(struct buf *b, const struct zcl_cli_render_env *e,
                           const char *label, const char *shell)
{
    size_t llen = strlen(label);
    buf_puts(b, label);
    if (e->ansi)
        buf_puts(b, "\033[1m");
    size_t room = (size_t)e->width > llen ? (size_t)e->width - llen : 1;
    buf_puts_trunc(b, shell, room);
    if (e->ansi)
        buf_puts(b, "\033[0m");
    buf_putc(b, '\n');
}

/* ── bounded JSON tree (ops.state / ops.logs data) ─────────────────── */

struct tree_ctx {
    struct buf *b;
    const struct zcl_cli_render_env *e;
    size_t lines;
    size_t max_lines;
    bool truncated;
};

static void scalar_text(const struct json_value *v, char *out, size_t cap)
{
    switch (v ? v->type : JSON_NULL) {
    case JSON_STR: {
        const char *s = json_get_str(v);
        snprintf(out, cap, "%s", s ? s : "");
        break;
    }
    case JSON_INT:
        snprintf(out, cap, "%lld", (long long)json_get_int(v));
        break;
    case JSON_REAL:
        snprintf(out, cap, "%g", json_get_real(v));
        break;
    case JSON_BOOL:
        snprintf(out, cap, "%s", json_get_bool(v) ? "true" : "false");
        break;
    default:
        snprintf(out, cap, "null");
        break;
    }
}

static bool tree_room(struct tree_ctx *ctx)
{
    if (ctx->lines >= ctx->max_lines) {
        ctx->truncated = true;
        return false;
    }
    return true;
}

static void emit_tree_node(struct tree_ctx *ctx, const char *key,
                           const struct json_value *v, int depth);

/* Widest scalar-child key at this object level, for kv alignment. */
static size_t tree_key_width(const struct json_value *obj)
{
    size_t kw = 0;
    for (size_t i = 0; i < obj->num_children; i++) {
        const struct json_value *c = &obj->children[i];
        if (c->type != JSON_OBJ && c->type != JSON_ARR) {
            size_t k = strlen(obj->keys[i]);
            if (k > kw)
                kw = k;
        }
    }
    if (kw > 32)
        kw = 32;
    return kw;
}

static void emit_tree_object(struct tree_ctx *ctx, const struct json_value *obj,
                             int depth)
{
    /* Scalar children align on the widest sibling key; object/array
     * children get their own "key:" section line and recurse. */
    size_t kw = tree_key_width(obj);
    for (size_t i = 0; i < obj->num_children; i++) {
        if (!tree_room(ctx))
            return;
        const struct json_value *c = &obj->children[i];
        if (c->type != JSON_OBJ && c->type != JSON_ARR) {
            char val[1024];
            scalar_text(c, val, sizeof(val));
            ctx->lines++;
            emit_kv(ctx->b, ctx->e, kw, obj->keys[i], val);
            continue;
        }
        emit_tree_node(ctx, obj->keys[i], c, depth);
    }
}

static void emit_tree_array(struct tree_ctx *ctx, const char *key,
                            const struct json_value *arr, int depth)
{
    bool all_scalar = arr->num_children > 0;
    for (size_t i = 0; i < arr->num_children; i++)
        if (arr->children[i].type == JSON_OBJ ||
            arr->children[i].type == JSON_ARR) {
            all_scalar = false;
            break;
        }
    if (arr->num_children == 0) {
        ctx->lines++;
        emit_kv(ctx->b, ctx->e, 0, key, "[]");
        return;
    }
    if (all_scalar) {
        /* Short scalar arrays inline as csv; long ones one per line. A log
         * line array (ops.logs "lines") is the natural one-per-line case. */
        size_t total_len = 0;
        for (size_t i = 0; i < arr->num_children; i++) {
            const char *s = json_get_str(&arr->children[i]);
            total_len += s ? strlen(s) : 16;
        }
        if (arr->num_children <= 6 &&
            total_len + 2 * arr->num_children <
                (size_t)ctx->e->width / 2) {
            char joined[512];
            size_t jl = 0;
            joined[0] = '\0';
            for (size_t i = 0; i < arr->num_children; i++) {
                char item[160];
                scalar_text(&arr->children[i], item, sizeof(item));
                int n = snprintf(joined + jl, sizeof(joined) - jl, "%s%s",
                                 i ? ", " : "", item);
                if (n < 0 || (size_t)n >= sizeof(joined) - jl)
                    break;
                jl += (size_t)n;
            }
            ctx->lines++;
            emit_kv(ctx->b, ctx->e, 0, key, joined);
            return;
        }
        for (size_t i = 0; i < arr->num_children; i++) {
            if (!tree_room(ctx))
                return;
            char item[1024];
            scalar_text(&arr->children[i], item, sizeof(item));
            ctx->lines++;
            emit_kv(ctx->b, ctx->e, 0, i == 0 ? key : "", item);
        }
        return;
    }
    for (size_t i = 0; i < arr->num_children; i++) {
        if (!tree_room(ctx))
            return;
        char idx[24];
        snprintf(idx, sizeof(idx), "%s[%zu]", key ? key : "", i);
        emit_tree_node(ctx, idx, &arr->children[i], depth);
    }
}

static void emit_tree_node(struct tree_ctx *ctx, const char *key,
                           const struct json_value *v, int depth)
{
    if (v->type == JSON_OBJ) {
        if (depth >= 6) {
            ctx->lines++;
            emit_kv(ctx->b, ctx->e, 0, key, "{…}");
            return;
        }
        if (key && key[0]) {
            ctx->lines++;
            buf_puts(ctx->b, "  ");
            ansi_dim(ctx->b, ctx->e, key);
            buf_puts(ctx->b, ":\n");
        }
        emit_tree_object(ctx, v, depth + 1);
        return;
    }
    if (v->type == JSON_ARR) {
        emit_tree_array(ctx, key, v, depth);
        return;
    }
    char val[1024];
    scalar_text(v, val, sizeof(val));
    ctx->lines++;
    emit_kv(ctx->b, ctx->e, 0, key, val);
}

/* ── error suggestions ─────────────────────────────────────────────── */

/* Curated code → next-action table. This is the optional suggestion
 * descriptor the mission asks for: an entry here is a human-worded next
 * step for a code the registry's own next[] does not cover well; codes
 * absent from the table fall back to the envelope's next[0], then to
 * none. "%s" substitutes the envelope's command path. */
static const struct {
    const char *code;
    const char *suggestion;
} g_error_suggestions[] = {
    { "MISSING_SUBSYSTEM", "z23 statecatalog" },
    { "STATE_ERROR", "z23 statecatalog" },
    { "UNKNOWN_COMMAND", "z23 discover search <query>" },
    { "MISSING_QUERY", "z23 discover search <query>" },
    { "MISSING_PATH", "z23 discover help" },
    { "UNKNOWN_PATH", "z23 discover help" },
    { "BAD_INPUT", "z23 discover schema %s" },
    { "INVALID_INPUT", "z23 discover schema %s" },
    { "BAD_FLAG", "z23 discover schema %s" },
    { "TOO_MANY_ARGS", "z23 discover schema %s" },
    { "DUPLICATE_CONTROL", "z23 discover schema %s" },
    { "NODE_UNAVAILABLE", "z23 status" },
    { "CONNECT_REFUSED", "z23 status" },
    { "AUTH_REJECTED", "z23 status" },
};

static const char *error_suggestion_for(const char *code)
{
    if (!code)
        return NULL;
    for (size_t i = 0;
         i < sizeof(g_error_suggestions) / sizeof(g_error_suggestions[0]);
         i++)
        if (strcmp(g_error_suggestions[i].code, code) == 0)
            return g_error_suggestions[i].suggestion;
    return NULL;
}

/* Render an envelope next[0] ({command, input, reason}) as one executable
 * shell line. discover.* single-key inputs (path/query) render as the
 * documented positional; anything else as --input='<json>'. */
static void next_as_shell(const struct json_value *next, char *out,
                          size_t cap)
{
    out[0] = '\0';
    const char *cmd = json_get_str(json_get(next, "command"));
    if (!cmd || !cmd[0])
        return;
    char words[128];
    size_t wl = 0;
    for (const char *p = cmd; *p && wl + 1 < sizeof(words); p++)
        words[wl++] = *p == '.' ? ' ' : *p;
    words[wl] = '\0';

    const struct json_value *input = json_get(next, "input");
    if (input && input->type == JSON_OBJ && input->num_children == 1 &&
        (strcmp(input->keys[0], "path") == 0 ||
         strcmp(input->keys[0], "query") == 0)) {
        const char *v = json_get_str(&input->children[0]);
        snprintf(out, cap, "z23 %s %s", words, v ? v : "");
        return;
    }
    if (input && input->type == JSON_OBJ && input->num_children > 0) {
        char ij[384];
        size_t n = json_write(input, ij, sizeof(ij));
        if (n > 0 && n < sizeof(ij)) {
            snprintf(out, cap, "z23 %s --input='%s'", words, ij);
            return;
        }
    }
    snprintf(out, cap, "z23 %s", words);
}

/* ── per-shape renderers ───────────────────────────────────────────── */

static void render_menu(struct buf *b, const struct zcl_cli_render_env *e,
                        const struct json_value *root)
{
    const char *path = json_get_str(json_get(root, "path"));
    const char *summary = json_get_str(json_get(root, "summary"));
    bool is_root = !path || strcmp(path, "root") == 0;

    char head[256];
    snprintf(head, sizeof(head), "%s — %s", is_root ? "z23" : path,
             summary ? summary : "");
    emit_header(b, e, head);
    buf_putc(b, '\n');

    const struct json_value *children = json_get(root, "children");
    size_t total = children && children->type == JSON_ARR
                       ? children->num_children
                       : 0;
    size_t rows = total > e->max_rows ? e->max_rows : total;
    if (rows > 24)
        rows = 24;
    const char *headers[4] = { "PATH", "SUMMARY", "RISK", "AVAIL" };
    const char *cellbuf[24 * 4];
    if (rows > 0) {
        for (size_t r = 0; r < rows; r++) {
            const struct json_value *ch = json_at(children, r);
            cellbuf[r * 4 + 0] = json_get_str(json_get(ch, "path"));
            cellbuf[r * 4 + 1] = json_get_str(json_get(ch, "summary"));
            cellbuf[r * 4 + 2] = json_get_str(json_get(ch, "risk"));
            cellbuf[r * 4 + 3] = json_get_str(json_get(ch, "availability"));
        }
        emit_table(b, e, 4, headers, cellbuf, rows);
    }
    if (total > rows)
        emit_more_footer(b, total - rows);

    const struct json_value *next = json_get(root, "next");
    if (next && next->type == JSON_OBJ) {
        char shell[512];
        next_as_shell(next, shell, sizeof(shell));
        if (shell[0]) {
            buf_putc(b, '\n');
            emit_hint_line(b, e, "next: ", shell);
        }
    }
}

static void render_search(struct buf *b, const struct zcl_cli_render_env *e,
                          const struct json_value *root)
{
    const char *query = json_get_str(json_get(root, "query"));
    int64_t count = json_get_int(json_get(root, "count"));
    int64_t total = json_get_int(json_get(root, "total_matches"));

    char head[256];
    if (total > count)
        snprintf(head, sizeof(head), "%lld of %lld matches for \"%s\"",
                 (long long)count, (long long)total, query ? query : "");
    else
        snprintf(head, sizeof(head), "%lld matches for \"%s\"",
                 (long long)count, query ? query : "");
    emit_header(b, e, head);
    buf_putc(b, '\n');

    const struct json_value *matches = json_get(root, "matches");
    size_t rows = matches && matches->type == JSON_ARR
                      ? matches->num_children
                      : 0;
    if (rows > e->max_rows)
        rows = e->max_rows;
    if (rows > 24)
        rows = 24;
    const char *headers[4] = { "PATH", "MATCH", "RISK", "AVAIL" };
    const char *cellbuf[24 * 4];
    for (size_t r = 0; r < rows; r++) {
        const struct json_value *m = json_at(matches, r);
        cellbuf[r * 4 + 0] = json_get_str(json_get(m, "path"));
        cellbuf[r * 4 + 1] = json_get_str(json_get(m, "reason"));
        cellbuf[r * 4 + 2] = json_get_str(json_get(m, "risk"));
        cellbuf[r * 4 + 3] = json_get_str(json_get(m, "availability"));
    }
    if (rows > 0) {
        emit_table(b, e, 4, headers, cellbuf, rows);
        buf_putc(b, '\n');
    }

    const struct json_value *next = json_get(root, "next");
    if (next && next->type == JSON_OBJ) {
        char shell[512];
        next_as_shell(next, shell, sizeof(shell));
        if (shell[0])
            emit_hint_line(b, e, "next: ", shell);
    }
}

static void render_spec(struct buf *b, const struct zcl_cli_render_env *e,
                        const struct json_value *root)
{
    const char *path = json_get_str(json_get(root, "path"));
    const char *summary = json_get_str(json_get(root, "summary"));
    const char *avail = json_get_str(json_get(root, "availability"));

    char head[256];
    snprintf(head, sizeof(head), "%s — %s", path ? path : "",
             summary ? summary : "");
    emit_header(b, e, head);

    char availbuf[160];
    availbuf[0] = '\0';
    if (avail && avail[0]) {
        snprintf(availbuf, sizeof(availbuf), "%s", avail);
        const char *reason =
            json_get_str(json_get(root, "availability_reason"));
        if (reason && reason[0])
            snprintf(availbuf + strlen(availbuf),
                     sizeof(availbuf) - strlen(availbuf), " — %s", reason);
    }
    if (availbuf[0])
        emit_kv(b, e, 12, "availability", availbuf);

    const char *sem = json_get_str(json_get(root, "semantics"));
    if (sem && sem[0]) {
        buf_putc(b, '\n');
        size_t room = (size_t)e->width > 2 ? (size_t)e->width - 2 : 1;
        buf_puts(b, "  ");
        buf_puts_trunc(b, sem, room);
        buf_putc(b, '\n');
        buf_putc(b, '\n');
    }

    const struct json_value *input = json_get(root, "input_schema");
    const struct json_value *allowed =
        input ? json_get(input, "allowed_keys") : NULL;
    const struct json_value *positional =
        input ? json_get(input, "positional_keys") : NULL;
    if (allowed && allowed->type == JSON_ARR) {
        char keys[384];
        keys[0] = '\0';
        size_t kl = 0;
        for (size_t i = 0; i < allowed->num_children; i++) {
            const char *k = json_get_str(json_at(allowed, i));
            bool pos = false;
            if (positional && positional->type == JSON_ARR)
                for (size_t j = 0; j < positional->num_children; j++) {
                    const char *pk = json_get_str(json_at(positional, j));
                    if (k && pk && strcmp(k, pk) == 0)
                        pos = true;
                }
            int n = snprintf(keys + kl, sizeof(keys) - kl, "%s%s%s",
                             i ? ", " : "", k ? k : "",
                             pos ? " (positional)" : "");
            if (n < 0 || (size_t)n >= sizeof(keys) - kl)
                break;
            kl += (size_t)n;
        }
        emit_kv(b, e, 12, "input",
                allowed->num_children ? keys : "(no arguments)");
    }
    const char *out_schema = json_get_str(json_get(root, "output_schema"));
    if (out_schema && out_schema[0])
        emit_kv(b, e, 12, "output", out_schema);

    const struct json_value *policy = json_get(root, "policy");
    if (policy && policy->type == JSON_OBJ) {
        char pol[384];
        snprintf(pol, sizeof(pol),
                 "%s · %s · %s · %s latency · %s cost · %lld ms budget",
                 json_get_str(json_get(policy, "effect"))
                     ? json_get_str(json_get(policy, "effect"))
                     : "?",
                 json_get_str(json_get(policy, "scope"))
                     ? json_get_str(json_get(policy, "scope"))
                     : "?",
                 json_get_str(json_get(policy, "authority"))
                     ? json_get_str(json_get(policy, "authority"))
                     : "?",
                 json_get_str(json_get(policy, "latency"))
                     ? json_get_str(json_get(policy, "latency"))
                     : "?",
                 json_get_str(json_get(policy, "cost"))
                     ? json_get_str(json_get(policy, "cost"))
                     : "?",
                 (long long)json_get_int(json_get(policy, "budget_ms")));
        emit_kv(b, e, 12, "policy", pol);
    }

    const struct json_value *aliases = json_get(root, "aliases");
    if (aliases && aliases->type == JSON_ARR && aliases->num_children > 0) {
        char al[256];
        al[0] = '\0';
        size_t al_len = 0;
        for (size_t i = 0; i < aliases->num_children; i++) {
            const char *a = json_get_str(json_at(aliases, i));
            int n = snprintf(al + al_len, sizeof(al) - al_len, "%s%s",
                             i ? ", " : "", a ? a : "");
            if (n < 0 || (size_t)n >= sizeof(al) - al_len)
                break;
            al_len += (size_t)n;
        }
        emit_kv(b, e, 12, "aliases", al);
    }

    const char *example = json_get_str(json_get(root, "example"));
    if (example && example[0]) {
        buf_putc(b, '\n');
        buf_puts(b, "  ");
        ansi_dim(b, e, "example:    ");
        if (e->ansi)
            buf_puts(b, "\033[1m");
        size_t room = (size_t)e->width > 14 ? (size_t)e->width - 14 : 1;
        buf_puts_trunc(b, example, room);
        if (e->ansi)
            buf_puts(b, "\033[0m");
        buf_putc(b, '\n');
    }
}

static void render_schema_doc(struct buf *b,
                              const struct zcl_cli_render_env *e,
                              const struct json_value *root)
{
    const char *path = json_get_str(json_get(root, "path"));
    const char *side = json_get_str(json_get(root, "side"));
    char head[256];
    snprintf(head, sizeof(head), "%s (%s)", path ? path : "",
             side ? side : "input");
    emit_header(b, e, head);
    const char *id = json_get_str(json_get(root, "id"));
    if (id && id[0])
        emit_kv(b, e, 8, "id", id);
    const char *keys = json_get_str(json_get(root, "allowed_keys"));
    char spaced[384];
    if (keys && keys[0]) {
        /* the schema doc carries keys as one CSV string; humans read ", " */
        size_t sl = 0;
        for (const char *p = keys; *p && sl + 2 < sizeof(spaced); p++) {
            if (*p == ',') {
                spaced[sl++] = ',';
                spaced[sl++] = ' ';
            } else {
                spaced[sl++] = *p;
            }
        }
        spaced[sl] = '\0';
        keys = spaced;
    }
    emit_kv(b, e, 8, "keys",
            (keys && keys[0]) ? keys : "(no arguments)");
}

static void render_statecatalog(struct buf *b,
                                const struct zcl_cli_render_env *e,
                                const struct json_value *root)
{
    int64_t count = json_get_int(json_get(root, "count"));
    char head[256];
    snprintf(head, sizeof(head),
             "%lld dumpstate subsystems — z23 ops state "
             "--subsystem=<name>",
             (long long)count);
    emit_header(b, e, head);
    buf_putc(b, '\n');

    const struct json_value *subs = json_get(root, "subsystems");
    size_t total = subs && subs->type == JSON_ARR ? subs->num_children : 0;
    size_t rows = total > e->max_rows ? e->max_rows : total;
    if (rows > 24)
        rows = 24;
    const char *headers[4] = { "NAME", "COST", "KEYS", "DESCRIPTION" };
    const char *cellbuf[24 * 4];
    char keybuf[24][64];
    for (size_t r = 0; r < rows; r++) {
        const struct json_value *s = json_at(subs, r);
        cellbuf[r * 4 + 0] = json_get_str(json_get(s, "name"));
        cellbuf[r * 4 + 1] = json_get_str(json_get(s, "cost"));
        const struct json_value *keys = json_get(s, "accepted_keys");
        if (keys && keys->type == JSON_ARR && keys->num_children > 0) {
            size_t kl = 0;
            keybuf[r][0] = '\0';
            for (size_t i = 0; i < keys->num_children; i++) {
                const char *k = json_get_str(json_at(keys, i));
                int n = snprintf(keybuf[r] + kl, sizeof(keybuf[r]) - kl,
                                 "%s%s", i ? "," : "", k ? k : "");
                if (n < 0 || (size_t)n >= sizeof(keybuf[r]) - kl)
                    break;
                kl += (size_t)n;
            }
        } else if (keys && keys->type == JSON_STR) {
            snprintf(keybuf[r], sizeof(keybuf[r]), "%s", json_get_str(keys));
        } else {
            snprintf(keybuf[r], sizeof(keybuf[r]), "-");
        }
        cellbuf[r * 4 + 2] = keybuf[r];
        cellbuf[r * 4 + 3] = json_get_str(json_get(s, "description"));
    }
    if (rows > 0)
        emit_table(b, e, 4, headers, cellbuf, rows);
    if (total > rows)
        emit_more_footer(b, total - rows);
}

static void render_error(struct buf *b, const struct zcl_cli_render_env *e,
                         const struct json_value *root)
{
    const struct json_value *err = json_get(root, "error");
    const char *code = err ? json_get_str(json_get(err, "code")) : NULL;
    const char *message = err ? json_get_str(json_get(err, "message")) : NULL;
    const char *phase = err ? json_get_str(json_get(err, "phase")) : NULL;
    const char *command = json_get_str(json_get(root, "command"));

    if (e->ansi)
        buf_puts(b, "\033[1;31m");
    buf_puts(b, "error:");
    if (e->ansi)
        buf_puts(b, "\033[0m");
    buf_putc(b, ' ');
    ansi_bold(b, e, code ? code : "UNKNOWN");
    if (phase && phase[0])
        buf_printf(b, " (%s)", phase);
    buf_putc(b, '\n');

    if (message && message[0]) {
        size_t room = (size_t)e->width > 2 ? (size_t)e->width - 2 : 1;
        buf_puts(b, "  ");
        buf_puts_trunc(b, message, room);
        buf_putc(b, '\n');
    }
    const char *evidence = err ? json_get_str(json_get(err, "evidence")) : NULL;
    if (evidence && evidence[0] && command &&
        strcmp(evidence, command) != 0) {
        size_t room = (size_t)e->width > 2 ? (size_t)e->width - 2 : 1;
        buf_puts(b, "  ");
        ansi_dim(b, e, "at: ");
        buf_puts_trunc(b, evidence, room > 4 ? room - 4 : 1);
        buf_putc(b, '\n');
    }

    char suggestion[512];
    suggestion[0] = '\0';
    /* UNKNOWN_COMMAND's envelope next[0] carries the operator's actual
     * query — a concrete "search <typo>" beats the table's generic one. */
    const struct json_value *next = json_get(root, "next");
    const struct json_value *first =
        next && next->type == JSON_ARR ? json_at(next, 0) : NULL;
    if (code && strcmp(code, "UNKNOWN_COMMAND") == 0 && first &&
        first->type == JSON_OBJ) {
        const char *ncmd = json_get_str(json_get(first, "command"));
        if (ncmd && strcmp(ncmd, "discover.search") == 0)
            next_as_shell(first, suggestion, sizeof(suggestion));
    }
    const char *fmt = suggestion[0] ? NULL : error_suggestion_for(code);
    if (fmt) {
        if (strchr(fmt, '%'))
            snprintf(suggestion, sizeof(suggestion), fmt,
                     (command && command[0]) ? command : "<path>");
        else
            snprintf(suggestion, sizeof(suggestion), "%s", fmt);
    } else if (!suggestion[0]) {
        if (first && first->type == JSON_OBJ)
            next_as_shell(first, suggestion, sizeof(suggestion));
    }
    if (suggestion[0]) {
        if (e->ansi)
            buf_puts(b, "\033[32m");
        buf_puts(b, "run:");
        if (e->ansi)
            buf_puts(b, "\033[0m");
        buf_putc(b, ' ');
        if (e->ansi)
            buf_puts(b, "\033[1m");
        size_t room = (size_t)e->width > 5 ? (size_t)e->width - 5 : 1;
        buf_puts_trunc(b, suggestion, room);
        if (e->ansi)
            buf_puts(b, "\033[0m");
        buf_putc(b, '\n');
    }
}

/* Leaves whose ok=true envelope data renders as a human tree. Extend by
 * adding a path here — everything else keeps the canonical JSON even on a
 * TTY (the registry document IS its human form for discovery leaves). */
static bool tree_render_leaf(const char *command_path)
{
    return command_path &&
           (strcmp(command_path, "ops.state") == 0 ||
            strcmp(command_path, "ops.logs") == 0);
}

/* zcode.guide is a recipe: one next action, one copyable start, the journey. */
static void render_zcode_guide(struct buf *b, const struct zcl_cli_render_env *e,
                               const struct json_value *root)
{
    emit_header(b, e, "zcode.guide");
    buf_putc(b, '\n');
    const struct json_value *data = json_get(root, "data");
    const char *mission = json_get_str(json_get(data, "mission"));
    const char *next = json_get_str(json_get(data, "next_action"));
    const char *journey = json_get_str(json_get(data, "journey"));
    const char *keep = json_get_str(json_get(data, "continue_rule"));
    if (mission && mission[0])
        emit_kv(b, e, 4, "do", mission);
    if (next && next[0])
        emit_kv(b, e, 4, "next", next);
    emit_kv(b, e, 4, "run",
            json_get_str(json_get(data, "start_command")));
    if (journey && journey[0])
        emit_kv(b, e, 4, "then", journey);
    if (keep && keep[0])
        emit_kv(b, e, 4, "keep", keep);
}

/* code.guide is a recipe, not a schema dump: four copyable commands. */
static void render_code_guide(struct buf *b, const struct zcl_cli_render_env *e,
                              const struct json_value *root)
{
    emit_header(b, e, "code.guide");
    buf_putc(b, '\n');
    const struct json_value *data = json_get(root, "data");
    emit_kv(b, e, 6, "run",
            json_get_str(json_get(data, "start_command")));
    emit_kv(b, e, 6, "prove",
            json_get_str(json_get(data, "proof_command")));
    emit_kv(b, e, 6, "lint",
            json_get_str(json_get(data, "lint_command")));
    emit_kv(b, e, 6, "push",
            json_get_str(json_get(data, "push_command")));
    const char *never = json_get_str(json_get(data, "never"));
    if (never && never[0]) {
        buf_putc(b, '\n');
        emit_kv(b, e, 6, "never", never);
    }
}

/* Who is connected: address, direction, advertised height, kind.
 * Lifecycle, bytes, ping, and services stay behind JSON. */
static void render_peer_list(struct buf *b, const struct zcl_cli_render_env *e,
                             const struct json_value *root)
{
    const struct json_value *data = json_get(root, "data");
    const struct json_value *items = data ? json_get(data, "items") : NULL;
    const struct json_value *page = data ? json_get(data, "_page") : NULL;
    int64_t total = page ? json_get_int(json_get(page, "total_items")) : 0;
    size_t n = items && items->type == JSON_ARR ? items->num_children : 0;
    char head[96];
    if (total > (int64_t)n)
        snprintf(head, sizeof(head), "peers — %zu of %lld connected", n,
                 (long long)total);
    else
        snprintf(head, sizeof(head), "peers — %zu connected", n);
    emit_header(b, e, head);
    buf_putc(b, '\n');

    size_t rows = n > e->max_rows ? e->max_rows : n;
    if (rows > 24)
        rows = 24;
    const char *headers[4] = { "ADDR", "DIR", "HEIGHT", "KIND" };
    const char *cellbuf[24 * 4];
    char dirbuf[24][4];
    char hbuf[24][12];
    char kindbuf[24][8];
    for (size_t r = 0; r < rows; r++) {
        const struct json_value *row = json_at(items, r);
        const struct json_value *inb = json_get(row, "inbound");
        const struct json_value *z23 = json_get(row, "zclassic23");
        const struct json_value *bean = json_get(row, "magicbean");
        const struct json_value *ht = json_get(row, "startingheight");
        bool inbound = inb && inb->type == JSON_BOOL && json_get_bool(inb);
        bool is_z23 = z23 && z23->type == JSON_BOOL && json_get_bool(z23);
        bool is_bean = bean && bean->type == JSON_BOOL && json_get_bool(bean);
        snprintf(dirbuf[r], sizeof(dirbuf[r]), "%s", inbound ? "in" : "out");
        if (ht && ht->type == JSON_INT)
            snprintf(hbuf[r], sizeof(hbuf[r]), "%lld",
                     (long long)json_get_int(ht));
        else
            snprintf(hbuf[r], sizeof(hbuf[r]), "?");
        snprintf(kindbuf[r], sizeof(kindbuf[r]), "%s",
                 is_z23 ? "z23" : (is_bean ? "bean" : "other"));
        cellbuf[r * 4 + 0] = json_get_str(json_get(row, "addr"));
        cellbuf[r * 4 + 1] = dirbuf[r];
        cellbuf[r * 4 + 2] = hbuf[r];
        cellbuf[r * 4 + 3] = kindbuf[r];
    }
    if (rows > 0)
        emit_table(b, e, 4, headers, cellbuf, rows);
    if (n > rows)
        emit_more_footer(b, n - rows);

    const char *cont = page ? json_get_str(json_get(page, "continue")) : NULL;
    if (cont && cont[0]) {
        buf_putc(b, '\n');
        emit_hint_line(b, e, "run: ", cont);
    }
}

static void render_data_tree(struct buf *b,
                             const struct zcl_cli_render_env *e,
                             const struct json_value *root,
                             const char *command_path)
{
    char head[192];
    snprintf(head, sizeof(head), "%s", command_path ? command_path : "");
    emit_header(b, e, head);
    buf_putc(b, '\n');

    const struct json_value *data = json_get(root, "data");
    struct tree_ctx ctx = {
        .b = b, .e = e, .lines = 0,
        .max_lines = e->max_rows * 3, .truncated = false,
    };
    if (data && data->type == JSON_OBJ)
        emit_tree_object(&ctx, data, 0);
    else if (data && data->type == JSON_ARR)
        emit_tree_array(&ctx, "items", data, 0);
    else {
        char val[256];
        scalar_text(data, val, sizeof(val));
        buf_printf(b, "  %s\n", val);
    }
    if (ctx.truncated)
        buf_puts(b, "... (truncated, pipe to JSON for full)\n");
}

/* ── entry points ──────────────────────────────────────────────────── */

size_t zcl_cli_render_doc(const char *doc, size_t doc_len,
                          const char *command_path,
                          const struct zcl_cli_render_env *env,
                          char *out, size_t cap)
{
    if (!doc || !env || !env->human || !out || cap == 0)
        return 0;

    struct json_value root;
    if (!json_read(&root, doc, doc_len) || root.type != JSON_OBJ) {
        json_free(&root);
        return 0;
    }

    struct buf b = { .p = out, .cap = cap, .len = 0, .overflow = false };
    out[0] = '\0';

    const char *schema = json_get_str(json_get(&root, "schema"));
    bool handled = true;
    if (schema && strcmp(schema, "zcl.command_menu.v1") == 0)
        render_menu(&b, env, &root);
    else if (schema && strcmp(schema, "zcl.command_search.v1") == 0)
        render_search(&b, env, &root);
    else if (schema && strcmp(schema, "zcl.command_spec.v1") == 0)
        render_spec(&b, env, &root);
    else if (schema && strcmp(schema, "zcl.command_schema.v1") == 0)
        render_schema_doc(&b, env, &root);
    else if (schema && strcmp(schema, "zcl.state_catalog.v2") == 0)
        render_statecatalog(&b, env, &root);
    else if (schema && strcmp(schema, "zcl.result.v1") == 0) {
        const struct json_value *okv = json_get(&root, "ok");
        if (okv && okv->type == JSON_BOOL && !json_get_bool(okv))
            render_error(&b, env, &root);
        else if (command_path &&
                 strcmp(command_path, "code.guide") == 0)
            render_code_guide(&b, env, &root);
        else if (command_path &&
                 strcmp(command_path, "zcode.guide") == 0)
            render_zcode_guide(&b, env, &root);
        else if (command_path &&
                 strcmp(command_path, "core.network.peers.list") == 0)
            render_peer_list(&b, env, &root);
        else if (tree_render_leaf(command_path))
            render_data_tree(&b, env, &root, command_path);
        else
            handled = false;
    } else {
        handled = false;
    }

    json_free(&root);
    if (!handled || b.overflow || b.len == 0)
        return 0;
    return b.len;
}

size_t zcl_cli_render_brief(const char *line,
                            const struct zcl_cli_render_env *env,
                            char *out, size_t cap)
{
    if (!line || !env || !out || cap == 0)
        return 0;
    struct buf b = { .p = out, .cap = cap, .len = 0, .overflow = false };
    out[0] = '\0';

    const char *p = line;
    while (*p) {
        while (*p == ' ')
            p++;
        if (!*p)
            break;
        const char *eq = strchr(p, '=');
        if (!eq)
            break;
        const char *end = strchr(eq, ' ');
        if (!end)
            end = p + strlen(p);
        char key[48], val[96];
        size_t kl = (size_t)(eq - p);
        size_t vl = (size_t)(end - eq - 1);
        if (kl >= sizeof(key) || vl >= sizeof(val))
            break;
        memcpy(key, p, kl);
        key[kl] = '\0';
        memcpy(val, eq + 1, vl);
        val[vl] = '\0';

        ansi_dim(&b, env, key);
        buf_putc(&b, '=');
        int color = 0;
        if (strcmp(key, "sync") == 0)
            color = strcmp(val, "synced") == 0 ? 32 : 33;
        else if (strcmp(key, "blocker") == 0 ||
                 strcmp(key, "blocker_head") == 0)
            color = strcmp(val, "none") == 0 ? 32 : 31;
        if (color && env->ansi)
            ansi_color(&b, env, color, val);
        else
            buf_puts(&b, val);
        if (*end)
            buf_putc(&b, ' ');
        p = *end ? end + 1 : end;
    }
    if (b.overflow || b.len == 0)
        return 0;
    return b.len;
}

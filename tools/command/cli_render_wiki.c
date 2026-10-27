/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * cli_render_wiki - terminal presentation of `z23 wiki [topic]`
 * (zcl.wiki_node.v1) and `z23 discover read <page>` (zcl.wiki_page.v1).
 *
 * Same contract as cli_render.c: the canonical JSON is computed first and
 * is untouched; this only runs when a human is watching. Any shape it does
 * not recognize, or output that would not fit, returns 0 and the caller
 * prints the canonical JSON. Allocates nothing. */

#include "command/cli_render.h"
#include "json/json.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

struct wbuf {
    char *p;
    size_t cap;
    size_t len;
    bool overflow;
};

static void w_putn(struct wbuf *b, const char *s, size_t n)
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

static void w_puts(struct wbuf *b, const char *s)
{
    if (s)
        w_putn(b, s, strlen(s));
}

/* Formatted append straight into the output; anything that does not fit
 * marks overflow so the caller falls back to the canonical JSON. */
static void w_printf(struct wbuf *b, const char *fmt, ...)
{
    if (b->overflow)
        return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= b->cap - b->len) {
        b->overflow = true;
        b->p[b->len] = '\0';
        return;
    }
    b->len += (size_t)n;
}

/* Longest prefix of s that fits `room` bytes without splitting UTF-8. */
static size_t w_fit(const char *s, size_t room)
{
    size_t n = strlen(s);
    if (n <= room)
        return n;
    while (room > 0 && ((unsigned char)s[room] & 0xC0) == 0x80)
        room--;
    return room;
}

static void w_header(struct wbuf *b, const struct zcl_cli_render_env *e,
                     const struct json_value *data)
{
    const char *title = json_get_str(json_get(data, "title"));
    const char *path = json_get_str(json_get(data, "path"));
    if (e->ansi)
        w_puts(b, "\033[1m");
    w_puts(b, title && title[0] ? title : "Z23 documentation");
    if (e->ansi)
        w_puts(b, "\033[0m");
    if (path && path[0]) {
        w_puts(b, "  (");
        w_puts(b, path);
        w_puts(b, ")");
    }
    w_puts(b, "\n");
}

static size_t w_slug_width(const struct json_value *kids, size_t rows,
                           size_t width)
{
    size_t w = 4;
    for (size_t i = 0; i < rows; i++) {
        const char *p = json_get_str(json_get(json_at(kids, i), "path"));
        size_t n = p ? strlen(p) : 0;
        if (n > w)
            w = n;
    }
    return w > width / 2 ? width / 2 : w;
}

static void w_row(struct wbuf *b, const char *slug, const char *title,
                  size_t sw, size_t width)
{
    size_t sn = w_fit(slug, sw);
    size_t used = 2 + sw + 2;
    size_t room = width > used ? width - used : 1;
    w_printf(b, "  %.*s%*s  %.*s\n", (int)sn, slug, (int)(sw - sn), "",
             (int)w_fit(title, room), title);
}

/* Continuation for the next window of children (the producer's real
 * `next_after` field), plus the first suggested follow-up. */
static void w_node_hints(struct wbuf *b, const struct json_value *data)
{
    const struct json_value *after = json_get(data, "next_after");
    const char *path = json_get_str(json_get(data, "path"));
    const struct json_value *next = json_get(data, "next");
    const char *first = next && next->type == JSON_ARR && next->num_children
                            ? json_get_str(json_at(next, 0))
                            : NULL;
    if (after && after->type == JSON_INT)
        w_printf(b, "\nmore: z23 wiki%s%s --after=%lld\n",
                 path && path[0] ? " " : "", path ? path : "",
                 (long long)json_get_int(after));
    if (first && first[0])
        w_printf(b, "%snext: %s\n", after ? "" : "\n", first);
}

static void w_node(struct wbuf *b, const struct zcl_cli_render_env *e,
                   const struct json_value *data)
{
    const struct json_value *kids = json_get(data, "children");
    size_t n = kids && kids->type == JSON_ARR ? kids->num_children : 0;
    size_t rows = n > e->max_rows ? e->max_rows : n;
    size_t width = (size_t)e->width;
    w_header(b, e, data);
    w_puts(b, "\n");
    size_t sw = w_slug_width(kids, rows, width);
    for (size_t i = 0; i < rows; i++) {
        const struct json_value *k = json_at(kids, i);
        const char *slug = json_get_str(json_get(k, "path"));
        const char *title = json_get_str(json_get(k, "title"));
        w_row(b, slug ? slug : "?", title ? title : "", sw, width);
    }
    if (n > rows)
        w_printf(b, "... (%zu more in this window; add --json to see them)\n",
                 n - rows);
    w_node_hints(b, data);
}

/* A page is shown whole or not at all: text that does not fit the human
 * buffer returns 0 so the caller prints the canonical JSON (which carries
 * the text and next_offset exactly). Never a silent cut. */
static void w_page(struct wbuf *b, const struct zcl_cli_render_env *e,
                   const struct json_value *data)
{
    const char *text = json_get_str(json_get(data, "text"));
    const struct json_value *noff = json_get(data, "next_offset");
    const char *path = json_get_str(json_get(data, "path"));
    w_header(b, e, data);
    w_puts(b, "\n");
    if (text)
        w_printf(b, "%s\n", text);
    if (noff && noff->type == JSON_INT)
        w_printf(b, "\nmore: z23 discover read %s --offset=%lld\n",
                 path ? path : "<page>", (long long)json_get_int(noff));
}

size_t zcl_cli_render_wiki(const struct json_value *root,
                           const struct zcl_cli_render_env *env, char *out,
                           size_t cap)
{
    if (!root || !env || !env->human || !out || cap == 0)
        return 0;
    const struct json_value *data = json_get(root, "data");
    const char *ds = json_get_str(json_get(root, "data_schema"));
    if (!data || data->type != JSON_OBJ || !ds)
        return 0;
    struct wbuf b = { .p = out, .cap = cap, .len = 0, .overflow = false };
    out[0] = '\0';
    if (strcmp(ds, "zcl.wiki_node.v1") == 0)
        w_node(&b, env, data);
    else if (strcmp(ds, "zcl.wiki_page.v1") == 0)
        w_page(&b, env, data);
    else
        return 0;
    return b.overflow ? 0 : b.len;
}

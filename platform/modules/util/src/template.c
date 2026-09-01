/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * HTML template engine: {{var}}, {{{raw}}}, {{> partial}}. */

#include "util/template.h"
#include <string.h>
#include <stdbool.h>

/* ── HTML escaping ─────────────────────────────────────────── */

size_t html_escape(char *dst, size_t max, const char *src)
{
    if (!dst || max == 0) return 0;
    if (!src) { dst[0] = '\0'; return 0; }
    size_t w = 0;
    for (size_t i = 0; src[i]; i++) {
        const char *esc = NULL;
        size_t elen = 0;
        switch (src[i]) {
        case '<':  esc = "&lt;";   elen = 4; break;
        case '>':  esc = "&gt;";   elen = 4; break;
        case '&':  esc = "&amp;";  elen = 5; break;
        case '"':  esc = "&quot;"; elen = 6; break;
        case '\'': esc = "&#39;";  elen = 5; break;
        default: break;
        }
        if (esc) {
            if (w + elen >= max) break;
            memcpy(dst + w, esc, elen);
            w += elen;
        } else {
            if (w + 1 >= max) break;
            dst[w++] = src[i];
        }
    }
    if (max > 0) dst[w] = '\0';
    return w;
}

/* ── Key validation ────────────────────────────────────────── */

#define TMPL_MAX_KEY_LEN 64

static bool tmpl_valid_key(const char *key, size_t len)
{
    if (len == 0 || len > TMPL_MAX_KEY_LEN) return false;
    for (size_t i = 0; i < len; i++) {
        char c = key[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_'))
            return false;
    }
    return true;
}

/* Validate partial name: alphanumeric + hyphens, max 64 chars. */
static bool tmpl_valid_partial_name(const char *name, size_t len)
{
    if (len == 0 || len > TMPL_MAX_KEY_LEN) return false;
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-'))
            return false;
    }
    return true;
}

/* ── Variable lookup ───────────────────────────────────────── */

static const char *tmpl_lookup(const struct template_var *vars, size_t n,
                               const char *key, size_t key_len)
{
    if (!tmpl_valid_key(key, key_len))
        return NULL;
    for (size_t i = 0; i < n; i++) {
        if (vars[i].key && strlen(vars[i].key) == key_len &&
            memcmp(vars[i].key, key, key_len) == 0)
            return vars[i].value ? vars[i].value : "";
    }
    return NULL;
}

/* ── Partial registry ──────────────────────────────────────── */

static const struct template_partial *g_partials = NULL;
static size_t g_num_partials = 0;

void template_register_partials(const struct template_partial *partials,
                                size_t count)
{
    g_partials = partials;
    g_num_partials = count;
}

static const char *tmpl_lookup_partial(const char *name, size_t name_len)
{
    if (!g_partials || !tmpl_valid_partial_name(name, name_len))
        return NULL;
    for (size_t i = 0; i < g_num_partials; i++) {
        if (g_partials[i].name &&
            strlen(g_partials[i].name) == name_len &&
            memcmp(g_partials[i].name, name, name_len) == 0)
            return g_partials[i].tmpl;
    }
    return NULL;
}

/* ── Render (with recursion depth limit) ───────────────────── */

#define TMPL_MAX_DEPTH 4

static size_t render_impl(const char *tmpl,
                          const struct template_var *vars, size_t num_vars,
                          char *out, size_t out_max, int depth)
{
    if (!out || out_max == 0) return 0;
    if (!tmpl) { out[0] = '\0'; return 0; }
    if (!vars) num_vars = 0;
    if (depth > TMPL_MAX_DEPTH) { out[0] = '\0'; return 0; }

    size_t w = 0;
    const char *p = tmpl;

    while (*p && w + 1 < out_max) {
        /* Triple-brace {{{key}}} — raw output */
        if (p[0] == '{' && p[1] == '{' && p[2] == '{') {
            const char *key_start = p + 3;
            const char *end = strstr(key_start, "}}}");
            if (end) {
                size_t key_len = (size_t)(end - key_start);
                const char *val = tmpl_lookup(vars, num_vars,
                                              key_start, key_len);
                if (val) {
                    size_t vlen = strlen(val);
                    size_t avail = out_max - w - 1;
                    size_t copy = vlen < avail ? vlen : avail;
                    memcpy(out + w, val, copy);
                    w += copy;
                } else {
                    size_t span = (size_t)(end + 3 - p);
                    size_t avail = out_max - w - 1;
                    size_t copy = span < avail ? span : avail;
                    memcpy(out + w, p, copy);
                    w += copy;
                }
                p = end + 3;
                continue;
            }
        }

        /* Partial {{> name}} — inline include */
        if (p[0] == '{' && p[1] == '{' && p[2] == '>') {
            const char *name_start = p + 3;
            /* Skip leading whitespace */
            while (*name_start == ' ') name_start++;
            const char *end = strstr(name_start, "}}");
            if (end) {
                /* Trim trailing whitespace */
                const char *name_end = end;
                while (name_end > name_start && name_end[-1] == ' ')
                    name_end--;
                size_t name_len = (size_t)(name_end - name_start);
                const char *partial = tmpl_lookup_partial(
                    name_start, name_len);
                if (partial) {
                    size_t added = render_impl(partial, vars, num_vars,
                        out + w, out_max - w, depth + 1);
                    w += added;
                }
                /* Missing partial: silently skip (no placeholder) */
                p = end + 2;
                continue;
            }
        }

        /* Double-brace {{key}} — escaped output */
        if (p[0] == '{' && p[1] == '{') {
            const char *key_start = p + 2;
            const char *end = strstr(key_start, "}}");
            if (end) {
                size_t key_len = (size_t)(end - key_start);
                const char *val = tmpl_lookup(vars, num_vars,
                                              key_start, key_len);
                if (val) {
                    size_t added = html_escape(out + w,
                                              out_max - w, val);
                    w += added;
                } else {
                    size_t span = (size_t)(end + 2 - p);
                    size_t avail = out_max - w - 1;
                    size_t copy = span < avail ? span : avail;
                    memcpy(out + w, p, copy);
                    w += copy;
                }
                p = end + 2;
                continue;
            }
        }

        out[w++] = *p++;
    }

    out[w] = '\0';
    return w;
}

size_t template_render(const char *tmpl,
                       const struct template_var *vars, size_t num_vars,
                       char *out, size_t out_max)
{
    return render_impl(tmpl, vars, num_vars, out, out_max, 0);
}

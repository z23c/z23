/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_query — the public query surface: exact/ranked symbol lookup,
 * reverse refs, file→group, the group list, and a bounded human-readable card
 * render. Thin dispatch over the store; verify-on-read lives in the store. */

#include "codeindex_priv.h"

#include "util/log_macros.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

bool codeindex_symbol(struct codeindex *ci, const char *name,
                      struct ci_symbol *out, bool *found)
{
    if (found) *found = false;
    if (!ci || !ci->store || !name || !out)
        LOG_FAIL("codeindex", "null arg to codeindex_symbol");
    return ci_store_symbol_by_name(ci->store, name, out, found);
}

bool codeindex_symbol_by_id(struct codeindex *ci, const char *id,
                            struct ci_symbol *out, bool *found)
{
    if (found) *found = false;
    if (!ci || !ci->store || !id || !out)
        LOG_FAIL("codeindex", "null arg to codeindex_symbol_by_id");
    static const char static_prefix[] = "fn:static:";
    if (strncmp(id, static_prefix, sizeof(static_prefix) - 1) == 0) {
        const char *qualified = id + sizeof(static_prefix) - 1;
        const char *split = strrchr(qualified, ':');
        if (!split || split == qualified || split[1] == '\0')
            return true;
        char path[256];
        size_t path_len = (size_t)(split - qualified);
        if (path_len >= sizeof(path))
            return true;
        memcpy(path, qualified, path_len);
        path[path_len] = '\0';
        return ci_store_symbol_by_name_path(ci->store, split + 1, path,
                                             out, found);
    }

    const char *name = strrchr(id, ':');
    if (!name || name[1] == '\0')
        return true;
    name++;
    if (!ci_store_symbol_by_name(ci->store, name, out, found))
        return false;
    if (!*found)
        return true;
    char canonical[400];
    if (codeindex_symbol_record_id(out, canonical, sizeof(canonical)) < 0 ||
        strcmp(canonical, id) != 0) {
        *found = false;
        memset(out, 0, sizeof(*out));
    }
    return true;
}

int codeindex_find(struct codeindex *ci, const char *query,
                   struct ci_symbol *out, int cap)
{
    if (!ci || !ci->store || !query || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to codeindex_find");
    return ci_store_find_symbols(ci->store, query, out, cap);
}

int codeindex_search_text(struct codeindex *ci, const char *query,
                          struct ci_search_hit *out, int cap)
{
    if (!ci || !ci->store || !query || !query[0] || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to codeindex_search_text");
    return ci_store_search_text(ci->store, query, out, cap);
}

int codeindex_refs(struct codeindex *ci, const char *callee,
                   struct ci_ref *out, int cap)
{
    if (!ci || !ci->store || !callee || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to codeindex_refs");
    return ci_store_refs_by_callee(ci->store, callee, out, cap);
}

bool codeindex_file(struct codeindex *ci, const char *path,
                    struct ci_file *out, bool *found)
{
    if (found) *found = false;
    if (!ci || !ci->store || !path || !out)
        LOG_FAIL("codeindex", "null arg to codeindex_file");
    return ci_store_file_by_path(ci->store, path, out, found);
}

int codeindex_groups(struct codeindex *ci, struct ci_group *out, int cap)
{
    if (!ci || !ci->store || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to codeindex_groups");
    return ci_store_list_groups(ci->store, out, cap);
}

int codeindex_files_in_group(struct codeindex *ci, const char *group,
                             struct ci_file *out, int cap)
{
    if (!ci || !ci->store || !group || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to codeindex_files_in_group");
    return ci_store_files_in_group(ci->store, group, out, cap);
}

int codeindex_file_count(struct codeindex *ci)
{
    if (!ci || !ci->store)
        LOG_ERR("codeindex", "bad arg to codeindex_file_count");
    return ci_store_file_count(ci->store);
}

int codeindex_files_page(struct codeindex *ci, int offset,
                         struct ci_file *out, int cap)
{
    if (!ci || !ci->store || offset < 0 || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to codeindex_files_page");
    return ci_store_files_page(ci->store, offset, out, cap);
}

int codeindex_count_files_in_group(struct codeindex *ci, const char *group,
                                   bool recursive)
{
    if (!ci || !ci->store || !group)
        LOG_ERR("codeindex", "bad arg to codeindex_count_files_in_group");
    return ci_store_count_files_in_group(ci->store, group, recursive);
}

bool codeindex_source_file_counts(struct codeindex *ci,
                                  struct ci_source_file_counts *out)
{
    if (!ci || !ci->store || !out)
        LOG_FAIL("codeindex", "bad arg to codeindex_source_file_counts");
    return ci_store_source_file_counts(ci->store, out);
}

int codeindex_symbols_in_file(struct codeindex *ci, const char *path,
                              struct ci_symbol *out, int cap)
{
    if (!ci || !ci->store || !path || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to codeindex_symbols_in_file");
    return ci_store_symbols_in_file(ci->store, path, out, cap);
}

int codeindex_includes_of_file(struct codeindex *ci, const char *path,
                               char (*out)[256], int cap)
{
    if (!ci || !ci->store || !path || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to codeindex_includes_of_file");
    return ci_store_includes_of_file(ci->store, path, out, cap);
}

int64_t codeindex_include_edge_count(struct codeindex *ci)
{
    if (!ci || !ci->store)
        LOG_ERR("codeindex", "bad arg to codeindex_include_edge_count");
    return ci_store_include_edge_count(ci->store);
}

bool codeindex_path_is_translation_unit(const char *path)
{
    if (!path || !path[0])
        return false;
    size_t n = strlen(path);
    return n >= 2 && path[n - 2] == '.' && path[n - 1] == 'c';
}

static const char *kind_name(char k)
{
    switch (k) {
    case 'T': return "func";
    case 't': return "static func";
    case 'S': return "struct/union";
    case 'Y': return "typedef";
    case 'E': return "enum";
    case 'M': return "macro";
    case 'D': return "data";
    default:  return "symbol";
    }
}

/* Append into buf[*len..cap) if room; always keep NUL-terminated. */
static void app(char *buf, size_t cap, size_t *len, const char *fmt, ...)
{
    if (*len >= cap) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *len, cap - *len, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    *len += (size_t)n;
    if (*len >= cap) *len = cap - 1;  /* clamp on truncation */
}

int codeindex_render_card(struct codeindex *ci, const char *name,
                          char *buf, size_t cap)
{
    if (!ci || !ci->store || !name || !buf || cap == 0)
        LOG_ERR("codeindex", "bad arg to render_card");
    buf[0] = '\0';

    struct ci_symbol s;
    bool found = false;
    if (!ci_store_symbol_by_name(ci->store, name, &s, &found))
        LOG_ERR("codeindex", "symbol lookup failed");
    if (!found)
        return -1;

    size_t len = 0;
    app(buf, cap, &len, "%s  [%s]%s\n", s.name, kind_name(s.kind),
        s.partial ? " (partial)" : "");
    if (s.def_path[0])
        app(buf, cap, &len, "  def:   %s:%d\n", s.def_path, s.def_line);
    if (s.decl_path[0])
        app(buf, cap, &len, "  decl:  %s:%d\n", s.decl_path, s.decl_line);
    if (s.signature[0])
        app(buf, cap, &len, "  sig:   %s\n", s.signature);
    if (s.doc[0])
        app(buf, cap, &len, "  doc:   %s\n", s.doc);
    if (s.guard[0])
        app(buf, cap, &len, "  guard: #ifdef %s\n", s.guard);
    if (s.group[0])
        app(buf, cap, &len, "  group: %s\n", s.group);
    return (int)len;
}

/* ── WF4 code-capsule: call-graph queries + linkage-aware ids ──────────
 *
 * Built on the refs.enclosing column populated by the scan pass. Callers of X
 * are the refs WHERE callee_name = X (who references X); callees of X are the
 * refs WHERE enclosing = X (what X's body references). Both are deterministic
 * (ORDER BY ref_file, ref_line) and bounded by `cap`. */

int codeindex_callers(struct codeindex *ci, const char *name,
                      struct ci_ref *out, int cap)
{
    if (!ci || !ci->store || !name || !out || cap <= 0)
        LOG_ERR("codeindex", "bad args to codeindex_callers");
    return ci_store_refs_by_callee(ci->store, name, out, cap);
}

int codeindex_callees(struct codeindex *ci, const char *enclosing_name,
                      struct ci_ref *out, int cap)
{
    if (!ci || !ci->store || !enclosing_name || !out || cap <= 0)
        LOG_ERR("codeindex", "bad args to codeindex_callees");
    return ci_store_refs_by_enclosing(ci->store, enclosing_name, out, cap);
}

int codeindex_callers_for_symbol(struct codeindex *ci,
                                 const struct ci_symbol *symbol,
                                 struct ci_ref *out, int cap)
{
    if (!ci || !ci->store || !symbol || !out || cap <= 0)
        LOG_ERR("codeindex", "bad args to identity-aware callers");
    if (symbol->kind == 't' && symbol->def_path[0])
        return ci_store_refs_by_callee_file(ci->store, symbol->name,
                                             symbol->def_path, out, cap);
    return ci_store_refs_by_callee(ci->store, symbol->name, out, cap);
}

int codeindex_callees_for_symbol(struct codeindex *ci,
                                 const struct ci_symbol *symbol,
                                 struct ci_ref *out, int cap)
{
    if (!ci || !ci->store || !symbol || !out || cap <= 0)
        LOG_ERR("codeindex", "bad args to identity-aware callees");
    if (symbol->kind == 't' && symbol->def_path[0])
        return ci_store_refs_by_enclosing_file(ci->store, symbol->name,
                                                symbol->def_path, out, cap);
    return ci_store_refs_by_enclosing(ci->store, symbol->name, out, cap);
}

/* Kind → id namespace word. Functions carry linkage in a second component
 * (static/external); other kinds are named directly under their namespace. */
static const char *kind_id_ns(char k)
{
    switch (k) {
    case 'T': case 't': return "fn";
    case 'S': return "struct";
    case 'Y': return "type";
    case 'E': return "enum";
    case 'M': return "macro";
    default:  return "data";  /* 'D' and any unknown kind */
    }
}

int codeindex_symbol_record_id(const struct ci_symbol *s,
                               char *buf, size_t cap)
{
    if (!s || !buf || cap == 0)
        LOG_ERR("codeindex", "bad args to codeindex_symbol_record_id");
    buf[0] = '\0';
    const char *ns = kind_id_ns(s->kind);
    int n;
    if (s->kind == 't' && s->def_path[0]) {
        /* A file-local (static) function is identified by its definition site
         * so two same-named statics in different files never collide. */
        n = snprintf(buf, cap, "%s:static:%s:%s", ns, s->def_path, s->name);
    } else if (s->kind == 'T' || s->kind == 't') {
        n = snprintf(buf, cap, "%s:external:%s", ns, s->name);
    } else {
        n = snprintf(buf, cap, "%s:%s", ns, s->name);
    }
    if (n < 0 || (size_t)n >= cap) {
        buf[0] = '\0';
        LOG_ERR("codeindex", "symbol id overflow for %s", s->name);
    }
    return n;
}

int codeindex_symbol_id(struct codeindex *ci, const char *name,
                        char *buf, size_t cap)
{
    if (!ci || !ci->store || !name || !buf || cap == 0)
        LOG_ERR("codeindex", "bad args to codeindex_symbol_id");
    struct ci_symbol s;
    bool found = false;
    if (!ci_store_symbol_by_name(ci->store, name, &s, &found))
        LOG_ERR("codeindex", "symbol lookup failed in symbol_id");
    if (!found)
        return -1;
    return codeindex_symbol_record_id(&s, buf, cap);
}

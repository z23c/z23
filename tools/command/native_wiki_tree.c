/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: discover.wiki - walk the docs/ knowledge tree one topic at a time:
 * title, summary, children, and the commands a topic names. */

#include "command/native_wiki_priv.h"

#include "config/command_catalog.h"

#include "json/json.h"

#include <stdio.h>
#include <string.h>

enum {
    WK_CHILD_CAP = 64,        /* children per reply */
    WK_CMD_CAP = 16,          /* resolved commands per topic */
    WK_DATA_BUDGET = 30000,   /* estimated child bytes per reply */
    WK_CHILD_OVERHEAD = 96,
};

struct wk_node {
    const struct wk_docs *docs;
    char rel[WK_REL_MAX + 1];
    char real[WK_PATH_MAX];
    int64_t after;
};

void wk_fail(struct zcl_command_reply *reply, const char *code,
             const char *message, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "resolve", false,
                           false, message, evidence);
}

static void wk_unknown_topic(const struct wk_docs *docs, const char *rel,
                             struct zcl_command_reply *reply)
{
    char parent[WK_REL_MAX + 1];
    char in[WK_REL_MAX + 32];
    wk_nearest_topic(docs, rel, parent, sizeof(parent));
    wk_fail(reply, "UNKNOWN_TOPIC", "no such topic; nearest existing topic is "
            "in the evidence", parent[0] ? parent : "(root)");
    int n = snprintf(in, sizeof(in), "{\"page\":\"%s%sREADME.md\"}", parent,
                     parent[0] ? "/" : "");
    if (n > 0 && (size_t)n < sizeof(in))
        (void)zcl_command_reply_add_next(reply, "discover.read", in,
                                         "read the nearest existing topic");
}

static bool wk_target(const struct zcl_command_request *request,
                      const struct wk_docs *docs, struct wk_node *node,
                      struct zcl_command_reply *reply)
{
    const char *topic = json_get_str(json_get(request->input, "topic"));
    if (!wk_rel_normalize(topic ? topic : "", node->rel, sizeof(node->rel))) {
        wk_fail(reply, "BAD_TOPIC", "topic must be a relative path inside "
                "docs/ without . or .. segments", "topic");
        return false;
    }
    enum wk_status st = wk_resolve(docs, node->rel, node->real,
                                   sizeof(node->real));
    if (st == WK_ESCAPES) {
        wk_fail(reply, "OUTSIDE_DOCS", "topic resolves outside docs/", "topic");
        return false;
    }
    if (st != WK_OK || !wk_is_topic(docs, node->real)) {
        wk_unknown_topic(docs, node->rel, reply);
        return false;
    }
    node->docs = docs;
    node->after = json_get_int(json_get(request->input, "after"));
    return true;
}

static bool wk_join(char *out, size_t cap, const char *dir, const char *name)
{
    int n = dir[0] ? snprintf(out, cap, "%s/%s", dir, name)
                   : snprintf(out, cap, "%s", name);
    return n > 0 && (size_t)n < cap;
}

static size_t wk_esc_len(const char *s)
{
    size_t n = 0;
    for (; *s; s++)
        n += (*s == '"' || *s == '\\') ? 2 : 1;
    return n;
}

static void wk_scan_file(const char *real, struct wk_meta *meta)
{
    char head[WK_HEAD_MAX + 1];
    size_t n = 0;
    meta->title[0] = '\0';
    meta->summary[0] = '\0';
    if (wk_head(real, head, sizeof(head), &n))
        wk_meta_scan(head, n, meta);
}

static bool wk_child_meta(const struct wk_node *node, const struct wk_child *c,
                          struct wk_meta *meta)
{
    char path[WK_PATH_MAX];
    int n = c->topic ? snprintf(path, sizeof(path), "%s/%s/README.md",
                                node->real, c->name)
                     : snprintf(path, sizeof(path), "%s/%s", node->real,
                                c->name);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    wk_scan_file(path, meta);
    if (!meta->title[0])
        snprintf(meta->title, sizeof(meta->title), "%s", c->name);
    return true;
}

static bool wk_push_child(struct json_value *arr, const char *rel,
                          const struct wk_child *c, const struct wk_meta *m)
{
    char path[WK_REL_MAX + WK_NAME_MAX + 2];
    struct json_value o;
    if (!wk_join(path, sizeof(path), rel, c->name))
        return false;
    json_init(&o);
    json_set_object(&o);
    bool ok = json_push_kv_str(&o, "kind", c->topic ? "topic" : "page") &&
              json_push_kv_str(&o, "path", path) &&
              json_push_kv_str(&o, "title", m->title) &&
              json_push_kv_str(&o, "summary", m->summary) &&
              json_push_back(arr, &o);
    json_free(&o);
    return ok;
}

static bool wk_push_str(struct json_value *arr, const char *s)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s);
    bool ok = json_push_back(arr, &v);
    json_free(&v);
    return ok;
}

/* Emits the window of children after `node->after`; returns the index one
 * past the last child emitted. */
static bool wk_emit_children(const struct wk_node *node,
                             const struct wk_children *kids,
                             struct json_value *arr, size_t *end)
{
    size_t i = node->after < 0 || (uint64_t)node->after > kids->n
                   ? kids->n : (size_t)node->after;
    size_t budget = 0;
    for (size_t used = 0; i < kids->n && used < WK_CHILD_CAP; i++, used++) {
        struct wk_meta m;
        if (!wk_child_meta(node, &kids->v[i], &m))
            return false;
        budget += WK_CHILD_OVERHEAD + strlen(node->rel) +
                  strlen(kids->v[i].name) + wk_esc_len(m.title) +
                  wk_esc_len(m.summary);
        if (budget > WK_DATA_BUDGET && used > 0)
            break;
        if (!wk_push_child(arr, node->rel, &kids->v[i], &m))
            return false;
    }
    *end = i;
    return true;
}

/* The `Commands:` line of a topic README, or NULL. */
static const char *wk_commands_line(const char *head)
{
    for (const char *p = head; p && *p; p = strchr(p, '\n')) {
        if (*p == '\n')
            p++;
        if (strncmp(p, "Commands:", 9) == 0)
            return p + 9;
    }
    return NULL;
}

/* Registry path for one backticked token, or NULL when it does not resolve. */
static const char *wk_resolve_token(const char *tok, size_t len)
{
    char buf[ZCL_COMMAND_MAX_PATH];
    if (len == 0 || len >= sizeof(buf))
        return NULL;
    memcpy(buf, tok, len);
    buf[len] = '\0';
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(), buf, NULL);
    return spec ? spec->path : NULL;
}

static bool wk_commands(const char *head, struct json_value *arr, int *bad)
{
    const char *q = wk_commands_line(head);
    const char *eol = q ? strchr(q, '\n') : NULL;
    size_t span = q ? (eol ? (size_t)(eol - q) : strlen(q)) : 0;
    const char *end = q ? q + span : NULL;
    while (q && (q = memchr(q, '`', (size_t)(end - q))) != NULL) {
        const char *e = memchr(q + 1, '`', (size_t)(end - q - 1));
        if (!e)
            break;
        const char *path = wk_resolve_token(q + 1, (size_t)(e - q - 1));
        if (!path)
            (*bad)++;
        else if (json_size(arr) < WK_CMD_CAP && !wk_push_str(arr, path))
            return false;
        q = e + 1;
    }
    return true;
}

static bool wk_next(struct json_value *next, const struct wk_node *node,
                    const struct wk_children *kids, size_t first, size_t end)
{
    char s[WK_REL_MAX + WK_NAME_MAX + 64];
    char path[WK_REL_MAX + WK_NAME_MAX + 2];
    bool topic_done = false, page_done = false;
    for (size_t i = first; i < end; i++) {
        bool t = kids->v[i].topic;
        if ((t && topic_done) || (!t && page_done))
            continue;
        if (!wk_join(path, sizeof(path), node->rel, kids->v[i].name))
            return false;
        snprintf(s, sizeof(s), t ? "z23 wiki %s" : "z23 discover read %s", path);
        if (!wk_push_str(next, s))
            return false;
        topic_done = topic_done || t;
        page_done = page_done || !t;
    }
    if (end < kids->n) {
        snprintf(s, sizeof(s), "z23 wiki %s --after=%zu", node->rel, end);
        return wk_push_str(next, s);
    }
    return true;
}

static bool wk_push_readme_hint(struct json_value *next, const char *rel)
{
    char path[WK_REL_MAX + 16];
    char s[WK_REL_MAX + 64];
    if (!wk_join(path, sizeof(path), rel, "README.md"))
        return false;
    snprintf(s, sizeof(s), "z23 discover read %s", path);
    return wk_push_str(next, s);
}

static bool wk_push_arr(struct zcl_command_reply *reply, const char *key,
                        struct json_value *arr)
{
    bool ok = json_push_kv(&reply->data, key, arr);
    json_free(arr);
    return ok;
}

static void wk_self_title(const struct wk_node *node, struct wk_meta *self)
{
    if (self->title[0])
        return;
    const char *slash = strrchr(node->rel, '/');
    snprintf(self->title, sizeof(self->title), "%s",
             slash ? slash + 1 : node->rel[0] ? node->rel : "docs");
}

static bool wk_push_head(struct zcl_command_reply *reply,
                         const struct wk_node *node, const struct wk_meta *self,
                         size_t total, size_t end, int unresolved)
{
    bool ok = json_push_kv_str(&reply->data, "path", node->rel) &&
              json_push_kv_str(&reply->data, "title", self->title) &&
              json_push_kv_str(&reply->data, "summary", self->summary) &&
              json_push_kv_int(&reply->data, "children_total", (int64_t)total) &&
              json_push_kv_int(&reply->data, "commands_unresolved", unresolved);
    if (ok && end < total)
        ok = json_push_kv_int(&reply->data, "next_after", (int64_t)end);
    return ok;
}

static bool wk_build(struct zcl_command_reply *reply, const struct wk_node *node,
                     const struct wk_children *kids)
{
    struct json_value ch, cmds, next;
    struct wk_meta self;
    char readme[WK_PATH_MAX], head[WK_HEAD_MAX + 1];
    size_t hn = 0, end = 0;
    int bad = 0;
    json_init(&ch); json_set_array(&ch);
    json_init(&cmds); json_set_array(&cmds);
    json_init(&next); json_set_array(&next);
    snprintf(readme, sizeof(readme), "%s/README.md", node->real);
    bool has = wk_head(readme, head, sizeof(head), &hn);
    wk_meta_scan(head, has ? hn : 0, &self);
    wk_self_title(node, &self);
    size_t first = node->after < 0 || (uint64_t)node->after > kids->n
                       ? kids->n : (size_t)node->after;
    bool ok = wk_emit_children(node, kids, &ch, &end) &&
              (!has || wk_commands(head, &cmds, &bad)) &&
              wk_next(&next, node, kids, first, end) &&
              (!has || wk_push_readme_hint(&next, node->rel)) &&
              wk_push_head(reply, node, &self, kids->n, end, bad);
    ok = ok && wk_push_arr(reply, "children", &ch);
    ok = ok && wk_push_arr(reply, "commands", &cmds);
    ok = ok && wk_push_arr(reply, "next", &next);
    json_free(&ch); json_free(&cmds); json_free(&next);
    return ok;
}

void zcl_native_handle_discover_wiki(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    struct wk_docs docs;
    struct wk_node node;
    struct wk_children kids = { 0 };
    if (!wk_docs_open(request, &docs, reply) ||
        !wk_target(request, &docs, &node, reply))
        return;
    enum wk_status st = wk_children_list(&docs, node.real, &kids);
    if (st == WK_NOMEM || st == WK_FULL)
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               st == WK_FULL ? "TOPIC_TOO_LARGE" : "NO_MEMORY",
                               "scan", false, false,
                               "topic directory could not be listed", node.rel);
    else if (!wk_build(reply, &node, &kids))
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "RENDER_FAILED",
                               "serialize", false, false,
                               "wiki node could not be rendered", node.rel);
    wk_children_free(&kids);
}

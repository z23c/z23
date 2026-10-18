/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: discover.read - one bounded, UTF-8-safe chunk of a docs/ page or of a
 * source file under code/. */

#include "command/native_wiki_priv.h"

#include "json/json.h"

#include <stdio.h>
#include <string.h>

static bool wk_ends_md(const char *s)
{
    size_t n = strlen(s);
    return n > 3 && strcmp(s + n - 3, ".md") == 0;
}

/* The root that serves `rel`, and the path below it. */
static const struct wk_docs *wk_page_root(
    const struct zcl_command_request *request, const struct wk_docs *docs,
    const char *rel, struct wk_docs *code, size_t *off)
{
    *off = 0;
    if (!wk_code_sub(rel, off))
        return docs;
    return wk_code_open(request, docs, code) ? code : NULL;
}

static bool wk_page_name_ok(const char *rel, bool code)
{
    return rel[0] && (code ? wk_code_ext_ok(rel) : wk_ends_md(rel));
}

static bool wk_page_target(const struct zcl_command_request *request,
                           const struct wk_docs *docs, char *rel, char *real,
                           struct zcl_command_reply *reply)
{
    struct wk_docs code;
    size_t off = 0;
    const char *page = json_get_str(json_get(request->input, "page"));
    if (!page || !wk_rel_normalize(page, rel, WK_REL_MAX + 1)) {
        wk_fail(reply, "BAD_PAGE", "page must be a relative .md path inside "
                "docs/, or a source file under code/, without . or .. "
                "segments", "page");
        return false;
    }
    const struct wk_docs *root = wk_page_root(request, docs, rel, &code, &off);
    if (!root) {
        wk_fail(reply, "CODE_UNAVAILABLE", "no source tree found beside "
                "docs/; the codedir input names it", "codedir");
        return false;
    }
    if (!wk_page_name_ok(rel, root->code)) {
        wk_fail(reply, "BAD_PAGE", "page must be a .md file under docs/ or a "
                ".c, .h, .def, .sh or .md file under code/", "page");
        return false;
    }
    enum wk_status st = wk_resolve(root, rel + off, real, WK_PATH_MAX);
    if (wk_fail_path(reply, st, root->code, "page"))
        return false;
    if (st != WK_OK || !wk_is_file(real)) {
        wk_fail(reply, "UNKNOWN_PAGE", "no such page; list a topic with "
                "discover.wiki", rel);
        return false;
    }
    return true;
}

static bool wk_bounds(const struct zcl_command_request *request,
                      int64_t *offset, size_t *bytes)
{
    const struct json_value *o = json_get(request->input, "offset");
    const struct json_value *b = json_get(request->input, "bytes");
    int64_t want = b ? json_get_int(b) : WK_CHUNK_DEFAULT;
    *offset = o ? json_get_int(o) : 0;
    *bytes = (size_t)want;
    return *offset >= 0 && want >= 1 && want <= WK_CHUNK_MAX;
}

/* A source file's title is its name; Markdown keeps its heading. */
static void wk_source_title(const char *rel, struct wk_meta *meta)
{
    size_t off = 0;
    const char *slash = strrchr(rel, '/');
    if (slash && wk_code_sub(rel, &off) && !wk_ends_md(rel))
        snprintf(meta->title, sizeof(meta->title), "%s", slash + 1);
}

static bool wk_render(struct zcl_command_reply *reply, const char *rel,
                      const char *real, int64_t offset, size_t bytes)
{
    char raw[WK_CHUNK_MAX + 4], text[WK_CHUNK_MAX + 1];
    char head[WK_HEAD_MAX + 1];
    struct wk_meta meta;
    size_t got = 0, hn = 0;
    int64_t size = 0;
    if (!wk_read_at(real, offset, bytes, raw, &got, &size))
        return false;
    if (offset > size) {
        wk_fail(reply, "BAD_RANGE", "offset is past the end of the page", rel);
        return true;
    }
    size_t skip = 0;
    while (skip < 3 && skip < got && ((unsigned char)raw[skip] & 0xC0) == 0x80)
        skip++;
    size_t used = wk_clean(text, bytes, raw + skip, got - skip, true, true);
    text[used] = '\0';
    int64_t next = offset + (int64_t)skip + (int64_t)used;
    if (!wk_head(real, head, sizeof(head), &hn))
        return false;
    wk_meta_scan(head, hn, &meta);
    wk_source_title(rel, &meta);
    struct json_value nul;
    json_init(&nul);
    json_set_null(&nul);
    bool ok = json_push_kv_str(&reply->data, "path", rel) &&
              json_push_kv_str(&reply->data, "title", meta.title) &&
              json_push_kv_int(&reply->data, "size", size) &&
              json_push_kv_int(&reply->data, "offset",
                               offset + (int64_t)skip) &&
              json_push_kv_str(&reply->data, "text", text) &&
              (next < size ? json_push_kv_int(&reply->data, "next_offset", next)
                           : json_push_kv(&reply->data, "next_offset", &nul));
    json_free(&nul);
    return ok;
}

void zcl_native_handle_discover_read(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    struct wk_docs docs;
    char rel[WK_REL_MAX + 1], real[WK_PATH_MAX];
    int64_t offset = 0;
    size_t bytes = 0;
    if (!wk_docs_open(request, &docs, reply) ||
        !wk_page_target(request, &docs, rel, real, reply))
        return;
    if (!wk_bounds(request, &offset, &bytes)) {
        wk_fail(reply, "BAD_RANGE", "offset must be >= 0 and bytes "
                     "1..16384", "offset,bytes");
        return;
    }
    if (!wk_render(reply, rel, real, offset, bytes))
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "READ_FAILED",
                               "read", true, false,
                               "page could not be read", rel);
}

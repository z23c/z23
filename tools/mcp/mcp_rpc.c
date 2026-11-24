/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Transport-neutral MCP JSON-RPC 2.0 core (see mcp_rpc.h). Pure buffer
 * functions: no I/O, no globals. */

#include "mcp_rpc.h"

#include "base/hex.h"
#include "base/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const mcp_versions[] = {"2025-06-18", "2025-03-26",
                                           "2024-11-05"};

/* ── output buffer ────────────────────────────────────────────────────── */

void mcp_buf_init(struct mcp_buf *b)
{
    memset(b, 0, sizeof(*b));
}

void mcp_buf_free(struct mcp_buf *b)
{
    if (!b)
        return;
    free(b->p);
    memset(b, 0, sizeof(*b));
}

void mcp_buf_put(struct mcp_buf *b, const char *s, size_t n)
{
    if (!b || b->oom || !s)
        return;
    if (b->len + n + 1 > b->cap) {
        size_t need = (b->len + n + 1 + 4095u) & ~(size_t)4095u;
        char *np = zcl_realloc(b->p, need, "mcp-rpc/buf");
        if (!np) {
            b->oom = true;
            return;
        }
        b->p = np;
        b->cap = need;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

void mcp_buf_str(struct mcp_buf *b, const char *s)
{
    if (s)
        mcp_buf_put(b, s, strlen(s));
}

static size_t mcp_escape_one(unsigned char c, char out[8])
{
    switch (c) {
    case '"':
        memcpy(out, "\\\"", 2);
        return 2;
    case '\\':
        memcpy(out, "\\\\", 2);
        return 2;
    case '\n':
        memcpy(out, "\\n", 2);
        return 2;
    case '\r':
        memcpy(out, "\\r", 2);
        return 2;
    case '\t':
        memcpy(out, "\\t", 2);
        return 2;
    default:
        break;
    }
    if (c >= 0x20) {
        out[0] = (char)c;
        return 1;
    }
    memcpy(out, "\\u00", 4);
    zcl_hex_encode(&c, 1, out + 4);
    return 6;
}

static void mcp_buf_escaped_n(struct mcp_buf *b, const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char esc[8];
        size_t w = mcp_escape_one((unsigned char)s[i], esc);
        mcp_buf_put(b, esc, w);
    }
}

void mcp_buf_json_str_n(struct mcp_buf *b, const char *s, size_t n)
{
    mcp_buf_put(b, "\"", 1);
    if (s)
        mcp_buf_escaped_n(b, s, n);
    mcp_buf_put(b, "\"", 1);
}

void mcp_buf_json_str(struct mcp_buf *b, const char *s)
{
    mcp_buf_json_str_n(b, s, s ? strlen(s) : 0);
}

void mcp_buf_json_value(struct mcp_buf *b, const struct json_value *v)
{
    if (!v) {
        mcp_buf_str(b, "null");
        return;
    }
    size_t need = json_write(v, NULL, 0);
    char *tmp = zcl_realloc(NULL, need + 1, "mcp-rpc/value");
    if (!tmp) {
        if (b)
            b->oom = true;
        return;
    }
    size_t got = json_write(v, tmp, need + 1);
    mcp_buf_put(b, tmp, got < need + 1 ? got : need);
    free(tmp);
}

/* ── capped text ──────────────────────────────────────────────────────── */

static size_t mcp_utf8_len(unsigned char lead)
{
    if (lead >= 0xf0)
        return 4;
    if (lead >= 0xe0)
        return 3;
    if (lead >= 0xc0)
        return 2;
    return 1;
}

/* Longest prefix of text whose escaped form fits in budget bytes and ends on
 * a UTF-8 sequence boundary. Returns the raw byte count of that prefix. */
static size_t mcp_escaped_prefix(const char *text, size_t n, size_t budget)
{
    size_t i = 0, used = 0;
    while (i < n) {
        char esc[8];
        size_t seq = mcp_utf8_len((unsigned char)text[i]);
        size_t w = seq > 1 ? seq : mcp_escape_one((unsigned char)text[i], esc);
        if (i + seq > n || used + w > budget)
            break;
        used += w;
        i += seq;
    }
    return i;
}

static bool mcp_text_is_object(const char *text, size_t n)
{
    size_t i = 0;
    while (i < n && (text[i] == ' ' || text[i] == '\n' || text[i] == '\r' ||
                     text[i] == '\t'))
        i++;
    return i < n && text[i] == '{';
}

#define MCP_FIELDS_MAX 32u
#define MCP_SELECT_MAX 8u
#define MCP_SELECT_PATH_MAX 128u

/* "fields":{"data.<key>":<bytes>,..}, for a reply whose data is an object;
 * nothing otherwise. */
static void mcp_fields_hint(struct mcp_buf *hint, const char *text, size_t n)
{
    struct json_value doc;
    json_init(&doc);
    const struct json_value *data =
        json_read(&doc, text, n) && doc.type == JSON_OBJ
            ? json_get(&doc, "data") : NULL;
    if (data && data->type == JSON_OBJ && data->keys) {
        mcp_buf_str(hint, ",\"fields\":{");
        for (size_t i = 0; i < data->num_children && i < MCP_FIELDS_MAX; i++) {
            struct mcp_buf one;
            char name[MCP_SELECT_PATH_MAX], size[24];
            mcp_buf_init(&one);
            mcp_buf_json_value(&one, &data->children[i]);
            snprintf(size, sizeof(size), ":%zu", one.len);
            hint->oom = hint->oom || one.oom; /* a short count is no size */
            mcp_buf_free(&one);
            snprintf(name, sizeof(name), "data.%s", data->keys[i]);
            mcp_buf_str(hint, i ? "," : "");
            mcp_buf_json_str(hint, name);
            mcp_buf_str(hint, size);
        }
        mcp_buf_str(hint, "}");
    }
    json_free(&doc);
}

static const char *const mcp_resume_keys[] = {"cursor_token", "after_slug"};
/* Select stores one path as a key. These name the same resume string. */
static const char *const mcp_resume_paths[] = {
    "data.cursor_token", "data.after_slug", "data.cursor"};

static bool mcp_str_set(const struct json_value *v)
{
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    return s && s[0];
}

/* A non-empty resume string covers every row in this reply. */
static bool mcp_obj_resume(const struct json_value *obj)
{
    size_t i;
    if (!obj || obj->type != JSON_OBJ)
        return false;
    for (i = 0; i < sizeof(mcp_resume_keys) / sizeof(mcp_resume_keys[0]); i++) {
        if (mcp_str_set(json_get(obj, mcp_resume_keys[i])))
            return true;
    }
    return false;
}

static bool mcp_named_resume(const char *key)
{
    size_t i;
    for (i = 0; i < sizeof(mcp_resume_paths) / sizeof(mcp_resume_paths[0]); i++) {
        if (key && strcmp(key, mcp_resume_paths[i]) == 0)
            return true;
    }
    return false;
}

/* select.data.cursor_token, or the path keys data.cursor_token and data.cursor. */
static bool mcp_select_resume(const struct json_value *sel)
{
    const struct json_value *data;
    size_t i;
    if (!sel || sel->type != JSON_OBJ)
        return false;
    data = json_get(sel, "data");
    if (mcp_obj_resume(data) || (data && mcp_str_set(json_get(data, "cursor"))))
        return true;
    if (!sel->keys)
        return false;
    for (i = 0; i < sel->num_children; i++) {
        if (mcp_named_resume(sel->keys[i]) && mcp_str_set(&sel->children[i]))
            return true;
    }
    return false;
}

static bool mcp_reply_has_resume(const char *text, size_t n)
{
    struct json_value doc;
    bool found;
    json_init(&doc);
    found = json_read(&doc, text, n) && doc.type == JSON_OBJ &&
            (mcp_obj_resume(&doc) || mcp_obj_resume(json_get(&doc, "data")) ||
             mcp_select_resume(json_get(&doc, "select")));
    json_free(&doc);
    return found;
}

/* The cursor names rows this budget did not keep. Omit it and say so. */
static void mcp_cap_held(struct mcp_buf *out, const char *text, size_t n,
                         size_t max_bytes)
{
    char head[96];
    struct mcp_buf hint;
    const char *tail = ",\"resume_cursor_missing\":true}";
    const char *bare = "{\"truncated\":true,\"resume_cursor_missing\":true}";
    int hl = snprintf(head, sizeof(head),
                      "{\"truncated\":true,\"original_bytes\":%zu", n);
    size_t tail_n = strlen(tail);
    size_t bare_n = strlen(bare);
    mcp_buf_init(&hint);
    mcp_fields_hint(&hint, text, n);
    if (hl < 0 || hint.oom || (size_t)hl + hint.len + tail_n > max_bytes)
        hint.len = 0;
    if (hl >= 0 && (size_t)hl + hint.len + tail_n <= max_bytes) {
        mcp_buf_put(out, head, (size_t)hl);
        mcp_buf_put(out, hint.p, hint.len);
        mcp_buf_put(out, tail, tail_n);
        mcp_buf_free(&hint);
        return;
    }
    mcp_buf_free(&hint);
    if (bare_n <= max_bytes)
        mcp_buf_put(out, bare, bare_n);
    else
        mcp_buf_put(out, "{\"truncated\":true}", max_bytes >= 18 ? 18 : 0);
}

static void mcp_cap_object(struct mcp_buf *out, const char *text, size_t n,
                           size_t max_bytes)
{
    char head[96];
    struct mcp_buf hint;
    int hl;
    if (mcp_reply_has_resume(text, n)) {
        mcp_cap_held(out, text, n, max_bytes);
        return;
    }
    hl = snprintf(head, sizeof(head),
                  "{\"truncated\":true,\"original_bytes\":%zu", n);
    mcp_buf_init(&hint);
    mcp_fields_hint(&hint, text, n);
    if (hint.oom || (size_t)hl + hint.len + 16 > max_bytes)
        hint.len = 0; /* the hint must never crowd out the marker */
    if (hl < 0 || (size_t)hl + hint.len + 14 > max_bytes) {
        mcp_buf_put(out, "{\"truncated\":true}", max_bytes >= 18 ? 18 : 0);
        mcp_buf_free(&hint);
        return;
    }
    size_t used = (size_t)hl + hint.len + 14;
    size_t keep = mcp_escaped_prefix(text, n, max_bytes - used);
    mcp_buf_put(out, head, (size_t)hl);
    mcp_buf_put(out, hint.p, hint.len);
    mcp_buf_str(out, ",\"partial\":\"");
    mcp_buf_escaped_n(out, text, keep);
    mcp_buf_put(out, "\"}", 2);
    mcp_buf_free(&hint);
}

/* ── select ───────────────────────────────────────────────────────────── */

bool mcp_select_valid(const struct json_value *select, const char **why)
{
    size_t n = select && select->type == JSON_ARR ? json_size(select) : 0;
    *why = "select must be an array of 1 to 8 paths";
    if (n == 0 || n > MCP_SELECT_MAX)
        return false;
    *why = "each select path is 1..128 bytes of dot-separated keys, "
           "decimal indexes or *";
    for (size_t i = 0; i < n; i++) {
        const struct json_value *p = json_at(select, i);
        const char *s = p && p->type == JSON_STR ? json_get_str(p) : NULL;
        size_t len = s ? strlen(s) : 0;
        if (len == 0 || len > MCP_SELECT_PATH_MAX || s[0] == '.' ||
            s[len - 1] == '.' || strstr(s, ".."))
            return false;
    }
    *why = NULL;
    return true;
}

static bool mcp_seg_index(const char *seg, size_t len, size_t *idx)
{
    size_t v = 0;
    if (len == 0 || len > 9)
        return false;
    for (size_t i = 0; i < len; i++) {
        if (seg[i] < '0' || seg[i] > '9')
            return false;
        v = v * 10 + (size_t)(seg[i] - '0');
    }
    *idx = v;
    return true;
}

static void mcp_select_walk(struct mcp_buf *out, const struct json_value *v,
                            const char *path);

/* `*`: the rest of the path below every element of an array. */
static void mcp_select_each(struct mcp_buf *out, const struct json_value *v,
                            const char *rest)
{
    if (v->type != JSON_ARR) {
        mcp_buf_str(out, "null");
        return;
    }
    mcp_buf_str(out, "[");
    for (size_t i = 0; i < json_size(v); i++) {
        if (i)
            mcp_buf_str(out, ",");
        mcp_select_walk(out, json_at(v, i), rest);
    }
    mcp_buf_str(out, "]");
}

/* The value at path below v; a step that does not resolve writes null. */
static void mcp_select_walk(struct mcp_buf *out, const struct json_value *v,
                            const char *path)
{
    char key[MCP_SELECT_PATH_MAX + 1];
    size_t idx;
    if (!v || !*path) {
        mcp_buf_json_value(out, v);
        return;
    }
    const char *dot = strchr(path, '.');
    size_t len = dot ? (size_t)(dot - path) : strlen(path);
    const char *rest = path + len + (dot ? 1 : 0);
    if (len == 1 && path[0] == '*') {
        mcp_select_each(out, v, rest);
        return;
    }
    if (v->type == JSON_ARR) {
        bool in = mcp_seg_index(path, len, &idx) && idx < json_size(v);
        mcp_select_walk(out, in ? json_at(v, idx) : NULL, rest);
        return;
    }
    memcpy(key, path, len);
    key[len] = '\0';
    mcp_select_walk(out, v->type == JSON_OBJ ? json_get(v, key) : NULL, rest);
}

/* Where a select path stopped resolving: the node it stopped at and how many
 * bytes of the path lead to it (no trailing dot). */
struct mcp_select_stop {
    const struct json_value *node;
    size_t prefix;
    bool set;
};

/* The element or member a non-`*` step of path names below v, or NULL. */
static const struct json_value *mcp_select_child(const struct json_value *v,
                                                 const char *seg, size_t len)
{
    char key[MCP_SELECT_PATH_MAX + 1];
    size_t idx;
    if (v->type == JSON_ARR)
        return mcp_seg_index(seg, len, &idx) && idx < json_size(v)
                   ? json_at(v, idx)
                   : NULL;
    if (v->type != JSON_OBJ)
        return NULL;
    memcpy(key, seg, len);
    key[len] = '\0';
    return json_get(v, key);
}

static bool mcp_select_probe(const struct json_value *v, const char *path,
                             size_t base, struct mcp_select_stop *stop);

/* `*`: v is an array and the rest resolves below every element. Every element
 * is probed; the stop reported is the deepest one any element reached (ties
 * keep the first element). A non-array v fails with no stop, so the caller
 * reports it at v. */
static bool mcp_select_probe_each(const struct json_value *v, const char *rest,
                                  size_t base, struct mcp_select_stop *stop)
{
    struct mcp_select_stop deepest = {0};
    bool ok = true;
    if (v->type != JSON_ARR)
        return false;
    for (size_t i = 0; i < json_size(v); i++) {
        struct mcp_select_stop es = {0};
        if (mcp_select_probe(json_at(v, i), rest, base, &es))
            continue;
        if (ok || es.prefix > deepest.prefix)
            deepest = es;
        ok = false;
    }
    if (!ok && stop)
        *stop = deepest;
    return ok;
}

/* True when every step of path resolves below v. On failure, records in stop
 * (when stop is non-NULL) the node and the prefix of the select path that
 * resolved. The rule: the prefix is the longest one that resolves on at least
 * one branch. A `*` counts as resolved on each element of an array, so a step
 * that no element has is reported with the prefix ending at the wildcard
 * (e.g. "data.rows.*", with that element's keys or length); a step that some
 * elements have is reported at the deepest such step (e.g. "data.rows.*.seq").
 * Where a `*` is applied to a non-array, the prefix ends before the `*`.
 * base is the offset of path within the whole select path. */
static bool mcp_select_probe(const struct json_value *v, const char *path,
                             size_t base, struct mcp_select_stop *stop)
{
    if (!*path)
        return true;
    const char *dot = strchr(path, '.');
    size_t len = dot ? (size_t)(dot - path) : strlen(path);
    const char *rest = path + len + (dot ? 1 : 0);
    bool star = len == 1 && path[0] == '*';
    const struct json_value *next = star ? NULL : mcp_select_child(v, path, len);
    if (star ? mcp_select_probe_each(v, rest, base + len + 1, stop)
             : next != NULL) {
        if (star)
            return true;
        return mcp_select_probe(next, rest, base + len + 1, stop);
    }
    if (stop && !stop->set) {
        stop->node = v;
        stop->prefix = base > 0 ? base - 1 : 0; /* before this step's dot */
        stop->set = true;
    }
    return false;
}

#define MCP_SELECT_KEYS_MAX 32

/* One select_missing entry body: the resolved prefix and what lies there. */
static void mcp_select_missing_entry(struct mcp_buf *out, const char *path,
                                     const struct mcp_select_stop *stop)
{
    const struct json_value *v = stop->node;
    mcp_buf_str(out, "{\"resolved\":");
    mcp_buf_json_str_n(out, path, stop->prefix);
    if (v->type == JSON_OBJ) {
        size_t n = json_size(v);
        mcp_buf_str(out, ",\"keys\":[");
        for (size_t i = 0; i < n && i < MCP_SELECT_KEYS_MAX; i++) {
            mcp_buf_str(out, i ? "," : "");
            mcp_buf_json_str(out, v->keys[i]);
        }
        if (n > MCP_SELECT_KEYS_MAX)
            mcp_buf_str(out, ",\"...\"");
        mcp_buf_str(out, "]");
    } else if (v->type == JSON_ARR) {
        char num[32];
        (void)snprintf(num, sizeof(num), ",\"length\":%zu", json_size(v));
        mcp_buf_str(out, num);
    }
    mcp_buf_str(out, "}");
}

bool mcp_select_reply(struct mcp_buf *out, const char *text, size_t n,
                      const struct json_value *select)
{
    struct json_value doc;
    json_init(&doc);
    if (!json_read(&doc, text, n)) {
        /* A reply json_valid accepts but json_read refused could not be
         * allocated: out of memory, not "not an object". */
        out->oom = out->oom || json_valid(text, n);
        return false;
    }
    if (doc.type != JSON_OBJ) {
        json_free(&doc);
        return false;
    }
    mcp_buf_str(out, "{\"ok\":");
    mcp_select_walk(out, json_get(&doc, "ok"), "");
    mcp_buf_str(out, ",\"status\":");
    mcp_select_walk(out, json_get(&doc, "status"), "");
    mcp_buf_str(out, ",\"select\":{");
    for (size_t i = 0; i < json_size(select); i++) {
        const char *path = json_get_str(json_at(select, i));
        mcp_buf_str(out, i ? "," : "");
        mcp_buf_json_str(out, path);
        mcp_buf_str(out, ":");
        mcp_select_walk(out, &doc, path);
    }
    mcp_buf_str(out, "}");
    const char *sep = ",\"select_missing\":{";
    bool any = false;
    for (size_t i = 0; i < json_size(select); i++) {
        const char *path = json_get_str(json_at(select, i));
        struct mcp_select_stop stop = {0};
        if (mcp_select_probe(&doc, path, 0, &stop) || !stop.set)
            continue;
        mcp_buf_str(out, sep);
        sep = ",";
        any = true;
        mcp_buf_json_str(out, path);
        mcp_buf_str(out, ":");
        mcp_select_missing_entry(out, path, &stop);
    }
    if (any)
        mcp_buf_str(out, "}");
    mcp_buf_str(out, "}");
    json_free(&doc);
    return true;
}

bool mcp_compact_packet_reply(struct mcp_buf *out, const char *text, size_t n)
{
    struct json_value doc;
    json_init(&doc);
    if (!json_read(&doc, text, n)) {
        out->oom = out->oom || json_valid(text, n);
        return false;
    }
    const struct json_value *data = json_get(&doc, "data");
    if (doc.type != JSON_OBJ || !data || data->type != JSON_OBJ) {
        json_free(&doc);
        return false;
    }
    mcp_buf_str(out, "{\"ok\":");
    mcp_select_walk(out, json_get(&doc, "ok"), "");
    mcp_buf_str(out, ",\"status\":");
    mcp_select_walk(out, json_get(&doc, "status"), "");
    mcp_buf_str(out, ",\"select\":{\"data\":{");
    const char *sep = "";
    for (size_t i = 0; i < json_size(data); i++) {
        if (strcmp(data->keys[i], "markdown") == 0)
            continue;
        mcp_buf_str(out, sep);
        sep = ",";
        mcp_buf_json_str(out, data->keys[i]);
        mcp_buf_str(out, ":");
        mcp_select_walk(out, &data->children[i], "");
    }
    mcp_buf_str(out, "}}}");
    json_free(&doc);
    return true;
}

static void mcp_cap_raw(struct mcp_buf *out, const char *text, size_t n,
                        size_t max_bytes)
{
    char mark[64];
    int ml = snprintf(mark, sizeof(mark), "\n[truncated: %zu bytes total]", n);
    size_t m = ml > 0 ? (size_t)ml : 0;
    size_t keep = max_bytes > m ? max_bytes - m : 0;
    while (keep > 0 && ((unsigned char)text[keep] & 0xc0) == 0x80)
        keep--;
    mcp_buf_put(out, text, keep);
    mcp_buf_put(out, mark, m < max_bytes ? m : max_bytes);
}

bool mcp_cap_text(struct mcp_buf *out, const char *text, size_t n,
                  size_t max_bytes)
{
    if (max_bytes == 0 || n <= max_bytes) {
        mcp_buf_put(out, text, n);
        return false;
    }
    if (mcp_text_is_object(text, n))
        mcp_cap_object(out, text, n, max_bytes);
    else
        mcp_cap_raw(out, text, n, max_bytes);
    return true;
}

/* ── envelopes ────────────────────────────────────────────────────────── */

static void mcp_reply_open(struct mcp_buf *b, const struct json_value *id)
{
    mcp_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":");
    mcp_buf_json_value(b, id);
}

void mcp_reply_error(struct mcp_buf *b, const struct json_value *id, int code,
                     const char *message)
{
    char num[16];
    mcp_reply_open(b, id);
    snprintf(num, sizeof(num), "%d", code);
    mcp_buf_str(b, ",\"error\":{\"code\":");
    mcp_buf_str(b, num);
    mcp_buf_str(b, ",\"message\":");
    mcp_buf_json_str(b, message);
    mcp_buf_str(b, "}}");
}

static void mcp_reply_refused(struct mcp_buf *b, const struct json_value *id,
                              int code, const struct mcp_refusal *why)
{
    char num[16];
    mcp_reply_open(b, id);
    snprintf(num, sizeof(num), "%d", code);
    mcp_buf_str(b, ",\"error\":{\"code\":");
    mcp_buf_str(b, num);
    mcp_buf_str(b, ",\"message\":");
    mcp_buf_json_str(b, why->message);
    mcp_buf_str(b, ",\"data\":{\"code\":");
    mcp_buf_json_str(b, why->code);
    mcp_buf_str(b, "}}}");
}

const char *mcp_negotiate_version(const char *asked)
{
    if (asked) {
        for (size_t i = 0; i < sizeof(mcp_versions) / sizeof(mcp_versions[0]);
             i++)
            if (strcmp(asked, mcp_versions[i]) == 0)
                return mcp_versions[i];
    }
    return mcp_versions[0];
}

static const char *mcp_str_member(const struct json_value *obj,
                                  const char *key);

/* FNV-1a 64 of the live tool table. Not a security hash: it only tells a
 * caller whether the schemas it already holds are still the ones served. */
static uint64_t mcp_fnv_str(uint64_t h, const char *s)
{
    const unsigned char *p = (const unsigned char *)(s ? s : "");
    if (!s)
        return h;
    for (; *p; p++) {
        h ^= *p;
        h *= UINT64_C(0x100000001b3);
    }
    return h;
}

static void mcp_schema_generation(const struct mcp_endpoint *ep, char out[17])
{
    uint64_t h = UINT64_C(0xcbf29ce484222325);
    size_t i;
    for (i = 0; ep && i < ep->tool_count; i++) {
        h = mcp_fnv_str(h, ep->tools[i].name);
        h = mcp_fnv_str(h, "\n");
        h = mcp_fnv_str(h, ep->tools[i].input_schema_json);
        h = mcp_fnv_str(h, ep->tools[i].read_only ? "\n1" : "\n0");
    }
    snprintf(out, 17, "%016llx", (unsigned long long)h);
}

void mcp_reply_tools_list(struct mcp_buf *b, const struct json_value *id,
                          const struct mcp_endpoint *ep,
                          const struct json_value *params)
{
    char gen[17];
    const char *held = mcp_str_member(params, "schema_generation");
    mcp_schema_generation(ep, gen);
    mcp_reply_open(b, id);
    if (held && held[0] && strcmp(held, gen) == 0) {
        mcp_buf_str(b, ",\"result\":{\"not_modified\":true,\"schema_generation\":");
        mcp_buf_json_str(b, gen);
        mcp_buf_str(b, "}}");
        return;
    }
    mcp_buf_str(b, ",\"result\":{\"tools\":[");
    for (size_t i = 0; i < ep->tool_count; i++) {
        const struct mcp_tool *t = &ep->tools[i];
        if (i > 0)
            mcp_buf_put(b, ",", 1);
        mcp_buf_str(b, "{\"name\":");
        mcp_buf_json_str(b, t->name);
        mcp_buf_str(b, ",\"description\":");
        mcp_buf_json_str(b, t->description);
        mcp_buf_str(b, ",\"inputSchema\":");
        mcp_buf_str(b, t->input_schema_json);
        mcp_buf_str(b, ",\"annotations\":{\"readOnlyHint\":");
        mcp_buf_str(b, t->read_only ? "true" : "false");
        mcp_buf_str(b, "}}");
    }
    mcp_buf_str(b, "],\"schema_generation\":");
    mcp_buf_json_str(b, gen);
    if (held && held[0])
        mcp_buf_str(b, ",\"not_modified\":false");
    mcp_buf_str(b, "}}");
}

void mcp_reply_tool_text(struct mcp_buf *b, const struct json_value *id,
                         const struct mcp_endpoint *ep, const char *text,
                         size_t n, bool is_error)
{
    struct mcp_buf capped;
    mcp_buf_init(&capped);
    mcp_cap_text(&capped, text, n, ep ? ep->max_reply_bytes : 0);
    mcp_reply_open(b, id);
    mcp_buf_str(b, ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":");
    mcp_buf_json_str_n(b, capped.p ? capped.p : "", capped.len);
    mcp_buf_str(b, "}],\"isError\":");
    mcp_buf_str(b, is_error ? "true" : "false");
    mcp_buf_str(b, "}}");
    if (capped.oom && b)
        b->oom = true;
    mcp_buf_free(&capped);
}

/* ── methods ──────────────────────────────────────────────────────────── */

static const char *mcp_str_member(const struct json_value *obj,
                                  const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static void mcp_do_initialize(const struct mcp_endpoint *ep,
                              const struct json_value *id,
                              const struct json_value *params,
                              struct mcp_buf *reply)
{
    const char *proto = mcp_str_member(params, "protocolVersion");
    const struct json_value *info = params ? json_get(params, "clientInfo")
                                           : NULL;
    const char *client = mcp_str_member(info, "name");
    struct mcp_refusal why = {0};
    if (ep->on_initialize &&
        !ep->on_initialize(ep->ctx, client, proto, &why)) {
        if (!why.code)
            why.code = "INITIALIZE_REFUSED";
        if (!why.message)
            why.message = "initialize refused";
        mcp_reply_refused(reply, id, MCP_ERR_INITIALIZE_REFUSED, &why);
        return;
    }
    mcp_reply_open(reply, id);
    mcp_buf_str(reply, ",\"result\":{\"protocolVersion\":");
    mcp_buf_json_str(reply, mcp_negotiate_version(proto));
    mcp_buf_str(reply, ",\"capabilities\":{\"tools\":{}},\"serverInfo\":"
                       "{\"name\":");
    mcp_buf_json_str(reply, ep->server_name);
    mcp_buf_str(reply, ",\"version\":");
    mcp_buf_json_str(reply, ep->server_version);
    mcp_buf_str(reply, "}");
    if (ep->instructions) {
        mcp_buf_str(reply, ",\"instructions\":");
        mcp_buf_json_str(reply, ep->instructions);
    }
    mcp_buf_str(reply, "}}");
}

static const struct mcp_tool *mcp_find_tool(const struct mcp_endpoint *ep,
                                            const char *name)
{
    for (size_t i = 0; name && i < ep->tool_count; i++)
        if (strcmp(ep->tools[i].name, name) == 0)
            return &ep->tools[i];
    return NULL;
}

static void mcp_refusal_text(struct mcp_buf *text,
                             const struct mcp_refusal *why)
{
    mcp_buf_str(text, "{\"ok\":false,\"error\":{\"code\":");
    mcp_buf_json_str(text, why->code ? why->code : "REFUSED");
    mcp_buf_str(text, ",\"message\":");
    mcp_buf_json_str(text, why->message ? why->message : "refused");
    if (why->detail) {
        mcp_buf_str(text, ",\"detail\":");
        mcp_buf_json_str(text, why->detail);
    }
    if (why->did_you_mean_json) {
        mcp_buf_str(text, ",\"did_you_mean\":");
        mcp_buf_str(text, why->did_you_mean_json);
    }
    mcp_buf_str(text, "}}");
}

static void mcp_do_tools_call(const struct mcp_endpoint *ep,
                              const struct json_value *id,
                              const struct json_value *params,
                              struct mcp_buf *reply)
{
    const struct mcp_tool *tool =
        mcp_find_tool(ep, mcp_str_member(params, "name"));
    const struct json_value *args = params ? json_get(params, "arguments")
                                           : NULL;
    struct json_value empty;
    struct mcp_buf text;
    struct mcp_refusal why = {0};
    bool is_error = false, ok = true;
    if (!tool) {
        mcp_reply_error(reply, id, MCP_ERR_INVALID_PARAMS, "unknown tool");
        return;
    }
    if (args && args->type != JSON_OBJ) {
        mcp_reply_error(reply, id, MCP_ERR_INVALID_PARAMS,
                        "arguments must be an object");
        return;
    }
    json_init(&empty);
    json_set_object(&empty);
    if (!args)
        args = &empty;
    mcp_buf_init(&text);
    if (ep->authority && !ep->authority(ep->ctx, tool, args, &why)) {
        mcp_refusal_text(&text, &why);
        is_error = true;
    } else {
        ok = ep->call(ep->ctx, tool, args, &text, &is_error);
    }
    if (ok && !text.oom)
        mcp_reply_tool_text(reply, id, ep, text.p ? text.p : "", text.len,
                            is_error);
    else
        mcp_reply_error(reply, id, MCP_ERR_INTERNAL, "tool failed");
    mcp_buf_free(&text);
    json_free(&empty);
}

static void mcp_route(const struct mcp_endpoint *ep, const char *method,
                      const struct json_value *id,
                      const struct json_value *params, struct mcp_buf *reply)
{
    if (strcmp(method, "initialize") == 0) {
        mcp_do_initialize(ep, id, params, reply);
    } else if (strcmp(method, "ping") == 0) {
        mcp_reply_open(reply, id);
        mcp_buf_str(reply, ",\"result\":{}}");
    } else if (strcmp(method, "tools/list") == 0) {
        mcp_reply_tools_list(reply, id, ep, params);
    } else if (strcmp(method, "tools/call") == 0) {
        mcp_do_tools_call(ep, id, params, reply);
    } else {
        mcp_reply_error(reply, id, MCP_ERR_METHOD_NOT_FOUND,
                        "method not found");
    }
}

static bool mcp_id_ok(const struct json_value *id)
{
    return id && (id->type == JSON_STR || id->type == JSON_INT);
}

static enum mcp_dispatch_result mcp_dispatch_root(
    const struct mcp_endpoint *ep, const struct json_value *root,
    struct mcp_buf *reply)
{
    const struct json_value *id, *method, *version;
    if (root->type != JSON_OBJ) {
        mcp_reply_error(reply, NULL, MCP_ERR_INVALID_REQUEST,
                        "request must be a single JSON object");
        return MCP_REPLY;
    }
    id = json_get(root, "id");
    method = json_get(root, "method");
    if (!method && (json_get(root, "result") || json_get(root, "error")))
        return MCP_NO_REPLY;
    if (id && !mcp_id_ok(id)) {
        mcp_reply_error(reply, NULL, MCP_ERR_INVALID_REQUEST,
                        "id must be a string or integer");
        return MCP_REPLY;
    }
    version = json_get(root, "jsonrpc");
    if (!version || version->type != JSON_STR || !json_get_str(version) ||
        strcmp(json_get_str(version), "2.0") != 0) {
        mcp_reply_error(reply, id, MCP_ERR_INVALID_REQUEST,
                        "jsonrpc must be the string \"2.0\"");
        return MCP_REPLY;
    }
    if (!method || method->type != JSON_STR) {
        mcp_reply_error(reply, id, MCP_ERR_INVALID_REQUEST,
                        "method must be a string");
        return MCP_REPLY;
    }
    if (!id)
        return MCP_NO_REPLY;
    mcp_route(ep, json_get_str(method), id, json_get(root, "params"), reply);
    return MCP_REPLY;
}

enum mcp_dispatch_result mcp_dispatch(const struct mcp_endpoint *ep,
                                      const char *frame, size_t len,
                                      struct mcp_buf *reply)
{
    struct json_value root;
    enum mcp_dispatch_result r;
    json_init(&root);
    if (!json_read(&root, frame, len)) {
        json_free(&root);
        if (json_valid(frame, len))
            return MCP_FATAL;
        mcp_reply_error(reply, NULL, MCP_ERR_PARSE, "parse error");
        return reply->oom ? MCP_FATAL : MCP_REPLY;
    }
    r = mcp_dispatch_root(ep, &root, reply);
    json_free(&root);
    return reply->oom ? MCP_FATAL : r;
}

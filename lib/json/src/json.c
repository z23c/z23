/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "json/json.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <inttypes.h>
#include "base/safe_alloc.h"

void json_init(struct json_value *v)
{
    memset(v, 0, sizeof(*v));
    v->type = JSON_NULL;
}

static void json_clear_children(struct json_value *v)
{
    for (size_t i = 0; i < v->num_children; i++) {
        json_free(&v->children[i]);
        free(v->keys[i]);
    }
    free(v->children);
    free(v->keys);
    v->children = NULL;
    v->keys = NULL;
    v->num_children = 0;
    v->children_cap = 0;
}

void json_free(struct json_value *v)
{
    if (v->type == JSON_STR)
        free(v->val.s);
    json_clear_children(v);
}

void json_set_null(struct json_value *v)
{
    json_free(v);
    v->type = JSON_NULL;
}

void json_set_bool(struct json_value *v, bool b)
{
    json_free(v);
    v->type = JSON_BOOL;
    v->val.b = b;
}

void json_set_int(struct json_value *v, int64_t i)
{
    json_free(v);
    v->type = JSON_INT;
    v->val.i = i;
}

void json_set_real(struct json_value *v, double d)
{
    json_free(v);
    v->type = JSON_REAL;
    v->val.d = d;
}

void json_set_str(struct json_value *v, const char *s)
{
    json_free(v);
    v->val.s = zcl_strdup(s, "json_set_str");
    /* Under OOM we silently degrade to JSON_NULL rather than leaving a
     * JSON_STR with NULL val.s — every downstream consumer dereferences
     * val.s expecting a real string. Loud failure was logged inside
     * zcl_strdup; here we just stay type-safe. */
    v->type = v->val.s ? JSON_STR : JSON_NULL;
}

void json_set_array(struct json_value *v)
{
    json_free(v);
    v->type = JSON_ARR;
}

void json_set_object(struct json_value *v)
{
    json_free(v);
    v->type = JSON_OBJ;
}

static bool json_grow(struct json_value *v)
{
    if (v->num_children >= v->children_cap) {
        size_t newcap = v->children_cap == 0 ? 8 : v->children_cap * 2;
        struct json_value *nc = zcl_realloc(v->children,
                                        newcap * sizeof(*nc), "json_children");
        if (!nc) return false;
        v->children = nc;
        char **nk = zcl_realloc(v->keys, newcap * sizeof(*nk), "json_keys");
        if (!nk) return false;
        v->keys = nk;
        v->children_cap = newcap;
    }
    return true;
}

void json_copy(struct json_value *dst, const struct json_value *src)
{
    json_init(dst);
    dst->type = src->type;
    switch (src->type) {
    case JSON_BOOL: dst->val.b = src->val.b; break;
    case JSON_INT:  dst->val.i = src->val.i; break;
    case JSON_REAL: dst->val.d = src->val.d; break;
    case JSON_STR:
        dst->val.s = zcl_strdup(src->val.s, "json_copy_str");
        /* Degrade to JSON_NULL on OOM rather than leaving a JSON_STR
         * with NULL val.s — see json_set_str for rationale. */
        if (!dst->val.s) dst->type = JSON_NULL;
        break;
    default: break;
    }
    if (src->num_children > 0) {
        dst->children_cap = src->num_children;
        dst->children = zcl_malloc(dst->children_cap * sizeof(*dst->children), "json_copy_children");
        if (!dst->children) {
            dst->children_cap = 0;
            return;
        }
        dst->keys = zcl_malloc(dst->children_cap * sizeof(*dst->keys), "json_copy_keys");
        if (!dst->keys) {
            free(dst->children);
            dst->children = NULL;
            dst->children_cap = 0;
            return;
        }
        dst->num_children = src->num_children;
        for (size_t i = 0; i < src->num_children; i++) {
            json_copy(&dst->children[i], &src->children[i]);
            dst->keys[i] = zcl_strdup(src->keys[i], "json_copy_key");
        }
    }
}

bool json_push_back(struct json_value *arr, const struct json_value *child)
{
    if (arr->type != JSON_ARR) return false;
    if (!json_grow(arr)) return false;
    json_copy(&arr->children[arr->num_children], child);
    arr->keys[arr->num_children] = NULL;
    arr->num_children++;
    return true;
}

bool json_push_kv(struct json_value *obj, const char *key,
                  const struct json_value *child)
{
    if (obj->type != JSON_OBJ) return false;
    if (!json_grow(obj)) return false;
    /* Allocate the key first so an OOM here doesn't leave a copied
     * child stranded with a NULL key — json_get does
     * strcmp(obj->keys[i], key) and a NULL slot would crash. */
    char *kdup = zcl_strdup(key, "json_push_kv_key");
    if (!kdup) return false;
    json_copy(&obj->children[obj->num_children], child);
    obj->keys[obj->num_children] = kdup;
    obj->num_children++;
    return true;
}

/* Append a prepared scalar under key, then release its temporary storage.
 * Takes ownership of *v's resources (always frees v before returning). */
static bool json_push_kv_owned(struct json_value *obj, const char *key,
                               struct json_value *v)
{
    bool ok = json_push_kv(obj, key, v);
    json_free(v);
    return ok;
}

bool json_push_kv_str(struct json_value *obj, const char *key, const char *s)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s);
    return json_push_kv_owned(obj, key, &v);
}

bool json_push_kv_int(struct json_value *obj, const char *key, int64_t i)
{
    struct json_value v;
    json_init(&v);
    json_set_int(&v, i);
    return json_push_kv_owned(obj, key, &v);
}

bool json_push_kv_real(struct json_value *obj, const char *key, double d)
{
    struct json_value v;
    json_init(&v);
    json_set_real(&v, d);
    return json_push_kv_owned(obj, key, &v);
}

bool json_push_kv_bool(struct json_value *obj, const char *key, bool b)
{
    struct json_value v;
    json_init(&v);
    json_set_bool(&v, b);
    return json_push_kv_owned(obj, key, &v);
}

/* Read accessors are NULL-safe: passing NULL (e.g. json_at()/json_get() on an
 * absent element/key) yields the type's zero value rather than dereferencing.
 * This makes the idiom json_get_str(json_at(params, N)) safe when the optional
 * param N is missing — a missing RPC arg must never crash the node. */
size_t json_size(const struct json_value *v)
{
    return v ? v->num_children : 0;
}

bool json_empty(const struct json_value *v)
{
    return !v || v->num_children == 0;
}

const struct json_value *json_get(const struct json_value *obj, const char *key)
{
    if (!obj || !key || obj->type != JSON_OBJ) return NULL;
    for (size_t i = 0; i < obj->num_children; i++)
        if (obj->keys[i] && strcmp(obj->keys[i], key) == 0)
            return &obj->children[i];
    return NULL;
}

const struct json_value *json_at(const struct json_value *v, size_t index)
{
    if (!v || index >= v->num_children) return NULL;
    return &v->children[index];
}

bool json_is_null(const struct json_value *v)
{
    return !v || v->type == JSON_NULL;
}

bool json_get_bool(const struct json_value *v)
{
    return v && v->type == JSON_BOOL && v->val.b;
}

int64_t json_get_int(const struct json_value *v)
{
    if (!v) return 0;
    if (v->type == JSON_INT) return v->val.i;
    if (v->type == JSON_REAL) return (int64_t)v->val.d;
    return 0;
}

double json_get_real(const struct json_value *v)
{
    if (!v) return 0.0;
    if (v->type == JSON_REAL) return v->val.d;
    if (v->type == JSON_INT) return (double)v->val.i;
    return 0.0;
}

const char *json_get_str(const struct json_value *v)
{
    if (v && v->type == JSON_STR) return v->val.s;
    return "";
}

/* --- JSON writer --- */

static size_t json_escape_str(const char *s, char *buf, size_t buflen)
{
    size_t pos = 0;
    if (pos < buflen) { buf[pos] = '"'; } pos++;
    for (const char *p = s; *p; p++) {
        char esc = 0;
        switch (*p) {
        case '"':  esc = '"'; break;
        case '\\': esc = '\\'; break;
        case '\b': esc = 'b'; break;
        case '\f': esc = 'f'; break;
        case '\n': esc = 'n'; break;
        case '\r': esc = 'r'; break;
        case '\t': esc = 't'; break;
        default: break;
        }
        if (esc) {
            if (pos < buflen) { buf[pos] = '\\'; } pos++;
            if (pos < buflen) { buf[pos] = esc; } pos++;
        } else if ((unsigned char)*p < 0x20) {
            char tmp[8];
            int n = snprintf(tmp, sizeof(tmp), "\\u%04x", (unsigned char)*p);
            for (int i = 0; i < n; i++) {
                if (pos < buflen) { buf[pos] = tmp[i]; } pos++;
            }
        } else {
            if (pos < buflen) { buf[pos] = *p; } pos++;
        }
    }
    if (pos < buflen) { buf[pos] = '"'; } pos++;
    return pos;
}

size_t json_write(const struct json_value *v, char *buf, size_t buflen)
{
    size_t pos = 0;
    switch (v->type) {
    case JSON_NULL:
        if (pos + 4 <= buflen) memcpy(buf + pos, "null", 4);
        pos += 4;
        break;
    case JSON_BOOL:
        if (v->val.b) {
            if (pos + 4 <= buflen) memcpy(buf + pos, "true", 4);
            pos += 4;
        } else {
            if (pos + 5 <= buflen) memcpy(buf + pos, "false", 5);
            pos += 5;
        }
        break;
    case JSON_INT: {
        char tmp[32];
        int n = snprintf(tmp, sizeof(tmp), "%" PRId64, v->val.i);
        if (pos + (size_t)n <= buflen) memcpy(buf + pos, tmp, (size_t)n);
        pos += (size_t)n;
        break;
    }
    case JSON_REAL: {
        char tmp[64];
        int n = snprintf(tmp, sizeof(tmp), "%.8g", v->val.d);
        if (pos + (size_t)n <= buflen) memcpy(buf + pos, tmp, (size_t)n);
        pos += (size_t)n;
        break;
    }
    case JSON_STR:
        pos += json_escape_str(v->val.s ? v->val.s : "", buf + pos,
                               buflen > pos ? buflen - pos : 0);
        break;
    case JSON_ARR: {
        if (pos < buflen) { buf[pos] = '['; } pos++;
        for (size_t i = 0; i < v->num_children; i++) {
            if (i > 0) { if (pos < buflen) { buf[pos] = ','; } pos++; }
            pos += json_write(&v->children[i], buf + pos,
                              buflen > pos ? buflen - pos : 0);
        }
        if (pos < buflen) { buf[pos] = ']'; } pos++;
        break;
    }
    case JSON_OBJ: {
        if (pos < buflen) { buf[pos] = '{'; } pos++;
        for (size_t i = 0; i < v->num_children; i++) {
            if (i > 0) { if (pos < buflen) { buf[pos] = ','; } pos++; }
            pos += json_escape_str(v->keys[i] ? v->keys[i] : "",
                                   buf + pos,
                                   buflen > pos ? buflen - pos : 0);
            if (pos < buflen) { buf[pos] = ':'; } pos++;
            pos += json_write(&v->children[i], buf + pos,
                              buflen > pos ? buflen - pos : 0);
        }
        if (pos < buflen) { buf[pos] = '}'; } pos++;
        break;
    }
    }
    /* Always NUL-terminate, even on truncation (pos >= buflen): callers pass
     * fixed buffers and then %s-print or strlen the result, so leaving it
     * unterminated is an over-read. On truncation, terminate at the last byte. */
    if (pos < buflen) buf[pos] = '\0';
    else if (buflen)  buf[buflen - 1] = '\0';
    return pos;
}

/* --- JSON reader --- */

/* Maximum nesting depth for arrays/objects.  Prevents stack overflow
 * under -O1+gcov where each recursive frame is larger due to
 * instrumentation overhead. 256 is generous for any real-world JSON. */
#define JSON_MAX_DEPTH 256

static const char *skip_ws(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
        p++;
    return p;
}

static bool parse_value_r(struct json_value *v, const char **pp,
                          const char *end, int depth);

static bool parse_string(char **out, const char **pp, const char *end)
{
    const char *p = *pp;
    if (p >= end || *p != '"') return false;
    p++;
    size_t cap = 64, len = 0;
    char *s = zcl_malloc(cap, "json_string");
    if (!s) return false;
    while (p < end && *p != '"') {
        if (*p == '\\') {
            p++;
            if (p >= end) { free(s); return false; }
            char c;
            switch (*p) {
            case '"':  c = '"'; break;
            case '\\': c = '\\'; break;
            case '/':  c = '/'; break;
            case 'b':  c = '\b'; break;
            case 'f':  c = '\f'; break;
            case 'n':  c = '\n'; break;
            case 'r':  c = '\r'; break;
            case 't':  c = '\t'; break;
            case 'u':
                p += 4;
                c = '?';
                break;
            default: free(s); return false;
            }
            if (len >= cap - 1) {
                cap *= 2;
                char *ns = zcl_realloc(s, cap, "json_string");
                if (!ns) { free(s); return false; }
                s = ns;
            }
            s[len++] = c;
        } else {
            if (len >= cap - 1) {
                cap *= 2;
                char *ns = zcl_realloc(s, cap, "json_string");
                if (!ns) { free(s); return false; }
                s = ns;
            }
            s[len++] = *p;
        }
        p++;
    }
    if (p >= end) { free(s); return false; }
    p++;
    s[len] = '\0';
    *out = s;
    *pp = p;
    return true;
}

static bool parse_number(struct json_value *v, const char **pp, const char *end)
{
    const char *start = *pp;
    const char *p = start;
    bool is_real = false;
    if (p < end && *p == '-') p++;
    while (p < end && *p >= '0' && *p <= '9') p++;
    if (p < end && *p == '.') { is_real = true; p++; }
    while (p < end && *p >= '0' && *p <= '9') p++;
    if (p < end && (*p == 'e' || *p == 'E')) {
        is_real = true;
        p++;
        if (p < end && (*p == '+' || *p == '-')) p++;
        while (p < end && *p >= '0' && *p <= '9') p++;
    }
    if (p == start) return false;
    char tmp[64];
    size_t len = (size_t)(p - start);
    if (len >= sizeof(tmp)) return false;
    memcpy(tmp, start, len);
    tmp[len] = '\0';
    if (is_real) {
        v->type = JSON_REAL;
        v->val.d = strtod(tmp, NULL);
    } else {
        v->type = JSON_INT;
        v->val.i = strtoll(tmp, NULL, 10);
    }
    *pp = p;
    return true;
}

static bool parse_value_r(struct json_value *v, const char **pp,
                          const char *end, int depth)
{
    const char *p = skip_ws(*pp, end);
    if (p >= end) return false;

    json_init(v);

    if (*p == '"') {
        char *s = NULL;
        if (!parse_string(&s, &p, end)) return false;
        v->type = JSON_STR;
        v->val.s = s;
        *pp = p;
        return true;
    }
    if (*p == '{') {
        if (depth >= JSON_MAX_DEPTH) return false;
        p++;
        json_set_object(v);
        p = skip_ws(p, end);
        if (p < end && *p == '}') { *pp = p + 1; return true; }
        while (p < end) {
            p = skip_ws(p, end);
            char *key = NULL;
            if (!parse_string(&key, &p, end)) return false;
            p = skip_ws(p, end);
            if (p >= end || *p != ':') { free(key); return false; }
            p++;
            struct json_value child;
            if (!parse_value_r(&child, &p, end, depth + 1)) { free(key); return false; }
            if (!json_grow(v)) { free(key); json_free(&child); return false; }
            v->keys[v->num_children] = key;
            v->children[v->num_children] = child;
            v->num_children++;
            p = skip_ws(p, end);
            if (p < end && *p == ',') { p++; continue; }
            if (p < end && *p == '}') { *pp = p + 1; return true; }
            return false;
        }
        return false;
    }
    if (*p == '[') {
        if (depth >= JSON_MAX_DEPTH) return false;
        p++;
        json_set_array(v);
        p = skip_ws(p, end);
        if (p < end && *p == ']') { *pp = p + 1; return true; }
        while (p < end) {
            struct json_value child;
            if (!parse_value_r(&child, &p, end, depth + 1)) return false;
            if (!json_grow(v)) { json_free(&child); return false; }
            v->keys[v->num_children] = NULL;
            v->children[v->num_children] = child;
            v->num_children++;
            p = skip_ws(p, end);
            if (p < end && *p == ',') { p++; continue; }
            if (p < end && *p == ']') { *pp = p + 1; return true; }
            return false;
        }
        return false;
    }
    if (end - p >= 4 && memcmp(p, "null", 4) == 0) {
        v->type = JSON_NULL;
        *pp = p + 4;
        return true;
    }
    if (end - p >= 4 && memcmp(p, "true", 4) == 0) {
        v->type = JSON_BOOL;
        v->val.b = true;
        *pp = p + 4;
        return true;
    }
    if (end - p >= 5 && memcmp(p, "false", 5) == 0) {
        v->type = JSON_BOOL;
        v->val.b = false;
        *pp = p + 5;
        return true;
    }
    if (*p == '-' || (*p >= '0' && *p <= '9')) {
        *pp = p;
        return parse_number(v, pp, end);
    }
    return false;
}

bool json_read(struct json_value *v, const char *raw, size_t len)
{
    json_init(v);
    const char *p = raw;
    const char *end = raw + len;
    if (!parse_value_r(v, &p, end, 0) || skip_ws(p, end) != end) {
        json_free(v);
        json_init(v);
        return false;
    }
    return true;
}

void diag_push_health(struct json_value *out, bool ok, const char *reason)
{
    struct json_value health = {0};
    json_set_object(&health);
    json_push_kv_bool(&health, "ok", ok);
    json_push_kv_str(&health, "reason", reason);
    json_push_kv(out, "_health", &health);
    json_free(&health);
}

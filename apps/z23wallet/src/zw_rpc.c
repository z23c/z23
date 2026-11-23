/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: JSON-RPC over the loopback HTTP client: endpoint location, the
 * 401 cookie re-read, error mapping (-28 warming, -32601 missing method)
 * and strict reply validation. */
#include <stdio.h>
#include <string.h>

#include "zw.h"

#define READ_TIMEOUT_MS 5000

static void set_err(struct zw_rpc_error *e, enum zw_err kind, int code, const char *msg)
{
    e->kind = kind;
    e->code = code;
    snprintf(e->message, sizeof(e->message), "%s", msg ? msg : "");
}

/* One POST with the single permitted 401 retry after re-reading the cookie. */
static enum zw_err post_with_auth_retry(struct zw_rpc *r, const char *body, size_t len,
                                        struct zw_buf *reply, int *status)
{
    enum zw_err e = zw_http_post(&r->ep, body, len, reply, READ_TIMEOUT_MS, status);
    if (e == ZW_OK && *status == 401) {
        zw_log("rpc: 401, re-reading the cookie once");
        zw_buf_free(reply);
        if (zw_cookie_load(&r->ep))
            e = zw_http_post(&r->ep, body, len, reply, READ_TIMEOUT_MS, status);
        if (e == ZW_OK && *status == 401) return ZW_ERR_AUTH;
    }
    return e;
}

static enum zw_err parse_envelope(const char *method, struct zw_buf *reply, struct json_value *result,
                                  struct zw_rpc_error *e)
{
    struct json_value root;
    json_init(&root);
    if (!reply->data || !json_read(&root, reply->data, reply->len) || root.type != JSON_OBJ) {
        json_free(&root);
        set_err(e, ZW_ERR_BAD_REPLY, 0, method);
        return ZW_ERR_BAD_REPLY;
    }
    const struct json_value *err = json_get(&root, "error");
    const struct json_value *res = json_get(&root, "result");
    enum zw_err out = ZW_OK;
    if (err && !json_is_null(err)) {
        const struct json_value *c = json_get(err, "code"), *m = json_get(err, "message");
        set_err(e, ZW_ERR_RPC, c ? (int)json_get_int(c) : 0,
                m && m->type == JSON_STR ? json_get_str(m) : "");
        out = ZW_ERR_RPC;
    } else if (!res) {
        set_err(e, ZW_ERR_BAD_REPLY, 0, method);
        out = ZW_ERR_BAD_REPLY;
    } else if (result) {
        json_copy(result, res);
    }
    json_free(&root);
    return out;
}

enum zw_err zw_rpc_call(struct zw_rpc *r, const char *method, const char *params_json,
                        struct json_value *result, struct zw_rpc_error *e)
{
    set_err(e, ZW_OK, 0, "");
    if (!r->ep.valid && !zw_locate(r->opt, &r->ep, &r->report)) {
        set_err(e, ZW_ERR_SEARCHING, 0, "no node found");
        return ZW_ERR_SEARCHING;
    }
    char body[512];
    int n = snprintf(body, sizeof(body),
                     "{\"jsonrpc\":\"1.0\",\"id\":%u,\"method\":\"%s\",\"params\":%s}",
                     (unsigned)++r->next_id, method, params_json ? params_json : "[]");
    if (n <= 0 || (size_t)n >= sizeof(body)) {
        set_err(e, ZW_ERR_IO, 0, "request too large");
        return ZW_ERR_IO;
    }
    struct zw_buf reply = {0};
    int status = 0;
    enum zw_err err = post_with_auth_retry(r, body, (size_t)n, &reply, &status);
    if (err == ZW_OK) {
        err = parse_envelope(method, &reply, result, e);
        if (err == ZW_ERR_BAD_REPLY && status == 403) err = ZW_ERR_AUTH;
    }
    zw_buf_free(&reply);
    if (err != ZW_OK && e->kind == ZW_OK) set_err(e, err, 0, method);
    if (err == ZW_ERR_REFUSED || err == ZW_ERR_AUTH) r->ep.valid = false; /* locate again */
    return err;
}

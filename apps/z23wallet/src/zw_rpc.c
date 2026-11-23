/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: JSON-RPC over the loopback HTTP client: endpoint location, the
 * zclassicd read-only allowlist (refused calls send no bytes), the 401
 * cookie re-read (cookie credentials only), the auto profile's fall back
 * from a refusing Z23 node to zclassicd, error mapping (-28 warming,
 * -32601 missing method) and strict reply validation. */
#include <stdio.h>
#include <string.h>

#include "zw.h"

/* R5: the only calls ever sent to a legacy zclassicd. All are reads. */
static const char *const k_legacy_allow[] = {
    "getinfo", "getblockchaininfo", "getnetworkinfo", "getpeerinfo", "getnetworksolps",
    "getwalletinfo", "getwalletsummary", "z_gettotalbalance", "listunspent", "z_listunspent",
    "z_listaddresses", "getaddressesbyaccount", "listtransactions", "z_listreceivedbyaddress",
    "gettransaction",
};

bool zw_rpc_legacy_allowed(const char *method)
{
    for (size_t i = 0; i < sizeof(k_legacy_allow) / sizeof(k_legacy_allow[0]); i++)
        if (!strcmp(method, k_legacy_allow[i])) return true;
    return false;
}

static void set_err(struct zw_rpc_error *e, enum zw_err kind, int code, const char *msg)
{
    e->kind = kind;
    e->code = code;
    snprintf(e->message, sizeof(e->message), "%s", msg ? msg : "");
}

/* One POST; a 401 re-reads the cookie once, but only when the cookie supplied
 * the credentials: conf credentials are never replaced by a (stale) cookie. */
static enum zw_err post_with_auth_retry(struct zw_rpc *r, const char *body, size_t len,
                                        struct zw_buf *reply, int *status)
{
    enum zw_err e = zw_http_post(&r->ep, body, len, reply, r->deadline_ms, status, &r->phase, r->cancel);
    if (e != ZW_OK || *status != 401) return e;
    if (r->ep.cred_src != ZW_CRED_COOKIE) return ZW_ERR_AUTH;
    zw_log("rpc: 401, re-reading the cookie once");
    zw_buf_free(reply);
    if (zw_cookie_load(&r->ep))
        e = zw_http_post(&r->ep, body, len, reply, r->deadline_ms, status, &r->phase, r->cancel);
    return e == ZW_OK && *status == 401 ? ZW_ERR_AUTH : e;
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

/* Locate; in auto mode a Z23 node that refused hands over to zclassicd. */
bool zw_rpc_ensure(struct zw_rpc *r)
{
    if (r->ep.valid) return true;
    atomic_store(&r->phase, ZW_PHASE_LOCATE);
    if (r->opt->profile == ZW_PROFILE_AUTO && r->z23_refused) {
        struct zw_options legacy = *r->opt;
        legacy.profile = ZW_PROFILE_ZCLASSICD;
        legacy.datadir[0] = 0; /* --datadir named the Z23 folder */
        if (zw_locate(&legacy, &r->ep, &r->report)) return true;
        r->z23_refused = false; /* nothing legacy either: look for Z23 again next time */
    }
    return zw_locate(r->opt, &r->ep, &r->report);
}

/* A failure decides where the next call looks for the node. */
static void after_failure(struct zw_rpc *r, enum zw_err err)
{
    if (err == ZW_ERR_REFUSED && r->ep.profile == ZW_PROFILE_Z23 && r->opt->profile == ZW_PROFILE_AUTO)
        r->z23_refused = true;
    if (err == ZW_ERR_REFUSED || err == ZW_ERR_AUTH || err == ZW_ERR_TIMEOUT) r->ep.valid = false; /* locate again */
}

/* SEARCHING, or the client-side refusal of a non-allowlisted zclassicd call. */
static enum zw_err precheck(struct zw_rpc *r, const char *method, struct zw_rpc_error *e)
{
    if (!zw_rpc_ensure(r)) {
        atomic_store(&r->phase, ZW_PHASE_IDLE);
        set_err(e, ZW_ERR_SEARCHING, 0, "no node found");
        return ZW_ERR_SEARCHING;
    }
    if (r->ep.profile == ZW_PROFILE_ZCLASSICD && !zw_rpc_legacy_allowed(method)) {
        char m[160];
        snprintf(m, sizeof(m), "%.64s is not allowed against zclassicd", method);
        zw_log("rpc: refused %s (zclassicd is read only)", method);
        set_err(e, ZW_ERR_RPC, 0, m);
        return ZW_ERR_RPC;
    }
    return ZW_OK;
}

enum zw_err zw_rpc_call(struct zw_rpc *r, const char *method, const char *params_json,
                        struct json_value *result, struct zw_rpc_error *e)
{
    set_err(e, ZW_OK, 0, "");
    enum zw_err err = precheck(r, method, e);
    if (err != ZW_OK) return err;
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
    err = post_with_auth_retry(r, body, (size_t)n, &reply, &status);
    if (err == ZW_OK) {
        err = parse_envelope(method, &reply, result, e);
        if (err == ZW_ERR_BAD_REPLY && status == 403) err = ZW_ERR_AUTH;
    }
    zw_buf_free(&reply);
    atomic_store(&r->phase, ZW_PHASE_IDLE);
    if (err != ZW_OK && e->kind == ZW_OK) set_err(e, err, 0, method);
    after_failure(r, err);
    return err;
}

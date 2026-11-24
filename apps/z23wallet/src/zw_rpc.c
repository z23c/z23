/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: JSON-RPC over the loopback HTTP client: endpoint location, the
 * zclassicd allowlist (refused calls send no bytes), the 401
 * cookie re-read (cookie credentials only), the auto profile's fall back
 * from an unreachable Z23 port to zclassicd, error mapping (-28 warming,
 * -32601 missing method) and strict reply validation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zw.h"

/* R5: the only calls ever sent to a legacy zclassicd: the reads, plus exactly
 * the three calls beta13's Send makes (z_sendmany, sent only by the send
 * runner after the confirm dialog, and its two status reads). */
static const char *const k_legacy_allow[] = {
    "getinfo", "getblockchaininfo", "getnetworkinfo", "getpeerinfo", "getnetworksolps",
    "getwalletinfo", "getwalletsummary", "z_gettotalbalance", "listunspent", "z_listunspent",
    "z_listaddresses", "getaddressesbyaccount", "listtransactions", "z_listreceivedbyaddress",
    "gettransaction", "z_sendmany", "z_getoperationstatus", "z_listsendjournal",
};

bool zw_rpc_legacy_allowed(const char *method)
{
    for (size_t i = 0; i < sizeof(k_legacy_allow) / sizeof(k_legacy_allow[0]); i++)
        if (!strcmp(method, k_legacy_allow[i])) return true;
    return false;
}

void zw_rpc_progress(struct zw_rpc *r) { atomic_store(&r->progress_ms, (long long)zw_monotonic_ms()); }

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
    zw_rpc_progress(r);
    if (e != ZW_OK || *status != 401) return e;
    if (r->ep.cred_src != ZW_CRED_COOKIE) return ZW_ERR_AUTH;
    zw_log("rpc: 401, re-reading the cookie once");
    zw_buf_free(reply);
    if (zw_cookie_load(&r->ep))
        e = zw_http_post(&r->ep, body, len, reply, r->deadline_ms, status, &r->phase, r->cancel);
    zw_rpc_progress(r);
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

/* Nobody is listening on the port. A loopback connect that does not finish
 * within the connect cap counts too: Windows retries the SYN after a reset and
 * reports "refused" only after about 2 s, past the cap (R7: a Z23 node is
 * preferred only if its port answers). */
bool zw_rpc_unreachable(enum zw_err err, int fail_phase)
{
    return err == ZW_ERR_REFUSED || (err == ZW_ERR_TIMEOUT && fail_phase == ZW_PHASE_CONNECT);
}

/* A failure decides where the next call looks for the node. True when this
 * failure just handed the auto profile over from Z23 to zclassicd. */
static bool after_failure(struct zw_rpc *r, enum zw_err err, int fail_phase)
{
    bool handover = zw_rpc_unreachable(err, fail_phase) && r->ep.profile == ZW_PROFILE_Z23 &&
                    r->opt->profile == ZW_PROFILE_AUTO && !r->z23_refused;
    if (handover) r->z23_refused = true;
    if (err == ZW_ERR_REFUSED || err == ZW_ERR_AUTH || err == ZW_ERR_TIMEOUT) r->ep.valid = false; /* locate again */
    return handover;
}

/* SEARCHING, a z_sendmany outside the send runner, or the client-side
 * refusal of a non-allowlisted zclassicd call. */
static enum zw_err precheck(struct zw_rpc *r, const char *method, struct zw_rpc_error *e)
{
    if (!strcmp(method, "z_sendmany") && !r->may_send) { /* only the send runner sends */
        zw_log("rpc: refused z_sendmany outside the send runner");
        set_err(e, ZW_ERR_RPC, 0, "z_sendmany is only sent from the confirm dialog");
        return ZW_ERR_RPC;
    }
    bool found = zw_rpc_ensure(r);
    zw_rpc_progress(r);
    if (!found) {
        atomic_store(&r->phase, ZW_PHASE_IDLE);
        set_err(e, ZW_ERR_SEARCHING, 0, "no node found");
        return ZW_ERR_SEARCHING;
    }
    if (r->ep.profile == ZW_PROFILE_ZCLASSICD && !zw_rpc_legacy_allowed(method)) {
        char m[160];
        snprintf(m, sizeof(m), "%.64s is not allowed against zclassicd", method);
        zw_log("rpc: refused %s (not on the zclassicd allowlist)", method);
        set_err(e, ZW_ERR_RPC, 0, m);
        return ZW_ERR_RPC;
    }
    return ZW_OK;
}

static enum zw_err call_once(struct zw_rpc *r, const char *method, const char *params_json,
                             struct json_value *result, struct zw_rpc_error *e, bool *handover)
{
    set_err(e, ZW_OK, 0, "");
    enum zw_err err = precheck(r, method, e);
    if (err != ZW_OK) return err;
    const char *params = params_json ? params_json : "[]";
    size_t cap = strlen(params) + strlen(method) + 96; /* a send with memos is a few KiB */
    char *body = cap <= 65536 ? malloc(cap) : NULL;
    if (!body) {
        set_err(e, ZW_ERR_IO, 0, "request too large");
        return ZW_ERR_IO;
    }
    int n = snprintf(body, cap, "{\"jsonrpc\":\"1.0\",\"id\":%u,\"method\":\"%s\",\"params\":%s}",
                     (unsigned)++r->next_id, method, params);
    struct zw_buf reply = {0};
    int status = 0;
    err = post_with_auth_retry(r, body, (size_t)n, &reply, &status);
    free(body);
    if (err == ZW_OK) {
        err = parse_envelope(method, &reply, result, e);
        if (err == ZW_ERR_BAD_REPLY && status == 403) err = ZW_ERR_AUTH;
    }
    zw_buf_free(&reply);
    int fail_phase = atomic_exchange(&r->phase, ZW_PHASE_IDLE);
    if (err != ZW_OK && e->kind == ZW_OK) set_err(e, err, 0, method);
    *handover = after_failure(r, err, fail_phase);
    return err;
}

/* When the auto profile's Z23 port turns out dead, the same call is asked of
 * zclassicd at once (still under its read-only allowlist), so Home does not
 * wait a poll interval for the fall back. */
enum zw_err zw_rpc_call(struct zw_rpc *r, const char *method, const char *params_json,
                        struct json_value *result, struct zw_rpc_error *e)
{
    bool handover = false;
    enum zw_err err = call_once(r, method, params_json, result, e, &handover);
    if (!handover) return err;
    zw_log("rpc: Z23 port did not answer; trying zclassicd");
    return call_once(r, method, params_json, result, e, &handover);
}

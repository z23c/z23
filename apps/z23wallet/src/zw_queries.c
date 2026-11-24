/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the query table: each abstract query maps to Z23 methods first
 * and legacy zclassicd methods second, and parses replies into plain
 * structs with integer zatoshi. Reads only; nothing here can spend. */
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "zw.h"

#define RPC_METHOD_NOT_FOUND (-32601)

static int64_t geti(const struct json_value *o, const char *k, int64_t dflt)
{
    const struct json_value *v = json_get(o, k);
    if (!v) return dflt;
    if (v->type == JSON_INT) return v->val.i;
    /* The node is untrusted: an out-of-range or NaN double is not convertible. */
    if (v->type == JSON_REAL) return v->val.d > -9.0e18 && v->val.d < 9.0e18 ? (int64_t)v->val.d : dflt;
    return dflt;
}

static void copy_str(char *dst, size_t cap, const struct json_value *o, const char *k)
{
    const struct json_value *v = json_get(o, k);
    snprintf(dst, cap, "%s", v && v->type == JSON_STR ? json_get_str(v) : "");
}

static bool parse_chain(const struct json_value *r, struct zw_chain *c)
{
    if (r->type != JSON_OBJ || !json_get(r, "blocks")) return false;
    c->blocks = geti(r, "blocks", 0);
    c->headers = geti(r, "headers", c->blocks);
    copy_str(c->chain, sizeof(c->chain), r, "chain");
    const struct json_value *p = json_get(r, "verificationprogress");
    double d = p && p->type == JSON_REAL ? p->val.d : p && p->type == JSON_INT ? (double)p->val.i : 0.0;
    c->progress_permille = (int32_t)lround((d < 0 ? 0 : d > 1 ? 1 : d) * 1000.0);
    const struct json_value *bv = json_get(r, "bootstrap_validation");
    const struct json_value *pv = bv && bv->type == JSON_OBJ ? json_get(bv, "provisional") : NULL;
    c->provisional = pv && pv->type == JSON_BOOL && pv->val.b;
    return true;
}

static bool parse_net(const struct json_value *r, struct zw_net *n)
{
    if (r->type != JSON_OBJ || !json_get(r, "connections")) return false;
    n->connections = geti(r, "connections", 0);
    n->inbound = geti(r, "inbound_connections", -1);
    n->outbound = geti(r, "outbound_connections", -1);
    n->version = geti(r, "version", 0);
    copy_str(n->subversion, sizeof(n->subversion), r, "subversion");
    return true;
}

static bool amount_key(const struct json_value *r, const char *k, int64_t *out)
{
    const struct json_value *v = json_get(r, k);
    return v && !json_is_null(v) && zw_amount_from_json(v, out);
}

static bool json_flag(const struct json_value *r, const char *k)
{
    const struct json_value *b = json_get(r, k);
    return b && b->type == JSON_BOOL && b->val.b;
}

static bool parse_summary(const struct json_value *r, struct zw_wallet *w)
{
    if (r->type != JSON_OBJ || !json_get(r, "schema")) return false;
    const struct json_value *ba = json_get(r, "balance_available");
    w->known = !ba || (ba->type == JSON_BOOL && ba->val.b);
    bool ok = amount_key(r, "spendable_zat", &w->spendable);
    if (!amount_key(r, "pending_zat", &w->pending)) w->pending = 0;
    if (!amount_key(r, "public_zat", &w->publicf)) w->publicf = 0;
    if (!amount_key(r, "immature_zat", &w->immature)) w->immature = 0;
    if (!ok) w->known = false;
    w->total = w->spendable + w->pending + w->publicf;
    w->scanned = geti(r, "scanned_through_height", -1);
    w->behind = geti(r, "blocks_behind", 0);
    w->current = json_flag(r, "current");
    w->locked = json_flag(r, "locked");
    w->encrypted = json_flag(r, "encrypted");
    w->send_allowed = json_flag(r, "send_allowed");
    copy_str(w->reason, sizeof(w->reason), r, "send_blocked_reason");
    return true;
}

static bool parse_legacy_total(const struct json_value *r, struct zw_wallet *w)
{
    if (r->type != JSON_OBJ) return false;
    int64_t t = 0, p = 0;
    if (!amount_key(r, "private", &p) || !amount_key(r, "transparent", &t)) return false;
    w->spendable = p;
    w->publicf = t;
    w->total = p + t;
    w->known = true;
    w->legacy = true;
    w->current = true;
    w->scanned = -1;
    snprintf(w->reason, sizeof(w->reason),
             "Sending through zclassicd isn't supported here. Use the ZClassic wallet, "
             "or connect to a Z23 node.");
    return true;
}

static enum zw_err wallet_query(struct zw_rpc *r, struct zw_result *out)
{
    struct json_value v;
    json_init(&v);
    enum zw_err e = ZW_OK;
    bool legacy = r->ep.profile == ZW_PROFILE_ZCLASSICD || r->missing_walletsummary;
    if (!legacy) {
        e = zw_rpc_call(r, "walletsummary", "[]", &v, &out->rpc);
        if (e == ZW_ERR_RPC && out->rpc.code == RPC_METHOD_NOT_FOUND) {
            r->missing_walletsummary = true; /* latched for the session */
            legacy = true;
        } else if (e == ZW_OK) {
            e = parse_summary(&v, &out->wallet) ? ZW_OK : ZW_ERR_BAD_REPLY;
            if (e != ZW_OK) snprintf(out->rpc.message, sizeof(out->rpc.message), "walletsummary");
            out->profile = ZW_PROFILE_Z23;
        }
    }
    if (legacy) {
        json_free(&v);
        json_init(&v);
        e = zw_rpc_call(r, "z_gettotalbalance", "[]", &v, &out->rpc);
        if (e == ZW_OK) {
            e = parse_legacy_total(&v, &out->wallet) ? ZW_OK : ZW_ERR_BAD_REPLY;
            if (e != ZW_OK) snprintf(out->rpc.message, sizeof(out->rpc.message), "z_gettotalbalance");
            out->profile = ZW_PROFILE_ZCLASSICD;
        }
    }
    json_free(&v);
    return e;
}

enum zw_err zw_query_run(struct zw_rpc *r, enum zw_query q, struct zw_result *out)
{
    out->kind = q;
    struct json_value v;
    json_init(&v);
    enum zw_err e;
    switch (q) {
    case ZW_Q_CHAIN:
        e = zw_rpc_call(r, "getblockchaininfo", "[]", &v, &out->rpc);
        if (e == ZW_OK && !parse_chain(&v, &out->chain)) {
            e = ZW_ERR_BAD_REPLY;
            snprintf(out->rpc.message, sizeof(out->rpc.message), "getblockchaininfo");
        }
        break;
    case ZW_Q_NET:
        e = zw_rpc_call(r, "getnetworkinfo", "[]", &v, &out->rpc);
        if (e == ZW_OK && !parse_net(&v, &out->net)) {
            e = ZW_ERR_BAD_REPLY;
            snprintf(out->rpc.message, sizeof(out->rpc.message), "getnetworkinfo");
        }
        break;
    default:
        e = wallet_query(r, out);
        break;
    }
    json_free(&v);
    out->err = e;
    out->port = r->ep.port;
    out->report = r->report;
    snprintf(out->datadir, sizeof(out->datadir), "%s", r->ep.datadir);
    if (out->profile == ZW_PROFILE_AUTO) out->profile = r->ep.profile;
    return e;
}

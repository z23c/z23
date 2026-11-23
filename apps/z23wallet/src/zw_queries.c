/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the query table: each abstract query maps to Z23 methods first
 * and legacy zclassicd methods second, and parses replies into plain
 * structs with integer zatoshi. Node replies are untrusted: every field is
 * type-checked and bounded. Reads only; nothing here can spend. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/safe_alloc.h"
#include "zw.h"

#define RPC_METHOD_NOT_FOUND (-32601)

static int64_t geti(const struct json_value *o, const char *k, int64_t dflt)
{
    const struct json_value *v = json_get(o, k);
    if (!v) return dflt;
    if (v->type == JSON_INT) return v->val.i;
    /* The node is untrusted: a NaN or out-of-range double is not convertible. */
    if (v->type == JSON_REAL) return v->val.d > -9e15 && v->val.d < 9e15 ? (int64_t)v->val.d : dflt;
    return dflt;
}

static void copy_str(char *dst, size_t cap, const struct json_value *o, const char *k)
{
    const struct json_value *v = json_get(o, k);
    snprintf(dst, cap, "%s", v && v->type == JSON_STR ? json_get_str(v) : "");
}

static bool json_flag(const struct json_value *r, const char *k)
{
    const struct json_value *b = json_get(r, k);
    return b && b->type == JSON_BOOL && b->val.b;
}

static bool parse_chain(const struct json_value *r, struct zw_chain *c)
{
    if (r->type != JSON_OBJ || !json_get(r, "blocks")) return false;
    c->blocks = geti(r, "blocks", 0);
    c->headers = geti(r, "headers", c->blocks);
    c->tiptime = geti(r, "tiptime", geti(r, "mediantime", 0));
    c->ibd = json_flag(r, "initialblockdownload");
    copy_str(c->chain, sizeof(c->chain), r, "chain");
    const struct json_value *p = json_get(r, "verificationprogress");
    double d = p && p->type == JSON_REAL ? p->val.d : p && p->type == JSON_INT ? (double)p->val.i : 0.0;
    c->progress_permille = (int32_t)lround((d < 0 ? 0 : d > 1 ? 1 : d) * 1000.0);
    const struct json_value *bv = json_get(r, "bootstrap_validation");
    const struct json_value *pv = bv && bv->type == JSON_OBJ ? json_get(bv, "provisional") : NULL;
    c->provisional = pv && pv->type == JSON_BOOL && pv->val.b;
    return c->blocks >= 0 && c->headers >= 0;
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

/* getwalletsummary [0] and z_gettotalbalance [0] share these three fields. */
static bool parse_legacy_total(const struct json_value *r, struct zw_wallet *w)
{
    if (r->type != JSON_OBJ) return false;
    int64_t t = 0, p = 0, total = 0;
    if (!amount_key(r, "private", &p) || !amount_key(r, "transparent", &t)) return false;
    if (!amount_key(r, "total", &total)) total = p + t;
    w->spendable = p;
    w->publicf = t;
    w->total = total;
    w->known = true;
    w->legacy = true;
    w->current = true;
    w->scanned = -1;
    snprintf(w->reason, sizeof(w->reason),
             "Sending through zclassicd isn't supported here. Use the ZClassic wallet, "
             "or connect to a Z23 node.");
    return true;
}

static enum zw_err call_parse(struct zw_rpc *r, const char *method, const char *params, struct zw_result *out,
                              bool (*parse)(const struct json_value *, struct zw_wallet *))
{
    struct json_value v;
    json_init(&v);
    enum zw_err e = zw_rpc_call(r, method, params, &v, &out->rpc);
    if (e == ZW_OK && !parse(&v, &out->wallet)) {
        e = ZW_ERR_BAD_REPLY;
        snprintf(out->rpc.message, sizeof(out->rpc.message), "%s", method);
    }
    json_free(&v);
    return e;
}

static enum zw_err legacy_wallet(struct zw_rpc *r, struct zw_result *out)
{
    out->profile = ZW_PROFILE_ZCLASSICD;
    if (!r->missing_getwalletsummary) {
        enum zw_err e = call_parse(r, "getwalletsummary", "[0]", out, parse_legacy_total);
        if (!(e == ZW_ERR_RPC && out->rpc.code == RPC_METHOD_NOT_FOUND)) return e;
        r->missing_getwalletsummary = true; /* latched for the session */
        zw_log("rpc: getwalletsummary missing; using z_gettotalbalance");
    }
    return call_parse(r, "z_gettotalbalance", "[0]", out, parse_legacy_total);
}

static enum zw_err wallet_query(struct zw_rpc *r, struct zw_result *out)
{
    bool legacy = zw_rpc_ensure(r) && r->ep.profile == ZW_PROFILE_ZCLASSICD;
    if (!legacy && !r->missing_walletsummary) {
        enum zw_err e = call_parse(r, "walletsummary", "[]", out, parse_summary);
        if (!(e == ZW_ERR_RPC && out->rpc.code == RPC_METHOD_NOT_FOUND)) {
            if (e == ZW_OK) out->profile = ZW_PROFILE_Z23;
            return e;
        }
        r->missing_walletsummary = true; /* latched for the session */
    }
    return legacy_wallet(r, out);
}

/* ---- per-address balances: listunspent [0] + z_listunspent [0] ---- */

enum zw_addr_kind zw_addr_kind_of(const char *a)
{
    if (a[0] != 'z') return ZW_ADDR_PUBLIC;
    if (!strncmp(a, "zs", 2) || !strncmp(a, "ztestsapling", 12) || !strncmp(a, "zregtestsapling", 15))
        return ZW_ADDR_SAPLING;
    return ZW_ADDR_SPROUT;
}

static int row_cmp(const void *a, const void *b)
{
    return strcmp(((const struct zw_bal_row *)a)->addr, ((const struct zw_bal_row *)b)->addr);
}

struct bal_acc { struct zw_bal_row *rows; size_t n, cap; };

static bool acc_unspent(struct bal_acc *acc, const struct json_value *arr)
{
    if (arr->type != JSON_ARR) return false;
    size_t n = json_size(arr);
    for (size_t i = 0; i < n; i++) {
        const struct json_value *u = json_at(arr, i), *a = u ? json_get(u, "address") : NULL;
        int64_t zat = 0;
        if (!a || a->type != JSON_STR || !amount_key(u, "amount", &zat)) return false;
        const char *s = json_get_str(a);
        if (!s[0] || strlen(s) >= sizeof(acc->rows[0].addr)) continue; /* not an address we can show */
        if (acc->n == acc->cap) {
            size_t cap = acc->cap ? acc->cap * 2 : 64;
            struct zw_bal_row *nr = zcl_realloc(acc->rows, cap * sizeof(*nr), "zw_bal_rows");
            if (!nr) return false;
            acc->rows = nr;
            acc->cap = cap;
        }
        struct zw_bal_row *r = &acc->rows[acc->n++];
        snprintf(r->addr, sizeof(r->addr), "%s", s);
        r->zat = zat;
        r->unconfirmed = geti(u, "confirmations", 1) <= 0;
        r->kind = (uint8_t)zw_addr_kind_of(s);
    }
    return true;
}

/* Sort by address (QMap order), sum duplicates, keep rows with a balance. */
static void acc_publish(struct bal_acc *acc, struct zw_balances *b)
{
    if (acc->n) qsort(acc->rows, acc->n, sizeof(*acc->rows), row_cmp);
    for (size_t i = 0; i < acc->n;) {
        struct zw_bal_row sum = acc->rows[i];
        size_t j = i + 1;
        for (; j < acc->n && !strcmp(acc->rows[j].addr, sum.addr); j++) {
            if (sum.zat <= ZW_MAX_MONEY) sum.zat += acc->rows[j].zat;
            sum.unconfirmed = sum.unconfirmed || acc->rows[j].unconfirmed;
        }
        i = j;
        if (sum.unconfirmed) b->any_unconfirmed = true;
        if (sum.zat <= 0) continue;
        if (b->n < ZW_BAL_MAX) b->rows[b->n++] = sum;
        else b->more++;
    }
}

static enum zw_err list_into(struct zw_rpc *r, const char *method, struct bal_acc *acc, struct zw_result *out)
{
    struct json_value v;
    json_init(&v);
    enum zw_err e = zw_rpc_call(r, method, "[0]", &v, &out->rpc);
    if (e == ZW_OK && !acc_unspent(acc, &v)) {
        e = ZW_ERR_BAD_REPLY;
        snprintf(out->rpc.message, sizeof(out->rpc.message), "%s", method);
    }
    json_free(&v);
    return e;
}

/* Both lists must answer or nothing is published (no partial table). */
static enum zw_err balances_query(struct zw_rpc *r, struct zw_result *out)
{
    struct bal_acc acc = {0};
    enum zw_err e = list_into(r, "listunspent", &acc, out);
    if (e == ZW_OK) e = list_into(r, "z_listunspent", &acc, out);
    if (e == ZW_OK) {
        out->bal = zcl_calloc(1, sizeof(*out->bal), "zw_balances");
        if (out->bal) acc_publish(&acc, out->bal);
        else e = ZW_ERR_NOMEM;
    }
    free(acc.rows);
    return e;
}

/* getinfo (connections, version) and getnetworksolps; neither is required. */
static enum zw_err info_query(struct zw_rpc *r, struct zw_result *out)
{
    struct json_value v;
    json_init(&v);
    enum zw_err e = zw_rpc_call(r, "getinfo", "[]", &v, &out->rpc);
    if (e == ZW_OK && v.type == JSON_OBJ) {
        out->info.connections = geti(&v, "connections", 0);
        out->info.version = geti(&v, "version", 0);
    }
    json_free(&v);
    json_init(&v);
    struct zw_rpc_error se;
    if (e == ZW_OK && zw_rpc_call(r, "getnetworksolps", "[]", &v, &se) == ZW_OK) {
        out->info.solps = v.type == JSON_INT ? v.val.i : v.type == JSON_REAL ? (int64_t)llround(v.val.d) : 0;
        out->info.has_solps = v.type == JSON_INT || v.type == JSON_REAL;
    }
    json_free(&v);
    return e;
}

static enum zw_err simple_query(struct zw_rpc *r, enum zw_query q, struct zw_result *out)
{
    struct json_value v;
    json_init(&v);
    const char *method = q == ZW_Q_CHAIN ? "getblockchaininfo" : "getnetworkinfo";
    enum zw_err e = zw_rpc_call(r, method, "[]", &v, &out->rpc);
    bool ok = e != ZW_OK || (q == ZW_Q_CHAIN ? parse_chain(&v, &out->chain) : parse_net(&v, &out->net));
    if (!ok) {
        e = ZW_ERR_BAD_REPLY;
        snprintf(out->rpc.message, sizeof(out->rpc.message), "%s", method);
    }
    json_free(&v);
    return e;
}

void zw_result_release(struct zw_result *r)
{
    free(r->bal);
    r->bal = NULL;
}

enum zw_err zw_query_run(struct zw_rpc *r, enum zw_query q, struct zw_result *out)
{
    out->kind = q;
    enum zw_err e;
    switch (q) {
    case ZW_Q_CHAIN:
    case ZW_Q_NET: e = simple_query(r, q, out); break;
    case ZW_Q_BALANCES: e = balances_query(r, out); break;
    case ZW_Q_INFO: e = info_query(r, out); break;
    default: e = wallet_query(r, out); break;
    }
    out->err = e;
    out->port = r->ep.port;
    out->testnet = r->ep.testnet || r->ep.regtest;
    out->cred_src = r->ep.cred_src;
    out->report = r->report;
    snprintf(out->datadir, sizeof(out->datadir), "%s", r->ep.datadir);
    snprintf(out->conf_path, sizeof(out->conf_path), "%s", r->ep.conf_path);
    if (out->profile == ZW_PROFILE_AUTO) out->profile = r->ep.profile;
    return e;
}

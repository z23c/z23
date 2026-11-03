/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "wallet_sweep.h"
#include "base/cleanse.h"
#include "json/json.h"
#include <stdio.h>
#include <string.h>

#define TOKEN_HEX 16

void wsw_init(struct wsw *sweep, const struct wsn_runner *runner, enum zapp_pay_network network)
{
    memset(sweep, 0, sizeof(*sweep));
    wsn_init(&sweep->node, runner, network);
}

/* ---- reading replies ---- */

/* The parsed reply of a command: {"ok":true,"data":{...}} or {"ok":false,"error":{"code":...}}. The node may print
 * warnings before the object. */
struct reply {
    struct json_value root;
    bool parsed, ok;
    const struct json_value *data;
    const char *code;
};
static void reply_read(struct reply *r, const char *text)
{
    memset(r, 0, sizeof(*r));
    const char *json = text[0] == '{' ? text : strstr(text, "\n{");
    if (json && json[0] == '\n') ++json;
    if (!json || !json_read(&r->root, json, strlen(json))) return;
    const struct json_value *ok = json_get(&r->root, "ok");
    if (!ok || ok->type != JSON_BOOL) return;
    r->parsed = true;
    r->ok = json_get_bool(ok);
    r->data = json_get(&r->root, "data");
    const struct json_value *code = json_get(json_get(&r->root, "error"), "code");
    r->code = code && code->type == JSON_STR ? json_get_str(code) : NULL;
}
static void reply_free(struct reply *r)
{
    json_cleanse_strings(&r->root);
    json_free(&r->root);
    memset(r, 0, sizeof(*r));
}
static const char *text_of(const struct json_value *obj, const char *key)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}
static bool int_of(const struct json_value *obj, const char *key, int64_t *out)
{
    const struct json_value *v = json_get(obj, key);
    if (!v || v->type != JSON_INT) return false;
    *out = json_get_int(v);
    return true;
}
static bool flag_of(const struct json_value *obj, const char *key, bool *out)
{
    const struct json_value *v = json_get(obj, key);
    if (!v || v->type != JSON_BOOL) return false;
    *out = json_get_bool(v);
    return true;
}
static bool is_object(const struct json_value *v) { return v && v->type == JSON_OBJ; }
static bool lower_hex(const char *text, size_t length)
{
    size_t n = 0;
    for (; text && text[n]; ++n)
        if (!((text[n] >= '0' && text[n] <= '9') || (text[n] >= 'a' && text[n] <= 'f'))) return false;
    return n == length;
}
static bool address_ok(const char *address, size_t cap)
{
    size_t n = address ? strlen(address) : 0;
    for (size_t i = 0; i < n; ++i) {
        char c = address[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) return false;
    }
    return n > 0 && n < cap;
}

/* ---- requests ---- */

static bool finish_json(struct json_value *doc, bool ok, char *out, size_t cap)
{
    size_t len = ok ? json_write(doc, out, cap) : 0;
    json_cleanse_strings(doc);
    json_free(doc);
    ok = ok && len > 0 && len < cap;
    if (!ok) out[0] = 0;
    return ok;
}
/* The plan: the scope and the key. The node names the source, the destination and the amount. */
static bool plan_json(const struct wsw *w, const struct wss_send_req *req, char *out, size_t cap)
{
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    bool ok = json_push_kv_str(&doc, "wallet_scope", wsn_scope(w->node.network)) &&
              json_push_kv_str(&doc, "idempotency_key", req->key);
    return finish_json(&doc, ok, out, cap);
}
/* The commit: the plan as the node quoted it, with the key and token of the review. It holds no amount. */
static bool commit_json(const struct wsw *w, const struct wss_send_req *req, char *out, size_t cap)
{
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    bool ok = json_push_kv_str(&doc, "wallet_scope", wsn_scope(w->node.network)) && json_push_kv_str(&doc, "from", w->from) &&
              json_push_kv_str(&doc, "to", w->to) && json_push_kv_int(&doc, "input_count", w->inputs) &&
              json_push_kv_int(&doc, "total_zat", (int64_t)w->total_zat) && json_push_kv_int(&doc, "fee_zat", (int64_t)w->fee_zat) &&
              json_push_kv_str(&doc, "idempotency_key", req->key) && json_push_kv_str(&doc, "plan_token", req->plan_token) &&
              json_push_kv_bool(&doc, "confirm", true);
    return finish_json(&doc, ok, out, cap);
}

/* ---- the plan ---- */

struct numbers { int64_t inputs, total, fee, amount, remaining, maturing; };
static bool plan_numbers(const struct json_value *data, struct numbers *n)
{
    bool ok = int_of(data, "input_count", &n->inputs) && int_of(data, "total_zat", &n->total) && int_of(data, "fee_zat", &n->fee) &&
              int_of(data, "amount_zat", &n->amount) && int_of(data, "remaining_inputs", &n->remaining) &&
              int_of(data, "maturing_zat", &n->maturing);
    return ok && n->inputs > 0 && n->amount > 0 && n->fee >= 0 && n->remaining >= 0 && n->maturing >= 0 && n->fee <= n->total &&
           n->total - n->fee == n->amount;
}
/* The plan as the node quotes it. Only the documented shape counts. */
static bool plan_read(struct wsw *w, const struct reply *r, struct ws_plan *out)
{
    struct numbers n;
    if (!r->parsed || !r->ok || !is_object(r->data) || !plan_numbers(r->data, &n)) return false;
    const char *stage = text_of(r->data, "stage"), *from = text_of(r->data, "from"), *to = text_of(r->data, "to");
    const char *token = text_of(r->data, "plan_token");
    if (!stage || strcmp(stage, "plan") || !address_ok(from, sizeof(w->from)) || !address_ok(to, sizeof(w->to)) ||
        !token || strlen(token) != TOKEN_HEX || !lower_hex(token, TOKEN_HEX))
        return false;
    snprintf(w->from, sizeof(w->from), "%s", from);
    snprintf(w->to, sizeof(w->to), "%s", to);
    snprintf(w->token, sizeof(w->token), "%s", token);
    w->inputs = n.inputs;
    w->total_zat = (uint64_t)n.total;
    w->fee_zat = (uint64_t)n.fee;
    *out = (struct ws_plan){.amount_zat = (uint64_t)n.amount, .fee_zat = w->fee_zat, .total_zat = w->total_zat,
                            .remaining_inputs = (uint64_t)n.remaining, .maturing_zat = (uint64_t)n.maturing};
    memcpy(out->token, token, TOKEN_HEX + 1);
    return true;
}

static const struct { const char *code; enum ws_why why; } reasons[] = {
    {"NOTHING_TO_SHIELD", WS_WHY_NOTHING}, {"NO_PRIVATE_ADDRESS", WS_WHY_NO_ADDRESS},
    {"PROVING_UNAVAILABLE", WS_WHY_NO_PROVER}, {"PLAN_TOKEN_MISMATCH", WS_WHY_CHANGED},
};
static enum ws_why why_of(const char *code)
{
    for (size_t i = 0; code && i < sizeof(reasons) / sizeof(reasons[0]); ++i)
        if (!strcmp(code, reasons[i].code)) return reasons[i].why;
    return WS_WHY_NONE;
}

/* core wallet shielded shield without confirm. The reply is read whatever the exit status, because a refusal is a typed
 * error and carries the reason. */
static bool sweep_plan(struct wsw *w, const struct wss_send_req *req, struct ws_plan *out)
{
    char input[WSN_INPUT_MAX], text[WSN_REPLY_MAX];
    struct reply r;
    memset(w->from, 0, sizeof(w->from));
    memset(w->to, 0, sizeof(w->to));
    memset(w->token, 0, sizeof(w->token));
    memset(out, 0, sizeof(*out));
    if (!plan_json(w, req, input, sizeof(input))) return false;
    text[0] = 0;
    bool ran = w->node.runner.run(w->node.runner.ctx, "shieldplan", input, WSN_STEP_TIMEOUT_MS, text, sizeof(text));
    memory_cleanse(input, sizeof(input));
    reply_read(&r, text);
    bool ok = ran && plan_read(w, &r, out);
    if (!ok) {
        memset(w->token, 0, sizeof(w->token));
        memset(out, 0, sizeof(*out));
        out->why = why_of(r.code);
    }
    reply_free(&r);
    memory_cleanse(text, sizeof(text));
    return ok;
}

/* ---- the commit ---- */

/* Whether the node's answer is a committed sweep, with what it reports about it. A replay answers from the node's record
 * of an earlier commit under this key and echoes only the transaction, so the token echo is the one this commit sent. */
static bool commit_answer(const struct reply *r, const char *sent, char echo[WS_TOKEN_MAX], struct wss_commit_info *info)
{
    bool flag = false, replayed = false;
    if (!r->parsed || !r->ok || !is_object(r->data) || !flag_of(r->data, "committed", &flag) || !flag) return false;
    const char *token = text_of(r->data, "plan_token"), *txid = text_of(r->data, "txid");
    (void)flag_of(r->data, "replayed", &replayed);
    if (token && strlen(token) < WS_TOKEN_MAX) snprintf(echo, WS_TOKEN_MAX, "%s", token);
    else if (replayed) snprintf(echo, WS_TOKEN_MAX, "%s", sent);
    else return false;
    info->replayed = replayed;
    if (lower_hex(txid, WS_TXID_MAX - 1)) snprintf(info->txid, sizeof(info->txid), "%s", txid);
    return true;
}
/* The refusals that prove nothing was sent: the node freed the key (or refused before it sent anything). A stale plan
 * needs a new review, so it is reported as the changed fee is. Any other answer is the shared mapping, where an unclear
 * answer is unknown and final. */
static enum wss_commit_outcome commit_outcome(const struct reply *r, bool committed, struct wss_commit_info *info)
{
    enum ws_why why = !committed && r->parsed ? why_of(r->code) : WS_WHY_NONE;
    if (why == WS_WHY_NONE) return wss_commit_outcome_of(r->parsed, committed, r->code);
    info->why = why;
    return why == WS_WHY_CHANGED ? WSS_FEE_CHANGED : WSS_KEY_RELEASED;
}
/* core wallet shielded shield with confirm. A missing or unreadable answer is unknown, and the commit is never repeated. */
static enum wss_commit_outcome sweep_commit(struct wsw *w, const struct wss_send_req *req, char echo[WS_TOKEN_MAX],
                                            struct wss_commit_info *info)
{
    char input[WSN_INPUT_MAX], text[WSN_REPLY_MAX];
    struct reply r;
    echo[0] = 0;
    memset(info, 0, sizeof(*info));
    /* A plan this adapter did not make, or an older one, cannot be committed: no call is made, nothing is sent. */
    if (!w->token[0] || strcmp(w->token, req->plan_token) || req->fee_zat != w->fee_zat ||
        !commit_json(w, req, input, sizeof(input))) {
        info->why = WS_WHY_CHANGED;
        return WSS_FEE_CHANGED;
    }
    text[0] = 0;
    (void)w->node.runner.run(w->node.runner.ctx, "shieldcommit", input, WSN_COMMIT_TIMEOUT_MS, text, sizeof(text));
    memory_cleanse(input, sizeof(input));
    reply_read(&r, text);
    bool committed = commit_answer(&r, req->plan_token, echo, info);
    enum wss_commit_outcome outcome = commit_outcome(&r, committed, info);
    reply_free(&r);
    memory_cleanse(text, sizeof(text));
    return outcome;
}

/* ---- the operations ---- */

static bool plan_op(void *ctx, const struct wss_send_req *req, struct ws_plan *out)
{
    struct wsw *w = ctx;
    return req->sweep ? sweep_plan(w, req, out) : w->send.plan(&w->node, req, out);
}
static enum wss_commit_outcome commit_op(void *ctx, const struct wss_send_req *req, char echo[WS_TOKEN_MAX],
                                         struct wss_commit_info *info)
{
    struct wsw *w = ctx;
    return req->sweep ? sweep_commit(w, req, echo, info) : w->send.commit(&w->node, req, echo, info);
}

void wsw_ops(struct wsw *sweep, struct wss_node_ops *ops)
{
    wsn_ops(&sweep->node, &sweep->send);
    *ops = sweep->send;
    ops->ctx = sweep;
    ops->plan = plan_op;
    ops->commit = commit_op;
}

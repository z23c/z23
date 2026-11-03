/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "wallet_send_node.h"
#include "base/cleanse.h"
#include "json/json.h"
#include "wallet_view.h"
#include <stdio.h>
#include <string.h>

#define FLEET_SCHEMA "zcl.fleet_status.v1"
#define TEXT_NOT_ENCRYPTED "This wallet is not protected by this phone's screen lock yet, so the app does not send from it."
#define TEXT_FLEET_DISAGREES "Your fleet disagrees with this node about the latest block. Sending waits until they agree."
#define TEXT_FLEET_NOT_CHECKED "Your fleet has not been checked yet: this node cannot read which fleet it joined. Sending waits until it can."
#define TEXT_FLEET_UNREADABLE "This node could not read your fleet's status, so sending waits."
#define BROADCAST_SCHEMA "zcl.wallet_broadcast_status.v1"
#define TOKEN_HEX 16

const char *wsn_scope(enum zapp_pay_network network)
{
    return network == ZAPP_PAY_MAINNET ? "prod" : "test";
}

size_t wsn_format_amount(uint64_t zat, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%llu.%08llu", (unsigned long long)(zat / 100000000u), (unsigned long long)(zat % 100000000u));
    return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

void wsn_init(struct wsn *node, const struct wsn_runner *runner, enum zapp_pay_network network)
{
    memset(node, 0, sizeof(*node));
    node->runner = *runner;
    node->network = network;
}

/* ---- reading replies ---- */

/* The parsed reply of a command: {"ok":true,"data":{...}} or {"ok":false,"error":{"code":...}}. The node may print
 * warnings before the object. */
struct reply {
    struct json_value root;
    bool parsed;
    bool ok;
    const struct json_value *data;
    const char *code;
};
static void reply_read(struct reply *r, const char *text)
{
    memset(r, 0, sizeof(*r));
    const char *json = text;
    if (json[0] != '{') {
        json = strstr(text, "\n{");
        if (json) ++json;
    }
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

/* ---- the gate ---- */

struct summary_numbers { uint64_t spendable, public_zat; uint32_t behind; bool encrypted; };
static bool summary_numbers(const char *text, struct summary_numbers *s)
{
    struct reply r;
    int64_t spendable, public_zat, behind;
    reply_read(&r, text);
    bool ok = r.parsed && r.ok && is_object(r.data) && int_of(r.data, "spendable_zat", &spendable) &&
              int_of(r.data, "public_zat", &public_zat) && int_of(r.data, "blocks_behind", &behind) &&
              flag_of(r.data, "encrypted", &s->encrypted) && spendable >= 0 && public_zat >= 0 && behind >= 0 &&
              behind <= UINT32_MAX;
    if (ok) {
        s->spendable = (uint64_t)spendable;
        s->public_zat = (uint64_t)public_zat;
        s->behind = (uint32_t)behind;
    }
    reply_free(&r);
    return ok;
}

enum fleet_verdict { FLEET_UNREADABLE, FLEET_CLEAR, FLEET_DISAGREES, FLEET_NOT_CHECKED };
/* A refusal keeps its cause: the node refuses with verdict disagree when a machine named another block, and with
 * verdict unchecked when it cannot read its recorded fleet root, so nothing was checked. A refusal with any other
 * verdict is not the documented reply and reads as unreadable. */
static enum fleet_verdict refusal_of(const char *verdict)
{
    if (!strcmp(verdict, "disagree")) return FLEET_DISAGREES;
    return strcmp(verdict, "unchecked") ? FLEET_UNREADABLE : FLEET_NOT_CHECKED;
}
/* The fleet answer of the node. Only the documented shape counts; a missing command, an error, a garbled reply and a
 * reply with another schema are unreadable, and an unreadable fleet blocks the send. `checked` is true when the
 * fleet's own verdict is agree; any other clear verdict, not a member included, is shown as not checked. */
static enum fleet_verdict read_fleet(const struct wsn *n, bool *checked)
{
    char text[WSN_REPLY_MAX];
    struct reply r;
    bool member, refuses;
    *checked = false;
    text[0] = 0;
    bool ran = n->runner.run(n->runner.ctx, "fleet", NULL, WSN_STEP_TIMEOUT_MS, text, sizeof(text));
    if (ran) reply_read(&r, text);
    else memset(&r, 0, sizeof(r));
    const char *verdict = r.parsed && r.ok && is_object(r.data) ? text_of(r.data, "verdict") : NULL;
    const char *schema = verdict ? text_of(r.data, "schema") : NULL;
    enum fleet_verdict result = FLEET_UNREADABLE;
    if (schema && !strcmp(schema, FLEET_SCHEMA) && flag_of(r.data, "member", &member) &&
        flag_of(r.data, "refuses_send", &refuses)) {
        result = refuses ? refusal_of(verdict) : FLEET_CLEAR;
        *checked = !refuses && !strcmp(verdict, "agree");
    }
    reply_free(&r);
    memory_cleanse(text, sizeof(text));
    return result;
}

static void block(struct ws_gate *g, const char *why)
{
    g->send_allowed = false;
    snprintf(g->blocked_reason, sizeof(g->blocked_reason), "%s", why);
}

/* core wallet summary and core wallet fleet status. The summary is read by exact shape; its sentence for a blocked
 * wallet is the app's own wording from wallet_view, never the node's. */
static bool read_gate(void *ctx, struct ws_gate *out)
{
    struct wsn *n = ctx;
    char text[WSN_REPLY_MAX];
    struct wallet_view view;
    struct summary_numbers s = {0};
    memset(out, 0, sizeof(*out));
    text[0] = 0;
    bool ran = n->runner.run(n->runner.ctx, "summary", NULL, WSN_STEP_TIMEOUT_MS, text, sizeof(text));
    bool ok = ran && wallet_view_from_summary(text, &view) && summary_numbers(text, &s);
    memory_cleanse(text, sizeof(text));
    if (!ok) return false;
    bool checked;
    enum fleet_verdict fleet = read_fleet(n, &checked);
    out->known = true;
    out->blocks_behind = s.behind;
    out->spendable_zat = s.spendable;
    out->public_zat = s.public_zat;
    out->thermal_paused = n->runner.paused && n->runner.paused(n->runner.ctx);
    out->fleet_checked = checked;
    out->send_allowed = true;
    if (!view.send_allowed) block(out, view.send);
    else if (!s.encrypted) block(out, TEXT_NOT_ENCRYPTED);
    else if (fleet == FLEET_DISAGREES) block(out, TEXT_FLEET_DISAGREES);
    else if (fleet == FLEET_NOT_CHECKED) block(out, TEXT_FLEET_NOT_CHECKED);
    else if (fleet == FLEET_UNREADABLE) block(out, TEXT_FLEET_UNREADABLE);
    return true;
}

/* ---- address ---- */

static bool address_chars(const char *address)
{
    size_t n = strlen(address);
    if (n == 0 || n >= ZAPP_PAY_ADDRESS_MAX) return false;
    for (size_t i = 0; i < n; ++i) {
        char c = address[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) return false;
    }
    return true;
}
/* validateaddress of the node's own RPC. Valid only when the reply says isvalid true; anything else is false. */
static bool validate_address(void *ctx, const char *address, bool *valid)
{
    struct wsn *n = ctx;
    char params[ZAPP_PAY_ADDRESS_MAX + 8], text[WSN_REPLY_MAX];
    struct json_value root = {0};
    *valid = false;
    if (!address_chars(address)) return true;   /* letters and digits only: the text needs no JSON escaping */
    snprintf(params, sizeof(params), "[\"%s\"]", address);
    text[0] = 0;
    bool ran = n->runner.run(n->runner.ctx, "validateaddress", params, WSN_STEP_TIMEOUT_MS, text, sizeof(text));
    bool read = ran && json_read(&root, text, strlen(text));
    const struct json_value *result = read ? json_get(&root, "result") : NULL;
    const struct json_value *error = read ? json_get(&root, "error") : NULL;
    const struct json_value *flag = is_object(result) ? json_get(result, "isvalid") : NULL;
    *valid = flag && flag->type == JSON_BOOL && json_get_bool(flag) && (!error || json_is_null(error));
    json_cleanse_strings(&root);
    json_free(&root);
    memory_cleanse(text, sizeof(text));
    memory_cleanse(params, sizeof(params));
    return ran;
}

/* ---- plan ---- */

static bool hex_text(const uint8_t *bytes, size_t len, char *out, size_t cap)
{
    static const char hex[] = "0123456789abcdef";
    if (cap < 2 * len + 1) return false;
    for (size_t i = 0; i < len; ++i) {
        out[2 * i] = hex[bytes[i] >> 4];
        out[2 * i + 1] = hex[bytes[i] & 15];
    }
    out[2 * len] = 0;
    return true;
}

static bool add_memo(struct json_value *doc, const struct wss_send_req *req)
{
    char memo[2 * ZAPP_PAY_MEMO_MAX + 1];
    bool ok = !req->memo_len || (hex_text(req->memo, req->memo_len, memo, sizeof(memo)) && json_push_kv_str(doc, "memo_hex", memo));
    memory_cleanse(memo, sizeof(memo));
    return ok;
}
static bool add_commit_fields(struct json_value *doc, const struct wss_send_req *req)
{
    return json_push_kv_str(doc, "plan_token", req->plan_token) && json_push_kv_bool(doc, "confirm", true);
}
/* The request of both stages as one object. The sender and the amount text come from the caller, so a commit carries
 * exactly what its plan carried. The memo always goes as hex, never as text. */
static bool request_json(const struct wsn *n, const struct wss_send_req *req, const char *from, const char *amount,
                         bool commit, char *out, size_t cap)
{
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    bool ok = json_push_kv_str(&doc, "wallet_scope", wsn_scope(n->network)) && json_push_kv_str(&doc, "from", from) &&
              json_push_kv_str(&doc, "to", req->address) && json_push_kv_str(&doc, "amount", amount);
    if (ok && commit) ok = req->fee_zat <= INT64_MAX && json_push_kv_int(&doc, "fee_zat", (int64_t)req->fee_zat);
    ok = ok && add_memo(&doc, req) && json_push_kv_str(&doc, "idempotency_key", req->key);
    if (ok && commit) ok = add_commit_fields(&doc, req);
    size_t len = ok ? json_write(&doc, out, cap) : 0;
    json_cleanse_strings(&doc);
    json_free(&doc);
    ok = ok && len > 0 && len < cap;
    if (!ok) out[0] = 0;
    return ok;
}

/* The wallet's latest shielded address, the sender of the plan. */
static bool read_sender(struct wsn *n, char *from, size_t cap)
{
    char text[WSN_REPLY_MAX];
    struct reply r;
    text[0] = 0;
    bool ran = n->runner.run(n->runner.ctx, "latest", NULL, WSN_STEP_TIMEOUT_MS, text, sizeof(text));
    if (ran) reply_read(&r, text);
    else memset(&r, 0, sizeof(r));
    const char *address = r.parsed && r.ok && is_object(r.data) ? text_of(r.data, "address") : NULL;
    bool ok = address && address_chars(address) && strlen(address) < cap;
    if (ok) snprintf(from, cap, "%s", address);
    reply_free(&r);
    memory_cleanse(text, sizeof(text));
    return ok;
}

static bool token_shape(const char *token)
{
    if (!token || strlen(token) != TOKEN_HEX) return false;
    for (size_t i = 0; i < TOKEN_HEX; ++i)
        if (!((token[i] >= '0' && token[i] <= '9') || (token[i] >= 'a' && token[i] <= 'f'))) return false;
    return true;
}
/* The node's echo of the plan must be the request: stage, recipient, amount text and sender. */
static bool plan_echo_ok(const struct json_value *data, const struct wss_send_req *req, const char *from, const char *amount)
{
    const char *stage = text_of(data, "stage"), *to = text_of(data, "to"), *echoed = text_of(data, "amount"), *sender = text_of(data, "from");
    return stage && !strcmp(stage, "plan") && to && !strcmp(to, req->address) && echoed && !strcmp(echoed, amount) && sender &&
           !strcmp(sender, from);
}
static bool plan_numbers(const struct json_value *data, struct ws_plan *out)
{
    int64_t amount_zat, fee, total;
    if (!int_of(data, "amount_zat", &amount_zat) || !int_of(data, "fee_zat", &fee) || !int_of(data, "total_zat", &total) ||
        amount_zat < 0 || fee < 0 || total < 0)
        return false;
    out->amount_zat = (uint64_t)amount_zat;
    out->fee_zat = (uint64_t)fee;
    out->total_zat = (uint64_t)total;
    return true;
}
/* The plan as the node quotes it: the amount, fee and total as integers and the token. */
static bool plan_read(const struct reply *r, const struct wss_send_req *req, const char *from, const char *amount,
                      struct ws_plan *out)
{
    if (!r->parsed || !r->ok || !is_object(r->data) || !plan_echo_ok(r->data, req, from, amount)) return false;
    const char *token = text_of(r->data, "plan_token");
    if (!token_shape(token)) return false;
    memset(out, 0, sizeof(*out));
    if (!plan_numbers(r->data, out)) return false;
    memcpy(out->token, token, TOKEN_HEX + 1);
    return true;
}

/* core wallet shielded send without confirm. The sender is read here and kept for the commit of this plan. */
static bool plan(void *ctx, const struct wss_send_req *req, struct ws_plan *out)
{
    struct wsn *n = ctx;
    char from[ZAPP_PAY_ADDRESS_MAX], amount[32], input[WSN_INPUT_MAX], text[WSN_REPLY_MAX];
    struct reply r;
    memset(n->from, 0, sizeof(n->from));
    memset(n->token, 0, sizeof(n->token));
    memset(n->txid, 0, sizeof(n->txid));
    if (!read_sender(n, from, sizeof(from)) || !wsn_format_amount(req->amount_zat, amount, sizeof(amount)) ||
        !request_json(n, req, from, amount, false, input, sizeof(input)))
        return false;
    text[0] = 0;
    bool ran = n->runner.run(n->runner.ctx, "plan", input, WSN_STEP_TIMEOUT_MS, text, sizeof(text));
    memory_cleanse(input, sizeof(input));
    if (ran) reply_read(&r, text);
    else memset(&r, 0, sizeof(r));
    bool ok = ran && plan_read(&r, req, from, amount, out);
    if (ok) {
        snprintf(n->from, sizeof(n->from), "%s", from);
        snprintf(n->token, sizeof(n->token), "%s", out->token);
    }
    reply_free(&r);
    memory_cleanse(text, sizeof(text));
    memory_cleanse(from, sizeof(from));
    return ok;
}

/* ---- unlock, lock, commit ---- */

/* core wallet security unlock: the request is read from standard input and never put in argv. */
static bool unlock(void *ctx, const char *stdin_json, size_t len, uint32_t seconds)
{
    struct wsn *n = ctx;
    char text[WSN_REPLY_MAX];
    struct reply r;
    (void)len;
    (void)seconds;   /* the request already carries timeout_seconds */
    text[0] = 0;
    bool ran = n->runner.run(n->runner.ctx, "unlock", stdin_json, WSN_STEP_TIMEOUT_MS, text, sizeof(text));
    if (ran) reply_read(&r, text);
    else memset(&r, 0, sizeof(r));
    bool ok = ran && r.parsed && r.ok;
    reply_free(&r);
    memory_cleanse(text, sizeof(text));
    return ok;
}
static bool lock(void *ctx)
{
    struct wsn *n = ctx;
    char text[WSN_REPLY_MAX];
    struct reply r;
    text[0] = 0;
    bool ran = n->runner.run(n->runner.ctx, "lock", NULL, WSN_STEP_TIMEOUT_MS, text, sizeof(text));
    if (ran) reply_read(&r, text);
    else memset(&r, 0, sizeof(r));
    bool ok = ran && r.parsed && r.ok;
    reply_free(&r);
    memory_cleanse(text, sizeof(text));
    return ok;
}

static bool is_txid(const char *text)
{
    size_t n = 0;
    for (; text && text[n]; ++n)
        if (!((text[n] >= '0' && text[n] <= '9') || (text[n] >= 'a' && text[n] <= 'f'))) return false;
    return n == WS_TXID_MAX - 1;
}
/* Whether the node's answer is a committed payment under the plan this adapter made, with what it reports about it. A
 * replay is the node answering from its record of an earlier commit under this key: nothing was built. */
static bool commit_answer(const struct reply *r, char token_echo[WS_TOKEN_MAX], struct wss_commit_info *info)
{
    bool flag = false, replayed = false;
    if (!r->parsed || !r->ok || !is_object(r->data)) return false;
    const char *echo = text_of(r->data, "plan_token");
    const char *txid = text_of(r->data, "txid");
    if (!flag_of(r->data, "committed", &flag) || !flag || !echo || strlen(echo) >= WS_TOKEN_MAX) return false;
    snprintf(token_echo, WS_TOKEN_MAX, "%s", echo);
    if (flag_of(r->data, "replayed", &replayed)) info->replayed = replayed;
    if (is_txid(txid)) snprintf(info->txid, sizeof(info->txid), "%s", txid);
    return true;
}
/* core wallet shielded send with confirm. The reply is read whatever the exit status, because a process that was
 * killed after the node answered still carried the answer. A missing or unreadable reply is unknown, and the commit
 * is never repeated. The node's message is never read. */
static enum wss_commit_outcome commit(void *ctx, const struct wss_send_req *req, char token_echo[WS_TOKEN_MAX],
                                      struct wss_commit_info *info)
{
    struct wsn *n = ctx;
    char amount[32], input[WSN_INPUT_MAX], text[WSN_REPLY_MAX];
    struct reply r;
    token_echo[0] = 0;
    memset(info, 0, sizeof(*info));
    /* A plan this adapter did not make, or an older one, cannot be committed: no call is made, nothing is sent. */
    if (!n->from[0] || strcmp(n->token, req->plan_token) || !wsn_format_amount(req->amount_zat, amount, sizeof(amount)) ||
        !request_json(n, req, n->from, amount, true, input, sizeof(input)))
        return WSS_FEE_CHANGED;
    text[0] = 0;
    (void)n->runner.run(n->runner.ctx, "commit", input, WSN_COMMIT_TIMEOUT_MS, text, sizeof(text));
    memory_cleanse(input, sizeof(input));
    reply_read(&r, text);
    bool committed = commit_answer(&r, token_echo, info);
    if (committed) snprintf(n->txid, sizeof(n->txid), "%s", info->txid);
    enum wss_commit_outcome outcome = wss_commit_outcome_of(r.parsed, committed, r.code);
    reply_free(&r);
    memory_cleanse(text, sizeof(text));
    return outcome;
}

/* Whether the payment is still pending in the broadcast list: its transaction is listed in a state other than sent or
 * seen. With no transaction id, any listed send counts. */
static bool still_pending(const struct json_value *list, const char *txid)
{
    if (!txid[0]) return json_size(list) > 0;
    for (size_t i = 0; i < json_size(list); ++i) {
        const struct json_value *item = json_at(list, i);
        const char *listed = text_of(item, "txid"), *state = text_of(item, "state");
        if (listed && !strcmp(listed, txid)) return !state || (strcmp(state, "sent") && strcmp(state, "seen"));
    }
    return false;
}
/* core wallet broadcast status. A payment counts as sent when its transaction is listed as sent or seen, or is not
 * listed at all: a public send and a transaction already relayed are not pending. waiting_for_route, scheduled and
 * any other state keep waiting, as does a failed or unreadable read; the machine asks again. When the commit reported
 * no transaction id, only an empty list proves the payment is not pending. */
static bool route(void *ctx, enum ws_route *out)
{
    struct wsn *n = ctx;
    char text[WSN_REPLY_MAX];
    struct reply r;
    *out = WS_ROUTE_WAITING;
    text[0] = 0;
    bool ran = n->runner.run(n->runner.ctx, "broadcast", NULL, WSN_STEP_TIMEOUT_MS, text, sizeof(text));
    if (ran) reply_read(&r, text);
    else memset(&r, 0, sizeof(r));
    const char *schema = r.parsed && r.ok && is_object(r.data) ? text_of(r.data, "schema") : NULL;
    const struct json_value *list = schema && !strcmp(schema, BROADCAST_SCHEMA) ? json_get(r.data, "transactions") : NULL;
    bool read = list && list->type == JSON_ARR;
    if (read) *out = still_pending(list, n->txid) ? WS_ROUTE_WAITING : WS_ROUTE_SENT;
    reply_free(&r);
    memory_cleanse(text, sizeof(text));
    return read;
}

void wsn_ops(struct wsn *node, struct wss_node_ops *ops)
{
    *ops = (struct wss_node_ops){node, validate_address, read_gate, plan, unlock, lock, commit, route};
}

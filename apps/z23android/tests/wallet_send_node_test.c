/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "wallet_send_node.h"
#include "controllers/wallet_send_once.h"
#include "json/json.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FROM "zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
#define TO "zs1ppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp"
#define TOKEN "0123456789abcdef"
#define NODE_SENTENCE "NODE-ONLY-SENTENCE wallet.dat is not ready"

/* A runner that answers each op from a script and records what it was asked. */
struct reply { bool ran; char text[WSN_REPLY_MAX]; };
struct fake {
    struct reply summary, fleet, latest, broadcast, plan, commit, unlock, lock, validate;
    char calls[256];                 /* one letter per op, in order */
    char plan_input[WSN_INPUT_MAX], commit_input[WSN_INPUT_MAX], unlock_input[WSN_INPUT_MAX], validate_input[256];
    unsigned commit_timeout, step_timeout_max;
    int commits, plans;
    bool paused;
    bool is_plan_stage_ok;           /* the plan reply is well-formed */
};
static void say(struct reply *r, bool ran, const char *text) { r->ran = ran; snprintf(r->text, sizeof(r->text), "%s", text); }

static void summary_json(char *out, size_t cap, bool allowed, const char *reason, bool encrypted, unsigned behind, unsigned long long spendable)
{
    snprintf(out, cap,
             "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\",\"spendable_zat\":%llu,\"spendable\":\"%llu.%08llu\","
             "\"pending_zat\":0,\"pending\":\"0.00000000\",\"pending_notes\":0,\"pending_min_confirmations_needed\":0,"
             "\"sending_zat\":0,\"sending\":\"0.00000000\",\"public_zat\":100000000,\"public\":\"1.00000000\",\"immature_zat\":0,"
             "\"immature\":\"0.00000000\",\"tip_height\":3000000,\"header_height\":3000000,\"scanned_through_height\":3000000,"
             "\"blocks_behind\":%u,\"current\":true,\"locked\":true,\"encrypted\":%s,\"shielded_keys\":1,"
             "\"send_allowed\":%s,\"send_blocked_reason\":\"%s\"}}",
             spendable, spendable / 100000000ull, spendable % 100000000ull, behind, encrypted ? "true" : "false",
             allowed ? "true" : "false", reason);
}
static void fleet_json(char *out, size_t cap, const char *verdict, bool member, bool refuses)
{
    snprintf(out, cap,
             "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet_status.v1\",\"member\":%s,\"verdict\":\"%s\",\"refuses_send\":%s,"
             "\"machines_total\":0,\"machines_connected\":0,\"local_tip\":3000000,\"machines\":[]}}",
             member ? "true" : "false", verdict, refuses ? "true" : "false");
}
static void plan_json(char *out, size_t cap, const char *to, unsigned long long amount, unsigned long long fee, const char *amount_text)
{
    snprintf(out, cap,
             "{\"ok\":true,\"data\":{\"stage\":\"plan\",\"action\":\"shielded-send\",\"committed\":false,\"plan_token\":\"" TOKEN "\","
             "\"wallet_scope\":\"prod\",\"from\":\"" FROM "\",\"to\":\"%s\",\"amount\":\"%s\",\"amount_zat\":%llu,"
             "\"fee_zat\":%llu,\"total_zat\":%llu,\"total\":\"x\",\"commit_input\":\"{}\"}}",
             to, amount_text, amount, fee, amount + fee);
}
static void committed_json(char *out, size_t cap, bool replayed)
{
    snprintf(out, cap,
             "{\"ok\":true,\"data\":{\"stage\":\"committed\",\"committed\":true,\"replayed\":%s,\"txid\":\"%064d\","
             "\"plan_token\":\"" TOKEN "\"}}",
             replayed ? "true" : "false", 7);
}
#define COMMIT_TXID "0000000000000000000000000000000000000000000000000000000000000007"
#define OTHER_TXID "0000000000000000000000000000000000000000000000000000000000000009"
/* The reply of core wallet broadcast status; entries is the inside of the transactions array, NULL for none. */
static void broadcast_json(char *out, size_t cap, const char *entries)
{
    snprintf(out, cap,
             "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_broadcast_status.v1\",\"mode\":\"private\",\"pending\":0,\"expired\":0,"
             "\"eligible_onion_peers\":0,\"transactions\":[%s]}}",
             entries ? entries : "");
}
static void broadcast_entry(char *out, size_t cap, const char *txid, const char *state)
{
    snprintf(out, cap, "{\"txid\":\"%s\",\"state\":\"%s\",\"next_step\":\"x\",\"attempts\":1,\"seconds_since_last_attempt\":2}", txid, state);
}
static void error_json(char *out, size_t cap, const char *code, const char *message)
{
    snprintf(out, cap, "{\"ok\":false,\"error\":{\"code\":\"%s\",\"error_code\":\"%s\",\"message\":\"%s\"}}", code, code, message);
}
static void fake_init(struct fake *f)
{
    memset(f, 0, sizeof(*f));
    summary_json(f->summary.text, sizeof(f->summary.text), true, "", true, 0, 500000000ull);
    f->summary.ran = true;
    fleet_json(f->fleet.text, sizeof(f->fleet.text), "not_member", false, false);
    f->fleet.ran = true;
    say(&f->latest, true, "{\"ok\":true,\"data\":{\"address\":\"" FROM "\"}}");
    broadcast_json(f->broadcast.text, sizeof(f->broadcast.text), NULL);
    f->broadcast.ran = true;
    plan_json(f->plan.text, sizeof(f->plan.text), TO, 125000000ull, 10000ull, "1.25000000");
    f->plan.ran = true;
    committed_json(f->commit.text, sizeof(f->commit.text), false);
    f->commit.ran = true;
    say(&f->unlock, true, "{\"ok\":true,\"data\":{\"unlocked\":true}}");
    say(&f->lock, true, "{\"ok\":true,\"data\":{\"locked\":true}}");
    say(&f->validate, true, "{\"result\":{\"isvalid\":true,\"type\":\"sapling\"},\"error\":null,\"id\":1}");
}
static bool run(void *ctx, const char *op, const char *input, unsigned timeout_ms, char *out, size_t cap)
{
    struct fake *f = ctx;
    struct reply *r = NULL;
    char letter = '?';
    if (!strcmp(op, "summary")) { r = &f->summary; letter = 's'; }
    else if (!strcmp(op, "fleet")) { r = &f->fleet; letter = 'f'; }
    else if (!strcmp(op, "latest")) { r = &f->latest; letter = 'a'; }
    else if (!strcmp(op, "broadcast")) { r = &f->broadcast; letter = 'b'; assert(!input); }
    else if (!strcmp(op, "validateaddress")) { r = &f->validate; letter = 'v'; snprintf(f->validate_input, sizeof(f->validate_input), "%s", input); }
    else if (!strcmp(op, "plan")) { r = &f->plan; letter = 'p'; f->plans++; snprintf(f->plan_input, sizeof(f->plan_input), "%s", input); }
    else if (!strcmp(op, "unlock")) { r = &f->unlock; letter = 'u'; snprintf(f->unlock_input, sizeof(f->unlock_input), "%s", input); }
    else if (!strcmp(op, "lock")) { r = &f->lock; letter = 'l'; assert(!input); }
    else if (!strcmp(op, "commit")) {
        r = &f->commit; letter = 'c'; f->commits++; f->commit_timeout = timeout_ms;
        snprintf(f->commit_input, sizeof(f->commit_input), "%s", input);
    } else assert(!"an op the adapter has no right to ask for");
    if (strcmp(op, "commit") && timeout_ms > f->step_timeout_max) f->step_timeout_max = timeout_ms;
    assert(strlen(f->calls) + 2 < sizeof(f->calls));
    f->calls[strlen(f->calls)] = letter;
    snprintf(out, cap, "%s", r->text);
    return r->ran;
}
static bool paused(void *ctx) { return ((struct fake *)ctx)->paused; }
static void adapter(struct fake *f, struct wsn *n, struct wss_node_ops *ops)
{
    wsn_init(n, &(struct wsn_runner){f, run, paused}, ZAPP_PAY_MAINNET);
    wsn_ops(n, ops);
}

static struct zapp_payment pay_of(const char *tail)
{
    char text[512];
    struct zapp_payment p;
    snprintf(text, sizeof(text), "zclassic:%s%s", TO, tail);
    assert(zapp_payment_parse(text, strlen(text), ZAPP_PAY_MAINNET, &p) == ZAPP_PAY_OK);
    return p;
}
static void request_of(struct wss_send_req *r, uint64_t amount, const struct zapp_payment *p)
{
    memset(r, 0, sizeof(*r));
    snprintf(r->address, sizeof(r->address), "%s", p->address);
    r->amount_zat = amount;
    memcpy(r->memo, p->memo, p->memo_len);
    r->memo_len = p->memo_len;
    snprintf(r->key, sizeof(r->key), "0123456789abcdef0123456789abcdef");
}

/* ---- amounts and scope ---- */

static void amounts_and_scope(void)
{
    char out[32];
    assert(wsn_format_amount(125000000ull, out, sizeof(out)) && !strcmp(out, "1.25000000"));
    assert(wsn_format_amount(0, out, sizeof(out)) && !strcmp(out, "0.00000000"));
    assert(wsn_format_amount(1, out, sizeof(out)) && !strcmp(out, "0.00000001"));
    assert(wsn_format_amount(2100000000000000ull, out, sizeof(out)) && !strcmp(out, "21000000.00000000"));
    assert(wsn_format_amount(125000000ull, out, 10) == 0);
    /* The node accepts only dev, prod and test (wallet_money_scope_valid): mainnet is prod, a test network is test. */
    assert(!strcmp(wsn_scope(ZAPP_PAY_MAINNET), "prod"));
    assert(!strcmp(wsn_scope(ZAPP_PAY_TESTNET), "test") && !strcmp(wsn_scope(ZAPP_PAY_REGTEST), "test"));
}

/* ---- plan and commit carry one request ---- */

static const struct json_value *field(const struct json_value *root, const char *key, int type)
{
    const struct json_value *v = json_get(root, key);
    assert(v && (int)v->type == type);
    return v;
}
/* Plan then commit of 1.25 ZCL: the sender, recipient, amount text, memo and key are the same bytes in both, the commit adds the
 * fee, the token and confirm, and no amount is written as 1.25 or 1.250000, which would not match the token the node bound. */
static void plan_then_commit_is_one_request(void)
{
    struct fake f; struct wsn n; struct wss_node_ops ops;
    fake_init(&f);
    adapter(&f, &n, &ops);
    struct zapp_payment p = pay_of("?amount=1.25&memo=aGk");
    struct wss_send_req req; struct ws_plan plan = {0};
    request_of(&req, 125000000ull, &p);
    assert(ops.plan(ops.ctx, &req, &plan));
    assert(plan.amount_zat == 125000000ull && plan.fee_zat == 10000 && plan.total_zat == 125010000ull && !strcmp(plan.token, TOKEN));
    assert(!strcmp(f.calls, "ap"));
    req.fee_zat = plan.fee_zat;
    snprintf(req.plan_token, sizeof(req.plan_token), "%s", plan.token);
    char echo[WS_TOKEN_MAX];
    struct wss_commit_info info;
    assert(ops.commit(ops.ctx, &req, echo, &info) == WSS_COMMITTED && !strcmp(echo, TOKEN));
    assert(!info.replayed && strlen(info.txid) == WS_TXID_MAX - 1);
    assert(!strcmp(f.calls, "apc") && f.commits == 1);

    struct json_value a = {0}, c = {0};
    assert(json_read(&a, f.plan_input, strlen(f.plan_input)) && json_read(&c, f.commit_input, strlen(f.commit_input)));
    static const char *const same[] = {"wallet_scope", "from", "to", "amount", "memo_hex", "idempotency_key"};
    for (size_t i = 0; i < sizeof(same) / sizeof(same[0]); ++i)
        assert(!strcmp(json_get_str(field(&a, same[i], JSON_STR)), json_get_str(field(&c, same[i], JSON_STR))));
    assert(!strcmp(json_get_str(json_get(&c, "amount")), "1.25000000"));
    assert(!strcmp(json_get_str(json_get(&c, "from")), FROM) && !strcmp(json_get_str(json_get(&c, "to")), TO));
    assert(!strcmp(json_get_str(json_get(&c, "wallet_scope")), "prod"));
    assert(!strcmp(json_get_str(json_get(&c, "memo_hex")), "6869") && !json_get(&a, "memo") && !json_get(&c, "memo"));
    assert(!strcmp(json_get_str(json_get(&c, "idempotency_key")), req.key));
    assert(json_get_int(field(&c, "fee_zat", JSON_INT)) == 10000 && !strcmp(json_get_str(json_get(&c, "plan_token")), TOKEN));
    assert(json_get_bool(field(&c, "confirm", JSON_BOOL)));
    assert(!json_get(&a, "confirm") && !json_get(&a, "fee_zat") && !json_get(&a, "plan_token"));
    json_free(&a); json_free(&c);
}

/* A commit asks for the sender its own plan used, not whatever the wallet reports now. */
static void commit_keeps_the_sender_of_its_plan(void)
{
    struct fake f; struct wsn n; struct wss_node_ops ops;
    fake_init(&f);
    adapter(&f, &n, &ops);
    struct zapp_payment p = pay_of("");
    struct wss_send_req req; struct ws_plan plan = {0};
    request_of(&req, 125000000ull, &p);
    assert(ops.plan(ops.ctx, &req, &plan));
    say(&f.latest, true, "{\"ok\":true,\"data\":{\"address\":\"zs1anotheraddressxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}}");
    req.fee_zat = plan.fee_zat;
    snprintf(req.plan_token, sizeof(req.plan_token), "%s", plan.token);
    char echo[WS_TOKEN_MAX];
    struct wss_commit_info info;
    assert(ops.commit(ops.ctx, &req, echo, &info) == WSS_COMMITTED);
    struct json_value c = {0};
    assert(json_read(&c, f.commit_input, strlen(f.commit_input)));
    assert(!strcmp(json_get_str(json_get(&c, "from")), FROM));
    json_free(&c);
    assert(strchr(f.calls, 'a') == strrchr(f.calls, 'a'));   /* the sender was read once, at the plan */
    /* A token this adapter did not plan: no node call at all, and nothing was sent. */
    snprintf(req.plan_token, sizeof(req.plan_token), "fedcba9876543210");
    f.commits = 0;
    assert(ops.commit(ops.ctx, &req, echo, &info) == WSS_FEE_CHANGED && f.commits == 0);
}

static void plan_replies_are_read_by_shape(void)
{
    struct fake f; struct wsn n; struct wss_node_ops ops;
    struct zapp_payment p = pay_of("");
    struct wss_send_req req; struct ws_plan plan;
    request_of(&req, 125000000ull, &p);
    char text[WSN_REPLY_MAX];
    struct { const char *to, *amount; const char *replace_from, *replace_to; bool ran; } bad[] = {
        {TO, "1.25", NULL, NULL, true},                                /* another amount text than was asked */
        {"zs1yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", "1.25000000", NULL, NULL, true},
        {TO, "1.25000000", TOKEN, "short", true},                      /* a token that is not 16 hex characters */
        {TO, "1.25000000", "\"stage\":\"plan\"", "\"stage\":\"done\"", true},
        {TO, "1.25000000", "\"fee_zat\":10000", "\"fee_zat\":\"10000\"", true},
        {TO, "1.25000000", NULL, NULL, false},                         /* the command failed */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        fake_init(&f);
        adapter(&f, &n, &ops);
        plan_json(text, sizeof(text), bad[i].to, 125000000ull, 10000ull, bad[i].amount);
        if (bad[i].replace_from) {
            char *at = strstr(text, bad[i].replace_from);
            char tail[WSN_REPLY_MAX];
            assert(at);
            snprintf(tail, sizeof(tail), "%s", at + strlen(bad[i].replace_from));
            snprintf(at, sizeof(text) - (size_t)(at - text), "%s%s", bad[i].replace_to, tail);
        }
        say(&f.plan, bad[i].ran, text);
        assert(!ops.plan(ops.ctx, &req, &plan));
    }
    fake_init(&f); adapter(&f, &n, &ops);
    say(&f.latest, true, "{\"ok\":true,\"data\":{\"address\":null}}");   /* no address yet: no plan is asked for */
    assert(!ops.plan(ops.ctx, &req, &plan) && f.plans == 0);
    say(&f.latest, false, "{\"ok\":false,\"error\":{\"code\":\"X\"}}");
    assert(!ops.plan(ops.ctx, &req, &plan) && f.plans == 0);
}

/* ---- the commit reply ---- */

static struct wss_commit_info last_info;   /* what the latest commit_with reported */
static enum wss_commit_outcome commit_with(const char *reply, bool ran, int *commits, unsigned *timeout)
{
    struct fake f; struct wsn n; struct wss_node_ops ops;
    struct zapp_payment p = pay_of("");
    struct wss_send_req req; struct ws_plan plan = {0};
    char echo[WS_TOKEN_MAX];
    struct wss_commit_info info;
    fake_init(&f);
    adapter(&f, &n, &ops);
    request_of(&req, 125000000ull, &p);
    assert(ops.plan(ops.ctx, &req, &plan));
    req.fee_zat = plan.fee_zat;
    snprintf(req.plan_token, sizeof(req.plan_token), "%s", plan.token);
    say(&f.commit, ran, reply);
    enum wss_commit_outcome out = ops.commit(ops.ctx, &req, echo, &info);
    last_info = info;
    if (commits) *commits = f.commits;
    if (timeout) *timeout = f.commit_timeout;
    return out;
}
static enum wss_commit_outcome commit_code(const char *code)
{
    char text[WSN_REPLY_MAX];
    /* The node's sentence says "nothing was sent" for several codes; it is never read. */
    error_json(text, sizeof(text), code, "nothing was sent and the idempotency_key is free to retry");
    return commit_with(text, false, NULL, NULL);
}
static void commit_codes_are_pinned(void)
{
    char text[WSN_REPLY_MAX];
    /* The released code is the node's own constant. */
    assert(!strcmp(WALLET_SEND_ONCE_CODE_RELEASED, "SEND_REFUSED_KEY_RELEASED"));
    assert(commit_code(WALLET_SEND_ONCE_CODE_RELEASED) == WSS_KEY_RELEASED);
    assert(commit_code("FEE_CHANGED") == WSS_FEE_CHANGED);
    static const char *const unknown[] = {"WALLET_RPC_ERROR", "SEND_IN_PROGRESS", "SEND_OUTCOME_UNKNOWN", "IDEMPOTENCY_KEY_REUSED",
        "PLAN_REQUIRED", "PLAN_TOKEN_MISMATCH", "MISSING_IDEMPOTENCY_KEY", "INVALID_IDEMPOTENCY_KEY", "SHIELDED_SEND_FAILED",
        "INVALID_AMOUNT", "NODE_UNAVAILABLE", "", "send_refused_key_released"};
    for (size_t i = 0; i < sizeof(unknown) / sizeof(unknown[0]); ++i) assert(commit_code(unknown[i]) == WSS_UNKNOWN);
    committed_json(text, sizeof(text), false);
    assert(commit_with(text, true, NULL, NULL) == WSS_COMMITTED);
    committed_json(text, sizeof(text), true);   /* a replay of an earlier commit of the same key is a commit */
    assert(commit_with(text, true, NULL, NULL) == WSS_COMMITTED);
    /* A node that answered after the process was killed still answered. */
    assert(commit_with(text, false, NULL, NULL) == WSS_COMMITTED);
}
/* A replay is the node answering from its record of an earlier commit under the same key; the transaction it names is the
 * earlier one. A reply that does not say, or names something that is not a transaction id, reports neither. */
static void a_replay_is_reported_with_its_transaction(void)
{
    char text[WSN_REPLY_MAX], expected[WS_TXID_MAX];
    snprintf(expected, sizeof(expected), "%064d", 7);
    committed_json(text, sizeof(text), true);
    assert(commit_with(text, true, NULL, NULL) == WSS_COMMITTED);
    assert(last_info.replayed && !strcmp(last_info.txid, expected));
    committed_json(text, sizeof(text), false);
    assert(commit_with(text, true, NULL, NULL) == WSS_COMMITTED);
    assert(!last_info.replayed && !strcmp(last_info.txid, expected));
    const char *plain = "{\"ok\":true,\"data\":{\"committed\":true,\"plan_token\":\"" TOKEN "\"}}";
    assert(commit_with(plain, true, NULL, NULL) == WSS_COMMITTED);
    assert(!last_info.replayed && !last_info.txid[0]);
    const char *odd = "{\"ok\":true,\"data\":{\"committed\":true,\"replayed\":\"yes\",\"txid\":\"nothex\",\"plan_token\":\"" TOKEN "\"}}";
    assert(commit_with(odd, true, NULL, NULL) == WSS_COMMITTED);
    assert(!last_info.replayed && !last_info.txid[0]);
}
static void commit_without_a_usable_answer_is_unknown(void)
{
    char text[WSN_REPLY_MAX];
    assert(commit_with("", false, NULL, NULL) == WSS_UNKNOWN);
    assert(commit_with("\nThe command timed out.", false, NULL, NULL) == WSS_UNKNOWN);
    assert(commit_with("not json at all", true, NULL, NULL) == WSS_UNKNOWN);
    assert(commit_with("{\"ok\":true}", true, NULL, NULL) == WSS_UNKNOWN);
    assert(commit_with("{\"ok\":true,\"data\":{\"committed\":false,\"plan_token\":\"" TOKEN "\"}}", true, NULL, NULL) == WSS_UNKNOWN);
    assert(commit_with("{\"ok\":true,\"data\":{\"committed\":true}}", true, NULL, NULL) == WSS_UNKNOWN);   /* no token echo */
    assert(commit_with("{\"ok\":false}", true, NULL, NULL) == WSS_UNKNOWN);
    error_json(text, sizeof(text), "FEE_CHANGED", "m");
    memmove(text + 9, text, strlen(text) + 1);   /* a warning line before the reply */
    memcpy(text, "warning:\n", 9);
    assert(commit_with(text, false, NULL, NULL) == WSS_FEE_CHANGED);
}
static void commit_is_asked_once_and_given_time(void)
{
    int commits = 0;
    unsigned timeout = 0;
    char text[WSN_REPLY_MAX];
    error_json(text, sizeof(text), "WALLET_RPC_ERROR", "m");
    assert(commit_with(text, false, &commits, &timeout) == WSS_UNKNOWN);
    assert(commits == 1);   /* an unknown answer is never retried */
    /* A phone builds the proof in about 100 seconds; the CLI's 15 second limit must never apply to a commit. */
    assert(timeout >= 300000u && timeout == WSN_COMMIT_TIMEOUT_MS);
}

/* ---- the gate ---- */

static struct ws_gate gate_of(struct fake *f, bool *ok)
{
    struct wsn n; struct wss_node_ops ops;
    struct ws_gate g;
    memset(&g, 0x5a, sizeof(g));
    adapter(f, &n, &ops);
    *ok = ops.read_gate(ops.ctx, &g);
    return g;
}
static void gate_reads_numbers_and_never_shows_node_text(void)
{
    struct fake f; bool ok;
    fake_init(&f);
    f.paused = true;
    summary_json(f.summary.text, sizeof(f.summary.text), true, "", true, 3, 500000000ull);
    struct ws_gate g = gate_of(&f, &ok);
    assert(ok && g.known && g.send_allowed && g.blocks_behind == 3 && g.spendable_zat == 500000000ull && g.public_zat == 100000000ull);
    assert(g.thermal_paused && !g.blocked_reason[0]);
    fake_init(&f);
    summary_json(f.summary.text, sizeof(f.summary.text), false, NODE_SENTENCE, true, 0, 500000000ull);
    g = gate_of(&f, &ok);
    assert(ok && !g.send_allowed && g.blocked_reason[0] && !strstr(g.blocked_reason, "NODE-ONLY") && !strstr(g.blocked_reason, "wallet.dat"));
    assert(!strcmp(g.blocked_reason, "Sending is paused for a reason this app does not recognize."));
    fake_init(&f);
    summary_json(f.summary.text, sizeof(f.summary.text), false, "progress_store_unavailable", true, 0, 500000000ull);
    g = gate_of(&f, &ok);
    assert(!g.send_allowed && strstr(g.blocked_reason, "save its progress") && !strstr(g.blocked_reason, "progress_store_unavailable"));
}
static void an_unencrypted_wallet_never_sends(void)
{
    struct fake f; bool ok;
    fake_init(&f);
    summary_json(f.summary.text, sizeof(f.summary.text), true, "", false, 0, 500000000ull);
    struct ws_gate g = gate_of(&f, &ok);
    assert(ok && g.known && !g.send_allowed && strstr(g.blocked_reason, "screen lock"));
}
static void a_summary_that_is_not_the_documented_one_is_unknown(void)
{
    struct fake f; bool ok;
    fake_init(&f);
    say(&f.summary, false, "{\"ok\":false,\"error\":{\"code\":\"NODE_UNAVAILABLE\"}}");
    (void)gate_of(&f, &ok);
    assert(!ok);
    fake_init(&f);
    say(&f.summary, true, "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\"}}");
    (void)gate_of(&f, &ok);
    assert(!ok);
    fake_init(&f);
    say(&f.summary, true, "garbage");
    (void)gate_of(&f, &ok);
    assert(!ok);
}
static void the_fleet_decides_by_its_own_field(void)
{
    struct fake f; bool ok;
    struct ws_gate g;
    /* Not a member: sending is allowed, and the review says it was not checked. */
    fake_init(&f);
    g = gate_of(&f, &ok);
    assert(ok && g.send_allowed && !g.fleet_checked);
    fake_init(&f);
    fleet_json(f.fleet.text, sizeof(f.fleet.text), "agree", true, false);
    g = gate_of(&f, &ok);
    assert(ok && g.send_allowed && g.fleet_checked);
    fake_init(&f);
    fleet_json(f.fleet.text, sizeof(f.fleet.text), "none_connected", true, false);
    g = gate_of(&f, &ok);
    assert(ok && g.send_allowed && !g.fleet_checked);
    /* A missing command, an error, and every garbled reply block. */
    static const char *const garbled[] = {
        "", "garbage", "{\"ok\":true}", "{\"ok\":true,\"data\":{}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet_status.v1\",\"member\":false,\"verdict\":\"not_member\"}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet_status.v1\",\"member\":false,\"verdict\":\"not_member\",\"refuses_send\":\"false\"}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet_status.v1\",\"member\":false,\"verdict\":\"not_member\",\"refuses_send\":null}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet_status.v1\",\"member\":false,\"verdict\":\"not_member\",\"refuses_send\":0}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.other.v1\",\"member\":false,\"verdict\":\"not_member\",\"refuses_send\":false}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet_status.v1\",\"verdict\":\"not_member\",\"refuses_send\":false}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet_status.v1\",\"member\":false,\"refuses_send\":false}}",
        "{\"ok\":false,\"error\":{\"code\":\"UNKNOWN_COMMAND\"}}",
    };
    for (size_t i = 0; i < sizeof(garbled) / sizeof(garbled[0]); ++i) {
        for (int ran = 0; ran < 2; ++ran) {
            fake_init(&f);
            say(&f.fleet, ran, garbled[i]);
            g = gate_of(&f, &ok);
            assert(ok && g.known && !g.send_allowed && strstr(g.blocked_reason, "fleet"));
        }
    }
}
/* The gate of a member whose node reports refuses_send true with `verdict`: the send is blocked whatever the verdict. */
static struct ws_gate refused_with(const char *verdict)
{
    struct fake f; bool ok;
    fake_init(&f);
    fleet_json(f.fleet.text, sizeof(f.fleet.text), verdict, true, true);
    struct ws_gate g = gate_of(&f, &ok);
    assert(ok && !g.send_allowed && !g.fleet_checked);
    return g;
}
/* The reason follows the verdict. A node that cannot read its recorded fleet root refuses with verdict unchecked:
 * nothing was compared, so the reason says the fleet has not been checked and never that it disagrees. */
static void a_refusal_says_why(void)
{
    struct ws_gate g = refused_with("disagree");
    assert(strstr(g.blocked_reason, "fleet disagrees"));
    g = refused_with("unchecked");
    assert(strstr(g.blocked_reason, "has not been checked yet") && !strstr(g.blocked_reason, "disagree"));
    g = refused_with("agree");
    assert(strstr(g.blocked_reason, "could not read") && !strstr(g.blocked_reason, "disagree"));
}

/* ---- the address ---- */

static void validate_accepts_only_a_valid_reply(void)
{
    struct fake f; struct wsn n; struct wss_node_ops ops;
    bool valid = true;
    fake_init(&f);
    adapter(&f, &n, &ops);
    assert(ops.validate_address(ops.ctx, TO, &valid) && valid);
    assert(!strcmp(f.validate_input, "[\"" TO "\"]"));
    static const char *const refused[] = {
        "{\"result\":{\"isvalid\":false},\"error\":null,\"id\":1}",
        "{\"result\":{},\"error\":null,\"id\":1}",
        "{\"result\":{\"isvalid\":\"true\"},\"error\":null,\"id\":1}",
        "{\"result\":{\"isvalid\":true},\"error\":{\"code\":-1},\"id\":1}",
        "{\"error\":{\"code\":-1,\"message\":\"x\"},\"id\":1}",
        "garbage", "",
    };
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); ++i) {
        fake_init(&f);
        adapter(&f, &n, &ops);
        say(&f.validate, true, refused[i]);
        valid = true;
        (void)ops.validate_address(ops.ctx, TO, &valid);
        assert(!valid);
    }
    fake_init(&f);
    adapter(&f, &n, &ops);
    say(&f.validate, false, "The node did not answer.");
    valid = true;
    assert(!ops.validate_address(ops.ctx, TO, &valid) && !valid);
    /* An address with a character outside letters and digits never reaches the node. */
    fake_init(&f);
    adapter(&f, &n, &ops);
    valid = true;
    assert(ops.validate_address(ops.ctx, "zs1\"],\"x", &valid) && !valid && !f.calls[0]);
    assert(ops.validate_address(ops.ctx, "", &valid) && !valid && !f.calls[0]);
    assert(ops.validate_address(ops.ctx, "zs1\\x", &valid) && !valid && !f.calls[0]);   /* a backslash too */
}

/* ---- the route ---- */

/* Plans and commits a payment over a fresh adapter whose broadcast status is the given reply, then asks for the route. */
static bool route_of(const char *status, bool ran, bool with_txid, enum ws_route *out)
{
    struct fake f; struct wsn n; struct wss_node_ops ops;
    struct zapp_payment p = pay_of("");
    struct wss_send_req req; struct ws_plan plan = {0};
    char echo[WS_TOKEN_MAX];
    struct wss_commit_info info;
    fake_init(&f);
    adapter(&f, &n, &ops);
    request_of(&req, 125000000ull, &p);
    assert(ops.plan(ops.ctx, &req, &plan));
    req.fee_zat = plan.fee_zat;
    snprintf(req.plan_token, sizeof(req.plan_token), "%s", plan.token);
    if (!with_txid) say(&f.commit, true, "{\"ok\":true,\"data\":{\"committed\":true,\"plan_token\":\"" TOKEN "\"}}");
    assert(ops.commit(ops.ctx, &req, echo, &info) == WSS_COMMITTED);
    say(&f.broadcast, ran, status);
    *out = WS_ROUTE_SENT;
    bool read = ops.route(ops.ctx, out);
    assert(strchr(f.calls, 'b') && f.calls[strlen(f.calls) - 1] == 'b');
    return read;
}
static enum ws_route route_with(const char *entries, bool with_txid)
{
    char text[WSN_REPLY_MAX];
    enum ws_route route;
    broadcast_json(text, sizeof(text), entries);
    assert(route_of(text, true, with_txid, &route));
    return route;
}
static enum ws_route route_for_state(const char *state)
{
    char entry[256];
    broadcast_entry(entry, sizeof(entry), COMMIT_TXID, state);
    return route_with(entry, true);
}

/* Only sent and seen release the payment; every other state of its transaction keeps it waiting. */
static void a_payment_is_sent_when_its_transaction_is_sent_or_seen(void)
{
    assert(route_for_state("waiting_for_route") == WS_ROUTE_WAITING);
    assert(route_for_state("scheduled") == WS_ROUTE_WAITING);
    assert(route_for_state("preparing") == WS_ROUTE_WAITING);
    assert(route_for_state("expired") == WS_ROUTE_WAITING);
    assert(route_for_state("something_new") == WS_ROUTE_WAITING);
    assert(route_for_state("") == WS_ROUTE_WAITING);
    assert(route_for_state("sent") == WS_ROUTE_SENT);
    assert(route_for_state("seen") == WS_ROUTE_SENT);
}

/* A transaction that is not pending was sent in public mode or relayed already; other payments never decide this one. */
static void a_payment_that_is_not_pending_is_sent(void)
{
    char other[256], ours[256], both[600];
    assert(route_with(NULL, true) == WS_ROUTE_SENT);
    broadcast_entry(other, sizeof(other), OTHER_TXID, "waiting_for_route");
    assert(route_with(other, true) == WS_ROUTE_SENT);
    broadcast_entry(ours, sizeof(ours), COMMIT_TXID, "waiting_for_route");
    snprintf(both, sizeof(both), "%s,%s", other, ours);
    assert(route_with(both, true) == WS_ROUTE_WAITING);
    broadcast_entry(ours, sizeof(ours), COMMIT_TXID, "seen");
    snprintf(both, sizeof(both), "%s,%s", other, ours);
    assert(route_with(both, true) == WS_ROUTE_SENT);
    /* A commit that named no transaction: only an empty list proves nothing is pending. */
    assert(route_with(NULL, false) == WS_ROUTE_SENT);
    assert(route_with(other, false) == WS_ROUTE_WAITING);
}

/* A read that fails or is not the documented shape is not an answer: the payment keeps waiting and the poll repeats. */
static void a_failed_status_read_keeps_waiting(void)
{
    static const char *const bad[] = {
        "", "garbage", "{\"ok\":false,\"error\":{\"code\":\"UNKNOWN_COMMAND\"}}", "{\"ok\":true,\"data\":{}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.other.v1\",\"transactions\":[]}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_broadcast_status.v1\"}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_broadcast_status.v1\",\"transactions\":{}}}",
    };
    enum ws_route route;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        assert(!route_of(bad[i], true, true, &route) && route == WS_ROUTE_WAITING);
        assert(!route_of(bad[i], false, true, &route) && route == WS_ROUTE_WAITING);
    }
    char text[WSN_REPLY_MAX];
    broadcast_json(text, sizeof(text), NULL);
    assert(!route_of(text, false, true, &route) && route == WS_ROUTE_WAITING);   /* the command itself failed */
}

/* ---- the whole flow over the adapter ---- */

#define LOG_CAP 256
struct host {
    struct fake *f;
    void (*job)(void *);
    void *arg;
    uint64_t now;
    int unwraps, outcomes, last_outcome;
    enum wss_key_status key;
};
static bool h_random(void *c, uint8_t *out, size_t len) { (void)c; for (size_t i = 0; i < len; ++i) out[i] = (uint8_t)(i * 7 + 3); return true; }
static uint64_t h_now(void *c) { return ((struct host *)c)->now; }
static bool h_spawn(void *c, void (*job)(void *), void *arg) { struct host *h = c; assert(!h->job); h->job = job; h->arg = arg; return true; }
static void h_redraw(void *c) { (void)c; }
static void h_outcome(void *c, int result) { struct host *h = c; h->outcomes++; h->last_outcome = result; }
static bool s_on(void *c, bool on) { (void)c; (void)on; return true; }
static enum wss_key_status d_unwrap(void *c, uint8_t secret[32])
{
    struct host *h = c;
    h->unwraps++;
    memset(secret, h->key == WSS_KEY_OK ? 0x11 : 0, 32);
    return h->key;
}
static void drain(struct host *h)
{
    while (h->job) { void (*job)(void *) = h->job; void *arg = h->arg; h->job = NULL; job(arg); }
}
static struct wss *screen_over(struct fake *f, struct wsn *n, struct host *h)
{
    struct wss_deps d = {.network = ZAPP_PAY_MAINNET};
    wsn_init(n, &(struct wsn_runner){f, run, paused}, ZAPP_PAY_MAINNET);
    wsn_ops(n, &d.node);
    memset(h, 0, sizeof(*h));
    h->f = f; h->now = 10000; h->key = WSS_KEY_OK;
    d.device = (struct wss_device_ops){h, d_unwrap};
    d.host = (struct wss_host_ops){h, h_random, h_now, h_spawn, h_redraw, NULL, NULL, h_outcome};
    d.secure = (struct zapp_secure_ops){h, s_on, s_on, s_on, s_on, s_on};
    struct wss *s = wss_create(&d);
    assert(s);
    return s;
}
static struct wss_view view_of(struct wss *s) { struct wss_view v; wss_view(s, &v); return v; }
static struct wss *reviewed(struct fake *f, struct wsn *n, struct host *h, const char *tail)
{
    struct wss *s = screen_over(f, n, h);
    struct zapp_payment p = pay_of(tail);
    assert(wss_begin(s, &p));
    drain(h);
    return s;
}

/* The owner's fleet says no: nothing is planned and nothing is committed, however the field arrives. */
static void a_refusing_fleet_stops_the_flow_before_the_plan(void)
{
    static const char *const stops[] = {
        NULL,   /* refuses_send true */
        "{\"ok\":true,\"data\":{}}",
        "garbage",
        "{\"ok\":false,\"error\":{\"code\":\"UNKNOWN_COMMAND\"}}",
    };
    for (size_t i = 0; i < sizeof(stops) / sizeof(stops[0]); ++i) {
        struct fake f; struct wsn n; struct host h;
        fake_init(&f);
        if (!stops[i]) fleet_json(f.fleet.text, sizeof(f.fleet.text), "disagree", true, true);
        else say(&f.fleet, i != 3, stops[i]);
        struct wss *s = reviewed(&f, &n, &h, "?amount=1.25");
        struct wss_view v = view_of(s);
        assert(v.state == WS_FAILED && !v.can_send && !v.review);
        assert(f.plans == 0 && f.commits == 0 && h.unwraps == 0 && !strchr(f.calls, 'p') && !strchr(f.calls, 'c'));
        assert(strstr(v.status, "fleet") && !strstr(v.status, "disagree\""));
        wss_tap_send(s, v.serial);
        drain(&h);
        assert(f.commits == 0 && h.unwraps == 0);
        assert(wss_end(s) && wss_destroy(s));
    }
}

static void a_fleet_that_is_not_configured_allows_send_and_says_so(void)
{
    struct fake f; struct wsn n; struct host h;
    fake_init(&f);
    struct wss *s = reviewed(&f, &n, &h, "?amount=1.25");
    struct wss_view v = view_of(s);
    assert(v.state == WS_REVIEW && v.can_send && v.review && !strcmp(v.fleet, "Not checked by your fleet"));
    assert(!strcmp(v.amount, "1.25 ZCL") && !strcmp(v.fee, "0.0001 ZCL"));
    fleet_json(f.fleet.text, sizeof(f.fleet.text), "agree", true, false);
    wss_destroy(s);
    s = reviewed(&f, &n, &h, "?amount=1.25");
    assert(!strcmp(view_of(s).fleet, "Checked by your fleet"));
    wss_destroy(s);
}

/* The node lists the payment of commit as waiting for a private route. */
static void broadcast_waiting(struct fake *f)
{
    char entry[256];
    broadcast_entry(entry, sizeof(entry), COMMIT_TXID, "waiting_for_route");
    broadcast_json(f->broadcast.text, sizeof(f->broadcast.text), entry);
}
/* A commit that commits: the node holds the payment, the screen never says Sent, and Done is offered once the wallet is locked. */
static void a_committed_payment_is_not_called_sent(void)
{
    struct fake f; struct wsn n; struct host h;
    fake_init(&f);
    broadcast_waiting(&f);
    struct wss *s = reviewed(&f, &n, &h, "?amount=1.25");
    assert(f.commits == 0 && h.unwraps == 0);   /* nothing is committed or authenticated before the tap */
    wss_tap_send(s, view_of(s).serial);
    drain(&h);
    struct wss_view v = view_of(s);
    assert(f.commits == 1 && h.unwraps == 1 && v.state == WS_BROADCAST);
    assert(strstr(f.unlock_input, "\"passphrase\"") && strstr(f.unlock_input, "\"timeout_seconds\":300"));
    assert(f.commit_timeout >= 300000u);
    assert(strstr(v.status, "Sending privately") && strstr(v.status, "onion peer"));
    assert(!strstr(v.status, "Sent") && !strstr(v.status, "sent"));
    assert(v.can_leave && !v.can_retry && !v.can_send);
    drain(&h);
    assert(f.calls[strlen(f.calls) - 1] == 'l' || strchr(f.calls, 'l'));   /* the wallet is locked right after the answer */
    assert(wss_end(s) && wss_destroy(s));
}

/* The flow leaves the broadcast only when the node lists the payment as sent or seen: one notice, then the stop guard lets go. */
static void a_payment_is_done_when_the_node_has_sent_it(void)
{
    static const char *const states[] = {"waiting_for_route", "scheduled", "sent"};
    struct fake f; struct wsn n; struct host h;
    char entry[256];
    fake_init(&f);
    struct wss *s = reviewed(&f, &n, &h, "?amount=1.25");
    broadcast_waiting(&f);
    wss_tap_send(s, view_of(s).serial);
    drain(&h);
    assert(view_of(s).state == WS_BROADCAST && wss_in_flight(s) && h.outcomes == 0);
    for (int i = 0; i < 3; ++i) {   /* waiting and scheduled: still in the broadcast, no notice, the guard holds */
        broadcast_entry(entry, sizeof(entry), COMMIT_TXID, states[i]);
        broadcast_json(f.broadcast.text, sizeof(f.broadcast.text), entry);
        h.now += 3000; wss_on_tick(s); drain(&h);
        struct wss_view v = view_of(s);
        if (i < 2) {
            assert(v.state == WS_BROADCAST && wss_in_flight(s) && h.outcomes == 0);
            assert(strstr(v.status, "onion peer") && !strstr(v.status, "left the phone"));
        }
    }
    assert(view_of(s).state == WS_DONE && !wss_in_flight(s));
    assert(h.outcomes == 1 && h.last_outcome == ZAPP_PAYMENT_SENT);
    for (int i = 0; i < 3; ++i) { h.now += 3000; wss_on_tick(s); drain(&h); }
    assert(h.outcomes == 1 && view_of(s).state == WS_DONE);
    assert(wss_end(s) && wss_destroy(s));
}

/* The commit process is killed or never answers: unknown, final, no retry, no second commit. */
static void a_killed_commit_is_unknown_and_never_repeated(void)
{
    struct fake f; struct wsn n; struct host h;
    fake_init(&f);
    say(&f.commit, false, "\nThe command timed out.");
    struct wss *s = reviewed(&f, &n, &h, "?amount=1.25");
    wss_tap_send(s, view_of(s).serial);
    drain(&h);
    struct wss_view v = view_of(s);
    assert(v.state == WS_FAILED && v.check_history && !v.can_retry && !v.can_send);
    assert(!strstr(v.status, "Nothing was sent") && strstr(v.status, "History"));
    for (int i = 0; i < 5; ++i) { h.now += 3000; wss_on_tick(s); wss_tap_retry(s); wss_tap_send(s, v.serial); drain(&h); }
    assert(f.commits == 1 && h.unwraps == 1);
    assert(wss_end(s) && wss_destroy(s));
}

/* Node message text never reaches the screen: the node says "nothing was sent" for codes where that is not known. */
static void node_message_text_never_reaches_the_screen(void)
{
    static const char *const codes[] = {"PLAN_TOKEN_MISMATCH", "SEND_OUTCOME_UNKNOWN", "WALLET_RPC_ERROR", "SEND_IN_PROGRESS"};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        struct fake f; struct wsn n; struct host h;
        char text[WSN_REPLY_MAX];
        fake_init(&f);
        error_json(text, sizeof(text), codes[i], "NODE-MESSAGE nothing was sent; the key is free");
        say(&f.commit, false, text);
        struct wss *s = reviewed(&f, &n, &h, "?amount=1.25");
        wss_tap_send(s, view_of(s).serial);
        drain(&h);
        struct wss_view v = view_of(s);
        assert(v.state == WS_FAILED && v.check_history && !v.can_retry);
        assert(!strstr(v.status, "NODE-MESSAGE") && !strstr(v.status, "Nothing was sent") && !strstr(v.status, "free"));
        wss_destroy(s);
    }
    /* Only the released key proves nothing was sent, and it allows a new tap on the same review. */
    struct fake f; struct wsn n; struct host h;
    char text[WSN_REPLY_MAX];
    fake_init(&f);
    error_json(text, sizeof(text), WALLET_SEND_ONCE_CODE_RELEASED, "NODE-MESSAGE");
    say(&f.commit, false, text);
    struct wss *s = reviewed(&f, &n, &h, "?amount=1.25");
    wss_tap_send(s, view_of(s).serial);
    drain(&h);
    struct wss_view v = view_of(s);
    assert(v.state == WS_FAILED && v.can_retry && strstr(v.status, "Nothing was sent") && !strstr(v.status, "NODE-MESSAGE"));
    wss_destroy(s);
}

/* A declined or failed authentication commits nothing and the passphrase never exists on the node side. */
/* The balance the Send pages show is the summary's spendable amount, read with the summary alone. A summary that hides the
 * private amounts, a summary of another shape and a node that does not answer give no balance, never 0. */
static void the_send_balance_is_the_summary_spendable(void)
{
    static const char hidden[] =
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\",\"shielded_state\":\"keys_unavailable\","
        "\"spendable_zat\":null,\"spendable\":null,\"pending_zat\":null,\"pending\":null,\"pending_notes\":null,"
        "\"pending_min_confirmations_needed\":null,\"unready_zat\":null,\"unready\":null,\"unready_notes\":null,"
        "\"public_zat\":10000000,\"public\":\"0.10000000\",\"immature_zat\":0,\"immature\":\"0.00000000\","
        "\"tip_height\":3000000,\"header_height\":3000000,\"scanned_through_height\":null,\"blocks_behind\":0,"
        "\"current\":false,\"locked\":true,\"encrypted\":true,\"shielded_keys\":0,\"send_allowed\":false,"
        "\"send_blocked_reason\":\"progress_store_unavailable\"}}";
    struct fake f; struct wsn n; struct wss_node_ops ops; struct wss_balance b;
    fake_init(&f);
    adapter(&f, &n, &ops);
    assert(ops.read_balance(ops.ctx, &b) && b.known && b.spendable_zat == 500000000u && !strcmp(f.calls, "s"));
    summary_json(f.summary.text, sizeof(f.summary.text), true, "", true, 0, 0);
    assert(ops.read_balance(ops.ctx, &b) && b.known && b.spendable_zat == 0);
    say(&f.summary, true, hidden);
    assert(ops.read_balance(ops.ctx, &b) && !b.known && b.spendable_zat == 0);
    say(&f.summary, true, "{\"ok\":true,\"data\":{\"schema\":\"zcl.other.v1\"}}");
    assert(ops.read_balance(ops.ctx, &b) && !b.known);
    say(&f.summary, false, "");
    assert(!ops.read_balance(ops.ctx, &b) && !b.known);
    assert(!strcmp(f.calls, "sssss"));
}
static void a_declined_prompt_commits_nothing(void)
{
    struct fake f; struct wsn n; struct host h;
    fake_init(&f);
    struct wss *s = reviewed(&f, &n, &h, "?amount=1.25");
    h.key = WSS_KEY_DECLINED;
    wss_tap_send(s, view_of(s).serial);
    drain(&h);
    assert(view_of(s).state == WS_FAILED && f.commits == 0 && !strchr(f.calls, 'u') && wss_secrets_clear(s));
    wss_destroy(s);
}

int main(void)
{
    amounts_and_scope();
    plan_then_commit_is_one_request();
    commit_keeps_the_sender_of_its_plan();
    plan_replies_are_read_by_shape();
    commit_codes_are_pinned();
    a_replay_is_reported_with_its_transaction();
    commit_without_a_usable_answer_is_unknown();
    commit_is_asked_once_and_given_time();
    gate_reads_numbers_and_never_shows_node_text();
    an_unencrypted_wallet_never_sends();
    a_summary_that_is_not_the_documented_one_is_unknown();
    the_fleet_decides_by_its_own_field();
    a_refusal_says_why();
    validate_accepts_only_a_valid_reply();
    a_refusing_fleet_stops_the_flow_before_the_plan();
    a_fleet_that_is_not_configured_allows_send_and_says_so();
    a_committed_payment_is_not_called_sent();
    a_payment_is_done_when_the_node_has_sent_it();
    a_payment_is_sent_when_its_transaction_is_sent_or_seen();
    a_payment_that_is_not_pending_is_sent();
    a_failed_status_read_keeps_waiting();
    a_killed_commit_is_unknown_and_never_repeated();
    node_message_text_never_reaches_the_screen();
    a_declined_prompt_commits_nothing();
    the_send_balance_is_the_summary_spendable();
    puts("wallet_send_node_test: ok");
    return 0;
}

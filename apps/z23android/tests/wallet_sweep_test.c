/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "wallet_sweep.h"
#include "json/json.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Make private over the real send machine, screen and node adapter, with a fake runner, device key and host. The fixtures
 * hold no real key: the wallet secret is a fixed byte pattern and the node is a script. */

#define FROM "t1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define P10 "pppppppppp"
#define TO "zs1" P10 P10 P10 P10 P10 P10 P10 "ppppp"
#define TOKEN "0123456789abcdef"
#define SECRET_HEX "1111111111111111111111111111111111111111111111111111111111111111"
#define DONE "Done. It shows in your private balance after the next block."
#define REPLAYED "Done. This move was already made. It shows in your private balance after the next block."
#define MOVE "Move 0.1 ZCL from your public address into your private balance. Fee 0.0001 ZCL."

struct reply { bool ran; char text[WSN_REPLY_MAX]; };
struct fake {
    struct reply summary, fleet, plan, commit, unlock, lock, latest;
    char calls[64];   /* one letter per node call, in order */
    char plan_input[WSN_INPUT_MAX], commit_input[2][WSN_INPUT_MAX], unlock_input[WSN_INPUT_MAX];
    int plans, commits, unlocks, locks;
    bool paused;
    void (*on_commit)(void);
};
static struct wss *current;
static void say(struct reply *r, bool ran, const char *text) { r->ran = ran; snprintf(r->text, sizeof(r->text), "%s", text); }

static void summary_json(char *out, size_t cap, bool allowed, const char *reason, bool encrypted, unsigned behind)
{
    snprintf(out, cap,
             "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\",\"spendable_zat\":0,\"spendable\":\"0.00000000\","
             "\"pending_zat\":0,\"pending\":\"0.00000000\",\"pending_notes\":0,\"pending_min_confirmations_needed\":0,"
             "\"sending_zat\":0,\"sending\":\"0.00000000\",\"public_zat\":10000000,\"public\":\"0.10000000\",\"immature_zat\":0,"
             "\"immature\":\"0.00000000\",\"tip_height\":3000000,\"header_height\":3000000,\"scanned_through_height\":3000000,"
             "\"blocks_behind\":%u,\"current\":true,\"locked\":true,\"encrypted\":%s,\"shielded_keys\":1,"
             "\"send_allowed\":%s,\"send_blocked_reason\":\"%s\"}}",
             behind, encrypted ? "true" : "false", allowed ? "true" : "false", reason);
}
static void fleet_json(char *out, size_t cap, bool refuses)
{
    snprintf(out, cap,
             "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet_status.v1\",\"member\":%s,\"verdict\":\"%s\",\"refuses_send\":%s,"
             "\"machines_total\":0,\"machines_connected\":0,\"local_tip\":3000000,\"machines\":[]}}",
             refuses ? "true" : "false", refuses ? "disagree" : "not_member", refuses ? "true" : "false");
}
/* The plan the node quotes: the total leaves the address, the fee is taken from it, and the rest arrives. */
static void plan_json(char *out, size_t cap, unsigned long long total, unsigned long long fee, unsigned long long remaining,
                      unsigned long long maturing)
{
    snprintf(out, cap,
             "{\"ok\":true,\"data\":{\"stage\":\"plan\",\"action\":\"shield-address\",\"committed\":false,\"plan_token\":\"" TOKEN "\","
             "\"wallet_scope\":\"prod\",\"from\":\"" FROM "\",\"to\":\"" TO "\",\"input_count\":2,\"coinbase_input_count\":0,"
             "\"total_zat\":%llu,\"fee_zat\":%llu,\"amount_zat\":%llu,\"remaining_inputs\":%llu,\"maturing_zat\":%llu,"
             "\"confirm_hint\":\"x\",\"commit_input\":\"{}\"}}",
             total, fee, total - fee, remaining, maturing);
}
static void committed_json(char *out, size_t cap, bool replayed)
{
    if (replayed)   /* a replay holds only what the node's send-once record holds */
        snprintf(out, cap, "{\"ok\":true,\"data\":{\"stage\":\"committed\",\"committed\":true,\"replayed\":true,\"txid\":\"%064d\","
                           "\"idempotency_key\":\"k\"}}", 7);
    else
        snprintf(out, cap, "{\"ok\":true,\"data\":{\"stage\":\"committed\",\"committed\":true,\"replayed\":false,\"txid\":\"%064d\","
                           "\"from\":\"" FROM "\",\"to\":\"" TO "\",\"input_count\":2,\"total_zat\":10000000,\"fee_zat\":10000,"
                           "\"amount_zat\":9990000,\"idempotency_key\":\"k\",\"plan_token\":\"" TOKEN "\"}}", 7);
}
static void error_json(char *out, size_t cap, const char *code)
{
    snprintf(out, cap, "{\"ok\":false,\"error\":{\"code\":\"%s\",\"message\":\"NODE-SENTENCE nothing was sent\"}}", code);
}
static void fake_init(struct fake *f)
{
    memset(f, 0, sizeof(*f));
    summary_json(f->summary.text, sizeof(f->summary.text), true, "", true, 0);
    f->summary.ran = true;
    fleet_json(f->fleet.text, sizeof(f->fleet.text), false);
    f->fleet.ran = true;
    plan_json(f->plan.text, sizeof(f->plan.text), 10000000ull, 10000ull, 0, 0);
    f->plan.ran = true;
    committed_json(f->commit.text, sizeof(f->commit.text), false);
    f->commit.ran = true;
    say(&f->unlock, true, "{\"ok\":true,\"data\":{\"unlocked\":true}}");
    say(&f->lock, true, "{\"ok\":true,\"data\":{\"locked\":true}}");
    say(&f->latest, false, "{\"ok\":false,\"error\":{\"code\":\"UNKNOWN_COMMAND\"}}");
}
static bool run(void *ctx, const char *op, const char *input, unsigned timeout_ms, char *out, size_t cap)
{
    struct fake *f = ctx;
    struct reply *r = NULL;
    char letter = '?';
    (void)timeout_ms;
    if (!strcmp(op, "summary")) { r = &f->summary; letter = 's'; }
    else if (!strcmp(op, "fleet")) { r = &f->fleet; letter = 'f'; }
    else if (!strcmp(op, "latest")) { r = &f->latest; letter = 'a'; }
    else if (!strcmp(op, "shieldplan")) { r = &f->plan; letter = 'P'; f->plans++; snprintf(f->plan_input, sizeof(f->plan_input), "%s", input); }
    else if (!strcmp(op, "unlock")) { r = &f->unlock; letter = 'u'; f->unlocks++; snprintf(f->unlock_input, sizeof(f->unlock_input), "%s", input); }
    else if (!strcmp(op, "lock")) { r = &f->lock; letter = 'l'; f->locks++; assert(!input); }
    else if (!strcmp(op, "shieldcommit")) {
        r = &f->commit; letter = 'C';
        snprintf(f->commit_input[f->commits < 2 ? f->commits : 1], WSN_INPUT_MAX, "%s", input);
        f->commits++;
        if (f->on_commit) f->on_commit();
    } else assert(!"an op a sweep has no right to ask for");
    assert(strlen(f->calls) + 2 < sizeof(f->calls));
    f->calls[strlen(f->calls)] = letter;
    snprintf(out, cap, "%s", r->text);
    return r->ran;
}
static bool paused(void *ctx) { return ((struct fake *)ctx)->paused; }

/* ---- the host: a worker that runs when the test says so, and a device key that answers with a fixed secret ---- */

struct host {
    void (*job)(void *);
    void *arg;
    uint64_t now;
    int unwraps, randoms;
    enum wss_key_status key;
    void (*on_unwrap)(void);
};
static bool h_random(void *c, uint8_t *out, size_t len)
{
    struct host *h = c;
    h->randoms++;
    for (size_t i = 0; i < len; ++i) out[i] = (uint8_t)(i * 7 + 3 + h->randoms);
    return true;
}
static uint64_t h_now(void *c) { return ((struct host *)c)->now; }
static bool h_spawn(void *c, void (*job)(void *), void *arg) { struct host *h = c; assert(!h->job); h->job = job; h->arg = arg; return true; }
static void h_redraw(void *c) { (void)c; }
static bool s_on(void *c, bool on) { (void)c; (void)on; return true; }
static enum wss_key_status d_unwrap(void *c, uint8_t secret[32])
{
    struct host *h = c;
    h->unwraps++;
    if (h->on_unwrap) h->on_unwrap();
    memset(secret, h->key == WSS_KEY_OK ? 0x11 : 0, 32);
    return h->key;
}
static void drain(struct host *h)
{
    while (h->job) { void (*job)(void *) = h->job; void *arg = h->arg; h->job = NULL; job(arg); }
}
static struct wss *screen_over(struct fake *f, struct wsw *w, struct host *h)
{
    struct wss_deps d = {.network = ZAPP_PAY_MAINNET};
    wsw_init(w, &(struct wsn_runner){f, run, paused}, ZAPP_PAY_MAINNET);
    wsw_ops(w, &d.node);
    memset(h, 0, sizeof(*h));
    h->now = 10000; h->key = WSS_KEY_OK;
    d.device = (struct wss_device_ops){h, d_unwrap};
    d.host = (struct wss_host_ops){h, h_random, h_now, h_spawn, h_redraw, NULL, NULL, NULL};
    d.secure = (struct zapp_secure_ops){h, s_on, s_on, s_on, s_on, s_on};
    current = wss_create(&d);
    assert(current);
    return current;
}
static struct wss_view view_of(struct wss *s) { struct wss_view v; wss_view(s, &v); return v; }
static struct wss *at_review(struct fake *f, struct wsw *w, struct host *h)
{
    struct wss *s = screen_over(f, w, h);
    assert(wss_begin_sweep(s));
    drain(h);
    assert(view_of(s).state == WS_REVIEW);
    return s;
}
static void tap_through(struct wss *s, struct host *h)
{
    wss_tap_send(s, view_of(s).serial);
    drain(h);
}
static void finish_screen(struct wss *s)
{
    assert(wss_end(s) && wss_destroy(s));
    current = NULL;
}
static const struct json_value *field(const struct json_value *root, const char *key, int type)
{
    const struct json_value *v = json_get(root, key);
    assert(v && (int)v->type == type);
    return v;
}
static void key_of(const char *request, char key[WS_KEY_HEX + 1])
{
    struct json_value doc = {0};
    assert(json_read(&doc, request, strlen(request)));
    snprintf(key, WS_KEY_HEX + 1, "%s", json_get_str(field(&doc, "idempotency_key", JSON_STR)));
    json_free(&doc);
}

/* ---- the flow ---- */

/* Plan, review, authentication, commit, done. The plan names no destination and no amount, nothing is authenticated or
 * committed before the tap, the commit carries what the node quoted, and no secret reaches a request or stays in a buffer. */
static void plan_review_auth_commit_done(void)
{
    struct fake f; struct wsw w; struct host h;
    fake_init(&f);
    struct wss *s = at_review(&f, &w, &h);
    struct wss_view v = view_of(s);
    assert(v.sweep && v.review && v.can_send && !v.can_retry && !v.can_pay_again && !v.address[0] && !v.memo[0] && !v.warning[0]);
    assert(!strcmp(v.move, MOVE) && !strcmp(v.arrives, "0.0999 ZCL arrives in your private balance.") && !v.move_note[0]);
    assert(!strcmp(f.calls, "sfP") && f.commits == 0 && h.unwraps == 0 && f.unlocks == 0);
    assert(!strcmp(v.fleet, "Not checked by your fleet") && !wss_send_busy(v.state));

    struct json_value a = {0}, c = {0};
    assert(json_read(&a, f.plan_input, strlen(f.plan_input)));
    static const char *const absent[] = {"to", "from", "amount", "amount_zat", "memo", "memo_hex", "fee_zat", "plan_token", "confirm"};
    for (size_t i = 0; i < sizeof(absent) / sizeof(absent[0]); ++i) assert(!json_get(&a, absent[i]));
    assert(!strcmp(json_get_str(field(&a, "wallet_scope", JSON_STR)), "prod") && field(&a, "idempotency_key", JSON_STR));
    assert(!strstr(f.plan_input, TO) && !strstr(f.plan_input, FROM) && !strstr(f.plan_input, SECRET_HEX));

    wss_tap_send(s, v.serial);
    assert(view_of(s).state == WS_AUTH && wss_send_busy(WS_AUTH));
    drain(&h);
    v = view_of(s);
    assert(v.state == WS_DONE && !strcmp(v.status, DONE) && v.can_leave && !v.can_retry && !wss_send_busy(v.state));
    assert(!strcmp(f.calls, "sfPuCl") && h.unwraps == 1 && f.commits == 1 && f.locks == 1);
    assert(strstr(f.unlock_input, SECRET_HEX));   /* the unlock request is where the secret goes, and nowhere else */
    assert(!wss_exposed(s) && wss_secrets_clear(s));

    assert(json_read(&c, f.commit_input[0], strlen(f.commit_input[0])));
    assert(!strcmp(json_get_str(field(&c, "from", JSON_STR)), FROM) && !strcmp(json_get_str(field(&c, "to", JSON_STR)), TO));
    assert(json_get_int(field(&c, "input_count", JSON_INT)) == 2 && json_get_int(field(&c, "total_zat", JSON_INT)) == 10000000);
    assert(json_get_int(field(&c, "fee_zat", JSON_INT)) == 10000 && json_get_bool(field(&c, "confirm", JSON_BOOL)));
    assert(!strcmp(json_get_str(field(&c, "plan_token", JSON_STR)), TOKEN) && !strcmp(json_get_str(field(&c, "wallet_scope", JSON_STR)), "prod"));
    assert(!strcmp(json_get_str(field(&c, "idempotency_key", JSON_STR)), json_get_str(field(&a, "idempotency_key", JSON_STR))));
    assert(!json_get(&c, "amount") && !json_get(&c, "amount_zat") && !json_get(&c, "memo") && !json_get(&c, "memo_hex"));
    assert(!strstr(f.commit_input[0], SECRET_HEX));
    char line[WSS_LINE];
    assert(wss_progress(s, line, sizeof(line)) && !strcmp(line, DONE));
    json_free(&a); json_free(&c);
    finish_screen(s);
    printf("  plan, review, authentication, commit, done\n");
}

/* Coins left for a later sweep, and coinbase still maturing, are said in plain words. */
static void notes_for_coins_left(void)
{
    static const struct { unsigned long long remaining, maturing; const char *left, *mature; } cases[] = {
        {0, 0, NULL, NULL}, {3, 0, "left for a later move", NULL},
        {0, 5000000, NULL, "Mined coins of 0.05 ZCL are still maturing"}, {3, 5000000, "left for a later move", "Mined coins of 0.05 ZCL"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        struct fake f; struct wsw w; struct host h;
        fake_init(&f);
        plan_json(f.plan.text, sizeof(f.plan.text), 10000000ull, 10000ull, cases[i].remaining, cases[i].maturing);
        struct wss *s = at_review(&f, &w, &h);
        struct wss_view v = view_of(s);
        assert(!strcmp(v.move, MOVE));
        assert(cases[i].left ? strstr(v.move_note, cases[i].left) != NULL : !strstr(v.move_note, "later move"));
        assert(cases[i].mature ? strstr(v.move_note, cases[i].mature) != NULL : !strstr(v.move_note, "maturing"));
        assert((cases[i].left || cases[i].mature) == (v.move_note[0] != 0));
        finish_screen(s);
    }
    printf("  coins left and coins maturing are noted\n");
}

/* Cancel at the review: nothing is authenticated or committed, and the old tap does nothing. */
static void cancel_at_review(void)
{
    struct fake f; struct wsw w; struct host h;
    fake_init(&f);
    struct wss *s = at_review(&f, &w, &h);
    uint32_t serial = view_of(s).serial;
    wss_tap_cancel(s);
    drain(&h);
    struct wss_view v = view_of(s);
    assert(v.state == WS_CANCELLED && !strcmp(v.status, "Cancelled. Nothing was moved.") && !v.can_send);
    wss_tap_send(s, serial);
    drain(&h);
    assert(view_of(s).state == WS_CANCELLED && f.commits == 0 && h.unwraps == 0 && !strchr(f.calls, 'u') && !strchr(f.calls, 'C'));
    finish_screen(s);
    printf("  cancel at the review commits nothing\n");
}

/* A declined prompt commits nothing and leaves the review open; the retry keeps the plan and the key. */
static void declined_auth_then_retry(void)
{
    struct fake f; struct wsw w; struct host h;
    char first[WS_KEY_HEX + 1], second[WS_KEY_HEX + 1];
    fake_init(&f);
    struct wss *s = at_review(&f, &w, &h);
    h.key = WSS_KEY_DECLINED;
    tap_through(s, &h);
    struct wss_view v = view_of(s);
    assert(v.state == WS_FAILED && v.can_retry && !strcmp(v.status, "Device authentication was not completed. Nothing was moved. Try again when you are ready."));
    assert(f.commits == 0 && h.unwraps == 1 && !wss_exposed(s) && wss_secrets_clear(s));
    h.key = WSS_KEY_OK;
    wss_tap_retry(s);
    drain(&h);
    assert(view_of(s).state == WS_REVIEW && f.plans == 1);
    tap_through(s, &h);
    assert(view_of(s).state == WS_DONE && f.commits == 1 && h.unwraps == 2);
    key_of(f.plan_input, first);
    key_of(f.commit_input[0], second);
    assert(!strcmp(first, second));
    finish_screen(s);
    printf("  declined authentication, then the same review\n");
}

/* A commit the node refused is retried under the same plan and key; the node answers a sweep that did happen from its record. */
static void refused_then_replayed(void)
{
    struct fake f; struct wsw w; struct host h;
    char text[WSN_REPLY_MAX];
    fake_init(&f);
    error_json(text, sizeof(text), "NOTHING_TO_SHIELD");
    say(&f.commit, false, text);
    struct wss *s = at_review(&f, &w, &h);
    tap_through(s, &h);
    struct wss_view v = view_of(s);
    assert(v.state == WS_FAILED && v.can_retry && strstr(v.status, "not enough public money") && !strstr(v.status, "NODE-SENTENCE"));
    char line[WSS_LINE];
    assert(wss_progress(s, line, sizeof(line)) && !strcmp(line, "Not moved: the node refused it. Your coins were not spent."));
    assert(f.commits == 1 && !wss_exposed(s));
    say(&f.commit, true, "");
    committed_json(f.commit.text, sizeof(f.commit.text), true);
    wss_tap_retry(s);
    drain(&h);
    assert(view_of(s).state == WS_REVIEW && f.plans == 1);
    tap_through(s, &h);
    v = view_of(s);
    assert(v.state == WS_PAID && !strcmp(v.status, REPLAYED) && !v.can_pay_again && v.can_leave);
    assert(f.commits == 2 && h.unwraps == 2 && !strcmp(f.commit_input[0], f.commit_input[1]));   /* same key, same plan */
    assert(wss_progress(s, line, sizeof(line)) && !strcmp(line, REPLAYED));
    assert(!wss_exposed(s) && wss_secrets_clear(s));
    finish_screen(s);
    printf("  a refused commit retried under its key replays\n");
}

/* Every refusal that proves nothing was sent gets one plain sentence, and the node's own words never show. */
static void refusals_by_code(void)
{
    static const struct { const char *code, *words; bool new_plan; } cases[] = {
        {"NOTHING_TO_SHIELD", "There is not enough public money to move after the fee.", false},
        {"NO_PRIVATE_ADDRESS", "Your wallet has no private address yet. Open Receive", false},
        {"PROVING_UNAVAILABLE", "This phone cannot build private transactions yet.", false},
        {"SEND_REFUSED_KEY_RELEASED", "The node refused this move. Nothing was moved. Try again.", false},
        {"PLAN_TOKEN_MISMATCH", "Your public coins changed while you were reviewing.", true},
        {"FEE_CHANGED", "The network fee changed. Nothing was moved.", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        struct fake f; struct wsw w; struct host h;
        char text[WSN_REPLY_MAX], first[WS_KEY_HEX + 1], second[WS_KEY_HEX + 1];
        fake_init(&f);
        error_json(text, sizeof(text), cases[i].code);
        say(&f.commit, false, text);
        struct wss *s = at_review(&f, &w, &h);
        key_of(f.plan_input, first);
        tap_through(s, &h);
        struct wss_view v = view_of(s);
        assert(v.state == WS_FAILED && v.can_retry && !v.check_history && strstr(v.status, cases[i].words) && strstr(v.status, "Nothing was moved"));
        assert(!strstr(v.status, "NODE-SENTENCE") && f.commits == 1);
        wss_tap_retry(s);
        drain(&h);
        key_of(f.plan_input, second);
        assert(view_of(s).state == WS_REVIEW && f.plans == (cases[i].new_plan ? 2 : 1) && !strcmp(first, second) == !cases[i].new_plan);
        finish_screen(s);
    }
    printf("  each commit refusal has one plain sentence\n");
}

/* An answer that is missing or unclear may hide a sent sweep: it is final and never repeated. */
static void unknown_commit_is_final(void)
{
    static const char *const answers[] = {
        "{\"ok\":false,\"error\":{\"code\":\"WALLET_RPC_ERROR\"}}", "{\"ok\":false,\"error\":{\"code\":\"SEND_IN_PROGRESS\"}}",
        "{\"ok\":false,\"error\":{\"code\":\"SEND_OUTCOME_UNKNOWN\"}}", "{\"ok\":false,\"error\":{\"code\":\"IDEMPOTENCY_KEY_REUSED\"}}",
        "{\"ok\":false,\"error\":{\"code\":\"PLAN_REQUIRED\"}}", "{\"ok\":true,\"data\":{\"committed\":false}}", "{\"ok\":true}", "not json", "",
    };
    for (size_t i = 0; i < sizeof(answers) / sizeof(answers[0]); ++i) {
        struct fake f; struct wsw w; struct host h;
        fake_init(&f);
        say(&f.commit, false, answers[i]);
        struct wss *s = at_review(&f, &w, &h);
        tap_through(s, &h);
        struct wss_view v = view_of(s);
        assert(v.state == WS_FAILED && v.check_history && !v.can_retry && strstr(v.status, "not known whether this move was made"));
        char line[WSS_LINE];
        assert(wss_progress(s, line, sizeof(line)) && !strncmp(line, "Move status unknown", 19));
        wss_tap_retry(s);
        wss_tap_send(s, v.serial);
        drain(&h);
        assert(view_of(s).state == WS_FAILED && f.commits == 1 && !wss_exposed(s));
        finish_screen(s);
    }
    printf("  an unclear commit answer is final\n");
}

/* A plan the node refuses or garbles stops before any authentication, and says why when the reason is known. */
static void plan_refusals(void)
{
    static const struct { const char *code; const char *words; } cases[] = {
        {"NOTHING_TO_SHIELD", "There is not enough public money to move after the fee."},
        {"NO_PRIVATE_ADDRESS", "Your wallet has no private address yet."},
        {"PROVING_UNAVAILABLE", "This phone cannot build private transactions yet."},
        {"SHIELD_REFUSED", "The node refused this move. Nothing was moved. Try again."},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        struct fake f; struct wsw w; struct host h;
        char text[WSN_REPLY_MAX];
        fake_init(&f);
        error_json(text, sizeof(text), cases[i].code);
        say(&f.plan, false, text);
        struct wss *s = screen_over(&f, &w, &h);
        assert(wss_begin_sweep(s));
        drain(&h);
        struct wss_view v = view_of(s);
        assert(v.state == WS_FAILED && v.can_retry && !v.can_send && strstr(v.status, cases[i].words) && !strstr(v.status, "NODE-SENTENCE"));
        assert(f.commits == 0 && h.unwraps == 0 && !strchr(f.calls, 'u'));
        finish_screen(s);
    }
    /* A reply that is not the documented plan is a refusal without a reason. */
    static const char *const garbled[] = {
        "garbage", "", "{\"ok\":true,\"data\":{}}",
        "{\"ok\":true,\"data\":{\"stage\":\"plan\",\"plan_token\":\"" TOKEN "\",\"from\":\"" FROM "\",\"to\":\"" TO "\",\"input_count\":2,\"total_zat\":10000000,"
        "\"fee_zat\":10000,\"amount_zat\":1,\"remaining_inputs\":0,\"maturing_zat\":0}}",          /* the amounts do not add up */
        "{\"ok\":true,\"data\":{\"stage\":\"plan\",\"plan_token\":\"short\",\"from\":\"" FROM "\",\"to\":\"" TO "\",\"input_count\":2,\"total_zat\":10000000,"
        "\"fee_zat\":10000,\"amount_zat\":9990000,\"remaining_inputs\":0,\"maturing_zat\":0}}",   /* a token that is not 16 hex characters */
        "{\"ok\":true,\"data\":{\"stage\":\"plan\",\"plan_token\":\"" TOKEN "\",\"from\":\"" FROM "\",\"to\":\"" TO "\",\"input_count\":0,\"total_zat\":10000000,"
        "\"fee_zat\":10000,\"amount_zat\":9990000,\"remaining_inputs\":0,\"maturing_zat\":0}}",   /* no coins */
    };
    for (size_t i = 0; i < sizeof(garbled) / sizeof(garbled[0]); ++i) {
        struct fake f; struct wsw w; struct host h;
        fake_init(&f);
        say(&f.plan, true, garbled[i]);
        struct wss *s = screen_over(&f, &w, &h);
        assert(wss_begin_sweep(s));
        drain(&h);
        struct wss_view v = view_of(s);
        assert(v.state == WS_FAILED && !v.can_send && strstr(v.status, "The node refused this move.") && f.commits == 0 && h.unwraps == 0);
        finish_screen(s);
    }
    printf("  a refused or garbled plan stops before authentication\n");
}

/* The same gate as Send: a closed gate, a wallet behind the chain, a refusing fleet and a warm phone plan nothing. */
static void the_send_gate_stops_the_plan(void)
{
    struct fake f; struct wsw w; struct host h;
    fake_init(&f);
    summary_json(f.summary.text, sizeof(f.summary.text), false, "progress_store_unavailable", true, 0);
    struct wss *s = screen_over(&f, &w, &h);
    assert(wss_begin_sweep(s));
    drain(&h);
    struct wss_view v = view_of(s);
    assert(v.state == WS_FAILED && strstr(v.status, "save its progress") && !strcmp(f.calls, "sf") && f.plans == 0);
    finish_screen(s);

    fake_init(&f);
    summary_json(f.summary.text, sizeof(f.summary.text), true, "", false, 0);
    s = screen_over(&f, &w, &h);
    assert(wss_begin_sweep(s));
    drain(&h);
    assert(view_of(s).state == WS_FAILED && strstr(view_of(s).status, "screen lock") && f.plans == 0);
    finish_screen(s);

    fake_init(&f);
    fleet_json(f.fleet.text, sizeof(f.fleet.text), true);
    s = screen_over(&f, &w, &h);
    assert(wss_begin_sweep(s));
    drain(&h);
    assert(view_of(s).state == WS_FAILED && strstr(view_of(s).status, "fleet") && f.plans == 0);
    finish_screen(s);

    fake_init(&f);
    f.paused = true;
    s = screen_over(&f, &w, &h);
    assert(wss_begin_sweep(s));
    drain(&h);
    v = view_of(s);
    assert(v.state == WS_FAILED && strstr(v.status, "too warm") && strstr(v.status, "Nothing was moved") && f.plans == 0 && h.unwraps == 0);
    finish_screen(s);

    fake_init(&f);
    summary_json(f.summary.text, sizeof(f.summary.text), true, "", true, 4);
    s = screen_over(&f, &w, &h);
    assert(wss_begin_sweep(s));
    drain(&h);
    assert(view_of(s).state == WS_WAITING && strstr(view_of(s).status, "4 blocks behind") && f.plans == 0);
    wss_tap_cancel(s);
    drain(&h);
    finish_screen(s);
    printf("  the send gate stops the plan\n");
}

static void check_commit_busy(void)
{
    struct wss_view v = view_of(current);
    char line[WSS_LINE];
    assert(v.state == WS_COMMIT && wss_send_busy(v.state) && wss_in_flight(current));
    assert(wss_progress(current, line, sizeof(line)) &&
           !strcmp(line, "Sending 0.1 ZCL to your private balance: building the transaction (about 2 min)"));
    assert(!strcmp(v.status, "Moving your funds. This can take about two minutes on this phone.") && !v.can_cancel);
}
static void check_auth_busy(void)
{
    struct wss_view v = view_of(current);
    assert(v.state == WS_AUTH && wss_send_busy(v.state) && !strcmp(v.status, "Confirm with your screen lock to make your public funds private."));
}
/* From the tap to the answer a sweep is a payment in flight: the stop guard and the Show private balance relock read this. */
static void a_sweep_in_flight_is_busy(void)
{
    struct fake f; struct wsw w; struct host h;
    fake_init(&f);
    f.on_commit = check_commit_busy;
    struct wss *s = at_review(&f, &w, &h);
    h.on_unwrap = check_auth_busy;
    assert(!wss_send_busy(view_of(s).state) && !wss_in_flight(s));
    tap_through(s, &h);
    assert(view_of(s).state == WS_DONE && !wss_send_busy(WS_DONE) && !wss_in_flight(s) && f.commits == 1 && h.unwraps == 1);
    finish_screen(s);
    assert(wss_send_busy(WS_AUTH) && wss_send_busy(WS_COMMIT) && wss_send_busy(WS_BROADCAST) && !wss_send_busy(WS_REVIEW));
    printf("  a sweep in flight is busy\n");
}

/* One flow at a time: a sweep neither replaces a flow that has not ended nor is replaced by one, and nothing edits it. */
static void one_flow_at_a_time(void)
{
    struct fake f; struct wsw w; struct host h;
    fake_init(&f);
    struct wss *s = at_review(&f, &w, &h);
    uint32_t serial = view_of(s).serial;
    assert(!wss_begin_sweep(s));
    struct zapp_payment p;
    assert(zapp_payment_parse("zclassic:" TO "?amount=1.25", strlen("zclassic:" TO "?amount=1.25"), ZAPP_PAY_MAINNET, &p) == ZAPP_PAY_OK);
    assert(!wss_begin(s, &p));
    wss_edit_amount(s, 5);
    wss_edit_address(s, TO);
    wss_edit_memo(s, "hi", 2);
    drain(&h);
    assert(view_of(s).state == WS_REVIEW && view_of(s).serial == serial && f.plans == 1);
    wss_tap_cancel(s);
    drain(&h);
    assert(wss_begin_sweep(s));   /* once it has ended, the next begins */
    drain(&h);
    assert(view_of(s).state == WS_REVIEW && f.plans == 2);
    finish_screen(s);

    fake_init(&f);
    s = screen_over(&f, &w, &h);
    assert(wss_begin(s, &p) && !wss_begin_sweep(s));
    wss_tap_cancel(s);
    drain(&h);
    finish_screen(s);
    printf("  one flow at a time, and a sweep cannot be edited\n");
}

/* Every review of a sweep has its own key. */
static void each_review_has_its_own_key(void)
{
    struct fake f; struct wsw w; struct host h;
    char first[WS_KEY_HEX + 1], second[WS_KEY_HEX + 1];
    fake_init(&f);
    struct wss *s = at_review(&f, &w, &h);
    key_of(f.plan_input, first);
    wss_tap_cancel(s);
    drain(&h);
    assert(wss_begin_sweep(s));
    drain(&h);
    key_of(f.plan_input, second);
    assert(strcmp(first, second) && strlen(first) == WS_KEY_HEX && strlen(second) == WS_KEY_HEX);
    finish_screen(s);
    printf("  each review has its own key\n");
}

/* ---- the node adapter alone ---- */

static struct wss_commit_info last_info;
static struct wss_send_req sweep_request(void)
{
    struct wss_send_req req = {.sweep = true};
    snprintf(req.key, sizeof(req.key), "0123456789abcdef0123456789abcdef");
    return req;
}
static enum wss_commit_outcome commit_with(const char *reply, bool ran)
{
    struct fake f; struct wsw w; struct wss_node_ops ops;
    struct wss_send_req req = sweep_request();
    struct ws_plan plan;
    char echo[WS_TOKEN_MAX];
    fake_init(&f);
    wsw_init(&w, &(struct wsn_runner){&f, run, paused}, ZAPP_PAY_MAINNET);
    wsw_ops(&w, &ops);
    assert(ops.plan(ops.ctx, &req, &plan) && plan.total_zat == 10000000ull && plan.amount_zat == 9990000ull && plan.fee_zat == 10000ull);
    req.fee_zat = plan.fee_zat;
    snprintf(req.plan_token, sizeof(req.plan_token), "%s", plan.token);
    say(&f.commit, ran, reply);
    enum wss_commit_outcome out = ops.commit(ops.ctx, &req, echo, &last_info);
    assert(f.commits == 1);
    return out;
}
static enum wss_commit_outcome commit_code(const char *code)
{
    char text[WSN_REPLY_MAX];
    error_json(text, sizeof(text), code);
    return commit_with(text, false);
}
/* The commit codes of the shield command, as the screen reads them. */
static void commit_codes_are_pinned(void)
{
    assert(commit_code("NOTHING_TO_SHIELD") == WSS_KEY_RELEASED && last_info.why == WS_WHY_NOTHING);
    assert(commit_code("NO_PRIVATE_ADDRESS") == WSS_KEY_RELEASED && last_info.why == WS_WHY_NO_ADDRESS);
    assert(commit_code("PROVING_UNAVAILABLE") == WSS_KEY_RELEASED && last_info.why == WS_WHY_NO_PROVER);
    assert(commit_code("PLAN_TOKEN_MISMATCH") == WSS_FEE_CHANGED && last_info.why == WS_WHY_CHANGED);
    assert(commit_code("SEND_REFUSED_KEY_RELEASED") == WSS_KEY_RELEASED && last_info.why == WS_WHY_NONE);
    assert(commit_code("FEE_CHANGED") == WSS_FEE_CHANGED && last_info.why == WS_WHY_NONE);
    static const char *const unknown[] = {"WALLET_RPC_ERROR", "SEND_IN_PROGRESS", "SEND_OUTCOME_UNKNOWN", "IDEMPOTENCY_KEY_REUSED",
        "PLAN_REQUIRED", "MISSING_IDEMPOTENCY_KEY", "INVALID_IDEMPOTENCY_KEY", "SHIELDED_SEND_FAILED", "nothing_to_shield", ""};
    for (size_t i = 0; i < sizeof(unknown) / sizeof(unknown[0]); ++i) assert(commit_code(unknown[i]) == WSS_UNKNOWN);
    char text[WSN_REPLY_MAX];
    committed_json(text, sizeof(text), false);
    assert(commit_with(text, true) == WSS_COMMITTED && !last_info.replayed && strlen(last_info.txid) == WS_TXID_MAX - 1);
    /* A replay echoes no token; it is the answer to the commit that was sent. */
    committed_json(text, sizeof(text), true);
    assert(commit_with(text, true) == WSS_COMMITTED && last_info.replayed && strlen(last_info.txid) == WS_TXID_MAX - 1);
    assert(commit_with(text, false) == WSS_COMMITTED);   /* a node that answered before the process was killed still answered */
    /* A fresh commit that does not echo its token is unknown, not committed. */
    assert(commit_with("{\"ok\":true,\"data\":{\"committed\":true,\"replayed\":false}}", true) == WSS_UNKNOWN);
    printf("  commit codes are pinned\n");
}

/* A commit for a plan this adapter did not make, an older plan or another fee reaches no node call. */
static void commit_needs_its_own_plan(void)
{
    struct fake f; struct wsw w; struct wss_node_ops ops;
    struct wss_send_req req = sweep_request();
    struct ws_plan plan;
    char echo[WS_TOKEN_MAX];
    struct wss_commit_info info;
    fake_init(&f);
    wsw_init(&w, &(struct wsn_runner){&f, run, paused}, ZAPP_PAY_MAINNET);
    wsw_ops(&w, &ops);
    snprintf(req.plan_token, sizeof(req.plan_token), "%s", TOKEN);
    req.fee_zat = 10000;
    assert(ops.commit(ops.ctx, &req, echo, &info) == WSS_FEE_CHANGED && f.commits == 0 && info.why == WS_WHY_CHANGED);   /* no plan yet */
    assert(ops.plan(ops.ctx, &req, &plan));
    snprintf(req.plan_token, sizeof(req.plan_token), "fedcba9876543210");
    assert(ops.commit(ops.ctx, &req, echo, &info) == WSS_FEE_CHANGED && f.commits == 0);
    snprintf(req.plan_token, sizeof(req.plan_token), "%s", plan.token);
    req.fee_zat = 20000;
    assert(ops.commit(ops.ctx, &req, echo, &info) == WSS_FEE_CHANGED && f.commits == 0);
    req.fee_zat = plan.fee_zat;
    assert(ops.commit(ops.ctx, &req, echo, &info) == WSS_COMMITTED && f.commits == 1);
    /* A refused plan forgets the earlier one. */
    say(&f.plan, true, "garbage");
    assert(!ops.plan(ops.ctx, &req, &plan));
    assert(ops.commit(ops.ctx, &req, echo, &info) == WSS_FEE_CHANGED && f.commits == 1);
    printf("  a commit needs the plan of this adapter\n");
}

/* A request that is not a sweep goes to the payment adapter, and a sweep never reaches its payment calls. */
static void payments_pass_through(void)
{
    struct fake f; struct wsw w; struct wss_node_ops ops;
    struct wss_send_req req = {0};
    struct ws_plan plan;
    fake_init(&f);
    wsw_init(&w, &(struct wsn_runner){&f, run, paused}, ZAPP_PAY_MAINNET);
    wsw_ops(&w, &ops);
    snprintf(req.address, sizeof(req.address), "%s", TO);
    req.amount_zat = 125000000ull;
    assert(!ops.plan(ops.ctx, &req, &plan));   /* the payment adapter reads the sender first, and the fake has none */
    assert(!strcmp(f.calls, "a") && f.plans == 0);
    assert(ops.read_gate && ops.lock && ops.unlock && ops.validate_address && ops.route);
    printf("  payments keep their own adapter\n");
}

int main(void)
{
    plan_review_auth_commit_done();
    notes_for_coins_left();
    cancel_at_review();
    declined_auth_then_retry();
    refused_then_replayed();
    refusals_by_code();
    unknown_commit_is_final();
    plan_refusals();
    the_send_gate_stops_the_plan();
    a_sweep_in_flight_is_busy();
    one_flow_at_a_time();
    each_review_has_its_own_key();
    commit_codes_are_pinned();
    commit_needs_its_own_plan();
    payments_pass_through();
    puts("wallet_sweep_test: ok");
    return 0;
}

/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "wallet_send.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_STEPS 400000u
#define HISTORY 4096

static char priv[ZAPP_PAY_ADDRESS_MAX], priv2[ZAPP_PAY_ADDRESS_MAX], pub[ZAPP_PAY_ADDRESS_MAX];

struct rnd { uint64_t s; };
static uint64_t next64(struct rnd *r)
{
    uint64_t z = (r->s += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}
static bool fake_random(void *ctx, uint8_t *out, size_t len)
{
    struct rnd *r = ctx;
    for (size_t i = 0; i < len; ++i) out[i] = (uint8_t)next64(r);
    return true;
}
static bool no_random(void *ctx, uint8_t *out, size_t len) { (void)ctx; (void)out; (void)len; return false; }

struct world {
    struct ws ws;
    struct rnd rnd;
    struct ws_actions acts;
    enum ws_action_kind hist[HISTORY];
    size_t hist_n;
    uint64_t now;
};
static void world_init(struct world *w, uint64_t seed)
{
    memset(w, 0, sizeof(*w));
    w->rnd.s = seed;
    w->now = 1000;
}
static struct ws_env env_of(struct world *w) { return (struct ws_env){ZAPP_PAY_MAINNET, &w->rnd, fake_random}; }
static void record(struct world *w)
{
    for (size_t i = 0; i < w->acts.count; ++i)
        if (w->hist_n < HISTORY) w->hist[w->hist_n++] = w->acts.item[i].kind;
}
static struct ws_event E(enum ws_event_kind kind) { struct ws_event e = {0}; e.kind = kind; return e; }
static void feed(struct world *w, struct ws_event e)
{
    if (!e.now_ms) e.now_ms = w->now;
    ws_step(&w->ws, &e, &w->acts);
    record(w);
}
static size_t count(const struct world *w, enum ws_action_kind kind)
{
    size_t n = 0;
    for (size_t i = 0; i < w->hist_n; ++i) n += w->hist[i] == kind;
    return n;
}
static bool emitted(const struct world *w, enum ws_action_kind kind)
{
    for (size_t i = 0; i < w->acts.count; ++i)
        if (w->acts.item[i].kind == kind) return true;
    return false;
}
static struct zapp_payment pay_of(const char *address, const char *tail)
{
    char text[ZAPP_PAY_INPUT_MAX];
    struct zapp_payment p;
    snprintf(text, sizeof(text), "zclassic:%s%s", address, tail);
    assert(zapp_payment_parse(text, strlen(text), ZAPP_PAY_MAINNET, &p) == ZAPP_PAY_OK);
    return p;
}
static struct ws_gate good_gate(void)
{
    return (struct ws_gate){.known = true, .send_allowed = true, .spendable_zat = 500000000u, .public_zat = 100000000u};
}
static struct ws_event gate_ev(struct world *w, struct ws_gate g)
{
    struct ws_event e = E(WS_EV_GATE);
    e.ticket = w->ws.ticket;
    e.gate = g;
    return e;
}
static struct ws_event plan_ev(struct world *w, uint64_t fee)
{
    struct ws_event e = E(WS_EV_PLAN);
    e.ticket = w->ws.ticket;
    e.ok = true;
    e.plan.amount_zat = w->ws.pay.amount_zat;
    e.plan.fee_zat = fee;
    e.plan.total_zat = w->ws.pay.amount_zat + fee;
    snprintf(e.plan.token, sizeof(e.plan.token), "tok%u", (unsigned)w->ws.seq);
    return e;
}
static struct ws_event tk_ev(struct world *w, enum ws_event_kind kind, bool ok)
{
    struct ws_event e = E(kind);
    e.ticket = w->ws.ticket;
    e.ok = ok;
    return e;
}
static struct ws_event unlock_ev(struct world *w, bool ok, enum ws_auth_result why)
{
    struct ws_event e = E(WS_EV_UNLOCK);
    e.ticket = w->ws.ticket;
    e.ok = ok;
    e.auth = why;
    return e;
}
static struct ws_event tap_ev(const struct world *w)
{
    struct ws_event e = E(WS_EV_TAP_SEND);
    e.serial = ws_serial(&w->ws);
    return e;
}
static void to_review_with(struct world *w, const struct zapp_payment *p, struct ws_gate g)
{
    struct ws_env env = env_of(w);
    ws_open(&w->ws, &env, p, w->now, &w->acts);
    record(w);
    assert(w->ws.state == WS_VALIDATING && emitted(w, WS_ACT_VALIDATE_ADDRESS));
    feed(w, tk_ev(w, WS_EV_ADDRESS, true));
    assert(w->ws.state == WS_GATE && emitted(w, WS_ACT_READ_GATE));
    feed(w, gate_ev(w, g));
    if (w->ws.state != WS_PLAN) return;
    /* The key exists before the plan is requested: the node binds it into the plan token. */
    assert(emitted(w, WS_ACT_PLAN) && strlen(w->ws.key) == WS_KEY_HEX);
    feed(w, plan_ev(w, 10000));
}
static void to_review(struct world *w, const struct zapp_payment *p)
{
    to_review_with(w, p, good_gate());
    assert(w->ws.state == WS_REVIEW && ws_can_send(&w->ws));
}
/* Review, tap, authentication and unlock together: stops on the commit action. */
static void to_commit(struct world *w, const struct zapp_payment *p)
{
    to_review(w, p);
    feed(w, tap_ev(w));
    assert(w->ws.state == WS_AUTH && emitted(w, WS_ACT_UNLOCK));
    feed(w, unlock_ev(w, true, WS_AUTH_OK));
    assert(w->ws.state == WS_COMMIT && emitted(w, WS_ACT_COMMIT));
}
static void commit_answer(struct world *w, bool ok, bool refused)
{
    struct ws_event c = tk_ev(w, WS_EV_COMMIT, ok);
    c.refused = refused;
    memcpy(c.plan.token, w->ws.plan.token, sizeof(c.plan.token));
    feed(w, c);
}
static void lock_ok(struct world *w)
{
    struct ws_event l = E(WS_EV_LOCK); l.ticket = w->ws.lock_ticket; l.ok = true;
    feed(w, l);
}

/* ---- directed tests ---- */

static void happy_path(void)
{
    struct world w; world_init(&w, 1);
    struct zapp_payment p = pay_of(priv, "?amount=1.5&memo=aGk");
    to_review(&w, &p);
    assert(count(&w, WS_ACT_COMMIT) == 0 && count(&w, WS_ACT_UNLOCK) == 0);
    assert(w.ws.plan.fee_zat == 10000 && strlen(w.ws.key) == WS_KEY_HEX);
    feed(&w, tap_ev(&w));
    assert(count(&w, WS_ACT_UNLOCK) == 1 && count(&w, WS_ACT_COMMIT) == 0);
    feed(&w, unlock_ev(&w, true, WS_AUTH_OK));
    assert(count(&w, WS_ACT_COMMIT) == 1 && ws_wallet_exposed(&w.ws));
    commit_answer(&w, true, false);
    assert(w.ws.state == WS_BROADCAST && emitted(&w, WS_ACT_LOCK) && emitted(&w, WS_ACT_POLL_ROUTE));
    lock_ok(&w);
    assert(!ws_wallet_exposed(&w.ws));
    struct ws_event r = tk_ev(&w, WS_EV_ROUTE, true); r.route = WS_ROUTE_WAITING;
    feed(&w, r);
    assert(w.ws.state == WS_BROADCAST);
    w.now += 4000; struct ws_event t = E(WS_EV_TICK); t.now_ms = w.now; feed(&w, t);
    assert(emitted(&w, WS_ACT_POLL_ROUTE));
    r = tk_ev(&w, WS_EV_ROUTE, true); r.route = WS_ROUTE_SENT;
    feed(&w, r);
    assert(w.ws.state == WS_DONE && ws_terminal(&w.ws));
}
static void scan_opens_review_only(void)
{
    struct world w; world_init(&w, 2);
    struct zapp_payment p = pay_of(priv, "?amount=2");
    to_review_with(&w, &p, good_gate());
    assert(w.ws.state == WS_REVIEW);
    assert(count(&w, WS_ACT_UNLOCK) + count(&w, WS_ACT_COMMIT) == 0);
    struct zapp_payment bare = pay_of(priv, "");
    struct ws_env env = env_of(&w);
    ws_open(&w.ws, &env, &bare, w.now, &w.acts);
    assert(w.ws.state == WS_PARSED && w.acts.count == 0);
    struct ws_event e = E(WS_EV_SET_AMOUNT); e.amount_zat = 0;
    feed(&w, e); assert(w.ws.state == WS_PARSED);
    e.amount_zat = ZAPP_PAY_MAX_ZAT + 1; feed(&w, e); assert(w.ws.state == WS_PARSED);
    e.amount_zat = 150000000; feed(&w, e);
    assert(w.ws.state == WS_VALIDATING && emitted(&w, WS_ACT_VALIDATE_ADDRESS));
}
static void tap_must_match_review(void)
{
    struct world w; world_init(&w, 3);
    struct zapp_payment p = pay_of(priv, "?amount=1");
    to_review(&w, &p);
    struct ws_event t = tap_ev(&w); t.serial++;
    feed(&w, t);
    assert(w.ws.state == WS_REVIEW && w.acts.count == 0);
    t.serial = ws_serial(&w.ws) - 1; feed(&w, t);
    assert(w.ws.state == WS_REVIEW);
    /* an unlock or commit answer without a tap does nothing */
    feed(&w, unlock_ev(&w, true, WS_AUTH_OK));
    assert(w.ws.state == WS_REVIEW && count(&w, WS_ACT_COMMIT) == 0);
    feed(&w, tk_ev(&w, WS_EV_COMMIT, true));
    assert(count(&w, WS_ACT_COMMIT) == 0 && w.ws.state == WS_REVIEW);
}
static void authentication_is_required(void)
{
    struct world w; world_init(&w, 4);
    struct zapp_payment p = pay_of(priv, "?amount=1");
    to_review(&w, &p);
    feed(&w, tap_ev(&w));
    /* a commit answer cannot skip the authentication and unlock */
    feed(&w, tk_ev(&w, WS_EV_COMMIT, true));
    assert(w.ws.state == WS_AUTH && count(&w, WS_ACT_COMMIT) == 0);
    feed(&w, unlock_ev(&w, false, WS_AUTH_DECLINED));
    assert(w.ws.state == WS_FAILED && w.ws.fail == WS_FAIL_AUTH_DECLINED && w.ws.retry_ok);
    assert(count(&w, WS_ACT_COMMIT) == 0 && emitted(&w, WS_ACT_LOCK));
    /* every send asks for its own authentication: a second tap makes a second unlock action */
    lock_ok(&w);
    feed(&w, E(WS_EV_RETRY));
    assert(w.ws.state == WS_REVIEW);
    feed(&w, tap_ev(&w));
    assert(emitted(&w, WS_ACT_UNLOCK) && count(&w, WS_ACT_UNLOCK) == 2);
}
static void edits_need_a_new_review(void)
{
    struct world w; world_init(&w, 5);
    struct zapp_payment p = pay_of(priv, "?amount=1&memo=aGk");
    to_review(&w, &p);
    char key[WS_KEY_HEX + 1]; memcpy(key, w.ws.key, sizeof(key));
    uint32_t old = ws_serial(&w.ws);
    struct ws_event e = E(WS_EV_SET_AMOUNT); e.amount_zat = 250000000;
    feed(&w, e);
    assert(w.ws.state == WS_VALIDATING && w.ws.pay.amount_zat == 250000000 && ws_serial(&w.ws) != old);
    assert(!w.ws.tapped && !w.ws.key[0]);
    struct ws_event t = E(WS_EV_TAP_SEND); t.serial = old;
    feed(&w, t); assert(w.ws.state == WS_VALIDATING);
    feed(&w, tk_ev(&w, WS_EV_ADDRESS, true)); feed(&w, gate_ev(&w, good_gate())); feed(&w, plan_ev(&w, 10000));
    assert(w.ws.state == WS_REVIEW && memcmp(key, w.ws.key, sizeof(key)) != 0);
    feed(&w, t); assert(w.ws.state == WS_REVIEW);
    /* address */
    e = E(WS_EV_SET_ADDRESS); snprintf(e.text, sizeof(e.text), "%s", priv2);
    feed(&w, e); assert(w.ws.state == WS_VALIDATING && !strcmp(w.ws.pay.address, priv2));
    feed(&w, tk_ev(&w, WS_EV_ADDRESS, true)); feed(&w, gate_ev(&w, good_gate())); feed(&w, plan_ev(&w, 10000));
    /* memo */
    e = E(WS_EV_SET_MEMO); memcpy(e.text, "thanks", 6); e.text_len = 6;
    feed(&w, e); assert(w.ws.state == WS_VALIDATING && w.ws.pay.memo_len == 6);
    feed(&w, tk_ev(&w, WS_EV_ADDRESS, true)); feed(&w, gate_ev(&w, good_gate())); feed(&w, plan_ev(&w, 10000));
    assert(w.ws.state == WS_REVIEW && count(&w, WS_ACT_COMMIT) == 0);
    /* a public address cannot take a memo, and an address that is not one changes nothing */
    e = E(WS_EV_SET_ADDRESS); snprintf(e.text, sizeof(e.text), "%s", pub);
    feed(&w, e); assert(w.ws.state == WS_REVIEW && !strcmp(w.ws.pay.address, priv2));
    e = E(WS_EV_SET_ADDRESS); snprintf(e.text, sizeof(e.text), "hello");
    feed(&w, e); assert(w.ws.state == WS_REVIEW);
}
static void no_edit_once_authenticating(void)
{
    struct world w; world_init(&w, 6);
    struct zapp_payment p = pay_of(priv, "?amount=1");
    to_review(&w, &p);
    feed(&w, tap_ev(&w));
    struct ws_event e = E(WS_EV_SET_AMOUNT); e.amount_zat = 450000000;
    feed(&w, e);
    assert(w.ws.state == WS_AUTH && w.ws.pay.amount_zat == 100000000);
    e = E(WS_EV_SET_ADDRESS); snprintf(e.text, sizeof(e.text), "%s", priv2);
    feed(&w, e);
    e = E(WS_EV_SET_MEMO); memcpy(e.text, "x", 1); e.text_len = 1;
    feed(&w, e);
    assert(w.ws.state == WS_AUTH && !strcmp(w.ws.pay.address, priv) && w.ws.pay.amount_zat == 100000000 && !w.ws.pay.memo_len);
    feed(&w, unlock_ev(&w, true, WS_AUTH_OK));
    assert(w.ws.state == WS_COMMIT);
}
/* A refused commit proves that nothing was sent, so the same review can try again on the same key. */
static void refused_commit_retries_on_the_same_key(void)
{
    struct world w; world_init(&w, 7);
    struct zapp_payment p = pay_of(priv, "?amount=1");
    to_review(&w, &p);
    char key[WS_KEY_HEX + 1]; memcpy(key, w.ws.key, sizeof(key));
    for (int attempt = 0; attempt < 3; ++attempt) {
        feed(&w, tap_ev(&w));
        feed(&w, unlock_ev(&w, true, WS_AUTH_OK));
        assert(w.ws.state == WS_COMMIT);
        commit_answer(&w, false, true);
        assert(w.ws.state == WS_FAILED && w.ws.fail == WS_FAIL_COMMIT_REFUSED && emitted(&w, WS_ACT_LOCK));
        lock_ok(&w);
        feed(&w, E(WS_EV_RETRY));
        assert(w.ws.state == WS_REVIEW && !w.ws.tapped && !memcmp(key, w.ws.key, sizeof(key)));
        assert(count(&w, WS_ACT_COMMIT) == (size_t)attempt + 1);
    }
    /* a retry is not a payment: the owner must tap again */
    assert(w.acts.count == 0);
    /* a fresh review has its own key */
    struct world v; world_init(&v, 7);
    to_review(&v, &p);
    char first[WS_KEY_HEX + 1]; memcpy(first, v.ws.key, sizeof(first));
    to_review(&v, &p);
    assert(memcmp(first, v.ws.key, sizeof(first)) != 0);
}
/* Finding 1: a commit with no usable answer may have been sent. It is final: no retry, no second commit. */
static void unknown_commit_is_final(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    for (int how = 0; how < 3; ++how) {
        struct world w; world_init(&w, 70 + (uint64_t)how);
        to_commit(&w, &p);
        if (how == 0) commit_answer(&w, false, false);     /* no answer */
        else if (how == 1) {                               /* an answer for a different plan */
            struct ws_event c = tk_ev(&w, WS_EV_COMMIT, true); snprintf(c.plan.token, sizeof(c.plan.token), "other");
            feed(&w, c);
        } else {                                           /* an answer with no token */
            feed(&w, tk_ev(&w, WS_EV_COMMIT, true));
        }
        assert(w.ws.state == WS_FAILED && w.ws.fail == WS_FAIL_COMMIT_UNKNOWN && !w.ws.retry_ok);
        assert(emitted(&w, WS_ACT_LOCK) && strstr(ws_fail_text(&w.ws), "History"));
        lock_ok(&w);
        feed(&w, E(WS_EV_RETRY));
        assert(w.ws.state == WS_FAILED && w.acts.count == 0);
        feed(&w, tap_ev(&w));
        assert(w.ws.state == WS_FAILED && w.acts.count == 0 && !ws_can_send(&w.ws));
        feed(&w, E(WS_EV_CANCEL));
        assert(w.ws.state == WS_FAILED && count(&w, WS_ACT_COMMIT) == 1 && count(&w, WS_ACT_UNLOCK) == 1);
    }
}
static void gate_refusals(void)
{
    struct world w; world_init(&w, 8);
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct ws_gate g = good_gate();
    g.send_allowed = false;
    snprintf(g.blocked_reason, sizeof(g.blocked_reason), "History is still being checked.");
    to_review_with(&w, &p, g);
    assert(w.ws.state == WS_FAILED && w.ws.fail == WS_FAIL_BLOCKED && !strcmp(ws_fail_text(&w.ws), "History is still being checked."));
    assert(count(&w, WS_ACT_PLAN) == 0);
    g = good_gate(); g.send_allowed = false;
    to_review_with(&w, &p, g);
    assert(w.ws.state == WS_FAILED && ws_fail_text(&w.ws)[0] && count(&w, WS_ACT_PLAN) == 0);
    g = good_gate(); g.thermal_paused = true; g.send_allowed = false;
    to_review_with(&w, &p, g);
    assert(w.ws.fail == WS_FAIL_THERMAL && strstr(ws_fail_text(&w.ws), "too warm"));
    g = (struct ws_gate){0};
    to_review_with(&w, &p, g);
    assert(w.ws.fail == WS_FAIL_STATE_UNKNOWN);
    /* a wallet behind the chain waits, reads again, and goes on once it has caught up */
    g = good_gate(); g.blocks_behind = 12; g.send_allowed = false;
    struct ws_env env = env_of(&w);
    ws_open(&w.ws, &env, &p, w.now, &w.acts);
    feed(&w, tk_ev(&w, WS_EV_ADDRESS, true));
    feed(&w, gate_ev(&w, g));
    assert(w.ws.state == WS_WAITING && w.acts.count == 0);
    w.now += 6000; struct ws_event t = E(WS_EV_TICK); t.now_ms = w.now;
    feed(&w, t); assert(emitted(&w, WS_ACT_READ_GATE));
    feed(&w, gate_ev(&w, good_gate()));
    assert(w.ws.state == WS_PLAN);
    /* an address the node refuses stops the flow before anything else */
    ws_open(&w.ws, &env, &p, w.now, &w.acts);
    feed(&w, tk_ev(&w, WS_EV_ADDRESS, false));
    assert(w.ws.fail == WS_FAIL_ADDRESS && !emitted(&w, WS_ACT_READ_GATE));
    /* a plan that disagrees with the request is refused */
    ws_open(&w.ws, &env, &p, w.now, &w.acts);
    feed(&w, tk_ev(&w, WS_EV_ADDRESS, true)); feed(&w, gate_ev(&w, good_gate()));
    struct ws_event pl = plan_ev(&w, 10000); pl.plan.amount_zat += 1; pl.plan.total_zat += 1;
    feed(&w, pl);
    assert(w.ws.fail == WS_FAIL_PLAN);
    /* no random source: no key, so no plan is asked for and no review */
    struct ws_env bad = {ZAPP_PAY_MAINNET, NULL, no_random};
    ws_open(&w.ws, &bad, &p, w.now, &w.acts);
    feed(&w, tk_ev(&w, WS_EV_ADDRESS, true)); feed(&w, gate_ev(&w, good_gate()));
    assert(w.ws.fail == WS_FAIL_NO_RANDOM && !w.ws.key[0] && !emitted(&w, WS_ACT_PLAN) && w.ws.state == WS_FAILED);
}
static void insufficient_private_funds(void)
{
    struct world w; world_init(&w, 10);
    struct zapp_payment p = pay_of(priv, "?amount=4.9999");
    struct ws_gate g = good_gate(); g.spendable_zat = 100000000; g.public_zat = 900000000;
    to_review_with(&w, &p, g);
    assert(w.ws.state == WS_REVIEW && w.ws.insufficient && !ws_can_send(&w.ws));
    feed(&w, tap_ev(&w));
    assert(w.ws.state == WS_REVIEW && count(&w, WS_ACT_UNLOCK) == 0);
    feed(&w, E(WS_EV_MAKE_PRIVATE));
    assert(emitted(&w, WS_ACT_OPEN_MAKE_PRIVATE) && w.ws.state == WS_CANCELLED && count(&w, WS_ACT_COMMIT) == 0);
    /* without public funds there is nothing to offer */
    g.public_zat = 0;
    to_review_with(&w, &p, g);
    feed(&w, E(WS_EV_MAKE_PRIVATE));
    assert(w.ws.state == WS_REVIEW && !emitted(&w, WS_ACT_OPEN_MAKE_PRIVATE));
}
static void every_exit_locks(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct world w;
    /* unlock fails */
    world_init(&w, 11); to_review(&w, &p);
    feed(&w, tap_ev(&w));
    feed(&w, unlock_ev(&w, false, WS_AUTH_OK));
    assert(w.ws.state == WS_FAILED && w.ws.fail == WS_FAIL_UNLOCK && emitted(&w, WS_ACT_LOCK) && ws_wallet_exposed(&w.ws));
    lock_ok(&w); assert(!ws_wallet_exposed(&w.ws));
    /* the owner declined the prompt */
    world_init(&w, 12); to_review(&w, &p);
    feed(&w, tap_ev(&w));
    feed(&w, unlock_ev(&w, false, WS_AUTH_DECLINED));
    assert(w.ws.fail == WS_FAIL_AUTH_DECLINED && emitted(&w, WS_ACT_LOCK));
    /* the node refuses the commit */
    world_init(&w, 13); to_commit(&w, &p);
    commit_answer(&w, false, true);
    assert(w.ws.fail == WS_FAIL_COMMIT_REFUSED && emitted(&w, WS_ACT_LOCK));
    /* the node answers a different plan */
    world_init(&w, 14); to_commit(&w, &p);
    struct ws_event c = tk_ev(&w, WS_EV_COMMIT, true); snprintf(c.plan.token, sizeof(c.plan.token), "other");
    feed(&w, c);
    assert(w.ws.state == WS_FAILED && emitted(&w, WS_ACT_LOCK));
    /* a send that finishes locks right after the commit, before the route is known */
    world_init(&w, 18); to_commit(&w, &p);
    commit_answer(&w, true, false);
    assert(emitted(&w, WS_ACT_LOCK) && w.ws.state == WS_BROADCAST);
}
/* A running commit is not failed by the clock. It stays until the answer arrives, however long the proof
 * takes, and the lock follows the answer at once. */
static void a_running_commit_outlasts_the_clock(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct world w;
    world_init(&w, 15); to_commit(&w, &p);
    struct ws_event t = E(WS_EV_TICK); t.now_ms = w.ws.unlock_ms + WS_UNLOCK_WINDOW_MS - 1;
    feed(&w, t); assert(w.ws.state == WS_COMMIT && w.acts.count == 0);
    t.now_ms = w.ws.unlock_ms + WS_UNLOCK_WINDOW_MS;
    feed(&w, t); assert(w.ws.state == WS_COMMIT && w.acts.count == 0);
    t.now_ms = w.ws.unlock_ms + 10 * WS_UNLOCK_WINDOW_MS;
    feed(&w, t); assert(w.ws.state == WS_COMMIT && w.acts.count == 0 && count(&w, WS_ACT_LOCK) == 0);
    commit_answer(&w, true, false);
    assert(w.ws.state == WS_BROADCAST && emitted(&w, WS_ACT_LOCK));
    assert(WS_UNLOCK_SECONDS == 300 && WS_UNLOCK_WINDOW_MS == 300000);
}
static void the_window_and_the_lock_retry(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct world w;
    struct ws_event t = E(WS_EV_TICK);
    /* the window ends while the owner is still at the prompt */
    world_init(&w, 16); to_review(&w, &p);
    feed(&w, tap_ev(&w));
    t.now_ms = w.ws.unlock_ms + WS_UNLOCK_WINDOW_MS; feed(&w, t);
    assert(w.ws.fail == WS_FAIL_WINDOW && emitted(&w, WS_ACT_LOCK));
    /* a lock that fails is asked for again, three times in all, and again when the clock says so */
    world_init(&w, 17); to_commit(&w, &p);
    commit_answer(&w, false, true);
    for (int i = 0; i < 2; ++i) {
        struct ws_event l = E(WS_EV_LOCK); l.ticket = w.ws.lock_ticket; l.ok = false;
        feed(&w, l); assert(emitted(&w, WS_ACT_LOCK));
    }
    struct ws_event l = E(WS_EV_LOCK); l.ticket = w.ws.lock_ticket; l.ok = false;
    feed(&w, l); assert(!emitted(&w, WS_ACT_LOCK) && ws_wallet_exposed(&w.ws) && count(&w, WS_ACT_LOCK) == 3);
    t.now_ms = w.ws.lock_ms + WS_LOCK_RETRY_MS - 1; feed(&w, t); assert(!emitted(&w, WS_ACT_LOCK));
    t.now_ms = w.ws.lock_ms + WS_LOCK_RETRY_MS; feed(&w, t); assert(emitted(&w, WS_ACT_LOCK) && count(&w, WS_ACT_LOCK) == 4);
    /* a lock answer for a stale ticket changes nothing */
    l.ticket = w.ws.lock_ticket + 5; l.ok = true; feed(&w, l);
    assert(ws_wallet_exposed(&w.ws));
}
/* Finding 6: while a lock is owed no tap is accepted, so a late lock answer can never be taken for the
 * lock of a newer unlock. */
static void no_tap_while_a_lock_is_owed(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct world w; world_init(&w, 19);
    to_commit(&w, &p);
    commit_answer(&w, false, true);                       /* queue: lock L1 */
    struct ws_event l = E(WS_EV_LOCK); l.ticket = w.ws.lock_ticket; l.ok = false;
    feed(&w, l);                                          /* L1 failed, L2 asked */
    assert(emitted(&w, WS_ACT_LOCK) && w.ws.lock_wanted);
    feed(&w, E(WS_EV_RETRY));
    assert(w.ws.state == WS_REVIEW && !ws_can_send(&w.ws));
    size_t unlocks = count(&w, WS_ACT_UNLOCK);
    feed(&w, tap_ev(&w));
    assert(w.ws.state == WS_REVIEW && w.acts.count == 0 && count(&w, WS_ACT_UNLOCK) == unlocks);
    lock_ok(&w);                                          /* L2 confirmed */
    assert(!ws_wallet_exposed(&w.ws) && ws_can_send(&w.ws));
    feed(&w, tap_ev(&w));
    assert(w.ws.state == WS_AUTH && count(&w, WS_ACT_UNLOCK) == unlocks + 1 && ws_wallet_exposed(&w.ws));
    /* a second flow opened while a lock is owed waits for it too */
    struct world v; world_init(&v, 29);
    to_commit(&v, &p);
    commit_answer(&v, false, true);
    to_review_with(&v, &p, good_gate());
    assert(v.ws.state == WS_REVIEW && v.ws.lock_wanted && !ws_can_send(&v.ws));
    feed(&v, tap_ev(&v));
    assert(v.ws.state == WS_REVIEW && v.acts.count == 0);
}
static void leaving_the_app(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct world w;
    world_init(&w, 20); to_review(&w, &p);
    feed(&w, E(WS_EV_BACKGROUND));
    assert(w.ws.state == WS_CANCELLED && count(&w, WS_ACT_COMMIT) == 0);
    feed(&w, tap_ev(&w)); assert(w.ws.state == WS_CANCELLED);
    /* the system prompt backgrounds the app: that is not leaving, and the answer still belongs to the tap */
    world_init(&w, 21); to_review(&w, &p);
    feed(&w, tap_ev(&w)); feed(&w, E(WS_EV_BACKGROUND)); feed(&w, E(WS_EV_RESUME));
    assert(w.ws.state == WS_AUTH);
    feed(&w, unlock_ev(&w, true, WS_AUTH_OK));
    assert(w.ws.state == WS_COMMIT);
    /* the owner cancels at the prompt: the wallet is locked and a late unlock answer commits nothing */
    world_init(&w, 22); to_review(&w, &p);
    feed(&w, tap_ev(&w)); uint32_t keep = w.ws.ticket;
    feed(&w, E(WS_EV_CANCEL));
    assert(w.ws.state == WS_CANCELLED && emitted(&w, WS_ACT_LOCK));
    struct ws_event late = unlock_ev(&w, true, WS_AUTH_OK); late.ticket = keep;
    feed(&w, late);
    assert(w.ws.state == WS_CANCELLED && count(&w, WS_ACT_COMMIT) == 0);
    /* once the commit runs the send goes on and cannot be cancelled */
    world_init(&w, 26); to_commit(&w, &p);
    feed(&w, E(WS_EV_BACKGROUND)); feed(&w, E(WS_EV_CANCEL));
    assert(w.ws.state == WS_COMMIT && w.acts.count == 0);
    /* a key that is gone is final */
    world_init(&w, 27); to_review(&w, &p);
    feed(&w, tap_ev(&w)); feed(&w, unlock_ev(&w, false, WS_AUTH_KEY_GONE));
    assert(w.ws.fail == WS_FAIL_KEY_GONE && !w.ws.retry_ok);
    feed(&w, E(WS_EV_RETRY)); assert(w.ws.state == WS_FAILED);
}
static void stale_events_are_ignored(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct world w; world_init(&w, 30);
    struct ws_env env = env_of(&w);
    ws_open(&w.ws, &env, &p, w.now, &w.acts);
    struct ws_event e = tk_ev(&w, WS_EV_ADDRESS, true); e.ticket += 1;
    feed(&w, e); assert(w.ws.state == WS_VALIDATING);
    e = tk_ev(&w, WS_EV_PLAN, true); feed(&w, e); assert(w.ws.state == WS_VALIDATING);
    feed(&w, tk_ev(&w, WS_EV_ADDRESS, true));
    e = gate_ev(&w, good_gate()); e.ticket += 7; feed(&w, e); assert(w.ws.state == WS_GATE);
    /* a plan quoted for an earlier amount never reaches the review */
    feed(&w, gate_ev(&w, good_gate()));
    struct ws_event pl = plan_ev(&w, 10000);
    struct ws_event edit = E(WS_EV_SET_AMOUNT); edit.amount_zat = 200000000;
    feed(&w, edit);
    feed(&w, pl);
    assert(w.ws.state == WS_VALIDATING);
}
static void public_destination(void)
{
    struct zapp_payment p = pay_of(pub, "?amount=1");
    assert(p.kind == ZAPP_PAY_PUBLIC);
    struct world w; world_init(&w, 31);
    to_review(&w, &p);
    assert(w.ws.pay.kind == ZAPP_PAY_PUBLIC);
}
/* ---- deterministic random event sequences ---- */

struct model {
    uint32_t tap_serial, unlocked_serial;
    struct zapp_payment pay;
    char key[WS_KEY_HEX + 1];
    char token[WS_TOKEN_MAX];
    char last_key[WS_KEY_HEX + 1];
    char commit_key[WS_KEY_HEX + 1];  /* The key of the latest commit action. */
    bool commit_refused;              /* The node proved that commit sent nothing. */
    bool owed;                        /* An unlock action was issued and no lock is confirmed since. */
    bool lock_asked;                  /* A lock action was issued since that unlock. */
};
struct tally { size_t steps, taps, auths, unlocks, commits, locks, retries, done, failed, cancelled, reviews,
                      unknown, same_key_commits, blocked_taps, owed_ends; };

static unsigned pick(struct rnd *r, unsigned n) { return (unsigned)(next64(r) % n); }
static bool chance(struct rnd *r, unsigned percent) { return pick(r, 100) < percent; }
static struct ws_gate random_gate(struct rnd *r)
{
    struct ws_gate g = {.known = chance(r, 96), .send_allowed = chance(r, 92), .thermal_paused = chance(r, 3),
                        .blocks_behind = chance(r, 5) ? pick(r, 40) : 0};
    g.spendable_zat = chance(r, 15) ? 1000 : 300000000u + pick(r, 300000000u);
    g.public_zat = chance(r, 50) ? 0 : 50000000u;
    snprintf(g.blocked_reason, sizeof(g.blocked_reason), "blocked %u", pick(r, 9));
    return g;
}
static uint32_t pick_ticket(const struct world *w, struct rnd *r, bool lock)
{
    unsigned roll = pick(r, 100);
    if (roll < 75) return lock ? w->ws.lock_ticket : w->ws.ticket;
    if (roll < 85) return lock ? w->ws.ticket : w->ws.lock_ticket;
    return pick(r, w->ws.seq + 4);
}
/* The answer a working world would give to what the machine waits for. */
static struct ws_event guided(struct world *w, struct rnd *r)
{
    struct ws_event e = E(WS_EV_TICK);
    e.ticket = w->ws.ticket;
    e.now_ms = w->now;
    switch (w->ws.state) {
    case WS_VALIDATING: e.kind = WS_EV_ADDRESS; e.ok = chance(r, 92); break;
    case WS_GATE: case WS_WAITING: e.kind = WS_EV_GATE; e.gate = random_gate(r); break;
    case WS_PLAN:
        e = plan_ev(w, 1000 + pick(r, 20000)); e.ok = chance(r, 95); e.now_ms = w->now; break;
    case WS_REVIEW:
        e.kind = WS_EV_TAP_SEND; e.serial = chance(r, 85) ? w->ws.serial : w->ws.serial - pick(r, 3); break;
    case WS_AUTH:
        e.kind = WS_EV_UNLOCK; e.ok = chance(r, 80); e.auth = chance(r, 80) ? WS_AUTH_OK : (enum ws_auth_result)(1 + pick(r, 2)); break;
    case WS_COMMIT:
        e.kind = WS_EV_COMMIT; e.ok = chance(r, 60); e.refused = chance(r, 50);
        if (chance(r, 90)) memcpy(e.plan.token, w->ws.plan.token, sizeof(e.plan.token));
        break;
    case WS_BROADCAST: e.kind = WS_EV_ROUTE; e.route = chance(r, 60) ? WS_ROUTE_SENT : WS_ROUTE_WAITING; break;
    case WS_FAILED: e.kind = WS_EV_RETRY; break;
    default: break;
    }
    return e;
}
static struct ws_event noise(struct world *w, struct rnd *r)
{
    static const char *const addrs[] = {priv, priv2, pub, "hello", ""};
    struct ws_event e = E((enum ws_event_kind)pick(r, WS_EV_TICK + 1));
    e.ticket = pick_ticket(w, r, e.kind == WS_EV_LOCK);
    e.serial = chance(r, 70) ? w->ws.serial : pick(r, w->ws.serial + 3);
    e.ok = chance(r, 70); e.refused = chance(r, 30);
    e.auth = (enum ws_auth_result)pick(r, 3);
    e.route = (enum ws_route)pick(r, 2);
    e.gate = random_gate(r);
    e.plan = plan_ev(w, 1000 + pick(r, 20000)).plan;
    if (chance(r, 20)) e.plan.amount_zat += 1;
    e.amount_zat = chance(r, 15) ? 0 : 1 + pick(r, 900000000u);
    snprintf(e.text, sizeof(e.text), "%s", addrs[pick(r, 5)]);
    if (e.kind == WS_EV_SET_MEMO) { e.text_len = pick(r, 40); memset(e.text, 'm', e.text_len); }
    e.now_ms = chance(r, 5) ? w->now + pick(r, 130000) : 0;
    return e;
}
static struct zapp_payment random_payment(struct rnd *r)
{
    static const char *const tails[] = {"?amount=1.5", "", "?amount=0.5&memo=aGk", "?amount=3"};
    const char *address = pick(r, 4) == 0 ? pub : (pick(r, 2) ? priv : priv2);
    const char *tail = tails[pick(r, 4)];
    if (address == pub && strstr(tail, "memo")) tail = "?amount=2";
    return pay_of(address, tail);
}
static bool same_payment(const struct zapp_payment *a, const struct zapp_payment *b)
{
    return !strcmp(a->address, b->address) && a->kind == b->kind && a->has_amount == b->has_amount &&
           a->amount_zat == b->amount_zat && a->memo_len == b->memo_len && !memcmp(a->memo, b->memo, a->memo_len);
}
static void model_tap(struct model *m, struct tally *t, const struct ws *pre, const struct ws_event *e,
                      const struct world *w)
{
    const struct ws *post = &w->ws;
    bool tap_accepts = e->kind == WS_EV_TAP_SEND && pre->state == WS_REVIEW && !pre->insufficient &&
                       pre->plan.token[0] && e->serial == pre->serial;
    if (tap_accepts && pre->lock_wanted) {
        /* A lock is owed: the tap is refused whole. */
        assert(post->state == WS_REVIEW && w->acts.count == 0);
        t->blocked_taps++;
    } else if (tap_accepts) {
        assert(post->state == WS_AUTH);
        m->tap_serial = pre->serial; m->unlocked_serial = 0; m->pay = pre->pay;
        memcpy(m->key, pre->key, sizeof(m->key)); memcpy(m->token, pre->plan.token, sizeof(m->token));
        t->taps++;
    }
    if (e->kind == WS_EV_UNLOCK && pre->state == WS_AUTH && e->ticket == pre->ticket && e->ok &&
        m->tap_serial == pre->serial) { m->unlocked_serial = pre->serial; t->auths++; }
}
static void model_answers(struct model *m, struct tally *t, const struct ws *pre, const struct ws_event *e,
                          const struct world *w)
{
    const struct ws *post = &w->ws;
    /* Commit once: a key is committed a second time only after the node proved the first sent nothing. */
    if (e->kind == WS_EV_COMMIT && pre->state == WS_COMMIT && e->ticket == pre->ticket) {
        if (!e->ok && e->refused) m->commit_refused = true;
        if (post->state == WS_FAILED && post->fail == WS_FAIL_COMMIT_UNKNOWN) t->unknown++;
    }
}
/* An unknown commit is not retried, and a confirmed lock closes the debt of the unlock before it. */
static void model_lock(struct model *m, const struct ws *pre, const struct ws_event *e, const struct world *w)
{
    if (e->kind == WS_EV_RETRY && pre->state == WS_FAILED && pre->fail == WS_FAIL_COMMIT_UNKNOWN)
        assert(w->ws.state == WS_FAILED && w->acts.count == 0);
    if (e->kind == WS_EV_LOCK && e->ok && pre->lock_wanted && e->ticket == pre->lock_ticket) m->owed = false;
}
static void model_action(struct model *m, struct tally *t, const struct ws *post, enum ws_action_kind k)
{
    if (k == WS_ACT_UNLOCK || k == WS_ACT_COMMIT) {
        /* The only way to the node's spend: a tap on this review, then this review's authentication. */
        assert(m->tap_serial && m->tap_serial == post->serial);
        assert(same_payment(&post->pay, &m->pay) && !strcmp(post->key, m->key));
    }
    if (k == WS_ACT_COMMIT) {
        assert(m->unlocked_serial == post->serial && !strcmp(post->plan.token, m->token));
        assert(post->pay.amount_zat == post->plan.amount_zat);
        if (!strcmp(post->key, m->commit_key)) { assert(m->commit_refused); t->same_key_commits++; }
        memcpy(m->commit_key, post->key, sizeof(m->commit_key));
        m->commit_refused = false;
        t->commits++; m->tap_serial = m->unlocked_serial = 0;
    }
    if (k == WS_ACT_UNLOCK) {
        /* No unlock while an earlier one is not confirmed locked again. */
        assert(!m->owed);
        m->owed = true; m->lock_asked = false;
        t->unlocks++;
    }
    if (k == WS_ACT_LOCK) { t->locks++; m->lock_asked = true; }
}
static void model_tail(struct model *m, struct tally *t, const struct ws *post)
{
    assert(ws_wallet_exposed(post) == m->owed);
    if (ws_terminal(post) && m->owed) { assert(m->lock_asked && post->lock_wanted); t->owed_ends++; }
    if (post->serial != m->tap_serial || !same_payment(&post->pay, &m->pay)) m->tap_serial = m->unlocked_serial = 0;
}
static void model_counts(struct model *m, struct tally *t, const struct ws *pre, const struct ws_event *e,
                         const struct ws *post)
{
    if (e->kind == WS_EV_RETRY && pre->state == WS_FAILED && post->state == WS_REVIEW) {
        assert(!strcmp(pre->key, post->key) && pre->key[0] && !post->tapped);
        t->retries++;
    }
    if (pre->state == WS_PLAN && post->state == WS_REVIEW) {
        assert(strcmp(post->key, m->last_key) != 0 && strlen(post->key) == WS_KEY_HEX);
        memcpy(m->last_key, post->key, sizeof(m->last_key));
        t->reviews++;
    }
    if (post->state == WS_DONE && pre->state != WS_DONE) t->done++;
    if (post->state == WS_FAILED && pre->state != WS_FAILED) t->failed++;
    if (post->state == WS_CANCELLED && pre->state != WS_CANCELLED) t->cancelled++;
}
/* What the node would see: the commit and unlock actions. The invariants are stated on the actions alone,
 * from the model's own bookkeeping. */
static void model_after(struct model *m, struct tally *t, const struct ws *pre, const struct ws_event *e,
                        const struct world *w)
{
    model_tap(m, t, pre, e, w);
    model_answers(m, t, pre, e, w);
    model_lock(m, pre, e, w);
    for (size_t i = 0; i < w->acts.count; ++i) model_action(m, t, &w->ws, w->acts.item[i].kind);
    model_tail(m, t, &w->ws);
    model_counts(m, t, pre, e, &w->ws);
}

static void fuzz(uint64_t seed, size_t steps, struct tally *t)
{
    struct world w; world_init(&w, seed);
    struct rnd r = {seed * 7919u + 13u};
    struct model m = {0};
    struct zapp_payment p = random_payment(&r);
    struct ws_env env = env_of(&w);
    ws_open(&w.ws, &env, &p, w.now, &w.acts);
    for (size_t i = 0; i < steps; ++i) {
        struct ws_event e;
        w.now += pick(&r, 700);
        if (ws_terminal(&w.ws) && chance(&r, 40)) {
            p = random_payment(&r);
            ws_open(&w.ws, &env, &p, w.now, &w.acts);
            record(&w);
            m.tap_serial = m.unlocked_serial = 0;
            continue;
        }
        bool want_lock = w.ws.lock_wanted && w.ws.unlock_requested;
        if (want_lock && chance(&r, 45)) { e = E(WS_EV_LOCK); e.ticket = w.ws.lock_ticket; e.ok = chance(&r, 70); }
        else e = chance(&r, 60) ? guided(&w, &r) : noise(&w, &r);
        if (!e.now_ms) e.now_ms = w.now;
        struct ws pre = w.ws;
        ws_step(&w.ws, &e, &w.acts);
        model_after(&m, t, &pre, &e, &w);
        t->steps++;
    }
}
static void random_sequences(void)
{
    struct tally t = {0};
    for (uint64_t seed = 1; seed <= 4; ++seed) fuzz(seed, FUZZ_STEPS / 4, &t);
    assert(t.steps >= 100000);
    /* the sequences must reach the dangerous ground, or the invariants say nothing */
    assert(t.taps > 500 && t.auths > 300 && t.unlocks > 200 && t.commits > 100 && t.locks > 200);
    assert(t.retries > 20 && t.done > 20 && t.failed > 200 && t.cancelled > 50 && t.reviews > 1000);
    assert(t.unknown > 10 && t.same_key_commits > 5 && t.blocked_taps > 5 && t.owed_ends > 20);
    printf("wallet_send_test: %zu random steps, %zu reviews, %zu taps, %zu authentications, %zu commits "
           "(%zu on a key whose earlier commit was refused, %zu unknown and final), %zu locks, %zu taps refused "
           "while a lock was owed, %zu retries, %zu done: no commit without tap then authentication on the same plan, "
           "no key committed twice unless refused, no unlock while a lock is owed\n",
           t.steps, t.reviews, t.taps, t.auths, t.commits, t.same_key_commits, t.unknown, t.locks, t.blocked_taps,
           t.retries, t.done);
}

 int main(int argc, char **argv)
{
    memcpy(priv, "zs1", 3); memset(priv + 3, 'q', 75); priv[78] = 0;
    memcpy(priv2, "zs1", 3); memset(priv2 + 3, 'p', 75); priv2[78] = 0;
    memcpy(pub, "t1", 2); memset(pub + 2, '2', 33); pub[35] = 0;
    /* "random" runs only the random event sequences. */
    if (argc > 1 && !strcmp(argv[1], "random")) { random_sequences(); return 0; }
    happy_path();
    scan_opens_review_only();
    tap_must_match_review();
    authentication_is_required();
    edits_need_a_new_review();
    no_edit_once_authenticating();
    refused_commit_retries_on_the_same_key();
    unknown_commit_is_final();
    gate_refusals();
    insufficient_private_funds();
    every_exit_locks();
    a_running_commit_outlasts_the_clock();
    the_window_and_the_lock_retry();
    no_tap_while_a_lock_is_owed();
    leaving_the_app();
    stale_events_are_ignored();
    public_destination();
    random_sequences();
    puts("wallet_send_test: directed ok");
    return 0;
}

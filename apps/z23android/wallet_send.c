/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "wallet_send.h"
#include <string.h>

#define WS_GATE_REFRESH_MS 10000u
#define WS_ROUTE_POLL_MS 3000u

static void push(struct ws_actions *out, enum ws_action_kind kind, uint32_t ticket)
{
    if (out->count < WS_ACTIONS_MAX) out->item[out->count++] = (struct ws_action){kind, ticket};
}
static void enter(struct ws *ws, enum ws_state state)
{
    ws->state = state;
    ws->state_ms = ws->now_ms;
}
/* Issues the next ticket for an action whose answer the current state waits for. */
static void ask(struct ws *ws, struct ws_actions *out, enum ws_action_kind kind)
{
    ws->ticket = ++ws->seq;
    push(out, kind, ws->ticket);
}
static void ask_lock(struct ws *ws, struct ws_actions *out)
{
    if (!ws->unlock_requested) return;
    ws->lock_wanted = true;
    ws->lock_ticket = ++ws->seq;
    push(out, WS_ACT_LOCK, ws->lock_ticket);
}
/* Ends the flow in state, locking the wallet when an unlock was ever asked for. */
static void finish(struct ws *ws, struct ws_actions *out, enum ws_state state, enum ws_fail fail, bool retry)
{
    enter(ws, state);
    ws->fail = fail;
    ws->retry_ok = retry;
    ws->tapped = false;
    ws->ticket = ++ws->seq;
    ask_lock(ws, out);
}
static void clear_review(struct ws *ws)
{
    memset(&ws->plan, 0, sizeof(ws->plan));
    memset(ws->key, 0, sizeof(ws->key));
    ws->tapped = false;
    ws->insufficient = false;
    ws->fail = WS_FAIL_NONE;
    ws->retry_ok = false;
}
/* A new review: every earlier tap, plan and key is void. */
static void begin_validation(struct ws *ws, struct ws_actions *out)
{
    clear_review(ws);
    ws->serial++;
    enter(ws, WS_VALIDATING);
    ask(ws, out, WS_ACT_VALIDATE_ADDRESS);
}
void ws_open(struct ws *ws, const struct ws_env *env, const struct zapp_payment *pay, uint64_t now_ms,
             struct ws_actions *out)
{
    uint32_t seq = ws->seq, serial = ws->serial, lock_ticket = ws->lock_ticket;
    unsigned attempts = ws->lock_attempts;
    bool exposed = ws->unlock_requested, wanted = ws->lock_wanted;
    memset(ws, 0, sizeof(*ws));
    memset(out, 0, sizeof(*out));
    ws->env = *env;
    ws->pay = *pay;
    ws->seq = seq;
    ws->serial = serial + 1;
    /* A lock the earlier flow still owes outlives it. */
    ws->unlock_requested = exposed;
    ws->lock_wanted = wanted;
    ws->lock_ticket = lock_ticket;
    ws->lock_attempts = attempts;
    ws->now_ms = now_ms;
    if (!pay->has_amount) { enter(ws, WS_PARSED); return; }
    begin_validation(ws, out);
}

static bool new_key(struct ws *ws)
{
    static const char hex[] = "0123456789abcdef";
    uint8_t raw[WS_KEY_HEX / 2];
    if (!ws->env.random || !ws->env.random(ws->env.ctx, raw, sizeof(raw))) return false;
    for (size_t i = 0; i < sizeof(raw); ++i) {
        ws->key[2 * i] = hex[raw[i] >> 4];
        ws->key[2 * i + 1] = hex[raw[i] & 15];
    }
    ws->key[WS_KEY_HEX] = 0;
    memset(raw, 0, sizeof(raw));
    return true;
}

/* ---- gate ---- */

static void copy_reason(struct ws *ws, const char *reason)
{
    size_t n = 0;
    for (; reason && reason[n] && n + 1 < sizeof(ws->blocked); ++n) {
        unsigned char c = (unsigned char)reason[n];
        ws->blocked[n] = c < 0x20 || c == 0x7f ? ' ' : (char)c;
    }
    ws->blocked[n] = 0;
}
static void on_gate(struct ws *ws, const struct ws_event *ev, struct ws_actions *out)
{
    bool fresh = ws->state == WS_GATE || ws->state == WS_WAITING;
    if (!fresh && ws->state != WS_REVIEW) return;
    if (ev->ticket != ws->ticket) return;
    const struct ws_gate *g = &ev->gate;
    if (!g->known) { finish(ws, out, WS_FAILED, WS_FAIL_STATE_UNKNOWN, true); return; }
    if (g->thermal_paused) { finish(ws, out, WS_FAILED, WS_FAIL_THERMAL, true); return; }
    if (g->blocks_behind > 0) {
        if (ws->state == WS_REVIEW) {
            copy_reason(ws, "The wallet is behind the chain. Try again when it is up to date.");
            finish(ws, out, WS_FAILED, WS_FAIL_BLOCKED, true);
            return;
        }
        ws->gate = *g;
        enter(ws, WS_WAITING);
        return;
    }
    if (!g->send_allowed) {
        copy_reason(ws, g->blocked_reason);
        finish(ws, out, WS_FAILED, WS_FAIL_BLOCKED, true);
        return;
    }
    if (!fresh) { ws->gate_ms = ws->now_ms; return; }
    ws->gate = *g;
    /* The node binds the key into the plan token, so the key exists before the plan is asked for. */
    if (!new_key(ws)) { finish(ws, out, WS_FAILED, WS_FAIL_NO_RANDOM, false); return; }
    enter(ws, WS_PLAN);
    ask(ws, out, WS_ACT_PLAN);
}

/* ---- plan and review ---- */

static bool plan_matches(const struct ws *ws, const struct ws_plan *p)
{
    return p->token[0] && memchr(p->token, 0, sizeof(p->token)) && p->amount_zat == ws->pay.amount_zat &&
           p->total_zat == p->amount_zat + p->fee_zat && p->total_zat >= p->amount_zat;
}
static void on_plan(struct ws *ws, const struct ws_event *ev, struct ws_actions *out)
{
    if (ws->state != WS_PLAN || ev->ticket != ws->ticket) return;
    if (!ev->ok || !plan_matches(ws, &ev->plan)) { finish(ws, out, WS_FAILED, WS_FAIL_PLAN, true); return; }
    ws->plan = ev->plan;
    ws->serial++;
    ws->tapped = false;
    ws->insufficient = ws->plan.total_zat > ws->gate.spendable_zat;
    ws->gate_ms = ws->now_ms;
    ws->ticket = ++ws->seq;
    enter(ws, WS_REVIEW);
}
bool ws_can_send(const struct ws *ws)
{
    return ws->state == WS_REVIEW && !ws->insufficient && !ws->lock_wanted && ws->plan.token[0] && ws->key[0];
}
static void on_tap(struct ws *ws, const struct ws_event *ev, struct ws_actions *out)
{
    if (!ws_can_send(ws) || ev->serial != ws->serial) return;
    ws->tapped = true;
    ws->unlock_requested = true;
    ws->unlock_ms = ws->now_ms;
    enter(ws, WS_AUTH);
    ask(ws, out, WS_ACT_UNLOCK);
}
static void on_make_private(struct ws *ws, struct ws_actions *out)
{
    if (ws->state != WS_REVIEW || !ws->insufficient || ws->gate.public_zat == 0) return;
    enter(ws, WS_CANCELLED);
    ws->fail = WS_FAIL_NONE;
    ws->tapped = false;
    ws->ticket = ++ws->seq;
    push(out, WS_ACT_OPEN_MAKE_PRIVATE, ws->ticket);
}

/* ---- authentication, unlock, commit ---- */

/* The answer of the one operation that authenticates the owner for this use, unwraps the secret and
 * unlocks the wallet. An earlier authentication never counts: there is no other path to the secret. */
static void on_unlock(struct ws *ws, const struct ws_event *ev, struct ws_actions *out)
{
    if (ws->state != WS_AUTH || ev->ticket != ws->ticket) return;
    if (!ev->ok) {
        if (ev->auth == WS_AUTH_KEY_GONE) finish(ws, out, WS_FAILED, WS_FAIL_KEY_GONE, false);
        else finish(ws, out, WS_FAILED, ev->auth == WS_AUTH_DECLINED ? WS_FAIL_AUTH_DECLINED : WS_FAIL_UNLOCK, true);
        return;
    }
    if (!ws->tapped) { finish(ws, out, WS_CANCELLED, WS_FAIL_NONE, false); return; }
    ws->tapped = false;
    enter(ws, WS_COMMIT);
    ask(ws, out, WS_ACT_COMMIT);
}
static void on_commit(struct ws *ws, const struct ws_event *ev, struct ws_actions *out)
{
    if (ws->state != WS_COMMIT || ev->ticket != ws->ticket) return;
    if (ev->ok && strncmp(ev->plan.token, ws->plan.token, sizeof(ws->plan.token)) == 0) {
        ask_lock(ws, out);
        enter(ws, WS_BROADCAST);
        ask(ws, out, WS_ACT_POLL_ROUTE);
        return;
    }
    /* Only a refusal proves that nothing was sent. Any other answer leaves the payment possibly sent, so the
     * flow ends for good: no retry, no second commit for this review. */
    if (!ev->ok && ev->refused) finish(ws, out, WS_FAILED, WS_FAIL_COMMIT_REFUSED, true);
    else finish(ws, out, WS_FAILED, WS_FAIL_COMMIT_UNKNOWN, false);
}
static void on_route(struct ws *ws, const struct ws_event *ev)
{
    if (ws->state != WS_BROADCAST || ev->ticket != ws->ticket) return;
    if (ev->route == WS_ROUTE_SENT) enter(ws, WS_DONE);
}
static void on_lock(struct ws *ws, const struct ws_event *ev, struct ws_actions *out)
{
    if (!ws->lock_wanted || ev->ticket != ws->lock_ticket) return;
    if (ev->ok) { ws->unlock_requested = false; ws->lock_wanted = false; ws->lock_attempts = 0; return; }
    ws->lock_ms = ws->now_ms;
    if (++ws->lock_attempts < WS_LOCK_ATTEMPTS) ask_lock(ws, out);
}

/* ---- edits, retry, cancel, lifecycle ---- */

static bool editable(const struct ws *ws)
{
    switch (ws->state) {
    case WS_PARSED: case WS_VALIDATING: case WS_GATE: case WS_WAITING: case WS_PLAN: case WS_REVIEW: return true;
    default: return false;
    }
}
static void on_set_amount(struct ws *ws, const struct ws_event *ev, struct ws_actions *out)
{
    if (!editable(ws) || ev->amount_zat == 0 || ev->amount_zat > ZAPP_PAY_MAX_ZAT) return;
    ws->pay.has_amount = true;
    ws->pay.amount_zat = ev->amount_zat;
    begin_validation(ws, out);
}
static void on_set_address(struct ws *ws, const struct ws_event *ev, struct ws_actions *out)
{
    struct zapp_payment next;
    const char *end = memchr(ev->text, 0, sizeof(ev->text));
    size_t n = end ? (size_t)(end - ev->text) : sizeof(ev->text);
    if (!editable(ws)) return;
    if (zapp_payment_parse(ev->text, n, ws->env.network, &next) != ZAPP_PAY_OK) return;
    if (next.kind == ZAPP_PAY_PUBLIC && ws->pay.memo_len) return;
    memcpy(ws->pay.address, next.address, sizeof(ws->pay.address));
    ws->pay.kind = next.kind;
    if (ws->pay.has_amount) begin_validation(ws, out);
    else { ws->serial++; clear_review(ws); }
}
static void on_set_memo(struct ws *ws, const struct ws_event *ev, struct ws_actions *out)
{
    if (!editable(ws) || ev->text_len > ZAPP_PAY_MEMO_MAX) return;
    if (ws->pay.kind == ZAPP_PAY_PUBLIC && ev->text_len) return;
    memset(ws->pay.memo, 0, sizeof(ws->pay.memo));
    memcpy(ws->pay.memo, ev->text, ev->text_len);
    ws->pay.memo_len = ev->text_len;
    if (ws->pay.has_amount) begin_validation(ws, out);
    else { ws->serial++; clear_review(ws); }
}
static bool back_to_same_review(const struct ws *ws)
{
    switch (ws->fail) {
    case WS_FAIL_AUTH_DECLINED: case WS_FAIL_UNLOCK: case WS_FAIL_WINDOW: case WS_FAIL_COMMIT_REFUSED:
        return ws->plan.token[0] && ws->key[0];
    default: return false;
    }
}
static void on_retry(struct ws *ws, struct ws_actions *out)
{
    if (ws->state != WS_FAILED || !ws->retry_ok) return;
    if (back_to_same_review(ws)) {
        /* Same review, same plan, same key: a second attempt cannot pay twice. A new tap is required. */
        ws->tapped = false;
        ws->fail = WS_FAIL_NONE;
        ws->retry_ok = false;
        ws->serial++;
        ws->gate_ms = ws->now_ms;
        ws->ticket = ++ws->seq;
        enter(ws, WS_REVIEW);
        return;
    }
    if (ws->pay.has_amount) begin_validation(ws, out);
}
static void on_cancel(struct ws *ws, struct ws_actions *out)
{
    switch (ws->state) {
    case WS_COMMIT: case WS_BROADCAST: case WS_DONE: case WS_FAILED: case WS_CANCELLED: case WS_IDLE:
        return;
    default: finish(ws, out, WS_CANCELLED, WS_FAIL_NONE, false);
    }
}
/* The system credential screen backgrounds the app, so leaving during authentication is not a cancel: the
 * result belongs to the tap on this review. The owner can still cancel from the screen. */
static void on_background(struct ws *ws, struct ws_actions *out)
{
    if (ws->state == WS_AUTH) return;
    on_cancel(ws, out);
}

static void on_tick_window(struct ws *ws, struct ws_actions *out)
{
    if (!ws->unlock_requested || ws->lock_wanted || ws->now_ms - ws->unlock_ms < WS_UNLOCK_WINDOW_MS) return;
    /* A running commit is never failed here: the node may still broadcast, so only its answer ends it. */
    if (ws->state == WS_COMMIT) return;
    if (ws->state == WS_AUTH) finish(ws, out, WS_FAILED, WS_FAIL_WINDOW, true);
    else ask_lock(ws, out);
}
static void on_tick(struct ws *ws, struct ws_actions *out)
{
    on_tick_window(ws, out);
    /* A lock that kept failing is asked for again; the wallet may still be open. */
    if (ws->lock_wanted && ws->lock_attempts >= WS_LOCK_ATTEMPTS && ws->now_ms - ws->lock_ms >= WS_LOCK_RETRY_MS) {
        ws->lock_attempts = 0;
        ask_lock(ws, out);
    }
    if (ws->state == WS_WAITING && ws->now_ms - ws->state_ms >= WS_GATE_REFRESH_MS / 2) {
        ws->state_ms = ws->now_ms;
        ask(ws, out, WS_ACT_READ_GATE);
    } else if (ws->state == WS_REVIEW && ws->now_ms - ws->gate_ms >= WS_GATE_REFRESH_MS) {
        ws->gate_ms = ws->now_ms;
        ask(ws, out, WS_ACT_READ_GATE);
    } else if (ws->state == WS_BROADCAST && ws->now_ms - ws->state_ms >= WS_ROUTE_POLL_MS) {
        ws->state_ms = ws->now_ms;
        ask(ws, out, WS_ACT_POLL_ROUTE);
    }
}

/* Answers to what the machine asked for, and the owner's taps. */
static void step_answers(struct ws *ws, const struct ws_event *ev, struct ws_actions *out)
{
    switch (ev->kind) {
    case WS_EV_ADDRESS:
        if (ws->state != WS_VALIDATING || ev->ticket != ws->ticket) break;
        if (!ev->ok) { finish(ws, out, WS_FAILED, WS_FAIL_ADDRESS, true); break; }
        enter(ws, WS_GATE);
        ask(ws, out, WS_ACT_READ_GATE);
        break;
    case WS_EV_GATE: on_gate(ws, ev, out); break;
    case WS_EV_PLAN: on_plan(ws, ev, out); break;
    case WS_EV_TAP_SEND: on_tap(ws, ev, out); break;
    case WS_EV_MAKE_PRIVATE: on_make_private(ws, out); break;
    case WS_EV_UNLOCK: on_unlock(ws, ev, out); break;
    case WS_EV_COMMIT: on_commit(ws, ev, out); break;
    case WS_EV_ROUTE: on_route(ws, ev); break;
    case WS_EV_LOCK: on_lock(ws, ev, out); break;
    default: break;
    }
}
/* Edits, retry, cancel and the lifecycle of the screen. */
static void step_owner(struct ws *ws, const struct ws_event *ev, struct ws_actions *out)
{
    switch (ev->kind) {
    case WS_EV_SET_AMOUNT: on_set_amount(ws, ev, out); break;
    case WS_EV_SET_ADDRESS: on_set_address(ws, ev, out); break;
    case WS_EV_SET_MEMO: on_set_memo(ws, ev, out); break;
    case WS_EV_RETRY: on_retry(ws, out); break;
    case WS_EV_CANCEL: on_cancel(ws, out); break;
    case WS_EV_BACKGROUND: on_background(ws, out); break;
    case WS_EV_RESUME: break;
    case WS_EV_TICK: on_tick(ws, out); break;
    default: break;
    }
}
void ws_step(struct ws *ws, const struct ws_event *ev, struct ws_actions *out)
{
    memset(out, 0, sizeof(*out));
    if (ev->now_ms > ws->now_ms) ws->now_ms = ev->now_ms;
    step_answers(ws, ev, out);
    step_owner(ws, ev, out);
}

bool ws_terminal(const struct ws *ws)
{
    return ws->state == WS_DONE || ws->state == WS_FAILED || ws->state == WS_CANCELLED || ws->state == WS_IDLE;
}
bool ws_wallet_exposed(const struct ws *ws) { return ws->unlock_requested; }
uint32_t ws_serial(const struct ws *ws) { return ws->serial; }

const char *ws_fail_text(const struct ws *ws)
{
    switch (ws->fail) {
    case WS_FAIL_NONE: return "";
    case WS_FAIL_ADDRESS: return "The node does not accept this address. Nothing was sent.";
    case WS_FAIL_BLOCKED: return ws->blocked[0] ? ws->blocked : "Sending is not available right now. Nothing was sent.";
    case WS_FAIL_THERMAL: return "This phone is too warm, so the node is paused. Try again when it has cooled down. Nothing was sent.";
    case WS_FAIL_STATE_UNKNOWN: return "The wallet state could not be read. Nothing was sent.";
    case WS_FAIL_PLAN: return "The node could not prepare this payment. Nothing was sent.";
    case WS_FAIL_AUTH_DECLINED: return "Device authentication was not completed. Nothing was sent.";
    case WS_FAIL_KEY_GONE: return "The wallet key on this phone is gone. Restore the wallet from its recovery phrase.";
    case WS_FAIL_UNLOCK: return "The wallet could not be unlocked. Nothing was sent.";
    case WS_FAIL_WINDOW: return "The unlock time ended and the wallet is locked again. Nothing was sent.";
    case WS_FAIL_COMMIT_REFUSED: return "The node refused this payment. Nothing was sent.";
    case WS_FAIL_COMMIT_UNKNOWN: return "It is not known whether this payment was sent. It will not be sent again from here. Check History.";
    case WS_FAIL_NO_RANDOM: return "A payment key could not be made. Nothing was sent.";
    }
    return "";
}
const char *ws_state_name(enum ws_state state)
{
    static const char *const names[] = {"idle", "parsed", "validating", "gate", "waiting", "plan", "review",
        "auth", "commit", "broadcast", "done", "failed", "cancelled"};
    return (unsigned)state < sizeof(names) / sizeof(names[0]) ? names[state] : "unknown";
}

/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "wallet_send_screen.h"
#include "base/cleanse.h"
#include "wallet_screens.h"
#include "wallet_view.h"
#include "zutf8/zutf8.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QUEUE_MAX 16
#define PUBLIC_WARNING "This payment is public. The amount and address are visible to everyone, forever."
#define INSUFFICIENT_NOTE "Not enough private funds for this payment. Public funds are never used for it."
#define INSUFFICIENT_PUBLIC_NOTE INSUFFICIENT_NOTE " Public funds cannot be spent from this phone. Move them to your private balance from your fleet node."
#define FLEET_CHECKED "Checked by your fleet"
#define ALREADY_PAID "Already paid. Your node has this payment, so nothing new was sent."
#define SENT_TO_NODE "Sending privately. Waiting for an onion peer to carry it. You can leave this screen."
#define SWEEP_DONE "Done. It shows in your private balance after the next block."
#define SWEEP_REPLAYED "Done. This move was already made. It shows in your private balance after the next block."
#define MAX_FAILED "The node did not quote the fee, so Max set no amount. Enter an amount."
#define MAX_NONE "The fee is more than you have to send."

struct wss {
    pthread_mutex_t lock;
    struct wss_deps d;
    struct ws ws;
    struct ws_action queue[QUEUE_MAX];
    size_t queued;
    bool worker;
    bool dying;
    bool protected_window;
    bool begun;
    bool replayed; /* the node answered this payment's commit from its record of an earlier one */
    bool progress_seen; /* the owner dismissed the line of the ended payment; cleared when the next payment begins or runs */
    bool closed;   /* the owner left the flow's outcome and no later payment has begun */
    struct wss_unlock_buf unlock;
    bool unprotected;   /* the window protections are not in force: the payment is not shown */
    struct wss_send_req tapped;   /* The plan the owner tapped Send on; the commit is bound to it. */
    struct wss_balance balance;   /* the latest spendable reading */
    uint64_t balance_ms;          /* when it was taken */
    bool balance_wanted;          /* a reading is asked for and not yet started */
    bool balance_reading;         /* the worker is taking a reading */
    bool quoting, quote_wanted;   /* Max on the amount page waits for the node to quote the fee */
    uint32_t quote_serial;        /* the amount page the quote was asked on */
    char max_note[WSS_LINE];      /* why Max set no amount */
};

/* ---- formatting ---- */

void wss_format_zat(uint64_t zat, char *out, size_t cap)
{
    uint64_t whole = zat / 100000000u, frac = zat % 100000000u;
    char digits[16];
    snprintf(digits, sizeof(digits), "%08llu", (unsigned long long)frac);
    size_t n = strlen(digits);
    while (n && digits[n - 1] == '0') digits[--n] = 0;
    if (n) snprintf(out, cap, "%llu.%s ZCL", (unsigned long long)whole, digits);
    else snprintf(out, cap, "%llu ZCL", (unsigned long long)whole);
}
/* The memo is shown as data in its own field. memo is valid UTF-8, so every lead byte has its tail. */
static void fill_memo(const struct zapp_payment *pay, struct wss_view *v)
{
    v->memo_label[0] = v->memo[0] = 0;
    if (!pay->memo_len) return;
    const uint8_t *m = pay->memo;
    size_t len = pay->memo_len, o = 0;
    if (!zutf8_validate_n((const char *)m, len)) {
        snprintf(v->memo_label, sizeof(v->memo_label), "Memo (data)");
        snprintf(v->memo, sizeof(v->memo), "%zu bytes of data", len);
        return;
    }
    snprintf(v->memo_label, sizeof(v->memo_label), "Memo");
    for (size_t i = 0; i < len;) {
        size_t n = m[i] < 0x80 ? 1 : m[i] < 0xe0 ? 2 : m[i] < 0xf0 ? 3 : 4;
        uint32_t cp = n == 1 ? m[i] : m[i] & (0xffu >> (n + 1));
        for (size_t k = 1; k < n; ++k) cp = (cp << 6) | (m[i + k] & 0x3f);
        if (zapp_pay_cp_hidden(cp)) o += (size_t)snprintf(v->memo + o, sizeof(v->memo) - o, "<U+%04X>", (unsigned)cp);
        else { memcpy(v->memo + o, m + i, n); o += n; v->memo[o] = 0; }
        i += n;
    }
}
/* The review of a sweep, in plain words. The total leaves the public address; the private balance gains it less the fee. */
static void fill_sweep_review(const struct ws *ws, struct wss_view *v)
{
    char total[WSS_AMOUNT], arrives[WSS_AMOUNT], maturing[WSS_AMOUNT];
    v->review = true;
    wss_format_zat(ws->plan.total_zat, total, sizeof(total));
    wss_format_zat(ws->plan.fee_zat, v->fee, sizeof(v->fee));
    wss_format_zat(ws->plan.amount_zat, arrives, sizeof(arrives));
    snprintf(v->amount, sizeof(v->amount), "%s", total);
    snprintf(v->move, sizeof(v->move), "Move %s from your public address into your private balance. Fee %s.", total, v->fee);
    snprintf(v->arrives, sizeof(v->arrives), "%s arrives in your private balance.", arrives);
    if (ws->plan.remaining_inputs)
        snprintf(v->move_note, sizeof(v->move_note), "Some coins on this address are left for a later move. Tap Make private again after this one.");
    if (ws->plan.maturing_zat) {
        wss_format_zat(ws->plan.maturing_zat, maturing, sizeof(maturing));
        size_t used = strlen(v->move_note);
        snprintf(v->move_note + used, sizeof(v->move_note) - used, "%sMined coins of %s are still maturing and are not moved.", used ? " " : "", maturing);
    }
    snprintf(v->fleet, sizeof(v->fleet), "%s", ws->gate.fleet_checked ? FLEET_CHECKED : WALLET_FLEET_UNCHECKED);
}
static void fill_review(const struct ws *ws, struct wss_view *v)
{
    if (ws->sweep) { fill_sweep_review(ws, v); return; }
    v->review = true;
    wss_format_zat(ws->pay.amount_zat, v->amount, sizeof(v->amount));
    wss_format_zat(ws->plan.fee_zat, v->fee, sizeof(v->fee));
    if (!wallet_view_group_address(ws->pay.address, v->address, sizeof(v->address)))
        snprintf(v->address, sizeof(v->address), "Address cannot be shown");
    snprintf(v->kind, sizeof(v->kind), "%s", ws->pay.kind == ZAPP_PAY_PUBLIC ? "Public" : "Private");
    fill_memo(&ws->pay, v);
    snprintf(v->fleet, sizeof(v->fleet), "%s", ws->gate.fleet_checked ? FLEET_CHECKED : WALLET_FLEET_UNCHECKED);
    if (ws->pay.kind == ZAPP_PAY_PUBLIC) snprintf(v->warning, sizeof(v->warning), "%s", PUBLIC_WARNING);
    if (ws->insufficient) {
        snprintf(v->note, sizeof(v->note), "%s", ws->gate.public_zat > 0 ? INSUFFICIENT_PUBLIC_NOTE : INSUFFICIENT_NOTE);
        return;
    }
    wss_format_zat(ws->gate.spendable_zat - ws->plan.total_zat, v->remains, sizeof(v->remains));
}
/* The phone's local label of a time in seconds since the epoch, such as "Today 14:05"; empty when there is none or
 * the phone has no clock. */
static void format_confirmed(const struct wss *s, int64_t seconds, char *out, size_t cap)
{
    out[0] = 0;
    if (seconds > 0 && s->d.host.wall_s)
        wallet_time_label(s->d.host.wall_s(s->d.host.ctx), seconds, wallet_utc_offset(seconds), out, cap);
}
/* The two states a payment waits in: for the wallet to catch up, and, in review, for the wallet to lock. */
static void fill_hold_status(const struct ws *ws, struct wss_view *v)
{
    if (ws->state == WS_WAITING)
        snprintf(v->status, sizeof(v->status),
                 "The wallet is catching up with the chain, %u blocks behind. Sending waits until it is up to date.",
                 (unsigned)ws->gate.blocks_behind);
    else if (ws->lock_wanted)
        snprintf(v->status, sizeof(v->status), "Locking the wallet. Sending is possible again in a moment.");
}
/* The words of a sweep where they differ from a payment's. False for the states that read the same. */
static bool sweep_status(const struct ws *ws, struct wss_view *v)
{
    const char *text;
    switch (ws->state) {
    case WS_PLAN: text = "Looking at your public coins."; break;
    case WS_AUTH: text = "Confirm with your screen lock to make your public funds private."; break;
    case WS_COMMIT: text = "Moving your funds. This can take about two minutes on this phone."; break;
    case WS_DONE: text = SWEEP_DONE; break;
    case WS_PAID: text = SWEEP_REPLAYED; break;
    case WS_CANCELLED: text = "Cancelled. Nothing was moved."; break;
    default: return false;
    }
    snprintf(v->status, sizeof(v->status), "%s", text);
    return true;
}
static void payment_status(const struct ws *ws, struct wss_view *v)
{
    switch (ws->state) {
    case WS_PARSED: snprintf(v->status, sizeof(v->status), "Enter an amount to send."); break;
    case WS_VALIDATING: snprintf(v->status, sizeof(v->status), "Checking the address with your node."); break;
    case WS_GATE: snprintf(v->status, sizeof(v->status), "Checking the wallet."); break;
    case WS_WAITING:
    case WS_REVIEW: fill_hold_status(ws, v); break;
    case WS_PLAN: snprintf(v->status, sizeof(v->status), "Preparing the payment."); break;
    case WS_AUTH: snprintf(v->status, sizeof(v->status), "Confirm with your screen lock to send."); break;
    case WS_COMMIT:
        snprintf(v->status, sizeof(v->status), "Building the payment. This can take about two minutes on this phone.");
        break;
    case WS_BROADCAST: snprintf(v->status, sizeof(v->status), "%s", SENT_TO_NODE); break;
    case WS_DONE: snprintf(v->status, sizeof(v->status), "The payment left the phone. History shows it."); break;
    case WS_FAILED: snprintf(v->status, sizeof(v->status), "%s", ws_fail_text(ws)); break;
    case WS_CANCELLED: snprintf(v->status, sizeof(v->status), "Cancelled. Nothing was sent."); break;
    case WS_PAID: snprintf(v->status, sizeof(v->status), "%s", ALREADY_PAID); break;
    case WS_IDLE: break;
    }
}
static void fill_status(const struct ws *ws, struct wss_view *v)
{
    if (!ws->sweep || !sweep_status(ws, v)) payment_status(ws, v);
}
static bool is_busy(enum ws_state state)
{
    return state == WS_VALIDATING || state == WS_GATE || state == WS_PLAN || state == WS_AUTH || state == WS_COMMIT ||
           state == WS_BROADCAST || state == WS_WAITING;
}
/* The flow has nothing left to ask of the owner: it ended, or the node holds the payment and only History can say more. */
static bool flow_over(const struct ws *ws) { return ws_terminal(ws) || ws->state == WS_BROADCAST; }
static bool shows_review(enum ws_state state) { return state == WS_REVIEW || state == WS_AUTH || state == WS_COMMIT; }

/* ---- balance and Max ---- */

static uint64_t now_of(const struct wss *s) { return s->d.host.now_ms ? s->d.host.now_ms(s->d.host.ctx) : 0; }
/* Under the lock: whether the latest reading may still be shown. */
static bool balance_fresh(const struct wss *s)
{
    uint64_t now = now_of(s);
    return s->balance.known && (now < s->balance_ms || now - s->balance_ms <= WSS_BALANCE_FRESH_MS);
}
uint64_t wss_max_amount(uint64_t spendable_zat, uint64_t fee_zat) { return spendable_zat > fee_zat ? spendable_zat - fee_zat : 0; }
/* Under the lock: the amount Max gives on a review, from the balance and the fee of that review; 0 when it gives none. */
static uint64_t review_max(const struct ws *ws)
{
    if (ws->state != WS_REVIEW || ws->sweep || !ws->plan.token[0] || !ws->gate.known) return 0;
    uint64_t target = wss_max_amount(ws->gate.spendable_zat, ws->plan.fee_zat);
    return target != ws->pay.amount_zat ? target : 0;
}
/* The amount page: the address named, the balance and Max, or the quote Max waits for. */
static void fill_amount_page(const struct wss *s, struct wss_view *v)
{
    char amount[WSS_AMOUNT];
    v->focus = WSS_FOCUS_AMOUNT;
    if (!wallet_view_group_address(s->ws.pay.address, v->address, sizeof(v->address))) v->address[0] = 0;
    if (balance_fresh(s)) {
        wss_format_zat(s->balance.spendable_zat, amount, sizeof(amount));
        snprintf(v->available, sizeof(v->available), "Available: %s", amount);
    }
    v->can_max = balance_fresh(s) && s->balance.spendable_zat > 0 && !s->quoting;
    snprintf(v->note, sizeof(v->note), "%s", s->max_note);
    if (!s->quoting) return;
    v->busy = true;
    snprintf(v->status, sizeof(v->status), "Working out the most you can send.");
}
void wss_start_page(const struct wss_balance *balance, bool clip_holds_address, struct wss_start *out)
{
    memset(out, 0, sizeof(*out));
    out->zero = balance && balance->known && balance->spendable_zat == 0;
    if (out->zero) { snprintf(out->line, sizeof(out->line), "%s", WSS_ZERO_BALANCE); return; }
    out->paste = clip_holds_address;
    out->focus = WSS_FOCUS_ADDRESS;
}
bool wss_paste_offered(const char *clip, enum zapp_pay_network network)
{
    char text[ZAPP_PAY_INPUT_MAX + 1];
    struct zapp_payment pay;
    if (!clip || !memchr(clip, 0, sizeof(text))) return false;
    snprintf(text, sizeof(text), "%s", clip);
    wallet_view_trim_address(text);
    bool ok = text[0] && zapp_payment_parse(text, strlen(text), network, &pay) == ZAPP_PAY_OK;
    memory_cleanse(text, sizeof(text));
    memory_cleanse(&pay, sizeof(pay));
    return ok;
}
void wss_view(struct wss *s, struct wss_view *v)
{
    memset(v, 0, sizeof(*v));
    pthread_mutex_lock(&s->lock);
    const struct ws *ws = &s->ws;
    v->state = ws->state;
    if (!s->begun || s->unprotected) {
        snprintf(v->status, sizeof(v->status), "This screen could not be protected, so the payment is not shown.");
        pthread_mutex_unlock(&s->lock);
        return;
    }
    v->visible = true;
    v->serial = ws->serial;
    v->elapsed_s = ws->now_ms >= ws->state_ms ? (unsigned)((ws->now_ms - ws->state_ms) / 1000u) : 0;
    v->busy = is_busy(ws->state);
    v->can_send = ws_can_send(ws);
    v->can_retry = ws->state == WS_FAILED && ws->retry_ok;
    v->check_history = ws->state == WS_FAILED && ws->fail == WS_FAIL_COMMIT_UNKNOWN;
    v->can_pay_again = ws_can_pay_again(ws);
    v->sweep = ws->sweep;
    if (ws->state == WS_PAID) {
        snprintf(v->txid, sizeof(v->txid), "%s", ws->txid);
        format_confirmed(s, ws->sent.answered_s, v->confirmed, sizeof(v->confirmed));
    }
    v->can_cancel = ws->state != WS_COMMIT && ws->state != WS_BROADCAST && !ws_terminal(ws);
    v->can_leave = flow_over(ws);
    if (shows_review(ws->state) && ws->plan.token[0]) fill_review(ws, v);
    fill_status(ws, v);
    if (ws->state == WS_PARSED && !ws->sweep) fill_amount_page(s, v);
    v->can_max |= review_max(ws) > 0 && !ws->lock_wanted;
    pthread_mutex_unlock(&s->lock);
}

/* ---- progress ---- */

/* "zs1abcde…uvwxyz": the first eight and the last six characters. */
static void short_address(const char *address, char *out, size_t cap)
{
    size_t n = strlen(address);
    if (n <= 14) snprintf(out, cap, "%s", address);
    else snprintf(out, cap, "%.8s…%s", address, address + n - 6);
}
static const char *refusal_cause(enum ws_fail fail)
{
    return fail == WS_FAIL_FEE_CHANGED ? "the wallet fee changed" : "the node refused it";
}
static bool failed_after_tap(enum ws_fail fail)
{
    return fail == WS_FAIL_COMMIT_REFUSED || fail == WS_FAIL_FEE_CHANGED || fail == WS_FAIL_COMMIT_UNKNOWN;
}
/* Under the lock: whether the screen has a payment line to give. A payment that runs again clears the owner's dismissal. */
static bool progress_shown(struct wss *s, enum ws_state state)
{
    if (state == WS_COMMIT || state == WS_BROADCAST) s->progress_seen = false;
    return s->begun && !s->closed && !s->progress_seen;
}
/* The line of a sweep from the owner's confirmation on. A sweep is done or refused; it never waits to leave the phone. */
static bool sweep_line(enum ws_state state, enum ws_fail fail, const char *amount, char *line, size_t cap)
{
    if (state == WS_COMMIT) snprintf(line, cap, "Sending %s to your private balance: building the transaction (about 2 min)", amount);
    else if (state == WS_DONE) snprintf(line, cap, "%s", SWEEP_DONE);
    else if (state == WS_PAID) snprintf(line, cap, "%s", SWEEP_REPLAYED);
    else if (state == WS_FAILED && fail == WS_FAIL_COMMIT_UNKNOWN)
        snprintf(line, cap, "Move status unknown: it may have been made. Check History before trying again.");
    else if (state == WS_FAILED && failed_after_tap(fail))
        snprintf(line, cap, "Not moved: %s. Your coins were not spent.", refusal_cause(fail));
    else return false;
    return true;
}
bool wss_progress(struct wss *s, char *line, size_t cap)
{
    char amount[WSS_AMOUNT], to[40];
    pthread_mutex_lock(&s->lock);
    const struct ws *ws = &s->ws;
    enum ws_state state = ws->state;
    enum ws_fail fail = ws->fail;
    bool shown = progress_shown(s, state);
    bool replayed = s->replayed;
    bool sweep = ws->sweep;
    wss_format_zat(sweep ? ws->plan.total_zat : ws->pay.amount_zat, amount, sizeof(amount));
    short_address(ws->pay.address, to, sizeof(to));
    pthread_mutex_unlock(&s->lock);
    if (!shown || !line || !cap) return false;
    if (sweep) return sweep_line(state, fail, amount, line, cap);
    if (state == WS_COMMIT) snprintf(line, cap, "Sending %s to %s: building the payment (about 2 min)", amount, to);
    else if (state == WS_BROADCAST) snprintf(line, cap, "Sending %s to %s: waiting to leave the phone", amount, to);
    else if (state == WS_DONE) snprintf(line, cap, "Sent %s", amount);
    else if (state == WS_PAID && replayed) snprintf(line, cap, "Already sent %s", amount);
    else if (state == WS_FAILED && fail == WS_FAIL_COMMIT_UNKNOWN)
        snprintf(line, cap, "Payment status unknown: it may have been sent. Check History before paying again.");
    else if (state == WS_FAILED && failed_after_tap(fail))
        snprintf(line, cap, "Payment not sent: %s. Your coins were not spent.", refusal_cause(fail));
    else return false;
    return true;
}
void wss_progress_dismiss(struct wss *s)
{
    pthread_mutex_lock(&s->lock);
    if (s->ws.state != WS_COMMIT && s->ws.state != WS_BROADCAST) s->progress_seen = true;
    pthread_mutex_unlock(&s->lock);
}
bool wss_in_flight(struct wss *s)
{
    pthread_mutex_lock(&s->lock);
    bool flying = s->ws.state == WS_COMMIT || s->ws.state == WS_BROADCAST;
    pthread_mutex_unlock(&s->lock);
    return flying;
}
bool wss_send_busy(enum ws_state state)
{
    return state == WS_AUTH || state == WS_COMMIT || state == WS_BROADCAST;
}
void wss_gate_prover(struct wss_view *v, bool ready, const char *why)
{
    if (ready || !v->can_send) return;
    v->can_send = false;
    snprintf(v->status, sizeof(v->status), "%s", why && why[0] ? why : "Sending is not ready yet.");
}
/* The result of a payment that reached the node, at the step where it ends (once per attempt: the machine leaves COMMIT
 * and BROADCAST only forward): sent, refused, or unknown. -1 at every other step. */
static int outcome_of(struct wss *s, enum ws_state before)
{
    enum ws_state now = s->ws.state;
    if ((before != WS_COMMIT && before != WS_BROADCAST) || (now != WS_DONE && now != WS_FAILED && now != WS_PAID)) return -1;
    s->replayed = now == WS_PAID;   /* the node already held this payment as sent */
    if (s->ws.sweep) return -1;     /* the Funds line tells the owner; a sweep sends no payment notice */
    if (now == WS_DONE || now == WS_PAID) return ZAPP_PAYMENT_SENT;
    return s->ws.fail == WS_FAIL_COMMIT_UNKNOWN ? ZAPP_PAYMENT_UNKNOWN : ZAPP_PAYMENT_NOT_SENT;
}

/* ---- the worker ---- */

static void snapshot(struct wss *s, struct wss_send_req *req, bool with_token)
{
    memset(req, 0, sizeof(*req));
    pthread_mutex_lock(&s->lock);
    req->sweep = s->ws.sweep;
    if (!req->sweep) {
        memcpy(req->address, s->ws.pay.address, sizeof(req->address));
        req->amount_zat = s->ws.pay.amount_zat;
        memcpy(req->memo, s->ws.pay.memo, sizeof(req->memo));
        req->memo_len = s->ws.pay.memo_len;
    }
    memcpy(req->key, s->ws.key, sizeof(req->key));
    if (with_token) memcpy(req->plan_token, s->ws.plan.token, sizeof(req->plan_token));
    pthread_mutex_unlock(&s->lock);
}
/* Whether the action still belongs to the flow: a ticket the machine has moved past is dead. */
static bool live(struct wss *s, uint32_t ticket, enum ws_state state)
{
    pthread_mutex_lock(&s->lock);
    bool ok = s->ws.ticket == ticket && s->ws.state == state;
    pthread_mutex_unlock(&s->lock);
    return ok;
}
static void run_job(void *arg);
/* Adds the machine's actions to the queue with the lock held. A poll, a gate read and a lock replace the one
 * already queued, so ticks that arrive while the worker is blocked in a node call cannot fill the queue. A
 * lock is never dropped: a full queue gives up a poll or a gate read for it. */
static bool coalesces(enum ws_action_kind k) { return k == WS_ACT_POLL_ROUTE || k == WS_ACT_READ_GATE || k == WS_ACT_LOCK; }
static void enqueue(struct wss *s, const struct ws_actions *acts)
{
    for (size_t i = 0; i < acts->count; ++i) {
        struct ws_action a = acts->item[i];
        bool merged = false;
        for (size_t j = 0; coalesces(a.kind) && j < s->queued; ++j)
            if (s->queue[j].kind == a.kind) { s->queue[j].ticket = a.ticket; merged = true; }
        if (merged) continue;
        for (size_t j = 0; s->queued == QUEUE_MAX && a.kind == WS_ACT_LOCK && j < s->queued; ++j)
            if (s->queue[j].kind == WS_ACT_POLL_ROUTE || s->queue[j].kind == WS_ACT_READ_GATE) {
                memmove(s->queue + j, s->queue + j + 1, (s->queued - j - 1) * sizeof(s->queue[0]));
                s->queued--;
            }
        if (s->queued < QUEUE_MAX) s->queue[s->queued++] = a;
    }
}
/* Drops every queued action but the locks the wallet is owed. */
static void keep_locks(struct wss *s)
{
    size_t n = 0;
    for (size_t i = 0; i < s->queued; ++i)
        if (s->queue[i].kind == WS_ACT_LOCK) s->queue[n++] = s->queue[i];
    s->queued = n;
}
/* Starts the worker when work is queued. The UI thread never runs a job: unwrap blocks for the prompt and
 * the proof. When no worker can be started the flow ends before anything ran and only the owed lock stays
 * queued; the next tick tries to start the worker again. */
static void kick(struct wss *s)
{
    struct ws_actions acts;
    struct ws_event ev = {.kind = WS_EV_ABORT};
    pthread_mutex_lock(&s->lock);
    bool start = (s->queued || s->balance_wanted || s->quote_wanted) && !s->worker;
    if (start) s->worker = true;
    pthread_mutex_unlock(&s->lock);
    if (!start || s->d.host.spawn(s->d.host.ctx, run_job, s)) return;
    pthread_mutex_lock(&s->lock);
    s->worker = false;
    /* A reading or a quote that cannot start is dropped; only queued actions of the flow end it. */
    if (s->quote_wanted) snprintf(s->max_note, sizeof(s->max_note), "%s", MAX_FAILED);
    s->balance_wanted = s->quote_wanted = s->quoting = false;
    if (!s->queued) { pthread_mutex_unlock(&s->lock); return; }
    ev.now_ms = s->d.host.now_ms ? s->d.host.now_ms(s->d.host.ctx) : 0;
    enum ws_state before = s->ws.state;
    ws_step(&s->ws, &ev, &acts);
    if (before != WS_FAILED && s->ws.state == WS_FAILED && s->ws.fail == WS_FAIL_WORKER) {
        keep_locks(s);
        memory_cleanse(&s->tapped, sizeof(s->tapped));
    }
    enqueue(s, &acts);
    pthread_mutex_unlock(&s->lock);
}
/* Copies the reviewed plan at the moment of the tap. Called with the lock held. */
static void freeze(struct wss *s)
{
    struct wss_send_req *r = &s->tapped;
    memset(r, 0, sizeof(*r));
    r->sweep = s->ws.sweep;
    if (!r->sweep) {
        memcpy(r->address, s->ws.pay.address, sizeof(r->address));
        r->amount_zat = s->ws.pay.amount_zat;
        memcpy(r->memo, s->ws.pay.memo, sizeof(r->memo));
        r->memo_len = s->ws.pay.memo_len;
    }
    r->fee_zat = s->ws.plan.fee_zat;   /* the fee the owner saw; the node refuses a commit without it */
    memcpy(r->key, s->ws.key, sizeof(r->key));
    memcpy(r->plan_token, s->ws.plan.token, sizeof(r->plan_token));
}
static void post(struct wss *s, struct ws_event *ev)
{
    struct ws_actions acts;
    pthread_mutex_lock(&s->lock);
    ev->now_ms = s->d.host.now_ms ? s->d.host.now_ms(s->d.host.ctx) : 0;
    enum ws_state before = s->ws.state;
    ws_step(&s->ws, ev, &acts);
    if (ev->kind == WS_EV_TAP_SEND && before == WS_REVIEW && s->ws.state == WS_AUTH) freeze(s);
    if (flow_over(&s->ws)) memory_cleanse(&s->tapped, sizeof(s->tapped));
    int result = outcome_of(s, before);
    enqueue(s, &acts);
    pthread_mutex_unlock(&s->lock);
    kick(s);
    if (s->d.host.redraw) s->d.host.redraw(s->d.host.ctx);
    if (result >= 0 && s->d.host.outcome) s->d.host.outcome(s->d.host.ctx, result);
}
void wss_unlock_cleanse(struct wss_unlock_buf *buf)
{
    memory_cleanse(buf->secret, sizeof(buf->secret));
    memory_cleanse(buf->json, sizeof(buf->json));
}
bool wss_unlock_buf_clear(const struct wss_unlock_buf *buf)
{
    uint8_t any = 0;
    for (size_t i = 0; i < sizeof(buf->secret); ++i) any |= buf->secret[i];
    for (size_t i = 0; i < sizeof(buf->json); ++i) any |= (uint8_t)buf->json[i];
    return any == 0;
}
static void cleanse_secrets(struct wss *s) { wss_unlock_cleanse(&s->unlock); }
/* The passphrase is 32 random bytes written as 64 lowercase hex characters on standard input. */
static bool build_unlock_json(struct wss_unlock_buf *buf, uint32_t seconds)
{
    static const char hex[] = "0123456789abcdef";
    char pass[65];
    for (size_t i = 0; i < sizeof(buf->secret); ++i) {
        pass[2 * i] = hex[buf->secret[i] >> 4];
        pass[2 * i + 1] = hex[buf->secret[i] & 15];
    }
    pass[64] = 0;
    int n = snprintf(buf->json, sizeof(buf->json), "{\"passphrase\":\"%s\",\"timeout_seconds\":%u}\n", pass, seconds);
    memory_cleanse(pass, sizeof(pass));
    return n > 0 && (size_t)n < sizeof(buf->json);
}
struct wss_unlock_result wss_unlock_node(const struct wss_device_ops *device, const struct wss_node_ops *node,
                                         struct wss_unlock_buf *buf, uint32_t seconds, bool (*wanted)(void *ctx),
                                         void *wanted_ctx)
{
    struct wss_unlock_result r = {.key = WSS_KEY_ERROR};
    /* One call authenticates the owner for this use and returns the secret; it blocks while the prompt is up. */
    r.key = device->unwrap(device->ctx, buf->secret);
    /* The owner may have cancelled during the prompt: then the wallet is not opened. */
    if (r.key == WSS_KEY_OK && (!wanted || wanted(wanted_ctx)) && build_unlock_json(buf, seconds)) {
        r.sent = true;
        r.ok = node->unlock(node->ctx, buf->json, strlen(buf->json), seconds);
    }
    wss_unlock_cleanse(buf);
    return r;
}
static enum ws_auth_result auth_of(enum wss_key_status key)
{
    switch (key) {
    case WSS_KEY_GONE: return WS_AUTH_KEY_GONE;
    case WSS_KEY_DECLINED: return WS_AUTH_DECLINED;
    case WSS_KEY_NO_SCREEN_LOCK: return WS_AUTH_NO_SCREEN_LOCK;
    default: return WS_AUTH_OK;
    }
}
struct auth_ticket { struct wss *s; uint32_t ticket; };
static bool still_authenticating(void *arg)
{
    const struct auth_ticket *t = arg;
    return live(t->s, t->ticket, WS_AUTH);
}
static void do_unlock(struct wss *s, uint32_t ticket)
{
    struct ws_event ev = {.kind = WS_EV_UNLOCK, .ticket = ticket};
    struct auth_ticket t = {s, ticket};
    struct wss_unlock_result r =
        wss_unlock_node(&s->d.device, &s->d.node, &s->unlock, WS_UNLOCK_SECONDS, still_authenticating, &t);
    ev.ok = r.ok;
    ev.auth = auth_of(r.key);
    post(s, &ev);
}
/* The commit carries the plan the owner tapped, not whatever the machine holds now, and only while its
 * ticket is current. */
static void do_commit(struct wss *s, uint32_t ticket)
{
    struct wss_send_req req;
    struct ws_event ev = {.kind = WS_EV_COMMIT, .ticket = ticket};
    char echo[WS_TOKEN_MAX] = "";
    struct wss_commit_info info = {0};
    pthread_mutex_lock(&s->lock);
    bool ok = s->ws.ticket == ticket && s->ws.state == WS_COMMIT;
    if (ok) req = s->tapped;
    pthread_mutex_unlock(&s->lock);
    if (!ok) return;
    enum wss_commit_outcome out = s->d.node.commit(s->d.node.ctx, &req, echo, &info);
    ev.ok = out == WSS_COMMITTED;
    if (ev.ok && s->d.host.wall_s) ev.wall_s = s->d.host.wall_s(s->d.host.ctx);
    ev.replayed = ev.ok && info.replayed;
    ev.why = info.why;
    if (ev.ok) snprintf(ev.txid, sizeof(ev.txid), "%s", info.txid);
    ev.refused = out == WSS_KEY_RELEASED;
    ev.fee_changed = out == WSS_FEE_CHANGED;
    memcpy(ev.plan.token, echo, sizeof(echo));
    ev.plan.token[WS_TOKEN_MAX - 1] = 0;
    memory_cleanse(&req, sizeof(req));
    post(s, &ev);
}
static void do_plan(struct wss *s, uint32_t ticket)
{
    struct wss_send_req req;
    struct ws_event ev = {.kind = WS_EV_PLAN, .ticket = ticket};
    snapshot(s, &req, false);
    ev.ok = s->d.node.plan(s->d.node.ctx, &req, &ev.plan);
    memory_cleanse(&req, sizeof(req));
    post(s, &ev);
}
static void do_validate(struct wss *s, uint32_t ticket)
{
    struct wss_send_req req;
    struct ws_event ev = {.kind = WS_EV_ADDRESS, .ticket = ticket};
    bool valid = false;
    snapshot(s, &req, false);
    ev.ok = s->d.node.validate_address(s->d.node.ctx, req.address, &valid) && valid;
    memory_cleanse(&req, sizeof(req));
    post(s, &ev);
}
static void run_action(struct wss *s, struct ws_action a)
{
    struct ws_event ev = {.ticket = a.ticket};
    /* An action the machine has moved past is dropped. A lock is owed whatever happened and always runs. */
    pthread_mutex_lock(&s->lock);
    bool stale = a.kind != WS_ACT_LOCK && a.ticket != s->ws.ticket;
    pthread_mutex_unlock(&s->lock);
    if (stale) return;
    switch (a.kind) {
    case WS_ACT_VALIDATE_ADDRESS: do_validate(s, a.ticket); return;
    case WS_ACT_READ_GATE:
        ev.kind = WS_EV_GATE;
        if (!s->d.node.read_gate(s->d.node.ctx, &ev.gate)) ev.gate.known = false;
        break;
    case WS_ACT_PLAN: do_plan(s, a.ticket); return;
    case WS_ACT_UNLOCK: do_unlock(s, a.ticket); return;
    case WS_ACT_COMMIT: do_commit(s, a.ticket); return;
    case WS_ACT_POLL_ROUTE:
        ev.kind = WS_EV_ROUTE;
        ev.route = WS_ROUTE_WAITING;
        if (!s->d.node.route(s->d.node.ctx, &ev.route)) ev.route = WS_ROUTE_WAITING;
        break;
    case WS_ACT_LOCK:
        ev.kind = WS_EV_LOCK;
        ev.ok = s->d.node.lock(s->d.node.ctx);
        break;
    case WS_ACT_NONE: return;
    }
    post(s, &ev);
}
static void destroy_now(struct wss *s)
{
    void (*release)(void *) = s->d.release;
    void *release_ctx = s->d.release_ctx;
    cleanse_secrets(s);
    memory_cleanse(&s->tapped, sizeof(s->tapped));
    memory_cleanse(&s->ws, sizeof(s->ws));
    memory_cleanse(&s->balance, sizeof(s->balance));
    pthread_mutex_destroy(&s->lock);
    free(s);
    if (release) release(release_ctx);
}
static void do_balance(struct wss *s)
{
    struct wss_balance b = {0};
    if (!s->d.node.read_balance || !s->d.node.read_balance(s->d.node.ctx, &b)) b.known = false;
    pthread_mutex_lock(&s->lock);
    /* An unanswered or hidden reading leaves the last one, which goes out of date by itself. */
    if (b.known) { s->balance = b; s->balance_ms = now_of(s); }
    s->balance_reading = false;
    pthread_mutex_unlock(&s->lock);
    if (s->d.host.redraw) s->d.host.redraw(s->d.host.ctx);
}
static bool random_key(struct wss *s, char out[WS_KEY_HEX + 1])
{
    static const char hex[] = "0123456789abcdef";
    uint8_t raw[WS_KEY_HEX / 2];
    if (!s->d.host.random || !s->d.host.random(s->d.host.ctx, raw, sizeof(raw))) return false;
    for (size_t i = 0; i < sizeof(raw); ++i) { out[2 * i] = hex[raw[i] >> 4]; out[2 * i + 1] = hex[raw[i] & 15]; }
    out[WS_KEY_HEX] = 0;
    memory_cleanse(raw, sizeof(raw));
    return true;
}
/* Under the lock: whether the amount page that asked for the quote is still on screen. */
static bool quote_live(const struct wss *s)
{
    return s->quoting && s->ws.state == WS_PARSED && s->ws.serial == s->quote_serial;
}
/* The fee a plan of the whole balance quotes. The plan binds nothing and is never committed: its key is a throwaway. */
static void do_quote(struct wss *s)
{
    struct wss_send_req req;
    struct ws_plan plan = {0};
    snapshot(s, &req, false);
    pthread_mutex_lock(&s->lock);
    bool live = quote_live(s) && balance_fresh(s);
    uint64_t spendable = s->balance.spendable_zat;
    pthread_mutex_unlock(&s->lock);
    req.amount_zat = spendable;
    bool ok = live && random_key(s, req.key) && s->d.node.plan(s->d.node.ctx, &req, &plan) && plan.amount_zat == spendable &&
              plan.total_zat == plan.amount_zat + plan.fee_zat;
    uint64_t target = ok ? wss_max_amount(spendable, plan.fee_zat) : 0;
    memory_cleanse(&req, sizeof(req));
    memory_cleanse(&plan, sizeof(plan));
    pthread_mutex_lock(&s->lock);
    bool still = quote_live(s);
    s->quoting = false;
    if (still && !target) snprintf(s->max_note, sizeof(s->max_note), "%s", ok ? MAX_NONE : MAX_FAILED);
    pthread_mutex_unlock(&s->lock);
    if (still && target) wss_edit_amount(s, target);
    else if (s->d.host.redraw) s->d.host.redraw(s->d.host.ctx);
}
/* Under the lock: takes the next piece of work of the worker. Queued actions of the flow come first; a reading and a quote
 * follow them. */
enum work { WORK_NONE, WORK_ACTION, WORK_BALANCE, WORK_QUOTE };
static enum work next_work(struct wss *s, struct ws_action *a)
{
    if (s->queued) {
        *a = s->queue[0];
        memmove(s->queue, s->queue + 1, (s->queued - 1) * sizeof(s->queue[0]));
        s->queued--;
        return WORK_ACTION;
    }
    if (s->dying) return WORK_NONE;
    if (s->balance_wanted) { s->balance_wanted = false; s->balance_reading = true; return WORK_BALANCE; }
    if (s->quote_wanted) { s->quote_wanted = false; return WORK_QUOTE; }
    return WORK_NONE;
}
static void run_job(void *arg)
{
    struct wss *s = arg;
    for (;;) {
        struct ws_action a = {0};
        pthread_mutex_lock(&s->lock);
        enum work work = next_work(s, &a);
        if (work == WORK_NONE) {
            bool dead = s->dying;
            s->worker = false;
            pthread_mutex_unlock(&s->lock);
            if (dead) destroy_now(s);
            return;
        }
        pthread_mutex_unlock(&s->lock);
        if (work == WORK_BALANCE) do_balance(s);
        else if (work == WORK_QUOTE) do_quote(s);
        else run_action(s, a);
    }
}

/* ---- lifecycle and input ---- */

struct wss *wss_create(const struct wss_deps *deps)
{
    struct wss *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    if (pthread_mutex_init(&s->lock, NULL) != 0) { free(s); return NULL; }
    s->d = *deps;
    return s;
}
bool wss_destroy(struct wss *s)
{
    if (!s) return true;
    pthread_mutex_lock(&s->lock);
    bool exposed = ws_wallet_exposed(&s->ws);
    if (!exposed) s->dying = true;
    bool busy = s->worker;
    pthread_mutex_unlock(&s->lock);
    if (exposed) return false;   /* The wallet may be open: the lock is still owed and ticks must go on. */
    if (!busy) destroy_now(s);
    return true;
}
void wss_close(struct wss *s)
{
    pthread_mutex_lock(&s->lock);
    if (flow_over(&s->ws)) s->closed = true;
    pthread_mutex_unlock(&s->lock);
}
bool wss_closed(struct wss *s)
{
    pthread_mutex_lock(&s->lock);
    bool closed = s->closed;
    pthread_mutex_unlock(&s->lock);
    return closed;
}
void wss_unbind(struct wss *s)
{
    pthread_mutex_lock(&s->lock);
    memset(&s->d.secure, 0, sizeof(s->d.secure));
    s->unprotected = true;
    pthread_mutex_unlock(&s->lock);
}
bool wss_rebind(struct wss *s, const struct zapp_secure_ops *secure)
{
    pthread_mutex_lock(&s->lock);
    s->d.secure = *secure;
    bool begun = s->begun;
    pthread_mutex_unlock(&s->lock);
    bool ok = !begun || zapp_secure_window_apply(secure, true);
    if (!ok) (void)zapp_secure_window_apply(secure, false);
    pthread_mutex_lock(&s->lock);
    s->unprotected = !ok;
    pthread_mutex_unlock(&s->lock);
    return ok;
}
bool wss_exposed(struct wss *s)
{
    pthread_mutex_lock(&s->lock);
    bool exposed = ws_wallet_exposed(&s->ws);
    pthread_mutex_unlock(&s->lock);
    return exposed;
}
/* pay NULL begins a sweep. */
static bool begin_flow(struct wss *s, const struct zapp_payment *pay)
{
    struct ws_actions acts;
    struct ws_env env = {s->d.network, s->d.host.ctx, s->d.host.random, s->d.host.derive_key};
    pthread_mutex_lock(&s->lock);
    bool busy = s->begun && !flow_over(&s->ws);
    pthread_mutex_unlock(&s->lock);
    if (busy) return false;   /* A second code never replaces a flow that has not ended. */
    if (!zapp_secure_window_apply(&s->d.secure, true)) {
        (void)zapp_secure_window_apply(&s->d.secure, false);
        return false;
    }
    pthread_mutex_lock(&s->lock);
    s->protected_window = s->begun = true;
    s->unprotected = false;
    s->closed = false;
    s->replayed = false;
    s->progress_seen = false;
    uint64_t now = s->d.host.now_ms ? s->d.host.now_ms(s->d.host.ctx) : 0;
    if (pay) ws_open(&s->ws, &env, pay, now, &acts);
    else ws_open_sweep(&s->ws, &env, now, &acts);
    s->quoting = s->quote_wanted = false;
    s->max_note[0] = 0;
    /* The amount page shows what can be sent, so a payment named without an amount reads the balance at once. */
    if (s->ws.state == WS_PARSED && s->d.node.read_balance) s->balance_wanted = true;
    enqueue(s, &acts);
    pthread_mutex_unlock(&s->lock);
    kick(s);
    if (s->d.host.redraw) s->d.host.redraw(s->d.host.ctx);
    return true;
}
bool wss_begin(struct wss *s, const struct zapp_payment *pay) { return begin_flow(s, pay); }
bool wss_begin_sweep(struct wss *s) { return begin_flow(s, NULL); }
/* Leaving the screen cancels a flow that has not reached the wallet. A flow in authentication is not cancelled: the
 * system credential screen backgrounds the app, and the result of the prompt completes the payment. Only the Cancel
 * button ends it. A running commit is never cancelled either; the wallet is locked when the node answers. */
bool wss_end(struct wss *s)
{
    struct ws_event ev = {.kind = WS_EV_CANCEL};
    pthread_mutex_lock(&s->lock);
    bool authenticating = s->ws.state == WS_AUTH;
    pthread_mutex_unlock(&s->lock);
    if (!authenticating) post(s, &ev);
    pthread_mutex_lock(&s->lock);
    /* An exposed wallet keeps the screen alive: the lock is owed and only ticks can finish it. */
    bool done = flow_over(&s->ws) && !ws_wallet_exposed(&s->ws);
    pthread_mutex_unlock(&s->lock);
    if (done) (void)zapp_secure_window_apply(&s->d.secure, false);
    return done;
}
static void send_kind(struct wss *s, enum ws_event_kind kind)
{
    struct ws_event ev = {.kind = kind};
    post(s, &ev);
}
void wss_tap_send(struct wss *s, uint32_t serial)
{
    struct ws_event ev = {.kind = WS_EV_TAP_SEND, .serial = serial};
    post(s, &ev);
}
bool wss_tap_send_ready(struct wss *s, uint32_t serial, bool ready)
{
    if (!ready) return false;
    wss_tap_send(s, serial);
    return true;
}
void wss_tap_retry(struct wss *s) { send_kind(s, WS_EV_RETRY); }
void wss_tap_cancel(struct wss *s) { send_kind(s, WS_EV_CANCEL); }
void wss_tap_pay_again(struct wss *s) { send_kind(s, WS_EV_PAY_AGAIN); }
void wss_on_pause(struct wss *s) { send_kind(s, WS_EV_BACKGROUND); }
void wss_on_resume(struct wss *s) { send_kind(s, WS_EV_RESUME); }
void wss_on_tick(struct wss *s) { send_kind(s, WS_EV_TICK); }
void wss_edit_amount(struct wss *s, uint64_t amount_zat)
{
    struct ws_event ev = {.kind = WS_EV_SET_AMOUNT, .amount_zat = amount_zat};
    post(s, &ev);
}
void wss_tap_max(struct wss *s)
{
    pthread_mutex_lock(&s->lock);
    const struct ws *ws = &s->ws;
    uint64_t target = ws->lock_wanted ? 0 : review_max(ws);
    bool quote = ws->state == WS_PARSED && !ws->sweep && balance_fresh(s) && s->balance.spendable_zat > 0 && !s->quoting;
    if (quote) {
        s->quoting = s->quote_wanted = true;
        s->quote_serial = ws->serial;
        s->max_note[0] = 0;
    }
    pthread_mutex_unlock(&s->lock);
    if (target) { wss_edit_amount(s, target); return; }
    if (!quote) return;
    kick(s);
    if (s->d.host.redraw) s->d.host.redraw(s->d.host.ctx);
}
void wss_read_balance(struct wss *s)
{
    if (!s->d.node.read_balance) return;
    pthread_mutex_lock(&s->lock);
    s->balance_wanted = true;
    pthread_mutex_unlock(&s->lock);
    kick(s);
}
void wss_keep_balance(struct wss *s)
{
    if (!s->d.node.read_balance) return;
    pthread_mutex_lock(&s->lock);
    uint64_t now = now_of(s);
    bool old = !s->balance.known || now < s->balance_ms || now - s->balance_ms >= WSS_BALANCE_FRESH_MS / 2;
    bool ask = s->begun && s->ws.state == WS_PARSED && !s->ws.sweep && old && !s->balance_wanted && !s->balance_reading;
    if (ask) s->balance_wanted = true;
    pthread_mutex_unlock(&s->lock);
    if (ask) kick(s);
}
bool wss_keyboard_due(enum wss_focus focus, enum wss_focus *asked)
{
    bool due = focus != WSS_FOCUS_NONE && focus != *asked;
    *asked = focus;
    return due;
}
void wss_note_balance(struct wss *s, uint64_t spendable_zat)
{
    pthread_mutex_lock(&s->lock);
    s->balance = (struct wss_balance){.known = true, .spendable_zat = spendable_zat};
    s->balance_ms = now_of(s);
    pthread_mutex_unlock(&s->lock);
}
void wss_balance(struct wss *s, struct wss_balance *out)
{
    pthread_mutex_lock(&s->lock);
    *out = balance_fresh(s) ? s->balance : (struct wss_balance){0};
    pthread_mutex_unlock(&s->lock);
}
void wss_edit_address(struct wss *s, const char *address)
{
    struct ws_event ev = {.kind = WS_EV_SET_ADDRESS};
    snprintf(ev.text, sizeof(ev.text), "%s", address ? address : "");
    post(s, &ev);
}
void wss_edit_memo(struct wss *s, const char *memo, size_t len)
{
    struct ws_event ev = {.kind = WS_EV_SET_MEMO};
    if (len > ZAPP_PAY_MEMO_MAX) return;
    if (len) memcpy(ev.text, memo, len);
    ev.text_len = len;
    post(s, &ev);
}
bool wss_secrets_clear(struct wss *s)
{
    pthread_mutex_lock(&s->lock);
    bool clear = wss_unlock_buf_clear(&s->unlock);
    pthread_mutex_unlock(&s->lock);
    return clear;
}

/* ---- mappings ---- */

enum wss_commit_outcome wss_commit_outcome_of(bool answered, bool committed, const char *error_code)
{
    if (!answered) return WSS_UNKNOWN;
    if (committed) return WSS_COMMITTED;
    if (error_code && !strcmp(error_code, "SEND_REFUSED_KEY_RELEASED")) return WSS_KEY_RELEASED;
    if (error_code && !strcmp(error_code, "FEE_CHANGED")) return WSS_FEE_CHANGED;
    return WSS_UNKNOWN;
}
enum wss_key_status wss_key_status_of_devkey(const char *name)
{
    static const struct { const char *name; enum wss_key_status status; } table[] = {
        {"ok", WSS_KEY_OK}, {"declined", WSS_KEY_DECLINED},
        {"invalidated", WSS_KEY_GONE}, {"not_found", WSS_KEY_GONE}, {"corrupt", WSS_KEY_GONE},
        {"old_format", WSS_KEY_GONE}, {"not_hardware", WSS_KEY_GONE}, {"not_per_use", WSS_KEY_GONE},
        {"no_screen_lock", WSS_KEY_NO_SCREEN_LOCK},
        {"exists", WSS_KEY_ERROR}, {"strongbox_unavailable", WSS_KEY_ERROR}, {"error", WSS_KEY_ERROR},
    };
    for (size_t i = 0; name && i < sizeof(table) / sizeof(table[0]); ++i)
        if (!strcmp(name, table[i].name)) return table[i].status;
    return WSS_KEY_ERROR;
}

/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "wallet_send_screen.h"
#include "base/cleanse.h"
#include "wallet_view.h"
#include "zutf8/zutf8.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QUEUE_MAX 16
#define PUBLIC_WARNING "This payment is public. The amount and address are visible to everyone, forever."

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
    uint8_t secret[32];
    char unlock_json[WSS_UNLOCK_JSON];
    struct wss_send_req tapped;   /* The plan the owner tapped Send on; the commit is bound to it. */
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
/* Characters that move, hide or reorder text: controls, soft hyphen, zero width and bidi marks and
 * isolates, line and paragraph separators, byte order mark. They are written out, never acted on. */
static bool invisible_cp(uint32_t cp)
{
    return cp < 0x20 || (cp >= 0x7f && cp <= 0x9f) || cp == 0xad || cp == 0x61c || cp == 0x180e ||
           (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x2028 && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x206f) ||
           cp == 0xfeff || (cp >= 0xfff9 && cp <= 0xfffb);
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
        if (invisible_cp(cp)) o += (size_t)snprintf(v->memo + o, sizeof(v->memo) - o, "<U+%04X>", (unsigned)cp);
        else { memcpy(v->memo + o, m + i, n); o += n; v->memo[o] = 0; }
        i += n;
    }
}
static void fill_review(const struct ws *ws, struct wss_view *v)
{
    v->review = true;
    wss_format_zat(ws->pay.amount_zat, v->amount, sizeof(v->amount));
    wss_format_zat(ws->plan.fee_zat, v->fee, sizeof(v->fee));
    if (!wallet_view_group_address(ws->pay.address, v->address, sizeof(v->address)))
        snprintf(v->address, sizeof(v->address), "Address cannot be shown");
    snprintf(v->kind, sizeof(v->kind), "%s", ws->pay.kind == ZAPP_PAY_PUBLIC ? "Public" : "Private");
    fill_memo(&ws->pay, v);
    if (ws->pay.kind == ZAPP_PAY_PUBLIC) snprintf(v->warning, sizeof(v->warning), "%s", PUBLIC_WARNING);
    if (ws->insufficient) {
        snprintf(v->note, sizeof(v->note), "Not enough private funds for this payment. Public funds are never used for it.");
        v->offer_make_private = ws->gate.public_zat > 0;
        return;
    }
    wss_format_zat(ws->gate.spendable_zat - ws->plan.total_zat, v->remains, sizeof(v->remains));
}
static void fill_status(const struct ws *ws, struct wss_view *v)
{
    switch (ws->state) {
    case WS_PARSED: snprintf(v->status, sizeof(v->status), "Enter an amount to send."); break;
    case WS_VALIDATING: snprintf(v->status, sizeof(v->status), "Checking the address with your node."); break;
    case WS_GATE: snprintf(v->status, sizeof(v->status), "Checking the wallet."); break;
    case WS_WAITING:
        snprintf(v->status, sizeof(v->status),
                 "The wallet is catching up with the chain, %u blocks behind. Sending waits until it is up to date.",
                 (unsigned)ws->gate.blocks_behind);
        break;
    case WS_PLAN: snprintf(v->status, sizeof(v->status), "Preparing the payment."); break;
    case WS_REVIEW:
        if (ws->lock_wanted)
            snprintf(v->status, sizeof(v->status), "Locking the wallet. Sending is possible again in a moment.");
        break;
    case WS_AUTH: snprintf(v->status, sizeof(v->status), "Confirm with your screen lock to send."); break;
    case WS_COMMIT:
        snprintf(v->status, sizeof(v->status), "Building the payment. This can take about two minutes on this phone.");
        break;
    case WS_BROADCAST: snprintf(v->status, sizeof(v->status), "Sent. Waiting for a private route."); break;
    case WS_DONE: snprintf(v->status, sizeof(v->status), "Payment sent."); break;
    case WS_FAILED: snprintf(v->status, sizeof(v->status), "%s", ws_fail_text(ws)); break;
    case WS_CANCELLED: snprintf(v->status, sizeof(v->status), "Cancelled. Nothing was sent."); break;
    case WS_IDLE: break;
    }
}
static bool is_busy(enum ws_state state)
{
    return state == WS_VALIDATING || state == WS_GATE || state == WS_PLAN || state == WS_AUTH || state == WS_COMMIT ||
           state == WS_BROADCAST || state == WS_WAITING;
}
static bool shows_review(enum ws_state state) { return state == WS_REVIEW || state == WS_AUTH || state == WS_COMMIT; }
void wss_view(struct wss *s, struct wss_view *v)
{
    memset(v, 0, sizeof(*v));
    pthread_mutex_lock(&s->lock);
    const struct ws *ws = &s->ws;
    v->state = ws->state;
    if (!s->begun) {
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
    v->can_cancel = ws->state != WS_COMMIT && !ws_terminal(ws);
    if (shows_review(ws->state) && ws->plan.token[0]) fill_review(ws, v);
    fill_status(ws, v);
    pthread_mutex_unlock(&s->lock);
}

/* ---- the worker ---- */

static void snapshot(struct wss *s, struct wss_send_req *req, bool with_token)
{
    memset(req, 0, sizeof(*req));
    pthread_mutex_lock(&s->lock);
    memcpy(req->address, s->ws.pay.address, sizeof(req->address));
    req->amount_zat = s->ws.pay.amount_zat;
    memcpy(req->memo, s->ws.pay.memo, sizeof(req->memo));
    req->memo_len = s->ws.pay.memo_len;
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
/* Copies the reviewed plan at the moment of the tap. Called with the lock held. */
static void freeze(struct wss *s)
{
    struct wss_send_req *r = &s->tapped;
    memset(r, 0, sizeof(*r));
    memcpy(r->address, s->ws.pay.address, sizeof(r->address));
    r->amount_zat = s->ws.pay.amount_zat;
    memcpy(r->memo, s->ws.pay.memo, sizeof(r->memo));
    r->memo_len = s->ws.pay.memo_len;
    memcpy(r->key, s->ws.key, sizeof(r->key));
    memcpy(r->plan_token, s->ws.plan.token, sizeof(r->plan_token));
}
static void post(struct wss *s, struct ws_event *ev)
{
    struct ws_actions acts;
    bool start = false;
    pthread_mutex_lock(&s->lock);
    ev->now_ms = s->d.host.now_ms ? s->d.host.now_ms(s->d.host.ctx) : 0;
    enum ws_state before = s->ws.state;
    ws_step(&s->ws, ev, &acts);
    if (ev->kind == WS_EV_TAP_SEND && before == WS_REVIEW && s->ws.state == WS_AUTH) freeze(s);
    if (ws_terminal(&s->ws)) memory_cleanse(&s->tapped, sizeof(s->tapped));
    for (size_t i = 0; i < acts.count && s->queued < QUEUE_MAX; ++i) s->queue[s->queued++] = acts.item[i];
    if (s->queued && !s->worker) start = s->worker = true;
    pthread_mutex_unlock(&s->lock);
    if (start && !s->d.host.spawn(s->d.host.ctx, run_job, s)) run_job(s);
    if (s->d.host.redraw) s->d.host.redraw(s->d.host.ctx);
}
static void cleanse_secrets(struct wss *s)
{
    memory_cleanse(s->secret, sizeof(s->secret));
    memory_cleanse(s->unlock_json, sizeof(s->unlock_json));
}
/* The passphrase is 32 random bytes written as 64 lowercase hex characters on standard input. */
static bool build_unlock_json(struct wss *s)
{
    static const char hex[] = "0123456789abcdef";
    char pass[65];
    for (size_t i = 0; i < sizeof(s->secret); ++i) {
        pass[2 * i] = hex[s->secret[i] >> 4];
        pass[2 * i + 1] = hex[s->secret[i] & 15];
    }
    pass[64] = 0;
    int n = snprintf(s->unlock_json, sizeof(s->unlock_json), "{\"passphrase\":\"%s\",\"timeout_seconds\":%u}\n", pass,
                     WS_UNLOCK_SECONDS);
    memory_cleanse(pass, sizeof(pass));
    return n > 0 && (size_t)n < sizeof(s->unlock_json);
}
static void do_unlock(struct wss *s, uint32_t ticket)
{
    struct ws_event ev = {.kind = WS_EV_UNLOCK, .ticket = ticket};
    /* One call authenticates the owner for this use and returns the secret; it blocks while the prompt is up. */
    enum wss_key_status key = s->d.device.unwrap(s->d.device.ctx, s->secret);
    /* The owner may have cancelled during the prompt: then the wallet is not opened. */
    if (key == WSS_KEY_OK && live(s, ticket, WS_AUTH) && build_unlock_json(s))
        ev.ok = s->d.node.unlock(s->d.node.ctx, s->unlock_json, strlen(s->unlock_json), WS_UNLOCK_SECONDS);
    ev.auth = key == WSS_KEY_GONE ? WS_AUTH_KEY_GONE : key == WSS_KEY_DECLINED ? WS_AUTH_DECLINED : WS_AUTH_OK;
    cleanse_secrets(s);
    post(s, &ev);
}
/* The commit carries the plan the owner tapped, not whatever the machine holds now, and only while its
 * ticket is current. */
static void do_commit(struct wss *s, uint32_t ticket)
{
    struct wss_send_req req;
    struct ws_event ev = {.kind = WS_EV_COMMIT, .ticket = ticket};
    char echo[WS_TOKEN_MAX] = "";
    pthread_mutex_lock(&s->lock);
    bool ok = s->ws.ticket == ticket && s->ws.state == WS_COMMIT;
    if (ok) req = s->tapped;
    pthread_mutex_unlock(&s->lock);
    if (!ok) return;
    enum wss_commit_outcome out = s->d.node.commit(s->d.node.ctx, &req, echo);
    ev.ok = out == WSS_COMMITTED;
    ev.refused = out == WSS_REFUSED;
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
    case WS_ACT_OPEN_MAKE_PRIVATE:
        if (s->d.host.open_make_private) s->d.host.open_make_private(s->d.host.ctx);
        return;
    case WS_ACT_NONE: return;
    }
    post(s, &ev);
}
static void destroy_now(struct wss *s)
{
    cleanse_secrets(s);
    memory_cleanse(&s->tapped, sizeof(s->tapped));
    memory_cleanse(&s->ws, sizeof(s->ws));
    pthread_mutex_destroy(&s->lock);
    free(s);
}
static void run_job(void *arg)
{
    struct wss *s = arg;
    for (;;) {
        pthread_mutex_lock(&s->lock);
        if (!s->queued) {
            bool dead = s->dying;
            s->worker = false;
            pthread_mutex_unlock(&s->lock);
            if (dead) destroy_now(s);
            return;
        }
        struct ws_action a = s->queue[0];
        memmove(s->queue, s->queue + 1, (s->queued - 1) * sizeof(s->queue[0]));
        s->queued--;
        pthread_mutex_unlock(&s->lock);
        run_action(s, a);
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
void wss_destroy(struct wss *s)
{
    if (!s) return;
    pthread_mutex_lock(&s->lock);
    s->dying = true;
    bool busy = s->worker;
    pthread_mutex_unlock(&s->lock);
    if (!busy) destroy_now(s);
}
bool wss_begin(struct wss *s, const struct zapp_payment *pay)
{
    struct ws_actions acts;
    struct ws_env env = {s->d.network, s->d.host.ctx, s->d.host.random};
    pthread_mutex_lock(&s->lock);
    bool busy = s->begun && !ws_terminal(&s->ws);
    pthread_mutex_unlock(&s->lock);
    if (busy) return false;   /* A second code never replaces a flow that has not ended. */
    if (!zapp_secure_window_apply(&s->d.secure, true)) {
        (void)zapp_secure_window_apply(&s->d.secure, false);
        return false;
    }
    pthread_mutex_lock(&s->lock);
    s->protected_window = s->begun = true;
    ws_open(&s->ws, &env, pay, s->d.host.now_ms ? s->d.host.now_ms(s->d.host.ctx) : 0, &acts);
    for (size_t i = 0; i < acts.count && s->queued < QUEUE_MAX; ++i) s->queue[s->queued++] = acts.item[i];
    bool start = s->queued && !s->worker;
    if (start) s->worker = true;
    pthread_mutex_unlock(&s->lock);
    if (start && !s->d.host.spawn(s->d.host.ctx, run_job, s)) run_job(s);
    if (s->d.host.redraw) s->d.host.redraw(s->d.host.ctx);
    return true;
}
bool wss_end(struct wss *s)
{
    struct ws_event ev = {.kind = WS_EV_CANCEL};
    post(s, &ev);
    pthread_mutex_lock(&s->lock);
    bool done = ws_terminal(&s->ws);
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
void wss_tap_retry(struct wss *s) { send_kind(s, WS_EV_RETRY); }
void wss_tap_cancel(struct wss *s) { send_kind(s, WS_EV_CANCEL); }
void wss_tap_make_private(struct wss *s) { send_kind(s, WS_EV_MAKE_PRIVATE); }
void wss_on_pause(struct wss *s) { send_kind(s, WS_EV_BACKGROUND); }
void wss_on_resume(struct wss *s) { send_kind(s, WS_EV_RESUME); }
void wss_on_tick(struct wss *s) { send_kind(s, WS_EV_TICK); }
void wss_edit_amount(struct wss *s, uint64_t amount_zat)
{
    struct ws_event ev = {.kind = WS_EV_SET_AMOUNT, .amount_zat = amount_zat};
    post(s, &ev);
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
    uint8_t any = 0;
    pthread_mutex_lock(&s->lock);
    for (size_t i = 0; i < sizeof(s->secret); ++i) any |= s->secret[i];
    for (size_t i = 0; i < sizeof(s->unlock_json); ++i) any |= (uint8_t)s->unlock_json[i];
    pthread_mutex_unlock(&s->lock);
    return any == 0;
}

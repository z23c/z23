/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "send_key.h"
#include "wallet_send_keeper.h"
#include "wallet_send_screen.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOG_MAX 4096
#define TXID "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define WALL_14_32 1767277920   /* 2026-01-01 14:32:00 UTC */
#define PAID_MAX 16

static const uint8_t SECRET[32] = {0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                   13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28};
#define SECRET_HEX "deadbeef0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"

/* A node, a device key and a host, all scripted. */
/* One activity window: every protection call it receives, and what it was last told. */
struct win { int calls, on_calls, off_calls; bool on; };
struct fake {
    /* script */
    struct ws_gate gate;
    uint64_t fee;
    bool address_valid, plan_ok, unlock_ok, lock_ok;
    enum wss_commit_outcome commit_outcome;
    enum ws_route route;
    enum wss_key_status key;
    bool flag_ok, filter_ok, flag_on, filter_on;
    /* record */
    char calls[LOG_MAX];          /* One letter per node and device call, in order. */
    char args[LOG_MAX];           /* Every string a call other than unlock received. */
    char commit_keys[8][WS_KEY_HEX + 1];
    char commit_address[ZAPP_PAY_ADDRESS_MAX];
    uint64_t commit_amount;
    char plan_key[WS_KEY_HEX + 1];
    int commits, unlocks, locks, prompts, repeated_keys, plan_required, plans;
    struct win *window;           /* when set, the screen is protected through this window */
    bool derive_on;               /* the host derives the payment key from id */
    struct zapp_send_id id;
    int64_t wall;
    uint64_t commit_fee;
    bool spawn_fail;
    int ticks_in_lock;            /* Ticks that arrive while a lock call is blocked. */
    bool lock_ok_after_ticks;
    char stdin_seen[256];
    const char *stdin_ptr;
    uint64_t now;
    void (*job)(void *);
    void *job_arg;
    int redraws;
    int outcomes, last_outcome;
    uint64_t rnd;
    /* the node's memory of keys that may have paid */
    char paid[PAID_MAX][WS_KEY_HEX + 1];
    char paid_token[PAID_MAX][WS_TOKEN_MAX];
    enum wss_commit_outcome paid_outcome[PAID_MAX];
    int paid_n;
    /* threaded host */
    bool threaded, hold, parked, released;
    struct wss *screen;
    pthread_t main_thread;
    pthread_mutex_t mu;
    pthread_cond_t cv;
};
static void note(struct fake *f, char c, const char *arg)
{
    size_t n = strlen(f->calls);
    f->calls[n] = c; f->calls[n + 1] = 0;
    if (arg) strncat(f->args, arg, sizeof(f->args) - strlen(f->args) - 2);
}
/* The plan token as the node makes it: a hash over the sender-visible fields, the fee and the idempotency key.
 * A plan asked for without a key, or committed under another key, gives another token. */
static void node_token(const struct wss_send_req *r, uint64_t fee, char out[WS_TOKEN_MAX])
{
    uint64_t h = 1469598103934665603ull;
    const char *sep = "|";
    for (const char *c = r->address; *c; ++c) h = (h ^ (uint8_t)*c) * 1099511628211ull;
    h = (h ^ (uint8_t)*sep) * 1099511628211ull;
    for (int i = 0; i < 8; ++i) h = (h ^ ((r->amount_zat >> (8 * i)) & 0xff)) * 1099511628211ull;
    for (int i = 0; i < 8; ++i) h = (h ^ ((fee >> (8 * i)) & 0xff)) * 1099511628211ull;
    for (size_t i = 0; i < r->memo_len; ++i) h = (h ^ r->memo[i]) * 1099511628211ull;
    h = (h ^ (uint8_t)*sep) * 1099511628211ull;
    for (const char *c = r->key; *c; ++c) h = (h ^ (uint8_t)*c) * 1099511628211ull;
    snprintf(out, WS_TOKEN_MAX, "tok-%016llx", (unsigned long long)h);
}
static bool n_validate(void *c, const char *address, bool *valid) { struct fake *f = c; note(f, 'v', address); *valid = f->address_valid; return true; }
static bool n_gate(void *c, struct ws_gate *out) { struct fake *f = c; note(f, 'g', NULL); *out = f->gate; return true; }
static bool n_plan(void *c, const struct wss_send_req *r, struct ws_plan *out)
{
    struct fake *f = c;
    note(f, 'p', r->address);
    f->plans++;
    assert(r->key[0]);   /* the node binds the key into the token, so the plan request must carry it */
    memcpy(f->plan_key, r->key, sizeof(f->plan_key));
    out->amount_zat = r->amount_zat; out->fee_zat = f->fee; out->total_zat = r->amount_zat + f->fee;
    node_token(r, f->fee, out->token);
    return f->plan_ok;
}
static bool n_unlock(void *c, const char *json, size_t len, uint32_t seconds)
{
    struct fake *f = c;
    note(f, 'u', NULL);
    /* One credential prompt per unwrap, one unwrap per unlock: no unlock rides on an earlier authentication. */
    assert(f->prompts == f->unlocks + 1);
    f->unlocks++;
    f->stdin_ptr = json;
    snprintf(f->stdin_seen, sizeof(f->stdin_seen), "%.*s", (int)len, json);
    assert(seconds == 300);
    return f->unlock_ok;
}
static void tick_ticks(struct fake *f);
static bool n_lock(void *c)
{
    struct fake *f = c;
    note(f, 'l', NULL); f->locks++;
    bool ok = f->lock_ok;
    tick_ticks(f);
    return ok;
}
static int paid_index(const struct fake *f, const char *key)
{
    for (int i = 0; i < f->paid_n; ++i) if (!strcmp(f->paid[i], key)) return i;
    return -1;
}
static enum wss_commit_outcome n_commit(void *c, const struct wss_send_req *r, char echo[WS_TOKEN_MAX],
                                        struct wss_commit_info *info)
{
    struct fake *f = c;
    char token[WS_TOKEN_MAX];
    memset(info, 0, sizeof(*info));
    note(f, 'c', r->address);
    snprintf(f->commit_address, sizeof(f->commit_address), "%s", r->address);
    f->commit_amount = r->amount_zat;
    if (f->commits < 8) memcpy(f->commit_keys[f->commits], r->key, sizeof(r->key));
    f->commits++;
    f->commit_fee = r->fee_zat;
    /* The real node: no fee in the commit is PLAN_REQUIRED, a stale fee is FEE_CHANGED, both before any build. */
    if (r->fee_zat == 0) { f->plan_required++; return WSS_UNKNOWN; }
    if (r->fee_zat != f->fee) return WSS_FEE_CHANGED;
    node_token(r, f->fee, token);
    if (strcmp(token, r->plan_token)) return WSS_UNKNOWN;
    int seen = paid_index(f, r->key);
    if (seen >= 0) {   /* the real node replays the earlier answer for the same key and moves no funds */
        f->repeated_keys++;
        snprintf(echo, WS_TOKEN_MAX, "%s", f->paid_token[seen]);
        if (f->paid_outcome[seen] == WSS_COMMITTED) { info->replayed = true; snprintf(info->txid, sizeof(info->txid), "%s", TXID); }
        return f->paid_outcome[seen];
    }
    if (f->commit_outcome != WSS_KEY_RELEASED && f->paid_n < PAID_MAX) {
        memcpy(f->paid[f->paid_n], r->key, sizeof(r->key));
        snprintf(f->paid_token[f->paid_n], WS_TOKEN_MAX, "%s", f->commit_outcome == WSS_UNKNOWN ? "" : token);
        f->paid_outcome[f->paid_n++] = f->commit_outcome;
    }
    snprintf(echo, WS_TOKEN_MAX, "%s", f->commit_outcome == WSS_UNKNOWN ? "" : token);
    if (f->commit_outcome == WSS_COMMITTED) snprintf(info->txid, sizeof(info->txid), "%s", TXID);
    return f->commit_outcome;
}
static bool n_route(void *c, enum ws_route *out) { struct fake *f = c; note(f, 'r', NULL); *out = f->route; return true; }
/* The device key with a timeout of 0: every unwrap is one prompt, and the secret leaves only with an answer. */
static enum wss_key_status d_unwrap(void *c, uint8_t secret[32])
{
    struct fake *f = c;
    note(f, 'k', NULL);
    f->prompts++;
    if (f->key == WSS_KEY_OK) memcpy(secret, SECRET, 32);
    return f->key;
}
static bool h_random(void *c, uint8_t *out, size_t len)
{
    struct fake *f = c;
    for (size_t i = 0; i < len; ++i) { f->rnd = f->rnd * 6364136223846793005ull + 1442695040888963407ull; out[i] = (uint8_t)(f->rnd >> 33); }
    return true;
}
static uint64_t h_now(void *c) { return ((struct fake *)c)->now; }
struct launch { void (*job)(void *); void *arg; };
static void *thread_main(void *p)
{
    struct launch l = *(struct launch *)p;
    free(p);
    l.job(l.arg);
    return NULL;
}
static bool h_spawn(void *c, void (*job)(void *), void *arg)
{
    struct fake *f = c;
    if (f->spawn_fail) return false;
    if (f->threaded) {
        struct launch *l = malloc(sizeof(*l));
        pthread_t t;
        assert(l);
        *l = (struct launch){job, arg};
        int rc = pthread_create(&t, NULL, thread_main, l);
        assert(rc == 0);
        pthread_detach(t);
        return true;
    }
    assert(!f->job); f->job = job; f->job_arg = arg; return true;
}
/* In the threaded test the worker parks inside the redraw that follows the unlock answer, with the commit
 * action queued and not yet run: the window in which a second scan used to replace the payment. */
static void h_redraw(void *c)
{
    struct fake *f = c;
    __atomic_fetch_add(&f->redraws, 1, __ATOMIC_RELAXED);
    if (!f->threaded || !f->hold || pthread_equal(pthread_self(), f->main_thread)) return;
    struct wss_view v;
    wss_view(f->screen, &v);
    if (v.state != WS_COMMIT) return;
    pthread_mutex_lock(&f->mu);
    f->parked = true;
    pthread_cond_broadcast(&f->cv);
    while (!f->released) pthread_cond_wait(&f->cv, &f->mu);
    pthread_mutex_unlock(&f->mu);
}
static bool h_derive(void *c, const struct zapp_payment *pay, char out[WS_KEY_HEX + 1])
{
    return zapp_send_key_derive(&((struct fake *)c)->id, pay, out);
}
static int64_t h_wall(void *c) { return ((struct fake *)c)->wall; }
static void h_outcome(void *c, int result)
{
    struct fake *f = c;
    __atomic_store_n(&f->last_outcome, result, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&f->outcomes, 1, __ATOMIC_SEQ_CST);
}
static bool s_flag(void *c, bool on) { struct fake *f = c; if (f->flag_ok) f->flag_on = on; return f->flag_ok; }
static bool s_granted(void *c, bool on) { (void)c; (void)on; return true; }
static bool w_set(void *c, bool on)
{
    struct win *w = c;
    w->calls++;
    if (on) w->on_calls++; else w->off_calls++;
    w->on = on;
    return true;
}
static struct zapp_secure_ops win_ops(struct win *w) { return (struct zapp_secure_ops){w, w_set, w_set, w_set, w_set, w_set}; }
static bool s_filter(void *c, bool on) { struct fake *f = c; if (f->filter_ok) f->filter_on = on; return f->filter_ok; }

/* Runs queued worker jobs until none is left. Nothing runs on its own: the UI thread never waits. */
static void drain(struct fake *f)
{
    while (f->job) { void (*job)(void *) = f->job; void *arg = f->job_arg; f->job = NULL; job(arg); }
}
static void fake_init(struct fake *f)
{
    memset(f, 0, sizeof(*f));
    f->gate = (struct ws_gate){.known = true, .send_allowed = true, .spendable_zat = 500000000u, .public_zat = 100000000u};
    f->fee = 10000; f->address_valid = f->plan_ok = f->unlock_ok = f->lock_ok = true;
    f->commit_outcome = WSS_COMMITTED; f->route = WS_ROUTE_SENT; f->key = WSS_KEY_OK;
    f->flag_ok = f->filter_ok = true; f->now = 5000; f->rnd = 42;
    pthread_mutex_init(&f->mu, NULL);
    pthread_cond_init(&f->cv, NULL);
}
/* Ticks that arrive while the worker is blocked in a node call, three seconds apart. */
static void tick_ticks(struct fake *f)
{
    int n = f->ticks_in_lock;
    f->ticks_in_lock = 0;
    for (int i = 0; i < n; ++i) { f->now += 3000; wss_on_tick(f->screen); }
    if (n && f->lock_ok_after_ticks) f->lock_ok = true;
}
static struct wss *screen_of(struct fake *f)
{
    struct wss_deps d = {
        .network = ZAPP_PAY_MAINNET,
        .node = {f, n_validate, n_gate, n_plan, n_unlock, n_lock, n_commit, n_route},
        .device = {f, d_unwrap},
        .host = {f, h_random, h_now, h_spawn, h_redraw, f->derive_on ? h_derive : NULL, h_wall, h_outcome},
        .secure = {f, s_flag, s_filter, s_granted, s_granted, s_granted},
    };
    if (f->window) d.secure = win_ops(f->window);
    struct wss *s = wss_create(&d);
    assert(s);
    f->screen = s;
    return s;
}
static char priv[ZAPP_PAY_ADDRESS_MAX], priv2[ZAPP_PAY_ADDRESS_MAX], pub[ZAPP_PAY_ADDRESS_MAX];
static struct zapp_payment pay_of(const char *address, const char *tail)
{
    char text[512]; struct zapp_payment p;
    snprintf(text, sizeof(text), "zclassic:%s%s", address, tail);
    assert(zapp_payment_parse(text, strlen(text), ZAPP_PAY_MAINNET, &p) == ZAPP_PAY_OK);
    return p;
}
static struct wss_view view_of(struct wss *s) { struct wss_view v; wss_view(s, &v); return v; }
static struct wss *reviewed(struct fake *f, const struct zapp_payment *p)
{
    struct wss *s = screen_of(f);
    assert(wss_begin(s, p));
    assert(f->calls[0] == 0);              /* begin returns at once; the node is asked from the worker */
    drain(f);
    return s;
}
static void tap_and_run(struct wss *s, struct fake *f)
{
    wss_tap_send(s, view_of(s).serial);
    drain(f);
}

static void review_shows_the_plan(void)
{
    struct fake f; fake_init(&f);
    struct zapp_payment p = pay_of(priv, "?amount=1.5&memo=aGk");
    struct wss *s = reviewed(&f, &p);
    struct wss_view v = view_of(s);
    assert(v.visible && v.review && v.state == WS_REVIEW && v.can_send && !strstr(v.note, "Public funds"));
    assert(!strcmp(v.amount, "1.5 ZCL") && !strcmp(v.fee, "0.0001 ZCL") && !strcmp(v.remains, "3.4999 ZCL"));
    assert(!strcmp(v.kind, "Private") && !strcmp(v.memo_label, "Memo") && !strcmp(v.memo, "hi") && !v.warning[0] && !v.note[0]);
    wss_destroy(s);
}
static void review_shows_the_address_and_calls_nothing_else(void)
{
    struct fake f; fake_init(&f);
    struct zapp_payment p = pay_of(priv, "?amount=1.5&memo=aGk");
    struct wss *s = reviewed(&f, &p);
    struct wss_view v = view_of(s);
    assert(!strncmp(v.address, "zs1 qqqq qqqq", 13) && v.address[strlen(v.address) - 1] == 'q');
    char plain[ZAPP_PAY_ADDRESS_MAX]; size_t n = 0;
    for (const char *c = v.address; *c; ++c) if (*c != ' ') plain[n++] = *c;
    plain[n] = 0;
    assert(!strcmp(plain, priv));
    assert(f.commits == 0 && f.unlocks == 0 && !strchr(f.calls, 'k'));
    assert(!strcmp(f.calls, "vgp"));
    assert(f.flag_on && f.filter_on);
    wss_destroy(s);
}
static void tap_runs_the_whole_send(void)
{
    struct fake f; fake_init(&f);
    struct zapp_payment p = pay_of(priv, "?amount=2");
    struct wss *s = reviewed(&f, &p);
    wss_tap_send(s, view_of(s).serial);
    assert(!strcmp(f.calls, "vgp"));   /* the tap itself calls nothing: the UI thread never waits */
    assert(view_of(s).busy);
    drain(&f);
    assert(!strcmp(f.calls, "vgpkuclr"));
    assert(f.commits == 1 && f.unlocks == 1 && f.locks == 1 && f.prompts == 1 && f.commit_fee == 10000 && f.plan_required == 0);
    /* Finding 2: the key the plan was made with is the key the commit used, so the node's answer matches */
    assert(!strcmp(f.plan_key, f.commit_keys[0]) && strlen(f.plan_key) == WS_KEY_HEX);
    /* the passphrase is on standard input only, in the one form, and nowhere else */
    assert(!strcmp(f.stdin_seen, "{\"passphrase\":\"" SECRET_HEX "\",\"timeout_seconds\":300}\n"));
    assert(!strstr(f.args, SECRET_HEX) && !strstr(f.calls, "deadbeef"));
    assert(wss_secrets_clear(s));
    for (size_t i = 0; i < strlen(f.stdin_seen); ++i) assert(f.stdin_ptr[i] == 0);
    struct wss_view v = view_of(s);
    assert(v.state == WS_DONE && !strcmp(v.status, "The payment left the phone. History shows it.") && !v.busy && !v.check_history);
    assert(!strstr(v.status, priv) && !strstr(v.status, "2 ZCL"));
    assert(wss_end(s) && !f.flag_on && !f.filter_on);
    wss_destroy(s);
}
static void public_destination_is_flagged(void)
{
    struct fake f; fake_init(&f);
    struct zapp_payment p = pay_of(pub, "?amount=1");
    struct wss *s = reviewed(&f, &p);
    struct wss_view v = view_of(s);
    assert(!strcmp(v.kind, "Public"));
    assert(!strcmp(v.warning, "This payment is public. The amount and address are visible to everyone, forever."));
    assert(!v.memo[0] && !v.memo_label[0]);
    wss_destroy(s);
}
static void refusals_are_said_in_plain_words(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f);
    f.gate.send_allowed = false;
    snprintf(f.gate.blocked_reason, sizeof(f.gate.blocked_reason), "Older blocks are still being checked.");
    struct wss *s = reviewed(&f, &p);
    struct wss_view v = view_of(s);
    assert(v.state == WS_FAILED && !v.review && !strcmp(v.status, "Older blocks are still being checked.") && !v.can_send);
    assert(!strchr(f.calls, 'p'));
    wss_destroy(s);
    fake_init(&f); f.gate.thermal_paused = true; f.gate.send_allowed = false;
    s = reviewed(&f, &p);
    assert(strstr(view_of(s).status, "too warm") && !strchr(f.calls, 'p'));
    wss_destroy(s);
    fake_init(&f); f.gate.blocks_behind = 12; f.gate.send_allowed = false;
    s = reviewed(&f, &p);
    v = view_of(s);
    assert(v.state == WS_WAITING && v.busy && strstr(v.status, "12 blocks behind") && !v.can_send);
    f.gate = (struct ws_gate){.known = true, .send_allowed = true, .spendable_zat = 500000000u};
    f.now += 6000; wss_on_tick(s); drain(&f);
    assert(view_of(s).state == WS_REVIEW);
    wss_destroy(s);
    fake_init(&f); f.address_valid = false;
    s = reviewed(&f, &p);
    assert(view_of(s).state == WS_FAILED && !strchr(f.calls, 'g') && !strstr(view_of(s).status, priv));
    wss_destroy(s);
}
static void insufficient_says_why_and_emits_nothing(void)
{
    struct fake f; fake_init(&f);
    f.gate.spendable_zat = 100000000; f.gate.public_zat = 900000000;
    struct zapp_payment p = pay_of(priv, "?amount=4");
    struct wss *s = reviewed(&f, &p);
    struct wss_view v = view_of(s);
    assert(v.review && !v.can_send && strstr(v.note, "Not enough private funds") && !v.remains[0]);
    assert(strstr(v.note, "Public funds cannot be spent from this phone. Move them to your private balance from your fleet node."));
    size_t calls = strlen(f.calls);
    wss_tap_send(s, v.serial); drain(&f);
    assert(view_of(s).state == WS_REVIEW && strlen(f.calls) == calls && f.commits == 0 && f.unlocks == 0);
    wss_destroy(s);
    fake_init(&f);
    f.gate.spendable_zat = 100000000; f.gate.public_zat = 0;
    s = reviewed(&f, &p);
    v = view_of(s);
    assert(v.review && strstr(v.note, "Not enough private funds") && !strstr(v.note, "Public funds cannot be spent"));
    wss_destroy(s);
}
static void protection_is_required(void)
{
    struct fake f; fake_init(&f); f.filter_ok = false;
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct wss *s = screen_of(&f);
    assert(!wss_begin(s, &p));
    drain(&f);
    struct wss_view v = view_of(s);
    assert(!v.visible && !v.review && strstr(v.status, "could not be protected") && f.calls[0] == 0);
    assert(!f.flag_on);
    wss_destroy(s);
}
static void leaving_cancels(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f);
    struct wss *s = reviewed(&f, &p);
    wss_on_pause(s); drain(&f);
    assert(view_of(s).state == WS_CANCELLED && !strchr(f.calls, 'k'));
    assert(wss_end(s) && !f.flag_on && !f.filter_on);
    wss_destroy(s);
    /* the system prompt pauses the app: that is not leaving, the send goes on */
    fake_init(&f);
    s = reviewed(&f, &p);
    wss_tap_send(s, view_of(s).serial);
    wss_on_pause(s); wss_on_resume(s); drain(&f);
    assert(view_of(s).state == WS_DONE && f.commits == 1);
    wss_destroy(s);
    /* cancelled between the tap and the prompt: the queued unlock is dead, nothing is opened, the lock runs */
    fake_init(&f);
    s = reviewed(&f, &p);
    wss_tap_send(s, view_of(s).serial);
    wss_tap_cancel(s); drain(&f);
    assert(view_of(s).state == WS_CANCELLED && !strchr(f.calls, 'k') && !strchr(f.calls, 'u') && f.commits == 0);
    assert(f.locks == 1);
    wss_destroy(s);
}
static void secrets_never_survive(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f;
    for (int k = 0; k < 6; ++k) {
        fake_init(&f);
        struct wss *s = reviewed(&f, &p);
        switch (k) {
        case 0: f.unlock_ok = false; break;
        case 1: f.key = WSS_KEY_DECLINED; break;
        case 2: f.key = WSS_KEY_GONE; break;
        case 3: f.key = WSS_KEY_ERROR; break;
        case 4: f.commit_outcome = WSS_UNKNOWN; break;
        default: f.commit_outcome = WSS_KEY_RELEASED; break;
        }
        tap_and_run(s, &f);
        struct wss_view v = view_of(s);
        assert(v.state == WS_FAILED && wss_secrets_clear(s) && !v.busy);
        assert(f.commits == (k >= 4 ? 1 : 0));
        assert(f.locks == 1);                              /* once asked to unlock, the wallet is locked on every way out */
        assert(f.unlocks == (k == 0 || k >= 4 ? 1 : 0));
        assert(f.prompts == 1);
        if (k == 2 || k == 4) assert(!v.can_retry);        /* a gone key and an unknown commit are final */
        else assert(v.can_retry);
        assert(v.check_history == (k == 4));
        assert(!strstr(v.status, priv) && !strstr(v.status, SECRET_HEX));
        wss_destroy(s);
    }
}
/* Finding 1: an unknown commit is final. No retry, no second tap, no second commit; the node's repeated-key
 * refusal is never even reached. */
static void unknown_commit_is_never_retried(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f);
    f.commit_outcome = WSS_UNKNOWN;
    struct wss *s = reviewed(&f, &p);
    tap_and_run(s, &f);
    struct wss_view v = view_of(s);
    assert(f.commits == 1 && v.state == WS_FAILED && !v.can_retry && !v.can_send && v.check_history);
    assert(strstr(v.status, "Check History") && strstr(v.status, "not be sent again") && !strstr(v.status, "Nothing was sent"));
    wss_tap_retry(s); drain(&f);
    wss_tap_send(s, view_of(s).serial); drain(&f);
    wss_tap_send(s, v.serial); drain(&f);
    assert(view_of(s).state == WS_FAILED && f.commits == 1 && f.unlocks == 1 && f.prompts == 1 && f.repeated_keys == 0);
    assert(wss_end(s));
    wss_destroy(s);
}
/* A refused commit proves nothing was sent: the same review tries again on the same key, with a new prompt. */
static void refused_commit_retries_with_a_new_prompt(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f);
    f.commit_outcome = WSS_KEY_RELEASED;
    struct wss *s = reviewed(&f, &p);
    tap_and_run(s, &f);
    assert(f.commits == 1 && view_of(s).can_retry && f.prompts == 1);
    wss_tap_retry(s); drain(&f);
    assert(view_of(s).state == WS_REVIEW && f.commits == 1 && f.prompts == 1);
    tap_and_run(s, &f);
    assert(f.commits == 2 && f.prompts == 2 && f.unlocks == 2);        /* every send is its own authentication */
    wss_tap_retry(s); drain(&f);
    f.commit_outcome = WSS_COMMITTED;
    tap_and_run(s, &f);
    assert(f.commits == 3 && f.prompts == 3 && f.unlocks == 3 && view_of(s).state == WS_DONE);
    assert(!strcmp(f.commit_keys[0], f.commit_keys[1]) && !strcmp(f.commit_keys[1], f.commit_keys[2]));
    assert(strlen(f.commit_keys[0]) == WS_KEY_HEX && f.repeated_keys == 0);
    wss_destroy(s);
}
/* Changing the amount is a new review, with a new key, and the old tap does not carry over. */
static void an_edit_voids_the_old_tap(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f);
    struct wss *s = reviewed(&f, &p);
    uint32_t old = view_of(s).serial;
    wss_edit_amount(s, 250000000); drain(&f);
    struct wss_view v = view_of(s);
    assert(v.state == WS_REVIEW && v.serial != old && !strcmp(v.amount, "2.5 ZCL"));
    wss_tap_send(s, old); drain(&f);
    assert(view_of(s).state == WS_REVIEW && f.commits == 0);
    tap_and_run(s, &f);
    assert(f.commits == 1 && strcmp(f.plan_key, "") != 0 && view_of(s).state == WS_DONE);
    wss_destroy(s);
}
static void progress_shows_the_wait(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f);
    struct wss *s = reviewed(&f, &p);
    wss_tap_send(s, view_of(s).serial);
    struct wss_view v = view_of(s);
    assert(v.state == WS_AUTH && v.busy && strstr(v.status, "screen lock") && v.can_cancel);
    drain(&f);
    wss_destroy(s);
    fake_init(&f);
    s = reviewed(&f, &p);
    f.commit_outcome = WSS_COMMITTED; f.route = WS_ROUTE_WAITING;
    tap_and_run(s, &f);
    v = view_of(s);
    assert(v.state == WS_BROADCAST && v.busy && strstr(v.status, "The node has your payment") && !strstr(v.status, "Sent") && !v.can_cancel && v.can_leave);
    f.route = WS_ROUTE_SENT; f.now += 4000; wss_on_tick(s); drain(&f);
    assert(view_of(s).state == WS_DONE);
    wss_destroy(s);
}
/* The review says whether the owner's fleet checked the wallet, from the gate and from nothing else. */
static void review_says_whether_the_fleet_checked(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f);
    struct wss *s = reviewed(&f, &p);
    assert(view_of(s).review && !strcmp(view_of(s).fleet, "Not checked by your fleet"));
    wss_destroy(s);
    fake_init(&f);
    f.gate.fleet_checked = true;
    s = reviewed(&f, &p);
    assert(view_of(s).review && !strcmp(view_of(s).fleet, "Checked by your fleet"));
    wss_destroy(s);
}
/* Finding 4: a second scan while a send is in progress opens nothing; the commit carries the tapped plan. */
static void second_scan_never_replaces_the_tapped_plan(void)
{
    struct zapp_payment a = pay_of(priv, "?amount=1"), b = pay_of(priv2, "?amount=3.5");
    struct fake f; fake_init(&f);
    struct wss *s = reviewed(&f, &a);
    wss_tap_send(s, view_of(s).serial);                   /* the unlock action is queued */
    assert(!wss_begin(s, &b));
    drain(&f);
    assert(view_of(s).state == WS_DONE && f.commits == 1);
    assert(!strcmp(f.commit_address, priv) && f.commit_amount == 100000000);
    /* a flow in review is not replaced either */
    wss_destroy(s);
    fake_init(&f);
    s = reviewed(&f, &a);
    assert(!wss_begin(s, &b));
    assert(view_of(s).state == WS_REVIEW && !strcmp(view_of(s).amount, "1 ZCL"));
    wss_tap_cancel(s); drain(&f);
    assert(wss_begin(s, &b));                              /* ended: a new code is accepted */
    drain(&f);
    assert(view_of(s).state == WS_REVIEW && !strcmp(view_of(s).amount, "3.5 ZCL") && f.commits == 0);
    wss_destroy(s);
}
/* Actions queued for a flow that has ended never run for the next one. */
static void a_dead_action_does_not_run(void)
{
    struct zapp_payment a = pay_of(priv, "?amount=1"), b = pay_of(priv2, "?amount=3.5");
    struct fake f; fake_init(&f);
    struct wss *s = reviewed(&f, &a);
    wss_tap_send(s, view_of(s).serial);                   /* queue: unlock */
    wss_tap_cancel(s);                                    /* queue: unlock, lock */
    assert(wss_begin(s, &b));                             /* queue: unlock, lock, validate */
    drain(&f);
    assert(!strchr(f.calls, 'k') && !strchr(f.calls, 'u') && !strchr(f.calls, 'c') && f.prompts == 0);
    assert(strchr(f.calls, 'l'));                          /* the lock the first flow owed still ran */
    assert(view_of(s).state == WS_REVIEW && !strcmp(view_of(s).amount, "3.5 ZCL"));
    wss_destroy(s);
}
/* The same with the real worker thread: the worker is parked between the unlock answer and the commit, and a
 * second scan arrives. The commit must carry the first payment. */
static struct fake threaded_fake;
static void pause_ms(long ms) { struct timespec t = {0, ms * 1000000L}; nanosleep(&t, NULL); }
static void wait_state(struct wss *s, enum ws_state want)
{
    for (int i = 0; i < 5000; ++i) {
        if (view_of(s).state == want) return;
        pause_ms(1);
    }
    assert(!"timed out");
}
static void concurrent_scan_with_the_real_worker(void)
{
    struct zapp_payment a = pay_of(priv, "?amount=1"), b = pay_of(priv2, "?amount=3.5");
    struct fake *f = &threaded_fake;
    fake_init(f);
    f->threaded = f->hold = true;
    f->main_thread = pthread_self();
    struct wss *s = screen_of(f);
    assert(wss_begin(s, &a));
    wait_state(s, WS_REVIEW);
    wss_tap_send(s, view_of(s).serial);
    pthread_mutex_lock(&f->mu);
    while (!f->parked) pthread_cond_wait(&f->cv, &f->mu);
    pthread_mutex_unlock(&f->mu);
    /* the commit is queued, the worker is in the redraw */
    assert(view_of(s).state == WS_COMMIT && f->commits == 0);
    assert(!wss_begin(s, &b));
    wss_edit_amount(s, 999999999);
    wss_edit_address(s, priv2);
    pthread_mutex_lock(&f->mu);
    f->released = true;
    pthread_cond_broadcast(&f->cv);
    pthread_mutex_unlock(&f->mu);
    wait_state(s, WS_DONE);
    assert(f->commits == 1 && !strcmp(f->commit_address, priv) && f->commit_amount == 100000000);
    assert(f->repeated_keys == 0 && f->prompts == 1);
    assert(wss_begin(s, &b));                              /* the first flow ended: the next code is accepted */
    wait_state(s, WS_REVIEW);
    wss_destroy(s);
    pause_ms(20);
}

/* The system credential screen pauses the app during authentication. Leaving the screen then must not cancel: the
 * result of the prompt completes the payment, and only the Cancel button ends it. */
static void leaving_during_authentication_does_not_cancel(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f);
    struct wss *s = reviewed(&f, &p);
    wss_tap_send(s, view_of(s).serial);
    assert(view_of(s).state == WS_AUTH);
    wss_on_pause(s);
    assert(!wss_end(s));                       /* the screen stays; nothing was cancelled */
    assert(view_of(s).state == WS_AUTH && f.commits == 0);
    drain(&f);                                 /* the prompt answers */
    struct wss_view v = view_of(s);
    assert(f.commits == 1 && f.prompts == 1 && v.state == WS_DONE && !strstr(v.status, "Cancelled"));
    assert(wss_end(s) && wss_destroy(s));
    /* The Cancel button still ends an authentication. */
    fake_init(&f);
    s = reviewed(&f, &p);
    wss_tap_send(s, view_of(s).serial);
    wss_tap_cancel(s);
    assert(view_of(s).state == WS_CANCELLED);
    drain(&f);
    assert(f.commits == 0);
    wss_destroy(s);
}
/* Once the commit has started, leaving locks the wallet but never cancels or repeats the commit. */
static void leaving_during_the_commit_never_cancels(void)
{
    struct zapp_payment a = pay_of(priv, "?amount=1");
    struct fake *f = &threaded_fake;
    fake_init(f);
    f->threaded = f->hold = true;
    f->main_thread = pthread_self();
    struct wss *s = screen_of(f);
    assert(wss_begin(s, &a));
    wait_state(s, WS_REVIEW);
    wss_tap_send(s, view_of(s).serial);
    pthread_mutex_lock(&f->mu);
    while (!f->parked) pthread_cond_wait(&f->cv, &f->mu);
    pthread_mutex_unlock(&f->mu);
    assert(view_of(s).state == WS_COMMIT);
    wss_on_pause(s);
    assert(!wss_end(s) && view_of(s).state == WS_COMMIT);
    pthread_mutex_lock(&f->mu);
    f->released = true;
    pthread_cond_broadcast(&f->cv);
    pthread_mutex_unlock(&f->mu);
    wait_state(s, WS_DONE);
    assert(f->commits == 1 && f->repeated_keys == 0);
    wss_destroy(s);
    pause_ms(20);
}

static void derived(struct fake *f);
static struct wss *keeper_make(void *c) { return screen_of(c); }
/* The host binds an adopted flow to the fake's own protections, as the app binds it to the new activity's window. */
static void keeper_bind(void *c, struct wss *s)
{
    struct fake *f = c;
    struct zapp_secure_ops ops = f->window ? win_ops(f->window) : (struct zapp_secure_ops){f, s_flag, s_filter, s_granted, s_granted, s_granted};
    assert(wss_rebind(s, &ops));
}
/* The activity is destroyed and re-created while the commit runs. The new activity gets the same flow, not a second
 * one: the same code scanned again is refused, and the outcome of the first payment is what the screen shows. */
static void recreating_the_activity_during_a_commit_keeps_one_payment(void)
{
    struct zapp_payment a = pay_of(priv, "?amount=1");
    struct fake *f = &threaded_fake;
    struct wsk k;
    fake_init(f);
    f->threaded = f->hold = true;
    f->main_thread = pthread_self();
    wsk_init(&k, &(struct wsk_host){f, keeper_make, NULL, keeper_bind});
    assert(wsk_attach(&k));
    struct wss *first = k.screen;
    assert(wss_begin(first, &a));
    wait_state(first, WS_REVIEW);
    wss_tap_send(first, view_of(first).serial);
    pthread_mutex_lock(&f->mu);
    while (!f->parked) pthread_cond_wait(&f->cv, &f->mu);
    pthread_mutex_unlock(&f->mu);
    assert(view_of(first).state == WS_COMMIT);
    wsk_detach(&k);                                        /* the activity is destroyed */
    assert(!k.screen && k.retired == first && wsk_owes(&k));
    assert(wsk_attach(&k) && k.screen == first && k.reshow);   /* the new activity gets the flow back */
    assert(view_of(k.screen).state == WS_COMMIT);
    assert(!wss_begin(k.screen, &a));                      /* the same code again starts nothing */
    assert(f->commits == 0 && view_of(k.screen).state == WS_COMMIT);
    pthread_mutex_lock(&f->mu);
    f->released = true;
    pthread_cond_broadcast(&f->cv);
    pthread_mutex_unlock(&f->mu);
    wait_state(first, WS_DONE);
    assert(f->commits == 1 && f->prompts == 1 && f->repeated_keys == 0);
    /* Another re-creation after the outcome: it is shown again until the owner closes it. */
    wsk_detach(&k);
    assert(k.retired == first);
    assert(wsk_attach(&k) && k.screen == first && !strcmp(view_of(first).status, "The payment left the phone. History shows it."));
    wss_close(first);
    assert(wss_end(first));
    wsk_detach(&k);                                        /* closed: nothing is kept */
    assert(!k.screen && !k.retired);
    pause_ms(20);
}
/* A flow with nothing in flight is not kept. */
static void a_flow_in_review_is_not_kept(void)
{
    struct zapp_payment a = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f);
    struct wsk k;
    wsk_init(&k, &(struct wsk_host){&f, keeper_make, NULL, keeper_bind});
    assert(wsk_attach(&k));
    assert(wss_begin(k.screen, &a));
    drain(&f);
    assert(view_of(k.screen).state == WS_REVIEW);
    wsk_detach(&k);
    assert(!k.screen && !k.retired);
}

/* A flow kept for a re-created activity is bound to the window it began on. Detach drops that binding, so the destroyed
 * activity's window is never touched again; adoption protects the new window before the flow can be drawn. */
static void an_adopted_flow_is_bound_to_the_new_window(void)
{
    struct zapp_payment a = pay_of(priv, "?amount=1");
    struct win old_window = {0}, new_window = {0};
    struct fake f; fake_init(&f);
    f.window = &old_window;
    struct wsk k;
    wsk_init(&k, &(struct wsk_host){&f, keeper_make, NULL, keeper_bind});
    assert(wsk_attach(&k));
    struct wss *first = k.screen;
    assert(wss_begin(first, &a));
    drain(&f);
    assert(old_window.on && old_window.on_calls == 5 && view_of(first).visible);
    tap_and_run(first, &f);
    assert(view_of(first).state == WS_DONE);
    wsk_detach(&k);                                        /* the activity and its window are destroyed */
    assert(k.retired == first);
    int old_calls = old_window.calls;
    assert(!view_of(first).visible);                       /* nothing is drawn until a window is bound */
    f.window = &new_window;                                /* the new activity */
    assert(wsk_attach(&k) && k.screen == first && k.reshow);
    assert(new_window.on && new_window.on_calls == 5 && view_of(first).visible);
    assert(view_of(first).state == WS_DONE);
    wss_close(first);
    assert(wss_end(first));                                /* Done: protections come off the new window */
    assert(new_window.off_calls == 5 && !new_window.on);
    assert(old_window.calls == old_calls);                 /* the old window is never called again */
    wsk_detach(&k);
    assert(old_window.calls == old_calls && !k.screen && !k.retired);
}
/* A window that cannot be protected keeps the adopted payment hidden. */
static void an_unprotectable_new_window_keeps_the_flow_hidden(void)
{
    struct zapp_payment a = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f);
    struct wsk k;
    wsk_init(&k, &(struct wsk_host){&f, keeper_make, NULL, NULL});
    assert(wsk_attach(&k));
    assert(wss_begin(k.screen, &a));
    drain(&f);
    tap_and_run(k.screen, &f);
    wsk_detach(&k);
    assert(wsk_attach(&k) && !view_of(k.screen).visible);  /* adopted and not bound: hidden */
    f.flag_ok = false;
    struct zapp_secure_ops refusing = {&f, s_flag, s_filter, s_granted, s_granted, s_granted};
    assert(!wss_rebind(k.screen, &refusing) && !view_of(k.screen).visible);
    f.flag_ok = true;
    assert(wss_rebind(k.screen, &refusing) && view_of(k.screen).visible);
    wss_close(k.screen);
    assert(wss_end(k.screen));
    wsk_detach(&k);
}

/* An Already paid screen is an outcome the owner has not closed: a re-created activity shows it again, with Pay again, until Done. */
static void an_already_paid_flow_is_kept_until_it_is_closed(void)
{
    struct zapp_payment a = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f); derived(&f);
    struct wsk k;
    wsk_init(&k, &(struct wsk_host){&f, keeper_make, NULL, keeper_bind});
    assert(wsk_attach(&k));
    assert(wss_begin(k.screen, &a));
    drain(&f);
    tap_and_run(k.screen, &f);
    wss_close(k.screen);                                   /* the first payment was closed with Done */
    assert(wss_begin(k.screen, &a));                       /* the same code scanned again */
    drain(&f);
    assert(view_of(k.screen).state == WS_PAID);
    struct wss *first = k.screen;
    wsk_detach(&k);
    assert(!k.screen && k.retired == first);
    assert(wsk_attach(&k) && k.screen == first && k.reshow);
    assert(view_of(first).state == WS_PAID && view_of(first).can_pay_again);
    wss_close(first);
    assert(wss_end(first));
    wsk_detach(&k);
    assert(!k.screen && !k.retired);
}

/* Finding 8: the memo is data in its own field. It cannot fake a review line. */
static void memo_cannot_spoof_a_line(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=0.5");
    struct fake f; fake_init(&f);
    struct wss *s = reviewed(&f, &p);
    const char spoof[] = "thanks\nAmount: 0.1 ZCL\nTo: zs1evil\xe2\x80\xae" "gnp\xe2\x80\x8b\xe2\x81\xa6x\xc2\x85\xef\xbb\xbf";
    wss_edit_memo(s, spoof, sizeof(spoof) - 1); drain(&f);
    struct wss_view v = view_of(s);
    assert(v.state == WS_REVIEW && !strcmp(v.memo_label, "Memo") && !strcmp(v.amount, "0.5 ZCL"));
    assert(!strcmp(v.memo, "thanks<U+000A>Amount: 0.1 ZCL<U+000A>To: zs1evil<U+202E>gnp<U+200B><U+2066>x<U+0085><U+FEFF>"));
    const char *fields[] = {v.amount, v.fee, v.remains, v.address, v.kind, v.memo_label, v.warning, v.note, v.status};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i)
        for (const unsigned char *c = (const unsigned char *)fields[i]; *c; ++c) assert(*c >= 0x20 && *c != 0x7f);
    for (const unsigned char *c = (const unsigned char *)v.memo; *c; ++c) assert(*c >= 0x20 && *c != 0x7f && *c != 0xe2);
    /* ordinary text and non-ASCII letters are shown as they are */
    wss_edit_memo(s, "caf\xc3\xa9 \xe2\x9c\x93", 9); drain(&f);
    v = view_of(s);
    assert(!strcmp(v.memo, "caf\xc3\xa9 \xe2\x9c\x93") && !strcmp(v.memo_label, "Memo"));
    /* bytes that are not text are named as data, not shown */
    wss_edit_memo(s, "\xff\xfe\x01", 3); drain(&f);
    v = view_of(s);
    assert(!strcmp(v.memo_label, "Memo (data)") && !strcmp(v.memo, "3 bytes of data"));
    /* the longest memo made only of line breaks still fits, written out in full */
    char many[ZAPP_PAY_MEMO_MAX];
    memset(many, '\n', sizeof(many));
    wss_edit_memo(s, many, sizeof(many)); drain(&f);
    v = view_of(s);
    assert(strlen(v.memo) == 8 * sizeof(many) && !strncmp(v.memo + strlen(v.memo) - 8, "<U+000A>", 8));
    wss_destroy(s);
}

/* The commit carries the fee the owner saw; a fee that moved since the plan makes a new review. */
static void the_commit_carries_the_planned_fee(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f);
    struct wss *s = reviewed(&f, &p);
    tap_and_run(s, &f);
    assert(view_of(s).state == WS_DONE && f.commit_fee == 10000 && f.plan_required == 0);
    wss_destroy(s);
    fake_init(&f);
    s = reviewed(&f, &p);
    uint32_t old = view_of(s).serial;
    char first[WS_KEY_HEX + 1]; memcpy(first, f.plan_key, sizeof(first));
    f.fee = 25000;                                          /* the wallet fee moves after the plan */
    tap_and_run(s, &f);
    struct wss_view v = view_of(s);
    assert(v.state == WS_FAILED && v.can_retry && !v.check_history && strstr(v.status, "fee changed"));
    assert(f.commits == 1 && f.locks == 1);
    wss_tap_retry(s); drain(&f);
    v = view_of(s);
    assert(v.state == WS_REVIEW && v.serial != old && !strcmp(v.fee, "0.00025 ZCL") && strcmp(first, f.plan_key) != 0);
    tap_and_run(s, &f);
    assert(view_of(s).state == WS_DONE && f.commits == 2 && f.commit_fee == 25000 && f.repeated_keys == 0);
    wss_destroy(s);
}
/* Finding: only a released key says "Nothing was sent". Any other failure is the unknown result. */
static void the_node_replay_reads_as_sent(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f);
    struct wss *s = reviewed(&f, &p);
    tap_and_run(s, &f);
    assert(view_of(s).state == WS_DONE);
    /* the same key committed again is a replay of the first answer, as the real node answers it */
    struct wss_send_req again = {0};
    memcpy(again.address, priv, strlen(priv) + 1);
    again.amount_zat = 100000000; again.fee_zat = 10000;
    memcpy(again.key, f.plan_key, sizeof(again.key));
    node_token(&again, f.fee, again.plan_token);
    char echo[WS_TOKEN_MAX] = "";
    struct wss_commit_info info;
    assert(n_commit(&f, &again, echo, &info) == WSS_COMMITTED && f.repeated_keys == 1 && echo[0] && info.replayed);
    wss_destroy(s);
}
static void outcome_mapping_is_pinned(void)
{
    assert(wss_commit_outcome_of(true, true, NULL) == WSS_COMMITTED);
    assert(wss_commit_outcome_of(true, true, "WALLET_RPC_ERROR") == WSS_COMMITTED);
    assert(wss_commit_outcome_of(true, false, "SEND_REFUSED_KEY_RELEASED") == WSS_KEY_RELEASED);
    assert(wss_commit_outcome_of(true, false, "FEE_CHANGED") == WSS_FEE_CHANGED);
    /* WALLET_RPC_ERROR also covers an admitted transaction whose compensation failed: unknown */
    assert(wss_commit_outcome_of(true, false, "WALLET_RPC_ERROR") == WSS_UNKNOWN);
    assert(wss_commit_outcome_of(true, false, "PLAN_REQUIRED") == WSS_UNKNOWN);
    /* none of these proves that nothing was sent (a reused key proves an earlier send exists, an unknown outcome may have been sent): all read as unknown */
    static const char *const unknown[] = {"SEND_IN_PROGRESS", "SEND_OUTCOME_UNKNOWN", "IDEMPOTENCY_KEY_REUSED",
        "MISSING_IDEMPOTENCY_KEY", "INVALID_IDEMPOTENCY_KEY", "SEND_KEY_RELEASED"};
    for (size_t i = 0; i < sizeof(unknown) / sizeof(unknown[0]); ++i)
        assert(wss_commit_outcome_of(true, false, unknown[i]) == WSS_UNKNOWN);
    assert(wss_commit_outcome_of(true, false, "PLAN_TOKEN_MISMATCH") == WSS_UNKNOWN);
    assert(wss_commit_outcome_of(true, false, "SHIELDED_SEND_FAILED") == WSS_UNKNOWN);
    assert(wss_commit_outcome_of(true, false, "") == WSS_UNKNOWN);
    assert(wss_commit_outcome_of(true, false, NULL) == WSS_UNKNOWN);
    assert(wss_commit_outcome_of(false, true, "SEND_REFUSED_KEY_RELEASED") == WSS_UNKNOWN);   /* no answer */
    assert(wss_commit_outcome_of(false, false, NULL) == WSS_UNKNOWN);
}
/* Every status name zapp_devkey_status_name can return, as the screen reads it and what the owner sees. */
static void device_statuses_are_mapped(void)
{
    static const struct { const char *name; enum wss_key_status want; const char *text; bool retry; } t[] = {
        {"ok", WSS_KEY_OK, NULL, false},
        {"declined", WSS_KEY_DECLINED, "not completed", true},
        {"invalidated", WSS_KEY_GONE, "recovery phrase", false},
        {"not_found", WSS_KEY_GONE, "recovery phrase", false},
        {"corrupt", WSS_KEY_GONE, "recovery phrase", false},
        {"old_format", WSS_KEY_GONE, "recovery phrase", false},
        {"not_hardware", WSS_KEY_GONE, "recovery phrase", false},
        {"not_per_use", WSS_KEY_GONE, "recovery phrase", false},
        {"no_screen_lock", WSS_KEY_NO_SCREEN_LOCK, "screen lock", true},
        {"exists", WSS_KEY_ERROR, "could not be unlocked", true},
        {"strongbox_unavailable", WSS_KEY_ERROR, "could not be unlocked", true},
        {"error", WSS_KEY_ERROR, "could not be unlocked", true},
        {"a_status_from_the_future", WSS_KEY_ERROR, "could not be unlocked", true},
    };
    assert(wss_key_status_of_devkey(NULL) == WSS_KEY_ERROR);
    struct zapp_payment p = pay_of(priv, "?amount=1");
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); ++i) {
        assert(wss_key_status_of_devkey(t[i].name) == t[i].want);
        struct fake f; fake_init(&f);
        f.key = wss_key_status_of_devkey(t[i].name);
        struct wss *s = reviewed(&f, &p);
        tap_and_run(s, &f);
        struct wss_view v = view_of(s);
        if (!t[i].text) { assert(v.state == WS_DONE); wss_destroy(s); continue; }
        assert(v.state == WS_FAILED && v.can_retry == t[i].retry && strstr(v.status, t[i].text));
        assert(f.unlocks == 0 && f.commits == 0);
        wss_destroy(s);
    }
}
/* The wallet may be open: the screen cannot be left or destroyed until the lock is confirmed. */
static void an_owed_lock_keeps_the_screen(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f);
    f.commit_outcome = WSS_KEY_RELEASED; f.lock_ok = false;
    struct wss *s = reviewed(&f, &p);
    tap_and_run(s, &f);
    assert(view_of(s).state == WS_FAILED && f.locks == 3);        /* three attempts, all failed */
    assert(!wss_end(s) && f.flag_on && f.filter_on);
    assert(!wss_destroy(s));
    f.now += 4000; wss_on_tick(s); drain(&f);
    assert(f.locks == 3 && !wss_end(s));                          /* not yet time to ask again */
    f.lock_ok = true; f.now += 2000; wss_on_tick(s); drain(&f);
    assert(f.locks == 4 && wss_end(s) && !f.flag_on);
    assert(wss_destroy(s));
}
/* Ticks pile up while the worker is inside a node call; the lock retry must still run. */
static void ticks_cannot_starve_a_lock(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f);
    f.route = WS_ROUTE_WAITING;
    f.lock_ok = false; f.lock_ok_after_ticks = true; f.ticks_in_lock = 15;
    struct wss *s = reviewed(&f, &p);
    tap_and_run(s, &f);
    assert(f.locks == 2);                                           /* the failed lock was retried */
    assert(view_of(s).state == WS_BROADCAST && !view_of(s).can_cancel);
    f.route = WS_ROUTE_SENT; f.now += 4000; wss_on_tick(s); drain(&f);
    assert(view_of(s).state == WS_DONE && wss_end(s) && wss_destroy(s));
}
/* No worker thread: the UI thread runs nothing. The flow fails before any commit and the lock is still owed. */
static void a_missing_worker_fails_the_flow(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f);
    f.spawn_fail = true;
    struct wss *s = screen_of(&f);
    assert(wss_begin(s, &p));
    struct wss_view v = view_of(s);
    assert(v.state == WS_FAILED && strstr(v.status, "could not start") && f.calls[0] == 0 && f.job == NULL);
    wss_destroy(s);
    fake_init(&f);
    s = reviewed(&f, &p);
    f.spawn_fail = true;
    wss_tap_send(s, view_of(s).serial);
    v = view_of(s);
    assert(v.state == WS_FAILED && strstr(v.status, "Nothing was sent") && v.can_retry);
    assert(!strchr(f.calls, 'k') && !strchr(f.calls, 'u') && !strchr(f.calls, 'c') && f.prompts == 0);
    assert(!wss_end(s));                                            /* the unlock was asked for: a lock is owed */
    f.spawn_fail = false;
    f.now += 1000; wss_on_tick(s); drain(&f);
    assert(f.locks == 1 && f.prompts == 0 && wss_end(s));
    wss_destroy(s);
}

/* ---- a payment request has one key, and the node's record decides what a rescan means ---- */

static void derived(struct fake *f)
{
    f->derive_on = true;
    memset(f->id.bytes, 7, sizeof(f->id.bytes));
    f->wall = WALL_14_32;
}
/* A new process: a new screen over a node that still holds the keys the earlier one sent. */
static void restarted(struct fake *next, const struct fake *old)
{
    fake_init(next);
    derived(next);
    memcpy(next->paid, old->paid, sizeof(next->paid));
    memcpy(next->paid_token, old->paid_token, sizeof(next->paid_token));
    memcpy(next->paid_outcome, old->paid_outcome, sizeof(next->paid_outcome));
    next->paid_n = old->paid_n;
    next->commit_outcome = old->commit_outcome;
    memcpy(next->id.bytes, old->id.bytes, sizeof(next->id.bytes));
}
static void rescan(struct wss *s, struct fake *f, const struct zapp_payment *p)
{
    assert(wss_begin(s, p));
    drain(f);
}
/* Another amount or another memo is another payment. */
static void another_request_is_another_payment(struct wss *s, struct fake *f)
{
    struct zapp_payment other = pay_of(priv, "?amount=2&memo=aGk");
    rescan(s, f, &other);
    assert(view_of(s).state == WS_REVIEW && f->plans == 2);
    wss_tap_cancel(s); drain(f);
    other = pay_of(priv, "?amount=1&memo=aGo");
    rescan(s, f, &other);
    assert(view_of(s).state == WS_REVIEW && f->plans == 3 && strcmp(f->plan_key, f->commit_keys[0]) != 0);
    wss_destroy(s);
}
/* Rescans come 40 minutes after the node's answer and start nothing: the screen shows the stored time, never now. */
static void rescans_show_already_paid(struct wss *s, struct fake *f, const struct zapp_payment *p)
{
    f->wall += 2400;
    for (int again = 0; again < 2; ++again) {
        rescan(s, f, p);
        struct wss_view v = view_of(s);
        assert(v.state == WS_PAID && v.can_pay_again && v.can_leave && !v.busy && !v.can_send && !v.can_retry && !v.can_cancel);
        assert(!strcmp(v.txid, TXID) && !strcmp(v.confirmed, "14:32 UTC") && strstr(v.status, "Already paid"));
        assert(f->plans == 1 && f->commits == 1 && f->prompts == 1 && f->unlocks == 1 && f->repeated_keys == 0);
    }
}
static void a_rescan_of_a_sent_payment_shows_already_paid(void)
{
    for (int waiting = 0; waiting < 2; ++waiting) {
        struct zapp_payment p = pay_of(priv, "?amount=1&memo=aGk");
        struct fake f; fake_init(&f); derived(&f);
        f.route = waiting ? WS_ROUTE_WAITING : WS_ROUTE_SENT;
        struct wss *s = reviewed(&f, &p);
        tap_and_run(s, &f);
        assert(view_of(s).state == (waiting ? WS_BROADCAST : WS_DONE));
        assert(f.plans == 1 && f.commits == 1 && f.prompts == 1 && f.unlocks == 1);
        rescans_show_already_paid(s, &f, &p);
        another_request_is_another_payment(s, &f);
    }
}
static void a_rescan_after_an_unknown_answer_starts_nothing(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f); derived(&f);
    f.commit_outcome = WSS_UNKNOWN;
    struct wss *s = reviewed(&f, &p);
    tap_and_run(s, &f);
    assert(view_of(s).check_history && f.commits == 1);
    for (int again = 0; again < 2; ++again) {
        rescan(s, &f, &p);
        struct wss_view v = view_of(s);
        assert(v.state == WS_FAILED && v.check_history && !v.can_retry && !v.can_send && !v.can_pay_again && v.can_leave);
        assert(strstr(v.status, "Check History") && strstr(v.status, "not be sent again") && !v.txid[0]);
        wss_tap_pay_again(s); drain(&f);
        wss_tap_retry(s); drain(&f);
        wss_tap_send(s, v.serial); drain(&f);
        assert(view_of(s).state == WS_FAILED && !view_of(s).can_pay_again);
        assert(f.plans == 1 && f.commits == 1 && f.prompts == 1 && f.unlocks == 1);
    }
    wss_destroy(s);
}
/* Pay again is a full review, planned under a new random key and committed under it. */
static void pay_again_plans_under_a_new_key(struct wss *s, struct fake *f, const char *first)
{
    wss_tap_pay_again(s); drain(f);
    struct wss_view v = view_of(s);
    assert(v.state == WS_REVIEW && v.can_send && !v.can_pay_again && f->plans == 2 && f->commits == 1 && f->prompts == 1);
    assert(strlen(f->plan_key) == WS_KEY_HEX && strcmp(f->plan_key, first) != 0);
    tap_and_run(s, f);
    assert(f->commits == 2 && f->prompts == 2 && f->unlocks == 2 && strcmp(f->commit_keys[1], first) != 0);
    assert(!strcmp(f->commit_keys[1], f->plan_key) && f->repeated_keys == 0 && view_of(s).state == WS_DONE);
}
static void pay_again_is_offered_only_on_a_committed_payment(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f); derived(&f);
    struct wss *s = reviewed(&f, &p);
    assert(!view_of(s).can_pay_again);
    wss_tap_pay_again(s); drain(&f);                   /* a review is not a paid payment */
    assert(view_of(s).state == WS_REVIEW && f.plans == 1);
    tap_and_run(s, &f);
    char first[WS_KEY_HEX + 1];
    memcpy(first, f.commit_keys[0], sizeof(first));
    assert(view_of(s).state == WS_DONE && !view_of(s).can_pay_again);
    rescan(s, &f, &p);
    assert(view_of(s).can_pay_again);
    pay_again_plans_under_a_new_key(s, &f, first);
    rescan(s, &f, &p);                                 /* the request is still the one the node holds */
    assert(view_of(s).state == WS_PAID && f.plans == 2 && f.commits == 2);
    wss_destroy(s);
}
static void a_fresh_process_asks_the_node_and_the_node_decides(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f); derived(&f);
    struct wss *s = reviewed(&f, &p);
    tap_and_run(s, &f);
    char first[WS_KEY_HEX + 1];
    memcpy(first, f.commit_keys[0], sizeof(first));
    assert(!strcmp(first, f.plan_key));
    wss_destroy(s);
    struct fake g; restarted(&g, &f);
    g.wall = WALL_14_32 + 2400;
    s = reviewed(&g, &p);
    assert(!strcmp(g.plan_key, first) && view_of(s).state == WS_REVIEW);   /* the same request, the same key */
    tap_and_run(s, &g);
    struct wss_view v = view_of(s);
    assert(v.state == WS_PAID && v.can_pay_again && !strcmp(v.txid, TXID) && !strcmp(v.confirmed, "15:12 UTC"));   /* the node answered just now */
    assert(g.repeated_keys == 1 && g.commits == 1 && g.locks == 1 && !strchr(g.calls, 'r') && wss_end(s));
    wss_destroy(s);
    /* an unknown answer is just as lasting */
    struct fake u; fake_init(&u); derived(&u);
    u.commit_outcome = WSS_UNKNOWN;
    s = reviewed(&u, &p);
    tap_and_run(s, &u);
    wss_destroy(s);
    struct fake w; restarted(&w, &u);
    s = reviewed(&w, &p);
    tap_and_run(s, &w);
    v = view_of(s);
    assert(v.state == WS_FAILED && v.check_history && !v.can_retry && !v.can_pay_again && w.commits == 1 && w.repeated_keys == 1);
    wss_destroy(s);
}
static void the_key_follows_the_request(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f); derived(&f);
    struct wss *s = reviewed(&f, &p);
    char k1[WS_KEY_HEX + 1], k2[WS_KEY_HEX + 1], k3[WS_KEY_HEX + 1];
    memcpy(k1, f.plan_key, sizeof(k1));
    wss_edit_amount(s, 200000000); drain(&f);
    memcpy(k2, f.plan_key, sizeof(k2));
    wss_edit_memo(s, "hi", 2); drain(&f);
    memcpy(k3, f.plan_key, sizeof(k3));
    assert(strcmp(k1, k2) && strcmp(k2, k3) && strcmp(k1, k3));
    wss_edit_memo(s, "", 0); wss_edit_amount(s, 100000000); drain(&f);
    assert(!strcmp(f.plan_key, k1));                    /* the same request again is the same key */
    /* a fee that moved before the commit re-plans the same request under the same key */
    f.fee = 25000;
    tap_and_run(s, &f);
    assert(view_of(s).state == WS_FAILED && view_of(s).can_retry && f.commits == 1);
    wss_tap_retry(s); drain(&f);
    assert(view_of(s).state == WS_REVIEW && !strcmp(f.plan_key, k1));
    tap_and_run(s, &f);
    assert(f.commits == 2 && !strcmp(f.commit_keys[0], k1) && !strcmp(f.commit_keys[1], k1) && f.repeated_keys == 0);
    wss_destroy(s);
    struct fake g; fake_init(&g); derived(&g);
    s = reviewed(&g, &p);
    assert(!strcmp(g.plan_key, k1));                    /* a new screen over the same wallet */
    wss_destroy(s);
    struct fake h; fake_init(&h); derived(&h);
    memset(h.id.bytes, 9, sizeof(h.id.bytes));
    s = reviewed(&h, &p);
    assert(strcmp(h.plan_key, k1) != 0);                /* another wallet, another key */
    wss_destroy(s);
}
#define TO "zs1qqqqq…qqqqqq"
/* The commit runs on the real worker while the owner is elsewhere: the progress line says so, the worker is not
 * cancelled, and the outcome is reported exactly once. */
static void a_payment_in_flight_keeps_running_and_reports_once(void)
{
    struct zapp_payment a = pay_of(priv, "?amount=1");
    struct fake *f = &threaded_fake;
    char line[300];
    fake_init(f);
    f->threaded = f->hold = true;
    f->main_thread = pthread_self();
    struct wss *s = screen_of(f);
    assert(wss_begin(s, &a));
    wait_state(s, WS_REVIEW);
    assert(!wss_progress(s, line, sizeof(line)) && !wss_in_flight(s));
    wss_tap_send(s, view_of(s).serial);
    pthread_mutex_lock(&f->mu);
    while (!f->parked) pthread_cond_wait(&f->cv, &f->mu);
    pthread_mutex_unlock(&f->mu);
    assert(wss_in_flight(s) && wss_progress(s, line, sizeof(line)));
    assert(!strcmp(line, "Sending 1 ZCL to " TO ": building the payment (about 2 min)"));
    assert(!strstr(line, priv));   /* only the first eight and the last six characters */
    wss_on_pause(s);               /* the owner left the screen and the app */
    assert(wss_in_flight(s) && f->commits == 0 && f->outcomes == 0);
    pthread_mutex_lock(&f->mu);
    f->released = true;
    pthread_cond_broadcast(&f->cv);
    pthread_mutex_unlock(&f->mu);
    wait_state(s, WS_DONE);
    assert(f->commits == 1 && f->repeated_keys == 0);
    assert(wss_progress(s, line, sizeof(line)) && !strcmp(line, "Sent 1 ZCL") && !wss_in_flight(s));
    wss_on_tick(s); wss_on_tick(s);
    pause_ms(20);
    assert(f->outcomes == 1 && f->last_outcome == ZAPP_PAYMENT_SENT);
    wss_close(s);
    assert(!wss_progress(s, line, sizeof(line)));
    wss_destroy(s);
    pause_ms(20);
}
/* Each status reads in its own words, and each ending is reported once with the right result. */
static void progress_and_notice_follow_each_status(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; char line[300];
    fake_init(&f);
    f.route = WS_ROUTE_WAITING;
    struct wss *s = reviewed(&f, &p);
    tap_and_run(s, &f);
    assert(wss_in_flight(s) && wss_progress(s, line, sizeof(line)));
    assert(!strcmp(line, "Sending 1 ZCL to " TO ": waiting to leave the phone") && f.outcomes == 0);
    f.route = WS_ROUTE_SENT; f.now += 4000; wss_on_tick(s); drain(&f);
    assert(wss_progress(s, line, sizeof(line)) && !strcmp(line, "Sent 1 ZCL"));
    assert(f.outcomes == 1 && f.last_outcome == ZAPP_PAYMENT_SENT);
    wss_destroy(s);
    fake_init(&f);
    f.commit_outcome = WSS_KEY_RELEASED;
    s = reviewed(&f, &p);
    tap_and_run(s, &f);
    assert(wss_progress(s, line, sizeof(line)));
    assert(!strcmp(line, "Payment not sent: the node refused it. Your coins were not spent."));
    assert(f.outcomes == 1 && f.last_outcome == ZAPP_PAYMENT_NOT_SENT);
    wss_destroy(s);
    fake_init(&f);
    s = reviewed(&f, &p);
    f.fee = 20000;   /* the wallet fee moved after the review */
    tap_and_run(s, &f);
    assert(wss_progress(s, line, sizeof(line)));
    assert(!strcmp(line, "Payment not sent: the wallet fee changed. Your coins were not spent."));
    assert(f.outcomes == 1 && f.last_outcome == ZAPP_PAYMENT_NOT_SENT);
    wss_destroy(s);
    fake_init(&f);
    f.commit_outcome = WSS_UNKNOWN;
    s = reviewed(&f, &p);
    tap_and_run(s, &f);
    assert(wss_progress(s, line, sizeof(line)));
    assert(strstr(line, "may have been sent") && strstr(line, "Check History") && !strstr(line, "not spent") && !strstr(line, "not sent"));
    assert(f.outcomes == 1 && f.last_outcome == ZAPP_PAYMENT_UNKNOWN);
    wss_destroy(s);
    fake_init(&f);   /* a refusal before the tap sends no notification and has no progress line */
    f.plan_ok = false;
    s = reviewed(&f, &p);
    assert(!wss_progress(s, line, sizeof(line)) && f.outcomes == 0);
    wss_destroy(s);
}
/* The node answers the commit from its record of the same key: the flow ends as already sent, with one notice, and the
 * progress line does not vanish. */
static void a_replayed_commit_reads_as_already_sent(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; char line[300];
    struct wss_send_req r = {0};
    fake_init(&f);
    struct wss *s = reviewed(&f, &p);
    /* the node holds this key as committed from an earlier send the phone does not know about */
    snprintf(r.address, sizeof(r.address), "%s", p.address);
    r.amount_zat = p.amount_zat;
    memcpy(r.key, f.plan_key, sizeof(r.key));
    node_token(&r, f.fee, f.paid_token[0]);
    memcpy(f.paid[0], f.plan_key, sizeof(f.plan_key));
    f.paid_outcome[0] = WSS_COMMITTED;
    f.paid_n = 1;
    tap_and_run(s, &f);
    assert(f.repeated_keys == 1 && view_of(s).state == WS_PAID);
    assert(wss_progress(s, line, sizeof(line)) && !strcmp(line, "Already sent 1 ZCL"));
    assert(f.outcomes == 1 && f.last_outcome == ZAPP_PAYMENT_SENT);
    wss_on_tick(s); drain(&f);
    assert(f.outcomes == 1);
    wss_destroy(s);
    fake_init(&f);   /* a payment already paid when it is opened is not a progress line */
    s = reviewed(&f, &p);
    assert(!wss_progress(s, line, sizeof(line)));
    wss_destroy(s);
}
/* A Send press while the prover is not ready starts nothing. */
static void a_send_press_without_a_ready_prover_starts_nothing(void)
{
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct fake f; fake_init(&f);
    struct wss *s = reviewed(&f, &p);
    uint32_t serial = view_of(s).serial;
    assert(!wss_tap_send_ready(s, serial, false));
    drain(&f);
    assert(view_of(s).state == WS_REVIEW && f.prompts == 0 && f.commits == 0);
    assert(wss_tap_send_ready(s, serial, true));
    drain(&f);
    assert(f.commits == 1);
    wss_destroy(s);
}
/* Without a ready prover the review offers no Send and says why; once ready it is unchanged. */
static void the_prover_gate_hides_send(void)
{
    struct fake f; fake_init(&f);
    struct zapp_payment p = pay_of(priv, "?amount=1");
    struct wss *s = reviewed(&f, &p);
    struct wss_view v = view_of(s), held = v;
    assert(v.can_send);
    wss_gate_prover(&held, false, "Sending is not ready yet: the payment keys are still being installed. This takes under a minute, once.");
    assert(!held.can_send && !strcmp(held.status, "Sending is not ready yet: the payment keys are still being installed. This takes under a minute, once."));
    wss_gate_prover(&held, false, NULL);
    held = v;
    wss_gate_prover(&held, false, NULL);
    assert(!held.can_send && !strcmp(held.status, "Sending is not ready yet."));
    held = v;
    wss_gate_prover(&held, true, "ignored");
    assert(held.can_send && !strcmp(held.status, v.status));
    wss_destroy(s);
}

static void busy_from_confirm_to_outcome(void)
{
    struct fake f; fake_init(&f);
    struct zapp_payment p = pay_of(priv, "?amount=2");
    struct wss *s = reviewed(&f, &p);
    assert(view_of(s).state == WS_REVIEW && !wss_send_busy(view_of(s).state));
    wss_tap_send(s, view_of(s).serial);
    assert(view_of(s).state == WS_AUTH && wss_send_busy(view_of(s).state));
    drain(&f);
    assert(view_of(s).state == WS_DONE && !wss_send_busy(view_of(s).state));
    wss_destroy(s);
}
static void busy_states_are_the_send_states(void)
{
    for (int st = WS_IDLE; st <= WS_PAID; ++st) {
        bool want = st == WS_AUTH || st == WS_COMMIT || st == WS_BROADCAST;
        assert(wss_send_busy((enum ws_state)st) == want);
    }
}

int main(void)
{
    memcpy(priv, "zs1", 3); memset(priv + 3, 'q', 75); priv[78] = 0;
    memcpy(priv2, "zs1", 3); memset(priv2 + 3, 'p', 75); priv2[78] = 0;
    memcpy(pub, "t1", 2); memset(pub + 2, '2', 33); pub[35] = 0;
    review_shows_the_plan();
    review_shows_the_address_and_calls_nothing_else();
    tap_runs_the_whole_send();
    busy_from_confirm_to_outcome();
    busy_states_are_the_send_states();
    public_destination_is_flagged();
    refusals_are_said_in_plain_words();
    insufficient_says_why_and_emits_nothing();
    protection_is_required();
    leaving_cancels();
    secrets_never_survive();
    unknown_commit_is_never_retried();
    refused_commit_retries_with_a_new_prompt();
    an_edit_voids_the_old_tap();
    progress_shows_the_wait();
    review_says_whether_the_fleet_checked();
    second_scan_never_replaces_the_tapped_plan();
    a_dead_action_does_not_run();
    concurrent_scan_with_the_real_worker();
    leaving_during_authentication_does_not_cancel();
    leaving_during_the_commit_never_cancels();
    a_payment_in_flight_keeps_running_and_reports_once();
    progress_and_notice_follow_each_status();
    the_prover_gate_hides_send();
    a_replayed_commit_reads_as_already_sent();
    a_send_press_without_a_ready_prover_starts_nothing();
    recreating_the_activity_during_a_commit_keeps_one_payment();
    a_flow_in_review_is_not_kept();
    an_already_paid_flow_is_kept_until_it_is_closed();
    an_adopted_flow_is_bound_to_the_new_window();
    an_unprotectable_new_window_keeps_the_flow_hidden();
    memo_cannot_spoof_a_line();
    the_commit_carries_the_planned_fee();
    the_node_replay_reads_as_sent();
    outcome_mapping_is_pinned();
    device_statuses_are_mapped();
    an_owed_lock_keeps_the_screen();
    ticks_cannot_starve_a_lock();
    a_missing_worker_fails_the_flow();
    a_rescan_of_a_sent_payment_shows_already_paid();
    a_rescan_after_an_unknown_answer_starts_nothing();
    pay_again_is_offered_only_on_a_committed_payment();
    a_fresh_process_asks_the_node_and_the_node_decides();
    the_key_follows_the_request();
    puts("wallet_send_screen_test: ok");
    return 0;
}

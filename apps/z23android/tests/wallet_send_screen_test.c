/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "wallet_send_screen.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOG_MAX 4096
#define PAID_MAX 16

static const uint8_t SECRET[32] = {0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                   13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28};
#define SECRET_HEX "deadbeef0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"

/* A node, a device key and a host, all scripted. */
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
    int commits, unlocks, locks, prompts, repeated_keys, plan_required;
    uint64_t commit_fee;
    bool spawn_fail;
    int ticks_in_lock;            /* Ticks that arrive while a lock call is blocked. */
    bool lock_ok_after_ticks;
    char stdin_seen[256];
    const char *stdin_ptr;
    uint64_t now;
    void (*job)(void *);
    void *job_arg;
    int redraws, make_private;
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
static enum wss_commit_outcome n_commit(void *c, const struct wss_send_req *r, char echo[WS_TOKEN_MAX])
{
    struct fake *f = c;
    char token[WS_TOKEN_MAX];
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
        return f->paid_outcome[seen];
    }
    if (f->commit_outcome != WSS_KEY_RELEASED && f->paid_n < PAID_MAX) {
        memcpy(f->paid[f->paid_n], r->key, sizeof(r->key));
        snprintf(f->paid_token[f->paid_n], WS_TOKEN_MAX, "%s", f->commit_outcome == WSS_UNKNOWN ? "" : token);
        f->paid_outcome[f->paid_n++] = f->commit_outcome;
    }
    snprintf(echo, WS_TOKEN_MAX, "%s", f->commit_outcome == WSS_UNKNOWN ? "" : token);
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
static void h_private(void *c) { ((struct fake *)c)->make_private++; }
static bool s_flag(void *c, bool on) { struct fake *f = c; if (f->flag_ok) f->flag_on = on; return f->flag_ok; }
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
        .host = {f, h_random, h_now, h_spawn, h_redraw, h_private},
        .secure = {f, s_flag, s_filter},
    };
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
    assert(v.visible && v.review && v.state == WS_REVIEW && v.can_send && !v.offer_make_private);
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
    assert(!strncmp(v.address, "zs1q qqqq qqqq", 14) && v.address[strlen(v.address) - 1] == 'q');
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
    assert(v.state == WS_DONE && !strcmp(v.status, "Payment sent.") && !v.busy && !v.check_history);
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
static void insufficient_offers_make_private(void)
{
    struct fake f; fake_init(&f);
    f.gate.spendable_zat = 100000000; f.gate.public_zat = 900000000;
    struct zapp_payment p = pay_of(priv, "?amount=4");
    struct wss *s = reviewed(&f, &p);
    struct wss_view v = view_of(s);
    assert(v.review && !v.can_send && v.offer_make_private && strstr(v.note, "Not enough private funds") && !v.remains[0]);
    wss_tap_send(s, v.serial); drain(&f);
    assert(view_of(s).state == WS_REVIEW && !strchr(f.calls, 'k') && !strchr(f.calls, 'c'));
    wss_tap_make_private(s); drain(&f);
    assert(f.make_private == 1 && f.commits == 0 && f.unlocks == 0);
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
    assert(v.state == WS_BROADCAST && v.busy && strstr(v.status, "private route") && !v.can_cancel);
    f.route = WS_ROUTE_SENT; f.now += 4000; wss_on_tick(s); drain(&f);
    assert(view_of(s).state == WS_DONE);
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
    assert(n_commit(&f, &again, echo) == WSS_COMMITTED && f.repeated_keys == 1 && echo[0]);
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

int main(void)
{
    memcpy(priv, "zs1", 3); memset(priv + 3, 'q', 75); priv[78] = 0;
    memcpy(priv2, "zs1", 3); memset(priv2 + 3, 'p', 75); priv2[78] = 0;
    memcpy(pub, "t1", 2); memset(pub + 2, '2', 33); pub[35] = 0;
    review_shows_the_plan();
    review_shows_the_address_and_calls_nothing_else();
    tap_runs_the_whole_send();
    public_destination_is_flagged();
    refusals_are_said_in_plain_words();
    insufficient_offers_make_private();
    protection_is_required();
    leaving_cancels();
    secrets_never_survive();
    unknown_commit_is_never_retried();
    refused_commit_retries_with_a_new_prompt();
    an_edit_voids_the_old_tap();
    progress_shows_the_wait();
    second_scan_never_replaces_the_tapped_plan();
    a_dead_action_does_not_run();
    concurrent_scan_with_the_real_worker();
    memo_cannot_spoof_a_line();
    the_commit_carries_the_planned_fee();
    the_node_replay_reads_as_sent();
    outcome_mapping_is_pinned();
    device_statuses_are_mapped();
    an_owed_lock_keeps_the_screen();
    ticks_cannot_starve_a_lock();
    a_missing_worker_fails_the_flow();
    puts("wallet_send_screen_test: ok");
    return 0;
}

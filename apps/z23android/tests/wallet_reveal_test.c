/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "wallet_reveal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Show private balance over a fake device key, node and host. The fixtures hold no real key: the secret is a fixed pattern
 * and the node is a counter. The host runs a job when the test says so, so a prompt that is still up can be observed. */

#define SECRET_BYTE 0xa5
#define SECRET_HEX "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"

static struct {
    enum wss_key_status key;
    bool unlock_ok, lock_ok, busy, defer, spawn_ok;
    int prompts, unlocks, locks, redraws;
    uint32_t last_seconds;
    char json[WSS_UNLOCK_JSON];
    uint64_t now;
    void (*job)(void *arg);
    void *arg;
    void (*in_prompt)(void);
    void (*in_unlock)(void);
    struct wrv *view;
} fake;

static enum wss_key_status f_unwrap(void *ctx, uint8_t secret[32])
{
    (void)ctx;
    ++fake.prompts;
    if (fake.in_prompt) fake.in_prompt();
    if (fake.key == WSS_KEY_OK) memset(secret, SECRET_BYTE, 32);
    return fake.key;
}
static bool f_unlock(void *ctx, const char *json, size_t len, uint32_t seconds)
{
    (void)ctx;
    ++fake.unlocks;
    fake.last_seconds = seconds;
    assert(len == strlen(json) && len < sizeof(fake.json));
    memcpy(fake.json, json, len + 1);
    if (fake.in_unlock) fake.in_unlock();
    return fake.unlock_ok;
}
static bool f_lock(void *ctx)
{
    (void)ctx;
    ++fake.locks;
    return fake.lock_ok;
}
static uint64_t f_now(void *ctx) { (void)ctx; return fake.now; }
static void f_redraw(void *ctx) { (void)ctx; ++fake.redraws; }
static bool f_spawn(void *ctx, void (*job)(void *arg), void *arg)
{
    (void)ctx;
    if (!fake.spawn_ok) return false;
    if (fake.defer) {
        assert(!fake.job);
        fake.job = job;
        fake.arg = arg;
        return true;
    }
    job(arg);
    return true;
}
static bool f_busy(void *ctx) { (void)ctx; return fake.busy; }

/* Runs the job the host held. */
static void run_pending(void)
{
    void (*job)(void *) = fake.job;
    void *arg = fake.arg;
    assert(job);
    fake.job = NULL;
    job(arg);
}

static void fresh(bool defer)
{
    if (fake.view) {
        bool freed = wrv_destroy(fake.view);
        assert(freed);
    }
    memset(&fake, 0, sizeof(fake));
    fake.key = WSS_KEY_OK;
    fake.unlock_ok = fake.lock_ok = fake.spawn_ok = true;
    fake.defer = defer;
    fake.now = 1000000;
    struct wrv_deps deps = {0};
    deps.node = (struct wss_node_ops){.unlock = f_unlock, .lock = f_lock};
    deps.device = (struct wss_device_ops){.unwrap = f_unwrap};
    deps.host = (struct wss_host_ops){.now_ms = f_now, .spawn = f_spawn, .redraw = f_redraw};
    deps.busy = f_busy;
    fake.view = wrv_create(&deps);
    assert(fake.view);
}

/* The owner confirms, the node unlocks, and the window opens for WRV_WINDOW_SECONDS. */
static void test_open_and_window(void)
{
    fresh(true);
    assert(wrv_state(fake.view) == WALLET_REVEAL_NONE && !wrv_owes(fake.view));
    assert(wrv_begin(fake.view));
    assert(wrv_state(fake.view) == WALLET_REVEAL_ASKING && wrv_owes(fake.view) && fake.prompts == 0);
    assert(!wrv_begin(fake.view) && fake.job);   /* one prompt at a time */
    run_pending();
    assert(fake.prompts == 1 && fake.unlocks == 1 && fake.last_seconds == WRV_WINDOW_SECONDS);
    assert(strstr(fake.json, "\"passphrase\":\"" SECRET_HEX "\"") && strstr(fake.json, "\"timeout_seconds\":120}\n"));
    assert(wrv_state(fake.view) == WALLET_REVEAL_OPEN && wrv_secrets_clear(fake.view) && fake.redraws > 0);
    assert(!wrv_begin(fake.view) && fake.prompts == 1);   /* no second prompt while the window is open */
    fake.now += 119000;
    wrv_tick(fake.view);
    assert(fake.locks == 0 && wrv_state(fake.view) == WALLET_REVEAL_OPEN);
    fake.now += 1000;
    wrv_tick(fake.view);   /* the window is over: the wallet is locked again */
    assert(wrv_state(fake.view) == WALLET_REVEAL_OPEN);   /* until the lock is done */
    run_pending();
    assert(fake.locks == 1 && wrv_state(fake.view) == WALLET_REVEAL_NONE && !wrv_owes(fake.view));
    wrv_tick(fake.view);
    assert(fake.locks == 1);
    printf("  unlock for the window, then lock when it ends\n");
}

/* A cancelled, declined or failed prompt leaves the wallet locked, with nothing sent to the node and nothing to lock. */
static void test_prompt_refused(void)
{
    static const struct { enum wss_key_status key; enum wallet_reveal want; } cases[] = {
        {WSS_KEY_DECLINED, WALLET_REVEAL_CANCELLED}, {WSS_KEY_NO_SCREEN_LOCK, WALLET_REVEAL_NO_SCREEN_LOCK},
        {WSS_KEY_GONE, WALLET_REVEAL_KEY_GONE}, {WSS_KEY_ERROR, WALLET_REVEAL_FAILED},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        fresh(false);
        fake.key = cases[i].key;
        assert(wrv_begin(fake.view));
        assert(fake.prompts == 1 && fake.unlocks == 0 && fake.locks == 0);
        assert(wrv_state(fake.view) == cases[i].want && !wrv_owes(fake.view) && wrv_secrets_clear(fake.view));
        wrv_end(fake.view);
        assert(fake.locks == 0 && wrv_state(fake.view) == WALLET_REVEAL_NONE);
        assert(wrv_begin(fake.view) && fake.prompts == 2);   /* a new tap asks again */
    }
    printf("  cancelled or refused prompt changes nothing\n");
}

/* A node that did not confirm the unlock may still have opened the wallet, so the lock is asked for until it answers. */
static void test_unlock_unconfirmed(void)
{
    fresh(false);
    fake.unlock_ok = false;
    fake.lock_ok = false;
    assert(wrv_begin(fake.view));
    assert(fake.unlocks == 1 && fake.locks == 1 && wrv_owes(fake.view) && wrv_secrets_clear(fake.view));
    assert(wrv_state(fake.view) == WALLET_REVEAL_OPEN);   /* not known to be locked */
    assert(!wrv_begin(fake.view));
    wrv_tick(fake.view);
    assert(fake.locks == 2 && wrv_owes(fake.view));
    fake.lock_ok = true;
    wrv_tick(fake.view);
    assert(fake.locks == 3 && !wrv_owes(fake.view) && wrv_state(fake.view) == WALLET_REVEAL_FAILED);
    wrv_tick(fake.view);
    assert(fake.locks == 3);
    printf("  unconfirmed unlock is locked, retried until the node answers\n");
}

/* Leaving the screens or hiding the app locks the wallet at once. */
static void test_end_locks(void)
{
    fresh(false);
    assert(wrv_begin(fake.view) && wrv_state(fake.view) == WALLET_REVEAL_OPEN);
    wrv_end(fake.view);
    assert(fake.locks == 1 && wrv_state(fake.view) == WALLET_REVEAL_NONE && !wrv_owes(fake.view));
    wrv_end(fake.view);
    assert(fake.locks == 1);   /* nothing owed, nothing asked */
    /* A failed lock stays owed and is asked again on the next tick. */
    fresh(false);
    assert(wrv_begin(fake.view));
    fake.lock_ok = false;
    wrv_end(fake.view);
    assert(fake.locks == 1 && wrv_owes(fake.view));
    fake.lock_ok = true;
    wrv_tick(fake.view);
    assert(fake.locks == 2 && !wrv_owes(fake.view));
    printf("  leaving locks the wallet and a failed lock is retried\n");
}

static void end_in_prompt(void) { wrv_end(fake.view); }
static void end_in_unlock(void) { wrv_end(fake.view); }

/* The owner leaves while the prompt is up: the answer opens nothing. If it leaves while the node unlocks, the wallet is locked. */
static void test_end_during_prompt(void)
{
    fresh(false);
    fake.in_prompt = end_in_prompt;
    assert(wrv_begin(fake.view));
    assert(fake.prompts == 1 && fake.unlocks == 0 && fake.locks == 0);
    assert(wrv_state(fake.view) == WALLET_REVEAL_NONE && !wrv_owes(fake.view) && wrv_secrets_clear(fake.view));

    fresh(false);
    fake.in_unlock = end_in_unlock;
    assert(wrv_begin(fake.view));
    assert(fake.unlocks == 1 && fake.locks == 1);
    assert(wrv_state(fake.view) == WALLET_REVEAL_NONE && !wrv_owes(fake.view) && wrv_secrets_clear(fake.view));
    printf("  leaving during the prompt opens nothing; during the unlock it locks\n");
}

/* A payment in flight holds the wallet open under its own unlock: this view never locks under it and never asks for it. */
static void test_payment_in_flight(void)
{
    fresh(false);
    fake.busy = true;
    assert(!wrv_begin(fake.view));
    assert(fake.prompts == 0 && fake.unlocks == 0 && wrv_state(fake.view) == WALLET_REVEAL_SENDING && !wrv_owes(fake.view));
    fake.busy = false;
    assert(wrv_begin(fake.view) && wrv_state(fake.view) == WALLET_REVEAL_OPEN);   /* a new tap works once it ends */

    fake.busy = true;   /* a payment starts inside the window */
    wrv_end(fake.view);
    assert(fake.locks == 0 && !wrv_owes(fake.view) && wrv_state(fake.view) == WALLET_REVEAL_NONE);

    fresh(false);
    assert(wrv_begin(fake.view));
    fake.busy = true;
    fake.now += (uint64_t)WRV_WINDOW_SECONDS * 1000u;
    wrv_tick(fake.view);   /* the window ends while a payment runs */
    assert(fake.locks == 0 && !wrv_owes(fake.view));

    fresh(false);   /* a lock owed after an unconfirmed unlock is dropped too */
    fake.unlock_ok = false;
    fake.lock_ok = false;
    assert(wrv_begin(fake.view) && wrv_owes(fake.view));
    fake.busy = true;
    wrv_tick(fake.view);
    assert(fake.locks == 1 && !wrv_owes(fake.view));
    printf("  never locks under a payment in flight\n");
}

static void test_spawn_failure(void)
{
    fresh(false);
    fake.spawn_ok = false;
    assert(!wrv_begin(fake.view));
    assert(wrv_state(fake.view) == WALLET_REVEAL_FAILED && !wrv_owes(fake.view) && fake.prompts == 0);
    fake.spawn_ok = true;
    assert(wrv_begin(fake.view) && wrv_state(fake.view) == WALLET_REVEAL_OPEN);
    printf("  a worker that cannot start leaves the wallet locked\n");
}

int main(void)
{
    printf("private balance on request:\n");
    test_open_and_window();
    test_prompt_refused();
    test_unlock_unconfirmed();
    test_end_locks();
    test_end_during_prompt();
    test_payment_in_flight();
    test_spawn_failure();
    wrv_end(fake.view);
    if (fake.view) {
        bool freed = wrv_destroy(fake.view);
        assert(freed);
    }
    printf("private balance on request: all tests passed\n");
    return 0;
}

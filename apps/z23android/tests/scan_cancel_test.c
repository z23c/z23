/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include <stdbool.h>
#define ZAPP_WALLET_SEND_UI_H
bool zapp_send_busy(void);
#include "../controller.c"
#include <assert.h>

static int offers, clears;
static bool held;
bool zapp_pay_stash_offer(const char *payload, enum zapp_scan_kind kind)
{ (void)payload; ++offers; held = kind == ZAPP_SCAN_PAY; return held; }
void zapp_pay_stash_clear(void) { ++clears; held = false; }
void zapp_camera_stop(void) {}
bool zapp_speech_client_paired(const char *files, const char *json)
{ (void)files; (void)json; return false; }
bool zapp_pair_code(const char *descriptor, char code[7])
{ (void)descriptor; memcpy(code, "123456", 7); return true; }

static struct controller c;
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static bool waiting, release_worker, committed;
static void *blocked_commit(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&gate); waiting = true; pthread_cond_signal(&changed);
    while (!release_worker) pthread_cond_wait(&changed, &gate);
    pthread_mutex_unlock(&gate);
    enum zapp_scan_kind kind = ZAPP_SCAN_PAY;
    char value[32] = "payment"; const char *notice = NULL;
    committed = scan_commit(&c, 7, "payment", &kind, value, &notice);
    return NULL;
}
int main(void)
{
    assert(!pthread_mutex_init(&c.lock, NULL));
    current = &c; memcpy(c.action, "scan", sizeof("scan")); c.camera_ticket = 7; c.view.scanning = true;
    pthread_t worker; assert(!pthread_create(&worker, NULL, blocked_commit, NULL));
    pthread_mutex_lock(&gate); while (!waiting) pthread_cond_wait(&changed, &gate); pthread_mutex_unlock(&gate);
    zapp_controller_cancel_scan();
    pthread_mutex_lock(&gate); release_worker = true; pthread_cond_signal(&changed); pthread_mutex_unlock(&gate);
    assert(!pthread_join(worker, NULL)); assert(!committed && offers == 0 && clears == 1);
    c.scan_cancelled = false; c.view.scanning = true;
    enum zapp_scan_kind payment = ZAPP_SCAN_PAY; char payment_value[32] = "payment"; const char *payment_notice = NULL;
    assert(scan_commit(&c, 7, "payment", &payment, payment_value, &payment_notice) && held);
    zapp_controller_cancel_scan(); assert(!held);
    c.scan_cancelled = false; c.view.scanning = true;
    enum zapp_scan_kind kind = ZAPP_SCAN_PAIR; char value[32] = "descriptor"; const char *notice = NULL;
    assert(scan_commit(&c, 7, "descriptor", &kind, value, &notice));
    assert(c.scan_pair_owned && !strcmp(c.view.pair_offer, "descriptor"));
    c.view.scanning = false; /* The owner can dismiss a just-finished review. */
    zapp_controller_cancel_scan();
    assert(!c.scan_pair_owned && !c.view.pair_offer[0] && !c.view.pair_code[0]);
    c.scan_cancelled = false; c.view.scanning = true;
    kind = ZAPP_SCAN_PAIR; assert(scan_commit(&c, 7, "descriptor", &kind, value, &notice));
    pthread_mutex_lock(&c.lock); assert(pair_control(&c, "pair_offer", "new offer")); pthread_mutex_unlock(&c.lock);
    zapp_controller_cancel_scan(); assert(!strcmp(c.view.pair_offer, "new offer"));
    c.scan_cancelled = false; c.view.scanning = true;
    kind = ZAPP_SCAN_PAY; assert(!scan_commit(&c, 6, "payment", &kind, value, &notice));
    assert(offers == 3);
    current = NULL; pthread_mutex_destroy(&c.lock);
    return 0;
}

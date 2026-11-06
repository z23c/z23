/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include <stdbool.h>
#define ZAPP_WALLET_SEND_UI_H
bool zapp_send_busy(void);
#include "../controller.c"
#include "../fleet_review_state.h"
#include <assert.h>

bool zapp_send_busy(void) { return false; }
const char *zapp_node_stop_refusal(bool busy) { (void)busy; return NULL; }
void zapp_restart_stopped(struct zapp_restart *r) { (void)r; }
bool zapp_node_start_reserve(struct zapp_runtime *r, uint64_t *ticket, char *out, size_t cap)
{ (void)r; (void)out; (void)cap; *ticket = 42; return true; }
bool zapp_node_stop(struct zapp_runtime *r, char *out, size_t cap)
{ (void)r; (void)out; (void)cap; return true; }

static int offers, clears;
static bool fixture_paired;
static bool held;
bool zapp_pay_stash_offer(const char *payload, enum zapp_scan_kind kind)
{ (void)payload; ++offers; held = kind == ZAPP_SCAN_PAY; return held; }
void zapp_pay_stash_clear(void) { ++clears; held = false; }
void zapp_camera_stop(void) {}
uint64_t zapp_camera_ticket(void) { return 7; }
bool zapp_action_shows_itself(const char *action) { (void)action; return true; }
const char *zapp_action_doing(const char *action) { (void)action; return NULL; }
void zapp_action_refusal(enum zapp_refusal why, const char *running, const char *asked, char *out, size_t cap)
{ (void)why; (void)running; (void)asked; (void)out; (void)cap; }
bool zapp_hosts_label(const char *report, size_t index, char label[16])
{ (void)report; (void)index; (void)label; return false; }
bool zapp_speech_client_paired(const char *files, const char *json)
{ (void)files; (void)json; return fixture_paired; }
bool zapp_pair_code(const char *descriptor, char code[7])
{ (void)descriptor; memcpy(code, "123456", 7); return true; }
static int join_calls;
enum zapp_onion zapp_onion_wait(struct zapp_runtime *r, unsigned seconds, void (*waiting)(void *), void *arg)
{ (void)r; (void)seconds; (void)waiting; (void)arg; return ZAPP_ONION_NODE_STOPPED; }
bool zapp_fleet_join_run(struct zapp_runtime *r, const char *token, char *out, size_t cap)
{ (void)r; (void)token; (void)out; (void)cap; ++join_calls; return false; }
bool zapp_fleet_join_receipt(const char *text, char *receipt, size_t cap)
{ (void)text; (void)receipt; (void)cap; return false; }
bool zapp_fleet_receipt_save(const char *directory, const char *token)
{ (void)directory; (void)token; return false; }
static int machine_calls, invite_calls;
enum zapp_preview_result zapp_fleet_machine_preview_cancelable(struct zapp_runtime *r, const char *s, char *o, size_t n, const atomic_bool *cancel)
{ (void)r; (void)s; (void)o; (void)n; ++machine_calls; return atomic_load(cancel) ? ZAPP_PREVIEW_CANCELLED : ZAPP_PREVIEW_FAILED; }
enum zapp_preview_result zapp_fleet_preview_cancelable(struct zapp_runtime *r, const char *s, char *o, size_t n, const atomic_bool *cancel)
{ (void)r; (void)s; (void)o; (void)n; (void)cancel; ++invite_calls; return ZAPP_PREVIEW_OK; }
bool zapp_fleet_machine_preview_run(struct zapp_runtime *r, const char *s, char *o, size_t n)
{ (void)r; (void)s; (void)o; (void)n; ++machine_calls; return false; }
bool zapp_fleet_preview_run(struct zapp_runtime *r, const char *s, char *o, size_t n)
{ (void)r; (void)s; (void)o; (void)n; ++invite_calls; return true; }
bool zapp_fleet_machine_preview_text(const char *s, char *p, size_t n, char *o, size_t m)
{ (void)s; (void)p; (void)n; (void)o; (void)m; return false; }
bool zapp_fleet_preview_text(const char *s, char *p, size_t n)
{ (void)s; (void)p; (void)n; return true; }
const char *zapp_json_object(const char *s) { (void)s; return NULL; }
void zapp_plain_text(char *s, size_t n) { (void)s; (void)n; }

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
static void paired_notice(void)
{
    fixture_paired = true; c.scan_cancelled = false; c.view.scanning = true;
    enum zapp_scan_kind kind = ZAPP_SCAN_PAIR; char value[32] = "descriptor"; const char *notice = NULL;
    assert(scan_commit(&c, 7, "descriptor", &kind, value, &notice));
    assert(kind == ZAPP_SCAN_TEXT && !value[0] && !c.view.scan_text[0]);
    assert(notice && !strcmp(notice, "That laptop is already paired."));
}

int main(void)
{
    assert(zapp_fleet_node_state(false, false, false, false) == ZAPP_FLEET_NODE_START);
    assert(zapp_fleet_node_state(false, false, false, true) == ZAPP_FLEET_NODE_WAIT);
    assert(zapp_fleet_node_state(false, true, true, false) == ZAPP_FLEET_NODE_WAIT);
    assert(zapp_fleet_node_state(false, true, false, false) == ZAPP_FLEET_NODE_READY);
    assert(zapp_fleet_node_state(true, false, false, false) == ZAPP_FLEET_NODE_READY);
    bool joined = false, started = false;
    zapp_fleet_review_select(&joined, &started, true);
    assert(!strcmp(zapp_fleet_review_message(joined, started, "join failed", "old start"), "join failed"));
    zapp_fleet_review_select(&joined, &started, false);
    assert(!strcmp(zapp_fleet_review_message(joined, started, "old join", "start failed"), "start failed"));
    zapp_fleet_review_select(&joined, &started, true);
    assert(!strcmp(zapp_fleet_review_message(joined, started, "join failed", "old start"), "join failed"));
    assert(!strcmp(zapp_fleet_review_message(false, false, "old join", "old start"), ""));
    assert(!pthread_mutex_init(&c.lock, NULL));
    assert(!pthread_cond_init(&c.changed, NULL));
    char join_output[ZAPP_TEXT_CAP] = "";
    assert(!join_fleet(&c, "synthetic", join_output));
    assert(join_calls == 0 && strstr(join_output, "Start the node first"));
    c.camera_ticket = 7; c.start_ticket = 42;
    assert(action_ticket(&c, "node_start") == 42 && action_ticket(&c, "scan") == 7);
    c.view.scanning = true;
    scan_denied(&c, 8); assert(!c.view.scan_permission_denied);
    c.scan_cancelled = true; scan_denied(&c, 7); assert(!c.view.scan_permission_denied);
    c.scan_cancelled = false; scan_denied(&c, 7); assert(c.view.scan_permission_denied);
    c.view.scan_permission_denied = false;
    current = &c; c.view.busy = true;
    assert(!zapp_controller_action("scan", "", NULL, 0));
    c.view.busy = false; assert(zapp_controller_action("scan", "", NULL, 0));
    assert(c.view.scanning && c.camera_ticket == 7);
    c.pending = false; c.view.busy = false; c.view.scanning = false;
    clears = 0;
    current = &c; memcpy(c.action, "scan", sizeof("scan")); c.camera_ticket = 7; c.view.scanning = true;
    pthread_t worker; assert(!pthread_create(&worker, NULL, blocked_commit, NULL));
    pthread_mutex_lock(&gate); while (!waiting) pthread_cond_wait(&changed, &gate); pthread_mutex_unlock(&gate);
    zapp_controller_cancel_scan();
    assert(atomic_load(&c.scan_cancel));
    pthread_mutex_lock(&gate); release_worker = true; pthread_cond_signal(&changed); pthread_mutex_unlock(&gate);
    assert(!pthread_join(worker, NULL)); assert(!committed && offers == 0 && clears == 1);
    c.scan_cancelled = false; c.view.scanning = true;
    memcpy(c.action, "scan_paste", sizeof("scan_paste")); assert(scan_action(c.action));
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
    static char reply[ZAPP_TEXT_CAP]; char preview[2048] = "", onion[128] = "", error[256] = "";
    bool machine = false, cancelled = false;
    atomic_store(&c.scan_cancel, true);
    assert(!fleet_review_run(&c, "code", false, false, reply, preview, onion, error, &machine, false, &cancelled));
    assert(cancelled && machine_calls == 1 && invite_calls == 0);
    assert(fleet_review_run(&c, "code", false, false, reply, preview, onion, error, &machine, true, &cancelled));
    assert(!cancelled && machine_calls == 2 && invite_calls == 1);
    paired_notice();
    current = NULL; pthread_mutex_destroy(&c.lock);
    return 0;
}

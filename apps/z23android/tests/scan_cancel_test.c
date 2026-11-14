/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include <stdbool.h>
#define ZAPP_CONTROLLER_TEST
#define ZAPP_WALLET_SEND_UI_H
bool zapp_send_busy(void);
#include "../controller.c"
#include "../fleet_review_state.h"
#include <assert.h>
#define zapp_node_stop_refusal test_real_stop_refusal
#define zapp_handoff_hold_begin test_real_hold_begin
#define zapp_handoff_hold_end test_real_hold_end
#include "../node_restart.c"
#undef zapp_node_stop_refusal
#undef zapp_handoff_hold_begin
#undef zapp_handoff_hold_end

static bool send_busy;
bool zapp_send_busy(void) { return send_busy; }
const char *zapp_node_stop_refusal(bool busy) { (void)busy; return NULL; }
bool zapp_node_start_reserve(struct zapp_runtime *r, uint64_t *ticket, char *out, size_t cap)
{ (void)r; (void)out; (void)cap; *ticket = 42; return true; }
bool zapp_node_stop(struct zapp_runtime *r, char *out, size_t cap)
{ (void)r; (void)out; (void)cap; return true; }
bool zapp_node_handoff_resume_reserve(struct zapp_runtime *r, uint64_t epoch, uint64_t *ticket, char *out, size_t cap)
{ (void)r; (void)epoch; (void)out; (void)cap; *ticket = 43; return true; }
bool zapp_node_handoff_current(struct zapp_runtime *r, uint64_t epoch)
{ (void)r; (void)epoch; return false; }
static bool handoff_hold;
bool zapp_handoff_hold_begin(bool (*busy)(void))
{ if (handoff_hold || busy()) return false; handoff_hold = true; return true; }
void zapp_handoff_hold_end(void) { handoff_hold = false; }
enum zapp_pace zapp_node_pace(const struct zapp_runtime *r) { (void)r; return ZAPP_PACE_NORMAL; }
static int handoff_stops;
bool zapp_node_handoff_stop(struct zapp_runtime *r, const struct zapp_node_identity *id, uint64_t *epoch)
{ (void)r; ++handoff_stops; *epoch = id->epoch + 1; return true; }

static int discarded;
void zapp_node_start_discard(struct zapp_runtime *r, uint64_t ticket)
{ (void)r; assert(ticket == 42); ++discarded; }
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

static bool fixture_progress;
bool zapp_installer_observe_locked(struct zapp_runtime *r, struct zapp_replay_progress *out, bool *has)
{
    bool active = r->installer > 0 && !r->stopping && !atomic_load(&r->start_cancel) &&
        r->installer_epoch == r->start_epoch;
    *has = active && fixture_progress;
    if (*has) *out = (struct zapp_replay_progress){.phase = ZAPP_REPLAY_BLOCK_INDEX, .next = 50};
    return active;
}
void zapp_nodelog_replay_text(const struct zapp_replay_progress *p, char *out, size_t cap)
{ snprintf(out, cap, "Preparing block index: %lld%%", (long long)p->next); }
const char *zapp_suggestion(bool paired, bool responding, int64_t height, int64_t target, int64_t peers,
                            const char *report, const char *asked, char *out, size_t cap)
{
    (void)paired; (void)height; (void)target; (void)peers; (void)report; (void)asked;
    snprintf(out, cap, "%s", responding ? "current" : "checking");
    return out;
}
static void installer_view_case(void)
{
    static struct controller test;
    assert(!pthread_mutex_init(&test.lock, NULL));
    assert(!pthread_mutex_init(&test.runtime.mutex, NULL));
    test.runtime.installer = 123; test.runtime.start_epoch = test.runtime.installer_epoch = 7;
    test.view.node_running = true; test.view.chain_state = ZAPP_CHAIN_CURRENT;
    test.view.node_reference = 100; test.seen_responding = true;
    snprintf(test.view.node_line, sizeof(test.view.node_line), "Node in sync");
    fixture_progress = false;
    assert(observe_installer(&test));
    assert(test.view.node_installing && !test.view.node_stopping && !test.view.node_running);
    assert(test.view.chain_state == ZAPP_CHAIN_NONE && test.view.node_reference == -1 && !test.seen_responding);
    assert(!strcmp(test.view.node_line, "Node starting") && !test.view.node_wallet_replaying);
    fixture_progress = true;
    assert(observe_installer(&test));
    assert(test.view.node_wallet_replaying && strstr(test.view.node_wallet_replay, "50%"));
    atomic_store(&test.runtime.start_cancel, true); ++test.runtime.start_epoch;
    assert(observe_installer(&test));
    assert(test.view.node_installing && test.view.node_stopping && !test.view.node_wallet_replaying);
    assert(!strcmp(test.view.node_line, "Node stopping") && test.view.node_wallet_replay[0] == 0);
    assert(test.view.chain_state == ZAPP_CHAIN_NONE && !test.seen_responding);
    pthread_mutex_destroy(&test.runtime.mutex); pthread_mutex_destroy(&test.lock);
}

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

static void status_cases(void)
{
    static const char good[] = "{\"ok\":true,\"data\":{\"provable_tip\":1,\"restart_pending\":true,\"restart_bundle_height\":42,\"restart_bundle_bytes\":100,\"restart_bundle_digest\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}}";
    struct node_reading n = read_status(good);
    assert(n.responding && n.restart_pending && strlen(n.digest) == 64);
    static struct controller test;
    test.pace_lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    struct zapp_node_identity id = {.pid = 10, .epoch = 4};
    handoff_offer_locked(&test, &n, &id, true, true, ZAPP_PACE_PAUSE);
    assert(!handoff_stops);
    send_busy = true; handoff_offer_locked(&test, &n, &id, true, true, ZAPP_PACE_NORMAL);
    assert(!handoff_stops); send_busy = false;
    handoff_offer_locked(&test, &n, &id, true, true, ZAPP_PACE_NORMAL);
    assert(handoff_stops == 1 && test.handoff_wait && test.handoff_epoch == 5);
    test.handoff_wait = false;
    handoff_offer_locked(&test, &n, &id, true, true, ZAPP_PACE_NORMAL);
    assert(handoff_stops == 1);
    zapp_handoff_hold_end(); pthread_mutex_destroy(&test.pace_lock);
    n = read_status("{\"ok\":true,\"data\":{\"provable_tip\":1,\"restart_pending\":true}}");
    assert(n.responding && !n.restart_pending);
    n = read_status("{\"ok\":true,\"data\":{\"provable_tip\":1,\"restart_pending\":false}}");
    assert(n.responding && !n.restart_pending);
    n = read_status("{bad"); assert(!n.responding && !n.restart_pending);
}

static void allocation_failure_case(void)
{
    handoff_hold = true; c.handoff_active = c.handoff_wait = true;
    execute_test_fail_allocation = true;
    assert(!execute_output(&c, "node_resume", 42));
    execute_test_fail_allocation = false;
    assert(discarded == 1 && !handoff_hold && !c.handoff_active && !c.handoff_wait);
}

static void preview_observation_case(void)
{
    static struct controller test;
    test.runtime.preview = true;
    observe_node(&test);
    assert(node_observations_for_test == 0);
    test.runtime.preview = false;
    observe_node(&test);
    assert(node_observations_for_test == 1);
}

static void unexpected_exit_observation_view(void)
{
    struct controller c = {0};
    struct zapp_restart_seen s = {.wanted = true, .ready = true, .now = 100};
    bool changed = false;
    zapp_restart_started(&c.restart);
    assert(!restart_observe_view(&c, &s, &changed));
    assert(changed && c.view.node_unexpected_exit);
    s.now = 130; assert(restart_observe_view(&c, &s, &changed));
    assert(changed && !c.view.node_unexpected_exit);
    zapp_restart_started(&c.restart); s.now = 131;
    assert(!restart_observe_view(&c, &s, &changed) && c.view.node_unexpected_exit);
    zapp_restart_stopped(&c.restart); s.wanted = false;
    assert(!restart_observe_view(&c, &s, &changed) && !c.view.node_unexpected_exit);
}

int main(void)
{
    unexpected_exit_observation_view();
    preview_observation_case();
    installer_view_case();
    struct zapp_runtime delayed = {0};
    delayed.start_epoch = 10; delayed.installer_generation = 20;
    uint64_t epoch = delayed.start_epoch, generation = delayed.installer_generation;
    assert(status_current_locked(&delayed, epoch, generation));
    delayed.installer = 123; ++delayed.installer_generation;
    assert(!status_current_locked(&delayed, epoch, generation));
    delayed.installer = 0;
    assert(!status_current_locked(&delayed, epoch, generation));
    generation = delayed.installer_generation; ++delayed.start_epoch;
    assert(!status_current_locked(&delayed, epoch, generation));
    status_cases();
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
    allocation_failure_case();
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

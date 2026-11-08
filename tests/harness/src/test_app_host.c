/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Coordinator lifecycle fixtures use an actual signed, pinned carrier. */
#include "test/test_core.h"
#include "base/hex.h"
#include "chain/chainparams.h"
#include "command/native_command.h"
#include "command/native_app_compose.h"
#include "config/boot_app_host.h"
#include "config/boot_fleet_board.h"
#include "controllers/rpc_client.h"
#include "crypto/ed25519.h"
#include "models/database.h"
#include "models/app_host_intent.h"
#include "models/fleet_board_post.h"
#include "json/json.h"
#include "util/fleet_role_check.h"
#include "vcs/app_offer.h"
#include "vcs/bundle_carry.h"
#include "vcs/package_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>

/* Constructed by the existing signed-copy/share fixture; the caller owns the
 * returned isolated fixture tree. It restores the process HOME before return. */
extern bool test_app_host_fixture_create(char *fixture_root, size_t root_cap,
    char *share_path, size_t share_cap, struct zcl_app_offer *offer);

struct app_host_test_world {
    char root[512], share[700], store_path[700], db_path[700];
    struct zcl_app_offer offer;
    struct vcs_package_store *store;
    struct node_db db;
};

static bool app_host_test_open(struct app_host_test_world *w)
{
    memset(w, 0, sizeof(*w));
    if (!test_app_host_fixture_create(w->root, sizeof(w->root), w->share,
                                      sizeof(w->share), &w->offer)) return false;
    int n = snprintf(w->store_path, sizeof(w->store_path), "%s/host-store", w->root);
    int d = snprintf(w->db_path, sizeof(w->db_path), "%s/host.db", w->root);
    if (n < 0 || (size_t)n >= sizeof(w->store_path) || d < 0 || (size_t)d >= sizeof(w->db_path)) return false;
    w->store = vcs_package_store_open(w->store_path, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    size_t len = 0; uint8_t root[32], expected[32];
    uint8_t *bytes = zcl_native_source_bundle_read(w->share, &len);
    bool ok = w->store && bytes && zcl_hex_decode_lower(w->offer.carrier, expected, sizeof(expected)) &&
        vcs_bundle_put_to_no_evict(w->store, bytes, len, root) == VCS_BUNDLE_OK &&
        !memcmp(root, expected, sizeof(root)) &&
        vcs_package_store_pin(w->store, root, true) == VCS_PACKAGE_STORE_OK &&
        node_db_open(&w->db, w->db_path);
    free(bytes); return ok;
}

static bool app_host_test_close(struct app_host_test_world *w)
{
    if (w->db.open) node_db_close(&w->db);
    if (w->store) vcs_package_store_close(w->store);
    return w->root[0] && test_rm_rf_recursive(w->root) == 0;
}

/* Fixture clock is supplied to enable/tick, never to the machine clock. */
struct app_host_test_hooks_state {
    uint8_t seed[32], host[32];
    char endpoint[ZCL_APP_OFFER_ONION_MAX + 1u];
    unsigned announcements;
    unsigned signs, guard_calls;
    int sign_result, verify_result;
    bool signed_bound;
    uint8_t last_id[32];
    bool interrupt_after_ingest, lookup_error;
    const char *datadir;
    struct vcs_package_store *store;
    uint8_t carrier[32];
    bool unpin_before_guard;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    bool block_guard, entered_guard, release_guard;
};

static bool app_host_test_datadir(void *ctx, const char *datadir)
{
    struct app_host_test_hooks_state *s = ctx;
    return datadir && s->datadir && !strcmp(datadir, s->datadir);
}

static bool app_host_test_identity(void *ctx, uint8_t host[32], bool create)
{
    struct app_host_test_hooks_state *s = ctx;
    (void)create; memcpy(host, s->host, 32); return true;
}

static bool app_host_test_endpoint(void *ctx, char host[63], char endpoint[ZCL_APP_OFFER_ONION_MAX + 1u])
{
    struct app_host_test_hooks_state *s = ctx;
    (void)snprintf(host, 63, "%.62s", s->endpoint);
    (void)snprintf(endpoint, ZCL_APP_OFFER_ONION_MAX + 1u, "%s", s->endpoint);
    return true;
}

static bool app_host_test_sign(void *ctx, struct fleet_board_post *post)
{
    struct app_host_test_hooks_state *s = ctx;
    ++s->signs;
    s->sign_result = fleet_board_post_sign(post, s->seed, s->host);
    s->verify_result = fleet_board_post_verify(post);
    s->signed_bound = boot_fleet_board_validate_app_offer(post, s->host);
    return s->sign_result == FLEET_BOARD_OK;
}

static void app_host_test_announce(void *ctx, const uint8_t id[32])
{
    struct app_host_test_hooks_state *s = ctx;
    ++s->announcements; memcpy(s->last_id, id, 32);
}

static bool app_host_test_after_ingest(void *ctx, const uint8_t id[32])
{
    struct app_host_test_hooks_state *s = ctx;
    (void)id; return !s->interrupt_after_ingest;
}

static void app_host_test_before_guard(void *ctx)
{
    struct app_host_test_hooks_state *s = ctx;
    ++s->guard_calls;
    if (s->unpin_before_guard) {
        s->unpin_before_guard = false;
        (void)vcs_package_store_pin(s->store, s->carrier, false);
    }
    if (s->block_guard) {
        pthread_mutex_lock(&s->mutex);
        s->entered_guard = true; pthread_cond_broadcast(&s->condition);
        while (!s->release_guard) pthread_cond_wait(&s->condition, &s->mutex);
        pthread_mutex_unlock(&s->mutex);
    }
}

static int app_host_test_lookup(void *ctx, struct node_db *db, const uint8_t id[32],
                                struct db_fleet_board_post *out)
{
    struct app_host_test_hooks_state *s = ctx;
    return s->lookup_error ? FLEET_BOARD_LOOKUP_ERROR : db_fleet_board_post_lookup_checked(db, id, out);
}

struct app_host_test_plan {
    struct boot_app_host_plan plan;
    char id[65], source_host[65], expected[65];
};

static bool app_host_test_plan_create(struct app_host_test_world *w,
    struct app_host_test_plan *p, int64_t now)
{
    static const char receive[] = "1111111111111111111111111111111111111111111111111111111111111111";
    static const char token[] = "22222222222222222222222222222222";
    uint8_t seed[32] = {7}, private_key[32], public_key[32], digest[32];
    struct fleet_board_post post = {0}; bool stored = false;
    ed25519_keypair(public_key, private_key, seed); memcpy(seed, private_key, 32);
    post.kind = FLEET_BOARD_KIND_OFFER; post.scope = FLEET_BOARD_SCOPE_PUBLIC;
    post.created_at = (uint64_t)now; post.ttl = 86400;
    (void)snprintf(post.room, sizeof(post.room), "apps");
    (void)snprintf(post.agent, sizeof(post.agent), "fixture");
    if (!zcl_app_offer_format(&w->offer, post.text, sizeof(post.text))) return false;
    post.text_len = (uint32_t)strlen(post.text);
    if (fleet_board_post_sign(&post, seed, public_key) != FLEET_BOARD_OK ||
        db_fleet_board_post_ingest(&w->db, &post, now, &stored) != FLEET_BOARD_OK || !stored) return false;
    memset(p, 0, sizeof(*p)); zcl_hex_encode(post.id, 32, p->id);
    zcl_hex_encode(public_key, 32, p->source_host);
    p->plan.offer = w->offer; p->plan.post_id = p->id; p->plan.post_host = p->source_host;
    p->plan.receive_plan = receive; p->plan.datadir = w->store_path; p->plan.token = token;
    if (!vcs_app_get_recurring_plan(&p->plan.offer, p->id, p->source_host, receive,
                                    p->plan.datadir, token, digest)) return false;
    zcl_hex_encode(digest, 32, p->expected); p->plan.expected_plan = p->expected;
    return true;
}

static bool app_host_test_plan_rehash(struct app_host_test_plan *p)
{
    uint8_t digest[32];
    if (!vcs_app_get_recurring_plan(&p->plan.offer, p->plan.post_id, p->plan.post_host,
            p->plan.receive_plan, p->plan.datadir, p->plan.token, digest)) return false;
    zcl_hex_encode(digest, sizeof(digest), p->expected); return true;
}

static void app_host_test_legacy_plan(struct app_host_test_plan *p)
{
    const struct zcl_app_offer *o = &p->plan.offer;
    const char *parts[] = {p->plan.post_id, p->plan.post_host, o->name, o->root,
        o->publisher, o->carrier, o->sha256, o->onion, p->plan.receive_plan,
        p->plan.datadir, p->plan.token, "public-rebuild-report-v1",
        "pin-carrier-and-public-host-if-ready-24h-v1"};
    uint8_t digest[32];
    vcs_app_plan_hash("zcl.app_get.plan.v1", parts, sizeof(parts) / sizeof(parts[0]), digest);
    zcl_hex_encode(digest, sizeof(digest), p->expected);
}

struct app_host_test_thread {
    struct app_host_test_world *world;
    uint8_t host[32]; int64_t generation, now;
    enum boot_app_host_result result;
    atomic_bool started, done;
};

static void *app_host_test_tick_thread(void *arg)
{
    struct app_host_test_thread *t = arg;
    t->result = boot_app_host_tick(&t->world->db, t->world->store, t->now);
    atomic_store(&t->done, true); return NULL;
}

static void *app_host_test_stop_thread(void *arg)
{
    struct app_host_test_thread *t = arg;
    atomic_store(&t->started, true);
    t->result = boot_app_host_stop(&t->world->db, t->host,
                                   t->world->offer.carrier, t->generation);
    atomic_store(&t->done, true); return NULL;
}

static bool app_host_test_wait_guard(struct app_host_test_hooks_state *s)
{
    struct timespec deadline;
    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) return false;
    deadline.tv_sec += 10;
    pthread_mutex_lock(&s->mutex);
    int result = 0;
    while (!s->entered_guard && result == 0)
        result = pthread_cond_timedwait(&s->condition, &s->mutex, &deadline);
    bool entered = s->entered_guard; pthread_mutex_unlock(&s->mutex);
    return entered;
}

static bool app_host_test_wait_started(struct app_host_test_thread *t)
{
    struct timespec pause = {.tv_nsec = 1000000};
    for (unsigned i = 0; i < 1000 && !atomic_load(&t->started); ++i) (void)nanosleep(&pause, NULL);
    if (!atomic_load(&t->started)) return false;
    pause.tv_nsec = 100000000; (void)nanosleep(&pause, NULL);
    return !atomic_load(&t->done);
}

static int host_cli_response_tests(void);

int model_app_host_coordinator_tests(void)
{
    int failures = 0; struct app_host_test_world w = {0};
    struct app_host_test_hooks_state s = {0}; struct app_host_test_plan plan;
    struct db_app_host_intent row; struct db_fleet_board_post found;
    uint8_t sk[32], selected_host[32], first_id[32], prior_id[32]; int64_t generation = 0;
    struct app_host_test_thread tick = {0}, stop = {0};
    pthread_t tick_id, stop_id; bool tick_live = false, stop_live = false;
    bool sync_ready = false;
    struct boot_app_host_test_hooks hooks = {
        .context = &s, .identity = app_host_test_identity, .datadir = app_host_test_datadir,
        .endpoint = app_host_test_endpoint, .sign = app_host_test_sign,
        .announce = app_host_test_announce, .before_guard = app_host_test_before_guard,
        .after_ingest = app_host_test_after_ingest, .lookup = app_host_test_lookup
    };
    TEST("app host coordinator: real carrier consent, restart, renewal and revocation") {
        ASSERT_EQ(pthread_mutex_init(&s.mutex, NULL), 0);
        ASSERT_EQ(pthread_cond_init(&s.condition, NULL), 0); sync_ready = true;
        zcl_fleet_role_checker_install_permissive_for_testing();
        ASSERT(app_host_test_open(&w));
        s.seed[0] = 11; ed25519_keypair(s.host, sk, s.seed); memcpy(s.seed, sk, 32);
        s.datadir = w.store_path; s.store = w.store;
        ASSERT(zcl_hex_decode_lower(w.offer.carrier, s.carrier, sizeof(s.carrier)));
        (void)snprintf(s.endpoint, sizeof(s.endpoint),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:29135");
        boot_app_host_set_test_hooks(&hooks);
        char original_root = w.offer.root[0];
        w.offer.root[0] = original_root == '0' ? '1' : '0';
        ASSERT(app_host_test_plan_create(&w, &plan, 432100));
        ASSERT_EQ(boot_app_host_enable(&w.db, w.store, &plan.plan, 432100, selected_host, &generation), BOOT_APP_HOST_INVALID);
        ASSERT_EQ(db_app_host_intent_find(&w.db, s.host, w.offer.carrier, &row), APP_HOST_NOT_FOUND);
        w.offer.root[0] = original_root;
        ASSERT(app_host_test_plan_create(&w, &plan, 432100));
        app_host_test_legacy_plan(&plan);
        ASSERT_EQ(boot_app_host_enable(&w.db, w.store, &plan.plan, 432100, selected_host, &generation), BOOT_APP_HOST_INVALID);
        ASSERT_EQ(db_app_host_intent_find(&w.db, s.host, w.offer.carrier, &row), APP_HOST_NOT_FOUND);
        plan.plan.datadir = "/different/private/datadir";
        ASSERT(app_host_test_plan_rehash(&plan));
        ASSERT_EQ(boot_app_host_enable(&w.db, w.store, &plan.plan, 432100, selected_host, &generation), BOOT_APP_HOST_INVALID);
        plan.plan.datadir = w.store_path; ASSERT(app_host_test_plan_rehash(&plan));
        ASSERT_EQ(vcs_package_store_pin(w.store, s.carrier, false), VCS_PACKAGE_STORE_OK);
        ASSERT_EQ(boot_app_host_enable(&w.db, w.store, &plan.plan, 432100, selected_host, &generation), BOOT_APP_HOST_INVALID);
        ASSERT_EQ(vcs_package_store_pin(w.store, s.carrier, true), VCS_PACKAGE_STORE_OK);
        ASSERT_EQ(boot_app_host_enable(&w.db, w.store, &plan.plan, 432100, selected_host, &generation), BOOT_APP_HOST_OK);
        ASSERT(generation == 1 && !memcmp(selected_host, s.host, 32));
        s.interrupt_after_ingest = true;
        enum boot_app_host_result first_tick = boot_app_host_tick(&w.db, w.store, 432100);
        if (first_tick != BOOT_APP_HOST_BUSY)
            printf("tick diagnosis: result=%d signs=%u sign=%d verify=%d bound=%d guards=%u announcements=%u\n",
                   first_tick, s.signs, s.sign_result, s.verify_result, s.signed_bound,
                   s.guard_calls, s.announcements);
        ASSERT_EQ(first_tick, BOOT_APP_HOST_BUSY);
        ASSERT_EQ(db_app_host_intent_find(&w.db, selected_host, w.offer.carrier, &row), APP_HOST_OK);
        ASSERT(row.pending && row.enabled); memcpy(first_id, row.pending_id, 32);
        ASSERT_EQ(db_fleet_board_post_lookup_checked(&w.db, first_id, &found), FLEET_BOARD_LOOKUP_FOUND);
        ASSERT_EQ(s.announcements, 0u);
        node_db_close(&w.db); ASSERT(node_db_open(&w.db, w.db_path));
        s.interrupt_after_ingest = false;
        ASSERT_EQ(boot_app_host_tick(&w.db, w.store, 432100), BOOT_APP_HOST_OK);
        ASSERT_EQ(s.announcements, 1u); ASSERT(!memcmp(s.last_id, first_id, 32));
        ASSERT_EQ(db_app_host_intent_find(&w.db, selected_host, w.offer.carrier, &row), APP_HOST_OK);
        ASSERT(!row.pending && row.due_at == 475200);
        /* Force loss of possession after reservation, before the store guard. */
        s.unpin_before_guard = true;
        ASSERT_EQ(boot_app_host_tick(&w.db, w.store, 475200), BOOT_APP_HOST_BUSY);
        ASSERT_EQ(db_app_host_intent_find(&w.db, selected_host, w.offer.carrier, &row), APP_HOST_OK);
        ASSERT(row.pending); memcpy(prior_id, row.pending_id, 32);
        ASSERT_EQ(db_fleet_board_post_lookup_checked(&w.db, prior_id, &found), FLEET_BOARD_LOOKUP_ABSENT);
        ASSERT_EQ(vcs_package_store_pin(w.store, s.carrier, true), VCS_PACKAGE_STORE_OK);
        (void)snprintf(s.endpoint, sizeof(s.endpoint),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion:29135");
        s.lookup_error = true;
        ASSERT_EQ(boot_app_host_tick(&w.db, w.store, 475260), BOOT_APP_HOST_STORAGE);
        ASSERT_EQ(db_app_host_intent_find(&w.db, selected_host, w.offer.carrier, &row), APP_HOST_OK);
        ASSERT(row.pending && !memcmp(row.pending_id, prior_id, 32));
        s.lookup_error = false;
        node_db_close(&w.db); ASSERT(node_db_open(&w.db, w.db_path));
        ASSERT_EQ(boot_app_host_tick(&w.db, w.store, 518400), BOOT_APP_HOST_OK);
        ASSERT_EQ(s.announcements, 2u); ASSERT(memcmp(s.last_id, prior_id, 32));
        memcpy(prior_id, s.last_id, 32);
        ASSERT_EQ(boot_app_host_tick(&w.db, w.store, 561600), BOOT_APP_HOST_OK);
        ASSERT_EQ(s.announcements, 3u); ASSERT(memcmp(s.last_id, prior_id, 32));
        /* Identity rotation does not transfer consent; the old identity is
         * still explicitly revocable without loading its signing key. */
        memset(s.seed, 0, sizeof(s.seed)); s.seed[0] = 12;
        ed25519_keypair(s.host, sk, s.seed); memcpy(s.seed, sk, 32);
        ASSERT_EQ(boot_app_host_tick(&w.db, w.store, 604800), BOOT_APP_HOST_OK);
        ASSERT_EQ(s.announcements, 3u);
        ASSERT_EQ(boot_app_host_stop(&w.db, selected_host, w.offer.carrier, generation), BOOT_APP_HOST_OK);
        ASSERT_EQ(db_app_host_intent_find(&w.db, selected_host, w.offer.carrier, &row), APP_HOST_OK);
        ASSERT(!row.enabled && !row.pending && row.generation == generation + 1);
        node_db_close(&w.db); ASSERT(node_db_open(&w.db, w.db_path));
        ASSERT_EQ(boot_app_host_tick(&w.db, w.store, 648000), BOOT_APP_HOST_OK);
        ASSERT_EQ(s.announcements, 3u);
        /* A stop concurrent with a guarded publish waits for that in-flight
         * append, then revokes before returning; a later tick cannot emit. */
        memset(s.seed, 0, sizeof(s.seed)); s.seed[0] = 11;
        ed25519_keypair(s.host, sk, s.seed); memcpy(s.seed, sk, 32);
        ASSERT(app_host_test_plan_rehash(&plan));
        ASSERT_EQ(boot_app_host_enable(&w.db, w.store, &plan.plan, 432100, selected_host, &generation), BOOT_APP_HOST_OK);
        s.block_guard = true; tick.world = &w; tick.now = 432100;
        ASSERT_EQ(pthread_create(&tick_id, NULL, app_host_test_tick_thread, &tick), 0); tick_live = true;
        ASSERT(app_host_test_wait_guard(&s));
        stop.world = &w; memcpy(stop.host, selected_host, 32); stop.generation = generation;
        ASSERT_EQ(pthread_create(&stop_id, NULL, app_host_test_stop_thread, &stop), 0); stop_live = true;
        ASSERT(app_host_test_wait_started(&stop));
        pthread_mutex_lock(&s.mutex); s.release_guard = true; pthread_cond_broadcast(&s.condition); pthread_mutex_unlock(&s.mutex);
        ASSERT_EQ(pthread_join(tick_id, NULL), 0); tick_live = false;
        ASSERT_EQ(pthread_join(stop_id, NULL), 0); stop_live = false;
        ASSERT_EQ(tick.result, BOOT_APP_HOST_OK); ASSERT_EQ(stop.result, BOOT_APP_HOST_OK);
        unsigned after_stop = s.announcements;
        ASSERT_EQ(boot_app_host_tick(&w.db, w.store, 475200), BOOT_APP_HOST_OK);
        ASSERT_EQ(s.announcements, after_stop);
        PASS();
    }
_test_next:
    if (sync_ready) {
        pthread_mutex_lock(&s.mutex); s.release_guard = true; pthread_cond_broadcast(&s.condition); pthread_mutex_unlock(&s.mutex);
    }
    if (tick_live) (void)pthread_join(tick_id, NULL);
    if (stop_live) (void)pthread_join(stop_id, NULL);
    if (sync_ready) { pthread_cond_destroy(&s.condition); pthread_mutex_destroy(&s.mutex); }
    boot_app_host_set_test_hooks(NULL); zcl_fleet_role_checker_install(NULL);
    if (!app_host_test_close(&w)) { printf("FAIL: app host fixture cleanup\n"); ++failures; }
    return failures + host_cli_response_tests();
}
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Inert snippet for test_app_host.c; uses actual registered CLI handlers.
 * Requires test_core, native_app_compose, rpc_client, json, stdlib/string/stdio.
 * Call host_cli_response_tests() from the app_host group. */
#define HCLI_HOST "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define HCLI_CARRIER "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define HCLI_DIGIT_HOST "1111111111111111111111111111111111111111111111111111111111111111"
static int hcli_fault;
static bool hcli_fault_status;
static unsigned hcli_stops;
static const char *hcli_host = HCLI_HOST;

static char *hcli_wire_response(int fault, bool stop)
{
    char wire[768];
    const char *host = fault == 4 ? HCLI_CARRIER : hcli_host;
    const char *carrier = fault == 5 ? hcli_host : HCLI_CARRIER;
    const char *enabled = fault == 6 ? "\"false\"" : stop ? "false" : "true";
    int generation = fault == 7 ? 99 : stop ? 8 : 7;
    const char *ok = fault == 8 ? "\"true\"" : "true";
    const char *pending = fault == 9 ? "true" : "false";
    int due = fault == 10 ? 1 : stop ? 0 : 100;
    int n = snprintf(wire, sizeof(wire),
        "{\"ok\":%s,\"host\":\"%s\",\"carrier\":\"%s\",\"generation\":%d,"
        "\"enabled\":%s,\"due_at\":%d,\"pending\":%s,"
        "\"executed\":true,\"hosting_notice\":\"untrusted override\"}",
        ok, host, carrier, generation, enabled, due, pending);
    return n > 0 && (size_t)n < sizeof(wire) ? strdup(wire) : NULL;
}

static char *hcli_response(int fault, bool stop)
{
    if (fault == 1) return strdup("{}");
    if (fault == 2) return strdup("{\"ok\":true}");
    if (fault == 3) return NULL; /* acknowledgement lost */
    return hcli_wire_response(fault, stop);
}

static char *hcli_rpc(const char *method, const char *params)
{
    if (strcmp(method, "fleet_board")) return NULL;
    struct json_value input;
    json_init(&input);
    bool parsed = json_read(&input, params, strlen(params));
    const char *op = parsed ? json_get_str(json_get(json_at(&input, 0), "op")) : NULL;
    bool stop = op && !strcmp(op, "app_host_stop");
    bool status = op && !strcmp(op, "app_host_status");
    json_free(&input);
    if (!stop && !status) return NULL;
    if (stop) ++hcli_stops;
    return hcli_response((stop || hcli_fault_status) ? hcli_fault : 0, stop);
}

static bool hcli_call(const char *path, const char *generation,
                       const char *plan, struct zcl_command_reply *reply)
{
    struct json_value input;
    bool typed_generation = generation && !strcmp(generation, "7");
    const char *kv[] = {"host", HCLI_HOST, "carrier", HCLI_CARRIER,
                        "generation", typed_generation ? NULL : generation, "plan_id", plan};
    bool built = zcl_app_input(&input, kv, 8);
    if (built && typed_generation) built = json_push_kv_int(&input, "generation", 7);
    if (built && plan) built = json_push_kv_bool(&input, "confirm", true);
    bool ok = zcl_app_inner_call_built(path, &input, built, reply);
    return ok;
}

static int host_cli_response_tests(void)
{
    int failures = 0;
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.app_host.test.v1");
    node_rpc_client_set_test_hook(hcli_rpc);
    hcli_fault = 0; hcli_fault_status = false; hcli_stops = 0;
    TEST("app host CLI: exact confirmation, malformed replies and lost acknowledgement") {
        ASSERT(hcli_call("app.host.status", NULL, NULL, &reply));
        ASSERT(!json_get_bool(json_get(&reply.data, "executed")));
        const char *notice = json_get_str(json_get(&reply.data, "hosting_notice"));
        ASSERT(notice && strcmp(notice, "untrusted override"));
        zcl_command_reply_free(&reply);
        ASSERT(hcli_call("app.host.stop", "7", NULL, &reply));
        const char *id = json_get_str(json_get(&reply.data, "plan_id"));
        ASSERT(id && strlen(id) == 64 && hcli_stops == 0);
        char plan[65]; (void)snprintf(plan, sizeof(plan), "%s", id);
        zcl_command_reply_free(&reply);
        ASSERT(hcli_call("app.host.stop", "7", plan, &reply));
        ASSERT(hcli_stops == 1 && json_get_bool(json_get(&reply.data, "executed")));
        ASSERT(!json_get_bool(json_get(&reply.data, "enabled")));
        ASSERT(json_get_int(json_get(&reply.data, "generation")) == 8);
        for (int fault = 1; fault <= 10; ++fault) {
            zcl_command_reply_free(&reply);
            hcli_fault = fault;
            unsigned before = hcli_stops;
            ASSERT(!hcli_call("app.host.stop", "7", plan, &reply));
            ASSERT(hcli_stops == before + 1 && reply.error.mutated);
            ASSERT(!json_get_bool(json_get(&reply.data, "executed")));
        }
        hcli_fault = 0;
        const char *bad[] = {"0", "-1", "7junk", "9223372036854775807", "9223372036854775808"};
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
            zcl_command_reply_free(&reply);
            unsigned before = hcli_stops;
            ASSERT(!hcli_call("app.host.stop", bad[i], plan, &reply));
            ASSERT(hcli_stops == before && !reply.error.mutated);
        }
        hcli_fault_status = true;
        const int status_faults[] = {1, 2, 3, 4, 5, 6, 8};
        for (size_t i = 0; i < sizeof(status_faults) / sizeof(status_faults[0]); ++i) {
            zcl_command_reply_free(&reply);
            hcli_fault = status_faults[i];
            ASSERT(!hcli_call("app.host.status", NULL, NULL, &reply));
            ASSERT(!reply.error.mutated);
        }
        hcli_fault = 0; hcli_fault_status = false;
        const char *cli_args[] = {"host", "stop", "--host=" HCLI_HOST,
                                  "--carrier=" HCLI_CARRIER, "--generation=7"};
        const char *digit_args[] = {"host", "stop", "--host=" HCLI_DIGIT_HOST,
                                    "--carrier=" HCLI_CARRIER, "--generation=7"};
        unsigned before_cli = hcli_stops;
        hcli_host = HCLI_DIGIT_HOST;
        int digit_result = zcl_native_command_main("app", digit_args, 5, "", 0, CHAIN_MAIN, false);
        hcli_host = HCLI_HOST;
        int mixed_result = zcl_native_command_main("app", cli_args, 5, "", 0, CHAIN_MAIN, false);
        ASSERT_EQ(digit_result, 0); ASSERT_EQ(mixed_result, 0);
        ASSERT_EQ(hcli_stops, before_cli); /* plan only */
        PASS();
    } _test_next:;
    zcl_command_reply_free(&reply);
    node_rpc_client_set_test_hook(NULL);
    hcli_fault = 0; hcli_fault_status = false;
    return failures;
}

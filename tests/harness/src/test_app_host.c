/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Coordinator lifecycle fixtures use an actual signed, pinned carrier. */
#include "test/test_core.h"
#include "base/hex.h"
#include "chain/chainparams.h"
#include "command/native_command.h"
#include "command/native_app_compose.h"
#include "command/native_app_host_browser.h"
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
#include "vcs/package_share.h"
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
extern bool boot_app_host_rpc_dispatch(struct node_db *db, const char *op,
    const struct json_value *in, struct json_value *result, int64_t now);
extern bool boot_app_host_rpc_dispatch_test(struct node_db *db, const char *op,
    const struct json_value *in, struct json_value *result, int64_t now,
    struct vcs_package_store *store);

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

static bool app_host_test_page_seed(struct app_host_test_world *w, const struct app_host_binding *base)
{
    struct app_host_binding binding = *base;
    for (unsigned i = 0; i < 5; ++i) {
        memset(binding.local_host, 0, sizeof(binding.local_host)); binding.local_host[0] = i < 3 ? 1 : 2;
        memset(binding.carrier_root, (int)('1' + i), 64); binding.carrier_root[64] = 0;
        if (db_app_host_intent_enable(&w->db, &binding, 0, 999999) != APP_HOST_OK) return false;
        if (i == 4 && db_app_host_intent_disable(&w->db, binding.local_host, binding.carrier_root, 1) != APP_HOST_OK) return false;
    }
    return true;
}
static bool app_host_test_page_order(const struct db_app_host_intent *row, const uint8_t prior[32],
                                     const char *prior_carrier, size_t total)
{
    int order = memcmp(row->binding.local_host, prior, 32);
    return !total || order > 0 || (!order && strcmp(row->binding.carrier_root, prior_carrier) > 0);
}
static bool app_host_test_page_scan(struct app_host_test_world *w)
{
    struct db_app_host_intent rows[2]; uint8_t host[32] = {0}, prior[32] = {0};
    char carrier[65] = {0}, prior_carrier[65] = {0}; size_t total = 0; bool more = false, disabled = false;
    do {
        size_t count = 0;
        if (db_app_host_intent_list(&w->db, total ? host : NULL, total ? carrier : NULL,
                                    rows, 2, &count, &more) != APP_HOST_OK || !count) return false;
        for (size_t i = 0; i < count; ++i) {
            if (!app_host_test_page_order(&rows[i], prior, prior_carrier, total)) return false;
            memcpy(prior, rows[i].binding.local_host, 32);
            (void)snprintf(prior_carrier, sizeof(prior_carrier), "%s", rows[i].binding.carrier_root);
            disabled |= !rows[i].enabled; ++total;
        }
        memcpy(host, prior, 32); (void)snprintf(carrier, sizeof(carrier), "%s", prior_carrier);
        if (total > 6) return false;
    } while (more);
    size_t count = 99; more = true;
    return total == 6 && disabled &&
        db_app_host_intent_list(&w->db, NULL, carrier, rows, 2, &count, &more) == APP_HOST_INVALID && count == 0 && !more;
}
static bool app_host_test_pages(struct app_host_test_world *w, const struct app_host_binding *base)
{
    if (!app_host_test_page_seed(w, base)) return false;
    node_db_close(&w->db); if (!node_db_open(&w->db, w->db_path)) return false;
    bool ok = app_host_test_page_scan(w);
    struct json_value in, result; json_init(&in); json_init(&result); json_set_object(&in);
    ok = ok && boot_app_host_rpc_dispatch(&w->db, "app_host_list", &in, &result, 1) &&
        json_get_bool(json_get(&result, "ok")) && json_get_bool(json_get(&result, "more")) &&
        json_size(json_get(&result, "items")) == 4;
    json_free(&result);
    ok = ok && json_push_kv_str(&in, "after_host", base->carrier_root) &&
        boot_app_host_rpc_dispatch(&w->db, "app_host_list", &in, &result, 1) &&
        !json_get_bool(json_get(&result, "ok")) && !strcmp(json_get_str(json_get(&result, "code")), "BAD_INPUT");
    json_free(&in); json_free(&result); return ok;
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
    bool local_absent, local_conflict, local_error;
    unsigned local_creates;
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
static enum vcs_zcode_dht_key_probe app_host_test_probe(void *ctx, uint8_t host[32])
{
    struct app_host_test_hooks_state *s = ctx;
    memset(host, 0, 32);
    if (s->local_error) return VCS_DHT_IDENTITY_PROBE_ERROR;
    if (s->local_absent) return VCS_DHT_IDENTITY_ABSENT;
    memcpy(host, s->host, 32); return VCS_DHT_IDENTITY_PRESENT;
}
static enum vcs_zcode_dht_key_create app_host_test_create(void *ctx, uint8_t host[32])
{
    struct app_host_test_hooks_state *s = ctx; ++s->local_creates; memset(host, 0, 32);
    if (s->local_error) return VCS_DHT_IDENTITY_CREATE_ERROR;
    if (s->local_conflict || !s->local_absent) return VCS_DHT_IDENTITY_PREEXISTING;
    s->local_absent = false; memcpy(host, s->host, 32); return VCS_DHT_IDENTITY_CREATED;
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
static int host_local_cli_cases(void);

static bool app_host_test_local_rpc_refuses_unconfirmed(struct app_host_test_world *w)
{
    struct json_value in, out; json_init(&in); json_init(&out); json_set_object(&in);
    uint8_t carrier[32]; struct vcs_package_possession_receipt before = {0}, after = {0};
    struct db_app_host_intent row; size_t count = 0; bool more = false;
    bool safe = zcl_hex_decode_lower(w->offer.carrier, carrier, 32) &&
        vcs_package_store_possession_snapshot(w->store, carrier, &before) &&
        db_app_host_intent_list(&w->db, NULL, NULL, &row, 1, &count, &more) == APP_HOST_OK && !count && !more;
    bool handled = boot_app_host_rpc_dispatch_test(&w->db, "app_host_local", &in, &out, 432100, w->store);
    const char *code = json_get_str(json_get(&out, "code"));
    bool ok = safe && handled && !json_get_bool(json_get(&out, "ok")) && code && !strcmp(code, "BAD_INPUT") &&
        vcs_package_store_possession_snapshot(w->store, carrier, &after) &&
        before.pinned == after.pinned && before.mutation_generation == after.mutation_generation &&
        db_app_host_intent_list(&w->db, NULL, NULL, &row, 1, &count, &more) == APP_HOST_OK && !count && !more;
    json_free(&in); json_free(&out); return ok;
}

static bool app_host_same_original(const struct zcl_app_offer *a, const struct zcl_app_offer *b)
{
    return !strcmp(a->root, b->root) && !strcmp(a->publisher, b->publisher) &&
           !strcmp(a->carrier, b->carrier);
}

static bool app_host_test_rpc_refusals(struct app_host_test_world *w,
    const char *host_hex, int64_t generation, const char *parts[3], struct json_value *in)
{
    struct json_value result; json_init(&result); json_set_object(in);
    char plan_hex[65]; uint8_t plan[32];
    bool ok = json_push_kv_str(in, "host", host_hex) &&
        json_push_kv_str(in, "carrier", w->offer.carrier) && json_push_kv_int(in, "generation", generation);
    vcs_app_plan_hash("zcl.app_host.stop.v1", parts, 3, plan); zcl_hex_encode(plan, 32, plan_hex);
    ok = ok && json_push_kv_str(in, "plan_id", plan_hex) && json_push_kv_bool(in, "confirm", true) &&
        boot_app_host_rpc_dispatch_test(&w->db, "app_host_resume", in, &result, 648000, w->store) &&
        !json_get_bool(json_get(&result, "ok"));
    json_free(in); json_free(&result); json_init(in); json_init(&result); json_set_object(in);
    vcs_app_plan_hash("zcl.app_host.resume.v1", parts, 3, plan); zcl_hex_encode(plan, 32, plan_hex);
    ok = ok && json_push_kv_str(in, "host", host_hex) && json_push_kv_str(in, "carrier", w->offer.carrier) &&
        json_push_kv_int(in, "generation", generation) && json_push_kv_str(in, "plan_id", plan_hex) &&
        boot_app_host_rpc_dispatch_test(&w->db, "app_host_resume", in, &result, 648000, w->store) &&
        !json_get_bool(json_get(&result, "ok"));
    json_free(&result); return ok;
}

static bool app_host_test_rpc_resume(struct app_host_test_world *w,
                                     const uint8_t host[32], int64_t generation)
{
    char host_hex[65], number[32]; zcl_hex_encode(host, 32, host_hex);
    (void)snprintf(number, sizeof(number), "%lld", (long long)generation);
    const char *parts[] = {host_hex, w->offer.carrier, number};
    struct json_value in, result; json_init(&in); json_init(&result);
    bool ok = app_host_test_rpc_refusals(w, host_hex, generation, parts, &in);
    ok = ok && json_push_kv_bool(&in, "confirm", true) &&
        boot_app_host_rpc_dispatch_test(&w->db, "app_host_resume", &in, &result, 648000, w->store) &&
        json_get_bool(json_get(&result, "ok")) && json_get_bool(json_get(&result, "enabled")) &&
        json_get_int(json_get(&result, "generation")) == generation + 1;
    json_free(&in); json_free(&result);
    return ok;
}

static bool app_host_test_release_id(const char *path, uint8_t id[32])
{
    size_t len = 0; uint8_t *bytes = zcl_native_source_bundle_read(path, &len);
    struct vcs_package_share share = {0}; const char *why = NULL;
    bool ok = bytes && vcs_package_share_load(&share, bytes, len, &why);
    if (ok) memcpy(id, share.release_id, 32);
    vcs_package_share_cleanup(&share); free(bytes); return ok;
}
static bool app_host_local_rpc_input(struct json_value *in, const struct app_host_test_world *w,
                                     const char *release, const char *datadir,
                                     const struct json_value *plan)
{
    char offer[ZCL_APP_OFFER_TEXT_MAX + 1u]; json_init(in); json_set_object(in);
    bool ok = zcl_app_offer_format(&w->offer, offer, sizeof(offer)) &&
        json_push_kv_str(in, "offer", offer) && json_push_kv_str(in, "release_id", release) &&
        json_push_kv_str(in, "datadir", datadir);
    if (!plan) return ok;
    const char *keys[] = {"identity", "generation", "already_enabled", "plan_id"};
    for (size_t i = 0; ok && i < sizeof(keys)/sizeof(keys[0]); ++i)
        ok = json_get(plan, keys[i]) && json_push_kv(in, keys[i], json_get(plan, keys[i]));
    return ok && json_push_kv_bool(in, "confirm", true);
}
static bool app_host_local_rpc_call(struct app_host_test_world *w, struct json_value *in,
                                    struct json_value *out)
{
    json_init(out);
    return boot_app_host_rpc_dispatch_test(&w->db, "app_host_local", in, out, 432100, w->store);
}
static bool app_host_local_rpc_wrong(struct app_host_test_world *w, struct app_host_test_hooks_state *s,
    const char *release, const char *datadir, const struct json_value *plan)
{
    struct json_value in, out; struct db_app_host_intent row; json_init(&out);
    bool ok = app_host_local_rpc_input(&in, w, release, datadir, plan) && app_host_local_rpc_call(w, &in, &out);
    ok = ok && !json_get_bool(json_get(&out, "ok")) && !strcmp(json_get_str(json_get(&out, "code")), "PLAN_MISMATCH") &&
        !s->local_creates && db_app_host_intent_find(&w->db, s->host, w->offer.carrier, &row) == APP_HOST_NOT_FOUND;
    json_free(&in); json_free(&out); return ok;
}
static bool app_host_local_rpc_success(const struct json_value *out,
                                       const struct app_host_test_hooks_state *s)
{
    return json_get_bool(json_get(out, "ok")) && json_get_bool(json_get(out, "enabled")) &&
        json_get_bool(json_get(out, "executed")) && json_get_int(json_get(out, "generation")) == 1 && s->local_creates == 1;
}
static bool app_host_local_rpc_uncertain(struct app_host_test_world *w, struct app_host_test_hooks_state *s,
    const char *release, const struct json_value *plan)
{
    struct json_value in, out; struct db_app_host_intent row; json_init(&out);
    s->local_conflict = true;
    bool ok = app_host_local_rpc_input(&in, w, release, w->store_path, plan) && app_host_local_rpc_call(w, &in, &out);
    ok = ok && !json_get_bool(json_get(&out, "ok")) &&
        !strcmp(json_get_str(json_get(&out, "code")), "HOST_LOCAL_UNCONFIRMED") &&
        s->local_creates == 1 && db_app_host_intent_find(&w->db, s->host, w->offer.carrier, &row) == APP_HOST_NOT_FOUND;
    json_free(&in); json_free(&out); s->local_conflict = false; return ok;
}
static bool app_host_local_rpc_roundtrip(struct app_host_test_world *w,
                                         struct app_host_test_hooks_state *s, const uint8_t release[32])
{
    char hex[65]; zcl_hex_encode(release, 32, hex);
    struct json_value in, plan, out; json_init(&plan); json_init(&out);
    bool ok = app_host_local_rpc_input(&in, w, hex, w->store_path, NULL) && app_host_local_rpc_call(w, &in, &plan);
    json_free(&in);
    ok = ok && json_get_bool(json_get(&plan, "ok")) && !json_get_bool(json_get(&plan, "executed")) &&
        !strcmp(json_get_str(json_get(&plan, "identity")), "absent") && !s->local_creates;
    char wrong[65]; memcpy(wrong, hex, sizeof(wrong)); wrong[0] = wrong[0] == '0' ? '1' : '0';
    ok = ok && app_host_local_rpc_wrong(w, s, hex, "/different", &plan) &&
        app_host_local_rpc_wrong(w, s, wrong, w->store_path, &plan);
    ok = ok && app_host_local_rpc_uncertain(w, s, hex, &plan);
    json_free(&plan); json_init(&plan);
    if (ok) ok = app_host_local_rpc_input(&in, w, hex, w->store_path, NULL) && app_host_local_rpc_call(w, &in, &plan);
    else json_init(&in);
    json_free(&in);
    /* A fresh observation is required before a new confirmed attempt. */
    s->local_creates = 0;
    if (ok) ok = app_host_local_rpc_input(&in, w, hex, w->store_path, &plan) && app_host_local_rpc_call(w, &in, &out);
    else { json_init(&in); json_init(&out); }
    ok = ok && app_host_local_rpc_success(&out, s);
    json_free(&in); json_free(&out); json_free(&plan); return ok;
}
static int app_host_local_rpc_cases(void)
{
    int failures = 0; struct app_host_test_world w = {0}; struct app_host_test_hooks_state s = {0};
    struct boot_app_host_test_hooks hooks = {.context = &s, .identity_probe = app_host_test_probe,
        .identity_create = app_host_test_create, .datadir = app_host_test_datadir};
    uint8_t release[32];
    TEST("local hosting RPC binds confirmed plan to exact node and identity state") {
        ASSERT(app_host_test_open(&w)); ASSERT(app_host_test_release_id(w.share, release));
        s.datadir = w.store_path; s.local_absent = true; s.host[0] = 9; boot_app_host_set_test_hooks(&hooks);
        ASSERT(app_host_local_rpc_roundtrip(&w, &s, release)); PASS();
    } _test_next:;
    boot_app_host_set_test_hooks(NULL);
    if (w.root[0] && !app_host_test_close(&w)) ++failures;
    return failures;
}
static int app_host_local_cases(void)
{
    int failures = 0; struct app_host_test_world w = {0}; struct app_host_test_hooks_state s = {0};
    struct boot_app_host_test_hooks hooks = {.context = &s, .identity_probe = app_host_test_probe,
        .identity_create = app_host_test_create, .datadir = app_host_test_datadir,
        .before_guard = app_host_test_before_guard};
    uint8_t release[32], host[32], root[32]; int64_t generation = 0; bool attempted = false;
    struct boot_app_host_local_state absent, present, enabled, disabled; struct db_app_host_intent row;
    TEST("local original hosting binds identity, signed release, possession and consent generation") {
        ASSERT(app_host_test_open(&w)); ASSERT(app_host_test_release_id(w.share, release));
        ASSERT(zcl_hex_decode_lower(w.offer.carrier, root, 32));
        s.datadir = w.store_path; s.store = w.store; memcpy(s.carrier, root, 32);
        s.local_absent = true; s.host[0] = 9;
        boot_app_host_set_test_hooks(&hooks);
        ASSERT_EQ(boot_app_host_local_observe(&w.db, w.store_path, &w.offer, &absent), BOOT_APP_HOST_OK);
        ASSERT(absent.identity_absent); ASSERT_EQ(absent.generation, 0); ASSERT(!absent.enabled);
        ASSERT_EQ(vcs_package_store_pin(w.store, root, false), VCS_PACKAGE_STORE_OK);
        ASSERT_EQ(boot_app_host_local_commit(&w.db, w.store, w.store_path, &w.offer, release,
                  &absent, 432100, host, &generation, &attempted), BOOT_APP_HOST_INVALID);
        ASSERT(!attempted); ASSERT_EQ(s.local_creates, 0u);
        ASSERT_EQ(vcs_package_store_pin(w.store, root, true), VCS_PACKAGE_STORE_OK);
        release[0] ^= 1;
        ASSERT_EQ(boot_app_host_local_commit(&w.db, w.store, w.store_path, &w.offer, release,
                  &absent, 432100, host, &generation, &attempted), BOOT_APP_HOST_INVALID);
        ASSERT(!attempted); ASSERT_EQ(s.local_creates, 0u); release[0] ^= 1;
        s.local_conflict = true;
        ASSERT_EQ(boot_app_host_local_commit(&w.db, w.store, w.store_path, &w.offer, release,
                  &absent, 432100, host, &generation, &attempted), BOOT_APP_HOST_STALE);
        ASSERT(attempted); ASSERT(s.local_absent); ASSERT_EQ(s.local_creates, 1u);
        ASSERT_EQ(db_app_host_intent_find(&w.db, s.host, w.offer.carrier, &row), APP_HOST_NOT_FOUND);
        s.local_conflict = false; s.unpin_before_guard = true;
        ASSERT_EQ(boot_app_host_local_commit(&w.db, w.store, w.store_path, &w.offer, release,
                  &absent, 432100, host, &generation, &attempted), BOOT_APP_HOST_UNAVAILABLE);
        ASSERT(attempted); ASSERT(!s.local_absent); ASSERT_EQ(s.local_creates, 2u);
        ASSERT_EQ(db_app_host_intent_find(&w.db, s.host, w.offer.carrier, &row), APP_HOST_NOT_FOUND);
        ASSERT_EQ(vcs_package_store_pin(w.store, root, true), VCS_PACKAGE_STORE_OK);
        ASSERT_EQ(boot_app_host_local_commit(&w.db, w.store, w.store_path, &w.offer, release,
                  &absent, 432100, host, &generation, &attempted), BOOT_APP_HOST_STALE);
        ASSERT(!attempted);
        ASSERT_EQ(boot_app_host_local_observe(&w.db, w.store_path, &w.offer, &present), BOOT_APP_HOST_OK);
        ASSERT(!present.identity_absent); ASSERT_EQ(present.generation, 0); ASSERT(!present.enabled);
        ASSERT_EQ(boot_app_host_local_commit(&w.db, w.store, w.store_path, &w.offer, release,
                  &present, 432100, host, &generation, &attempted), BOOT_APP_HOST_OK);
        ASSERT(attempted); ASSERT_EQ(generation, 1); ASSERT(!memcmp(host, s.host, 32));
        ASSERT_EQ(boot_app_host_local_observe(&w.db, w.store_path, &w.offer, &enabled), BOOT_APP_HOST_OK);
        ASSERT(enabled.enabled); ASSERT_EQ(enabled.generation, 1);
        ASSERT_EQ(boot_app_host_local_commit(&w.db, w.store, w.store_path, &w.offer, release,
                  &enabled, 432100, host, &generation, &attempted), BOOT_APP_HOST_OK);
        ASSERT(!attempted); ASSERT_EQ(generation, 1);
        ASSERT_EQ(boot_app_host_stop(&w.db, s.host, w.offer.carrier, 1), BOOT_APP_HOST_OK);
        ASSERT_EQ(boot_app_host_local_commit(&w.db, w.store, w.store_path, &w.offer, release,
                  &absent, 432100, host, &generation, &attempted), BOOT_APP_HOST_STALE);
        ASSERT(!attempted);
        ASSERT_EQ(boot_app_host_local_observe(&w.db, w.store_path, &w.offer, &disabled), BOOT_APP_HOST_OK);
        ASSERT(!disabled.enabled); ASSERT_EQ(disabled.generation, 2);
        s.host[0] ^= 1;
        ASSERT_EQ(boot_app_host_local_commit(&w.db, w.store, w.store_path, &w.offer, release,
                  &disabled, 432100, host, &generation, &attempted), BOOT_APP_HOST_STALE);
        ASSERT(!attempted); s.host[0] ^= 1;
        s.unpin_before_guard = true;
        ASSERT_EQ(boot_app_host_local_commit(&w.db, w.store, w.store_path, &w.offer, release,
                  &disabled, 432100, host, &generation, &attempted), BOOT_APP_HOST_UNAVAILABLE);
        ASSERT(!attempted);
        ASSERT_EQ(db_app_host_intent_find(&w.db, s.host, w.offer.carrier, &row), APP_HOST_OK);
        ASSERT(!row.enabled); ASSERT_EQ(row.generation, 2);
        ASSERT_EQ(vcs_package_store_pin(w.store, root, true), VCS_PACKAGE_STORE_OK);
        ASSERT_EQ(boot_app_host_local_commit(&w.db, w.store, w.store_path, &w.offer, release,
                  &disabled, 432100, host, &generation, &attempted), BOOT_APP_HOST_OK);
        ASSERT(attempted); ASSERT_EQ(generation, 3);
        PASS();
    } _test_next:;
    boot_app_host_set_test_hooks(NULL);
    if (w.root[0] && !app_host_test_close(&w)) ++failures;
    return failures;
}

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
        ASSERT(app_host_test_local_rpc_refuses_unconfirmed(&w));
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
        ASSERT(app_host_test_pages(&w, &row.binding));
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
        ASSERT_EQ(boot_app_host_resume(&w.db, w.store, selected_host, w.offer.carrier,
                                       row.generation, 648000), BOOT_APP_HOST_UNAVAILABLE);
        node_db_close(&w.db); ASSERT(node_db_open(&w.db, w.db_path));
        ASSERT_EQ(boot_app_host_tick(&w.db, w.store, 648000), BOOT_APP_HOST_OK);
        ASSERT_EQ(s.announcements, 3u);
        /* A stop concurrent with a guarded publish waits for that in-flight
         * append, then revokes before returning; a later tick cannot emit. */
        memset(s.seed, 0, sizeof(s.seed)); s.seed[0] = 11;
        ed25519_keypair(s.host, sk, s.seed); memcpy(s.seed, sk, 32);
        ASSERT_EQ(boot_app_host_resume(&w.db, w.store, selected_host, w.offer.carrier,
                                       row.generation - 1, 648000), BOOT_APP_HOST_STALE);
        ASSERT_EQ(vcs_package_store_pin(w.store, s.carrier, false), VCS_PACKAGE_STORE_OK);
        ASSERT_EQ(boot_app_host_resume(&w.db, w.store, selected_host, w.offer.carrier,
                                       row.generation, 648000), BOOT_APP_HOST_INVALID);
        ASSERT_EQ(vcs_package_store_pin(w.store, s.carrier, true), VCS_PACKAGE_STORE_OK);
        ASSERT(node_db_exec(&w.db, "DELETE FROM fleet_board_posts"));
        ASSERT(app_host_test_rpc_resume(&w, selected_host, row.generation));
        generation = row.generation + 1;
        ASSERT_EQ(boot_app_host_tick(&w.db, w.store, 648000), BOOT_APP_HOST_OK);
        ASSERT_EQ(db_fleet_board_post_lookup_checked(&w.db, s.last_id, &found), FLEET_BOARD_LOOKUP_FOUND);
        struct zcl_app_offer resumed;
        ASSERT(zcl_app_offer_parse(found.post.text, found.post.text_len, &resumed));
        ASSERT(!memcmp(found.post.host_pubkey, selected_host, 32));
        ASSERT(app_host_same_original(&resumed, &w.offer));
        ASSERT_EQ(boot_app_host_stop(&w.db, selected_host, w.offer.carrier, generation), BOOT_APP_HOST_OK);
        ASSERT(app_host_test_plan_create(&w, &plan, 432100));
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
    return failures + host_cli_response_tests() + app_host_local_cases() + app_host_local_rpc_cases() + host_local_cli_cases();
}
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Inert snippet for test_app_host.c; uses actual registered CLI handlers.
 * Requires test_core, native_app_compose, rpc_client, json, stdlib/string/stdio.
 * Call host_cli_response_tests() from the app_host group. */
#define HCLI_HOST "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define HCLI_CARRIER "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define HCLI_DIGIT_HOST "1111111111111111111111111111111111111111111111111111111111111111"
static int hcli_fault;
static int hcli_list_fault;
static bool hcli_fault_status;
static bool hcli_disabled;
static unsigned hcli_stops;
static unsigned hcli_resumes;
static unsigned hcli_status_calls, hcli_stale_after;
static const char *hcli_host = HCLI_HOST;

static const char *hcli_enabled(int fault, bool stop, bool resume)
{
    if (fault == 6) return "\"false\"";
    if (resume) return "true";
    return stop || hcli_disabled ? "false" : "true";
}
static char *hcli_wire_response(int fault, bool stop, bool resume)
{
    char wire[768];
    const char *host = fault == 4 ? HCLI_CARRIER : hcli_host;
    const char *carrier = fault == 5 ? hcli_host : HCLI_CARRIER;
    const char *enabled = hcli_enabled(fault, stop, resume);
    int generation = fault == 7 ? 99 : stop || resume ? 8 : 7;
    const char *ok = fault == 8 ? "\"true\"" : "true";
    const char *pending = fault == 9 ? "true" : "false";
    int due = fault == 10 ? 1 : stop || hcli_disabled ? 0 : 100;
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
    return hcli_wire_response(fault, stop, false);
}

static char *hcli_list_response(void)
{
    if (hcli_list_fault == 1) return strdup("{\"ok\":true,\"items\":[],\"more\":true}");
    if (hcli_list_fault == 2) return strdup("{\"ok\":true,\"items\":{},\"more\":false}");
    return strdup("{\"ok\":true,\"items\":[{\"host\":\"" HCLI_HOST "\",\"carrier\":\"" HCLI_CARRIER "\",\"name\":\"fixture\",\"publisher\":\"02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"package_root\":\"" HCLI_CARRIER "\",\"generation\":7,\"enabled\":true,\"due_at\":100,\"pending\":false,\"untrusted\":\"ignore\"}],\"more\":false}");
}
static char *hcli_dispatch(bool stop, bool resume, bool status, bool list)
{
    if (list) return hcli_list_response();
    if (!stop && !resume && !status) return NULL;
    if (stop) ++hcli_stops;
    if (resume) {
        ++hcli_resumes;
        if (hcli_fault == 3) return NULL;
        return hcli_wire_response(hcli_fault, false, true);
    }
    if (status && ++hcli_status_calls > hcli_stale_after && hcli_stale_after) return hcli_response(7, false);
    return hcli_response((stop || hcli_fault_status) ? hcli_fault : 0, stop);
}
static char *hcli_rpc(const char *method, const char *params)
{
    if (strcmp(method, "fleet_board")) return NULL;
    struct json_value input;
    json_init(&input);
    bool parsed = json_read(&input, params, strlen(params));
    const char *op = parsed ? json_get_str(json_get(json_at(&input, 0), "op")) : NULL;
    bool stop = op && !strcmp(op, "app_host_stop");
    bool resume = op && !strcmp(op, "app_host_resume");
    bool status = op && !strcmp(op, "app_host_status");
    bool list = op && !strcmp(op, "app_host_list");
    json_free(&input);
    return hcli_dispatch(stop, resume, status, list);
}

struct hbrowser_script { unsigned list_views, reviews; bool confirm_stop; };
static bool hbrowser_present(void *context, const struct zcl_present_model_v1 *model,
    const char *copy, struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    (void)copy; (void)why; (void)cap; struct hbrowser_script *s = context;
    if (strcmp(model->request_id, "hosting-browser")) return false;
    const char *id = s->list_views++ ? "back" : "review";
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION;
    for (unsigned i = 0; i < model->action_count; ++i)
        if (!strcmp(model->actions[i].id, id)) { event->action_index = i; return true; }
    return false;
}
static bool hbrowser_confirm(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live,
    char *why, size_t cap)
{
    struct hbrowser_script *s = context;
    if (strcmp(model->request_id, "hosting-review") || !pages || !live) return false;
    ++s->reviews; bool redraw = false, close = false;
    struct zcl_present_window_event_v1 event = {.outcome = ZCL_PRESENT_WINDOW_ACTION};
    bool confirm = s->confirm_stop && model->action_count == 4;
    uint32_t page_count = 0;
    if (confirm && !zcl_present_model_page_count_v1(model, &page_count, why, cap)) return false;
    if (confirm) for (uint32_t i = 1; i < page_count; ++i) {
        event.action_index = 2; live->owner.update(live->owner.context, &event, false, &redraw, &close);
        if (close) return false;
    }
    event.action_index = confirm ? 3 : 0;
    live->owner.update(live->owner.context, &event, false, &redraw, &close); return close;
}
static bool hbrowser_case(bool confirm, bool stale, bool lost, bool resume, unsigned *changes, bool *mutated)
{
    struct hbrowser_script script = {.confirm_stop = confirm};
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_library.v1");
    hcli_stops = hcli_resumes = hcli_status_calls = 0; hcli_disabled = resume;
    hcli_stale_after = stale ? 1 : 0; hcli_fault = lost ? 3 : 0;
    bool ok = app_host_browser_run(hbrowser_present, hbrowser_confirm, &script, &reply);
    *changes = resume ? hcli_resumes : hcli_stops; *mutated = reply.error.mutated;
    bool expected = stale ? (!ok && !strcmp(reply.error.code, "HOST_INTENT_STALE")) :
        lost ? (!ok && reply.error.mutated) : ok;
    zcl_command_reply_free(&reply); hcli_stale_after = hcli_fault = 0; hcli_disabled = false;
    return expected && script.list_views && (stale || script.reviews);
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
        struct json_value list_input; json_init(&list_input); json_set_object(&list_input);
        ASSERT(zcl_app_inner_call("app.host.list", &list_input, &reply, NULL));
        ASSERT_EQ(json_size(json_get(&reply.data, "items")), 1);
        ASSERT(!json_get_bool(json_get(&reply.data, "more")));
        ASSERT(!json_get(json_at(json_get(&reply.data, "items"), 0), "untrusted"));
        json_free(&list_input); zcl_command_reply_free(&reply);
        for (hcli_list_fault = 1; hcli_list_fault <= 2; ++hcli_list_fault) {
            json_init(&list_input); json_set_object(&list_input);
            ASSERT(!zcl_app_inner_call("app.host.list", &list_input, &reply, NULL));
            json_free(&list_input); zcl_command_reply_free(&reply);
        }
        hcli_list_fault = 0;
        unsigned browser_stops = 0; bool browser_mutated = false;
        ASSERT(hbrowser_case(false, false, false, false, &browser_stops, &browser_mutated));
        ASSERT_EQ(browser_stops, 0u); ASSERT(!browser_mutated);
        ASSERT(hbrowser_case(true, false, false, false, &browser_stops, &browser_mutated));
        ASSERT_EQ(browser_stops, 1u); ASSERT(browser_mutated);
        ASSERT(hbrowser_case(true, true, false, false, &browser_stops, &browser_mutated));
        ASSERT_EQ(browser_stops, 0u); ASSERT(!browser_mutated);
        ASSERT(hbrowser_case(true, false, true, false, &browser_stops, &browser_mutated));
        ASSERT_EQ(browser_stops, 1u); ASSERT(browser_mutated);
        ASSERT(hbrowser_case(false, false, false, true, &browser_stops, &browser_mutated));
        ASSERT_EQ(browser_stops, 0u); ASSERT(!browser_mutated);
        ASSERT(hbrowser_case(true, false, false, true, &browser_stops, &browser_mutated));
        ASSERT_EQ(browser_stops, 1u); ASSERT(browser_mutated);
        ASSERT(hbrowser_case(true, true, false, true, &browser_stops, &browser_mutated));
        ASSERT_EQ(browser_stops, 0u); ASSERT(!browser_mutated);
        ASSERT(hbrowser_case(true, false, true, true, &browser_stops, &browser_mutated));
        ASSERT_EQ(browser_stops, 1u); ASSERT(browser_mutated);
        hcli_stops = hcli_resumes = hcli_status_calls = 0;
        /* A stopped accepted intent must offer a separate owner-bound resume plan. */
        hcli_disabled = true;
        bool resume_ok = hcli_call("app.host.resume", "7", NULL, &reply);
        if (!resume_ok) printf("resume plan: %s %s\n", reply.error.code, reply.error.message);
        ASSERT(resume_ok);
        const char *resume_id = zcl_app_inner_str(&reply, "plan_id");
        ASSERT(resume_id && strlen(resume_id) == 64 && hcli_resumes == 0);
        char resume_plan[65]; (void)snprintf(resume_plan, sizeof(resume_plan), "%s", resume_id);
        zcl_command_reply_free(&reply);
        ASSERT(hcli_call("app.host.resume", "7", resume_plan, &reply));
        ASSERT_EQ(hcli_resumes, 1u);
        ASSERT(json_get_bool(json_get(&reply.data, "enabled")));
        ASSERT_EQ(json_get_int(json_get(&reply.data, "generation")), 8);
        zcl_command_reply_free(&reply);
        hcli_disabled = false;
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
    hcli_fault = hcli_list_fault = 0; hcli_fault_status = false;
    return failures;
}

static char *hcli_local_rpc(const char *method, const char *params)
{
    if (strcmp(method, "fleet_board")) return NULL;
    struct json_value doc; json_init(&doc);
    if (!json_read(&doc, params, strlen(params))) { json_free(&doc); return NULL; }
    const struct json_value *in = json_at(&doc, 0);
    const char *op = json_get_str(json_get(in, "op"));
    if (!op || strcmp(op, "app_host_local")) { json_free(&doc); return NULL; }
    bool confirm = json_get_bool(json_get(in, "confirm")); char wire[4096];
    int n;
    if (confirm) {
        n = snprintf(wire, sizeof(wire), "{\"ok\":true,\"host\":\"%s\",\"carrier\":\"%s\","
            "\"generation\":7,\"enabled\":true,\"due_at\":100,\"pending\":true,\"executed\":false}", HCLI_HOST, HCLI_CARRIER);
    } else {
        const char *parts[] = {json_get_str(json_get(in, "offer")), json_get_str(json_get(in, "release_id")),
            json_get_str(json_get(in, "datadir")), HCLI_HOST, "7", "enabled"};
        uint8_t plan[32]; char hex[65]; zcl_app_plan_id("zcl.app_host.local.v1", parts, 6, plan); zcl_hex_encode(plan, 32, hex);
        n = snprintf(wire, sizeof(wire), "{\"ok\":true,\"plan_id\":\"%s\",\"identity\":\"%s\","
            "\"generation\":7,\"already_enabled\":true,\"executed\":false}", hex, HCLI_HOST);
    }
    json_free(&doc); return n > 0 && (size_t)n < sizeof(wire) ? strdup(wire) : NULL;
}
static int host_local_cli_cases(void)
{
    int failures = 0; struct json_value in; json_init(&in); json_set_object(&in);
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.local.v1");
    TEST("local hosting accepts an already-enabled pending result without mutation") {
        struct zcl_app_offer offer = {0}; char text[ZCL_APP_OFFER_TEXT_MAX + 1u];
        (void)snprintf(offer.name, sizeof(offer.name), "%s", "fixture/app");
        (void)snprintf(offer.root, sizeof(offer.root), "%s", HCLI_HOST);
        (void)snprintf(offer.publisher, sizeof(offer.publisher), "02%s", HCLI_HOST);
        (void)snprintf(offer.carrier, sizeof(offer.carrier), "%s", HCLI_CARRIER);
        (void)snprintf(offer.sha256, sizeof(offer.sha256), "%s", HCLI_CARRIER);
        (void)snprintf(offer.onion, sizeof(offer.onion), "%s", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:29135");
        offer.size = 100; ASSERT(zcl_app_offer_format(&offer, text, sizeof(text)));
        ASSERT(json_push_kv_str(&in, "offer", text)); ASSERT(json_push_kv_str(&in, "release_id", HCLI_HOST));
        ASSERT(json_push_kv_str(&in, "datadir", "/fixture")); node_rpc_client_set_test_hook(hcli_local_rpc);
        ASSERT(zcl_app_inner_call("app.host.local", &in, &reply, NULL));
        const char *keys[] = {"identity", "generation", "already_enabled", "plan_id"};
        for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); ++i) ASSERT(json_push_kv(&in, keys[i], json_get(&reply.data, keys[i])));
        zcl_command_reply_free(&reply); ASSERT(json_push_kv_bool(&in, "confirm", true));
        ASSERT(zcl_app_inner_call("app.host.local", &in, &reply, NULL));
        ASSERT(json_get_bool(json_get(&reply.data, "pending"))); ASSERT(!reply.error.mutated);
        ASSERT(!json_get_bool(json_get(&reply.data, "executed"))); PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL); json_free(&in); zcl_command_reply_free(&reply); return failures;
}

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Coordinator lifecycle fixtures use an actual signed, pinned carrier. */
#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif
#include "test/test_core.h"
#include "base/hex.h"
#include "chain/chainparams.h"
#include "command/native_command.h"
#include "command/native_app_compose.h"
#include "command/native_app_host_browser.h"
#include "command/native_app_host_job.h"
#include "command/native_app_host_controller.h"
#include "command/native_app_host_worker.h"
#include "command/native_app_host_view.h"
#include "command/native_app_host_flow.h"
#include "command/native_app_share_command.h"
#include "command/native_app_launch.h"
#include "command/app_selection.h"
#include "command/native_zcode_package_copy.h"
#include "config/command_catalog.h"
#include "command/native_app_network_lifeline.h"
#include "vcs/package_share.h"
#include "platform/time_compat.h"
#include "platform/clock.h"
#include "config/boot_app_host.h"
#include "config/boot_fleet_board.h"
#include "controllers/rpc_client.h"
#include "crypto/ed25519.h"
#include "crypto/sha256.h"
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
#if !defined(_WIN32)
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#endif

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
#if !defined(_WIN32)
/* Build-only identity fields are seeded; the selected source, grant and plan
 * below are real. This does not claim a compiled Keep journey. */
struct host_flow_fixture {
    char root[512], share[700], home[700], data[700], copy[700], worker[800], sentinel[800];
    char package[65], publisher[67], release[65], version[65], app_name[256], semver[256];
    struct app_launch_env env; struct app_selection selection, changed;
    bool stale, presented, identity_ok, cas_ok;
};
static bool host_flow_field(const struct zcl_present_model_v1 *model, const char *label, const char *expected)
{
    char value[512] = {0}; size_t used = 0; bool found = false;
    for (unsigned i = 0; i < model->item_count; i++) {
        const struct zcl_present_model_item_v1 *item = &model->items[i];
        const char *part = item->value;
        if (!found) { size_t prefix = strlen(label); if (strncmp(part, label, prefix)) continue; found = true; part += prefix; }
        else { if (strncmp(part, "  ", 2)) break; part += 2; }
        size_t n = strlen(part); if (n >= sizeof(value) - used) return false;
        memcpy(value + used, part, n); used += n;
    }
    return found && !strcmp(value, expected);
}
static bool host_flow_events(bool stale, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    uint32_t count = 0; if (!zcl_present_model_page_count_v1(model, &count, why, cap)) return false;
    bool redraw = false, close = false;
    if (stale) {
        if (count < 2) return false;
        struct zcl_present_window_event_v1 early = {.outcome = ZCL_PRESENT_WINDOW_ACTION, .action_index = 3};
        live->owner.update(live->owner.context, &early, true, &redraw, &close);
        if (close) return false;
    }
    if (stale) for (uint32_t i = 1; i < count; ++i) {
        struct zcl_present_window_event_v1 e = {.outcome = ZCL_PRESENT_WINDOW_ACTION, .action_index = 2};
        live->owner.update(live->owner.context, &e, true, &redraw, &close); if (close) return false;
    }
    struct zcl_present_window_event_v1 e = {.outcome = ZCL_PRESENT_WINDOW_ACTION, .action_index = stale ? 3u : 0u};
    live->owner.update(live->owner.context, &e, true, &redraw, &close); return close;
}
static bool host_flow_present(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live,
    char *why, size_t cap)
{
    (void)pages; struct host_flow_fixture *f = context; f->presented = true;
    f->identity_ok = host_flow_field(model, "App: ", f->app_name) && host_flow_field(model, "Version: ", f->semver) &&
        host_flow_field(model, "Publisher: ", f->publisher) &&
        host_flow_field(model, "Package: ", f->package) && host_flow_field(model, "Release: ", f->release) &&
        host_flow_field(model, "Saved version: ", f->version) &&
        host_flow_field(model, "Availability: ", "Anyone with the link can receive this version while this window stays open, for up to 24 hours.");
    if (!f->identity_ok) return false;
    if (f->stale) {
        f->cas_ok = app_selection_save(f->env.state_dir, f->selection.revision, &f->selection, &f->changed) == APP_SELECTION_OK;
        if (!f->cas_ok) return false;
    }
    return host_flow_events(f->stale, model, live, why, cap);
}
static bool host_flow_no_scratch(const char *dir)
{
    DIR *d = opendir(dir); if (!d) return false;
    bool ok = true; struct dirent *e;
    while ((e = readdir(d))) if (!strncmp(e->d_name, ".app-network-", 13)) { ok = false; break; }
    closedir(d); return ok;
}
/* Drive the same plan and owner-confirm transitions as the adopted app flow. */
static bool host_fixture_call(const char *path, struct json_value *input, struct zcl_command_reply *reply)
{
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    if (!spec || !spec->handler) return false;
    struct zcl_command_request request = {.spec = spec, .input = input, .invoked_name = spec->path};
    spec->handler(&request, reply);
    if (reply->status != ZCL_COMMAND_STATUS_PASSED)
        fprintf(stderr, "host fixture %s: %s %s\n", path, reply->error.code, reply->error.message);
    return reply->status == ZCL_COMMAND_STATUS_PASSED;
}
static bool host_fixture_confirm(const char *path, struct json_value *input, struct zcl_command_reply *reply)
{
    struct zcl_command_reply planned; zcl_command_reply_init(&planned, "zcl.test.host.v1");
    bool ok = host_fixture_call(path, input, &planned);
    const char *id = ok ? zcl_package_copy_str(&planned.data, "plan_id") : NULL;
    char plan[65];
    ok = id && strlen(id) == 64;
    if (ok) memcpy(plan, id, sizeof(plan));
    zcl_command_reply_free(&planned);
    return ok && json_push_kv_str(input, "plan_id", plan) && json_push_kv_bool(input, "confirm", true) &&
        host_fixture_call(path, input, reply);
}
static bool host_fixture_adopt(struct host_flow_fixture *f)
{
    size_t len = 0; uint8_t *bytes = zcl_native_source_bundle_read(f->share, &len);
    struct vcs_package_share *share = calloc(1, sizeof(*share)); const char *why = NULL; char release[65];
    bool ok = bytes && share && vcs_package_share_load(share, bytes, len, &why) && vcs_package_share_check_source(share, &why);
    if (ok) zcl_hex_encode(share->release_id, 32, release);
    if (share) vcs_package_share_cleanup(share);
    free(share); free(bytes);
    struct json_value in; json_init(&in); json_set_object(&in);
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.host.v1");
    ok = ok && json_push_kv_str(&in, "root", release) && json_push_kv_str(&in, "datadir", f->data) &&
        host_fixture_confirm("zcode.package.adopt", &in, &reply);
    const char *copy = ok ? zcl_package_copy_str(&reply.data, "copy") : NULL;
    if (!copy || strlen(copy) >= sizeof(f->copy)) ok = false;
    else memcpy(f->copy, copy, strlen(copy) + 1);
    zcl_command_reply_free(&reply); json_free(&in); return ok;
}
static bool host_fixture_successor(struct host_flow_fixture *f)
{
    char path[800]; int n = snprintf(path, sizeof(path), "%s/src/zpb_boost.c", f->copy);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    FILE *file = fopen(path, "ab"); if (!file) return false;
    bool ok = fputs("\n/* host consent fixture successor */\n", file) >= 0;
    if (fclose(file)) ok = false;
    struct json_value in; json_init(&in); json_set_object(&in);
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.host.v1");
    ok = ok && json_push_kv_str(&in, "dir", f->copy) && host_fixture_confirm("zcode.package.version.save", &in, &reply);
    zcl_command_reply_free(&reply); json_free(&in); return ok;
}
static bool host_fixture_package(struct host_flow_fixture *f, struct zcl_app_offer *offer)
{
    struct json_value in; json_init(&in); json_set_object(&in);
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.host.v1");
    bool ok = json_push_kv_str(&in, "dir", f->copy) && json_push_kv_str(&in, "datadir", f->data) &&
        json_push_kv_str(&in, "publisher_pubkey", offer->publisher) &&
        host_fixture_call("zcode.package.share", &in, &reply);
    const char *root = ok ? zcl_package_copy_str(&reply.data, "package_root") : NULL;
    if (!root || strlen(root) != 64) ok = false;
    else memcpy(offer->root, root, 65);
    zcl_command_reply_free(&reply); json_free(&in); return ok;
}

/* Prepare an owner-adopted copy and bind its saved successor's package root. */
static bool host_fixture_prepare(struct host_flow_fixture *f, struct zcl_app_offer *offer)
{
    return host_fixture_adopt(f) && host_fixture_successor(f) && host_fixture_package(f, offer);
}

static bool host_flow_selection(struct host_flow_fixture *f, const struct zcl_app_offer *offer)
{
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.host.v1");
    struct zcl_package_copy copy = {0};
    bool ok = zcl_package_copy_open_as(f->copy, ZCL_PACKAGE_COPY_READ, &copy, &reply, "test");
    struct app_selection selection = {0};
    if (ok) {
        (void)snprintf(selection.app, sizeof(selection.app), "host-fixture");
        (void)snprintf(selection.copy, sizeof(selection.copy), "%s", f->copy);
        (void)snprintf(selection.datadir, sizeof(selection.datadir), "%s", f->data);
        memcpy(selection.fork, copy.fork_version, 32); memcpy(selection.parent, copy.parent_release, 32);
        memcpy(selection.version, copy.selected_version, 32);
        ok = zcl_hex_decode_lower(offer->root, selection.package, 32);
        memset(selection.env, 1, 32); memset(selection.dependencies, 2, 32);
        memset(selection.record, 3, 32); memset(selection.image, 4, 32);
        zcl_hex_encode(selection.version, 32, f->version);
    }
    zcl_package_copy_close(&copy); zcl_command_reply_free(&reply);
    return ok && app_selection_save(f->env.state_dir, 0, &selection, &f->selection) == APP_SELECTION_OK;
}
static bool host_flow_plan(struct host_flow_fixture *f, const struct zcl_app_offer *offer)
{
    char output[800]; if (snprintf(output, sizeof(output), "%s/unused-share", f->root) >= (int)sizeof(output)) return false;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.host.v1");
    struct zcl_app_share_session *s = zcl_app_share_prepare(f->selection.app, output, &f->selection, &reply);
    bool ok = s != NULL;
    if (!ok) fprintf(stderr, "host flow share plan: code=%s message=%s evidence=%s\n", reply.error.code, reply.error.message, reply.error.evidence);
    if (ok) {
        struct zcl_app_share_identity id; zcl_app_share_identity(s, &id);
        ok = !strcmp(id.package, offer->root) && !strcmp(id.publisher, offer->publisher) && !strcmp(id.version, f->version);
        if (ok) { (void)snprintf(f->package, sizeof(f->package), "%s", id.package);
            (void)snprintf(f->publisher, sizeof(f->publisher), "%s", id.publisher);
            (void)snprintf(f->release, sizeof(f->release), "%s", id.release);
            int a = snprintf(f->app_name, sizeof(f->app_name), "%s", id.name);
            int v = snprintf(f->semver, sizeof(f->semver), "%s", id.semver);
            ok = a > 0 && (size_t)a < sizeof(f->app_name) && v > 0 && (size_t)v < sizeof(f->semver); }
    }
    zcl_app_share_dispose(s); zcl_command_reply_free(&reply); return ok;
}
struct host_flow_disk { uint8_t share[32], key[32], version[32]; };
static bool host_flow_hash_file(const char *path, uint8_t digest[32])
{
    size_t len = 0; uint8_t *bytes = zcl_native_source_bundle_read(path, &len);
    if (!bytes) return false;
    struct sha256_ctx sha; sha256_init(&sha); sha256_write(&sha, bytes, len); sha256_finalize(&sha, digest);
    free(bytes); return true;
}
static bool host_flow_disk_snapshot(struct host_flow_fixture *f, struct host_flow_disk *out)
{
    char key[800]; int n = snprintf(key, sizeof(key), "%s/.z23/zcode_publisher.key", f->home);
    if (n <= 0 || (size_t)n >= sizeof(key) || !host_flow_hash_file(f->share, out->share) ||
        !host_flow_hash_file(key, out->key)) return false;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.host.v1");
    struct zcl_package_copy copy = {0};
    bool ok = zcl_package_copy_open_as(f->copy, ZCL_PACKAGE_COPY_READ, &copy, &reply, "test");
    if (ok) memcpy(out->version, copy.head_version, 32);
    zcl_package_copy_close(&copy); zcl_command_reply_free(&reply); return ok;
}
static bool host_flow_paths(struct host_flow_fixture *f)
{
    return snprintf(f->home, sizeof(f->home), "%s/alice", f->root) < (int)sizeof(f->home) &&
        snprintf(f->data, sizeof(f->data), "%s/datadir", f->home) < (int)sizeof(f->data) &&
        snprintf(f->copy, sizeof(f->copy), "%s/my-skycombat", f->home) < (int)sizeof(f->copy) &&
        snprintf(f->worker, sizeof(f->worker), "%s/worker", f->root) < (int)sizeof(f->worker) &&
        snprintf(f->sentinel, sizeof(f->sentinel), "%s/worker-invoked", f->root) < (int)sizeof(f->sentinel);
}
static bool host_flow_worker(struct host_flow_fixture *f)
{
    FILE *fp = fopen(f->worker, "w"); if (!fp) return false;
    int n = fprintf(fp, "#!/bin/sh\n: > '%s'\n", f->sentinel); int closed = fclose(fp);
    return n > 0 && closed == 0 && chmod(f->worker, 0700) == 0;
}
static bool host_flow_setup(struct host_flow_fixture *f)
{
    struct zcl_app_offer offer = {0};
    if (!test_app_host_fixture_create(f->root, sizeof(f->root), f->share, sizeof(f->share), &offer) || !host_flow_paths(f)) return false;
    if (setenv("HOME", f->home, 1) || setenv("XDG_STATE_HOME", f->home, 1) || setenv("XDG_CONFIG_HOME", f->home, 1)) return false;
    char why[256], parent[800];
    if (!app_launch_env_from_process(&f->env, why, sizeof(why))) return false;
    int n = snprintf(parent, sizeof(parent), "%s/z23", f->home);
    if (n <= 0 || (size_t)n >= sizeof(parent) || mkdir(parent, 0700) || mkdir(f->env.state_dir, 0700)) return false;
    if (!host_fixture_prepare(f, &offer) || !host_flow_selection(f, &offer) || !host_flow_plan(f, &offer)) return false;
    return host_flow_worker(f);
}
static bool host_flow_outcome(const struct host_flow_fixture *f, const struct zcl_command_reply *reply)
{
    const char *status = zcl_package_copy_str(&reply->data, "status");
    return f->stale ? reply->status != ZCL_COMMAND_STATUS_PASSED && !strcmp(reply->error.code, "SELECTION_STALE") :
        reply->status == ZCL_COMMAND_STATUS_PASSED && status && !strcmp(status, "canceled");
}
static bool host_flow_absent(const char *path)
{ errno = 0; return access(path, F_OK) != 0 && errno == ENOENT; }
static bool host_flow_selection_same(const struct app_selection *a, const struct app_selection *b)
{
    const uint8_t *left[] = {a->fork, a->parent, a->version, a->package, a->env, a->dependencies, a->record, a->image};
    const uint8_t *right[] = {b->fork, b->parent, b->version, b->package, b->env, b->dependencies, b->record, b->image};
    if (a->revision != b->revision || strcmp(a->app, b->app) || strcmp(a->copy, b->copy) || strcmp(a->datadir, b->datadir)) return false;
    for (size_t i = 0; i < 8; ++i) if (memcmp(left[i], right[i], 32)) return false;
    return true;
}
static bool host_flow_result(struct host_flow_fixture *f, struct zcl_command_reply *reply,
                             const struct host_flow_disk *before)
{
    struct app_selection actual = {0}; struct host_flow_disk after = {0};
    return f->presented && f->identity_ok && (!f->stale || f->cas_ok) && !reply->error.mutated && host_flow_outcome(f, reply) &&
        app_selection_load(f->env.state_dir, f->selection.app, &actual) == APP_SELECTION_OK &&
        host_flow_selection_same(&actual, f->stale ? &f->changed : &f->selection) && host_flow_absent(f->sentinel) &&
        host_flow_no_scratch(f->data) && host_flow_disk_snapshot(f, &after) && !memcmp(before, &after, sizeof(after));
}
static bool host_flow_child(bool stale)
{
    struct host_flow_fixture f = {.stale = stale}; struct host_flow_disk before = {0};
    bool setup = host_flow_setup(&f);
    bool snapshot = setup && host_flow_disk_snapshot(&f, &before);
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.host.v1");
    bool ok = false;
    if (snapshot) {
        app_host_flow(&f.selection, f.worker, host_flow_present, &f, &reply);
        ok = host_flow_result(&f, &reply, &before);
    }
    if (!ok) fprintf(stderr, "host flow: setup=%d snapshot=%d presented=%d identity=%d cas=%d status=%d code=%s message=%s mutated=%d\n",
        setup, snapshot, f.presented, f.identity_ok, f.cas_ok, reply.status, reply.error.code, reply.error.message, reply.error.mutated);
    zcl_command_reply_free(&reply); if (f.root[0] && test_rm_rf_recursive(f.root) != 0) ok = false;
    return ok;
}
static bool host_flow_case(bool stale)
{
    pid_t pid = fork(); if (pid < 0) return false;
    if (!pid) _exit(host_flow_child(stale) ? 0 : 2);
    int status = 0; pid_t done; do { done = waitpid(pid, &status, 0); } while (done < 0 && errno == EINTR);
    return done == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
#endif
static int host_ready_frame_tests(void);

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
    return failures + host_cli_response_tests() + app_host_local_cases() + app_host_local_rpc_cases() + host_local_cli_cases() + host_ready_frame_tests();
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
/* App-only ready is valid only for the exact signed carrier and selected tuple. */
#if !defined(_WIN32)
struct host_fake_owner { bool stop; unsigned ready_calls; const char *ack_path; };
static bool host_fake_ready(const struct app_host_ready *ready, void *context)
{
    struct host_fake_owner *owner = context;
    owner->ready_calls++;
    owner->stop = ready && ready->post_id[0];
    return true;
}
static void host_fake_unavailable(void *context) { (void)context; }
static bool host_fake_cancel(void *context)
{ return ((struct host_fake_owner *)context)->stop; }
/* Simulate Stop arriving only after the observer reports child termination. */
static bool host_late_ready(const struct app_host_ready *ready, void *context)
{
    struct host_fake_owner *owner = context; owner->ready_calls++;
    if (!ready || !owner->ack_path) return false;
    FILE *ack = fopen(owner->ack_path, "w");
    if (!ack) return false;
    return fclose(ack) == 0;
}
static void host_late_stop(void *context)
{ ((struct host_fake_owner *)context)->stop = true; }

static bool host_scratch_replacement(const char *root);
static bool host_terminal_script(const char *root, const char *line, int len, unsigned mode,
    char *script, size_t script_cap, char *ack, size_t ack_cap, struct stat *st)
{
    int n = snprintf(script, script_cap, "%s/fake-terminal", root);
    int a = snprintf(ack, ack_cap, "%s/ready-ack", root);
    if (a <= 0 || (size_t)a >= ack_cap) return false;
    (void)unlink(ack);
    FILE *fp = n > 0 && (size_t)n < script_cap ? fopen(script, "w") : NULL;
    if (!fp) return false;
    const char *wait = mode == 3 ? "i=0; while [ ! -f \"$2/ready-ack\" ] && [ $i -lt 100 ]; do sleep 0.02; i=$((i+1)); done; [ -f \"$2/ready-ack\" ] || exit 2" : "sleep 1";
    const char *finish = mode == 1 ? "printf x; exec sleep 5" : (mode == 2 ? "exit 73" : "exit 0");
    int wrote = fprintf(fp, "#!/bin/sh\nprintf '%%s\\n' '%.*s'\n%s\n%s\n", len - 1, line, wait, finish);
    int closed = fclose(fp);
    return wrote > 0 && !closed && !chmod(script, 0700) && !stat(root, st);
}
static bool host_terminal_late_stop(struct app_host_job_args *args, const char *ack)
{
    struct host_fake_owner late = {.ack_path = ack}; struct app_host_job_result result = {0};
    args->cancel = host_fake_cancel; args->cancel_context = &late;
    bool completed = app_host_job_run(args, host_late_ready, host_late_stop, &late, &result);
    return !completed && late.stop && late.ready_calls == 1 && result.ready && result.reaped &&
        !result.cancelled && !result.invalid_frame && result.outcome == APP_HOST_FAILED;
}
static bool host_terminal_result(const struct app_host_job_result *result, bool completed, unsigned mode)
{
    if (mode == 2) return completed && result->outcome == APP_HOST_EXPIRED && !result->invalid_frame;
    return !completed && result->outcome == APP_HOST_FAILED &&
        (mode == 1 ? result->invalid_frame : !result->invalid_frame);
}
static bool host_terminal_state(struct app_host_job_args *args, unsigned mode)
{
    struct app_host_state state; if (!app_host_state_init(&state)) return false;
    args->cancel = app_host_state_cancel; args->cancel_context = &state;
    struct app_host_job_result result = {0};
    bool completed = app_host_job_run(args, app_host_state_publish, app_host_state_unavailable, &state, &result);
    struct app_host_snapshot snapshot;
    bool ok = app_host_state_snapshot(&state, &snapshot) && result.ready && result.launched && result.reaped &&
        snapshot.ever_ready && snapshot.terminal && !snapshot.available && host_terminal_result(&result, completed, mode);
    app_host_state_destroy(&state); return ok;
}
static bool host_fake_terminal(const char *root, const char *line, int line_len,
    struct app_host_job_args *args, unsigned mode)
{
    char script[800], ack[800]; struct stat st;
    if (!host_terminal_script(root, line, line_len, mode, script, sizeof(script), ack, sizeof(ack), &st)) return false;
    args->self_path = script; args->scratch_path = root; args->scratch_dev = (uint64_t)st.st_dev;
    args->scratch_ino = (uint64_t)st.st_ino; args->duration_ms = 5000;
    return mode == 3 ? host_terminal_late_stop(args, ack) : host_terminal_state(args, mode);
}
struct host_view_probe { unsigned copies; bool valid, feedback, numbered; };
static bool host_view_copy(const char *text, void *context)
{
    struct host_view_probe *p = context; p->copies++;
    p->valid = text && !strncmp(text, "http://", 7) && strstr(text, "/board/apps/v1/");
    return p->valid;
}
static bool host_view_wait(const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_live_view_v1 *live, bool closing)
{
    struct zcl_present_window_event_v1 event = {0}; struct timespec pause = {.tv_nsec = 10000000};
    for (unsigned i = 0; i < 500; i++) {
        bool redraw = false, allow = false;
        live->owner.update(live->owner.context, &event, false, &redraw, &allow);
        if (closing ? allow : strstr(model->summary, "Available while") != NULL) return true;
        (void)nanosleep(&pause, NULL); /* real-clock: bounded fake-worker readiness */
    }
    return false;
}
static bool host_view_key(const struct zcl_present_window_live_view_v1 *live,
                          uint32_t *focus, char key)
{
    uint32_t action = UINT32_MAX;
    struct zcl_present_input_v1 input = {.key = ZCL_PRESENT_INPUT_TEXT, .character = key};
    return live->input(live->owner.context, &input, focus, &action) && action == UINT32_MAX;
}
static bool host_view_notice(const struct zcl_present_model_v1 *model, const char *text)
{
    for (unsigned i = 0; i < model->item_count; i++)
        if (strstr(model->items[i].value, text)) return true;
    return false;
}
static bool host_view_present(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live,
    char *why, size_t cap)
{
    (void)pages; (void)why; (void)cap; struct host_view_probe *p = context;
    if (!host_view_wait(model, live, false)) return false;
    uint32_t focus = 0;
    int copy_key = p->numbered ? '1' : 'c';
    if (!host_view_key(live, &focus, copy_key)) return false;
    bool redraw = false, allow = false; struct zcl_present_window_event_v1 event = {0};
    live->owner.update(live->owner.context, &event, false, &redraw, &allow);
    if (allow || !strstr(model->summary, "Available while")) return false;
    p->feedback = host_view_notice(model, "Copied. Send the link");
    if (!host_view_key(live, &focus, p->numbered ? '2' : 'q')) return false;
    live->owner.update(live->owner.context, &event, false, &redraw, &allow);
    if (strstr(model->summary, "Connecting")) return false;
    if (!host_view_wait(model, live, true)) return false;
    if (!host_view_key(live, &focus, copy_key)) return false;
    live->owner.update(live->owner.context, &event, false, &redraw, &allow);
    if (host_view_notice(model, "Copied.") || host_view_notice(model, "Try again")) return false;
    return p->valid && p->feedback && p->copies == 1;
}
struct host_ready_fixture_data {
    char root[512], path[700], release[65], line[8300];
    struct zcl_app_offer offer; struct app_host_job_args args;
    struct vcs_package_share *share; struct fleet_board_post *post;
    uint8_t *bytes; int line_len;
};
static bool host_ready_sign(struct host_ready_fixture_data *f)
{
    uint8_t seed[32] = {7}, pk[32], sk[32]; ed25519_keypair(pk, sk, seed); memcpy(seed, sk, 32);
    struct fleet_board_post *post = f->post;
    post->kind = FLEET_BOARD_KIND_OFFER; post->scope = FLEET_BOARD_SCOPE_PUBLIC;
    post->created_at = (uint64_t)platform_time_wall_unix(); post->ttl = 120;
    (void)snprintf(post->room, sizeof(post->room), "apps");
    (void)snprintf(post->agent, sizeof(post->agent), "app-host");
    bool ok = zcl_app_offer_format(&f->offer, post->text, sizeof(post->text));
    post->text_len = (uint32_t)strlen(post->text);
    ok = ok && fleet_board_post_sign(post, seed, pk) == FLEET_BOARD_OK;
    uint8_t wire[4096]; size_t n = 0; char hex[8193];
    if (ok) ok = fleet_board_frame_encode_post(post, wire, sizeof(wire), &n) == FLEET_BOARD_OK;
    if (ok) zcl_hex_encode(wire, n, hex);
    f->line_len = ok ? snprintf(f->line, sizeof(f->line), "zcl-app-host-v1 %s %s\n", f->offer.onion, hex) : -1;
    return f->line_len > 0 && (size_t)f->line_len < sizeof(f->line);
}
static bool host_ready_setup(struct host_ready_fixture_data *f)
{
    bool ok = test_app_host_fixture_create(f->root, sizeof(f->root), f->path, sizeof(f->path), &f->offer);
    if (ok) { char *port = strchr(f->offer.onion, ':'); if (port) *port = '\0'; }
    size_t len = 0; if (ok) f->bytes = zcl_native_source_bundle_read(f->path, &len);
    f->share = calloc(1, sizeof(*f->share)); const char *reason = NULL;
    ok = ok && f->bytes && f->share && vcs_package_share_load(f->share, f->bytes, len, &reason);
    if (ok) zcl_hex_encode(f->share->release_id, 32, f->release);
    f->post = calloc(1, sizeof(*f->post));
    ok = ok && f->post && host_ready_sign(f);
    f->args = (struct app_host_job_args){.name = f->offer.name, .release_root = f->release,
        .package_root = f->offer.root, .publisher = f->offer.publisher,
        .carrier_sha256 = f->offer.sha256, .carrier_size = (uint64_t)f->offer.size, .network = CHAIN_MAIN};
    return ok;
}
static bool host_ready_identity(struct host_ready_fixture_data *f)
{
    struct app_host_ready ready = {0}; struct zcl_app_offer *o = &f->offer; int n = f->line_len;
    bool ok = zcl_test_app_host_ready(&f->args, f->line, (size_t)n, 1, &ready) &&
        !strcmp(ready.package_root, o->root) && !strcmp(ready.release_root, f->release) &&
        !strcmp(ready.publisher, o->publisher) && !strcmp(ready.carrier_sha256, o->sha256);
    if (ok) { char bad[67]; memcpy(bad, o->publisher, sizeof(bad)); bad[0] = bad[0] == '0' ? '1' : '0';
        f->args.publisher = bad; ok = !zcl_test_app_host_ready(&f->args, f->line, (size_t)n, (size_t)n/2, &ready);
        f->args.publisher = o->publisher; }
    return ok;
}
static bool host_ready_view(struct app_host_job_args *args, bool numbered)
{
    struct app_host_owner *owner = app_host_owner_start(args); struct host_view_probe view = {.numbered = numbered};
    char why[256] = {0}; struct app_host_job_result result = {0};
    if (!owner) return false;
    bool shown = zcl_test_app_host_view_run(owner, host_view_present, &view, host_view_copy, &view, why, sizeof(why));
    app_host_owner_stop(owner); bool joined = app_host_owner_join(owner, &result);
    bool ok = shown && joined && result.reaped && result.outcome == APP_HOST_STOPPED;
    if (joined) app_host_owner_free(owner);
    return ok;
}
static bool host_ready_stopped(const struct host_fake_owner *owner,
                               const struct app_host_job_result *result, bool completed)
{
    return !completed && owner->ready_calls == 1 && result->ready && result->cancelled &&
        result->launched && result->reaped && !result->invalid_frame && result->outcome == APP_HOST_STOPPED;
}
static bool host_ready_process(struct host_ready_fixture_data *f)
{
    char script[800]; struct stat st; struct host_fake_owner owner = {0};
    int k = snprintf(script, sizeof(script), "%s/fake-host", f->root);
    FILE *fp = k > 0 && (size_t)k < sizeof(script) ? fopen(script, "w") : NULL;
    if (!fp) return false;
    int written = fprintf(fp, "#!/bin/sh\n[ \"${14}\" = main ] || exit 9\nprintf '%%s\\n' '%.*s'\nexec sleep 5\n", f->line_len - 1, f->line);
    int closed = fclose(fp);
    if (written <= 0 || closed || chmod(script, 0700) || stat(f->root, &st)) return false;
    f->args.self_path = script; f->args.scratch_path = f->root; f->args.scratch_dev = (uint64_t)st.st_dev;
    f->args.scratch_ino = (uint64_t)st.st_ino; f->args.duration_ms = 5000;
    f->args.cancel = host_fake_cancel; f->args.cancel_context = &owner;
    struct app_host_job_result result = {0};
    bool completed = app_host_job_run(&f->args, host_fake_ready, host_fake_unavailable, &owner, &result);
    return host_ready_stopped(&owner, &result, completed) && host_ready_view(&f->args, false) && host_ready_view(&f->args, true);
}
static bool host_ready_rejections(struct host_ready_fixture_data *f)
{
    struct app_host_ready ready = {0}; int n = f->line_len;
    f->args.publisher = f->offer.publisher; f->args.carrier_size++;
    bool ok = !zcl_test_app_host_ready(&f->args, f->line, (size_t)n, 0, &ready); f->args.carrier_size--;
    if (ok) { f->line[n] = 'x'; ok = !zcl_test_app_host_ready(&f->args, f->line, (size_t)n+1u, (size_t)n/2, &ready); }
    if (ok) { f->line[n-2] = f->line[n-2] == '0' ? '1' : '0';
        ok = !zcl_test_app_host_ready(&f->args, f->line, (size_t)n, (size_t)n/2, &ready); }
    return ok;
}
static bool host_carrier_write(const char *root, const struct host_ready_fixture_data *f)
{
    char path[900];
    int n = snprintf(path, sizeof(path), "%s/carrier.z23share", root);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    size_t size = (size_t)f->offer.size;
    bool ok = fwrite(f->bytes, 1, size, file) == size;
    return fclose(file) == 0 && ok;
}
static bool host_chain_carrier_child(const char *root, const struct host_ready_fixture_data *f,
    enum chain_network network, bool expected)
{
    if (chdir(root)) return false;
    chain_params_select(network);
    bool ok = zcl_test_app_host_verify_carrier(f->args.name, f->args.release_root,
        f->args.package_root, f->args.publisher, f->args.carrier_sha256, f->args.carrier_size);
    struct stat st;
    if (ok != expected || (stat("zcode/chain-binding.v1", &st) == 0) != expected) return false;
    if (!expected) return true;
    FILE *file = fopen("zcode/chain-binding.v1", "r");
    if (!file) return false;
    char binding[128]; size_t n = fread(binding, 1, sizeof(binding), file);
    bool matches = n == strlen("zcl.package-store.chain.v1\nzclassic-main\n") &&
        !memcmp(binding, "zcl.package-store.chain.v1\nzclassic-main\n", n) && !ferror(file);
    return fclose(file) == 0 && matches;
}
static bool host_chain_carrier(const struct host_ready_fixture_data *f, enum chain_network network, bool expected)
{
    char root[800];
    if (!test_mkdtemp(root, sizeof(root), "host_chain") || !host_carrier_write(root, f)) return false;
    pid_t child = fork();
    if (!child) _exit(host_chain_carrier_child(root, f, network, expected) ? 0 : 2);
    int status = 0; pid_t waited = -1;
    if (child > 0) do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    bool ok = child > 0 && waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    return test_rm_rf_recursive(root) == 0 && ok;
}
static bool host_ready_fixture(void)
{
    struct host_ready_fixture_data f = {0};
    bool ok = host_ready_setup(&f) && host_ready_identity(&f) && host_ready_process(&f);
    if (ok) ok = !strcmp(f.share->release.chain_id, "zclassic-main") &&
        host_chain_carrier(&f, CHAIN_MAIN, true) && host_chain_carrier(&f, CHAIN_TESTNET, false) &&
        host_chain_carrier(&f, CHAIN_REGTEST, false);
    for (unsigned mode = 0; ok && mode < 4; mode++)
        ok = host_fake_terminal(f.root, f.line, f.line_len, &f.args, mode);
    if (ok) ok = host_ready_rejections(&f);
    if (ok) ok = host_scratch_replacement(f.root);
    free(f.post); if (f.share) { vcs_package_share_cleanup(f.share); free(f.share); } free(f.bytes);
    if (f.root[0] && test_rm_rf_recursive(f.root) != 0) ok = false;
    return ok;
}
static bool host_scratch_refused(const char *path, const char *sentinel, const struct stat *original)
{
    pid_t pid = fork(); if (pid < 0) return false;
    if (!pid) _exit(zcl_test_app_host_enter_scratch(path, (uint64_t)original->st_dev, (uint64_t)original->st_ino) ? 2 : 0);
    int status = 0; pid_t done;
    do { done = waitpid(pid, &status, 0); } while (done < 0 && errno == EINTR);
    char text[8] = {0}; FILE *fp = fopen(sentinel, "r"); if (!fp) return false;
    size_t n = fread(text, 1, sizeof(text), fp); int closed = fclose(fp);
    return done == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
        closed == 0 && n == 4 && !memcmp(text, "KEEP", 4);
}
static bool host_scratch_replacement(const char *root)
{
    char path[800], saved[800], sentinel[800]; struct stat st;
    if (snprintf(path, sizeof(path), "%s/host-scratch", root) >= (int)sizeof(path) ||
        snprintf(saved, sizeof(saved), "%s/host-saved", root) >= (int)sizeof(saved) ||
        snprintf(sentinel, sizeof(sentinel), "%s/host-scratch/sentinel", root) >= (int)sizeof(sentinel) ||
        mkdir(path, 0700) != 0 || stat(path, &st) != 0 || rename(path, saved) != 0 || mkdir(path, 0700) != 0)
        return false;
    FILE *fp = fopen(sentinel, "w"); if (!fp) return false;
    int wrote = fputs("KEEP", fp); int closed = fclose(fp);
    if (wrote < 0 || closed != 0) return false;
    return host_scratch_refused(path, sentinel, &st);
}
static bool host_test_copy(const struct app_host_ready *, void *);
struct host_copy_race {
    struct app_host_state state;
    pthread_mutex_t mutex; pthread_cond_t condition;
    bool entered, release, copied;
};
static bool host_race_copy(const struct app_host_ready *ready, void *context)
{
    struct host_copy_race *race = context; (void)ready;
    pthread_mutex_lock(&race->mutex); race->entered = true;
    pthread_cond_broadcast(&race->condition);
    while (!race->release) pthread_cond_wait(&race->condition, &race->mutex);
    pthread_mutex_unlock(&race->mutex); return true;
}
static void *host_race_copy_thread(void *context)
{
    struct host_copy_race *race = context;
    race->copied = app_host_state_copy(&race->state, host_race_copy, race); return NULL;
}
static void *host_race_stop_thread(void *context)
{ struct host_copy_race *race = context; app_host_state_stop(&race->state); return NULL; }
static bool host_race_wait_entered(struct host_copy_race *race)
{
    struct timespec deadline = {0}; bool ok = clock_gettime(CLOCK_REALTIME, &deadline) == 0;
    if (ok) deadline.tv_sec += 10;
    pthread_mutex_lock(&race->mutex); int rc = 0;
    while (ok && !race->entered && rc == 0) rc = pthread_cond_timedwait(&race->condition, &race->mutex, &deadline);
    ok = ok && race->entered; pthread_mutex_unlock(&race->mutex); return ok;
}
static bool host_race_result(struct host_copy_race *race)
{
    struct app_host_snapshot snapshot; unsigned copies = 0;
    return race->copied && app_host_state_snapshot(&race->state, &snapshot) && snapshot.stop &&
        !snapshot.available && snapshot.ever_ready && !app_host_state_copy(&race->state, host_test_copy, &copies) && !copies;
}
static bool host_copy_stop_race(void)
{
    struct host_copy_race race = {0}; struct app_host_ready ready = {0};
    pthread_t copier, stopper; ready.post_id[0] = 'a';
    if (!app_host_state_init(&race.state)) return false;
    if (pthread_mutex_init(&race.mutex, NULL)) { app_host_state_destroy(&race.state); return false; }
    if (pthread_cond_init(&race.condition, NULL)) { pthread_mutex_destroy(&race.mutex); app_host_state_destroy(&race.state); return false; }
    bool copy_started = false, stop_started = false;
    bool ok = app_host_state_publish(&ready, &race.state) &&
              pthread_create(&copier, NULL, host_race_copy_thread, &race) == 0;
    copy_started = ok;
    if (ok) ok = host_race_wait_entered(&race);
    if (ok) { stop_started = pthread_create(&stopper, NULL, host_race_stop_thread, &race) == 0; ok = stop_started; }
    pthread_mutex_lock(&race.mutex); race.release = true; pthread_cond_broadcast(&race.condition); pthread_mutex_unlock(&race.mutex);
    if (copy_started) ok = pthread_join(copier, NULL) == 0 && ok;
    if (stop_started) ok = pthread_join(stopper, NULL) == 0 && ok;
    ok = ok && host_race_result(&race);
    pthread_cond_destroy(&race.condition); pthread_mutex_destroy(&race.mutex); app_host_state_destroy(&race.state);
    return ok;
}
struct host_test_clock { int64_t ns; };
static int64_t host_test_now(void *context) { return ((struct host_test_clock *)context)->ns; }
static bool host_state_clock_child(unsigned mode)
{
    struct host_test_clock time = {.ns = 1500000000LL};
    clock_iface_t fake = {.now_monotonic_ns = host_test_now, .now_wall_ms = host_test_now, .self = &time};
    const clock_iface_t *previous = clock_default(); clock_set_default(&fake);
    struct app_host_state state; struct app_host_ready ready = {0}; struct app_host_snapshot snapshot;
    bool ok = app_host_state_init(&state);
    if (ok) {
        state.started_ms = state.last_ms = 1000; state.deadline_ms = 2000;
        ready.post_id[0] = 'a'; ok = app_host_state_publish(&ready, &state);
        time.ns = mode == 0 ? 0 : (mode == 1 ? 1400000000LL : 2000000000LL);
        ok = ok && app_host_state_snapshot(&state, &snapshot) && snapshot.terminal &&
            !snapshot.available && snapshot.ever_ready && !app_host_state_publish(&ready, &state);
        app_host_state_destroy(&state);
    }
    clock_set_default(previous); return ok;
}
static bool host_state_clock_case(unsigned mode)
{
    pid_t pid = fork(); if (pid < 0) return false;
    if (!pid) _exit(host_state_clock_child(mode) ? 0 : 2);
    int status = 0; pid_t done;
    do { done = waitpid(pid, &status, 0); } while (done < 0 && errno == EINTR);
    return done == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static bool host_cleanup_paths(const struct json_value *error, const struct json_value *facts,
                               const char *scratch, const char *path, bool unconfirmed)
{
    const char *actual = zcl_package_copy_str(facts, "output");
    const char *cleanup = zcl_package_copy_str(facts, "cleanup_path");
    const char *evidence = zcl_package_copy_str(error, "evidence");
    return unconfirmed ? actual && !strcmp(actual, path) && cleanup && !strcmp(cleanup, scratch) &&
        json_get_bool(json_get(facts, "cleanup_unconfirmed")) :
        !actual && !cleanup && (!evidence || strcmp(evidence, path)) && json_get_bool(json_get(facts, "cleanup_completed"));
}
static bool host_cleanup_check(const struct json_value *decoded, const char *scratch, const char *path,
    const char *release, const char *package, const char *version, bool unconfirmed)
{
    const struct json_value *error = json_get(decoded, "error"), *facts = json_get(error, "facts");
    const char *code = zcl_package_copy_str(error, "code");
    const char *r = zcl_package_copy_str(facts, "release_id"), *p = zcl_package_copy_str(facts, "package_root");
    const char *v = zcl_package_copy_str(facts, "version");
    return code && !strcmp(code, "SHARE_FILE_WRITE") && r && !strcmp(r, release) && p && !strcmp(p, package) &&
        v && !strcmp(v, version) && json_get_bool(json_get(error, "mutated")) &&
        host_cleanup_paths(error, facts, scratch, path, unconfirmed);
}
static bool host_cleanup_failure_wire(bool unconfirmed)
{
    const char scratch[] = "/private/tmp/quoted-\"-scratch";
    const char path[] = "/private/tmp/quoted-\"-scratch/carrier.z23share";
    char release[65], package[65], version[65];
    memset(release, 'c', 64); release[64] = 0;
    memset(package, 'b', 64); package[64] = 0;
    memset(version, 'a', 64); version[64] = 0;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_host_link.v1");
    zcl_package_copy_fail(&reply, "SHARE_FILE_WRITE", true,
        "the release is kept, but the share file could not be created; name a new path as output", path);
    /* This is the actual shape added by sh_partial_facts after signer failure. */
    struct json_value existing; json_init(&existing); json_set_object(&existing);
    bool ok = json_push_kv_str(&existing, "release_id", release) && json_push_kv_str(&existing, "package_root", package) &&
        json_push_kv_str(&existing, "version", version) && json_push_kv_str(&existing, "output", path) &&
        json_push_kv(&reply.data, "failure_facts", &existing);
    json_free(&existing);
    if (ok) zcl_test_app_host_failure_facts(&reply, scratch, path, unconfirmed);
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), "app.library", NULL);
    char wire[3073];
    size_t n = ok && spec ? zcl_command_registry_test_reply_wire(zcl_command_catalog(), spec, &reply, wire, sizeof(wire)) : 0;
    struct json_value decoded; json_init(&decoded);
    ok = n && n < sizeof(wire) && json_read(&decoded, wire, n);
    ok = ok && host_cleanup_check(&decoded, scratch, path, release, package, version, unconfirmed);
    json_free(&decoded); zcl_command_reply_free(&reply); return ok;
}
static bool host_lifeline_limits(void)
{
    pid_t pid = fork(); if (pid < 0) return false;
    if (!pid) {
        struct app_network_lifeline guard;
        uint64_t parent = (uint64_t)getppid();
        if (app_network_lifeline_start(&guard, parent, 135001u) ||
            app_host_lifeline_start(&guard, parent, 86405001u) ||
            !app_host_lifeline_start(&guard, parent, 86405000u) ||
            !app_network_lifeline_stop(&guard)) _exit(2);
        _exit(0);
    }
    int status = 0; pid_t done;
    do { done = waitpid(pid, &status, 0); } while (done < 0 && errno == EINTR);
    return done == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static bool host_test_copy(const struct app_host_ready *ready, void *context)
{ unsigned *calls = context; (*calls)++; return ready->post_id[0] != 0; }
static bool host_state_before_ready(bool stop)
{
    struct app_host_state state; struct app_host_snapshot snapshot; struct app_host_ready ready = {0};
    unsigned copies = 0; ready.post_id[0] = 'a';
    if (!app_host_state_init(&state)) return false;
    if (stop) app_host_state_stop(&state); else app_host_state_unavailable(&state);
    bool ok = !app_host_state_publish(&ready, &state) &&
        (!stop || !app_host_state_copy(&state, host_test_copy, &copies)) &&
        app_host_state_snapshot(&state, &snapshot) && !snapshot.ever_ready &&
        (stop ? snapshot.stop : snapshot.terminal && !snapshot.available);
    app_host_state_destroy(&state); return ok;
}
static bool host_state_after_ready(void)
{
    struct app_host_state state; struct app_host_snapshot snapshot; struct app_host_ready ready = {0};
    unsigned copies = 0; ready.post_id[0] = 'a';
    if (!app_host_state_init(&state)) return false;
    bool ok = app_host_state_publish(&ready, &state) && app_host_state_copy(&state, host_test_copy, &copies);
    app_host_state_unavailable(&state);
    ok = ok && !app_host_state_copy(&state, host_test_copy, &copies) &&
        !app_host_state_publish(&ready, &state) &&
        app_host_state_snapshot(&state, &snapshot) && snapshot.ever_ready && snapshot.terminal && !snapshot.available;
    app_host_state_finish(&state, APP_HOST_FAILED);
    ok = ok && app_host_state_snapshot(&state, &snapshot) && snapshot.finished &&
        !snapshot.available && snapshot.ever_ready && copies == 1;
    app_host_state_destroy(&state); return ok;
}
static bool host_state_transitions(void)
{ return host_state_before_ready(true) && host_state_before_ready(false) && host_state_after_ready(); }
static bool host_carrier_capacity_child(const char *path)
{
    if (chdir(path)) return false;
    size_t size = VCS_BUNDLE_MAX_BYTES;
    uint8_t *bytes = malloc(size), *readback = malloc(size);
    if (!bytes || !readback) { free(bytes); free(readback); return false; }
    for (size_t i = 0; i < size; i++) bytes[i] = (uint8_t)(i * 37u);
    char hex[65]; uint8_t root[32]; size_t got = 0;
    bool ok = !zcl_test_app_host_store_carrier(bytes, 0, hex) &&
        !zcl_test_app_host_store_carrier(bytes, size + 1, hex) &&
        zcl_test_app_host_store_carrier(bytes, size, hex) && zcl_hex_decode_lower(hex, root, 32);
    struct vcs_package_store *store = ok ? vcs_package_store_open(".",
        VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES) : NULL;
    ok = ok && store && vcs_bundle_get_from(store, root, readback, size, &got) == VCS_BUNDLE_OK &&
        got == size && !memcmp(bytes, readback, size);
    if (store) vcs_package_store_close(store);
    free(bytes); free(readback); return ok;
}
static bool host_carrier_capacity(void)
{
    char path[800];
    if (!test_mkdtemp(path, sizeof(path), "app_host_capacity")) return false;
    pid_t child = fork();
    if (!child) _exit(host_carrier_capacity_child(path) ? 0 : 2);
    int status = 0; pid_t waited = -1;
    if (child > 0) do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    bool ok = child > 0 && waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    return test_rm_rf_recursive(path) == 0 && ok;
}
static bool host_port_low(uint8_t *out, size_t size)
{ if (size != 2) return false; out[0] = 0; out[1] = 0; return true; }
static bool host_port_high(uint8_t *out, size_t size)
{ if (size != 2) return false; out[0] = 0xcd; out[1] = 0x41; return true; }
static bool host_port_failure(uint8_t *out, size_t size)
{ (void)out; (void)size; return false; }
static int host_ready_frame_tests(void)
{
    int failures = 0;
    TEST("host private Tor bootstrap port varies and refuses entropy failure") {
        uint16_t port = 99;
        ASSERT(zcl_test_app_host_bootstrap_port(host_port_low, &port) && port == 1024);
        ASSERT(zcl_test_app_host_bootstrap_port(host_port_high, &port) && port == 53569);
        port = 99; ASSERT(!zcl_test_app_host_bootstrap_port(host_port_failure, &port) && port == 99);
        ASSERT(!zcl_test_app_host_bootstrap_port(NULL, &port));
        ASSERT(!zcl_test_app_host_bootstrap_port(host_port_low, NULL)); PASS();
    }
    TEST("host worker chain names are explicit and bounded") {
        ASSERT(!strcmp(app_host_chain_token(CHAIN_MAIN), "main"));
        ASSERT(!strcmp(app_host_chain_token(CHAIN_TESTNET), "test"));
        ASSERT(!strcmp(app_host_chain_token(CHAIN_REGTEST), "regtest"));
        ASSERT(!app_host_chain_token(CHAIN_MAX_NETWORK_TYPES)); PASS();
    }
    TEST("host carrier storage admits the full legal byte limit without eviction") {
        ASSERT(host_carrier_capacity()); PASS();
    }
    TEST("host confirmation Cancel and stale revision never start a worker") {
        ASSERT(host_flow_case(false)); ASSERT(host_flow_case(true)); PASS();
    }
    TEST("app host failure wire preserves signer facts and only unconfirmed cleanup path") {
        ASSERT(host_cleanup_failure_wire(false)); ASSERT(host_cleanup_failure_wire(true)); PASS();
    }
    TEST("app host stop serializes with an in-flight copy") {
        ASSERT(host_copy_stop_race()); PASS();
    }
    TEST("app host serializes stop, ready, copy, and observed failure") {
        ASSERT(host_state_transitions()); PASS();
    }
    TEST("app host availability fails closed on zero, backward and expired clock") {
        ASSERT(host_state_clock_case(0)); ASSERT(host_state_clock_case(1)); ASSERT(host_state_clock_case(2)); PASS();
    }
    TEST("app host lifeline preserves separate receiving and hosting limits") {
        ASSERT(host_lifeline_limits()); PASS();
    }
    TEST("app host ready validates signed carrier identity") {
        ASSERT(host_ready_fixture()); PASS();
    } _test_next:;
    return failures;
}
static bool host_evidence_has(const struct zcl_spawn_evidence *e, const char *text)
{
    size_t n = strlen(text);
    for (size_t i = 0; i + n <= e->stderr_len; ++i)
        if (!memcmp(e->stderr_tail + i, text, n)) return true;
    return false;
}
static bool host_cold_scratch(const struct host_ready_fixture_data *f, char *root, size_t cap, struct stat *st)
{
    char zcode[900], binding[960];
    if (!test_mkdtemp(root, cap, "host_cold") || !host_carrier_write(root, f) || stat(root, st)) return false;
    int n = snprintf(zcode, sizeof(zcode), "%s/zcode", root);
    int b = snprintf(binding, sizeof(binding), "%s/chain-binding.v1", zcode);
    if (n <= 0 || (size_t)n >= sizeof(zcode) || b <= 0 || (size_t)b >= sizeof(binding) || mkdir(zcode, 0700)) return false;
    FILE *file = fopen(binding, "w");
    if (!file) return false;
    bool ok = fputs("invalid binding\n", file) >= 0;
    return fclose(file) == 0 && ok;
}
static bool host_cold_exec(const struct host_ready_fixture_data *f, const char *root, const struct stat *st,
    const char *network, bool expect_binding)
{
    char image[4096], dev[32], ino[32], size[32], deadline[32], parent[32];
    int64_t now = platform_time_monotonic_ms();
    if (!realpath("build/bin/z23-dev", image) || now <= 0 || now > INT64_MAX - 5000) return false;
    (void)snprintf(dev, sizeof(dev), "%llu", (unsigned long long)st->st_dev);
    (void)snprintf(ino, sizeof(ino), "%llu", (unsigned long long)st->st_ino);
    (void)snprintf(size, sizeof(size), "%llu", (unsigned long long)f->args.carrier_size);
    (void)snprintf(deadline, sizeof(deadline), "%llu", (unsigned long long)(now + 5000));
    (void)snprintf(parent, sizeof(parent), "%llu", (unsigned long long)getpid());
    const char *argv[] = {image, "--app-host-worker", root, dev, ino, f->args.name, f->args.release_root,
        f->args.package_root, f->args.publisher, f->args.carrier_sha256, size, "5000", deadline, parent, network, NULL};
    char output[256]; struct zcl_spawn_evidence e = {0};
    (void)zcl_spawn_capture_evidence(argv, output, sizeof(output), 8000, &e);
    return e.exit_observed && e.exit_code == 2 && !e.timed_out && e.stderr_complete &&
        host_evidence_has(&e, "package store chain binding refused") == expect_binding;
}
static bool host_cold_worker(void)
{
    struct host_ready_fixture_data f = {0}; char root[800] = {0}; struct stat st;
    bool ok = host_ready_setup(&f) && host_cold_scratch(&f, root, sizeof(root), &st);
    if (ok) ok = host_cold_exec(&f, root, &st, "main", true) &&
        host_cold_exec(&f, root, &st, "test", false) &&
        host_cold_exec(&f, root, &st, "invalid", false);
    free(f.post); if (f.share) { vcs_package_share_cleanup(f.share); free(f.share); } free(f.bytes);
    if (root[0] && test_rm_rf_recursive(root) != 0) ok = false;
    if (f.root[0] && test_rm_rf_recursive(f.root) != 0) ok = false;
    return ok;
}
int test_app_host_worker(void)
{
    int failures = 0;
    TEST("cold host worker selects its chain before opening the private store") {
        ASSERT(host_cold_worker()); PASS();
    } _test_next:;
    return failures;
}
#else
static int host_ready_frame_tests(void) { return 0; }
int test_app_host_worker(void) { puts("UNOBSERVED (app_host_worker requires POSIX)"); return 0; }
#endif

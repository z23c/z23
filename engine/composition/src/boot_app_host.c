/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Coordinate verified app-host intent, renewal and revocation. */
#include "config/boot_app_host.h"
#include "config/boot_fleet_board.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/sha256.h"
#include "controllers/network_controller.h"
#include "json/json.h"
#include "models/app_host_intent.h"
#include "models/database.h"
#include "models/fleet_board_post.h"
#include "util/sync.h"
#include "vcs/bundle_carry.h"
#include "vcs/package_share.h"
#include "vcs/package_store.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

static zcl_mutex_t s_host_lock;
static zcl_once_t s_host_once = ZCL_ONCE_INIT;
#ifdef ZCL_TESTING
static const struct boot_app_host_test_hooks *s_host_test_hooks;
void boot_app_host_set_test_hooks(const struct boot_app_host_test_hooks *hooks)
{
    s_host_test_hooks = hooks;
}
#endif
static void host_lock_init(void) { zcl_mutex_init(&s_host_lock); }
static void host_lock(void)
{
    (void)zcl_once_call(&s_host_once, host_lock_init);
    zcl_mutex_lock(&s_host_lock);
}

static bool host_identity(uint8_t host[32], bool create)
{
#ifdef ZCL_TESTING
    if (s_host_test_hooks && s_host_test_hooks->identity)
        return s_host_test_hooks->identity(s_host_test_hooks->context, host, create);
#endif
    if (!create) return boot_fleet_board_load_existing_identity(host);
    uint8_t seed[32] = {0}; char why[256];
    bool ok = boot_fleet_board_identity(seed, host, why, sizeof(why));
    memory_cleanse(seed, sizeof(seed));
    return ok;
}

static bool host_datadir(const char *datadir)
{
#ifdef ZCL_TESTING
    if (s_host_test_hooks && s_host_test_hooks->datadir)
        return s_host_test_hooks->datadir(s_host_test_hooks->context, datadir);
#endif
    return boot_fleet_board_datadir_matches(datadir);
}

bool boot_app_host_endpoint(char host[static 63],
                            char endpoint[static ZCL_APP_OFFER_ONION_MAX + 1u])
{
    struct json_value status;
    host[0] = endpoint[0] = '\0';
    json_init(&status);
    bool ready = network_onion_status_rpc(NULL, false, &status) &&
                 vcs_app_offer_endpoint(&status, host, endpoint);
    json_free(&status);
    return ready;
}

struct host_expected {
    uint8_t root[32], sha[32], release[32], publisher[33];
};

static bool host_decode(const struct zcl_app_offer *offer, struct host_expected *e)
{
    return zcl_app_offer_valid(offer) &&
        zcl_hex_decode_lower(offer->carrier, e->root, sizeof(e->root)) &&
        zcl_hex_decode_lower(offer->sha256, e->sha, sizeof(e->sha)) &&
        zcl_hex_decode_lower(offer->root, e->release, sizeof(e->release)) &&
        zcl_hex_decode_lower(offer->publisher, e->publisher, sizeof(e->publisher));
}

static bool host_verify_bytes(const struct zcl_app_offer *offer,
                              const struct host_expected *e,
                              const uint8_t *bytes, size_t len, const uint8_t *release_id)
{
    uint8_t actual_sha[32];
    struct vcs_package_share share = {0};
    struct sha256_ctx hash;
    const char *reason = NULL;
    sha256_init(&hash); sha256_write(&hash, bytes, len); sha256_finalize(&hash, actual_sha);
    bool ok = memcmp(actual_sha, e->sha, sizeof(actual_sha)) == 0 &&
         vcs_package_share_load(&share, bytes, len, &reason) &&
         vcs_package_share_check_source(&share, &reason) &&
         (!release_id || !memcmp(share.release_id, release_id, 32)) &&
         memcmp(share.release.package_root, e->release, sizeof(e->release)) == 0 &&
         memcmp(share.release.publisher_pubkey, e->publisher, sizeof(e->publisher)) == 0 &&
         strcmp(share.release.name, offer->name) == 0;
    vcs_package_share_cleanup(&share);
    return ok;
}

static bool host_receipt_current(struct vcs_package_store *store,
                                 const uint8_t root[32], uint64_t generation)
{
    struct vcs_package_possession_receipt current = {0};
    return vcs_package_store_possession_snapshot(store, root, &current) &&
           current.complete && current.pinned &&
           current.mutation_generation == generation;
}

static bool host_verify_carrier(struct vcs_package_store *store,
    const struct zcl_app_offer *offer, const uint8_t *release_id, uint64_t *generation)
{
    struct host_expected expected;
    struct vcs_package_possession_receipt receipt = {0};
    size_t len = 0, actual_len = 0;
    uint8_t *bytes = NULL;
    if (generation) *generation = 0;
    bool ok = generation && store && host_decode(offer, &expected) &&
        vcs_package_store_verify_possession_receipt(store, expected.root, true, &receipt) &&
        vcs_bundle_size_of(store, expected.root, &len) == VCS_BUNDLE_OK &&
        len == (size_t)offer->size;
    if (ok) bytes = zcl_malloc(len, "app host verified carrier");
    ok = ok && bytes && vcs_bundle_get_from(store, expected.root, bytes, len, &actual_len) == VCS_BUNDLE_OK &&
         actual_len == len && host_verify_bytes(offer, &expected, bytes, len, release_id) &&
         host_receipt_current(store, expected.root, receipt.mutation_generation);
    if (ok) *generation = receipt.mutation_generation;
    free(bytes);
    return ok;
}
bool boot_app_host_verify_carrier(struct vcs_package_store *store,
                                  const struct zcl_app_offer *offer,
                                  uint64_t *generation)
{ return host_verify_carrier(store, offer, NULL, generation); }

static bool host_plan_fields(const struct boot_app_host_plan *p)
{
    return p && p->datadir && strnlen(p->datadir, 4097) <= 4096 &&
        p->expected_plan && strnlen(p->expected_plan, 65) == 64 &&
        p->post_id && strnlen(p->post_id, 65) == 64 &&
        p->post_host && strnlen(p->post_host, 65) == 64 &&
        p->receive_plan && strnlen(p->receive_plan, 65) == 64 &&
        p->token && strnlen(p->token, 33) == 32;
}

static bool host_offer_fields(const struct boot_app_host_plan *p)
{
    return memchr(p->offer.name, 0, sizeof(p->offer.name)) &&
        memchr(p->offer.root, 0, sizeof(p->offer.root)) &&
        memchr(p->offer.publisher, 0, sizeof(p->offer.publisher)) &&
        memchr(p->offer.carrier, 0, sizeof(p->offer.carrier)) &&
        memchr(p->offer.sha256, 0, sizeof(p->offer.sha256)) &&
        memchr(p->offer.onion, 0, sizeof(p->offer.onion));
}

static bool host_plan_ok(const struct boot_app_host_plan *p)
{
    uint8_t actual[32], expected[32];
    if (!host_plan_fields(p) || !host_offer_fields(p)) return false;
    return zcl_hex_decode_lower(p->expected_plan, expected, sizeof(expected)) &&
        vcs_app_get_recurring_plan(&p->offer, p->post_id, p->post_host,
                                   p->receive_plan, p->datadir, p->token, actual) &&
        memcmp(actual, expected, sizeof(actual)) == 0;
}

static bool host_same_binding(const struct app_host_binding *a,
                              const struct app_host_binding *b)
{
    return a->recurring && a->size == b->size &&
        !memcmp(a->local_host, b->local_host, 32) && !strcmp(a->name, b->name) &&
        !strcmp(a->publisher, b->publisher) && !strcmp(a->release_root, b->release_root) &&
        !strcmp(a->carrier_root, b->carrier_root) && !strcmp(a->sha256, b->sha256);
}

static bool host_source_offer(struct node_db *db,
                              const struct boot_app_host_plan *plan, int64_t now)
{
    uint8_t id[32], host[32];
    struct db_fleet_board_post row;
    struct zcl_app_offer parsed;
    char expected[ZCL_APP_OFFER_TEXT_MAX + 1u], actual[ZCL_APP_OFFER_TEXT_MAX + 1u];
    return zcl_hex_decode_lower(plan->post_id, id, sizeof(id)) &&
        zcl_hex_decode_lower(plan->post_host, host, sizeof(host)) &&
        db_fleet_board_post_lookup_checked(db, id, &row) == FLEET_BOARD_LOOKUP_FOUND &&
        row.post.kind == FLEET_BOARD_KIND_OFFER && row.post.scope == FLEET_BOARD_SCOPE_PUBLIC &&
        !strcmp(row.post.room, "apps") && !memcmp(row.post.host_pubkey, host, sizeof(host)) &&
        fleet_board_post_check_time(&row.post, now) == FLEET_BOARD_OK &&
        zcl_app_offer_parse(row.post.text, row.post.text_len, &parsed) &&
        zcl_app_offer_format(&parsed, actual, sizeof(actual)) &&
        zcl_app_offer_format(&plan->offer, expected, sizeof(expected)) &&
        !strcmp(actual, expected);
}

static enum boot_app_host_result host_result(enum app_host_result r)
{
    if (r == APP_HOST_OK) return BOOT_APP_HOST_OK;
    if (r == APP_HOST_BUSY) return BOOT_APP_HOST_BUSY;
    if (r == APP_HOST_STALE || r == APP_HOST_CONFLICT) return BOOT_APP_HOST_STALE;
    if (r == APP_HOST_INVALID || r == APP_HOST_NOT_FOUND) return BOOT_APP_HOST_INVALID;
    return BOOT_APP_HOST_STORAGE;
}

static struct app_host_binding host_binding(const struct zcl_app_offer *offer, const uint8_t host[32])
{
    struct app_host_binding b = {.size = offer->size, .recurring = true};
    memcpy(b.local_host, host, 32);
    (void)snprintf(b.name, sizeof(b.name), "%s", offer->name);
    (void)snprintf(b.publisher, sizeof(b.publisher), "%s", offer->publisher);
    (void)snprintf(b.release_root, sizeof(b.release_root), "%s", offer->root);
    (void)snprintf(b.carrier_root, sizeof(b.carrier_root), "%s", offer->carrier);
    (void)snprintf(b.sha256, sizeof(b.sha256), "%s", offer->sha256);
    return b;
}

static enum vcs_zcode_dht_key_probe host_local_probe(const char *datadir, uint8_t host[32])
{
#ifdef ZCL_TESTING
    if (s_host_test_hooks && s_host_test_hooks->identity_probe)
        return s_host_test_hooks->identity_probe(s_host_test_hooks->context, host);
#endif
    return boot_fleet_board_identity_probe(datadir, host);
}
static enum vcs_zcode_dht_key_create host_local_create(const char *datadir, uint8_t host[32])
{
#ifdef ZCL_TESTING
    if (s_host_test_hooks && s_host_test_hooks->identity_create)
        return s_host_test_hooks->identity_create(s_host_test_hooks->context, host);
#endif
    return boot_fleet_board_identity_create_if_absent(datadir, host);
}
static enum boot_app_host_result host_local_observe_locked(struct node_db *db,
    const char *datadir, const struct zcl_app_offer *offer, struct boot_app_host_local_state *out)
{
    memset(out, 0, sizeof(*out));
    enum vcs_zcode_dht_key_probe probe = host_local_probe(datadir, out->host);
    if (probe == VCS_DHT_IDENTITY_PROBE_ERROR) return BOOT_APP_HOST_UNAVAILABLE;
    if (probe == VCS_DHT_IDENTITY_ABSENT) { out->identity_absent = true; return BOOT_APP_HOST_OK; }
    if (probe != VCS_DHT_IDENTITY_PRESENT) return BOOT_APP_HOST_UNAVAILABLE;
    struct db_app_host_intent row;
    enum app_host_result r = db_app_host_intent_find(db, out->host, offer->carrier, &row);
    if (r == APP_HOST_NOT_FOUND) return BOOT_APP_HOST_OK;
    if (r != APP_HOST_OK) return host_result(r);
    struct app_host_binding binding = host_binding(offer, out->host);
    if (!host_same_binding(&row.binding, &binding) || row.generation >= INT64_MAX - 1)
        return BOOT_APP_HOST_STALE;
    out->generation = row.generation; out->enabled = row.enabled;
    return BOOT_APP_HOST_OK;
}
enum boot_app_host_result boot_app_host_local_observe(struct node_db *db,
    const char *datadir, const struct zcl_app_offer *offer, struct boot_app_host_local_state *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!db || !datadir || !offer || !out || !host_datadir(datadir) || !zcl_app_offer_valid(offer)) return BOOT_APP_HOST_INVALID;
    host_lock(); enum boot_app_host_result result = host_datadir(datadir) ?
        host_local_observe_locked(db, datadir, offer, out) : BOOT_APP_HOST_UNAVAILABLE;
    zcl_mutex_unlock(&s_host_lock); return result;
}
static bool host_local_same(const struct boot_app_host_local_state *a,
                            const struct boot_app_host_local_state *b)
{
    return a->identity_absent == b->identity_absent && a->generation == b->generation &&
        a->enabled == b->enabled && !memcmp(a->host, b->host, 32);
}
struct host_local_apply {
    struct node_db *writer;
    struct app_host_binding binding;
    int64_t generation, now;
    enum app_host_result result;
    bool called;
};
static void host_local_apply_if_current(void *context, bool current)
{
    struct host_local_apply *a = context;
    if (!current) return;
    a->called = true;
    a->result = db_app_host_intent_enable(a->writer, &a->binding, a->generation, a->now);
}
static bool host_local_writer(struct node_db *db, struct node_db *writer)
{
    if (!db->path[0] || !node_db_open_existing_runtime(writer, db->path, "app_host.local")) return false;
    if (sqlite3_busy_timeout(writer->db, 0) == SQLITE_OK) return true;
    node_db_close(writer); return false;
}
static enum boot_app_host_result host_local_create_if_needed(const char *datadir,
    struct boot_app_host_local_state *current, bool *attempted)
{
    if (!current->identity_absent) return BOOT_APP_HOST_OK;
    *attempted = true;
    enum vcs_zcode_dht_key_create created = host_local_create(datadir, current->host);
    if (created == VCS_DHT_IDENTITY_PREEXISTING) return BOOT_APP_HOST_STALE;
    return created == VCS_DHT_IDENTITY_CREATED ? BOOT_APP_HOST_OK : BOOT_APP_HOST_UNAVAILABLE;
}
static enum boot_app_host_result host_local_transition(struct node_db *db,
    struct vcs_package_store *store, const char *datadir, const struct zcl_app_offer *offer,
    const uint8_t root[32], uint64_t receipt, int64_t now,
    struct boot_app_host_local_state *current, bool *attempted)
{
    if (!host_datadir(datadir) || !host_receipt_current(store, root, receipt)) return BOOT_APP_HOST_UNAVAILABLE;
    enum boot_app_host_result result = host_local_create_if_needed(datadir, current, attempted);
    if (result != BOOT_APP_HOST_OK) return result;
    if (!host_datadir(datadir) || !host_receipt_current(store, root, receipt)) return BOOT_APP_HOST_UNAVAILABLE;
    if (!current->enabled) {
        struct host_local_apply apply = {.writer = db, .binding = host_binding(offer, current->host),
            .generation = current->generation, .now = now, .result = APP_HOST_STORAGE};
#ifdef ZCL_TESTING
        if (s_host_test_hooks && s_host_test_hooks->before_guard)
            s_host_test_hooks->before_guard(s_host_test_hooks->context);
#endif
        vcs_package_store_possession_apply_if_current(store, root, receipt, true, host_local_apply_if_current, &apply);
        *attempted |= apply.called;
        result = apply.called ? host_result(apply.result) : BOOT_APP_HOST_UNAVAILABLE;
        if (result == BOOT_APP_HOST_OK) ++current->generation;
    }
    return result;
}
static enum boot_app_host_result host_local_commit_locked(struct node_db *db,
    struct vcs_package_store *store, const char *datadir, const struct zcl_app_offer *offer,
    const struct boot_app_host_local_state *expected, const uint8_t root[32],
    uint64_t receipt, int64_t now, struct boot_app_host_local_state *current, bool *attempted)
{
    enum boot_app_host_result result = host_datadir(datadir) ?
        host_local_observe_locked(db, datadir, offer, current) : BOOT_APP_HOST_UNAVAILABLE;
    if (result != BOOT_APP_HOST_OK) return result;
    if (!host_local_same(current, expected)) return BOOT_APP_HOST_STALE;
    return host_local_transition(db, store, datadir, offer, root, receipt, now, current, attempted);
}
static bool host_local_commit_valid(struct node_db *db, struct vcs_package_store *store,
    const char *datadir, const struct zcl_app_offer *offer, const uint8_t release_id[32],
    const struct boot_app_host_local_state *expected, int64_t now,
    uint8_t host_out[32], const int64_t *generation_out, const bool *mutation_attempted)
{
    return db && store && datadir && host_datadir(datadir) && offer && release_id && expected && host_out &&
        generation_out && mutation_attempted && now > 0 && expected->generation >= 0 && expected->generation < INT64_MAX - 1;
}
enum boot_app_host_result boot_app_host_local_commit(struct node_db *db,
    struct vcs_package_store *store, const char *datadir, const struct zcl_app_offer *offer,
    const uint8_t release_id[32], const struct boot_app_host_local_state *expected,
    int64_t now, uint8_t host_out[32], int64_t *generation_out, bool *mutation_attempted)
{
    if (host_out) memset(host_out, 0, 32);
    if (generation_out) *generation_out = 0;
    if (mutation_attempted) *mutation_attempted = false;
    if (!host_local_commit_valid(db, store, datadir, offer, release_id, expected, now,
                                 host_out, generation_out, mutation_attempted))
        return BOOT_APP_HOST_INVALID;
    uint64_t receipt = 0; uint8_t root[32];
    if (!host_verify_carrier(store, offer, release_id, &receipt) ||
        !zcl_hex_decode_lower(offer->carrier, root, sizeof(root))) return BOOT_APP_HOST_INVALID;
    struct node_db writer = {0};
    if (!expected->enabled && !host_local_writer(db, &writer)) return BOOT_APP_HOST_STORAGE;
    host_lock(); struct boot_app_host_local_state current = {0};
    enum boot_app_host_result result = host_local_commit_locked(expected->enabled ? db : &writer, store, datadir, offer, expected,
                                                               root, receipt, now, &current, mutation_attempted);
    memcpy(host_out, current.host, 32);
    if (result == BOOT_APP_HOST_OK) *generation_out = current.generation;
    zcl_mutex_unlock(&s_host_lock);
    if (writer.open) node_db_close(&writer);
    return result;
}

static enum boot_app_host_result host_enable_locked(struct node_db *db,
    const struct boot_app_host_plan *plan, int64_t now, const uint8_t host[32],
    uint8_t local_host_out[32], int64_t *generation_out)
{
    struct app_host_binding binding = host_binding(&plan->offer, host);
    struct db_app_host_intent row;
    enum app_host_result r = db_app_host_intent_find(db, host, binding.carrier_root, &row);
    int64_t expected = r == APP_HOST_NOT_FOUND ? 0 : r == APP_HOST_OK ? row.generation : -1;
    if (r == APP_HOST_OK && row.enabled)
        r = host_same_binding(&row.binding, &binding) ? APP_HOST_OK : APP_HOST_CONFLICT;
    else if (expected >= 0) {
        r = db_app_host_intent_enable(db, &binding, expected, now);
        if (r == APP_HOST_OK) row.generation = expected + 1;
    }
    if (r == APP_HOST_OK) { memcpy(local_host_out, host, 32); *generation_out = row.generation; }
    return host_result(r);
}

enum boot_app_host_result boot_app_host_enable(
    struct node_db *db, struct vcs_package_store *store,
    const struct boot_app_host_plan *plan, int64_t now,
    uint8_t local_host_out[32], int64_t *generation_out)
{
    uint8_t host[32], carrier[32];
    uint64_t generation = 0;
    if (local_host_out) memset(local_host_out, 0, 32);
    if (generation_out) *generation_out = 0;
    if (!db || !store || !local_host_out || !generation_out || now <= 0 ||
        !host_plan_ok(plan) || !host_datadir(plan->datadir) ||
        !host_source_offer(db, plan, now)) return BOOT_APP_HOST_INVALID;
    if (!boot_app_host_verify_carrier(store, &plan->offer, &generation) ||
        !zcl_hex_decode_lower(plan->offer.carrier, carrier, sizeof(carrier)))
        return BOOT_APP_HOST_INVALID;
    host_lock();
    bool identity_ok = host_receipt_current(store, carrier, generation) &&
        host_identity(host, true);
    if (!identity_ok) {
        zcl_mutex_unlock(&s_host_lock); return BOOT_APP_HOST_UNAVAILABLE;
    }
    enum boot_app_host_result result = host_enable_locked(db, plan, now, host,
                                                           local_host_out, generation_out);
    zcl_mutex_unlock(&s_host_lock);
    return result;
}

enum boot_app_host_result boot_app_host_stop(
    struct node_db *db, const uint8_t local_host[32], const char *carrier,
    int64_t expected_generation)
{
    if (!db || !local_host || !carrier || expected_generation <= 0) return BOOT_APP_HOST_INVALID;
    host_lock();
    enum app_host_result r = db_app_host_intent_disable(db, local_host, carrier, expected_generation);
    zcl_mutex_unlock(&s_host_lock);
    return host_result(r);
}

static bool host_endpoint(char host[63], char endpoint[ZCL_APP_OFFER_ONION_MAX + 1u])
{
#ifdef ZCL_TESTING
    if (s_host_test_hooks && s_host_test_hooks->endpoint)
        return s_host_test_hooks->endpoint(s_host_test_hooks->context, host, endpoint);
#endif
    return boot_app_host_endpoint(host, endpoint);
}

static bool host_sign(struct fleet_board_post *post)
{
#ifdef ZCL_TESTING
    if (s_host_test_hooks && s_host_test_hooks->sign)
        return s_host_test_hooks->sign(s_host_test_hooks->context, post);
#endif
    return boot_fleet_board_sign_app_offer(post) == FLEET_BOARD_OK;
}

static enum fleet_board_lookup_status host_lookup(struct node_db *db,
    const uint8_t id[32], struct db_fleet_board_post *out)
{
#ifdef ZCL_TESTING
    if (s_host_test_hooks && s_host_test_hooks->lookup)
        return (enum fleet_board_lookup_status)s_host_test_hooks->lookup(s_host_test_hooks->context, db, id, out);
#endif
    return db_fleet_board_post_lookup_checked(db, id, out);
}

static void host_announce(const uint8_t id[32])
{
#ifdef ZCL_TESTING
    if (s_host_test_hooks && s_host_test_hooks->announce) {
        s_host_test_hooks->announce(s_host_test_hooks->context, id); return;
    }
#endif
    boot_fleet_board_announce(id);
}

static int64_t host_later(int64_t now, int64_t delta)
{
    return now > INT64_MAX - delta ? INT64_MAX : now + delta;
}

static int64_t host_next_slot(int64_t now)
{
    return host_later(now - now % 43200, 43200);
}

static int64_t host_retry_due(const struct db_app_host_intent *row, int64_t now)
{
    uint32_t shift = row->retry_count < 6u ? row->retry_count : 6u;
    int64_t seconds = (int64_t)60 << shift;
    return host_later(now, seconds > 3600 ? 3600 : seconds);
}

static void host_offer_from_row(const struct db_app_host_intent *row,
                                const char *endpoint, struct zcl_app_offer *offer)
{
    memset(offer, 0, sizeof(*offer));
    (void)snprintf(offer->name, sizeof(offer->name), "%s", row->binding.name);
    (void)snprintf(offer->root, sizeof(offer->root), "%s", row->binding.release_root);
    (void)snprintf(offer->publisher, sizeof(offer->publisher), "%s", row->binding.publisher);
    (void)snprintf(offer->carrier, sizeof(offer->carrier), "%s", row->binding.carrier_root);
    (void)snprintf(offer->sha256, sizeof(offer->sha256), "%s", row->binding.sha256);
    (void)snprintf(offer->onion, sizeof(offer->onion), "%s", endpoint);
    offer->size = row->binding.size;
}

static enum boot_app_host_result host_resume_locked(struct node_db *db,
    struct vcs_package_store *store, const struct db_app_host_intent *row,
    const uint8_t root[32], uint64_t generation, int64_t now)
{
    struct db_app_host_intent current; uint8_t host[32];
    enum app_host_result r = db_app_host_intent_find(db, row->binding.local_host,
                                                      row->binding.carrier_root, &current);
    if (r == APP_HOST_OK && (current.enabled || current.generation != row->generation ||
                             !host_same_binding(&current.binding, &row->binding))) r = APP_HOST_STALE;
    if (r == APP_HOST_OK && (!host_identity(host, false) || memcmp(host, row->binding.local_host, 32) ||
                             !host_receipt_current(store, root, generation))) {
        return BOOT_APP_HOST_UNAVAILABLE;
    }
    if (r == APP_HOST_OK)
        r = db_app_host_intent_enable(db, &current.binding, row->generation, now);
    return host_result(r);
}

enum boot_app_host_result boot_app_host_resume(
    struct node_db *db, struct vcs_package_store *store,
    const uint8_t local_host[32], const char *carrier,
    int64_t expected_generation, int64_t now)
{
    struct db_app_host_intent row; struct zcl_app_offer offer;
    uint8_t root[32]; uint64_t generation = 0;
    if (!db || !store || !local_host || !carrier || expected_generation <= 0 || now <= 0 ||
        !vcs_app_offer_hex_valid(carrier, 32) ||
        !zcl_hex_decode_lower(carrier, root, sizeof(root))) return BOOT_APP_HOST_INVALID;
    enum app_host_result r = db_app_host_intent_find(db, local_host, carrier, &row);
    if (r != APP_HOST_OK) return host_result(r);
    if (row.enabled || row.generation != expected_generation) return BOOT_APP_HOST_STALE;
    /* The endpoint is only needed to validate the internal offer shape. */
    host_offer_from_row(&row, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:29135", &offer);
    if (!boot_app_host_verify_carrier(store, &offer, &generation)) return BOOT_APP_HOST_INVALID;
    host_lock();
    enum boot_app_host_result result = host_resume_locked(db, store, &row, root, generation, now);
    zcl_mutex_unlock(&s_host_lock);
    return result;
}

static bool host_new_post(const struct db_app_host_intent *row, const char *endpoint,
                          int64_t now, struct fleet_board_post *post)
{
    struct zcl_app_offer offer;
    host_offer_from_row(row, endpoint, &offer);
    memset(post, 0, sizeof(*post));
    post->kind = FLEET_BOARD_KIND_OFFER; post->scope = FLEET_BOARD_SCOPE_PUBLIC;
    post->created_at = (uint64_t)now; post->ttl = 86400;
    (void)snprintf(post->room, sizeof(post->room), "apps");
    (void)snprintf(post->agent, sizeof(post->agent), "app-host");
    if (!zcl_app_offer_format(&offer, post->text, sizeof(post->text))) return false;
    post->text_len = (uint32_t)strlen(post->text);
    return host_sign(post) && boot_fleet_board_validate_app_offer(post, row->binding.local_host);
}

static enum app_host_result host_defer(struct node_db *db,
    const struct db_app_host_intent *row, int64_t due)
{
    uint32_t retry = row->retry_count < APP_HOST_RETRY_MAX ? row->retry_count + 1u : APP_HOST_RETRY_MAX;
    return db_app_host_intent_defer(db, row->binding.local_host, row->binding.carrier_root,
        row->generation, row->pending ? row->pending_id : NULL, due, retry);
}

static enum app_host_result host_pending_changed(struct node_db *db,
    struct db_app_host_intent *row, const char *endpoint, int64_t now,
    struct fleet_board_post *post, bool *reconciled)
{
    *reconciled = false;
    struct db_fleet_board_post existing;
    enum fleet_board_lookup_status found = host_lookup(db, row->pending_id, &existing);
    if (found != FLEET_BOARD_LOOKUP_FOUND && found != FLEET_BOARD_LOOKUP_ABSENT)
        return APP_HOST_STORAGE;
    uint8_t wire[APP_HOST_WIRE_MAX]; size_t len = 0;
    if (found == FLEET_BOARD_LOOKUP_FOUND) {
        if (fleet_board_post_encode(&existing.post, wire, sizeof(wire), &len) != FLEET_BOARD_OK ||
            len != row->pending_wire_len || memcmp(wire, row->pending_wire, len)) return APP_HOST_CORRUPT;
        enum app_host_result r = db_app_host_intent_reconcile(db, row->binding.local_host,
            row->binding.carrier_root, row->generation, row->pending_id, now, 0);
        if (r != APP_HOST_OK) return r;
        struct db_app_host_intent refreshed;
        r = db_app_host_intent_find(db, row->binding.local_host, row->binding.carrier_root, &refreshed);
        if (r != APP_HOST_OK) return r;
        *row = refreshed; *reconciled = true; return APP_HOST_OK;
    }
    if (!host_new_post(row, endpoint, now, post) ||
        fleet_board_post_encode(post, wire, sizeof(wire), &len) != FLEET_BOARD_OK) return APP_HOST_INVALID;
    return db_app_host_intent_replace_absent(db, row->binding.local_host, row->binding.carrier_root,
        row->generation, row->pending_id, now, endpoint, wire, len);
}

/* The intent lock is held; persist one exact signed post before any append. */
static enum app_host_result host_pending(struct node_db *db,
    struct db_app_host_intent *row, const char *endpoint, int64_t now,
    struct fleet_board_post *post)
{
    if (row->pending) {
        if (fleet_board_post_decode(row->pending_wire, row->pending_wire_len, post) != FLEET_BOARD_OK)
            return APP_HOST_CORRUPT;
        if (post->created_at > (uint64_t)now) return APP_HOST_BUSY;
        enum fleet_board_result timing = fleet_board_post_check_time(post, now);
        if (timing == FLEET_BOARD_ERR_EXPIRED) {
            enum app_host_result r = db_app_host_intent_retire_expired(db, row->binding.local_host,
                row->binding.carrier_root, row->generation, row->pending_id, now);
            if (r != APP_HOST_OK) return r;
            row->pending = false;
        } else if (timing != FLEET_BOARD_OK) return APP_HOST_INVALID;
        else if (!strcmp(row->slot_endpoint, endpoint)) return APP_HOST_OK;
        else {
            bool reconciled;
            enum app_host_result r = host_pending_changed(db, row, endpoint, now, post, &reconciled);
            if (r != APP_HOST_OK || !reconciled) return r;
        }
    }
    int64_t slot = now / 43200 + 1;
    if (row->renewal_slot == slot && !strcmp(row->slot_endpoint, endpoint)) return APP_HOST_BUSY;
    if (!host_new_post(row, endpoint, now, post)) return APP_HOST_INVALID;
    uint8_t wire[APP_HOST_WIRE_MAX]; size_t len = 0;
    if (fleet_board_post_encode(post, wire, sizeof(wire), &len) != FLEET_BOARD_OK) return APP_HOST_INVALID;
    return db_app_host_intent_reserve(db, row->binding.local_host, row->binding.carrier_root,
        row->generation, slot, now, endpoint, wire, len);
}

struct host_append {
    struct node_db *writer;
    struct fleet_board_post *post;
    const uint8_t *host;
    int64_t now;
    enum fleet_board_result result;
};

static void host_append_if_current(void *arg, bool current)
{
    struct host_append *a = arg;
    a->result = current ? boot_fleet_board_append_app_offer_nowait(a->writer, a->post,
        a->host, a->now, NULL) : FLEET_BOARD_ERR_BUSY;
}

static enum boot_app_host_result host_defer_current(struct node_db *db,
    const struct db_app_host_intent *snapshot, int64_t now)
{
    struct db_app_host_intent current;
    enum app_host_result r = db_app_host_intent_find(db, snapshot->binding.local_host,
        snapshot->binding.carrier_root, &current);
    if (r == APP_HOST_OK && current.enabled && current.generation == snapshot->generation)
        r = host_defer(db, &current, host_retry_due(&current, now));
    else if (r == APP_HOST_OK) r = APP_HOST_STALE;
    return host_result(r);
}

static enum boot_app_host_result host_due_snapshot(struct node_db *db, int64_t now,
    struct db_app_host_intent *row, bool *found)
{
    uint8_t host[32]; size_t count = 0; bool more = false;
    if (!host_identity(host, false)) return BOOT_APP_HOST_UNAVAILABLE;
    enum app_host_result r = db_app_host_intent_due(db, host, now, row, 1, &count, &more);
    (void)more; *found = r == APP_HOST_OK && count == 1;
    return host_result(r);
}

static bool host_prepare_writer(struct node_db *db, struct node_db *writer)
{
    if (!db->path[0] || !node_db_open_existing_runtime(writer, db->path, "app_host.renew")) return false;
    if (sqlite3_busy_timeout(writer->db, 0) == SQLITE_OK) {
        db_fleet_board_post_prepare_nowait(); return true;
    }
    node_db_close(writer); return false;
}

static enum boot_app_host_result host_publish_due(struct node_db *db,
    struct node_db *writer, struct vcs_package_store *store,
    struct db_app_host_intent *row, const char *endpoint, int64_t now, uint64_t generation)
{
    struct fleet_board_post post;
    int64_t slot = now / 43200 + 1;
    if (!row->pending && row->renewal_slot == slot && !strcmp(row->slot_endpoint, endpoint))
        return host_result(host_defer(db, row, host_next_slot(now)));
    enum app_host_result r = host_pending(db, row, endpoint, now, &post);
    if (r != APP_HOST_OK) {
        (void)host_defer_current(db, row, now); return host_result(r);
    }
    struct db_app_host_intent refreshed;
    r = db_app_host_intent_find(db, row->binding.local_host, row->binding.carrier_root, &refreshed);
    if (r != APP_HOST_OK || !refreshed.pending) return host_result(r == APP_HOST_OK ? APP_HOST_CORRUPT : r);
    *row = refreshed;
    uint8_t carrier[32];
    if (!zcl_hex_decode_lower(row->binding.carrier_root, carrier, sizeof(carrier))) return BOOT_APP_HOST_INVALID;
    struct host_append append = {writer, &post, row->binding.local_host, now, FLEET_BOARD_ERR_BUSY};
#ifdef ZCL_TESTING
    if (s_host_test_hooks && s_host_test_hooks->before_guard)
        s_host_test_hooks->before_guard(s_host_test_hooks->context);
#endif
    vcs_package_store_possession_apply_if_current(store, carrier, generation, true,
                                                   host_append_if_current, &append);
    if (append.result != FLEET_BOARD_OK) {
        (void)host_defer(db, row, host_retry_due(row, now)); return BOOT_APP_HOST_BUSY;
    }
#ifdef ZCL_TESTING
    if (s_host_test_hooks && s_host_test_hooks->after_ingest &&
        !s_host_test_hooks->after_ingest(s_host_test_hooks->context, post.id))
        return BOOT_APP_HOST_BUSY;
#endif
    host_announce(post.id);
    return host_result(db_app_host_intent_reconcile(db, row->binding.local_host,
        row->binding.carrier_root, row->generation, post.id, host_next_slot(now), 0));
}

static enum boot_app_host_result host_publish_checked(struct node_db *db,
    struct node_db *writer, struct vcs_package_store *store,
    const struct db_app_host_intent *snapshot, const char *endpoint,
    int64_t now, uint64_t generation)
{
    struct db_app_host_intent current; uint8_t local[32];
    char checked_host[63], checked_endpoint[ZCL_APP_OFFER_ONION_MAX + 1u];
    enum app_host_result r = db_app_host_intent_find(db, snapshot->binding.local_host,
                                                     snapshot->binding.carrier_root, &current);
    if (r != APP_HOST_OK || !current.enabled || current.generation != snapshot->generation ||
        !host_identity(local, false) || memcmp(local, snapshot->binding.local_host, 32) ||
        !host_endpoint(checked_host, checked_endpoint) || strcmp(endpoint, checked_endpoint))
        return BOOT_APP_HOST_STALE;
    return host_publish_due(db, writer, store, &current, endpoint, now, generation);
}

enum boot_app_host_result boot_app_host_tick(
    struct node_db *db, struct vcs_package_store *store, int64_t now)
{
    if (!db || !store || now <= 0 || now > INT64_MAX - 86400) return BOOT_APP_HOST_INVALID;
    struct db_app_host_intent row; bool found = false;
    host_lock();
    enum boot_app_host_result result = host_due_snapshot(db, now, &row, &found);
    zcl_mutex_unlock(&s_host_lock);
    if (result != BOOT_APP_HOST_OK || !found) return result;
    char host[63], endpoint[ZCL_APP_OFFER_ONION_MAX + 1u];
    struct zcl_app_offer offer; uint64_t generation = 0;
    bool ready = host_endpoint(host, endpoint);
    if (ready) { host_offer_from_row(&row, endpoint, &offer); ready = boot_app_host_verify_carrier(store, &offer, &generation); }
    struct node_db writer = {0};
    if (ready) ready = host_prepare_writer(db, &writer);
    host_lock();
    if (!ready) result = host_defer_current(db, &row, now);
    else result = host_publish_checked(db, &writer, store, &row, endpoint, now, generation);
    zcl_mutex_unlock(&s_host_lock);
    if (writer.open) node_db_close(&writer);
    return result;
}

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Durable recurring hosting intent uses authenticated, exact board bytes. */
#include "test/test_core.h"
#include "crypto/ed25519.h"
#include "models/app_host_intent.h"
#include "models/database.h"
#include "json/json.h"
#include "vcs/app_offer.h"
#include <limits.h>
extern bool boot_app_host_rpc_dispatch(struct node_db *db, const char *op,
    const struct json_value *in, struct json_value *result, int64_t now);

static void hi_binding(struct app_host_binding *b, const uint8_t host[32])
{
    memset(b, 0, sizeof(*b)); memcpy(b->local_host, host, 32);
    snprintf(b->name, sizeof(b->name), "alice/skycombat");
    memset(b->publisher, '1', 66); b->publisher[66] = 0;
    memset(b->release_root, 'a', 64); b->release_root[64] = 0;
    memset(b->carrier_root, 'b', 64); b->carrier_root[64] = 0;
    memset(b->sha256, 'c', 64); b->sha256[64] = 0;
    b->size = 1234; b->recurring = true;
}

static bool hi_wire(const struct app_host_binding *b, const uint8_t seed[32],
                    const char *endpoint, uint64_t created,
                    uint8_t *wire, size_t *len, uint8_t id[32])
{
    struct zcl_app_offer offer = {0}; struct fleet_board_post p = {0};
    snprintf(offer.name, sizeof(offer.name), "%s", b->name);
    snprintf(offer.root, sizeof(offer.root), "%s", b->release_root);
    snprintf(offer.publisher, sizeof(offer.publisher), "%s", b->publisher);
    snprintf(offer.carrier, sizeof(offer.carrier), "%s", b->carrier_root);
    snprintf(offer.sha256, sizeof(offer.sha256), "%s", b->sha256);
    snprintf(offer.onion, sizeof(offer.onion), "%s", endpoint); offer.size = b->size;
    if (!zcl_app_offer_format(&offer, p.text, sizeof(p.text))) return false;
    p.text_len = (uint32_t)strlen(p.text); p.kind = FLEET_BOARD_KIND_OFFER;
    p.scope = FLEET_BOARD_SCOPE_PUBLIC; p.created_at = created; p.ttl = 86400;
    snprintf(p.room, sizeof(p.room), "apps");
    if (fleet_board_post_sign(&p, seed, b->local_host) != FLEET_BOARD_OK ||
        fleet_board_post_encode(&p, wire, APP_HOST_WIRE_MAX, len) != FLEET_BOARD_OK) return false;
    memcpy(id, p.id, 32); return true;
}

int model_app_host_intent_tests(void)
{
    int failures = 0;
    TEST("app hosting consent, exact reservations and recovery survive reopen") {
        char dir[512], path[640]; struct node_db db = {0};
        uint8_t seed[32] = {1}, sk[32], host[32], id1[32], id2[32], badid[32] = {1};
        uint8_t wire1[APP_HOST_WIRE_MAX], wire2[APP_HOST_WIRE_MAX]; size_t n1 = 0, n2 = 0;
        const char *a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:29135";
        const char *b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion:29135";
        struct app_host_binding binding, other, old; struct db_app_host_intent row, rows[1];
        size_t count = 0; bool more = false; const int64_t now = 432100;
        ASSERT(test_mkdtemp(dir, sizeof(dir), "app_host_intent"));
        ASSERT(snprintf(path, sizeof(path), "%s/intent.db", dir) > 0);
        ASSERT(node_db_open(&db, path)); ed25519_keypair(host, sk, seed); memcpy(seed, sk, 32);
        hi_binding(&binding, host); other = binding; other.carrier_root[0] = 'd';
        old = binding; memset(old.local_host, 0, sizeof(old.local_host)); old.local_host[31] = 1;
        binding.recurring = false;
        ASSERT_EQ(db_app_host_intent_enable(&db, &binding, 0, 0), APP_HOST_INVALID);
        binding.recurring = true;
        ASSERT_EQ(db_app_host_intent_enable(&db, &binding, 0, 0), APP_HOST_OK);
        ASSERT_EQ(db_app_host_intent_enable(&db, &other, 0, 0), APP_HOST_OK);
        ASSERT_EQ(db_app_host_intent_enable(&db, &old, 0, 0), APP_HOST_OK);
        ASSERT_EQ(db_app_host_intent_due(&db, host, now, rows, 1, &count, &more), APP_HOST_OK);
        ASSERT_EQ(count, 1u); ASSERT(more); ASSERT(!memcmp(rows[0].binding.local_host, host, 32));
        ASSERT_EQ(db_app_host_intent_due(&db, old.local_host, now, rows, 1, &count, &more), APP_HOST_OK);
        ASSERT_EQ(count, 1u); ASSERT(!more); ASSERT(!memcmp(rows[0].binding.local_host, old.local_host, 32));
        ASSERT_EQ(db_app_host_intent_defer(&db, host, binding.carrier_root, 1, NULL, now, 1), APP_HOST_OK);
        ASSERT(hi_wire(&binding, seed, a, (uint64_t)now, wire1, &n1, id1));
        ASSERT_EQ(db_app_host_intent_reserve(&db, host, binding.carrier_root, 1, 11, now, a, wire1, n1), APP_HOST_OK);
        ASSERT_EQ(db_app_host_intent_reserve(&db, host, binding.carrier_root, 1, 11, now + 86400, a, wire1, n1), APP_HOST_OK);
        ASSERT_EQ(db_app_host_intent_defer(&db, host, binding.carrier_root, 1, NULL, now, 2), APP_HOST_STALE);
        node_db_close(&db); ASSERT(node_db_open(&db, path));
        ASSERT_EQ(db_app_host_intent_find(&db, host, binding.carrier_root, &row), APP_HOST_OK);
        ASSERT(row.pending && row.pending_wire_len == n1 && !memcmp(row.pending_wire, wire1, n1));
        /* An absent old-slot pending post can be replaced in the current
         * later bucket after restart without waiting for its 24-hour TTL. */
        ASSERT(hi_wire(&other, seed, a, (uint64_t)now, wire2, &n2, id2));
        ASSERT_EQ(db_app_host_intent_reserve(&db, host, other.carrier_root, 1, 11, now, a, wire2, n2), APP_HOST_OK);
        node_db_close(&db); ASSERT(node_db_open(&db, path));
        uint8_t old_other_id[32]; memcpy(old_other_id, id2, 32);
        ASSERT(hi_wire(&other, seed, b, 475200u, wire2, &n2, id2));
        ASSERT_EQ(db_app_host_intent_replace_absent(&db, host, other.carrier_root, 1, old_other_id, 475200, b, wire2, n2), APP_HOST_OK);
        ASSERT_EQ(db_app_host_intent_find(&db, host, other.carrier_root, &row), APP_HOST_OK);
        ASSERT(row.pending && row.renewal_slot == 12 && row.replacement_count == 0);
        memcpy(old_other_id, id2, 32);
        ASSERT(hi_wire(&other, seed, a, (uint64_t)now, wire2, &n2, id2));
        ASSERT_EQ(db_app_host_intent_replace_absent(&db, host, other.carrier_root, 1, old_other_id, now, a, wire2, n2), APP_HOST_CONFLICT);
        ASSERT(hi_wire(&other, seed, a, 475201u, wire2, &n2, id2));
        ASSERT_EQ(db_app_host_intent_replace_absent(&db, host, other.carrier_root, 1, old_other_id, 475201, a, wire2, n2), APP_HOST_OK);
        node_db_close(&db); ASSERT(node_db_open(&db, path));
        ASSERT_EQ(db_app_host_intent_find(&db, host, other.carrier_root, &row), APP_HOST_OK);
        ASSERT(row.pending && row.renewal_slot == 12 && row.replacement_count == 1);
        memcpy(old_other_id, id2, 32);
        ASSERT(hi_wire(&other, seed, b, 475202u, wire2, &n2, id2));
        ASSERT_EQ(db_app_host_intent_replace_absent(&db, host, other.carrier_root, 1, old_other_id, 475202, b, wire2, n2), APP_HOST_CONFLICT);
        ASSERT(hi_wire(&binding, seed, b, (uint64_t)now + 1, wire2, &n2, id2));
        ASSERT_EQ(db_app_host_intent_replace_absent(&db, host, binding.carrier_root, 1, badid, now + 1, b, wire2, n2), APP_HOST_STALE);
        ASSERT_EQ(db_app_host_intent_replace_absent(&db, host, binding.carrier_root, 2, id1, now + 1, b, wire2, n2), APP_HOST_STALE);
        wire2[n2 - 1] ^= 1;
        ASSERT_EQ(db_app_host_intent_replace_absent(&db, host, binding.carrier_root, 1, id1, now + 1, b, wire2, n2), APP_HOST_INVALID);
        wire2[n2 - 1] ^= 1;
        ASSERT_EQ(db_app_host_intent_replace_absent(&db, host, binding.carrier_root, 1, id1, now + 1, b, wire2, APP_HOST_WIRE_MAX + 1u), APP_HOST_INVALID);
        ASSERT_EQ(db_app_host_intent_replace_absent(&db, host, binding.carrier_root, 1, id1, now - 1, b, wire2, n2), APP_HOST_INVALID);
        ASSERT_EQ(db_app_host_intent_replace_absent(&db, host, binding.carrier_root, 1, id1, now + 1, b, wire2, n2), APP_HOST_OK);
        ASSERT_EQ(db_app_host_intent_replace_absent(&db, host, binding.carrier_root, 1, id2, now + 1, a, wire1, n1), APP_HOST_CONFLICT);
        ASSERT_EQ(db_app_host_intent_retire_expired(&db, host, binding.carrier_root, 1, id1, now + 86401), APP_HOST_STALE);
        ASSERT_EQ(db_app_host_intent_retire_expired(&db, host, binding.carrier_root, 2, id2, now + 86401), APP_HOST_STALE);
        ASSERT_EQ(db_app_host_intent_retire_expired(&db, host, binding.carrier_root, 1, id2, now + 86400), APP_HOST_CONFLICT);
        ASSERT_EQ(db_app_host_intent_retire_expired(&db, host, binding.carrier_root, 1, id2, now + 86401), APP_HOST_OK);
        ASSERT_EQ(db_app_host_intent_find(&db, host, binding.carrier_root, &row), APP_HOST_OK);
        ASSERT(!row.pending && row.renewal_slot == 11 && row.replacement_count == 1);
        ASSERT_EQ(db_app_host_intent_reserve(&db, host, binding.carrier_root, 1, 10, now, a, wire1, n1), APP_HOST_CONFLICT);
        ASSERT(hi_wire(&binding, seed, a, (uint64_t)now + 86401u, wire1, &n1, id1));
        ASSERT_EQ(db_app_host_intent_reserve(&db, host, binding.carrier_root, 1, 13, now + 86401, a, wire1, n1), APP_HOST_OK);
        ASSERT_EQ(db_app_host_intent_find(&db, host, binding.carrier_root, &row), APP_HOST_OK);
        ASSERT(row.pending && row.renewal_slot == 13 && row.replacement_count == 0);
        ASSERT_EQ(db_app_host_intent_reconcile(&db, host, binding.carrier_root, 1, id1, now + 90000, 0), APP_HOST_OK);
        ASSERT_EQ(db_app_host_intent_reserve(&db, host, binding.carrier_root, 1, 13, now + 86401, a, wire1, n1), APP_HOST_CONFLICT);
        ASSERT(hi_wire(&binding, seed, b, (uint64_t)INT64_MAX - 1u, wire2, &n2, id2));
        ASSERT_EQ(db_app_host_intent_reserve(&db, host, binding.carrier_root, 1, INT64_MAX / 43200 + 1, INT64_MAX, b, wire2, n2), APP_HOST_INVALID);
        ASSERT_EQ(db_app_host_intent_disable(&db, host, binding.carrier_root, 1), APP_HOST_OK);
        other = binding; other.sha256[0] = 'd';
        ASSERT_EQ(db_app_host_intent_enable(&db, &other, 2, now), APP_HOST_CONFLICT);
        ASSERT_EQ(db_app_host_intent_enable(&db, &binding, 2, now), APP_HOST_OK);
        ASSERT_EQ(db_app_host_intent_disable(&db, host, binding.carrier_root, 1), APP_HOST_STALE);
        ASSERT_EQ(db_app_host_intent_find(&db, host, binding.carrier_root, &row), APP_HOST_OK);
        ASSERT_EQ(row.generation, 3);
        ASSERT(node_db_exec(&db, "UPDATE app_host_intents SET generation=9223372036854775806"));
        ASSERT_EQ(db_app_host_intent_disable(&db, host, binding.carrier_root, INT64_MAX - 1), APP_HOST_OK);
        ASSERT_EQ(db_app_host_intent_find(&db, host, binding.carrier_root, &row), APP_HOST_OK);
        ASSERT(!row.enabled && row.generation == INT64_MAX);
        ASSERT_EQ(db_app_host_intent_enable(&db, &binding, INT64_MAX, now), APP_HOST_INVALID);
        ASSERT(node_db_exec(&db, "UPDATE app_host_intents SET name='INVALID'"));
        ASSERT_EQ(db_app_host_intent_find(&db, host, binding.carrier_root, &row), APP_HOST_CORRUPT);
        ASSERT_EQ(db_app_host_intent_due(&db, host, INT64_MAX, rows, 1, &count, &more), APP_HOST_CORRUPT);
        ASSERT_EQ(count, 0u); ASSERT(!more);
        ASSERT_EQ(db_app_host_intent_list(&db, NULL, NULL, rows, 1, &count, &more), APP_HOST_CORRUPT);
        ASSERT_EQ(count, 0u); ASSERT(!more);
        ASSERT(node_db_exec(&db, "DROP TABLE app_host_intents"));
        ASSERT_EQ(db_app_host_intent_find(&db, host, binding.carrier_root, &row), APP_HOST_STORAGE);
        ASSERT_EQ(db_app_host_intent_list(&db, NULL, NULL, rows, 1, &count, &more), APP_HOST_STORAGE);
        ASSERT_EQ(count, 0u); ASSERT(!more);
        struct json_value list_in, list_result; json_init(&list_in); json_set_object(&list_in); json_init(&list_result);
        bool dispatched = boot_app_host_rpc_dispatch(&db, "app_host_list", &list_in, &list_result, 1);
        bool refused = dispatched && !json_get_bool(json_get(&list_result, "ok")) &&
            !strcmp(json_get_str(json_get(&list_result, "code")), "HOST_LIST_UNAVAILABLE") && !json_get(&list_result, "items");
        json_free(&list_in); json_free(&list_result); ASSERT(refused);
        node_db_close(&db); ASSERT_EQ(test_rm_rf_recursive(dir), 0);
    }
_test_next:
    return failures;
}

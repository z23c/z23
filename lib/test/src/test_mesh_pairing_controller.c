/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Adversarial acceptance for owner-visible pairing revocation. */

#include "test/test_core.h"

#include "base/hex.h"
#include "controllers/mesh_pairing_controller.h"
#include "json/json.h"
#include "models/mesh_pairing.h"
#include "platform/time_compat.h"
#include "services/mesh_pairing_service.h"

#include <stdio.h>
#include <string.h>

static void mpc_fill(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

static bool mpc_insert(struct node_db *ndb, uint8_t identity,
                       int64_t paired_at, int64_t expires_at,
                       struct db_mesh_pairing *out)
{
    memset(out, 0, sizeof(*out));
    mpc_fill(out->network_genesis, 0x11);
    mpc_fill(out->peer_master_pubkey, identity);
    mpc_fill(out->peer_noise_pubkey, (uint8_t)(identity + 1));
    out->capability_mask = MESH_PAIRING_CAP_STATUS_READ;
    out->delegation_sequence = 1;
    out->paired_at = paired_at;
    out->expires_at = expires_at;
    return mesh_pairing_id_derive(
               out->network_genesis, out->peer_master_pubkey,
               out->peer_noise_pubkey, out->pairing_id) &&
           db_mesh_pairing_insert(ndb, out);
}

static void mpc_params(struct json_value *params, const char *pairing_id,
                       const char *confirm, bool extra)
{
    json_set_array(params);
    struct json_value input = {0};
    json_set_object(&input);
    (void)json_push_kv_str(&input, "pairing_id", pairing_id);
    if (confirm)
        (void)json_push_kv_str(&input, "confirm", confirm);
    if (extra)
        (void)json_push_kv_bool(&input, "create", true);
    (void)json_push_back(params, &input);
    json_free(&input);
}

static bool mpc_ok(const struct json_value *result)
{
    const struct json_value *ok = result ? json_get(result, "ok") : NULL;
    return ok && ok->type == JSON_BOOL && json_get_bool(ok);
}

static int mpc_service_contract(void)
{
    int failures = 0;
    TEST_CASE("mesh pairing revoke token is bounded atomic and replayable") {
        char dir[256], path[320];
        test_make_tmpdir(dir, sizeof(dir), "mesh_pairing_controller",
                         "revoke");
        snprintf(path, sizeof(path), "%s/node.db", dir);
        struct node_db ndb = {0};
        struct db_mesh_pairing first, second, persisted;
        ASSERT(node_db_open(&ndb, path));
        ASSERT(mpc_insert(&ndb, 0x31, 900, 5000, &first));
        ASSERT(mpc_insert(&ndb, 0x51, 900, 5000, &second));
        struct mesh_pairing_revoke_plan plan;
        ASSERT_EQ(mesh_pairing_service_revoke_plan(
                      &ndb, first.pairing_id, 1000, &plan),
                  MESH_PAIRING_OK);
        ASSERT_EQ(plan.expires_at - plan.issued_at,
                  MESH_PAIRING_REVOKE_PLAN_SECONDS);
        char tampered[MESH_PAIRING_REVOKE_TOKEN_HEX + 1];
        memcpy(tampered, plan.confirmation_token, sizeof(tampered));
        tampered[MESH_PAIRING_REVOKE_TOKEN_HEX - 1] =
            tampered[MESH_PAIRING_REVOKE_TOKEN_HEX - 1] == '0' ? '1' : '0';
        struct mesh_pairing_revoke_result result;
        ASSERT_EQ(mesh_pairing_service_revoke_commit(
                      &ndb, first.pairing_id, tampered, 1001, &result),
                  MESH_PAIRING_CONFIRMATION_INVALID);
        ASSERT(db_mesh_pairing_find(&ndb, first.pairing_id, &persisted));
        ASSERT_EQ(persisted.revoked_at, 0);
        ASSERT_EQ(mesh_pairing_service_revoke_commit(
                      &ndb, first.pairing_id, plan.confirmation_token,
                      1001, &result), MESH_PAIRING_OK);
        ASSERT(!result.replayed);
        ASSERT_EQ(result.pairing.revocation_generation, 1);
        node_db_close(&ndb);
        ASSERT(node_db_open(&ndb, path));
        ASSERT_EQ(mesh_pairing_service_revoke_commit(
                      &ndb, first.pairing_id, plan.confirmation_token,
                      5000, &result), MESH_PAIRING_OK);
        ASSERT(result.replayed);
        ASSERT_EQ(result.pairing.revoked_at, 1001);
        ASSERT_EQ(mesh_pairing_service_revoke_plan(
                      &ndb, second.pairing_id, 1000, &plan),
                  MESH_PAIRING_OK);
        ASSERT_EQ(mesh_pairing_service_revoke_commit(
                      &ndb, second.pairing_id, plan.confirmation_token,
                      plan.expires_at, &result), MESH_PAIRING_PLAN_EXPIRED);
        ASSERT(db_mesh_pairing_find(&ndb, second.pairing_id, &persisted));
        ASSERT_EQ(persisted.revoked_at, 0);
        node_db_close(&ndb);
        test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

static int mpc_malformed_contract(void)
{
    int failures = 0;
    TEST_CASE("mesh pairing malformed and unknown plans make no write") {
        struct node_db ndb = {0};
        struct db_mesh_pairing row, after;
        ASSERT(node_db_open(&ndb, ":memory:"));
        ASSERT(mpc_insert(&ndb, 0x61, 900, 5000, &row));
        struct mesh_pairing_revoke_plan plan;
        ASSERT_EQ(mesh_pairing_service_revoke_plan(
                      &ndb, "ABC", 1000, &plan),
                  MESH_PAIRING_BAD_ARGUMENT);
        char unknown[65];
        memset(unknown, '0', 64);
        unknown[64] = '\0';
        ASSERT_EQ(mesh_pairing_service_revoke_plan(
                      &ndb, unknown, 1000, &plan), MESH_PAIRING_NOT_FOUND);
        struct mesh_pairing_revoke_result result;
        ASSERT_EQ(mesh_pairing_service_revoke_commit(
                      &ndb, row.pairing_id, "bad", 1000, &result),
                  MESH_PAIRING_BAD_ARGUMENT);
        ASSERT(db_mesh_pairing_find(&ndb, row.pairing_id, &after));
        ASSERT_EQ(after.revoked_at, 0);
        ASSERT_EQ(after.revocation_generation, 0);
        node_db_close(&ndb);
    } TEST_END
    return failures;
}

static int mpc_rpc_contract(void)
{
    int failures = 0;
    TEST_CASE("mesh pairing RPC redacts and exposes only revoke") {
        struct node_db ndb = {0};
        struct db_mesh_pairing row;
        int64_t now = (int64_t)platform_time_wall_unix();
        ASSERT(now > 10 && node_db_open(&ndb, ":memory:"));
        ASSERT(mpc_insert(&ndb, 0x71, now - 10, now + 3600, &row));
        struct rpc_table table;
        rpc_table_init(&table);
        register_mesh_pairing_rpc_commands(&table, &ndb);
        set_rpc_warmup_finished();
        ASSERT_EQ(table.num_commands, 3);
        ASSERT(!rpc_table_find(&table, "mesh_pairing_accept"));

        struct json_value params = {0}, result = {0};
        json_set_array(&params);
        ASSERT(rpc_table_execute(&table, "mesh_pairing_list", &params,
                                 &result));
        ASSERT(mpc_ok(&result));
        ASSERT(strcmp(json_get_str(json_get(&result, "schema")),
                      "zcl.mesh.pairing.list.v1") == 0);
        const struct json_value *records = json_get(&result, "pairings");
        ASSERT(records && records->type == JSON_ARR && json_size(records) == 1);
        const struct json_value *view = json_at(records, 0);
        ASSERT(json_get(view, "peer_master_fingerprint"));
        ASSERT(json_get(view, "peer_noise_fingerprint"));
        ASSERT(!json_get(view, "peer_master_pubkey"));
        ASSERT(!json_get(view, "peer_noise_pubkey"));
        ASSERT(!json_get(view, "network_genesis"));
        json_free(&params);
        json_free(&result);

        mpc_params(&params, row.pairing_id, NULL, false);
        ASSERT(rpc_table_execute(&table, "mesh_pairing_revoke_plan", &params,
                                 &result));
        ASSERT(mpc_ok(&result));
        ASSERT(strcmp(json_get_str(json_get(&result, "status")),
                      "planned") == 0);
        const char *token = json_get_str(json_get(&result, "confirmation"));
        ASSERT(token && strlen(token) == MESH_PAIRING_REVOKE_TOKEN_HEX);
        char saved[MESH_PAIRING_REVOKE_TOKEN_HEX + 1];
        memcpy(saved, token, sizeof(saved));
        json_free(&params);
        json_free(&result);

        mpc_params(&params, row.pairing_id, saved, true);
        ASSERT(rpc_table_execute(&table, "mesh_pairing_revoke_commit", &params,
                                 &result));
        ASSERT(!mpc_ok(&result));
        struct db_mesh_pairing unchanged;
        ASSERT(db_mesh_pairing_find(&ndb, row.pairing_id, &unchanged));
        ASSERT_EQ(unchanged.revoked_at, 0);
        json_free(&params);
        json_free(&result);

        mpc_params(&params, row.pairing_id, saved, false);
        ASSERT(rpc_table_execute(&table, "mesh_pairing_revoke_commit", &params,
                                 &result));
        ASSERT(mpc_ok(&result));
        ASSERT(!json_get_bool(json_get(&result, "idempotent_replay")));
        json_free(&params);
        json_free(&result);
        mpc_params(&params, row.pairing_id, saved, false);
        ASSERT(rpc_table_execute(&table, "mesh_pairing_revoke_commit", &params,
                                 &result));
        ASSERT(mpc_ok(&result));
        ASSERT(json_get_bool(json_get(&result, "idempotent_replay")));
        json_free(&params);
        json_free(&result);
        node_db_close(&ndb);
    } TEST_END
    return failures;
}

int test_mesh_pairing_controller(void)
{
    int failures = 0;
    failures += mpc_service_contract();
    failures += mpc_malformed_contract();
    failures += mpc_rpc_contract();
    return failures;
}

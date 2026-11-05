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

/* Mutation-gap coverage: exact response shapes and refusal reasons. */

typedef bool (*mpc_actor)(const struct json_value *, bool, struct json_value *);

static const char *mpc_str(const struct json_value *obj, const char *key)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static bool mpc_str_is(const struct json_value *obj, const char *key,
                       const char *expected)
{
    const char *s = mpc_str(obj, key);
    return s && strcmp(s, expected) == 0;
}

static bool mpc_int_is(const struct json_value *obj, const char *key,
                       int64_t expected)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_INT && json_get_int(v) == expected;
}

static bool mpc_bool_is(const struct json_value *obj, const char *key,
                        bool expected)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_BOOL && json_get_bool(v) == expected;
}

static bool mpc_in_window(const struct json_value *obj, const char *key,
                          int64_t lo, int64_t hi)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_INT && json_get_int(v) >= lo - 1 &&
           json_get_int(v) <= hi + 1;
}

/* A refusal carries ok=false and the same reason token twice. */
static bool mpc_refused(const struct json_value *result, const char *reason)
{
    return mpc_bool_is(result, "ok", false) &&
           mpc_str_is(result, "reason", reason) &&
           mpc_str_is(result, "message", reason);
}

static bool mpc_call(const struct rpc_table *table, const char *method,
                     const struct json_value *params,
                     struct json_value *result)
{
    return rpc_table_execute(table, method, params, result);
}

static void mpc_params_raw(struct json_value *params, const char *k1,
                           const char *v1, const char *k2, const char *v2)
{
    json_set_array(params);
    struct json_value input = {0};
    json_set_object(&input);
    if (k1)
        (void)json_push_kv_str(&input, k1, v1);
    if (k2)
        (void)json_push_kv_str(&input, k2, v2);
    (void)json_push_back(params, &input);
    json_free(&input);
}

static void mpc_int_params(struct json_value *params)
{
    json_set_array(params);
    struct json_value input = {0};
    json_set_object(&input);
    (void)json_push_kv_int(&input, "pairing_id", 5);
    (void)json_push_back(params, &input);
    json_free(&input);
}

static bool mpc_insert_cap(struct node_db *ndb, uint8_t identity,
                           int64_t paired_at, int64_t expires_at,
                           uint64_t mask, uint64_t sequence,
                           struct db_mesh_pairing *out)
{
    memset(out, 0, sizeof(*out));
    mpc_fill(out->network_genesis, 0x11);
    mpc_fill(out->peer_master_pubkey, identity);
    mpc_fill(out->peer_noise_pubkey, (uint8_t)(identity + 1));
    out->capability_mask = mask;
    out->delegation_sequence = sequence;
    out->paired_at = paired_at;
    out->expires_at = expires_at;
    return mesh_pairing_id_derive(
               out->network_genesis, out->peer_master_pubkey,
               out->peer_noise_pubkey, out->pairing_id) &&
           db_mesh_pairing_insert(ndb, out);
}

static const struct json_value *mpc_record(const struct json_value *list,
                                           const char *pairing_id)
{
    const struct json_value *records = json_get(list, "pairings");
    for (size_t i = 0; i < json_size(records); i++)
        if (mpc_str_is(json_at(records, i), "pairing_id", pairing_id))
            return json_at(records, i);
    return NULL;
}

static bool mpc_hex64(const char *s)
{
    if (!s || strlen(s) != 64)
        return false;
    for (size_t i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

static bool mpc_view_numbers(const struct json_value *view,
                             const struct db_mesh_pairing *row,
                             const char *state, int64_t revoked_at,
                             int64_t generation)
{
    return mpc_int_is(view, "capability_mask", (int64_t)row->capability_mask) &&
           mpc_int_is(view, "delegation_sequence",
                      (int64_t)row->delegation_sequence) &&
           mpc_int_is(view, "paired_at", row->paired_at) &&
           mpc_int_is(view, "expires_at", row->expires_at) &&
           mpc_int_is(view, "revoked_at", revoked_at) &&
           mpc_int_is(view, "revocation_generation", generation) &&
           mpc_str_is(view, "state", state);
}

static bool mpc_view_fingerprints(const struct json_value *view)
{
    const char *master = mpc_str(view, "peer_master_fingerprint");
    const char *noise = mpc_str(view, "peer_noise_fingerprint");
    return mpc_hex64(master) && mpc_hex64(noise) && strcmp(master, noise) != 0;
}

static int mpc_list_fields_contract(void)
{
    int failures = 0;
    TEST_CASE("mesh pairing list projects every field of every state") {
        struct node_db ndb = {0};
        struct db_mesh_pairing act, exp, rev;
        int64_t now = (int64_t)platform_time_wall_unix();
        ASSERT(now > 1000 && node_db_open(&ndb, ":memory:"));
        ASSERT(mpc_insert_cap(&ndb, 0x21, now - 300, now + 3600,
                              MESH_PAIRING_CAP_STATUS_READ |
                                  MESH_PAIRING_CAP_TERMINAL_EXEC,
                              7, &act));
        ASSERT(mpc_insert_cap(&ndb, 0x41, now - 200, now - 100,
                              MESH_PAIRING_CAP_STATUS_READ, 3, &exp));
        ASSERT(mpc_insert_cap(&ndb, 0x61, now - 100, now + 3600,
                              MESH_PAIRING_CAP_STATUS_READ, 5, &rev));
        ASSERT_EQ(mesh_pairing_service_revoke(&ndb, rev.pairing_id, now),
                  MESH_PAIRING_OK);
        struct rpc_table table;
        rpc_table_init(&table);
        register_mesh_pairing_rpc_commands(&table, &ndb);
        set_rpc_warmup_finished();
        struct json_value params = {0}, result = {0};
        json_set_array(&params);
        int64_t t0 = (int64_t)platform_time_wall_unix();
        ASSERT(mpc_call(&table, "mesh_pairing_list", &params, &result));
        int64_t t1 = (int64_t)platform_time_wall_unix();
        ASSERT(mpc_bool_is(&result, "ok", true));
        ASSERT(mpc_in_window(&result, "observed_at", t0, t1));
        ASSERT(mpc_int_is(&result, "total", 3));
        ASSERT(mpc_int_is(&result, "active", 1));
        ASSERT(mpc_int_is(&result, "expired", 1));
        ASSERT(mpc_int_is(&result, "revoked", 1));
        ASSERT(mpc_bool_is(&result, "truncated", false));
        ASSERT_EQ(json_size(json_get(&result, "pairings")), 3);
        const struct json_value *va = mpc_record(&result, act.pairing_id);
        const struct json_value *ve = mpc_record(&result, exp.pairing_id);
        const struct json_value *vr = mpc_record(&result, rev.pairing_id);
        ASSERT(va && ve && vr);
        ASSERT(mpc_view_numbers(va, &act, "active", 0, 0));
        ASSERT(mpc_view_numbers(ve, &exp, "expired", 0, 0));
        ASSERT(mpc_view_numbers(vr, &rev, "revoked", now, 1));
        ASSERT(mpc_view_fingerprints(va) && mpc_view_fingerprints(ve));
        ASSERT(mpc_str_is(va, "capability", "status_read+terminal_exec"));
        ASSERT(mpc_str_is(ve, "capability", "status_read"));
        json_free(&params);
        json_free(&result);
        node_db_close(&ndb);
    } TEST_END
    return failures;
}

static int mpc_list_truncation_contract(void)
{
    int failures = 0;
    TEST_CASE("mesh pairing list caps at the maximum and reports truncation") {
        struct node_db ndb = {0};
        struct db_mesh_pairing row;
        int64_t now = (int64_t)platform_time_wall_unix();
        ASSERT(now > 1000 && node_db_open(&ndb, ":memory:"));
        for (unsigned i = 0; i <= MESH_PAIRING_LIST_MAX; i++)
            ASSERT(mpc_insert_cap(&ndb, (uint8_t)(2 * i + 1), now - 100,
                                  now + 3600, MESH_PAIRING_CAP_STATUS_READ,
                                  1, &row));
        struct rpc_table table;
        rpc_table_init(&table);
        register_mesh_pairing_rpc_commands(&table, &ndb);
        set_rpc_warmup_finished();
        struct json_value params = {0}, result = {0};
        json_set_array(&params);
        ASSERT(mpc_call(&table, "mesh_pairing_list", &params, &result));
        ASSERT(mpc_int_is(&result, "total", MESH_PAIRING_LIST_MAX + 1));
        ASSERT(mpc_bool_is(&result, "truncated", true));
        ASSERT_EQ(json_size(json_get(&result, "pairings")),
                  MESH_PAIRING_LIST_MAX);
        json_free(&params);
        json_free(&result);
        node_db_close(&ndb);
    } TEST_END
    return failures;
}

static int mpc_list_refusal_contract(void)
{
    int failures = 0;
    TEST_CASE("mesh pairing list refuses arguments and a failed projection") {
        struct node_db ndb = {0}, closed = {0};
        ASSERT(node_db_open(&ndb, ":memory:"));
        struct rpc_table table;
        rpc_table_init(&table);
        register_mesh_pairing_rpc_commands(&table, &ndb);
        set_rpc_warmup_finished();
        struct json_value params = {0}, result = {0};
        mpc_params(&params, "x", NULL, false);
        ASSERT(mpc_call(&table, "mesh_pairing_list", &params, &result));
        ASSERT(mpc_refused(&result, "bad_argument"));
        json_free(&params);
        json_free(&result);
        json_set_object(&params);
        ASSERT(mpc_call(&table, "mesh_pairing_list", &params, &result));
        ASSERT(mpc_refused(&result, "bad_argument"));
        json_free(&result);
        const struct rpc_command *cmd = rpc_table_find(&table,
                                                       "mesh_pairing_list");
        ASSERT(cmd && cmd->actor(NULL, false, &result));
        ASSERT(mpc_refused(&result, "bad_argument"));
        json_free(&params);
        json_free(&result);
        struct rpc_table dead;
        rpc_table_init(&dead);
        register_mesh_pairing_rpc_commands(&dead, &closed);
        json_set_array(&params);
        ASSERT(mpc_call(&dead, "mesh_pairing_list", &params, &result));
        ASSERT(mpc_refused(&result, "persist_failed"));
        json_free(&params);
        json_free(&result);
        node_db_close(&ndb);
    } TEST_END
    return failures;
}

static bool mpc_help_is(const struct rpc_table *table, const char *name,
                        const char *expected)
{
    const struct rpc_command *cmd = rpc_table_find(table, name);
    struct json_value result = {0};
    bool ok = cmd && cmd->actor(NULL, true, &result) &&
              result.type == JSON_STR &&
              strcmp(json_get_str(&result), expected) == 0;
    json_free(&result);
    return ok;
}

static int mpc_register_contract(void)
{
    int failures = 0;
    TEST_CASE("mesh pairing registration is guarded and the help text is exact") {
        struct node_db ndb = {0};
        ASSERT(node_db_open(&ndb, ":memory:"));
        struct rpc_table none;
        rpc_table_init(&none);
        register_mesh_pairing_rpc_commands(&none, NULL);
        ASSERT_EQ(none.num_commands, 0);
        register_mesh_pairing_rpc_commands(NULL, &ndb);
        struct rpc_table table;
        rpc_table_init(&table);
        register_mesh_pairing_rpc_commands(&table, &ndb);
        ASSERT_EQ(table.num_commands, 3);
        const char *names[] = {"mesh_pairing_list", "mesh_pairing_revoke_plan",
                               "mesh_pairing_revoke_commit"};
        for (size_t i = 0; i < 3; i++) {
            const struct rpc_command *cmd = rpc_table_find(&table, names[i]);
            ASSERT(cmd && cmd->ok_safe_mode);
            ASSERT_STR_EQ(cmd->category, "mesh");
        }
        ASSERT(mpc_help_is(&table, names[0], "mesh_pairing_list\n"));
        ASSERT(mpc_help_is(&table, names[1],
                           "mesh_pairing_revoke_plan {pairing_id}\n"));
        ASSERT(mpc_help_is(&table, names[2],
                           "mesh_pairing_revoke_commit {pairing_id,confirm}\n"));
        node_db_close(&ndb);
    } TEST_END
    return failures;
}

static int mpc_revoke_fields_contract(void)
{
    int failures = 0;
    TEST_CASE("mesh pairing plan and commit responses carry every field") {
        struct node_db ndb = {0};
        struct db_mesh_pairing row;
        int64_t now = (int64_t)platform_time_wall_unix();
        ASSERT(now > 1000 && node_db_open(&ndb, ":memory:"));
        ASSERT(mpc_insert(&ndb, 0x15, now - 10, now + 3600, &row));
        struct rpc_table table;
        rpc_table_init(&table);
        register_mesh_pairing_rpc_commands(&table, &ndb);
        set_rpc_warmup_finished();
        struct json_value params = {0}, plan = {0}, done = {0};
        mpc_params(&params, row.pairing_id, NULL, false);
        int64_t t0 = (int64_t)platform_time_wall_unix();
        ASSERT(mpc_call(&table, "mesh_pairing_revoke_plan", &params, &plan));
        int64_t t1 = (int64_t)platform_time_wall_unix();
        ASSERT(mpc_bool_is(&plan, "ok", true));
        ASSERT(mpc_str_is(&plan, "schema", "zcl.mesh.pairing.revoke.v1"));
        ASSERT(mpc_str_is(&plan, "status", "planned"));
        ASSERT(mpc_str_is(&plan, "state", "active"));
        ASSERT(mpc_str_is(&plan, "pairing_id", row.pairing_id));
        ASSERT(mpc_int_is(&plan, "revocation_generation", 0));
        ASSERT(mpc_in_window(&plan, "issued_at", t0, t1));
        ASSERT_EQ(json_get_int(json_get(&plan, "expires_at")) -
                      json_get_int(json_get(&plan, "issued_at")),
                  MESH_PAIRING_REVOKE_PLAN_SECONDS);
        ASSERT(mpc_bool_is(&plan, "idempotent_replay", false));
        const char *token = mpc_str(&plan, "confirmation");
        ASSERT(token && strlen(token) == MESH_PAIRING_REVOKE_TOKEN_HEX);
        const struct json_value *commit = json_get(&plan, "commit_input");
        ASSERT(commit && commit->type == JSON_OBJ && json_size(commit) == 2);
        ASSERT(mpc_str_is(commit, "pairing_id", row.pairing_id));
        ASSERT(mpc_str_is(commit, "confirm", token));
        json_free(&params);
        mpc_params(&params, row.pairing_id, token, false);
        int64_t c0 = (int64_t)platform_time_wall_unix();
        ASSERT(mpc_call(&table, "mesh_pairing_revoke_commit", &params, &done));
        int64_t c1 = (int64_t)platform_time_wall_unix();
        ASSERT(mpc_bool_is(&done, "ok", true));
        ASSERT(mpc_str_is(&done, "schema", "zcl.mesh.pairing.revoke.v1"));
        ASSERT(mpc_str_is(&done, "status", "revoked"));
        ASSERT(mpc_str_is(&done, "state", "revoked"));
        ASSERT(mpc_str_is(&done, "pairing_id", row.pairing_id));
        ASSERT(mpc_in_window(&done, "revoked_at", c0, c1));
        ASSERT(mpc_int_is(&done, "revocation_generation", 1));
        ASSERT(mpc_str_is(&done, "confirmation", token));
        ASSERT(mpc_bool_is(&done, "idempotent_replay", false));
        json_free(&params);
        json_free(&plan);
        json_free(&done);
        node_db_close(&ndb);
    } TEST_END
    return failures;
}

static bool mpc_run_refused(const struct rpc_table *table, const char *method,
                            const struct json_value *params,
                            const char *reason)
{
    struct json_value result = {0};
    bool ok = mpc_call(table, method, params, &result) &&
              mpc_refused(&result, reason);
    json_free(&result);
    return ok;
}

static int mpc_revoke_refusal_contract(void)
{
    int failures = 0;
    TEST_CASE("mesh pairing revoke refuses malformed, unknown and wrong-key input") {
        struct node_db ndb = {0};
        struct db_mesh_pairing row, after;
        int64_t now = (int64_t)platform_time_wall_unix();
        ASSERT(now > 1000 && node_db_open(&ndb, ":memory:"));
        ASSERT(mpc_insert(&ndb, 0x19, now - 10, now + 3600, &row));
        struct rpc_table table;
        rpc_table_init(&table);
        register_mesh_pairing_rpc_commands(&table, &ndb);
        set_rpc_warmup_finished();
        const char *plan = "mesh_pairing_revoke_plan";
        const char *commit = "mesh_pairing_revoke_commit";
        char unknown[65];
        memset(unknown, '0', 64);
        unknown[64] = '\0';
        struct json_value p = {0};
        json_set_array(&p);
        ASSERT(mpc_run_refused(&table, plan, &p, "bad_argument"));
        ASSERT(mpc_run_refused(&table, commit, &p, "bad_argument"));
        json_free(&p);
        mpc_int_params(&p);
        ASSERT(mpc_run_refused(&table, plan, &p, "bad_argument"));
        json_free(&p);
        mpc_params_raw(&p, "pairing_id", unknown, NULL, NULL);
        ASSERT(mpc_run_refused(&table, plan, &p, "not_found"));
        json_free(&p);
        mpc_params_raw(&p, "pairing_id", row.pairing_id, "create", "x");
        ASSERT(mpc_run_refused(&table, plan, &p, "bad_argument"));
        ASSERT(mpc_run_refused(&table, commit, &p, "bad_argument"));
        json_free(&p);
        mpc_params_raw(&p, "pairing_id", row.pairing_id, "pairing_id",
                       row.pairing_id);
        ASSERT(mpc_run_refused(&table, commit, &p, "bad_argument"));
        json_free(&p);
        mpc_params_raw(&p, "confirm", "x", "confirm", "x");
        ASSERT(mpc_run_refused(&table, commit, &p, "bad_argument"));
        json_free(&p);
        mpc_params_raw(&p, "create", "x", NULL, NULL);
        ASSERT(mpc_run_refused(&table, plan, &p, "bad_argument"));
        json_free(&p);
        char wrong[MESH_PAIRING_REVOKE_TOKEN_HEX + 1];
        memset(wrong, '0', MESH_PAIRING_REVOKE_TOKEN_HEX);
        wrong[MESH_PAIRING_REVOKE_TOKEN_HEX] = '\0';
        mpc_params_raw(&p, "pairing_id", row.pairing_id, "confirm", wrong);
        ASSERT(mpc_run_refused(&table, commit, &p, "confirmation_invalid"));
        json_free(&p);
        ASSERT(db_mesh_pairing_find(&ndb, row.pairing_id, &after));
        ASSERT_EQ(after.revoked_at, 0);
        ASSERT_EQ(after.revocation_generation, 0);
        node_db_close(&ndb);
    } TEST_END
    return failures;
}

static int mpc_revoked_plan_contract(void)
{
    int failures = 0;
    TEST_CASE("mesh pairing plan on a revoked pairing is refused") {
        struct node_db ndb = {0};
        struct db_mesh_pairing row;
        int64_t now = (int64_t)platform_time_wall_unix();
        ASSERT(now > 1000 && node_db_open(&ndb, ":memory:"));
        ASSERT(mpc_insert(&ndb, 0x1d, now - 10, now + 3600, &row));
        ASSERT_EQ(mesh_pairing_service_revoke(&ndb, row.pairing_id, now),
                  MESH_PAIRING_OK);
        struct rpc_table table;
        rpc_table_init(&table);
        register_mesh_pairing_rpc_commands(&table, &ndb);
        set_rpc_warmup_finished();
        struct json_value p = {0};
        mpc_params_raw(&p, "pairing_id", row.pairing_id, NULL, NULL);
        ASSERT(mpc_run_refused(&table, "mesh_pairing_revoke_plan", &p,
                               "already_revoked"));
        json_free(&p);
        node_db_close(&ndb);
    } TEST_END
    return failures;
}

static int mpc_shape_contract(void)
{
    int failures = 0;
    failures += mpc_list_fields_contract();
    failures += mpc_list_truncation_contract();
    failures += mpc_list_refusal_contract();
    failures += mpc_register_contract();
    failures += mpc_revoke_fields_contract();
    failures += mpc_revoke_refusal_contract();
    failures += mpc_revoked_plan_contract();
    return failures;
}

int test_mesh_pairing_controller(void)
{
    int failures = 0;
    failures += mpc_service_contract();
    failures += mpc_malformed_contract();
    failures += mpc_rpc_contract();
    failures += mpc_shape_contract();
    return failures;
}

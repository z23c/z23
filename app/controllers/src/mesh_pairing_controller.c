/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Redacted owner inspection and explicit pairing revocation RPCs. */

#include "controllers/mesh_pairing_controller.h"

#include "base/log_macros.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "services/mesh_pairing_service.h"

#include <limits.h>
#include <string.h>

static struct node_db *g_mesh_pairing_ndb;

static bool mesh_pairing_refuse(struct json_value *result,
                                enum mesh_pairing_reason reason)
{
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", false);
    (void)json_push_kv_str(result, "reason",
                           mesh_pairing_reason_token(reason));
    (void)json_push_kv_str(result, "message",
                           mesh_pairing_reason_token(reason));
    return true;
}

static int64_t mesh_pairing_now(void)
{
    uint64_t now = platform_time_wall_unix();
    return now > 0 && now <= INT64_MAX ? (int64_t)now : 0;
}

static const struct json_value *mesh_pairing_input(
    const struct json_value *params)
{
    if (!params || params->type != JSON_ARR || json_size(params) != 1)
        return NULL;
    const struct json_value *input = json_at(params, 0);
    return input && input->type == JSON_OBJ ? input : NULL;
}

static bool mesh_pairing_exact_keys(const struct json_value *input,
                                    const char *first, const char *second)
{
    size_t expected = second ? 2u : 1u;
    if (!input || input->type != JSON_OBJ || input->num_children != expected)
        return false;
    bool have_first = false, have_second = second == NULL;
    for (size_t i = 0; i < input->num_children; i++) {
        if (strcmp(input->keys[i], first) == 0)
            have_first = true;
        else if (second && strcmp(input->keys[i], second) == 0)
            have_second = true;
        else
            return false;
    }
    return have_first && have_second;
}

static const char *mesh_pairing_string(const struct json_value *input,
                                       const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static void mesh_pairing_push_public(
    struct json_value *array, const struct mesh_pairing_public_view *view)
{
    struct json_value item = {0};
    json_set_object(&item);
    (void)json_push_kv_str(&item, "pairing_id", view->pairing_id);
    (void)json_push_kv_str(&item, "peer_master_fingerprint",
                           view->peer_master_fingerprint);
    (void)json_push_kv_str(&item, "peer_noise_fingerprint",
                           view->peer_noise_fingerprint);
    (void)json_push_kv_int(&item, "capability_mask",
                           (int64_t)view->capability_mask);
    (void)json_push_kv_str(&item, "capability", "status_read");
    (void)json_push_kv_int(&item, "delegation_sequence",
                           (int64_t)view->delegation_sequence);
    (void)json_push_kv_int(&item, "paired_at", view->paired_at);
    (void)json_push_kv_int(&item, "expires_at", view->expires_at);
    (void)json_push_kv_int(&item, "revoked_at", view->revoked_at);
    (void)json_push_kv_int(&item, "revocation_generation",
                           (int64_t)view->revocation_generation);
    (void)json_push_kv_str(&item, "state", view->state);
    (void)json_push_back(array, &item);
    json_free(&item);
}

static bool rpc_mesh_pairing_list(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    if (help) {
        json_set_str(result, "mesh_pairing_list\n");
        return true;
    }
    if (!params || params->type != JSON_ARR || !json_empty(params))
        return mesh_pairing_refuse(result, MESH_PAIRING_BAD_ARGUMENT);
    struct mesh_pairing_public_view views[MESH_PAIRING_LIST_MAX];
    struct db_mesh_pairing_counts counts = {0};
    size_t count = 0;
    int64_t observed_at = mesh_pairing_now();
    if (!mesh_pairing_service_list(g_mesh_pairing_ndb, observed_at,
                                   views, MESH_PAIRING_LIST_MAX, &count,
                                   &counts)) {
        LOG_ERROR("mesh_pairing.rpc", "list projection failed");
        return mesh_pairing_refuse(result, MESH_PAIRING_PERSIST_FAILED);
    }
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_str(result, "schema", "zcl.mesh.pairing.list.v1");
    (void)json_push_kv_int(result, "observed_at", observed_at);
    (void)json_push_kv_int(result, "total", counts.total);
    (void)json_push_kv_int(result, "active", counts.active);
    (void)json_push_kv_int(result, "expired", counts.expired);
    (void)json_push_kv_int(result, "revoked", counts.revoked);
    (void)json_push_kv_bool(result, "truncated", counts.total > (int64_t)count);
    struct json_value records = {0};
    json_set_array(&records);
    for (size_t i = 0; i < count; i++)
        mesh_pairing_push_public(&records, &views[i]);
    (void)json_push_kv(result, "pairings", &records);
    json_free(&records);
    return true;
}

static bool rpc_mesh_pairing_revoke_plan(const struct json_value *params,
                                         bool help,
                                         struct json_value *result)
{
    if (help) {
        json_set_str(result, "mesh_pairing_revoke_plan {pairing_id}\n");
        return true;
    }
    const struct json_value *input = mesh_pairing_input(params);
    if (!mesh_pairing_exact_keys(input, "pairing_id", NULL))
        return mesh_pairing_refuse(result, MESH_PAIRING_BAD_ARGUMENT);
    const char *pairing_id = mesh_pairing_string(input, "pairing_id");
    struct mesh_pairing_revoke_plan plan;
    enum mesh_pairing_reason reason = mesh_pairing_service_revoke_plan(
        g_mesh_pairing_ndb, pairing_id, mesh_pairing_now(), &plan);
    if (reason != MESH_PAIRING_OK)
        return mesh_pairing_refuse(result, reason);
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_str(result, "schema", "zcl.mesh.pairing.revoke.v1");
    (void)json_push_kv_str(result, "status", "planned");
    (void)json_push_kv_str(result, "state", "active");
    (void)json_push_kv_str(result, "pairing_id", plan.pairing_id);
    (void)json_push_kv_int(result, "revocation_generation",
                           (int64_t)plan.revocation_generation);
    (void)json_push_kv_int(result, "issued_at", plan.issued_at);
    (void)json_push_kv_int(result, "expires_at", plan.expires_at);
    (void)json_push_kv_str(result, "confirmation",
                           plan.confirmation_token);
    (void)json_push_kv_bool(result, "idempotent_replay", false);
    struct json_value commit = {0};
    json_set_object(&commit);
    (void)json_push_kv_str(&commit, "pairing_id", plan.pairing_id);
    (void)json_push_kv_str(&commit, "confirm", plan.confirmation_token);
    (void)json_push_kv(result, "commit_input", &commit);
    json_free(&commit);
    return true;
}

static bool rpc_mesh_pairing_revoke_commit(const struct json_value *params,
                                           bool help,
                                           struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "mesh_pairing_revoke_commit {pairing_id,confirm}\n");
        return true;
    }
    const struct json_value *input = mesh_pairing_input(params);
    if (!mesh_pairing_exact_keys(input, "pairing_id", "confirm"))
        return mesh_pairing_refuse(result, MESH_PAIRING_BAD_ARGUMENT);
    const char *pairing_id = mesh_pairing_string(input, "pairing_id");
    const char *confirm = mesh_pairing_string(input, "confirm");
    struct mesh_pairing_revoke_result committed;
    enum mesh_pairing_reason reason = mesh_pairing_service_revoke_commit(
        g_mesh_pairing_ndb, pairing_id, confirm, mesh_pairing_now(),
        &committed);
    if (reason != MESH_PAIRING_OK)
        return mesh_pairing_refuse(result, reason);
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_str(result, "schema", "zcl.mesh.pairing.revoke.v1");
    (void)json_push_kv_str(result, "status", "revoked");
    (void)json_push_kv_str(result, "state", "revoked");
    (void)json_push_kv_str(result, "pairing_id",
                           committed.pairing.pairing_id);
    (void)json_push_kv_int(result, "revoked_at",
                           committed.pairing.revoked_at);
    (void)json_push_kv_int(result, "revocation_generation",
                           (int64_t)committed.pairing.revocation_generation);
    (void)json_push_kv_str(result, "confirmation", confirm);
    (void)json_push_kv_bool(result, "idempotent_replay",
                            committed.replayed);
    return true;
}

void register_mesh_pairing_rpc_commands(struct rpc_table *table,
                                        struct node_db *ndb)
{
    if (!table || !ndb) {
        LOG_ERROR("mesh_pairing.rpc", "register requires table and node_db");
        return;
    }
    g_mesh_pairing_ndb = ndb;
    const struct rpc_command commands[] = {
        {"mesh", "mesh_pairing_list", rpc_mesh_pairing_list, true},
        {"mesh", "mesh_pairing_revoke_plan",
         rpc_mesh_pairing_revoke_plan, true},
        {"mesh", "mesh_pairing_revoke_commit",
         rpc_mesh_pairing_revoke_commit, true},
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        rpc_table_must_append(table, &commands[i]);
}

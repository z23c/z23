/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Local pairing ceremony RPC adapter (plan/commit/list/revoke).
 * Mirrors the boot_mesh_status_rpc.c precedent: every refusal carries an
 * explanatory body, every durable write goes through mesh_pairing_service
 * (ActiveRecord lifecycle) — never raw SQL here. */

#include "config/boot_mesh_pairing.h"

#include "config/runtime.h"
#include "base/hex.h"
#include "json/json.h"
#include "net/v2_identity.h"
#include "platform/time_compat.h"
#include "rpc/server.h"

#include <string.h>

static const struct json_value *rpc_input(const struct json_value *params)
{
    const struct json_value *first =
        params && json_size(params) ? json_at(params, 0) : NULL;
    return first && first->type == JSON_OBJ ? first : NULL;
}

static const char *input_str(const struct json_value *in, const char *key)
{
    const struct json_value *value = in ? json_get(in, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool input_days(const struct json_value *in, int64_t *days_out,
                       bool *given_out)
{
    *given_out = false;
    const struct json_value *value = in ? json_get(in, "days") : NULL;
    if (!value)
        return true;
    if (value->type == JSON_INT) {
        *days_out = json_get_int(value);
        *given_out = true;
        return true;
    }
    return false; /* a days value that is not an integer is a bad argument */
}

static void rpc_error(struct json_value *result, const char *code,
                      const char *message)
{
    json_set_object(result);
    json_push_kv_bool(result, "ok", false);
    json_push_kv_str(result, "code", code);
    json_push_kv_str(result, "message", message);
}

/* Stored pairing record view: public keys, fingerprints, capability mask,
 * derived state, and times. Never private material or local paths. */
static void pairing_record_json(struct json_value *value,
                                const struct db_mesh_pairing *row, int64_t now)
{
    char hex[65];
    json_set_object(value);
    json_push_kv_str(value, "pairing_id", row->pairing_id);
    zcl_hex_encode(row->peer_master_pubkey, 32, hex);
    json_push_kv_str(value, "peer_master_pubkey", hex);
    zcl_hex_encode(row->peer_noise_pubkey, 32, hex);
    json_push_kv_str(value, "peer_noise_pubkey", hex);
    uint8_t fingerprint[32];
    if (v2_identity_public_fingerprint(row->peer_noise_pubkey, fingerprint)) {
        zcl_hex_encode(fingerprint, 32, hex);
        json_push_kv_str(value, "peer_noise_fingerprint_sha3", hex);
    }
    json_push_kv_int(value, "capability_mask", (int64_t)row->capability_mask);
    if (row->capability_mask & MESH_PAIRING_CAP_STATUS_READ) {
        struct json_value caps;
        json_init(&caps);
        json_set_array(&caps);
        struct json_value cap;
        json_init(&cap);
        json_set_str(&cap, "status-read");
        json_push_back(&caps, &cap);
        json_free(&cap);
        json_push_kv(value, "capabilities", &caps);
        json_free(&caps);
    }
    json_push_kv_str(value, "state", boot_mesh_pairing_state(row, now));
    json_push_kv_int(value, "delegation_sequence",
                     (int64_t)row->delegation_sequence);
    json_push_kv_int(value, "paired_at", row->paired_at);
    json_push_kv_int(value, "expires_at", row->expires_at);
    json_push_kv_int(value, "revoked_at", row->revoked_at);
    json_push_kv_int(value, "revocation_generation",
                     (int64_t)row->revocation_generation);
}

static const char *plan_result_message(
    enum boot_mesh_pairing_plan_result result)
{
    switch (result) {
    case MESH_PAIR_PLAN_PEER_NOT_CONNECTED:
        return "no connected peer with an established v2 session matches; "
               "no dial is attempted";
    case MESH_PAIR_PLAN_AMBIGUOUS_PEER:
        return "the selector matched more than one session peer; narrow it "
               "with a longer fingerprint prefix";
    case MESH_PAIR_PLAN_V2_DISABLED:
        return "the v2 Noise transport is disabled on this node";
    case MESH_PAIR_PLAN_DELEGATION_UNAVAILABLE:
        return "no held ZID delegation names the session peer's Noise static";
    default:
        return "the pairing lane is unavailable";
    }
}

static const char *plan_result_code(enum boot_mesh_pairing_plan_result result)
{
    switch (result) {
    case MESH_PAIR_PLAN_PEER_NOT_CONNECTED: return "PEER_NOT_CONNECTED";
    case MESH_PAIR_PLAN_AMBIGUOUS_PEER: return "AMBIGUOUS_PEER";
    case MESH_PAIR_PLAN_V2_DISABLED: return "V2_TRANSPORT_DISABLED";
    case MESH_PAIR_PLAN_DELEGATION_UNAVAILABLE:
        return "DELEGATION_UNAVAILABLE";
    default: return "UNAVAILABLE";
    }
}

static bool rpc_mesh_pairing_plan(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "mesh_pairing_plan {\"peer\":\"<addr substring or Noise "
                     "fingerprint hex prefix>\"} — peer optional when exactly "
                     "one session peer is connected");
        return true;
    }
    const struct json_value *in = rpc_input(params);
    const char *selector = input_str(in, "peer");
    struct boot_mesh_pairing_plan plan;
    enum boot_mesh_pairing_plan_result planned =
        boot_mesh_pairing_plan(selector, &plan);
    if (planned != MESH_PAIR_PLAN_OK) {
        rpc_error(result, plan_result_code(planned),
                  plan_result_message(planned));
        return true;
    }
    char hex[65];
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "peer_addr", plan.peer_addr);
    zcl_hex_encode(plan.peer_noise_fingerprint, 32, hex);
    json_push_kv_str(result, "peer_noise_fingerprint_sha3", hex);
    zcl_hex_encode(plan.peer_noise_static, 32, hex);
    json_push_kv_str(result, "peer_noise_static", hex);
    zcl_hex_encode(plan.peer_master_pubkey, 32, hex);
    json_push_kv_str(result, "peer_master_pubkey", hex);
    json_push_kv_int(result, "delegation_not_before",
                     (int64_t)plan.delegation_not_before);
    json_push_kv_int(result, "delegation_expiry",
                     (int64_t)plan.delegation_expiry);
    json_push_kv_int(result, "delegation_sequence",
                     (int64_t)plan.delegation_sequence);
    json_push_kv_int(result, "delegation_beacon_height",
                     (int64_t)plan.delegation_beacon_height);
    json_push_kv_int(result, "capability_mask",
                     (int64_t)plan.capability_mask);
    json_push_kv_str(result, "capability", "status-read");
    json_push_kv_int(result, "default_days", BOOT_MESH_PAIRING_DEFAULT_DAYS);
    json_push_kv_int(result, "max_days", BOOT_MESH_PAIRING_MAX_DAYS);
    json_push_kv_int(result, "would_expire_at", plan.default_expires_at);
    json_push_kv_str(result, "pairing_id", plan.pairing_id);
    if (plan.existing_state[0])
        json_push_kv_str(result, "existing_state", plan.existing_state);
    return true;
}

static bool rpc_mesh_pairing_commit(const struct json_value *params, bool help,
                                    struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "mesh_pairing_commit {\"peer\":\"<selector>\","
                     "\"fingerprint\":\"<64 lowercase hex>\",\"days\":7} — "
                     "fingerprint is the mandatory out-of-band compared "
                     "value; days defaults to 7 (max 30)");
        return true;
    }
    const struct json_value *in = rpc_input(params);
    const char *selector = input_str(in, "peer");
    const char *fingerprint_hex = input_str(in, "fingerprint");
    if (!fingerprint_hex) {
        rpc_error(result, "MISSING_FINGERPRINT",
                  "fingerprint is mandatory: compare the peer's Noise "
                  "fingerprint out of band (ops mesh identity on the other "
                  "machine) and pass it here; nothing was written");
        return true;
    }
    uint8_t fingerprint[32];
    if (!boot_mesh_pairing_decode_fingerprint(fingerprint_hex, fingerprint)) {
        rpc_error(result, "INVALID_FINGERPRINT",
                  "fingerprint must be 64 canonical lowercase hex chars");
        return true;
    }
    int64_t days = 0;
    bool days_given = false;
    if (!input_days(in, &days, &days_given)) {
        rpc_error(result, "INVALID_DAYS", "days must be an integer");
        return true;
    }
    if (days_given && !boot_mesh_pairing_days_valid(days)) {
        rpc_error(result, "DAYS_OUT_OF_RANGE",
                  "days must be in [1, 30]; nothing was written");
        return true;
    }
    struct db_mesh_pairing row;
    enum mesh_pairing_reason service_reason = MESH_PAIRING_OK;
    enum boot_mesh_pairing_commit_result committed = boot_mesh_pairing_commit(
        selector, fingerprint, days, days_given, &row, &service_reason);
    if (committed != MESH_PAIR_COMMIT_OK) {
        if (committed == MESH_PAIR_COMMIT_SERVICE_REFUSED) {
            rpc_error(result, boot_mesh_pairing_reason_code(service_reason),
                      "the pairing authority refused the commit; nothing was "
                      "written (see mesh_pairing_reason for the code)");
            return true;
        }
        enum boot_mesh_pairing_plan_result as_plan =
            (enum boot_mesh_pairing_plan_result)committed;
        rpc_error(result, plan_result_code(as_plan),
                  plan_result_message(as_plan));
        return true;
    }
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    struct json_value view;
    json_init(&view);
    pairing_record_json(&view, &row,
                        (int64_t)platform_time_wall_time_t());
    json_push_kv(result, "pairing", &view);
    json_free(&view);
    return true;
}

static bool rpc_mesh_pairing_list(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "mesh_pairing_list — every durable pairing record with "
                     "derived state (active/expired/revoked)");
        return true;
    }
    (void)params;
    struct db_mesh_pairing rows[64];
    int count = boot_mesh_pairing_list(rows, 64);
    if (count < 0) {
        rpc_error(result, "UNAVAILABLE", "the node database is unavailable");
        return true;
    }
    int64_t now = (int64_t)platform_time_wall_time_t();
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    struct json_value list;
    json_init(&list);
    json_set_array(&list);
    for (int i = 0; i < count; i++) {
        struct json_value view;
        json_init(&view);
        pairing_record_json(&view, &rows[i], now);
        json_push_back(&list, &view);
        json_free(&view);
    }
    json_push_kv(result, "pairings", &list);
    json_free(&list);
    json_push_kv_int(result, "count", count);
    return true;
}

static bool rpc_mesh_pairing_revoke(const struct json_value *params, bool help,
                                    struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "mesh_pairing_revoke {\"pairing_id\":\"<64 lowercase "
                     "hex>\"} — direct, idempotent, sticky");
        return true;
    }
    const struct json_value *in = rpc_input(params);
    const char *pairing_id = input_str(in, "pairing_id");
    if (!pairing_id || strlen(pairing_id) != MESH_PAIRING_ID_HEX) {
        rpc_error(result, "INVALID_PAIRING_ID",
                  "pairing_id must be 64 canonical lowercase hex chars");
        return true;
    }
    enum mesh_pairing_reason revoked = boot_mesh_pairing_revoke(pairing_id);
    if (revoked != MESH_PAIRING_OK) {
        rpc_error(result, boot_mesh_pairing_reason_code(revoked),
                  revoked == MESH_PAIRING_NOT_FOUND
                      ? "no durable pairing record has that id"
                      : "the revocation could not be persisted");
        return true;
    }
    /* Post-revocation view: the sticky record with its new generation. */
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "pairing_id", pairing_id);
    json_push_kv_str(result, "state", "revoked");
    struct node_db *ndb = app_runtime_node_db();
    struct db_mesh_pairing row;
    if (ndb && app_runtime_node_db_handle_open(ndb) &&
        db_mesh_pairing_find(ndb, pairing_id, &row)) {
        struct json_value view;
        json_init(&view);
        pairing_record_json(&view, &row,
                            (int64_t)platform_time_wall_time_t());
        json_push_kv(result, "pairing", &view);
        json_free(&view);
    }
    return true;
}

void boot_mesh_pairing_register_rpc(struct rpc_table *table)
{
    const struct rpc_command commands[] = {
        {"mesh", "mesh_pairing_plan", rpc_mesh_pairing_plan, true},
        {"mesh", "mesh_pairing_commit", rpc_mesh_pairing_commit, true},
        {"mesh", "mesh_pairing_list", rpc_mesh_pairing_list, true},
        {"mesh", "mesh_pairing_revoke", rpc_mesh_pairing_revoke, true},
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        rpc_table_must_append(table, &commands[i]);
}

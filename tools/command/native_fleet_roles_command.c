/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `fleet roles list|grant|revoke|check` — this node's own view of which
 * key may call which fleet leaf. Every leaf here answers from local files
 * under the datadir and contacts no peer, same discipline as every other
 * `fleet` leaf. See tools/dev/fleet_roles.h for the catalog and store this
 * wraps, and docs/FLEET_ROLES.md for the feature.
 */

#include "command/native_command.h"

#include "base/hex.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "vcs/zcode_dht_identity.h"

#include "dev/fleet_roles.h"

#include <stdio.h>
#include <string.h>

static void roles_refuse(struct zcl_command_reply *reply, const char *code,
                         const char *message, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "roles", false,
                           false, message, evidence);
}

/* `<datadir>/fleet_roles`; the store itself appends `/roles.chain`. */
static bool roles_datadir(char *out, size_t cap)
{
    const char *datadir = zcl_native_command_datadir();
    if (!datadir || datadir[0] != '/')
        return false;
    return (size_t)snprintf(out, cap, "%s", datadir) < cap;
}

/* This node's own operator identity: the online key its filed delegation
 * delegates. Mirrors native_fleet_command.c's fleet_identity(), kept as its
 * own small copy rather than a cross-file call, the same way every other
 * fleet leaf file already does. */
static bool roles_operator_identity(uint8_t pub[32], uint8_t seed[32],
                                    const char **why)
{
    const char *datadir = zcl_native_command_datadir();
    struct vcs_zcode_dht_delegation delegation;
    char error[160];
    if (!datadir ||
        !vcs_zcode_dht_delegation_load(datadir, &delegation, error,
                                       sizeof error)) {
        *why = "this machine has no filed delegation, so it has no "
               "operator key to sign with";
        return false;
    }
    uint8_t online_pub[32];
    if (!vcs_zcode_dht_online_key_load(datadir, seed, online_pub, error,
                                       sizeof error)) {
        *why = "this machine has no online key";
        return false;
    }
    if (memcmp(online_pub, delegation.online_pubkey, 32) != 0) {
        *why = "the online key on disk is not the one this machine's "
               "delegation delegates";
        return false;
    }
    memcpy(pub, online_pub, 32);
    return true;
}

static bool roles_parse_fp(const char *hex, uint8_t out[ZCL_ROLE_FP_BYTES])
{
    return hex && zcl_hex_decode(hex, out, ZCL_ROLE_FP_BYTES);
}

/* ── fleet roles list ────────────────────────────────────────────────── */

void zcl_native_handle_fleet_roles_list(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    if (!reply)
        return;
    zcl_command_reply_init(reply, "zcl.fleet_roles_list.v1");
    char datadir[512];
    if (!roles_datadir(datadir, sizeof datadir)) {
        roles_refuse(reply, "DATADIR_UNAVAILABLE",
                    "the datadir must be an absolute path", "datadir");
        return;
    }
    struct zcl_role_report report;
    struct zcl_role_store *store = zcl_role_store_open(datadir, &report);
    if (!store) {
        roles_refuse(reply, "ROLE_STORE_UNAVAILABLE",
                    zcl_role_status_label(report.status), "fleet_roles");
        return;
    }
    struct zcl_role_entry entries[ZCL_ROLE_LEAF_MAX];
    size_t n = zcl_role_store_list(store, entries,
                                   sizeof entries / sizeof entries[0]);
    zcl_role_store_close(store);

    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < n; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        char fp_hex[65];
        zcl_hex_encode(entries[i].fp, ZCL_ROLE_FP_BYTES, fp_hex);
        char fp8[9];
        zcl_role_fingerprint_short(entries[i].fp, fp8);
        (void)json_push_kv_str(&row, "fingerprint", fp_hex);
        (void)json_push_kv_str(&row, "fp8", fp8);
        (void)json_push_kv_str(&row, "role", zcl_role_name(entries[i].role));
        (void)json_push_kv_bool(&row, "active", entries[i].active);
        (void)json_push_kv_int(&row, "changed_at", entries[i].changed_at);
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "grants", &rows);
    json_free(&rows);
    (void)json_push_kv_int(&reply->data, "count", (int64_t)n);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── fleet roles grant / revoke ──────────────────────────────────────── */

static void roles_write(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply, bool grant,
                        const char *schema)
{
    if (!reply)
        return;
    zcl_command_reply_init(reply, schema);
    if (!request || !request->input) {
        roles_refuse(reply, "MISSING_ARGS", "usage: fleet roles "
                    "grant|revoke <fingerprint> <role>", "fp,role");
        return;
    }
    const char *fp_hex = json_get_str(json_get(request->input, "fp"));
    const char *role_name = json_get_str(json_get(request->input, "role"));
    uint8_t fp[ZCL_ROLE_FP_BYTES];
    uint8_t role = 0;
    if (!roles_parse_fp(fp_hex, fp)) {
        roles_refuse(reply, "BAD_FINGERPRINT",
                    "fp must be a 64-character hex fingerprint", "fp");
        return;
    }
    if (!role_name || !zcl_role_from_name(role_name, &role) ||
        role == ZCL_ROLE_OPERATOR) {
        roles_refuse(reply, "ROLE_UNKNOWN",
                    "role must be one of the declared catalog roles",
                    "role");
        return;
    }
    char datadir[512];
    uint8_t operator_pub[32];
    uint8_t seed[32];
    const char *why = "";
    if (!roles_datadir(datadir, sizeof datadir)) {
        roles_refuse(reply, "DATADIR_UNAVAILABLE",
                    "the datadir must be an absolute path", "datadir");
        return;
    }
    if (!roles_operator_identity(operator_pub, seed, &why)) {
        roles_refuse(reply, "IDENTITY_UNAVAILABLE", why, "datadir");
        return;
    }
    struct zcl_role_report report;
    struct zcl_role_store *store = zcl_role_store_open(datadir, &report);
    if (!store) {
        memset(seed, 0, sizeof seed);
        roles_refuse(reply, "ROLE_STORE_UNAVAILABLE",
                    zcl_role_status_label(report.status), "fleet_roles");
        return;
    }
    int64_t now = (int64_t)platform_time_wall_time_t();
    uint64_t seq = 0;
    enum zcl_role_status status =
        grant ? zcl_role_store_grant(store, fp, role, operator_pub, seed,
                                     now, &seq)
              : zcl_role_store_revoke(store, fp, role, operator_pub, seed,
                                      now, &seq);
    memset(seed, 0, sizeof seed);
    zcl_role_store_close(store);
    if (status != ZCL_ROLE_OK) {
        roles_refuse(reply, "ROLE_REFUSED", zcl_role_status_label(status),
                    "row");
        return;
    }
    char fp8[9];
    zcl_role_fingerprint_short(fp, fp8);
    (void)json_push_kv_str(&reply->data, "fp8", fp8);
    (void)json_push_kv_str(&reply->data, "role", role_name);
    (void)json_push_kv_str(&reply->data, "action", grant ? "grant" : "revoke");
    (void)json_push_kv_int(&reply->data, "seq", (int64_t)seq);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
    reply->error.mutated = true;
}

void zcl_native_handle_fleet_roles_grant(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    roles_write(request, reply, true, "zcl.fleet_roles_grant.v1");
}

void zcl_native_handle_fleet_roles_revoke(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    roles_write(request, reply, false, "zcl.fleet_roles_revoke.v1");
}

/* ── fleet roles check ───────────────────────────────────────────────── */

void zcl_native_handle_fleet_roles_check(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    zcl_command_reply_init(reply, "zcl.fleet_roles_check.v1");
    if (!request || !request->input) {
        roles_refuse(reply, "MISSING_ARGS",
                    "usage: fleet roles check <fingerprint> <leaf> [kind]",
                    "fp,leaf");
        return;
    }
    const char *fp_hex = json_get_str(json_get(request->input, "fp"));
    const char *leaf = json_get_str(json_get(request->input, "leaf"));
    const char *kind = json_get_str(json_get(request->input, "kind"));
    uint8_t fp[ZCL_ROLE_FP_BYTES];
    if (!roles_parse_fp(fp_hex, fp)) {
        roles_refuse(reply, "BAD_FINGERPRINT",
                    "fp must be a 64-character hex fingerprint", "fp");
        return;
    }
    if (!leaf || !leaf[0]) {
        roles_refuse(reply, "MISSING_LEAF", "leaf is required", "leaf");
        return;
    }
    char datadir[512];
    if (!roles_datadir(datadir, sizeof datadir)) {
        roles_refuse(reply, "DATADIR_UNAVAILABLE",
                    "the datadir must be an absolute path", "datadir");
        return;
    }
    uint8_t operator_pub[32];
    uint8_t seed[32];
    const char *why = "";
    bool is_operator = false;
    if (roles_operator_identity(operator_pub, seed, &why)) {
        memset(seed, 0, sizeof seed);
        uint8_t op_fp[ZCL_ROLE_FP_BYTES];
        zcl_role_fingerprint(operator_pub, op_fp);
        is_operator = memcmp(op_fp, fp, ZCL_ROLE_FP_BYTES) == 0;
    }
    struct zcl_role_report report;
    struct zcl_role_store *store = zcl_role_store_open(datadir, &report);
    if (!store && !is_operator) {
        roles_refuse(reply, "ROLE_STORE_UNAVAILABLE",
                    zcl_role_status_label(report.status), "fleet_roles");
        return;
    }
    char why_buf[ZCL_ROLE_LEAF_MAX];
    bool allowed = zcl_role_check(store, fp, is_operator, leaf, kind,
                                  why_buf, sizeof why_buf);
    if (store)
        zcl_role_store_close(store);
    (void)json_push_kv_bool(&reply->data, "allowed", allowed);
    (void)json_push_kv_str(&reply->data, "leaf", leaf);
    if (kind)
        (void)json_push_kv_str(&reply->data, "kind", kind);
    if (allowed)
        (void)json_push_kv_str(&reply->data, "role",
                               is_operator ? "operator" : "granted");
    else
        (void)json_push_kv_str(&reply->data, "reason", why_buf);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}
